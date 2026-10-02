//! M9 — Transparent TLS bridge.
//!
//! The data types and threat-control dispatchers the runtime calls:
//!
//! - `SessionCa` — per-session CA: a self-signed root plus an intermediate.
//! - `issue_leaf` / `LeafCertificate` — per-host leaves signed by that
//!   intermediate, carrying real x509.
//! - `ConnectPolicy` / `authorize_connect` — CONNECT allow-list.
//! - `authorize_redirect` — cross-origin redirect denial.
//! - `TrustInjector` trait + `OpenSslEnvInjector` — trust-injection
//!   adapter for OpenSSL/libcurl/Node.js-trust-store-legacy.
//! - `Bridge` — the dispatcher skeleton that the runtime follows.
//! - `Bridge::serve_connect` — the traffic path: authorise, terminate TLS with
//!   a per-host leaf, relay to the upstream.
//!
//! Authoritative source:
//!   `agent-secretless-vault-spec/docs/06-TRANSPARENT-BRIDGE-EBPF.md`
//!   sections 5, 6 and 7.
//!
//! Substitution is here (ADR-0019): `EstablishedTunnel::relay_substituted`
//! redeems the surrogate **in the tunnel's session**, lends the real
//! credential, rewrites the authorization header on the way upstream, audits
//! the operation without the secret, and relays the response back. The client
//! never receives the credential because there is no path from it to the
//! client side of the relay.
//!
//! Still not here: the eBPF redirect that makes the bridge transparent — it
//! needs kernel privileges this environment does not have, and ADR-0007 gates
//! it on an M8 GO that was recorded as NO-GO. The TLS acceptor is no longer
//! absent: `serve_connect` terminates through it.

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use asv_connector_http::SecretSink;
use asv_domain::{AgentSessionId, Authority};
use asv_tls_acceptor::{handshake_once, LeafMaterial};
use time::OffsetDateTime;
use zeroize::Zeroize;

/// Default TTL for a session CA: 8 hours.
pub const DEFAULT_SESSION_CA_TTL: Duration = Duration::from_secs(8 * 3600);

/// Why a CONNECT request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// The target host:port is not in the session's allow-list.
    #[error("CONNECT tunnel not allowed: {0}")]
    TunnelNotAllowed(String),
}

/// Why a 30x redirect was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedirectError {
    /// The redirect target is not same-origin as the original.
    #[error("cross-origin redirect denied: {from} -> {to}")]
    CrossOrigin {
        /// The original authority.
        from: String,
        /// The proposed redirect target.
        to: String,
    },
}

/// Why a trust-injection adapter failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InjectError {
    /// The session directory could not be written.
    #[error("session dir write failed: {0}")]
    SessionDir(String),
    /// The CA was empty.
    #[error("empty CA DER for {0}")]
    EmptyCa(String),
}

/// Why leaf issuance or leaf verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeafError {
    /// The session CA has already aged out, so no leaf may be minted under it.
    #[error("session CA for {0} is expired")]
    CaExpired(String),
    /// The leaf itself has aged out, so it can no longer be presented even
    /// though its host binding still matches.
    #[error("leaf for {0} has expired")]
    LeafExpired(String),
    /// The requested host is not the one the leaf is bound to. Issuance is
    /// per exact host: a leaf for `a.example` must never validate `b.example`.
    #[error("leaf is bound to {bound}, not to {requested}")]
    HostMismatch {
        /// The host the leaf was issued for.
        bound: String,
        /// The host the caller asked for.
        requested: String,
    },
    /// The session CA carries no intermediate to sign with.
    #[error("session CA for {0} has no signing material")]
    NoSigner(String),
    /// The session CA carries no root, so a leaf minted under it would chain
    /// to nothing and no trust store could validate it.
    #[error("session CA for {0} has no root")]
    NoRoot(String),
    /// The requested host is not a bare, canonical DNS name.
    #[error("{0}")]
    InvalidHost(String),
}

/// Errors that the bridge dispatcher returns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// CONNECT tunnel rejected.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Redirect rejected.
    #[error(transparent)]
    Redirect(#[from] RedirectError),
    /// Leaf issuance rejected.
    #[error(transparent)]
    Leaf(#[from] LeafError),
    /// The client did not send a CONNECT request the bridge can serve.
    #[error("malformed CONNECT request: {0}")]
    Protocol(String),
    /// No leaf was available for the requested host.
    #[error("no leaf available for {0}")]
    NoLeaf(String),
    /// The client presented no session proof, or one that resolved to
    /// nothing (ADR-0019).
    ///
    /// Its own variant rather than `Protocol`, because "you did not prove
    /// which session you are" and "your CONNECT was malformed" are
    /// different operator-facing facts and collapsing them would make a
    /// misconfigured client indistinguishable from a hostile one.
    #[error("no session proof resolved for this tunnel")]
    NoSessionProof,
    /// The upstream could not be resolved or reached.
    #[error("upstream unavailable: {0}")]
    Upstream(String),
    /// A request inside an established tunnel could not be substituted.
    ///
    /// Transparent because the tunnel closes either way; what differs is
    /// only what the operator reads. The *caller* still sees one refusal
    /// (`SubstitutionError::Refused`) whatever went wrong — this variant is
    /// the detail the operator gets and the client does not.
    #[error(transparent)]
    Substitution(#[from] SubstitutionError),
    /// The TLS handshake with the client failed.
    #[error("client handshake failed: {0}")]
    Handshake(String),
    /// A socket operation failed.
    #[error("bridge io: {0}")]
    Io(String),
}

/// A canonicalized (host, port) endpoint. The M9 prototype defines
/// this in-broker; the M9-runtime follow-up may move it to asv-domain
/// once the port field becomes a first-class concept.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorityEndpoint {
    /// The canonical DNS host.
    pub authority: Authority,
    /// The TCP port.
    pub port: u16,
}

impl AuthorityEndpoint {
    /// Constructs a new endpoint. Rejects port 0 (no valid service).
    pub fn new(authority: Authority, port: u16) -> Result<Self, NewAuthorityError> {
        if port == 0 {
            return Err(NewAuthorityError::ZeroPort);
        }
        Ok(Self { authority, port })
    }

    /// Returns the host as a string slice.
    pub fn host(&self) -> &str {
        self.authority.as_ref()
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for AuthorityEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.authority, self.port)
    }
}

/// Why `AuthorityEndpoint::new` failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NewAuthorityError {
    /// Port 0 is reserved; not a valid service.
    #[error("port 0 is not a valid service port")]
    ZeroPort,
}

/// The per-session certificate authority.
///
/// Real x509 material: a self-signed root and an intermediate the root
/// signs. Leaves are signed by the intermediate, so a validating peer that
/// trusts only the root still gets a complete chain. The `seed` argument
/// exists so unit tests are reproducible; production callers pass
/// [`rand::random`].
pub struct SessionCa {
    /// The session this CA belongs to.
    pub session_id: String,
    /// DER-encoded root certificate.
    pub root_der: Vec<u8>,
    /// DER-encoded intermediate certificate.
    pub intermediate_der: Vec<u8>,
    /// The intermediate's private key, used to sign leaves.
    ///
    /// `rcgen::KeyPair` is neither `Clone` nor `Debug`-cheap, so this field is
    /// not part of the struct's derives. The CA is therefore not `Clone`; a
    /// session that needs a second handle re-derives from `intermediate_der`
    /// or shares by reference.
    pub intermediate_key: rcgen::KeyPair,
    /// The intermediate certificate itself, kept because `rcgen` needs the
    /// issuer's `Certificate` (not just its DER) to stamp a leaf's issuer
    /// field, and exposes no public DER-to-`Certificate` conversion.
    pub intermediate_cert: rcgen::Certificate,
    /// When the CA was generated.
    pub issued_at: Instant,
    /// How long the CA is valid for.
    pub ttl: Duration,
}

impl fmt::Debug for SessionCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written because `rcgen::Certificate` is not `Debug`, and
        // because the intermediate's private key must never reach a log line.
        f.debug_struct("SessionCa")
            .field("session_id", &self.session_id)
            .field("root_der_len", &self.root_der.len())
            .field("intermediate_der_len", &self.intermediate_der.len())
            .field("issued_at", &self.issued_at)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl SessionCa {
    /// Generate a fresh two-tier CA: a self-signed root plus an
    /// intermediate it signs.
    ///
    /// Both certificates carry an explicit `not_before`/`not_after` derived
    /// from `ttl`. This is not optional: `rcgen`'s default validity window
    /// is 1975 to 4096, so a certificate generated without setting these
    /// would outlive every session by two thousand years and quietly defeat
    /// the TTL the rest of this module enforces.
    ///
    /// `seed` is only threaded into the subject so tests can distinguish two
    /// CAs; the key material itself comes from the system CSPRNG either way.
    pub fn new(session_id: impl Into<String>, seed: u64, ttl: Duration) -> Self {
        let id = session_id.into();
        let issued_at = Instant::now();
        let now = OffsetDateTime::now_utc();
        let not_after = now + time::Duration::try_from(ttl).unwrap_or(time::Duration::seconds(1));

        let root_key = rcgen::KeyPair::generate().expect("rcgen root key");
        let mut root_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        root_params.not_before = now;
        root_params.not_after = not_after;
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("ASV session root {id}"));
        root_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, format!("asv/{id}/{seed}"));
        let root = root_params
            .self_signed(&root_key)
            .expect("self-signed root");

        let inter_key = rcgen::KeyPair::generate().expect("rcgen intermediate key");
        let mut inter_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
        inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        inter_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        inter_params.not_before = now;
        inter_params.not_after = not_after;
        inter_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("ASV session intermediate {id}"),
        );
        let intermediate = inter_params
            .signed_by(&inter_key, &root, &root_key)
            .expect("root signs intermediate");

        Self {
            session_id: id,
            root_der: root.der().to_vec(),
            intermediate_der: intermediate.der().to_vec(),
            intermediate_key: inter_key,
            intermediate_cert: intermediate,
            issued_at,
            ttl,
        }
    }

    /// True if the CA is past its TTL.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.ttl
    }
}

/// The CONNECT allow-list. Authorising a target is a single linear scan
/// over the allowed endpoints. The runtime follow-up upgrades the scan
/// to a `HashSet` if the connector audience grows past ~100 entries.
#[derive(Debug, Clone, Default)]
pub struct ConnectPolicy {
    /// The set of endpoints that may be `CONNECT`-ed through the bridge.
    pub allowed: Vec<AuthorityEndpoint>,
}

impl ConnectPolicy {
    /// Authorise a CONNECT target.
    pub fn authorize(&self, target: &AuthorityEndpoint) -> Result<(), ConnectError> {
        for allowed in &self.allowed {
            if allowed == target {
                return Ok(());
            }
        }
        Err(ConnectError::TunnelNotAllowed(target.to_string()))
    }

    /// True if the policy is empty. An empty policy means the bridge is
    /// closed (no traffic may flow).
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Number of allowed endpoints.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }
}

/// Authorise a 30x redirect against the original authority.
///
/// `same_origin` is true iff `original` and `proposed` have the same
/// canonical host (case-folded) AND the same port. Different schemes
/// (e.g. `https` → `http`) are an additional concern the M9 runtime
/// follow-up handles via the bridge's TLS state.
pub fn authorize_redirect(
    original: &AuthorityEndpoint,
    proposed: &AuthorityEndpoint,
) -> Result<(), RedirectError> {
    if original.authority == proposed.authority && original.port == proposed.port {
        Ok(())
    } else {
        Err(RedirectError::CrossOrigin {
            from: original.to_string(),
            to: proposed.to_string(),
        })
    }
}

/// A trust-injection binding: when the broker spawns the agent's process
/// tree, it sets `env_var = env_value` and arranges for the file at
/// `env_value` to exist (the broker wrote it at session start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBinding {
    /// The adapter name (`"openssl"`, `"python"`, etc.).
    pub name: &'static str,
    /// The environment variable the agent's process tree should set.
    pub env_var: &'static str,
    /// The value the variable takes. For OpenSSL, this is the file path
    /// of the session-scoped PEM bundle.
    pub env_value: PathBuf,
}

/// The trust-injection trait. Each concrete adapter knows how to make a
/// specific runtime trust the session CA.
pub trait TrustInjector {
    /// Adapter name (stable identifier for the audit log).
    fn name(&self) -> &'static str;

    /// Emit the trust binding. Writes the CA material to a session
    /// directory and returns the env var the broker sets when spawning
    /// the agent's process tree.
    fn inject(&self, ca: &SessionCa, session_dir: &Path) -> Result<TrustBinding, InjectError>;
}

/// Adapter for OpenSSL and the libcurl / Git / Go-runtime stacks that
/// honour `SSL_CERT_FILE` (or its platform-specific aliases).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenSslEnvInjector;

impl OpenSslEnvInjector {
    /// File name inside `session_dir` where the root DER is written.
    pub const PEM_FILE: &'static str = "ssl-cert.pem";
}

impl TrustInjector for OpenSslEnvInjector {
    fn name(&self) -> &'static str {
        "openssl"
    }

    fn inject(&self, ca: &SessionCa, session_dir: &Path) -> Result<TrustBinding, InjectError> {
        if ca.root_der.is_empty() {
            return Err(InjectError::EmptyCa(ca.session_id.clone()));
        }
        let path = session_dir.join(Self::PEM_FILE);
        std::fs::write(&path, &ca.root_der)
            .map_err(|e| InjectError::SessionDir(format!("{}: {e}", path.display())))?;
        Ok(TrustBinding {
            name: "openssl",
            env_var: "SSL_CERT_FILE",
            env_value: path,
        })
    }
}

/// A leaf certificate minted under a session CA for exactly one host.
///
/// Real x509: the intermediate signs it, it carries the host as its only
/// SAN, it is `CA:FALSE`, and its validity ends no later than the CA's. The
/// per-host binding is enforced twice, on purpose:
/// [`LeafCertificate::verify_host_at`] refuses any other host, and the
/// certificate itself does not name any other host, so a TLS peer doing its
/// own hostname check agrees with us. A leaf whose SAN list was merely a
/// superset of the requested host would pass the first check and defeat the
/// second.
#[derive(Debug)]
pub struct LeafCertificate {
    /// The session this leaf belongs to.
    pub session_id: String,
    /// The single host this leaf is valid for.
    pub host: String,
    /// DER-encoded leaf certificate.
    pub leaf_der: Vec<u8>,
    /// The leaf's private key, needed to complete a TLS handshake.
    pub leaf_key: rcgen::KeyPair,
    /// When the leaf was minted.
    pub issued_at: Instant,
    /// How long the leaf is valid for. Never outlives the CA's own TTL in
    /// practice; the CA is re-minted per session, so a leaf outliving its
    /// CA would be a certificate no trust store can validate.
    pub ttl: Duration,
}

impl LeafCertificate {
    /// True if the leaf is past its own TTL.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.ttl
    }

    /// Exact host binding, checked against `now`.
    ///
    /// Exact match, not suffix or wildcard. A CA that can mint for any host
    /// in a zone can mint for a host it was never asked to vouch for, which
    /// is the whole point of per-host issuance: a session authorized for
    /// `api.github.com` must not gain a leaf for `internal.github.com`.
    ///
    /// The time is a parameter on purpose, and this is the only verifier.
    /// An earlier design also offered a clock-free `verify_host` that
    /// checked the binding against `self.issued_at`, and nothing in the
    /// type system stopped a caller from picking it for a decision that
    /// depends on time — which is every real verification. An expired leaf
    /// still binds its host perfectly; only the clock reveals that it must
    /// not be accepted. Passing `self.issued_at` gives the old structural
    /// comparison to a caller that genuinely wants it, but makes the choice
    /// of instant visible at the call site instead of hidden in a second
    /// method.
    pub fn verify_host_at(&self, host: &str, now: Instant) -> Result<(), LeafError> {
        if self.is_expired(now) {
            return Err(LeafError::LeafExpired(self.host.clone()));
        }
        if self.host != host {
            return Err(LeafError::HostMismatch {
                bound: self.host.clone(),
                requested: host.to_string(),
            });
        }
        Ok(())
    }
}

/// Mints a leaf for `host` under `ca`.
///
/// Fails closed in five cases, all of them security-relevant:
///
/// - the CA has expired, so no leaf may outlive its issuer;
/// - the CA has no intermediate, so there is nothing to sign with;
/// - the CA has no root, so the chain terminates in nothing;
/// - the CA material is empty, which would mint a leaf that chains to
///   nothing;
/// - `host` is not a bare, canonical DNS name, so a leaf could be minted for
///   a spelling that no allowlist would ever match.
///
/// `host` is canonicalized with [`Authority::canonicalize`], the same
/// authority that the CONNECT allowlist uses. A leaf is therefore bound to
/// the same notion of "this host" the rest of the codebase has, and two
/// spellings of one host cannot mint two different leaves.
pub fn issue_leaf(ca: &SessionCa, host: &str, now: Instant) -> Result<LeafCertificate, LeafError> {
    if ca.is_expired(now) {
        return Err(LeafError::CaExpired(ca.session_id.clone()));
    }
    if ca.intermediate_der.is_empty() {
        return Err(LeafError::NoSigner(ca.session_id.clone()));
    }
    if ca.root_der.is_empty() {
        return Err(LeafError::NoRoot(ca.session_id.clone()));
    }
    // Canonicalize before doing anything else with the host. This rejects the
    // empty string, surrounding whitespace, embedded `:port`, userinfo,
    // percent-encoding, bare IP literals and single labels, and it lowercases
    // the rest. A leaf bound to `"API.Example.COM"` would never be matched by
    // an allowlist that spells the host in canonical form.
    let host = Authority::canonicalize(host)
        .map_err(|e| LeafError::InvalidHost(e.to_string()))?
        .as_str()
        .to_string();
    // The leaf never outlives the CA: a certificate whose issuer expired
    // first cannot be validated by any trust store that checks the chain.
    let ttl = ca
        .ttl
        .saturating_sub(now.saturating_duration_since(ca.issued_at));
    let key = rcgen::KeyPair::generate().expect("rcgen leaf key");
    let not_before = OffsetDateTime::now_utc();
    // Clamp: the leaf may never outlive the CA, and a wall-clock offset from
    // the monotonic `Instant` is the honest way to say so in x509 terms.
    let remaining = time::Duration::try_from(ttl).unwrap_or(time::Duration::seconds(1));
    let mut params =
        rcgen::CertificateParams::new(vec![host.clone()]).expect("canonical host is a valid SAN");
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = not_before;
    params.not_after = not_before + remaining;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.clone());
    let cert = params
        .signed_by(&key, &ca.intermediate_cert, &ca.intermediate_key)
        .expect("intermediate signs leaf");
    Ok(LeafCertificate {
        session_id: ca.session_id.clone(),
        host,
        leaf_der: cert.der().to_vec(),
        leaf_key: key,
        issued_at: now,
        ttl,
    })
}

/// The bridge dispatcher. The runtime follow-up replaces the single struct
/// with a `rustls::Server` + `hyper` acceptor.
#[derive(Debug, Clone)]
pub struct Bridge {
    policy: ConnectPolicy,
}

impl Bridge {
    /// Build a bridge from a CONNECT policy.
    pub fn new(policy: ConnectPolicy) -> Self {
        Self { policy }
    }

    /// Authorise a CONNECT target. The runtime follow-up replaces this
    /// body with the TLS handshake + surrogate substitution.
    pub fn handle_connect(&self, target: &AuthorityEndpoint) -> Result<(), BridgeError> {
        self.policy.authorize(target).map_err(BridgeError::Connect)
    }

    /// Authorise a 30x redirect. The runtime follow-up calls this when
    /// the upstream returns a 30x.
    pub fn handle_redirect(
        &self,
        original: &AuthorityEndpoint,
        proposed: &AuthorityEndpoint,
    ) -> Result<(), BridgeError> {
        authorize_redirect(original, proposed).map_err(BridgeError::Redirect)
    }

    /// Returns the number of endpoints in the CONNECT allow-list.
    pub fn allowed_count(&self) -> usize {
        self.policy.len()
    }
}

/// A leaf the bridge is willing to present, bound to exactly one host.
pub struct VerifiedLeaf {
    certificate: LeafCertificate,
    material: LeafMaterial,
}

impl VerifiedLeaf {
    /// Pairs a minted leaf with the material that presents it.
    ///
    /// The chain is ordered `[end-entity, intermediate]`; that order is
    /// load-bearing, and a client that cannot build a path reports it as a
    /// trust failure indistinguishable from a missing intermediate.
    pub fn from_certificate(
        ca: &SessionCa,
        certificate: LeafCertificate,
    ) -> Result<Self, BridgeError> {
        let material = LeafMaterial::new(
            ca.root_der.clone(),
            vec![certificate.leaf_der.clone(), ca.intermediate_der.clone()],
            certificate.leaf_key.serialize_der(),
        )
        .map_err(|e| BridgeError::Handshake(e.to_string()))?;
        Ok(Self {
            certificate,
            material,
        })
    }
}

/// Where the bridge gets per-session leaves from.
///
/// A trait rather than a field because `tls_bridge` must not depend on the
/// vault (D2, enforced by a test): the broker holds the vault and implements
/// this. The bridge only ever sees material it cannot mint.
pub trait LeafSource {
    /// Issues a leaf for exactly `host`, or refuses.
    ///
    /// `serve_connect` checks the returned leaf's host binding again. An
    /// implementation that skips its own check does not weaken the bridge,
    /// because the bridge does not take its word for it.
    fn issue_for(&self, host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError>;
}

/// Turns an authorised target into a socket address.
///
/// Also a trait, so a test can point at a loopback origin without DNS and the
/// runtime can apply whatever address policy it already holds.
pub trait UpstreamResolver {
    /// The address to dial for `target`.
    fn resolve(&self, target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError>;
}

/// A CONNECT that has been authorised, TLS-terminated and dialled.
///
/// Both halves are returned rather than relayed, because a duplex relay over
/// one `StreamOwned` has no shape in this rustls version that does not
/// deadlock. See [`Bridge::serve_connect`].
#[derive(Debug)]
pub struct EstablishedTunnel {
    /// To the client, presenting the session leaf for `target`'s host.
    pub client: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    /// To the upstream, already connected.
    pub upstream: TcpStream,
    /// The authorised target this tunnel is for.
    pub target: AuthorityEndpoint,
    /// The session this tunnel belongs to (ADR-0019).
    ///
    /// Resolved from a signature, not asserted by the client. It is `None`
    /// only on a path that does not attempt substitution at all; a tunnel
    /// that is going to carry a credential always has one.
    pub session: Option<AgentSessionId>,
}

/// Where the bridge gets session proofs from.
///
/// A trait rather than a field for the same reason `LeafSource` is one:
/// `tls_bridge` must not depend on the broker's state or the vault (D2,
/// enforced by a test). The bridge only ever sees the answer.
pub trait SessionProofs {
    /// Resolves a session proof to the session whose registered key signed
    /// it, or `None` if no registered key does.
    ///
    /// The presented blob only *selects* a candidate. What proves ownership
    /// is the signature over the nonce, checked by the implementation
    /// against the key the broker actually registered — never against the
    /// blob the client presented.
    fn resolve(
        &self,
        presented_key: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Option<AgentSessionId>;
}

/// The nonce a session proof is computed over.
///
/// It is bound to the destination, not drawn fresh per tunnel. That is a
/// deliberate trade: a server-issued nonce would be stronger against
/// replay, but it costs a round trip before the CONNECT, and this path
/// exists to serve ordinary HTTP clients that do not have one.
///
/// What the binding buys is that a proof captured for one destination does
/// not verify against another, so it cannot be moved to a host the operator
/// did not authorise. What it does not buy is freshness: a proof replayed
/// against the *same* destination verifies again. That is not a grant,
/// because the surrogate it would be spent with is single-use and was
/// already spent the first time.
pub fn proof_nonce(presented_key: &[u8], target: &AuthorityEndpoint) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Length-prefixed so a key ending in the same bytes as a host cannot
    // produce the same digest as a shorter key followed by a longer host.
    hasher.update((presented_key.len() as u64).to_be_bytes());
    hasher.update(presented_key);
    hasher.update(target.host().as_bytes());
    hasher.update((target.port() as u64).to_be_bytes());
    hasher.finalize().to_vec()
}

/// Why a credential could not be substituted into a CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubstitutionError {
    /// The request carried no bearer token to substitute.
    #[error("request carries no bearer credential")]
    NoCredential,
    /// The surrogate is unknown, expired, exhausted, of the wrong class,
    /// or belongs to another session.
    ///
    /// Carries no reason, and that is load-bearing rather than tidy. A
    /// caller that could tell "unknown token" from "wrong session" learns
    /// whether a token it holds is real, which is the difference between
    /// "try another one" and "you do not own this". Every one of those
    /// causes answers the same way, and the detail is logged where the
    /// operator can read it and the caller cannot.
    #[error("the presented surrogate was refused")]
    Refused,
    /// The port refused to lend.
    #[error("the credential could not be lent: {0}")]
    Lend(String),
}

/// What a successful substitution says about itself, for the audit record.
///
/// The family is returned rather than asked for separately because only the
/// port knows it: it is the credential's class translated into the operation
/// family the surrogate was minted for. A bridge that guessed it, or that
/// audited a hard-coded string, would be auditing a fact it had not
/// established — which is the same defect `WrongSession` is a guard against
/// on the spending side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substituted {
    /// Wire name of the operation family, e.g. `"github"`.
    pub family: &'static str,
}

/// Where the bridge gets credential substitution from.
///
/// The third trait for the same reason as `LeafSource`: `tls_bridge` must
/// not depend on the vault or the broker's state (D2, enforced by a test).
/// What the bridge contributes is the header surgery; what the
/// implementation contributes is the decision.
pub trait CredentialSubstituter {
    /// Redeems `surrogate` **in `session`** and lends what it stands for
    /// into `sink`.
    ///
    /// The session is the tunnel's, resolved from a signature in
    /// `serve_connect`. It is not the client's to choose, which is what
    /// keeps `WrongSession` meaningful: a token minted elsewhere still
    /// fails, because "elsewhere" is now a fact the broker established
    /// rather than a claim it accepted.
    ///
    /// `&mut self` because redeeming spends a use: `SurrogateRegistry::
    /// redeem_for` is `&mut self` because a token has a budget, and a trait
    /// that hid that behind a `&self` would force every production
    /// implementation to invent a lock to be honest about it.
    fn substitute(
        &mut self,
        surrogate: &str,
        session: AgentSessionId,
        sink: &mut dyn SecretSink,
    ) -> Result<Substituted, SubstitutionError>;
}

/// One substitution, as the audit log records it.
///
/// Metadata only by construction: every field is a wire name, a host or an
/// opaque id, and there is **no field that could hold secret bytes**. That is
/// the property R-9.5 asks for, and it is structural rather than a promise
/// about a caller's discipline — a record that had a field to put the
/// credential in would stop being safe the first time someone used it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionRecord {
    /// The session whose key signed the proof, resolved by `serve_connect`.
    pub session: AgentSessionId,
    /// The authorised destination, `host:port`.
    pub destination: String,
    /// The operation family the credential was spent on.
    pub family: &'static str,
    /// `"substituted"`, or `"refused"` when the tunnel closed instead.
    pub outcome: &'static str,
}

/// Where the bridge sends substitution records.
///
/// A trait for the same reason `LeafSource` and `CredentialSubstituter` are
/// ones: the bridge must not depend on the broker's audit store. The
/// implementation decides durability and chaining; the bridge only states
/// what happened.
pub trait SubstitutionAudit {
    fn record(&mut self, record: SubstitutionRecord) -> Result<(), BridgeError>;
}

/// Bounds on one relay, so a peer cannot make the bridge hold memory or
/// block forever.
///
/// The response cap is not a politeness limit. A relay that waits for an
/// upstream EOF will wait forever against an origin that keeps the
/// connection open, and the tunnel is the broker's to bound, not the peer's
/// to extend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Largest inner request head that will be read from the client.
    pub max_head: usize,
    /// Largest number of response bytes relayed back to the client.
    pub max_response: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_head: 8 * 1024,
            max_response: 1024 * 1024,
        }
    }
}

/// What one relay accomplished, in numbers.
///
/// Deliberately counts only. Returning the forwarded request or the lent
/// credential would make this struct a second place the secret lives, and a
/// caller that logged it would have undone the substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubstitutionOutcome {
    /// Bytes written to the upstream, headers included.
    pub forwarded: usize,
    /// Bytes relayed back from the upstream to the client.
    pub returned: usize,
}

/// The bearer token in a request, if it has one.
///
/// Returns the value without the `Bearer ` prefix, which is the form a
/// surrogate is presented in and the form `redeem_for` takes.
pub fn bearer_token(request: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("authorization") {
            continue;
        }
        let value = value.trim();
        return Some(match value.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => {
                token.trim().to_string()
            }
            _ => value.to_string(),
        });
    }
    None
}

/// Returns `request` with its bearer token replaced.
///
/// The rewrite is byte-oriented on purpose: re-serialising the request
/// would reformat headers the provider may be sensitive to, and would
/// risk normalising a token that contains bytes a naive parse would
/// mangle. Only the token's extent is replaced, and the length change is
/// accounted for so the head and body boundary is preserved.
pub fn replace_bearer_token(
    request: &[u8],
    replacement: &str,
) -> Result<Vec<u8>, SubstitutionError> {
    let text = std::str::from_utf8(request).map_err(|_| SubstitutionError::NoCredential)?;
    let mut out = Vec::with_capacity(request.len() + replacement.len());
    let mut replaced = false;
    let mut offset = 0usize;
    for line in text.split_inclusive("\r\n") {
        let Some((name, _value)) = line.split_once(':') else {
            out.extend_from_slice(line.as_bytes());
            offset += line.len();
            continue;
        };
        if !replaced && name.trim().eq_ignore_ascii_case("authorization") {
            let value_start = offset + name.len() + 1;
            let body_end = offset + line.len();
            let raw_value = &text[value_start..body_end];
            let kept_prefix = match raw_value.split_once(' ') {
                Some((scheme, _)) => scheme.len() + 1,
                None => 0,
            };
            out.extend_from_slice(&request[offset..value_start + kept_prefix]);
            out.extend_from_slice(replacement.as_bytes());
            out.extend_from_slice(b"\r\n");
            replaced = true;
            offset = body_end;
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        offset += line.len();
    }
    if !replaced {
        return Err(SubstitutionError::NoCredential);
    }
    Ok(out)
}

/// The header a CONNECT client presents its session proof in.
///
/// Named, not positional, so that a client which does not know about ASV
/// is unaffected: an absent header means "no proof", and the tunnel is
/// refused rather than half-authorised.
pub const SESSION_PROOF_HEADER: &str = "x-asv-session-proof";

/// A session proof as it arrives on the wire: the client's key blob and a
/// signature over [`proof_nonce`], both unpadded base64 and separated by a
/// dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProof {
    pub key: Vec<u8>,
    pub signature: Vec<u8>,
}

fn parse_session_proof(head: &str) -> Option<SessionProof> {
    let raw = head.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(SESSION_PROOF_HEADER) {
            Some(value.trim())
        } else {
            None
        }
    })?;
    let (key, signature) = raw.split_once('.')?;
    let key = base64_decode(key)?;
    let signature = base64_decode(signature)?;
    // An empty half is not a malformed proof, it is *no* proof: accepting
    // one would hand the resolver an empty signature to fail on later, at
    // a point where the failure no longer says the client sent nonsense.
    if key.is_empty() || signature.is_empty() {
        return None;
    }
    Some(SessionProof { key, signature })
}

/// Standard base64, no padding, no external dependency.
///
/// Decoding is strict on purpose: this reads attacker-chosen bytes, and a
/// decoder that skips unknown characters would let `key` and `signature`
/// disagree with what was on the wire in a way no later check would notice.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Unpadded base64 cannot have a group of one character: six bits do not
    // make a byte. Refusing it here means two encodings of the same nonce
    // cannot both be accepted, one of them truncated.
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Reads a CONNECT request head without reading past its terminator.
///
/// A `BufReader` would be the obvious way and it is wrong here: it may buffer
/// past `\r\n\r\n` and swallow the first bytes of the client's TLS
/// ClientHello, which then never reach the handshake. This reads one byte at a
/// time and stops exactly at the terminator.
fn read_connect_head(stream: &TcpStream) -> Result<String, BridgeError> {
    const MAX_HEAD: usize = 8 * 1024;
    let mut reader = stream;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return String::from_utf8(head)
                .map_err(|_| BridgeError::Protocol("non-UTF-8 head".into()));
        }
        if head.len() > MAX_HEAD {
            return Err(BridgeError::Protocol("CONNECT head exceeds 8 KiB".into()));
        }
    }
}

/// Parses `CONNECT host:port HTTP/1.1`.
fn parse_connect_target(head: &str) -> Result<AuthorityEndpoint, BridgeError> {
    let request_line = head
        .split("\r\n")
        .next()
        .ok_or_else(|| BridgeError::Protocol("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| BridgeError::Protocol("no method".into()))?;
    if method != "CONNECT" {
        return Err(BridgeError::Protocol(format!(
            "method {method} is not CONNECT"
        )));
    }
    let authority = parts
        .next()
        .ok_or_else(|| BridgeError::Protocol("no authority".into()))?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| BridgeError::Protocol(format!("{authority} has no port")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| BridgeError::Protocol(format!("{authority} has a non-numeric port")))?;
    let authority =
        Authority::canonicalize(host).map_err(|e| BridgeError::Protocol(format!("{host}: {e}")))?;
    AuthorityEndpoint::new(authority, port).map_err(|e| BridgeError::Protocol(e.to_string()))
}

impl Bridge {
    /// Serves one CONNECT request on `client`, and returns the established
    /// tunnel.
    ///
    /// The order of the operations is the specification, not a detail:
    /// `handle_connect` authorises **before** the first socket is opened, so a
    /// target outside the allow-list produces no upstream connection at all,
    /// not a connection that failed to be authorised.
    ///
    /// Why this returns the pair instead of relaying it: a duplex relay over
    /// one `StreamOwned` needs either `Arc<Mutex<..>>` — which deadlocks the
    /// moment one direction blocks in a read while holding the lock — or a
    /// connection API this version of rustls does not offer. Handing the
    /// tunnel back keeps the security-relevant half here, where it can be
    /// tested, and leaves the loop to a caller that knows the protocol it is
    /// relaying.
    ///
    /// What this does not do is substitute the surrogate for a real credential
    /// on the way upstream. The caller sees the decrypted bytes. That is why
    /// UAT-010 still has no suite.
    pub fn serve_connect(
        &self,
        client: TcpStream,
        leaves: &dyn LeafSource,
        upstream: &dyn UpstreamResolver,
        proofs: Option<&dyn SessionProofs>,
        now: Instant,
    ) -> Result<EstablishedTunnel, BridgeError> {
        let head = read_connect_head(&client)?;
        let target = parse_connect_target(&head)?;

        self.handle_connect(&target)?;

        // The destination is authorised before the proof is even looked at.
        // A target outside the allow-list must not be able to induce a
        // signature verification, let alone a credential loan.
        let session = match parse_session_proof(&head) {
            None => None,
            Some(proof) => {
                let Some(proofs) = proofs else {
                    return Err(BridgeError::NoSessionProof);
                };
                let nonce = proof_nonce(&proof.key, &target);
                match proofs.resolve(&proof.key, &nonce, &proof.signature) {
                    Some(session) => Some(session),
                    // A presented proof that does not resolve is a failure,
                    // not an anonymous tunnel. Forwarding it unsubstituted
                    // would send the client's credential to the outside
                    // world and report a provider error instead of the
                    // truth.
                    None => return Err(BridgeError::NoSessionProof),
                }
            }
        };

        let mut ack = &client;
        ack.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        ack.flush().map_err(|e| BridgeError::Io(e.to_string()))?;

        let leaf = leaves
            .issue_for(target.host(), now)
            .map_err(BridgeError::Leaf)?;
        leaf.certificate.verify_host_at(target.host(), now)?;

        let config = leaf
            .material
            .server_config()
            .map_err(|e| BridgeError::Handshake(e.to_string()))?;
        let client =
            handshake_once(client, &config).map_err(|e| BridgeError::Handshake(e.to_string()))?;

        let addr = upstream.resolve(&target)?;
        let upstream =
            TcpStream::connect(addr).map_err(|e| BridgeError::Upstream(e.to_string()))?;

        Ok(EstablishedTunnel {
            client,
            upstream,
            target,
            session,
        })
    }
}

/// Reads an inner request head from the decrypted client side.
///
/// Same reasoning as `read_connect_head`, and for the same reason: a
/// `BufReader` would read past the terminator and swallow bytes that belong
/// to the body or to the next request on the tunnel. Reading stops exactly at
/// `\r\n\r\n`.
///
/// Unlike the CONNECT head this runs *through* TLS, so each byte is a
/// `StreamOwned` read. That is not a performance claim — it is a head, once
/// per tunnel.
fn read_inner_head<R: Read>(stream: &mut R, max: usize) -> Result<Vec<u8>, BridgeError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > max {
            return Err(BridgeError::Protocol(
                "inner request head exceeds the relay limit".into(),
            ));
        }
    }
}

/// Copies upstream to client until the upstream closes or `max` is reached.
fn relay_back<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    max: usize,
) -> Result<usize, BridgeError> {
    let mut buf = [0u8; 8 * 1024];
    let mut total = 0usize;
    while total < max {
        let want = (max - total).min(buf.len());
        let n = from
            .read(&mut buf[..want])
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n])
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        total += n;
    }
    to.flush().map_err(|e| BridgeError::Io(e.to_string()))?;
    Ok(total)
}

/// Holds a lent credential for exactly as long as the rewrite needs it.
///
/// The `Drop` is the point, not a nicety: every exit from `relay_substituted`
/// — success, refusal, a write that failed, an audit that failed — passes
/// through here, and only one of them is the happy path. A wipe written at the
/// end of the happy path would leave the credential in the heap on all the
/// others.
struct Lending(Vec<u8>);

impl SecretSink for Lending {
    fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
        self.0.extend_from_slice(secret);
        Ok(())
    }
}

impl Drop for Lending {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl EstablishedTunnel {
    /// Substitutes the surrogate in the first inner request and relays the
    /// response back.
    ///
    /// The order is `design.md` F5, and it is the contract rather than a
    /// detail:
    ///
    /// 1. the session comes from the tunnel, resolved by signature in
    ///    `serve_connect` — never from the request;
    /// 2. the surrogate is redeemed **in that session**, which is what keeps
    ///    `WrongSession` intact;
    /// 3. only then is the credential lent and the header rewritten;
    /// 4. only then is anything written to the upstream;
    /// 5. and the record is written before the response goes back, so a relay
    ///    that dies mid-copy still leaves the audit trail of a substitution.
    ///
    /// What it refuses to do is the thing the spec calls out: a request that
    /// cannot be substituted is **not** forwarded with its surrogate intact
    /// on the theory that the provider will reject it. That would send the
    /// client's credential to the outside world and report a provider error
    /// instead of the truth. Here the upstream socket is written zero bytes
    /// and the tunnel closes.
    ///
    /// What it does not do is own the whole connection. This relays the first
    /// request's head and then the upstream's response; a second request on
    /// the same tunnel is a later increment. The duplex-copy deadlock that
    /// kept `serve_connect` from relaying at all is not solved here — the
    /// two copies run in sequence instead.
    pub fn relay_substituted(
        &mut self,
        substituter: &mut dyn CredentialSubstituter,
        audit: &mut dyn SubstitutionAudit,
        limits: RelayLimits,
    ) -> Result<SubstitutionOutcome, BridgeError> {
        let session = self.session.ok_or(BridgeError::NoSessionProof)?;
        let destination = format!("{}:{}", self.target.host(), self.target.port());

        let head = read_inner_head(&mut self.client, limits.max_head)?;
        let token = bearer_token(&head).ok_or(SubstitutionError::NoCredential)?;

        let mut lent = Lending(Vec::new());
        let substituted = match substituter.substitute(&token, session, &mut lent) {
            Ok(s) => s,
            Err(e) => {
                // Recorded before returning, and the family is `"unresolved"`
                // rather than a guess: the port declined before it
                // established one, and inventing it would put an
                // unestablished fact in the audit log.
                audit.record(SubstitutionRecord {
                    session,
                    destination,
                    family: "unresolved",
                    outcome: "refused",
                })?;
                return Err(BridgeError::Substitution(e));
            }
        };

        // Borrowed only inside this block, so the credential stops being
        // reachable the moment the rewritten request exists.
        let mut rewritten = {
            let credential =
                std::str::from_utf8(&lent.0).map_err(|_| SubstitutionError::NoCredential)?;
            replace_bearer_token(&head, credential)?
        };

        self.upstream
            .write_all(&rewritten)
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        self.upstream
            .flush()
            .map_err(|e| BridgeError::Io(e.to_string()))?;
        let forwarded = rewritten.len();
        // The buffer that carried the credential upstream is wiped here, not
        // left to the allocator's discretion.
        rewritten.zeroize();

        audit.record(SubstitutionRecord {
            session,
            destination,
            family: substituted.family,
            outcome: "substituted",
        })?;

        let returned = relay_back(&mut self.upstream, &mut self.client, limits.max_response)?;

        Ok(SubstitutionOutcome {
            forwarded,
            returned,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(s: &str) -> Authority {
        Authority::canonicalize(s).expect("test authority")
    }

    #[test]
    fn session_ca_has_distinct_root_and_intermediate() {
        let ca = SessionCa::new("sess-001", 42, DEFAULT_SESSION_CA_TTL);
        assert!(!ca.root_der.is_empty());
        assert!(!ca.intermediate_der.is_empty());
        assert_ne!(ca.root_der, ca.intermediate_der);
        assert_eq!(ca.session_id, "sess-001");
        assert_eq!(ca.ttl, DEFAULT_SESSION_CA_TTL);
    }

    #[test]
    fn session_ca_is_not_expired_immediately() {
        let ca = SessionCa::new("sess-002", 0, DEFAULT_SESSION_CA_TTL);
        assert!(!ca.is_expired(Instant::now()));
    }

    #[test]
    fn session_ca_is_expired_past_ttl() {
        let ttl = Duration::from_millis(100);
        let ca = SessionCa::new("sess-003", 0, ttl);
        std::thread::sleep(Duration::from_millis(150));
        assert!(ca.is_expired(Instant::now()));
    }

    #[test]
    fn session_ca_uses_session_id_in_payload() {
        // Two CAs with different session ids but the same seed produce
        // different root/intermediate DER. This is the structural
        // guarantee that the prototype is content-addressed.
        let a = SessionCa::new("a", 1, DEFAULT_SESSION_CA_TTL);
        let b = SessionCa::new("b", 1, DEFAULT_SESSION_CA_TTL);
        assert_ne!(a.root_der, b.root_der);
    }

    #[test]
    fn authority_endpoint_rejects_zero_port() {
        assert!(AuthorityEndpoint::new(auth("api.example.com"), 0).is_err());
        let ok = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert_eq!(ok.port(), 443);
        assert_eq!(ok.host(), "api.example.com");
        assert_eq!(ok.to_string(), "api.example.com:443");
    }

    #[test]
    fn connect_policy_authorises_allowed_target() {
        let p = ConnectPolicy {
            allowed: vec![AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok")],
        };
        let target = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert!(p.authorize(&target).is_ok());
    }

    #[test]
    fn connect_policy_rejects_unauthorised_target() {
        let p = ConnectPolicy {
            allowed: vec![AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok")],
        };
        // Host not allowed.
        let other_host = AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("ok");
        let err = p.authorize(&other_host).unwrap_err();
        assert_eq!(
            err,
            ConnectError::TunnelNotAllowed("attacker.example.net:443".into())
        );
        // Same host, wrong port.
        let wrong_port = AuthorityEndpoint::new(auth("api.example.com"), 8443).expect("ok");
        assert!(p.authorize(&wrong_port).is_err());
    }

    #[test]
    fn connect_policy_rejects_empty_policy() {
        let p = ConnectPolicy::default();
        assert!(p.is_empty());
        let target = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert!(p.authorize(&target).is_err());
    }

    #[test]
    fn authorize_redirect_passes_for_same_origin() {
        let a = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        let b = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert!(authorize_redirect(&a, &b).is_ok());
    }

    #[test]
    fn authorize_redirect_denies_cross_origin() {
        let a = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        let b = AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("ok");
        let err = authorize_redirect(&a, &b).unwrap_err();
        match err {
            RedirectError::CrossOrigin { from, to } => {
                assert_eq!(from, "api.example.com:443");
                assert_eq!(to, "attacker.example.net:443");
            }
        }
    }

    #[test]
    fn authorize_redirect_denies_cross_port() {
        let a = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        let b = AuthorityEndpoint::new(auth("api.example.com"), 8443).expect("ok");
        assert!(authorize_redirect(&a, &b).is_err());
    }

    #[test]
    fn openssl_injector_writes_pem_and_returns_binding() {
        let tmp = std::env::temp_dir().join(format!("asv-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let ca = SessionCa::new("sess-inject", 7, DEFAULT_SESSION_CA_TTL);
        let binding = OpenSslEnvInjector.inject(&ca, &tmp).expect("inject OK");
        assert_eq!(binding.name, "openssl");
        assert_eq!(binding.env_var, "SSL_CERT_FILE");
        assert!(binding.env_value.exists());
        let written = std::fs::read(&binding.env_value).expect("read");
        assert_eq!(written, ca.root_der);
        let _ = std::fs::remove_file(&binding.env_value);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn openssl_injector_rejects_empty_ca() {
        let tmp = std::env::temp_dir().join("asv-tls-empty-test");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let mut ca = SessionCa::new("sess-empty", 0, DEFAULT_SESSION_CA_TTL);
        ca.root_der.clear();
        let err = OpenSslEnvInjector.inject(&ca, &tmp).unwrap_err();
        assert!(matches!(err, InjectError::EmptyCa(_)));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn bridge_handle_connect_delegates_to_policy() {
        let p = ConnectPolicy {
            allowed: vec![AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok")],
        };
        let bridge = Bridge::new(p);
        let target = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert!(bridge.handle_connect(&target).is_ok());
        let denied = AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("ok");
        assert!(bridge.handle_connect(&denied).is_err());
        assert_eq!(bridge.allowed_count(), 1);
    }

    #[test]
    fn bridge_handle_redirect_delegates_to_authorize() {
        let p = ConnectPolicy::default();
        let bridge = Bridge::new(p);
        let a = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        let b = AuthorityEndpoint::new(auth("api.example.com"), 443).expect("ok");
        assert!(bridge.handle_redirect(&a, &b).is_ok());
        let cross = AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("ok");
        assert!(bridge.handle_redirect(&a, &cross).is_err());
    }

    fn leaf_ca() -> SessionCa {
        SessionCa::new("sess-leaf", 7, Duration::from_secs(3600))
    }

    #[test]
    fn issued_leaf_is_bound_to_the_requested_host() {
        let ca = leaf_ca();
        let leaf = issue_leaf(&ca, "api.example.com", Instant::now()).expect("issuance");
        assert_eq!(leaf.session_id, "sess-leaf");
        assert_eq!(leaf.host, "api.example.com");
        assert!(!leaf.leaf_der.is_empty());
        assert!(leaf
            .verify_host_at("api.example.com", leaf.issued_at)
            .is_ok());
    }

    #[test]
    fn leaf_for_one_host_does_not_validate_a_sibling() {
        // The adversarial case that per-host issuance exists to prevent: a
        // session authorized for a public API must not gain a leaf for an
        // internal host in the same zone. Suffix and prefix neighbours both
        // have to be refused, not just unrelated hosts.
        let ca = leaf_ca();
        let leaf = issue_leaf(&ca, "api.example.com", Instant::now()).expect("issuance");
        for other in [
            "internal.example.com",
            "example.com",
            "api.example.com.evil.net",
            "API.example.com",
            "api.example.co",
        ] {
            assert!(
                leaf.verify_host_at(other, leaf.issued_at).is_err(),
                "leaf for api.example.com must not validate {other}"
            );
        }
    }

    #[test]
    fn leaf_der_differs_per_host_and_per_session() {
        let ca = leaf_ca();
        let a = issue_leaf(&ca, "api.example.com", Instant::now()).expect("a");
        let b = issue_leaf(&ca, "internal.example.com", Instant::now()).expect("b");
        assert_ne!(
            a.leaf_der, b.leaf_der,
            "distinct hosts must not share a leaf"
        );

        let other_session = SessionCa::new("sess-other", 7, Duration::from_secs(3600));
        let c = issue_leaf(&other_session, "api.example.com", Instant::now()).expect("c");
        assert_ne!(
            a.leaf_der, c.leaf_der,
            "the same host in a different session must not share a leaf"
        );
    }

    #[test]
    fn issuance_fails_once_the_ca_has_expired() {
        let ca = SessionCa::new("sess-old", 3, Duration::from_secs(1));
        let later = ca.issued_at + Duration::from_secs(2);
        assert!(ca.is_expired(later), "precondition: the CA must be expired");
        assert_eq!(
            issue_leaf(&ca, "api.example.com", later).unwrap_err(),
            LeafError::CaExpired("sess-old".to_string())
        );
    }

    #[test]
    fn leaf_never_outlives_its_issuer() {
        let ca = SessionCa::new("sess-ttl", 5, Duration::from_secs(100));
        let midway = ca.issued_at + Duration::from_secs(40);
        let leaf = issue_leaf(&ca, "api.example.com", midway).expect("issuance");
        // 40s of the CA's 100s are already spent, so the leaf has 60s left.
        assert_eq!(leaf.ttl, Duration::from_secs(60));
        // The leaf expires exactly when the CA does, never after.
        assert!(!leaf.is_expired(ca.issued_at + Duration::from_secs(99)));
        assert!(leaf.is_expired(ca.issued_at + Duration::from_secs(100)));
    }

    #[test]
    fn issuance_fails_closed_without_signing_material() {
        let mut ca = leaf_ca();
        ca.intermediate_der.clear();
        assert_eq!(
            issue_leaf(&ca, "api.example.com", Instant::now()).unwrap_err(),
            LeafError::NoSigner("sess-leaf".to_string())
        );
    }

    #[test]
    fn issuance_refuses_an_empty_host() {
        let ca = leaf_ca();
        assert!(issue_leaf(&ca, "", Instant::now()).is_err());
    }

    // ─── Fail-closed edges, each established red before the fix ───

    #[test]
    fn verify_host_at_rejects_an_expired_leaf() {
        let ca = leaf_ca();
        let leaf = issue_leaf(&ca, "api.example.com", Instant::now()).expect("issuance");
        let after = leaf.issued_at + leaf.ttl;
        assert!(
            leaf.is_expired(after),
            "precondition: the leaf must be expired at {after:?}"
        );
        assert_eq!(
            leaf.verify_host_at("api.example.com", after).unwrap_err(),
            LeafError::LeafExpired("api.example.com".to_string())
        );
    }

    #[test]
    fn issuance_fails_closed_without_a_root() {
        let mut ca = leaf_ca();
        ca.root_der.clear();
        assert_eq!(
            issue_leaf(&ca, "api.example.com", Instant::now()).unwrap_err(),
            LeafError::NoRoot("sess-leaf".to_string())
        );
    }

    #[test]
    fn issuance_refuses_a_malformed_host() {
        let ca = leaf_ca();
        // Every one of these is a spelling `Authority::canonicalize`
        // rejects. A leaf bound to any of them could never be matched by a
        // canonical allowlist: a certificate that authorises nothing while
        // looking like it authorises something.
        for bad in [
            "api.example.com:443",
            " api.example.com",
            "api.example.com ",
            "api example.com",
            "api.example.com@evil.net",
            "api.example.com%2e",
            "[::1]",
            "localhost",
        ] {
            assert!(
                matches!(
                    issue_leaf(&ca, bad, Instant::now()),
                    Err(LeafError::InvalidHost(_))
                ),
                "issue_leaf must reject the malformed host {bad:?}"
            );
        }
    }

    #[test]
    fn issuance_canonicalises_the_host() {
        let ca = leaf_ca();
        let upper = issue_leaf(&ca, "API.Example.COM", Instant::now()).expect("issuance");
        let lower = issue_leaf(&ca, "api.example.com", Instant::now()).expect("issuance");
        assert_eq!(upper.host, "api.example.com");
        // One host, one *name*. The DERs legitimately differ now that leaves
        // carry real keys: two issuances are two certificates, which is what a
        // CA is for. What must not differ is the name they assert, or the
        // session would be able to present a leaf for a spelling the
        // allowlist never named. The check is therefore on the SAN, not the
        // bytes, and `leaf_for_one_host_does_not_validate_a_sibling` covers
        // the refusal direction.
        assert!(upper
            .verify_host_at(lower.host.as_str(), upper.issued_at)
            .is_ok());
        assert!(lower
            .verify_host_at(upper.host.as_str(), lower.issued_at)
            .is_ok());
    }

    #[test]
    fn host_mismatch_reports_a_host_not_a_session_id() {
        let ca = leaf_ca();
        let leaf = issue_leaf(&ca, "api.example.com", Instant::now()).expect("issuance");
        match leaf
            .verify_host_at("internal.example.com", leaf.issued_at)
            .unwrap_err()
        {
            LeafError::HostMismatch { bound, .. } => assert_ne!(
                bound, ca.session_id,
                "HostMismatch.bound is documented as a host, not a session id"
            ),
            other => panic!("expected HostMismatch, got {other:?}"),
        }
    }
}

/// ADR-0019's proof resolution. These pin what a CONNECT client can prove
/// and, just as importantly, what it cannot.
#[cfg(test)]
mod proof_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Stands in for the broker: it knows which key belongs to which
    /// session, and checks the signature against the **registered** key
    /// rather than against the blob the client presented.
    struct FakeProofs {
        registered: Vec<(AgentSessionId, Vec<u8>)>,
    }

    impl SessionProofs for FakeProofs {
        fn resolve(
            &self,
            presented_key: &[u8],
            nonce: &[u8],
            signature: &[u8],
        ) -> Option<AgentSessionId> {
            self.registered
                .iter()
                .find(|(_, key)| {
                    key.len() == presented_key.len()
                        && bool::from(subtle::ConstantTimeEq::ct_eq(key.as_slice(), presented_key))
                })
                .and_then(|(session, key)| {
                    asv_ssh_agent::verify_proof(key, nonce, signature).then_some(*session)
                })
        }
    }

    fn endpoint(host: &str, port: u16) -> AuthorityEndpoint {
        AuthorityEndpoint::new(Authority::canonicalize(host).expect("authority"), port)
            .expect("endpoint")
    }

    fn encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn head_with(proof: Option<&str>, host: &str, port: u16) -> String {
        let mut head = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(p) = proof {
            head.push_str(&format!("{SESSION_PROOF_HEADER}: {p}\r\n"));
        }
        head.push_str("\r\n");
        head
    }

    /// A registered session, its key and its public blob.
    fn fixture() -> (AgentSessionId, SigningKey, Vec<u8>, FakeProofs) {
        let key = SigningKey::from_bytes(&[21u8; 32]);
        let blob = public_key_blob_for(&key);
        let session = AgentSessionId::new();
        let proofs = FakeProofs {
            registered: vec![(session, blob.clone())],
        };
        (session, key, blob, proofs)
    }

    fn public_key_blob_for(key: &SigningKey) -> Vec<u8> {
        asv_ssh_agent::public_key_blob(&key.verifying_key())
    }

    #[test]
    fn a_proof_over_the_destination_resolves_to_its_session() {
        let (session, _key, blob, proofs) = fixture();
        let target = endpoint("asv.test", 443);
        let nonce = proof_nonce(&blob, &target);
        let signature = _key.sign(&nonce).to_bytes();
        assert_eq!(
            proofs.resolve(&blob, &nonce, &signature),
            Some(session),
            "a valid proof did not resolve"
        );
    }

    #[test]
    fn a_proof_for_one_destination_does_not_resolve_against_another() {
        let (_session, key, blob, proofs) = fixture();
        let honest = endpoint("asv.test", 443);
        let attacker = endpoint("evil.example", 443);
        let nonce = proof_nonce(&blob, &honest);
        let signature = key.sign(&nonce).to_bytes();
        assert_eq!(
            proofs.resolve(&blob, &proof_nonce(&blob, &attacker), &signature),
            None,
            "a proof captured for one host verified against another"
        );
    }

    #[test]
    fn a_proof_made_by_a_key_the_broker_never_registered_does_not_resolve() {
        let (_session, _key, blob, proofs) = fixture();
        let other = SigningKey::from_bytes(&[22u8; 32]);
        let target = endpoint("asv.test", 443);
        let nonce = proof_nonce(&blob, &target);
        let signature = other.sign(&nonce).to_bytes();
        assert_eq!(
            proofs.resolve(&blob, &nonce, &signature),
            None,
            "a stranger's signature resolved against a registered blob"
        );
    }

    /// The attack this whole design exists to stop: an attacker presents
    /// *their own* key and signs with *their own* private key. Nothing they
    /// send is malformed, and the signature is perfectly valid -- it is
    /// just valid for a key the broker never registered.
    ///
    /// This case was missing, and two falsification attempts found it. The
    /// earlier tests presented the *registered* blob with a foreign
    /// signature, which fails for a different reason. Selecting the session
    /// by verifying against the presented key instead of matching the
    /// registered one left all seven of them green -- and so did removing
    /// the match, because the second check against the registered key was
    /// doing the work. Only with both gone does this one fail.
    #[test]
    fn a_stranger_presenting_their_own_key_and_their_own_signature_is_refused() {
        let (session, _key, blob, proofs) = fixture();
        let attacker = SigningKey::from_bytes(&[77u8; 32]);
        let their_blob = public_key_blob_for(&attacker);
        let target = endpoint("asv.test", 443);
        let nonce = proof_nonce(&their_blob, &target);
        let signature = attacker.sign(&nonce).to_bytes();
        assert_ne!(their_blob, blob, "the fixture keys collided");
        assert_eq!(
            proofs.resolve(&their_blob, &nonce, &signature),
            None,
            "a stranger's own key resolved to session {session}"
        );
    }

    #[test]
    fn an_absent_header_means_no_proof_rather_than_an_error() {
        let head = head_with(None, "asv.test", 443);
        assert_eq!(parse_session_proof(&head), None);
    }

    #[test]
    fn a_malformed_proof_header_is_refused_rather_than_guessed() {
        for bad in ["not-base64.not-base64", "!!!.###", "onlyonepart", "AAAA=."] {
            let head = head_with(Some(bad), "asv.test", 443);
            assert_eq!(
                parse_session_proof(&head),
                None,
                "a malformed proof parsed: {bad:?}"
            );
        }
    }

    #[test]
    fn the_header_is_matched_case_insensitively_like_every_http_header() {
        let (session, key, blob, proofs) = fixture();
        let target = endpoint("asv.test", 443);
        let nonce = proof_nonce(&blob, &target);
        let signature = key.sign(&nonce).to_bytes();
        let proof = format!("{}.{}", encode(&blob), encode(&signature));
        let head = format!("CONNECT asv.test:443 HTTP/1.1\r\nX-ASV-Session-Proof: {proof}\r\n\r\n");
        let parsed = parse_session_proof(&head).expect("a case-variant header parsed");
        assert_eq!(
            proofs.resolve(&parsed.key, &nonce, &parsed.signature),
            Some(session)
        );
    }

    #[test]
    fn the_nonce_differs_per_destination_and_per_key() {
        let a = endpoint("asv.test", 443);
        let b = endpoint("asv.test", 8443);
        assert_ne!(proof_nonce(b"k", &a), proof_nonce(b"k", &b));
        assert_ne!(proof_nonce(b"k", &a), proof_nonce(b"kk", &a));
        assert_eq!(proof_nonce(b"k", &a), proof_nonce(b"k", &a));
    }
}

/// The substitution itself: a surrogate in a request becomes the real
/// credential on the way upstream, and the client never sees it.
#[cfg(test)]
mod substitution_tests {
    use super::*;

    const REAL: &[u8] = b"ASV-REAL-CANARY-4d7e2a91-must-reach-upstream";
    const SURROGATE: &str = "asv_gh_9f2c7d10";

    fn request_with(token: &str) -> Vec<u8> {
        format!(
            "GET /repos/o/r/issues HTTP/1.1\r\nHost: api.github.test\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\n\r\n"
        )
        .into_bytes()
    }

    /// A port that hands out `REAL` for exactly `mine`, and refuses for
    /// every other session — the way `redeem_for` behaves.
    struct Port {
        mine: AgentSessionId,
    }

    impl CredentialSubstituter for Port {
        fn substitute(
            &mut self,
            surrogate: &str,
            session: AgentSessionId,
            sink: &mut dyn SecretSink,
        ) -> Result<Substituted, SubstitutionError> {
            if surrogate != SURROGATE {
                return Err(SubstitutionError::Refused);
            }
            if session != self.mine {
                // The refusal a token from another session gets.
                return Err(SubstitutionError::Refused);
            }
            sink.accept(REAL)
                .map_err(|e| SubstitutionError::Lend(e.to_string()))?;
            Ok(Substituted { family: "github" })
        }
    }

    /// Collects what the port lends, and never keeps the borrow.
    struct Collect(Vec<u8>);
    impl SecretSink for Collect {
        fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
            self.0.extend_from_slice(secret);
            Ok(())
        }
    }

    #[test]
    fn the_bearer_token_is_read_out_of_the_request() {
        assert_eq!(
            bearer_token(&request_with(SURROGATE)).as_deref(),
            Some(SURROGATE)
        );
        assert!(bearer_token(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn the_upstream_request_carries_the_real_credential_and_not_the_surrogate() {
        let session = AgentSessionId::new();
        let mut port = Port { mine: session };
        let original = request_with(SURROGATE);
        let token = bearer_token(&original).expect("a bearer token");

        let mut sink = Collect(Vec::new());
        port.substitute(&token, session, &mut sink)
            .expect("substitution");

        let upstream = replace_bearer_token(&original, std::str::from_utf8(&sink.0).unwrap())
            .expect("rewrite");
        let text = String::from_utf8(upstream).expect("utf-8 request");

        assert!(text.contains(std::str::from_utf8(REAL).unwrap()));
        assert!(
            !text.contains(SURROGATE),
            "the surrogate was forwarded upstream: {text}"
        );
        // Everything that is not the token survives byte for byte.
        assert!(text.starts_with("GET /repos/o/r/issues HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.github.test\r\n"));
        assert!(text.contains("Accept: application/json\r\n"));
    }

    #[test]
    fn a_surrogate_from_another_session_is_still_refused() {
        let mine = AgentSessionId::new();
        let theirs = AgentSessionId::new();
        let mut port = Port { mine };
        let mut sink = Collect(Vec::new());
        let outcome = port.substitute(SURROGATE, theirs, &mut sink);
        assert!(
            matches!(outcome, Err(SubstitutionError::Refused)),
            "a token from another session was redeemed: {outcome:?}"
        );
        assert!(
            sink.0.is_empty(),
            "a refused substitution still lent the credential"
        );
    }

    #[test]
    fn a_request_with_no_authorization_header_is_refused_rather_than_guessed() {
        let bare = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(bearer_token(bare).is_none());
        assert!(matches!(
            replace_bearer_token(bare, "anything"),
            Err(SubstitutionError::NoCredential)
        ));
    }

    #[test]
    fn the_refusal_says_the_same_thing_whatever_was_wrong() {
        // The caller must not be able to tell "unknown token" from "wrong
        // session", because that is the difference between a client that
        // retries and a client that learns it does not own the credential.
        let mine = AgentSessionId::new();
        let mut port = Port { mine };
        let mut sink = Collect(Vec::new());
        let unknown = port.substitute("asv_gh_deadbeef", mine, &mut sink);
        let wrong_session = port.substitute(SURROGATE, AgentSessionId::new(), &mut sink);
        assert_eq!(unknown, wrong_session);
    }
}
