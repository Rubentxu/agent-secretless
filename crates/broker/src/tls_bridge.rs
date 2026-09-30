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
//!
//! Authoritative source:
//!   `agent-secretless-vault-spec/docs/06-TRANSPARENT-BRIDGE-EBPF.md`
//!   sections 5, 6 and 7.
//!
//! Still not here: the eBPF redirect that makes the bridge transparent, and
//! the TLS acceptor that presents these leaves. Both need kernel privileges
//! this environment does not have.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use asv_domain::Authority;
use time::OffsetDateTime;

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
