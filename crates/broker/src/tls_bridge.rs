//! M9 — Transparent TLS bridge (prototype pass).
//!
//! The full TLS termination runtime is in the M9-runtime follow-up.
//! This module owns the data types and the threat-control dispatchers
//! that the runtime will call:
//!
//! - `SessionCa` — per-session CA shape (root + intermediate DER).
//! - `ConnectPolicy` / `authorize_connect` — CONNECT allow-list.
//! - `authorize_redirect` — cross-origin redirect denial.
//! - `TrustInjector` trait + `OpenSslEnvInjector` — trust-injection
//!   adapter for OpenSSL/libcurl/Node.js-trust-store-legacy.
//! - `Bridge` — the dispatcher skeleton that the runtime follows.
//!
//! Authoritative source:
//!   `agent-secretless-vault-spec/docs/06-TRANSPARENT-BRIDGE-EBPF.md`
//!   sections 5, 6 and 7.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use asv_domain::Authority;

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

/// Errors that the bridge dispatcher returns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// CONNECT tunnel rejected.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Redirect rejected.
    #[error(transparent)]
    Redirect(#[from] RedirectError),
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

/// The per-session CA. M9-prototype only stores the DER bytes; the
/// runtime follow-up wires `rcgen::CertificateParams::new` with OsRng.
#[derive(Debug, Clone)]
pub struct SessionCa {
    /// The session this CA belongs to.
    pub session_id: String,
    /// DER-encoded root certificate.
    pub root_der: Vec<u8>,
    /// DER-encoded intermediate certificate.
    pub intermediate_der: Vec<u8>,
    /// When the CA was generated.
    pub issued_at: Instant,
    /// How long the CA is valid for.
    pub ttl: Duration,
}

impl SessionCa {
    /// Construct a fresh CA. The `session_id` is opaque; the broker uses
    /// its existing session identifier type. The `seed` is mixed into the
    /// root/intermediate DER generation so unit tests are reproducible
    /// while the runtime follow-up uses `OsRng`.
    ///
    /// The prototype does NOT generate real x509 material; it emits
    /// `Vec<u8>` payloads that contain the session id, the seed, and a
    /// header byte. The runtime follow-up replaces the body with
    /// `rcgen::Certificate::generate_self_signed` + a sibling
    /// intermediate signed by the root.
    pub fn new(session_id: impl Into<String>, seed: u64, ttl: Duration) -> Self {
        let id = session_id.into();
        let issued_at = Instant::now();
        // Stable, content-addressed payload. The runtime replaces this
        // with a real DER. The structural claim is that root_der and
        // intermediate_der are non-empty and distinct.
        let root_der = synth_ca_der(&id, seed, ROLE_ROOT);
        let intermediate_der = synth_ca_der(&id, seed, ROLE_INTERMEDIATE);
        Self {
            session_id: id,
            root_der,
            intermediate_der,
            issued_at,
            ttl,
        }
    }

    /// True if the CA is past its TTL.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.ttl
    }
}

const ROLE_ROOT: u8 = 0x01;
const ROLE_INTERMEDIATE: u8 = 0x02;

fn synth_ca_der(session_id: &str, seed: u64, role: u8) -> Vec<u8> {
    // The structural DER is a hash of (session_id, seed, role). It is
    // not a real x509 certificate; the M9-runtime follow-up replaces
    // this with rcgen output. The point is that the data type exists,
    // the bytes are non-empty, and the two halves are distinct.
    use std::hash::{Hash, Hasher};
    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    session_id.hash(&mut h1);
    seed.hash(&mut h1);
    role.hash(&mut h1);
    let h1 = h1.finish();
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    role.hash(&mut h2);
    seed.hash(&mut h2);
    session_id.hash(&mut h2);
    let h2 = h2.finish();
    let mut out = vec![role];
    out.extend_from_slice(&h1.to_le_bytes());
    out.extend_from_slice(&h2.to_le_bytes());
    out
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
    fn inject(
        &self,
        ca: &SessionCa,
        session_dir: &Path,
    ) -> Result<TrustBinding, InjectError>;
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

    fn inject(
        &self,
        ca: &SessionCa,
        session_dir: &Path,
    ) -> Result<TrustBinding, InjectError> {
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

/// The bridge dispatcher. M9-prototype is a single struct that the
/// runtime follow-up replaces with the `rustls::Server` + `hyper`
/// acceptor.
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
        let tmp = std::env::temp_dir().join(format!(
            "asv-tls-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let ca = SessionCa::new("sess-inject", 7, DEFAULT_SESSION_CA_TTL);
        let binding = OpenSslEnvInjector
            .inject(&ca, &tmp)
            .expect("inject OK");
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
}