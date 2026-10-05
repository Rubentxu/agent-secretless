//! The broker's own client identity, and the client configuration it yields.
//!
//! [`issue_client_certificate`] is the half of R2.E where the *agent* holds
//! the key: the agent has material
//! somewhere ASV cannot reach — a keychain, an HSM, a checkout — and asks for a
//! certificate naming an identity the broker is willing to vouch for. This is
//! the other half. The key lives here, inside the process, and the destination
//! authenticates the broker rather than something the agent is carrying.
//!
//! # The two halves are not alternatives
//!
//! They answer different questions, and the choice between them is a fact
//! about the caller rather than a preference. An agent with a hardware-held
//! key gets strategy 4 of the ladder, proof of possession. An agent with
//! nothing gets strategy 5, a signer or proxy that holds the key instead of
//! projecting it — which is the strongest posture available when the caller
//! has no key of its own, and the reason this is a provider rather than a
//! convenience.
//!
//! Both go through the same issuer, on purpose. This module does not call
//! `signed_by` itself; it builds a request for the key it just generated and
//! hands it to [`issue_client_certificate`], so there is exactly one place in
//! the broker where a certificate's identity is decided. A second path from a
//! key to a signed certificate is the overlap the architecture rules forbid,
//! and the reuse also makes the two halves test each other: a bug in the
//! issuer is a bug in both.
//!
//! # Why there is no accessor for the key
//!
//! `rustls::ClientConfig::builder().with_client_auth_cert` wants a
//! `PrivateKeyDer`, so the obvious shape is a `key()` getter and a caller that
//! passes it to something. That shape is the defect. Once a getter exists,
//! every call site in the repository is a place the key can be logged,
//! serialised, written to a temporary file or put in a DTO, and nothing in
//! the type says which of them did it.
//!
//! So there is no getter. [`ClientIdentity::client_config`] takes the roots
//! and returns a finished configuration, and the key is read exactly once,
//! inside this module. The property is then structural: the key has no path
//! out of the struct. That is a stronger statement than "no caller uses it
//! today", and it is what makes the lifetime meaningful — the broker drops the
//! identity when the session ends and the material goes with it.
//!
//! What this does **not** claim: the key is in process memory, in the same
//! address space as the vault it guards. Isolation from the agent is real, in
//! the sense that the agent never receives it and so cannot replay it
//! elsewhere. Isolation from a broker compromise is not, and is not claimed.
//! That limit is the one `SessionCa` already lives under, and naming it here
//! is more useful than letting the type look stronger than the process is.
//!
//! # Why the identity is bound to a destination
//!
//! A client certificate presented to the wrong host is the identity handed to
//! whoever answered there, and "the destination that asked for one" is not a
//! safe rule: a server that requests a client certificate is exactly what an
//! attacker wants to impersonate in order to receive one. The binding is
//! therefore fixed at issue time from the same [`asv_domain::Authority`] that
//! `issue_leaf` uses, and compared exactly — never by suffix, never on
//! request.

use std::fmt;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};

use super::grant::ClientGrant;
use super::issue::{ClientCertError, ClientCsr, issue_client_certificate};
use crate::tls_bridge::SessionCa;

/// A client certificate and the key that matches it, held in the broker.
///
/// Deliberately not `Clone`. An `Arc` of this is already cheap to share, so a
/// `Clone` implementation would exist for exactly one purpose: a second copy
/// of a private key somewhere the first copy's lifetime does not govern.
pub struct ClientIdentity {
    identity: String,
    /// The one destination this identity may be presented to.
    bound_host: String,
    /// Leaf first, then the intermediate.
    ///
    /// The order is load-bearing, not cosmetic: a peer that trusts only the
    /// root has to build the path itself and can only do it from what the
    /// client sends, so a leaf alone is a certificate no such peer can
    /// validate.
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    issued_at: Instant,
    ttl: Duration,
}

impl ClientIdentity {
    /// Mint a client identity for `grant`, presentable only to `host`.
    ///
    /// The key is generated here and is not an argument anywhere, which is
    /// what keeps the one operation that could leak it inside the one place
    /// with a reason to hold it.
    pub fn issue(
        ca: &SessionCa,
        grant: &ClientGrant,
        host: &str,
        now: Instant,
    ) -> Result<Self, ClientCertError> {
        let bound_host = asv_domain::Authority::canonicalize(host)
            .map_err(|e| ClientCertError::Unusable(format!("{host} is not a destination: {e}")))?
            .as_str()
            .to_string();

        let key = rcgen::KeyPair::generate().expect("rcgen client key");
        // A request for the key that was just generated, handed straight to
        // the issuer, which keeps only its public half. Its subject and SAN
        // carry the granted name rather than a description of what this
        // module wants, because the issuer discards them either way and a
        // request that described the broker's intentions would read as though
        // they were honoured.
        let identity = grant.identity().as_str().to_string();
        let mut params = rcgen::CertificateParams::new(vec![identity.clone()]).map_err(|e| {
            ClientCertError::Unusable(format!("the granted name is not a SAN: {e}"))
        })?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, identity.clone());
        let request = params
            .serialize_request(&key)
            .map_err(|e| ClientCertError::Unusable(format!("the request does not serialize: {e}")))?;
        let csr = ClientCsr::from_der(request.der().to_vec());

        let issued = issue_client_certificate(ca, grant, &csr, now)?;

        // PKCS#8 DER, never PEM. A PEM here would be a private key in text in
        // a heap buffer this process could log, and it would buy nothing:
        // `with_client_auth_cert` takes the DER form.
        let key_der = key.serialize_der();

        Ok(Self {
            identity: issued.identity().to_string(),
            bound_host,
            chain: vec![
                CertificateDer::from(issued.der().to_vec()),
                CertificateDer::from(ca.intermediate_der.clone()),
            ],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            issued_at: now,
            ttl: issued.granted_ttl(),
        })
    }

    /// The identity the destination will see.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The one destination this identity was issued for.
    pub fn bound_host(&self) -> &str {
        &self.bound_host
    }

    /// Whether this identity may be presented to `host`.
    ///
    /// A method rather than a public field so that a caller cannot read
    /// `bound_host` and then do its own, looser, comparison.
    pub fn presents_to(&self, host: &str) -> bool {
        self.bound_host == host
    }

    /// A client configuration that presents this identity to a destination
    /// trusted against `roots`.
    ///
    /// The only way out of this type. A caller that wants to reach a service
    /// with this identity asks for a configuration; it never handles the key.
    pub fn client_config(&self, roots: &RootCertStore) -> Result<ClientConfig, ClientCertError> {
        ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|e| {
                ClientCertError::Unusable(format!(
                    "the issued identity cannot be offered to a destination: {e}"
                ))
            })
    }

    /// True once the certificate is past the lifetime it was granted.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.ttl
    }

    /// The certificate chain as DER, for a peer that is not `rustls`.
    ///
    /// Public material only, and the reason it exists is a reader that wants
    /// to know what was signed. The key has no equivalent, on purpose.
    pub fn chain_der(&self) -> Vec<Vec<u8>> {
        self.chain.iter().map(|c| c.to_vec()).collect()
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written for the same reason `LeafCertificate` and `SessionCa`
        // are: a derived `Debug` would print a private key. The chain is
        // public, but a certificate in a log line is a correlation handle for
        // an identity a destination is about to trust, so only the shape is
        // printed.
        f.debug_struct("ClientIdentity")
            .field("identity", &self.identity)
            .field("bound_host", &self.bound_host)
            .field("chain_len", &self.chain.len())
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}
