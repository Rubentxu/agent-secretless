//! CSR intake and issuance.
//!
//! Read this file with one question in mind: *which field of the request
//! reaches the signed certificate?* The answer should be exactly one — the
//! public key — and every other line here exists to make that answer hard to
//! change by accident.
//!
//! The sequence is deliberately ordered from cheapest-and-most-certain to
//! most-expensive-and-most-attacker-influenced: the CA's own fitness, then the
//! grant's lifetime, and only then the bytes the requester sent. A refusal
//! that costs nothing should be reached before a refusal that requires
//! parsing attacker-controlled ASN.1.

use std::fmt;
use std::time::{Duration, Instant};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateSigningRequestDer;
use time::OffsetDateTime;

use super::grant::{ClientGrant, MIN_CLIENT_CERT_TTL};
use super::super::SessionCa;

/// A certificate signing request: the public half of a key, and a request for
/// an identity to go with it.
///
/// There is no constructor that takes a private key, and no field that holds
/// one. That is the entire reason this type exists rather than passing `&[u8]`
/// around, and it is why the issuance path below never has a variable in
/// scope that could carry one.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCsr {
    der: CertificateSigningRequestDer<'static>,
}

impl ClientCsr {
    /// Read a request from DER bytes.
    ///
    /// Named to say what the encoding is, not to imply that the bytes are
    /// valid. Nothing is checked here beyond the length: a CSR that does not
    /// parse, or whose signature does not verify, is refused by
    /// [`issue_client_certificate`] rather than by a constructor, so that
    /// every refusal in this module happens in one place with one error type.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            der: CertificateSigningRequestDer::from(der.into()),
        }
    }

    /// Read a request from PEM text.
    ///
    /// PEM is what a real client sends, so refusing it would make the API
    /// honest and useless. This decodes the armour before the bytes reach the
    /// field above, because the field is a *DER* request and handing it
    /// base64 text would fail later with a parse error that names the wrong
    /// problem.
    ///
    /// Unlike [`ClientCsr::from_der`] this does report failure, because there
    /// is no wrapper type for "a PEM document that contains no request" — the
    /// decode is the whole of what this function does, and a caller that
    /// ignored the result would be holding an empty request.
    pub fn from_pem(pem: &str) -> Result<Self, ClientCertError> {
        let der =
            CertificateSigningRequestDer::from_pem_slice(pem.as_bytes()).map_err(|e| {
                ClientCertError::UnreadableCsr(format!("the PEM holds no certificate request: {e}"))
            })?;
        Ok(Self { der })
    }
}

impl fmt::Debug for ClientCsr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A CSR is not a secret — it carries a public key — but it is large,
        // binary, and entirely attacker-chosen, so the derived `Debug` would
        // be a log-injection vector with an attacker's text in it. Length is
        // the only part of it that means anything operationally.
        f.debug_struct("ClientCsr")
            .field("der_len", &self.der.len())
            .finish_non_exhaustive()
    }
}

/// A certificate this module minted, and the terms it was minted under.
///
/// The public key inside is the one the requester proved it holds. The private
/// half never entered the process, which is why this struct has no field for
/// it and why nothing downstream of issuance can ask for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedClientCert {
    identity: String,
    der: Vec<u8>,
    issued_at: Instant,
    ttl: Duration,
}

impl IssuedClientCert {
    /// The identity in the certificate's subject and SAN — the one the broker
    /// granted.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The DER-encoded certificate.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The lifetime actually granted.
    ///
    /// Not the lifetime that was asked for. Those differ whenever the CA had
    /// less life left than the grant, and a caller that assumed otherwise
    /// would hold a certificate it believed was long-lived.
    pub fn granted_ttl(&self) -> Duration {
        self.ttl
    }

    /// True if the certificate is past the lifetime it was granted.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.ttl
    }
}

/// Why a client certificate was not minted.
///
/// Every arm is a refusal. There is no variant that returns a certificate
/// with something adjusted, because "issued under reduced terms" and "issued"
/// are different outcomes and a caller cannot tell them apart if they are the
/// same one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientCertError {
    /// The session CA has aged out, so nothing may be signed under it.
    #[error("session CA for {0} is expired")]
    CaExpired(String),

    /// The CA carries no intermediate to sign with.
    #[error("session CA for {0} has no signing material")]
    NoSigner(String),

    /// The CA carries no root, so a leaf would chain to nothing.
    #[error("session CA for {0} has no root")]
    NoRoot(String),

    /// The grant's identity is not a name a certificate can carry.
    ///
    /// A wildcard is the motivating case, and it never reaches here as a
    /// special check: [`asv_domain::Authority`] has no representation for
    /// `*.example.com`, so a grant asking for one cannot be constructed. This
    /// arm exists for the canonicalizer's other refusals — userinfo, a port,
    /// percent-encoding, a non-ASCII label — and for the possibility that the
    /// accepted form widens later without this type being revisited.
    #[error("identity is not a name a client certificate can carry: {0}")]
    UnusableIdentity(String),

    /// The grant asked for less time than a certificate is worth issuing for.
    #[error("grant asked for {requested:?}, below the {minimum:?} floor")]
    GrantTtlTooShort {
        /// What the grant asked for.
        requested: Duration,
        /// The floor it was measured against.
        minimum: Duration,
    },

    /// The CA has too little life left to issue anything usable.
    #[error("session CA has {remaining:?} left, below the {minimum:?} floor")]
    CaNearlyExpired {
        /// What was left of the CA's own lifetime.
        remaining: Duration,
        /// The floor it was measured against.
        minimum: Duration,
    },

    /// The request is not a CSR this parser can read.
    #[error("the certificate signing request is unreadable: {0}")]
    UnreadableCsr(String),

    /// The request was read, but it did not verify against the public key it
    /// carries.
    ///
    /// A distinct arm from [`ClientCertError::UnreadableCsr`] because the two
    /// mean opposite things and only one of them is an attack: unreadable is
    /// garbage, unsigned-with-the-wrong-key is someone asking to have a key
    /// certified that they cannot prove they hold.
    #[error("the certificate signing request does not verify against its own key")]
    CsrSignatureInvalid,

    /// The issuer could not produce a certificate from material that parsed.
    #[error("the certificate could not be signed: {0}")]
    SigningFailed(String),

    /// Material this module signed itself could not be assembled into
    /// something a destination can be offered.
    ///
    /// Separate from [`ClientCertError::SigningFailed`] because the cause is
    /// on this side of the boundary rather than in a request: a chain whose
    /// key and certificate do not match is a broker that built something
    /// unusable, and reporting that as a bad request sends an operator looking
    /// at the wrong process.
    #[error("{0}")]
    Unusable(String),
}

/// Sign `csr`'s public key into a client certificate for the identity in
/// `grant`, under `ca`.
///
/// # What the requester controls
///
/// The public key, and nothing else. The subject, the SANs, the key usages and
/// the extended key usages in the request are read and dropped; the
/// certificate is built from [`ClientGrant`] alone. The private half of the
/// keypair is not present in any argument and cannot be, so a certificate
/// issued here is one the requester can use and nobody else can steal.
///
/// # What the broker controls
///
/// The identity, the ceiling on the lifetime, and the issuer. A request for a
/// year returns a certificate no longer-lived than the CA it chains to.
pub fn issue_client_certificate(
    ca: &SessionCa,
    grant: &ClientGrant,
    csr: &ClientCsr,
    now: Instant,
) -> Result<IssuedClientCert, ClientCertError> {
    // The CA's fitness, before anything the requester sent is looked at.
    if ca.is_expired(now) {
        return Err(ClientCertError::CaExpired(ca.session_id.clone()));
    }
    if ca.intermediate_der.is_empty() {
        return Err(ClientCertError::NoSigner(ca.session_id.clone()));
    }
    if ca.root_der.is_empty() {
        return Err(ClientCertError::NoRoot(ca.session_id.clone()));
    }

    // The lifetime, before the request is parsed. The CA's own remaining life
    // is the ceiling and is checked first, because a CA that is nearly done is
    // the case where the grant's request is irrelevant: no grant can be
    // honoured, whatever it asked for.
    let ca_remaining = ca
        .ttl
        .saturating_sub(now.saturating_duration_since(ca.issued_at));
    if ca_remaining < MIN_CLIENT_CERT_TTL {
        return Err(ClientCertError::CaNearlyExpired {
            remaining: ca_remaining,
            minimum: MIN_CLIENT_CERT_TTL,
        });
    }
    let requested = grant.requested_ttl();
    if requested < MIN_CLIENT_CERT_TTL {
        return Err(ClientCertError::GrantTtlTooShort {
            requested,
            minimum: MIN_CLIENT_CERT_TTL,
        });
    }
    // The granted lifetime is the smaller of the two. Not the CA's, because a
    // certificate that outlives its issuer is one no trust store can chain;
    // not the grant's, because the CA is the thing that stops existing first.
    let ttl = requested.min(ca_remaining);

    // The request. `from_der` parses the structure *and* verifies the
    // request's own signature, so a request whose SPKI was edited after
    // signing is refused here rather than certified.
    let parsed =
        rcgen::CertificateSigningRequestParams::from_der(&csr.der).map_err(|e| {
            // `rcgen` reports a signature failure and a structural failure
            // through one error type. The distinction is worth keeping because
            // only one of them is an attack, so it is recovered from the
            // message rather than flattened into "unreadable".
            if matches!(e, rcgen::Error::RingUnspecified) {
                ClientCertError::CsrSignatureInvalid
            } else {
                ClientCertError::UnreadableCsr(e.to_string())
            }
        })?;

    // **The line this module exists for.**
    //
    // `requested_identity` holds the subject, the SANs, the key usages and the
    // EKUs the requester asked for, all of them populated by the parser from
    // attacker-chosen extensions. Binding them into the certificate would make
    // this a CA for its own subscribers: one request can ask for
    // `*.internal`, for `CA:TRUE`, and for a `keyCertSign` usage, and a CA that
    // honours requests is a CA. Only `public_key` is carried forward.
    //
    // The field is *named* rather than discarded as `_`, and handed to
    // [`certificate_params`], so that the decision not to use it is a line a
    // reviewer can point at and a falsification campaign can attack with a
    // single substitution. Discarding it at the destructuring would be equally
    // correct and one keystroke harder to see.
    let rcgen::CertificateSigningRequestParams {
        params: requested_identity,
        public_key,
    } = parsed;

    let identity = grant.identity().as_str().to_string();
    let params = certificate_params(&identity, ttl, &requested_identity)?;

    let certificate = rcgen::CertificateSigningRequestParams { params, public_key }
        .signed_by(&ca.intermediate_cert, &ca.intermediate_key)
        .map_err(|e| ClientCertError::SigningFailed(e.to_string()))?;

    Ok(IssuedClientCert {
        identity,
        der: certificate.der().to_vec(),
        issued_at: now,
        ttl,
    })
}

/// Build the parameter list for a client certificate.
///
/// `requested` is the requester's own opinion of who it is, in exactly the
/// shape that would make this a CA for its own subscribers. It is accepted
/// and not read, and that is the module's central refusal.
fn certificate_params(
    identity: &str,
    ttl: Duration,
    requested: &rcgen::CertificateParams,
) -> Result<rcgen::CertificateParams, ClientCertError> {
    let _ = requested;

    let not_before = OffsetDateTime::now_utc();
    let remaining = time::Duration::try_from(ttl)
        .map_err(|e| ClientCertError::SigningFailed(format!("lifetime {ttl:?}: {e}")))?;

    let mut params = rcgen::CertificateParams::new(vec![identity.to_string()])
        .map_err(|e| ClientCertError::SigningFailed(e.to_string()))?;
    // `ExplicitNoCa` writes `CA:FALSE` rather than omitting the extension. The
    // difference matters to a strict verifier, and omitting is the choice that
    // would let a future default flip this line to something permissive
    // without the certificate changing shape.
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    // Digital signature only. A client certificate authenticates; it does not
    // terminate a key exchange, so `keyEncipherment` would be a claim this
    // certificate has no use for, and `keyCertSign` is precisely the usage
    // that would let its holder issue certificates of their own.
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = not_before;
    params.not_after = not_before + remaining;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, identity.to_string());
    Ok(params)
}
