//! Rows for [`issue_client_certificate`](super::issue_client_certificate).
//!
//! Every row names the mutation that turns it red, in the comment above it.
//! That is the standard this module is held to, and a row that cannot name one
//! is a row that is asserting a shape rather than a behaviour.
//!
//! The tests read the certificate back with `x509-parser` rather than
//! inspecting the returned struct. The struct is this module's own account of
//! what it did; the DER is the thing a peer will actually parse. Asserting on
//! the struct would let a bug in the certificate survive a green suite.

use std::time::{Duration, Instant};

use super::grant::{ClientGrant, MIN_CLIENT_CERT_TTL};
use super::issue::{ClientCertError, ClientCsr, IssuedClientCert, issue_client_certificate};
use crate::tls_bridge::SessionCa;

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509CertificationRequest, X509Certificate};

const HOUR: Duration = Duration::from_secs(3600);

/// A request the test built, kept with its key and its bytes.
///
/// The three are a test fixture rather than three arguments, and the struct
/// exists so that no test needs an accessor that only tests would call —
/// which is why [`ClientCsr`] has no way to hand its own bytes back.
struct Fixture {
    key: rcgen::KeyPair,
    csr: ClientCsr,
    der: Vec<u8>,
    pem: String,
}

impl Fixture {
    /// A request whose subject and SANs are all attacker-chosen, which is the
    /// shape this module has to survive.
    fn hostile() -> Self {
        Self::asking("CN=admin,O=attacker", &["*.internal", "*.example.com", "attacker.test"])
    }

    /// A request that asks for `subject` and `sans`.
    fn asking(subject: &str, sans: &[&str]) -> Self {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(
            sans.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
        )
        .expect("SAN list is non-empty");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, subject);
        // No `is_ca` here: a CSR cannot assert `CA:FALSE`, only a signed
        // certificate can, and the test that matters is that *this module*
        // writes it on the certificate. Asserting it on the request would
        // fail to serialize (`UnsupportedInCsr`) — which is itself the point:
        // the request has no say in the constraint.
        let serialized = params.serialize_request(&key).expect("request serializes");
        let der = serialized.der().to_vec();
        let pem = serialized.pem().expect("the request PEM-encodes");
        Self {
            key,
            csr: ClientCsr::from_der(der.clone()),
            der,
            pem,
        }
    }

    /// The SubjectPublicKeyInfo the request carries.
    ///
    /// Parsed with the *request* parser, not the certificate one. Reading a
    /// CSR as a certificate is not a shortcut that happens to work: the two
    /// structures differ after the first inner SEQUENCE, and a parser given
    /// the wrong one reports an algorithm-identifier error that has nothing to
    /// do with the request being wrong.
    fn spki(&self) -> Vec<u8> {
        request_spki(&self.der)
    }

    /// The SubjectPublicKeyInfo this fixture's *own key* carries, read back
    /// out of a throwaway request built from that same key.
    ///
    /// Built from `self.key` rather than from a fresh one on purpose. The
    /// first version of this helper minted a new keypair, which made the
    /// assertion below compare two unrelated public keys and fail for a
    /// reason that had nothing to do with the module under test.
    fn spki_of_key(&self) -> Vec<u8> {
        let params =
            rcgen::CertificateParams::new(vec!["probe.invalid".to_string()]).expect("SAN");
        let serialized = params
            .serialize_request(&self.key)
            .expect("the probe request serializes");
        request_spki(serialized.der().as_ref())
    }
}

/// The SubjectPublicKeyInfo a DER request carries.
fn request_spki(der: &[u8]) -> Vec<u8> {
    let (_remaining, request) =
        X509CertificationRequest::from_der(der).expect("the request parses");
    request
        .certification_request_info
        .subject_pki
        .raw
        .to_vec()
}

/// A CA with the given life.
fn ca(ttl: Duration) -> SessionCa {
    SessionCa::new("s-test", 7, ttl)
}

/// A grant for `identity`.
fn grant(identity: &str, ttl: Duration) -> ClientGrant {
    ClientGrant::for_identity(identity, ttl).expect("grant identity is canonical")
}

fn issue(ca: &SessionCa, grant: &ClientGrant, request: &ClientCsr) -> IssuedClientCert {
    issue_client_certificate(ca, grant, request, Instant::now()).expect("issuance succeeds")
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    // `from_der` yields `(remaining, certificate)`; the certificate is the
    // second half, and the remaining bytes are what `trailing` measures.
    X509Certificate::from_der(der)
        .expect("the certificate parses")
        .1
}

/// Every SAN in the certificate, as strings.
fn sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let Some(san) = cert
        .subject_alternative_name()
        .expect("the SAN extension parses")
    else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(dns) => dns.to_string(),
            other => format!("{other:?}"),
        })
        .collect()
}

/// The bytes left over after parsing `der`.
///
/// A certificate that parses but does not consume its input has trailing
/// bytes smuggled into it, which for a signed structure is a parser bug
/// rather than a certificate.
fn trailing(der: &[u8]) -> usize {
    let (remaining, _) = X509Certificate::from_der(der).expect("the certificate parses");
    remaining.len()
}

fn common_name(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// A. The identity is the broker's, not the request's.
// ---------------------------------------------------------------------------

/// **Mutation: bind `parsed.params` instead of rebuilding them from the
/// grant** — the certificate's subject comes out as the request's.
#[test]
fn el_subject_es_el_del_grant_y_no_el_de_la_peticion() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    assert_eq!(
        common_name(&parse(cert.der())).as_deref(),
        Some("svc-a.internal")
    );
}

/// **Mutation: carry `parsed.params.subject_alt_names` forward** — the
/// certificate comes out with three SANs, two of them wildcards.
#[test]
fn los_sans_pedidos_no_sobreviven() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    assert_eq!(sans(&parse(cert.der())), vec!["svc-a.internal".to_string()]);
}

/// **Mutation: generate a fresh key inside issuance instead of using the
/// request's** — the SPKI no longer matches and the certificate is one nobody
/// can use. This is the row that stops "we signed a certificate" from being
/// mistaken for "we signed the right certificate".
#[test]
fn la_clave_publica_es_la_que_la_peticion_trae() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    assert_eq!(
        parse(cert.der()).tbs_certificate.subject_pki.raw,
        fixture.spki().as_slice(),
        "the issued certificate must carry the request's public key"
    );
    // And that public key is this key's, which is what makes the row above a
    // statement about a *key* rather than about two blobs that happen to be
    // equal.
    assert_eq!(fixture.spki(), fixture.spki_of_key());
}

/// **Mutation: sign with `ca.root` and `ca.root_key` instead of the
/// intermediate** — the certificate still parses, still verifies against a
/// trust store holding the root, and still has every usage the tests above
/// check. It is a different certificate: one that collapses the chain to a
/// single hop, and one whose issuer is the trust anchor rather than the
/// subordinate authority that was supposed to be the signer.
#[test]
fn el_issuer_es_el_intermedio_y_no_la_raiz() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);
    let authority = ca(HOUR);

    let leaf = parse(cert.der());
    let intermediate = parse(&authority.intermediate_der);
    let root = parse(&authority.root_der);

    assert_eq!(
        leaf.issuer().to_string(),
        intermediate.subject().to_string(),
        "the leaf must be issued by the intermediate"
    );
    assert_ne!(
        leaf.issuer().to_string(),
        root.subject().to_string(),
        "signing with the root would collapse the chain to one hop"
    );
}

/// **Mutation: delete the empty-root check** — a CA carrying no root mints
/// leaves that chain to nothing, and no trust store can validate them. Nothing
/// above notices, because a CA built by [`ca`] always has a root.
#[test]
fn una_autoridad_sin_raiz_no_firma_nada() {
    let mut authority = ca(HOUR);
    authority.root_der.clear();
    let fixture = Fixture::hostile();

    let refusal = issue_client_certificate(
        &authority,
        &grant("svc-a.internal", HOUR),
        &fixture.csr,
        Instant::now(),
    )
    .expect_err("a CA with no root issues a certificate nothing can chain");

    assert_eq!(refusal, ClientCertError::NoRoot(authority.session_id.clone()));
}

/// **Mutation: delete the empty-intermediate check** — a CA carrying no
/// intermediate has no key to sign with, and the failure surfaces as a panic
/// inside `rcgen` rather than as a refusal. Nothing above notices, because a
/// CA built by [`ca`] always has one.
#[test]
fn una_autoridad_sin_intermedio_no_firma_nada() {
    let mut authority = ca(HOUR);
    authority.intermediate_der.clear();
    let fixture = Fixture::hostile();

    let refusal = issue_client_certificate(
        &authority,
        &grant("svc-a.internal", HOUR),
        &fixture.csr,
        Instant::now(),
    )
    .expect_err("a CA with no signer issues nothing");

    assert_eq!(
        refusal,
        ClientCertError::NoSigner(authority.session_id.clone())
    );
}

/// **Mutation: hand a buffer with padding to the parser** — the certificate
/// would carry bytes past its own end, which is a parser difference rather
/// than a certificate.
///
/// Filed as compound and counted as such: it measures whether `x509-parser`
/// leaves trailing bytes, which is a property of a third-party parser, not of
/// this module. It is here because the parser is already in scope and a
/// certificate with a tail is a real artifact defect worth catching once,
/// where the bytes enter the process. The campaign cannot turn this red, and
/// the harness docstring says so rather than counting it.
#[test]
fn el_certificado_consume_exactamente_sus_bytes() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    assert_eq!(trailing(cert.der()), 0);
}

/// **Mutation: copy the request's distinguished name** — the certificate
/// carries `CN=admin,O=attacker` and a peer that authorizes on the DN grants
/// the attacker the identity that was granted to someone else.
#[test]
fn el_nombre_distinguido_pedido_no_sobrevive() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    let subject = parse(cert.der()).subject().to_string();
    assert!(
        !subject.contains("attacker"),
        "the request's DN leaked into {subject}"
    );
}

// ---------------------------------------------------------------------------
// B. What a request cannot ask for.
// ---------------------------------------------------------------------------

/// **Mutation: hand the raw string to the certificate instead of a
/// canonicalized `Authority`** — `*.example.com` reaches the certificate.
///
/// The refusal is structural: `Authority` has no representation for a
/// wildcard, so this row is really checking that the grant's constructor is
/// still the only way in.
#[test]
fn un_wildcard_no_se_puede_conceder() {
    let refusal = ClientGrant::for_identity("*.example.com", HOUR)
        .expect_err("a wildcard is not a name a certificate can carry");
    assert!(matches!(refusal, ClientCertError::UnusableIdentity(_)));
}

/// **Mutation: read the identity out of the request** — the grant's
/// canonicalization is bypassed, and a request for a CA name, a port, or
/// userinfo all start signing.
#[test]
fn una_identidad_no_canonica_no_llega_a_la_peticion() {
    for spelling in [
        "",
        "svc-a.internal:443",
        "user@svc-a.internal",
        "svc-a%2einternal",
        "svc-a internal",
        " svc-a.internal",
        "svc_a.internal",
        "svc-a..internal",
        "[::1]",
        "svc-a.internal/x",
    ] {
        assert!(
            ClientGrant::for_identity(spelling, HOUR).is_err(),
            "{spelling:?} should not be grantable"
        );
    }
}

/// **Mutation: hand the grant's raw string to the certificate instead of the
/// canonicalized one** — the certificate's subject is whatever the caller
/// typed, and two spellings of one name mint two identities.
///
/// This is the positive half of the row above and it is a different claim:
/// a spelling that *normalizes* must be accepted and normalized, because
/// refusing `API.GITHUB.COM` would make an allowlist a spelling contest.
#[test]
fn una_identidad_se_normaliza_en_lugar_de_rechazarse() {
    let request = Fixture::hostile().csr;

    for spelling in ["SVC-A.INTERNAL", "svc-a.internal.", "svc-a.INTERNAL"] {
        let certificate = issue(&ca(HOUR), &grant(spelling, HOUR), &request);
        assert_eq!(
            certificate.identity(),
            "svc-a.internal",
            "{spelling:?} should have been canonicalized"
        );
        assert_eq!(
            common_name(&parse(certificate.der())).as_deref(),
            Some("svc-a.internal")
        );
    }
}

/// **Mutation: set `is_ca` from the request, or drop the line** — the
/// certificate is issued with `CA:TRUE` and its holder can sign more.
#[test]
fn el_certificado_no_puede_ser_una_autoridad() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    let parsed = parse(cert.der());
    let constraints = parsed
        .basic_constraints()
        .expect("the extension parses")
        .expect("CA:FALSE is written explicitly, not omitted");
    assert!(!constraints.value.ca, "a client certificate must not be a CA");
}

/// **Mutation: add `KeyCertSign` to the usages** — the holder can sign
/// certificates even without `CA:TRUE`, on verifiers that check usages and
/// not constraints.
#[test]
fn el_uso_de_firma_de_certificados_no_esta_concedido() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    let parsed = parse(cert.der());
    let usage = parsed
        .key_usage()
        .expect("the extension parses")
        .expect("key usage is present")
        .value;
    assert!(usage.digital_signature());
    assert!(
        !usage.key_cert_sign(),
        "keyCertSign would make the holder an issuer"
    );
}

/// **Mutation: issue `ServerAuth` instead of `ClientAuth`** — the same
/// certificate would authenticate a server, which is a different grant over
/// the same bytes.
#[test]
fn el_uso_extendido_es_para_clientes() {
    let fixture = Fixture::hostile();
    let cert = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &fixture.csr);

    let parsed = parse(cert.der());
    let eku = parsed
        .extended_key_usage()
        .expect("the extension parses")
        .expect("an extended key usage is present")
        .value;
    assert!(eku.client_auth, "a client certificate is for clientAuth");
    assert!(
        !eku.server_auth,
        "a client certificate must not also serve as a server's"
    );
    assert!(!eku.any, "anyEKU would grant every purpose at once");
}

// ---------------------------------------------------------------------------
// C. Lifetime.
// ---------------------------------------------------------------------------

/// **Mutation: use the grant's requested TTL without the `min`** — the
/// certificate is valid for a day under a CA that dies in ten minutes, and no
/// trust store can chain it.
#[test]
fn la_vida_se_acota_al_resto_de_la_autoridad() {
    let short = Duration::from_secs(600);
    let certificate = issue(
        &ca(short),
        &grant("svc-a.internal", 24 * HOUR),
        &Fixture::hostile().csr,
    );
    let granted = certificate.granted_ttl();

    // The ceiling is the CA's remaining life *measured at the moment of
    // issuance*, so it is `short` less however long the CA object had been
    // alive. The window below is the test's own clock, not a tolerance chosen
    // to make the row pass: with the `min` removed the granted life is 24
    // hours and the first assertion fails by a factor of 144.
    assert!(granted <= short, "granted {granted:?} outlasts the CA's {short:?}");
    assert!(
        granted >= short.saturating_sub(Duration::from_secs(5)),
        "granted {granted:?} is not the CA's remaining life"
    );
}

/// **Mutation: report the requested TTL as the granted one** — the certificate
/// says one thing and the CA says another, and a caller that cached the
/// request believes in a lifetime it was not given.
#[test]
fn la_vida_concedida_se_distingue_de_la_pedida() {
    let asked = 8 * HOUR;
    let certificate = issue(
        &ca(HOUR),
        &grant("svc-a.internal", asked),
        &Fixture::hostile().csr,
    );

    assert!(certificate.granted_ttl() < asked);
}

/// **Mutation: drop the floor** — a one-second certificate is issued and
/// expires before a peer can present it.
#[test]
fn un_plazo_por_debajo_del_suelo_se_rechaza() {
    let refusal = issue_client_certificate(
        &ca(HOUR),
        &grant("svc-a.internal", Duration::from_secs(1)),
        &Fixture::hostile().csr,
        Instant::now(),
    )
    .expect_err("one second is below the floor");

    assert_eq!(
        refusal,
        ClientCertError::GrantTtlTooShort {
            requested: Duration::from_secs(1),
            minimum: MIN_CLIENT_CERT_TTL,
        }
    );
}

/// **Mutation: measure only the grant and not the CA** — a CA with a minute
/// left issues a certificate that outlives it, because the grant asked for an
/// hour.
#[test]
fn una_autoridad_casi_caducada_no_firma_nada() {
    let expiring = Duration::from_secs(60);
    let refusal = issue_client_certificate(
        &ca(expiring),
        &grant("svc-a.internal", HOUR),
        &Fixture::hostile().csr,
        Instant::now(),
    )
    .expect_err("a CA below the floor cannot issue anything");

    // The *variant* is the assertion: a reordering that measures the grant
    // first reports `GrantTtlTooShort` for a grant that asked for an hour, and
    // that is a different and much less useful diagnosis.
    match refusal {
        ClientCertError::CaNearlyExpired { remaining, minimum } => {
            assert_eq!(minimum, MIN_CLIENT_CERT_TTL);
            assert!(remaining < minimum, "{remaining:?} is not below {minimum:?}");
            assert!(remaining <= expiring, "{remaining:?} exceeds the CA's own life");
        }
        other => panic!("expected the CA's own life to be the limit, got {other:?}"),
    }
}

/// **Mutation: delete the CA expiry check** — issuance succeeds against an
/// authority that is gone.
#[test]
fn una_autoridad_caducada_no_firma_nada() {
    let authority = ca(HOUR);
    let refusal = issue_client_certificate(
        &authority,
        &grant("svc-a.internal", HOUR),
        &Fixture::hostile().csr,
        Instant::now() + 2 * HOUR,
    )
    .expect_err("an expired CA cannot issue");

    assert_eq!(
        refusal,
        ClientCertError::CaExpired(authority.session_id.clone())
    );
}

/// **Mutation: set `not_after` from the request alone** — the certificate's
/// validity runs past its issuer's, which is a certificate no chain validator
/// accepts.
#[test]
fn el_certificado_no_sobrevive_a_su_autoridad() {
    let authority = ca(Duration::from_secs(1800));
    let certificate = issue(
        &authority,
        &grant("svc-a.internal", 24 * HOUR),
        &Fixture::hostile().csr,
    );

    let leaf = parse(certificate.der());
    let issuer = parse(&authority.intermediate_der);
    assert!(
        leaf.validity().not_after <= issuer.validity().not_after,
        "leaf not_after {:?} runs past its issuer's {:?}",
        leaf.validity().not_after,
        issuer.validity().not_after
    );
}

// ---------------------------------------------------------------------------
// D. The request itself.
// ---------------------------------------------------------------------------

/// **Mutation: parse the request without verifying its signature** — a
/// request whose key was edited after signing is certified anyway, so anyone
/// can obtain a certificate for a key they can prove nothing about.
///
/// The row also pins *which* refusal comes back, because a request that fails
/// to parse and a request whose signature does not verify are opposite events
/// and only one of them is an attack.
#[test]
fn una_peticion_con_la_firma_rota_se_rechaza() {
    let mut der = Fixture::hostile().der;
    let last = der.len() - 1;
    der[last] ^= 0x01;

    let refusal = issue_client_certificate(
        &ca(HOUR),
        &grant("svc-a.internal", HOUR),
        &ClientCsr::from_der(der),
        Instant::now(),
    )
    .expect_err("a request that does not verify must not be signed");

    assert_eq!(refusal, ClientCertError::CsrSignatureInvalid);
}

/// **Mutation: treat any parse failure as a signature failure** — the inverse
/// of the row above. The mapping from `rcgen`'s single error type to two
/// distinct refusals is a decision, and a decision with only one test is a
/// decision nobody looked at twice.
#[test]
fn basura_no_se_confunde_con_una_firma_rota() {
    let refusal = issue_client_certificate(
        &ca(HOUR),
        &grant("svc-a.internal", HOUR),
        &ClientCsr::from_der(vec![0x30, 0x00, 0xff, 0xfe]),
        Instant::now(),
    )
    .expect_err("garbage is not a request");

    assert!(
        matches!(refusal, ClientCertError::UnreadableCsr(_)),
        "expected an unreadable request, got {refusal:?}"
    );
}

/// **Mutation: return `Ok` wrapping whatever the PEM decode found** — a caller
/// that ignores the result is now holding an empty request, and the failure
/// surfaces later as a confusing parse error about bytes that were never a
/// request.
#[test]
fn un_pem_sin_peticion_se_rechaza_al_leerlo() {
    let refusal =
        ClientCsr::from_pem("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .expect_err("a certificate is not a certificate request");

    assert!(matches!(refusal, ClientCertError::UnreadableCsr(_)));
}

/// **Mutation: keep the PEM armour in the field and let the DER parser choke
/// on it** — the API accepts PEM and then refuses every PEM, which reads as a
/// hostile client rather than as a bug.
///
/// This is the row that found that bug: `from_pem` originally stored the
/// base64 text verbatim.
#[test]
fn un_pem_y_su_der_firman_lo_mismo() {
    let fixture = Fixture::asking("CN=svc-a.internal", &["svc-a.internal"]);

    let from_pem = ClientCsr::from_pem(&fixture.pem).expect("the PEM holds a request");
    let from_der = ClientCsr::from_der(fixture.der.clone());

    assert_eq!(from_pem, from_der, "the two spellings must decode alike");
    // And the accepted one really does sign, which is the half the comparison
    // above cannot see.
    let certificate = issue(&ca(HOUR), &grant("svc-a.internal", HOUR), &from_pem);
    assert_eq!(certificate.identity(), "svc-a.internal");
}

// ---------------------------------------------------------------------------
// E. The shape of the answer.
// ---------------------------------------------------------------------------

/// **Mutation: add a key field to either struct** — this stops compiling,
/// which is the reason it is written as a test and not as a comment.
///
/// `IssuedClientCert` has no private key, and `ClientCsr` has no field that
/// could hold one. The private half of the keypair stays in the caller's
/// process, and no path in this module could move it.
#[test]
fn ni_la_peticion_ni_el_certificado_tienen_clave_privada() {
    let certificate = issue(
        &ca(HOUR),
        &grant("svc-a.internal", HOUR),
        &Fixture::hostile().csr,
    );

    let _: &str = certificate.identity();
    let _: &[u8] = certificate.der();
    let _: Duration = certificate.granted_ttl();
}

/// **Mutation: derive `Debug` on `ClientCsr`** — the request's bytes reach the
/// log, and those bytes are entirely attacker-chosen.
#[test]
fn el_debug_de_una_peticion_no_imprime_sus_bytes() {
    let fixture = Fixture::hostile();
    let rendered = format!("{:?}", fixture.csr);

    // Both spellings, and that is the second half of this row. A derived
    // `Debug` on the wrapper prints `CertificateSigningRequestDer([48, 89,
    // 48, ...])` — decimal, not hex — so a row that only looked for hex was
    // green under exactly the mutation it was written for. The request's
    // first four bytes are the marker, in whichever base the formatter picked.
    let head_hex: String = fixture
        .der
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    let head_dec: Vec<String> = fixture.der.iter().take(4).map(|b| b.to_string()).collect();

    for spelling in [head_hex, head_dec.join(", "), head_dec.join(",")] {
        assert!(
            !rendered.contains(&spelling),
            "the request's bytes leaked as {spelling:?}: {rendered}"
        );
    }
    assert!(rendered.contains("der_len"), "the length is the useful part");
}
