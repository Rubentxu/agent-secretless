#!/usr/bin/env python3
"""Falsification for R2.E.1, mTLS client certificate issuance.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**The module has twenty-five rows. This campaign files twenty mutations, and
four of the twenty-five rows are not falsifiable and are counted as such
rather than quietly folded into the total.**

**One of the four is structural, and it is the module's whole posture.**
`ni_la_peticion_ni_el_certificado_tienen_clave_privada` is a compiler-refused
row: adding a key field to either struct breaks the crate rather than failing
an assertion. It is filed precisely because the campaign *cannot* turn it red,
which is the point rather than a gap.

**Two are not falsifiable because the API does not offer the defect, and that
is a stronger claim than "there is no test".** "We wrote a test for it" and "a
mutation of it exists" are different claims and only the first is usually made.

`la_clave_publica_es_la_que_la_peticion_trae` is the row a reviewer looks for
first, and there is no mutation for it: `rcgen::PublicKey` has no public
constructor and no `From`, so the only source of a public key is
`CertificateSigningRequestParams::from_der`, and the only request in scope is
the one the requester sent. "Sign a fresh key generated inside issuance" is not
a line someone can write against this version of `rcgen`; it is a compile
error. The row still measures the property end to end — it parses the issued
DER and compares the SubjectPublicKeyInfo against the request's and against
the fixture's own key — and it is what would go red the day `rcgen` grows a
constructor.

`el_issuer_es_el_intermedio_y_no_la_raiz` has the same shape for a different
reason: `SessionCa` keeps `root_der` and `intermediate_der` but keeps only the
*intermediate's* private key. Signing with the root is not forbidden by this
module, it is impossible through the handle this module holds. The row asserts
the property anyway, because a change that starts keeping the root key must
have something to fail.

**The fourth is not about this module's code at all.**
`el_certificado_consume_exactamente_sus_bytes` is filed as compound: it
measures whether `x509-parser` leaves trailing bytes, which is a property of a
third-party parser. It is here because the parser is already in scope and a
certificate with a tail is a real artifact defect worth catching once, where
the bytes enter the process.

**The mutation to read first is the first one.** This module's claim is that
the certificate names the identity the *broker* granted.
`rcgen::CertificateSigningRequestParams::from_der` populates a full
`CertificateParams` from the request — subject, SANs, key usages, EKUs, all
attacker-chosen — and the obvious implementation binds it. Honouring it turns
a client-certificate issuer into a CA for its own subscribers: one request asks
for `*.internal`, for `CA:TRUE` and for `keyCertSign` at once.
`certificate_params` accepts that struct, names it, and does not read it, and
the first two mutations below are the two ways of changing that.

**Two defects were found by this campaign rather than by reading the code, and
both are about the tests.**

`ClientCsr::from_pem` originally stored the PEM text verbatim in the field that
holds DER, so the API accepted PEM and then refused every PEM. The mutation
filed against `un_pem_y_su_der_firman_lo_mismo` is that exact bug, kept because
the row and the defect are the same finding.

And `el_debug_de_una_peticion_no_imprime_sus_bytes` first searched for the
request's bytes in hex only. A derived `Debug` on the wrapper prints them in
decimal, so the row was green under the one mutation it was written for. It now
checks both spellings. That is the failure the accounting exists for: a row
that looks adversarial and is not.

**Do not copy this repository out of an isolated working copy while a campaign
is running against it.** This is written down because it happened, and the
consequence was worse than a failed run: the copy that the campaign mutates and
restores is *not* a safe source of truth while it runs, and reading a file from
it mid-campaign can hand you a file with the first mutation still applied. A
commit made from that copy shipped a broker that signed the identity the
requester asked for — the exact defect this module exists to prevent — and the
only thing that caught it was running the rows in the real repository, where
seven of them went red. The harness restored the working copy correctly; the
copy-out did not know that.

**Why this harness has a second loop.** The base harness edits exactly one
file, and the canonicalization bypass is a mutation of `grant.rs`. Rather than
fork the bucket accounting — which is the one number in the file nobody checks
— the second phase reuses `run_test` and prints its own four buckets. The
totals are two lines, and the phase that produced each is named.

Run:  python3 mtls_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

ISSUE = f.REPO / "crates/broker/src/mtls/issue.rs"
GRANT = f.REPO / "crates/broker/src/mtls/grant.rs"

# (label, old, new, test that must go red) -- all in ISSUE.
MUTATIONS = [
    # ---- the one this module exists for ------------------------------------
    (
        # Honour the request, whole. `certificate_params` receives the
        # requester's own `CertificateParams` and does not read it; this reads
        # it instead. The certificate then carries `CN=admin,O=attacker`, the
        # SANs `*.internal`, `*.example.com` and `attacker.test`, no key usage
        # and no extended key usage, and whatever `is_ca` the request carried
        # (which a CSR cannot assert, so it lands on the default).
        #
        # Two rows go red on a *panic* rather than an assertion, which is the
        # honest shape of this failure: a certificate with no key usage and no
        # EKU is not "wrong", it is unparseable as the thing it claims to be.
        "sign the identity the request asked for",
        "    let params = certificate_params(&identity, ttl, &requested_identity)?;",
        "    let mut params = { let mut taken = requested_identity.clone(); taken.not_before = OffsetDateTime::now_utc(); taken.not_after = taken.not_before + time::Duration::try_from(ttl).unwrap_or_default(); taken };",
        "el_subject_es_el_del_grant_y_no_el_de_la_peticion",
    ),
    (
        # The same defect from the SAN side, filed separately because the SAN is
        # what a peer actually checks, and because a fix that binds the subject
        # but not the SANs leaves the wildcard hole open.
        "carry the requested SANs forward",
        "    let params = certificate_params(&identity, ttl, &requested_identity)?;",
        "    let mut params = { let mut taken = certificate_params(&identity, ttl, &requested_identity)?; taken.subject_alt_names = requested_identity.subject_alt_names.clone(); taken };",
        "los_sans_pedidos_no_sobreviven",
    ),
    # ---- the constraints, one line each ------------------------------------
    (
        # `CA:TRUE` turns the holder into an issuer. The broker signs a leaf
        # whose holder can then sign leaves, and the chain this module exists
        # to keep short becomes a tree.
        "issue a certificate that is itself a CA",
        "    params.is_ca = rcgen::IsCa::ExplicitNoCa;",
        "    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);",
        "el_certificado_no_puede_ser_una_autoridad",
    ),
    (
        # The same escalation without `CA:TRUE`, which is why these are two
        # rows rather than one.
        "grant the keyCertSign usage",
        "    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];",
        "    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature, rcgen::KeyUsagePurpose::KeyCertSign];",
        "el_uso_de_firma_de_certificados_no_esta_concedido",
    ),
    (
        # A client certificate that also serves as a server's is a different
        # grant over the same bytes, and a peer checking EKUs accepts it for
        # both.
        "issue it for servers instead",
        "    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];",
        "    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];",
        "el_uso_extendido_es_para_clientes",
    ),
    (
        # `anyEKU` is the same escalation in one OID, and it is what a careless
        # "make it flexible" edit produces.
        "issue it for every purpose",
        "    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];",
        "    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Any];",
        "el_uso_extendido_es_para_clientes",
    ),
    (
        # Dropping the extension entirely. A certificate with no EKU is
        # "unrestricted" to some verifiers and invalid to others; this pins
        # that the module writes one rather than leaving the question to the
        # peer.
        "leave the purpose unstated",
        "    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];",
        "    params.extended_key_usages = Vec::new();",
        "el_uso_extendido_es_para_clientes",
    ),
    # ---- lifetime ----------------------------------------------------------
    (
        # The one that matters: a certificate valid for a day under a CA that
        # dies in ten minutes. It parses, it verifies, and no trust store can
        # chain it, so the failure appears at the peer rather than here.
        "honour the requested lifetime instead of the CA's",
        "    let ttl = requested.min(ca_remaining);",
        "    let ttl = requested;",
        "la_vida_se_acota_al_resto_de_la_autoridad",
    ),
    (
        # The same ceiling written in x509 rather than in Rust. If the `min` were
        # ever reintroduced in the struct and dropped here, the struct would
        # report one lifetime and the certificate would carry another, and only
        # this row would notice.
        "write a lifetime that outruns the issuer into the certificate",
        "    params.not_after = not_before + remaining;",
        "    params.not_after = not_before + remaining + time::Duration::hours(1);",
        "el_certificado_no_sobrevive_a_su_autoridad",
    ),
    (
        "issue below the floor the grant set",
        "    if requested < MIN_CLIENT_CERT_TTL {",
        "    if false {",
        "un_plazo_por_debajo_del_suelo_se_rechaza",
    ),
    (
        # Removing the CA's own check does not produce `CaExpired`: the
        # remaining-life calculation saturates to zero and the request is
        # refused as `CaNearlyExpired` instead. The row names the variant, so it
        # goes red on a *different* refusal, which is the point of pinning it.
        "issue under an expired authority",
        "    if ca.is_expired(now) {",
        "    if false {",
        "una_autoridad_caducada_no_firma_nada",
    ),
    (
        "issue under an authority that is nearly done",
        "    if ca_remaining < MIN_CLIENT_CERT_TTL {",
        "    if false {",
        "una_autoridad_casi_caducada_no_firma_nada",
    ),
    # ---- the authority's own fitness ---------------------------------------
    (
        "issue a certificate that chains to nothing",
        "    if ca.root_der.is_empty() {",
        "    if false {",
        "una_autoridad_sin_raiz_no_firma_nada",
    ),
    (
        "issue with no signing material",
        "    if ca.intermediate_der.is_empty() {",
        "    if false {",
        "una_autoridad_sin_intermedio_no_firma_nada",
    ),
    # ---- the request's integrity -------------------------------------------
    (
        # Collapse a signature failure into "unreadable". The request is still
        # refused, so a caller that only checks `is_err()` sees no difference —
        # which is exactly why the row pins the variant rather than the
        # outcome.
        "report every request failure as unreadable",
        "            if matches!(e, rcgen::Error::RingUnspecified) {",
        "            if false {",
        "una_peticion_con_la_firma_rota_se_rechaza",
    ),
    (
        # And the inverse, which is what keeps the row above honest.
        "report every request failure as a broken signature",
        "            if matches!(e, rcgen::Error::RingUnspecified) {",
        "            if true {",
        "basura_no_se_confunde_con_una_firma_rota",
    ),
    # ---- the PEM path ------------------------------------------------------
    (
        # The bug this campaign found. `from_pem` accepted the armour and stored
        # it, so the DER parser later choked on base64: an API that takes PEM
        # and refuses every PEM, which reads as a hostile client.
        "keep the PEM armour instead of decoding it",
        "    Ok(Self { der })",
        "    Ok(Self { der: CertificateSigningRequestDer::from(pem.as_bytes().to_vec()) })",
        "un_pem_y_su_der_firman_lo_mismo",
    ),
    (
        # And the lazy version: no decode, no error, an empty request. The
        # failure now surfaces much later as a parse error about bytes that
        # were never a request.
        "never fail to read a PEM",
        "            CertificateSigningRequestDer::from_pem_slice(pem.as_bytes()).map_err(|e| {",
        "            Ok(CertificateSigningRequestDer::from(Vec::new())).map_err(|e: std::convert::Infallible| {",
        "un_pem_sin_peticion_se_rechaza_al_leerlo",
    ),
    # ---- the answer's shape -----------------------------------------------
    (
        # `Debug` on a wrapper whose bytes are entirely attacker-chosen is a
        # log-injection vector. This prints them in decimal, which is why the
        # row now checks both spellings — see the docstring.
        "log the request's bytes",
        '    f.debug_struct("ClientCsr")\n            .field("der_len", &self.der.len())\n            .finish_non_exhaustive()',
        '    f.debug_tuple("ClientCsr").field(&self.der).finish()',
        "el_debug_de_una_peticion_no_imprime_sus_bytes",
    ),
]

# The grant's constructor is the only place an identity is ever canonicalized,
# which makes it the only place the three identity rows can be attacked. It
# lives in a different file from the module's body, so it gets its own phase.
GRANT_MUTATIONS = [
    (
        # Ignoring the argument makes three rows red at once: the wildcard
        # becomes grantable, the non-canonical spellings become grantable, and
        # `SVC-A.INTERNAL` reaches the certificate un-normalized — so a peer
        # that authorizes on the exact spelling sees two identities for one
        # name.
        "accept an identity without canonicalizing it",
        "        let identity = Authority::canonicalize(identity)\n            .map_err(|e| ClientCertError::UnusableIdentity(e.to_string()))?;",
        "        let identity = Authority::canonicalize(\"placeholder.invalid\")\n            .map_err(|e| ClientCertError::UnusableIdentity(e.to_string()))?;\n        let _ = identity;",
        "un_wildcard_no_se_puede_conceder",
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> tuple[int, dict, list]:
    """Apply `mutations` to one file and return the four-bucket tally.

    Deliberately a thin re-use of the base harness's `run_test` and of its
    snippet-uniqueness rule rather than a fork of its summary logic: the
    buckets partition the run, and a summary that does not partition is the
    one number nobody checks.
    """
    original = path.read_text()
    buckets = {
        "red": 0,
        "compiler-refused": 0,
        "green (SURVIVOR)": 0,
        "measured nothing": 0,
    }
    problems: list = []
    try:
        for label, old, new, test in mutations:
            if original.count(old) != 1:
                buckets["green (SURVIVOR)"] += 1
                problems.append((label, test, f"snippet counts {original.count(old)}, want 1"))
                print(f"SKIP  {label!r}: snippet is not unique", flush=True)
                continue
            path.write_text(original.replace(old, new, 1))
            try:
                verdict, out = f.run_test(test)
            finally:
                path.write_text(original)
            if verdict == "red":
                buckets["red"] += 1
                print(f"ok    [{title}] {label}\n      -> {test} went red", flush=True)
            elif verdict == "green":
                buckets["green (SURVIVOR)"] += 1
                problems.append((label, test, "the row stayed green"))
                print(f"SURVIVOR  [{title}] {label}\n      -> {test} stayed GREEN  <-- the finding", flush=True)
            elif verdict == "refused":
                buckets["compiler-refused"] += 1
                first = next(
                    (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
                )
                print(f"ok*   [{title}] {label}\n      -> {test}: refused by the compiler\n         {first}", flush=True)
            else:
                buckets["measured nothing"] += 1
                problems.append((label, test, verdict))
                print(f"BAD   [{title}] {label}\n      -> {test}: {verdict}", flush=True)
    finally:
        path.write_text(original)
    assert path.read_text() == original, f"{path} was not restored"
    assert sum(buckets.values()) == len(mutations), (buckets, len(mutations))
    return len(mutations), buckets, problems


def main() -> int:
    f.TEST_PREFIX = "tls_bridge::mtls::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = ISSUE
    f.MUTATIONS[:] = MUTATIONS

    total = len(MUTATIONS) + len(GRANT_MUTATIONS)
    print(
        f"# falsifying {ISSUE.relative_to(f.REPO)} and {GRANT.relative_to(f.REPO)} "
        f"with {total} mutations\n"
    )

    print(f"## phase 1 -- {ISSUE.name}")
    _, buckets_a, problems_a = run_phase(ISSUE, MUTATIONS, ISSUE.name)
    print()
    print(f"## phase 2 -- {GRANT.name}")
    _, buckets_b, problems_b = run_phase(GRANT, GRANT_MUTATIONS, GRANT.name)

    merged = {k: buckets_a[k] + buckets_b[k] for k in buckets_a}
    print()
    print(f"mutations: {total}  (the four buckets partition the run)")
    for name, count in merged.items():
        print(f"  {name:<22}: {count}")
    print(f"\n  phase 1 {ISSUE.name}: " + ", ".join(f"{k}={v}" for k, v in buckets_a.items() if v))
    print(f"  phase 2 {GRANT.name}: " + ", ".join(f"{k}={v}" for k, v in buckets_b.items() if v))

    problems = problems_a + problems_b
    for label, test, why in problems:
        print(f"\nFINDING: {label}\n  test: {test}\n  {why}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
