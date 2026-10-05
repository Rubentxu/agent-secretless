#!/usr/bin/env python3
"""Falsification for R2.E, mTLS: issuance (R2.E.1) and presentation (R2.E.2).

Four phases across four files, because R2.E has two halves that live in two
places. The phases are named in the output and tallied separately so that a
reader can see which half a mutation belongs to; the totals are one line each
rather than one number that hides all four.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**R2.E.1 has twenty-six rows and this campaign files twenty mutations against
them, and four of the twenty-six are not falsifiable and are counted as such
rather than quietly folded into the total. R2.E.2 has twelve rows and ten
mutations, of which one row is positive and one is half compile-time. R2.E.3,
the operator's declaration, has ten rows and four mutations, of which two are
not falsifiable.**

**One R2.E.3 mutation was compiler-refused on its first run and that was the
mutation's fault, not the type's.** It reached for `super::super::grant::…` from
a file that already imports those names, so the refusal was `cannot find
'grant' in 'super'` and nothing about the property was measured. The base
harness says this out loud elsewhere in this repository and the rule applies
here: a mutation that stops compiling because it is malformed is not evidence,
and filing it as a structural refusal would be the harness flattering itself.
Re-pointed at the names actually in scope, it compiles and the row goes red.

**The two R2.E.3 rows the campaign cannot turn red fail for a reason worth
stating.** `un_nombre_no_canonico_no_se_declara` would be falsified by
canonicalising nothing, and `un_destino_repetido_con_otra_ortografia_tambien_se_rechaza`
by comparing a destination before it is canonical. Both are changes of a
field's type rather than of a line: `asv_domain::Authority` has no public
constructor from a raw string, so a binding that stored one would have to stop
storing an `Authority`. What pins the behaviour instead is
`el_host_se_canonicaliza_antes_de_resolver`, which a one-line mutation does
reach, and which is the half that a route actually depends on.

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

**Why this harness has four loops.** The base harness edits exactly one file.
`grant.rs` carries the canonicalization bypass, `present.rs` the R2.E.2
identity, and `tls_bridge.rs` the branch that offers it. Rather than fork the
bucket accounting — which is the one number in the file nobody checks — each
phase reuses `run_test` and prints its own four buckets.

**The two R2.E.2 mutations worth reading first are the binding ones.** A
client certificate presented to "whoever asked for one" hands the identity to
a host impersonating a server, so `presents_to` is an exact comparison against
the host fixed at issue time. `la_identidad_no_se_presenta_a_un_destino_distinto`
and `un_destino_distinto_no_llega_de_ninguna_forma` are a pair on purpose: the
first pins the refusal, the second pins that the refusal is not a silent
downgrade to a handshake with no certificate. Either alone is satisfiable by
the wrong behaviour.

Run:  python3 mtls_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

ISSUE = f.REPO / "crates/broker/src/mtls/issue.rs"
GRANT = f.REPO / "crates/broker/src/mtls/grant.rs"
PRESENT = f.REPO / "crates/broker/src/mtls/present.rs"
DEPLOYMENT = f.REPO / "crates/broker/src/mtls/deployment.rs"
BRIDGE = f.REPO / "crates/broker/src/tls_bridge.rs"

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
        "        if matches!(e, rcgen::Error::RingUnspecified) {",
        "        if false {",
        "una_peticion_con_la_firma_rota_se_rechaza",
    ),
    (
        # And the inverse, which is what keeps the row above honest.
        "report every request failure as a broken signature",
        "        if matches!(e, rcgen::Error::RingUnspecified) {",
        "        if true {",
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
        "        let der = CertificateSigningRequestDer::from_pem_slice(pem.as_bytes()).map_err(|e| {",
        "        let der = Ok(CertificateSigningRequestDer::from(Vec::new())).map_err(|e: std::convert::Infallible| {",
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


# R2.E.2 -- the identity the broker holds. Same rule: the binding to one
# destination is the property, and every mutation here attacks the binding or
# the material.
PRESENT_MUTATIONS = [
    (
        # Without canonicalization, a grant can be bound to a spelling no
        # route would ever produce, so `presents_to` compares against a string
        # the destination never answers to and the identity is unusable in
        # both directions rather than refusing the wrong one.
        "bind the identity to a host without canonicalizing it",
        "        let bound_host = asv_domain::Authority::canonicalize(host)\n            .map_err(|e| ClientCertError::Unusable(format!(\"{host} is not a destination: {e}\")))?\n            .as_str()\n            .to_string();",
        "        let bound_host = host.to_string();",
        "una_identidad_no_se_emite_para_un_host_que_no_es_un_host",
    ),
    (
        # The classic off-by-one-suffix. A grant for `svc.example` would then
        # authenticate `other.svc.example`, and a server that asks for a
        # client certificate is exactly what an attacker impersonates in
        # order to receive one.
        "compare the binding by suffix",
        "        self.bound_host == host",
        "        self.bound_host.ends_with(host) || self.bound_host == host",
        "la_identidad_solo_llega_al_host_exacto",
    ),
    (
        # The same defect with the comparison removed entirely: present it to
        # whoever asks. Two rows go red, and the handshake row is the one that
        # says a peer really did receive it.
        "present the identity to whoever asks for one",
        "        self.bound_host == host",
        "        let _ = host;\n        true",
        "la_identidad_solo_llega_al_host_exacto",
    ),
    (
        # A leaf alone chains to nothing for a peer that trusts only the root,
        # which is every peer in this product's model: the root is the anchor
        # and the intermediate is the broker's.
        "send the leaf without the intermediate",
        "            chain: vec![\n                CertificateDer::from(issued.der().to_vec()),\n                CertificateDer::from(ca.intermediate_der.clone()),\n            ],",
        "            chain: vec![CertificateDer::from(issued.der().to_vec())],",
        "la_cadena_lleva_el_intermedio_para_que_el_destino_pueda_encadenar",
    ),
    (
        # An expired client certificate is one the destination will reject, so
        # `is_expired` reporting false here spends a handshake to learn
        # something the broker already knew and reports it as a transport
        # failure.
        "report an identity past its lifetime as usable",
        "        now.saturating_duration_since(self.issued_at) >= self.ttl",
        "        let _ = (now, self.issued_at, self.ttl);\n        false",
        "una_identidad_caducada_no_se_presenta",
    ),
    (
        # A derived `Debug` on a struct holding a `PrivateKeyDer` prints the
        # key. `PrivateKeyDer` and `CertificateDer` both implement `Debug`, so
        # this compiles and is exactly the edit someone makes when the
        # hand-written impl looks like boilerplate.
        "derive Debug on the identity and print the key",
        '        f.debug_struct("ClientIdentity")\n            .field("identity", &self.identity)\n            .field("bound_host", &self.bound_host)\n            .field("chain_len", &self.chain.len())\n            .field("ttl", &self.ttl)\n            .finish_non_exhaustive()',
        '        f.debug_struct("ClientIdentity")\n            .field("identity", &self.identity)\n            .field("bound_host", &self.bound_host)\n            .field("key", &self.key)\n            .finish()',
        "el_debug_de_una_identidad_no_imprime_su_clave",
    ),
]

# R2.E.2 -- the branch in `dial_upstream` that offers it.
BRIDGE_MUTATIONS = [
    (
        # The guard removed: the identity is offered to every destination the
        # bridge reaches. Both binding rows go red, and the destination that
        # demands a certificate accepts one it was never granted.
        "offer the identity to every destination",
        "                    Some(identity) if identity.presents_to(target.host()) => {",
        "                    Some(identity) => {",
        "la_identidad_no_se_presenta_a_un_destino_distinto",
    ),
    (
        # The silent downgrade. A grant that stopped matching the route becomes
        # a handshake with no certificate instead of an error, and the
        # destination -- which demands one -- refuses for a reason that names
        # nothing about the identity.
        "answer a mismatched identity with no client auth",
        """                    Some(identity) => {
                        return Err(BridgeError::Handshake(format!(
                            "{target}: this bridge holds a client identity for {}, and \\
                             presenting it here would hand that identity to a host it was \\
                             not granted to",
                            identity.bound_host()
                        )));
                    }""",
        """                    Some(_) => rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),""",
        "un_destino_distinto_no_llega_de_ninguna_forma",
    ),
    (
        # Left to the destination, which rejects it: the operator sees a
        # transport failure rather than "this session's identity has aged out
        # and needs reissuing".
        "present an identity that is past its lifetime",
        "                        if identity.is_expired(std::time::Instant::now()) {",
        "                        if false {",
        "una_identidad_caducada_no_se_presenta",
    ),
    (
        # The builder that silently does nothing, which is the shape a
        # half-finished feature takes: the type exists, the call site reads
        # correctly, and no certificate is ever presented.
        "accept a client identity and keep it nowhere",
        "        self.client_identity = Some(identity);",
        "        let _ = identity;",
        "un_destino_que_exige_certificado_acepta_la_identidad_concedida",
    ),
]


# R2.E.3 -- the operator's declaration. Every mutation attacks the resolution:
# which destination an identity comes out for, and what happens to a list that
# is ambiguous.
DEPLOYMENT_MUTATIONS = [
    (
        # First-one-wins would be the alternative, and it makes the file's
        # formatting decide which identity a destination is authenticated as.
        "resolve a repeated destination by order instead of refusing it",
        "        for (index, binding) in bindings.iter().enumerate() {\n            if let Some(first) = bindings[..index]\n                .iter()\n                .find(|other| other.destination() == binding.destination())\n            {\n                return Err(DeploymentError::DuplicateDestination {\n                    destination: binding.destination().to_string(),\n                    first: first.identity().to_string(),\n                    second: binding.identity().to_string(),\n                });\n            }\n        }",
        "        let _ = &bindings;",
        "un_destino_declarado_dos_veces_se_rechaza",
    ),
    (
        # A declaration for `svc.example` would then mint an identity for
        # `other.svc.example`, and the client certificate would be presented
        # to a host the operator never named.
        "resolve a declared destination by suffix",
        "            .find(|binding| binding.destination() == canonical.as_str())",
        "            .find(|binding| canonical.as_str().ends_with(binding.destination()))",
        "la_resolucion_es_exacta_y_no_por_sufijo",
    ),
    (
        # The failure the whole module exists to prevent, in its purest form:
        # an identity for any destination asked about, which is a client
        # certificate handed to whoever routed here.
        "mint an identity for whichever host was asked for",
        "        else {\n            return Ok(None);\n        };",
        "        else {\n            let fallback = ClientGrant::for_identity(\"fallback.internal\", MIN_CLIENT_CERT_TTL)?;\n            return Ok(Some(ClientIdentity::issue(ca, &fallback, canonical.as_str(), now)?));\n        };",
        "un_destino_sin_declaracion_no_produce_identidad",
    ),
    (
        # The declaration holds the canonical form and the route names the same
        # host in another case, so the identity silently stops existing and
        # every request reads like a routing fault rather than a spelling one.
        "compare the declared destination against the host as it was asked for",
        "            .find(|binding| binding.destination() == canonical.as_str())",
        "            .find(|binding| binding.destination() == host)",
        "el_host_se_canonicaliza_antes_de_resolver",
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


# (file, prefix, mutations, phase title)
PHASES = [
    (ISSUE, "tls_bridge::mtls::tests::", MUTATIONS, "R2.E.1 issuance"),
    (GRANT, "tls_bridge::mtls::tests::", GRANT_MUTATIONS, "R2.E.1 grant"),
    (PRESENT, "tls_bridge::client_auth::", PRESENT_MUTATIONS, "R2.E.2 identity"),
    (BRIDGE, "tls_bridge::client_auth::", BRIDGE_MUTATIONS, "R2.E.2 presentation"),
    (DEPLOYMENT, "tls_bridge::mtls::deployment::tests::", DEPLOYMENT_MUTATIONS, "R2.E.3 declaration"),
]


def main() -> int:
    f.CARGO_TARGET = "--lib"
    f.MUTATIONS[:] = MUTATIONS
    f.STS = ISSUE

    total = sum(len(m) for _, _, m, _ in PHASES)
    print(f"# falsifying R2.E with {total} mutations across {len(PHASES)} phases\n")

    tally = {}
    problems = []
    for index, (path, prefix, mutations, title) in enumerate(PHASES, start=1):
        f.TEST_PREFIX = prefix
        f.STS = path
        print(f"## phase {index} -- {title} ({path.relative_to(f.REPO)})")
        _, buckets, found = run_phase(path, mutations, f"{path.name}")
        tally[title] = buckets
        problems += found
        print()

    merged = {}
    for buckets in tally.values():
        for key, value in buckets.items():
            merged[key] = merged.get(key, 0) + value
    assert sum(merged.values()) == total, (merged, total)

    print(f"mutations: {total}  (the four buckets partition the run)")
    for name, count in merged.items():
        print(f"  {name:<22}: {count}")
    print()
    for title, buckets in tally.items():
        line = ", ".join(f"{k}={v}" for k, v in buckets.items() if v)
        print(f"  {title}: {line or 'none'}")

    for label, test, why in problems:
        print(f"\nFINDING: {label}\n  test: {test}\n  {why}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
