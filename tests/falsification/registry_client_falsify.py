#!/usr/bin/env python3
"""Falsification for R2.F.2 (the registry request loop), R2.F.4 (its token
cache) and R2.F.5 (the content address and the check that the bytes have it).

Seven phases over one file: the reference grammar, the token query, the loop
that spends what the query asked for, the cache key, the cache clock, the cache
as the wire sees it, and then the two halves of the blob -- the digest as a
parsed value, and the comparison as the wire exercises it. The phases are named
in the output and tallied separately, because "which half survived" is the
first question to ask of a survivor.

Same five-bucket accounting as `registry_falsify.py` -- red, compiler-refused,
green survivor, measured nothing, and a snippet this harness could not find,
which is a defect in the harness rather than a result about the code.

**Thirty-seven mutations, thirty-seven red, and four rows with no mutation of
their own. The reasons are worth stating.**

`the_stored_credential_reaches_the_realm_and_nothing_else` is the row a
reviewer looks for first, and there is no mutation for it. The stored
credential exists only as the borrowed bytes a `SecretSink::accept` receives,
inside one `SecretPort::lend` call. There is no line to change: a mutation that
put the password on the registry request would need a variable holding it, and
no such variable is in scope in `build_request`. That is a stronger claim than
"there is no test" -- the row still measures the property, by reading both
origins' recorded requests, and it is what would go red the day the sink's shape
changed.

`a_realm_the_vetting_refuses_never_receives_a_connection` is filed as compound
because the rule it exercises lives in `registry.rs`, where the R2.F.1 campaign
already falsified it. What is new here is the socket: the trap origin records
zero connections, which is the only way to see that a refusal happened *before*
the request rather than during it.

`a_reply_can_carry_the_header_a_registry_would` measures the fixture, not the
module. It is here because a `401` without `WWW-Authenticate` is not a `401`,
and every row in the loop phase depends on that variant existing.

`la_ruta_de_un_blob_viene_de_las_dos_mitades_comprobadas` is the fourth. It
pins a path, and a path is a formatting detail rather than a security property;
what makes it worth keeping is that it is the one row that would go red the day
someone routed the path through a caller-supplied string, which is the change
that would turn a checked digest into an unchecked one.

**The mutation to read first is the one that forwards the challenge's scope.**
`token_query` is four lines and the whole argument of R2.F is in them: the
challenge is the sender's request, and what reaches the token endpoint is what
this side decided. Docker Hub answers `pull,push` to a pull, so a client that
forwarded the challenge would ask for a push-capable token while reading an
image, and every other check in the loop would still pass. The wire row reads
the token endpoint's own record of its request line rather than the code that
built it, so it is the query string on the wire that is being asserted and not
the string in memory.

**The second is skipping the narrowing.** The token is already in memory when
`narrow` is called, so `let _ = narrow(...)` compiles, every other check still
passes, and a grant of `repository:someone/else:pull,push` is spent against
`library/alpine`. That is the confused deputy, and one character is the
difference between refusing it and doing it.

**The third is believing the registry's own digest header.** A registry may
answer a blob request with `Docker-Content-Digest` set to whatever it likes, and
a client that reads it is checking the registry against itself: the header
agrees with the request, the request agrees with the manifest, and the manifest
was never checked against the layer. Nothing in the protocol stops the
assertion, so the row serves bytes that do not carry the digest asked for while
asserting in a header that they do. Only hashing the body is not circular.

**Four rows were green for a reason that was not the code they named, and all
four were found by this campaign.**

`la_comprobacion_del_digest_no_es_una_advertencia_al_lado_del_exito` is the
fourth, and it is the one worth reading twice, because the survivor it produced
was the campaign's own fault rather than the code's. The row asserted only that
a mismatched blob is refused, so a mutation that made the comparison
unconditionally *true* still refused it and came back green. A row that asks
"is this an error?" cannot tell a correct refusal from an indiscriminate one.
The row was not strengthened -- it was replaced, by
`el_digest_que_el_registry_afirma_en_una_cabecera_no_sustituye_al_hash`, which
asks a question the indiscriminate version cannot answer: would this client
still refuse a registry that *agrees with the request*? The lesson is the
strongest form of the one below: a row has to be able to fail for a reason that
is not the reason it was written for.

`la_clave_de_cache_no_olvida_ninguna_parte_de_la_decision` spelled `TokenKey`
out by hand in the test file, and came back green under all four of its
mutations -- because a row that rebuilds the thing under test is measuring its
own hand, and the four mutations were all on the copy `redeem` uses. The key is
now built by one constructor, `RegistryClient::key_for`, and the row goes
through it. That is the same lesson as the two below in a stronger form: a
duplicate spelling of the code under test is a row that passes no matter what
the code does.

`a_push_body_arrives_at_the_registry_exactly_as_it_was_given` compared the body
the fake origin recorded, and the fixture reads bodies as text. A mutation that
re-encodes the body through `String::from_utf8_lossy` therefore agreed with the
row, because both were lossy in the same way. The row is now
`a_push_body_reaches_the_request_byte_for_byte` and reads the bytes out of the
built request, where they are still bytes. The same class of bug was then found
a second time in R2.F.5 -- hashing the text form of a blob instead of its bytes
-- and the fix is the same in both places: the *fixture* has to carry bytes, not
text, or it cannot tell a correct hash from a lossy one. `OriginResponse::body`
is a `Vec<u8>` now for that reason, and `OriginResponse::bytes` exists so a blob
row has a way to say so.

`a_refusal_without_a_challenge_is_not_a_puzzle` came back green with the
`BearerChallenge::parse` line replaced, because a `401` carrying no challenge
header is refused one line earlier -- at the `ok_or(NoChallenge)` -- and the
parse is never reached. The mutation now sits on the `ok_or`, which is the line
the row was always about.

**One defect was found while building this campaign, and it was in the harness
rather than the code.** The first run reported a row as a survivor when the
mutation had not been applied at all, because the snippet it looked for had
been re-wrapped by `rustfmt`. That is the reason `harness error` is a bucket
of its own: a mutation that did not run and a row that resisted a mutation are
both a "no" and only one of them says anything about the code.

Run:  python3 registry_client_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

CLIENT = f.REPO / "crates/connector-http/src/registry/client.rs"

UNIT = "registry::client::tests::"
WIRE = "registry::client::wire_tests::"

# (label, old, new, test that must go red)
REFERENCE_MUTATIONS = [
    (
        # A digest that is not a digest is a lookup the registry will answer
        # about a blob nobody named.
        "accept a digest of any length",
        "if digest.len() != 64\n                || !digest\n                    .bytes()\n                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())\n            {",
        "if false {",
        "a_digest_reference_is_a_real_sha256_and_nothing_else",
    ),
    (
        # `sha256` digests are lowercase hex. Two spellings of one address means
        # two cache keys for one blob, and a comparison that treats them as
        # different.
        "accept an uppercase digest",
        "        if let Some(digest) = raw.strip_prefix(\"sha256:\") {\n            if digest.len() != 64\n                || !digest\n                    .bytes()\n                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())",
        "        if let Some(digest) = raw.strip_prefix(\"sha256:\") {\n            if digest.len() != 64\n                || !digest\n                    .bytes()\n                    .all(|b| b.is_ascii_hexdigit())",
        "a_digest_reference_is_a_real_sha256_and_nothing_else",
    ),
    (
        # The traversal. A reference is interpolated into a URL path, so
        # `latest/../other` addresses a different resource on the same registry
        # and `/v2/../v2/admin/manifests/x` is a pull from `admin`.
        "accept any reference without a control character",
        "        if !raw\n            .bytes()\n            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))\n        {",
        "        if !raw.bytes().all(|b| !b.is_ascii_control()) {",
        "a_reference_cannot_step_out_of_its_own_repository",
    ),
    (
        # A very long reference is a very long string for every hop to read.
        "stop bounding the reference length",
        "if raw.len() > MAX_REFERENCE_LENGTH {",
        "if false {",
        "an_over_long_reference_is_refused_as_a_length",
    ),
    (
        # The push body is the agent's data. A connector that re-encodes it is a
        # connector that can change it, and a manifest that survived a lossy
        # round trip is a manifest nobody asked for. Filed here rather than in
        # the loop phase because the row reads the built request, not a socket.
        "re-encode the push body on the way out",
        "        builder = builder.body(body.to_vec());",
        "        builder = builder.body(String::from_utf8_lossy(body).as_bytes().to_vec());",
        "a_push_body_reaches_the_request_byte_for_byte",
    ),
    (
        "build the manifest path with the halves the wrong way round",
        "        \"/v2/{}/manifests/{}\",\n        repository.as_str(),\n        reference.as_str()",
        "        \"/v2/{}/manifests/{}\",\n        reference.as_str(),\n        repository.as_str()",
        "the_manifest_path_is_built_from_the_two_checked_halves",
    ),
]

# (label, old, new, test that must go red)
QUERY_MUTATIONS = [
    (
        # The mutation to read first. The challenge is a request from the party
        # being authenticated; this query is the decision.
        "ask the token endpoint for the challenge's scope",
        '    query.push(("scope".to_string(), asked.as_str()));',
        '    query.push(("scope".to_string(), "repository:library/alpine:pull,push".to_string()));',
        "the_token_query_carries_the_asked_scope_and_not_the_challenges",
    ),
    (
        # Without the service, the token endpoint cannot tell which registry
        # asked, and answers for the wrong one or not at all.
        "leave the service out of the token query",
        '    if let Some(service) = service {\n        query.push(("service".to_string(), service.to_string()));\n    }',
        '    let _ = service;',
        "the_token_query_carries_the_asked_scope_and_not_the_challenges",
    ),
    (
        # A push that asked for a pull. The operation is the only input, so
        # this is the shape a "just add what the challenge said" change takes.
        "ask for every action whatever the operation is",
        '    query.push(("scope".to_string(), asked.as_str()));\n    query\n}',
        '    query.push(("scope".to_string(), "repository:library/alpine:pull,push".to_string()));\n    query\n}',
        "the_token_query_names_the_operation_and_not_the_operation_set",
    ),
]

# (label, old, new, test that must go red)
LOOP_MUTATIONS = [
    (
        # A `200` is not a reason to redeem a token. Taking this branch away
        # makes every anonymous pull ask the vault for a credential nobody
        # requested.
        "redeem a token whether or not there was a challenge",
        "        if response.status() != reqwest::StatusCode::UNAUTHORIZED {",
        "        if false {",
        "an_anonymous_pull_never_opens_the_vault",
    ),
    (
        # Inventing a token endpoint is inventing a credential source, and
        # inventing one on a registry's say-so is how a redirect becomes SSRF.
        #
        # The first version of this mutation replaced the `BearerChallenge::parse`
        # line and came back green, and the reason is the third thing this
        # campaign found about its own tests: a `401` with no challenge header
        # is refused one line *earlier*, by the `ok_or(NoChallenge)`, so the
        # parse was never reached and nothing about it had been measured. The
        # mutation belongs on the `ok_or`.
        "guess a realm when the registry names none",
        "            .ok_or(RegistryError::NoChallenge)?\n            .to_string();",
        '            .unwrap_or(r#"Bearer realm="https://auth.docker.io/token""#)\n            .to_string();',
        "a_refusal_without_a_challenge_is_not_a_puzzle",
    ),
    (
        # The token is already in memory here, so dropping the check compiles
        # and everything else still passes.
        "spend a grant that does not cover the operation",
        "        narrow(&asked, &granted)?;",
        "        let _ = narrow(&asked, &granted);",
        "a_grant_that_does_not_cover_the_operation_never_reaches_the_retry",
    ),
    (
        # The confused deputy, spelled out: a token for `someone/else` spent
        # against `library/alpine`.
        "spend a grant for another repository",
        "        let granted = granted_scope_from_token_response(&outcome.body)?;\n        narrow(&asked, &granted)?;",
        "        let granted = granted_scope_from_token_response(&outcome.body)?;\n        let _ = narrow(&asked, &granted);",
        "a_grant_for_another_repository_never_reaches_the_retry",
    ),
    (
        # A locked vault has to stop the exchange. Treating a failed lend as an
        # empty token sends the retry unauthenticated and calls it a refusal.
        "carry on when the vault would not open",
        "        self.port.lend(&self.credential, &mut sink)?;",
        "        let _ = self.port.lend(&self.credential, &mut sink);",
        "a_locked_vault_stops_the_exchange",
    ),
    (
        # `403` from a token endpoint means the credential is not entitled to
        # this scope, which is a different thing from a transport failure and
        # leads the operator somewhere else entirely.
        "ignore a token endpoint that refused",
        "        if !outcome.status.is_success() {",
        "        if false {",
        "a_refusing_token_endpoint_names_its_status",
    ),
    (
        # A `401` is a step in this protocol, so a second one is not a manifest.
        "read the body whatever the registry answered",
        "    if response.status().as_u16() != expected {",
        "    if false {",
        "a_second_refusal_is_reported_and_not_read_as_a_manifest",
    ),
    (
        # A `PUT` answers `201`. Expecting `200` would make every push fail
        # against a registry that followed the specification.
        "expect a 200 from a push",
        "        RegistryOperation::Push => 201,",
        "        RegistryOperation::Push => 200,",
        "a_push_asks_for_a_push_and_takes_the_answered_manifest",
    ),
]


# (label, old, new, test that must go red)
#
# The cache is what makes the loop usable and what could quietly make it a
# widening, so its rows are about the key and the clock rather than about the
# request. A key missing its action is a pull's token reachable from a push --
# and the token really does carry a push grant, because Docker Hub answers
# `pull,push` to a pull and R2.F.1 only narrows what this side *asks* for.
KEY_MUTATIONS = [
    (
        "drop the action from the cache key",
        "            action: operation.action().to_string(),",
        "            action: String::new(),",
        "la_clave_de_cache_no_olvida_ninguna_parte_de_la_decision",
    ),
    (
        "drop the repository from the cache key",
        "            repository: repository.clone(),",
        '            repository: RepositoryName::parse("library/alpine").expect("a fixed name"),',
        "la_clave_de_cache_no_olvida_ninguna_parte_de_la_decision",
    ),
    (
        "drop the realm from the cache key",
        "            realm: realm.to_string(),",
        "            realm: String::new(),",
        "la_clave_de_cache_no_olvida_ninguna_parte_de_la_decision",
    ),
    (
        "drop the credential from the cache key",
        "            credential: self.credential.clone(),",
        "            credential: String::new(),",
        "forget_deja_solo_lo_que_no_venia_de_esa_credencial",
    ),
    (
        # A token with ten seconds left is a token that expires while the
        # request that carries it is still being written.
        "hand out a token that has expired",
        "        left > TOKEN_EXPIRY_MARGIN",
        "        left >= Duration::ZERO",
        "a_token_a_punto_de_caducar_no_se_reutiliza",
    ),
    (
        "treat an elapsed token as one with time left",
        "        let Some(left) = self.valid_until.checked_duration_since(now) else {\n            return false;\n        };\n        left > TOKEN_EXPIRY_MARGIN",
        "        let _ = self.valid_until.checked_duration_since(now);\n        true",
        "a_token_caducado_no_se_reutiliza",
    ),
    (
        "keep a token whose stated lifetime is shorter than the margin",
        "        if lifetime <= TOKEN_EXPIRY_MARGIN {",
        "        if lifetime <= Duration::ZERO {",
        "un_token_sin_tiempo_de_vida_no_se_cachea",
    ),
    (
        # `forget` exists so a deleted credential stops being served. Clearing
        # everything is the other half of the same bug: it works, and it
        # revokes credentials nobody deleted.
        "let forget clear the whole cache",
        "            .retain(|key, _| key.credential != credential);",
        "            .retain(|_, _| false);",
        "forget_deja_solo_lo_que_no_venia_de_esa_credencial",
    ),
]

# (label, old, new, test that must go red)
#
# The rows here are the socket's, so they measure the exchange rather than the
# map: how many times the token endpoint was spoken to, and what survived a
# credential being retired.
CACHE_WIRING_MUTATIONS = [
    (
        "ask the token endpoint again even with a usable token held",
        "        if let Some(token) = self.cached_token(&key, now) {\n            return Ok(token);\n        }",
        "        if let Some(token) = self.cached_token(&key, now).filter(|_| false) {\n            return Ok(token);\n        }",
        "un_token_se_canjea_una_vez_para_varias_peticiones",
    ),
    (
        "keep a token whose response said nothing about its lifetime",
        "        if let Some(seconds) = expires_in {\n            self.store_token(key, token.clone(), Duration::from_secs(seconds), now);\n        }",
        "        if let Some(seconds) = expires_in {\n            self.store_token(key, token.clone(), Duration::from_secs(seconds), now);\n        } else {\n            self.store_token(key, token.clone(), Duration::from_secs(300), now);\n        }",
        "un_token_sin_expires_in_no_se_cachea",
    ),
    (
        "redeem a token and then not keep it",
        "            self.store_token(key, token.clone(), Duration::from_secs(seconds), now);\n        }",
        "            let _ = (key, token.clone(), seconds, now);\n        }",
        "una_credencial_retirada_deja_de_servirse",
    ),
    (
        # The same key without its action, filed against the socket row: the
        # token this client holds after a pull really can push, because the
        # endpoint granted it one.
        "drop the action from the cache key (observed on the wire)",
        "            action: operation.action().to_string(),",
        "            action: String::new(),",
        "un_token_cacheado_para_un_pull_nunca_sirve_para_un_push",
    ),
]

# R2.F.5 -- the content address, and the check that the bytes have it.
#
# The digest is the only reference in the surface that cannot lie, because it
# is checked. Everything about R2.F.5's security rests on two things staying
# true: a string that is not a digest never becomes one, and the bytes are
# compared as bytes. A mutation that weakens either is the whole finding.
DIGEST_MUTATIONS = [
    (
        "accept any sha256: prefix as a content address",
        "        if hex.len() != 64\n            || !hex\n                .bytes()\n                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())\n        {\n            return Err(ReferenceError::MalformedDigest);\n        }",
        "        if false {\n            return Err(ReferenceError::MalformedDigest);\n        }",
        "un_digest_que_no_es_un_digest_se_rechaza",
    ),
    (
        # `A` and `a` are the same hex digit to a case-insensitive reader, and
        # a digest is content-addressed by the lowercase spelling every
        # implementation agrees on. Accepting both is accepting two spellings
        # for one address, which is a second name for the same content.
        "accept uppercase hex in a digest",
        "        if hex.len() != 64\n            || !hex\n                .bytes()\n                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())",
        "        if hex.len() != 64\n            || !hex\n                .bytes()\n                .all(|b| b.is_ascii_hexdigit())",
        "un_digest_que_no_es_un_digest_se_rechaza",
    ),
    (
        # The same mistake the push-body row made, in a new place: hashing the
        # *text form* of the bytes. `from_utf8_lossy` rewrites every invalid
        # byte to U+FFFD, so any layer that is not text would get a digest
        # that no registry computes, and the check would pass on the same
        # wrong value on both sides.
        "hash the text form of the bytes rather than the bytes",
        "        let hash = Sha256::digest(bytes);",
        "        let hash = Sha256::digest(String::from_utf8_lossy(bytes).as_bytes());",
        "un_digest_es_el_sha256_de_los_bytes",
    ),
    (
        "content-address every blob the same way",
        "        let hash = Sha256::digest(bytes);",
        "        let hash = Sha256::digest(b\"constant\");",
        "dos_blobs_distintos_no_comparten_digest",
    ),
    (
        "build the blob path from the tag rather than the digest",
        "    format!(\"/v2/{}/blobs/{}\", repository.as_str(), digest.as_str())",
        "    format!(\"/v2/{}/blobs/latest\", repository.as_str())",
        "la_ruta_de_un_blob_viene_de_las_dos_mitades_comprobadas",
    ),
]

# R2.F.5 on the wire. A unit row can show that a comparison is written; only a
# socket can show that the comparison is reached before the caller can install
# anything, and that the bytes that were refused really did arrive.
BLOB_WIRE_MUTATIONS = [
    (
        "hand the caller the lossy text form of the blob",
        "            bytes: outcome.body,",
        "            bytes: String::from_utf8_lossy(&outcome.body).into_owned().into_bytes(),",
        "un_blob_que_cumple_su_digest_llega_como_sono_sus_bytes",
    ),
    (
        # The whole method's purpose, deleted in one line. Everything else
        # still works: the request goes out, the token is spent, the 200 is
        # read. A registry that answers with different bytes is believed.
        "return the blob without comparing it to the digest asked for",
        "        let found = ContentDigest::of(&outcome.body);\n        if found != *digest {",
        "        let found = ContentDigest::of(&outcome.body);\n        if false {",
        "un_blob_que_no_cumple_su_digest_no_se_instala",
    ),
    (
        # The one a client that has read the Docker Registry spec is tempted to
        # write. `Docker-Content-Digest` is the registry's *claim* about what it
        # sent, and taking it is a closed loop: a registry that answers with the
        # wrong bytes and asserts the digest that was asked for agrees with
        # itself, with the request and with the manifest. Only hashing the body
        # is not circular.
        "believe the registry's own digest header instead of hashing the body",
        "        let found = ContentDigest::of(&outcome.body);",
        "        let found = outcome\n            .headers\n            .get(reqwest::header::HeaderName::from_static(\"docker-content-digest\"))\n            .and_then(|v| v.to_str().ok())\n            .and_then(|v| ContentDigest::parse(v).ok())\n            .unwrap_or_else(|| ContentDigest::of(&outcome.body));",
        "el_digest_que_el_registry_afirma_en_una_cabecera_no_sustituye_al_hash",
    ),
]


def run_phase(path: Path, prefix: str, mutations: list, title: str) -> tuple[int, dict, list]:
    """Apply `mutations` to one file and return the five-bucket tally.

    A snippet this harness cannot find exactly once is a defect in the harness,
    not a result about the code, and it has its own bucket for that reason.
    """
    original = path.read_text()
    buckets = {
        "red": 0,
        "compiler-refused": 0,
        "green (SURVIVOR)": 0,
        "measured nothing": 0,
        "harness error": 0,
    }
    problems: list = []
    f.TEST_PREFIX = prefix
    try:
        for label, old, new, test in mutations:
            if original.count(old) != 1:
                buckets["harness error"] += 1
                problems.append(
                    (label, test, f"snippet counts {original.count(old)}, want 1 -- harness defect")
                )
                print(f"SKIP  {label!r}: snippet is not unique ({original.count(old)})", flush=True)
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


# (prefix, mutations, phase title)
PHASES = [
    (UNIT, REFERENCE_MUTATIONS, "R2.F.2 reference"),
    (UNIT, QUERY_MUTATIONS, "R2.F.2 token query"),
    (WIRE, LOOP_MUTATIONS, "R2.F.2 the loop"),
    (UNIT, KEY_MUTATIONS, "R2.F.4 cache key and clock"),
    (WIRE, CACHE_WIRING_MUTATIONS, "R2.F.4 cache on the wire"),
    (UNIT, DIGEST_MUTATIONS, "R2.F.5 the content address"),
    (WIRE, BLOB_WIRE_MUTATIONS, "R2.F.5 the check on the wire"),
]


def main() -> int:
    f.CARGO_TARGET = "--lib"
    f.PACKAGE = "asv-connector-http"
    f.MUTATIONS[:] = REFERENCE_MUTATIONS
    f.STS = CLIENT

    total = sum(len(m) for _, m, _ in PHASES)
    print(f"# falsifying R2.F.2, R2.F.4 and R2.F.5 with {total} mutations across {len(PHASES)} phases\n")

    tally = {}
    problems = []
    for index, (prefix, mutations, title) in enumerate(PHASES, start=1):
        f.STS = CLIENT
        print(f"## phase {index} -- {title} ({CLIENT.relative_to(f.REPO)})")
        _, buckets, found = run_phase(CLIENT, prefix, mutations, title)
        tally[title] = buckets
        problems += found
        print()

    merged = {}
    for buckets in tally.values():
        for key, value in buckets.items():
            merged[key] = merged.get(key, 0) + value
    assert sum(merged.values()) == total, (merged, total)

    print(f"mutations: {total}  (the five buckets partition the run)")
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
