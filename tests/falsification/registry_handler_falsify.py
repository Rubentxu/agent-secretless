#!/usr/bin/env python3
"""Falsification for R2.F.3b's registry handler (the broker half).

The declaration campaign falsified the allowlist *as a lookup*. This one
falsifies what the broker does with it: the order of the checks, the resource
Cedar sees, the authority that gets resolved, and the equality between the
credential a surrogate stands for and the credential a registry is served by.

Same five-bucket accounting as the other campaigns here -- red,
compiler-refused, green survivor, measured nothing, and a snippet this harness
could not find, which is a defect in the harness rather than a result about the
code.

**The mutation to read first is `credential != declaration.credential` deleted
entirely.** It compiles, it passes every other row in this file, and it is the
difference between "this session may pull from the registry the operator
declared for its own credential" and "any session holding any surrogate may
pull from any declared registry, with whatever secret that registry is served
by". The declaration says *which credential serves this host*; the surrogate
says *which credential this session was granted*. They are separate statements
and neither implies the other. The connector's `redeem_for` already checks that
the credential's **class** backs `OperationFamily::Registry`, which is a
different question and answers `yes` for both credentials in this vault.

**Two rows are declared structural rather than falsified, and the reasons are
part of the result rather than an excuse for it.**

`a_different_spelling_of_the_declared_host_is_the_same_host` cannot be made red
from this file. By the time the authority reaches the handler it has been
through `Authority::canonicalize`, so the request's spelling and the declared
spelling are the *same value* and there is no second string for a mutation to
divert. The property it pins -- canonicalization is spelling independence, not
approval -- is falsified in `registry_declaration_falsify.py`, where the
comparison still has two operands.

`no_refusal_carries_the_credential` has no mutation either. The broker never
holds the credential's *value* in any of these paths: it holds a `CredentialId`,
and the value only exists inside a `SecretPort` borrow inside the connector. A
mutation that leaked it would have to fetch it first, so the mutation would be
a second bug rather than a demonstration that this one is caught.

`the_written_digest_is_the_digest_of_the_written_bytes` is fixture integrity,
not product: it pins two constants in the test file against each other. It is
kept because it earned its place immediately -- it went red on its first run,
because the digest literal I wrote by hand was not the digest of the bytes.

Run:  python3 registry_handler_falsify.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

MODULE = f.REPO / "crates/broker/src/lib.rs"

# These rows live at the root of an integration test file, so there is no module
# path in front of them and the target is the file rather than the lib.
TEST_PREFIX = ""
CARGO_TARGET = "--test r2f_registry_vertical"
PACKAGE = "asv-broker"

ENV = dict(os.environ)

# (label, old, new, row that must go red)
MUTATIONS = [
    (
        # THE mutation. The grant is two statements and this deletes the check
        # that joins them.
        "stop comparing the surrogate's credential with the declared one",
        "            // surrogate redeems (the shape check `redeem_for` already did) is\n"
        "            // not enough; it says the credential is the right *class*, not that\n"
        "            // it is the right credential.\n"
        "            if credential != declaration.credential {",
        "            // surrogate redeems (the shape check `redeem_for` already did) is\n"
        "            // not enough; it says the credential is the right *class*, not that\n"
        "            // it is the right credential.\n"
        "            if false && credential != declaration.credential {",
        "a_surrogate_for_another_credential_serves_no_registry",
    ),
    (
        # Answers for whatever host is asked, falling back to the first
        # declaration. The allowlist becomes decorative and every row about an
        # undeclared host fails -- which is the point of running them.
        "serve an undeclared registry with the first credential in the vault",
        "        let declaration = self\n"
        "            .registries\n"
        "            .credential_for(&requested)\n"
        "            .ok_or_else(|| {\n"
        "                Box::new(Response::Error {\n"
        "                    code: ErrorCode::Denied,\n"
        "                    message: format!(\n"
        "                        \"this deployment does not declare the registry {requested}\"\n"
        "                    ),\n"
        "                })\n"
        "            })?;",
        "        const FALLBACK: &str = \"3f7c1d92-4a6b-4c1e-9d3f-2b8e5a7c0d14\";\n"
        "        let chosen: Option<CredentialId> = self\n"
        "            .registries\n"
        "            .credential_for(&requested)\n"
        "            .map(|c| *c)\n"
        "            .or_else(|| CredentialId::from_wire(FALLBACK).ok());\n"
        "        let declaration = &chosen.expect(\"the fallback literal always parses\");",
                "an_undeclared_registry_is_refused_before_any_socket",
    ),
    (
        # The repository is the agent's half of the resource. Hardcoding it
        # makes every rule an operator wrote about a repository decorative, and
        # it is invisible to a test that only ever asks for one repository.
        "build the policy resource from a constant repository",
        "                authority: requested.clone(),\n"
        "                repository: repository.as_str().to_string(),",
        "                authority: requested.clone(),\n"
        "                repository: \"library/alpine\".to_string(),",
        "the_requested_repository_is_the_one_the_policy_sees",
    ),
    (
        # A pull answered as a push. Every policy that permits pushes and not
        # pulls would then serve reads, and the two actions -- which exist
        # separately in the schema -- would be decorative.
        "authorize every registry pull with the push action",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::RegistryPull,",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::RegistryPush,",
        "a_policy_that_permits_push_only_refuses_the_pull",
    ),
    (
        # A caller's malformed string is not the registry's failure. Reporting
        # it as `Upstream` tells an agent its call was fine and the peer is
        # unwell, which is the opposite of the truth and the reason the two
        # codes exist.
        "report a malformed reference as an upstream failure",
        "                Err(error) => {\n"
        "                    return Response::Error {\n"
        "                        code: ErrorCode::InvalidRequest,\n"
        "                        message: format!(\"the reference is not an image reference: {error}\"),\n"
        "                    }\n"
        "                }",
        "                Err(error) => {\n"
        "                    return Response::Error {\n"
        "                        code: ErrorCode::Upstream,\n"
        "                        message: format!(\"the reference is not an image reference: {error}\"),\n"
        "                    }\n"
        "                }",
        "a_malformed_reference_is_refused_before_the_socket",
    ),
    (
        # The digest is recomputed from the bytes precisely so the registry is
        # not checked against itself. Hashing something else is a check that
        # cannot fail, which is worse than no check because it looks like one.
        "compute the manifest digest over the wrong bytes",
        "                    let digest = ContentDigest::of(&read.body).to_string();",
        "                    let digest = ContentDigest::of(b\"\").to_string();",
        "the_manifest_digest_is_computed_and_a_lying_header_is_ignored",
    ),
    (
        # The blob arm reaching the registry without asking the declaration.
        # It is the one shape that would make `PullBlob` a hole around
        # `authorize_registry`, and nothing else in the file would catch it.
        "take the blob arm around the declaration",
        "            let declaration = match state.authorize_registry(session, peer, &registry, &repository)\n"
        "            {\n"
        "                Ok(declaration) => declaration,\n"
        "                Err(denial) => return *denial,\n"
        "            };\n"
        "            let credential = match surrogates!(state).redeem_for(\n"
        "                &surrogate,\n"
        "                session,\n"
        "                OperationFamily::Registry,\n"
        "                now_secs(),\n"
        "            ) {\n"
        "                Ok(credential) => credential,\n"
        "                Err(error) => return surrogate_failure(error),\n"
        "            };\n"
        "            // The same equality as above, and for the same reason. A blob is a",
        "            let credential = match surrogates!(state).redeem_for(\n"
        "                &surrogate,\n"
        "                session,\n"
        "                OperationFamily::Registry,\n"
        "                now_secs(),\n"
        "            ) {\n"
        "                Ok(credential) => credential,\n"
        "                Err(error) => return surrogate_failure(error),\n"
        "            };\n"
        "            let declaration = crate::registry_declaration::RegistryDeclaration {\n"
        "                authority: Authority::canonicalize(&registry)\n"
        "                    .expect(\"the manifest arm parsed the same string\"),\n"
        "                credential,\n"
        "            };\n"
        "            // The same equality as above, and for the same reason. A blob is a",
        "a_blob_read_goes_through_the_declaration_too",
    ),
    (
        # An empty declaration file is a deployment that chose nothing, and it
        # refuses everything. Reading it as "no restriction" would make the
        # fail-closed default the fail-open one.
        "read an empty declaration file as no restriction",
        "        let requested = Authority::canonicalize(registry).map_err(|error| {",
        "        if self.registries.is_empty() {\n"
        "            return Ok(crate::registry_declaration::RegistryDeclaration {\n"
        "                authority: Authority::canonicalize(registry)\n"
        "                    .expect(\"canonicalize already refused the malformed host\"),\n"
        "                credential: self\n"
        "                    .credentials\n"
        "                    .iter()\n"
        "                    .next()\n"
        "                    .expect(\"an empty vault cannot mint, so this is unreachable\")\n"
        "                    .id,\n"
        "            });\n"
        "        }\n"
        "        let requested = Authority::canonicalize(registry).map_err(|error| {",
        "an_empty_declaration_refuses_every_registry",
    ),
    (
        # A digest is the only reference whose bytes can be checked, which is
        # why it is its own type in the connector. Accepting any string lets a
        # tag name a blob, and a name is not a check.
        "accept any string as a content digest",
        "            let digest = match ContentDigest::parse(&digest) {\n"
        "                Ok(digest) => digest,\n"
        "                Err(error) => {\n"
        "                    return Response::Error {\n"
        "                        code: ErrorCode::InvalidRequest,\n"
        "                        message: format!(\"the digest is not a sha256 content address: {error}\"),\n"
        "                    }\n"
        "                }\n"
        "            };",
        "            let digest = ContentDigest::of(digest.as_bytes());",
        "a_digest_that_is_not_a_content_address_is_refused",
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> dict:
    """Apply each mutation and tally the five buckets.

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
            print(
                f"SURVIVOR  [{title}] {label}\n      -> {test} stayed GREEN  <-- the finding",
                flush=True,
            )
        elif verdict == "refused":
            buckets["compiler-refused"] += 1
            first = next(
                (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
            )
            print(
                f"ok*   [{title}] {label}\n      -> {test}: refused by the compiler\n         {first}",
                flush=True,
            )
        else:
            buckets["measured nothing"] += 1
            problems.append((label, test, verdict))
            print(f"BAD   [{title}] {label}\n      -> {test}: {verdict}", flush=True)
    assert path.read_text() == original, f"{path} was not restored"
    assert sum(buckets.values()) == len(mutations), (buckets, len(mutations))
    return buckets


def main() -> int:
    f.CARGO_TARGET = CARGO_TARGET
    f.PACKAGE = PACKAGE
    f.TEST_PREFIX = TEST_PREFIX
    f.MUTATIONS[:] = MUTATIONS

    total = len(MUTATIONS)
    print(f"# falsifying the registry handler with {total} mutations\n")
    print(f"## phase 1 -- the broker arm ({MODULE.relative_to(f.REPO)})")
    buckets = run_phase(MODULE, MUTATIONS, "R2.F.3b the handler")
    print()

    print(f"mutations: {total}  (the five buckets partition the run)")
    for name, count in buckets.items():
        print(f"  {name:<22}: {count}")
    print()
    print(
        "  R2.F.3b the handler: "
        + (", ".join(f"{k}={v}" for k, v in buckets.items() if v) or "none")
    )
    return (
        1
        if buckets["green (SURVIVOR)"] or buckets["harness error"] or buckets["measured nothing"]
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())