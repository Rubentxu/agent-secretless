#!/usr/bin/env python3
"""Falsification harness for the production CONNECT wiring (V1-C2).

Every mutation here targets a way the wiring could be *present and useless*.
That is the whole failure class this cycle is about: the first version of
`main.rs` handed the listener a fresh `SessionStore::new()`, which compiled,
bound, accepted, refused every proof, and reported every refusal correctly.

A test that asserted "the listener answers" passes on that code. A test that
asserts *which* session a proof resolves to, and that a live session vanishes
when it ends, does not — and the mutations below are the ways a future edit
could get back to "it looks alive and can never work" without anyone noticing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "crates/broker/src/connect_runtime.rs"
BRIDGE = ROOT / "crates/broker/src/tls_bridge.rs"
LIB = ROOT / "crates/broker/src/lib.rs"
SUITE = "connect_runtime_wiring"

COMPILE_ERROR = r"^(error\[E\d+\]:|error: could not compile)"


@dataclass
class Mutation:
    """One way the wiring could be present and useless.

    `edits` is a list rather than one site because a control can be made of two
    halves that each compensate for the other. Proof resolution is exactly
    that shape: the blob comparison and the choice of which key the signature
    is verified against. Mutating either alone changes nothing observable, so
    neither looks load-bearing and a mutation run over them separately reports
    a suite with no hole in it. The mutation that matters breaks both at once.
    """

    name: str
    edits: list[tuple[Path, str, str]]
    expect_red: str
    why: str


MUTATIONS = [
    Mutation(
        name="the-listener-resolves-nothing-at-all",
        edits=[
            (
                RUNTIME,
                # **Re-anchored.** The port no longer calls a free function; it
                # implements `SessionProofs::authenticate` and delegates to
                # `SessionStore::authenticate` under the store's own guard. Same
                # defect, current spelling: a proxy wired to a store it never
                # reads binds, accepts, refuses every proof and reports every
                # refusal correctly.
                "        crate::SessionStore::authenticate(&mut store, proof, target)",
                """        let _ = (&store, proof, target);
        // MUTANT: the port never consults the store it was given
        Err(crate::ProofRejection::NoSuchSession)""",
            )
        ],
        expect_red="the_shared_store_resolves_a_proof_and_an_empty_one_cannot",
        why=(
            "the shape of the wiring bug this cycle nearly shipped: a proxy wired to "
            "a store it never reads binds, accepts, refuses every proof and reports "
            "every refusal correctly. Every symptom of a working listener, none of "
            "the substance. **The literal `main.rs` line is not what this mutates** — "
            "an integration test does not build the binary, so that line is covered "
            "by the mirrored construction in the suite, not here. Recorded rather "
            "than papered over"
        ),
    ),
    Mutation(
        name="proof-resolution-becomes-self-authenticating",
        edits=[
            (
                LIB,
                # **Re-anchored.** The comparison moved into the `find_map`
                # closure, so it is indented at 16 and names `proof.key` rather
                # than a free `presented_key`. The comment above it says a
                # falsification run already proved this line alone is not what
                # holds the property — which is exactly why this mutation is two
                # edits and not one.
                "                if registered != proof.key {\n                    return None;\n                }\n",
                "                // MUTANT: the presented blob is no longer compared to the\n                // registered one\n",
            ),
            (
                LIB,
                # **Re-anchored, and the shape changed.** Verification is not a
                # `then_some` folded into the lookup any more; it is an early
                # return in its own right. Dropping it means any signature passes.
                "        if !asv_ssh_agent::verify_proof(&registered, &nonce, &proof.signature) {\n            return Err(ProofRejection::NoSuchSession);\n        }",
                "        if !asv_ssh_agent::verify_proof(&proof.key, &nonce, &proof.signature) {\n            return Err(ProofRejection::NoSuchSession);\n        }",
            ),
        ],
        expect_red="a_proof_under_one_key_never_resolves_to_another_session",
        why=(
            "the fatal one, and the reason this harness needed two-site mutations. "
            "The blob comparison and the choice of verification key are two halves "
            "of one control: drop the comparison and the signature is still checked "
            "against each session's own key, so a stranger fails everywhere; verify "
            "against the presented key and the comparison still pins it to a real "
            "session. Either half alone is an equivalent mutant, so a run that only "
            "ever breaks one of them reports a suite with no hole in it. Together "
            "they are a stranger's own key and signature inheriting whichever session "
            "is first in the table — the token authenticating itself, which is the "
            "option ADR-0019 discarded"
        ),
    ),
    Mutation(
        name="a-signature-that-does-not-verify-still-resolves",
        edits=[
            (
                LIB,
                "        if !asv_ssh_agent::verify_proof(&registered, &nonce, &proof.signature) {\n            return Err(ProofRejection::NoSuchSession);\n        }",
                "        // MUTANT: the signature is never checked\n        let _ = (&registered, &nonce);",
            )
        ],
        expect_red="a_matching_blob_with_a_bad_signature_resolves_to_nothing",
        why=(
            "with the blob public, the signature is the whole of authentication. "
            "Removing it turns proof resolution into 'do you know a public string', "
            "which is exactly the option ADR-0019 discarded"
        ),
    ),
    Mutation(
        name="an-ended-session-still-resolves",
        edits=[
            (
                LIB,
                # **Re-anchored, and de-duplicated.** This used to mutate the very
                # same `SessionStore::resolve` line as
                # `the-listener-resolves-nothing-at-all`, with a replacement that
                # also made the port resolve nothing: two names for one
                # measurement, and neither one doing the defect its name claims.
                # Ending a session is now one removal from the table, and
                # `authenticate` refuses precisely by not finding the id — so the
                # removal *is* the window this row is about, and this is what
                # reopens it.
                "        self.sessions.remove(&id).is_some()",
                """        // MUTANT: the session stays in the table, so it still resolves
        self.sessions.contains_key(&id)""",
            )
        ],
        expect_red="an_ended_session_stops_resolving",
        why=(
            "the window a revocation exists to close. The shared store is live state, "
            "so a session the socket path has ended must vanish from proof resolution "
            "too — otherwise a revoked agent can still open a tunnel"
        ),
    ),
    Mutation(
        name="the-published-root-is-not-the-signing-cas-root",
        edits=[(RUNTIME, "        &self.ca.root_der", "        // MUTANT: an empty trust anchor\n        &[]")],
        expect_red="the_leaf_source_publishes_the_root_a_client_must_trust",
        why=(
            "the root is what a client is told to trust. Publishing something other "
            "than the CA that signs the leaves produces a proxy whose every handshake "
            "fails, and the failure looks like a client misconfiguration"
        ),
    ),
    Mutation(
        name="issuance-skips-canonicalisation",
        edits=[
            (
                BRIDGE,
                "    let host = Authority::canonicalize(host)\n        .map_err(|e| LeafError::InvalidHost(e.to_string()))?\n        .as_str()\n        .to_string();",
                "    // MUTANT: the host is used as presented\n    let host = host.to_string();",
            )
        ],
        expect_red="issuance_follows_the_canonical_form_and_refuses_what_it_cannot_repair",
        why=(
            "canonicalisation is what makes 'this host' mean one thing across the "
            "allow-list, the leaf and rustls's server-name check. Without it, "
            "`API.EXAMPLE.TEST` mints a leaf the allow-list never approved and "
            "`localhost` mints a leaf for a bare service name"
        ),
    ),
]


SOURCES = (RUNTIME, BRIDGE, LIB)


def refuse_to_run_on_a_dirty_tree() -> None:
    """Refuse to start if a previous run left a mutation behind.

    This harness was killed mid-run once, and the tree kept
    `let deadline = None` — after which the next run reported a confident
    "site matched 0 times" about a file it had already changed. A `finally`
    covers exceptions and normal exits; it does not cover a signal.
    """
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if "MUTANT" in line:
                print(
                    f"REFUSING: {path.name}:{number} still carries a mutation\n"
                    f"  {line.strip()}\n"
                    "A previous run was interrupted before it could restore the file.\n"
                    "Revert that line before re-running, or every verdict below is\n"
                    "about a tree that was already mutated."
                )
                sys.exit(2)


def run_suite() -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-broker", "--test", SUITE, "--", "--test-threads=4"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    if "--dry-run" not in sys.argv:
        refuse_to_run_on_a_dirty_tree()

    if "--dry-run" in sys.argv:
        bad = 0
        for mutation in MUTATIONS:
            for path, old, _ in mutation.edits:
                count = path.read_text(encoding="utf-8").count(old)
                if count != 1:
                    print(f"BAD {mutation.name}: {path.name} site matched {count} times, expected 1")
                    bad += 1
        sites = sum(len(m.edits) for m in MUTATIONS)
        print(f"{len(MUTATIONS) - bad}/{len(MUTATIONS)} mutations, {sites} sites, apply cleanly")
        return 1 if bad else 0

    results: list[tuple[str, bool, str]] = []
    for mutation in MUTATIONS:
        # Snapshot every file the mutation touches, so the `finally` restores
        # all of them. A two-site mutation reverted on one site is worse than
        # no revert: the next run grades a tree nobody chose.
        # Two maps, deliberately. `pristine` is what gets restored and
        # `working` is what gets edited, because a single map silently stores
        # the *last* mutation of a file rather than the original: the first
        # two-site run left the comparison removed, the next run's site did not
        # match, and the harness reported "site matched 0 times" for a
        # mutation that had nothing wrong with it. The tree was left mutated and
        # nothing said so.
        pristine: dict[Path, str] = {}
        working: dict[Path, str] = {}
        ok_sites = True
        for path, old, new in mutation.edits:
            if path not in pristine:
                pristine[path] = path.read_text(encoding="utf-8")
                working[path] = pristine[path]
            if working[path].count(old) != 1:
                print(f"FAIL {mutation.name}: {path.name} site matched {working[path].count(old)} times")
                ok_sites = False
                break
            working[path] = working[path].replace(old, new)
        if not ok_sites:
            for path, text in pristine.items():
                path.write_text(text, encoding="utf-8")
            return 2
        for path, text in working.items():
            path.write_text(text, encoding="utf-8")
        try:
            code, output = run_suite()
            if code != 0 and re.search(COMPILE_ERROR, output, re.MULTILINE):
                results.append((mutation.name, False, "INDETERMINATE — did not compile"))
                print(f"FAIL {mutation.name}: INDETERMINATE — the suite did not compile")
                for line in re.findall(r"^error.*$", output, re.MULTILINE)[:3]:
                    print(f"    {line}")
                continue
            red = code != 0
            named = re.search(
                rf"test [\w:]*\b{re.escape(mutation.expect_red)} \.\.\. FAILED", output
            )
            if red and not named:
                also = sorted(set(re.findall(r"test ([\w:]+) \.\.\. FAILED", output)))
                note = f"red, but not by the expected test; also failed: {also or 'unknown'}"
                ok = False
            elif red:
                note = f"red via {mutation.expect_red}"
                ok = True
            else:
                note = "GREEN — the suite does not detect this mutation"
                ok = False
            results.append((mutation.name, ok, note))
            print(f"{'ok  ' if ok else 'FAIL'} {mutation.name}: {note}")
        except subprocess.TimeoutExpired:
            results.append((mutation.name, False, "TIMEOUT — hung rather than failed"))
            print(f"FAIL {mutation.name}: the suite hung instead of reporting a failure")
        finally:
            for path, text in pristine.items():
                path.write_text(text, encoding="utf-8")

    print()
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"{passed}/{len(results)} mutations detected")
    if passed != len(results):
        print("\nfailures, with the claim each one undercuts:")
        for name, ok, _ in results:
            if not ok:
                why = next(m.why for m in MUTATIONS if m.name == name)
                print(f"  - {name}: {why}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
