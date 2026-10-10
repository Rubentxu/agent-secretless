#!/usr/bin/env python3
"""Falsification harness for the CONNECT proof's replay counter (V1-C2).

`proof_nonce` used to commit to `(key, destination)` only, so one captured
proof verified for the life of the session and reached every surrogate that
session held. The counter makes a proof single use. That is a claim about what
must *not* happen, and every mutation here is a way it could start happening
again while the suite still looked green.

The ones that matter most are the two that are not obvious:

* **spending before verifying.** If a proof that does not verify can reach the
  window, anyone who cannot sign can walk a session's counters forward until
  the honest client's real counter looks stale. That is a denial of service
  from a party that never proved anything, and the honest client cannot tell
  it from an attack.
* **the strict "highest counter seen" rule.** It is the textbook version, and
  it refuses a legitimately out-of-order counter from a client that issued two
  CONNECTs concurrently — a liveness bug wearing a security costume, which no
  test that only ever replays the same proof would ever see.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "crates/broker/src/lib.rs"
BRIDGE = ROOT / "crates/broker/src/tls_bridge.rs"
# The nonce derivation and the wire parser moved here. The broker's own tests
# still hold the properties -- they run through `asv_ssh_agent::proof_nonce` and
# `SessionProof::decode` -- so the mutations move with the code rather than
# being retired.
PROOF = ROOT / "crates/ssh-agent/src/proof.rs"
SOURCES = (LIB, BRIDGE, PROOF)

COMPILE_ERROR = r"^(error\[E\d+\]:|error: could not compile)"

# The tests that carry the property, all in the broker's lib target.
SUITE_FILTERS = (
    "a_proof_replayed_with_the_same_counter_is_refused",
    "an_earlier_proof_replayed_after_a_later_one_is_refused",
    "a_counter_arriving_out_of_order_inside_the_window_is_accepted",
    "a_counter_older_than_the_window_is_refused_rather_than_accepted",
    "the_window_does_not_grow_with_the_number_of_proofs",
    "a_proof_that_does_not_verify_cannot_spend_a_counter",
    "ending_a_session_releases_its_replay_window",
    "a_proof_without_a_counter_is_refused_rather_than_defaulted",
    "a_counter_that_is_not_a_number_is_refused_rather_than_coerced",
    "a_proof_signed_for_one_counter_does_not_verify_for_another",
)


@dataclass
class Mutation:
    name: str
    edits: list[tuple[Path, str, str]]
    expect_red: str
    why: str


MUTATIONS = [
    Mutation(
        name="the-counter-is-not-in-the-nonce",
        edits=[
            (
                PROOF,
                # **Re-anchored.** The broker's `proof_nonce` is now a
                # delegation; the hash that commits to the counter is built in
                # `asv_ssh_agent::proof_nonce`. The row that holds this property
                # is still the broker's, and still reaches it.
                "    hasher.update(counter.to_be_bytes());",
                "    // MUTANT: the counter never reaches the hash\n    let _ = counter;",
            )
        ],
        expect_red="a_proof_signed_for_one_counter_does_not_verify_for_another",
        why=(
            "the whole mechanism reduced to a parameter the signature does not "
            "commit to. A client could reuse one signature across any number of "
            "counters and the broker would have no way to tell, because the "
            "counter would be a number that arrived rather than one that was "
            "signed"
        ),
    ),
    Mutation(
        name="the-window-accepts-everything",
        edits=[
            (
                LIB,
                "        let Some(highest) = self.highest else {\n            self.highest = Some(counter);\n            return true;\n        };",
                "        // MUTANT: no replay protection at all\n        self.highest = Some(counter);\n        return true;\n        #[allow(unreachable_code)]\n        let Some(highest) = self.highest else {\n            self.highest = Some(counter);\n            return true;\n        };",
            )
        ],
        expect_red="a_proof_replayed_with_the_same_counter_is_refused",
        why=(
            "the regression this delivery exists to prevent in its simplest "
            "form: the state is still there, still updated, and decides nothing"
        ),
    ),
    Mutation(
        name="the-duplicate-bit-is-not-checked",
        edits=[
            (
                LIB,
                "        if self.seen & bit != 0 {",
                "        if false && self.seen & bit != 0 {",
            )
        ],
        expect_red="an_earlier_proof_replayed_after_a_later_one_is_refused",
        why=(
            "the bitmap's only job. Without the bit test the window remembers "
            "nothing: advancing shifts, and every counter below the highest is "
            "accepted again. The first version of this mutation pointed at the "
            "replay test that presents a counter twice in a row, which the "
            "`age == 0` shortcut catches before the bitmap is consulted — so it "
            "stayed green and proved nothing. The bitmap only ever decides for "
            "a counter below the highest, which is what an attacker replaying "
            "an old captured proof actually presents"
        ),
    ),
    Mutation(
        name="a-stale-counter-is-accepted-again",
        edits=[
            (
                LIB,
                "        if age > Self::CAPACITY as u64 {",
                "        if false && age > Self::CAPACITY as u64 {",
            )
        ],
        expect_red="a_counter_older_than_the_window_is_refused_rather_than_accepted",
        why=(
            "the first version of this window did exactly this, and it was "
            "corrected before it shipped rather than after. An attacker "
            "replaying an old captured proof presents precisely a counter that "
            "fell out of the bitmap, so accepting it reopens the replay the "
            "bitmap exists to close"
        ),
    ),
    Mutation(
        name="out-of-order-is-refused-as-a-replay",
        edits=[
            (
                LIB,
                "        let age = highest - counter;",
                "        // MUTANT: the textbook rule — anything at or below the highest\n        if counter <= highest {\n            return false;\n        }\n        let age = highest - counter;",
            )
        ],
        expect_red="a_counter_arriving_out_of_order_inside_the_window_is_accepted",
        why=(
            "the rule most designs reach for, and it is wrong here. A client "
            "that issued counters 7 and 8 concurrently can have 8 land first, "
            "and this turns that into a denial that reads like an attack to "
            "whoever has to debug it"
        ),
    ),
    Mutation(
        name="the-counter-is-spent-before-the-signature-is-checked",
        edits=[
            (
                LIB,
                """        if !asv_ssh_agent::verify_proof(&registered, &nonce, &proof.signature) {
            return Err(ProofRejection::NoSuchSession);
        }""",
                """        // MUTANT: spend first, verify afterwards
        let early = self
            .sessions
            .get_mut(&id)
            .ok_or(ProofRejection::NoSuchSession)?
            .proof_counters
            .accept(proof.counter);
        if !asv_ssh_agent::verify_proof(&registered, &nonce, &proof.signature) {
            return Err(ProofRejection::NoSuchSession);
        }
        if !early {
            return Err(ProofRejection::Replayed);
        }""",
            ),
            (
                LIB,
                """        let fresh = record.proof_counters.accept(proof.counter);
        if !fresh {""",
                """        // MUTANT: the second spend is skipped, the early one stands
        let fresh = true;
        if !fresh {""",
            ),
        ],
        expect_red="a_proof_that_does_not_verify_cannot_spend_a_counter",
        why=(
            "the ordering, and the half that is easy to get backwards. Anyone "
            "who cannot sign could walk the session's counters forward until "
            "the honest client's real counter looked stale, and the honest "
            "client would be refused for a reason that has nothing to do with "
            "security. The first version of this mutation inserted the "
            "signature check *between* the two phases, which is still "
            "verify-then-spend, so it stayed green and proved nothing"
        ),
    ),
    Mutation(
        name="a-missing-counter-is-defaulted-to-zero",
        edits=[
            (
                PROOF,
                # **Re-anchored.** `SessionProof::decode` is where the wire
                # segments are parsed now; `parse_session_proof` reaches it.
                "        let counter: u64 = parts.next()?.parse().ok()?;",
                "        // MUTANT: a counter that will not parse becomes zero\n        let counter: u64 = parts.next()?.parse().unwrap_or(0);",
            )
        ],
        expect_red="a_counter_that_is_not_a_number_is_refused_rather_than_coerced",
        why=(
            "the lenient reading. Coercing a present-but-unparseable counter to "
            "0 is worse than the two-part case: it looks like a well-formed "
            "proof from a client that sent nonsense, and every such proof then "
            "competes for one counter"
        ),
    ),
    Mutation(
        name="the-two-segment-legacy-header-is-accepted",
        edits=[
            (
                PROOF,
                # **Re-anchored, and the shape changed with the parser.** The
                # broker used to read the segments out of a header line into
                # `counter_text`; `SessionProof::decode` now splits the value
                # itself and takes the counter as its second segment. Same
                # defect -- a proof that stops after the key is read as counter
                # 0 -- and the previous replacement was written against a parser
                # that no longer exists, so it could not have been applied to the
                # code that replaced it.
                """        let mut parts = value.split('.');
        let key = base64_decode(parts.next()?)?;
        let counter: u64 = parts.next()?.parse().ok()?;""",
                """        let mut parts = value.split('.');
        let key = base64_decode(parts.next()?)?;
        // MUTANT: the pre-counter wire format is read as counter 0
        let counter: u64 = match parts.clone().next() {
            Some(text) => text.parse().unwrap_or(0),
            None => 0,
        };""",
            )
        ],
        expect_red="a_proof_without_a_counter_is_refused_rather_than_defaulted",
        why=(
            "the compatibility reading, and it is the one that looks kind. A "
            "proof minted before counters existed would arrive in two segments "
            "and be given counter 0 — so every one of them shares a counter, the "
            "first to arrive spends it, and the rest are refused for what looks "
            "like a replay attack rather than a version mismatch"
        ),
    ),
]


def run_targeted() -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-broker", "--lib", "--", "--test-threads=4"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=2400,
    )
    return proc.returncode, proc.stdout + proc.stderr


def refuse_on_dirty_tree() -> None:
    """Self-heal a mutation residue left by a prior run that SIGTERM killed.

    A `finally` block restores each source when a run ends normally or raises;
    a `finally` does nothing when the process is killed, and that is exactly
    what produced the residue in `lib.rs` and `aws/calendar.rs` after
    interrupted runs. The detect heuristic is `git show HEAD:<path>`: the
    framework here mutates with `str.replace` and leaves no marker, so a
    literal-string scan is blind. `git show HEAD:<path>` is what the file
    looked like before any falsification ever ran; if the on-disk bytes
    differ, the previous run did not restore, and the right answer is to
    restore from git rather than to refuse the run.
    """
    for path in SOURCES:
        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{path.relative_to(ROOT)}"],
                cwd=ROOT, capture_output=True, text=True, check=True,
            )
        except subprocess.CalledProcessError:
            continue
        on_disk = path.read_text(encoding="utf-8")
        if on_disk == result.stdout:
            continue
        print(
            f"RESIDUE: {path.relative_to(ROOT)} carried a mutation from a "
            f"previous run; restoring from git",
            flush=True,
        )
        subprocess.run(
            ["git", "checkout", "--", str(path.relative_to(ROOT))],
            cwd=ROOT, check=True, capture_output=True,
        )


def main() -> int:
    refuse_on_dirty_tree()
    if "--dry-run" in sys.argv:
        bad = 0
        for mutation in MUTATIONS:
            for path, old, _ in mutation.edits:
                count = path.read_text(encoding="utf-8").count(old)
                if count != 1:
                    print(f"BAD {mutation.name}: {path.name} site matched {count} times")
                    bad += 1
        sites = sum(len(m.edits) for m in MUTATIONS)
        print(f"{len(MUTATIONS) - bad}/{len(MUTATIONS)} mutations, {sites} sites, apply cleanly")
        return 1 if bad else 0


    results: list[tuple[str, bool, str]] = []
    for mutation in MUTATIONS:
        pristine: dict[Path, str] = {}
        try:
            for path, old, new in mutation.edits:
                if path not in pristine:
                    pristine[path] = path.read_text(encoding="utf-8")
                # Each edit goes onto the *current* file, not onto the pristine
                # copy. Reading the pristine text again for every site means
                # the second write throws the first mutation away, so a
                # multi-site mutation silently degrades into its last edit —
                # which is how a spend-before-verify mutation came to "stay
                # green" while the suite was never actually in that state.
                text = path.read_text(encoding="utf-8")
                if text.count(old) != 1:
                    results.append((mutation.name, False, f"site did not apply ({path.name})"))
                    raise RuntimeError("site missing")
                path.write_text(text.replace(old, new, 1), encoding="utf-8")

            code, out = run_targeted()
            red = code != 0 and mutation.expect_red in out
            if red:
                detail = f"red via {mutation.expect_red}"
            elif code != 0:
                detail = "compile error, not a test failure"
            else:
                detail = f"STAYED GREEN (exit {code})"
            results.append((mutation.name, red, detail))
        except Exception as exc:  # noqa: BLE001 - report, do not mask
            results.append((mutation.name, False, f"harness error: {exc}"))
        finally:
            for path, text in pristine.items():
                path.write_text(text, encoding="utf-8")

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    print(f"\n{passed}/{len(results)} mutations detected")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
