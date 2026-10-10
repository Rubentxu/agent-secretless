#!/usr/bin/env python3
"""Falsification harness for the CONNECT audit chain (V1-C2).

Every mutation here asks one of three questions:

* does the record still land, and does the class still say why;
* does a client-controlled string reach a durable, exported, hashed artefact; or
* does one reach the operator's log, which is where the measured injection was.

The leak this design exists to prevent arrived twice, and the two guards that
close it are independent on purpose. `parse_connect_target` builds
`BridgeError::Protocol(format!("{authority} has no port"))` from the request
line *before* the session proof is looked at, so that text is whatever an
unauthenticated peer wrote. `refusal_detail` is the guard that keeps it out of
the operator's line; `ChainReport::record` is the guard that keeps a detail out
of the chain whichever way it arrived. Falsifying only one of them proves only
that one, which is why `the-refusal-detail-rides-into-the-chain` and
`the-operator-log-quotes-the-client-after-all` are separate mutations rather
than one mutation checked twice.

A canary test that only asserted "something was recorded" would have passed for
every leak below, and two of these are re-expressions of code that really was
written and really did pass.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "crates/broker/src/connect_runtime.rs"
LISTENER = ROOT / "crates/broker/src/connect_listener.rs"
SUITE = "connect_audit_chain"
SOURCES = (RUNTIME, LISTENER)

COMPILE_ERROR = r"^(error\[E\d+\]:|error: could not compile)"


@dataclass
class Mutation:
    name: str
    edits: list[tuple[Path, str, str]]
    expect_red: str
    why: str


MUTATIONS = [
    Mutation(
        name="the-refusal-detail-rides-into-the-chain",
        edits=[
            (
                RUNTIME,
                "            ConnectionResult::Refused { class, .. } => (*class).to_string(),",
                "            // MUTANT: the detail rides into the chain beside the class\n"
                "            ConnectionResult::Refused { class, detail: why } => format!(\n"
                '                "{class}: {}",\n'
                "                why.as_deref().unwrap_or_default()\n"
                "            ),",
            )
        ],
        expect_red="a_refusal_is_recorded_as_a_class_and_never_quotes_the_detail",
        why=(
            "the leak this whole design exists to prevent, on the surface that is "
            "hashed, exported and shipped. Note what the mutation keeps: the class "
            "still lands, so every assertion about the record still being "
            "readable holds, and the chain keeps verifying. A guard that checked "
            "'a refusal was recorded and the class says why' would be green while a "
            "client chose the bytes"
        ),
    ),
    Mutation(
        name="the-operator-log-quotes-the-client-after-all",
        edits=[
            (
                RUNTIME,
                "        BridgeError::Protocol(_) => None,\n        other => Some(other.to_string()),",
                "        // MUTANT: the provenance rule is gone — every error offers its text\n"
                "        other => Some(other.to_string()),",
            )
        ],
        expect_red="the_detail_is_dropped_for_exactly_the_errors_that_quote_the_client",
        why=(
            "the same bytes, on the surface the measured injection actually landed "
            "on. `refusal_detail` is the *upstream* guard: it decides what text the "
            "listener is willing to hand the reporter at all. Deleting the "
            "provenance rule leaves the chain fine and every other test green, "
            "because the chain test builds its outcomes by hand and never asks "
            "where the detail came from. That is the argument for the two guards "
            "being falsified separately"
        ),
    ),
    Mutation(
        name="every-refusal-is-recorded-as-the-same-class",
        edits=[
            (
                RUNTIME,
                "pub fn refusal_class(error: &BridgeError) -> &'static str {\n    match error {",
                """pub fn refusal_class(error: &BridgeError) -> &'static str {
    if true { // MUTANT: one class for every refusal
        return "refused";
    }
    match error {""",
            )
        ],
        expect_red="distinct_bridge_errors_classify_distinctly",
        why=(
            "an operator who revoked a session and then reads one undifferentiated "
            "class goes looking for a client that misbehaved rather than for the "
            "policy that worked. Recording something is not the same as recording "
            "why. The class is derived from the error's *kind* rather than from its "
            "text precisely so that one arm cannot swallow the rest"
        ),
    ),
    Mutation(
        name="cancellations-are-classified-by-searching-the-message",
        edits=[
            (
                RUNTIME,
                "        crate::tls_bridge::CancelReason::DeadlineElapsed => \"head_deadline\",",
                "        // MUTANT: no arm for the deadline at all\n"
                "        crate::tls_bridge::CancelReason::DeadlineElapsed => \"other\",",
            )
        ],
        expect_red="a_connection_with_no_destination_is_still_recorded",
        why=(
            "the shape this mutation models already happened once, by hand: the "
            "classifier searched `CancelReason`'s Display text, a caller worded the "
            "reason differently, and the chain recorded `other` without anything "
            "failing. The arm is exhaustive now, so the plausible way back is a new "
            "arm folded into a catch-all rather than a match on rendered text"
        ),
    ),
    Mutation(
        name="an-outcome-with-no-destination-is-not-recorded",
        edits=[
            (
                RUNTIME,
                """        match self.log.lock() {
            Ok(mut log) => {""",
                """        if outcome.target.is_none() {
            // MUTANT: a connection that never said where it was going leaves
            // no record at all
            return;
        }
        match self.log.lock() {
            Ok(mut log) => {""",
            )
        ],
        expect_red="a_connection_with_no_destination_is_still_recorded",
        why=(
            "the first version of `ConnectionOutcome` had exactly this defect: a "
            "connection discarded before its destination was parseable produced "
            "no record, so a dropped connection was invisible rather than "
            "recorded. Returning early is the most plausible way to reintroduce it"
        ),
    ),
    Mutation(
        name="the-record-does-not-say-whose-tunnel-it-was",
        edits=[
            (
                RUNTIME,
                "                        session: outcome.session.clone(),",
                "                        // MUTANT: the session is dropped\n"
                "                        session: None,",
            )
        ],
        expect_red="a_completed_tunnel_is_recorded_as_completed",
        why=(
            "a chain that records that a tunnel completed but not whose it was "
            "cannot answer the question it is kept for. `CredentialSubstituted` "
            "carries the session for exactly this reason, and a connection-level "
            "record that omits it leaves the two halves of one event unable to be "
            "joined up afterwards"
        ),
    ),
]


def run_suite() -> tuple[int, str]:
    proc = subprocess.run(
        ["cargo", "test", "-p", "asv-broker", "--test", SUITE, "--", "--test-threads=4"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    return proc.returncode, proc.stdout + proc.stderr


def refuse_on_dirty_tree() -> None:
    """Detect mutations left by a previous interrupted run, and self-heal.

    The mutation runner restores the file in a `finally` block when a run
    ends normally or raises, but a `finally` does nothing when the process
    is killed by SIGTERM (which is what produced the residue this guard
    catches). Restoring from git here turns manual recovery into an
    automatic one, and the next mutation then runs against a clean tree.
    """
    dirty = False
    for path in SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "MUTANT" in line:
                dirty = True
                print(
                    f"RESIDUE: {path.name}:{number} carried a mutation from a previous run; "
                    f"restoring from git"
                )
    if dirty:
        for path in SOURCES:
            subprocess.run(
                ["git", "checkout", "--", str(path)],
                cwd=ROOT, check=True, capture_output=True,
            )


def main() -> int:
    if "--dry-run" not in sys.argv:
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
        working: dict[Path, str] = {}
        ok = True
        for path, old, new in mutation.edits:
            if path not in pristine:
                pristine[path] = path.read_text(encoding="utf-8")
                working[path] = pristine[path]
            if working[path].count(old) != 1:
                print(f"FAIL {mutation.name}: {path.name} site matched {working[path].count(old)} times")
                ok = False
                break
            working[path] = working[path].replace(old, new)
        if not ok:
            for path, text in pristine.items():
                path.write_text(text, encoding="utf-8")
            return 2
        for path, text in working.items():
            path.write_text(text, encoding="utf-8")
        try:
            code, output = run_suite()
            if code != 0 and re.search(COMPILE_ERROR, output, re.MULTILINE):
                results.append((mutation.name, False, "INDETERMINATE"))
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
            results.append((mutation.name, False, "TIMEOUT"))
            print(f"FAIL {mutation.name}: hung")
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
