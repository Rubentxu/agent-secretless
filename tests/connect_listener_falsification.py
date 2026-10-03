#!/usr/bin/env python3
"""Falsification harness for the V1-C2 CONNECT listener suite.

A green test proves nothing until it has been shown to go red for the right
reason. Each mutation below breaks exactly one behaviour the suite claims, and
the run only passes when *every* mutation turns the expected test red.

Design rules, learned the hard way in this repository:

* The mutation must break a **claim the suite makes**, not a line the suite
  happens to execute. Shifting a threshold in an unrelated place and watching
  something fail is not evidence.
* The expected-red test is named up front. A mutation that turns some *other*
  test red is a finding about that other test, reported as such rather than
  quietly accepted.
* Every mutation is reverted in a `finally` block, so an interrupted run cannot
  leave the working tree mutated. That is the failure mode that would make every
  later run meaningless.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "crates/broker/src/tls_bridge.rs"
LISTENER = ROOT / "crates/broker/src/connect_listener.rs"
SUITE = "connect_listener_lifecycle"

# A suite that does not compile exits non-zero without a single failing test,
# and a broken suite would make **every** mutation look detected.
#
# The first version of this pattern was `^error(\[E\d+\])?:`, which also matches
# `error: test failed, to rerun pass ...` — cargo's own line for *a test
# actually failed*. The harness then reported a working detection as
# INDETERMINATE, which is the same class of defect as a guard that overstates
# its coverage: a detector that is confidently wrong in the direction that hides
# work. It is now pinned to the two forms a rustc failure actually takes.
COMPILE_ERROR = r"^(error\[E\d+\]:|error: could not compile)"


@dataclass
class Mutation:
    name: str
    path: Path
    old: str
    new: str
    expect_red: str
    why: str


MUTATIONS = [
    Mutation(
        name="head-deadline-never-armed",
        path=BRIDGE,
        old="let deadline = self.head_deadline.map(|d| Instant::now() + d);",
        new="let deadline: Option<Instant> = None; // MUTANT: deadline dropped",
        expect_red="a_client_that_says_nothing_is_dropped_by_the_head_deadline",
        why=(
            "the listener's whole resource claim: a client that opens a socket and "
            "stays silent must be dropped, not waited on forever"
        ),
    ),
    Mutation(
        name="read-timeout-not-armed-for-deadline-only",
        path=BRIDGE,
        old="""    fn arm_read_timeout(&self, client: &TcpStream) -> std::io::Result<()> {
        if self.cancel.is_some() || self.head_deadline.is_some() {""",
        new="""    fn arm_read_timeout(&self, client: &TcpStream) -> std::io::Result<()> {
        if self.cancel.is_some() { // MUTANT: deadline no longer arms a timeout""",
        # Corrected after the first run. The mutation is caught — but by the
        # bridge-level test, not by the listener test named here on the first
        # attempt. That is the whole reason that test exists: a listener always
        # installs a cancel source, so `is_pollable` is already true without
        # this clause and no listener test can ever reach it. Guessing which
        # test would catch a mutation and writing that guess down is how a
        # falsification run starts reporting its own assumptions as results.
        expect_red="a_head_deadline_alone_stops_a_bridge_from_waiting_forever",
        why=(
            "the deadline is only reachable if the socket read is pollable; without "
            "the timeout the blocking read never returns to check it. The clause "
            "being removed is unreachable from any listener, because the listener "
            "always sets a cancel source first"
        ),
    ),
    Mutation(
        name="shutdown-does-not-cancel-a-session-less-connection",
        path=LISTENER,
        old="""        if self.is_stopped() {
            return Some(CancelReason::Shutdown);
        }
        let session = session?;""",
        new="""        let session = session?;
        if self.is_stopped() {
            return Some(CancelReason::Shutdown);
        }""",
        expect_red="a_signal_cancels_a_connection_that_has_no_session_yet",
        why=(
            "a session-scoped revoke cannot apply before the CONNECT head is read, so "
            "shutdown is the only thing that can drop a silent client. This mutation "
            "leaves shutdown working for tunnelled connections while silently making "
            "the un-tunnelled case un-droppable"
        ),
    ),
    Mutation(
        name="revoke-outranks-shutdown",
        path=LISTENER,
        old="""        if self.is_stopped() {
            return Some(CancelReason::Shutdown);
        }
        let session = session?;
        if self.is_revoked(&session.to_string()) {
            return Some(CancelReason::SessionRevoked);
        }
        None""",
        new="""        let session = session?;
        if self.is_revoked(&session.to_string()) {
            return Some(CancelReason::SessionRevoked);
        }
        if self.is_stopped() {
            return Some(CancelReason::Shutdown);
        }
        None""",
        expect_red="shutdown_wins_over_a_valid_session",
        why=(
            "an operator who stopped the broker must read 'shutdown' in the log. The "
            "mutated code still cancels the tunnel — the tunnel closes either way — "
            "but reports the wrong cause, which is the difference between working "
            "policy and a misleading audit trail"
        ),
    ),
    Mutation(
        name="a-refusal-before-the-tunnel-is-not-reported",
        path=LISTENER,
        old="""                report.record(outcome);""",
        new="""                // MUTANT: a connection with no destination is dropped silently
                if outcome.target.is_some() {
                    report.record(outcome);
                }""",
        expect_red="a_client_that_says_nothing_is_dropped_by_the_head_deadline",
        why=(
            "a listener that cannot say what it discarded is not auditable. The "
            "mutated code serves every client correctly and loses exactly the "
            "connections an operator would most want to see"
        ),
    ),
    Mutation(
        name="every-accept-error-is-fatal",
        path=LISTENER,
        old="""    if shutdown.is_stopped() {
        AcceptFailure::Stop
    } else {
        AcceptFailure::Continue
    }""",
        new="""    let _ = shutdown;
    AcceptFailure::Stop // MUTANT: a failed accept always ends the listener""",
        expect_red="a_transient_accept_failure_does_not_stop_the_listener",
        why=(
            "a host that runs out of file descriptors would take the broker down with "
            "it, and nothing would log a difference — the process is alive and has "
            "simply stopped serving"
        ),
    ),
    Mutation(
        name="an-accept-error-during-shutdown-keeps-the-loop-spinning",
        path=LISTENER,
        old="""    if shutdown.is_stopped() {
        AcceptFailure::Stop
    } else {
        AcceptFailure::Continue
    }""",
        new="""    let _ = shutdown;
    AcceptFailure::Continue // MUTANT: shutdown no longer ends a failing loop""",
        expect_red="an_accept_failure_during_shutdown_stops_the_loop",
        why=(
            "once stopped, the same accept error repeats forever, so continuing is a "
            "loop that spins at full CPU while the broker is going down — the "
            "shutdown that was supposed to free resources is the thing consuming them"
        ),
    ),
]


def refuse_to_run_on_a_dirty_tree() -> None:
    """Refuse to start if a previous run was killed mid-mutation.

    A `finally` block restores the source when a run ends normally or raises.
    It does nothing when the process is killed, and this harness was killed
    once — leaving `deadline = None` in `serve_connect` and making the *next*
    run report "this mutation's site matched 0 times" for a mutation that had
    in fact already been applied to the file it was about to mutate.

    That failure mode is worse than not running at all: it produces a confident
    verdict about a suite that was never exercised. The marker is written into
    every mutation, so its presence is unambiguous.
    """
    for path in (BRIDGE, LISTENER):
        text = path.read_text(encoding="utf-8")
        if "MUTANT" in text:
            for number, line in enumerate(text.splitlines(), 1):
                if "MUTANT" in line:
                    print(
                        f"REFUSING: {path.name}:{number} still carries a mutation\n"
                        f"  {line.strip()}\n"
                        "A previous run was interrupted before it could restore the file.\n"
                        "Revert that line before re-running, or every verdict below is about\n"
                        "a tree that was already mutated."
                    )
                    sys.exit(2)


def run_suite() -> tuple[int, str]:
    """Run both suites this work owns.

    The accept-failure decision is a private function, so its test is a unit
    test inside the module and lives in the lib target; the lifecycle
    properties are integration tests. A harness that ran only the integration
    target reported a mutation of the accept loop as undetected when the test
    catching it was sitting in the other binary.
    """
    output: list[str] = []
    code = 0
    for args in (
        ["cargo", "test", "-p", "asv-broker", "--lib", "--", "--test-threads=4"],
        ["cargo", "test", "-p", "asv-broker", "--test", SUITE, "--", "--test-threads=4"],
    ):
        proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=900)
        output.append(proc.stdout + proc.stderr)
        if proc.returncode != 0:
            code = proc.returncode
    return code, "\n".join(output)


def main() -> int:
    if "--dry-run" not in sys.argv:
        refuse_to_run_on_a_dirty_tree()

    if "--dry-run" in sys.argv:
        # A mutation whose site has drifted will be reported as "green" by a
        # run that never actually mutated anything, which is the most expensive
        # kind of wrong: it costs a full compile per mutation and then claims
        # the suite is weak. Checking the sites first costs nothing.
        bad = 0
        for mutation in MUTATIONS:
            count = mutation.path.read_text(encoding="utf-8").count(mutation.old)
            if count != 1:
                print(f"BAD {mutation.name}: site matched {count} times, expected 1")
                bad += 1
        print(f"{len(MUTATIONS) - bad}/{len(MUTATIONS)} mutation sites apply cleanly")
        return 1 if bad else 0

    results: list[tuple[str, bool, str]] = []
    for mutation in MUTATIONS:
        source = mutation.path.read_text(encoding="utf-8")
        if source.count(mutation.old) != 1:
            print(
                f"FAIL {mutation.name}: the mutation site matched "
                f"{source.count(mutation.old)} times, expected exactly 1. "
                "A mutation that does not apply to exactly one site is not a mutation."
            )
            return 2
        mutated = source.replace(mutation.old, mutation.new)
        mutation.path.write_text(mutated, encoding="utf-8")
        try:
            code, output = run_suite()
            red = code != 0
            if red and re.search(COMPILE_ERROR, output, re.MULTILINE):
                results.append((mutation.name, False, "INDETERMINATE — the suite did not compile"))
                print(f"FAIL {mutation.name}: INDETERMINATE — the suite did not compile, so this "
                      "says nothing about the mutation")
                print("  first compiler error:")
                for line in re.findall(r"^error.*$", output, re.MULTILINE)[:3]:
                    print(f"    {line}")
                continue
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
            mutation.path.write_text(source, encoding="utf-8")

    print()
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"{passed}/{len(results)} mutations detected")
    if passed != len(results):
        print("\nfailures, with the claim each one undercuts:")
        for name, ok, note in results:
            if not ok:
                why = next(m.why for m in MUTATIONS if m.name == name)
                print(f"  - {name}: {why}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
