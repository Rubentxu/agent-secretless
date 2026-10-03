#!/usr/bin/env python3
"""Falsification harness for cancelling an already-established tunnel (V1-C2).

Separate from `connect_listener_falsification.py` because the property is
different in kind. Those mutations break the *lifecycle* — accepting, dropping
a silent client, stopping a loop. These break the *teardown of a tunnel that is
already real*: session proven, TLS terminated, origin connected, and the relay
parked on the client's next request.

A separate file also keeps the runtime honest. The listener harness runs two
fast suites; this one runs `uat_010`, which takes ten seconds of real TLS and
real sockets per run. Merging them would make every mutation pay for the slow
suite and would blur which property each mutation is about.

The mutation that matters most here is the last one. `revoking_an_established_
session_tears_down_its_tunnel` and `shutting_down_tears_down_an_established_
tunnel` are both satisfied by an implementation that kills *every* tunnel the
moment any session is revoked. Those two tests would be green on a broker that
takes down every agent's traffic on the first revocation. The reciprocal test —
another session's tunnel must keep working — is the only thing that closes it,
and a reciprocal is exactly the kind of test that gets left out because the
other two already pass.
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
SUITE = "uat_010_connect_substitution"

# See the identical constant in `connect_listener_falsification.py` for why
# this is not `^error:`. A suite that does not compile must not be mistaken for
# a suite whose tests failed, or every mutation looks detected.
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
        name="revoke-records-nothing",
        path=LISTENER,
        old="""    pub fn revoke(&self, session: &str) {
        if let Ok(mut set) = self.revoked.lock() {
            set.insert(session.to_string());
        }
    }""",
        new="""    pub fn revoke(&self, session: &str) {
        let _ = session; // MUTANT: the revocation is accepted and forgotten
    }""",
        expect_red="revoking_an_established_session_tears_down_its_tunnel",
        why=(
            "the write side of revocation. A broker that logs 'session revoked' and "
            "keeps the tunnel is the worst shape this feature can take: the operator "
            "sees the action they took and the traffic continues anyway"
        ),
    ),
    Mutation(
        name="revocation-is-never-read",
        path=LISTENER,
        old="""    pub fn is_revoked(&self, session: &str) -> bool {
        self.revoked
            .lock()
            .map(|s| s.contains(session))
            .unwrap_or(false)
    }""",
        new="""    pub fn is_revoked(&self, _session: &str) -> bool {
        false // MUTANT: the set is written and never consulted
    }""",
        expect_red="revoking_an_established_session_tears_down_its_tunnel",
        why=(
            "the read side, and the twin of the previous mutation: a revocation store "
            "that is never queried passes every test that only checks the API"
        ),
    ),
    Mutation(
        name="the-relay-never-asks-whether-it-should-stop",
        path=BRIDGE,
        old="        let cancellable = self.cancel.is_some();",
        new="        let cancellable = false; // MUTANT: the relay is not interruptible",
        expect_red="revoking_an_established_session_tears_down_its_tunnel",
        why=(
            "`serve_connect` disarms the read timeout before handing the socket to "
            "rustls, so a tunnel that does not re-arm it is a tunnel no signal can "
            "interrupt. The agent that connects, proves its session and then goes "
            "quiet is the exact shape this exists for"
        ),
    ),
    Mutation(
        name="the-poll-checks-the-clock-but-not-the-signal",
        path=BRIDGE,
        old="""                if let Some(reason) = cancel.cancel_reason(session) {
                    return Err(BridgeError::Cancelled(reason));
                }
                if let Some(dl) = deadline {""",
        new="""                if let Some(dl) = deadline {""",
        expect_red="revoking_an_established_session_tears_down_its_tunnel",
        why=(
            "the same poll can serve a deadline, a revocation, or neither, and the "
            "mistake here is quiet: the loop still spins on every timeout, the code "
            "still reads as interruptible, and only the signal is dropped. A test "
            "that cancels with a deadline set would not see it"
        ),
    ),
    Mutation(
        name="any-revocation-kills-every-tunnel",
        path=LISTENER,
        old="""    pub fn is_revoked(&self, session: &str) -> bool {
        self.revoked
            .lock()
            .map(|s| s.contains(session))
            .unwrap_or(false)
    }""",
        new="""    pub fn is_revoked(&self, _session: &str) -> bool {
        // MUTANT: revocation is global
        !self.revoked.lock().map(|s| s.is_empty()).unwrap_or(true)
    }""",
        expect_red="revoking_another_session_leaves_this_tunnel_working",
        why=(
            "the global kill. Both teardown tests above pass on this code, because the "
            "tunnels do close — they just close for every agent the moment one of them "
            "is revoked, turning a security control into an availability outage that "
            "reads as the control working"
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
                f"{source.count(mutation.old)} times, expected exactly 1."
            )
            return 2
        mutation.path.write_text(source.replace(mutation.old, mutation.new), encoding="utf-8")
        try:
            code, output = run_suite()
            if code != 0 and re.search(COMPILE_ERROR, output, re.MULTILINE):
                results.append((mutation.name, False, "INDETERMINATE — the suite did not compile"))
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
            mutation.path.write_text(source, encoding="utf-8")

    print()
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"{passed}/{len(results)} mutations detected")
    if passed != len(results):
        print("\nfailures, with the claim each one undercuts:")
        for name, ok, note in results:
            if not ok:
                why = next(m.why for m in MUTATIONS if m.name == name)
                print(f"  - {name}: {note}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
