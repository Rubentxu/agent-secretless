#!/usr/bin/env python3
"""Falsification campaign for the C2.8 tunnel-lifecycle work.

The C2.8 lifecycle slice found three defects in a row, and each of them was
*already covered by a green test*:

1.  `SubstitutionPort` borrowed the surrogate registry, so the broker's lock
    was held for the whole length of every tunnel. One established and idle
    tunnel froze `EndSession` for every peer in the broker, and an `asv run`
    whose child exited with its tunnel open never returned.
2.  `ShutdownSignal::revoke` had no caller outside tests. The mechanism was
    proven by C1.1 — which revokes the signal itself, so it passed against a
    broker that never revokes anything.
3.  `relay_back` never consulted the cancellation source, so a revoke could
    only ever reach a tunnel still reading its first request head. The normal
    state of a live tunnel is *past* that head.

Every row below deletes one of the controls and requires a **named** assertion
to notice. A run only counts if the test goes red *and* says why, which is what
separates "the assertion fired" from "the test broke for another reason".

## Two rules, both learned in this slice

*   `cargo build --workspace` before every run. These tests launch the real
    `asv-brokerd` and the real `asv`. A mutation in a library that only rebuilds
    the test target leaves the binaries stale and the test passes against
    unmutated code — which is how the first run of the earlier campaign
    "passed" everything.

*   Restore in `finally`, from a copy taken before the mutation, and rebuild
    after. A campaign that leaves a mutation behind reports a suite nobody can
    reproduce.

## A hang counts as a detection, and why that is not hypothetical

The original form of defect 1 did not make a test fail — it made the broker
stop answering. An `asv run` sat there for five minutes, the audit chain never
recorded an `end_session`, and the test never came back; it was found by
looking at `/proc`. A campaign that scored a killed run as "the test did not
fail" would have scored the most severe defect in the slice as the mildest.

So a run that has to be killed at the timeout counts, and says so. In practice
L1 does not take that path — the lock is taken *before* the relay, so the
request is never even read and the test goes red at an earlier gate. The
branch is here because the defect it guards against is a hang, and a campaign
that cannot represent a hang cannot certify the fix for one.

Run from the repository root:

    python3 tests/connect_lifecycle_falsification.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 300

WIRING = "connect_session_revocation_wiring"
VERTICAL = "connect_vertical_e2e"
LIFECYCLE = "a_tunnel_does_not_outlive_the_session_that_authorised_it"


@dataclass(frozen=True)
class Target:
    """One test binary that has to notice, and the words it has to say."""

    binary: str
    test: str
    expect: str


@dataclass(frozen=True)
class Mutation:
    name: str
    target: Path
    before: str
    after: str
    targets: list[Target] = field(default_factory=list)


END_SESSION_REVOKE = """                state.shutdown.revoke(session.to_string().as_str());"""

MUTATIONS: list[Mutation] = [
    Mutation(
        name="L1 a lock is held across the relay",
        target=ROOT / "crates/broker/src/connect_runtime.rs",
        before="""        let mut port =
            SubstitutionPort::new(self.surrogates.as_ref(), self.secrets.as_ref(), family, family_name);
        let outcome = tunnel.relay_substituted(&mut port, &mut audit, self.limits)?;""",
        after="""        let mut port =
            SubstitutionPort::new(self.surrogates.as_ref(), self.secrets.as_ref(), family, family_name);
        let _held = self
            .surrogates
            .lock()
            .map_err(|_| BridgeError::Io("the surrogate registry is poisoned".into()))?;
        let outcome = tunnel.relay_substituted(&mut port, &mut audit, self.limits)?;
        drop(_held);""",
        targets=[
            Target(VERTICAL, LIFECYCLE, "the destination never received a request"),
        ],
    ),
    Mutation(
        name="L2 ending a session does not tell the CONNECT path",
        target=ROOT / "crates/broker/src/lib.rs",
        before=END_SESSION_REVOKE,
        after="""                // mutation: the session's tunnels are left up""",
        targets=[
            Target(
                WIRING,
                "ending_a_session_revokes_the_tunnels_it_authorised",
                "the session ended and its tunnels are still up",
            ),
            Target(VERTICAL, LIFECYCLE, "a tunnel outlived the session that authorised it"),
        ],
    ),
    Mutation(
        name="L3 revocation happens before the ownership check",
        target=ROOT / "crates/broker/src/lib.rs",
        before="""            if owner_pid != peer.credentials.pid {
                return Response::Error {
                    code: ErrorCode::Denied,""",
        after="""            state.shutdown.revoke(session.to_string().as_str());
            if owner_pid != peer.credentials.pid {
                return Response::Error {
                    code: ErrorCode::Denied,""",
        targets=[
            Target(
                WIRING,
                "a_refused_end_session_revokes_nothing",
                "a refused `EndSession` still cancelled the session's tunnels",
            ),
        ],
    ),
    Mutation(
        name="L4 revocation is not scoped to a session",
        target=ROOT / "crates/broker/src/connect_listener.rs",
        before="""    pub fn is_revoked(&self, session: &str) -> bool {
        self.revoked
            .lock()
            .map(|s| s.contains(session))
            .unwrap_or(false)
    }""",
        after="""    pub fn is_revoked(&self, session: &str) -> bool {
        self.revoked
            .lock()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }""",
        targets=[
            Target(
                WIRING,
                "ending_one_session_does_not_revoke_another",
                "ending one session cancelled another session's tunnel",
            ),
        ],
    ),
    Mutation(
        name="L5 a broker is born shutting down",
        target=ROOT / "crates/broker/src/lib.rs",
        before="""            shutdown: Arc::new(crate::connect_listener::ShutdownSignal::new()),""",
        after="""            shutdown: {
                let s = crate::connect_listener::ShutdownSignal::new();
                s.stop();
                Arc::new(s)
            }""",
        targets=[
            Target(
                WIRING,
                "a_default_broker_is_serving_and_revoking_nothing",
                "a broker that has not been asked to shut down reports that it has",
            ),
        ],
    ),
    Mutation(
        name="L6 the response relay ignores cancellation",
        target=ROOT / "crates/broker/src/tls_bridge.rs",
        before="""                if let Some(reason) = cancel.cancel_reason(Some(session)) {
                    return Err(BridgeError::Cancelled(reason));
                }
                continue;""",
        after="""                // mutation: a poll tick with nothing to say is simply retried
                continue;""",
        targets=[
            Target(VERTICAL, LIFECYCLE, "a tunnel outlived the session that authorised it"),
        ],
    ),
    Mutation(
        name="L7 the origin never holds the connection at all",
        target=ROOT / "crates/broker/tests/connect_vertical_e2e.rs",
        before="""    fn start_holding() -> Self {
        Self::spawn(1, true)
    }""",
        after="""    fn start_holding() -> Self {
        Self::spawn(1, false)
    }""",
        targets=[
            # Caught at the *first* gate, not the settle window: an origin that
            # answers and closes is gone before the 25 ms poll ever samples
            # `open == 1`. Both are the same assertion in spirit — the tunnel was
            # not there to outlive anything — and it is recorded here because a
            # campaign that names the wrong gate teaches the wrong lesson.
            Target(VERTICAL, LIFECYCLE, "the tunnel was never established"),
        ],
    ),
    Mutation(
        name="L8 the origin gives the connection back early",
        target=ROOT / "crates/broker/tests/connect_vertical_e2e.rs",
        before="""    if holding && served_any {
        // No deadline. From here the connection ends when the tunnel ends and
        // for no other reason, which is what lets `open_connections` answer
        // "is the tunnel still there" instead of "has the timeout fired".
        stream.set_read_timeout(None).ok();
        let mut buf = [0u8; 256];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    }""",
        after="""    if holding && served_any {
        // mutation: the connection is given back after a beat, long enough for
        // the test to observe it open and short enough for the settle window to
        // see it go
        std::thread::sleep(Duration::from_millis(400));
        return;
    }""",
        targets=[
            # This is the one that reaches the settle window. L7 is caught at
            # the first gate, which leaves the second gate unfalsified — and an
            # assertion no mutation can reach is the same decoration this whole
            # campaign exists to catch. So the fixture is mutated to close
            # *slowly* rather than instantly: the poll samples `open == 1`, and
            # only the settle window distinguishes that from a tunnel that
            # outlives its session.
            Target(
                VERTICAL,
                LIFECYCLE,
                "the tunnel did not survive the request that established it",
            ),
        ],
    ),
]


def run(cmd: list[str], timeout: int = TIMEOUT) -> tuple[int | None, str]:
    """Returns (returncode, output). A killed run reports a `None` code."""
    try:
        proc = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as expired:
        out = (expired.stdout or "") + (expired.stderr or "")
        return None, out if isinstance(out, str) else out.decode(errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def build() -> bool:
    rc, out = run(["cargo", "build", "--workspace"], timeout=1200)
    if rc != 0:
        print("FAIL  the workspace did not build")
        print(out[-2000:])
        return False
    return True


def check(mutation: Mutation, target: Target) -> bool:
    rc, test_out = run(
        [
            "cargo",
            "test",
            "-p",
            "asv-broker",
            "--test",
            target.binary,
            "--",
            "--exact",
            "--test-threads=1",
            target.test,
        ]
    )
    if rc is None:
        # L1's shape: the broker stops answering, so nothing ever comes back.
        # A hang is the defect reproducing itself, and it is reported as such
        # rather than as a runner problem.
        print(f"RED   {target.test} [{target.binary}] — hung and was killed")
        print("      the broker stopped answering, which is the defect")
        return True
    if "test result: FAILED" not in test_out:
        print(f"ESCAPED  {target.test} [{target.binary}]: the test stayed green")
        print(test_out[-2000:])
        return False
    if target.expect not in test_out:
        print(f"WRONG  {target.test} [{target.binary}]: red, but not for the expected reason")
        print(f"      expected: {target.expect!r}")
        print(test_out[-2000:])
        return False
    print(f"RED   {target.test} [{target.binary}]")
    print(f"      the named assertion caught it: {target.expect!r}")
    return True


def one(mutation: Mutation) -> bool:
    source = mutation.target.read_text()
    if mutation.before not in source:
        print(f"SKIP  {mutation.name}: the anchor text is not in {mutation.target}")
        return False

    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / mutation.target.name
        shutil.copy2(mutation.target, backup)
        try:
            mutation.target.write_text(source.replace(mutation.before, mutation.after, 1))
            if not build():
                return False
            return all(check(mutation, t) for t in mutation.targets)
        finally:
            mutation.target.write_text(backup.read_text())
            build()


def main() -> int:
    for mutation in MUTATIONS:
        print(f"\n=== {mutation.name}")
    print()
    results = [one(m) for m in MUTATIONS]
    falsified = sum(1 for r in results if r)
    print()
    print(f"{falsified}/{len(MUTATIONS)} mutations went red for the right reason")
    return 0 if falsified == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
