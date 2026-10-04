#!/usr/bin/env python3
"""C1-R, second increment — falsifying the identity **on the wire**.

The first increment made the posture enforced: a broker that is not the
identity its installation declared refuses to start. That is invisible to the
operator, which is the whole reason the M7 residual was a footnote. The field
on the wire is what makes it askable, so it needs the same treatment — a claim
nobody can contradict is a claim nobody can rely on.

    crates/ipc-protocol/src/lib.rs   W1
    crates/broker/src/identity.rs    W3
    crates/cli/src/ipc.rs             W2
    crates/cli/src/doctor.rs         W4

    crates/broker/tests/broker_identity.rs   the wire witnesses
    crates/cli/src/doctor/tests.rs           the three states

## What each row would break if the property were not real

*   **W1** makes `BrokerIdentity::measured` accept `dedicated` instead of
    deriving it. This is the row that justifies deriving it: a broker with no
    declared identity would report itself as a dedicated one, which is the
    claim the entire increment exists to stop being unfalsifiable. It passes
    every test about a broker that *did* declare an identity, because for those
    the hardcoded answer happens to be right.
*   **W2** drops the field where the CLI reads the response. Everything the
    broker says is still true and every trust test still passes; the operator
    simply gets `not_measured` from a broker that measured, because the value
    was lost in translation rather than never taken.
*   **W3** returns `0` for an undeclared broker's uid. This is the mistake the
    increment nearly shipped — `as_measured` originally returned `(0, None)` —
    and `0` reads as root, which is not a rounding of the answer but an
    inversion of it.
*   **W4** renders a shared, undeclared identity as `Warn` instead of `Info`.
    Nothing measured changes; the installation's *status* becomes `Degraded` on
    every development machine, which is the same shape as a check that always
    passes — a signal that carries no information and is therefore not read.

## What this campaign cannot falsify, and says so

**That an operator acts on it.** The remedies name the flags and the tests
assert the flags are named; nothing here observes a human or a deployment
following them. The `Info` state is a judgement about signal value, and a
judgement cannot be made to fail by a mutation — only the three-state
distinction and the status derivation can, and W4 does the latter.

**That a real `getent passwd` answer round-trips.** The declared uid in these
tests is the test process's own, read from `geteuid()`. A deployment whose
declared uid comes from a name lookup is the packaging's claim, and proving it
needs a host with a system account.

Run from the repository root:

    python3 tests/identity_wire_falsification.py
    python3 tests/identity_wire_falsification.py W1 W4
    python3 tests/identity_wire_falsification.py --list
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / "crates" / "ipc-protocol" / "src" / "lib.rs"
IDENTITY = ROOT / "crates" / "broker" / "src" / "identity.rs"
CLI_IPC = ROOT / "crates" / "cli" / "src" / "ipc.rs"
DOCTOR = ROOT / "crates" / "cli" / "src" / "doctor.rs"
BROKER_TEST = ROOT / "crates" / "broker" / "tests" / "broker_identity.rs"
ALL = (PROTOCOL, IDENTITY, CLI_IPC, DOCTOR, BROKER_TEST)

TIMEOUT = 3000


@dataclasses.dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    edits: tuple[tuple[str, str], ...]
    # Which target the row expects to go red. The two suites live in different
    # crates, and running both per row would double the cost of a campaign whose
    # whole cost is the relink.
    suite: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="W1 a dedicated identity is asserted instead of derived",
        path=PROTOCOL,
        edits=(
            (
                "            dedicated: declared_uid == Some(uid),",
                "            dedicated: true,",
            ),
        ),
        # The shared case in the broker suite: a broker with nothing declared
        # would now report itself as dedicated.
        suite="broker",
    ),
    Mutation(
        name="W2 the CLI drops the field reading the response",
        path=CLI_IPC,
        edits=(
            (
                "                identity: *identity,",
                "                identity: None,",
            ),
        ),
        # The three-state test in the CLI: a measured broker reads as
        # `not_measured`, which is a different state and a different sentence.
        suite="cli",
    ),
    Mutation(
        name="W3 an undeclared broker reports uid 0",
        path=IDENTITY,
        edits=(
            (
                "            IdentityVerdict::Undeclared { uid } => (uid, None),",
                "            IdentityVerdict::Undeclared { .. } => (0, None),",
            ),
        ),
        # Named for what it is: `0` reads as root.
        suite="broker",
    ),
    Mutation(
        name="W4 a shared identity degrades the installation",
        path=DOCTOR,
        edits=(
            (
                """                    // `Info`, and this is the state that earned its existence:
                    // a shared uid on an unpackaged deployment is what the
                    // product documents, not a fault in the installation.
                    state: CheckState::Info,""",
                """                    state: CheckState::Warn,""",
            ),
        ),
        # The status assertion, not the state assertion: this row's whole point
        # is that the *installation* changes, and the test that names it is the
        # one that compares `status()` to `Ready`.
        suite="cli",
    ),
)


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    bad = 0
    for m in MUTATIONS:
        text = m.path.read_text()
        for i, (before, _after) in enumerate(m.edits):
            n = text.count(before)
            if n != 1:
                say(f"BAD  {m.name[:48]:48} edit{i}: {n} matches in {m.path.name}")
                bad += 1
    return bad == 0


def run(suite: str) -> tuple[int, str]:
    if suite == "broker":
        cmd = [
            "cargo", "test", "-p", "asv-broker", "--release",
            "--test", "broker_identity", "--", "--test-threads=1",
        ]
    else:
        cmd = [
            "cargo", "test", "-p", "asv-cli", "--release", "--bin", "asv",
            "--", "--test-threads=1",
        ]
    try:
        done = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT,
            env={**os.environ, "TMPDIR": "/var/home/rubentxu/agent-secretless-tmp"},
        )
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    return done.returncode, done.stdout + done.stderr


def residue() -> list[str]:
    return [p.name for p in ALL if p.read_text() != ORIGINAL[p]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("rows", nargs="*", help="row name fragments, e.g. W1 W4")
    args = ap.parse_args()

    if args.list:
        for i, m in enumerate(MUTATIONS, 1):
            say(f"{i:2}. {m.name}  [{m.path.name} -> {m.suite}]")
        return 0

    global ORIGINAL
    ORIGINAL = {p: p.read_text() for p in ALL}

    if not verify_anchors():
        return 1

    wanted = MUTATIONS
    if args.rows:
        picked: list[Mutation] = []
        for arg in args.rows:
            hits = [m for m in MUTATIONS if arg.upper() in m.name.upper()]
            if not hits:
                say(f"no row matches {arg!r}")
                return 1
            picked.extend(hits)
        seen: set[str] = set()
        wanted = [m for m in picked if not (m.name in seen or seen.add(m.name))]
        if not wanted:
            say("no rows selected")
            return 1

    say(f"falsifying {len(wanted)} rows of the identity on the wire")
    say("")
    red = 0
    for m in wanted:
        applied = True
        for before, after in m.edits:
            text = m.path.read_text()
            if text.count(before) != 1:
                say(f"SKIP {m.name}: the anchor is stale")
                applied = False
                break
            m.path.write_text(text.replace(before, after, 1))
        if not applied:
            continue
        try:
            code, out = run(m.suite)
        finally:
            for p in ALL:
                p.write_text(ORIGINAL[p])

        if "error[" in out or "error: could not compile" in out:
            say(f"SKIP {m.name}: the mutation does not compile")
            continue
        if code == 124:
            say(f"KILL {m.name}: the suite did not finish")
            continue
        if code == 0:
            say(f"ESCAPE {m.name}: the suite stayed green")
            continue
        say(f"RED   {m.name}")
        for line in out.splitlines():
            if line.startswith("test ") and "FAILED" in line:
                say(f"      {line.strip()}")
                break
        for line in out.splitlines():
            if "panicked at" in line:
                say(f"      {line.strip()}")
                break
        red += 1

    left = residue()
    if left:
        say("")
        say(f"RESIDUE: {', '.join(left)} are not back to their original contents")
        return 1
    say("no mutation residue in the tree")
    say(f"{red}/{len(wanted)} mutations went red")
    return 0 if red == len(wanted) else 1


if __name__ == "__main__":
    ORIGINAL: dict[Path, str] = {}
    sys.exit(main())
