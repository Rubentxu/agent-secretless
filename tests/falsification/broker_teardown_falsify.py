#!/usr/bin/env python3
"""Falsifying the claim that a broker-spawning row takes its daemon with it.

`concurrent_connections_do_not_queue.rs` shipped three rows that spawn a real
`asv-brokerd`. The first version of that file bound the daemon to a bare
`std::process::Child`, and `Child` has **no** `Drop` impl that terminates the
child — dropping one closes the handle and the daemon keeps serving. Measured:
25 live `asv-brokerd` on the host, every one of them an `asv-concurrent-*`.

The disturbing half is what the suite said about it. With the guard deleted the
three rows still report `ok. 3 passed; 0 failed` and cargo still exits 0. **No
assertion in this repository can see this defect**, so the harness here does not
ask the rows at all. It asks the only thing that can tell the difference: is
there a daemon alive after the target exits?

    python3 broker_teardown_falsify.py guard     # does the guard hold?
    python3 broker_teardown_falsify.py scan      # which files spawn unguarded

`guard` is the falsification proper. It deletes the `kill()` the way a future
edit might, runs the target, and counts survivors. A run that leaves a daemon
behind is `red` — the oracle has bitten. A run that leaves none is `green`, and
because the same mutation is known to leave three, a green here is a statement
about the guard rather than about the absence of a leak.

`scan` is the cheap sibling: it names every broker-spawning test file and
whether that file contains a `kill()` at all, which is enough to point a reader
at the one file that would leak. It is a pointer, not a proof — the honest
static check on this shape is a heuristic, and a heuristic with false positives
gets switched off, which is worth less than nothing.
"""

import re
import subprocess
import sys
import time
from pathlib import Path

import sts_falsify as f

CONCURRENCY = f.REPO / "crates/broker/tests/concurrent_connections_do_not_queue.rs"

# The guard this file exists to check. Deleting it is the mutation: the rows
# keep passing either way, so without this oracle the defect is silent.
KILL = """        let _ = self.0.kill();
        let _ = self.0.wait();"""

# What the mutation leaves behind. `let _ = &self.0;` rather than a deletion so
# the value is still consumed and the change compiles: a mutation the compiler
# refuses measures nothing about the property it attacks.
KILLED_AWAY = """        let _ = &self.0;
        let _ = &self.0;"""

SPAWNERS = re.compile(r'(?:locate|cargo_bin)\(\s*"asv-brokerd"')


def live_brokers() -> int:
    """Daemons of *this* repository, counted by what they were told to serve.

    Matched on the socket path rather than on the bare binary name so that a
    suite running for another project on the same host cannot be mistaken for a
    leak here, and cannot be reported as one when this harness is clean.
    """
    proc = subprocess.run(
        ["ps", "-eo", "args"], capture_output=True, text=True, timeout=60
    )
    return sum(
        1
        for line in proc.stdout.splitlines()
        if "asv-brokerd" in line and "/tmp/asv-" in line and "ps -eo" not in line
    )


def run_target() -> tuple[str, str]:
    """Run the three rows and report what the *process table* said, not cargo.

    The three rows are the thing that has to run: a daemon only exists if a row
    started one, and a fix that stops the rows from spawning anything would pass
    an oracle that counted daemons without ever checking the rows still work.
    """
    before = live_brokers()
    proc = subprocess.run(
        [
            "cargo", "test", "--release", "-p", "asv-broker",
            "--test", "concurrent_connections_do_not_queue",
            "--", "--test-threads=1",
        ],
        cwd=f.REPO, env=f.ENV, capture_output=True, text=True, timeout=1200,
    )
    out = proc.stdout + proc.stderr
    if "error[E" in out or "error: could not compile" in out:
        return "refused", out
    ran = re.search(r"running (\d+) tests?", out)
    passed = re.search(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed", out)
    if not ran or not passed or int(ran.group(1)) != 3:
        return "unreadable", out
    if int(passed.group(2)) != 0:
        # The rows themselves failed. That is a different failure than the one
        # this harness exists to find, and calling it a caught mutation would
        # credit the oracle for a defect it never observed.
        return "rows-red", out
    # Give the kernel a moment to reap: the row drops the guard at the end of
    # the process, and `wait()` is what turns that into a reaped child.
    for _ in range(20):
        time.sleep(0.25)
        after = live_brokers()
        if after <= before:
            return "green", f"{before} before, {after} after"
    return "red", f"{before} before, {live_brokers()} after: the target left a daemon alive"


def guard() -> int:
    """Delete the guard, run the target, and see whether the oracle notices."""
    original = CONCURRENCY.read_text()
    if KILL not in original:
        print(f"!! {KILL!r} is not in {CONCURRENCY.name}; the guard moved")
        return 1
    print(
        "# falsifying the teardown guard in "
        f"{CONCURRENCY.relative_to(f.REPO)} with 1 mutation\n"
        "# oracle: live asv-brokerd after the target exits, not cargo's exit code\n"
    )
    CONCURRENCY.write_text(original.replace(KILL, KILLED_AWAY))
    try:
        verdict, detail = run_target()
    finally:
        CONCURRENCY.write_text(original)

    if verdict == "red":
        print(f"red     the guard was deleted and the oracle saw it ({detail})")
        print("\nthe guard is load-bearing: nothing else in the suite can see this.")
        return 0
    if verdict == "green":
        print(f"survivor the guard was deleted and the oracle saw nothing ({detail})")
        return 1
    print(f"{verdict}  {detail}")
    return 1


def scan() -> int:
    """Name every file that spawns this repository's broker and whether it kills."""
    files = sorted((f.REPO / "crates").glob("*/tests/**/*.rs"))
    print(f"broker-spawning test files under crates/*/tests:\n")
    unguarded = []
    for path in files:
        text = path.read_text()
        if not SPAWNERS.search(text):
            continue
        kills = text.count(".kill()")
        mark = "kills" if kills else "NO KILL"
        if not kills:
            unguarded.append(path)
        print(f"  {path.relative_to(f.REPO)}  — {kills} kill() call(s) [{mark}]")
    print()
    if unguarded:
        print(f"{len(unguarded)} file(s) spawn this broker without a kill():")
        for path in unguarded:
            print(f"  {path.relative_to(f.REPO)}")
        return 1
    print("every file that spawns the broker also kills it")
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "guard"
    if mode == "guard":
        return guard()
    if mode == "scan":
        return scan()
    print(f"unknown bucket {mode!r}; expected one of: guard, scan")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())