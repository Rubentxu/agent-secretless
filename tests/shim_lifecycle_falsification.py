#!/usr/bin/env python3
"""Mutation runner for the C2.7-A shim lifecycle controls.

Each mutation deletes one part of the stoppable accept loop and names the test
that must notice. Two rules this runner holds itself to, both learned the hard
way on the first attempt at this harness:

1. A wedged suite counts as RED. `a_stopped_shim_releases_its_port` calls
   `stop`, and a stop that cannot return would otherwise hang the run instead
   of failing it. The test bounds `stop` with a channel timeout precisely so
   that a regression is a failure and not a CI stall.

2. The target is restored in a `finally`. A runner killed mid-campaign leaves
   the mutation in the working tree, and the next thing that compiles is a
   source file with a security control commented out.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "crates" / "cli" / "src" / "session_shim.rs"
BACKUP = TARGET.read_text()

# A healthy stop returns in well under a second. 90s is a 90x margin and keeps
# the whole campaign short enough to survive a flaky background task.
PER_MUTATION_TIMEOUT = 90

MUTATIONS = [
    (
        "listener back to blocking accept",
        "        listener.set_nonblocking(true)?;",
        "        // listener.set_nonblocking(true)?;",
        "a_stopped_shim_releases_its_port",
    ),
    (
        "accept loop ignores the stop flag",
        "        while !self.stopping.load(Ordering::SeqCst) {",
        "        loop {",
        "a_stopped_shim_releases_its_port",
    ),
    (
        "stop never sets the flag",
        "        self.stopping.store(true, Ordering::SeqCst);",
        "        // self.stopping.store(true, Ordering::SeqCst);",
        "a_stopped_shim_releases_its_port",
    ),
    (
        "stop never unparks, so the join waits out the park",
        "            worker.thread().unpark();",
        "            // worker.thread().unpark();",
        "a_stopped_shim_releases_its_port",
    ),
    (
        "idle park becomes a spin",
        "                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {\n"
        "                    thread::park_timeout(IDLE_PARK);\n"
        "                }",
        "                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {\n"
        "                    std::hint::spin_loop();\n"
        "                }",
        "an_idle_shim_does_not_spin",
    ),
]


def run_mutation(name, old, new, expect):
    if BACKUP.count(old) != 1:
        return name, f"SKIP (pattern matched {BACKUP.count(old)}x)"
    TARGET.write_text(BACKUP.replace(old, new))
    try:
        proc = subprocess.run(
            ["cargo", "test", "-p", "asv-cli", "--bin", "asv", "session_shim"],
            capture_output=True,
            text=True,
            timeout=PER_MUTATION_TIMEOUT,
            cwd=ROOT,
        )
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return name, "RED (wedged — the stop is not bounded, which is a regression)"

    if "test result: ok" in out:
        return name, "ESCAPED"
    if f"session_shim::tests::{expect} ... FAILED" in out:
        return name, f"RED ({expect})"
    if "error[" in out or "error: could not compile" in out:
        first = next((l for l in out.splitlines() if l.startswith("error")), "compile error")
        return name, f"COMPILE ERROR: {first[:80]}"
    failed = [l.strip() for l in out.splitlines() if l.endswith("FAILED")]
    return name, f"RED (other test): {failed[:2]}"


def main():
    results = []
    try:
        for mutation in MUTATIONS:
            results.append(run_mutation(*mutation))
    finally:
        TARGET.write_text(BACKUP)

    print()
    for name, verdict in results:
        print(f"  {verdict:<62} {name}")
    print()
    bad = [n for n, v in results if v.startswith(("ESCAPED", "COMPILE"))]
    print(f"{len(results) - len(bad)}/{len(results)} mutations turned the suite red")
    if bad:
        print("NOT RED:")
        for n in bad:
            print(f"  - {n}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
