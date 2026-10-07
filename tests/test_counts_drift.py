#!/usr/bin/env python3
"""Falsification for scripts/check-test-counts.py.

The guard's whole claim is that a hand-transcribed count can no longer be wrong
without something saying so. A guard that has only ever agreed with its input
has not been shown to be able to disagree, so every branch below feeds it a run
it must refuse, and the last case feeds it the genuine logs to show it still
agrees.

The mutated inputs are copies in a temporary directory. The repository's own
logs are never touched: the point is to move the numbers, not to damage an
artefact.

Run:

    python3 tests/test_counts_drift.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GUARD = REPO / "scripts" / "check-test-counts.py"

ONE_OK = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
ONE_IGNORED = "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n"
ONE_FAILED = "test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
TWO_SKIPPED = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out\n"
TWO_PASSED_TWO_SKIPPED = "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out\n"


def run(debug: str, release: str, **flags: object) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "debug.log"
        r = Path(tmp) / "release.log"
        d.write_text(debug, encoding="utf-8")
        r.write_text(release, encoding="utf-8")
        cmd = [sys.executable, str(GUARD), "--debug", str(d), "--release", str(r)]
        for key, value in flags.items():
            cmd += [f"--{key.replace('_', '-')}", str(value)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr


def expect(name: str, rc: int, out: str, *, should_pass: bool, needle: str = "") -> None:
    ok = (rc == 0) if should_pass else (rc != 0 and needle in out)
    verdict = "PASS" if ok else "FAIL"
    print(f"  {verdict}  {name}")
    if not ok:
        print(f"        rc={rc} output={out.strip()[:400]!r}")
    if not ok:
        raise SystemExit(1)


def main() -> int:
    print("scripts/check-test-counts.py falsification")
    expect(
        "a run with no failures is accepted",
        *run(ONE_OK, ONE_OK),
        should_pass=True,
    )
    expect(
        "a block reporting FAILED is refused even when the counts look closed",
        *run(ONE_OK, ONE_FAILED),
        should_pass=False,
        needle="failed test",
    )
    expect(
        "a failed count hidden behind an ok verdict is still refused",
        *run(ONE_OK, ONE_OK + ONE_FAILED),
        should_pass=False,
        needle="failed test",
    )
    expect(
        "profiles that enumerate different sets are refused",
        *run(ONE_OK, ONE_OK + ONE_OK),
        should_pass=False,
        needle="different sets",
    )
    expect(
        "a filtered count with no matching --skip is refused",
        *run(ONE_OK, ONE_OK, release_skips=2),
        should_pass=False,
        needle="--skip",
    )
    expect(
        # Both sides skip the same two, so both enumerate 5. The first version
        # of this case had 3 on one side and 5 on the other and expected a pass:
        # the guard was right and the case was wrong, which is the third time in
        # this block that the weaker assertion was mine.
        "a matching --skip count is accepted",
        *run(TWO_SKIPPED, TWO_SKIPPED, debug_skips=2, release_skips=2),
        should_pass=True,
    )
    expect(
        "an enumerated total the documents do not claim is refused",
        *run(ONE_OK, ONE_OK, expect_enumerated=9999),
        should_pass=False,
        needle="different tree",
    )
    expect(
        "a log with no test results at all is refused rather than read as zero",
        *run("", ONE_OK),
        should_pass=False,
        needle="not a run",
    )
    # The shape this repository actually has: debug carries one row ignored that
    # release asserts, and release carries two --skip filters debug does not.
    # Both enumerate four, and the gate must say so rather than call it drift.
    expect(
        "one ignored row on one side and two skip filters on the other reconcile",
        *run(ONE_IGNORED, TWO_PASSED_TWO_SKIPPED, release_skips=2),
        should_pass=True,
    )
    print("all falsifications behaved as required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
