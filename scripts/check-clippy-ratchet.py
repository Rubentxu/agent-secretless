#!/usr/bin/env python3
"""Clippy ratchet: the warning count may go down, never up.

**Why this exists rather than a cleanup.** At v0.34.0 the tree carried 263
clippy warnings under `-D warnings`, 224 of them a single lint
(`needless_pass_by_ref_mut`) firing across the broker's entire `handle()`
surface. Clearing them means rewriting hundreds of public signatures — in a
broker that is scheduled to be reshaped anyway. A cleanup now would be churn
twice: once for the linter and once for the architecture. So the debt stays and
is *held*, not paid, and this file is what holds it.

**What the ratchet does and does not promise.**

- The **total** may never increase. New code that adds warnings fails here,
  which is the property that actually stops the debt growing.
- The baseline may be **lowered** deliberately, with `--update`, when the work
  that removed warnings was worth doing on its own terms. It is never raised.
- "The code I touched this week has no new warnings" is a **discipline, not a
  guard**, and this file does not pretend otherwise. Checking it per module
  needs a diff against a base that does not exist in a repository that gets
  rebased and force-pushed; what this file gives instead is the floor under
  that discipline.

**Why the number is not the point.** A ratchet that fails on 264 rather than 263
is a ratchet nobody trusts by the time it reads 300. The count is a proxy for
"the warning debt is not growing", and the commit that would make this fail
should come with a reason, not with an exception to the baseline.

Run:

    python3 scripts/check-clippy-ratchet.py            # gate: must not increase
    python3 scripts/check-clippy-ratchet.py --update   # lower the baseline
    python3 scripts/check-clippy-ratchet.py --current  # print, fail nothing
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASELINE = REPO / "scripts" / "clippy-baseline.txt"

# `warning: ...` on a line of its own, from the human-readable format. The
# per-crate summary lines (`warning: `asv-vault` (lib) generated 2 warnings`)
# are counted separately and deliberately excluded: they are a restatement of
# the same warnings, and including them would make the number depend on how many
# crates happen to have any.
DIAGNOSTIC = re.compile(r"^warning: (?![^ ]+ \(.*\) generated )\S")

# The same shape, in `--message-format short`, which is what this runs with.
# `path:line:col: warning: text`
SHORT_DIAGNOSTIC = re.compile(r"^[^\s:]+\.(rs|toml)[^\s]*:\d+:\d+: warning: ")


def count() -> int:
    """Run clippy the way the gate runs it and count its warnings.

    **`-D warnings` is not passed on purpose.** With it, clippy exits non-zero on
    the first error and stops reporting, so the count would be a function of
    where the build died rather than of the tree. Counting without promoting
    warnings to errors is the only way to get the total.
    """
    proc = subprocess.run(
        [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--message-format",
            "short",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    # A build that did not run measured nothing, and a ratchet that reports
    # zero on a broken build is worse than no ratchet at all.
    if "error[E" in proc.stdout + proc.stderr or "error: could not compile" in proc.stdout:
        tail = "\n".join(
            line for line in (proc.stdout + proc.stderr).splitlines() if "error" in line
        )[:2000]
        print("check-clippy-ratchet: clippy did not run, so it measured nothing:\n" + tail)
        return -1

    total = 0
    for line in (proc.stdout + proc.stderr).splitlines():
        if SHORT_DIAGNOSTIC.match(line) or DIAGNOSTIC.match(line):
            total += 1
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="write the current count as the new baseline")
    parser.add_argument("--current", action="store_true", help="print the count and fail nothing")
    args = parser.parse_args()

    current = count()
    if current < 0:
        return 1

    if args.current:
        print(f"clippy warnings now: {current}")
        return 0

    if args.update:
        # `--update` is deliberately checked *before* the baseline is required to
        # exist. The first baseline has to be written by this flag, so a check
        # that demanded the file first would make the documented first run
        # impossible -- the same shape as a manifest that claims to keep a
        # binary current and does not.
        baseline = int(BASELINE.read_text().strip()) if BASELINE.is_file() else None
        if baseline is not None and current > baseline:
            print(
                f"check-clippy-ratchet: refusing to raise the baseline from {baseline} to "
                f"{current}.\n"
                f"This script exists to stop the debt growing. If the growth is worth "
                f"having, it belongs in the commit that caused it, with the reason, not "
                f"here."
            )
            return 1
        BASELINE.write_text(f"{current}\n")
        if baseline is None:
            print(
                f"clippy baseline recorded at {current}.\n"
                f"There was no baseline to hold, so this is a measurement rather than a "
                f"concession: run it again without flags and it must pass at this number."
            )
        else:
            print(f"clippy baseline lowered {baseline} -> {current}")
        return 0

    if not BASELINE.is_file():
        print(
            f"check-clippy-ratchet: no baseline at {BASELINE.relative_to(REPO)}.\n"
            f"Run with --update once, deliberately, to record where the tree stands."
        )
        return 1
    baseline = int(BASELINE.read_text().strip())

    print(f"clippy warnings: {current} (baseline {baseline})")
    if current > baseline:
        print(
            f"\nFAIL: the tree carries {current - baseline} warning(s) more than the baseline "
            f"allows.\n"
            f"New warnings are not inherited from the old debt -- they were written by "
            f"code that did not exist when the baseline was set."
        )
        return 1
    if current < baseline:
        print(
            f"\nThe tree is {baseline - current} warning(s) below the baseline. Run with "
            f"--update to hold the line at the new number."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
