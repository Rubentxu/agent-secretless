#!/usr/bin/env python3
"""Test-count arithmetic over a real run, and a receipt derived from it.

**Why this is not a reader's job.** Every release number in this repository is
transcribed by hand from a `cargo test` run into three documents, and five
numbers per profile is exactly the kind of thing that is wrong without anybody
noticing. Reading the arithmetic off a log and then copying it into prose is
two chances to be wrong; this script collapses them into one, and prints the
receipt that the prose is then derived from.

**What it asserts.**

- **No profile carries a failure.** A `test result: FAILED` line fails the run,
  and so does any `failed` count above zero, whichever way it was reported.
- **Both profiles enumerate the same set.** Debug and release differ in what
  they *skip* and in which row is `ignore`d, never in how many tests exist.
  Two different totals means one of them was measured against a different tree,
  which is the failure this repository has already produced once — the two were
  normalised into a single number precisely because they disagreed.
- **The filtered count is the number of `--skip` flags the command carried.**
  Without this, a document can drop a filter and the arithmetic still closes.
- **`--expect-enumerated` binds the measurement to the documents.** Without it
  the receipt is a report; with it the run and the shipped prose are the same
  number, checked rather than asserted.

**Why it reads a log rather than the documents.** An earlier version of this
script parsed the counts out of three documents in two languages, and it failed
on its first honest run for two of them. Parsing prose is a second source of
truth with none of the authority. The documents are prose; a test run is a
measurement.

Run:

    python3 scripts/check-test-counts.py --debug /tmp/debug.log --release /tmp/release.log
    python3 scripts/check-test-counts.py --debug d.log --release r.log --expect-enumerated 2049
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RESULT = re.compile(
    r"^test result: (?P<verdict>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; "
    r"(?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; "
    r"(?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out",
    re.MULTILINE,
)


class Profile:
    def __init__(self, name: str, text: str, skips: int) -> None:
        blocks = list(RESULT.finditer(text))
        if not blocks:
            raise SystemExit(f"{name}: no `test result:` lines found; the log is not a run")
        self.name = name
        self.skips = skips
        self.blocks = len(blocks)
        self.passed = sum(int(m.group("passed")) for m in blocks)
        self.failed = sum(int(m.group("failed")) for m in blocks)
        self.ignored = sum(int(m.group("ignored")) for m in blocks)
        self.filtered = sum(int(m.group("filtered")) for m in blocks)
        self.failed_blocks = [
            m.group(0) for m in blocks if m.group("verdict") == "FAILED"
        ]

    @property
    def enumerated(self) -> int:
        return self.passed + self.failed + self.ignored + self.filtered

    def problems(self) -> list[str]:
        out: list[str] = []
        if self.failed:
            out.append(
                f"{self.name}: {self.failed} failed test(s) across {len(self.failed_blocks)} block(s)"
            )
        if self.filtered != self.skips:
            out.append(
                f"{self.name}: filtered {self.filtered} but the command carried "
                f"{self.skips} --skip flag(s)"
            )
        return out


def receipt(p: Profile) -> str:
    return (
        f"  blocks={p.blocks} passed={p.passed} failed={p.failed} "
        f"ignored={p.ignored} filtered={p.filtered} enumerated={p.enumerated}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--debug", required=True, type=Path)
    ap.add_argument("--release", required=True, type=Path)
    ap.add_argument("--debug-skips", type=int, default=0)
    ap.add_argument("--release-skips", type=int, default=0)
    ap.add_argument("--expect-enumerated", type=int, default=None)
    args = ap.parse_args()

    try:
        debug = Profile("debug", args.debug.read_text(encoding="utf-8"), args.debug_skips)
        release = Profile("release", args.release.read_text(encoding="utf-8"), args.release_skips)
    except FileNotFoundError as e:
        print(f"test-count arithmetic: cannot read {e.filename}", file=sys.stderr)
        return 1

    problems = debug.problems() + release.problems()
    if debug.enumerated != release.enumerated:
        problems.append(
            f"the two profiles enumerate different sets: debug {debug.enumerated}, "
            f"release {release.enumerated}. One tree has one set of tests."
        )
    if args.expect_enumerated is not None and debug.enumerated != args.expect_enumerated:
        problems.append(
            f"the run enumerates {debug.enumerated} but the documents claim "
            f"{args.expect_enumerated}; the prose is describing a different tree"
        )

    if problems:
        print("test-count arithmetic: FAIL\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\n" + receipt(debug) + "\n" + receipt(release), file=sys.stderr)
        return 1

    print("test-count arithmetic: PASS")
    print(receipt(debug))
    print(receipt(release))
    print(
        f"  identity: enumerated == passed + failed + ignored + filtered holds in "
        f"both ({debug.enumerated})"
    )
    delta = debug.passed - release.passed
    if (
        delta == debug.ignored
        and debug.filtered == 0
        and release.ignored == 0
        and debug.enumerated == release.enumerated
    ):
        print(
            f"  reconciled: debug carries {debug.ignored} ignored row(s) release "
            f"asserts, which is the whole of the {delta}-test difference; the "
            f"profiles enumerate the same {debug.enumerated}"
        )
    else:
        # No narrative when the shape is not the one this repository has. A
        # reconciliation sentence printed next to numbers it does not describe
        # is a caption, and this guard exists instead of captions.
        print(
            f"  reconciled: debug and release both enumerate {debug.enumerated} "
            f"({delta} difference in passed); the shape is not the expected "
            f"ignored-row pattern, so no cause is claimed here"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
