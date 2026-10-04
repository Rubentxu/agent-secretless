#!/usr/bin/env python3
"""Falsification campaign for the skip-aware suite-size check.

`tests/doc_claims_drift.py` drives the guard's *entry points* against synthetic
trees and asks whether a document claiming the wrong thing is rejected. That is
the right shape for "does the shipped behaviour notice a lie", and it is the
wrong shape for "does this check still work at all". Its cases are all judged
against documents that are correct except for the one claim under test, so a
check that had been quietly neutered — a parser that matches nothing, a filter
that is never read — would accept every one of them and be reported green.

That blindness was not hypothetical here, because it happened while this file
was being written. The first version of this campaign used only the shipped,
now-correct README as its control, and reported two mutants "inert" that were
in fact dangerous: one of them stopped the fenced-block parser from matching
anything, which disables the whole check, and the correct document could not
tell the difference. A falsification suite that only tests the happy path
cannot distinguish a working check from a disabled one.

So the unit under test here is the *verdict matrix*. Four documents are defined,
each with a verdict the repository can establish without the guard: one the
claim makes impossible and that must be rejected, one correct and that must be
accepted, one whose filter is a typo and must still be accepted, and one that
documents a subset run and is none of this check's business. A mutant is caught
when it moves any verdict. Disabling the check moves the first; over-rejecting
moves the second and fourth; a filter that removes tests when it matches nothing
moves the third.

Every mutant is reverted immediately, and the campaign verifies its own cleanup
by digest and refuses to report a result if a source file was left modified.

One candidate mutant is deliberately absent. Rewriting the fence pattern to
match every region between fences is *equivalent* under `findall` — the regions
it yields still cover each block's content — so it cannot be made to disagree
on any document, and a campaign entry that can never be caught is a number that
teaches a reader nothing. Equivalent is not the same as correct, but it is not a
defect, and this file is about defects.

Run: python3 tests/doc_claims_split_falsification.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-doc-claims.py"


def source_digest() -> str:
    return hashlib.sha256(GUARD.read_bytes()).hexdigest()


def load_guard():
    """A fresh module, so no mutant's rebinding survives into the next case."""
    spec = importlib.util.spec_from_file_location("doc_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def readme_names() -> list[str]:
    """Every test the workspace enumerates, via the guard's own derivation."""
    guard = load_guard()
    names = guard.enumerated_test_names()
    if names is None:
        raise SystemExit("could not enumerate the suite; the campaign has no ground truth")
    return names


def skip_excluded(names: list[str], patterns: list[str]) -> list[str]:
    return [n for n in names if any(p in n for p in patterns)]


def document(blocks: list[str]) -> str:
    """A README-shaped text carrying the given fenced blocks and nothing else."""
    parts = ["# ASV\n"]
    for block in blocks:
        parts.append(f"```bash\n{block}\n```\n")
    return "\n".join(parts)


def verdict_for(names: list[str], text: str) -> tuple[bool, str]:
    """Whether the guard accepts `text` as a README, and why not if it does not.

    The document is written to a scratch tree and the guard is pointed at it, so
    a campaign that dies mid-run cannot leave a synthetic document sitting in the
    repository's README. `REPO` is the only thing the guard needs rebinding:
    `readmes()` derives its paths from it at call time.
    """
    guard = load_guard()
    original_repo, original_names = guard.REPO, guard.enumerated_test_names
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "README.md").write_text(text, encoding="utf-8")
        guard.REPO = Path(tmp)
        guard.enumerated_test_names = lambda: names
        failures: list[str] = []
        try:
            guard.check_suite_claims(failures)
        finally:
            guard.REPO, guard.enumerated_test_names = original_repo, original_names
    return not failures, " | ".join(failures)


def verdicts(names: list[str], cases: list[tuple[str, str, bool]]) -> dict[str, bool]:
    """Map each case's name to whether the guard accepted its document."""
    return {name: verdict_for(names, text)[0] for name, text, _ in cases}


# Each mutant replaces one source expression, as literal text so a mutant that
# fails to apply is a loud campaign failure rather than a test that quietly
# measures the unmutated guard.
MUTANTS: list[tuple[str, str, str]] = [
    (
        "the fenced-block parser stops matching blocks entirely",
        r'FENCED_BLOCK = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)',
        r'FENCED_BLOCK = re.compile(r"^~~~[^\n]*\n(.*?)^~~~", re.DOTALL | re.MULTILINE)',
    ),
    (
        "the skip filter stops being read from the block",
        "patterns = SKIP_FLAG.findall(block)",
        "patterns = []",
    ),
    (
        "the skip filter is read as an exact test name instead of a substring",
        "return [n for n in names if not any(p in n for p in patterns)]",
        "return [n for n in names if n not in patterns]",
    ),
    (
        "the reachable count is not reduced by the filters",
        "reachable = reachable_tests(names, patterns)",
        "reachable = list(names)",
    ),
    (
        "a filter that matches nothing still removes one test",
        "return [n for n in names if not any(p in n for p in patterns)]",
        "return [n for n in names if not any(p in n for p in patterns)][:-1]",
    ),
    (
        "the check reverts to the sum-only comparison it replaced",
        "if total != len(reachable):",
        "if total != observed:",
    ),
    (
        "a documented subset run is treated as a whole-workspace claim",
        'if not CARGO_TEST.search(block) or PACKAGE_SELECT.search(block):',
        "if not CARGO_TEST.search(block):",
    ),
]


def main() -> int:
    if not GUARD.exists():
        print(f"FAIL guard not found: {GUARD}")
        return 1

    before = source_digest()
    names = readme_names()
    n = len(names)

    real_uat = [x for x in names if "uat_028" in x]
    real_perf = [x for x in names if "one_hundred_brokered_reads" in x]
    if len(real_uat) != 1 or len(real_perf) != 1:
        print(
            f"FAIL expected exactly one uat_028 and one p95 test to filter, found "
            f"{len(real_uat)} and {len(real_perf)}. The campaign's documents are "
            f"written against those names."
        )
        return 1

    full = f"cargo test --workspace --release -- --skip uat_028 --skip one_hundred_brokered_reads"
    reachable = n - len(skip_excluded(names, ["uat_028", "one_hundred_brokered_reads"]))

    cases: list[tuple[str, str, bool]] = [
        (
            "impossible",
            document([full + f"\n# expected: passed={n} failed=0 ignored=0"]),
            False,
        ),
        (
            "correct",
            document([full + f"\n# expected: passed={reachable} failed=0 ignored=0"]),
            True,
        ),
        (
            "typo_filter",
            document(
                [
                    f"cargo test --workspace --release -- --skip uat_999_no_such_test\n"
                    f"# expected: passed={n} failed=0 ignored=0"
                ]
            ),
            True,
        ),
        (
            "subset_run",
            document(
                [
                    f"cargo test --workspace --release -- --skip uat_028 --skip one_hundred_brokered_reads\n"
                    f"# expected: passed={reachable} failed=0 ignored=0",
                    f"cargo test -p asv-vault --release\n# expected: passed=40 failed=0 ignored=0",
                ]
            ),
            True,
        ),
    ]

    print("Ground truth, derived from the enumeration and the documents' own filters:")
    print(f"  enumerated  {n}")
    print(f"  reachable   {reachable}  (two filters exclude {n - reachable})")
    print(f"  documents   {', '.join(name for name, _, _ in cases)}")
    print()

    observed = verdicts(names, cases)
    mismatched = [
        (name, want) for name, _, want in cases if observed.get(name) is not want
    ]
    if mismatched:
        for name, want in mismatched:
            print(f"FAIL case {name!r} expected accepted={want}, got {observed.get(name)}")
        print("The guard does not hold the baseline matrix; measuring mutants against it is meaningless.")
        return 1
    print("  PASS  the baseline matrix holds on the unmutated guard")
    for name, _, want in cases:
        print(f"        {name:<14} accepted={observed[name]}")

    results: list[tuple[str, bool, str]] = []
    text = GUARD.read_text(encoding="utf-8")

    for name, old, new in MUTANTS:
        if text.count(old) != 1:
            print(
                f"FAIL mutant {name!r} does not apply cleanly "
                f"({text.count(old)} matches for its target); the guard has moved "
                f"and the campaign is measuring nothing"
            )
            return 1
        GUARD.write_text(text.replace(old, new), encoding="utf-8")
        try:
            got = verdicts(names, cases)
        finally:
            GUARD.write_text(text, encoding="utf-8")

        moved = [
            (case, want, got.get(case))
            for case, _, want in cases
            if got.get(case) is not want
        ]
        if not moved:
            results.append((name, False, "every verdict unchanged — equivalent, not a defect"))
            continue
        detail = "; ".join(f"{case}: expected accepted={want}, got {g}" for case, want, g in moved)
        results.append((name, True, detail))

    after = source_digest()
    if before != after:
        print("FAIL the campaign left the guard modified; refusing to report a result")
        return 1

    print("\nSkip-aware suite-size check, mutation campaign\n")
    failures = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures += 1
            print(f"        {detail}")
        else:
            print(f"        {detail}")

    print(
        f"\n{len(results) - failures}/{len(results)} mutants caught, "
        f"guard restored (sha256 {after[:12]})"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

