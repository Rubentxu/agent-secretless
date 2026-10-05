#!/usr/bin/env python3
"""Prove that two `skill_contract.py` checks can fail, by making them fail.

`skill_contract.py` is the R0.3 gate: it is what stops a release shipping a
skill that has drifted from the product. A gate nobody has seen go red is a gate
that might be vacuous, and this file is the answer to that for the two checks in
it whose failure mode is "the sentence is wrong" rather than "the source is
wrong".

**Both checks below had no harness at all.** `check_truth_is_not_vacuous`
carries a docstring saying it is "extracted so the falsification harness can call
it against a stub source and require it to go red", and as of 2026-10-06 no
harness imported `skill_contract` at all -- `r0_gate.py` runs it as a gate and
nothing called it as a subject. That is a comment describing infrastructure that
did not exist, which is the same shape of claim this campaign has been removing
from the product, in the tooling that was supposed to be checking the product.

`c5b_the_stated_count_is_the_published_count` was added in the same commit and
would have inherited exactly that problem, so both are covered here.

What each case proves
--------------------

`c5b` is asserted in both directions, because a check that only fails is as
useless as one that only passes:

  * a skill stating the wrong number goes red, with the two numbers in the
    message -- this is the real finding, the sibling checkout said nine while
    `operational()` returned thirteen;
  * a skill stating the right number goes green;
  * a skill stating **no** number goes red, so the sentence cannot be deleted to
    silence the check;
  * a skill stating two different counts goes red rather than the check picking
    the one it prefers.

`check_truth_is_not_vacuous` is called against a deliberately empty source and
required to go red, which is the only way to show that a parse yielding nothing
fails rather than passing every comparison downstream of it.

Run: python3 tests/skill_contract_falsification.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRACT = REPO / "tests" / "skill_contract.py"

_spec = importlib.util.spec_from_file_location("skill_contract", CONTRACT)
assert _spec and _spec.loader, "skill_contract.py did not load"
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)


def _reset() -> None:
    """The module counts passes and failures in globals; each case starts clean."""
    sc._passes = 0
    sc._failures.clear()
    sc._skips.clear()


def _run(fn, *args) -> tuple[bool, list[str]]:
    """Call a check and report its verdict, not its chatter.

    `check()` prints a line per assertion, so a suite that shows verdicts and
    lets the checks talk at the same time produces a report where the failures of
    the *subject* and the output of the *falsification* are indistinguishable.
    The captured text is returned and printed only when the case itself fails.
    """
    _reset()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        fn(*args)
    return (not sc._failures), list(sc._failures)


#: What `len(truth["operational"])` is today. A stub rather than the real parse:
#: this file is about the checks, and parsing relations.rs would make a failure
#: here indistinguishable from a change to the product.
STUB_TRUTH = {
    "rels": {f"V{i}": f"asv://rels/v{i}" for i in range(18)},
    "operational": [f"V{i}" for i in range(13)],
    "argv": {f"V{i}": ["x"] for i in range(18)},
    "codes": {"a", "b", "c", "d", "e"},
    "warn_codes": {"f"},
}


def _skill(statement: str) -> dict[str, str]:
    return {"SKILL.md": f"# skill\n\n## Relaciones publicadas\n\n{statement}\n"}


CASES = [
    (
        "a skill stating the wrong number is a defect",
        lambda: _run(sc.c5b_the_stated_count_is_the_published_count,
                     _skill("El runtime publica nueve y sólo nueve."),
                     STUB_TRUTH),
        False,
    ),
    (
        "a skill stating the right number passes",
        lambda: _run(sc.c5b_the_stated_count_is_the_published_count,
                     _skill("El runtime publica trece y sólo trece."),
                     STUB_TRUTH),
        True,
    ),
    (
        "a skill stating no number at all is a defect",
        lambda: _run(sc.c5b_the_stated_count_is_the_published_count,
                     _skill("El runtime publica algunas."),
                     STUB_TRUTH),
        False,
    ),
    (
        "two different counts are a defect, not a choice for the check",
        lambda: _run(sc.c5b_the_stated_count_is_the_published_count,
                     _skill("Uno: nueve y sólo nueve. Otro: trece y sólo trece."),
                     STUB_TRUTH),
        False,
    ),
    (
        "an unreadable count word is reported by name, not skipped",
        lambda: _run(sc.c5b_the_stated_count_is_the_published_count,
                     _skill("El runtime publica chorro y sólo chorro."),
                     STUB_TRUTH),
        False,
    ),
    (
        "a parse that yields nothing makes the vacuity check go red",
        lambda: _run(sc.check_truth_is_not_vacuous,
                     {"rels": {}, "operational": [], "argv": {}, "codes": set(),
                      "warn_codes": set()}),
        False,
    ),
    (
        "a full parse of the right shape passes the vacuity check",
        lambda: _run(sc.check_truth_is_not_vacuous, STUB_TRUTH),
        True,
    ),
]


def main() -> int:
    passed = 0
    for name, run, expected_ok in CASES:
        ok, failures = run()
        print(f"  {'PASS' if ok == expected_ok else 'FAIL'}  {name}")
        if ok != expected_ok:
            for f in failures:
                print(f"          {f}")
            continue
        passed += 1

    # The one case that asserts on the message rather than the verdict: a failure
    # that says only "the count is wrong" sends an author to the skill to count
    # the relations by hand, which is the work the check was supposed to do.
    with contextlib.redirect_stdout(io.StringIO()):
        ok, failures = _run(sc.c5b_the_stated_count_is_the_published_count,
                            _skill("El runtime publica nueve y sólo nueve."),
                            STUB_TRUTH)
    names_both = any("9" in f and "13" in f for f in failures)
    print(f"  {'PASS' if names_both else 'FAIL'}  "
          f"the wrong-number failure names both numbers")
    if names_both:
        passed += 1

    total = len(CASES) + 1
    print(f"\n{passed}/{total} behaviours confirmed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())