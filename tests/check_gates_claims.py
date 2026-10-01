#!/usr/bin/env python3
"""Falsifiability tests for the UAT-claim check in tools/check-gates.py.

A governance check nobody has watched reject anything does not establish that
its green result means anything. These cases pin the behaviours the check
promises, and each was run against the real repository before being pinned:

1. two test files declaring the same UAT id is a hard defect
2. a test file declaring an id the spec does not define is a hard defect
3. a filename implying an id its header does not declare is a warning only
4. a later doc line merely *discussing* an id is not a claim
5. a clean repository passes
6. a quotation attributed to the spec pack that exists nowhere in it is a
   hard defect
7. a faithful quotation, re-wrapped to the line width, is not a defect
8. a claim whose title shares no content word with the spec's title for
   that id warns without failing

Case 4 exists because the check got it wrong first: a header reading
"UAT-035 is not among them" matched the claim pattern and reported a file as
claiming UAT-035. Only the first doc line is a claim. If that regresses, this
test goes red.

Case 7 exists because the first attempt at case 6 was worthless. Scoring a
quotation by how many of its individual words appear in the pack gave the
forged UAT-034 header 95%: a pack that discusses vaults throughout contains
"vault", "attacker" and "passphrase" on their own. The measure that separates
them is the longest unbroken run of words, which scores the forgery at 5 and
the shortest faithful quotation at 14. If that regresses to word coverage,
this test goes red.

Run: python3 tests/check_gates_claims.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "check-gates.py"

# A minimal but real UAT document: two defined ids, two milestones.
UATDOC = """# UAT

## UAT-001 — first
Do the first thing.

## UAT-005 — placeholder replay outside session
Copy surrogate to an ordinary shell outside the session and expect a direct
provider request to be denied.
"""

ROADMAP = """# Roadmap

## M2 — early
### Exit UAT
- UAT-001,

## M4 — later
### Exit UAT
- UAT-005,
"""


def build(tmp: Path, tests: dict[str, str]) -> None:
    spec = tmp / "agent-secretless-vault-spec" / "docs"
    spec.mkdir(parents=True)
    (spec / "14-UAT-ADVERSARIAL.md").write_text(UATDOC, encoding="utf-8")
    (spec / "15-ROADMAP.md").write_text(ROADMAP, encoding="utf-8")
    tests_dir = tmp / "crates" / "broker" / "tests"
    tests_dir.mkdir(parents=True)
    for name, body in tests.items():
        (tests_dir / name).write_text(body, encoding="utf-8")


def run(tests: dict[str, str]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        build(Path(td), tests)
        proc = subprocess.run(
            [sys.executable, str(TOOL), td],
            capture_output=True, text=True, check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr


CLAIM_005 = "//! UAT-005 — placeholder replay outside session.\n//!\n//! body\n"
CLAIM_001 = "//! UAT-001 — first.\n//!\n//! body\n"
DISCUSS_035 = (
    "//! Crash / recovery — journal replay.\n"
    "//!\n"
    "//! Not a normative UAT: 14-UAT-ADVERSARIAL.md defines UAT-001..UAT-034 and\n"
    "//! UAT-035 is not among them. This suite took a number nothing reserves.\n"
    "//!\n"
    "//! body\n"
)
# Faithful: the spec sentence above, re-wrapped across three lines. A real
# quotation survives re-wrapping because word order is preserved.
FAITHFUL_QUOTE = (
    "//! UAT-005 — placeholder replay outside session.\n"
    "//!\n"
    "//! Per `14-UAT-ADVERSARIAL.md`:\n"
    "//!\n"
    "//! > Copy surrogate to an ordinary shell outside the session and\n"
    "//! > expect a direct provider request to be denied.\n"
)
# Modelled on the real UAT-034 forgery this check was written for: entirely
# plausible security prose that appears nowhere in the spec pack.
FORGED_QUOTE = (
    "//! UAT-005 — placeholder replay outside session.\n"
    "//!\n"
    "//! Per `14-UAT-ADVERSARIAL.md` and the M12 spec:\n"
    "//!\n"
    "//! > The device-bound vault mode keeps the long-lived passphrase out\n"
    "//! > of the vault file. An attacker who steals the file (and the broker\n"
    "//! > binary) but does not have the host device in the same PCR state\n"
    "//! > cannot open the vault.\n"
)
# Claims a real id but is about something else entirely.
DIVERGENT_TITLE = (
    "//! UAT-005 — TLS certificate pinning resolver.\n"
    "//!\n"
    "//! body\n"
)


def main() -> int:
    if not TOOL.exists():
        print(f"FAIL tool not found: {TOOL}")
        return 1

    results: list[tuple[str, bool, str]] = []

    # 1. Two files claiming the same id is a hard defect.
    code, out = run({
        "uat_005_replay.rs": CLAIM_005,
        "uat_005_other.rs": CLAIM_005,
    })
    results.append((
        "a duplicate UAT id is a hard defect",
        code == 1 and "claimed by 2 test files" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 2. A claim on an id the spec never defined is a hard defect.
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_050_phantom.rs": "//! UAT-050 — invented id.\n//!\n//! body\n",
    })
    results.append((
        "a claim on an undefined UAT id is a hard defect",
        code == 1 and "does not define it" in out and "UAT-050" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 3. A filename implying an id the header does not declare is a warning.
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_001_extra.rs": "//! Environment-quarantine regression.\n//!\n//! body\n",
    })
    results.append((
        "a filename-only claim warns without failing",
        code == 0 and "WARN" in out and "declares no UAT id" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 4. Prose mentioning an id later in the header is not a claim.
    #    The filename still implies UAT-035, so a filename-only WARNING is
    #    expected and correct; what must not happen is the file being counted
    #    as a claim. So the assertions are on the hard-defect section and on
    #    the claim count, not on the absence of the string "UAT-035".
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_035_crash.rs": DISCUSS_035,
    })
    hard_section = out.split("== hard defects ==")[1].split("== warnings ==")[0] \
        if "== hard defects ==" in out else ""
    results.append((
        "a later doc line discussing an id is not a claim",
        code == 0
        and "none" in hard_section
        and "does not define it" not in hard_section
        and re.search(r"UAT ids claimed in repo:\s+1\b", out) is not None,
        f"hard section said: {hard_section.strip()[:80]!r}",
    ))

    # 5. A clean repository passes.
    code, out = run({"uat_001_ok.rs": CLAIM_001, "uat_005_replay.rs": CLAIM_005})
    results.append((
        "a clean repository passes",
        code == 0 and "hard defects:           0" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 6. A quotation attributed to the spec pack that exists nowhere in it
    #    is a hard defect. This is the shape of all five real forgeries.
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_005_replay.rs": FORGED_QUOTE,
    })
    results.append((
        "a fabricated spec citation is a hard defect",
        code == 1 and "citation is fabricated" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 7. The same header quoting the spec faithfully, only re-wrapped, must
    #    not be flagged. Without this the check could reject every real
    #    quotation and still pass case 6.
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_005_replay.rs": FAITHFUL_QUOTE,
    })
    results.append((
        "a re-wrapped faithful citation is not a defect",
        code == 0 and "citation is fabricated" not in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    # 8. A claim about something other than what the spec titles that id
    #    warns but does not fail: only the spec author can say which side of
    #    a misattribution is wrong, and the test itself is real either way.
    code, out = run({
        "uat_001_ok.rs": CLAIM_001,
        "uat_005_replay.rs": DIVERGENT_TITLE,
    })
    results.append((
        "a claim whose title diverges from the spec warns without failing",
        code == 0 and "the id and the test do not describe the same thing" in out,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
    ))

    print("check-gates UAT-claim falsifiability\n")
    failures = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures += 1
            print(f"        {detail}")

    print(f"\n{len(results) - failures}/{len(results)} behaviours confirmed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
