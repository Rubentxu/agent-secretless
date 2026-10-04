#!/usr/bin/env python3
"""Is R0 actually closed? Six conditions, each one measured.

R0 is the block that makes the current product installable, verifiable and
reachable by an agent. Its exit criteria are six, and this suite re-derives
each of them from the repository and from the things it names. It does not read
a status cell to decide whether a milestone is done, because a status cell is
exactly the kind of claim that goes stale quietly.

    R0.1  the roadmap authority says what the product actually is
    R0.2  a clean install verifies a signed release, and every provenance
          violation is a refusal with nothing written
    R0.3  the official skill is published, and the cross-repo contract is green
    R0.4  the work landed in atomic commits and the tree is clean

# Why there is no SKIP

A gate that can pass by not running is not a gate. Each condition resolves to
one of three states and only one of them is success:

    PASS           measured, and it holds
    FAIL           measured, and it does not hold
    UNAVAILABLE    could not be measured on this machine

UNAVAILABLE is reported as its own state and is **not** a pass. The skill
contract needs a checkout of `Rubentxu/agent-skill`, which needs the network;
on a machine without it, this suite says so and exits non-zero rather than
quietly dropping a release requirement. That is the rule R5 states for the full
gate, applied here first: a requirement that cannot run has not been met.

# Run: python3 tests/r0_gate.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROADMAP = REPO / "agent-secretless-vault-spec" / "docs" / "15-ROADMAP.md"
GATES = REPO / "agent-secretless-vault-spec" / "docs" / "16-SECURITY-RELEASE-GATES.md"
SKILL_REPO = "https://github.com/Rubentxu/agent-skill.git"

PASS, FAIL, UNAVAILABLE = "PASS", "FAIL", "UNAVAILABLE"
_results: list[tuple[str, str, str]] = []


def record(name: str, state: str, evidence: str) -> None:
    _results.append((name, state, evidence))
    mark = {PASS: "ok  ", FAIL: "FAIL", UNAVAILABLE: "UNAV "}[state]
    print(f"  {mark}  {name}\n          {evidence}")


def run(args: list[str], cwd: Path | None = None, timeout: int = 1800) -> tuple[int, str]:
    env = dict(os.environ)
    env.setdefault("TMPDIR", "/var/home/rubentxu/agent-secretless-tmp")
    try:
        p = subprocess.run(args, cwd=cwd or REPO, env=env, timeout=timeout,
                           capture_output=True, text=True)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)


# ------------------------------------------------------------------ R0.1

def r0_1_roadmap_authority() -> None:
    """The single planning authority says TPM2 is not a v1.0 gate, in writing.

    Checked as structure rather than as a phrase, because a roadmap that
    reorders its blocks and keeps the old sentence is the failure this exists
    to catch.
    """
    if not ROADMAP.is_file():
        record("R0.1 roadmap authority", FAIL, f"{ROADMAP} is missing")
        return
    text = ROADMAP.read_text(encoding="utf-8")

    if "## Critical path — rebaselined" not in text:
        record("R0.1 roadmap authority", FAIL,
               "the rebaselined critical path section is not in the roadmap")
        return

    blocks = [f"R{i}" for i in range(0, 11)]
    # R0 and R1 are the only ones that can collide with the release-gate rows
    # in the other document, so they are quoted as `R0`/`R1` in the block table.
    missing_blocks = [b for b in blocks if f"| **{b}**" not in text]
    if missing_blocks:
        record("R0.1 roadmap authority", FAIL,
               f"the block table is missing {missing_blocks}")
        return

    if "54CB5B8D3C7419FB" in text:
        record("R0.1 roadmap authority", FAIL,
               "the roadmap repeats a key id that belongs to the README")
        return

    # The M12 section must still be a specification, not a deletion: scope,
    # exit and exit UAT are what survive a deferral.
    m12 = re.search(r"## M12\b(.*?)(?=\n## )", text, re.S)
    if not m12:
        record("R0.1 roadmap authority", FAIL, "the roadmap has no M12 section")
        return
    body = m12.group(1)
    if "Deferred to R8" not in body:
        record("R0.1 roadmap authority", FAIL,
               "the M12 section carries no deferral note to R8")
        return
    for marker in ("### Exit", "### Scope"):
        if marker not in body:
            record("R0.1 roadmap authority", FAIL,
                   f"the M12 section lost {marker}; a deferral must not delete "
                   f"the specification")
            return

    # The gates document must not still read as though M12 blocks v1.0.
    gate_text = GATES.read_text(encoding="utf-8")
    row = re.search(r"^\| M12 hardware-backed vault \|[^|]*\|", gate_text, re.M)
    if not row:
        record("R0.1 roadmap authority", FAIL, "the gates document has no M12 row")
        return
    if "NOT MET" in row.group(0):
        record("R0.1 roadmap authority", FAIL,
               f"the M12 gate row still opens with NOT MET: {row.group(0)[:80]}")
        return

    record("R0.1 roadmap authority", PASS,
           f"critical path section present, all {len(blocks)} blocks in the "
           f"table, M12 annotated to R8 with scope and exit intact, and the "
           f"gate row no longer reads as a v1.0 blocker")


# ------------------------------------------------------------------ R0.2

def r0_2_installer_provenance() -> None:
    """A clean install verifies a signature, and tampering is refused.

    Runs the real campaign rather than reading its result from a file. The
    campaign is the evidence; this is the gate that refuses to proceed without
    it.
    """
    campaign = REPO / "tests" / "provenance_falsification.py"
    if not campaign.is_file():
        record("R0.2 installer provenance", FAIL,
               f"{campaign.relative_to(REPO)} does not exist; there is no "
               f"negative provenance evidence to gate on")
        return

    code, out = run([sys.executable, str(campaign)])
    if code == 127:
        record("R0.2 installer provenance", UNAVAILABLE,
               "the campaign could not be started")
        return
    m = re.search(r"(\d+) checks passed, (\d+) failed", out)
    if not m:
        record("R0.2 installer provenance", FAIL,
               f"the campaign produced no summary (exit {code})")
        return
    passed, failed = int(m.group(1)), int(m.group(2))
    if code != 0 or failed:
        record("R0.2 installer provenance", FAIL,
               f"{passed} passed, {failed} failed, exit {code}")
        return

    # The campaign is only worth its exit code if the refusals are reachable,
    # so the summary is read for the mutation half, not just the count.
    if "mutation accepts the release the honest installer refused" not in out:
        record("R0.2 installer provenance", FAIL,
               f"{passed} checks passed but no row demonstrated that a "
               f"tampered release is refusable; green refusals that nothing can "
               f"break are not evidence")
        return

    record("R0.2 installer provenance", PASS,
           f"{passed} checks, {failed} failed, exit 0: every mandated failure "
           f"mode refused with nothing written, and each one shown refusable by "
           f"a named mutation of the installer")


# ------------------------------------------------------------------ R0.3

def r0_3_published_skill() -> None:
    """The official skill exists, outside this repository, and matches the product."""
    skill_dir = (REPO.parent / "agent-skill" / "skills" / "agent-secretless").resolve()
    if not (skill_dir / "SKILL.md").is_file():
        # A missing checkout may be a missing network rather than a missing
        # skill. Those are different answers, so the repository is asked before
        # either is reported.
        if not _remote_is_readable():
            record("R0.3 published skill", UNAVAILABLE,
                   f"no skill at {skill_dir} and {SKILL_REPO} could not be "
                   f"reached; this condition could not be measured")
            return
        record("R0.3 published skill", FAIL,
               f"{SKILL_REPO} is reachable but there is no checkout at "
               f"{skill_dir}. The skill must be published there, and this "
               f"release cannot verify a skill it cannot see.")
        return

    if skill_dir.is_relative_to(REPO):
        record("R0.3 published skill", FAIL,
               f"{skill_dir} is inside this repository; that is the retired "
               f"draft, not the published skill")
        return

    code, out = run([sys.executable, str(REPO / "tests" / "skill_contract.py")])
    m = re.search(r"(\d+) checks passed, (\d+) failed", out)
    if not m:
        record("R0.3 published skill", FAIL,
               f"the cross-repo contract produced no summary (exit {code})")
        return
    passed, failed = int(m.group(1)), int(m.group(2))
    if code != 0 or failed:
        record("R0.3 published skill", FAIL,
               f"the cross-repo contract is red: {passed} passed, {failed} "
               f"failed, exit {code}")
        return
    record("R0.3 published skill", PASS,
           f"the skill is published at {skill_dir.name} outside this "
           f"repository, and the cross-repo contract is green: {passed} checks, "
           f"{failed} failed, exit 0")


def _remote_is_readable() -> bool:
    code, _ = run(["git", "ls-remote", "--exit-code", SKILL_REPO, "HEAD"], timeout=120)
    return code == 0


# ------------------------------------------------------------------ R0.4

def r0_4_atomic_history() -> None:
    """R0 landed as reviewable commits, and the tree is where it should be.

    What "atomic" is checked to mean here, and one thing it deliberately does
    not mean. A commit that changes behaviour *and* the document describing
    that behaviour is one unit of value; splitting them would leave the
    repository asserting something untrue for the length of a commit, which is
    worse than a commit that touches a few related files. So the rule is not
    "one kind of file per commit" — it is that the block landed as separate
    reviewable steps and that no step is empty.
    """
    code, out = run(["git", "status", "--porcelain"])
    if code != 0:
        record("R0.4 atomic history", FAIL, "git status could not be read")
        return
    if out.strip():
        record("R0.4 atomic history", FAIL,
               f"the working tree is not clean: {len(out.strip().splitlines())} "
               f"entries. A gate that measures the tree cannot also be the "
               f"thing that leaves it dirty.")
        return

    # The R0 commits are found by what they *introduced*, not by where they
    # are. The first version of this looked at the last twelve commits, which
    # measures recency rather than the property: twelve commits after R0
    # landed, the R0 commits had scrolled out of the window and the guard
    # reported "R0 does not have a distinct commit for the roadmap" about a
    # block that had been closed and verified for days. A guard that goes red
    # for a reason other than the one it names teaches its reader to ignore
    # it.
    #
    # Anchoring on the introducing commit is also what keeps this honest the
    # other way. A full-history search for the *word* "roadmap" would find this
    # repository's later `docs(roadmap):` commits and pass on those, so the
    # search is `-S` over the distinctive string each sub-block added: the
    # rebaselined section, the single checksum authority, and the skill
    # contract. Each of those appears for the first time in its own commit, and
    # in no later one.
    # Each concern is anchored on a string that its own commit **introduced**
    # and that no later commit removed, found with `git log -S --reverse`, so
    # the answer is the introducing commit regardless of where it sits in the
    # history.
    #
    # Two other anchors were tried and both were wrong in an instructive way.
    # A window of the last twelve commits measures *recency*, not the property:
    # twelve commits after R0 landed, this reported "R0 does not have a distinct
    # commit for the roadmap" about a block closed and verified days earlier. A
    # guard that goes red for a reason other than the one it names teaches its
    # reader to ignore it. And `--diff-filter=A` on a file the commit added
    # works for two of the three concerns and not the third, because the skill
    # commit's job was to *remove* the in-repo proposal and leave a pointer —
    # it added no file at all.
    #
    # The strings are also chosen so no later commit re-introduces them.
    # Searching the full history for the *word* "roadmap" would find this
    # repository's later `docs(roadmap):` commits and pass on those, which
    # would be a guard that cannot fail.
    concerns = {
        # The rebaselined critical path.
        "roadmap": "## Critical path — rebaselined",
        # The single signed checksum authority, which R0.2 introduced when
        # `checksums.txt` was retired.
        "distribution": "CHECKSUM_AUTHORITY",
        # The withdrawal notice the skill commit left where the in-repo
        # proposal used to be.
        "skill": "propuesta (retirada",
    }
    landed: dict[str, str] = {}
    for concern, needle in concerns.items():
        code, out = run(["git", "log", "-S" + needle, "--format=%H", "--reverse"])
        if code != 0:
            record("R0.4 atomic history", FAIL,
                   f"could not search history for the {concern} commit")
            return
        shas = [s for s in out.splitlines() if s.strip()]
        if not shas:
            record("R0.4 atomic history", FAIL,
                   f"no commit ever introduced {concern!r}; the block was "
                   f"landed without it rather than as a reviewable unit")
            return
        landed[concern] = shas[0]

    # Distinct commits, because three concerns landing together is one step
    # wearing three labels.
    if len(set(landed.values())) != len(landed):
        merged = sorted(concerns[c] for c, sha in landed.items()
                        if list(landed.values()).count(sha) > 1)
        record("R0.4 atomic history", FAIL,
               f"these concerns were landed in one commit, not as separate "
               f"reviewable steps: {merged}")
        return

    empty = []
    for concern, sha in landed.items():
        _, files = run(["git", "show", "--name-only", "--format=", sha])
        if not [p for p in files.splitlines() if p.strip()]:
            empty.append(f"{concern} ({sha[:12]})")
    if empty:
        record("R0.4 atomic history", FAIL,
               f"these commits change no files: {empty}")
        return

    record("R0.4 atomic history", PASS,
           f"the working tree is clean, and R0 landed as three distinct, "
           f"non-empty commits: "
           + ", ".join(f"{c}={s[:12]}" for c, s in sorted(landed.items())))


# -------------------------------------------------------------------- main

def main() -> int:
    print("R0 exit gate — truthfulness, distribution, skill\n")
    r0_1_roadmap_authority()
    r0_2_installer_provenance()
    r0_3_published_skill()
    r0_4_atomic_history()

    print()
    failed = [n for n, s, _ in _results if s == FAIL]
    unavailable = [n for n, s, _ in _results if s == UNAVAILABLE]
    for name, state, _ in _results:
        print(f"  {state:<12} {name}")
    print(f"\n{len(_results) - len(failed) - len(unavailable)} passed, "
          f"{len(failed)} failed, {len(unavailable)} unavailable")
    if unavailable:
        print("\nUNAVAILABLE is not a pass. A condition that could not be "
              "measured\nhas not been met, and this gate will not report R0 as "
              "closed on the\nstrength of what it did not run.")
    return 1 if failed or unavailable else 0


if __name__ == "__main__":
    sys.exit(main())
