#!/usr/bin/env python3
"""Is R0 actually closed? Six conditions, each one measured.

R0 is the block that makes the current product installable, verifiable and
reachable by an agent. Its exit criteria are six, and this suite re-derives
each of them from the repository and from the things it names. It does not read
a status cell to decide whether a milestone is done, because a status cell is
exactly the kind of claim that goes stale quietly.

    R0.1  the roadmap authority says what the product actually is
    R0.1b main, the tags and the remote describe one tree
    R0.2  a clean install verifies a signed release, and every provenance
          violation is a refusal with nothing written
    R0.2b the command the README gives installs, in an empty HOME
    R0.3  the official skill is published, and the cross-repo contract is green
    R0.3b a stale protocol offers the agent a relation it can actually run
    R0.4  the work landed in atomic commits and the tree is clean

The `b` rows exist because the four above cannot go red when a release changes.
They were all green while `install.py` had never once completed an install and
while `main` was eight commits ahead of the remote; a campaign from a past block
is evidence about the past.

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

import json
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


# ------------------------------------------------- R0.1b / R0.2b / R0.3b
#
# The four rows above re-derive a past campaign. They are worth keeping and they
# are not the block's exit criteria: none of them can go red because a release
# was published, and a green that cannot go red is not evidence about the
# product. The three rows below measure the conditions R0 actually names, from
# the repository, from the published release, and from the surface an agent
# reads.
#
# They were added after the repairs, and they are why this gate does not go 4/4
# the moment the tree is clean: R0.2b is red until a release exists that the
# documented command can install, and R0.3b is red because no upgrade relation
# exists. Both were true while the four rows above were green.


def workspace_version() -> str | None:
    """The version the workspace declares, read rather than remembered."""
    m = re.search(r'^version\s*=\s*"([^"]+)"',
                  (REPO / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def r0_1b_repository_authority() -> None:
    """`main`, the tags and the remote describe one tree.

    `scripts/check-release-authority.py` owns the four rows; this gate requires
    them and refuses to let the block close while that script is red or cannot
    run. `UNKNOWN` in that script is its own state with a non-zero exit for the
    same reason `UNAVAILABLE` is one here.
    """
    script = REPO / "scripts" / "check-release-authority.py"
    if not script.is_file():
        record("R0.1b repository and release authority", FAIL,
               f"{script.relative_to(REPO)} does not exist; nothing enforces that "
               f"a release names a commit on this branch")
        return

    code, out = run([sys.executable, str(script)])
    if code == 127:
        record("R0.1b repository and release authority", UNAVAILABLE,
               "the authority gate could not be started")
        return
    if code != 0:
        tail = [ln for ln in out.strip().splitlines() if ln.strip()][-6:]
        record("R0.1b repository and release authority", FAIL,
               f"exit {code}: " + " | ".join(tail))
        return
    m = re.search(r"(\d+) passed, (\d+) failed, (\d+) unknown", out)
    if not m:
        record("R0.1b repository and release authority", FAIL,
               f"the authority gate produced no summary (exit {code})")
        return
    passed, failed, unknown = (int(m.group(i)) for i in (1, 2, 3))
    record("R0.1b repository and release authority", PASS,
           f"{passed} rows, {failed} failed, {unknown} unknown: every release tag "
           f"annotated and an ancestor of the branch, present on the remote "
           f"annotated and peeling to the same commit, and `origin/main` "
           f"contains every release commit")


def r0_2b_documented_install() -> None:
    """The command the README gives installs, in an empty HOME.

    `scripts/check-documented-install.py` reads the install command out of the
    document and runs it, in the version the document pins. That is the subject
    R0.2 names and nothing else measures: six consecutive releases shipped an
    installer that refused its own archive, and four gates were green, because
    every one of them exercised a component instead of the command.
    """
    script = REPO / "scripts" / "check-documented-install.py"
    if not script.is_file():
        record("R0.2b documented install", FAIL,
               f"{script.relative_to(REPO)} does not exist; nothing runs the "
               f"command the document tells a person to type")
        return

    version = workspace_version()
    if not version:
        record("R0.2b documented install", FAIL,
               "the workspace Cargo.toml declares no version to install")
        return

    code, out = run([sys.executable, str(script), "--version", version])
    if code == 127:
        record("R0.2b documented install", UNAVAILABLE,
               "the documented-install gate could not be started")
        return

    counts = re.search(r"^(\d+) passed, (\d+) failed$", out, re.M)
    if not counts:
        record("R0.2b documented install", FAIL,
               f"the gate produced no summary (exit {code})")
        return
    passed, failed = int(counts.group(1)), int(counts.group(2))

    # `re.findall` with two groups yields (group1, group2), so the state is the
    # first element and the row name the second. Building the dict the other way
    # round keys it by PASS/FAIL, and then every row looks green and the gate
    # reports "all rows hold" on the same output that just failed one.
    rows = {name: state for state, name in
            re.findall(r"^\s+(PASS|FAIL)\s+(D\d[^\n]*)$", out, re.M)}
    if failed or code != 0:
        failing = sorted(n for n, s in rows.items() if s == "FAIL")
        record("R0.2b documented install", FAIL,
               f"{passed} of {passed + failed} D-rows hold at {version}; failing: "
               f"{failing or '(none named)'}. Until these hold, the command the "
               f"document gives has not completed an install from a published "
               f"release")
        return
    record("R0.2b documented install", PASS,
           f"D-rows all hold at {version}: the documented command is a real "
           f"pipeline, its script is reachable, it completes in an empty HOME, "
           f"and the binary it leaves behind reports the pinned version")


def r0_3b_upgrade_relation() -> None:
    """A protocol mismatch offers the agent a relation it can actually run.

    Measured on the surface an agent reads — `asv capabilities --json`, which
    returns the static relation set even when no broker is reachable — rather
    than on the source that declares it. That list is what `PROTOCOL_MISMATCH`
    could have pointed an agent at.

    It is red, and it is left red. The repair the row implies — publish
    `asv://rels/upgrade` pointing at the installer — is not available without a
    fiction this codebase forbids: `every_operational_relation_parses_as_a_real_command`
    runs the real clap parser over every published relation, so a relation
    naming `install.sh` has no `asv` argv to parse. Closing this row means
    either shipping a real `asv upgrade` verb or amending that invariant, and
    both are decisions rather than repairs.
    """
    # Prefer the binary the worktree that owns this gate just built. The
    # fallback (`cargo metadata --manifest-path REPO/Cargo.toml`) reports the
    # target directory of the workspace root, which is shared between worktrees
    # and is the wrong file when `REPO` is a release-pinned worktree. Reading
    # the wrong binary here is the bug R0.4 names: a green that cannot go red
    # because the gate measured a different SHA than the one the row claims to
    # measure. The fix is a file-system lookup, not a metadata lookup, because
    # the metadata lookup inherits the workspace's shared target.
    asv = REPO / "target" / "debug" / "asv"
    if not asv.is_file():
        target = os.environ.get("CARGO_TARGET_DIR") or ""
        binary = (Path(target) if target else None)
        if binary is None:
            code, out = run(["cargo", "metadata", "--format-version", "1", "--no-deps",
                             "--manifest-path", str(REPO / "Cargo.toml")], timeout=300)
            # Guarded rather than trusted: a `cargo metadata` that exits zero having
            # printed something else used to take this gate down with a traceback,
            # and a gate that crashes reports nothing at all — which is the one
            # outcome that cannot be told apart from a row that was never run.
            try:
                binary = Path(json.loads(out)["target_directory"])
            except (ValueError, KeyError, TypeError):
                record("R0.3b protocol mismatch offers a runnable relation", UNAVAILABLE,
                       f"cargo did not report a target directory (exit {code}); the "
                       f"relation surface an agent reads could not be asked")
                return
        asv = binary / "debug" / "asv"
    if not asv.is_file():
        record("R0.3b protocol mismatch offers a runnable relation", UNAVAILABLE,
               f"no built asv at {asv}; the relation surface an agent reads "
               f"could not be asked")
        return

    code, out = run([str(asv), "capabilities", "--json",
                     "--socket", str(REPO / "target" / "r0-gate-absent.sock")],
                    timeout=300)
    # A non-zero exit is not a failure here. With no broker reachable the
    # envelope reports `status: blocked` and exits 1 — which is the correct
    # answer to the question it was asked — while still publishing the static
    # relation set, which is the thing this row needs. Treating the exit code
    # as the verdict reported the absence of a broker as the absence of a
    # relation, which are not the same claim.
    try:
        relations = json.loads(out)["data"]["relations"]
    except (ValueError, KeyError, TypeError):
        record("R0.3b protocol mismatch offers a runnable relation", FAIL,
               f"the capabilities envelope carried no relation list to read "
               f"(exit {code}); last output: "
               f"{out.strip().splitlines()[-1] if out.strip() else '(none)'}")
        return

    recovery = [r for r in relations
                if "upgrade" in r or "recover" in r or "repair" in r]
    if not recovery:
        record("R0.3b protocol mismatch offers a runnable relation", FAIL,
               f"a stale protocol fails with a message naming both versions and "
               f"no relation to act on. The static relation set is "
               f"{relations} — none of them upgrades or recovers, and no "
               f"`asv upgrade` verb exists to publish one honestly")
        return
    record("R0.3b protocol mismatch offers a runnable relation", PASS,
           f"the published relations include {recovery}, so the remedy "
           f"`PROTOCOL_MISMATCH` describes is one an agent can run")


def r0_4b_artifacts_come_from_this_tree() -> None:
    """The built artifacts name the commit they were built from, and it is this one.

    R0.4 names this property and nothing measured it, because nothing recorded
    it: `dist-manifest.json` carries no commit, and file mtimes are a proxy that
    a fresh checkout resets. So "the artifacts were produced from the SHA being
    certified" was a sentence in a document.

    The build stage now writes `target/distrib/build-commit.txt`, and this row
    compares it against HEAD. A build left behind by an earlier commit goes red
    here rather than being certified by whoever reads the roadmap next.

    No record means UNAVAILABLE, not a pass: a clean checkout has no build, and
    "there are no artifacts" is not evidence that the ones that would be
    published are current.
    """
    # Not named `record`: that is the module-level reporting function,
    # and a local of that name shadows it into a TypeError on the first
    # report — which is the one path this row takes on a clean checkout.
    built_from = REPO / "target" / "distrib" / "build-commit.txt"
    if not built_from.is_file():
        record("R0.4b artifacts name the commit they were built from", UNAVAILABLE,
               f"{built_from.relative_to(REPO)} does not exist; nothing records which "
               f"commit these artifacts came from, so the condition could not "
               f"be measured")
        return

    recorded = built_from.read_text(encoding="utf-8").strip()
    code, out = run(["git", "rev-parse", "HEAD"])
    head = out.strip()
    if code != 0 or len(head) != 40:
        record("R0.4b artifacts name the commit they were built from", UNAVAILABLE,
               f"git could not say what HEAD is (exit {code})")
        return

    if recorded != head:
        record("R0.4b artifacts name the commit they were built from", FAIL,
               f"the artifacts in target/distrib were built from {recorded[:12]}, "
               f"and HEAD is {head[:12]}. A build left behind by an earlier "
               f"commit is not evidence about this one; re-run the release "
               f"pipeline before treating it as a certification")
        return
    record("R0.4b artifacts name the commit they were built from", PASS,
           f"the artifacts in target/distrib record {recorded[:12]}, which is "
           f"HEAD. Whether the tree is clean is R0.4's claim and not this row's, "
           f"so it is not asserted here")


# -------------------------------------------------------------------- main

def main() -> int:
    print("R0 exit gate — truthfulness, distribution, skill\n")
    r0_1_roadmap_authority()
    r0_1b_repository_authority()
    r0_2_installer_provenance()
    r0_2b_documented_install()
    r0_3_published_skill()
    r0_3b_upgrade_relation()
    r0_4_atomic_history()
    r0_4b_artifacts_come_from_this_tree()

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
