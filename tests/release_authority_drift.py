#!/usr/bin/env python3
"""Falsification for `scripts/check-release-authority.py`.

Every row of R0.1 is a claim about git, and every one of them is a claim that
was *true* on the day it was written. Four green rows on a repository whose
history has never contained the defect prove only that the defects have not
happened yet. This suite builds a throwaway repository and a throwaway remote
for each row and breaks that row on purpose.

The remote is a local bare repository reached over the `file://` transport, so
A3 and A4 — which need to read a remote — are falsifiable on a machine with no
network at all. That matters: a remote property that can only be tested by
reaching GitHub is a property nobody runs the test for.

Run: python3 tests/release_authority_drift.py
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-release-authority.py"

ENV = dict(
    os.environ,
    GIT_AUTHOR_NAME="falsifier",
    GIT_AUTHOR_EMAIL="falsifier@example.invalid",
    GIT_COMMITTER_NAME="falsifier",
    GIT_COMMITTER_EMAIL="falsifier@example.invalid",
    # The tagger identity has to exist even for `--allow-empty` commits, and a
    # suite that depends on the developer's global git config is a suite that
    # passes on one machine for the wrong reason.
    GIT_CONFIG_GLOBAL="/dev/null",
    GIT_CONFIG_SYSTEM="/dev/null",
)


def git(cwd: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(cwd), *args], env=ENV,
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{p.stdout}{p.stderr}")
    return p.stdout.strip()


def load_guard():
    spec = importlib.util.spec_from_file_location("authority_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def build_repo(root: Path) -> tuple[Path, str]:
    """A repository whose releases are all correctly published, then push it.

    Returns `(worktree, remote_url)`. The result is a fixture in which all four
    rows pass, so each case below breaks exactly one thing.
    """
    remote = root / "remote.git"
    git(root, "init", "--bare", "-b", "main", str(remote))

    work = root / "work"
    git(root, "init", "-b", "main", str(work))
    # Identity is set on the fixture repository itself, by the wrapper's own
    # first suggestion. The alternative — `RANDOM_GIT_COMMITTER_DISABLED=1` —
    # would switch off a control this machine installs to keep commits signed,
    # and the only thing that would need signing here is a commit in /tmp that
    # is thrown away at the end of the case.
    git(work, "config", "user.name", "falsifier")
    git(work, "config", "user.email", "falsifier@example.invalid")
    git(work, "config", "commit.gpgsign", "false")
    git(work, "config", "tag.gpgsign", "false")
    git(work, "commit", "--allow-empty", "-m", "one")
    git(work, "tag", "-a", "v1.0.0", "-m", "agent-secretless 1.0.0")
    git(work, "commit", "--allow-empty", "-m", "two")
    git(work, "tag", "-a", "v1.1.0", "-m", "agent-secretless 1.1.0")
    git(work, "remote", "add", "origin", remote.as_uri())
    git(work, "push", "-q", "origin", "main", "--tags")
    return work, remote.as_uri()


def run_rows(work: Path, remote_url: str) -> dict[str, tuple[str, str]]:
    """Run the guard against the fixture and return `{row: (state, evidence)}`."""
    guard = load_guard()
    guard.REPO = work
    guard.BRANCH = "main"
    guard.REMOTE = remote_url
    guard._results = []
    guard.check_local_tags()
    guard.check_remote()
    return {name: (state, ev) for name, state, ev in guard._results}


def row_for(results: dict[str, tuple[str, str]], prefix: str) -> tuple[str, str]:
    for name, value in results.items():
        if name.startswith(prefix):
            return value
    raise AssertionError(f"no row starting with {prefix!r} in {sorted(results)}")


class Case:
    def __init__(self, name: str, expect_pass: bool, mutate, prefix: str,
                 must_contain: str = ""):
        self.name = name
        self.expect_pass = expect_pass
        self.mutate = mutate
        self.prefix = prefix
        self.must_contain = must_contain


def run_case(case: Case) -> tuple[str, bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        work, remote_url = build_repo(root)
        if case.mutate is not None:
            case.mutate(work, root, remote_url)
        results = run_rows(work, remote_url)
        state, evidence = row_for(results, case.prefix)
        if case.expect_pass:
            ok = state == "PASS"
            detail = f"{state}: {evidence}"
        else:
            blob = f"{state}: {evidence}"
            ok = state == "FAIL" and case.must_contain in evidence
            detail = blob or "(no evidence)"
    return case.name, ok, detail


def main() -> int:
    if not GUARD.exists():
        print(f"FAIL guard not found: {GUARD}")
        return 1

    def lightweight_tag(work: Path, root: Path, remote: str) -> None:
        # A1: `git tag <name>` with no `-a` is a ref, not an object. This is
        # the exact shape v0.35.0 shipped.
        git(work, "tag", "v2.0.0", "HEAD")
        git(work, "push", "-q", "origin", "v2.0.0")

    def tag_off_branch(work: Path, root: Path, remote: str) -> None:
        # A2: a release on a commit the branch does not contain.
        git(work, "checkout", "-q", "-b", "sidetrack")
        git(work, "commit", "--allow-empty", "-m", "unmerged")
        git(work, "tag", "-a", "v2.0.0", "-m", "agent-secretless 2.0.0")
        git(work, "push", "-q", "origin", "v2.0.0")
        git(work, "checkout", "-q", "main")

    def tag_missing_on_remote(work: Path, root: Path, remote: str) -> None:
        # A3: a release that exists only in the checkout. `gh release create`
        # would resolve such a tag against the remote default branch, which is
        # how v0.35.0 ended up naming a commit from v0.32.0.
        git(work, "commit", "--allow-empty", "-m", "three")
        git(work, "tag", "-a", "v2.0.0", "-m", "agent-secretless 2.0.0")

    def remote_tag_lightweight(work: Path, root: Path, remote: str) -> None:
        # A3: annotated locally, lightweight on the remote — a re-tag that
        # pushed a ref instead of an object.
        git(work, "tag", "-a", "v2.0.0", "-m", "agent-secretless 2.0.0")
        git(work, "push", "-q", "origin", "v2.0.0")
        git(work, "push", "-q", "--force", "origin", "refs/tags/v2.0.0:refs/tags/v2.0.0")
        # Replace the annotated object with a plain ref pointing at the commit.
        subprocess.run(["git", "-C", str(work), "update-ref", "-d", "refs/tags/v2.0.0"],
                       env=ENV, capture_output=True, text=True, check=True)
        sha = git(work, "rev-parse", "HEAD")
        subprocess.run(["git", "-C", str(work), "push", "-q", "--force", "origin",
                        f"{sha}:refs/tags/v2.0.0"],
                       env=ENV, capture_output=True, text=True, check=True)

    def local_and_remote_disagree(work: Path, root: Path, remote: str) -> None:
        # A3: the same tag name, two different commits. The release is cut
        # against the local tag while the remote still names the old commit.
        #
        # The first version of this re-tagged *and* force-pushed, which moves
        # both sides together and leaves them in agreement — a mutation that
        # tests nothing and passed for the wrong reason. Divergence needs
        # exactly one side to move, and the side that forgets is the one a
        # person controls.
        git(work, "commit", "--allow-empty", "-m", "four")
        git(work, "push", "-q", "origin", "main")
        subprocess.run(["git", "-C", str(work), "tag", "-f", "-a", "v1.1.0",
                        "-m", "agent-secretless 1.1.0"],
                       env=ENV, capture_output=True, text=True, check=True)

    def release_commit_outside_remote_branch(work: Path, root: Path, remote: str) -> None:
        # A4: the release is fully published — tag on the remote, annotated —
        # but `origin/main` does not contain it. Cloning and checking out the
        # tag lands somewhere the branch does not reach.
        git(work, "checkout", "-q", "-b", "sidetrack", "HEAD")
        git(work, "commit", "--allow-empty", "-m", "off the branch")
        git(work, "tag", "-a", "v2.0.0", "-m", "agent-secretless 2.0.0")
        git(work, "push", "-q", "origin", "v2.0.0")
        git(work, "checkout", "-q", "main")

    cases = [
        Case("a repository whose releases are all correctly published passes",
             True, None, "A1"),
        Case("a lightweight local release tag is caught", False,
             lightweight_tag, "A1", "lightweight"),
        Case("a release on a commit the branch does not contain is caught", False,
             tag_off_branch, "A2", "does not contain"),
        Case("a release tag missing from the remote is caught", False,
             tag_missing_on_remote, "A3", "not on the remote"),
        Case("a release tag that is lightweight on the remote is caught", False,
             remote_tag_lightweight, "A3", "lightweight on the remote"),
        Case("a release tag local and remote disagree about is caught", False,
             local_and_remote_disagree, "A3", "disagree"),
        Case("a published release whose commit is outside the remote branch is caught",
             False, release_commit_outside_remote_branch, "A4",
             "does not contain"),
    ]

    results = [run_case(case) for case in cases]
    failed = 0
    print("release authority falsification\n")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"          {detail}")
            failed += 1
    print(f"\n{len(results) - failed}/{len(results)} behaviours confirmed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())