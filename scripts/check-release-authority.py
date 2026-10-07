#!/usr/bin/env python3
"""R0.1 — repository and release authority. Four properties, each measured.

    A1  every release tag is annotated, not a lightweight ref
    A2  every release tag peels to a commit that is an ancestor of the branch
    A3  every release tag is on the remote, annotated, peeling to the same commit
    A4  the remote branch contains every release tag's commit

# Why this exists rather than `release-tag-check.sh`

`release-tag-check.sh` answers one question about one tag: is the tag being cut
right now annotated, on HEAD, and pushed. It is the right check at that moment
and it caught the tag `v0.35.0` actually shipped.

What it cannot do is answer *"has any release ever admitted a commit that is not
an ancestor of the branch"*. That is a property of the whole set, and it was
being asserted nowhere. On 2026-10-07 it happened to hold — 53 release tags,
every one annotated, every one an ancestor of `main` — but a property that no
command can make false is not a property, it is a sentence.

# Why A4 asks about the *remote* branch and not the local one

The v0.35.0 incident was not a tag problem at all. The published artifacts were
built from `b5c7a54` and were never wrong; only the commit the tag *named* was,
because `main` had not been pushed since v0.32.0 and `gh release create`
resolved the tag against the remote default branch. A release is reproducible
from the remote or it is not reproducible, so the question A4 asks is whether
`origin/main` contains the tag's commit — not whether the checkout the releaser
happens to be sitting on does.

# UNKNOWN is not PASS

The remote half needs the network. `scripts/ci-policy.sh` fails any pipeline
that finds one, so this runs on the machine cutting the release; a machine that
cannot reach the remote reports UNKNOWN for A3 and A4 and exits non-zero, the
same rule `tests/r0_gate.py` states. A release that cannot prove where its own
tag lives has not proved it.

Run: python3 scripts/check-release-authority.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Rebound by the falsification suite; never bound at import, for the same
# reason `scripts/check-doc-claims.py` does not bind its paths: a guard that
# cannot be pointed at a fixture is a guard that cannot be shown able to fail.
REPO = Path(__file__).resolve().parent.parent

BRANCH = "main"
REMOTE = "origin"

# `v1.2.3` exactly. A pre-release suffix is matched too, because a tag that
# names a release and is skipped by this glob is a tag nobody audits.
RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"

_results: list[tuple[str, str, str]] = []


def record(name: str, state: str, evidence: str) -> None:
    _results.append((name, state, evidence))
    mark = {PASS: "ok  ", FAIL: "FAIL", UNKNOWN: "unkn"}[state]
    print(f"  {mark}  {name}\n          {evidence}")


def run(args: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(args, cwd=REPO, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)


def local_release_tags() -> list[tuple[str, str, str | None]]:
    """`(name, objecttype, peeled)` for every release tag, in one call.

    `%(objecttype)` is `commit` for a lightweight ref and `tag` for an
    annotated one; `%(*objectname)` is empty unless the ref is annotated and
    peels to a commit. One `for-each-ref` rather than one subprocess per tag,
    because 53 tags at ~20ms a process is a second of doing nothing.
    """
    code, out = run([
        "git", "for-each-ref",
        "--format=%(refname:short)|%(objecttype)|%(*objectname)",
        "refs/tags/",
    ])
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        name, otype, peeled = parts
        if RELEASE_TAG.match(name):
            rows.append((name, otype, peeled or None))
    return rows


def commits_reachable(ref: str) -> set[str] | None:
    code, out = run(["git", "rev-list", ref])
    if code != 0:
        return None
    return set(out.split())


# --------------------------------------------------------------------- A1, A2

def check_local_tags() -> None:
    tags = local_release_tags()
    if not tags:
        record("A1/A2 local release tags", FAIL,
               "no release tags found; a repository where this cannot be read "
               "is not one where the property holds")
        return

    lightweight = [n for n, otype, _ in tags if otype != "tag"]
    if lightweight:
        record("A1 every release tag is annotated", FAIL,
               f"{len(lightweight)} of {len(tags)} release tags are lightweight "
               f"refs: {lightweight[:5]}. A lightweight ref is a pointer to a "
               f"commit with no author, no date and no message, so `git "
               f"describe`, a changelog and an auditor cannot say what the "
               f"release was without trusting whoever pushed the branch. This is "
               f"the exact shape v0.35.0 shipped.")
    else:
        record("A1 every release tag is annotated", PASS,
               f"{len(tags)} release tags, every one an annotated object that "
               f"peels to a commit")

    reachable = commits_reachable(BRANCH)
    if reachable is None:
        record("A2 release tags are ancestors of the branch", UNKNOWN,
               f"could not resolve {BRANCH}; refusing to pass a property that "
               f"cannot be read")
        return

    orphaned = []
    for name, _, peeled in tags:
        if peeled is None:
            continue  # already reported by A1
        if peeled not in reachable:
            orphaned.append(f"{name} -> {peeled[:12]}")
    if orphaned:
        record("A2 release tags are ancestors of the branch", FAIL,
               f"{len(orphaned)} release tags name a commit that {BRANCH} does "
               f"not contain: {orphaned[:5]}. A release on a commit outside the "
               f"branch is a release nobody can reach by cloning the project.")
    else:
        record("A2 release tags are ancestors of the branch", PASS,
               f"all {len(tags)} release tags resolve to commits {BRANCH} "
               f"contains")


# ----------------------------------------------------------------- A3, A4

def check_remote() -> None:
    """The remote half. One `ls-remote`, both properties, one round trip.

    `--refs` alone would report an annotated tag and its peeled form as two
    lines with no way to tell which is which, so both forms are requested and
    matched by name.
    """
    code, out = run(["git", "ls-remote", "--tags", REMOTE], timeout=180)
    if code != 0:
        record("A3 release tags exist on the remote", UNKNOWN,
               f"`git ls-remote --tags {REMOTE}` failed (exit {code}); the remote "
               f"could not be read, and a release that cannot prove where its own "
               f"tag lives has not proved it")
        return

    remote_annotated: dict[str, str] = {}
    remote_plain: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        sha, ref = parts
        # The `^{}` suffix marks the *peeled commit* of an annotated tag and is
        # not part of the tag's name. It has to come off before the name is
        # matched: the first version matched first and dropped every peeled
        # line, which left `remote_annotated` empty and reported all 53 release
        # tags as lightweight against a remote where all 53 are annotated.
        peeled = ref.endswith("^{}")
        name = ref[len("refs/tags/"):]
        if peeled:
            name = name[:-3]
        if not RELEASE_TAG.match(name):
            continue
        if peeled:
            remote_annotated[name] = sha
        else:
            remote_plain.add(name)

    # A tag is lightweight when it has a plain ref and *no* peeled form. The
    # first version of this counted the plain ref as lightweight on its own,
    # and reported all 53 release tags as lightweight against a remote where all
    # 53 are annotated — an annotated tag has a plain ref too, naming the tag
    # object, and the peeled commit arrives as the second line. That is the
    # failure this file's own header warns about, committed by the file that
    # warns about it: a guard that reports a defect which is not there teaches
    # its reader to ignore it.
    remote_lightweight = sorted(remote_plain - set(remote_annotated))

    local = local_release_tags()
    missing = [n for n, _, _ in local if n not in remote_plain]
    # A release tag the remote has and this clone does not is a release the
    # repository cannot describe: `git checkout <tag>` fails here, so the tag
    # is only reproducible for whoever cloned before it was pushed.
    remote_only = sorted(set(remote_plain) - {n for n, _, _ in local})
    diverged = [
        f"{n}: local {p[:12]} vs remote {remote_annotated[n][:12]}"
        for n, _, p in local
        if p and n in remote_annotated and p != remote_annotated[n]
    ]

    problems = []
    if remote_lightweight:
        problems.append(
            f"{len(remote_lightweight)} release tags are lightweight on the "
            f"remote: {remote_lightweight[:5]}"
        )
    if missing:
        problems.append(
            f"{len(missing)} release tags exist locally but not on the remote: "
            f"{missing[:5]}"
        )
    if remote_only:
        problems.append(
            f"{len(remote_only)} release tags exist on the remote but not in "
            f"this checkout: {remote_only[:5]}"
        )
    if diverged:
        problems.append(f"local and remote disagree on the commit: {diverged[:3]}")
    if problems:
        record("A3 release tags exist on the remote", FAIL, "; ".join(problems))
    else:
        record("A3 release tags exist on the remote", PASS,
               f"all {len(local)} release tags are on {REMOTE}, annotated, "
               f"peeling to the same commit they do locally")

    # A4 is asked of the remote branch on purpose. See the module header.
    code, out = run(["git", "ls-remote", REMOTE, f"refs/heads/{BRANCH}"], timeout=180)
    remote_head = out.split()[0] if code == 0 and out.split() else None
    if remote_head is None:
        record("A4 the remote branch contains every release commit", UNKNOWN,
               f"could not read {REMOTE}/{BRANCH}")
        return

    reachable = commits_reachable(remote_head)
    if reachable is None:
        record("A4 the remote branch contains every release commit", UNKNOWN,
               f"{remote_head[:12]} is not in this checkout, so its history "
               f"cannot be walked")
        return

    outside = [
        f"{n} -> {p[:12]}"
        for n, _, p in local
        if p and p not in reachable
    ]
    if outside:
        record("A4 the remote branch contains every release commit", FAIL,
               f"{len(outside)} release tags name commits {REMOTE}/{BRANCH} does "
               f"not contain: {outside[:5]}. Cloning the project and running "
               f"`git checkout <tag>` would land somewhere the branch does not "
               f"reach.")
    else:
        record("A4 the remote branch contains every release commit", PASS,
               f"{REMOTE}/{BRANCH} at {remote_head[:12]} contains all "
               f"{len(local)} release commits")


def main() -> int:
    print("R0.1 — repository and release authority\n")
    check_local_tags()
    check_remote()

    print()
    failed = [n for n, s, _ in _results if s == FAIL]
    unknown = [n for n, s, _ in _results if s == UNKNOWN]
    for name, state, _ in _results:
        print(f"  {state:<8} {name}")
    print(f"\n{len(_results) - len(failed) - len(unknown)} passed, "
          f"{len(failed)} failed, {len(unknown)} unknown")
    if unknown:
        print("\nUNKNOWN is not a pass. A property that could not be read "
              "has not been\nshown to hold.")
    return 1 if failed or unknown else 0


if __name__ == "__main__":
    sys.exit(main())