#!/usr/bin/env python3
"""The release law, executable: change -> classification -> commit -> version.

**The rule this enforces.** A version is not derived from a diff and it is not
allowed to be defended by a commit message. It is derived from a
*classification* — a judgement about what the change actually is — and the
Conventional Commit type is where that judgement is recorded. The chain runs
one way:

    real change -> semantic classification -> Conventional Commit -> version

`from_named_policy_text` is the case that produced this file. It was public
API in a publishable crate, called from another crate in the workspace, so it
was a new capability and the classification was `feat`; the version was
therefore a MINOR. It had been tagged `fix` first, and a `fix` would have
produced a PATCH. That is the whole point: the classification is the act that
moves the version, so choosing the type is the decision, and it cannot be
argued backwards from whatever number is already in the tree.

**What the script can and cannot do.** It cannot classify a change — nothing
that reads a commit message can, and a script that claimed to would be reading
the conclusion instead of the cause. What it can do is make the chain fail
closed: every commit since the last tag must carry a type, and the version in
the tree must be exactly what those types derive. So the person doing the
release has to classify before they can publish, and cannot publish a number
that contradicts the classification they already made.

**Pre-1.0.** A breaking change bumps MINOR rather than MAJOR while the major
version is 0. That is the ordinary reading of SemVer below 1.0, and it keeps
this gate from being the thing that pushes the project to 1.0.0 — a decision
that belongs to a release whose evidence says so, not to a version check that
fires on a `!`.

Run:

    python3 scripts/check-release-bump.py            # gate
    python3 scripts/check-release-bump.py --explain  # print the derivation
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Conventional Commits types, and what each one is allowed to mean for a
# version. This table is the law; a type absent from it is a commit this
# repository has not thought about, and an unclassified commit fails rather
# than defaulting to PATCH.
#
# PATCH carries the changes that alter behaviour without adding capability:
# `fix` is the obvious one and `perf` is the same promise made about speed.
# `refactor`, `test`, `docs`, `chore`, `ci`, `build` and `style` alter nothing
# a consumer of the crate can observe.
TYPE_IMPACT = {
    "feat": "minor",
    "fix": "patch",
    "perf": "patch",
    "revert": "patch",
    "refactor": "patch",
    "test": "patch",
    "docs": "patch",
    "chore": "patch",
    "ci": "patch",
    "build": "patch",
    "style": "patch",
}

CONVENTIONAL = re.compile(
    r"^(?P<type>[a-zA-Z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s"
)
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE", re.MULTILINE)

# Ordering for "the strongest impact on the branch".
RANK = {"patch": 0, "minor": 1, "breaking": 2}


def workspace_version() -> str:
    with open(REPO / "Cargo.toml", "rb") as fh:
        return str(tomllib.load(fh)["workspace"]["package"]["version"])


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def last_tag() -> str | None:
    try:
        return git("describe", "--tags", "--abbrev=0")
    except subprocess.CalledProcessError:
        return None


def commits_since(ref: str) -> list[str]:
    log = git("log", f"{ref}..HEAD", "--format=%H%x00%s%x00%B%x1e")
    commits = []
    for record in log.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, subject, body = (record.split("\0", 2) + ["", ""])[:3]
        commits.append((sha.strip(), subject.strip(), body))
    return commits


def classify(subject: str, body: str) -> tuple[str | None, str]:
    """Return `(impact, reason)` for one commit, or `(None, why)` if it cannot
    be classified.

    A `!` on the type, or a `BREAKING CHANGE` footer, outranks the type table:
    that is what the notation is for.
    """
    m = CONVENTIONAL.match(subject)
    if not m:
        return None, f"no Conventional Commits type in {subject!r}"
    ctype = m.group("type").lower()
    if m.group("bang") or BREAKING_FOOTER.search(body or ""):
        return "breaking", f"{ctype} with a breaking-change marker"
    impact = TYPE_IMPACT.get(ctype)
    if impact is None:
        return None, f"type {ctype!r} is not in the release law's table"
    return impact, ctype


def bump(version: str, impact: str) -> str:
    major, minor, patch = (int(p) for p in version.split("."))
    if impact == "breaking":
        # Below 1.0 a breaking change is a MINOR bump. See the docstring.
        if major > 0:
            return f"{major + 1}.0.0"
        return f"{major}.{minor + 1}.0"
    if impact == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--explain", action="store_true", help="print the derivation, fail nothing"
    )
    args = parser.parse_args()

    tag = last_tag()
    if tag is None:
        print("check-release-bump: no tag to measure against; nothing to derive.")
        return 0
    base = tag.lstrip("v")
    commits = commits_since(tag)

    if not commits:
        print(f"check-release-bump: HEAD is {tag}; no commits to classify.")
        return 0

    lines = [f"base {tag} ({base})"]
    unclassified = []
    impact = None
    for sha, subject, body in commits:
        got, reason = classify(subject, body)
        if got is None:
            unclassified.append((sha, reason))
            lines.append(f"  {sha[:7]}  UNCLASSIFIED  {reason}")
            continue
        lines.append(f"  {sha[:7]}  {got:<9}  {reason:<28} {subject.splitlines()[0][:60]}")
        # The release takes the strongest impact on the branch, not the last one
        # seen. Taking the last would make the version depend on commit order,
        # which is not a property anyone means.
        impact = got if impact is None else max(impact, got, key=RANK.__getitem__)

    if unclassified:
        for sha, reason in unclassified:
            print(f"check-release-bump: {sha[:7]} cannot be classified: {reason}")
        print(
            "\nEvery commit since the last tag must state what it is, because the\n"
            "version is derived from what they are. An unclassified commit has no\n"
            "standing in this law, and defaulting it to a PATCH would be exactly the\n"
            "move this file exists to prevent."
        )
        return 1

    expected = bump(base, impact or "patch")
    current = workspace_version()
    lines.append(f"strongest impact: {impact or 'patch'}")
    lines.append(f"derived version:   {expected}")
    lines.append(f"tree version:      {current}")

    if args.explain:
        print("\n".join(lines))
        return 0

    if current == base:
        print(f"check-release-bump: {tag} has {len(commits)} commit(s) behind it and "
              f"the tree is still at {current}.")
        print("\n".join(lines))
        print("\nFAIL: commits since the tag with no version change.")
        return 1

    if current != expected:
        print(f"check-release-bump: the tree says {current}, the classification says {expected}.")
        print("\n".join(lines))
        print(
            f"\nThe classification is not the argument; it is the decision. If {current}\n"
            f"is genuinely right, then a commit since {tag} is typed as what it is\n"
            f"rather than as what would have been convenient."
        )
        return 1

    print(f"check-release-bump: {current} follows from {len(commits)} commit(s) since {tag}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())