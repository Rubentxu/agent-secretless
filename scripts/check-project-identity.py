#!/usr/bin/env python3
"""Fails when SDDK would resolve this checkout to a different project than the
one its history belongs to.

## Why this exists

SDDK derives a project's identity from its git remote URL. Measured on
2026-10-01: a checkout whose `origin` names a *different* repository resolves
to a completely different `project_id`, and a write issued there succeeds with
**exit 0 and no warning** — into a ledger that reports `event_count: 0`. The
real ledger is untouched, and nothing in the output says the write went
somewhere else. That is silent divergence, and it is backlog
`bl-bl-01M3RYX76R000387QXS2QR7NC0` (P0).

The same measurement found a second, smaller thing: a URL differing only in
case no longer changes the identity, so that half of the original finding has
gone stale. This guard pins the half that still bites.

## What it checks

`EXPECTED_PROJECT_ID` below, against what `sddk project resolve` reports for
this checkout. Both are literal on purpose: the point is to notice that the
identity moved, and a value derived from the thing being checked cannot do
that.

A checkout that is *not* a clone of the recorded project fails loudly rather
than quietly, because a guard that only ever passes on the machine that wrote
it is not a guard.

Run: python3 scripts/check-project-identity.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# p-20a1ee316faf2ba3 — the project this repository's SDDK history belongs to.
# If this ever changes legitimately, change it in the same commit that changes
# the remote URL, and say so in the commit body: a silent identity change is
# precisely what this file exists to notice.
EXPECTED_PROJECT_ID = "p-20a1ee316faf2ba3"

# The remote this identity is derived from. Checked as well, because the
# project_id is a hash *of* this string: a changed remote with an unchanged
# project_id would mean the hash stopped being the thing it claims to be.
EXPECTED_REMOTE = "https://github.com/rubentxu/agent-secretless"


def resolve() -> dict:
    """Asks SDDK what project this checkout is, or fails."""
    try:
        out = subprocess.run(
            [
                "sddk",
                "project",
                "resolve",
                "--root",
                str(REPO),
                "--scope",
                ".",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
    except FileNotFoundError:
        print("sddk is not on PATH; cannot verify project identity", file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        print(f"sddk project resolve failed: {error.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)

    # `sddk project resolve` prints `key: value` lines, not JSON, despite
    # several sibling commands taking --format json.
    resolved = {}
    for line in out.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            resolved[key.strip()] = value.strip()
    return resolved


def main() -> int:
    resolved = resolve()
    project_id = resolved.get("project_id", "")
    remote = resolved.get("remote_url", "")

    if not project_id:
        print("sddk project resolve returned no project_id", file=sys.stderr)
        return 1

    if project_id != EXPECTED_PROJECT_ID:
        print(
            "SDDK project identity has moved.\n"
            f"  expected: {EXPECTED_PROJECT_ID}\n"
            f"  resolved: {project_id}\n"
            f"  remote:   {remote or '(none)'}\n"
            "\n"
            "Identity is derived from the remote URL, so a different remote "
            "means a different project with a different — and empty — ledger.\n"
            "A write issued under that identity succeeds with no warning.\n"
            "See bl-bl-01M3RYX76R000387QXS2QR7NC0.",
            file=sys.stderr,
        )
        return 1

    if remote.rstrip("/") != EXPECTED_REMOTE.rstrip("/"):
        print(
            "SDDK remote URL does not match the recorded one.\n"
            f"  expected: {EXPECTED_REMOTE}\n"
            f"  resolved: {remote}\n"
            "\n"
            "The project_id still resolved, which means it is not a hash of "
            "this string any more. Either the derivation changed or the guard "
            "needs re-baselining; both deserve a human.",
            file=sys.stderr,
        )
        return 1

    print(f"project identity ok: {project_id} from {remote}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
