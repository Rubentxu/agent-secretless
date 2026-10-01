#!/usr/bin/env python3
"""Falsifiability tests for scripts/check-gate-status.py.

A guard nobody has tried to break is a guard whose green means nothing. These
cases pin the three behaviours the guard promises:

1. a stale claim makes it exit 1 and name the contradiction,
2. an accurate table makes it exit 0,
3. a row it does not recognise is ignored rather than failed.

Case 1 is the one that matters. If the guard ever stops catching a stale
table, its own test goes red, which is the only way a gate like this can be
trusted.

Run: python3 tests/gate_status_drift.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-gate-status.py"

STALE = """
## Gate status as of 2026-01-01

| Gate | Status | Evidence |
|---|---|---|
| R11 full suite | pass | 486 passed / 0 failed / 1 ignored |
| R11 dependency audit | pass | `cargo audit`: 0 advisories, 335 deps |
| M11-M13 semver | **NOT MET** | tagged `m11-oauth2-framework` and `v9.9.9` is the release |
"""

ACCURATE = """
## Gate status as of 2026-01-01

| Gate | Status | Evidence |
|---|---|---|
| M12 hardware-backed vault | **NOT MET** | needs a host with a TPM; nothing here can decide it |
| M11 live OAuth2 provider | **NOT MET** | needs a real authorization server |
"""

UNRECOGNISED = """
## Gate status as of 2026-01-01

| Gate | Status | Evidence |
|---|---|---|
| Some future gate | pass | a claim this guard has never heard of, written honestly |
"""


def run_guard(table: str) -> tuple[int, str]:
    """Run the guard against a synthetic table by pointing it at a temp vault."""
    with tempfile.TemporaryDirectory() as tmp:
        fake_table = Path(tmp) / "16-SECURITY-RELEASE-GATES.md"
        fake_table.write_text(table, encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, str(GUARD),
                "--table", str(fake_table),
            ],
            capture_output=True, text=True, check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    if not GUARD.exists():
        print(f"FAIL guard not found: {GUARD}")
        return 1

    results: list[tuple[str, bool, str]] = []

    # 1. A stale claim must be caught.
    code, out = run_guard(STALE)
    caught = code == 1 and "drift" in out
    named_the_contradiction = bool(
        re.search(r"states \d+ (passed|tests|advisor|deps)", out)
    ) or "NOT an ancestor" in out or "which does not exist" in out
    results.append(
        (
            "a stale table fails the guard and names the contradiction",
            caught and named_the_contradiction,
            out.strip().splitlines()[-1] if out.strip() else "(no output)",
        )
    )

    # 2. An accurate table must pass.
    code, out = run_guard(ACCURATE)
    results.append(
        (
            "an accurate table passes",
            code == 0,
            out.strip() or "(no output)",
        )
    )

    # 3. An unrecognised row is ignored, not failed.
    code, out = run_guard(UNRECOGNISED)
    results.append(
        (
            "an unrecognised row is ignored rather than failed",
            code == 0,
            out.strip() or "(no output)",
        )
    )

    # 4. The unverifiable rows are never asserted on, even when they contain
    #    numbers that would look like a checkable count.
    code, out = run_guard(
        """
| M12 hardware-backed vault | **NOT MET** | 486 passed / 335 deps, unverifiable here |
"""
    )
    results.append(
        (
            "host-dependent rows are never machine-asserted",
            code == 0,
            out.strip() or "(no output)",
        )
    )

    print("Gate status guard falsifiability\n")
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
