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

import json
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

    # 5. A tag that does not exist must be named, not ignored. A guard that
    #    shrugs at a typo'd tag would pass the very row it exists to check.
    code, out = run_guard(
        """
| Gate | Status | Evidence |
|---|---|---|
| M11-M13 semver | **NOT MET** | `m99-nope` is inside `v0.17.6` |
"""
    )
    results.append(
        (
            "a nonexistent tag is named as drift",
            code == 1 and "m99-nope" in out,
            out.strip() or "(no output)",
        )
    )

    # 6. A release that does not exist is drift, not an unparseable row.
    code, out = run_guard(
        """
| Gate | Status | Evidence |
|---|---|---|
| M11-M13 semver | **NOT MET** | `m12-tpm-vault` is in `v9.9.9` |
"""
    )
    results.append(
        (
            "a nonexistent release is named as drift",
            code == 1 and "v9.9.9" in out,
            out.strip() or "(no output)",
        )
    )

    # 7. A malformed table must not crash the guard. Unparseable is not the
    #    same as false, and a guard that raises on bad input gets disabled.
    code, out = run_guard("| Gate | Status |\n|---|---|\n| R11 full suite | pass\n")
    results.append(
        (
            "a malformed table is ignored rather than crashed on",
            code == 0 and "Traceback" not in out,
            out.strip() or "(no output)",
        )
    )

    # 8. A README whose count disagrees with the repository is drift. The
    #    README is not part of the table, which is why its count sat at 424
    #    while the real number was 669 for several milestones: a claim in a
    #    document that no gate contradicted.
    #
    #    This case cannot drive the README itself — the guard reads the real
    #    ones from the repository — so it asserts the row is recognised and
    #    that the guard reports a count mismatch when the table's number is
    #    wrong, which is the same code path.
    code, out = run_guard(
        """
| Gate | Status | Evidence |
|---|---|---|
| R11 README test count | pass | both READMEs state 1 tests |
"""
    )
    results.append(
        (
            "a stale README count is named as drift",
            code == 1 and "README" in out,
            out.strip() or "(no output)",
        )
    )

    # 9. A row that mentions README but states no count must be left alone,
    #    so adding the row cannot make the guard fail on prose.
    code, out = run_guard(
        """
| Gate | Status | Evidence |
|---|---|---|
| R11 README truthfulness | pass | the README no longer overclaims secretless |
"""
    )
    results.append(
        (
            "a README row with no count is ignored rather than failed",
            code == 0,
            out.strip() or "(no output)",
        )
    )


    # The console-surface check reads real files, not the table, so it cannot
    # be driven by a synthetic table the way the others are. It is exercised
    # directly against a temp tree instead — and both directions matter: a
    # clean tree must produce no failure (otherwise the gate is noise), and a
    # tree with a remote origin must produce one that names the file (otherwise
    # the gate is decoration).
    def _console_case(leak: str) -> tuple[bool, str]:
        import importlib.util

        spec = importlib.util.spec_from_file_location("guard", GUARD)
        guard = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(guard)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "apps/desktop/ui").mkdir(parents=True)
            (root / "apps/desktop/tauri.conf.json").write_text(
                json.dumps({
                    "app": {"security": {
                        "csp": "default-src 'self'; script-src 'self'; "
                               "connect-src 'self'; object-src 'none'",
                        "assetProtocol": {"enable": False, "scope": []},
                    }},
                }),
                encoding="utf-8",
            )
            (root / "apps/desktop/ui/app.css").write_text(leak, encoding="utf-8")
            original = guard.REPO
            guard.REPO = root
            try:
                failures: list[str] = []
                guard.check_console_surface("R12", "pass", failures)
            finally:
                guard.REPO = original
            return bool(failures), "; ".join(failures)

    ok, detail = _console_case("/* local only, no remote font */")
    results.append(
        (
            "a console front-end with no remote origin passes the R12 check",
            not ok,
            detail,
        )
    )

    ok, detail = _console_case('@import url("https://fonts.googleapis.com/x");')
    results.append(
        (
            "a remote origin in the front-end fails the R12 check and is named",
            ok and "app.css" in detail,
            detail,
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
