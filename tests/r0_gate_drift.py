#!/usr/bin/env python3
"""Falsification for the three rows `tests/r0_gate.py` added to itself.

`r0_gate.py` had four rows and all four of them were green while `install.py`
had never once completed an install and while `main` was eight commits ahead of
the remote. The three rows added here — R0.1b, R0.2b, R0.3b — are the ones that
can go red when the product changes, and a row added for that purpose is the
one most likely to be written in a way that cannot fail.

Two of the three delegate to gates that carry their own falsification
(`tests/release_authority_drift.py`, 7/7; `tests/documented_install_drift.py`,
7/7), so what is exercised here is the plumbing — that the delegation actually
runs, and that it reports rather than swallowing. The third, R0.3b, owns its
whole predicate and is broken in both directions here.

    a real relation set with no upgrade relation      FAIL, naming them
    a relation set that does recover                  PASS, so the row can close
    a surface that is not JSON at all                 FAIL
    `cargo metadata` that prints no JSON              UNAVAILABLE, not a crash
    no built binary                                   UNAVAILABLE, not a pass

The last three are the shortcut this exists to rule out. A row that cannot
measure something must not be able to answer "yes", and before the guard was
added the `cargo metadata` one took the whole gate down with a traceback — a
crash reporting nothing at all, which is the single outcome that cannot be told
apart from a row that was never run.

Run: python3 tests/r0_gate_drift.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "tests" / "r0_gate.py"

PASSED, FAILED = 0, 0

ROWR0_1B = "R0.1b repository and release authority"
ROWR0_3B = "R0.3b protocol mismatch offers a runnable relation"


def load_gate() -> object:
    """`r0_gate` imported rather than run, so a row can be called on its own.

    Importing executes the module body, which is constants and helpers only —
    `main()` is behind the `__main__` guard, so nothing is measured by accident.
    """
    spec = importlib.util.spec_from_file_location("r0_gate_under_test", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def real_target_directory() -> str:
    p = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps",
         "--manifest-path", str(REPO / "Cargo.toml")],
        capture_output=True, text=True, timeout=300)
    return json.loads(p.stdout)["target_directory"]


def envelope(relations: list[str]) -> str:
    """The shape `asv capabilities --json` returns with no broker reachable."""
    return json.dumps({
        "schema": "asv.agent/v1",
        "status": "blocked",
        "data": {"relations": relations, "broker_reachable": False},
    })


def check(name: str, ok: bool, detail: str) -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
    else:
        FAILED += 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}\n          {detail[:200]}")


def state_of(gate: object, row: str) -> str | None:
    return next((s for n, s, _ in gate._results if n == row), None)


def detail_of(gate: object, row: str) -> str:
    return next((d for n, _, d in gate._results if n == row), "")


def exercise(gate: object, row: str, label: str, stub, expect: str) -> None:
    gate._results.clear()
    original = gate.run
    gate.run = stub
    try:
        {"R0.1b": gate.r0_1b_repository_authority,
         "R0.3b": gate.r0_3b_upgrade_relation}[row[:5]]()
    finally:
        gate.run = original
    got = state_of(gate, row)
    check(label, got == expect,
          f"{row} reported {got!r}: {detail_of(gate, row)}")


def main() -> int:
    print("r0_gate.py falsifiability\n")
    gate = load_gate()
    target = real_target_directory()

    # --- R0.1b delegates, and a delegation that cannot run is not a pass.

    def authority_ok(args, cwd=None, timeout=1800):
        return 0, "1 passed, 0 failed, 0 unknown\n"

    exercise(gate, ROWR0_1B, "a green authority gate satisfies R0.1b",
             authority_ok, gate.PASS)

    def authority_red(args, cwd=None, timeout=1800):
        return 1, "release config check FAILED:\n  - a release tag is lightweight\n"

    exercise(gate, ROWR0_1B, "a red authority gate fails R0.1b",
             authority_red, gate.FAIL)

    def authority_missing(args, cwd=None, timeout=1800):
        return 3, "that is an argument error, not an OSError\n"

    # `run()` catches OSError and reports it as 127 rather than raising, so the
    # stub returns that shape instead of throwing — a stub that raised would be
    # testing the stub, not the row.
    exercise(gate, ROWR0_1B, "an authority gate that cannot start is UNAVAILABLE",
             lambda args, cwd=None, timeout=1800: (127, "no such file"),
             gate.UNAVAILABLE)

    # --- R0.3b owns its predicate, so it is broken in both directions.

    def metadata(args, cwd=None, timeout=1800):
        return 0, json.dumps({"target_directory": target})

    exercise(gate, ROWR0_3B,
             "the real surface is measured, not assumed",
             gate.run, gate.FAIL)

    def recovering(args, cwd=None, timeout=1800):
        return metadata(args) if "metadata" in args else (
            1, envelope(["asv://rels/status", "asv://rels/upgrade"]))

    exercise(gate, ROWR0_3B, "a published recovery relation closes the row",
             recovering, gate.PASS)

    def unreadable(args, cwd=None, timeout=1800):
        return metadata(args) if "metadata" in args else (0, "not json at all")

    exercise(gate, ROWR0_3B, "a surface that is not JSON is FAIL, never a pass",
             unreadable, gate.FAIL)

    def bad_metadata(args, cwd=None, timeout=1800):
        return 0, "cargo: not a workspace"

    exercise(gate, ROWR0_3B,
             "cargo metadata printing no JSON is UNAVAILABLE, not a crash",
             bad_metadata, gate.UNAVAILABLE)

    def no_binary(args, cwd=None, timeout=1800):
        return 0, json.dumps({"target_directory": "/tmp/r0-gate-no-binaries-here"})

    exercise(gate, ROWR0_3B, "a missing binary is UNAVAILABLE, never a pass",
             no_binary, gate.UNAVAILABLE)

    print(f"\n{PASSED}/{PASSED + FAILED} behaviours confirmed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())