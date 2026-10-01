#!/usr/bin/env python3
"""Falsification tests for scripts/check-project-identity.py.

A guard nobody has tried to break is a guard whose green means nothing, and
this repository has already found three of those: a test that asserted a
command's *name* instead of its help text, a test that never compared the two
values it existed to compare, and `sddk ledger verify-chain` reporting PASS
over zero events. The pattern is the same each time, and it is the reason this
file exists.

These cases pin four behaviours:

1. the real checkout passes,
2. a checkout whose identity has moved **fails** and names both ids,
3. a changed remote URL with an unchanged project_id fails, because a
   project_id that is not derived from the remote is a guard that stopped
   guarding,
4. a `sddk` that cannot be reached exits 2 rather than passing.

Case 2 is the one that matters. The whole P0 this guard mitigates is a write
that succeeds silently somewhere else; a guard that could not detect the move
would leave that entirely unguarded while reporting green.

Run: python3 tests/project_identity_drift.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-project-identity.py"

# Read from the guard rather than restated here: a second copy of the expected
# id is a second thing to forget to update, and this file's job is to test the
# guard, not to duplicate its constants.
EXPECTED = next(
    line.split("=", 1)[1].strip().strip('"')
    for line in GUARD.read_text().splitlines()
    if line.startswith("EXPECTED_PROJECT_ID")
)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}" + (f"\n        {detail}" if detail else ""))


def run_guard(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD)],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def write_stub_sddk(tmp: Path, script: str) -> Path:
    """Puts a fake `sddk` first on PATH and returns the directory holding it."""
    bindir = tmp / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    stub = bindir / "sddk"
    stub.write_text(script)
    stub.chmod(0o755)
    return bindir


def with_stubbed_sddk(tmp: Path, script: str, body):
    """Runs `body()` with a stubbed `sddk` on PATH, restoring it afterwards."""
    import os

    bindir = write_stub_sddk(tmp, script)
    original = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bindir}{os.pathsep}{original}"
    try:
        return body()
    finally:
        os.environ["PATH"] = original


def main() -> int:
    print("check-project-identity.py falsifiability\n")

    # 1 — the real checkout.
    result = run_guard(REPO)
    report(
        "the real checkout passes",
        result.returncode == 0,
        f"exit {result.returncode}: {result.stderr.strip()}",
    )

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)

        # 2 — the identity has moved. This is the P0.
        def moved() -> subprocess.CompletedProcess:
            return with_stubbed_sddk(
                tmp,
                "#!/bin/sh\n"
                "echo 'project_id: p-somewhere-else'\n"
                "echo 'remote_url: https://github.com/someone/fork'\n",
                lambda: run_guard(REPO),
            )

        result = moved()
        ok = result.returncode == 1
        report(
            "a moved project identity fails",
            ok,
            f"exit {result.returncode}, expected 1: {result.stdout.strip()}",
        )
        report(
            "the failure names both the expected and the resolved id",
            EXPECTED in result.stderr and "p-somewhere-else" in result.stderr,
            result.stderr.strip(),
        )
        report(
            "the failure points at the P0 backlog item",
            "bl-bl-01M3RYX76R000387QXS2QR7NC0" in result.stderr,
            result.stderr.strip(),
        )

        # 3 — remote changed, project_id did not. The guard must not wave it
        #     through: that combination means project_id is no longer a hash
        #     of the remote, and the whole derivation is in question.
        def remote_only() -> subprocess.CompletedProcess:
            return with_stubbed_sddk(
                tmp,
                "#!/bin/sh\n"
                "echo 'project_id: p-20a1ee316faf2ba3'\n"
                "echo 'remote_url: https://github.com/rubentxu/agent-secretless-fork'\n",
                lambda: run_guard(REPO),
            )

        result = remote_only()
        report(
            "a changed remote with an unchanged project_id fails",
            result.returncode == 1,
            f"exit {result.returncode}, expected 1: {result.stdout.strip()}",
        )
        report(
            "that failure says the derivation is in question",
            "not a hash" in result.stderr,
            result.stderr.strip(),
        )

        # 4 — no sddk at all must not read as a pass.
        def missing() -> subprocess.CompletedProcess:
            empty = tmp / "empty-path"
            empty.mkdir(exist_ok=True)
            import os

            original = os.environ.get("PATH", "")
            os.environ["PATH"] = str(empty)
            try:
                return run_guard(REPO)
            finally:
                os.environ["PATH"] = original

        result = missing()
        report(
            "an unreachable sddk exits 2 rather than passing",
            result.returncode == 2,
            f"exit {result.returncode}, expected 2: {result.stderr.strip()}",
        )

    print(f"\n{PASS}/{PASS + FAIL} behaviours confirmed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
