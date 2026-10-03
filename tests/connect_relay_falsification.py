#!/usr/bin/env python3
"""Falsification harness for the C2.5-S2 relay spike.

`connect_relay_spike.py` decides an architecture: if an opaque relay can inject
the proof and become a byte pipe, the session-local shim is cheap; if it cannot,
the shim has to terminate TLS and the trust boundary moves.

A spike that has only ever printed green is a diagram with a table on it. Each
mutation below breaks exactly one thing the spike claims to have measured, and
the harness requires a *named* row to go red. A mutation that makes the whole
run explode counts as a failure of the harness, not as a caught mutant: a
spike that dies on any perturbation cannot distinguish "the property broke"
from "the test broke", and that is the same defect as a guard that never fires.

The interesting one is `origin_closes_early`. It leaves the shim untouched and
breaks reuse one layer below, which is the only way to show that row C measures
reuse and not merely "curl eventually got three bytes somewhere".
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPIKE = ROOT / "tests" / "connect_relay_spike.py"


# name -> (description, find, replace, rows that must go red)
MUTATIONS: dict[str, tuple[str, str, str, list[str]]] = {
    "shim_does_not_inject": (
        "the shim forwards the CONNECT without adding the proof",
        'if inject and b"\\r\\n" in head:',
        'if False and b"\\r\\n" in head:',
        ["B. shim, 1 request", "C. shim, 3 requests, 1 host"],
    ),
    "origin_closes_early": (
        "the origin drops the connection after one response, so no reuse is possible",
        "                + body\n            )\n    except OSError:",
        "                + body\n            )\n            return  # MUTATION\n    except OSError:",
        ["C. shim, 3 requests, 1 host"],
    ),
    "proof_gate_disarmed": (
        "the broker stops requiring the proof, so anything gets through",
        "if HEADER_NAME not in text.lower():",
        "if False:",
        ["A. direct to broker, no proof", "E. shim, injection off"],
    ),
    "shim_never_relays": (
        "the shim answers 200 and then drops the tunnel instead of relaying it",
        "        _relay(conn, up)",
        "        return  # MUTATION",
        ["B. shim, 1 request"],
    ),
}

COLUMNS = re.compile(r"\s{2,}")
ROW_LINE = re.compile(r"^(ok|XX)\s+([A-E]\..*?)(?:\s{2,}.*)?$")


def parse_rows(output: str) -> dict[str, str]:
    """Map row name -> ok|XX.

    Two parsers got this wrong before the harness could say anything true.

    The first used `^(ok|XX) (A\\..*)$`, whose greedy `.*` swallowed the
    expectation and observation columns along with the name, so every key was
    a whole table row and no mutation could ever match its expected rows. It
    reported "FALSIFICATION FAILED" for four mutants that had all been killed,
    with the right signature, in the output directly above the verdict.

    The second split on runs of two or more spaces, which does not separate
    `ok` from the row name: the mark and the name are one space apart, and
    only the later columns are wide. That one failed closed as a red control,
    which is the safer of the two failures and still useless.

    So: peel the mark off the front, then take the name up to the first wide
    gap.
    """
    rows: dict[str, str] = {}
    for line in output.splitlines():
        match = ROW_LINE.match(line.strip())
        if match:
            rows[match.group(2).strip()] = match.group(1)
    return rows


def run(source: str, label: str) -> tuple[int, str, dict[str, str]]:
    with tempfile.TemporaryDirectory(prefix="c2s2-falsify-") as tmp:
        path = Path(tmp) / "spike.py"
        path.write_text(source, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, str(path)],
                capture_output=True, text=True, timeout=180, cwd=str(ROOT),
            )
        except subprocess.TimeoutExpired:
            return 124, f"[{label}] spike timed out", {}
    output = proc.stdout + proc.stderr
    return proc.returncode, output, parse_rows(output)


def main() -> int:
    original = SPIKE.read_text(encoding="utf-8")
    failures: list[str] = []

    # Control. If the unmutated spike is not green there is nothing to falsify
    # and every mutant below would be scored against a baseline that is wrong.
    code, output, rows = run(original, "control")
    control_green = code == 0 and rows
    print(f"{'ok' if control_green else 'XX'} control: unmutated spike exits 0")
    if not control_green:
        print(output[-2000:])
        print("\nCONTROL IS RED — the spike does not pass on its own terms.")
        return 1
    for name in sorted(rows):
        print(f"     {rows[name]} {name}")

    for key in sorted(MUTATIONS):
        description, find, replace, must_be_red = MUTATIONS[key]
        if find not in original:
            failures.append(f"{key}: the mutation site no longer exists in the spike")
            print(f"XX {key}: mutation site not found — the spike drifted from its harness")
            continue
        mutated = original.replace(find, replace, 1)
        if mutated == original:
            failures.append(f"{key}: mutation did not apply")
            print(f"XX {key}: mutation was a no-op")
            continue

        code, output, mrows = run(mutated, key)
        red = {name for name, mark in mrows.items() if mark == "XX"}
        caught = set(must_be_red) <= red
        detail = ", ".join(f"{n.split('.')[0]}={'RED' if n in red else 'green'}" for n in sorted(mrows))
        print(f"{'ok' if caught else 'XX'} {key}: {description}")
        print(f"     rc={code}  {detail}")
        if not caught:
            failures.append(
                f"{key}: expected {sorted(must_be_red)} red, saw {sorted(red)}"
            )
            print(output[-1500:])

    print()
    if failures:
        print(f"FALSIFICATION FAILED ({len(failures)}):")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"All {len(MUTATIONS)} mutations killed, control green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
