#!/usr/bin/env python3
"""Falsification for `scripts/check-documented-install.py`.

The gate it checks runs the real thing — it downloads a release and installs
it — so its own cost is why it is not proven on every commit. That is exactly
the arrangement that let five defects through: a check nobody runs is not a
check, and a check that only runs in the one place nobody looks is the same
thing.

So every row here is broken against a fixture that costs a shell script and a
README, with no network and no release. Four cases, four rows.

Run: python3 tests/documented_install_drift.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-documented-install.py"

TEMPLATE = """# fixture

## Installing a release

```bash
{command}
```

The rest of the section is prose that no row reads.
"""


def readme_with(command: str) -> str:
    return TEMPLATE.format(command=command)


def gate(readme: Path) -> dict[str, tuple[str, str]]:
    p = subprocess.run([sys.executable, str(GUARD), "--readme", str(readme),
                        "--timeout", "120"],
                       capture_output=True, text=True)
    states: dict[str, tuple[str, str]] = {}
    for line in p.stdout.splitlines():
        line = line.strip()
        for prefix in ("PASS", "FAIL"):
            if line.startswith(f"{prefix:<6} ") or line.startswith(f"{prefix} "):
                name = line[len(prefix):].strip()
                states.setdefault(name, (prefix, ""))
    return states, p.stdout + p.stderr


def row(states: dict[str, tuple[str, str]], prefix: str) -> tuple[str, str]:
    for name, value in states.items():
        if name.startswith(prefix):
            return value
    raise AssertionError(f"no row starting with {prefix!r} in {sorted(states)}")


def main() -> int:
    if not GUARD.exists():
        print(f"FAIL guard not found: {GUARD}")
        return 1

    # A command that does nothing and reports the right version: the positive
    # control. Without it, four red rows prove only that the gate is red.
    working = (
        '#!/bin/sh\n'
        'prefix=""\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in --prefix) prefix="$2"; shift 2;; *) shift;; esac\n'
        'done\n'
        'mkdir -p "$prefix/bin"\n'
        'printf "#!/bin/sh\\necho asv 1.0.0\\n" > "$prefix/bin/asv"\n'
        'chmod +x "$prefix/bin/asv"\n'
    )
    broken = '#!/bin/sh\necho "something went wrong" >&2\nexit 3\n'
    wrong_version = (
        '#!/bin/sh\n'
        'prefix=""\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in --prefix) prefix="$2"; shift 2;; *) shift;; esac\n'
        'done\n'
        'mkdir -p "$prefix/bin"\n'
        'printf "#!/bin/sh\\necho asv 0.9.0\\n" > "$prefix/bin/asv"\n'
        'chmod +x "$prefix/bin/asv"\n'
    )
    no_version = '#!/bin/sh\nexit 0\n'
    silent = '#!/bin/sh\nexit 0\n'

    good = ('curl -LsSf file://{root}/installer.sh | sh -s -- --version 1.0.0 '
            '--prefix "$HOME/.local"')
    cases = [
        # (name, command template or None, expected row prefix, expected state,
        #  fixture script or None)
        ("a working documented command passes every row",
         good, "D4", "PASS", working),
        ("an install heading with no command is caught",
         None, "D1", "FAIL", None),
        ("a command that pins no version is caught",
         'curl -LsSf file://{root}/installer.sh | sh -s -- --prefix "$HOME/.local"',
         "D1", "FAIL", no_version),
        ("a script the document names that is not there is caught",
         'curl -LsSf file://{root}/absent.sh | sh -s -- --version 1.0.0 '
         '--prefix "$HOME/.local"', "D2", "FAIL", None),
        ("a documented command that fails is caught",
         good, "D3", "FAIL", broken),
        ("a command that installs the wrong version is caught",
         good, "D4", "FAIL", wrong_version),
        ("a command that exits zero having installed nothing is caught",
         good, "D4", "FAIL", silent),
    ]

    results = []
    for name, command, prefix, state, script in cases:
        # `{root}` is substituted inside `case` after the fixture exists; the
        # command string is built with the placeholder so the file:// URL is
        # only valid once the temporary directory has a name.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readme = root / "README.md"
            readme.write_text(
                readme_with(command.format(root=root) if command else ""),
                encoding="utf-8")
            if script is not None:
                (root / "installer.sh").write_text(script, encoding="utf-8")
            states, out = gate(readme)
            got, _ = row(states, prefix)
            ok = got == state
            detail = (out.strip().splitlines() or ["(no output)"])[-1]
            results.append((name, ok, detail))

    failed = sum(1 for _, ok, _ in results if not ok)
    print("documented install entry point falsification\n")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"          {detail}")
    print(f"\n{len(results) - failed}/{len(results)} behaviours confirmed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())