#!/usr/bin/env python3
"""Run the install command the README documents, and require it to work.

    D1  the documented command is a pipeline that resolves to a real script
    D2  the URL the command fetches is reachable
    D3  the command, run verbatim in an empty HOME, exits zero
    D4  the binary it installs reports the version the README pinned

# Why this exists

Five defects in one release cycle had the same shape, and this file is the
answer to the shape rather than to any one of them:

    a gate exercised a component, and the command the document tells a user to
    run was never executed by anything

The list, in the order they were found:

  * every checksum gate compared checksums against files in `target/distrib`
    and not one opened the installer, so six releases shipped an installer that
    refused its own archive;
  * `tests/distribution_bundle.py` checked the *set* of components in an
    archive and not its path depth, so a repack that nested every member one
    level too low passed 21/21;
  * `scripts/release-tag-check.sh` checked the tag being cut and never the 53
    that already existed, so "no release admits a commit outside the branch"
    was asserted and never measured;
  * `tests/provenance_falsification.py` invoked `scripts/install.py` directly,
    with the file present and its own fixtures, and never ran
    `scripts/install.sh` — which cannot be run by pipe at all;
  * and `install.py` asks for an archive name the manifest declares and `dist`
    has never produced, so the documented entry point has never completed a
    single install.

Four of those five had a gate. The gate was green in every case. What was
missing was not a check but a *subject*: the thing a person actually types.

# Why it reads the README rather than being given a command

A gate that hardcodes the command it runs is a gate about the hardcoded
command. If the README changes and the gate does not, the gate is testing
yesterday's entry point — which is exactly how the 46-check campaign came to
believe the installer worked. So the command is extracted from the document, and
D4 compares the installed binary's version against the `--version` the document
pinned, so a document and a build cannot drift apart without this going red.

# What this costs

It downloads a release and runs it. That is why it is a release-pipeline stage
and not one of the per-commit gates: the honest version of this check has to do
the thing, and the thing involves the network and megabytes.

Run: python3 scripts/check-documented-install.py [--readme PATH] [--version V]
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PASS, FAIL = "PASS", "FAIL"
_results: list[tuple[str, str, str]] = []

# A `curl … | sh -s -- …` pipeline, possibly continued across lines with `\`.
# `file://` is accepted alongside `https://` so a fixture can be a local script:
# a gate that can only be exercised against the live GitHub raw endpoint is a
# gate nobody runs on a change.
PIPELINE_URL = re.compile(r"curl\s+(?:-\S+\s+)*(?P<url>(?:https|file)://\S+)")
PINNED_VERSION = re.compile(r"--version\s+(?P<v>\d+\.\d+\.\d+)")
FENCED_BASH = re.compile(r"^```bash\n(.*?)^```", re.DOTALL | re.MULTILINE)


def record(name: str, state: str, evidence: str) -> None:
    _results.append((name, state, evidence))
    mark = {PASS: "ok  ", FAIL: "FAIL"}[state]
    print(f"  {mark}  {name}\n          {evidence}")


def install_block(readme: Path) -> str:
    """The bash fence under the installing heading, continuation lines joined.

    Reading the block rather than the whole file matters: the README contains
    several code fences and only one of them is the install path a reader is
    told to run.
    """
    text = readme.read_text(encoding="utf-8")
    start = re.search(r"^##+\s+Installing a release\s*$", text, re.MULTILINE)
    if not start:
        return ""
    rest = text[start.end():]
    fence = FENCED_BASH.search(rest)
    return fence.group(1) if fence else ""


def join_continuations(block: str) -> list[str]:
    """Fold `\\`-continued lines into one logical command."""
    out: list[str] = []
    buf = ""
    for raw in block.splitlines():
        line = raw.rstrip()
        if not buf:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            buf = line
        elif line.lstrip().startswith("#"):
            # A comment between a continuation and its end would swallow the
            # command; treat it as ending the logical line.
            out.append(buf)
            buf = ""
            continue
        else:
            buf = buf.rstrip("\\").rstrip() + " " + line.strip()
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
        else:
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 900):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True,
                          text=True, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--readme", default=str(REPO / "README.md"))
    ap.add_argument("--version", default=None,
                    help="override the release to install; the README's own "
                         "--version is used otherwise")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    readme = Path(args.readme)
    print("documented install entry point\n")

    if not readme.is_file():
        record("D1 the documented command is a real pipeline", FAIL,
               f"{readme} does not exist")
        return report()

    block = install_block(readme)
    commands = join_continuations(block)
    pipeline = next((c for c in commands if PIPELINE_URL.search(c)), None)
    if pipeline is None:
        record("D1 the documented command is a real pipeline", FAIL,
               f"{readme.name} has an install heading but no `curl … | sh` "
               f"command in it; commands found: {commands}")
        return report()

    url = PIPELINE_URL.search(pipeline).group("url")
    doc_version = None
    pinned = PINNED_VERSION.search(pipeline)
    if pinned is not None:
        doc_version = pinned.group("v")
    version = args.version or doc_version
    if version is None:
        record("D1 the documented command is a real pipeline", FAIL,
               f"the documented command pins no --version, so this gate "
               f"cannot tell which release the reader was told to install: "
               f"{pipeline}")
        return report()

    # The evidence quotes the document's own pin. When `--version` overrides it,
    # saying "pins 0.36.0" about a line that pins 0.37.0 is the gate
    # misreporting the thing it is auditing.
    if doc_version is None:
        detail = f"`{pipeline}` pins no version; this run installs {version}"
    elif version == doc_version:
        detail = f"`{pipeline}` pins {doc_version}"
    else:
        detail = (f"`{pipeline}` pins {doc_version}; this run installs "
                  f"{version} instead, so D4 is not checking the document")
    record("D1 the documented command is a real pipeline", PASS, detail)

    # D2: the script the command fetches has to still be there. A renamed file
    # is a 404 here rather than a confusing error three steps later.
    #
    # `file://` is judged on curl's exit status rather than on `%{http_code}`,
    # because there is no HTTP in that scheme and curl reports `000` for a
    # successful fetch. Checking `000 != "200"` turned every fixture red and
    # would have reported a reachable file as missing.
    scheme = url.split("://", 1)[0]
    probe = run(["curl", "-LsSf", "-o", os.devnull, "-w", "%{http_code}", url],
                REPO, dict(os.environ), timeout=180)
    code = (probe.stdout or "").strip()
    if scheme == "file":
        reachable = probe.returncode == 0
        detail = ("fetched" if reachable
                  else f"curl exit {probe.returncode} reading {url}")
    else:
        reachable = probe.returncode == 0 and code == "200"
        detail = f"HTTP {code or 'no response'}"
    if not reachable:
        record("D2 the documented script is reachable", FAIL,
               f"{url}: {detail}")
        return report()
    record("D2 the documented script is reachable", PASS, f"{url}: {detail}")

    # D3/D4: run the document's own words, in an empty HOME.
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        home.mkdir()
        env = dict(os.environ, HOME=str(home))
        # The prefix is forced into the throwaway HOME so a passing run cannot
        # be reading a binary this machine installed earlier.
        command = pipeline.replace('"$HOME/.local"', f'"{home}/.local"')
        argv = ["sh", "-c", command]
        print(f"  ....  running the documented command in {home}")
        try:
            result = run(argv, home, env, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            record("D3 the documented command completes", FAIL,
                   f"timed out after {args.timeout}s")
            return report()

        if result.returncode != 0:
            tail = (result.stderr or result.stdout or "").strip().splitlines()
            record("D3 the documented command completes", FAIL,
                   f"exit {result.returncode}. Last output: "
                   f"{tail[-4:] if tail else '(none)'}")
            return report()
        record("D3 the documented command completes", PASS,
               f"exit 0 from `{command}`")

        binary = home / ".local" / "bin" / "asv"
        if not binary.is_file():
            record("D4 the installed binary reports the pinned version", FAIL,
                   f"the command exited 0 but there is no asv at {binary}")
            return report()
        shown = run([str(binary), "--version"], home, env, timeout=60)
        text = (shown.stdout or "").strip()
        if shown.returncode != 0 or version not in text:
            record("D4 the installed binary reports the pinned version", FAIL,
                   f"{binary} said {text!r} and the document pinned {version}")
            return report()
        record("D4 the installed binary reports the pinned version", PASS,
               f"asv {version}, installed into an empty HOME from the command "
               f"the document gives")

    return report()


def report() -> int:
    print()
    failed = [n for n, s, _ in _results if s == FAIL]
    for name, state, _ in _results:
        print(f"  {state:<6} {name}")
    print(f"\n{len(_results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())