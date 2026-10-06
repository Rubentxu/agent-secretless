#!/usr/bin/env python3
"""Falsify the publish guard: a release without the product boundary is a refusal.

**What this exists for.** `scripts/publish-release.sh` decides what to upload by
collecting asset paths out of `dist-manifest.json`. The product boundary,
`manifest.toml`, is not a dist artifact, so it is not in that manifest, and the
installer downloads it to decide which components it is allowed to install.

The check that it is present used to live inside the python that builds the
asset list, calling `sys.exit`. That never stopped anything. The python runs
inside a `$( )` feeding `mapfile`, so its failure was the exit status of a
command substitution nobody inspected, and `mapfile` returned cleanly holding
the assets already printed before the check ran.

v0.35.0 is the proof. It published nine assets with no manifest and a signed
`sha256.sum` that did not list one, so the installer found an authority that
did not cover the file deciding what it may install — a refusal, not an
installation. The release had to be repaired after publication.

The same repository has now documented three guards that read like guards and
were not: a formatting claim checked by a stage nobody consulted, a stale test
count with no gate, and this one. The pattern is the same each time. A check
whose failure is swallowed by the construct that carries it is a comment.

**The two claims, and why they need both.**

1. With `manifest.toml` absent, the script exits non-zero, names the manifest,
   and never reaches `gh release create`.
2. With it present, the script passes this check and stops at whatever comes
   next — which is the difference between "this guard fired" and "the release
   train happened to refuse for another reason".

A one-sided check would pass against the second of those for the wrong reason.

Run: python3 tests/falsification/publish_manifest_guard_falsify.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "publish-release.sh"
MANIFEST = REPO / "target" / "distrib" / "manifest.toml"
STASH = Path("/tmp/asv-publish-guard-stash")

RED = "red"
OK = "ok"
SURVIVOR = "SURVIVOR"


def publish() -> tuple[int, str]:
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--confirm"],
        cwd=REPO,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    if not MANIFEST.is_file():
        print(
            f"publish_manifest_guard: {MANIFEST.relative_to(REPO)} is not staged, so "
            f"there is nothing to remove and nothing to prove.\n"
            f"Run dist build && pin-manifest-into-checksums.py first."
        )
        return 1

    STASH.mkdir(parents=True, exist_ok=True)
    shutil.copy2(MANIFEST, STASH / "manifest.toml")
    moved = STASH / "moved.toml"

    results: list[tuple[str, str, str]] = []
    try:
        shutil.move(str(MANIFEST), str(moved))
        rc, out = publish()
        if rc == 0:
            results.append((SURVIVOR, "exit 0", "the script would publish without the manifest"))
        elif "creating" in out and "gh release create" not in out and "creating v" in out:
            results.append((SURVIVOR, "reached create", "it got as far as creating the release"))
        elif "manifest.toml is missing" not in out:
            results.append(
                (SURVIVOR, "refused for another reason", out.strip().splitlines()[:1])
            )
        else:
            results.append((RED, f"exit {rc}", "named the manifest and refused"))
            print(f"ok    without the manifest: exit={rc}")
            for line in out.strip().splitlines()[:3]:
                print(f"      {line}")
    finally:
        if moved.is_file():
            shutil.move(str(moved), str(MANIFEST))

    rc, out = publish()
    if "manifest.toml is missing" in out:
        results.append((SURVIVOR, "still fires", "the guard fires with the manifest present"))
    else:
        results.append((OK, f"exit {rc}", "passed the guard and stopped at the next check"))
        print(f"\nok    with the manifest: passed this guard, exit={rc}")
        for line in out.strip().splitlines()[:2]:
            print(f"      {line}")
        print(
            "\n      That last refusal is the control. Without it, the mutation above "
            "would\n      pass for the wrong reason: the release train refuses for several\n"
            "      reasons, and only reaching one of the later ones shows this guard\n"
            "      is the difference."
        )

    shutil.rmtree(STASH, ignore_errors=True)

    survivors = [r for r in results if r[0] == SURVIVOR]
    print()
    for kind, detail, note in results:
        print(f"{kind:<9} {detail:<28} {note}")
    if survivors:
        print(f"\n{len(survivors)} survivor(s). The guard does not hold.")
        return 1
    print(f"\n{len(results)}/{len(results)} held; 0 survivors")
    return 0


if __name__ == "__main__":
    sys.exit(main())