#!/usr/bin/env python3
"""Repoint the installer's baked checksums at the bytes this release actually ships.

# The defect this exists to fix

`dist build` generates `agent-secretless-installer.sh` with each artifact's
sha256 written into it as `_checksum_value`. The installer then verifies every
download against that constant and refuses on a mismatch — which is the right
behaviour, and is why this is not a weakness in the check itself.

The `normalize` stage then repacks the archives to make them byte-reproducible,
which changes their bytes and therefore their digests. `normalize` repairs every
touchpoint it knows about: the archive, its `.sha256` sidecar, and its line in
`sha256.sum`. The installer was never on that list, so it kept the digest of the
archive as it existed *before* normalization.

The result is a release whose installer refuses its own artifact:

    downloading agent-secretless 0.36.0 x86_64-unknown-linux-gnu
    ERROR: checksum mismatch
                want: 42e73406aa8af352aa36c19ce3d18ffd829e33775716f66ebb2e6e15c60d782f
                got:  f1cce8da8f8c8e81746331955ecf8f9cffa201fa141ccdd99f5c3e867441ea6b

Measured across the published releases on 2026-10-07, **every release from
v0.31.0 to v0.36.0 ships an installer that cannot install anything**, and
`v0.30.0` ships no installer at all. Six consecutive releases of the documented
install path were broken, and nothing said so, because every checksum gate in
the release train compared checksums against files in `target/distrib` and none
of them opened the installer.

# What this does, and why not something cleverer

The installer's checksum is rewritten to the digest of the archive on disk,
after normalization, and then every artifact in the installer is re-verified
against the bytes. Anything that cannot be matched — an artifact the installer
does not mention, a block it does not have, a digest that does not match — is a
hard failure.

It deliberately does not try to make the installer read `sha256.sum` instead of
a constant. That would be the better design, but it means editing a template
`dist` owns and re-deriving it on every dist upgrade, and a silent failure there
produces the same broken release. Replacing a constant with the value the file
next to it already asserts is checkable, and the check is in
`scripts/verify-release-artifacts.py` so it fails the release rather than
trusting this script.

Run: python3 scripts/repair-installer-checksums.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRIB = REPO / "target" / "distrib"
MANIFEST = DISTRIB / "dist-manifest.json"

# The line dist writes, and the artifact block it lives in. The block opener is
# matched with the artifact name in it rather than by counting lines, because
# dist may order or pad the fields inside a block.
BLOCK_OPEN = re.compile(r'^\s*"(?P<name>[^"]+\.tar\.(?:zst|gz|xz))"\)\s*$')
CHECKSUM_VALUE = re.compile(r'^(\s*_checksum_value=")([0-9a-f]{64})(".*)$')


def digest_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_installer(manifest: dict) -> Path | None:
    """The installer dist generated, found by kind rather than by name.

    The same rule as publish-release.sh: `agent-secretless-installer.sh` is what
    dist happens to call it today, and a hardcoded name is what made the v0.36.0
    release notes point at an asset that did not exist.
    """
    names = [
        a["name"]
        for a in manifest.get("artifacts", {}).values()
        if isinstance(a, dict) and a.get("kind") == "installer"
    ]
    if len(names) != 1:
        print(
            f"repair-installer-checksums: expected exactly one artifact of kind "
            f"'installer', found {len(names)}: {sorted(names)}",
            file=sys.stderr,
        )
        return None
    return DISTRIB / names[0]


def main() -> int:
    if not MANIFEST.exists():
        print(
            f"repair-installer-checksums: {MANIFEST} is missing. Run `dist build` first.",
            file=sys.stderr,
        )
        return 1
    manifest = json.loads(MANIFEST.read_text())

    installer = find_installer(manifest)
    if installer is None or not installer.is_file():
        print(
            f"repair-installer-checksums: no installer artifact on disk in "
            f"{DISTRIB}. There is nothing to repair, and a release that ships no "
            f"installer is a release whose documented install path does not exist.",
            file=sys.stderr,
        )
        return 1

    lines = installer.read_text(encoding="utf-8").splitlines(keepends=True)

    # Walk the file once, tracking which artifact block each line belongs to.
    repaired: dict[str, str] = {}
    seen: dict[str, str] = {}
    current: str | None = None
    for i, line in enumerate(lines):
        opener = BLOCK_OPEN.match(line)
        if opener:
            current = opener.group("name")
            continue
        value = CHECKSUM_VALUE.match(line)
        if value and current is not None:
            seen[current] = value.group(2)
            archive = DISTRIB / current
            if not archive.is_file():
                print(
                    f"repair-installer-checksums: the installer verifies "
                    f"{current} but that archive was not built.",
                    file=sys.stderr,
                )
                return 1
            actual = digest_of(archive)
            if value.group(2) != actual:
                lines[i] = f"{value.group(1)}{actual}{value.group(3)}\n"
            repaired[current] = actual

    if not repaired:
        print(
            "repair-installer-checksums: the installer contains no artifact "
            "checksum block. Repairs are refused rather than assumed.",
            file=sys.stderr,
        )
        return 1

    # Every archive the manifest ships for this platform must be one the
    # installer actually verifies, and every archive the installer verifies must
    # be one the manifest ships. The first direction is the guard that matters:
    # an installer that pinned a digest for an archive the release does not carry
    # would be verifying a file nobody downloads, and the repair would have
    # written it successfully.
    #
    # `source.tar.gz` is excluded from the first direction and not from the
    # second, deliberately. It is a workspace-global artifact the release does
    # ship, but it is the *sources*, and the shell installer installs binaries;
    # it never downloads it, so requiring a checksum block for it would be
    # demanding that the installer verify a file it does not fetch. It is still
    # checked the other way round: if the installer ever grew a block for it, the
    # repair would have to keep it honest.
    shipped = sorted(
        name
        for release in manifest.get("releases", [])
        for name in release.get("artifacts", [])
        if name.endswith((".tar.zst", ".tar.gz", ".tar.xz"))
    )
    binaries = [a for a in shipped if not a.startswith("source.")]
    unmentioned = [a for a in binaries if a not in repaired]
    if unmentioned:
        print(
            f"repair-installer-checksums: the installer does not verify "
            f"{unmentioned}, so repairing it would leave the binaries a user "
            f"installs unverified by the only component a user runs first.",
            file=sys.stderr,
        )
        return 1
    unshipped = [n for n in repaired if n not in shipped]
    if unshipped:
        print(
            f"repair-installer-checksums: the installer verifies {unshipped}, "
            f"which the manifest does not list as part of this release. Repairing "
            f"it would pin a digest for a file the release does not carry.",
            file=sys.stderr,
        )
        return 1

    installer.write_text("".join(lines), encoding="utf-8")

    changed = [n for n in repaired if seen.get(n) != repaired[n]]
    for name in sorted(repaired):
        mark = "repaired" if name in changed else "already current"
        print(f"repair-installer-checksums: {name} {mark} ({repaired[name]})")
    print(
        f"repair-installer-checksums: {len(repaired)} artifact checksums in "
        f"{installer.name} describe the bytes on disk; {len(changed)} rewritten"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())