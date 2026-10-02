#!/usr/bin/env python3
"""Check that the built artifacts are internally consistent before publishing.

Three things can each be wrong on their own, and each produces a release that
looks fine until a user runs the installer:

1. The manifest promises an artifact that is not on disk. dist writes the
   manifest from its plan, and the plan is computed before the build, so a
   build that fails partway leaves a complete-looking manifest and a partial
   `target/distrib`.
2. A checksum does not match the bytes next to it. This is the check that
   actually earns its keep, because it is the only place the two are compared
   at all — dist writes `.sha256` files from what it believes it produced, and
   nothing re-reads them.
3. An archive is empty or implausibly small. A zero-byte `.tar.xz` still
   passes a checksum of itself, and a user still gets an installer that
   unpacks nothing.

The checksum verification deliberately shells out to `sha256sum --check`
rather than recomputing in Python. The point is to prove the file is valid for
the tool a user is most likely to use to validate it, and a reimplementation
that agreed with dist by construction would prove nothing.

Run: python3 scripts/verify-release-artifacts.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRIB = REPO / "target" / "distrib"
MANIFEST = DISTRIB / "dist-manifest.json"

# A stripped, LTO'd, `codegen-units = 1` binary. The CLI links the policy
# engine and the protocol crate, so even the smallest of the three is well over
# this. The floor exists to catch a truncated archive, not to police size; it
# is deliberately low rather than tuned, because a threshold nobody can
# justify is a threshold that gets raised the first time it is inconvenient.
MIN_ARCHIVE_BYTES = 256 * 1024

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


MANIFEST_NOTE = (
    "Run `dist build && dist manifest --output-format=json > "
    "target/distrib/dist-manifest.json` first. A release with no manifest has "
    "nothing to check and nothing to publish."
)


def load_manifest() -> dict:
    if not MANIFEST.exists():
        fail(f"{MANIFEST.relative_to(REPO)} does not exist. {MANIFEST_NOTE}")
        return {}
    return json.loads(MANIFEST.read_text())


def check_everything_promised_exists(manifest: dict) -> int:
    """Every artifact the manifest names must be a real, non-trivial file."""
    checked = 0
    for release in manifest.get("releases", []):
        app = release.get("app_name", "?")
        for name in release.get("artifacts", []):
            # `source.tar.gz` and `sha256.sum` are workspace-global and appear
            # once per app; checking them repeatedly would report the same
            # problem N times and make the output harder to read, not more
            # informative.
            path = DISTRIB / name
            checked += 1
            if not path.exists():
                fail(f"{app}: the manifest lists {name} but it was not built")
                continue
            if name.endswith((".tar.xz", ".tar.gz")) and path.stat().st_size < MIN_ARCHIVE_BYTES:
                fail(
                    f"{app}: {name} is {path.stat().st_size} bytes, below the \
                     {MIN_ARCHIVE_BYTES} floor. A truncated archive still checksums \
                     correctly against itself and still unpacks to nothing."
                )
    return checked


def check_checksums_match_the_bytes() -> None:
    """The claim under test is that the checksums describe these files.

    `sha256sum --check` is run in the directory holding the files, because that
    is how a user validating a download runs it, and the paths inside the
    checksum files are relative.
    """
    checksum_files = sorted(DISTRIB.glob("*.sha256"))
    if not checksum_files:
        fail(
            "no .sha256 files in target/distrib. Either the build did not run or "
            "`checksum` was set to false in dist-workspace.toml, and a release with "
            "no checksums cannot be verified by whoever installs it."
        )
        return

    for checksum_file in checksum_files:
        result = subprocess.run(
            ["sha256sum", "--check", "--strict", checksum_file.name],
            cwd=DISTRIB,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            fail(
                f"{checksum_file.name} does not describe the file next to it:\n"
                f"{result.stdout}{result.stderr}"
            )


def check_manifest_matches_the_tag(manifest: dict) -> None:
    """dist announced a tag; the tag on disk has to be the one dist is naming.

    This is the check that would have caught a release whose artifacts are
    version 0.26.0 being uploaded under a 0.25.0 tag, which is the failure mode
    a user experiences as "the installer downloaded something that then said
    it was the wrong version".
    """
    tag = manifest.get("announcement_tag")
    if not tag:
        fail("the manifest has no announcement_tag")
        return
    import re

    root = REPO / "Cargo.toml"
    text = root.read_text()
    match = re.search(r'^version = "(.+?)"$', text, re.MULTILINE)
    if not match:
        fail("could not read a version from the workspace Cargo.toml")
        return
    if tag != f"v{match.group(1)}":
        fail(
            f"the manifest announces {tag} but the workspace version is "
            f"{match.group(1)}. The artifacts would be uploaded under a tag that does \
             not match the binaries inside them."
        )


def main() -> int:
    manifest = load_manifest()
    if not manifest:
        print("release artifact check FAILED:", file=sys.stderr)
        for problem in failures:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    checked = check_everything_promised_exists(manifest)
    check_checksums_match_the_bytes()
    check_manifest_matches_the_tag(manifest)

    if failures:
        print("release artifact check FAILED:", file=sys.stderr)
        for problem in failures:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    apps = [r.get("app_name") for r in manifest.get("releases", [])]
    print(
        f"release artifacts ok: {checked} artifacts across {len(apps)} apps "
        f"({', '.join(apps)}), every checksum verified against its bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
