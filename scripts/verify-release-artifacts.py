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

import hashlib
import json
import re
import subprocess
import sys
import tempfile
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


def installer_path(manifest: dict) -> Path | None:
    """The installer dist generated, found by `kind` rather than by name.

    A hardcoded installer name is what made the v0.36.0 release notes point at
    an asset that does not exist, so the name is read the same way every other
    fact here is read: from the manifest.
    """
    names = [
        a["name"]
        for a in manifest.get("artifacts", {}).values()
        if isinstance(a, dict) and a.get("kind") == "installer"
    ]
    if len(names) != 1:
        return None
    return DISTRIB / names[0]


def installer_blocks(text: str) -> dict[str, dict[str, str]]:
    """The installer's per-artifact constants, keyed by artifact name.

    dist writes one `case` arm per archive, each setting `_checksum_value` and
    `_bins`. Both are read from the file rather than assumed, so a change in
    what dist names things moves this check instead of silently passing it.
    """
    opener = re.compile(r'^\s*"(?P<name>[^"]+\.tar\.(?:zst|gz|xz))"\)\s*$')
    blocks: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = opener.match(line)
        if match:
            current = match.group("name")
            blocks.setdefault(current, {})
            continue
        # `;;` ends the arm. Without this the walk runs on past the `case` into
        # the updater section, where dist assigns `_bins="$_bins $APP_NAME-update"`
        # to a local rather than to an archive — and that literal overwrites the
        # artifact's real binary list, which turns this check into a report about
        # a shell variable instead of about the release.
        if line.strip().endswith(";;"):
            current = None
            continue
        if current is None:
            continue
        for key in ("_checksum_value", "_bins"):
            found = re.match(rf'^\s*{re.escape(key)}="([^"]*)"\s*$', line)
            if found:
                blocks[current][key] = found.group(1)
    return blocks


def digest_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_installer_checksums_match_the_bytes(manifest: dict) -> None:
    """The digest the installer verifies against must be the archive's digest.

    Every checksum gate in this train compared checksums against files in
    `target/distrib`, and none of them opened the installer — so the one place a
    user's first command compares a number was never compared at all.

    The `normalize` stage is what breaks it: it repacks the archives so they are
    byte-reproducible, which changes their digests, and dist had already written
    the pre-normalization digest into the installer. Measured across published
    releases, v0.31.0 through v0.36.0 each ship an installer that refuses its own
    artifact with `ERROR: checksum mismatch`.
    """
    installer = installer_path(manifest)
    if installer is None or not installer.is_file():
        fail(
            "the manifest declares no single installer artifact on disk. A "
            "release whose documented install path does not exist is not a "
            "release nobody can install; it is a release that cannot be "
            "installed at all."
        )
        return

    blocks = installer_blocks(installer.read_text(encoding="utf-8"))
    if not blocks:
        fail(
            f"{installer.name} contains no artifact checksum block, so there is "
            f"nothing to verify and the installer's own verification cannot be "
            f"checked. Refusing to pass it."
        )
        return

    for name, values in sorted(blocks.items()):
        archive = DISTRIB / name
        if not archive.is_file():
            fail(f"{installer.name} verifies {name}, which was not built")
            continue
        claimed = values.get("_checksum_value")
        actual = digest_of(archive)
        if claimed != actual:
            fail(
                f"{installer.name} refuses its own release: it verifies {name} "
                f"against {claimed}, and those bytes hash to {actual}. A user "
                f"following the documented install gets ERROR: checksum "
                f"mismatch. Normalization rewrote the archive after dist baked "
                f"this digest; run scripts/repair-installer-checksums.py."
            )


def check_installer_can_reach_the_binaries(manifest: dict) -> None:
    """Unpack each archive the way the installer does, and require the binaries.

    This is the check `tests/distribution_bundle.py` cannot be. That suite
    confirms the right *set* of components is in the archive and passed 21/21 on
    an archive whose install path was broken. The defect was never the set: it
    was the path *depth*. `normalize` repacked with `tar -cf - .` from inside
    the staging directory, writing every member as `./name` and so adding a
    component to every entry. The installer runs `tar xf … --strip-components
    1`, stripped the wrong component, and looked for the binaries one directory
    too low.

    So the property under test is not "the archive contains asv". It is "the
    command line in the installer, applied to this archive, leaves the binaries
    where the installer then looks". Replaying the installer's own two commands
    is what makes this falsifiable rather than a guess about tar's behaviour.
    """
    installer = installer_path(manifest)
    if installer is None or not installer.is_file():
        # Already reported by the checksum check; one cause, one complaint.
        return

    blocks = installer_blocks(installer.read_text(encoding="utf-8"))
    for name, values in sorted(blocks.items()):
        archive = DISTRIB / name
        if not archive.is_file():
            continue
        bins = values.get("_bins", "").split()
        if not bins:
            fail(f"{installer.name} declares no binaries for {name}")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            # The same two commands the installer runs, in the same order, with
            # the mode given as separate options: `tar --zstd xf …` is not
            # accepted by every tar, and a check that fails because of how it
            # spelled its own argument reports a defect that is not there.
            tar = ["tar", "-x", "--no-same-owner", "--strip-components", "1",
                   "-f", str(archive), "-C", tmp]
            if name.endswith(".zst"):
                tar.insert(1, "--zstd")
            unpack = subprocess.run(tar, capture_output=True, text=True)
            if unpack.returncode != 0:
                fail(
                    f"the installer's own unpack of {name} failed:\n"
                    f"{unpack.stdout}{unpack.stderr}"
                )
                continue
            root = Path(tmp)
            missing = [b for b in bins if not (root / b).is_file()]
            if missing:
                top = sorted(p.name for p in root.iterdir())
                fail(
                    f"the installer's unpack of {name} leaves {missing} out of "
                    f"reach: after `tar xf --strip-components 1` the top level "
                    f"is {top}, not the binaries the installer then moves. Every "
                    f"member in this archive is one path component deeper than "
                    f"the installer expects."
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
    check_installer_checksums_match_the_bytes(manifest)
    check_installer_can_reach_the_binaries(manifest)
    check_manifest_matches_the_tag(manifest)

    if failures:
        print("release artifact check FAILED:", file=sys.stderr)
        for problem in failures:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    apps = [r.get("app_name") for r in manifest.get("releases", [])]
    print(
        f"release artifacts ok: {checked} artifacts across {len(apps)} apps "
        f"({', '.join(apps)}), every checksum verified against its bytes, and "
        f"the installer's own unpack of each archive reaches the binaries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
