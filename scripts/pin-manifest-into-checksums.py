#!/usr/bin/env python3
"""Put the product boundary inside the signed checksum authority.

# Why this stage exists

`dist` writes `sha256.sum` covering the artifacts it produced. It does not
know that `distribution/manifest.toml` exists — the manifest is this project's
own declaration of what ships, and `dist` never reads it. So the file that
decides which components a user ends up with was not covered by the file the
release signs.

That is not a theoretical gap. The installer reads the manifest first, uses it
to decide the archive name, and compares the archive against the declared set
of components. A substituted manifest therefore chooses both what is fetched
and what is accepted, while `sha256.sum` and its signature sit there
verifying an archive faithfully. The signature was real, the bytes were
authentic, and the boundary was still the attacker's.

So the manifest is copied into the release directory and its digest is written
into `sha256.sum` before the sign stage runs. Afterwards the installer finds
`manifest.toml` in the signed authority, and an authority that does not list it
is a refusal rather than a silently-unverified file.

# Why it rewrites rather than appends

`sha256.sum` is rewritten in full on every `dist build`, and
`scripts/normalize-release-archives.sh` already rewrites individual lines of it
to match re-normalized bytes. A stage that only ever appended would leave a
stale line behind after a rebuild, and `sha256sum --check` would then report
the manifest as changed. The line is therefore looked up by name and replaced
in place, preserving every other line byte for byte.

Note what is *not* asserted here, because the normalize stage asserts it and
asserting it here would be wrong. That stage fails when a rewrite changes no
line, because it is supposed to be changing an archive's digest and a no-op
means its name matching broke. This stage's second run over an already-correct
authority is supposed to change nothing, so a no-op is success. What is checked
instead is the property that matters and that a no-op could hide: the line in
the file, read back from disk, is the digest of the bytes that were published.

# Run: python3 scripts/pin-manifest-into-checksums.py
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRIB = REPO / "target" / "distrib"
SOURCE_MANIFEST = REPO / "distribution" / "manifest.toml"
PUBLISHED_MANIFEST = DISTRIB / "manifest.toml"
CHECKSUM_AUTHORITY = DISTRIB / "sha256.sum"

MANIFEST_NAME = "manifest.toml"


def fail(message: str) -> None:
    print(f"pin-manifest: {message}", file=sys.stderr)
    raise SystemExit(1)


def digest_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not SOURCE_MANIFEST.is_file():
        fail(f"{SOURCE_MANIFEST.relative_to(REPO)} is missing; there is no product "
             f"boundary to publish")
    if not DISTRIB.is_dir():
        fail("target/distrib does not exist. Run dist build first.")
    if not CHECKSUM_AUTHORITY.is_file():
        fail(f"{CHECKSUM_AUTHORITY.relative_to(REPO)} is missing. Run dist build "
             f"first — a release with no checksum authority cannot be signed, and "
             f"signing one that does not list the manifest would sign an authority "
             f"that says nothing about what installs.")

    # The published copy is a copy, not a link: `dist upload` reads this
    # directory, and a symlink back into the checkout would let a later edit to
    # the working tree change bytes that were already signed.
    shutil.copy2(SOURCE_MANIFEST, PUBLISHED_MANIFEST)
    want = digest_of(PUBLISHED_MANIFEST)

    lines = CHECKSUM_AUTHORITY.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    replaced = False
    for line in lines:
        parts = line.split(maxsplit=1)
        # dist spells its lines `<digest> *<name>` — one space, binary-mode
        # star — and `sha256sum` accepts one or two spaces with or without it,
        # so the match is on the name and the rest of the line is preserved.
        if len(parts) == 2 and parts[1].strip().lstrip("*") == MANIFEST_NAME:
            out.append(f"{want}  {MANIFEST_NAME}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{want}  {MANIFEST_NAME}")

    CHECKSUM_AUTHORITY.write_text("".join(f"{line}\n" for line in out), encoding="utf-8")

    # Read the line back rather than trusting the value just written. The point
    # of this stage is that the authority names the manifest, and a check that
    # compares the variable it just computed against itself would agree even if
    # the file on disk says something else.
    actual = digest_of(PUBLISHED_MANIFEST)
    listed = [line.split(maxsplit=1) for line
              in CHECKSUM_AUTHORITY.read_text(encoding="utf-8").splitlines()
              if len(line.split(maxsplit=1)) == 2
              and line.split(maxsplit=1)[1].strip().lstrip("*") == MANIFEST_NAME]
    if len(listed) != 1:
        # More than one line for the same name is not something this stage
        # produces, and choosing one of them would be picking a winner in a
        # file two writers disagree about. Replacing every match, which is what
        # the loop above does, turns a disagreement into two identical lines
        # that look resolved.
        fail(f"{CHECKSUM_AUTHORITY.name} holds {len(listed)} lines for "
             f"{MANIFEST_NAME}; it must hold exactly one. Two writers disagree "
             f"about this file and picking between them is not this stage's "
             f"call to make.")
    if listed[0][0] != actual:
        fail(f"{CHECKSUM_AUTHORITY.name} lists {MANIFEST_NAME} as {listed[0][0]} "
             f"but the published bytes are {actual}")

    print(f"pin-manifest: {MANIFEST_NAME} published and listed in "
          f"{CHECKSUM_AUTHORITY.name} ({actual[:16]}...)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
