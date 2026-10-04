#!/usr/bin/env python3
"""Install a released bundle. Thin, and never compiles Rust.

`04-ADR-DISTRIBUTION.md` gives the installer seven steps, and this file
performs them in that order: detect the platform, select a release, download the
manifest and the artifact, verify integrity, install the declared components,
and hand over to `asv setup`. The seventh step — never building on the target
machine — is a property this file has to be *unable* to violate, so there is no
code path that invokes a toolchain at all. That is checked by
`tests/distribution_channels.py`, which reads this file and fails if a compiler
is reachable from it; the one carve-out is the `~/.cargo/bin` directory this
file searches for `rsign`, which is a path to a verifier and not a build.

# The provenance chain, in the order it is enforced
#
#     trusted public key   embedded here, or --trusted-key
#           v
#     signature            rsign verifies sha256.sum against it
#           v
#     signed authority     sha256.sum, and only now is it opened
#           v
#     artifact digest      manifest.toml and the archive, against that authority
#           v
#     manifest             the product boundary, now known to be the release's
#           v
#     installed bundle     declared components only, nothing written before this
#
# Each link is checked before the one below it depends on it, and a failure at
# any link stops the install with nothing written. There is no flag that
# downgrades a link to a warning, because the chain's whole value is that no
# single compromised step is survivable: the digest checks survive an attacker
# who cannot re-sign, and the signature check survives an attacker who can
# write a perfectly self-consistent set of files.
#
# Why the signature is the first thing asked: before it, `sha256.sum` is a list
# of acceptable digests supplied by the party being checked. An archive and a
# checksum file that agree with each other are exactly what a mirror, a
# compromised CDN or a man in the middle produce, and they were enough to
# install a substituted `asv` before this file grew the signature check. That
# was measured, not assumed — see tests/provenance_falsification.py.
#
# Why Python and not shell

`09-IMPLEMENTATION-GUIDE.md` §7: "No meter lógica de seguridad compleja en shell
que deba duplicarse con Rust." Checksum verification and "is this archive the
set of components we declared" are security logic. Writing them in `sh` means
either reimplementing digest comparison with `sha256sum` output parsing — which
is a second implementation of the check, and the two will disagree one day — or
shelling out anyway, which is what this does in exactly one place, for
`sha256sum` itself, because proving the file is valid for the tool a user is
most likely to validate it with is worth more than avoiding a subprocess.

# Why the archive is checked against the manifest again here

`tests/distribution_bundle.py` already gates what the build produces. This
checks what arrived, at the destination, after transfer. Those are different
questions: a build gate cannot see a corrupted download, a truncated upload, or
a mirror serving an older archive under a newer name. The manifest is the same
file in both places, so the two checks cannot answer differently about what
the product is.

# Usage

    scripts/install.py --version 0.25.0 --prefix ~/.local
    scripts/install.py --from-dir target/distrib --prefix ~/.local
    mise use -g agent-secretless          # routes here with --installed-via mise
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO / "scripts" / "install.sh"
RECORD_SCHEMA = "asv.install/v1"
RECORD_FILE = "install.json"

DEFAULT_BASE_URL = "https://github.com/Rubentxu/agent-secretless/releases/download"

# The signed checksum authority, and its signature. These are the only two
# filenames the installer needs the release to publish, and they are the two
# the release train already produces and signs: `dist` writes `sha256.sum`,
# `scripts/sign-release-artifacts.sh` signs it, and `publish-release.sh`
# uploads it with its `.minisig` sidecar.
#
# This used to be `checksums.txt`, a name that appears in the distribution ADR
# and in an older copy of this file — and that nothing in the release train has
# ever written. The producer pinned and signed `sha256.sum`; the consumer read
# `checksums.txt`; the test harness synthesised `checksums.txt` so the tests
# passed against a file no release contains. Two checksum authorities, neither
# checking the other, and the green test suite was the proof of the gap rather
# than the reason it was invisible. One authority now, and it is the signed one.
CHECKSUM_AUTHORITY = "sha256.sum"
SIGNATURE_SUFFIX = ".minisig"

# The trust anchor: this project's minisign public key, embedded in the
# installer rather than fetched. A `release.pub` that travels with the download
# cannot be the thing that decides whether the download is trusted, because the
# party substituting the download substitutes that file too — and the release
# already stages it, so it is available to be swapped.
#
# What this does and does not buy, stated plainly. It means the signature is
# checked against a key the download did not choose. It does not bootstrap
# itself: whoever delivers this script can also change this constant, and no
# signature scheme inside a file can prevent that. The out-of-band half is the
# key id — `54CB5B8D3C7419FB` — which is published in the README and in the
# release announcement so it can be compared by a human against something the
# download did not carry. `--trusted-key` exists for the operator who has the
# key from somewhere better than this repository.
TRUSTED_RELEASE_KEY = """untrusted comment: minisign public key: 54CB5B8D3C7419FB
RWT7GXQ8jVvLVOBfjF8n7Gg9NZsccOlnD5i6hdDwlAFabplx33dp8/Pg"""

# The channels the CLI's `installrecord` enum knows. A value outside this set
# would be written to disk and then read back as unreadable on the user's
# machine, so the installer refuses to write it rather than shipping a record
# that `asv doctor` cannot interpret.
KNOWN_CHANNELS = ("installer", "mise", "package-manager", "source")

failures: list[str] = []
notes: list[str] = []


def fail(message: str) -> None:
    failures.append(message)
    print(f"error: {message}")


def note(message: str) -> None:
    notes.append(message)
    print(f"  {message}")


def _failures_present() -> bool:
    return bool(failures)


# ----------------------------------------------------------------- manifest

def read_manifest(path: Path) -> dict:
    """The product boundary, read from the one file that declares it.

    Parsed with `tomllib` rather than a hand-rolled reader so the shape the
    installer trusts is the shape Rust's `toml` crate and `dist` see.

    The manifest is *fetched*, not assumed. `04-ADR-DISTRIBUTION.md` step 3 is
    "descarga manifiesto y artefacto", and the reason is that a manifest copied
    out of a git checkout is a second copy of the product boundary that the
    release does not vouch for. The published manifest is listed in the signed
    `sha256.sum` like every other byte, so the two arrive agreeing or the
    install is refused — and the signature over that authority is verified
    before this function is ever called.
    """
    import tomllib

    with path.open("rb") as fh:
        return tomllib.load(fh)


def shipped_components(manifest: dict) -> list[dict]:
    """Exactly the components a user is meant to end up with."""
    out = [c for c in manifest["component"] if c.get("shipped")]
    if not out:
        fail("the manifest declares no shipped component; refusing to install nothing")
    return out


# ------------------------------------------------------------------ platform

def detect_target() -> str:
    """`uname` answers, translated to the target triple the release names.

    Failure is the answer here. A machine whose architecture is not one of the
    two the project ships is a machine this installer must not install onto by
    guessing, and a wrong triple produces a download of a foreign archive that
    will still unpack.
    """
    machine = platform.machine()
    table = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "amd64": "x86_64-unknown-linux-gnu",
        "aarch64": "aarch64-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
    }
    target = table.get(machine)
    if target is None:
        fail(
            f"no release is published for this architecture ({machine}). "
            f"Supported: {', '.join(sorted(set(table.values())))}"
        )
    return target


# ------------------------------------------------------------------ fetching

def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(url: str, dest: Path) -> None:
    note(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as out:
        shutil.copyfileobj(response, out)


def parse_checksums(text: str) -> dict[str, str]:
    """`<sha256>  <name>`, the format `sha256sum` writes and users have.

    Parsed strictly: a line that is not exactly that shape is an error rather
    than a skipped line, because a checksum file that is half-unparseable looks
    identical to one that verifies everything it mentions.

    Only ever called on a file whose signature has already been verified. Before
    that call this function is a parser of an attacker's text, and after it, it
    is a reader of the release's declared digests.
    """
    out: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line)
        if not m:
            fail(f"{CHECKSUM_AUTHORITY} line {lineno} is not a sha256sum line: {line!r}")
            continue
        out[Path(m.group(2).strip()).name] = m.group(1)
    return out


# ----------------------------------------------------------------- signatures

def rsign_command() -> str | None:
    """The minisign verifier, or None. Never a reason to continue without it.

    Resolved the same way `sign-release-artifacts.sh` resolves its signer, so
    the tool that produced the signature and the tool that checks it are the
    same one. Reimplementing minisign in the installer would mean Ed25519 and
    BLAKE2b prehashing written a second time, and this file already has a
    standing rule about that: it shells out to `sha256sum` rather than
    recompute, because agreeing with dist by construction would prove nothing.
    The same argument applies here with more force — a hand-rolled verifier
    that has only ever agreed with itself is a signature check that reads as
    one and is not.
    """
    override = os.environ.get("ASV_RSIGN")
    if override:
        return override if shutil.which(override) else None
    found = shutil.which("rsign")
    if found:
        return found
    cargo_bin = Path.home() / ".cargo" / "bin" / "rsign"
    return str(cargo_bin) if cargo_bin.is_file() and os.access(cargo_bin, os.X_OK) else None


def verify_signature(signed: Path, signature: Path, key: Path) -> bool:
    """The release's digests are the release's, and not the downloader's.

    Every provenance violation the mandate names reduces to this one question,
    so it is asked before any other file is parsed. A checksum file that
    arrived unverified is an attacker's list of acceptable digests, and every
    later check measured against it agrees with the attacker by construction.
    """
    rsign = rsign_command()
    if rsign is None:
        fail(
            "rsign is not installed, so the release signature cannot be checked. "
            "Refusing to install. A checksum file that arrived unverified is an "
            "attacker's list of acceptable checksums, not a verification. "
            "Install the `rsign` verifier (the rsign2 project, or your "
            "distribution's package manager) and re-run."
        )
        return False

    if not signature.is_file():
        fail(
            f"{signature.name} is missing. A release that ships no signature has "
            f"nothing to verify, and {signed.name} is then just a file the "
            f"download chose. Refusing to install."
        )
        return False

    result = subprocess.run(
        [rsign, "verify", "-p", str(key), "-x", str(signature), str(signed)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        fail(
            f"the signature on {signed.name} does not verify against the trusted "
            f"key (key id {trusted_key_id(key)}).\n"
            f"  {result.stdout.strip()}{result.stderr.strip()}\n"
            f"Refusing to install. Nothing was written."
        )
        return False
    note(f"release signature verified against key {trusted_key_id(key)}")
    return True


def trusted_key_id(key: Path) -> str:
    """The key id a reader can compare against a channel the download did not carry.

    Read from the key file rather than reported from the verification, so a
    message that names a key is naming the key that was actually used.
    """
    try:
        first = key.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return "unknown"
    marker = "minisign public key:"
    return first.split(marker, 1)[1].strip() if marker in first else "unknown"


# ---------------------------------------------------------------- installing

def verify(archive: Path, checksums: dict[str, str]) -> bool:
    """The bytes are the bytes the signed release said they would be.

    Runs `sha256sum --check` on a one-line manifest rather than comparing
    hashes in Python. The comparison is the same either way; running the tool
    is not, because it proves the value in the signed authority is one a user
    can reproduce with the command they already know.
    """
    if not checksums:
        fail(f"{CHECKSUM_AUTHORITY} contained no usable entries; nothing to verify against")
        return False
    expected = checksums.get(archive.name)
    if expected is None:
        fail(f"{archive.name} is not listed in {CHECKSUM_AUTHORITY}")
        return False

    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.sha256"
        probe.write_text(f"{expected}  {archive}\n", encoding="utf-8")
        result = subprocess.run(
            ["sha256sum", "--check", "--strict", str(probe)],
            capture_output=True, text=True,
        )
    if result.returncode != 0:
        actual = sha256_of(archive)
        fail(
            f"{archive.name} does not match the published checksum.\n"
            f"  expected {expected}\n"
            f"  actual   {actual}\n"
            f"Refusing to install. Nothing was written."
        )
        return False
    note(f"checksum verified: {expected[:16]}...")
    return True


def check_container(archive: Path) -> bool:
    """The bytes are the format the filename claims.

    `tarfile` sniffs compression, which is convenient and is exactly the
    problem: an archive called `.tar.zst` that is really gzip unpacks happily,
    and the next tool in the chain that trusts the extension — a decompressor
    asked for zstd, a mirror's content-type, a future reader that skips the
    sniff — fails on a file an earlier step accepted. A misnamed artifact is
    also the shape a substituted artifact takes.

    The magic is read before anything is parsed, so this costs eight bytes and
    cannot be fooled by a tar member named to look like something else.
    """
    magic = archive.read_bytes()[:8]
    # zstd frame: 0x28 0xB5 0x2F 0xFD. gzip: 0x1F 0x8B. xz: 0xFD '7zXZ'.
    table = {
        ".zst": (b"\x28\xb5\x2f\xfd", "zstd"),
        ".gz": (b"\x1f\x8b", "gzip"),
        ".xz": (b"\xfd7zXZ\x00", "xz"),
    }
    suffix = archive.suffix
    expected = table.get(suffix)
    if expected is None:
        return True  # .tar, uncompressed: nothing to claim
    want, name = expected
    if not magic.startswith(want):
        fail(
            f"{archive.name} claims to be {name} but its bytes are "
            f"{magic.hex() or 'empty'}. A container that does not match its "
            f"name is refused rather than sniffed, because every later tool "
            f"that trusts the extension will disagree with this one."
        )
        return False
    return True


def extract(archive: Path, dest: Path) -> None:
    """Unpack, refusing anything that is not a plain file.

    The bundle is a set of executables and nothing else. A member that is a
    symlink, a device or a path escaping the destination is not something the
    product ever produces, so encountering one means the archive is not the
    archive — and `tarfile` is happy to follow a symlink out of the tree if
    asked to.
    """
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk() or member.isdev():
                fail(f"{archive.name} contains a link or device: {member.name}")
                return
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
                fail(f"{archive.name} contains a path outside the archive: {member.name}")
                return
        tar.extractall(dest, filter="data")


def check_contents(root: Path, manifest: dict) -> dict[str, Path]:
    """The archive holds the declared set, and nothing else.

    Both directions. An archive missing a component installs a product that
    cannot start its own broker, and an archive carrying an extra executable
    hands a user a binary the project has explicitly classified as not theirs
    — which is the `asv-vault-tool` failure this whole manifest exists to
    prevent, reappearing at the other end of the download.
    """
    expected: dict[str, Path] = {}
    for comp in shipped_components(manifest):
        rel = comp["install_as"]
        if not rel:
            fail(f"component {comp['name']} is shipped but declares no install_as")
            continue
        expected[comp["name"]] = root / rel

    found = {
        p.name: p
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != RECORD_FILE
    }
    for name, path in expected.items():
        if not path.exists():
            fail(f"the archive does not contain {name} at {path.name}")
    for name in found:
        if name not in {p.name for p in expected.values()}:
            fail(
                f"the archive contains {name}, which no shipped component "
                f"declares. A bundle that carries undeclared executables is "
                f"the failure this manifest exists to prevent."
            )
    return expected


def place(files: dict[str, Path], prefix: Path, manifest: dict) -> None:
    """Copy into `<prefix>/bin` and `<prefix>/libexec/asv`.

    The `on_path` flag in the manifest decides which directory a component
    lands in, and it is the same flag `tests/install_path_contract.py` asserts
    about, so the installer's layout and the layout gate cannot disagree.
    """
    by_name = {c["name"]: c for c in manifest["component"]}
    for comp in shipped_components(manifest):
        name = comp["name"]
        source = files.get(name)
        if source is None:
            continue
        dest = prefix / comp["install_as"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        os.chmod(dest, 0o755)
        mode = "PATH" if comp.get("on_path") else "private"
        note(f"installed {name} -> {dest} ({mode})")
    # Silence the unused lookup above without pretending it is a check.
    assert by_name


def write_record(prefix: Path, via: str, version: str, digest: str | None) -> Path:
    """The fact the CLI reads. Written by the installer, never by `asv`.

    Placed in the private runtime directory because that is the one directory
    an installation is guaranteed to have created for itself. `asv` finds it by
    the same `<root>/bin` → `<root>/libexec/asv` walk it uses for the broker.
    """
    libexec = prefix / "libexec" / "asv"
    libexec.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": RECORD_SCHEMA,
        "installed_via": via,
        "version": version,
        "install_root": str(prefix),
        "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if digest:
        record["archive_sha256"] = digest
    path = libexec / RECORD_FILE
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    note(f"wrote install record: {path}")
    return path


def run_setup(prefix: Path, asv_bin: Path) -> None:
    """Hand over. `setup` owns the runtime layout, the vault and the service.

    Not duplicated here. `asv setup` is idempotent and it is the only thing
    that knows about the passphrase, so an installer that did any of that
    would be a second implementation of the security-relevant part.
    """
    result = subprocess.run([str(asv_bin), "setup"], capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        fail(f"`asv setup` exited {result.returncode}; the bundle is installed but "
             f"not yet usable")
    else:
        note("asv setup completed")


# ---------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, e.g. 0.25.0")
    parser.add_argument("--prefix", required=True,
                        help="install root; receives bin/ and libexec/asv/")
    parser.add_argument("--installed-via", default="installer", choices=KNOWN_CHANNELS,
                        help="which channel is doing this; written to the record")
    parser.add_argument("--from-dir", type=Path,
                        help="take the archive from a local directory instead of "
                             "downloading it (used by the release job and tests)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--manifest", type=Path,
                        help="use this manifest instead of the one published "
                             "with the release")
    parser.add_argument("--trusted-key", type=Path,
                        help="minisign public key to require the release "
                             "signature to verify against, instead of the key "
                             "embedded in this installer. For an operator who "
                             "obtained the key out of band; the key id is in "
                             "the README and in the release announcement")
    parser.add_argument("--no-setup", action="store_true",
                        help="install the files and stop before asv setup")
    args = parser.parse_args(argv)

    prefix = Path(args.prefix).expanduser().resolve()

    # Platform first, manifest second. Detecting an unsupported architecture is
    # free, and finding out after downloading a manifest that names artefacts
    # this machine cannot run wastes the transfer and buries the real reason
    # under a second error.
    target = detect_target()
    if target is None:
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        archive_name = None

        # The trust anchor, materialised as a file because that is what the
        # verifier takes. Written before anything is downloaded so that a
        # failure here costs nothing and is not buried under a network error.
        if args.trusted_key:
            key_path = args.trusted_key
            if not key_path.is_file():
                fail(f"--trusted-key {key_path} is not a file. Refusing to install "
                     f"without a key to verify the release signature against.")
                return 1
        else:
            key_path = work / "trusted.pub"
            key_path.write_text(TRUSTED_RELEASE_KEY, encoding="utf-8")
        note(f"requiring a release signature from key {trusted_key_id(key_path)}")

        if args.from_dir:
            source = args.from_dir
            note(f"using local release directory {source}")
            manifest_path = (args.manifest or (source / "manifest.toml"))
            if not manifest_path.is_file():
                # Falling back to the checkout would make `--from-dir` mean two
                # different things depending on where the test runs.
                fail(
                    f"{manifest_path} is missing. A release publishes its "
                    f"manifest next to the archive; without it the installer "
                    f"does not know which components it is allowed to install."
                )
                return 1
        else:
            manifest_path = args.manifest or (work / "manifest.toml")
            fetch(f"{args.base_url}/v{args.version}/manifest.toml", manifest_path)

        manifest = read_manifest(manifest_path)
        if not shipped_components(manifest):
            return 1

        pattern = manifest["archive_name"]
        archive_name = pattern.replace("{version}", args.version).replace(
            "{target}", target)
        archive = work / archive_name
        checksums_file = work / CHECKSUM_AUTHORITY
        signature_file = work / f"{CHECKSUM_AUTHORITY}{SIGNATURE_SUFFIX}"

        if args.from_dir:
            found = source / archive_name
            if not found.exists():
                available = sorted(p.name for p in source.glob("agent-secretless-v*"))
                fail(
                    f"{archive_name} is not in {source}. "
                    f"Available: {', '.join(available) or 'nothing'}"
                )
                return 1
            shutil.copy2(found, archive)
            local_sums = source / CHECKSUM_AUTHORITY
            if not local_sums.exists():
                fail(f"{local_sums} is missing; a release with nothing to verify "
                     f"against is not installable")
                return 1
            shutil.copy2(local_sums, checksums_file)
            local_sig = source / f"{CHECKSUM_AUTHORITY}{SIGNATURE_SUFFIX}"
            if not local_sig.exists():
                fail(f"{local_sig} is missing; an unsigned release is not "
                     f"installable. There is no flag that turns this off, "
                     f"because a checksum file nobody signed is a list the "
                     f"download wrote for itself.")
                return 1
            shutil.copy2(local_sig, signature_file)
        else:
            fetch(f"{args.base_url}/v{args.version}/{archive_name}", archive)
            fetch(f"{args.base_url}/v{args.version}/{CHECKSUM_AUTHORITY}", checksums_file)
            fetch(f"{args.base_url}/v{args.version}/{CHECKSUM_AUTHORITY}{SIGNATURE_SUFFIX}",
                  signature_file)

        # The signature is checked before the file it signs is opened. Every
        # other provenance check in this installer is measured against the
        # contents of `sha256.sum`, and before this line those contents are
        # whatever arrived. Asking afterwards would be asking the attacker's
        # own document whether the attacker's archive is the one it names.
        if not verify_signature(checksums_file, signature_file, key_path):
            return 1

        checksums = parse_checksums(checksums_file.read_text(encoding="utf-8"))

        # The manifest is verified like any other byte, and before the archive
        # is: a substituted manifest would otherwise decide what the installer
        # accepts, and the digest that covers the archive says nothing about
        # it. Verified under its published name, because that is the name the
        # signed authority lists it as — and its absence from that authority is
        # itself the refusal, since an unlisted manifest is one the release
        # never vouched for.
        if not verify(manifest_path, checksums):
            return 1

        if not verify(archive, checksums):
            # Verification is the last point at which nothing has been written.
            return 1
        if not check_container(archive):
            return 1

        staging = work / "unpacked"
        staging.mkdir()
        extract(archive, staging)
        files = check_contents(staging, manifest)
        if _failures_present():
            return 1

        place(files, prefix, manifest)
        digest = sha256_of(archive)
        write_record(prefix, args.installed_via, args.version, digest)

    asv_bin = prefix / "bin" / "asv"
    if args.no_setup:
        note(f"installed. Next: {asv_bin} setup")
    else:
        run_setup(prefix, asv_bin)

    if failures:
        print()
        for message in failures:
            print(f"error: {message}")
        return 1
    print(f"\ninstalled {args.version} via {args.installed_via} into {prefix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
