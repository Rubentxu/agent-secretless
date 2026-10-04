#!/usr/bin/env python3
"""Can the installer be made to install a release it should refuse?

`tests/distribution_channels.py` shows the installer refusing a bundle that does
not match the checksum file it ships with. That is real, and it is not the
attack. The file that names the acceptable checksums arrives over the same
connection as the archive it describes, so anyone who can serve the download can
serve a pair that agrees with itself.

That was not a hypothesis. Before the signature check existed, a release whose
archive and checksum file were both replaced — a trojanized `asv` beside a
checksum file naming its digest — installed cleanly: exit 0, two green
"checksum verified" lines, and `#!/bin/sh` sitting on PATH where `asv` belongs.
This campaign is the receipt for that, and the receipt for the fix.

# What each row is

A row is not "the installer refused". A row is a *specific* release mutation
paired with a *specific* mutation of the installer that defeats it, and the row
is green only when both halves are observed:

  1. the honest installer refuses, and writes nothing;
  2. the installer, with the named lines broken, accepts the same release.

Without the second half every row would pass against an installer that refuses
everything — including a broken download, including a typo in an archive name.
A refusal test that cannot be shown to be refusable is not a test.

Three rows failed that half on the first run, and each failure was the campaign
being wrong rather than the installer being right, which is the only reason this
paragraph is worth reading:

  * "signature missing" was paired with a mutation that disabled the verify
    call, but the install also refuses earlier because the sidecar is absent —
    so the mutation changed nothing and the row proved only that a missing file
    is a missing file.
  * "checksum tampered" flipped a byte in the middle of the compressed stream.
    A corrupt zstd stream fails to decompress, so the installer refused for a
    reason that had nothing to do with the digest. The attack was unreachable
    even with the digest check deleted.
  * "required binary missing" paired with removing the contents check, after
    which the copy of the absent binary raised and the installer exited non-zero
    — a refusal, but from `shutil`, not from the layer under test.

# Why the bundles here are stubs, not real binaries

`distribution_channels.py` installs the real `asv` and `asv-brokerd` and
compares digests between two channels. That is the right place to pay for real
bytes. This campaign is about provenance, and every check under test compares
names, digests and signatures — never the content of a binary. The payload is
therefore two distinguishable stub bodies: `REAL`, which a legitimate release
carries, and `EVIL`, which an attacker's does. The distinction is what lets a
row say "the substitution landed" rather than "something was installed".

# Run: python3 tests/provenance_falsification.py
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_PY = REPO / "scripts" / "install.py"
MANIFEST = REPO / "distribution" / "manifest.toml"

VERSION = "0.25.0"
TARGET = "x86_64-unknown-linux-gnu"
AUTHORITY = "sha256.sum"
SIGNATURE_SUFFIX = ".minisig"

REAL = b"#!/bin/sh\necho REAL\nexit 0\n"
EVIL = b"#!/bin/sh\necho EVIL\nexit 0\n"

_failures: list[str] = []
_passes = 0


def check(condition: bool, message: str) -> None:
    global _passes
    if condition:
        _passes += 1
        print(f"  ok   {message}")
    else:
        _failures.append(message)
        print(f"  FAIL {message}")


# ----------------------------------------------------------------- the tools

def rsign() -> str:
    found = shutil.which("rsign") or str(Path.home() / ".cargo" / "bin" / "rsign")
    if not (Path(found).is_file() and os.access(found, os.X_OK)):
        raise SystemExit(
            "provenance_falsification: rsign is not installed. The installer "
            "refuses unsigned releases, so this campaign cannot build or attack "
            "one. Install rsign2 and re-run."
        )
    return found


def make_key(directory: Path, name: str) -> tuple[Path, Path]:
    secret, public = directory / f"{name}.key", directory / f"{name}.pub"
    subprocess.run([rsign(), "generate", "-W", "-p", str(public), "-s", str(secret),
                    "-c", f"agent-secretless {name}"], check=True, capture_output=True)
    return secret, public


def sign(path: Path, secret: Path) -> None:
    subprocess.run([rsign(), "sign", "-W", "-s", str(secret), "-x",
                    str(path) + SIGNATURE_SUFFIX, str(path)],
                   check=True, capture_output=True)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------ building a release

class Release:
    """A release directory built the way a real one is: archive, manifest, signed authority.

    `trusted` is the key the installer is told to require; `rogue` is a second,
    untrusted key an attacker controls. Keeping both in one builder is what lets
    each row say whose signature is on the authority, which is the question the
    whole chain turns on.
    """

    def __init__(self, dest: Path, keys: Path) -> None:
        import tomllib

        self.dir = dest
        self.dir.mkdir(parents=True, exist_ok=True)
        self.keys = keys
        keys.mkdir(parents=True, exist_ok=True)
        self.trusted_secret, self.trusted_public = make_key(keys, "trusted")
        self.rogue_secret, self.rogue_public = make_key(keys, "rogue")
        with MANIFEST.open("rb") as fh:
            self.manifest = tomllib.load(fh)
        self.archive_name = self.manifest["archive_name"].replace(
            "{version}", VERSION).replace("{target}", TARGET)
        self.archive = self.dir / self.archive_name
        shutil.copy2(MANIFEST, self.dir / "manifest.toml")

    def pack(self, body: bytes = REAL, extra: dict[str, bytes] | None = None,
             drop: set[str] | None = None) -> None:
        """Rebuild the archive: the declared components, plus or minus named ones.

        The archive is always a valid zstd container. A bundle that cannot be
        decompressed is refused by the decompressor whatever the provenance
        checks say, which is how the first version of this campaign ended up
        proving nothing.
        """
        drop = drop or set()
        with tarfile.open(self.archive, "w:zst") as tar:
            for comp in self.manifest["component"]:
                if not comp.get("shipped") or comp["name"] in drop:
                    continue
                info = tarfile.TarInfo(comp["install_as"])
                info.size, info.mode = len(body), 0o755
                tar.addfile(info, io.BytesIO(body))
            for name, payload in (extra or {}).items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(payload), 0o755
                tar.addfile(info, io.BytesIO(payload))

    def publish(self, key: str = "trusted", include_manifest: bool = True) -> None:
        """Write the authority and sign it with the named key."""
        secret = self.trusted_secret if key == "trusted" else self.rogue_secret
        lines = [f"{sha256_of(self.archive)}  {self.archive_name}"]
        if include_manifest:
            lines.append(f"{sha256_of(self.dir / 'manifest.toml')}  manifest.toml")
        authority = self.dir / AUTHORITY
        authority.write_text("\n".join(lines) + "\n", encoding="utf-8")
        sign(authority, secret)

    def ship(self, **kwargs) -> "Release":
        self.pack(**kwargs)
        self.publish()
        return self


def run_installer(script: Path, release: Release, prefix: Path
                  ) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("ASV_INSTALLER", None)
    return subprocess.run(
        [sys.executable, str(script),
         "--version", VERSION, "--prefix", str(prefix),
         "--from-dir", str(release.dir), "--installed-via", "installer",
         "--no-setup", "--trusted-key", str(release.trusted_public)],
        capture_output=True, text=True, env=env, timeout=300)


def installed_as(prefix: Path) -> bytes | None:
    candidate = prefix / "bin" / "asv"
    return candidate.read_bytes() if candidate.is_file() else None


# ---------------------------------------------------------- installer mutations

# Each is a change to scripts/install.py that reads like a plausible mistake
# rather than a hole punched on purpose — a mutation nobody would ever write
# proves nothing about whether the original lines were load-bearing. A named
# mutation may span several places: "this project does not sign releases" is one
# decision expressed in more than one line, and a campaign that could only
# express it as a single line would be testing something the code never was.
MUTATIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "signature-layer-absent": (
        (
            '            local_sig = source / f"{CHECKSUM_AUTHORITY}{SIGNATURE_SUFFIX}"\n'
            "            if not local_sig.exists():\n"
            '                fail(f"{local_sig} is missing; an unsigned release is not "\n'
            '                     f"installable. There is no flag that turns this off, "\n'
            '                     f"because a checksum file nobody signed is a list the "\n'
            '                     f"download wrote for itself.")\n'
            "                return 1\n"
            "            shutil.copy2(local_sig, signature_file)\n",
            '            local_sig = source / f"{CHECKSUM_AUTHORITY}{SIGNATURE_SUFFIX}"\n'
            "            if local_sig.exists():\n"
            "                shutil.copy2(local_sig, signature_file)\n",
        ),
        (
            "        if not verify_signature(checksums_file, signature_file, key_path):\n"
            "            return 1\n",
            "        pass\n",
        ),
    ),
    "digest-check-removed": (
        (
            "    if result.returncode != 0:\n        actual = sha256_of(archive)",
            "    if False:\n        actual = sha256_of(archive)",
        ),
    ),
    "unlisted-file-is-accepted": (
        (
            '    if expected is None:\n'
            '        fail(f"{archive.name} is not listed in {CHECKSUM_AUTHORITY}")\n'
            "        return False\n",
            "    if expected is None:\n        return True\n",
        ),
    ),
    "contents-check-removed": (
        (
            "        files = check_contents(staging, manifest)\n",
            "        files = {c[\"name\"]: staging / c[\"install_as\"]\n"
            "                 for c in shipped_components(manifest)}\n",
        ),
    ),
    "absent-component-is-skipped": (
        (
            "        if source is None:\n            continue\n",
            "        if source is None or not source.exists():\n            continue\n",
        ),
    ),
    "the-download-supplies-the-key": (
        (
            "        if args.trusted_key:\n"
            "            key_path = args.trusted_key\n"
            "            if not key_path.is_file():\n",
            "        if args.trusted_key:\n"
            '            shipped = (args.from_dir or work) / "release.pub"\n'
            "            key_path = shipped if shipped.is_file() else args.trusted_key\n"
            "            if not key_path.is_file():\n",
        ),
    ),
}


def mutated_installer(names: tuple[str, ...], into: Path) -> Path | None:
    """A copy of the installer with the named mutations applied.

    None when an anchor is missing, which is reported as a failure of the row
    rather than as a defeated attack: a mutation whose anchor was renamed is a
    mutation this campaign can no longer evaluate, and silently skipping it
    would turn a renamed line into a permanently green row.
    """
    text = INSTALL_PY.read_text(encoding="utf-8")
    for name in names:
        for old, new in MUTATIONS[name]:
            if old not in text:
                return None
            text = text.replace(old, new, 1)
    into.write_text(text, encoding="utf-8")
    return into


# ----------------------------------------------------------------- the rows

def row(name: str, build, mutations: tuple[str, ...], payload: bytes | None,
        keys: Path, work: Path) -> None:
    """One failure mode: refused by the honest installer, accepted by a broken one.

    `payload` is the body the substituted release carries, and it is only a
    claim for the rows where something is actually substituted. For the rows
    whose release is a genuine one that merely should not have been accepted —
    a missing signature, an unlisted manifest, an incomplete bundle — the claim
    is acceptance itself, and asking for a trojan there would be asking a
    question the row does not pose.
    """
    print(f"\n-- {name}")
    # A slug of the whole name, not its first word: "firma ausente" and "firma
    # invalida" share a first word, and two rows writing into one key directory
    # means the second `rsign generate` fails on an existing file — which reads
    # as a broken campaign rather than as a collision.
    tag = name.replace(" ", "-")

    honest = work / f"{tag}-honest"
    release = Release(honest / "release", keys / f"{tag}-honest-keys")
    build(release)
    prefix = honest / "target"
    r = run_installer(INSTALL_PY, release, prefix)
    check(r.returncode != 0, f"refused (exit {r.returncode})")
    check(installed_as(prefix) is None, "nothing was written to the destination")

    broken = mutated_installer(mutations, work / f"{tag}-broken.py")
    if broken is None:
        check(False, f"the mutation {mutations} could not be applied — an anchor "
                     f"line is gone, so this row can no longer show the attack "
                     f"is reachable")
        return
    rerun = work / f"{tag}-broken"
    release2 = Release(rerun / "release", keys / f"{tag}-broken-keys")
    build(release2)
    prefix2 = rerun / "target"
    r2 = run_installer(broken, release2, prefix2)
    where = f"the {', '.join(mutations)} mutation"
    check(r2.returncode == 0,
          f"{where} accepts the release the honest installer refused "
          f"(exit {r2.returncode})"
          if r2.returncode == 0 else
          f"{where} still refuses (exit {r2.returncode}); this row cannot be "
          f"shown to be refusable and is not evidence")
    if payload is not None and r2.returncode == 0:
        check(installed_as(prefix2) == payload,
              "and what landed on PATH is the substituted body, not the original")


# ----------------------------------------------------------------- the builds

def build_clean(r: Release) -> None:
    r.ship()


def build_no_signature(r: Release) -> None:
    r.ship()
    (r.dir / (AUTHORITY + SIGNATURE_SUFFIX)).unlink()


def build_bad_signature(r: Release) -> None:
    r.ship()
    # The authority gains a line after it was signed: its contents are now
    # partly the attacker's, and the signature over the file is genuinely bad.
    authority = r.dir / AUTHORITY
    authority.write_text(
        authority.read_text(encoding="utf-8") + f"{'0' * 64}  asv-brokerd\n",
        encoding="utf-8")


def build_tampered_checksum(r: Release) -> None:
    """A valid archive whose bytes are not the ones the signed authority names."""
    r.ship(body=REAL)
    r.pack(body=EVIL)          # republished archive, authority left untouched


def build_substituted_pair(r: Release) -> None:
    """The one that installed a trojan before the signature check existed.

    Archive and authority both replaced, the authority rewritten to name the
    new archive and signed — with the attacker's key, and with `release.pub`
    riding along so the key travels with the download.
    """
    r.pack(body=EVIL)
    r.publish(key="rogue")
    shutil.copy2(r.rogue_public, r.dir / "release.pub")


def build_manifest_not_in_authority(r: Release) -> None:
    r.ship()
    r.publish(include_manifest=False)


def build_missing_required_binary(r: Release) -> None:
    r.ship(drop={"asv-brokerd"})


def build_forbidden_binary(r: Release) -> None:
    r.ship(extra={"bin/asv-vault-tool": EVIL})


# -------------------------------------------------------------------- the run

def control_row(keys: Path, work: Path) -> None:
    """A release that deserves to install, does.

    Without this, a campaign that passes could be passing because the installer
    refuses everything. The control is what makes the other rows mean something.
    """
    print("\n-- CONTROL: a correctly signed, untampered release installs")
    release = Release(work / "control-release", keys / "control-keys")
    release.ship(body=REAL)
    prefix = work / "control-target"
    r = run_installer(INSTALL_PY, release, prefix)
    if r.returncode != 0:
        print(r.stdout[-800:], r.stderr[-800:])
    check(r.returncode == 0, f"the untampered signed release installs ({r.returncode})")
    check(installed_as(prefix) == REAL, "the bytes installed are the release's own")
    check((prefix / "libexec" / "asv" / "asv-brokerd").is_file(),
          "the broker lands outside PATH")
    check("signature verified" in (r.stdout + r.stderr),
          "the install says the signature was verified")


def main() -> int:
    print("Installer provenance falsification\n")
    print("Every row refuses, then the named mutation of the installer accepts it.\n")
    if not INSTALL_PY.is_file():
        print(f"provenance_falsification: {INSTALL_PY} is missing")
        return 1

    with tempfile.TemporaryDirectory(prefix="asv-provenance-") as tmp:
        work = Path(tmp)
        keys = work / "keys"
        keys.mkdir(parents=True, exist_ok=True)

        control_row(keys, work)

        rows = [
            # (name, build, mutations, payload the substitution carries)
            ("firma ausente", build_no_signature, ("signature-layer-absent",), None),
            ("firma invalida", build_bad_signature, ("signature-layer-absent",), None),
            ("checksum manipulado", build_tampered_checksum,
             ("digest-check-removed",), EVIL),
            ("bundle y autoridad sustituidos, firmados por una clave ajena",
             build_substituted_pair, ("signature-layer-absent",), EVIL),
            ("la clave la trae la descarga", build_substituted_pair,
             ("the-download-supplies-the-key",), EVIL),
            ("manifest fuera de la autoridad firmada", build_manifest_not_in_authority,
             ("unlisted-file-is-accepted",), None),
            ("binario obligatorio ausente", build_missing_required_binary,
             ("contents-check-removed", "absent-component-is-skipped"), None),
            ("binario prohibido presente", build_forbidden_binary,
             ("contents-check-removed",), None),
        ]
        for entry in rows:
            row(*entry, keys, work)

        print("\n-- there is no flag that skips provenance")
        help_text = subprocess.run(
            [sys.executable, str(INSTALL_PY), "--help"],
            capture_output=True, text=True).stdout
        source = INSTALL_PY.read_text(encoding="utf-8")
        for banned in ("--no-verify", "--insecure", "--skip-signature",
                       "--allow-unsigned", "--trust-download", "--no-provenance"):
            check(banned not in help_text, f"{banned} does not exist")
            check(f'"{banned}"' not in source,
                  f"the installer does not even mention {banned}")

        print("\n-- the toolchain carve-out did not blind the guard that has it")
        _toolchain_guard_row()

    print(f"\n{_passes} checks passed, {len(_failures)} failed")
    for f in _failures:
        print(f"  FAILED: {f}")
    return 1 if _failures else 0


def _toolchain_guard_row() -> None:
    """`tests/distribution_channels.py` cannot scan for `cargo` with an exception.

    That guard forbids a toolchain in the installer and, since the installer
    started resolving `rsign` out of `~/.cargo/bin`, subtracts that one path
    before scanning. A guard that was widened so new code could pass is worth
    nothing unless the widening is itself shown to still bite, so the guard is
    run here against an installer that really does shell out to a compiler, and
    against the one that ships.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "distribution_channels", REPO / "tests" / "distribution_channels.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Under the repository's own build directory, because the guard names each
    # script it checked with a path relative to the repository root and a file
    # from the system temp dir makes that raise. `target/` is where build
    # artifacts already live and is not tracked.
    scratch = REPO / "target" / "provenance-falsification"
    scratch.mkdir(parents=True, exist_ok=True)

    def run_guard() -> bool:
        """Run the imported guard quietly, and say whether it reported a failure.

        The guard prints its own `FAIL` lines as it goes. Letting them through
        would put the word FAIL in this campaign's output while its own summary
        said zero failures, which is exactly the sort of thing a reader skims
        past and then believes. The two smuggled runs are *expected* to fail;
        they are reported here as passing checks instead.
        """
        module._failures.clear()
        module._passes = 0
        with contextlib.redirect_stdout(io.StringIO()):
            module.test_no_toolchain_is_reachable()
        return bool(module._failures)

    try:
        check(not run_guard(),
              f"the real installer passes the toolchain guard")

        for label, injected in (
            ("shells out to cargo",
             '    subprocess.run(["cargo", "build", "--release"], check=True)\n'),
            ("names cargo as a command string",
             '    TOOLCHAIN = "cargo"\n'),
        ):
            smuggled = scratch / f"smuggled-{label.replace(' ', '-')}.py"
            smuggled.write_text(
                INSTALL_PY.read_text(encoding="utf-8") + injected, encoding="utf-8")
            module.INSTALL_PY = smuggled
            check(run_guard(),
                  f"the guard still catches an installer that {label}")
    finally:
        module.INSTALL_PY = INSTALL_PY
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
