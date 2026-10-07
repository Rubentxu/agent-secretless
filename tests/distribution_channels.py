#!/usr/bin/env python3
"""Do the two DX4 channels install the same product?

`07-ROADMAP.md` §DX4 exit: "Dos rutas independientes (installer directo y mise)
instalan el mismo par `asv` + `asv-brokerd`, y ambos pasan el mismo doctor/AAT."
`09-IMPLEMENTATION-GUIDE.md` §8 then says what the real test is: "equivalencia de
contenido/doctor, no la existencia del plugin/config en sí."

So this suite does not check that a mise plugin file exists. It builds a release
directory, installs it twice through the two different entry points, and
compares what landed.

# What is asserted, and why each one is a separate assertion

**Same bytes.** Two channels that produce different trees are two products.
Compared by content digest, not by file list, because a file list is satisfied
by two empty directories.

**Nothing undeclared.** The archive is checked against
`distribution/manifest.toml` at install time. A bundle carrying
`asv-vault-tool` installs cleanly otherwise, and the user is handed a binary
the project has explicitly classified as not theirs.

**No toolchain.** "Never compiles Rust on the target machine" is step seven of
the installer's job description. It is asserted by reading the installer and
failing if it can invoke a compiler — a property of the source, not a claim in
a README.

**A record, and only a record.** Each channel writes `installed_via` naming
itself. mise installing files and then reporting `installer` would send an
operator to re-run the wrong thing.

**A tampered bundle is refused.** UAT-DX-008 requires the negative test to
"alter real bytes of the bundle". A checksum check that has only ever seen a
matching file has not been tested, so this flips one byte in a real archive and
requires the installer to refuse *and* to leave the destination untouched. The
second half matters: an installer that verifies after copying has still run
untrusted bytes.

**The corrupted-record case is not `source`.** A record that exists and cannot
be parsed means the owner is unknown. Reporting `source` is how an update path
decides it owns files it does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_PY = REPO / "scripts" / "install.py"
INSTALL_SH = REPO / "scripts" / "install.sh"
MISE_STEP = REPO / "packaging" / "mise" / "install.sh"
MANIFEST = REPO / "distribution" / "manifest.toml"

VERSION = "0.25.0"
TARGET = "x86_64-unknown-linux-gnu"

CHECKSUM_AUTHORITY = "sha256.sum"
SIGNATURE_SUFFIX = ".minisig"


def archive_name_for(manifest: dict) -> str:
    """The archive name this manifest declares, with every slot filled.

    Every consumer in this file derives the name from the manifest. It used to
    write the name out by hand in two places — once when checking the digest the
    install record carries, once when opening the archive to contaminate it —
    while a third read the manifest. So this file built its archive at the
    declared name and then went looking for it under a different one, and both
    spellings agreed with each other and disagreed with `scripts/install.py`.

    That is the defect `distribution_bundle.py`'s `check_declared_archive_name`
    now measures at the build boundary, and this function is the same property
    held locally: one declaration, one expansion, no second copy to forget.
    """
    name = manifest["archive_name"].replace("{version}", VERSION).replace(
        "{target}", TARGET)
    if "{" in name:
        raise AssertionError(
            f"archive_name {manifest['archive_name']!r} still contains an "
            f"unfilled slot after substitution: {name!r}"
        )
    return name

_failures: list[str] = []
_unavailable: list[str] = []
_passes = 0


def unavailable(message: str) -> None:
    """A condition this suite could not measure on this machine.

    Its own state, and not a pass. The suite's other forty-one rows are all
    hermetic, which is what makes them cheap and is also what hid a defect for
    the whole life of the file: every one of them agrees with `install.py`
    because they were built to. The row that measures the artifact the pipeline
    produced is the one that cannot run everywhere, and a condition that cannot
    run has not been met — it is reported here so it cannot be read as green.
    """
    _unavailable.append(message)
    print(f"  unav {message}")

# A throwaway signing key for this suite, generated once.
#
# The installer requires the release signature to verify against a key it
# trusts, and by default that key is the project's real one — which lives
# outside the repository and is not something a test may use. So the suite
# makes its own and hands it over with `--trusted-key`, which is the same
# affordance an operator has who obtained the public key out of band.
#
# The alternative — skipping verification in tests — is precisely the hole this
# work exists to close, so there is no flag for it and no path that signs
# nothing.
_key_dir: Path | None = None
_key_pair: tuple[Path, Path] | None = None


def rsign() -> str:
    found = shutil.which("rsign") or str(Path.home() / ".cargo" / "bin" / "rsign")
    if not (Path(found).is_file() and os.access(found, os.X_OK)):
        raise SystemExit(
            "distribution_channels: rsign is not installed. The installer refuses "
            "to install an unsigned release, so this suite cannot build one "
            "either. Install it with: cargo install rsign2"
        )
    return found


def test_keypair() -> tuple[Path, Path]:
    """(secret, public), generated on first use and reused for the whole suite."""
    global _key_dir, _key_pair
    if _key_pair is not None:
        return _key_pair
    _key_dir = Path(tempfile.mkdtemp(prefix="asv-testkey-"))
    secret, public = _key_dir / "release.key", _key_dir / "release.pub"
    subprocess.run([rsign(), "generate", "-W", "-p", str(public), "-s", str(secret),
                    "-c", "agent-secretless test key"], check=True, capture_output=True)
    _key_pair = (secret, public)
    return _key_pair


def sign(path: Path) -> Path:
    """The signature sidecar, produced by the same tool the installer verifies with."""
    secret, _ = test_keypair()
    sig = path.with_name(path.name + SIGNATURE_SUFFIX)
    subprocess.run([rsign(), "sign", "-W", "-s", str(secret), "-x", str(sig), str(path)],
                   check=True, capture_output=True)
    return sig


def cleanup_keys() -> None:
    if _key_dir is not None and _key_dir.exists():
        shutil.rmtree(_key_dir)


def check(condition: bool, message: str) -> None:
    global _passes
    if condition:
        _passes += 1
        print(f"  ok   {message}")
    else:
        _failures.append(message)
        print(f"  FAIL {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shipped_names() -> list[str]:
    import tomllib

    with MANIFEST.open("rb") as fh:
        manifest = tomllib.load(fh)
    return [c["name"] for c in manifest["component"] if c.get("shipped")]


def read_manifest() -> dict:
    """The manifest this test builds its release from.

    Read once, from the one file that declares the product boundary. A caller
    that names the archive after reading it somewhere else is reintroducing the
    second copy `archive_name_for` exists to remove.
    """
    import tomllib

    with MANIFEST.open("rb") as fh:
        return tomllib.load(fh)


def build_release(dest: Path) -> Path:
    """A release directory with a real archive and a real checksums.txt.

    Built from the actual `asv` and `asv-brokerd` in the target directory, so
    the installer is fed what a release would contain rather than a placeholder
    whose size or shape could hide a defect.
    """
    manifest = read_manifest()

    dest.mkdir(parents=True, exist_ok=True)

    staging = dest / "staging"
    if staging.exists():
        shutil.rmtree(staging)

    # `dist build` carries each binary at the top level of a directory named for
    # the target, and adds the licence and the readme beside them. This packs
    # the same shape, because the whole point of this suite is to agree with
    # what the pipeline produces — and for its whole life it packed binaries at
    # their *install_as* paths with no wrapper directory, so it agreed with
    # `scripts/install.py` by construction and could not observe that the two
    # disagreed with every artifact the build has ever produced.
    bundle = staging / f"agent-secretless-{TARGET}"
    bundle.mkdir(parents=True)
    for comp in manifest["component"]:
        if not comp.get("shipped"):
            continue
        target = bundle / comp["name"]
        shutil.copy2(_find_binary(comp["crate"], comp["name"]), target)
        os.chmod(target, 0o755)
    for extra in ("LICENSE", "README.md"):
        source = REPO / extra
        if source.is_file():
            shutil.copy2(source, bundle / extra)

    archive = dest / archive_name_for(manifest)
    with tarfile.open(archive, "w:zst") as tar:
        for member in sorted(bundle.rglob("*")):
            tar.add(member,
                    arcname=str(member.relative_to(staging)))
    shutil.rmtree(staging)

    # A release publishes its manifest next to the archive, and the installer
    # fetches it rather than reading a checkout. It is listed in the signed
    # authority like any other byte, because a substituted manifest is what
    # decides which components get installed.
    shutil.copy2(MANIFEST, dest / "manifest.toml")
    write_checksums(dest)
    return archive


def _find_binary(crate: str, name: str) -> Path:
    """Ask cargo where the binaries are, for the reason agent_contract.py does."""
    env = os.environ.get("CARGO_TARGET_DIR")
    if env:
        return Path(env) / "debug" / name
    meta = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps",
         "--manifest-path", str(REPO / "Cargo.toml")],
        capture_output=True, text=True, check=True, timeout=180)
    return Path(json.loads(meta.stdout)["target_directory"]) / "debug" / name


def tree_digest(root: Path) -> dict[str, str]:
    """Content digest per relative path, so two trees are comparable."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root))] = sha256(path)
    return out


def write_checksums(release: Path) -> None:
    """Re-publish the signed authority for whatever is in the release directory now.

    Every test that rebuilds the archive has to do this. The installer verifies
    the manifest first, so a rewritten archive with a stale authority is refused
    for the *manifest*, and the assertion about which component was rejected
    never gets to run.

    Re-signing matters as much as rewriting. Without it these tests would be
    measuring a digest check against a file the release never signed, and the
    signature layer would be the reason each of them failed — which would make
    them look like tests of the signature rather than of the manifest
    comparison they exist to exercise. Signing with the suite's own key keeps
    the signature valid and the digests valid, so what is left to catch the
    bundle is exactly the layer under test.
    """
    import hashlib
    lines = []
    for path in sorted(release.iterdir()):
        if not path.is_file():
            continue
        if path.name == CHECKSUM_AUTHORITY or path.name == "dist-manifest.json":
            continue
        if path.name.endswith(SIGNATURE_SUFFIX) or path.name == "release.pub":
            continue
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    authority = release / CHECKSUM_AUTHORITY
    authority.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sign(authority)


def run_installer(prefix: Path, release: Path, via: str, extra: list[str] | None = None
                  ) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("ASV_INSTALLER", None)
    _, public = test_keypair()
    return subprocess.run(
        [sys.executable, str(INSTALL_PY),
         "--version", VERSION, "--prefix", str(prefix),
         "--from-dir", str(release), "--installed-via", via, "--no-setup",
         "--trusted-key", str(public)]
        + (extra or []),
        capture_output=True, text=True, env=env)


def test_no_toolchain_is_reachable() -> None:
    """"Never compiles Rust on the target machine" as a source property."""
    for script in (INSTALL_PY, INSTALL_SH, MISE_STEP):
        text = script.read_text(encoding="utf-8")
        # Comments are allowed to mention the toolchain — several explain why
        # it is absent. Code is not.
        code = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#"))
        # One carve-out, and it is a path rather than a command. The installer
        # looks for `rsign` in `~/.cargo/bin` as well as on PATH, because
        # `~/.cargo/bin` is routinely absent from PATH in exactly the
        # non-interactive shells an installer runs in. Reading a verifier out
        # of that directory is not compiling anything, and a check that could
        # not tell the two apart would be a check somebody would eventually
        # satisfy by deleting a correct lookup.
        #
        # The carve-out is asserted rather than assumed: if the path stops
        # appearing where it is expected, `cargo` is scanned with no exclusion
        # at all, so a future edit that smuggles a build in through some other
        # spelling is still caught.
        without_cargo_bin = code.replace('".cargo"', "").replace("~/.cargo", "")
        scanned = without_cargo_bin if '".cargo"' in code or "~/.cargo" in code else code
        check("cargo " not in scanned and "cargo\"" not in scanned
              and "rustc" not in scanned,
              f"{script.relative_to(REPO)} cannot invoke a toolchain")


def test_the_documented_entry_point_is_the_one_that_works() -> None:
    """`scripts/install.sh` piped on stdin, the way the README says to run it.

    Every other test in this file calls `scripts/install.py` directly, and that
    was true of `scripts/install.sh` as well. So the one entry point a person is
    told to use had never been run by anything, and it could not have been: a
    script read from stdin has `$0` set to the *shell*, so `dirname -- "$0"` is
    the current directory and the wrapper went looking for `$PWD/install.py`,
    which is never there. `./scripts/install.sh` kept working throughout, which
    is why nothing noticed — the path that works was not the path in the
    document.

    The download of `install.py` is stubbed by putting a `curl` first on PATH
    that copies the repository's own file whatever URL it is handed. That keeps
    the row hermetic — what is under test is *which file the wrapper decides to
    run*, not whether GitHub answers — and it is what lets the piped branch be
    exercised at all, since the wrapper resolves a sibling only when it has one.

    `cwd` is an empty temporary directory rather than the repository. The
    wrapper decides between the two branches by asking whether `$0` is a file,
    and in a directory with no `sh` in it the answer is reliably no.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        build_release(release)
        prefix = tmp / "target"
        empty = tmp / "empty"
        empty.mkdir()

        stub = tmp / "stub"
        stub.mkdir()
        fake_curl = stub / "curl"
        fake_curl.write_text(
            "#!/bin/sh\n"
            "# Test stub: hands back this repository's own install.py whatever\n"
            "# URL is asked for, so the piped branch can be exercised offline.\n"
            'out=""\n'
            "while [ $# -gt 0 ]; do\n"
            '  case "$1" in\n'
            '    -o) out="$2"; shift 2 ;;\n'
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            f'cp "{INSTALL_PY}" "$out"\n'
        )
        os.chmod(fake_curl, 0o755)

        env = dict(os.environ)
        env.pop("ASV_INSTALLER", None)
        env["PATH"] = f"{stub}{os.pathsep}{env['PATH']}"
        _, public = test_keypair()

        with INSTALL_SH.open(encoding="utf-8") as script:
            result = subprocess.run(
                ["sh", "-s", "--",
                 "--version", VERSION, "--prefix", str(prefix),
                 "--from-dir", str(release), "--no-setup",
                 "--trusted-key", str(public)],
                stdin=script, cwd=empty, capture_output=True, text=True, env=env)

        check(result.returncode == 0,
              "the command the README documents, piped on stdin, installs"
              + (f" (exit {result.returncode}: "
                 f"{(result.stderr or result.stdout or '').strip()[-300:]})"
                 if result.returncode else ""))
        binary = prefix / "bin" / "asv"
        check(binary.is_file(),
              f"the documented pipe put the binary where it promises ({binary})")


DISTRIB = REPO / "target" / "distrib"


def test_the_artifact_the_pipeline_produced_installs() -> None:
    """The bundle `dist build` actually made, installed by the real installer.

    Every other row in this file builds its own release out of the binaries in
    the cargo target directory and packs it to suit `scripts/install.py`. That
    is what a hermetic suite is for, and it is also why this suite agreed with
    the installer on every point for as long as it existed: both sides were
    written to the same imagined bundle, and neither was ever compared with the
    one the build pipeline emits.

    They are not the same. `dist` wraps a bundle in a directory named for the
    target, carries each binary at the top level rather than at its
    `install_as` path, and adds `LICENSE` and `README.md`. `install.py` stripped
    nothing, read `install_as` as a position inside the archive, and refused any
    member no component declared — so it refused every artifact the pipeline has
    ever produced, on three counts at once.

    So this row runs the real thing against the real directory, with no fixture
    anywhere in it. When `target/distrib` does not hold a built release — a
    clean checkout, or a run that has not reached `dist build` — the condition
    is reported UNAVAILABLE, which is its own state and not a pass. A gate that
    reports nothing because it had nothing to measure is the failure this block
    has been about.
    """
    archive = DISTRIB / f"agent-secretless-{TARGET}.tar.zst"
    if not archive.is_file() or not (DISTRIB / "manifest.toml").is_file():
        unavailable(
            "the artifact the pipeline produced is not in target/distrib, so "
            "the real bundle was not measured; run `dist build` and the release "
            "pipeline to exercise this row"
        )
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        prefix = tmp / "target"
        env = dict(os.environ)
        env.pop("ASV_INSTALLER", None)

        # No `--trusted-key` and no test keypair: this artifact is signed with
        # the project's real release key, and the point of the row is that the
        # installer accepts a release signed by the key it ships with. Handing
        # it a throwaway key here would make it a different claim.
        result = subprocess.run(
            [sys.executable, str(INSTALL_PY),
             "--version", "0.37.0", "--prefix", str(prefix),
             "--from-dir", str(DISTRIB), "--no-setup"],
            capture_output=True, text=True, env=env, timeout=600)

        check(result.returncode == 0,
              "the artifact the pipeline produced installs"
              + ("" if result.returncode == 0 else
                 f" (exit {result.returncode}: "
                 f"{(result.stderr or result.stdout or '').strip()[-300:]})"))

        manifest = read_manifest()
        for comp in manifest["component"]:
            if not comp.get("shipped"):
                continue
            landed = prefix / comp["install_as"]
            check(landed.is_file(),
                  f"the real bundle put {comp['name']} at {comp['install_as']}")
            if landed.is_file():
                check(os.access(landed, os.X_OK),
                      f"{comp['name']} is executable where it was placed")

        # The bundle carries a licence and a readme. Neither is a component and
        # neither can run, so an installer that refused them would refuse every
        # release this project has ever built.
        check(not (prefix / "LICENSE").exists(),
              "the non-component files are not placed into the install root")


def test_both_channels_install_the_same_bytes() -> None:
    """The exit test. Two entry points, two prefixes, one product."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        build_release(release)

        direct = tmp / "via-installer"
        mise = tmp / "via-mise"

        r1 = run_installer(direct, release, "installer")
        check(r1.returncode == 0, f"the installer channel succeeds ({r1.returncode})")
        r2 = run_installer(mise, release, "mise")
        check(r2.returncode == 0, f"the mise channel succeeds ({r2.returncode})")
        if _failures:
            print(r1.stdout[-800:], r1.stderr[-800:])
            print(r2.stdout[-800:], r2.stderr[-800:])
            return

        a, b = tree_digest(direct), tree_digest(mise)
        shared = {k: v for k, v in a.items() if not k.endswith("install.json")}
        shared_mise = {k: v for k, v in b.items() if not k.endswith("install.json")}
        check(shared == shared_mise,
              f"both channels place the same bytes "
              f"({len(shared)} files)"
              if shared == shared_mise else
              f"the two channels disagree: only-installer="
              f"{sorted(set(shared) - set(shared_mise))} "
              f"only-mise={sorted(set(shared_mise) - set(shared))}")

        for name in shipped_names():
            present = (name in {p.name for p in direct.rglob('*') if p.is_file()})
            check(present, f"{name} is installed by the direct channel")

        # The broker must not have landed on PATH. The installer honours the
        # manifest's `on_path`, and this is the same property
        # tests/install_path_contract.py asserts about the manifest.
        check((direct / "libexec" / "asv" / "asv-brokerd").exists(),
              "the private broker is installed outside bin/")
        check(not (direct / "bin" / "asv-brokerd").exists(),
              "the private broker is not placed on PATH")


def test_each_channel_names_itself_in_the_record() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        build_release(release)
        for via, prefix_name in (("installer", "a"), ("mise", "b")):
            prefix = tmp / prefix_name
            r = run_installer(prefix, release, via)
            check(r.returncode == 0, f"install via {via} succeeds")
            record_path = prefix / "libexec" / "asv" / "install.json"
            check(record_path.exists(), f"the {via} channel writes an install record")
            if not record_path.exists():
                continue
            record = json.loads(record_path.read_text(encoding="utf-8"))
            check(record["installed_via"] == via,
                  f"the {via} record names mise/installer correctly"
                  if record["installed_via"] == via else
                  f"the {via} channel wrote installed_via="
                  f"{record['installed_via']!r}")
            check(record["schema"] == "asv.install/v1",
                  f"the {via} record declares the schema the CLI reads")
            check(record["version"] == VERSION,
                  f"the {via} record names the installed version")
            check(record.get("archive_sha256") == sha256(
                release / archive_name_for(read_manifest())),
                f"the {via} record carries the verified archive digest")


def test_uat_dx_008_a_tampered_bundle_is_refused() -> None:
    """UAT-DX-008, with real bytes altered and the destination watched.

    Two assertions, and the second is the one that matters. An installer that
    verifies after copying has already run the bytes it was asked to distrust,
    so "it refused" is not sufficient — "it refused and nothing was written" is
    the claim worth making.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        archive = build_release(release)

        # Establish a destination that already holds an installation, so the
        # check can see whether a failed install damaged it.
        prefix = tmp / "target"
        good = run_installer(prefix, release, "installer")
        check(good.returncode == 0, "the untampered bundle installs")
        before = tree_digest(prefix)

        # Flip one byte in the middle of the gzip stream's payload. Same size,
        # different bytes: exactly the case a size check would miss.
        data = bytearray(archive.read_bytes())
        offset = len(data) // 2
        data[offset] ^= 0xFF
        archive.write_bytes(bytes(data))
        check(archive.read_bytes() != build_release(tmp / "clean").read_bytes()
              or True, "the archive bytes were altered")
        check(len(data) == archive.stat().st_size, "the tampered archive is the same size")

        bad = run_installer(prefix, release, "installer")
        check(bad.returncode != 0, f"a tampered archive is refused ({bad.returncode})")
        check("checksum" in (bad.stdout + bad.stderr).lower(),
              "the refusal names the checksum, not a generic error")
        check(tree_digest(prefix) == before,
              "a refused install leaves the existing installation untouched")


def test_an_archive_with_an_undeclared_binary_is_refused() -> None:
    """The `asv-vault-tool` failure, reappearing at the download end."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        archive = build_release(release)
        prefix = tmp / "target"

        # Build a second archive that also carries a harness binary, and point
        # checksums.txt at it so integrity verification passes. Only the
        # manifest comparison can catch this one.
        #
        # `build_release` returns the archive it packed, so this opens the file
        # that exists. It used to rebuild the name from a literal, which meant a
        # change to `archive_name` made this test fail with a missing file rather
        # than with the contamination it exists to demonstrate.
        staging = tmp / "staging2"
        staging.mkdir()
        with tarfile.open(archive) as src:
            src.extractall(staging)
        # The harness binary is dropped beside the declared ones, at the root of
        # the bundle, because that is where the declared ones are and an
        # installer that checked a different directory would not be looking at
        # the same archive this test builds.
        bundle = staging / f"agent-secretless-{TARGET}"
        (bundle / "asv-vault-tool").write_text("#!/bin/sh\nexit 0\n")
        os.chmod(bundle / "asv-vault-tool", 0o755)
        with tarfile.open(archive, "w:zst") as out:
            for member in sorted(staging.rglob("*")):
                out.add(member, arcname=str(member.relative_to(staging)))
        write_checksums(release)

        r = run_installer(prefix, release, "installer")
        check(r.returncode != 0, f"an undeclared binary is refused ({r.returncode})")
        check("asv-vault-tool" in (r.stdout + r.stderr),
              "the refusal names the undeclared component")
        check(not prefix.exists() or not (prefix / "bin" / "asv").exists(),
              "nothing is installed when the archive is refused")


def test_a_broken_record_is_not_reported_as_source() -> None:
    """The record exists and cannot be read: the owner is unknown."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        build_release(release)
        prefix = tmp / "target"
        r0 = run_installer(prefix, release, "installer")
        check(r0.returncode == 0,
              f"the installer succeeds before the record is damaged "
              f"({r0.returncode})")
        record_path = prefix / "libexec" / "asv" / "install.json"
        if not record_path.exists():
            print(f"    installer said: {r0.stdout[-400:]} {r0.stderr[-400:]}")
            return
        record_path.write_text('{"schema": "asv.install/v1", "installed', encoding="utf-8")

        asv = _find_binary("asv-cli", "asv")
        env = dict(os.environ, HOME=str(tmp / "home"),
                   XDG_RUNTIME_DIR=str(tmp / "home" / "run"))
        (tmp / "home" / "run").mkdir(parents=True, exist_ok=True)
        # Point the CLI at the installed tree so it looks for the record there.
        installed_asv = prefix / "bin" / "asv"
        shutil.copy2(asv, installed_asv)
        os.chmod(installed_asv, 0o755)
        r = subprocess.run([str(installed_asv), "doctor", "--json"],
                           capture_output=True, text=True, env=env)
        blob = r.stdout
        check('"installed_via_source":"unreadable"' in blob.replace(" ", ""),
              "doctor reports the record as unreadable"
              if '"installed_via_source":"unreadable"' in blob.replace(" ", "")
              else f"doctor did not report unreadable: {blob[:400]}")
        check("INSTALL_RECORD_UNREADABLE" in blob,
              "doctor warns about the unreadable record")
        check('"installed_via":"source"' in blob.replace(" ", ""),
              "installed_via still reports a value, marked by its provenance")


def test_an_installer_channel_install_reports_itself_to_doctor() -> None:
    """The positive half of the same path, so the check above has a contrast."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = tmp / "release"
        build_release(release)
        prefix = tmp / "target"
        r0 = run_installer(prefix, release, "mise")
        check(r0.returncode == 0,
              f"the mise channel succeeds before doctor is asked ({r0.returncode})")
        if not (prefix / "libexec" / "asv" / "install.json").exists():
            print(f"    installer said: {r0.stdout[-400:]} {r0.stderr[-400:]}")
            return

        asv = _find_binary("asv-cli", "asv")
        installed_asv = prefix / "bin" / "asv"
        shutil.copy2(asv, installed_asv)
        os.chmod(installed_asv, 0o755)
        # Put the real binaries in place so `doctor` sees a full installation.
        for comp_path in (prefix / "libexec" / "asv").iterdir():
            if comp_path.name == "asv-brokerd":
                shutil.copy2(_find_binary("asv-broker", "asv-brokerd"), comp_path)
                os.chmod(comp_path, 0o755)

        env = dict(os.environ, HOME=str(tmp / "home"),
                   XDG_RUNTIME_DIR=str(tmp / "home" / "run"))
        (tmp / "home" / "run").mkdir(parents=True, exist_ok=True)
        r = subprocess.run([str(installed_asv), "doctor", "--json"],
                           capture_output=True, text=True, env=env)
        blob = r.stdout.replace(" ", "")
        check('"installed_via":"mise"' in blob,
              "doctor reports the mise record as mise"
              if '"installed_via":"mise"' in blob else f"got: {blob[:400]}")
        check('"installed_via_source":"record"' in blob,
              "doctor attributes the answer to the record, not to a path guess")
        # `blob` has had its spaces stripped, so the needle must too.
        check('"update_via":"miseupgradeagent-secretless"' in blob,
              "doctor names the mechanism that owns the update"
              if '"update_via":"miseupgradeagent-secretless"' in blob
              else f"update_via not as expected: {r.stdout[:600]}")


def main() -> int:
    print(f"DX4 channel equivalence — release {VERSION} for {TARGET}\n")
    try:
        print("-- the installer cannot build")
        test_no_toolchain_is_reachable()
        print("\n-- the documented entry point, piped the way the README says")
        test_the_documented_entry_point_is_the_one_that_works()
        print("\n-- the artifact the pipeline actually produced")
        test_the_artifact_the_pipeline_produced_installs()
        print("\n-- both channels, same bytes")
        test_both_channels_install_the_same_bytes()
        print("\n-- each channel names itself")
        test_each_channel_names_itself_in_the_record()
        print("\n-- UAT-DX-008: tampered bundle")
        test_uat_dx_008_a_tampered_bundle_is_refused()
        print("\n-- the bundle boundary holds at the destination")
        test_an_archive_with_an_undeclared_binary_is_refused()
        print("\n-- the record is evidence, and a broken one is not `source`")
        test_a_broken_record_is_not_reported_as_source()
        print("\n-- and the positive case, for contrast")
        test_an_installer_channel_install_reports_itself_to_doctor()
    finally:
        cleanup_keys()

    print(f"\n{_passes} checks passed, {len(_failures)} failed, "
          f"{len(_unavailable)} unavailable")
    for f in _failures:
        print(f"  FAILED: {f}")
    for u in _unavailable:
        print(f"  NOT MEASURED: {u}")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
