#!/usr/bin/env python3
"""Falsification tests for scripts/check-release-config.py.

A guard nobody has tried to break is a guard whose green means nothing, and
this repository has already found several of those: a test that asserted a
command's *name* instead of its help text, a test that never compared the two
values it existed to compare, `sddk ledger verify-chain` reporting PASS over
zero events, and a release-config guard that fired on `%h` versus `~` — the
same directory written two ways.

That last one is the reason this file exists in its current shape. The guard
was correct and its comparison was naive, and a false positive is not a milder
version of a false negative: it is a guard that gets switched off. So case 9
below pins the *absence* of a failure, which is a test most suites do not write.

Each case builds a throwaway tree and runs the same guard file against it with
`--root`, so the rules being exercised are the shipped rules and not a second
copy of them that could drift.

Run: python3 tests/release_config_drift.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "scripts" / "check-release-config.py"

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}" + (f"\n        {detail}" if detail else ""))


def crate_with_bin(binary: str, package: str = "asv-cli") -> str:
    return f'[package]\nname = "{package}"\n\n[[bin]]\nname = "{binary}"\npath = "src/main.rs"\n'


ROOT_CARGO = """[workspace]
members = []

[workspace.package]
version = "0.26.0"
"""

DIST_PACKAGE = """[package]
name = "agent-secretless"
version = "0.26.0"
binaries = ["asv", "asv-brokerd"]
"""

# The product boundary, kept as a literal in this file rather than read from the
# repository. A falsification fixture that inherited the real manifest could not
# distinguish "the guard is right" from "the fixture happened to agree".
DIST_MANIFEST = """
schema = "asv.distribution/v1"
product = "agent-secretless"

[layout.user]
root = "~"
bin = ".local/bin"
libexec = ".local/libexec/asv"
unit = ".config/systemd/user/asv-brokerd.service"

[[component]]
name = "asv"
class = "required-public"
crate = "asv-cli"
shipped = true
install_as = "bin/asv"
on_path = true

[[component]]
name = "asv-brokerd"
class = "required-private"
crate = "asv-broker"
shipped = true
install_as = "libexec/asv/asv-brokerd"
on_path = false

[[component]]
name = "asv-vault-tool"
class = "test-harness"
crate = "asv-vault"
shipped = false
forbidden_in_production = true
install_as = ""
on_path = false
"""


GOOD_INSTALL_SH = """#!/bin/sh
set -eu
RAW_BASE="https://raw.githubusercontent.com/Rubentxu/agent-secretless"
exec python3 "$here/install.py" "$@"
"""

GOOD_INSTALL_PY = '''#!/usr/bin/env python3
DEFAULT_BASE_URL = "https://github.com/Rubentxu/agent-secretless/releases/download"
'''


def make_tree(tmp: Path, *, dist_toml: str | None = None, unit: str | None = None,
              crates: dict[str, str] | None = None, root_cargo: str | None = None,
              dist_package: str | None = DIST_PACKAGE,
              dist_manifest: str | None = DIST_MANIFEST,
              install_sh: str | None = GOOD_INSTALL_SH,
              install_py: str | None = GOOD_INSTALL_PY) -> Path:
    """A minimal tree with the same shape the guard reads.

    Built from literals rather than copied from the repository so a case cannot
    accidentally inherit the very configuration it is supposed to break.

    The two installer entry points are here for the same reason. `scripts/install.sh`
    fetches `install.py` from a URL of its own when it is piped, and the guard
    compares that URL against the one `install.py` downloads releases from — so a
    fixture without them fails every positive case for a reason that has nothing
    to do with what those cases were written to exercise. That happened the first
    time the rule was added, and 4 of 25 cases went red on the guard's new error
    rather than on the drift it was checking for.
    """
    root = tmp
    if dist_toml is not None:
        (root / "dist-workspace.toml").write_text(dist_toml)
    (root / "Cargo.toml").write_text(root_cargo if root_cargo is not None else ROOT_CARGO)
    (root / "packaging").mkdir(parents=True, exist_ok=True)
    if unit is not None:
        (root / "packaging" / "asv-brokerd.service").write_text(unit)
    if dist_package is not None:
        (root / "packaging" / "dist.toml").write_text(dist_package)
    if dist_manifest is not None:
        (root / "distribution").mkdir(parents=True, exist_ok=True)
        (root / "distribution" / "manifest.toml").write_text(dist_manifest)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    if install_sh is not None:
        (root / "scripts" / "install.sh").write_text(install_sh)
    if install_py is not None:
        (root / "scripts" / "install.py").write_text(install_py)
    for name, manifest in (crates or DEFAULT_CRATES).items():
        path = root / "crates" / name / "Cargo.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(manifest)
    return root


def crate_with_bin(binary: str, package: str = "asv-cli") -> str:
    return f'[package]\nname = "{package}"\n\n[[bin]]\nname = "{binary}"\npath = "src/main.rs"\n'


GOOD_DIST = """
[workspace]
members = ["cargo:."]

[dist]
cargo-dist-version = "0.32.0"
installers = ["shell"]
targets = ["x86_64-unknown-linux-gnu"]
checksum = "sha256"
install-path = "~/.local/bin"
hosting = "github"
"""

GOOD_UNIT = """[Unit]
Description=agent-secretless broker

[Service]
Type=simple
ExecStart=%h/.local/libexec/asv/asv-brokerd %t/asv/broker.sock --vault %h/v --passphrase-file %h/p
NoNewPrivileges=true

[Install]
WantedBy=default.target
"""

# The directory names and the package names deliberately differ, exactly as they
# do in the repository: `crates/cli` declares `name = "asv-cli"`. A fixture that
# made them the same would not have caught the guard comparing the manifest's
# package name against a directory name, which it did for one iteration.
DEFAULT_CRATES = {
    "cli": crate_with_bin("asv", "asv-cli"),
    "broker": crate_with_bin("asv-brokerd", "asv-broker"),
    "vault": crate_with_bin("asv-vault-tool", "asv-vault"),
}


def run_guard(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD), "--root", str(root)],
        capture_output=True,
        text=True,
    )


def case(name: str, *, expect_pass: bool, **kwargs) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = make_tree(Path(tmp), **kwargs)
        result = run_guard(root)
        if expect_pass:
            ok = result.returncode == 0
            detail = f"exit {result.returncode}\n{result.stdout}{result.stderr}"
        else:
            ok = result.returncode != 0
            detail = "expected a non-zero exit, got 0"
        report(name, ok, detail)


def main() -> int:
    print("check-release-config.py falsifiability\n")

    # 1. The shape that must pass.
    case("a correct configuration passes", expect_pass=True,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 2. The prohibition. `ci` is the setting that makes dist write a workflow,
    #    and ci-policy.sh only sees the file, not the cause of it.
    case("a `ci` backend fails", expect_pass=False,
         dist_toml=GOOD_DIST + '\nci = ["github"]\n', unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 3-4. Platform drift.
    case("a Windows target fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace(
             'targets = ["x86_64-unknown-linux-gnu"]',
             'targets = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("a macOS target fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace(
             'targets = ["x86_64-unknown-linux-gnu"]',
             'targets = ["aarch64-apple-darwin"]'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("an empty target list fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace(
             'targets = ["x86_64-unknown-linux-gnu"]', "targets = []"),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("an aarch64 Linux target is allowed", expect_pass=True,
         dist_toml=GOOD_DIST.replace(
             'targets = ["x86_64-unknown-linux-gnu"]',
             'targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 5. Installers.
    case("a homebrew installer fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace('installers = ["shell"]', 'installers = ["shell", "homebrew"]'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("an msi installer fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace('installers = ["shell"]', 'installers = ["msi"]'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("no installers at all fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace('installers = ["shell"]', "installers = []"),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 6. Install location. A system-wide install needs root, and a credential
    #    broker running as root is a privilege story this project has not tested.
    case("a system-wide install-path fails", expect_pass=False,
         dist_toml=GOOD_DIST.replace('install-path = "~/.local/bin"',
                                     'install-path = "/usr/local/bin"'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 7-8. The unit.
    # 7a. UAT-DX-002 at the config level: the private runtime on PATH. This is
    #     the one that would have shipped a brokerd anyone could launch by hand.
    case("the private runtime installed into bin/ fails", expect_pass=False,
         dist_toml=GOOD_DIST,
         unit=GOOD_UNIT.replace(
             "%h/.local/libexec/asv/asv-brokerd", "%h/.local/bin/asv-brokerd"),
         crates=DEFAULT_CRATES)
    case("a unit pointing at an unrelated directory fails", expect_pass=False,
         dist_toml=GOOD_DIST,
         unit=GOOD_UNIT.replace("%h/.local/libexec/asv/", "%h/opt/asv/"),
         crates=DEFAULT_CRATES)
    case("a unit with no ExecStart fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit="[Unit]\nDescription=x\n", crates=DEFAULT_CRATES)
    case("a unit using a literal home path fails", expect_pass=False,
         dist_toml=GOOD_DIST,
         unit=GOOD_UNIT.replace("ExecStart=%h/.local/libexec/asv/",
                                "ExecStart=/home/someone/.local/libexec/asv/"),
         crates=DEFAULT_CRATES)

    # 9. The false positive this guard actually had. `%h` and `~` are the same
    #    directory in systemd's and the shell's spelling respectively. This case
    #    asserts there is NO failure, which is the part a guard suite normally
    #    omits and the part that keeps a guard switched on.
    case("`~` in the unit and `%h` in the config is not a disagreement", expect_pass=True,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES)
    case("a trailing slash on install-path is not a disagreement", expect_pass=True,
         dist_toml=GOOD_DIST.replace('install-path = "~/.local/bin"',
                                     'install-path = "~/.local/bin/"'),
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 10. The component sets, which is the DX0 property.
    case("a binary in the workspace that nobody classified fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT,
         crates={**DEFAULT_CRATES, "ebpfd": crate_with_bin("asv-ebpfd", "asv-ebpfd")})
    # A shipped component whose crate is not in the workspace: the boundary
    # points at a build that cannot happen.
    case("a shipped component whose crate is absent fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT,
         crates={"cli": crate_with_bin("asv", "asv-cli"),
                 "vault": crate_with_bin("asv-vault-tool", "asv-vault")})

    # 10a. THE DX0 defect, stated directly: dist packaging a binary the manifest
    #      forbids. This is the exact shape of the original bug.
    case("dist packaging the forbidden harness binary fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_package=DIST_PACKAGE.replace(
             'binaries = ["asv", "asv-brokerd"]',
             'binaries = ["asv", "asv-brokerd", "asv-vault-tool"]'))

    # 10b. The version drift that a second literal invites.
    case("a dist package version that disagrees with Cargo.toml fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_package=DIST_PACKAGE.replace('version = "0.26.0"', 'version = "0.25.0"'))
    case("a dist package that names no binaries fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_package=DIST_PACKAGE.replace(
             'binaries = ["asv", "asv-brokerd"]', "binaries = []"))
    case("no packaging/dist.toml fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_package=None)

    # 10c. A manifest that contradicts itself.
    case("a component both shipped and forbidden fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_manifest=DIST_MANIFEST.replace(
             "name = \"asv-vault-tool\"\nclass = \"test-harness\"\ncrate = \"asv-vault\"\nshipped = false",
             "name = \"asv-vault-tool\"\nclass = \"test-harness\"\ncrate = \"asv-vault\"\nshipped = true"))

    # 10d. The product boundary missing entirely.
    case("no distribution/manifest.toml fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         dist_manifest=None)

    # 11. Absence of configuration entirely — the state this repository was in.
    case("no dist-workspace.toml at all fails", expect_pass=False,
         unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    # 12. One repository, two spellings.
    #
    # `scripts/install.sh` fetches `install.py` from a URL of its own when it is
    # piped, and `install.py` downloads releases from another. They agree today
    # and nothing held them there: the wrapper did not have a URL until the piped
    # install path was repaired, and the moment it got one the repository had two
    # sources of truth for where it lives.
    #
    # The failure this catches is silent on purpose. A wrapper that fetches an
    # installer from one project while that installer installs from another does
    # not crash; it works, for everybody, right up until somebody renames or
    # forks and fixes the URL that visibly breaks.
    case("the wrapper fetching install.py from another repository fails",
         expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         install_sh=GOOD_INSTALL_SH.replace(
             "raw.githubusercontent.com/Rubentxu/agent-secretless",
             "raw.githubusercontent.com/someone-else/agent-secretless"))
    case("a wrapper that names no RAW_BASE fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         install_sh=GOOD_INSTALL_SH.replace('RAW_BASE="https://raw', "# RAW_BASE=https://raw"))
    case("an installer that names no DEFAULT_BASE_URL fails", expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         install_py="# nothing to compare the wrapper against\n")
    case("a RAW_BASE that is not a raw.githubusercontent location fails",
         expect_pass=False,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES,
         install_sh=GOOD_INSTALL_SH.replace(
             "https://raw.githubusercontent.com/Rubentxu/agent-secretless",
             "https://example.invalid/agent-secretless"))
    # The positive control for this rule specifically, not just "a correct
    # configuration passes" somewhere above: two spellings of one repository have
    # to be accepted, or the guard is only ever able to say no.
    case("two spellings of one repository agree", expect_pass=True,
         dist_toml=GOOD_DIST, unit=GOOD_UNIT, crates=DEFAULT_CRATES)

    print(f"\n{PASS}/{PASS + FAIL} behaviours confirmed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
