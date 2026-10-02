#!/usr/bin/env python3
"""Check that the release configuration still describes what actually ships.

`scripts/ci-policy.sh` already fails the run if a workflow appears under
`.github/workflows`. That guard is necessary and it is not sufficient: dist
does not write a workflow the moment someone adds `ci = ["github"]` to
`dist-workspace.toml`, it writes one the next time anybody runs `dist init` or
`dist generate`. Between those two moments the repository carries a config that
is one command away from reintroducing the thing the policy prohibits, and no
gate in the pipeline can see it. This file is that gate.

The second thing this checks is the one that actually bit: the systemd unit
pointed at `~/.local/libexec/asv/asv-brokerd` while the release installer put
binaries in `~/.local/bin`. Both files were correct in isolation, the install
would have succeeded, and the service would have failed to start on every
machine except the one where the daemon had been built by hand. A guard that
compares the two is worth more than either file's own tests.

Every check here states an invariant that could plausibly be violated by an
ordinary, well-intentioned edit — adding a platform, adding an installer,
adding a binary. None of them is a style opinion.

Run: python3 scripts/check-release-config.py
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIST_CONFIG_NAME = "dist-workspace.toml"
UNIT_NAME = "packaging/asv-brokerd.service"
# The product is Linux-only, and not by preference. The CLI does not compile
# off Unix at all — `crates/cli/src/main.rs` uses `std::os::unix::net::UnixStream`
# with no cfg gate — and the broker's entire security model (SO_PEERCRED,
# Landlock, seccomp, PR_SET_DUMPABLE) is Linux. A build for another platform
# would either fail to compile or, worse, compile and then be unable to
# enforce the properties the README claims for it.
ALLOWED_TARGET_PREFIXES = ("x86_64-unknown-linux-", "aarch64-unknown-linux-")

# `shell` only. `homebrew` and `npm` were evaluated and dropped: both need a
# second repository and its own release automation, neither has a user yet,
# and a Homebrew formula for a 0.x that has never been installed on a real
# machine is a support surface with no demand behind it. Adding one back is a
# deliberate edit here, which is the point.
ALLOWED_INSTALLERS = {"shell"}

MANIFEST = REPO / "distribution" / "manifest.toml"
DIST_PACKAGE = REPO / "packaging" / "dist.toml"

# Resolved from a root that may be overridden on the command line, so the
# falsification suite can point the same guard at a deliberately broken tree
# instead of a second copy of its rules.
#
# Everything the guard reads is derived from this one root, and `--root`
# replaces all of it. An earlier version of this file overrode only the config
# and the unit and left the binary scan pointing at the real repository, so
# three of the cases in tests/release_config_drift.py passed against the
# checkout instead of against the tree they built. The suite found it; that is
# what it is for.
ROOT = REPO
DIST_CONFIG = UNIT = None  # type: ignore[assignment]

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def load_dist() -> dict:
    assert DIST_CONFIG is not None
    if not DIST_CONFIG.exists():
        fail(
            f"{DIST_CONFIG_NAME} does not exist. Without it there is no "
            f"release configuration at all, which is the state this repository was in "
            f"until {DIST_CONFIG_NAME} was added."
        )
        return {}
    with DIST_CONFIG.open("rb") as handle:
        return tomllib.load(handle).get("dist", {})


def check_no_ci_backend(dist: dict) -> None:
    """The ci key is the one that would reintroduce GitHub Actions.

    dist calls it `ci`, and it is what generates `.github/workflows/release.yml`.
    This repository runs on PipelineK locally, by policy, and `ci-policy.sh`
    enforces the absence of the *file*. This check enforces the absence of the
    *cause*, which is the half of the problem that produces no failing test.
    """
    if "ci" in dist:
        fail(
            f"dist-workspace.toml declares `ci = {dist['ci']!r}`. That is the setting "
            f"that makes dist generate a release workflow, and this repository runs its "
            f"gates through PipelineK on the developer's machine. If a release train ever "
            f"needs a remote trigger, that is a change to docs/ci-policy.md made "
            f"deliberately — not a line added here by a `dist init`."
        )


def check_targets_are_linux(dist: dict) -> None:
    targets = dist.get("targets")
    if not targets:
        fail(
            "dist-workspace.toml declares no targets. An empty target list produces a "
            "release with no binaries in it, and `dist build` reports success."
        )
        return
    for target in targets:
        if not target.startswith(ALLOWED_TARGET_PREFIXES):
            fail(
                f"target {target!r} is not a Linux target. The CLI uses "
                f"std::os::unix::net::UnixStream without a cfg gate, so it does not "
                f"compile there, and the broker's Landlock/seccomp/SO_PEERCRED model is "
                f"Linux-only. A build for this target would be either a compile error or "
                f"a binary that cannot enforce what the README says it enforces."
            )


def check_installers(dist: dict) -> None:
    installers = dist.get("installers", [])
    if not installers:
        fail("dist-workspace.toml enables no installers, so a release ships no way to install.")
    for installer in installers:
        if installer not in ALLOWED_INSTALLERS:
            fail(
                f"installer {installer!r} is not enabled by policy. Allowed: "
                f"{sorted(ALLOWED_INSTALLERS)}. Homebrew and npm each need a second "
                f"repository and their own release automation; neither has a user yet."
            )


def check_install_path_is_user_writable(dist: dict) -> None:
    path = dist.get("install-path")
    if not path:
        fail("dist-workspace.toml sets no install-path.")
        return
    if not path.startswith("~"):
        fail(
            f"install-path is {path!r}, which is not under the user's home. A "
            f"system-wide install needs root, and a credential broker installed as root "
            f"is a different — and much larger — privilege story than the one this "
            f"project has tested. The broker runs as you, deliberately; M7, a dedicated "
            f"uid, does not exist yet."
        )


def known_packages() -> set[str]:
    """Every `name` a crate in the workspace declares.

    Package names, not directory names. `cargo build -p asv-cli` is what the
    build command runs, and `crates/cli` is what it lives in; the two differ,
    and a check that conflates them is wrong in both directions.
    """
    names: set[str] = set()
    for manifest_path in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        with manifest_path.open("rb") as handle:
            package = tomllib.load(handle).get("package", {})
        if "name" in package:
            names.add(package["name"])
    return names


def distribution_manifest() -> dict:
    """`distribution/manifest.toml`, the product boundary.

    Read here rather than restated as constants, which is the whole point of
    FR-001: a guard that carries its own copy of the expected component set is a
    second source of truth, and two sources of truth are one disagreement away
    from a release that ships a binary nobody declared.
    """
    path = ROOT / "distribution" / "manifest.toml"
    if not path.exists():
        fail(
            "distribution/manifest.toml does not exist. The product boundary has to be "
            "declared somewhere; the release pipeline must not infer it from whatever "
            "Cargo produces."
        )
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def workspace_binaries() -> set[str]:
    """Every `[[bin]]` name in the cargo workspace members.

    Read from the manifests rather than from `dist plan`, so the check has no
    dependency on dist being installed and cannot be satisfied by a tool that
    quietly decides to skip something.
    """
    found: set[str] = set()
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        with manifest.open("rb") as handle:
            package = tomllib.load(handle)
        for binary in package.get("bin", []):
            if "name" in binary:
                found.add(binary["name"])
    return found


def check_component_sets(manifest: dict) -> None:
    """The manifest, the dist package and the workspace must agree.

    Three places name a component, which is one more than is comfortable. The
    manifest decides, `packaging/dist.toml` tells dist what to package, and the
    workspace is what actually exists. The invariant is not that they are equal
    — `asv-vault-tool` is in the workspace and deliberately not shipped — but
    that the shipped set is exactly the manifest's shipped set, and that
    nothing in the workspace is a binary nobody has classified.
    """
    shipped = {c["name"] for c in manifest.get("component", []) if c.get("shipped")}
    classified = {c["name"] for c in manifest.get("component", [])}

    if not shipped:
        fail("distribution/manifest.toml declares no shipped components")
        return

    # 1. The dist package lists exactly the shipped components.
    package_path = ROOT / "packaging" / "dist.toml"
    if not package_path.exists():
        fail("packaging/dist.toml does not exist; nothing tells dist what to package")
    else:
        with package_path.open("rb") as handle:
            package = tomllib.load(handle)
        dist_binaries = set(package.get("package", {}).get("binaries", []))
        if dist_binaries != shipped:
            detail = []
            if dist_binaries - shipped:
                detail.append(
                    f"dist would package {sorted(dist_binaries - shipped)}, which the "
                    f"manifest does not ship. This is the asv-vault-tool defect."
                )
            if shipped - dist_binaries:
                detail.append(
                    f"the manifest ships {sorted(shipped - dist_binaries)} but dist "
                    f"would not package it"
                )
            fail("packaging/dist.toml disagrees with the manifest — " + "; ".join(detail))

    # 2. Every workspace binary is classified by the manifest. A new [[bin]]
    #    that nobody has classified fails here rather than shipping.
    found = workspace_binaries()
    unclassified = found - classified
    if unclassified:
        fail(
            f"the workspace builds {sorted(unclassified)}, which "
            f"distribution/manifest.toml does not classify. Every binary needs a class: "
            f"shipped or not. A new [[bin]] that nobody decided about is how "
            f"asv-vault-tool would have shipped."
        )

    # 3. Every shipped component's crate exists. The manifest says the build
    #    asks it what to compile, so a crate it names that is not in the
    #    workspace is a boundary that points at nothing. The build would fail
    #    too, but minutes later and with a cargo error; this says it in a
    #    second and names the mismatch.
    for component in manifest.get("component", []):
        if not component.get("shipped"):
            continue
        crate = component.get("crate")
        if not crate:
            continue
        # Matched by the package NAME a crate declares, not by its directory.
        # The manifest says `crate = "asv-cli"` because that is what the build
        # command passes to `cargo build -p`, and the directory is `crates/cli`.
        # Looking for `crates/asv-cli/` was a real failure of this check: it
        # rejected a correct tree and would have accepted a directory that
        # happened to share a name with a package.
        if crate not in known_packages():
            fail(
                f"the manifest ships {component['name']!r} from crate {crate!r}, but "
                f"crates/{crate} does not exist. Either the crate moved or the manifest "
                f"names a component that was never built."
            )

    # 4. A forbidden component is never also shipped. The manifest could say so
    #    and nothing else here would notice.
    for component in manifest.get("component", []):
        if component.get("forbidden_in_production") and component.get("shipped"):
            fail(
                f"{component['name']!r} is both forbidden_in_production and shipped. The "
                f"manifest contradicts itself, and every consumer of it would have to "
                f"pick a side."
            )

    # 5. The version in the dist package is the workspace version. dist requires
    #    a literal, so this is a second copy that has to be watched.
    with (ROOT / "Cargo.toml").open("rb") as handle:
        workspace_version = tomllib.load(handle).get("workspace", {}).get("package", {}).get("version")
    if package_path.exists():
        with package_path.open("rb") as handle:
            package_version = tomllib.load(handle).get("package", {}).get("version")
        if workspace_version and package_version != workspace_version:
            fail(
                f"packaging/dist.toml says version {package_version!r} while the workspace "
                f"Cargo.toml says {workspace_version!r}. dist names every artifact from "
                f"the package version, so a release built here would upload artifacts "
                f"tagged with a version the binaries do not carry."
            )


def normalise_home(path: str) -> str:
    """Reduce the two spellings of a home directory to one.

    The unit file uses systemd's `%h` specifier and the dist config uses a
    shell `~`. They are the same directory, and comparing them literally makes
    this guard report a failure for a configuration that is correct — which is
    how a guard gets switched off. Written once, here, so the two spellings
    cannot be compared raw anywhere else either.
    """
    return path.replace("%h", "~").rstrip("/")


def check_unit_agrees_with_manifest(manifest: dict, dist: dict) -> None:
    """The unit must run the private runtime from where the manifest installs it.

    This check was wrong for a while and the falsification suite is what found
    it. It compared the unit's ExecStart against dist's `install-path`, which
    is the directory the *public CLI* goes into — and those are different
    components with different rules. So a unit running
    `~/.local/bin/asv-brokerd` was accepted: the string matched `install-path`,
    the check passed, and the broker would have been on PATH, which is exactly
    what UAT-DX-002 forbids and exactly what `asv-vault-tool`-style thinking
    produces — inferring a location from a neighbouring component instead of
    reading the one that declares it.

    The expected path is therefore composed from the manifest: the private
    component's `install_as`, under the user layout's `libexec`, under the
    user root. Nothing here is a literal, so moving the layout in the manifest
    moves the expectation with it.
    """
    if not UNIT.exists():
        fail(f"{UNIT_NAME} does not exist; there is no unit to install.")
        return

    layout = manifest.get("layout", {}).get("user", {})
    libexec = layout.get("libexec")
    if not libexec:
        fail(
            "distribution/manifest.toml has no [layout.user] libexec. The private "
            "runtime's location comes from the manifest, and without it the unit has "
            "nothing to be checked against."
        )
        return

    private = [
        c
        for c in manifest.get("component", [])
        if c.get("class") == "required-private" and c.get("shipped")
    ]
    if len(private) != 1:
        fail(
            f"expected exactly one shipped required-private component, found "
            f"{[c.get('name') for c in private]}. The unit runs the private runtime, so "
            f"there has to be exactly one to point at."
        )
        return

    private_name = private[0]["name"]
    expected = f"{layout.get('root', '~')}/{libexec}/{private_name}"
    text = UNIT.read_text()
    match = re.search(r"^ExecStart=(\S+)", text, re.MULTILINE)
    if not match:
        fail(f"{UNIT_NAME} has no ExecStart line.")
        return
    actual = match.group(1)

    if not actual.startswith("%h/"):
        fail(
            f"ExecStart starts with {actual!r} rather than %h. The unit has to resolve "
            f"the same home directory the installer wrote to."
        )
        return

    if normalise_home(actual) != normalise_home(expected):
        fail(
            f"the unit runs {actual!r} but the manifest installs the private runtime at "
            f"{expected!r} (component {private_name!r}, class required-private). An "
            f"install that completes and a service that will not start is the failure "
            f"this compares."
        )

    # And the property UAT-DX-002 exists to assert, stated directly rather than
    # only implied by the path: the private runtime is not under the directory
    # the public CLI occupies.
    bin_dir = f"{layout.get('root', '~')}/{layout.get('bin', 'bin')}"
    if normalise_home(actual).startswith(normalise_home(bin_dir) + "/"):
        fail(
            f"the unit runs the private runtime from {actual!r}, which is on the same "
            f"PATH directory as the public CLI ({bin_dir}). asv-brokerd is the "
            f"secret-bearing process; it must not be launchable by name."
        )

    # The public CLI's location is a separate question, answered by dist.
    install_path = dist.get("install-path", "")
    if not install_path:
        fail("dist-workspace.toml sets no install-path.")
    elif normalise_home(install_path) != normalise_home(
        f"{layout.get('root', '~')}/{layout.get('bin', 'bin')}"
    ):
        fail(
            f"dist installs binaries under {install_path!r} but the manifest says the "
            f"public CLI goes in {bin_dir!r}. The archive is flat, so this is the only "
            f"thing tying dist's install directory to the declared layout."
        )


def main(argv: list[str] | None = None) -> int:
    global DIST_CONFIG, UNIT, ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO,
        help="repository root to check; the falsification suite points this at a "
             "deliberately broken copy so the same rules are exercised, not restated",
    )
    args = parser.parse_args(argv)
    ROOT = args.root
    DIST_CONFIG = ROOT / DIST_CONFIG_NAME
    UNIT = ROOT / UNIT_NAME

    dist = load_dist()
    if dist:
        check_no_ci_backend(dist)
        check_targets_are_linux(dist)
        check_installers(dist)
        check_install_path_is_user_writable(dist)
        check_unit_agrees_with_manifest(distribution_manifest(), dist)
    check_component_sets(distribution_manifest())

    if failures:
        print("release config check FAILED:", file=sys.stderr)
        for problem in failures:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    shipped = sorted(
        c["name"]
        for c in distribution_manifest().get("component", [])
        if c.get("shipped")
    )
    print(
        "release config ok: "
        f"ships {shipped}, targets {dist.get('targets')}, "
        f"installers {dist.get('installers')}, no CI backend"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
