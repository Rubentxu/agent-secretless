#!/usr/bin/env python3
"""UAT-DX-002 (runtime half) and the DX1 install-path contract.

`tests/distribution_bundle.py` proves the *bundle* contains `asv` and
`asv-brokerd` and not `asv-vault-tool`. It looks at an archive.

It cannot see this: a script that tells a user to run `asv-vault-tool create`
when the tool is not in the archive. Those instructions are unfollowable, and
nothing in the repository contradicts them — the manifest, the gate and the
archive are all correct, and the user is still stuck at step one of three.

`scripts/install-broker-service.sh` said exactly that until DX1. The unit was
right, the bundle was right, and the printed instructions named a binary the
product does not ship.

So this suite reads `distribution/manifest.toml` and asks a different
question: does anything a user is told to run name a component the manifest
excludes from the product?

The tests are deliberately about *strings a user would type*, not about
whether the binaries exist on this machine. The failure mode is a
documentation defect and the check has to be able to see it.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "distribution" / "manifest.toml"

# Every file whose contents a user may be told to follow. Not every script:
# a test helper that names a forbidden binary is doing its job.
USER_FACING = [
    "scripts/install-broker-service.sh",
    "scripts/publish-release.sh",
    "packaging/asv-brokerd.service",
]

_failures: list[str] = []
_passes = 0


def check(condition: bool, message: str) -> None:
    global _passes
    if condition:
        _passes += 1
    else:
        _failures.append(message)


def load_manifest() -> dict:
    with MANIFEST.open("rb") as handle:
        return tomllib.load(handle)


def forbidden_components(manifest: dict) -> dict[str, str]:
    """Name -> class, for every component the product excludes."""
    out: dict[str, str] = {}
    for component in manifest.get("component", []):
        if not component.get("shipped", False):
            out[component["name"]] = component.get("class", "unknown")
        if component.get("forbidden_in_production", False):
            out[component["name"]] = component["class"]
    return out


def test_no_user_facing_file_names_a_component_the_manifest_excludes():
    """The DX1 defect itself.

    A user-facing file that names a non-shipped component as something to run
    is a broken installation path. The check is over the whole file, not over
    a code block, because the sentences that mislead are the prose ones.
    """
    manifest = load_manifest()
    forbidden = forbidden_components(manifest)
    check(bool(forbidden), "the manifest excludes nothing; the test is vacuous")

    for relative in USER_FACING:
        path = REPO / relative
        if not path.exists():
            _failures.append(f"{relative} does not exist")
            continue
        text = path.read_text(encoding="utf-8")
        for name, klass in forbidden.items():
            # A mention is only a defect when it reads as an instruction.
            # Prose that explains *why* the tool is not used is allowed, and
            # this file legitimately names the tool to say it is not there.
            for line_number, line in enumerate(text.splitlines(), start=1):
                if name not in line:
                    continue
                instruction = re.search(
                    rf"(^|[\s`$(\{{]){re.escape(name)}\s+(create|list|probe|init|add|remove|run|serve)",
                    line,
                )
                explains = any(
                    token in line
                    for token in (
                        "used to print",
                        "is not in the bundle",
                        "not shipped",
                        "test-harness",
                        "classif",
                    )
                )
                # The property is the *absence* of a runnable instruction, so
                # the check passes when there is no instruction OR the line is
                # explaining itself. Written the other way round — which is
                # how it was first written — this suite failed on the very
                # sentence added to explain that the tool is no longer used,
                # which is the fastest way to teach a maintainer to delete the
                # guard.
                check(
                    instruction is None or explains,
                    f"{relative}:{line_number} tells the user to run "
                    f"`{name}` ({klass}), which the manifest excludes: {line.strip()!r}",
                )


def test_the_unit_executes_only_shipped_components():
    """`ExecStart` names a binary the bundle actually contains.

    The unit is the one place where a wrong name becomes a service that fails
    at boot with a path error, which reads as a broken product.
    """
    manifest = load_manifest()
    shipped = {c["name"] for c in manifest.get("component", []) if c.get("shipped")}
    unit = (REPO / "packaging" / "asv-brokerd.service").read_text(encoding="utf-8")

    exec_start = next(
        (line for line in unit.splitlines() if line.startswith("ExecStart=")), None
    )
    check(exec_start is not None, "the unit has no ExecStart")
    if exec_start is None:
        return

    named = [n for n in shipped if n in exec_start]
    check(
        bool(named),
        f"ExecStart names no shipped component; shipped={sorted(shipped)}: {exec_start}",
    )
    check(
        "asv-brokerd" in exec_start,
        f"ExecStart does not start the private broker: {exec_start}",
    )
    # The private runtime, not the directory on PATH. DX0's finding, restated
    # against the file that actually runs.
    check(
        "/libexec/" in exec_start,
        f"ExecStart is not in the private runtime directory: {exec_start}",
    )
    check(
        "%h/.local/bin" not in exec_start,
        f"ExecStart points into the directory on PATH: {exec_start}",
    )


def test_the_installer_defers_to_asv_setup_for_the_vault():
    """`asv setup` owns the vault, per implementation guide §7.

    The split is deliberate: the installer places files, `setup` creates the
    runtime layout and the service. An installer that also creates a vault has
    two places where a passphrase can be written, and the one that is not
    `setup` is the one with no idempotence tests.
    """
    installer = (REPO / "scripts" / "install-broker-service.sh").read_text(encoding="utf-8")
    check(
        "asv setup" in installer,
        "the installer never points the user at `asv setup`",
    )
    check(
        "--passphrase" not in installer,
        "the installer still handles a passphrase itself, which is the job "
        "`asv setup` does and the reason the unit takes a passphrase file",
    )
    check(
        "enable --now" not in installer,
        "the installer starts the service; `asv setup` does, and a service "
        "started before the vault exists fails in a way that reads as a "
        "broken install",
    )


def test_the_vault_is_only_ever_created_by_setup():
    """One writer for the vault.

    A second writer is a second set of permissions, a second passphrase
    format, and a second idempotence argument — none of which are tested.
    """
    setup = (REPO / "crates" / "cli" / "src" / "setup.rs").read_text(encoding="utf-8")
    check(
        "create_empty_vault" in setup,
        "asv setup no longer creates a vault; the install path is incomplete",
    )

    manifest = load_manifest()
    forbidden = forbidden_components(manifest)
    for name in forbidden:
        # The CLI must not shell out to a tool the product excludes.
        check(
            f"Command::new(\"{name}\")" not in setup,
            f"asv setup invokes `{name}` by name; the manifest classifies it "
            f"as {forbidden[name]}",
        )


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        try:
            test()
        except Exception as error:  # noqa: BLE001 - reported, not swallowed
            _failures.append(f"{test.__name__} raised {error!r}")

    print(f"\n{_passes} checks passed, {len(_failures)} failed\n")
    for failure in _failures:
        print(f"FAIL  {failure}")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
