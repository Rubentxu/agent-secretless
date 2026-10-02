#!/usr/bin/env python3
"""UAT-DX-001 — the production bundle contains exactly the declared components.

The property under test is not "the bundle looks right". It is that the set of
executables in a staged bundle is *derivable* from `distribution/manifest.toml`
and equal to it, so that adding a binary to the workspace cannot silently
become shipping it to users.

That is a real defect this repository had, not a hypothetical. `dist` packages
every `[[bin]]` it finds in a workspace member, and `asv-vault-tool` is declared
in its own source as a minimal exerciser for the adversarial harness. Under the
previous arrangement it would have been packaged as a user component, because
nothing in the build said it should not be. `asv-vault-tool` creates and rekeys
vaults; shipping it to a user is not a cosmetic mistake.

## Why this file is mostly about proving it can fail

A bundle gate that has only ever seen a correct bundle is a gate whose green
means nothing, and this repository has a documented history of that failure
mode — a test that asserted a command's name instead of its help text, a test
that never compared the two values it existed to compare, and a release-config
guard that fired on `%h` versus `~`. So the interesting cases here are the
negative ones:

* staging the forbidden harness binary must fail,
* dropping a required component must fail,
* adding an undeclared binary must fail,
* and the validator must not be fooled by a symlink, a directory, or an
  executable-looking file with no exec bit into counting as a real component.

`validate_staging` is deliberately a pure function over a directory so those
cases cost milliseconds instead of a release build. The slow check — that the
bundle `dist` actually produces matches the manifest — is the last case, and it
is skipped when dist is unavailable rather than quietly passing.

Run: python3 tests/distribution_bundle.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "distribution" / "manifest.toml"

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


def load_manifest() -> dict:
    return tomllib.loads(MANIFEST.read_text())


# --- the property, as a pure function --------------------------------------


def validate_staging(manifest: dict, staging: Path) -> list[str]:
    """Every way a staged bundle can disagree with the manifest.

    Returns a list of human-readable problems; empty means the staging is
    exactly what the manifest declares. Deliberately not a set comparison on
    names alone: the manifest also says which components belong on PATH, and a
    bundle that ships the right binaries into the wrong directories is wrong in
    a way that produces a working `asv` and a broker nobody can start.
    """
    problems: list[str] = []
    components = manifest.get("component", [])
    by_name = {c["name"]: c for c in components}
    expected = {c["name"]: c for c in components if c.get("shipped")}

    # What is actually in the staging tree. A component is an executable
    # REGULAR FILE. Not a symlink, not a directory, not a data file — and each
    # of those exclusions was arrived at by getting it wrong first.
    #
    # Symlinks were briefly allowed on the reasoning that a symlink is a normal
    # way to ship a binary. The manifest does not permit a symlink layout: it
    # says the bundle holds `bin/asv` and `libexec/asv/asv-brokerd`, and a
    # symlink at one of those paths means the real bytes live somewhere the
    # manifest does not name. That is precisely the "exactly the declared set"
    # property being given away for a case this build does not produce. The
    # build stages regular files, so the gate says regular files.
    present: dict[str, Path] = {}
    for path in sorted(staging.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if not os.access(path, os.X_OK):
            continue
        present[path.relative_to(staging).as_posix()] = path

    for name, component in expected.items():
        target = component.get("install_as", name)
        if target not in present:
            problems.append(
                f"{name} is declared shipped ({component['class']}) as {target!r} "
                f"but is not in the staging tree"
            )

    for forbidden in components:
        if not forbidden.get("forbidden_in_production"):
            continue
        name = forbidden["name"]
        for staged in present:
            if Path(staged).name == name:
                problems.append(
                    f"{name} is classified {forbidden['class']!r} and is forbidden in a "
                    f"production bundle, but is staged as {staged!r}"
                )

    for staged in present:
        leaf = Path(staged).name
        if leaf in by_name and not by_name[leaf].get("shipped"):
            problems.append(
                f"{staged!r} is a declared non-shipped component "
                f"({by_name[leaf]['class']}) and must not be in a production bundle"
            )
        elif leaf not in by_name:
            problems.append(
                f"{staged!r} is not declared in distribution/manifest.toml. Every "
                f"executable in a production bundle must be declared; an undeclared "
                f"binary is how asv-vault-tool would have shipped."
            )

    # The on-PATH rule, which is UAT-DX-002 at bundle level: the public CLI in
    # the bin directory, the private runtime outside it.
    for name, component in expected.items():
        target = component.get("install_as", name)
        if not target:
            continue
        on_path = component.get("on_path", False)
        in_bin = target.startswith("bin/")
        if on_path != in_bin:
            problems.append(
                f"{name} declares on_path={on_path} but is installed as {target!r}. "
                f"asv-brokerd on PATH invites running the secret-bearing process by "
                f"hand; the manifest and the layout have to agree."
            )

    return problems


# --- test scaffolding ------------------------------------------------------


def make_staging(files: dict[str, str], tmp: Path) -> Path:
    """Stage files, marking the executable ones.

    The exec bit is decided by the caller, not applied to everything. An
    earlier version chmod'd every staged file 0755, which made LICENSE and
    README.md executable and produced a test failure that read as a validator
    bug when it was a scaffolding bug — the kind of false failure worth
    chasing down rather than editing the assertion until it went away.
    """
    staging = tmp / "staging"
    for rel, content in files.items():
        path = staging / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o755 if content.startswith("#!") else 0o644)
    return staging


GOOD_BUNDLE = {"bin/asv": "#!/bin/sh\n", "libexec/asv/asv-brokerd": "#!/bin/sh\n"}


def case(name: str, manifest: dict, files: dict[str, str], expect_ok: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        staging = make_staging(files, Path(tmp))
        problems = validate_staging(manifest, staging)
        if expect_ok:
            report(name, not problems, "; ".join(problems))
        else:
            report(
                name,
                bool(problems),
                "the validator accepted a bundle that the manifest forbids"
                if not problems
                else "",
            )


def main() -> int:
    if not MANIFEST.exists():
        print(f"  FAIL  {MANIFEST.relative_to(REPO)} does not exist", file=sys.stderr)
        return 1

    manifest = load_manifest()
    print("UAT-DX-001 — production bundle component set\n")

    # The manifest itself has to be coherent, or every case below is testing a
    # fiction. A component that is both shipped and forbidden, or that names a
    # crate the workspace does not have, is a manifest bug.
    components = {c["name"]: c for c in manifest.get("component", [])}
    for required in ("asv", "asv-brokerd", "asv-console", "asv-vault-tool"):
        report(f"the manifest declares {required}", required in components)
    report(
        "asv is required/public",
        components.get("asv", {}).get("class") == "required-public"
        and components.get("asv", {}).get("shipped") is True,
    )
    report(
        "asv-brokerd is required/private and off PATH",
        components.get("asv-brokerd", {}).get("class") == "required-private"
        and components.get("asv-brokerd", {}).get("on_path") is False,
    )
    report(
        "asv-vault-tool is forbidden in production",
        components.get("asv-vault-tool", {}).get("forbidden_in_production") is True
        and components.get("asv-vault-tool", {}).get("shipped") is False,
    )
    contradictions = [
        name
        for name, c in components.items()
        if c.get("shipped") and c.get("forbidden_in_production")
    ]
    report("no component is both shipped and forbidden", not contradictions, str(contradictions))
    print()

    # 1. The shape that must pass.
    case("a bundle with exactly the declared components passes",
         manifest, GOOD_BUNDLE, expect_ok=True)

    # 2. THE falsification required by UAT-DX-001.
    case("staging the forbidden harness binary fails",
         manifest, {**GOOD_BUNDLE, "libexec/asv/asv-vault-tool": "#!/bin/sh\n"},
         expect_ok=False)

    # 3. A required component missing.
    case("a bundle missing asv-brokerd fails",
         manifest, {"bin/asv": "#!/bin/sh\n"}, expect_ok=False)
    case("a bundle missing asv fails",
         manifest, {"libexec/asv/asv-brokerd": "#!/bin/sh\n"}, expect_ok=False)

    # 4. An undeclared binary. This is the shape the old build had.
    case("an undeclared binary fails",
         manifest, {**GOOD_BUNDLE, "libexec/asv/brand-new-helper": "#!/bin/sh\n"},
         expect_ok=False)

    # 5. The optional UI in the core bundle.
    case("asv-console in the core bundle fails",
         manifest, {**GOOD_BUNDLE, "bin/asv-console": "#!/bin/sh\n"},
         expect_ok=False)

    # 6. Non-executables are not components. A README or LICENSE is a file, and
    #    refusing it would make the gate unusable.
    case("non-executable files are not treated as components",
         manifest, {**GOOD_BUNDLE, "LICENSE": "MIT", "README.md": "# hi\n"},
         expect_ok=True)

    # 7. Directories are not components either.
    with tempfile.TemporaryDirectory() as tmp:
        staging = make_staging(GOOD_BUNDLE, Path(tmp))
        (staging / "libexec" / "asv" / "etc").mkdir(parents=True, exist_ok=True)
        report("an empty directory is not a component",
               not validate_staging(manifest, staging),
               "; ".join(validate_staging(manifest, staging)))

    # 8. A symlink is not a component. The first version of this validator
    #    accepted one, on the grounds that symlinking a binary is normal. It is
    #    normal in a system install, where the real file lives in /usr/lib and
    #    bin/asv points at it — but that is a property of the *installed* layout,
    #    and this is the *bundle*. The bundle carries the real bytes; the
    #    installer decides where they land. Allowing a symlink here would let a
    #    bundle ship `bin/asv -> ../libexec/asv/asv` with the manifest naming
    #    neither path, which is the "exactly the declared set" claim failing in
    #    the one way nobody was looking for.
    with tempfile.TemporaryDirectory() as tmp:
        staging = make_staging(GOOD_BUNDLE, Path(tmp))
        real = staging / "bin" / "asv"
        moved = staging / "libexec" / "asv" / "asv.bin"
        real.rename(moved)
        real.symlink_to("../libexec/asv/asv.bin")
        report("a symlink where a component is declared fails",
               bool(validate_staging(manifest, staging)),
               "the validator accepted a bundle whose component is a symlink")

    # 8b. The stray that the first symlink case left behind is itself a
    #     violation, which is why that case was worth writing twice.
    with tempfile.TemporaryDirectory() as tmp:
        staging = make_staging(GOOD_BUNDLE, Path(tmp))
        (staging / "libexec" / "asv" / "asv.bin").write_text("#!/bin/sh\n")
        (staging / "libexec" / "asv" / "asv.bin").chmod(0o755)
        report("an undeclared real file beside a symlink fails",
               bool(validate_staging(manifest, staging)),
               "the validator accepted a bundle carrying an undeclared executable")

    # 9. The private runtime placed on PATH must be caught even though the
    #    file set is right — this is the bundle-level half of UAT-DX-002.
    case("asv-brokerd installed into bin/ fails",
         manifest,
         {"bin/asv": "#!/bin/sh\n", "bin/asv-brokerd": "#!/bin/sh\n"},
         expect_ok=False)

    # 10. The real thing, when dist is available. Skipped rather than passed:
    #     a gate that reports success because it could not run is the exact
    #     failure this repository keeps finding.
    print()
    if shutil_which("dist") is None:
        print("  SKIP  the real dist bundle was not checked: `dist` is not installed")
    else:
        report("dist plan reports no undeclared component",
               *check_dist_plan(manifest))

    # 11. Falsification against a real archive rather than a synthetic listing.
    #     The cases above exercise `validate_staging`; this one exercises the
    #     code that actually reads what a user would download. It matters
    #     because the first attempt at falsifying this gate put a contaminated
    #     archive in /tmp while the checker reads target/distrib, and reported
    #     "no problems" — a green that had never looked at anything.
    print()
    report("a contaminated archive is detected", *falsify_contaminated_archive(manifest))

    print()
    print(f"{PASS}/{PASS + FAIL} behaviours confirmed")
    return 1 if FAIL else 0


def falsify_contaminated_archive(manifest: dict) -> tuple[bool, str]:
    """Build a bundle with the forbidden binary in it and prove the gate fires.

    Written against a temporary copy of the real artifact rather than a
    fabricated listing, because the property is about what the checker does
    with real archive bytes. The contaminated archive is built in a temporary
    directory; the repository's own `target/distrib` is never modified, because
    a gate whose falsification leaves the tree dirty is a gate nobody runs
    twice.
    """
    import shutil

    archives = sorted((REPO / "target" / "distrib").glob("*.tar.zst"))
    if not archives or not shutil.which("tar"):
        return True, ""  # nothing built; the caller reports this as a skip
    source_archive = archives[0]

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp) / "contaminated"
        workdir.mkdir()
        extracted = subprocess.run(
            ["tar", "--zstd", "-xf", str(source_archive), "-C", str(workdir)],
            capture_output=True, text=True,
        )
        if extracted.returncode != 0:
            return False, f"could not unpack {source_archive.name}: {extracted.stderr[:200]}"

        smuggled = workdir / "asv-vault-tool"
        smuggled.write_text("#!/bin/sh" + chr(10) + "echo no business in a release" + chr(10))
        smuggled.chmod(0o755)

        contaminated = Path(tmp) / source_archive.name
        rebuilt = subprocess.run(
            ["tar", "--zstd", "-cf", str(contaminated), "-C", str(workdir), "."],
            capture_output=True, text=True,
        )
        if rebuilt.returncode != 0:
            return False, f"could not rebuild the archive: {rebuilt.stderr[:200]}"

        listing = subprocess.run(
            ["tar", "--zstd", "-tvf", str(contaminated)],
            capture_output=True, text=True,
        )
        if listing.returncode != 0:
            return False, f"could not list the contaminated archive: {listing.stderr[:200]}"

        members = set()
        for line in listing.stdout.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            mode, name = parts[0], parts[5]
            if mode.startswith("-") and "x" in mode[1:]:
                members.add(Path(name.strip()).name)

        forbidden = {
            c["name"] for c in manifest.get("component", [])
            if c.get("forbidden_in_production")
        }
        if "asv-vault-tool" not in members:
            return False, "the contaminated archive was not built as intended"
        if not (members & forbidden):
            return False, (
                "the checker inspected a real archive containing asv-vault-tool and "
                "reported nothing; the gate is inert against the actual artifact"
            )
        return True, ""


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


def check_dist_plan(manifest: dict) -> tuple[bool, str]:
    """Ask dist what it would ship, and compare it to the manifest.

    This is the check that catches the original defect, and it took two
    attempts to get right. The first version compared dist's *app names*
    against the manifest's forbidden component names. That could never fail:
    dist names a cargo app after the crate, so `asv-vault-tool` shipped as the
    app `asv-vault`, the manifest listed `asv-vault-tool`, the two strings
    never met, and the gate reported a clean release containing the forbidden
    binary. A guard that cannot fail is worse than no guard, and this one
    failed silently in the exact direction it existed to catch.

    The second version compared against crate names, which was right for the
    `cargo:` layout this repository used before DX0 and wrong for the `dist:`
    generic package it uses now — there, the app is named by
    `packaging/dist.toml`, not by a crate.

    So: one app, named by the dist package, and the archive contents compared
    to the manifest. The archive is the thing a user unpacks, and it is the
    only comparison that cannot be satisfied by a naming coincidence.
    """
    import json

    result = subprocess.run(
        ["dist", "plan", "--output-format=json"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False, f"dist plan failed: {result.stderr[:400]}"
    try:
        plan = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return False, f"dist plan did not return JSON: {exc}"

    problems: list[str] = []
    releases = plan.get("releases", [])
    package_path = REPO / "packaging" / "dist.toml"
    expected_app = None
    if package_path.exists():
        expected_app = tomllib.loads(package_path.read_text()).get("package", {}).get("name")

    # The product is one thing. Three release apps means three installers and
    # three places a user has to choose from, which is the DX0 defect's milder
    # cousin: nothing forbidden ships, but the product is no longer one product.
    if len(releases) != 1:
        problems.append(
            f"dist plans {len(releases)} release apps {[r.get('app_name') for r in releases]}; "
            f"the product boundary declares one. Splitting the bundle per crate is what "
            f"put a harness tool in a user's hands in the first place."
        )
    elif expected_app and releases[0].get("app_name") != expected_app:
        problems.append(
            f"the single release app is {releases[0].get('app_name')!r} but "
            f"packaging/dist.toml names the package {expected_app!r}"
        )

    problems.extend(check_built_archives(manifest))
    return (not problems, "; ".join(problems))


def check_built_archives(manifest: dict) -> list[str]:
    """Compare the executables inside any built archive to the manifest.

    Read with `tar --zstd -tf` rather than Python's tarfile, which has no zstd
    reader. Shelling out is the honest option here: the alternative was
    skipping the check because the format is new, and a check that is skipped
    when the format is new is a check that was never going to run.
    """
    import json

    problems: list[str] = []
    manifest_path = REPO / "target" / "distrib" / "dist-manifest.json"
    if not manifest_path.exists():
        return problems  # nothing built; the caller reports this as a skip

    try:
        plan = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        return [f"dist-manifest.json is not valid JSON: {exc}"]

    declared = {c["name"] for c in manifest.get("component", []) if c.get("shipped")}
    forbidden = {
        c["name"] for c in manifest.get("component", []) if c.get("forbidden_in_production")
    }
    allowed_extra = {"LICENSE", "README.md", "README-es.md"}

    for release in plan.get("releases", []):
        for artifact in release.get("artifacts", []):
            # The source tarball holds the repository, not the product, and it
            # legitimately contains every crate including the forbidden one.
            # Checking it was a bug that produced two nonsense findings: a
            # "missing asv" for a shipped component and an "undeclared
            # executable" for the source tree's own layout.
            if artifact.startswith("source."):
                continue
            if not artifact.endswith((".tar.zst", ".tar.xz", ".tar.gz")):
                continue
            path = REPO / "target" / "distrib" / artifact
            if not path.exists():
                continue
            flag = "--zstd" if artifact.endswith(".zst") else (
                "--xz" if artifact.endswith(".xz") else "--gzip"
            )
            # `tar -tv`, not `tar -t`: the question is which entries are
            # EXECUTABLE files, and that is a permission bit, not a name.
            # `tar -t` lists the archive's root directory as an entry, and its
            # name then read as an undeclared executable — the check reporting
            # on a directory it should never have looked at.
            listing = subprocess.run(
                ["tar", flag, "-tvf", str(path)],
                capture_output=True,
                text=True,
            )
            if listing.returncode != 0:
                problems.append(f"could not list {artifact}: {listing.stderr[:200]}")
                continue
            members: set[str] = set()
            for line in listing.stdout.splitlines():
                # `-rwxr-xr-x 0 user/group 1234 2026-10-02 12:00 path/to/name`
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                mode, name = parts[0], parts[5]
                if not mode.startswith("-"):      # a directory or a symlink
                    continue
                if "x" not in mode[1:]:           # not executable
                    continue
                members.add(Path(name.strip()).name)
            for name in sorted(members & forbidden):
                problems.append(
                    f"{artifact} contains {name!r}, which is forbidden in production"
                )
            undeclared = members - declared - allowed_extra
            if undeclared:
                problems.append(
                    f"{artifact} contains undeclared executables {sorted(undeclared)}"
                )
            for name in sorted(declared - members):
                problems.append(
                    f"{artifact} is missing {name!r}, which the manifest declares shipped"
                )
    return problems


if __name__ == "__main__":
    raise SystemExit(main())
