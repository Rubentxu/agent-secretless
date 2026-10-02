#!/usr/bin/env python3
"""Build and stage exactly the components distribution/manifest.toml declares.

FR-001 asks for a single source of truth for the distributable components, and
a manifest that only a *test* reads is not one: the build would still be free to
package whatever Cargo produced, and the gate would merely complain afterwards.
So the build asks this script what to build, and this script asks the manifest.

The previous arrangement did not do this. `dist` was pointed at the cargo
workspace, which packages every `[[bin]]` in every member, and `asv-vault-tool`
— declared in its own source as a minimal exerciser for the adversarial
harness — would have shipped to users. Nothing in the build said it should not
be, because the build was not being told anything.

Two layout questions, both settled by the manifest rather than by a constant
here:

* **What gets built.** Every component with `shipped = true`, and nothing else.
  A component with `forbidden_in_production` is not built for the bundle at
  all, rather than built and then filtered — a binary that is compiled and
  discarded is a binary whose absence has to be checked, and a check can be
  forgotten.
* **Where it lands.** `install_as`, relative to the install root, which is the
  FR-002 layout: `bin/` for the public CLI, `libexec/asv/` for the private
  runtime. This is why `asv-brokerd` is not on PATH, and it is recorded once.

## Why two output views of one build

`dist` is pointed at this workspace as a generic (`dist:`) project rather than a
cargo one, so it looks for `<out-dir>/<binary-name>` — flat, one file per
binary, and it has no notion of a manifest that says which of them belong in
`bin/` and which belong in `libexec/`. So the build runs once and produces two
views of the same bytes:

* `packaging/target/<name>` — flat, which is what dist tars up. The archive is
  a transport format; the install layout is a product decision, and conflating
  them means either giving up the layout or teaching dist about a manifest it
  has no field for.
* the install layout under `target/dist/staging` — `bin/asv` and
  `libexec/asv/asv-brokerd`, which is what FR-002 describes and what the
  bundle gate validates.

Both are copies of the same compiled artifacts from the same invocation, so
they cannot disagree about what was built. Only the placement differs, and the
gate checks the placement.

Run: python3 packaging/stage-bundle.py [--out DIR] [--target TRIPLE] [--check]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "distribution" / "manifest.toml"
DEFAULT_OUT = REPO / "target" / "dist" / "staging"
# dist's `out-dir`, which it resolves relative to this script's own directory
# because the package root is `packaging/`.
FLAT_OUT = Path(__file__).resolve().parent / "target"


def die(message: str) -> None:
    print(f"stage-bundle: {message}", file=sys.stderr)
    raise SystemExit(1)


def load() -> dict:
    if not MANIFEST.exists():
        die(f"{MANIFEST} does not exist; there is no product boundary to build to")
    return tomllib.loads(MANIFEST.read_text())


def cargo_binaries(manifest: dict) -> list[tuple[str, str]]:
    """(component, crate) for every shipped component, in manifest order."""
    out = []
    for component in manifest.get("component", []):
        if not component.get("shipped"):
            continue
        crate = component.get("crate")
        if not crate:
            die(
                f"component {component['name']!r} is marked shipped but names no crate; "
                f"the manifest cannot drive a build it does not describe"
            )
        out.append((component["name"], crate))
    if not out:
        die("the manifest declares no shipped components")
    return out


def build(manifest: dict, target: str | None, out: Path) -> list[str]:
    """Build each declared binary and copy it to its declared install path."""
    out.mkdir(parents=True, exist_ok=True)

    # One `cargo build` with every declared --bin, rather than one invocation
    # per component: the workspace shares a target directory, and N invocations
    # means re-resolving the dependency graph N times for the same artifacts.
    command = ["cargo", "build", "--profile=dist", "--locked"]
    if target:
        command += ["--target", target]
    for name, crate in cargo_binaries(manifest):
        command += ["-p", crate, "--bin", name]

    print(f"stage-bundle: {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=REPO)
    if result.returncode != 0:
        die("the build failed; nothing was staged")

    cargo_target = os.environ.get("CARGO_TARGET_DIR", str(REPO / "target"))
    profile_dir = Path(cargo_target) / ("dist" if not target else f"{target}/dist")

    staged: list[str] = []
    for component in manifest.get("component", []):
        if not component.get("shipped"):
            continue
        name = component["name"]
        source = profile_dir / name
        if not source.exists():
            die(
                f"cargo reported success but {source} does not exist. The manifest "
                f"declares {name!r} as shipped; a component that is declared and "
                f"absent is the failure this whole mechanism exists to make loud."
            )
        destination = out / component["install_as"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        # 0755 rather than copying cargo's mode: the installed layout is a
        # product decision, and inheriting whatever umask the build ran under
        # would make the installed permissions depend on the builder's shell.
        shutil.copy2(source, destination)
        destination.chmod(0o755)
        staged.append(component["install_as"])
        print(f"stage-bundle: {name} -> {destination.relative_to(REPO)}")

        # The flat view dist consumes. Same bytes, one level up and outside the
        # staging tree, so the gate's "exactly the declared set" check over the
        # staging tree is not confused by a duplicate of the same binary.
        flat = FLAT_OUT / name
        flat.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, flat)
        flat.chmod(0o755)

    # Anything the build dropped in the output that the manifest does not name
    # is a defect, caught here rather than at install time. The bundle gate
    # checks the same property; this one runs before the archive exists.
    declared = {
        component["install_as"]
        for component in manifest.get("component", [])
        if component.get("shipped")
    }
    for path in sorted(out.rglob("*")):
        if path.is_dir() or not os.access(path, os.X_OK):
            continue
        relative = path.relative_to(out).as_posix()
        if relative not in declared:
            die(
                f"{relative} is executable in the staging tree but is not declared in "
                f"distribution/manifest.toml. This is how asv-vault-tool would have "
                f"shipped."
            )

    return staged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--target", default=None, help="Rust target triple")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate an existing staging tree against the manifest and exit, "
             "without building. Used by the bundle gate.",
    )
    args = parser.parse_args()

    manifest = load()

    if args.check:
        sys.path.insert(0, str(REPO / "tests"))
        from distribution_bundle import validate_staging  # noqa: PLC0415

        problems = validate_staging(manifest, args.out)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        if problems:
            print("staging does not match the manifest", file=sys.stderr)
            return 1
        print(f"staging at {args.out} matches the manifest")
        return 0

    # A stale staging tree is worse than none: the bundle gate validates a
    # directory, and a leftover binary from a previous component set would be
    # validated as if it were current.
    if args.out.exists():
        shutil.rmtree(args.out)
    if FLAT_OUT.exists():
        shutil.rmtree(FLAT_OUT)

    staged = build(manifest, args.target, args.out)
    print(f"staged {len(staged)} declared components into {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
