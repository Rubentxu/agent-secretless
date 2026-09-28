#!/usr/bin/env python3
"""Falsification test for the adversarial harness.

`run_harness.py` reports PASS for every probe. That result is only worth
anything if the harness is capable of reporting FAIL. This test proves it is.

The revision that shipped in commit 28c0ee4 generated a canary, compared it
against probe output, and never planted it anywhere. Every probe passed, the
harness was structurally incapable of failing, and the green result proved
nothing about the product. This file is the regression test for that class of
defect: it injects a real leak into a real build and requires the harness to
notice.

    tests/adversarial/test_falsifiability.py

Exits 0 when the harness correctly rejects every injected leak, and 1 when it
fails to, which means the harness cannot be trusted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "run_harness.py"
WORKSPACE = Path(__file__).resolve().parents[2]

#: Pristine copies of every file an injection may touch, keyed by flattened
#: relative path. Populated in `main` before the first injection runs.
STASH_DIR: Path | None = None

#: Source files mutated to prove the harness detects a leak. Each entry is
#: (label, relative path, original snippet, replacement that leaks).
#:
#: Every injection must sit on a path that actually executes in M0 and must
#: still compile, otherwise it proves nothing about the harness. Two earlier
#: entries did neither: one changed `SecretBytes::Debug` when no vault exists to
#: format one, and another read an environment variable the harness never set.
#: Both were reported as "harness passed" and were mistakes in this test, not
#: blind spots in the harness. Keep each entry to a real, executed path.
#:
#: "Still compiles" is stricter than it looks. CI builds with `-D warnings`, so
#: an injection that leaves an unused binding is a build failure there and a
#: pass here. The third entry below was caught exactly that way: it rebound `id`
#: and then stopped using it. `RUSTFLAGS` is therefore set for every build this
#: script performs, so a local run rejects what CI would reject. Without it the
#: two environments disagree and the local result is the untrustworthy one.
INJECTIONS = [
    (
        "secret-in-broker-log",
        "crates/broker/src/main.rs",
        "    let response = match decode_request(&buf[..n]) {",
        "    tracing::warn!(raw = %String::from_utf8_lossy(&buf[..n]));\n    let response = match decode_request(&buf[..n]) {",
    ),
    (
        # Reflects the request field back in an error message, so the canary
        # reaches the client through the response bytes. The log is untouched,
        # which is what separates this from `secret-in-broker-log`: the two
        # injections must fail through different probes, otherwise one of them
        # is untested.
        "secret-in-ipc-response",
        "crates/broker/src/lib.rs",
        """        Request::CreateSession { workspace } => {
            let id = state.sessions.create(workspace, peer);
            Response::SessionCreated { session: id }
        }""",
        """        Request::CreateSession { workspace } => {
            state.sessions.create(workspace.clone(), peer);
            Response::Error {
                code: ErrorCode::InvalidRequest,
                message: format!("session opened for {workspace}"),
            }
        }""",
    ),
    (
        "secret-in-cli-output",
        "crates/cli/src/main.rs",
        "Command::Session { workspace } => Request::CreateSession { workspace },",
        "Command::Session { workspace } => {\n                eprintln!(\"debug workspace={workspace}\");\n                Request::CreateSession { workspace }\n            }",
    ),
    (
        # M1: the vault tool reveals the stored secret. This is the crudest
        # possible leak in the new path, which is exactly why it is worth
        # injecting: it proves the uat-018 probe scans the *tool's own output*
        # and not just the files it writes. A probe that only grepped the
        # artefacts on disk would report PASS here.
        #
        # The injection must still compile under `-D warnings`, so it replaces
        # the existing `writeln!` rather than adding an early return that would
        # leave the rest of the arm unreachable.
        "secret-in-vault-tool-output",
        "crates/vault/src/bin/asv-vault-tool.rs",
        '            writeln!(out, "id={id} len={len}")?;',
        '            let leaked = store.with_secret(&key, &id, |b| String::from_utf8_lossy(b).into_owned())?;\n            writeln!(out, "id={id} len={len} secret={leaked}")?;',
    ),
]


def _run_harness() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(HARNESS)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=WORKSPACE,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _apply(path: Path, original: str, replacement: str) -> None:
    text = path.read_text()
    if original not in text:
        raise SystemExit(
            f"injection target not found in {path}. The source has drifted; "
            f"update INJECTIONS in {Path(__file__).name}."
        )
    path.write_text(text.replace(original, replacement, 1))


def _restore(path: Path) -> None:
    """Restores a file from the pristine stash and makes cargo notice.

    `shutil.copy2` preserves mtime, so a restored source can be byte-identical
    to HEAD yet still look unchanged to cargo's fingerprint check. The result is
    a stale binary that still contains the injected leak, which makes the next
    probe fail for the wrong reason. Bumping mtime forces a real rebuild.
    """
    stash_name = path.relative_to(WORKSPACE).as_posix().replace("/", "__")
    shutil.copy2(STASH_DIR / stash_name, path)
    os.utime(path, None)


def _build() -> subprocess.CompletedProcess[str]:
    """Builds the workspace the way CI does: warnings are errors.

    CI sets `-D warnings`, so an injection that compiles with a warning fails
    there and passes here. A green local run that CI rejects is the worst kind
    of false signal, because it looks like the harness proved something. The
    flag is set unconditionally rather than inherited, so the two environments
    cannot disagree.
    """
    env = dict(os.environ)
    flags = env.get("RUSTFLAGS", "")
    if "-D warnings" not in flags:
        env["RUSTFLAGS"] = f"{flags} -D warnings".strip()
    return subprocess.run(
        ["cargo", "build", "--workspace"],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=WORKSPACE,
        env=env,
    )


def _check(label: str, path: Path, original: str, replacement: str) -> bool:
    """Applies one leak, requires the harness to fail, then reverts."""
    _apply(path, original, replacement)
    try:
        # The mutated source must still compile, otherwise the harness would
        # report INVALID for a missing binary and "detect" nothing at all.
        build = _build()
        if build.returncode != 0:
            print(f"  ERROR   {label}: mutated build failed, injection is not valid")
            print(build.stderr[-800:])
            return False

        code, out = _run_harness()
        if code == 0:
            print(f"  BROKEN  {label}: harness passed with a real leak injected")
            print("          the harness cannot fail, so its green result means nothing")
            return False

        marker = [ln for ln in out.splitlines() if "FAIL" in ln]
        detail = marker[0].strip() if marker else "(no FAIL line reported)"
        print(f"  CAUGHT  {label}: exit {code}, {detail[:110]}")
        return True
    finally:
        _restore(path)


def main() -> int:
    global STASH_DIR

    if not HARNESS.is_file():
        print(f"harness not found at {HARNESS}")
        return 1

    print("Falsification test: the harness must fail on injected leaks")
    print()

    with tempfile.TemporaryDirectory(prefix="asv-falsify-") as tmp:
        STASH_DIR = Path(tmp)
        for _label, rel, _orig, _repl in INJECTIONS:
            src = WORKSPACE / rel
            if not src.is_file():
                print(f"  ERROR   {rel} is missing; the workspace layout has drifted")
                return 1
            shutil.copy2(src, STASH_DIR / rel.replace("/", "__"))

        results = []
        for label, rel, original, replacement in INJECTIONS:
            results.append(_check(label, WORKSPACE / rel, original, replacement))

        # Restore from the pristine copy, never by reverse substitution, so a
        # partial revert cannot leave a leak in the tree.
        for _label, rel, _orig, _repl in INJECTIONS:
            _restore(WORKSPACE / rel)

    # A final build on the restored tree both verifies cleanliness and clears
    # any stale artifact left by the last injection.
    build = _build()
    if build.returncode != 0:
        print()
        print("  ERROR   the workspace does not build after restoring the sources")
        print(build.stderr[-800:])
        return 1

    code, _out = _run_harness()

    print()
    caught = sum(results)
    print(f"injected leaks detected: {caught}/{len(results)}")
    print(f"harness on clean tree: exit {code}")

    if caught == len(results) and code == 0:
        print()
        print("RESULT: the harness detects every injected leak and passes clean.")
        print("Its green result is evidence.")
        return 0

    print()
    if caught != len(results):
        print("RESULT: the harness missed a real leak. Its green result is not evidence.")
    else:
        print("RESULT: every leak was caught but the clean tree does not pass,")
        print("        which means the probes are unstable rather than trustworthy.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
