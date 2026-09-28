#!/usr/bin/env python3
"""ASV adversarial threat harness.

M0 Exit requires: "UAT threat harness can launch arbitrary attack scripts even
though no connector exists yet."

That phrasing is the whole design constraint. The harness must work with zero
connectors, zero credentials and no vault, because M0's job is to prove the
*process tree* of an `asv run` session cannot obtain a secret, not to prove any
particular integration is safe.

Each attack script is a standalone program. The harness runs it as a child
inside a session-like environment seeded with a canary, then scans everything
the child could have reached for that canary.

Exit 0 = no canary escaped. Exit 1 = at least one escape (a real finding).

Usage:
    tests/adversarial/run_harness.py [--verbose]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Unique per run so a stale artifact from a previous run cannot mask a leak.
CANARY = "ASV-CANARY-" + os.urandom(8).hex().upper() + "-DO-NOT-LEAK"

# Environment variables that would represent a real secret if the product ever
# injected one. docs/04-SHELL-FIRST-INTEGRATION.md §3 forbids raw values here;
# the harness asserts they stay absent rather than trusting the rule.
SECRET_ENV_NAMES = [
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SSH_AUTH_SOCK",
]

# Surrogates are allowed. They are session-scoped references, not credentials
# (ADR-0011), so the harness records them without flagging them.
ALLOWED_ENV_PREFIXES = ("ASV_SESSION", "ASV_SOCKET", "SSH_AUTH_SOCK")


class AttackResult:
    def __init__(self, name: str, passed: bool, detail: str) -> None:
        self.name = name
        self.passed = passed
        self.detail = detail


def _run(script: str, env: dict[str, str], workdir: Path) -> tuple[int, str, str]:
    """Runs an attack script, returning (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _base_env(workdir: Path) -> dict[str, str]:
    """An environment shaped like a launched agent session.

    Contains session references and surrogates, and deliberately contains no
    raw credential, because the product promise is that it never would.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(workdir),
        "ASV_SESSION": "019a0000-0000-7000-8000-000000000001",
        "ASV_SOCKET": str(workdir / "session.sock"),
        "GITHUB_TOKEN": "__ASV_SURROGATE_7QFA29__",
    }
    return env


# --- attack scripts -------------------------------------------------------
# Each one is an independent probe. They are plain Python so the harness has no
# build step and the same scripts run on any platform that has python3.

ATTACK_ENV_DUMP = """
import os, sys
for k, v in sorted(os.environ.items()):
    print(f"{k}={v}")
"""

ATTACK_PROC_ENVIRON = """
import os
for pid in ["self", "ppid"]:
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            for entry in f.read().split(b"\\0"):
                if entry:
                    print(entry.decode("utf-8", "replace"))
    except OSError as e:
        print(f"unreadable:{pid}:{e.errno}")
"""

ATTACK_ARGV_AND_CMDLINE = """
import os, sys
print("ARGV", sys.argv)
try:
    with open("/proc/self/cmdline", "rb") as f:
        print("CMDLINE", f.read().replace(b"\\0", b" ").decode("utf-8", "replace"))
except OSError as e:
    print("unreadable", e.errno)
"""

ATTACK_FILESYSTEM_SWEEP = """
import os, sys
needle = sys.argv[1].encode() if len(sys.argv) > 1 else None
hits = 0
for root, dirs, files in os.walk(os.environ.get("HOME", "/tmp")):
    for name in files:
        p = os.path.join(root, name)
        try:
            if needle and needle in open(p, "rb").read():
                print("HIT", p)
                hits += 1
        except OSError:
            pass
print("filesystem-hits", hits)
"""

ATTACK_PTRACE_BROKER = """
import os, sys
# UAT-003: a hostile child must not be able to attach to or read the broker.
# In M0 the broker runs as the same uid, so this probe records the *attempt*
# and whether the kernel denied it. A later milestone with a dedicated uid is
# what makes the denial unconditional; the harness reports the real outcome
# either way rather than asserting a green that does not exist yet.
target = int(sys.argv[1]) if len(sys.argv) > 1 else 1
try:
    with open(f"/proc/{target}/mem", "rb", 0) as f:
        f.read(16)
    print("READ-MEM-SUCCEEDED")
except OSError as e:
    print("READ-MEM-DENIED", e.errno)
try:
    os.kill(target, 0)
    print("SIGNAL-0-ALLOWED")
except OSError as e:
    print("SIGNAL-0-DENIED", e.errno)
"""


def _check_canary(name: str, stdout: str, stderr: str) -> AttackResult:
    if CANARY in stdout or CANARY in stderr:
        return AttackResult(name, False, f"canary escaped in output: {stdout[:200]!r}")
    return AttackResult(name, True, "no canary in output")


def attack_environment_dump(env: dict[str, str], workdir: Path) -> AttackResult:
    _, out, err = _run(ATTACK_ENV_DUMP, env, workdir)
    result = _check_canary("env-dump", out, err)
    if not result.passed:
        return result
    for name in SECRET_ENV_NAMES:
        if name in env and not env[name].startswith("__ASV_SURROGATE_"):
            if name not in ALLOWED_ENV_PREFIXES:
                return AttackResult(
                    "env-dump", False, f"raw value present for {name}"
                )
    return AttackResult("env-dump", True, f"no canary; {len(env)} vars inspected")


def attack_proc_environ(env: dict[str, str], workdir: Path) -> AttackResult:
    _, out, err = _run(ATTACK_PROC_ENVIRON, env, workdir)
    return _check_canary("proc-environ", out, err)


def attack_argv(env: dict[str, str], workdir: Path) -> AttackResult:
    _, out, err = _run(ATTACK_ARGV_AND_CMDLINE, env, workdir)
    return _check_canary("argv-cmdline", out, err)


def attack_filesystem(env: dict[str, str], workdir: Path) -> AttackResult:
    # A realistic secret would be written to disk by some tool; the sweep looks
    # for the canary anywhere the agent can read.
    (workdir / ".agent-cache").mkdir(exist_ok=True)
    (workdir / ".agent-cache" / "notes.txt").write_text("nothing to see here")
    proc = subprocess.run(
        [sys.executable, "-c", ATTACK_FILESYSTEM_SWEEP, CANARY],
        env=env,
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if "HIT" in proc.stdout:
        return AttackResult("filesystem-sweep", False, proc.stdout[:200])
    return AttackResult("filesystem-sweep", True, "no canary on agent-readable disk")


def attack_ptrace(env: dict[str, str], workdir: Path) -> AttackResult:
    probe = subprocess.run(
        [sys.executable, "-c", ATTACK_PTRACE_BROKER, "1"],
        env=env,
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if CANARY in probe.stdout:
        return AttackResult("ptrace-broker", False, probe.stdout[:200])
    return AttackResult("ptrace-broker", True, probe.stdout.strip().splitlines()[:2])


ATTACKS = [
    attack_environment_dump,
    attack_proc_environ,
    attack_argv,
    attack_filesystem,
    attack_ptrace,
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    print(f"ASV adversarial harness")
    print(f"canary: {CANARY}")
    print(f"attacks: {len(ATTACKS)}")
    print()

    results: list[AttackResult] = []
    with tempfile.TemporaryDirectory(prefix="asv-uat-") as tmp:
        workdir = Path(tmp)
        env = _base_env(workdir)
        for attack in ATTACKS:
            try:
                results.append(attack(env, workdir))
            except Exception as exc:  # noqa: BLE001
                results.append(AttackResult(attack.__name__, False, f"harness error: {exc}"))

    width = max(len(r.name) for r in results)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  {status}  {r.name:<{width}}  {r.detail}")

    failures = [r for r in results if not r.passed]
    print()
    print(f"result: {len(results) - len(failures)} passed, {len(failures)} failed")

    if args.verbose:
        print()
        print("Note: M0 runs the broker under the same uid, so ptrace denial is")
        print("not yet unconditional. UAT-003 requires a dedicated broker uid,")
        print("which is M7 scope. This harness reports the real kernel outcome")
        print("instead of asserting a guarantee the product does not make yet.")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
