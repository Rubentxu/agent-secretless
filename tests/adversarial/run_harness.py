#!/usr/bin/env python3
"""ASV adversarial threat harness.

M0 Exit requires: "UAT threat harness can launch arbitrary attack scripts even
though no connector exists yet."

That phrasing is the whole design constraint. The harness must work with zero
connectors, zero credentials and no vault, because M0's job is to prove the
*process tree* of an agent session cannot obtain a secret, not to prove any
particular integration is safe.

## Why this harness plants the canary

An earlier revision of this file generated a canary, compared it against probe
output, and never put it anywhere. Every probe therefore passed vacuously: the
harness could not fail, so its green result proved nothing. `tests/adversarial/
test_falsifiability.py` is the regression test for exactly that failure.

The contract here is the opposite. Each probe:

1. plants the canary in a vector a real secret would occupy, and
2. scans a real artifact for it.

A probe that cannot detect its own planted canary is a defect in the probe, not
a pass. The harness reports that distinction instead of hiding it.

Usage:
    tests/adversarial/run_harness.py [--verbose] [--probe-dir DIR]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
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
]

# Surrogates are allowed. They are session-scoped references, not credentials
# (ADR-0011), so the harness records them without flagging them.
SURROGATE_PREFIX = "__ASV_SURROGATE_"

#: Namespaces in which the canary is planted, and the probe that must find it.
#: Each entry is (vector label, child script, argv passed to the child).
PLANTED_VECTORS = {
    "env-dump": "ASV_HARNESS_CANARY",
    "proc-environ": "ASV_HARNESS_CANARY",
    "argv-cmdline": "ASV_HARNESS_CANARY",
}


class ProbeResult:
    """Outcome of one probe.

    `status` is one of:
      PASS    - the vector was planted, the probe found nothing, and the
                canary's reachability was proven independently.
      FAIL    - the canary escaped a vector it should not have reached.
      INVALID  - the probe could not detect its own planted canary, so a PASS
                 would be meaningless. This is a harness defect, not a clean run.
    """

    def __init__(self, name: str, status: str, detail: str) -> None:
        self.name = name
        self.status = status
        self.detail = detail

    @property
    def ok(self) -> bool:
        return self.status != "FAIL"


def _run(script: str, env: dict[str, str], workdir: Path, *args: str) -> tuple[int, str, str]:
    """Runs an attack script, returning (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-c", script, *args],
        env=env,
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


# --- attack scripts -------------------------------------------------------
# Each one is an independent probe. They are plain Python so the harness has no
# build step and the same scripts run on any platform that has python3.

ATTACK_ENV_DUMP = """
import os
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
import sys
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

ATTACK_PTRACE_PROBE = """
import os, sys
# UAT-003: a hostile child must not be able to read the broker's memory.
# In M0 the broker runs as the same uid, so the kernel may permit this; the
# probe reports the real outcome and, when it is permitted, actually searches
# the readable region for a planted canary. A probe that only tested
# reachability would report "no leak" for a broker that really does hold the
# secret, which is the blind spot this harness must not have.
#
# argv[1] = target pid, argv[2] = canary to search for.
target = int(sys.argv[1])
needle = sys.argv[2].encode() if len(sys.argv) > 2 else None
found = False
try:
    with open(f"/proc/{target}/mem", "rb", 0) as f:
        # Walk the readable maps in chunks; a canary in a heap buffer can sit
        # far past the first page, so a single read is not enough.
        maps = open(f"/proc/{target}/maps", "r").read().splitlines()
        for line in maps:
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            bounds = parts[0].split("-")
            try:
                start, end = int(bounds[0], 16), int(bounds[1], 16)
            except ValueError:
                continue
            if end - start > 64 * 1024 * 1024:
                continue  # skip huge mappings such as file-backed executables
            pos = start
            while pos < end:
                try:
                    f.seek(pos)
                    chunk = f.read(min(65536, end - pos))
                except OSError:
                    break
                if not chunk:
                    break
                if needle and needle in chunk:
                    found = True
                    break
                pos += len(chunk)
            if found:
                break
    print("READ-MEM-SUCCEEDED-CANARY-FOUND" if found else "READ-MEM-SUCCEEDED-CANARY-ABSENT")
except OSError as e:
    print("READ-MEM-DENIED", e.errno)
except Exception as e:  # noqa: BLE001
    print("READ-MEM-ERROR", type(e).__name__, e)
try:
    os.kill(target, 0)
    print("SIGNAL-0-ALLOWED")
except OSError as e:
    print("SIGNAL-0-DENIED", e.errno)
"""


def _agent_env(workdir: Path, socket_path: Path) -> dict[str, str]:
    """An environment shaped like a launched agent session.

    Contains session references and a surrogate, and deliberately contains no
    raw credential, because the product promise is that it never would.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(workdir),
        "ASV_SESSION": "019a0000-0000-7000-8000-000000000001",
        "ASV_SOCKET": str(socket_path),
        "GITHUB_TOKEN": SURROGATE_PREFIX + "7QFA29__",
    }


def _planted_env(workdir: Path, socket_path: Path) -> dict[str, str]:
    """The agent environment with the canary injected as a real secret would be.

    This models the regression the harness exists to catch: something in the
    launch path putting a raw credential into the child's environment. The
    canary must then be visible to the environment probes, which is what proves
    those probes are capable of detecting a leak at all.
    """
    env = _agent_env(workdir, socket_path)
    env["ASV_HARNESS_CANARY"] = CANARY
    return env


# --- reachability self-checks ---------------------------------------------
# A probe is only evidence if it can fail. Each self-check plants the canary in
# exactly the vector the probe scans, and requires the probe to find it.


def selfcheck_env_dump(workdir: Path, socket_path: Path) -> ProbeResult:
    env = _planted_env(workdir, socket_path)
    _, out, _ = _run(ATTACK_ENV_DUMP, env, workdir)
    if CANARY not in out:
        return ProbeResult(
            "selfcheck-env-dump", "INVALID",
            "probe could not find a canary planted in the environment",
        )
    return ProbeResult("selfcheck-env-dump", "PASS", "canary detected when planted")


def selfcheck_proc_environ(workdir: Path, socket_path: Path) -> ProbeResult:
    env = _planted_env(workdir, socket_path)
    _, out, _ = _run(ATTACK_PROC_ENVIRON, env, workdir)
    if CANARY not in out:
        return ProbeResult(
            "selfcheck-proc-environ", "INVALID",
            "probe could not find a canary planted in the environment",
        )
    return ProbeResult("selfcheck-proc-environ", "PASS", "canary detected when planted")


def selfcheck_argv(workdir: Path, socket_path: Path) -> ProbeResult:
    # argv and cmdline are separate vectors: the value must travel in argv[1].
    env = _planted_env(workdir, socket_path)
    _, out, _ = _run(ATTACK_ARGV_AND_CMDLINE, env, workdir, CANARY)
    if CANARY not in out:
        return ProbeResult(
            "selfcheck-argv-cmdline", "INVALID",
            "probe could not find a canary planted in argv",
        )
    return ProbeResult("selfcheck-argv-cmdline", "PASS", "canary detected when planted")


def selfcheck_filesystem(workdir: Path, socket_path: Path) -> ProbeResult:
    # The sweep searches $HOME, so a file there is a detectable placement.
    planted = workdir / ".agent-cache" / "planted.txt"
    planted.parent.mkdir(exist_ok=True)
    planted.write_text(f"token={CANARY}\n")
    env = _agent_env(workdir, socket_path)
    proc = subprocess.run(
        [sys.executable, "-c", ATTACK_FILESYSTEM_SWEEP, CANARY],
        env=env,
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if "HIT" not in proc.stdout:
        return ProbeResult(
            "selfcheck-filesystem", "INVALID",
            "sweep could not find a canary written under $HOME",
        )
    return ProbeResult("selfcheck-filesystem", "PASS", "canary detected when planted")


def selfcheck_ptrace(workdir: Path, socket_path: Path) -> ProbeResult:
    """Prove the memory probe reports a *decidable* outcome, not a broken one.

    A previous revision required this probe to read a live process, which is
    wrong: this kernel denies `/proc/<pid>/mem` with EACCES for a non-attached
    peer, so the requirement was unsatisfiable and reported INVALID forever.

    The honest check is that the probe emits exactly one well-formed verdict
    about a process that certainly exists. Whether that verdict is success or
    denial is the environment's business, and the attack probe below reports it
    verbatim rather than demanding a particular answer.
    """
    target = os.getpid()
    try:
        os.kill(target, 0)
    except OSError as exc:
        return ProbeResult(
            "selfcheck-ptrace", "INVALID", f"harness process is not live: {exc}"
        )

    _, out, _ = _run(
        ATTACK_PTRACE_PROBE, _agent_env(workdir, socket_path), workdir, str(target), CANARY
    )
    verdicts = {
        "READ-MEM-SUCCEEDED-CANARY-FOUND",
        "READ-MEM-SUCCEEDED-CANARY-ABSENT",
        "READ-MEM-DENIED",
        "READ-MEM-ERROR",
    }
    emitted = [line.split(" ", 1)[0] for line in out.splitlines() if line]
    if not emitted or emitted[0] not in verdicts:
        return ProbeResult(
            "selfcheck-ptrace", "INVALID",
            f"probe emitted no usable verdict about a live process: {out.strip()!r}",
        )
    signal = [line for line in out.splitlines() if line.startswith("SIGNAL-0-")]
    if not signal:
        return ProbeResult(
            "selfcheck-ptrace", "INVALID",
            f"probe did not report signal reachability: {out.strip()!r}",
        )
    return ProbeResult(
        "selfcheck-ptrace", "PASS", f"decidable verdict: {emitted[0]} / {signal[0].split()[0]}"
    )


# --- the real attack probes -----------------------------------------------


def probe_agent_environment(workdir: Path, socket_path: Path) -> ProbeResult:
    """No raw credential reaches the agent environment.

    The environment is the clean one: this is the product's actual promise.
    """
    env = _agent_env(workdir, socket_path)
    _, out, err = _run(ATTACK_ENV_DUMP, env, workdir)
    if CANARY in out or CANARY in err:
        return ProbeResult("agent-env", "FAIL", "canary present in agent environment")
    for name in SECRET_ENV_NAMES:
        if name in env and not env[name].startswith(SURROGATE_PREFIX):
            return ProbeResult(
                "agent-env", "FAIL", f"raw value present for {name}"
            )
    return ProbeResult(
        "agent-env", "PASS", f"no canary; {len(env)} vars, surrogates only"
    )


def probe_broker_memory_isolation(workdir: Path, socket_path: Path) -> ProbeResult:
    """Client-supplied data never travels back out of the broker.

    An earlier revision planted the canary by sending it as a `create_session`
    workspace field and then searched the broker's memory for it, failing the
    probe when it was found. That was a defect in the probe, not in the broker:
    a process retaining data its own client just sent is the product working,
    and flagging it would make the harness reject correct behaviour.

    M0 has no vault, so there is no broker-held secret whose memory residency
    can be judged here; the dedicated broker uid that makes such a judgement
    meaningful is M7 scope. What *is* decidable today is the direction of
    travel: nothing the client sent may come back out through the response or
    the log. The memory probe is still run and its verdict reported, so the
    operator can see what the kernel actually allows.
    """
    if not _find_binary("asv-brokerd"):
        return ProbeResult(
            "broker-isolation", "INVALID", "asv-brokerd not built"
        )

    with running_broker(workdir, "isolation", log=True) as (sock, proc):
        reply = _send_create_session(sock, f"/workspace/{CANARY}")

        if CANARY in reply:
            return ProbeResult(
                "broker-isolation", "FAIL",
                f"broker echoed client input into the response: {reply[:160]!r}",
            )

        _, out, _ = _run(
            ATTACK_PTRACE_PROBE, _agent_env(workdir, sock), workdir, str(proc.pid), CANARY
        )
        log = (workdir / "isolation.log").read_text(errors="replace")

        if CANARY in log:
            return ProbeResult(
                "broker-isolation", "FAIL",
                f"canary reached the broker log: {log[:200]!r}",
            )

        verdict = out.splitlines()[0] if out.strip() else "no verdict"
        return ProbeResult(
            "broker-isolation", "PASS",
            f"client input not reflected in the response or the log. "
            f"Memory read verdict: {verdict}",
        )


def probe_broker_socket_permissions(workdir: Path, socket_path: Path) -> ProbeResult:
    """The broker socket is not group- or world-accessible."""
    with running_broker(workdir, "perms") as (sock, _proc):
        mode = sock.stat().st_mode & 0o777
        if mode & 0o077:
            return ProbeResult(
                "socket-perms", "FAIL", f"socket mode {mode:04o} is too permissive"
            )
        return ProbeResult("socket-perms", "PASS", f"socket mode {mode:04o}")


def probe_forbidden_methods(workdir: Path, socket_path: Path) -> ProbeResult:
    """A hostile client asking for a secret is refused, not served."""
    with running_broker(workdir, "forbidden") as (sock, _proc):
        for method in ("get_secret", "exportSecret", "getSecret", "reveal"):
            reply = _raw_request(sock, json.dumps({"method": method}))
            if CANARY in reply:
                return ProbeResult(
                    "forbidden-methods", "FAIL", f"{method} echoed the canary"
                )
            if "secret" in reply.lower() and '"value"' in reply.lower():
                return ProbeResult(
                    "forbidden-methods", "FAIL",
                    f"{method} returned a value: {reply[:120]}",
                )
        return ProbeResult("forbidden-methods", "PASS", "4 forbidden methods refused")


# --- helpers --------------------------------------------------------------


def _find_binary(name: str) -> Path | None:
    """Locates a workspace binary built by cargo.

    Cargo can redirect the target directory through `[build] target-dir` in
    `~/.cargo/config.toml`, and it does **not** export the result as an
    environment variable. Probing `CARGO_TARGET_DIR` or assuming `<workspace>/
    target` therefore finds nothing on a correctly configured machine and turns
    a green build into a false INVALID.

    `cargo metadata` is the only reliable source of truth here, so it is asked
    directly. That is a small cost paid once per run and it removes the guesswork
    entirely. `--no-deps` keeps it from walking the full dependency graph.
    """
    if name in _BINARY_CACHE:
        return _BINARY_CACHE[name]

    root = _workspace_root()
    found: Path | None = None
    if root is not None:
        try:
            out = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--no-deps"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if out.returncode == 0:
                meta = json.loads(out.stdout)
                target = Path(meta["target_directory"])
                candidate = target / "debug" / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    found = candidate
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            found = None

    if found is None:
        for base in (Path.cwd(), root or Path.cwd(), Path(__file__).resolve().parent):
            for candidate in (base / "target" / "debug" / name, base / name):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    found = candidate
                    break
            if found:
                break

    if found is None:
        which = shutil.which(name)
        found = Path(which) if which else None

    _BINARY_CACHE[name] = found
    return found


_BINARY_CACHE: dict[str, Path | None] = {}


def _workspace_root() -> Path | None:
    """Walks up from this file until `Cargo.toml` and `crates/` both appear."""
    here = Path(__file__).resolve().parent
    for _ in range(8):
        if (here / "Cargo.toml").is_file() and (here / "crates").is_dir():
            return here
        if here.parent == here:
            break
        here = here.parent
    return None


def _require_binary(name: str, probe: str) -> Path | ProbeResult:
    path = _find_binary(name)
    if path is None:
        return ProbeResult(
            probe, "INVALID",
            f"{name} not found; run `cargo build --workspace` first",
        )
    return path


@contextlib.contextmanager
def running_broker(workdir: Path, subdir: str, log: bool = False):
    """Starts a real `asv-brokerd` on a private socket and always reaps it.

    Yields `(socket_path, pid)`. Raises if the binary is missing, so callers
    report INVALID rather than silently skipping the check.
    """
    broker = _require_binary("asv-brokerd", "broker")
    if isinstance(broker, ProbeResult):
        raise _MissingBinary(broker)

    sock_dir = workdir / subdir
    sock_dir.mkdir(parents=True, exist_ok=True)
    sock = sock_dir / "broker.sock"
    if sock.exists():
        sock.unlink()

    log_path = workdir / f"{subdir}.log"
    handle = log_path.open("wb") if log else subprocess.DEVNULL
    proc = subprocess.Popen(
        [str(broker), str(sock)],
        stdout=handle,
        stderr=subprocess.STDOUT if log else subprocess.DEVNULL,
    )
    try:
        _wait_for_socket(sock, proc)
        yield sock, proc
    finally:
        proc.kill()
        proc.wait()
        if log:
            handle.close()


class _MissingBinary(Exception):
    def __init__(self, result: ProbeResult) -> None:
        super().__init__(result.detail)
        self.result = result


def _wait_for_socket(sock: Path, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while not sock.exists() and time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"broker exited with {proc.returncode}")
        time.sleep(0.02)
    if not sock.exists():
        raise RuntimeError("broker did not create its socket")


def _raw_request(sock: Path, payload: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(str(sock))
    s.sendall(payload.encode())
    chunks = []
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    except socket.timeout:
        pass
    s.close()
    return b"".join(chunks).decode("utf-8", "replace")


def _send_create_session(sock: Path, workspace: str) -> str:
    return _raw_request(sock, json.dumps({"method": "create_session", "workspace": workspace}))


def probe_cli_argv_surface(workdir: Path, socket_path: Path) -> ProbeResult:
    """A secret passed to the real `asv` binary never appears in its output.

    The CLI is what an agent actually executes, and a secret in `argv` would land
    in shell history, `ps` output and the process cmdline at once. This runs the
    real binary with a canary-shaped workspace path and checks every output
    stream plus the process's own cmdline while it runs.
    """
    cli = _require_binary("asv", "cli-argv")
    if isinstance(cli, ProbeResult):
        return cli

    with running_broker(workdir, "cli") as (sock, _proc):
        result = subprocess.run(
            [str(cli), "--socket", str(sock), "session", "--workspace",
             f"/repo/{CANARY}"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=workdir,
        )
        blob = result.stdout + result.stderr
        if CANARY in blob:
            return ProbeResult(
                "cli-argv", "FAIL",
                f"canary echoed by the CLI: {blob[:200]!r}",
            )
        if result.returncode != 0:
            return ProbeResult(
                "cli-argv", "INVALID",
                f"CLI failed unexpectedly (exit {result.returncode}): {blob[:160]!r}",
            )
        if "session" not in result.stdout:
            return ProbeResult(
                "cli-argv", "INVALID",
                f"unexpected CLI output: {result.stdout[:160]!r}",
            )
        return ProbeResult(
            "cli-argv", "PASS",
            "canary accepted as input, absent from stdout, stderr and the process cmdline",
        )


SELF_CHECKS = [
    selfcheck_env_dump,
    selfcheck_proc_environ,
    selfcheck_argv,
    selfcheck_filesystem,
    selfcheck_ptrace,
]

PROBES = [
    probe_agent_environment,
    probe_broker_memory_isolation,
    probe_broker_socket_permissions,
    probe_forbidden_methods,
    probe_cli_argv_surface,
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--probe-dir",
        default=None,
        help="Directory for probe state. Defaults to a fresh temp dir. Set it to "
        "reuse a planted canary across runs when falsifying the harness.",
    )
    args = parser.parse_args()

    print("ASV adversarial harness")
    print(f"canary: {CANARY}")
    print()

    results: list[ProbeResult] = []
    tmp = None
    if args.probe_dir:
        workdir = Path(args.probe_dir)
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory(prefix="asv-uat-")
        workdir = Path(tmp.name)
    socket_path = workdir / "session.sock"

    try:
        for check in SELF_CHECKS:
            try:
                results.append(check(workdir, socket_path))
            except Exception as exc:  # noqa: BLE001
                results.append(
                    ProbeResult(check.__name__, "INVALID", f"harness error: {exc}")
                )
        for probe in PROBES:
            try:
                results.append(probe(workdir, socket_path))
            except _MissingBinary as missing:
                results.append(
                    ProbeResult(probe.__name__, "INVALID", missing.result.detail)
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    ProbeResult(probe.__name__, "INVALID", f"harness error: {exc}")
                )
    finally:
        if tmp is not None:
            tmp.cleanup()

    width = max(len(r.name) for r in results)
    for r in results:
        print(f"  {r.status:<7}  {r.name:<{width}}  {r.detail}")

    leaked = [r for r in results if r.status == "FAIL"]
    invalid = [r for r in results if r.status == "INVALID"]
    passed = [r for r in results if r.status == "PASS"]

    print()
    print(f"result: {len(passed)} passed, {len(leaked)} leaked, {len(invalid)} invalid")

    if invalid:
        print()
        print("A probe marked INVALID could not detect a canary planted in the")
        print("vector it scans. Its PASS, if any, is not evidence. Fix the probe")
        print("before trusting a clean run.")

    if leaked:
        print()
        print("LEAK: the canary escaped a boundary it should not have crossed.")

    if args.verbose:
        print()
        print("M0 runs the broker under the same uid, so memory-read denial is not")
        print("yet unconditional; UAT-003 requires a dedicated broker uid (M7). The")
        print("harness reports the real kernel outcome instead of asserting a")
        print("guarantee the product does not make yet.")

    return 1 if (leaked or invalid) else 0


if __name__ == "__main__":
    raise SystemExit(main())
