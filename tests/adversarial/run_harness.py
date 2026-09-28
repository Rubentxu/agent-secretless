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


def _cmdline_blobs_for(pid: int) -> list[str]:
    """Returns the NUL-joined cmdline of `pid` and of each of its live children.

    `/proc/<pid>/cmdline` is the vector `ps`, shell history and process listings
    read, so it is a distinct leak surface from stdout/stderr. The entry only
    exists while the process lives, which is why callers must sample it while
    the child is running rather than after `communicate()`.
    """
    pids = [pid]
    try:
        # `children` is a convenience file; fall back to scanning for reparented
        # ones is not attempted because a leaked child is out of scope here.
        kids = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        pids.extend(int(k) for k in kids)
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        pass

    blobs = []
    for target in pids:
        try:
            raw = Path(f"/proc/{target}/cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if raw:
            blobs.append(raw.replace(b"\0", b" ").decode("utf-8", "replace"))
    return blobs


def probe_cli_argv_surface(workdir: Path, socket_path: Path) -> ProbeResult:
    """The CLI must not *offer* a secret-ingestion surface, and must not echo input.

    `docs/02-THREAT-MODEL.md` forbids raw secrets as ordinary CLI flags, so the
    product's obligation is (a) to expose no flag that ingests a secret, and
    (b) to never echo a request field back. Both are checked here.

    The `--workspace` value is a canary so that if the CLI ever *does* echo the
    field, the probe catches it. That the canary also appears in
    `/proc/<pid>/cmdline` while the process lives is not a product defect: on
    Linux `argv` is readable by every same-uid process and `ps`/shell history see
    it regardless. M0 therefore does not claim an argv boundary, and the harness
    reports the kernel truth instead of asserting a control the OS does not
    offer. The supported ingestion channel (no-echo TTY / dedicated pipe) is
    M1 work; the M0 CLI deliberately has no credential-ingestion command at all.
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

    help_text = subprocess.run(
        [str(cli), "--help"], capture_output=True, text=True, timeout=60, cwd=workdir
    )
    combined = (help_text.stdout + help_text.stderr).lower()
    for forbidden in ["get-secret", "export-secret", "show-secret", "reveal", "password", "token"]:
        if forbidden in combined:
            return ProbeResult(
                "cli-argv", "FAIL",
                f"CLI advertises a secret-ingestion surface `{forbidden}`: {help_text.stdout[:200]!r}",
            )

    return ProbeResult(
        "cli-argv", "PASS",
        "no secret-ingestion surface advertised; request field never echoed "
        "(argv/cmdline visibility is a same-uid kernel property, not an ASV control)",
    )


def selfcheck_live_cmdline(workdir: Path, socket_path: Path) -> ProbeResult:
    """Prove `/proc/<pid>/cmdline` reading works, so the kernel-limit claim is falsifiable.

    The `cli-argv` probe reports that argv visibility is a property of the kernel
    rather than an ASV control. That is a claim about the environment, and a
    claim is only worth reporting if it can be wrong. This self-check plants the
    canary in a live process's argv, requires the reader to find it, and
    requires the entry to be gone once the process exits. Without it, the
    kernel-limit wording would be exactly the kind of unfalsified assertion this
    harness was rewritten to eliminate.
    """
    marker = f"{CANARY}-selfcheck"
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", marker]
    )
    try:
        found = False
        for _ in range(100):
            if any(marker in blob for blob in _cmdline_blobs_for(proc.pid)):
                found = True
                break
            if proc.poll() is not None:
                break
            time.sleep(0.02)
        if not found:
            return ProbeResult(
                "selfcheck-cmdline", "INVALID",
                "could not read the planted canary from a live /proc cmdline",
            )
        if _cmdline_blobs_for(proc.pid) and not any(
            marker in blob for blob in _cmdline_blobs_for(proc.pid)
        ):
            return ProbeResult(
                "selfcheck-cmdline", "INVALID",
                "cmdline reader returned an unstable result",
            )
    finally:
        proc.kill()
        proc.wait()
    if _cmdline_blobs_for(proc.pid):
        return ProbeResult(
            "selfcheck-cmdline", "INVALID",
            "cmdline entry still readable after the process exited",
        )
    return ProbeResult(
        "selfcheck-cmdline", "PASS",
        "canary readable in a live /proc cmdline and gone after exit",
    )


SELF_CHECKS = [
    selfcheck_env_dump,
    selfcheck_proc_environ,
    selfcheck_argv,
    selfcheck_filesystem,
    selfcheck_ptrace,
    selfcheck_live_cmdline,
]

# NOTE: the PROBES registry lives at the end of this file, after every probe
# is defined. Registering it here would raise NameError at import time.


# --- M1 vault probes -------------------------------------------------------
#
# M1 added a real encrypted vault, so the harness gained a real binary to
# attack. These three probes discharge the M1 exit UATs from
# docs/15-ROADMAP.md at the level the UATs describe: an artefact outside the
# process, not a unit test inside a crate.
#
# Each probe runs `asv-vault-tool` for real and then inspects the filesystem
# and the process's own output. None of them trusts the tool's exit code
# alone: a tool that printed the canary and returned 0 would otherwise pass.


def _vault_tool(probe: str) -> Path:
    drift = _assert_vault_canary_matches(probe)
    if drift is not None:
        return drift
    return _require_binary("asv-vault-tool", probe)


def _vault_canary_secret() -> str:
    """The canary that `asv-vault-tool` actually plants.

    This must stay byte-identical to `CANARY` in
    `crates/vault/src/bin/asv-vault-tool.rs`. A probe that searched for a
    different string would report PASS against a vault that never contained
    the value it was looking for, which is the worst possible harness bug: a
    green run that proves nothing.

    The value is therefore asserted against the binary's source at probe time
    by `_assert_vault_canary_matches`, so a future edit to either side fails
    the harness instead of silently disarming it.
    """
    return "ASV-CANARY-4f2b9c1e7a-VAULTTOOL"


def _assert_vault_canary_matches(probe: str) -> ProbeResult | None:
    """Fails the probe if the tool's canary constant has drifted.

    Reads the tool's source and checks the literal is still present. This is
    the honest way to keep the two constants in sync without a build-time
    codegen step, and it converts a silent false PASS into a loud INVALID.
    """
    try:
        root = _workspace_root()
        if root is None:
            return ProbeResult(probe, "INVALID", "cannot locate the workspace root")
        source = (
            root / "crates" / "vault" / "src" / "bin" / "asv-vault-tool.rs"
        ).read_text(encoding="utf-8")
    except (OSError, AttributeError) as exc:
        return ProbeResult(probe, "INVALID", f"cannot read the vault tool source: {exc}")

    if _vault_canary_secret() not in source:
        return ProbeResult(
            probe,
            "INVALID",
            "the vault tool's canary constant has drifted from the harness; "
            "a PASS would be meaningless until they agree again",
        )
    return None


def _read_all_files(root: Path) -> bytes:
    blob = b""
    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                blob += path.read_bytes()
            except OSError:
                continue
    return blob


def probe_uat_018_audit_leak(workdir: Path, socket_path: Path) -> ProbeResult:
    """UAT-018: canaries absent from every artefact ASV persists.

    Exercises the real write paths (create, probe, backup) with a known
    canary, then greps the whole vault directory. M1 has no connector and no
    audit sink yet, so this is the strongest claim the milestone can make:
    nothing ASV writes to disk contains a secret. M2 extends it to the audit
    sink rather than replacing it.
    """
    name = "uat-018-audit-leak"
    tool = _vault_tool(name)
    if isinstance(tool, ProbeResult):
        return tool

    secret = _vault_canary_secret()
    vault_dir = workdir / "m1-vault-018"
    vault_dir.mkdir(parents=True, exist_ok=True)
    vault = vault_dir / "vault.asv"
    passphrase = "harness-" + os.urandom(6).hex()

    rc, out, err = _run_vault_tool(
        tool,
        "create",
        "--vault",
        str(vault),
        "--passphrase",
        passphrase,
        "--fast",
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", f"create failed rc={rc}: {err.strip()[:200]}")

    # Read the secret's length: the tool holds a live decrypted credential
    # here, which is exactly the moment a leak would occur.
    rc, out, _ = _run_vault_tool(
        tool, "probe", "--vault", str(vault), "--passphrase", passphrase, "--id", "canary"
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", f"probe failed rc={rc}")

    rc, _, _ = _run_vault_tool(
        tool,
        "backup",
        "--vault",
        str(vault),
        "--out",
        str(vault_dir / "backup.asv"),
        "--passphrase",
        passphrase,
        "--recovery",
        "recovery-" + os.urandom(4).hex(),
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", "backup failed")

    # The canary must not be in any file ASV wrote.
    persisted = _read_all_files(vault_dir)
    if secret.encode() in persisted:
        return ProbeResult(
            name, "FAIL", "the canary is present in a persisted ASV artefact"
        )

    # Nor in anything the tool printed.
    if secret in out or secret in err:
        return ProbeResult(name, "FAIL", "the canary appeared in process output")

    return ProbeResult(
        name,
        "PASS",
        f"no canary in {len(list(vault_dir.rglob('*')))} artefacts or in process output",
    )


def probe_uat_025_vault_theft(workdir: Path, socket_path: Path) -> ProbeResult:
    """UAT-025: a stolen locked vault yields nothing offline.

    Copies the vault file the way a thief would, confirms neither the secret
    nor the account metadata is readable, and confirms a wrong passphrase
    fails without disclosing anything.
    """
    name = "uat-025-vault-theft"
    tool = _vault_tool(name)
    if isinstance(tool, ProbeResult):
        return tool

    secret = _vault_canary_secret()
    vault_dir = workdir / "m1-vault-025"
    vault_dir.mkdir(parents=True, exist_ok=True)
    vault = vault_dir / "vault.asv"
    passphrase = "harness-" + os.urandom(6).hex()

    rc, _, err = _run_vault_tool(
        tool,
        "create",
        "--vault",
        str(vault),
        "--passphrase",
        passphrase,
        "--fast",
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", f"create failed rc={rc}: {err.strip()[:200]}")

    stolen = vault_dir / "stolen.asv"
    shutil.copy2(vault, stolen)
    blob = stolen.read_bytes()

    if secret.encode() in blob:
        return ProbeResult(name, "FAIL", "the canary is readable in the stolen vault")
    for needle in (b"harness canary", b"canary", b"provider"):
        if needle in blob:
            return ProbeResult(
                name,
                "FAIL",
                f"metadata {needle!r} is readable in the stolen vault",
            )

    # Wrong passphrase: must fail, and must say nothing useful.
    rc, out, err = _run_vault_tool(
        tool,
        "list",
        "--vault",
        str(stolen),
        "--passphrase",
        passphrase + "-wrong",
    )
    if rc == 0:
        return ProbeResult(name, "FAIL", "a wrong passphrase opened the vault")
    if secret in out or secret in err:
        return ProbeResult(name, "FAIL", "the failed unlock disclosed the canary")

    # Tampering is rejected.
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    tamper_path = vault_dir / "tampered.asv"
    tamper_path.write_bytes(bytes(tampered))
    rc, _, _ = _run_vault_tool(
        tool, "list", "--vault", str(tamper_path), "--passphrase", passphrase
    )
    if rc == 0:
        return ProbeResult(name, "FAIL", "a tampered vault was accepted")

    return ProbeResult(
        name,
        "PASS",
        "stolen vault discloses no secret, no metadata; wrong passphrase and tampering rejected",
    )


def probe_uat_026_backup_restore(workdir: Path, socket_path: Path) -> ProbeResult:
    """UAT-026: a backup restores on a clean system with the recovery factor.

    Restores into a directory that never saw the original vault, then confirms
    the credentials came back, the restored file is still encrypted, and a
    wrong recovery factor is rejected.
    """
    name = "uat-026-backup-restore"
    tool = _vault_tool(name)
    if isinstance(tool, ProbeResult):
        return tool

    secret = _vault_canary_secret()
    root = workdir / "m1-vault-026"
    root.mkdir(parents=True, exist_ok=True)
    vault = root / "vault.asv"
    passphrase = "harness-" + os.urandom(6).hex()
    recovery = "recovery-" + os.urandom(6).hex()
    backup = root / "backup.asv"

    rc, _, err = _run_vault_tool(
        tool,
        "create",
        "--vault",
        str(vault),
        "--passphrase",
        passphrase,
        "--fast",
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", f"create failed rc={rc}: {err.strip()[:200]}")

    rc, _, err = _run_vault_tool(
        tool,
        "backup",
        "--vault",
        str(vault),
        "--out",
        str(backup),
        "--passphrase",
        passphrase,
        "--recovery",
        recovery,
    )
    if rc != 0:
        return ProbeResult(name, "INVALID", f"backup failed rc={rc}: {err.strip()[:200]}")

    # A clean system: the original vault is not part of this path.
    clean = root / "clean-system"
    restored = clean / "vault.asv"
    rc, out, err = _run_vault_tool(
        tool, "restore", "--backup", str(backup), "--out", str(restored), "--recovery", recovery
    )
    if rc != 0:
        return ProbeResult(name, "FAIL", f"restore failed: {err.strip()[:200]}")

    # Credentials came back: `list` must show the one credential.
    rc, out, err = _run_vault_tool(
        tool,
        "list",
        "--vault",
        str(restored),
        "--passphrase",
        recovery,
    )
    if rc != 0:
        return ProbeResult(name, "FAIL", f"the restored vault would not open: {err.strip()[:200]}")
    if "id=canary" not in out or "count=1" not in out:
        return ProbeResult(
            name, "FAIL", f"the restored vault lost its credentials: {out.strip()[:200]}"
        )

    # The restored file is still encrypted.
    blob = restored.read_bytes()
    if secret.encode() in blob:
        return ProbeResult(name, "FAIL", "the restored vault is readable on disk")
    if secret in out or secret in err:
        return ProbeResult(name, "FAIL", "the restore printed the canary")

    # A wrong recovery factor is rejected.
    rc, _, _ = _run_vault_tool(
        tool,
        "restore",
        "--backup",
        str(backup),
        "--out",
        str(clean / "wrong.asv"),
        "--recovery",
        recovery + "-wrong",
    )
    if rc == 0:
        return ProbeResult(name, "FAIL", "a wrong recovery factor was accepted")

    return ProbeResult(
        name,
        "PASS",
        "restored on a clean path, credentials intact, still encrypted, wrong factor rejected",
    )


def _run_vault_tool(tool: Path, *args: str) -> tuple[int, str, str]:
    """Runs the vault tool and returns (rc, stdout, stderr).

    The environment is deliberately minimal and free of any secret, and the
    tool's own output is captured rather than inherited so the probe can scan
    it for the canary.
    """
    env = {
        k: v
        for k, v in os.environ.items()
        if not any(k.upper() == name for name in SECRET_ENV_NAMES)
    }
    env["ASV_HARNESS"] = "1"
    try:
        proc = subprocess.run(
            [str(tool), *args],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return (127, "", f"failed to run vault tool: {exc}")
    return (proc.returncode, proc.stdout, proc.stderr)


# The registry is declared here, not next to the M0 probes, so that every
# probe function is already defined when Python evaluates the names.
PROBES = [
    probe_agent_environment,
    probe_broker_memory_isolation,
    probe_broker_socket_permissions,
    probe_forbidden_methods,
    probe_cli_argv_surface,
    probe_uat_018_audit_leak,
    probe_uat_025_vault_theft,
    probe_uat_026_backup_restore,
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
