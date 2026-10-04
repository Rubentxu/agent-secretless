#!/usr/bin/env python3
"""C2.8 — a real workload through the real relay, with the real client.

`15-ROADMAP.md` owes this block one measurement it has not made: whether the
multi-request loop carries a *build* rather than three `GET`s. Every other number
in this block came from a harness, and a harness that scripts three requests on
one connection cannot tell a relay that survives `npm` from one that survives a
test.

    npm  ->  asv shim  ->  asv-brokerd  ->  local origin (independent witness)

Every process is real. `npm` is the npm on this machine and has never heard of
Agent Secretless; it is handed a registry URL and an `HTTPS_PROXY` and nothing
else. The broker is the shipped binary with a real vault, route and policy. The
origin is a process this script starts, and it is the *witness*: it decides
whether the bytes it was handed are the real credential or the surrogate, which
is the only vantage point from which that question has an answer.

## Why the registry is local, and what that costs

The broker dials its upstream with a plain `TcpStream`
(`crates/broker/src/tls_bridge.rs`, `serve_connect`), so the leg from the broker
to the destination is **cleartext**. A real `registry.npmjs.org` speaks TLS only,
so pointing this at the real registry would fail at the first byte for a reason
that has nothing to do with the loop. That is a finding about the product, not
about this script, and it is the reason the registry here is a local one.

The cost is stated rather than hidden: this measures the relay against a local
origin serving a synthetic dependency tree, not against npm's own registry. The
client is real and the workload is real — hundreds of requests, connection
reuse, a chunked response, multi-megabyte transfer — and the claim it supports
is scoped to that.

The synthetic tree is a top-level package depending on `LEAVES` independent
leaves, so `npm` fetches one packument and one tarball per leaf. `LEAVES` is 120
on purpose: the workload measured against the real registry was 93 requests and
2.1 MiB, and a tree smaller than the one that broke two of this block's limits
would not be worth running.

Run from the repository root:

    python3 tests/connect_workload_e2e.py
    python3 tests/connect_workload_e2e.py --leaves 300 --keep

`--keep` leaves the working directory in place and prints its path.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import io
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 300

# The credential the operator planted, and the only one the destination may see.
# Shaped like the canary the vertical uses: a prefix a client would send and a
# body no registry would ever issue, so "it came from us" is not a coincidence.
REAL = "npm_ASVcanaryWorkload7f1a9b3c5e8f0a2b4d6c8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f"
CREDENTIAL_LABEL = "workload-token"
REGISTRY_HOST = "localhost.localdomain"

# Roughly 18 KiB per tarball, incompressible and deterministic, so the transfer
# is comparable in size to the real 2.1 MiB measurement rather than a rounding
# error above zero.
FILLER_BYTES = 18_000


def find_binaries() -> tuple[Path, Path, Path]:
    """The shipped `asv`, `asv-brokerd` and `asv-vault-tool`, built.

    Built rather than assumed: a driver that silently measured a stale binary
    would report numbers for code that is not the code in the tree.

    `asv-vault-tool` is here to create a vault at a chosen path. The CLI's own
    `asv setup` would also create one, but it does it in the standard layout and
    then calls `systemctl --user` — so pointing this driver at it would install
    and start a unit in the operator's real session to measure a relay. The tool
    exists for exactly this and takes the path as an argument.
    """
    target = os.environ.get("CARGO_TARGET_DIR")
    candidates = [Path(target)] if target else []
    candidates += [Path(os.environ.get("HOME", "/")) / "cargo-targets", ROOT / "target"]
    needed = ("asv", "asv-brokerd", "asv-vault-tool")
    for base in candidates:
        if all((base / "debug" / n).exists() for n in needed):
            return tuple(base / "debug" / n for n in needed)  # type: ignore[return-value]
    raise SystemExit(
        "asv, asv-brokerd and asv-vault-tool are not built. Run:\n"
        "  cargo build --workspace\n"
        "and point CARGO_TARGET_DIR at the result if it is not ./target."
    )


# ---------------------------------------------------------------------------
# The origin: a registry, and the witness
# ---------------------------------------------------------------------------


class Witness:
    """What the destination actually received.

    Counts are the measurement. `credential_requests` and `surrogate_requests`
    are the security property, and they are counted here rather than inferred
    from the broker's own log, because a log written by the thing under test is
    not an independent witness of what the thing under test sent.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests = 0
        self.connections = 0
        self.credential_requests = 0
        self.surrogate_requests = 0
        self.unauthenticated_requests = 0
        self.tarball_bytes = 0
        self.packument_bytes = 0
        self.paths: list[str] = []

    def record(self, path: str, header: str | None) -> None:
        with self.lock:
            self.requests += 1
            self.paths.append(path)
            if header is None:
                self.unauthenticated_requests += 1
            elif REAL in header:
                self.credential_requests += 1
            else:
                self.surrogate_requests += 1

    def connection(self) -> None:
        with self.lock:
            self.connections += 1

    def add_bytes(self, packument: bool, n: int) -> None:
        with self.lock:
            if packument:
                self.packument_bytes += n
            else:
                self.tarball_bytes += n


@lru_cache(maxsize=None)
def build_tarball(name: str, size: int) -> bytes:
    """A real `.tgz` for one leaf, deterministic across runs.

    Cached because npm fetches each tarball more than once — it retries a
    mismatch, and a registry that served different bytes for the same version on
    the second request would be measuring npm's retry logic rather than the
    relay.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        payload = json.dumps(
            {"name": name, "version": "1.0.0", "main": "index.js"}, indent=2
        ).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(payload)
        info.mtime = 0
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(payload))

        entry = tarfile.TarInfo("package/index.js")
        entry.size = len(payload)
        entry.mtime = 0
        entry.mode = 0o644
        tar.addfile(entry, io.BytesIO(payload))

        # The filler is what makes the workload a workload. Seeded so two runs
        # transfer the same bytes, and drawn from a PRNG so the compressor cannot
        # shrink it to a header.
        filler = random.Random(0xC0FFEE).randbytes(size)
        big = tarfile.TarInfo("package/data.bin")
        big.size = len(filler)
        big.mtime = 0
        big.mode = 0o644
        tar.addfile(big, io.BytesIO(filler))
    return buf.getvalue()


def packument(name: str, leaves: int, port: int, chunked: bool) -> bytes:
    """The metadata `npm` asks for first.

    `dist.tarball` points back at *this* origin, so the tarballs travel through
    the tunnel as well. A registry whose tarball URLs pointed somewhere else
    would measure a packument and nothing else.
    """
    body: dict = {
        "name": name,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": f"https://{REGISTRY_HOST}:{port}/{name}-1.0.0.tgz",
                    # The real digest of the real bytes. `shasum: "0"*40` was
                    # the first version and npm refused every tarball with
                    # EINTEGRITY after retrying each one — a fixture that turns
                    # a correct relay into a wall of integrity errors and makes
                    # the noise look like the product.
                    "shasum": hashlib.sha1(build_tarball(name, FILLER_BYTES)).hexdigest(),
                    "integrity": "sha1-"
                    + base64.b64encode(
                        hashlib.sha1(build_tarball(name, FILLER_BYTES)).digest()
                    ).decode(),
                },
            }
        },
    }
    if leaves:
        body["versions"]["1.0.0"]["dependencies"] = {
            f"asv-leaf-{i}": "1.0.0" for i in range(leaves)
        }
    del chunked  # the flag is about transport, not metadata
    return json.dumps(body).encode()


class Registry(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    witness: Witness
    leaves: int
    port: int
    chunked_root: bool

    def log_message(self, *_args) -> None:  # noqa: D102 - silence the default
        pass

    def setup(self) -> None:
        super().setup()
        # `http.server` calls this once per accepted socket, which is the only
        # place a tunnel is observable from this side: after the CONNECT there
        # is no protocol left that names it.
        self.witness.connection()

    def _send(self, status: int, body: bytes, content_type: str, chunked: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if chunked:
            # No Content-Length and no close: the body is framed by chunks. This
            # is the framing `relay_chunked` exists for, on a real client's path
            # rather than a scripted one.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            step = 4096
            for at in range(0, len(body), step):
                piece = body[at : at + step]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802 - http.server's spelling
        path = self.path.split("?", 1)[0].lstrip("/")
        self.witness.record(path, self.headers.get("Authorization"))

        if path == "asv-workload":
            body = packument(path, self.leaves, self.port, self.chunked_root)
            # The root packument is the one served chunked, and it is also the
            # biggest: it names every leaf, so it is the response most likely to
            # cross a budget.
            self._send(200, body, "application/json", chunked=True)
            self.witness.add_bytes(True, len(body))
            return

        if path.endswith("-1.0.0.tgz"):
            # Any versioned tarball, not only the leaves': npm fetches the root
            # package's tarball too, and a registry that 404s it turns a
            # complete install into a failure that has nothing to do with the
            # relay.
            name = path[: -len("-1.0.0.tgz")]
            body = build_tarball(name, FILLER_BYTES)
            self._send(200, body, "application/octet-stream", chunked=False)
            self.witness.add_bytes(False, len(body))
            return

        if path.startswith("asv-leaf-"):
            body = packument(path, 0, self.port, False)
            self._send(200, body, "application/json", chunked=False)
            self.witness.add_bytes(True, len(body))
            return

        self._send(404, b'{"error":"not found"}', "application/json", chunked=False)

    def do_POST(self) -> None:  # noqa: N802
        # `npm` posts the audit bulk endpoint. Answering it keeps the run about
        # the registry and not about an audit request this measurement does not
        # care about; the flag `--no-audit` also asks for it not to be sent.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.witness.record(self.path, self.headers.get("Authorization"))
        self._send(200, b"{}", "application/json", chunked=False)


def start_origin(witness: Witness, leaves: int, chunked_root: bool) -> tuple[int, threading.Thread]:
    """Bind the registry on an ephemeral port and serve it on a thread."""
    probe = socket.socket(socket.AF_INET6)
    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    probe.bind(("::1", 0))
    port = probe.getsockname()[1]
    probe.close()

    handler = type(
        "BoundRegistry",
        (Registry,),
        {"witness": witness, "leaves": leaves, "port": port, "chunked_root": chunked_root},
    )
    class DualStack(http.server.ThreadingHTTPServer):
        """Loopback on both families.

        `localhost.localdomain` resolves to `::1` on this host, and a route is
        required to name a *host* rather than a literal address so the broker can
        pin it — so the origin is bound dual-stack rather than to whichever
        family the resolver happens to prefer first.
        """

        address_family = socket.AF_INET6
        allow_reuse_address = True

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    server = DualStack(("::1", port), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, thread


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, **kw)


def strip_ansi(text: str) -> str:
    """Remove CSI escape sequences.

    Stripped rather than worked around, and for the reason the Rust vertical
    gives: `tracing_subscriber` colourises whether or not a terminal is attached,
    so a parser that only matches on plain text reports "no address" on half the
    machines it runs on.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def connect_address_from_log(log: Path) -> str:
    """The address the broker published, read from its own log.

    Read from the log rather than from a port this script chose, because the
    listener is `--connect-listen 127.0.0.1:0` and the number the broker tells
    the world is the one the world will use.
    """
    deadline = time.time() + 30
    while time.time() < deadline:
        if log.exists():
            for line in strip_ansi(log.read_text(errors="replace")).splitlines():
                if "bound=" in line:
                    addr = line.split("bound=", 1)[1].split()[0].strip()
                    if re.fullmatch(r"127\.0\.0\.1:\d+", addr):
                        return addr
        time.sleep(0.1)
    raise SystemExit(f"the broker never published a connect address; log:\n{log.read_text()[-2000:]}")


def build_fixture(bin_dir: Path, work: Path, port: int) -> tuple[Path, Path, str]:
    """Vault, enrolled principal, one credential, a route and a policy.

    Two broker runs, for the reason the vertical's fixture gives and which is
    still true: a route names a credential by the id the *product* minted, and
    the broker reads its inventory at startup, so a credential added to a running
    broker is a credential the running broker has never heard of.
    The vault comes from `asv-vault-tool create`, which also plants a canary of
    its own. That does not collide with the credential below: the broker skips
    non-canonical ids when it loads a route, which is the right behaviour and is
    why this driver cannot invent an id and write a route against it.
    """
    asv, brokerd, vault_tool = bin_dir / "asv", bin_dir / "asv-brokerd", bin_dir / "asv-vault-tool"
    vault = work / "vault.asv"
    passphrase = work / "passphrase.txt"
    sock = work / "broker.sock"

    value = "workload-passphrase"
    passphrase.write_text(f"{value}\n")
    created = run([str(vault_tool), "create", "--vault", str(vault),
                   "--passphrase", value, "--fast"])
    if created.returncode != 0:
        raise SystemExit(f"could not create a vault:\n{created.stderr}")

    enrolled = run([str(brokerd), "--vault", str(vault), "--enrol-principal", str(asv)])
    if not enrolled.returncode == 0:
        raise SystemExit(f"enrolment failed:\n{enrolled.stderr}")

    plant = subprocess.Popen(
        [str(brokerd), str(sock), "--vault", str(vault), "--passphrase-file", str(passphrase)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 30
    while not sock.exists() and time.time() < deadline:
        time.sleep(0.05)
    if not sock.exists():
        plant.kill()
        raise SystemExit("the planting broker never created its socket")

    add = subprocess.run(
        [str(asv), "--socket", str(sock), "add-credential",
         "--label", CREDENTIAL_LABEL, "--kind", "bearer_token",
         "--provider", "github", "--account", "workload"],
        input=REAL + "\n", capture_output=True, text=True, timeout=TIMEOUT,
    )
    plant.terminate()
    plant.wait(timeout=30)
    if add.returncode != 0:
        raise SystemExit(f"add-credential failed:\n{add.stderr}")
    credential_id = add.stdout.split()[1]
    sock.unlink(missing_ok=True)
    return vault, passphrase, credential_id


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--leaves", type=int, default=120)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--diagnose", action="store_true",
                    help="ask the session what the child actually sees, then stop")
    ap.add_argument("--no-chunked-root", action="store_true")
    args = ap.parse_args()

    asv, brokerd, _vault_tool = find_binaries()
    work = ROOT / "target" / f"asv-workload-{os.getpid()}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    witness = Witness()
    port, _ = start_origin(witness, args.leaves, not args.no_chunked_root)
    print(f"[origin] local npm registry on {REGISTRY_HOST}:{port}, {args.leaves} leaves")

    vault, passphrase, credential_id = build_fixture(brokerd.parent, work, port)
    print(f"[vault] credential {credential_id} planted")

    routes = work / "routes.json"
    routes.write_text(json.dumps([{
        "authority": REGISTRY_HOST,
        "port": port,
        "operation_family": "git_hub",
        "credential": credential_id,
        "minimum_posture": "STRONG_SECRETLESS",
        # C2.8: how the broker reaches this destination. Required, and named
        # rather than defaulted, because the credential crosses this leg and
        # "the default happens to be cleartext" is not a decision anyone made.
        "upstream": "cleartext",
    }]))
    policy = work / "policy.cedar"
    policy.write_text(
        'permit (principal, action == Action::"github_issue_read", resource is Api);\n'
        f'permit (principal, action == Action::"connect_route", '
        f'resource == Host::"host:{REGISTRY_HOST}");\n'
    )

    log = work / "broker.log"
    errlog = work / "broker.err"
    audit = work / "audit.jsonl"
    sock = work / "broker.sock"
    broker = subprocess.Popen(
        [str(brokerd), str(sock), "--vault", str(vault),
         "--passphrase-file", str(passphrase),
         "--connect-listen", "127.0.0.1:0",
         "--connect-routes", str(routes), "--policy", str(policy),
         "--audit-file", str(audit)],
        stdout=open(log, "w"), stderr=open(errlog, "w"),
    )

    project = work / "project"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({
        "name": "workload", "version": "1.0.0", "private": True,
        "dependencies": {"asv-workload": "1.0.0"},
    }))

    # The credential adapter, in the one form npm understands. npm expands
    # `${VAR}` in its own config, so this file names the *environment variable*
    # and never the value: the child reads a surrogate out of the session it was
    # handed, exactly as an M14 adapter would, and nothing here teaches npm
    # anything about Agent Secretless.
    #
    # Without it the relay refuses with `request carries no bearer credential`,
    # which is the correct refusal — a CONNECT carrying no credential is a
    # tunnel with nothing to substitute, and the broker does not invent one.
    env_name = "ASV_SURROGATE_" + "".join(
        c.upper() if c.isalnum() else "_" for c in CREDENTIAL_LABEL
    )
    # npm scopes a registry credential by a key that begins with a **double**
    # slash, and one slash is silently a different key: the first version of
    # this wrote `/host:port/` and npm read it back verbatim, expanded the
    # token correctly, and sent no `Authorization` at all. Written as
    # `'/' * 2` so the shape is visible in review rather than something a
    # reader has to count.
    scope = f"{'/' * 2}{REGISTRY_HOST}:{port}/"
    (project / ".npmrc").write_text(
        f"registry=https://{REGISTRY_HOST}:{port}/\n"
        f"{scope}:_authToken=${{{env_name}}}\n"
    )

    try:
        listen = connect_address_from_log(log)
        print(f"[broker] connect listener on {listen}")

        if args.diagnose:
            # What the child can actually see, asked from inside the session.
            # A driver that cannot tell "the shim did not export the surrogate"
            # from "npm would not use it" would report a relay refusal for a
            # credential-wiring problem, which is the one failure this whole
            # measurement is most likely to have.
            script = (
                f"cd {project} && "
                "echo '--- surrogate in env ---'; "
                "env | grep -i surrogate || echo NONE; "
                "echo '--- npmrc ---'; cat .npmrc; "
                "echo '--- npm sees ---'; "
                f"npm config list 2>&1 | grep -iE 'token|registry|proxy' | head -8"
            )
        else:
            script = (
                f"cd {project} && "
                # The registry is https, so npm sends a CONNECT and the broker
                # terminates TLS with a session leaf. The leaf's trust is not what
                # this measurement is about, and the child is an ordinary client that
                # was told nothing, so the check is relaxed rather than taught about
                # ASV's CA — `--strict-ssl=false` is npm's `curl -k`, which is what
                # the Rust vertical uses for the same reason.
                #
                # `NODE_TLS_REJECT_UNAUTHORIZED=0` was tried first and does not work
                # here: npm passes `rejectUnauthorized` explicitly, so the config
                # flag overrides the environment and the handshake still fails with
                # UNABLE_TO_GET_ISSUER_CERT_LOCALLY.
                f"npm install --registry https://{REGISTRY_HOST}:{port}/ "
                "--strict-ssl=false --no-audit --no-fund --loglevel=http --maxsockets=4"
            )
        print(f"[run] {script}")
        started = time.time()
        done = run([str(asv), "--socket", str(sock), "run", "sh", "-c", script], cwd=work)
        elapsed = time.time() - started

        installed = (project / "node_modules" / "asv-workload").exists()
        # **A cross-check, not a second count.** Only a tunnel that *finishes*
        # logs its request total, and a tunnel still open when the session ends
        # is revoked rather than closed politely, so this number is legitimately
        # below what the origin saw — 199 against 242 in one run, and 242 in
        # another. Reading the gap as a discrepancy is reading the revocation
        # path as a lost log line, so it is reported with its own name and
        # checked as an upper bound. The origin is the witness: it counts what it
        # was handed, and nothing the broker says about itself can move it.
        finished = 0
        for line in strip_ansi(log.read_text(errors="replace")).splitlines():
            if "requests=" in line and "relayed" in line:
                m = re.search(r"requests=(\d+)", line)
                if m:
                    finished += int(m.group(1))

        report = {
            "npm exit": done.returncode,
            "installed asv-workload": installed,
            "seconds": round(elapsed, 1),
            "origin requests": witness.requests,
            "origin connections (tunnels)": witness.connections,
            "requests per tunnel": round(witness.requests / max(witness.connections, 1), 2),
            "credential reached the destination": witness.credential_requests,
            "surrogate reached the destination": witness.surrogate_requests,
            "requests with no Authorization": witness.unauthenticated_requests,
            "packument bytes": witness.packument_bytes,
            "tarball bytes": witness.tarball_bytes,
            "total bytes": witness.packument_bytes + witness.tarball_bytes,
            "requests in tunnels the broker logged as finished": finished,
        }
        width = max(len(k) for k in report)
        print("\n=== measurement ===")
        for key, value in report.items():
            print(f"{key:<{width}}  {value}")
        if done.returncode != 0 or args.diagnose:
            print("\n--- child stdout ---\n" + done.stdout[-3000:])
            print("\n--- child stderr ---\n" + done.stderr[-3000:])
        if done.returncode != 0:
            print("\n--- broker log tail ---\n" + log.read_text()[-2000:])

        if args.diagnose:
            # The diagnosis is the product of this mode, not a verdict about the
            # relay: it answers what the child can see, which is a wiring
            # question, and the run it describes never made a request.
            return 0

        failures = []
        if done.returncode != 0:
            failures.append(f"npm exited {done.returncode}")
        if not installed:
            failures.append("the install did not produce node_modules/asv-workload")
        if witness.requests < 93:
            failures.append(
                f"only {witness.requests} requests reached the origin; the workload this "
                f"block measured against the real registry was 93, so this run did not "
                f"exercise more of the relay than the harness already did"
            )
        if witness.surrogate_requests:
            failures.append(
                f"{witness.surrogate_requests} requests carried a surrogate to the "
                f"destination"
            )
        if witness.requests and witness.credential_requests != witness.requests:
            failures.append(
                f"{witness.requests - witness.credential_requests} of {witness.requests} "
                f"requests did not carry the real credential"
            )
        if witness.connections < 1:
            failures.append("no tunnel was ever established")
        if finished > witness.requests:
            failures.append(
                f"the broker logged {finished} requests across tunnels that finished, "
                f"which is more than the {witness.requests} the destination was actually "
                f"handed, so a relayed line counts something that did not happen"
            )

        print()
        if failures:
            for f in failures:
                print(f"FAIL  {f}")
            return 1
        print(
            f"PASS  {witness.requests} requests over {witness.connections} tunnel(s), "
            f"{witness.requests / max(witness.connections, 1):.1f} per tunnel; the real "
            f"credential reached the destination on every one and no surrogate ever did"
        )
        return 0
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=20)
        except subprocess.TimeoutExpired:
            broker.kill()
        if args.keep:
            print(f"\n[keep] {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
