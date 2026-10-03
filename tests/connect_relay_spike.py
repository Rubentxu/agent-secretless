#!/usr/bin/env python3
"""C2.5-S2 — can an opaque relay inject the proof without breaking reuse?

C2.5-S1 measured who can *carry* `x-asv-session-proof` on a CONNECT and found
exactly one client that can, which is why the architecture is a session-local
shim rather than a portable header. That decision still had one unmeasured
premise, and it is the premise the whole design rests on:

    the shim can inject the header and then stop being a protocol participant.

A shim is only cheap if, after `200 Connection Established`, it can become a
blind byte pipe. It can only be that if injecting a header into the pre-200
conversation does not disturb the post-200 tunnel — and, harder, if the reuse
that an ordinary client performs *inside* that tunnel survives being relayed by
something that cannot read it.

This measures both, over real TLS, with a real CONNECT listener that refuses
connections without the proof. Nothing here is simulated: the broker
terminates TLS, the origin is a separate process-socket speaking HTTP, and the
client is the ordinary `curl` an agent would run.

The failure being measured is an architectural failure. If the blind relay
breaks reuse, the shim needs to terminate TLS and re-originate, which drags
the broker's entire trust boundary down into the session directory and is a
very different design with very different risk.

The rows are arranged so the interesting direction is falsifiable: a relay
that *preserves* reuse falsifies "the blind relay breaks keep-alive", and the
control row — shim present, header deliberately not injected — falsifies "the
proof gate is real" if it is ever allowed to succeed.

Re-run with `--verbose` to print every captured CONNECT head verbatim.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = Path("/tmp/c2s2")
HEADER_NAME = "x-asv-session-proof"
HEADER_VALUE = "ASV-RELAY-PROOF-7c1e4b90"
CERT = WORK / "cert.pem"
KEY = WORK / "key.pem"
TIMEOUT = 20.0
VERBOSE = "--verbose" in sys.argv


# --------------------------------------------------------------------------
# certificate
# --------------------------------------------------------------------------

def ensure_cert() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(KEY), "-out", str(CERT),
            "-days", "2", "-nodes", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )


def server_tls() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    return ctx


def client_tls() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# --------------------------------------------------------------------------
# counters — the whole point is counting, so they are explicit and thread-safe
# --------------------------------------------------------------------------

@dataclass
class Counters:
    lock: threading.Lock = field(default_factory=threading.Lock)
    origin_requests: int = 0
    origin_connections: int = 0
    broker_connects: int = 0
    broker_tls_sessions: int = 0
    broker_refusals: int = 0
    shim_client_conns: int = 0
    shim_upstream_conns: int = 0
    shim_client_connect_heads: int = 0
    heads: list[str] = field(default_factory=list)

    def bump(self, name: str, by: int = 1) -> None:
        with self.lock:
            setattr(self, name, getattr(self, name) + by)

    def note(self, head: str) -> None:
        with self.lock:
            self.heads.append(head)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {
                "origin_requests": self.origin_requests,
                "origin_connections": self.origin_connections,
                "broker_connects": self.broker_connects,
                "broker_tls_sessions": self.broker_tls_sessions,
                "broker_refusals": self.broker_refusals,
                "shim_client_conns": self.shim_client_conns,
                "shim_upstream_conns": self.shim_upstream_conns,
                "shim_client_connect_heads": self.shim_client_connect_heads,
            }


# --------------------------------------------------------------------------
# origin — a real TLS server speaking HTTP/1.1, counting what it is asked for
# --------------------------------------------------------------------------

def read_head(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 16384:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def serve_origin(ctx: Counters, srv: socket.socket) -> None:
    """Plain HTTP origin.

    Plain on purpose. The broker terminates TLS and then talks to the
    upstream, so the upstream is plaintext — which is also the shape the real
    broker has. Hand-rolling a second TLS hop plus request/response body
    parsing inside the harness put two bugs between the table and the thing
    the table is about, and both showed up as failures of the *shim*.
    """
    while True:
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=_origin_conn, args=(ctx, raw), daemon=True).start()


def _origin_conn(ctx: Counters, sock: socket.socket) -> None:
    ctx.bump("origin_connections")
    try:
        sock.settimeout(TIMEOUT)
        while True:
            head = read_head(sock)
            if not head:
                return
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            ctx.bump("origin_requests")
            if VERBOSE:
                print(f"   origin <- {line}")
            body = f"origin-saw: {line}\n".encode()
            sock.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: keep-alive\r\n\r\n"
                + body
            )
    except OSError:
        return
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# broker stand-in — a real CONNECT listener with a real proof gate
# --------------------------------------------------------------------------

def serve_broker(ctx: Counters, srv: socket.socket, origin_port: int) -> None:
    tls_ctx = server_tls()
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        ctx.bump("broker_connects")
        threading.Thread(
            target=_broker_conn, args=(ctx, conn, origin_port, tls_ctx), daemon=True
        ).start()


def _broker_conn(
    ctx: Counters, conn: socket.socket, origin_port: int, tls_ctx: ssl.SSLContext
) -> None:
    try:
        conn.settimeout(TIMEOUT)
        head = read_head(conn)
        text = head.decode("latin-1")
        ctx.note(text)
        if not head.startswith(b"CONNECT "):
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        # The gate. This is the control the rest of the table is read against.
        if HEADER_NAME not in text.lower():
            ctx.bump("broker_refusals")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tls = tls_ctx.wrap_socket(conn, server_side=True)
    except (OSError, ssl.SSLError):
        conn.close()
        return

    ctx.bump("broker_tls_sessions")
    if VERBOSE:
        print(f"   broker: TLS session {ctx.snapshot()['broker_tls_sessions']} open")
    try:
        # Terminate, then stop being a protocol participant — the same shape
        # the shim has above it. No HTTP parsing in the broker, so nothing in
        # the measurement can be a broker parsing bug.
        upstream = socket.create_connection(("127.0.0.1", origin_port), timeout=TIMEOUT)
        _relay(tls, upstream)
    except (OSError, ssl.SSLError):
        return
    finally:
        try:
            tls.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# the candidate: session-local shim, blind after 200
# --------------------------------------------------------------------------

def serve_shim(
    ctx: Counters, srv: socket.socket, broker_port: int, inject: bool
) -> None:
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        ctx.bump("shim_client_conns")
        threading.Thread(
            target=_shim_conn, args=(ctx, conn, broker_port, inject), daemon=True
        ).start()


def _shim_conn(
    ctx: Counters, conn: socket.socket, broker_port: int, inject: bool
) -> None:
    try:
        conn.settimeout(TIMEOUT)
        head = read_head(conn)
        if not head.startswith(b"CONNECT "):
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        ctx.bump("shim_client_connect_heads")
        # The only thing the shim knows about the protocol.
        if inject and b"\r\n" in head:
            head = head[:-2] + f"{HEADER_NAME}: {HEADER_VALUE}\r\n".encode() + b"\r\n"
        up = socket.create_connection(("127.0.0.1", broker_port), timeout=TIMEOUT)
        ctx.bump("shim_upstream_conns")
        up.settimeout(TIMEOUT)
        up.sendall(head)
        response = read_head(up)
        conn.sendall(response)
        if not response.startswith(b"HTTP/1.1 200"):
            up.close()
            return
        # From here the shim knows nothing and relays bytes.
        _relay(conn, up)
    except OSError:
        return
    finally:
        for sock in (conn,):
            try:
                sock.close()
            except OSError:
                pass


def _relay(a: socket.socket, b: socket.socket) -> None:
    done = threading.Event()

    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            done.set()

    threads = [
        threading.Thread(target=pump, args=(a, b), daemon=True),
        threading.Thread(target=pump, args=(b, a), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=TIMEOUT)
    b.close()


# --------------------------------------------------------------------------
# client — ordinary curl, the way an agent runs it
# --------------------------------------------------------------------------

def run_curl(proxy_port: int, urls: list[str], label: str) -> tuple[bool, str]:
    # `-k` is not a convenience. Without it every row dies at certificate
    # verification, the origin is never reached, and the table reports "the
    # relay does not carry a tunnel" — a conclusion about the architecture
    # drawn from a harness that never let the tunnel open. The first run of
    # this spike was exactly that mistake, and the counter that gave it away
    # was `broker_tls_sessions`: six handshakes, zero origin requests.
    argv = [
        "curl", "-sS", "-k", "--max-time", "15",
        "--proxy", f"http://127.0.0.1:{proxy_port}",
        "-o", "/dev/null", "-w", "%{http_code} ",
    ]
    argv += urls
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30, cwd="/tmp")
        return True, (proc.stdout + proc.stderr).strip()[:200]
    except subprocess.TimeoutExpired:
        return False, f"[{label}] timed out"
    except FileNotFoundError:
        return False, "[no curl]"
    except OSError as exc:
        return False, f"[{label}] {exc}"


def listen() -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(1.0)
    return srv


def serve_forever(fn, *args) -> None:
    while True:
        fn(*args)


# --------------------------------------------------------------------------
# the table
# --------------------------------------------------------------------------

@dataclass
class Row:
    name: str
    question: str
    expected: str
    observed: str
    ok: bool
    note: str = ""


def main() -> int:
    ensure_cert()

    origin_srv, broker_srv, shim_srv = listen(), listen(), listen()
    origin_port = origin_srv.getsockname()[1]
    broker_port = broker_srv.getsockname()[1]
    shim_port = shim_srv.getsockname()[1]
    ctx = Counters()

    threading.Thread(target=serve_forever, args=(serve_origin, ctx, origin_srv), daemon=True).start()
    threading.Thread(target=serve_forever, args=(serve_broker, ctx, broker_srv, origin_port), daemon=True).start()
    threading.Thread(target=serve_forever, args=(serve_shim, ctx, shim_srv, broker_port, True), daemon=True).start()
    time.sleep(0.2)

    target = f"https://localhost:{origin_port}/"
    rows: list[Row] = []

    # --- control: no shim, no header. The proof gate must actually bite. ----
    before = ctx.snapshot()
    ran, note = run_curl(broker_port, [target], "direct")
    after = ctx.snapshot()
    refused = after["broker_refusals"] > before["broker_refusals"]
    rows.append(Row(
        "A. direct to broker, no proof",
        "is the gate real, or does anything get through?",
        "403, zero origin requests",
        "403" if refused else ("through!" if ran else "no attempt"),
        refused and after["origin_requests"] == before["origin_requests"],
        note if not refused else "",
    ))

    # --- the single-request baseline: does the blind relay work at all? ----
    before = ctx.snapshot()
    ran, note = run_curl(shim_port, [target], "one")
    after = ctx.snapshot()
    ok = ran and after["origin_requests"] == before["origin_requests"] + 1
    rows.append(Row(
        "B. shim, 1 request",
        "does an opaque relay carry a working tunnel at all?",
        "1 request reaches origin",
        f"{after['origin_requests'] - before['origin_requests']} request(s)",
        ok,
        note,
    ))

    # --- THE question: reuse *inside* the tunnel ----------------------------
    before = ctx.snapshot()
    ran, note = run_curl(shim_port, [target, target, target], "three")
    after = ctx.snapshot()
    delta_reqs = after["origin_requests"] - before["origin_requests"]
    delta_tls = after["broker_tls_sessions"] - before["broker_tls_sessions"]
    ok = ran and delta_reqs == 3 and delta_tls == 1
    rows.append(Row(
        "C. shim, 3 requests, 1 host",
        "does TLS keep-alive survive a relay that cannot read it?",
        "3 requests over 1 TLS session",
        f"{delta_reqs} request(s) over {delta_tls} TLS session(s)",
        ok,
        note,
    ))

    # --- does the client try to reuse the *client* socket for a 2nd CONNECT?
    before = ctx.snapshot()
    ran, note = run_curl(shim_port, [target, f"https://127.0.0.1:{origin_port}/"], "two")
    after = ctx.snapshot()
    d_client = after["shim_client_conns"] - before["shim_client_conns"]
    d_up = after["shim_upstream_conns"] - before["shim_upstream_conns"]
    d_heads = after["shim_client_connect_heads"] - before["shim_client_connect_heads"]
    # Informational, not pass/fail: the number the shim must be able to serve.
    rows.append(Row(
        "D. shim, 2 hosts",
        "does the client multiplex CONNECT on one client socket?",
        "informational",
        f"{d_client} client conn(s), {d_up} upstream, {d_heads} CONNECT head(s)",
        True,
        "shim must loop" if d_heads > d_client else "one CONNECT per socket",
    ))

    # --- and the shim with injection disabled: a second control -----------
    plain_srv = listen()
    plain_port = plain_srv.getsockname()[1]
    threading.Thread(
        target=serve_forever, args=(serve_shim, ctx, plain_srv, broker_port, False), daemon=True
    ).start()
    before = ctx.snapshot()
    ran, note = run_curl(plain_port, [target], "noinject")
    after = ctx.snapshot()
    ok = after["broker_refusals"] > before["broker_refusals"] and ran
    rows.append(Row(
        "E. shim, injection off",
        "is the header the shim adds actually load-bearing?",
        "403 through the shim too",
        "403" if ok else ("through!" if ran else "no attempt"),
        ok,
        note,
    ))
    plain_srv.close()

    print("C2.5-S2 — can an opaque relay inject the proof without breaking reuse?\n")
    print(f"{'row':<34} {'expectation':<38} {'observed'}")
    print("-" * 118)
    for row in rows:
        mark = "ok" if row.ok else "XX"
        print(f"{mark} {row.name:<31} {row.expected:<38} {row.observed}")
        if row.note:
            print(f"   {'':<31} {'':<38} {row.note[:60]}")
    if VERBOSE:
        print("\n--- every CONNECT head the broker saw ---")
        for head in ctx.heads:
            for line in head.splitlines():
                if line.strip():
                    print(f"   | {line}")

    counts = ctx.snapshot()
    print("\ntotals:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    failures = [r for r in rows if not r.ok]
    print()
    if failures:
        print(f"MEASUREMENT CONTRADICTED: {len(failures)} row(s) did not behave as the architecture assumes.")
        for row in failures:
            print(f"  - {row.name}: expected {row.expected}, observed {row.observed}")
        return 1
    print("The blind relay holds: a shim can inject the proof and become a byte pipe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
