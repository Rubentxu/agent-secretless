#!/usr/bin/env python3
"""C2.5-S1 — can an ordinary HTTP client carry a custom header on CONNECT?

The replay fix made the session proof single use. The next block needs some
real process to *produce* that proof, and the shape of that block turns on one
question nobody has measured: does `x-asv-session-proof` reach a CONNECT
request at all, on the clients an agent actually runs?

`HTTPS_PROXY` is not an answer on its own. Some clients let you add headers to
the proxy CONNECT, some let you add headers to the *origin* request — the wrong
place, because the broker never sees those — and some let you do neither.
Assuming portability here is how a design gets built on a capability that
turns out to exist on exactly one stack.

What this measures, per client, is one thing: **does our header appear on the
CONNECT head?** The table is the evidence, and it is falsifiable in the useful
direction: a client that *can* carry the header falsifies "we need a
session-local shim", which is the outcome the architecture would prefer.

Nothing here touches the network. Every client is pointed at a local listener
that reads the CONNECT head and closes. The failure being measured is a
capability failure, not a connection failure.

Re-run with `--verbose` to print every captured head verbatim.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER_NAME = "x-asv-session-proof"
HEADER_VALUE = "ASV-CANARY-3f9a17c2-PROOF"
TARGET = "asv.test:443"
VERBOSE = "--verbose" in sys.argv


@dataclass
class Capture:
    port: int
    head: str

    @property
    def carried(self) -> bool:
        """Case-insensitively.

        The first version compared the *uppercase* canary against a lowercased
        head, so it reported "no" for a header that was sitting right there in
        the captured bytes — the control row was the only thing that made the
        table look plausible. A detector that cannot see a positive is worse
        than no detector, because the conclusion it produces is the opposite of
        the truth and nothing about the output looks wrong.
        """
        low = self.head.lower()
        return HEADER_NAME.lower() in low and HEADER_VALUE.lower() in low


def open_listener() -> socket.socket:
    """Bind in the calling thread, so the port is known before anything runs."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(20)
    return srv


def capture(srv: socket.socket) -> str:
    """Accept one connection, read its head, close. Returns the raw text."""
    try:
        conn, _ = srv.accept()
    except (socket.timeout, OSError):
        return ""
    with conn:
        conn.settimeout(20)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
    return data.decode("utf-8", "replace")


def drive(argv: list[str], env: dict[str, str] | None = None) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=25, env=env, cwd="/tmp"
        )
        return True, (proc.stdout + proc.stderr).strip()[:300]
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except FileNotFoundError:
        return False, "client not installed"
    except OSError as exc:
        return False, f"could not run: {exc}"


def probe(name: str, argv_for, env_for=None) -> dict[str, object]:
    """One client, one fresh listener, one captured head."""
    srv = open_listener()
    port = srv.getsockname()[1]
    box: dict[str, str] = {}

    thread = threading.Thread(target=lambda: box.__setitem__("head", capture(srv)), daemon=True)
    thread.start()
    time.sleep(0.05)
    ran, note = drive(argv_for(port), env_for(port) if env_for else None)
    thread.join(timeout=25)
    srv.close()
    head = box.get("head", "")
    cap = Capture(port, head)
    return {"client": name, "carried": cap.carried, "head": head, "ran": ran, "note": note}


def base_env(port: int) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/tmp",
        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
        "https_proxy": f"http://127.0.0.1:{port}",
    }


def main() -> int:
    rows: list[dict[str, object]] = []

    # The positive case: curl's documented proxy-header mechanism.
    rows.append(probe(
        "curl --proxy-header",
        lambda p: [
            "curl", "-sS", "--max-time", "10",
            "--proxy-header", f"{HEADER_NAME}: {HEADER_VALUE}",
            "--proxy", f"http://127.0.0.1:{p}",
            f"https://{TARGET}/",
        ],
    ))

    # The control. If the canary appears here, the probe is measuring the
    # environment rather than the client and every other row is suspect.
    rows.append(probe(
        "curl (control, no flag)",
        lambda p: [
            "curl", "-sS", "--max-time", "10",
            "--proxy", f"http://127.0.0.1:{p}",
            f"https://{TARGET}/",
        ],
    ))

    rows.append(probe(
        "git (http.proxy)",
        lambda p: [
            "git", "-c", f"http.proxy=http://127.0.0.1:{p}",
            "-c", "http.sslVerify=false",
            "ls-remote", f"https://{TARGET}/repo.git",
        ],
    ))

    rows.append(probe(
        "npm (HTTPS_PROXY)",
        lambda p: [
            "npm", "view", "left-pad", "version",
            "--registry", f"https://{TARGET}/",
            "--fetch-timeout", "8000",
        ],
        env_for=base_env,
    ))

    # The JVM's proxy settings are a host:port pair and nothing else, but a
    # class that does not exist exits before opening a socket, so its absence
    # of a CONNECT is absence of evidence rather than evidence of absence.
    # A real program, run from source, actually attempts the connection.
    java_src = Path("/tmp/c2s1/Probe.java")
    if not java_src.exists():
        java_src.parent.mkdir(parents=True, exist_ok=True)
        java_src.write_text(
            "import java.net.*;\n"
            "public class Probe {\n"
            "  public static void main(String[] a) throws Exception {\n"
            "    try {\n"
            "      URLConnection c = new URL(\"https://asv.test:443/\").openConnection();\n"
            "      c.getInputStream();\n"
            "    } catch (Exception e) {\n"
            "      System.out.println(\"expected: \" + e.getClass().getSimpleName());\n"
            "    }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
    rows.append(probe(
        "java (-Dhttps.proxyHost)",
        lambda p: [
            "java",
            f"-Dhttps.proxyHost=127.0.0.1", f"-Dhttps.proxyPort={p}",
            "-Djavax.net.ssl.trustAll=true",
            "-Djava.net.preferIPv4Stack=true",
            str(java_src),
        ],
    ))

    print("C2.5-S1 — does x-asv-session-proof reach the CONNECT?\n")
    print(f"{'client':<28} {'header on CONNECT':<18} client ran")
    print("-" * 72)
    for row in rows:
        carried = row["carried"]
        mark = "YES" if carried else ("no" if carried is False else "n/a")
        ran = "yes" if row["ran"] else "no"
        print(f"{row['client']:<28} {mark:<18} {ran}")
        if not row["ran"] and row["note"]:
            print(f"{'':<28} {str(row['note'])[:120]}")
        if VERBOSE and row["head"]:
            for line in str(row["head"]).splitlines():
                if line.strip():
                    print(f"{'':<30} | {line}")
    print()
    # The control exists to prove the probe is measuring the client rather than
    # the host, and until now nothing checked it. If the canary reaches a
    # CONNECT head that asked for no header, something on this machine is
    # injecting it -- a proxy in the environment, a wrapper script, a shell
    # alias -- and every row above is then a reading of that thing instead of
    # the client it names. The table would still print, and it would still look
    # like evidence. That is the failure this refuses.
    #
    # Environment-independent on purpose: it says nothing about which clients
    # exist or what they support, only that the measurement itself is sound.
    control = next((r for r in rows if "control, no flag" in str(r["client"])), None)
    if control is not None and control["carried"] is True:
        print(
            "CONTROL LEAKED: the canary appeared on a CONNECT head that asked "
            "for no header.\n"
            "  Something on this host is injecting it, so the rows above measure\n"
            "  the environment rather than the clients they name, and none of them\n"
            "  can be believed."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
