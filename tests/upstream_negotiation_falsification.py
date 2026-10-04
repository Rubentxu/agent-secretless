#!/usr/bin/env python3
"""M9 / C2.8 — falsifying what the broker's **client** leg negotiates.

`docs/tls-compatibility-matrix.md` measures the TLS **server** the bridge presents
to the agent, and its own header says those rows describe "both TLS surfaces in
the workspace" — which was true when it was written and stopped being true when
C2.8 made the broker-to-destination hop TLS.

`Bridge::dial_upstream` builds a `rustls::ClientConfig` of its own:

    crates/broker/src/tls_bridge.rs   N1, N2, N3

Three cells are set. The three that are **not** — the protocol version range,
the ALPN protocols offered, and the crypto provider — are inherited from a
library default, and `connect_upstream_tls.rs` measures what this leg *trusts*
while saying nothing about what it *negotiates*. So the ALPN hazard the matrix
pinned for the server side is unwatched here, and the two are mirror images: a
broker that **offered** `h2` would get a destination that believes it is
speaking HTTP/2, and then relay `curl`'s HTTP/1.1 bytes into it.

    crates/broker/tests/connect_upstream_negotiation.rs   the witnesses

## What each row would break if the property were not real

*   **N1** offers `h2` and `http/1.1` on the upstream leg — the single line an
    engineer would add while "improving" the client, and nothing about it reads
    as a security change. The destination accepts it, the handshake completes,
    and every other test in this file still passes. Only the one that reads the
    destination's ALPN selection can tell.
*   **N2** pins the client's version range to TLS 1.2. The tunnel to a
    TLS-1.3-only destination is refused with a `ProtocolVersion` alert, which
    reads as "that destination is broken" rather than as "we asked for less".
*   **N3** pins it to TLS 1.3. The TLS 1.2 floor disappears, so a destination
    that has not moved is unreachable — and the observed ceiling, which is the
    matrix's most-quoted cell, keeps passing, so only the floor row sees it.

## What this campaign cannot falsify, and says so

**The client-authentication row has no production mutation, and this file does
not pretend otherwise.** `the_broker_presents_no_client_certificate_to_a
_destination_that_demands_one` asserts the destination saw **zero** client
certificates. The only mutation that could redden it is one that gives the
broker a client certificate, and the bridge holds no key material it could use —
so the mutation does not exist as a one-line change, and a row that cannot be
written is a row that must be declared rather than faked.

That row is instead falsified by a **mutually falsifying pair**, which is a
weaker thing and is labelled as one:

*   the pin goes red if the destination's demand were not real, because a
    destination that accepts anything would record `handshook=true`;
*   the control goes red if the certificate were not verifiable, because a
    destination that accepts nothing would never handshook.

Two tests that each redden when the other's premise is removed, with no
production change. The first version of that control presented the
destination's own leaf and was refused, because `issue_leaf` stamps
`ExtendedKeyUsage: serverAuth` and nothing else — a verifier is right to reject
a server certificate presented as a client one. The control now mints a real
`clientAuth` leaf from the same intermediate. It is worth recording that the
control was wrong twice before it was right: once for a short chain, once for
the wrong EKU, and both failures read as "the anchor is wrong".

**The crypto provider cell is unpinned and unfalsifiable here.** The workspace
enables `rustls` with `ring` and no alternative provider, so there is no second
value to mutate into and no test that could notice the first one moving.

## Why this campaign runs one target at a time

Each mutation changes the broker library, so running the whole `asv-broker`
suite per row would relink every test binary in the workspace and turn a
three-row campaign into an hour of linking. The witnesses are all in one test
target, so `--test connect_upstream_negotiation` is both the cheaper and the
more precise choice: a row that escapes cannot be blamed on an unrelated suite
having failed for its own reasons.

`--release` because the release artefacts are already warm on this host and the
debug profile would rebuild the broker library from scratch on every row.

Run from the repository root:

    python3 tests/upstream_negotiation_falsification.py
    python3 tests/upstream_negotiation_falsification.py N1 N3
    python3 tests/upstream_negotiation_falsification.py --list
"""

from __future__ import annotations

import argparse
import dataclasses
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "crates" / "broker" / "src" / "tls_bridge.rs"
TARGET = ROOT / "crates" / "broker" / "tests" / "connect_upstream_negotiation.rs"
ALL = (BRIDGE, TARGET)

SUITE = "connect_upstream_negotiation"
TIMEOUT = 1800

# The client config, verbatim, with the indentation the source has.
CLIENT_CONFIG = (
    "                let config = rustls::ClientConfig::builder()\n"
    "                    .with_root_certificates(self.destination_roots.as_ref().clone())\n"
    "                    .with_no_client_auth();"
)


@dataclasses.dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    edits: tuple[tuple[str, str], ...]
    expect: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="N1 the upstream leg offers h2 and http/1.1",
        path=BRIDGE,
        # `with_alpn_protocols` does not exist on the client builder in this
        # rustls — the server has one and the client does not, because
        # `ClientConfig::alpn_protocols` is a public field. The first attempt at
        # this row used the server-side spelling and the runner reported SKIP
        # for "does not compile", which is the correct outcome and the reason a
        # skip is never counted as a pass.
        edits=(
            (
                CLIENT_CONFIG,
                "                let mut config = rustls::ClientConfig::builder()\n"
                "                    .with_root_certificates(self.destination_roots.as_ref().clone())\n"
                "                    .with_no_client_auth();\n"
                "                config.alpn_protocols = vec![b\"h2\".to_vec(), b\"http/1.1\".to_vec()];",
            ),
        ),
        # The origin offers both protocols and is built to accept a selection,
        # so with the mutation the destination completes the handshake *and*
        # records `Some("h2")`. Every trust row in the file is unaffected:
        # verification is untouched, and a tunnel that works is not evidence of
        # what was negotiated inside it.
        expect="the broker's upstream leg offered an ALPN protocol",
    ),
    Mutation(
        name="N2 the upstream leg refuses TLS 1.3",
        path=BRIDGE,
        edits=(
            (
                CLIENT_CONFIG,
                "                let config =\n"
                "                    rustls::ClientConfig::builder_with_protocol_versions(&[\n"
                "                        &rustls::version::TLS12,\n"
                "                    ])\n"
                "                    .with_root_certificates(self.destination_roots.as_ref().clone())\n"
                "                    .with_no_client_auth();",
            ),
        ),
        # A destination that offers only TLS 1.3 answers with a fatal
        # `ProtocolVersion` alert, so `serve_connect` never returns a tunnel and
        # the `expect` on `establish` fires — the ceiling pin, named by the
        # assertion that actually runs first. The version assertion behind it
        # is never reached, for the same reason T3 and T4 in the sibling
        # campaign name their `establish` expectation rather than the buffer
        # behind it: when no tunnel comes back there is nothing to negotiate.
        expect="the broker reaches a TLS 1.3 only destination",
    ),
    Mutation(
        name="N3 the upstream leg refuses TLS 1.2",
        path=BRIDGE,
        edits=(
            (
                CLIENT_CONFIG,
                "                let config =\n"
                "                    rustls::ClientConfig::builder_with_protocol_versions(&[\n"
                "                        &rustls::version::TLS13,\n"
                "                    ])\n"
                "                    .with_root_certificates(self.destination_roots.as_ref().clone())\n"
                "                    .with_no_client_auth();",
            ),
        ),
        # The floor row, and only the floor row. The observed-ceiling test still
        # passes — it negotiates TLS 1.3, which is all it ever claimed — so
        # this mutation is invisible to the cell the matrix quotes most and
        # visible only to the one it quotes as a limit.
        expect="the broker reaches a TLS 1.2 only destination",
    ),
)


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    """Every `before` must be present exactly once.

    A row whose anchor is stale is a row that silently tests nothing. A skip is
    reported, never counted as a pass.
    """
    bad = 0
    for m in MUTATIONS:
        text = m.path.read_text()
        for i, (before, _after) in enumerate(m.edits):
            n = text.count(before)
            if n != 1:
                say(f"BAD  {m.name[:48]:48} edit{i}: {n} matches in {m.path.name}")
                bad += 1
    return bad == 0


def run_suite() -> tuple[int, str]:
    cmd = [
        "cargo", "test", "-p", "asv-broker", "--release",
        "--test", SUITE, "--", "--test-threads=1",
    ]
    try:
        done = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT,
            env={**__import__("os").environ, "TMPDIR": "/var/home/rubentxu/agent-secretless-tmp"},
        )
    except subprocess.TimeoutExpired:
        # Never reported as ESCAPED. A suite that could not finish has not been
        # shown to pass, and calling that a result is the one thing a
        # falsification campaign must not do.
        return 124, "TIMEOUT"
    return done.returncode, done.stdout + done.stderr


def residue() -> list[str]:
    return [p.name for p in ALL if p.read_text() != ORIGINAL[p]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print the rows and exit")
    # Declared, not read off `sys.argv` directly: `parse_args` rejects unknown
    # positionals, so a runner that selects rows by indexing `sys.argv[1:]`
    # while never declaring them cannot be asked for a subset at all.
    ap.add_argument("rows", nargs="*", help="row name fragments to run, e.g. N1 N3")
    args = ap.parse_args()

    if args.list:
        for i, m in enumerate(MUTATIONS, 1):
            say(f"{i:2}. {m.name}  [{m.path.name}]")
        return 0

    global ORIGINAL
    ORIGINAL = {p: p.read_text() for p in ALL}

    if not verify_anchors():
        return 1

    wanted = MUTATIONS
    if args.rows:
        picked: list[Mutation] = []
        for arg in args.rows:
            # A fragment that matches nothing is an error rather than an empty
            # selection: "two rows" silently running zero is how a campaign
            # reports a pass over rows it never touched.
            hits = [m for m in MUTATIONS if arg.upper() in m.name.upper()]
            if not hits:
                say(f"no row matches {arg!r}")
                return 1
            picked.extend(hits)
        seen: set[str] = set()
        wanted = [m for m in picked if not (m.name in seen or seen.add(m.name))]
        if not wanted:
            say("no rows selected")
            return 1

    say(f"falsifying {len(wanted)} rows of the destination TLS **client** leg")
    say("")
    red = 0
    for m in wanted:
        applied = True
        for before, after in m.edits:
            text = m.path.read_text()
            if text.count(before) != 1:
                say(f"SKIP {m.name}: the anchor is stale")
                applied = False
                break
            m.path.write_text(text.replace(before, after, 1))
        if not applied:
            continue
        try:
            code, out = run_suite()
        finally:
            for p in ALL:
                p.write_text(ORIGINAL[p])

        if "error[" in out or "error: could not compile" in out:
            say(f"SKIP {m.name}: the mutation does not compile")
            continue
        if code == 124:
            say(f"KILL {m.name}: the suite did not finish")
            continue
        if code == 0:
            say(f"ESCAPE {m.name}: the suite stayed green")
            continue
        if m.expect in out:
            say(f"RED   {m.name}")
            say(f"      the named assertion caught it: {m.expect!r}")
            red += 1
        else:
            say(f"WRONG {m.name}")
            say("      it went red for a reason this row did not name; the failing")
            say("      tests were:")
            for line in out.splitlines():
                if line.startswith("test ") and ("FAILED" in line or "failed" in line):
                    say(f"        {line.strip()}")
            for line in out.splitlines():
                if "panicked at" in line:
                    say(f"        {line.strip()}")
                    break

    left = residue()
    if left:
        say("")
        say(f"RESIDUE: {', '.join(left)} are not back to their original contents")
        return 1
    say("no mutation residue in the tree")
    say(f"{red}/{len(wanted)} mutations went red for the right reason")
    return 0 if red == len(wanted) else 1


if __name__ == "__main__":
    ORIGINAL: dict[Path, str] = {}
    sys.exit(main())
