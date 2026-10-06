#!/usr/bin/env python3
"""C2.8 — falsifying the destination TLS leg.

The increment this campaign guards added the one hop that had no shape at all:
`serve_connect` used to dial a bare `TcpStream`, and the bytes that crossed it
were the request the relay had just rewritten — `Authorization: Bearer <the
real credential>`. Seven tests in `connect_upstream_tls.rs` say that hop is now
encrypted, and a test that says a thing is not a measurement of whether the
thing holds.

    crates/broker/src/tls_bridge.rs        T1-T4, U1, U2
    crates/broker/src/connect_runtime.rs    R1, R2

## The row that escaped, and what it was

`R2` — *a route that declares tls is dialled in the clear* — came back ESCAPE
on its first run, and it is the reason this section exists.

The mutation was sound. The gap was a **hole in the tests**: all five original
properties were measured through a test-local `Always` policy that answers
whatever it is handed, while the implementation production actually installs is
`RouteTransports`. Nothing in the workspace constructed a `RouteTransports` and
asked it anything. So a mutation that turned the route's declaration into
decoration — the real credential onto the wire in the clear, which is the entire
leak this change exists to close — had nothing to catch it.

The other seven rows were unaffected, and that is the part worth keeping: every
other mutation in this file had a witness, and the one that did not was the one
that mattered. **A campaign row that escapes is a statement about the tests, not
about the mutation**, and reading it the other way round is how a suite ends up
green and wrong.

The hole is closed by two tests rather than one. `the_route_table_says_how_its
_destination_is_reached` loads a real route file through `ConnectRouteSet::load`
and drives `RouteTransports` into a real TLS origin, which is what R2 needs.
`a_destination_no_route_declares_is_not_dialled` builds the two gates
**disagreeing on purpose** — the table names one host, the bridge's policy
authorizes another — which is the only state in which `transport_for` is asked
about a destination it has no answer for, and that is what R1 needs. Had the
two gates agreed, the bridge's own policy would have refused first and the test
would have measured that refusal, which is a real property and not this one.

## What each row would break if the property were not real

*   **T1** makes the broker reach a TLS destination **in the clear**. Every
    other row in this file still passes: the refusals are refusals, the
    cleartext route is cleartext, and the destination that verifies is reached
    either way. Only the test that watched the origin's own buffer can tell the
    difference, which is the reason that test exists.
*   **T2** moves the upstream handshake off the dial and onto the first read.
    The credential has been written by then, so a destination that does not
    verify is refused *after* it has already been handed the secret — the exact
    failure the change was made to prevent, and one that looks identical from
    the broker's error.
*   **T3** replaces the configured anchors with an empty store. Every TLS
    destination stops being verifiable, which is what an operator gets if the
    flag is wired to the wrong variable.
*   **T4** verifies the certificate but against the resolved address instead of
    the route's name. A certificate issued for any other host on that address
    is then accepted, so the name in the route stops being a claim about who is
    on the other end.
*   **R1** makes `Cleartext` the fallback for an undeclared transport. The
    fail-closed default becomes fail-open, and nothing in the configuration ever
    said so.
*   **U1** skips the connection entirely when no transport is declared, so the
    refusal has to come from somewhere else — which is what "reachable only
    because it was never asked" looks like.
*   **U2** maps a handshake failure to a plain `Io`, so an untrusted
    destination is reported as a network problem rather than as a trust
    decision, and an operator reading the log is sent looking in the wrong
    place.
*   **R2** gives `upstream` a default, so a route that forgets to say how its
    destination is reached no longer has to. This one guards the *loader's*
    strictness rather than the relay's behaviour, and it is here because the
    field being required was, until this campaign asked, a claim nothing
    checked.

## What this campaign cannot falsify, and says so

The `--connect-roots` default in `main.rs` — that a broker with no anchors
verifies nothing rather than falling back to a public root set — is **not
covered by any row here**, and neither is it any test. Every fixture trusts a
session CA it minted itself, so a public bundle in the fallback would change
nothing any of them can see, and `webpki-roots` is not a dependency of this
crate, so the mutation would not even compile.

That is a real gap and it is left open rather than dressed up: the default is
asserted by a log line, and a log line is not a gate. The two ways to close it
are a test that starts the real binary without `--connect-roots` and observes a
refusal, and a decision about whether the bundled public roots should exist as
an opt-in at all. Both are owed; the first is cheap and is written down in
`15-ROADMAP.md` rather than pretended at here.

Run from the repository root:

    python3 tests/upstream_tls_falsification.py
    python3 tests/upstream_tls_falsification.py T1 T4
    python3 tests/upstream_tls_falsification.py --list
"""

from __future__ import annotations

import argparse
import dataclasses
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "crates" / "broker" / "src" / "tls_bridge.rs"
RUNTIME = ROOT / "crates" / "broker" / "src" / "connect_runtime.rs"
ROUTES = ROOT / "crates" / "broker" / "src" / "connect_routes.rs"
MAIN = ROOT / "crates" / "broker" / "src" / "main.rs"
TARGET = ROOT / "crates" / "broker" / "tests" / "connect_upstream_tls.rs"
SUITE = "connect_upstream_tls"
ALL = (BRIDGE, ROUTES, RUNTIME, TARGET)

TIMEOUT = 900


@dataclasses.dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    edits: tuple[tuple[str, str], ...]
    suite: str
    expect: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="T1 a TLS destination is reached in the clear",
        path=BRIDGE,
        edits=((
            "        match policy.transport_for(target)? {",
            "        match crate::connect_routes::UpstreamTransport::Cleartext {",
        ),),
        suite=SUITE,
        # The origin is a real TLS server, so a cleartext relay cannot read a
        # single byte from it and the test fails on the *absence* of the
        # credential rather than on its presence. That is the point: the two
        # readings are not interchangeable, and only the absence pins the leg.
        expect="the destination never completed a handshake",
    ),
    Mutation(
        name="T2 the upstream handshake is deferred to the first read",
        path=BRIDGE,
        edits=((
            "                tls.conn\n                    .complete_io(&mut tls.sock)\n                    .map_err(|e| BridgeError::Handshake(format!(\"{target}: {e}\")))?;\n",
            "",
        ),),
        suite=SUITE,
        # The refusal still happens — rustls still refuses an unknown issuer —
        # but only when the relay reads, which is after it wrote the rewritten
        # request. The origin's buffer is what tells the two apart.
        # `establish`, not the origin's buffer. A destination whose handshake
        # failed cannot report the bytes it never got to read, so the only
        # witness to "before" is whether `serve_connect` returned a tunnel. This
        # row is why the test was split: with only the buffer, deleting the
        # eager handshake left the suite green.
        expect="a destination this broker does not trust must be refused, not reached",
    ),
    Mutation(
        name="T3 the configured anchors are ignored",
        path=BRIDGE,
        edits=((
            "                    None => rustls::ClientConfig::builder()\n                        .with_root_certificates(roots)",
            "                    None => rustls::ClientConfig::builder()\n                        .with_root_certificates(rustls::RootCertStore::empty())",
        ),),
        suite=SUITE,
        # Every TLS destination stops verifying, and the first one to say so is
        # the property-1 test — the `expect` on `establish`, not the buffer
        # assertion behind it, because the tunnel is never returned at all.
        expect="a verifying destination is reached",
    ),
    Mutation(
        name="T4 the certificate is verified against the address, not the name",
        path=BRIDGE,
        edits=((
            "                let name = rustls::pki_types::ServerName::try_from(target.host().to_owned())",
            "                let name = rustls::pki_types::ServerName::try_from(\n                    target\n                        .host()\n                        .to_owned()\n                        .split('.')\n                        .next_back()\n                        .unwrap_or(\"localhost\")\n                        .to_owned(),\n                )",
        ),),
        suite=SUITE,
        # `origin.example.com` verified against `com` is refused, so the test
        # that watched a verifying destination be reached fails on the `expect`
        # — the same witness T3 uses, and the reason both rows name it rather
        # than the buffer assertion behind it. The mutation does the reverse of
        # what its name says: it makes the check *stricter*, and "stricter" is
        # not what anyone asked for, so a suite that cannot see the difference
        # is not a gate.
        expect="a verifying destination is reached",
    ),
    Mutation(
        name="R1 a destination with no route falls back to cleartext",
        path=RUNTIME,
        # The whole chain, not just the `ok_or_else` arm, and the replacement has
        # to keep the `Result`: the policy returns one, so a bare
        # `unwrap_or(Cleartext)` does not compile and the row reported SKIP for
        # two different reasons across two attempts — first as a doubled `.map`,
        # then as a type mismatch. A row that cannot compile is a row that
        # measured nothing while looking like it had, and a SKIP is never a pass.
        edits=((
            "            .route_for(target)\n"
            "            .map(|route| route.upstream())\n"
            "            .ok_or_else(|| {\n"
            "                crate::tls_bridge::BridgeError::Upstream(format!(\n"
            "                    \"no route declares how to reach {target}, so the broker will not dial it\"\n"
            "                ))\n"
            "            })",
            "            .route_for(target)\n"
            "            .map(|route| route.upstream())\n"
            "            .map(Ok)\n"
            "            .unwrap_or(Ok(crate::connect_routes::UpstreamTransport::Cleartext))",
        ),),
        suite=SUITE,
        # The route set and the policy can disagree, and the disagreement is the
        # case where a default is most tempting and least acceptable: nothing
        # said how to reach it, and the answer would be the credential in the
        # clear. `a_destination_no_route_declares_is_not_dialled` is the
        # witness: the tunnel is established, so its `expect_err` is what fires.
        expect="a destination no route declares how to reach must not be dialled at all",
    ),
    Mutation(
        name="R2 a route that declares tls is dialled in the clear",
        path=RUNTIME,
        edits=((
            "            .map(|route| route.upstream())",
            "            .map(|route| match route.upstream() {\n                crate::connect_routes::UpstreamTransport::Tls => {\n                    crate::connect_routes::UpstreamTransport::Cleartext\n                }\n                other => other,\n            })",
        ),),
        suite=SUITE,
        # The declaration becomes decoration. Every refusal still refuses and
        # the cleartext route still works, so only a destination that verifies
        # and then does not hear from anybody can tell — which is
        # `the_route_table_says_how_its_destination_is_reached`. That test exists
        # because this row first escaped: the suite exercised only the test-local
        # `Always` policy, so the implementation production actually uses was
        # untested and this mutation had nothing to catch it.
        expect="the route table said tls and the destination never completed a handshake",
    ),
    Mutation(
        name="U1 a dial with no declared transport proceeds in the clear",
        path=BRIDGE,
        edits=((
            "        let Some(policy) = self.upstream.as_deref() else {\n            return Err(BridgeError::Upstream(format!(\n                \"no upstream transport is declared for {}, so this broker reaches no \\\n                 destination at all\",\n                target.host()\n            )));\n        };",
            "        let policy = match self.upstream.as_deref() {\n            Some(p) => p,\n            None => {\n                return Ok(Upstream::Plain(socket));\n            }\n        };",
        ),),
        suite=SUITE,
        # The refusal has to come from somewhere, so if it is not here it is
        # later — and later is after the request has been rewritten. The
        # property-3 test's `expect_err` is the witness: a plain socket to a TLS
        # origin establishes, so the tunnel comes back and there is nothing
        # left to refuse it.
        expect="a bridge with no declared transport reaches nothing",
    ),
    Mutation(
        name="U2 a trust failure is reported as a network failure",
        path=BRIDGE,
        edits=((
            "                    .map_err(|e| BridgeError::Handshake(format!(\"{target}: {e}\")))?;",
            "                    .map_err(|e| BridgeError::Io(format!(\"{target}: {e}\")))?;",
        ),),
        suite=SUITE,
        expect="which blames something other than the certificate",
    ),
)


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    """Every `before` must be present exactly once.

    A row whose anchor is stale is a row that silently tests nothing, and this
    file has already been bitten by that twice in the loop campaign: a mutation
    that did not compile, and a pair of rows that were the same edit under two
    names. A skip is reported, never counted as a pass.
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


def run_suite(suite: str) -> tuple[int, str]:
    cmd = ["cargo", "test", "-p", "asv-broker", "--test", suite, "--", "--test-threads=1"]
    try:
        done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT)
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
    # while never declaring them cannot be asked for a subset at all. That is
    # not a cosmetic defect — it is how a row stays un-rerun for a whole
    # campaign while the file claims it can be isolated.
    ap.add_argument("rows", nargs="*", help="row name fragments to run, e.g. T1 R2")
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

    say(f"falsifying {len(wanted)} rows of the destination TLS leg")
    say("")
    red = 0
    for m in wanted:
        for before, after in m.edits:
            text = m.path.read_text()
            if text.count(before) != 1:
                say(f"SKIP {m.name}: the anchor is stale")
                break
            m.path.write_text(text.replace(before, after, 1))
        try:
            code, out = run_suite(m.suite)
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
            say("      it went red for a reason this row did not name; the first")
            say("      assertion that fired was:")
            for line in out.splitlines():
                if "panicked at" in line or line.strip().startswith(("the ", "a ", "an ")):
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
