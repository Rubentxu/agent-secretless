#!/usr/bin/env python3
"""C3 / M11 — falsifying the OAuth2 vertical.

M11 was a `prototype` because "Nothing in the runtime calls the module yet", and
this campaign is the reason the milestone is no longer one. The property being
claimed is narrow and it is the whole of M11:

    the client secret stays inside the broker, and what the operation receives
    is a short-lived token the provider really issued

    crates/broker/src/oauth2.rs         R4, R5
    crates/broker/src/oauth2_port.rs    R1, R2, R3
    crates/broker/src/main.rs           (the wiring, not mutated here)

    crates/broker/tests/oauth2_vertical.rs   R1, R2
    crates/broker/tests/oauth2_provider.rs   R4, R5
    crates/broker/src/oauth2_port.rs::tests  R3

## The two rows the goal named

*   **R1** replaces the exchange with a direct read of the stored secret, so
    the port hands the operation the `client_secret` on every lend. This is the
    mutation the entire increment exists to make impossible, and it lives in one
    function. Measured: **eight of the ten vertical tests go red**, not only the
    one that names the claim — the leaked bytes are not a credential the
    resource accepts, so the grant counts, the cache, the audience check and the
    agent-side assertion all move at once. That density is the reason to trust
    the row, and it is also why the docstring for this campaign states the
    measured number rather than the flattering one.
*   **R2** drops the deadline check in the token cache. The token is still
    real, still issued by the provider, and still the right token for the right
    operation — it is simply served after it has expired. Nothing about the
    exchange changes, so no test that watches a single operation can see it; it
    is `a_token_is_reused_inside_its_lifetime_and_replaced_outside_it` that
    does, and only because it sleeps.

## Three more that this work produced

Found while building, not by reading, and included because a security claim
nobody has tried to break is a claim nobody has checked.

*   **R3** is the tempting version of the router: fall back to the vault on
    *any* error rather than only on `NotFound`. It reads as resilience and it
    is a silent catastrophic leak — provider down, no token obtainable, the
    router asks the vault, the vault hands over the `client_secret`, and the
    operation proceeds. The operation *succeeds*. This row is the one a
    reviewer would most likely approve.
*   **R4** accepts a widened scope. RFC 6749 §5.1 permits the server to grant
    more and requires the client to notice; here the "noticing" is a refusal,
    and a refusal is a branch that can be deleted.
*   **R5** sends the Basic credential over the raw pair instead of the
    form-encoded one. §2.3.1's entire content is the encoding, so this is the
    same bug class as R4 wearing a spec citation.

## What this campaign cannot falsify, and says so

**That a real third-party IdP behaves like this one.** The authorization server
is self-hosted and speaks RFC 6749, RFC 7009, RFC 7662 and RFC 8707 with twenty
tests of its own. V1-C3 stays host-dependent for a provider this repository does
not run.

**That the scope is the right one.** The scope is operator-configured, not
policy-derived. A mutation can prove the escalation is refused; nothing here can
prove the requested scope is the scope the operation needs.

**That a revocation takes effect immediately.** `forget` exists and is
measured, but nothing in the credential-removal path calls it yet, so a
revocation's real effect is bounded by the token's `expires_in`. R2 measures
that bound is honoured, not that it is short.

**Profile.** These run in debug, not release. The campaign's claim is *which
tests go red*, and the optimisation profile has no bearing on that; a release
campaign would spend most of its wall clock relinking with LTO.

Run from the repository root:

    python3 tests/oauth2_falsification.py
    python3 tests/oauth2_falsification.py R1 R2
    python3 tests/oauth2_falsification.py --list
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OAUTH2 = ROOT / "crates" / "broker" / "src" / "oauth2.rs"
OAUTH2_PORT = ROOT / "crates" / "broker" / "src" / "oauth2_port.rs"
ALL = (OAUTH2, OAUTH2_PORT)

TIMEOUT = 1800


@dataclasses.dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    edits: tuple[tuple[str, str], ...]
    # Which target the row expects to go red. Split by target because each one
    # is a separate link, and a campaign whose cost is the relink should not
    # pay for targets a row cannot affect.
    suite: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="R1 the port hands the stored secret to the operation",
        path=OAUTH2_PORT,
        edits=(
            (
                """    fn exchange(&self, client: &OAuth2Client) -> Result<OAuth2Token, SecretError> {
        let config = self.config_for(client)?;
        let issuer = self.factory.issuer(config).map_err(unavailable)?;
        issuer.issue(&client.scope).map_err(unavailable)
    }""",
                """    fn exchange(&self, client: &OAuth2Client) -> Result<OAuth2Token, SecretError> {
        let _ = self.factory.issuer(self.config_for(client)?).map_err(unavailable)?;
        let mut leaked: Option<Zeroizing<Vec<u8>>> = None;
        self.vault
            .lend(&client.credential, &mut Capture { out: &mut leaked })?;
        Ok(OAuth2Token::new(
            leaked.map(|bytes| bytes.to_vec()).unwrap_or_default(),
            "Bearer",
            Duration::from_secs(3600),
            None,
            None,
        ))
    }""",
            ),
        ),
        suite="vertical",
    ),
    Mutation(
        name="R2 the token cache is consulted without a deadline",
        path=OAUTH2_PORT,
        edits=(
            (
                "        if now >= entry.serve_until {",
                "        if false {",
            ),
        ),
        suite="vertical",
    ),
    Mutation(
        name="R3 the router falls back to the vault on any error",
        path=OAUTH2_PORT,
        edits=(
            (
                "            Err(SecretError::Unavailable(reason)) => "
                "Err(SecretError::Unavailable(reason)),",
                "            Err(SecretError::Unavailable(reason)) => self\n"
                "                .vault\n"
                "                .lend(credential, sink)\n"
                "                .or(Err(SecretError::Unavailable(reason))),",
            ),
        ),
        suite="lib",
    ),
    Mutation(
        name="R4 a widened scope is accepted",
        path=OAUTH2,
        edits=(
            (
                """    if widened {
        Err(OAuth2Error::ScopeEscalated {""",
                """    if widened {
        if false {
        return Err(OAuth2Error::ScopeEscalated {""",
            ),
            (
                """            granted: granted.to_string(),
        })
    } else {
        Err(OAuth2Error::ScopeNarrowed {""",
                """            granted: granted.to_string(),
        });
        }
        return Ok(());
    } else {
        Err(OAuth2Error::ScopeNarrowed {""",
            ),
        ),
        suite="provider",
    ),
    Mutation(
        name="R5 the Basic credential skips the form encoding",
        path=OAUTH2,
        edits=(
            (
                """    push_form_encoded(&mut joined, config.client_id.as_bytes());
    joined.push(':');
    push_form_encoded(&mut joined, &config.client_secret);""",
                """    joined.push_str(&config.client_id);
    joined.push(':');
    joined.push_str(&String::from_utf8_lossy(&config.client_secret));""",
            ),
        ),
        suite="provider",
    ),
)


def say(line: str) -> None:
    print(line, flush=True)


def verify_anchors() -> bool:
    bad = 0
    for m in MUTATIONS:
        text = m.path.read_text()
        for i, (before, _after) in enumerate(m.edits):
            n = text.count(before)
            if n != 1:
                say(f"BAD  {m.name[:48]:48} edit{i}: {n} matches in {m.path.name}")
                bad += 1
    return bad == 0


def run(suite: str) -> tuple[int, str]:
    if suite == "vertical":
        cmd = ["cargo", "test", "-p", "asv-broker", "--test", "oauth2_vertical"]
    elif suite == "provider":
        cmd = ["cargo", "test", "-p", "asv-broker", "--test", "oauth2_provider"]
    else:
        cmd = ["cargo", "test", "-p", "asv-broker", "--lib", "oauth2_port"]
    try:
        done = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env={**os.environ, "TMPDIR": "/var/home/rubentxu/agent-secretless-tmp"},
        )
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    return done.returncode, done.stdout + done.stderr


def residue() -> list[str]:
    return [p.name for p in ALL if p.read_text() != ORIGINAL[p]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("rows", nargs="*", help="row name fragments, e.g. R1 R2")
    args = ap.parse_args()

    if args.list:
        for i, m in enumerate(MUTATIONS, 1):
            say(f"{m.name}  [{m.path.name} -> {m.suite}]")
        return 0

    global ORIGINAL
    ORIGINAL = {p: p.read_text() for p in ALL}

    if not verify_anchors():
        return 1

    wanted = MUTATIONS
    if args.rows:
        picked: list[Mutation] = []
        for arg in args.rows:
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

    say(f"falsifying {len(wanted)} rows of the OAuth2 vertical")
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
            code, out = run(m.suite)
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
        say(f"RED   {m.name}")
        for line in out.splitlines():
            if line.startswith("test ") and "FAILED" in line:
                say(f"      {line.strip()}")
                break
        for line in out.splitlines():
            if "panicked at" in line:
                say(f"      {line.strip()}")
                break
        red += 1

    left = residue()
    if left:
        say("")
        say(f"RESIDUE: {', '.join(left)} are not back to their original contents")
        return 1
    say("no mutation residue in the tree")
    say(f"{red}/{len(wanted)} mutations went red")
    return 0 if red == len(wanted) else 1


if __name__ == "__main__":
    ORIGINAL: dict[Path, str] = {}
    sys.exit(main())
