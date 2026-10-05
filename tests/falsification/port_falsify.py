#!/usr/bin/env python3
"""Falsification for the R2.C.2.b port rows.

Same four-bucket accounting as the other three harnesses. These rows carry no
socket, so the mutations that matter are the ones that would let a session be
served past its margin, let a credential outlive `forget`, or let three values
reach the single-value sink that builds a bearer header.

Run:  python3 port_falsify.py
"""

import sys
from pathlib import Path

# The base harness lives beside this one. `python3 tests/falsification/x.py`
# already puts this directory on `sys.path`, so the insert is only load-
# bearing for a runner that imports it as a module instead of executing
# it -- and a campaign that only works one way is a campaign that stops
# being reproducible the first time someone automates it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

PORT = f.REPO / "crates/broker/src/aws/port.rs"

MUTATIONS = [
    # ---- the margin is load-bearing ---------------------------------------
    (
        # The row this bit is the boundary row, and the boundary is strict:
        # exactly the margin left is not usable. Dropping the margin to zero
        # makes a session with 60s left look like one with an hour.
        "consult no margin when deciding whether a cached session is usable",
        "        if cached.usable_at(now, self.margin) {",
        "        if cached.usable_at(now, Duration::ZERO) {",
        "a_session_inside_the_margin_is_not_served_and_is_replaced",
    ),
    (
        # The other direction, which is the one that hides: a margin so large
        # that nothing is ever usable re-mints on every single request. No error,
        # no log, just STS on the critical path of everything.
        "treat every cached session as already inside the margin",
        "        if cached.usable_at(now, self.margin) {",
        "        if cached.usable_at(now, Duration::from_secs(u32::MAX as u64)) {",
        "one_exchange_serves_many_lends_inside_the_margin",
    ),
    # ---- the arithmetic is public -----------------------------------------
    (
        "serve for the whole lifetime whatever the margin is",
        "        lifetime.checked_sub(margin).unwrap_or(Duration::ZERO)",
        "        lifetime",
        "a_margin_above_the_lifetime_serves_nothing_and_says_so",
    ),
    (
        "serve for nothing whatever the margin is",
        "        lifetime.checked_sub(margin).unwrap_or(Duration::ZERO)",
        "        Duration::ZERO",
        "a_margin_above_the_lifetime_serves_nothing_and_says_so",
    ),
    (
        # A fallback that looks defensive and is worse than the underflow it
        # replaces: a margin at the lifetime now reports one second of service
        # instead of none, so the degenerate case reads as a working cache.
        "invent a second of service for a margin that swallows the lifetime",
        "        lifetime.checked_sub(margin).unwrap_or(Duration::ZERO)",
        "        lifetime.checked_sub(margin).unwrap_or(Duration::from_secs(1))",
        "a_margin_above_the_lifetime_serves_nothing_and_says_so",
    ),
    # ---- three values do not become one -----------------------------------
    (
        # The structural row. Serving through the one-value sink is what the
        # whole shape exists to make impossible, and this is the mutation that
        # makes it possible without writing a conversion.
        "report success from the one-value sink without reaching it",
        "        Err(SecretError::Unavailable(\n"
        '            "an AWS session is three values and is served through lend_session; \\\n'
        "             the single-value sink builds a bearer header and must not be handed \\\n"
        '             a session token"\n'
        '                .into(),\n'
        "        ))",
        "        Ok(())",
        "the_single_value_sink_refuses_an_aws_session_and_says_why",
    ),
    (
        # Refusing is not the property; refusing *with a reason* is. An
        # operator who cannot tell why a credential will not lend is the
        # operator who tries a different port.
        "refuse without saying that a session is three values",
        '            "an AWS session is three values and is served through lend_session; \\\n',
        '            "this credential is not available and is served through lend_session; \\\n',
        "the_single_value_sink_refuses_an_aws_session_and_says_why",
    ),
    # ---- forget is the revocation ----------------------------------------
    (
        "forget the credential and keep the session",
        "            cache.remove(credential);",
        "            let _ = credential;",
        "forget_drops_the_cache_and_the_next_lend_re_mints",
    ),
    (
        # The other direction, and the reason the row above is not enough: a
        # `forget` that clears everything turns one deletion into every
        # credential re-minting, and looks like a working revocation in a test
        # that only ever used one credential.
        "forget every credential when asked for one",
        "            cache.remove(credential);",
        "            cache.clear();\n            let _ = credential;",
        "forgetting_one_credential_leaves_the_others_cached",
    ),
    # ---- a failure is a failure ------------------------------------------
    (
        "throw away the cache when the provider is unreachable",
        "        let minted = Arc::new(self.exchange.exchange(credential, now)?);",
        "        let minted = match self.exchange.exchange(credential, now) {\n"
        "            Ok(session) => Arc::new(session),\n"
        "            Err(error) => {\n"
        "                if let Ok(mut cache) = self.cache.lock() {\n"
        "                    cache.clear();\n"
        "                }\n"
        "                return Err(error);\n"
        "            }\n"
        "        };",
        "a_failing_exchange_leaves_the_cache_alone",
    ),
    (
        # The tempting one. Serving a stale session beats refusing when STS is
        # down, right up until the signature is rejected with a name that
        # points at the credential rather than at the margin.
        "fall back to a cached session when the exchange fails",
        "        let minted = Arc::new(self.exchange.exchange(credential, now)?);",
        "        let minted = match self.exchange.exchange(credential, now) {\n"
        "            Ok(session) => Arc::new(session),\n"
        "            Err(error) => {\n"
        "                let stale = self\n"
        "                    .cache\n"
        "                    .lock()\n"
        "                    .ok()\n"
        "                    .and_then(|cache| cache.get(credential).cloned());\n"
        "                if let Some(stale) = stale {\n"
        "                    return Self::hand_over(&stale, sink);\n"
        "                }\n"
        "                return Err(error);\n"
        "            }\n"
        "        };",
        "an_exchange_failure_does_not_buy_a_stale_session",
    ),
    # ---- the listing describes the cache ---------------------------------
    (
        # `AwsSession` redacts its own `Debug`, so printing one does not leak
        # the two secrets -- which is exactly why this row needed the assertion
        # about the session's *own* detail. Without that, the leak assertion
        # would have been defended by the other file and read as if it were
        # defended here.
        "print each cached session instead of the credentials that own it",
        '            .field("cached", &self.cached())',
        "            .field(\"cached\", &{\n"
        "                let mut names = Vec::new();\n"
        "                if let Ok(cache) = self.cache.lock() {\n"
        "                    for session in cache.values() {\n"
        "                        names.push(format!(\"{session:?}\"));\n"
        "                    }\n"
        "                }\n"
        "                names\n"
        "            })",
        "printing_the_port_never_prints_a_session",
    ),
    (
        "print how many sessions are cached instead of which",
        '            .field("cached", &self.cached())',
        '            .field("cached", &self.cache.lock().map(|c| c.len()).unwrap_or(0))',
        "printing_the_port_never_prints_a_session",
    ),
]


def main() -> int:
    f.STS = PORT
    f.TEST_PREFIX = "aws::port::tests::"
    f.CARGO_TARGET = "--lib"
    # `f.main()` reads `MUTATIONS` out of its own module namespace, so assigning
    # a local of the same name does nothing. The first run of this harness
    # reported 25 survivors about `sts.rs` and said nothing at all about the port
    # -- a run that looks like evidence and is about a different file entirely.
    f.MUTATIONS[:] = MUTATIONS
    print(f"# falsifying {PORT.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
