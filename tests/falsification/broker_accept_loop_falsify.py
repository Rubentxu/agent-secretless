#!/usr/bin/env python3
"""Falsifying the broker's accept loop, in `crates/broker/src/main.rs`.

`concurrent_connections_do_not_queue.rs` asserts three properties of the Unix
accept loop. Until this harness existed they were three rows that passed, which
is the weakest thing a row can be: a row nobody has tried to break measures
nothing about whether it can fail. The rest of this repository answers that
with a mutation campaign per subsystem, and `main.rs` — the one file on the
path every connection takes — had none.

Three buckets, run one per invocation like every other harness here, because
the framework takes a single mutation list:

    python3 broker_accept_loop_falsify.py cap          # the ceiling
    python3 broker_accept_loop_falsify.py concurrency  # the thread per connection
    python3 broker_accept_loop_falsify.py release      # the counter counting down

The third bucket exists because the first two are satisfiable by a counter that
only ever counts up. Fill the cap once and refuse from then on, and both cap
rows pass forever. Nothing in the first two buckets can see a missing
`fetch_sub`, so it gets its own bucket and its own row.
"""

import sys
from pathlib import Path

import sts_falsify as f

MAIN = f.REPO / "crates/broker/src/main.rs"

# The three lines that make the cap a ceiling, verbatim. The `fetch_update`
# closure is the whole admission decision: `then_some` returns `None` once the
# count reaches the limit, `fetch_update` then leaves the value untouched and
# returns `Err`, and `is_ok()` reads that as a refusal.
CEILING = """                        |n| (n < MAX_IN_FLIGHT_CONNECTIONS).then_some(n + 1),"""

# The thread's own exit path. Removing the decrement is the failure that turns
# a broker into one that refuses every agent for the rest of the process's life
# after a single busy minute.
DECREMENT = """                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);"""

SPAWN = """                std::thread::spawn(move || {
                    // One bad connection must not take the broker down
                    // (UAT-017 requires fail-closed, not fail-crashed), and one
                    // slow connection must not delay another agent: `serve`
                    // runs to its own 5s deadline on this thread while the
                    // accept loop is already back on the next `incoming()`.
                    if let Err(e) = serve(&state, stream) {
                        tracing::warn!(error = %e, "connection failed");
                    }
                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });"""

SERVE_INLINE = """                if let Err(e) = serve(&state, stream) {
                    tracing::warn!(error = %e, "connection failed");
                }
                in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);"""

CAP = [
    (
        # The admission decision deleted rather than weakened: every peer is
        # admitted no matter how many are already being served. This is the
        # unbounded-threads denial of service that `MAX_IN_FLIGHT_CONNECTIONS`
        # exists to prevent, and the ceiling row reds it because the over-limit
        # peer now gets served instead of turned away.
        "admit every peer, however many are already in flight",
        CEILING,
        """                        |n| Some(n + 1),""",
        "a_burst_past_the_in_flight_cap_is_refused_rather_than_queued",
    ),
    (
        # The subtler version: the ceiling is still there, written down, and
        # raised past anything a machine can open. A reader of `main.rs` sees a
        # limit; a burst of sockets costs a stack each. This is the mutation
        # worth having, because the claim it attacks is the one the constant
        # makes most convincing.
        "raise the ceiling above anything a machine can open",
        CEILING,
        """                        |n| (n < usize::MAX).then_some(n + 1),""",
        "a_burst_past_the_in_flight_cap_is_refused_rather_than_queued",
    ),
]

RELEASE = [
    (
        # Counted in, never counted out. The cap stays a ceiling and refuses
        # correctly forever after — so both ceiling rows stay green, because
        # neither of them ever expects a slot back. Only the row that closes a
        # held peer and waits for the next one to be admitted can see this.
        # `let _ = &in_flight;` rather than a deletion, so the closure still
        # consumes the handle and the mutation is a semantic change rather than
        # a compile error: a mutation the compiler refuses measures nothing
        # about the property it attacks.
        "count a connection in and never count it out",
        DECREMENT,
        """                    let _ = &in_flight;""",
        "a_slot_comes_back_when_a_peer_finishes",
    ),
]

CONCURRENCY = [
    (
        # Back to serving the connection on the accept thread, which is what
        # `main.rs` did before the change and what the surviving
        # `idle_connection_does_not_block_the_broker` row could not detect
        # because its 20s patience is longer than the 5s socket deadline. The
        # honest-client row bounds at 2s, so a serialised loop cannot reach it:
        # it has to wait out the silent peer's whole deadline first.
        "serve the connection on the accept thread again",
        SPAWN,
        SERVE_INLINE,
        "an_honest_client_is_answered_while_a_silent_peer_is_still_open",
    ),
]

BUCKETS = {
    "cap": CAP,
    "release": RELEASE,
    "concurrency": CONCURRENCY,
}


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "cap"
    f.PACKAGE = "asv-broker"
    # An integration target, not the lib: these rows spawn the real
    # `asv-brokerd` binary, and the binary is what the mutation changes.
    f.CARGO_TARGET = "--test concurrent_connections_do_not_queue"
    # Integration-test row names are already fully qualified.
    f.TEST_PREFIX = ""
    f.STS = MAIN
    # Three named bucket lists here, so the summary line must say three. The
    # framework only ever sees one bucket per invocation and cannot know.
    f.BUCKET_COUNT_LABEL = "three"
    mutations = BUCKETS[mode]
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    raise SystemExit(main())