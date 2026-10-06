#!/usr/bin/env python3
"""Falsification for B1.1, the bounded worker output bound.

A worker is a program the operator declared but did not write. Before this
bound, `read_to_end` on its pipes meant the broker's heap was whatever the
tool chose to print, so a tool logging in a loop took the control plane with
it. The 10s lifetime cap never covered that: it bounds how long the worker
runs, not how much it says while running.

**The property is two-sided and both halves are filed.** `a_worker_that_
never_stops_printing_is_capped_and_says_so` is the one that matters — a
producer with no end has to end as `OutputLimitExceeded`, promptly, with only
the capped prefix handed back. `a_worker_under_the_bound_reports_no_limit_
and_keeps_everything` is what stops the first from being satisfied by a reader
that drops everything unconditionally: if every run reported `limit_hit`, "the
bound works" would still be true and would mean nothing.

The third mutation is the one a reviewer should look at first. Reading a
capped prefix and *also* draining the tail is bounded memory too, and it
looks strictly safer — but a producer that never ends never reaches EOF, so
the child runs to the timeout and the run is recorded as `TimedOut`. That is
a different claim about a different fault, and it loses the fact that the
broker stopped it. The mutation turns the close back into a drain, and the
first row goes green again: proof that the promptness in that row is carried
by closing the pipe, not by anything else in the run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sts_falsify", HERE / "sts_falsify.py")
assert spec and spec.loader, "sts_falsify.py did not load"
f = importlib.util.module_from_spec(spec)
sys.modules["sts_falsify"] = f
spec.loader.exec_module(f)

REPO = HERE.parent.parent
WORKER = REPO / "crates/broker/src/worker.rs"

MUTATIONS: list[tuple[str, str, str, str]] = [
    (
        # The whole bound. Without it there is no limit to hit, so the capped
        # row cannot distinguish "the worker stopped" from "the broker gave up".
        "read the worker's pipe without a bound",
        "    std::io::Read::take(&mut *pipe, limit as u64 + 1).read_to_end(&mut kept)?;",
        "    std::io::Read::take(&mut *pipe, u64::MAX).read_to_end(&mut kept)?;",
        "a_worker_that_never_stops_printing_is_capped_and_says_so",
    ),
    (
        # Keep the read bounded but forget to record that it was. The caller
        # would then be handed a truncated prefix as though it were the whole of
        # the output, which is the failure this exists to prevent.
        "forget that the read was truncated",
        """    Ok(Captured {
        bytes: kept,
        total: limit as u64 + 1,
        truncated: true,
    })""",
        """    Ok(Captured {
        bytes: kept,
        total: limit as u64 + 1,
        truncated: false,
    })""",
        "a_worker_that_never_stops_printing_is_capped_and_says_so",
    ),
    (
        # Drain the tail instead of closing the pipe. Memory stays bounded, so
        # nothing about `limit_hit` moves — but an endless producer never
        # reaches EOF, the child runs to the timeout, and the run is recorded as
        # `TimedOut`. The first row's promptness assertion is what catches it.
        "drain past the bound instead of closing the pipe",
        """    kept.truncate(limit);""",
        """    kept.truncate(limit);
    std::io::copy(pipe, &mut std::io::sink())?;""",
        "a_worker_that_never_stops_printing_is_capped_and_says_so",
    ),
    (
        # The pair's other half. If every run reported `limit_hit`, the capped
        # row above would still pass, and "the bound works" would be unfalsifiable
        # in the direction that matters.
        "report every run as capped",
        "        stdout.truncated || stderr.truncated || total > limits.max_total_bytes as u64;",
        "        true;",
        "a_worker_under_the_bound_reports_no_limit_and_keeps_everything",
    ),
]


def main() -> int:
    f.STS = WORKER
    f.TEST_PREFIX = "worker::tests::"
    f.CARGO_TARGET = "--lib"
    f.MUTATIONS[:] = MUTATIONS
    original = WORKER.read_text()
    print(f"# falsifying {WORKER.relative_to(REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert WORKER.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())