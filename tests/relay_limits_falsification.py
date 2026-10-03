#!/usr/bin/env python3
"""Falsification campaign for the C2.8 relay limits (increments 2 and 3a).

Five numbers are in scope here, and every one of them is a value somebody could
lower again without a test noticing:

*   `MAX_SURROGATE_TTL_SECS` was 900 while the broker asked for 3600, and the
    gap was invisible because `mint` clamps **silently**. That is the third
    instance of the same line of code: the uses clamp had a test and was found
    and fixed, the TTL clamp had nobody looking at it and stayed live.
*   `MAX_SURROGATE_USES` was 32 against a measured 93 requests for a trivial
    `npm install express`, so the product refused a third of the way through.
*   `SESSION_SURROGATE_MAX_USES` was 32 against that same 93 — the **fourth**
    clamp, and the one that actually killed the product. Fixing the protocol
    ceiling to 8192 changed nothing, because `asv run` does not mint through
    `MintSurrogate`; it goes through `CreateSession`, which mints whatever this
    constant says. Raising the ceiling fixed the clamp and left the limit, and
    the tunnel's own `max_requests` of 4096 was a number no connection could
    reach. L8 is the row for it.
*   `RelayLimits` grew a `max_forwarded` because it had a bound on one direction
    and none on the other.
*   `max_requests` had to stay *below* the budget its own session was handed, or
    a connection dies for a reason that has nothing to do with the session
    holding it. That check used to compare against the protocol ceiling — a
    grant `asv run` never receives — and passed for the wrong reason.

Each row below moves one number back or breaks one relationship and requires a
**named** assertion to notice. A row where the suite stays green is a limit
nothing is watching, which is the failure this increment is about.

Run from the repository root:

    python3 tests/relay_limits_falsification.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 300

PROTOCOL = ROOT / "crates/ipc-protocol/src/lib.rs"
BRIDGE = ROOT / "crates/broker/src/tls_bridge.rs"
REGISTRY = ROOT / "crates/broker/src/surrogate.rs"
BROKER = ROOT / "crates/broker/src/lib.rs"


@dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    before: str
    after: str
    binary: str
    expect: str


MUTATIONS: list[Mutation] = [
    Mutation(
        name="L1 the TTL ceiling goes back to a quarter of what the broker asks for",
        path=PROTOCOL,
        before="pub const MAX_SURROGATE_TTL_SECS: u64 = 3600;",
        after="pub const MAX_SURROGATE_TTL_SECS: u64 = 900;",
        binary="--lib",
        expect="silently cut the surrogate lifetime",
    ),
    # **The protocol ceiling is no longer what holds the floor.** It used to be
    # assumed that lowering the ceiling to 32 would be caught by the divergence
    # test alone; it is not, and the comment above this row used to say so. What
    # holds the floor now is two things the fourth clamp forced into being: the
    # budget the session is actually handed, and the workload it has to pay for.
    Mutation(
        name="L2 the use ceiling goes back to a third of a trivial install",
        path=PROTOCOL,
        before="pub const MAX_SURROGATE_USES: u32 = 8192;",
        after="pub const MAX_SURROGATE_USES: u32 = 32;",
        binary="--lib",
        expect="a_session_surrogate_pays_for_a_workload_that_was_actually_run",
    ),
    Mutation(
        name="L3 mint stops clamping and honours whatever it is asked for",
        path=REGISTRY,
        before="        let ttl = ttl_secs.clamp(1, MAX_SURROGATE_TTL_SECS);\n"
               "        let uses = max_uses.clamp(1, MAX_SURROGATE_USES);",
        after="        let ttl = ttl_secs;\n        let uses = max_uses;",
        binary="--lib",
        expect="an absurd TTL must be clamped, not honoured",
    ),
    Mutation(
        name="L4 a single tunnel may spend more than its whole session",
        path=BRIDGE,
        before="            max_requests: 4096,",
        after="            max_requests: 1_000_000,",
        binary="--lib",
        expect="a_tunnel_is_bounded_below_the_budget_its_own_session_was_handed",
    ),
    Mutation(
        name="L5 the request direction goes unbudgeted",
        path=BRIDGE,
        before="            max_forwarded: 64 * 1024 * 1024,",
        after="            max_forwarded: 1024 * 1024,",
        binary="--lib",
        expect="a different budget from the response direction",
    ),
    Mutation(
        name="L6 the defaults fall back below a measured workload",
        path=BRIDGE,
        before="            max_requests: 4096,",
        after="            max_requests: 16,",
        binary="--lib",
        expect="the_defaults_cleared_a_measured_workload",
    ),
    Mutation(
        name="L7 the response cap falls back below a measured workload",
        path=BRIDGE,
        before="            max_response: 64 * 1024 * 1024,",
        after="            max_response: 1024 * 1024,",
        binary="--lib",
        expect="the_defaults_cleared_a_measured_workload",
    ),
    # **The row that would have caught the defect this increment fixed.**
    #
    # The session's budget is defined as the protocol's ceiling, so L2 lowers
    # both at once — and `session_mint_survives_the_protocol_ceiling`, which
    # exists to catch a silent clamp, is perfectly happy, because no clamp
    # happened. The product was broken by a constant that was *not* wrong on
    # its own terms: 32 against a measured 93. The two rows that catch it are
    # the one that spends the token and the one that compares the tunnel's cap
    # against the grant, and neither of them is the clamp test.
    Mutation(
        name="L8 the session budget goes back under a measured workload",
        path=BROKER,
        before="pub(crate) const SESSION_SURROGATE_MAX_USES: u32 = asv_ipc_protocol::MAX_SURROGATE_USES;",
        after="pub(crate) const SESSION_SURROGATE_MAX_USES: u32 = 32;",
        binary="--lib",
        expect="a_session_surrogate_pays_for_a_workload_that_was_actually_run",
    ),
]


def say(line: str) -> None:
    """Print and flush.

    Flushed because the failure this campaign's own hardening is about is being
    killed partway with a mutation in the tree. A run whose progress is sitting
    in a buffer tells nobody where it got to.
    """
    print(line, flush=True)


def run(cmd: list[str], timeout: int = TIMEOUT) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        out = (expired.stdout or "") + (expired.stderr or "")
        return None, out if isinstance(out, str) else out.decode(errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def check(mutation: Mutation) -> bool:
    rc, out = run(["cargo", "test", "-p", "asv-broker", *mutation.binary.split(), "--", "--test-threads=1"])
    if rc is None:
        say(f"RED   {mutation.name} — hung and was killed")
        return True
    if "test result: FAILED" not in out:
        say(f"ESCAPED  {mutation.name}: the whole broker lib stayed green")
        print(out[-2500:])
        return False
    # **Searched over the whole output, not its tail.** The first run of this
    # campaign scored 3 of 7 for four mutations that were in fact caught: the lib
    # test binary prints every failure, and with several of them the row this
    # check cares about lands well above the last 2500 characters. A campaign
    # that scores a detection as an escape because it did not read far enough is
    # worse than one that never ran.
    if mutation.expect not in out:
        say(f"WRONG  {mutation.name}: red, but not for the expected reason")
        say(f"      expected: {mutation.expect!r}")
        print(out[-2500:])
        return False
    print(f"RED   {mutation.name}")
    print(f"      the named assertion caught it: {mutation.expect!r}")
    return True


def one(mutation: Mutation) -> bool:
    source = mutation.path.read_text()
    if mutation.before not in source:
        say(f"SKIP  {mutation.name}: the anchor text is not in {mutation.path}")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / mutation.path.name
        shutil.copy2(mutation.path, backup)
        try:
            mutation.path.write_text(source.replace(mutation.before, mutation.after, 1))
            return check(mutation)
        finally:
            mutation.path.write_text(backup.read_text())


def main() -> int:
    # `python3 tests/relay_limits_falsification.py L2 L4` runs a subset. These
    # campaigns cost minutes per row, because each mutation rebuilds the crate
    # with all of its test binaries, and re-running rows that already passed in
    # order to fix a search fragment is not a cost worth paying.
    wanted = set(sys.argv[1:])
    chosen = [m for m in MUTATIONS if not wanted or m.name.split()[0] in wanted]
    for mutation in chosen:
        say(f"\n=== {mutation.name}")
    say("")
    results = [one(m) for m in chosen]
    # The self-check, and it exists because a real run of this campaign was
    # killed from outside partway through and left a mutation in the tree: a
    # `finally` restores on an exception, not on a signal that arrives while a
    # child `cargo` is holding the pipe open. So the last thing the campaign does
    # is read its own subjects back and prove they carry no mutation — a run
    # that ends without this line saying so has not been verified.
    residue = [m.name for m in MUTATIONS if m.after in m.path.read_text()]
    if residue:
        say(f"RESIDUE  a mutation is still in the tree: {residue}")
        return 1
    say("no mutation residue in the tree")
    falsified = sum(1 for r in results if r)
    print()
    # The denominator is what this run chose, not the size of the whole table.
    # It said 7 while four rows ran, which is a number nobody should believe —
    # and a campaign whose own summary lies about its coverage is the last
    # place to be casual about a figure.
    say(f"{falsified}/{len(chosen)} mutations went red for the right reason")
    if len(chosen) != len(MUTATIONS):
        say(f"  (subset run: {len(MUTATIONS)} rows exist; the other "
            f"{len(MUTATIONS) - len(chosen)} were not exercised here)")
    return 0 if falsified == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
