#!/usr/bin/env python3
"""Falsification campaign for the C2.8 observability sweep.

The sweep found one real defect and one property that held. Both needed to be
measurable, and the defect was measurable only because the test was written as
a claim and watched fail:

*   `a_client_with_no_credential_cannot_write_its_own_text_into_the_operator_log`
    was **red** against a broker that let a bare socket write its own words
    into the operator's log, unauthenticated, because `parse_connect_target`
    runs before the session proof is looked at and
    `ConnectTargetError::NoPort` carries the request line's authority verbatim.
    The durable chain was already protected; the operator's line was not, and
    the two disagreed for most variants because the chain recovered its class by
    matching on rendered text.

*   `the_brokers_own_log_carries_neither_the_credential_nor_a_surrogate` was
    green from the start. It is here because the surface had never been checked
    at all, and a sweep that only reports the defect it found is a sweep that
    cannot be re-run against a future change to the surface it did not find.

## What the rules are

*   `cargo build --workspace` before every run. Both tests launch the real
    `asv-brokerd`; a mutation that only rebuilds the test target leaves a stale
    binary and the test passes against unmutated code.

*   Restore in `finally` from a copy taken before the mutation, and rebuild
    after.

*   A row counts only if the test goes red **and** says the expected words. A
    test that fails for another reason is an escape, not a detection.

Run from the repository root:

    python3 tests/connect_observability_falsification.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 300

VERTICAL = "connect_vertical_e2e"
CHAIN = "connect_audit_chain"
INJECTION = "a_client_with_no_credential_cannot_write_its_own_text_into_the_operator_log"
SWEEP = "the_brokers_own_log_carries_neither_the_credential_nor_a_surrogate"
PROVENANCE = "the_detail_is_dropped_for_exactly_the_errors_that_quote_the_client"
NEVER_QUOTES = "a_refusal_is_recorded_as_a_class_and_never_quotes_the_detail"


@dataclass(frozen=True)
class Target:
    binary: str
    test: str
    expect: str


@dataclass(frozen=True)
class Mutation:
    name: str
    target: Path
    before: str
    after: str
    targets: list[Target] = field(default_factory=list)


MUTATIONS: list[Mutation] = [
    Mutation(
        name="O1 the provenance rule is dropped for the client's own text",
        target=ROOT / "crates/broker/src/connect_runtime.rs",
        before="""pub fn refusal_detail(error: &BridgeError) -> Option<String> {
    match error {
        BridgeError::Protocol(_) => None,
        other => Some(other.to_string()),
    }
}""",
        after="""pub fn refusal_detail(error: &BridgeError) -> Option<String> {
    Some(error.to_string())
}""",
        targets=[
            Target(VERTICAL, INJECTION, "wrote its own text into the operator's log"),
            Target(
                CHAIN,
                PROVENANCE,
                "still offers that text to the operator's log",
            ),
        ],
    ),
    Mutation(
        name="O2 the chain records the detail instead of the class",
        target=ROOT / "crates/broker/src/connect_runtime.rs",
        before="""            ConnectionResult::Refused { class, .. } => (*class).to_string(),""",
        after="""            ConnectionResult::Refused { detail, .. } => detail
                .clone()
                .unwrap_or_else(|| "refused".to_string()),""",
        targets=[
            Target(
                CHAIN,
                NEVER_QUOTES,
                "the refusal detail reached the durable chain",
            ),
        ],
    ),
    Mutation(
        name="O3 a careless trace of the forwarded request prints the credential",
        target=ROOT / "crates/broker/src/tls_bridge.rs",
        before="""        let forwarded = rewritten.len();
        // The buffer that carried the credential upstream is wiped here, not
        // left to the allocator's discretion.""",
        after="""        let forwarded = rewritten.len();
        tracing::info!(
            head = ?String::from_utf8_lossy(&rewritten),
            forwarded,
            "forwarded the substituted request"
        );
        // The buffer that carried the credential upstream is wiped here, not
        // left to the allocator's discretion.""",
        targets=[
            Target(
                VERTICAL,
                SWEEP,
                "the real credential reached the operator's log",
            ),
        ],
    ),
    Mutation(
        name="O5 a careful-looking trace of the redemption prints the token",
        target=ROOT / "crates/broker/src/surrogate.rs",
        before="""        let credential = self
            .registry
            .redeem(surrogate, session, self.family, now_secs())""",
        after="""        tracing::info!(%surrogate, "redeemed a surrogate");
        let credential = self
            .registry
            .redeem(surrogate, session, self.family, now_secs())""",
        targets=[
            Target(
                VERTICAL,
                SWEEP,
                "a surrogate reached the operator's log",
            ),
        ],
    ),
    Mutation(
        name="O4 a refusal with no detail leaves no record",
        target=ROOT / "crates/broker/src/connect_runtime.rs",
        before="""        let verdict = outcome_wire_name(&outcome.result);""",
        after="""        if matches!(
            &outcome.result,
            ConnectionResult::Refused { detail: None, .. }
        ) {
            return;
        }
        let verdict = outcome_wire_name(&outcome.result);""",
        targets=[
            Target(
                CHAIN,
                "a_refusal_without_a_detail_is_still_recorded_with_its_class",
                "left no usable record",
            ),
        ],
    ),
]


def run(cmd: list[str], timeout: int = TIMEOUT) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        out = (expired.stdout or "") + (expired.stderr or "")
        return None, out if isinstance(out, str) else out.decode(errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def build() -> bool:
    rc, out = run(["cargo", "build", "--workspace"], timeout=1200)
    if rc != 0:
        print("FAIL  the workspace did not build")
        print(out[-2000:])
        return False
    return True


def check(target: Target) -> bool:
    rc, test_out = run(
        [
            "cargo", "test", "-p", "asv-broker", "--test", target.binary, "--",
            "--exact", "--test-threads=1", target.test,
        ]
    )
    if rc is None:
        print(f"RED   {target.test} [{target.binary}] — hung and was killed")
        return True
    if "test result: FAILED" not in test_out:
        print(f"ESCAPED  {target.test} [{target.binary}]: the test stayed green")
        print(test_out[-2000:])
        return False
    if target.expect not in test_out:
        print(f"WRONG  {target.test} [{target.binary}]: red, but not for the expected reason")
        print(f"      expected: {target.expect!r}")
        print(test_out[-2000:])
        return False
    print(f"RED   {target.test} [{target.binary}]")
    print(f"      the named assertion caught it: {target.expect!r}")
    return True


def one(mutation: Mutation) -> bool:
    source = mutation.target.read_text()
    if mutation.before not in source:
        print(f"SKIP  {mutation.name}: the anchor text is not in {mutation.target}")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / mutation.target.name
        shutil.copy2(mutation.target, backup)
        try:
            mutation.target.write_text(source.replace(mutation.before, mutation.after, 1))
            if not build():
                return False
            return all(check(t) for t in mutation.targets)
        finally:
            mutation.target.write_text(backup.read_text())
            build()


def main() -> int:
    for mutation in MUTATIONS:
        print(f"\n=== {mutation.name}")
    print()
    results = [one(m) for m in MUTATIONS]
    falsified = sum(1 for r in results if r)
    print()
    print(f"{falsified}/{len(MUTATIONS)} mutations went red for the right reason")
    return 0 if falsified == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
