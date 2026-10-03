#!/usr/bin/env python3
"""Falsification campaign for the C2.7-D vertical.

The vertical asserts four things that no other test in the repository measures
end to end: that a surrogate is refused outside the session that minted it, that
a fresh session's own surrogate still works, that the substitution is written to
the durable audit chain, and that the chain verifier can see a break. Each is
falsified here by deleting the control it covers and requiring a named
assertion to go red.

Two rules this campaign follows because both were learned the hard way:

*   `cargo build --workspace` before every run. The vertical launches the real
    `asv-brokerd` and the real `asv` binaries; a mutation in a library that only
    rebuilds the test target leaves the binaries stale, and the test then passes
    against unmutated code — which is how the first run of this campaign
    "passed" everything.
*   Restore in `finally`, from a copy taken before the mutation, and rebuild
    after. A campaign that leaves a mutation behind reports a suite nobody can
    reproduce.

Run from the repository root:

    python3 tests/connect_vertical_falsification.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_BINARY = "connect_vertical_e2e"
VERTICAL = "asv_run_curl_reaches_the_origin_with_the_real_credential_and_nobody_else"
TIMEOUT = 300


@dataclass(frozen=True)
class Mutation:
    """One control removed, and the assertion that must notice."""

    name: str
    target: Path
    before: str
    after: str
    #: A fragment of the failure the mutated code has to produce. The run is
    #: only a pass if the test fails *and* says this, which is what separates
    #: "the assertion fired" from "the test broke for some other reason".
    expect: str


MUTATIONS: list[Mutation] = [
    Mutation(
        name="M1 a surrogate is redeemable by any session",
        target=ROOT / "crates/broker/src/surrogate.rs",
        before="""        if record.session != session {
            return Err(SurrogateError::WrongSession);
        }""",
        after="""        if false {
            return Err(SurrogateError::WrongSession);
        }""",
        expect="a live session's surrogate was redeemed by a different one",
    ),
    Mutation(
        name="M2 the chain verifier cannot see a break",
        target=ROOT / "crates/broker/src/audit.rs",
        before="""pub fn verify_file(path: &Path) -> Result<(), AuditFileError> {
    let bytes = std::fs::read(path).map_err(AuditFileError::Io)?;""",
        after="""pub fn verify_file(path: &Path) -> Result<(), AuditFileError> {
    if std::path::Path::new("x").exists() {
        return Err(AuditFileError::Io(std::io::Error::other("unreachable")));
    }
    return Ok(());
    #[allow(unreachable_code)]
    let bytes = std::fs::read(path).map_err(AuditFileError::Io)?;""",
        expect="the chain verifier accepted an altered record",
    ),
    Mutation(
        name="M3 the substitution is not recorded as a substitution",
        target=ROOT / "crates/broker/src/connect_runtime.rs",
        before="""            outcome: outcome.to_string(),""",
        after="""            outcome: "unrecorded".to_string(),""",
        expect="expected both authorised substitutions to be recorded",
    ),
    Mutation(
        name="M4 the chain records a destination nobody authorised",
        target=ROOT / "crates/broker/src/tls_bridge.rs",
        before="""        let destination = format!("{}:{}", self.target.host(), self.target.port());""",
        after="""        let destination = format!("elsewhere.invalid:{}", self.target.port());""",
        expect="a recorded substitution names a destination nobody authorised",
    ),
    Mutation(
        name="M5 the child is handed an empty surrogate",
        target=ROOT / "crates/cli/src/main.rs",
        before='            &grant.token,',
        after='            "",',
        expect="the tunnel did not complete; curl reported something other than 200",
    ),
]


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )
    return proc.returncode, proc.stdout + proc.stderr


def one(mutation: Mutation) -> bool:
    """Apply, build, require red, restore. Returns True when it was falsified."""
    source = mutation.target.read_text()
    if mutation.before not in source:
        print(f"SKIP  {mutation.name}: the anchor text is not in {mutation.target}")
        return False

    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / mutation.target.name
        shutil.copy2(mutation.target, backup)
        try:
            mutation.target.write_text(source.replace(mutation.before, mutation.after, 1))
            build_rc, build_out = run(["cargo", "build", "--workspace"])
            if build_rc != 0:
                print(f"FAIL  {mutation.name}: the workspace did not build")
                print(build_out[-2000:])
                return False
            _, test_out = run(
                [
                    "cargo",
                    "test",
                    "-p",
                    "asv-broker",
                    "--test",
                    TEST_BINARY,
                    "--",
                    "--exact",
                    "--test-threads=1",
                    VERTICAL,
                ]
            )
            red = "test result: FAILED" in test_out
            right_reason = mutation.expect in test_out
            if red and right_reason:
                print(f"RED   {mutation.name}")
                print("      the named assertion caught it")
                return True
            if not red:
                print(f"ESCAPED  {mutation.name}: the test stayed green")
                print(test_out[-2000:])
                return False
            print(f"WRONG  {mutation.name}: red, but not for the expected reason")
            print(f"      expected: {mutation.expect!r}")
            print(test_out[-2000:])
            return False
        finally:
            mutation.target.write_text(backup.read_text())
            run(["cargo", "build", "--workspace"])


def main() -> int:
    results = [one(m) for m in MUTATIONS]
    falsified = sum(1 for r in results if r)
    print()
    print(f"{falsified}/{len(MUTATIONS)} mutations went red for the right reason")
    return 0 if falsified == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
