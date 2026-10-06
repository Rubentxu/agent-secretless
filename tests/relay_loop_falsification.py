#!/usr/bin/env python3
"""Falsification campaign for the multi-request relay (C2.8 increment 3b).

A relay loop's claims are all of the form "this byte was relayed" or "that
message was refused", and every one of them can be satisfied by a loop that is
slightly wrong in a way no assertion notices. So each row below breaks one thing
the loop is supposed to get right and requires a **named** assertion to go red. A
row where the suite stays green is a property nothing is watching.

Six of these rows are here because the campaign found the defect when it was
written, not because the defect was anticipated:

*   `relay_chunked` **read the CRLF terminating each chunk and dropped it** — 26
    bytes counted against 22 written. L3 deletes the write and a client parsing
    the body finds the next chunk's size line where its data was supposed to end.
*   A client hanging up at a message boundary, which is how every keep-alive
    connection ends, was reported as an I/O error. L4 puts the error back, and
    with a loop it lands on **every ordinary teardown** rather than on an
    occasional one.
*   A body over the per-message limit was classified `malformed_request`, which
    blames the peer for a number chosen in this repository. L8 puts that
    classification back and the operator-facing class changes.
*   The lifetime budget was **spent after the body was copied**, not before: an
    origin declaring a `Content-Length` of eight gigabytes had all eight
    gigabytes forwarded to the client before the tunnel noticed. R10 puts the
    check back where it was and the byte count the client holds is the
    observation.
*   A close-delimited response that ran past the cap was **cut at the cap and
    reported complete** — a head promising 512 bytes, 181 of them, and a clean
    end. R17 deletes the one-byte look that distinguishes "exactly the budget"
    from "past it".
*   A response head was not charged to the budget at all. R16 puts the check
    back in front of the write.

Two of the sixteen rows were **pointing at a test that could not fail for the
reason it named**, which is the failure mode this campaign exists to find and
therefore the one worth writing down. L6 named the per-chunk budget check, but
the running total refuses everything that check refuses, so deleting it changed
nothing; and the version of that test that claimed to isolate the framing check
made an arithmetic claim about its own fixture that was simply false. The row
now names the one input that reaches the running total on its own — a terminal
chunk — and the assertion that fires is the byte count on the client side of the
copy. A row whose arithmetic is not checked is a row that survives the defect it
was written to catch.

The campaign runs two suites, because the loop's claims are split across two
kinds of test and a mutation usually reaches only one of them:

*   `--lib` for the pieces that are pure: the chunked copy, the size parser, the
    clean-close read.
*   the UAT-010 binary for the pieces that need a real TLS tunnel: per-request
    re-substitution, the budgets, the three refusals.

Run from the repository root:

    python3 tests/relay_loop_falsification.py

A subset, by index or by substring:

    python3 tests/relay_loop_falsification.py 4 7
    python3 tests/relay_loop_falsification.py chunk
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Generous, and the reason is measured rather than guessed. The broker's lib
# suite takes ~287 s with `--test-threads=1` on this host — the key derivation in
# every fixture is deliberately expensive — and a rebuild on top of that pushed
# the first version of this campaign past a 600 s deadline. It did not hang: it
# was killed mid-run, and a killed run with no `test result:` line was being
# reported as ESCAPED, which is the one verdict a campaign must never invent.
TIMEOUT = 2400
BRIDGE = ROOT / "crates/broker/src/tls_bridge.rs"
FRAME = ROOT / "crates/broker/src/http_frame.rs"
UAT = ROOT / "crates/broker/tests/uat_010_connect_substitution.rs"
RUNTIME = ROOT / "crates/broker/src/connect_runtime.rs"


@dataclass(frozen=True)
class Mutation:
    name: str
    path: Path
    #: One or more `(before, after)` pairs. More than one where the mutation has
    #: to introduce something as well as change something — a reused token needs
    #: a field to live in — because a row that cannot be expressed as a single
    #: edit is better expressed as two than quietly dropped.
    edits: tuple[tuple[str, str], ...]
    #: `--lib` or `--test uat_010_connect_substitution`
    suite: str
    expect: str

    @property
    def before(self) -> str:
        """The first edit's anchor, for the pre-flight anchor check."""
        return self.edits[0][0]


# Every mutation makes the relay wrong in the direction of *relaying more*, or of
# *reporting less*, and every expectation is the words of the assertion that
# exists to hold the line.
MUTATIONS: list[Mutation] = [
    Mutation(
        name='R1 the loop carries one request and stops',
        path=BRIDGE,
        edits=(("                break;\n            }\n        }\n\n        Ok(SubstitutionOutcome {",
                "                break 'exchange;\n            }\n        }\n\n        Ok(SubstitutionOutcome {"),),
        suite='--test uat_010_connect_substitution',
        # The bare `break` inside the response loop becomes `break 'exchange`, so
        # the tunnel ends after one response. The first attempt at this row
        # replaced the `while let` with a bounded `for` and did not compile —
        # a closure capturing `self` twice is not a mutation, it is a different
        # program.
        #
        # The failure lands in `read_head_str`'s own `expect` and not in the
        # `assert_eq!` around it, because the comparison's argument is the read
        # that blocks: the tunnel is gone, so the client waits for an answer that
        # is never coming and the reader gives up first. A row names the
        # assertion that actually fired, not the one that would have been tidier.
        expect='client reads one response head',
    ),
    Mutation(
        name='R2 the rewritten head is not what reaches the origin',
        path=BRIDGE,
        edits=(("""            self.upstream
                .write_all(&rewritten)
                .map_err(|e| BridgeError::Io(e.to_string()))?;""",
                """            self.upstream
                .write_all(&head)
                .map_err(|e| BridgeError::Io(e.to_string()))?;"""),),
        suite="--test uat_010_connect_substitution",
        # The exact thing `relay_substituted`'s contract refuses to do: forward
        # the client's own token and let the provider reject it. The mutation
        # this row replaced — re-using an already-redeemed token — was
        # *invisible*, because the token was still redeemable and produced the
        # same credential. A row nobody can see is a row for a different
        # property.
        #
        # And the assertion that fires is not the one about a surrogate reaching
        # the destination, which was the first guess: six tests go red, and the
        # one whose message names the rewritten head losing is
        # `a_valid_proof_resolves_its_session_and_the_origin_receives_the_credential`.
        expect='the origin did not receive the real credential',
    ),
    Mutation(
        name='R3 a request body is relayed by a window instead of by its declared length',
        path=BRIDGE,
        edits=(('                http_frame::Framing::Length(n) => {\n                    let want = n as usize;\n                    let copied = relay_bytes(\n                        &mut self.client,\n                        &mut self.upstream,\n                        want,\n                        &session,\n                        source,\n                        cancellable,\n                    )?;',
                '                http_frame::Framing::Length(n) => {\n                    // The scan-for-the-terminator relay: read a window rather\n                    // than the declared length, which is the mistake the framing\n                    // layer exists to prevent. The body staged here is 39 bytes\n                    // long and contains CRLFCRLF twice.\n                    let _ = n;\n                    let copied = relay_bytes(\n                        &mut self.client,\n                        &mut self.upstream,\n                        4,\n                        &session,\n                        source,\n                        cancellable,\n                    )?;\n                    let want = copied;'),),
        suite='--test uat_010_connect_substitution',
        # The failure surfaces on the client: the origin never receives a whole
        # request, so it never answers, so the client is still waiting for a
        # head. That is the clearest statement of what the declared length is
        # for, and it is the assertion that actually fires.
        expect='client reads one response head',
    ),
    Mutation(
        name='L3 the CRLF that ends each chunk is read and dropped',
        path=BRIDGE,
        edits=(('        if &terminator != b"\\r\\n" {\n            return Err(BridgeError::Io("a chunk was not terminated by CRLF".into()));\n        }\n        to.write_all(b"\\r\\n")\n            .map_err(|e| BridgeError::Io(e.to_string()))?;',
                '        if &terminator != b"\\r\\n" {\n            return Err(BridgeError::Io("a chunk was not terminated by CRLF".into()));\n        }'),),
        suite='--lib',
        # **This wording was right all along, and it was being reported wrong.**
        # `crates/broker/src/binary.rs` muted the process panic hook and, with two
        # overlapping guards, left it muted -- so every failure in the lib binary
        # printed no message at all and this row came back WRONG with nothing to
        # read. Re-anchoring the expectation would have "fixed" the campaign by
        # pointing it at an assertion that never fires: the byte count at
        # tls_bridge.rs:1539 panics first, so the "framing was rewritten"
        # assertion at the end of the row is never reached. The defect was the
        # swallowed reason, not the expectation.
        expect='the byte count and the bytes written disagree',
    ),
    Mutation(
        name='L4 a chunk terminator that is not a CRLF is repaired rather than refused',
        path=BRIDGE,
        edits=(('        if &terminator != b"\\r\\n" {\n            return Err(BridgeError::Io("a chunk was not terminated by CRLF".into()));\n        }',
                '        if &terminator != b"\\r\\n" {}'),),
        suite='--lib',
        # **These two rows were the same mutation under two names until the
        # campaign said so.** L3's replacement re-added the write it meant to
        # delete, so it actually neutered the *check* — which is L4's defect and
        # L4's name. L4's own replacement, a bare `if false {`, left the block
        # unclosed and did not compile, so the runner skipped it. Neither row
        # was testing what its name said, and one of them was passing for the
        # other's reason.
        #
        # L3 now deletes the write and keeps the check, which is the original
        # defect: 26 bytes counted against 22 written. L4 keeps the write and
        # empties the check, so a body with `XX` where the CRLF belongs is
        # repaired into one the client can parse.
        expect='a chunk with no CRLF after its data is not a chunked body',
    ),
    Mutation(
        name='L5 a chunk size a second parser could read differently is accepted',
        path=BRIDGE,
        edits=(('    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_hexdigit()) {',
                '    if digits.is_empty() {'),),
        suite='--lib',
        expect='was accepted as a chunk size',
    ),
    Mutation(
        name='L6 a chunked body over the budget is copied anyway',
        path=BRIDGE,
        edits=(('        if total > max {\n            return Err(limit_spent(\n                "max_body",\n                format!("a chunked body of more than {max} bytes, including its framing"),\n            ));\n        }',
                '        let _ = max;'),),
        suite='--lib',
        # **Re-anchored, because the row it pointed at was decoration.** The
        # per-chunk check (`body_end > max`) fires first for a single oversized
        # chunk, so the test that named this row kept passing with it deleted.
        # And the running total cannot be reached on its own either, since every
        # chunk sets `total = body_end` on the way out — except when the offending
        # line is the *terminal* chunk's, because `size == 0` breaks before
        # `body_end` exists. The assertion that fires is the byte count on the
        # client side of the copy: the refused terminal size line was never
        # written.
        expect='the relay wrote the size line of the chunk it had just refused',
    ),
    Mutation(
        name='L7 a client hanging up is an I/O error again',
        path=BRIDGE,
        edits=(('            Ok(_) => return Ok(None),\n            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),',
                '            Ok(_) => return Err(BridgeError::Io("unexpected end of stream".into())),\n            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {\n                return Err(BridgeError::Io(e.to_string()))\n            }'),),
        suite='--test uat_010_connect_substitution',
        expect='a body-carrying request followed by a plain one',
    ),
    Mutation(
        name='L8 an over-limit body is reported as a malformed request',
        path=BRIDGE,
        edits=(("""    match error {
        http_frame::FrameError::TooLarge { limit, subject } => BridgeError::Limit {
            budget: match subject {
                http_frame::Subject::Head => "max_head",
                http_frame::Subject::Body => "max_body",
            },
            detail: format!("{what} whose {subject} is over the {limit}-byte limit"),
        },
        other => BridgeError::Protocol(format!("{what} this relay will not frame: {other}")),
    }""",
                """    match error {
        other => BridgeError::Protocol(format!("{what} this relay will not frame: {other}")),
    }"""),),
        suite="--test uat_010_connect_substitution",
        expect="which reports a deliberate limit as something else",
    ),
    Mutation(
        name='R9 a tunnel that reaches its request budget says nothing about it',
        path=BRIDGE,
        edits=(("                    request_budget_spent = true;\n                    break 'exchange;",
                "                    break 'exchange;"),),
        suite='--test uat_010_connect_substitution',
        expect='ended at the request budget and did not say so',
    ),
    Mutation(
        name='R10 a declared response body is copied before the budget is checked',
        path=BRIDGE,
        edits=(('                        if want > remaining {\n                            return Err(limit_spent(',
                '                        if false {\n                            return Err(limit_spent('),),
        suite='--test uat_010_connect_substitution',
        # The budget used to be spent by adding `body` to `returned` *after* the
        # copy, so an origin declaring a `Content-Length` of eight gigabytes had
        # all eight gigabytes on the wire to the client before the tunnel
        # noticed. The check is in front of the copy now, and the observation is
        # the byte count the client ends up holding.
        expect='was spent after the copy',
    ),
    Mutation(
        name='R16 a response head is put on the wire past the lifetime budget',
        path=BRIDGE,
        edits=(('                if response_head.len() > limits.max_response.saturating_sub(returned) {',
                '                if false {'),),
        suite='--test uat_010_connect_substitution',
        # This row is what found that the subtraction below the head check was a
        # plain `-` leaning on this very check: with the check gone, the second
        # response of an over-budget tunnel panicked on `usize` underflow in a
        # worker thread. Saturating, the mutation is caught by the tunnel
        # refusing nothing.
        expect='the head went on the wire past the lifetime budget',
    ),
    Mutation(
        name='R17 a close-delimited body is cut at the cap and called complete',
        path=BRIDGE,
        edits=(('                        if copied == remaining\n                            && read_byte_cancellable(',
                '                        if false\n                            && read_byte_cancellable('),),
        suite='--test uat_010_connect_substitution',
        expect='it was cut at the cap and reported as complete',
    ),
    Mutation(
        name='R11 Expect: 100-continue is served like an ordinary request',
        path=FRAME,
        edits=(('    Fields::of(head, true)\n        .map(|fields| {\n            fields\n                .values("expect")\n                .into_iter()\n                .filter_map(|v| std::str::from_utf8(v).ok())\n                .any(|v| v.trim().eq_ignore_ascii_case("100-continue"))\n        })\n        .unwrap_or(false)',
                '    let _ = head;\n    false'),),
        suite='--test uat_010_connect_substitution',
        expect='was refused as',
    ),
    Mutation(
        name='R12 Upgrade is served like an ordinary request',
        path=FRAME,
        edits=(('    Fields::of(head, true)\n        .map(|fields| fields.has("upgrade"))\n        .unwrap_or(false)',
                '    let _ = head;\n    false'),),
        suite='--test uat_010_connect_substitution',
        expect='was refused as',
    ),
    Mutation(
        name='R13 a 101 from the origin is treated as an ordinary response',
        path=BRIDGE,
        edits=(('                if response.status == Some(101) {',
                '                if false && response.status == Some(101) {'),),
        suite='--test uat_010_connect_substitution',
        expect='a 101 was refused as',
    ),
    Mutation(
        name='R14 a 100 is treated as the end of the exchange',
        path=BRIDGE,
        edits=(('                if response.status.is_some_and(|s| (100..200).contains(&s)) {\n                    continue;\n                }',
                '                if response.status.is_some_and(|s| (100..200).contains(&s)) {\n                    break;\n                }'),),
        suite='--test uat_010_connect_substitution',
        expect='client reads one response head',
    ),
    Mutation(
        name="R15 the request count is not in the operator's line",
        path=RUNTIME,
        edits=(('            requests = outcome.requests,\n            request_budget_spent = outcome.request_budget_spent,',
                '            requests = 1,'),),
        suite="--test connect_vertical_e2e",
        expect="does not say the tunnel carried two requests",
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


def cargo_for(suite: str) -> list[str]:
    if suite == "--lib":
        # **Not serialised**, unlike the other campaigns in this directory, and
        # the reason is the measurement above: this suite's cost is per-fixture
        # key derivation, so `--test-threads=1` multiplies it by the core count
        # and buys nothing — the rows here mutate one function, and cargo runs
        # the resulting binary exactly as CI does.
        return ["cargo", "test", "-p", "asv-broker", "--lib"]
    return [
        "cargo",
        "test",
        "-p",
        "asv-broker",
        "--test",
        suite.removeprefix("--test "),
        "--",
        "--test-threads=1",
    ]


def check(mutation: Mutation) -> bool:
    rc, out = run(cargo_for(mutation.suite))
    if rc is None:
        say(f"RED   {mutation.name} — hung and was killed")
        return True
    if "test result:" not in out:
        # A run with no result line at all is not a pass and not a failure: it
        # was killed, or it never got as far as running anything. Reporting that
        # as ESCAPED would be the campaign inventing the one verdict it exists
        # to avoid, and the first version of this runner did exactly that.
        say(f"KILLED  {mutation.name}: the run produced no result line at all")
        print(out[-2500:])
        return False
    if "test result: FAILED" not in out:
        say(f"ESCAPED  {mutation.name}: every test in {mutation.suite} stayed green")
        print(out[-2500:])
        return False
    # **Searched over the whole output, not its tail.** A failure that names its
    # assertion can appear anywhere in the listing, and a campaign that only
    # reads the last few hundred characters calls a correctly-caught mutation
    # WRONG whenever the test order puts the interesting failure higher up.
    if mutation.expect not in out:
        say(f"WRONG  {mutation.name}: red, but not for the expected reason")
        say(f"      expected: {mutation.expect!r}")
        print(out[-2500:])
        return False
    say(f"RED   {mutation.name}")
    say(f"      the named assertion caught it: {mutation.expect!r}")
    return True


def one(mutation: Mutation) -> bool:
    source = mutation.path.read_text()
    missing = [
        index
        for index, (before, _) in enumerate(mutation.edits)
        if before not in source
    ]
    if missing:
        say(
            f"SKIP  {mutation.name}: the anchor for edit(s) {missing} is not in "
            f"{mutation.path}"
        )
        return False
    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / mutation.path.name
        shutil.copy2(mutation.path, backup)
        try:
            mutated = source
            for before, after in mutation.edits:
                mutated = mutated.replace(before, after, 1)
            mutation.path.write_text(mutated)
            args = cargo_for(mutation.suite)
            rc, out = run([*args[: args.index("--")], "--no-run"] if "--" in args else [*args, "--no-run"])
            if rc != 0:
                say(f"SKIP  {mutation.name}: the mutation does not compile")
                print(out[-1500:])
                return False
            return check(mutation)
        finally:
            # Restored in `finally` and not on the success path, because the
            # success path is exactly the one where somebody is tempted to skip
            # it. A campaign killed from outside leaves a mutation in the tree
            # and no output saying so; this at least cannot be the cause.
            mutation.path.write_text(backup.read_text())


def residue() -> bool:
    """Any mutation left in the tree after the run."""
    dirty = [
        str(path.relative_to(ROOT))
        for path in (BRIDGE, FRAME, UAT, RUNTIME)
        if path.read_text() != ORIGINAL[path]
    ]
    if dirty:
        print(f"MUTATION RESIDUE in {', '.join(dirty)}")
        return False
    print("no mutation residue in the tree")
    return True


ORIGINAL: dict[Path, str] = {}


def main() -> int:
    wanted = MUTATIONS
    if len(sys.argv) > 1:
        # **Union, not intersection.** The first version filtered `wanted` once
        # per argument, so two arguments narrowed twice and asked for a row that
        # had both properties. With names like `R1`, `R10` and `R11` sharing a
        # prefix that is not a corner case either: asking for `R1` and `L3`
        # silently selected nothing, and the campaign reported zero rows run as
        # a clean result rather than as the empty selection it was.
        picked: list[Mutation] = []
        for arg in sys.argv[1:]:
            if arg.isdigit():
                index = int(arg) - 1
                if not 0 <= index < len(MUTATIONS):
                    say(f"no row {index + 1}: the campaign has {len(MUTATIONS)}")
                    return 1
                picked.append(MUTATIONS[index])
            else:
                hits = [m for m in MUTATIONS if arg.lower() in m.name.lower()]
                if not hits:
                    say(f"no row matches {arg!r}")
                    return 1
                picked.extend(hits)
        seen: set[str] = set()
        wanted = [m for m in picked if not (m.name in seen or seen.add(m.name))]

    for path in (BRIDGE, FRAME, UAT, RUNTIME):
        ORIGINAL[path] = path.read_text()

    for mutation in wanted:
        say(f"\n=== {mutation.name}")
    say("")
    results = [one(m) for m in wanted]
    falsified = sum(1 for r in results if r)
    say("")
    clean = residue()
    say(f"{falsified}/{len(wanted)} mutations went red for the right reason")
    return 0 if falsified == len(wanted) and clean else 1


if __name__ == "__main__":
    sys.exit(main())
