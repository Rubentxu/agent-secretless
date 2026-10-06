#!/usr/bin/env python3
"""Falsification campaign for the HTTP framing parser (C2.8 increment 1).

The parser's whole claim is that it **refuses** rather than guesses, and the
cases it refuses are the shapes that have been used for request smuggling: two
`Content-Length` headers with different values, `Content-Length` beside
`Transfer-Encoding`, a folded header, a length that is a number to one parser
and not to another.

A parser that is merely *tolerant* looks exactly like a parser that is correct
until somebody smuggles something through it, and none of these tests can catch
that by themselves — they assert on the parser's own output. So every row below
deletes one refusal and requires the named test to go red. A row where the test
stays green means a refusal nothing checks, which is the same decoration this
campaign exists to find.

Run from the repository root:

    python3 tests/http_frame_falsification.py
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
SOURCE = ROOT / "crates/broker/src/http_frame.rs"


@dataclass(frozen=True)
class Mutation:
    name: str
    before: str
    after: str
    expect: str


# Every mutation makes the parser *more tolerant*, and every expectation is the
# words of the test that exists to hold the line.
MUTATIONS: list[Mutation] = [
    Mutation(
        name="H1 the first Content-Length wins again",
        before="""                Some(previous) if previous != n => {
                    return Err(FrameError::Ambiguous {
                        detail: "Content-Length repeated with a different value",
                    })
                }
                _ => seen = Some(n),""",
        after="""                _ => seen = Some(n),""",
        expect="Content-Length repeated with a different value",
    ),
    Mutation(
        name="H2 Content-Length beside Transfer-Encoding is allowed",
        before="""        if fields.len_of("content-length")?.is_some() {
            return Err(FrameError::Ambiguous {
                detail: "both Content-Length and Transfer-Encoding",
            });
        }
        if !fields.transfer_encoding_is_chunked() {
            return Err(FrameError::Unsupported {
                detail: "Transfer-Encoding is not chunked",
            });
        }
        Framing::Chunked""",
        after="""        if !fields.transfer_encoding_is_chunked() {
            return Err(FrameError::Unsupported {
                detail: "Transfer-Encoding is not chunked",
            });
        }
        Framing::Chunked""",
        expect="both Content-Length and Transfer-Encoding",
    ),
    Mutation(
        name="H3 a folded header is unfolded again",
        before="""            if line[0] == b' ' || line[0] == b'\\t' {
                return Err(FrameError::Ambiguous {
                    detail: "obsolete line folding in a header",
                });
            }""",
        after="""            if line[0] == b' ' || line[0] == b'\\t' {
                // mutation: the continuation line is dropped rather than refused,
                // which is what a parser that does not implement folding does
                continue;
            }""",
        expect="obsolete line folding in a header",
    ),
    Mutation(
        name="H4 a leading zero is a number like any other",
        before="""    if value.len() > 1 && value[0] == b'0' {
        return Err(FrameError::Ambiguous {
            detail: "Content-Length has a leading zero",
        });
    }""",
        after="""    // mutation: a leading zero is accepted""",
        expect="was accepted, and it is a length some other parser reads differently",
    ),
    Mutation(
        name="H5 a Content-Length list is read as its first entry",
        before="""    if value.contains(&b',') {
        return Err(FrameError::Ambiguous {
            detail: "Content-Length carries a list",
        });
    }""",
        after="""    // mutation: a list is accepted""",
        expect="Content-Length carries a list",
    ),
    Mutation(
        name="H6 an unknown method is relayed anyway",
        before="""        return Err(FrameError::Unsupported {
            detail: "unrecognised request method",
        });""",
        after="""        // mutation: any method is relayed""",
        expect="unrecognised request method",
    ),
    Mutation(
        name="H7 a head over the limit is truncated rather than refused",
        before="""            if len > max {
                return Err(FrameError::TooLarge {
                    limit: max,
                    subject: Subject::Head,
                });
            }
            Ok(Some(len))""",
        # **Re-anchored.** `FrameError::TooLarge` carries a `subject` now, so
        # the error is built over three lines rather than one and the old
        # spelling occurs nowhere. The refusal is the same one: a head longer
        # than the cap is refused, not truncated and not kept buffering.
        after="""            if len > max {
                // MUTANT: an oversized head is answered "not yet", so the
                // caller keeps buffering a head it will never accept
                return Ok(None);
            }
            Ok(Some(len))""",
        # This test uses `assert_eq!` with no message of its own, so what the
        # runner prints is the `Debug` of the two sides. Matching the variant
        # name is the honest fragment to look for; the `Display` string never
        # appears.
        expect="TooLarge",
    ),
    Mutation(
        name="H8 a 304 is given a body to wait for",
        before="""    if (100..200).contains(&status) || status == 204 || status == 304 {""",
        after="""    if false {""",
        expect="was given a body to wait for",
    ),
    Mutation(
        name="H9 a response with no framing headers is refused instead of run to close",
        before="""            // No length and no chunking: the body ends when the peer closes. That
            // is the specification's rule, and it is the *only* correct answer —
            // refusing it would break a large share of real servers, and unlike
            // the ambiguous cases above there is nothing here for a second parser
            // to disagree about.
            None => Framing::UntilClose,""",
        after="""            None => {
                return Err(FrameError::Unsupported {
                    detail: "a response with no framing headers",
                })
            }""",
        expect="runs_until_the_peer_closes",
    ),
    Mutation(
        name="H10 the last Transfer-Encoding is not the one that counts",
        before="""            .next_back()
            .map(|last| last.trim().eq_ignore_ascii_case("chunked"))
            .unwrap_or(false)""",
        after="""            .next()
            .map(|last| last.trim().eq_ignore_ascii_case("chunked"))
            .unwrap_or(false)""",
        # Taking the *first* encoding makes `gzip, chunked` look like plain
        # `gzip`, so the very first assertion in the test fails — on the
        # `.expect("framed")`, not on the `chunked, gzip` case. The mutation is
        # caught earlier than the case it was aimed at, and the expectation has
        # to name the assertion that actually fired.
        expect="Transfer-Encoding is not chunked",
    ),
    Mutation(
        name="H11 header names are compared case-sensitively",
        before="""            .filter(|(key, _)| key.eq_ignore_ascii_case(name.as_bytes()))""",
        after="""            .filter(|(key, _)| *key == name.as_bytes())""",
        # A case-sensitive comparison makes `cOnTeNt-LeNgTh` invisible, so the
        # request parses as a body-less one and the head carries a length nobody
        # on this side is reading.
        expect="Length(7)",
    ),
]


def run(cmd: list[str], timeout: int = TIMEOUT) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        out = (expired.stdout or "") + (expired.stderr or "")
        return None, out if isinstance(out, str) else out.decode(errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def check(mutation: Mutation) -> bool:
    rc, out = run(["cargo", "test", "-p", "asv-broker", "--lib", "http_frame", "--", "--test-threads=1"])
    if rc is None:
        print(f"RED   {mutation.name} — hung and was killed")
        return True
    if "test result: FAILED" not in out:
        print(f"ESCAPED  {mutation.name}: every framing test stayed green")
        print(out[-2500:])
        return False
    if mutation.expect not in out:
        print(f"WRONG  {mutation.name}: red, but not for the expected reason")
        print(f"      expected: {mutation.expect!r}")
        print(out[-2500:])
        return False
    print(f"RED   {mutation.name}")
    print(f"      the named assertion caught it: {mutation.expect!r}")
    return True


def one(mutation: Mutation) -> bool:
    source = SOURCE.read_text()
    if mutation.before not in source:
        print(f"SKIP  {mutation.name}: the anchor text is not in {SOURCE}")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        backup = Path(tmp) / SOURCE.name
        shutil.copy2(SOURCE, backup)
        try:
            SOURCE.write_text(source.replace(mutation.before, mutation.after, 1))
            rc, out = run(["cargo", "test", "-p", "asv-broker", "--lib", "http_frame", "--no-run"])
            if rc != 0:
                print(f"SKIP  {mutation.name}: the mutation does not compile")
                print(out[-1500:])
                return False
            return check(mutation)
        finally:
            SOURCE.write_text(backup.read_text())


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
