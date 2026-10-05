#!/usr/bin/env python3
"""Falsification for R2.D.2, the ServiceAccount token port.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the six that are not are
counted as such rather than quietly folded into the total.**

The port has fifteen rows. This campaign files eight mutations, and they take
**nine** rows red — the path mutation is one edit that breaks both path rules,
because the empty and the relative case are a single condition rather than two.
That is measured, not assumed: applying it alone and running the whole module
gives `13 passed; 2 failed`, and the two are
`a_relative_token_path_is_refused_at_construction` and
`an_empty_token_path_is_refused_at_construction`. The harness reports one row per
mutation by design, so the ninth red row is not a ninth mutation.

The six rows no mutation here reaches fall into two groups, and they are
unmeasured for different reasons:

Three assert a **structural** fact that no edit to this file can undo. The port
has no getter, so a caller cannot be written that holds the token, and
`the_only_accessor_is_the_path` asserts a compile-time shape rather than a
value. The constructor reads nothing, so `the_constructor_reads_nothing` would
need a mutation that *adds* a read rather than removing one. And `forget` takes
`&self` over a port that holds no state, so
`forget_costs_nothing_because_nothing_is_held` has no body to change.

Three are **positive** rows — `a_well_formed_token_is_lent_verbatim`,
`a_port_that_refused_everything_would_fail_these` and
`the_token_never_appears_in_the_ports_own_rendering` — which is where the
earlier trap would have bitten. Breaking a positive row needs a *compound*
mutation (a port that lends nothing is not one edit away), and filing a
multi-site edit to force one would be measuring a rewrite rather than a defect.
They are the rows that catch the port being useless, and the note above is the
argument for why they exist.

So the honest summary of this campaign is eight mutations against nine of the
fifteen rows, and six rows that stand on the shape of the file. Both numbers are
reported because a total without the second one would read as more coverage than
exists — and a mutation count quoted as if it were a row count would read as
more of that too.

The eight below are the rows where a concrete mutation exists, and they are the
ones where the defect would actually be introduced by an edit rather than by a
design choice. The control-character refusal is first because it is the one
that carries the property: a token becomes an `Authorization` header value, and
a newline in a header is a second header.

One mutation here is worth naming because the defect it introduces is a
*misdiagnosis* rather than a leak. Swallowing a read error and letting the empty
token refusal handle it would make a rotated-away token file and an empty one
indistinguishable, and the API server's `401` would be the only thing left to
say which happened.

Run:  python3 k8s_port_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

PORT = f.REPO / "crates/broker/src/k8s/port.rs"

MUTATIONS = [
    # ---- the refusal that carries the property ------------------------------
    (
        "accept a token carrying a control character",
        "        if let Some(offset) = token.iter().position(|b| b.is_ascii_control()) {",
        "        if let Some(offset) = None::<usize> {",
        "a_token_carrying_a_control_character_is_refused",
    ),
    # ---- a misdiagnosis rather than a leak ----------------------------------
    (
        # A token file that is gone becomes an empty token, and the operator is
        # told the credential is empty rather than that the mount is missing.
        "report a missing token file as an empty token",
        "        let raw = fs::read(&self.token_path).map_err(|e| {",
        "        let raw = (|| -> std::io::Result<Vec<u8>> {\n"
        "            Ok(fs::read(&self.token_path).unwrap_or_default())\n"
        "        })()\n"
        "        .map_err(|e| {",
        "a_missing_token_file_is_unavailable_rather_than_empty",
    ),
    # ---- the cheap refusals -------------------------------------------------
    (
        "accept an empty token",
        "        if token.is_empty() {",
        "        if false {",
        "an_empty_token_is_refused_and_never_reaches_a_sink",
    ),
    (
        "drop the size bound",
        "        if raw.len() > MAX_TOKEN_BYTES {",
        "        if false {",
        "a_token_past_the_bound_is_refused",
    ),
    (
        # One edit takes BOTH path rows red, and that was measured rather than
        # reasoned about: this mutation alone gives `13 passed; 2 failed`. The
        # harness credits one row per mutation, so it reports the relative row;
        # the empty row is red for the same reason and is counted in the total
        # without a second attribution, which would be a claim nothing checked.
        "accept an empty or relative token path",
        "        if token_path.as_os_str().is_empty() || !token_path.is_absolute() {",
        "        if false {",
        "a_relative_token_path_is_refused_at_construction",
    ),
    (
        "lend without a credential id",
        "        if credential.is_empty() {",
        "        if false {",
        "lending_without_naming_a_credential_is_refused",
    ),
    # ---- the bytes the sink receives ----------------------------------------
    (
        # Trimming is the smallest possible lie about a credential: the request
        # is well-formed, the signature is irrelevant here, and the `401` says
        # nothing about a trailing byte.
        "trim the token on its way to the sink",
        "        sink.accept(&token)",
        "        sink.accept(token.trim_ascii())",
        "nothing_is_trimmed_normalised_or_appended",
    ),
    (
        # A request that was never sent would look like one that was, and the
        # sink's error is the only place that can say otherwise.
        "swallow the sink's error so a failed send looks like a sent one",
        "        sink.accept(&token)",
        "        let _ = sink.accept(&token);\n        Ok(())",
        "a_failing_sink_does_not_keep_the_token_either",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "k8s::port::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = PORT
    f.MUTATIONS[:] = MUTATIONS
    original = PORT.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert PORT.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
