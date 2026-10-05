#!/usr/bin/env python3
"""Falsification harness for R2.C.2.a.

Every security row in `crates/broker/src/aws/sts/tests.rs` has to be able to
answer "what concrete mutation makes this red?". This applies each mutation on
its own, runs the one test that is supposed to catch it, and restores the file.

A mutation that leaves its test green is the finding: either the row cannot fail,
or it is measuring something other than what it says.

Run:  python3 sts_falsify.py
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Derived from this file, not written down. The first version of this harness
# hardcoded one developer's checkout, which made every figure produced by it
# unreproducible for anyone else — the campaign was in the repository in name
# only, because the path it resolved was not.
REPO = Path(__file__).resolve().parents[2]
STS = REPO / "crates/broker/src/aws/sts.rs"
# The caller's environment, inherited rather than replaced. The previous
# literal `PATH`/`HOME`/`CARGO_TARGET_DIR` belonged to one machine and would
# have silently pointed cargo at a target directory that did not exist here.
ENV = dict(os.environ)

# (label, old, new, test name that must go red)
MUTATIONS = [
    (
        "accept a leap second and clamp it to 59",
        "        || second > 59\n    {\n        return Err(malformed());\n    }",
        "        || second > 60\n    {\n        return Err(malformed());\n    }",
        "an_expiration_outside_the_one_documented_shape_is_refused",
    ),
    (
        # Replaced the original "clamp rather than refuse the second field":
        # that mutation could never go red, because the guard above it already
        # refuses second == 60, so the clamp is unreachable. A vacuous mutation
        # is worse than none — it looks like coverage. This one removes the
        # component bounds outright, which is reachable and is the thing the
        # oracle's rejection set exists to check.
        "drop the month, day and clock bounds on the instant",
        "    if !(1..=12).contains(&month)\n"
        "        || !(1..=31).contains(&day)\n"
        "        || hour > 23\n"
        "        || minute > 59\n"
        "        || second > 59\n"
        "    {\n        return Err(malformed());\n    }",
        "    let _ = (month, day, hour, minute, second);",
        "an_expiration_outside_the_one_documented_shape_is_refused",
    ),
    (
        # The first version of this replaced the `match_indices` pair with a
        # `find` plus an index one byte past the tag — and was reported as
        # "compiler-refused", which was my mutation being malformed, not a
        # structural guarantee: it deleted the `occurrences` binding the rest of
        # the function still reads. Claiming a structural refusal there would
        # have been the harness flattering itself. The honest mutation is a
        # one-byte shift of the slice start, which compiles, and which on a
        # document with no multibyte character silently misreads by one byte
        # instead of panicking.
        "slice one byte past the tag, inside a multi-byte character",
        "    let after_open = first + open.len();",
        "    let after_open = first + open.len() + 1;",
        "a_multibyte_character_beside_a_tag_is_read_whole_and_does_not_bring_the_reader_down",
    ),
    (
        "take the first of two credential elements instead of refusing",
        "    if occurrences.next().is_some() {\n"
        "        return Err(StsError::UnrecognisedDocument(format!(\n"
        "            \"<{name}> appears more than once\"\n"
        "        )));\n"
        "    }",
        "    let _ = occurrences.next();",
        "a_duplicated_credential_field_is_a_refusal_and_not_a_first_one_wins",
    ),
    (
        # Third attempt, and the two before it are the reason this comment is
        # long. (1) Stripping the `<!--`/`-->` markers left the comment's body,
        # which still contains the tag, so nothing changed. (2) Stripping the
        # whole span removed it — and shifted every offset after the comment, so
        # `SecretAccessKey` was then sliced out of the middle of the comment and
        # the row stayed green for an unrelated reason. A mutation that leaves a
        # row green *for the wrong reason* is as misleading as one that cannot
        # turn it red.
        #
        # The clean version masks the comment body with spaces instead of
        # removing it: the length is unchanged, so every offset into the masked
        # copy is still an offset into `text`, and the only thing that differs is
        # which tags the duplicate count sees.
        "mask comment bodies so the duplicate count skips them",
        "    let mut occurrences = text.match_indices(&open);",
        "    let bytes = text.as_bytes();\n"
        "    let mut masked: Vec<u8> = bytes.to_vec();\n"
        "    let mut at = 0usize;\n"
        "    while at + 3 < bytes.len() {\n"
        "        if &bytes[at..at + 4] == b\"<!--\" {\n"
        "            let mut end = at + 4;\n"
        "            while end + 2 < bytes.len() && &bytes[end..end + 3] != b\"-->\" {\n"
        "                masked[end] = b' ';\n"
        "                end += 1;\n"
        "            }\n"
        "            at = end;\n"
        "        } else {\n"
        "            at += 1;\n"
        "        }\n"
        "    }\n"
        "    let masked = String::from_utf8(masked).expect(\"masking with spaces keeps it UTF-8\");\n"
        "    let mut occurrences = masked.match_indices(&open);",
        "a_duplicated_field_hidden_in_a_comment_is_still_a_duplicated_field",
    ),
    (
        "accept a credential field carrying whitespace",
        "    if let Some(found) = raw.chars().find(|c| c.is_whitespace()) {\n"
        "        return Err(StsError::UnrecognisedDocument(format!(\n"
        "            \"<{name}> contains {found:?}, which a credential never does\"\n"
        "        )));\n"
        "    }",
        "    let _ = name;",
        "a_credential_field_the_documentation_folded_is_refused",
    ),
    (
        "keep an undefined entity as literal text",
        "                None => {\n"
        "                    return Err(StsError::UnrecognisedDocument(format!(\n"
        "                        \"<{name}> contains &{entity};, which is not a defined entity\"\n"
        "                    )))\n"
        "                }",
        "                None => out.push_str(&tail[..=semi]),",
        "an_external_entity_reference_is_never_resolved_into_a_credential",
    ),
    (
        "keep a bare ampersand as a character",
        "            return Err(StsError::UnrecognisedDocument(format!(\n"
        "                \"<{name}> contains a bare `&`, which XML does not allow unescaped\"\n"
        "            )));",
        "            out.push('&');\n            rest = &tail[1..];\n            continue;",
        "an_ampersand_a_credential_cannot_contain_is_refused_rather_than_kept",
    ),
    (
        "ignore a document that declares a DTD",
        "    if text.contains(\"<!DOCTYPE\") {",
        "    if false {",
        "a_document_declaring_a_dtd_is_refused_before_it_is_read",
    ),
    (
        "accept an empty credential as an empty string",
        "    if raw.is_empty() {\n        return Err(StsError::Missing(name));\n    }",
        "    let _ = name;",
        "a_credential_field_left_empty_is_missing_rather_than_empty",
    ),
    (
        "drop the bound on the response size",
        "    if body.len() > MAX_RESPONSE_BYTES {\n        return Err(StsError::ResponseTooLarge);\n    }",
        "    let _ = MAX_RESPONSE_BYTES;",
        "a_response_larger_than_the_bound_is_refused_unread",
    ),
    (
        "serve a session that has already expired",
        "    if !session.usable_at(now, Duration::ZERO) {\n"
        "        return Err(StsError::AlreadyExpired(expiration));\n    }",
        "    let _ = now;",
        "a_session_that_expired_before_it_was_used_is_refused_rather_than_served",
    ),
    (
        "count the expiry instant itself as usable",
        "            .map(|left| left > skew)",
        "            .map(|left| left >= skew)",
        "a_session_is_usable_before_its_expiry_and_not_at_or_after_it",
    ),
    (
        "print the secret pair in Debug",
        "            .field(\"secret_access_key\", &\"<redacted>\")\n"
        "            .field(\"session_token\", &\"<redacted>\")",
        "            .field(\"secret_access_key\", &self.secret_access_key)\n"
        "            .field(\"session_token\", &self.session_token)",
        "printing_a_session_shows_the_receipt_and_not_the_credential",
    ),
    (
        "encode a space as %20 rather than +",
        "            b' ' => out.push('+'),",
        "            b' ' => {\n                out.push('%');\n                out.push('2');\n                out.push('0');\n            }",
        "a_space_is_a_plus_and_a_plus_is_escaped",
    ),
    (
        "emit the parameters in declaration order rather than sorted",
        "        params.sort_by(|a, b| a.0.cmp(b.0));",
        "        let _ = &params;",
        "the_parameters_are_ordered_by_name_and_not_by_the_order_they_were_written",
    ),
    (
        "hash something other than the body that goes on the wire",
        "        crate::aws::sigv4::sha256_hex_of(self.form_body().as_bytes())",
        "        crate::aws::sigv4::sha256_hex_of(self.role_arn.as_bytes())",
        "the_payload_hash_is_the_sha256_of_exactly_those_bytes",
    ),
    (
        # Snippet updated when the inline `(2..=64)` became `Self::SESSION_NAME_LEN`.
        # A mutation that stops matching the source is a mutation that measures
        # nothing, and the harness says so rather than quietly reporting nothing.
        "accept a name too short for the field",
        "        if !Self::SESSION_NAME_LEN.contains(&session_len) {\n"
        "            return Err(StsError::IncompleteRequest(\"role session name\"));\n        }",
        "        let _ = session_len;",
        "a_name_too_short_to_be_one_is_refused_here_and_not_at_aws",
    ),
    (
        "accept a session name carrying whitespace",
        "        if role_session_name.chars().any(char::is_whitespace) {\n"
        "            return Err(StsError::IncompleteRequest(\"role session name\"));\n        }",
        "        let _ = &role_session_name;",
        "a_session_name_carrying_whitespace_is_refused",
    ),
    (
        "hold the expiration in a 32-bit second counter",
        "    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64))",
        "    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u32 as u64))",
        "an_instant_past_the_32_bit_boundary_is_still_read_correctly",
    ),
    (
        # Re-pointed. Deleting the `<Error` sniff does not break the error
        # direction at all: the fixture still has a `<Code>`, so it is still read
        # as a provider refusal and `an_error_response_is_never_mistaken_for_credentials`
        # stays green. The direction it breaks is the *success* one — a successful
        # document has no `<Code>`, so the reader would report it as
        # `Provider { code: "Unknown" }`. That is what the sample row catches.
        "not recognise an error document as one",
        "    if !text.contains(\"<Error\") {\n        return Ok(None);\n    }",
        "    if false {\n        return Ok(None);\n    }",
        "the_documented_sample_response_yields_a_session",
    ),
    (
        "decode before locating the closing tag",
        "    Ok(&text[after_open..after_open + offset])",
        "    let decoded = decode_predefined(&text[after_open..after_open + offset], name)?;\n"
        "    let start = text.find(decoded.as_str()).unwrap_or(after_open);\n"
        "    let end = start + decoded.len();\n"
        "    Ok(&text[start..end])",
        "an_escaped_tag_in_a_credential_is_text_and_not_structure",
    ),
    (
        "read a body that is not UTF-8",
        "    let text = std::str::from_utf8(body)\n"
        "        .map_err(|_| StsError::UnrecognisedDocument(\"the body is not UTF-8\".into()))?;",
        "    let text = std::str::from_utf8(body).unwrap_or(\"\");",
        "a_body_that_is_not_utf8_is_refused_before_it_is_parsed",
    ),
    (
        "read an unclosed field to the end of the document",
        "    let Some(offset) = text[after_open..].find(&close) else {\n"
        "        return Err(StsError::UnrecognisedDocument(format!(\n"
        "            \"<{name}> is never closed\"\n"
        "        )));\n    };\n"
        "    Ok(&text[after_open..after_open + offset])",
        "    let offset = text[after_open..].find(&close).unwrap_or(text.len() - after_open);\n"
        "    Ok(&text[after_open..after_open + offset])",
        "an_unclosed_field_is_refused_rather_than_read_to_the_end_of_the_document",
    ),
    (
        "serve the API version another provider release serves",
        'pub const API_VERSION: &str = "2011-06-15";',
        'pub const API_VERSION: &str = "2010-05-08";',
        "the_api_version_is_the_one_aws_serves",
    ),
]


TEST_PREFIX = "aws::sts::tests::"
# Which cargo target holds the rows. An integration test file is not in
# `--lib`, and pointing `--lib` at one measures nothing -- which the
# `no-run` bucket reports rather than passing off as green.
CARGO_TARGET = "--lib"
# Which package holds them.
#
# This was hardcoded to `asv-broker` and every campaign inherited it, which
# meant the first campaign written against another crate -- the CLI's two
# secret-bearing buffers -- ran `cargo test -p asv-broker --bin asv`, matched
# no test, and reported `unreadable` for all six of its mutations. A
# hardcoded package is the same failure as the hardcoded `PATH` above: it
# looks like a finding about the code under test rather than about the
# harness. The four-bucket accounting is what made it visible.
PACKAGE = "asv-broker"


def run_test(short_name: str) -> tuple[str, str]:
    """Run exactly one row and report what actually happened.

    Three outcomes, and the distinction between them is the whole reason this
    function is not `return proc.returncode == 0`:

    ``red``      the row ran and failed
    ``green``    the row ran and passed — the mutation was not caught
    ``no-run``   cargo matched no test, so nothing was measured at all

    The third one is not hypothetical. The first version of this harness passed
    the *short* test name together with `--exact`, cargo matched nothing, printed
    ``running 0 tests`` and ``test result: ok. 0 passed``, and the harness read
    that as a falsification for all twenty-four mutations. A row that never ran
    is indistinguishable from a row that passed, unless the harness is built so
    it cannot say so — which is now what the `no-run` outcome is for.
    """
    name = TEST_PREFIX + short_name
    proc = subprocess.run(
        ["cargo", "test", "-p", PACKAGE, *CARGO_TARGET.split(), name, "--", "--exact"],
        cwd=REPO, env=ENV, capture_output=True, text=True, timeout=1200,
    )
    out = proc.stdout + proc.stderr
    if "error[E" in out or "error: could not compile" in out:
        return "refused", out
    ran = re.search(r"running (\d+) tests?", out)
    # cargo prints `test result: ok. N passed; M failed` when the row passed and
    # `test result: FAILED. N passed; M failed` when it did not, so both forms
    # have to be read. A first version matched only the `ok` form and reported
    # every genuine failure as unreadable, which is the same mistake as the one
    # it replaced: the row ran, and the harness did not look at the answer.
    passed = re.search(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed", out
    )
    if not ran or not passed:
        return "unreadable", out
    # "Did the row I named actually execute?" and "did it pass?" are two
    # different questions and reading one off the other is how a failing row gets
    # reported as one that never ran. The first is answered by the `running N
    # tests` line; the second by the failure count.
    if int(ran.group(1)) != 1:
        return "no-run", out
    if int(passed.group(2)) == 0 and int(passed.group(1)) == 1:
        return "green", out
    return "red", out


def main() -> int:
    original = STS.read_text()
    # The backup lives beside the harness, not in a directory named on one
    # machine. `tempfile` picks the system temp unless TMPDIR says otherwise,
    # which is the right answer for a checkout someone else cloned.
    backup = Path(tempfile.mkdtemp(prefix="asv-falsify-")) / "sts.rs.orig"
    backup.write_text(original)

    survivors = []
    refused = []
    unreadable = []
    for label, old, new, test in MUTATIONS:
        pairs = new if isinstance(new, list) else [(old, new)]
        unmatched = [a for a, _ in pairs if original.count(a) != 1]
        if unmatched:
            counts = [original.count(a) for a in unmatched]
            print(f"SKIP  {label!r}: snippet counts {counts}, want all 1", flush=True)
            survivors.append((label, test, "snippet not unique"))
            continue
        pairs = new if isinstance(new, list) else [(old, new)]
        mutated = original
        for a, b in pairs:
            mutated = mutated.replace(a, b, 1)
        STS.write_text(mutated)
        try:
            verdict, out = run_test(test)
        finally:
            STS.write_text(original)
        if verdict == "red":
            print(f"ok    {label}\n      -> {test} went red", flush=True)
        elif verdict == "green":
            survivors.append((label, test, "the row stayed green"))
            print(f"SURVIVOR  {label}\n      -> {test} stayed GREEN  <-- the finding", flush=True)
        elif verdict == "refused":
            refused.append((label, test))
            # The first compiler line, so the claim "structural" is inspectable
            # rather than asserted. A refusal caused by a broken mutation looks
            # exactly like a refusal caused by the type system unless the reader
            # can see which error it was.
            first_error = next(
                (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
            )
            print(f"ok*   {label}\n      -> {test}: refused by the compiler\n"
                  f"         {first_error}", flush=True)
        else:
            unreadable.append((label, test, verdict))
            print(f"BAD   {label}\n      -> {test}: {verdict}", flush=True)

    assert STS.read_text() == original, "the file was not restored"
    # Every mutation lands in exactly one bucket, and the buckets partition the
    # run: red | green | refused | unreadable. The first version of this summary
    # computed `falsified` as `len(MUTATIONS) - survivors - unreadable`, which
    # swept the compiler-refused mutations into "falsified" while the line right
    # below it said they were not counted — so it reported 25 of 25 when 23 rows
    # went red and 2 were stopped by the compiler. A summary that overstates its
    # own evidence is the one number in the file nobody checks.
    falsified = len(MUTATIONS) - len(survivors) - len(unreadable) - len(refused)
    buckets = {
        "red": falsified,
        "compiler-refused": len(refused),
        "green (SURVIVOR)": len(survivors),
        "measured nothing": len(unreadable),
    }
    assert sum(buckets.values()) == len(MUTATIONS), (buckets, len(MUTATIONS))
    print()
    print(f"mutations: {len(MUTATIONS)}  (the four buckets partition the run)")
    for name, count in buckets.items():
        print(f"  {name:<22}: {count}")
    if refused:
        print("\ncompiler-refused, which is a stronger answer than a red row rather "
              "than a weaker one:")
        for label, test in refused:
            print(f"  - {label}\n      ({test})")
    for label, test, why in unreadable:
        print(f"\nUNMEASURED: {label}\n  test: {test}\n  {why}")
    for label, test, why in survivors:
        print(f"\nSURVIVOR: {label}\n  test: {test}\n  {why}")
    return 1 if (survivors or unreadable) else 0


if __name__ == "__main__":
    sys.exit(main())
