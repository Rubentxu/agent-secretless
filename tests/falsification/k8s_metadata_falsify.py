#!/usr/bin/env python3
"""Falsification for R2.D.3.1b, the reply filter that keeps a Secret's value out.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the six that are not are
counted as such rather than quietly folded into the total.**

The module has thirteen rows. This campaign files nine mutations; seven take a
row red and two stop the build. One row per red mutation, with no overlap
between them, and that was checked rather than assumed — the docstring of this
file first claimed the kind-check mutation would take two rows at once, and the
campaign said otherwise. It does not: a document with *no* `kind` takes the
`None` arm of the match, which is still a refusal, so
`a_document_with_no_kind_at_all_is_refused` stays green under it. The `None` arm
and the wrong-kind arm are the same refusal, and a mutation of one does not
reach the other.

The first pass of this campaign filed three of them wrong, and all three
failures were the harness refusing to let a bad filing pass unnoticed — two were
reported as SKIP because the anchor was not unique, one because the mutation
did not compile, and one as a survivor that turned out to be a real gap in the
filing rather than in the code. A row reached through `#[serde(default)]` never
enters the visitor, so no mutation of the visitor can touch it; that row needed
its own, and it now has one.

**Three are positive.** `a_secret_with_no_data_still_answers`,
`a_reply_carrying_no_metadata_still_answers` and
`a_filter_that_refused_every_secret_would_fail_these`. They are what stop a
filter that refuses everything from passing a module made almost entirely of
refusals — which this one is, and that shape is exactly where the mistake is
invisible. Breaking one is a compound edit.

**Three are held by a type rather than by a line** — `the_count_does_not_come_with_the_key_names`,
`no_field_of_the_answer_can_hold_the_value` and
`the_base64_of_the_value_is_not_copied_out_of_the_reply`. They are the three
rows that carry the module's actual claim, and the campaign cannot turn any of
them red, which is worth being blunt about rather than reporting as coverage.

The mutations that would break them are filed anyway, and both land in the
**compiler-refused** bucket. `carry the values into the answer` and `keep the key
names as well as the count` each add a field to `SecretMetadata`, and
`no_field_of_the_answer_can_hold_the_value` is a destructuring row — so the
crate stops compiling rather than an assertion failing. The type is the guard,
and it fires before the test can. Calling that a survivor would be reporting
the harness missing something it was built to catch.

Both mutations are filed against `SecretMetadata` rather than against the
private view on purpose. A field added only to `SecretView` compiles, is never
read, and changes nothing an agent can observe — so filing there would have
produced two more survivors and taught nothing.

**The bug this module's first draft had.** The view's field is named
`key_count`, and the natural way to write the attribute is
`#[serde(default, deserialize_with = "count_entries")]` — which matches no
member of the document. `data` is then ignored as an unknown field and the count
is always zero. Two rows caught it before any mutation did. It is recorded here
because it is the exact class a campaign over finished code misses: an
attribute that is syntactically fine and semantically inert.

Run:  python3 k8s_metadata_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

METADATA = f.REPO / "crates/broker/src/k8s/metadata.rs"

MUTATIONS = [
    # ---- the count ---------------------------------------------------------
    (
        # The count is what "is this secret populated" is answered with, and a
        # filter that always says zero is a filter that says "no" to every
        # secret an operator asks about.
        "count nothing",
        "    deserializer.deserialize_map(CountingVisitor)",
        "    let _ = deserializer;\n    Ok(0)",
        "a_populated_secret_is_counted_rather_than_read",
    ),
    (
        # The other side of the same rule. An empty Secret is a real object and
        # a real answer; counting it as one entry turns "it exists and is
        # empty" into "it has something in it", which is the wrong answer in
        # the direction that sends somebody to debug the wrong Secret.
        "count an empty object as one entry",
        "            let mut counted = 0usize;",
        "            let mut counted = 1usize;",
        "a_secret_with_no_data_still_answers",
    ),
    # ---- the kind ----------------------------------------------------------
    (
        # One edit removes the check two rows depend on: the row that refuses a
        # Pod, and the row that refuses a document with no `kind` at all. A
        # `Status` served with a 200 is the case that matters -- it has a
        # `metadata.name`, so a filter that skipped the kind check would answer
        # "yes, that secret exists" for a Status object.
        "accept a document of any kind",
        '        Some("Secret") => {}',
        "        Some(_) => {}",
        "a_document_that_is_not_a_secret_is_refused_on_its_kind",
    ),
    # ---- the order ---------------------------------------------------------
    (
        # Parsing first is the natural way to write this and it destroys the
        # diagnosis: a 404 carries a `Status` body, so the answer becomes "that
        # is a Status, not a Secret" instead of "there is no such secret". The
        # operator is sent to look at a document-type problem for what is a
        # not-found.
        "parse the body before the status is checked",
        "    if !reply.is_success() {\n        return Err(MetadataError::NotFound(reply.status));\n    }",
        "    let _ = reply.is_success();",
        "a_refusal_status_is_refused_before_the_body_is_parsed",
    ),
    # ---- the field names --------------------------------------------------
    (
        # `type` is a Rust keyword, so the view field is `secret_type` and
        # needs the rename. Dropping it compiles, fails no refusal row, and
        # leaves the field defaulting to empty — so a `kubernetes.io/tls`
        # Secret is reported as having no type at all, and the operator
        # debugging a TLS mount is told nothing.
        "read the secret type from the wrong place",
        '    #[serde(rename = "type", default)]\n    secret_type: String,',
        "    #[serde(default)]\n    secret_type: String,",
        "the_answer_carries_the_facts_an_operator_asks_and_nothing_else",
    ),
    # ---- a lenient parse ---------------------------------------------------
    (
        # An HTML error page from something in front of the API server becomes
        # an empty document, and an empty document has no `kind` — so the
        # answer is a refusal for the wrong reason today, and a Secret with no
        # name the moment the kind check is relaxed. A parse failure is a fact
        # about the origin and is worth keeping as one.
        "treat an unreadable body as an empty document",
        "        serde_json::from_slice(&reply.body).map_err(|error| MetadataError::Unreadable(error.to_string()))?;",
        "        serde_json::from_slice(&reply.body).unwrap_or_else(|_| {\n"
        "            serde_json::from_str(r#\"{\"kind\":\"Secret\"}\"#).expect(\"a literal parses\")\n"
        "        });",
        "a_body_that_is_not_json_is_refused_rather_than_half_read",
    ),
    (
        # A different path from the count mutations, and the reason the first
        # pass filed "count an empty object as one entry" against the wrong row.
        # A document with no `data` member never enters the visitor at all --
        # serde takes `#[serde(default)]` and the count is simply never
        # computed -- so a mutation of `count_entries` cannot reach it, and
        # filing one there reported a survivor that meant nothing. This one
        # removes the `default` instead, which is the only edit that touches
        # the path that row exercises.
        "refuse a Secret whose data member is absent",
        '    #[serde(\n        rename = "data",\n        default,\n        deserialize_with = "count_entries"\n    )]',
        '    #[serde(\n        rename = "data",\n        deserialize_with = "count_entries"\n    )]',
        "a_secret_with_no_data_member_at_all_answers_with_a_zero_count",
    ),
    # ---- the two the type refuses -----------------------------------------
    (
        # Expected: compiler-refused, which is the result this mutation exists
        # to produce. The row that catches it is a destructuring pattern, so a
        # value-bearing field does not fail an assertion -- it fails the
        # build, which is a stronger answer than any test could give. Filed
        # against `SecretMetadata` and not the private view: a field added only
        # to the view compiles, is never read, and would have filed as another
        # survivor while proving nothing.
        "carry the values into the answer",
        "    key_count: usize,\n}\n\nimpl SecretMetadata {",
        "    key_count: usize,\n    /// Injected by a falsification campaign.\n"
        "    pub data: std::collections::HashMap<String, String>,\n}\n\nimpl SecretMetadata {",
        "no_field_of_the_answer_can_hold_the_value",
    ),
    (
        # Same bucket, same reason. Key names are not secret and are often
        # wanted, but they are the first half of a credential hunt, and a
        # broker that lists them is a broker an agent can point at a
        # directory. The count is the whole reason `data` is a visitor rather
        # than a map, and this is what stops a later change from undoing that.
        "keep the key names as well as the count",
        "    key_count: usize,\n}\n\nimpl SecretMetadata {",
        "    key_count: usize,\n    /// Injected by a falsification campaign.\n"
        "    pub key_names: Vec<String>,\n}\n\nimpl SecretMetadata {",
        "the_count_does_not_come_with_the_key_names",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "k8s::metadata::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = METADATA
    f.MUTATIONS[:] = MUTATIONS
    original = METADATA.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert METADATA.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
