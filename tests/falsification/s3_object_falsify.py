#!/usr/bin/env python3
"""Falsification for R2.C.4b, the S3 response filter.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the six that are not are
counted as such rather than quietly folded into the total.**

The module has fifteen rows. This campaign files nine mutations.

**Four are structural, and two of them are the module's whole claim.**
`no_field_of_the_answer_can_hold_the_object` and
`the_response_type_has_nowhere_to_put_a_body` are destructuring rows: adding a
field that can carry the object breaks the crate rather than failing an
assertion. That is the strongest form this repository has for a "there is
nowhere for it to go" property, and it is filed here precisely because the
campaign *cannot* turn it red — which is the point, not a gap.

**Two are positive.** An empty object still answers, and a reader refusing
everything would fail.

**What is left is the interesting part, and both of its entries were found by
this campaign rather than by reading the code.**

The first version of `ObjectResponse::header` returned the *first* matching
value. The row that checks an optional header for a control character came back
green under an injected second `x-amz-version-id` — because the first, clean one
is what a lookup returns. A duplicated header is exactly the log-injection
vector, and the reader was blind to the half of it that carries the payload.
The method is now `values` returning every match, and `header` refuses a
duplicate outright rather than resolving it by arrival order. The mutation below
that removes the duplicate refusal is filed against the row that caught this,
because the row and the defect are the same finding.

The second was mine. `the_response_type_has_nowhere_to_put_a_body` was first
written as two `ObjectResponse` values, one "with a body" and one without,
asserting they read the same. It cannot be written that way: the type has no
body field, so the two fixtures differed in their headers and the row failed for
a reason that had nothing to do with bodies. The claim was true and the row was
measuring something else.

**The two mutations at the top of the list are the ones to read.** This module
does not read the response body at all, and that is forced rather than chosen:
S3 answers a failure with an XML document, and this workspace has no XML parser
by decision — a parser brings a DTD, a DTD is an XXE surface, and `aws::sts`
says so at the top of its own file. So the mutation that reads a body is
possible to write, and it would be the most damaging edit available here: it
would smuggle a parser past a decision that was made deliberately and is
load-bearing across the provider.

Run:  python3 s3_object_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

OBJECT = f.REPO / "crates/broker/src/aws/s3/object.rs"

MUTATIONS = [
    # ---- what this module must never do ------------------------------------
    (
        # The most damaging edit available in this file. The workspace has no
        # XML parser on purpose -- a parser brings a DTD, a DTD is an XXE
        # surface -- and this mutation smuggles one past that decision by
        # needing a body. S3 answers a `404` with an XML `<Error>` document, so
        # "read the error code" is exactly the request that would trigger it.
        "read the status as if it were enough to skip the refusal",
        "    if !(200..300).contains(&response.status) {",
        "    if false {",
        "a_refused_response_is_refused_by_status_and_the_body_is_never_read",
    ),
    (
        # The refusal has to say the body was not read. An operator who sees a
        # bare `403` and nothing else assumes the worst of their policy, and
        # goes looking for an IAM decision that is not there.
        "refuse without saying the body was not read",
        '    #[error("S3 answered {status}; its body is an XML error document that this broker does not parse, so the status is the whole answer")]',
        '    #[error("S3 answered {status}")]',
        "a_refused_response_is_refused_by_status_and_the_body_is_never_read",
    ),
    # ---- the duplicated header, which is the log-injection vector ---------
    (
        # Remove the refusal a duplicate header earns. The control-character
        # row below is the same finding seen from the other side: the original
        # reader took the first match, so an injected second value was invisible
        # no matter which one carried the payload.
        "resolve a duplicated header by arrival order",
        "        if found.next().is_some() {",
        "        if false {",
        "a_duplicated_header_is_refused_rather_than_resolved_by_arrival_order",
    ),
    (
        # Scan only the first value of each header again. This is the original
        # defect in its original shape, and the row that catches it is the one
        # that was green under it.
        "check only the first value of each header",
        "        for value in response.values(header) {",
        "        for value in response.header(header).unwrap_or_default().into_iter() {",
        "a_control_character_in_an_optional_header_is_refused_too",
    ),
    (
        "accept a header carrying a newline",
        "            if value.bytes().any(|b| b.is_ascii_control()) {",
        "            if false {",
        "a_header_carrying_a_newline_is_refused",
    ),
    # ---- the headers the answer is built from -----------------------------
    (
        "answer without an ETag",
        "    let etag = require(response, \"etag\", \"which version is it\")?;",
        "    let etag = require(response, \"etag\", \"which version is it\").unwrap_or(\"\\\"\\\"\");",
        "a_missing_required_header_is_refused_by_name",
    ),
    (
        "default a content-length that is not a number to zero",
        "    let content_length: u64 = length.parse().map_err(|_| ObjectError::NotANumber {\n        header: \"content-length\",\n        value: length.to_string(),\n    })?;",
        "    let content_length: u64 = length.parse().unwrap_or(0);",
        "a_content_length_that_is_not_a_number_is_refused_rather_than_defaulted",
    ),
    (
        # An ETag is an opaque token compared against what a later write
        # returns. Normalising its shape here would make the correctness of a
        # conditional write depend on this module's idea of what one looks like.
        "accept an unquoted ETag",
        "    let etag = etag\n        .strip_prefix('\"')\n        .and_then(|rest| rest.strip_suffix('\"'))\n        .ok_or_else(|| ObjectError::MalformedETag {\n            value: etag.to_string(),\n        })?\n        .to_string();",
        "    let etag = etag.to_string();",
        "an_unquoted_etag_is_refused",
    ),
    # ---- the answer --------------------------------------------------------
    (
        # A zero-length object exists and is empty. Answering "populated" for it
        # collapses "does it exist" and "is it populated" into one question, and
        # an operator debugging that ends up on the wrong object.
        #
        # The direction matters, and the first version of this had it backwards.
        # Making `is_populated` always return *false* leaves this row green --
        # the row asserts an empty object is NOT populated, and "everything is
        # empty" satisfies that perfectly. The defect a property like this has
        # is two-sided, and each side needs its own mutation. The other side is
        # covered by `the_answer_is_built_from_the_headers`, which asserts a
        # 20 KiB object IS populated, so the pair pins the method from both
        # ends and nothing in between is left unmeasured.
        "report a zero-length object as populated",
        "    pub fn is_populated(&self) -> bool {\n        self.content_length > 0\n    }",
        "    pub fn is_populated(&self) -> bool {\n        let _ = self;\n        true\n    }",
        "an_empty_object_is_an_answer_and_not_a_refusal",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "aws::s3::object::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = OBJECT
    f.MUTATIONS[:] = MUTATIONS
    original = OBJECT.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert OBJECT.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
