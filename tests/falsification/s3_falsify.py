#!/usr/bin/env python3
"""Falsification for R2.C.4a, S3 addressing.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the two that are not are
counted as such rather than quietly folded into the total.**

The module has twenty-three rows. This campaign files thirteen mutations and
takes **thirteen** rows red, one for one.

That number was predicted wrong the first time — the docstring said sixteen, on
the argument that three mutations would each take a second row for the other
half of their rule. They do not, because the other halves are only reached by
rows this campaign does not file against: the harness credits one row per
mutation by design, and a second attribution would be a claim nothing checked.
The number below is the one that was measured.

The ten rows left are the ordinary remainder, and they are left for reasons
rather than by omission.

**Four test the encoder** — the slash, the space, the uppercase-hex and the
unreserved cases. They are testing `encode_component`, which lives in `sigv4`
and has a campaign of its own with sixteen rows against the AWS documentation's
own vectors. Filing them here would measure the same code twice and would go
stale the day `sigv4` changed.

**Two are positive**, and one is the path-style arm, which is a `match` over two
variants rather than a refusal anything can remove.

**Three are the other half of a rule whose mutation is filed elsewhere.**
`an_upper_case_bucket_name_is_refused` is the clearest: the explicit arm it was
written against is gone (see below), so what catches `Acme` now is the catch-all.
`a_key_carrying_a_control_character_is_refused` shares its check with the
line-break row, and `a_key_containing_a_single_dot_segment_is_refused_too`
shares its check with the dot-dot row. Both are red under the same edit; the
harness reports one row per mutation and that is not a claim they are green.

**Two defects in this module were found by the campaign rather than by reading
it**, and one of them was a defect in the campaign.

The bucket validator had an explicit `is_ascii_uppercase` arm with its own
message. The first pass filed the mutation that deletes it against the row that
covers it and got a survivor, so the arm looked redundant — and the catch-all
below *does* already refuse `Acme`. The arm is gone now.

The underscore arm survived the same treatment and stayed, which is the more
interesting outcome and the reason the two are not symmetric. Removing the
underscore check does not change *whether* `acme_artifacts` is refused, because
`_` is outside the catch-all's set. What it changes is the message: the row
asserts the refusal names the rule, and the catch-all's message does not mention
underscores. A check that earns its keep through the diagnosis rather than
through the effect is still load-bearing, and a campaign that reported it as
redundant would have been wrong.

The second pass also produced two survivors that were **artifacts of mine**: I
edited the isolated checkout while the campaign was running, which invalidated
both the measurement and the file the campaign restored. A third pass on an
untouched copy gave 13 red and no survivors, which is the number reported here.
The lesson is the one already recorded in the harness contract — never edit a
checkout a campaign is running against — and it was worth learning by doing it.

**What most of these mutations are for.** The module exists because of one
property: *the path that is signed is the path that is sent.* A type with a
single `path` field makes that structural, and two mutations below try to break
it anyway — one that re-encodes the canonical form, one that returns a
differently-built string from `canonical_path`. Neither can be written the way
the obvious implementation would, because the obvious implementation has two
fields, and that is the point of the shape.

**The rest are attempts to widen a bucket name into a different host.** A
bucket is a DNS label, and the rules that look like style are the rules that
decide which host gets contacted: `Acme` and `acme` are two different names,
`acme..artifacts` is a name S3 will not create, and `192.168.0.1` is one no
wildcard certificate can cover. Each of those is a refusal here rather than a
normalisation, and each is named so an operator can act on the answer.

One mutation is worth reading twice because it is the smallest plausible
mistake in the file. `a_key_containing_dots_that_are_not_a_segment_is_fine`
pins that `archive..zip/config` is an ordinary key. A traversal check written
as "does the key contain two dots in a row" would pass every other row in this
campaign and would break a legitimate one — and a check that is wrong often
enough gets disabled by whoever hits it first.

Run:  python3 s3_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

S3 = f.REPO / "crates/broker/src/aws/s3.rs"

MUTATIONS = [
    # ---- the property the module exists for --------------------------------
    (
        # The mutation the type is shaped to make hard to write. An
        # implementation with two path fields would have exactly this line in
        # it, and the signature would then be computed over `%2520` for a
        # request that goes out as `%20` — which AWS reports as a credentials
        # error, not an encoding one.
        "encode the canonical path a second time",
        "    pub fn canonical_path(&self) -> String {\n        self.path.clone()\n    }",
        "    pub fn canonical_path(&self) -> String {\n"
        "        crate::aws::sigv4::canonical_uri(&self.path, true)\n    }",
        "the_path_that_is_signed_is_the_path_that_is_sent",
    ),
    (
        # The other shape of the same bug: two fields, one built from the key
        # and one assembled from the parts. They agree until a key contains a
        # character one of them encodes and the other does not.
        "build the signed path separately from the sent one",
        "    pub fn canonical_path(&self) -> String {\n        self.path.clone()\n    }",
        "    pub fn canonical_path(&self) -> String {\n"
        "        format!(\"/{}\", self.authority.as_str().split('.').next().unwrap_or_default())\n    }",
        "the_signed_path_is_encoded_exactly_once",
    ),
    # ---- the bucket becomes a host ----------------------------------------
    (
        "accept an underscore in a bucket name",
        "    if bucket.contains('_') {",
        "    if false {",
        "an_underscore_in_a_bucket_name_is_refused",
    ),
    (
        "accept adjacent dots in a bucket name",
        "    if bucket.contains(\"..\") {",
        "    if false {",
        "adjacent_dots_in_a_bucket_name_are_refused",
    ),
    (
        # A wildcard certificate cannot cover an IP-shaped label, so nothing can
        # prove the host the signature was made for is the host being reached.
        "accept an IP-shaped bucket name",
        "    if looks_like_ipv4(bucket) {",
        "    if false {",
        "an_ip_shaped_bucket_name_is_refused",
    ),
    (
        "accept a bucket name outside the length bounds",
        "    if bucket.len() < 3 || bucket.len() > 63 {",
        "    if false {",
        "a_bucket_name_that_is_too_short_or_too_long_is_refused",
    ),
    (
        "accept a bucket name that starts or ends with a separator",
        "    if bucket.starts_with('.')\n        || bucket.ends_with('.')\n        || bucket.starts_with('-')\n        || bucket.ends_with('-')\n    {",
        "    if false {",
        "a_bucket_name_that_starts_or_ends_with_a_separator_is_refused",
    ),
    (
        # The refusals are only useful if they say which rule. Turn them into
        # one message and the operator has to bisect a 63-character name by
        # hand, which is the outcome the error is a struct to avoid.
        "say nothing about which rule was broken",
        '        return Err(invalid(\n            "a bucket name is lowercase letters, digits, dots and hyphens",\n        ));',
        '        return Err(invalid("invalid"));',
        "the_refusal_names_the_rule_that_was_broken",
    ),
    # ---- the key ----------------------------------------------------------
    (
        "accept a key carrying a line break",
        "    if let Some(byte) = key.bytes().find(|b| b.is_ascii_control()) {",
        "    if let Some(byte) = None::<u8> {",
        "a_key_carrying_a_line_break_is_refused",
    ),
    (
        "accept an empty key",
        "    if key.is_empty() {",
        "    if false {",
        "an_empty_key_is_refused",
    ),
    (
        # Normalising is the temptation: a key is not a path expression, but
        # resolving `a/../b` to `b` looks helpful. The signature would then be
        # computed over the resolved path while the operator's key is what the
        # request claims to name.
        "normalise a traversing key instead of refusing it",
        "    if key\n        .split('/')\n        .any(|segment| segment == \"..\" || segment == \".\")\n    {",
        "    if false {",
        "a_key_containing_a_dot_dot_segment_is_refused_rather_than_rewritten",
    ),
    (
        # The smallest plausible mistake in the file. A traversal check written
        # as "two dots in a row anywhere" passes every other row in this
        # campaign and breaks a legitimate key — and a check that is wrong
        # often enough gets disabled by whoever hits it first.
        "refuse any key with two dots in a row",
        "    if key\n        .split('/')\n        .any(|segment| segment == \"..\" || segment == \".\")\n    {",
        "    if key.contains(\"..\") || key.contains(\"./\") {",
        "a_key_containing_dots_that_are_not_a_segment_is_fine",
    ),
    # ---- the scope ---------------------------------------------------------
    (
        # The credential scope is date/region/service/aws4_request. Without a
        # region the signature is over an incomplete scope, and the failure an
        # operator sees names their credentials rather than their config.
        "resolve without a region",
        "        if region.is_empty() {",
        "        if false {",
        "an_empty_region_is_refused",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "aws::s3::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = S3
    f.MUTATIONS[:] = MUTATIONS
    original = S3.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert S3.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
