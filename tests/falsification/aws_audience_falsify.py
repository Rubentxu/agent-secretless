#!/usr/bin/env python3
"""Falsification for R2.C.5, the audience and the region may not disagree.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the three that are not are
counted as such rather than quietly folded into the total.**

The module has **fourteen** rows. This campaign files ten mutations; nine take
a row red and one is refused by the compiler. The number below is the one that
was measured, and the first draft of this file said sixteen rows and eleven
mutations, which was wrong in both.

**Five rows are not reached**, and one of them is worth reading because the
campaign *should* have covered it and did not.

`an_attacker_bucket_whose_name_contains_sts_is_refused` is the S3-bucket attack:
`mysts.s3.us-east-1.amazonaws.com` is a name anyone can create, it contains
`sts.` and a real region, and it is not STS. The substring mutation is filed
against it, and the row stayed green — for a *second* reason. The substring
split produces `s3.us-east-1` as the "region", and the single-label rule refuses
it before anything else looks. The same mutation against
`a_host_that_merely_ends_with_sts_is_refused` does go red, because there the
substring yields a clean `eu-west-1`. So the row is genuinely uncovered and the
mutation is genuinely caught; the harness credits one row per mutation, and
filing the same mutation against both would be a second attribution nothing
checked. The row stays in the file because it documents the attack even though
a different edit currently stops it.

`a_region_that_is_not_shaped_like_one_is_refused_before_the_audience_is_read` is
uncovered because the mutation filed against it turned out to be a defect in the
*code*: removing the "at least two parts" rule left every answer unchanged,
because the character set and the digit rule were carrying it. That arm is gone
and the mutation with it.

`an_empty_region_label_never_reaches_this_module` asserts that
`Authority::canonicalize` refuses a name with an empty label, so
`sts..amazonaws.com` cannot be constructed at all and the label check here is not
what saves us. It was first written asserting the refusal came from this module
and failed for a reason one layer up.

**Two are positive**, and a check refusing everything would pass every refusal in
this file.

**What most of these mutations are for.** The property is that a deployment
signs for a region and talks to *that region's* endpoint or the global one, and
the interesting failures are hosts that contain the right characters. Two of the
rows are the same attack wearing different clothes:

`mysts.s3.us-east-1.amazonaws.com` is a bucket name in the host, because S3's
virtual-hosted addressing puts one there and a bucket is something anyone can
create. It contains `sts.` and a real region, and it is not STS. A `contains`
check passes it. `evil-sts.eu-west-1.amazonaws.com` ends with the region and the
AWS suffix, and an `ends_with` on the prefix rather than a `strip_prefix`
passes it too.

So the mutations below are three different ways to widen the comparison — a
substring, a suffix, a last-label split — and the rows that catch them are why
this is a control rather than a convenience.

**The one mutation to read twice** is `read the region out of the audience`.
Validating the region's *shape* before comparing it is what stops a region
string carrying a dot from turning a whole-label match into a substring one, and
that ordering is the property rather than an implementation detail. Flipping it
leaves every other row in this campaign green.

Run:  python3 aws_audience_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

AUDIENCE = f.REPO / "crates/broker/src/aws/audience.rs"

MUTATIONS = [
    # ---- the comparison itself --------------------------------------------
    (
        # A substring check. `mysts.s3.us-east-1.amazonaws.com` is a bucket
        # anybody can create, it contains "sts." and a real region, and it is
        # not STS.
        "match the service name anywhere in the host",
        "    let rest = name.strip_prefix(REGIONAL_STS_PREFIX)?;",
        "    let rest = name.split(REGIONAL_STS_PREFIX).nth(1)?;",
        "a_host_that_merely_ends_with_sts_is_refused",
    ),
    (
        # A suffix check on the prefix. `evil-sts.eu-west-1.amazonaws.com`
        # ends with the region and the AWS suffix, so anything that looks at
        # the end of the name rather than the start of it approves an attacker
        # host that reads exactly like the real one.
        "match the service name at the end of the host",
        "    let rest = name.strip_prefix(REGIONAL_STS_PREFIX)?;",
        "    let rest = name.strip_suffix(REGIONAL_STS_PREFIX).or(Some(name.as_str()))?;",
        "a_host_that_merely_ends_with_sts_is_refused",
    ),
    (
        # The AWS suffix as a fragment rather than as the end. This is the
        # whole-name check turned into a `contains`.
        "accept a host with the shape before a foreign suffix",
        "    let label = rest.strip_suffix(AWS_SUFFIX)?;",
        "    let label = rest.split(AWS_SUFFIX).next().unwrap_or_default();",
        "a_host_with_the_shape_before_a_foreign_suffix_is_refused",
    ),
    (
        # A label that still contains a dot is two labels. Reading the first
        # gives `x`; reading the last gives `eu-west-1`. Neither is what the
        # host means, and either would match some deployment.
        "accept a region label carrying a dot",
        "    if label.is_empty() || label.contains('.') {",
        "    if label.is_empty() {",
        "a_region_label_carrying_a_dot_is_not_a_label",
    ),
    # ---- the order, which is the property ---------------------------------
    (
        # The one mutation to read twice. Validating the region's shape *before*
        # comparing it is what stops a region carrying a dot from turning a
        # whole-label match into a substring one. Flipping the order leaves
        # every other row in this campaign green, because every other row
        # configures a well-shaped region.
        "read the region out of the audience before checking its shape",
        "        if !is_region_shaped(&self.region) {\n            return Err(AudienceError::NotARegion {\n                region: self.region.clone(),\n            });\n        }\n",
        "",
        "a_region_with_a_dot_is_refused_even_when_the_audience_would_match",
    ),
    # ---- the two shapes that are allowed ----------------------------------
    (
        # The confused deputy. The signature would be bound to `eu-west-1` and
        # the request would go to `us-east-1`: a credential used outside the
        # scope it was issued for, written by an operator who believed they had
        # pinned both.
        "accept a regional endpoint for a region this deployment does not sign for",
        "            Some(label) if label == self.region => Ok(()),",
        "            Some(_) => Ok(()),",
        "a_regional_endpoint_for_another_region_is_refused",
    ),
    (
        "refuse the region-agnostic endpoint",
        "        if is_global_sts(&self.audience) {\n            return Ok(());\n        }",
        "        if false {\n            return Ok(());\n        }",
        "the_global_endpoint_is_allowed_for_any_region",
    ),
    (
        "refuse a regional endpoint for its own region",
        "            Some(label) if label == self.region => Ok(()),",
        "            Some(_) => Err(AudienceError::NotAnStsEndpoint {\n                audience: self.audience.clone(),\n            }),",
        "a_regional_endpoint_is_allowed_for_exactly_its_own_region",
    ),
    # ---- what an operator is told -----------------------------------------
    (
        # "Wrong region" sends an operator to check their credentials. Naming
        # both sides sends them to the two lines of their own config, which is
        # where the answer is.
        "name only the configured region",
        '        "audience {audience} is the {pinned} endpoint, but this deployment \\\n         signs for {configured}; a request signed for one region and sent to \\\n         another is a credential used outside its scope"',
        '        "audience {audience} is in the wrong region"',
        "the_refusal_names_both_regions",
    ),
    (
        "refuse a first-party host without saying what the two shapes are",
        '        "audience {audience} is neither {GLOBAL_STS_ENDPOINT} nor \\\n         sts.<region>{AWS_SUFFIX}; a deployment signs for one region and talks \\\n         to that region\'s endpoint or the global one"',
        '        "audience {audience} is not allowed"',
        "a_first_party_api_that_is_not_sts_is_refused",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "aws::audience::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = AUDIENCE
    f.MUTATIONS[:] = MUTATIONS
    original = AUDIENCE.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert AUDIENCE.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
