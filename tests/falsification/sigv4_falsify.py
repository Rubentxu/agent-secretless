#!/usr/bin/env python3
"""Falsification for R2.C.1, the SigV4 signing core.

This is the campaign the roadmap names as the one figure that could not be
re-derived. Every other harness in this directory answers "what concrete
mutation makes this row red?" for a module that was measured; this one supplies
the missing question for the signing core, so the `16/16 against the AWS
documentation's own vectors` figure becomes re-derivable like the rest instead
of being an inherited number.

Same four-bucket accounting as its siblings, and the same refusal to count a
mutation that cannot compile as a break.

The ordering below is not arbitrary. The first group is the *arithmetic* — the
four HMAC steps and the encoding rules — because those are what the published
vectors pin down. The second group is the *property* the module docs argue for:
a signature that commits to the host and to a header list the caller cannot
choose. The vectors cannot establish the property, because every vector is a
request that should succeed; only a row that refuses a request can. A signer
that computes the right HMAC and drops the host requirement would pass all six
vectors and replay across destinations, so the mutations that matter most here
are the ones that delete a refusal.

Run:  python3 sigv4_falsify.py
"""

import sys
from pathlib import Path

# The base harness lives beside this one. `python3 tests/falsification/x.py`
# already puts this directory on `sys.path`, so the insert is only load-
# bearing for a runner that imports it as a module instead of executing
# it -- and a campaign that only works one way is a campaign that stops
# being reproducible the first time someone automates it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

SIGV4 = f.REPO / "crates/broker/src/aws/sigv4/mod.rs"

MUTATIONS = [
    # ---- the four-step derivation -----------------------------------------
    (
        "derive the chain under a different algorithm prefix",
        'format!("AWS4{secret}")',
        'format!("AWS5{secret}")',
        "the_signing_key_matches_the_documented_iam_derivation",
    ),
    (
        # The doc for this row says a collapsed chain is the thing it exists to
        # notice. Collapsing it to the first step is the coarsest version.
        "collapse the chain: skip the date step",
        "    let k_date = hmac_sha256(&initial, date_stamp.as_bytes());",
        "    let k_date = initial.to_vec();",
        "the_signing_key_matches_the_documented_iam_derivation",
    ),
    (
        "collapse the chain: skip the region step",
        "    let k_region = hmac_sha256(&k_date, region.as_bytes());",
        "    let k_region = k_date.clone();",
        "the_signing_key_matches_the_documented_iam_derivation",
    ),
    (
        # Reaches only this row: the vanilla vector is service `service`, and
        # the credential scope already names the same string, so dropping the
        # terminator from the chain is invisible everywhere else.
        "sign with the service key instead of the signing key",
        '    hmac_sha256(&k_service, b"aws4_request")',
        "    k_service.clone()",
        "the_signing_key_matches_the_documented_iam_derivation",
    ),
    # ---- the string to sign -----------------------------------------------
    (
        "name a different algorithm in the string to sign",
        'pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";',
        'pub const ALGORITHM: &str = "AWS4-HMAC-SHA384";',
        "the_documented_get_vanilla_case_signs_to_the_published_signature",
    ),
    (
        # The historical defect this module documents is an extra path segment
        # on the scope that is never hashed, so the signature stays correct and
        # the header becomes unreadable. Here it is a trailing separator on the
        # scope the string-to-sign *does* hash, so the signature moves and the
        # published vector is what catches it.
        "add a trailing separator to the hashed scope",
        '            "{}/{}/{}/aws4_request",',
        '            "{}/{}/{}/aws4_request/",',
        "the_documented_get_vanilla_case_signs_to_the_published_signature",
    ),
    (
        # Re-attributed after the first run. It was filed against
        # `every_signed_dimension_changes_the_signature`, on the reasoning that
        # dropping the date from the string to sign must make two dates collide.
        # That row stayed GREEN, which is a fact about the row and not about the
        # signer: it has no pair of instants differing only in the date, so it
        # cannot see a dropped one. The mutation is still a real break -- the
        # signature changes, so the published constant no longer matches -- and
        # the row that catches it is the vector. Measured, not assumed.
        "leave the timestamp out of the string to sign",
        '            "{ALGORITHM}\\n{amz_date}\\n{scope}\\n{}",',
        '            "{ALGORITHM}\\n{scope}\\n{}",',
        "the_documented_get_vanilla_case_signs_to_the_published_signature",
    ),
    (
        "use a digest that is not the empty string's",
        '    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";',
        '    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";',
        "the_canonical_request_is_the_documented_one",
    ),
    # ---- the timestamp the scope is derived from --------------------------
    (
        # `get(..0)` yields the empty string, and `all` on an empty iterator is
        # vacuously true, so this is the mutation that turns a refusal into an
        # empty date scope rather than an error.
        "derive an empty date scope from any timestamp",
        "        .get(..8)",
        "        .get(..0)",
        "a_timestamp_the_scope_cannot_be_derived_from_is_refused",
    ),
    (
        "accept a scope whose first eight characters are not digits",
        "        .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))",
        "        .filter(|_| true)",
        "a_timestamp_the_scope_cannot_be_derived_from_is_refused",
    ),
    # ---- the refusals, which are the property ----------------------------
    (
        # The one this file would most want to be quoted for. It deletes the
        # host requirement entirely: the signature is still arithmetically
        # correct, every published vector still matches, and a captured request
        # is now replayable against a different destination. Nothing in the
        # vector set can notice, which is why the refusal needs its own row.
        "sign a request that carries no host at all",
        '    if !prepared.iter().any(|(name, _)| name == "host") {',
        "    if false {",
        "a_request_without_a_host_is_refused",
    ),
    (
        # Re-attributed after the first run, and this one is worth reading twice
        # because the first attribution looked obviously right and was wrong.
        # Filed against `a_request_without_a_host_is_refused`, reasoning that a
        # comparison that can never match refuses *every* request, so the row
        # must notice. It does not, and the reason is the shape of the row: it
        # asserts that a hostless request is REFUSED, and under this mutation a
        # hostless request is still refused -- it simply stops being the only one
        # that is. A row that checks a refusal is satisfied by a signer that
        # refuses everything. The defect is real and worse than the one it was
        # filed under: it is a signer that signs nothing at all, which no
        # failure-only row can see. What sees it is a request that should have
        # been signed.
        "look for the host in the wrong case after lowercasing",
        'name == "host")',
        'name == "Host")',
        "the_documented_get_vanilla_case_signs_to_the_published_signature",
    ),
    (
        "accept a header name carrying a separator",
        "        if !is_token(&name) {",
        "        if false {",
        "a_header_name_carrying_a_separator_is_refused",
    ),
    (
        # Header injection. The canonical form joins headers with a newline, so
        # an accepted newline in a value is a second header the signature never
        # named.
        "accept a header value carrying a control character",
        "        if value.chars().any(|c| c.is_control()) {",
        "        if false {",
        "a_header_value_carrying_a_newline_is_refused",
    ),
    (
        # A caller that appends a second value to a header it already signed
        # would otherwise get a signature that validates for a header it did not
        # intend. The comment in the module says signing only the first is the
        # alternative; this is that alternative, reached.
        "sign the first of two identically named headers",
        "        if pair[0].0 == pair[1].0 {",
        "        if false {",
        "a_duplicated_header_name_is_refused",
    ),
    (
        "accept an empty region",
        "        if region.is_empty() {",
        "        if false {",
        "an_incomplete_credential_scope_is_refused_at_construction",
    ),
    (
        "accept an empty service",
        "        if service.is_empty() {",
        "        if false {",
        "an_incomplete_credential_scope_is_refused_at_construction",
    ),
    # ---- the canonical header list ---------------------------------------
    (
        # The row this is attributed to asserts two things at once, and the
        # first of them dies here: `HOST` and `host` stop agreeing.
        "match header names case-sensitively",
        "        let name = header.name.to_ascii_lowercase();",
        "        let name = header.name.to_string();",
        "header_names_match_case_insensitively_and_values_fold",
    ),
    (
        "stop folding whitespace inside a header value",
        '        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");',
        "        let value = value.to_string();",
        "header_names_match_case_insensitively_and_values_fold",
    ),
    # ---- the encoding rules ----------------------------------------------
    (
        "encode a space literally instead of as %20",
        "            b'-' | b'.' | b'_' | b'~' => true,",
        "            b'-' | b'.' | b'_' | b'~' | b' ' => true,",
        "a_space_is_percent_twenty_and_never_a_plus",
    ),
    (
        "encode percent-escapes with lowercase hex",
        '    const HEX: &[u8; 16] = b"0123456789ABCDEF";',
        '    const HEX: &[u8; 16] = b"0123456789abcdef";',
        "percent_encoding_uses_uppercase_hex",
    ),
    (
        "encode the path once for every service, S3 included",
        "    if s3_path {",
        "    if true {",
        "the_path_is_encoded_twice_unless_it_is_s3",
    ),
    (
        "encode the S3 path twice, like every other service",
        "    if s3_path {",
        "    if !s3_path {",
        "the_path_is_encoded_twice_unless_it_is_s3",
    ),
    (
        # The sort is by the *encoded* name, which is the whole reason this is
        # not a `sort()` on the caller's strings. Sorting by value reorders a
        # list whose values were never the ordering key.
        "sort query parameters by value instead of by name",
        "    encoded.sort();",
        "    encoded.sort_by(|a, b| a.1.cmp(&b.1));",
        "query_parameters_sort_by_encoded_name",
    ),
    # ---- the one surface a secret could reach ----------------------------
    (
        # Not an encoding change: a `Debug` that printed the key would put it in
        # every assertion failure that touched a signer, which is the most-read
        # place a secret ends up.
        "print the secret access key in the signer's Debug",
        '            .field("secret_access_key", &"<redacted>")',
        "            .field(\"secret_access_key\", &self.secret_access_key)",
        "the_secret_never_appears_in_the_signer_output",
    ),
]


def main() -> int:
    f.STS = SIGV4
    f.TEST_PREFIX = "aws::sigv4::tests::"
    f.MUTATIONS[:] = MUTATIONS
    original = SIGV4.read_text()
    print(f"# falsifying {SIGV4.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert SIGV4.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
