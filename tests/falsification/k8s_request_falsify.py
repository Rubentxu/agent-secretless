#!/usr/bin/env python3
"""Falsification for R2.D.1, the Kubernetes request core.

The module's claim is a single sentence: **the agent-supplied parts cannot
escape their position in the request.** It takes three strings from a caller and
puts each at a fixed place in a URL, so the mutations that matter are the ones
that would let a named part mean something other than what it was named as.

That is the failure a proxy can have without a vulnerability anywhere: a builder
that does `format!("/api/v1/namespaces/{ns}/{resource}/{name}")` will happily
turn `pods/../../secrets` into a well-formed, correctly authenticated request
aimed somewhere the agent never named. So this campaign is mostly about
*removing refusals*, not about perturbing encodings — a check that stops being
applied, or stops excluding one character, is the defect in shape.

**This campaign is the union of two that were written against this module
independently, and the merge changed what is claimed here.**

The first version of this file was written by one author; a second was written
by another against the same module, and each had read the module's doc comment
rather than the other's harness. Neither is a subset of the other, and running
one instead of both would have left rows unmeasured while the totals still
looked like a number. The union is what a single reviewer would have produced.

What the merge settled, rather than merely concatenating:

- The second harness's three "place the X without checking it" mutations are the
  sharpest expression of the property and were absent from the first, which had
  reasoned that removing a check was redundant with another rule. That reasoning
  was wrong: the redundancy was between checks *inside* `checked_subdomain`,
  not between a check and its absence. Removing `checked_subdomain(..)?` at the
  call site is the defect in its purest form and it is measured.
- One mutation was **misattributed** in the second harness and the merge fixed
  it. `matches!(self, Verb::Get | Verb::Delete)` narrowed to `Verb::Get` was
  filed against `get_and_list_share_a_method_but_not_a_shape`, which still
  passes under it — `Get` takes a name and `List` does not, so the `assert_ne!`
  holds. What the mutation actually breaks is `delete`, which stops requiring a
  name, so that is the row it is filed against now. Left as it was, it would
  have been reported as a survivor and read as a gap in the test rather than a
  gap in the filing.
- The first harness's `b < 0x20` and the second's `.any(|_| false)` are the same
  defect expressed two ways. The `.any(|_| false)` form is kept: it reads as
  "stop excluding anything" rather than as "start excluding control characters
  explicitly", which is closer to what the mutation means.

Two findings from writing the module itself are recorded rather than hidden,
both of which came out of falsifying code that had just been written and was
believed correct:

- The `ApiError` arms `NamespaceMismatch` and `UnsupportedGroup` could not be
  constructed. `Scope` already refuses both by type, so they were claims the
  code could not keep, and they are gone.
- Three explicit traversal checks in `checked_subdomain` — `== "." || == ".."`,
  `starts_with('.')` and `contains("..")` — could never be the arm that refused,
  because the per-label loop catches every one of those inputs as an empty or
  edge-shaped label. They were unreachable rules that read in review as handled.
  The traversal argument is now made once, by the loop.

Run:  python3 k8s_request_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

REQUEST = f.REPO / "crates/broker/src/k8s/request.rs"

# The subdomain alphabet. Adding one character here is how a name grows a `/`,
# a `%` or a `?` — the three characters that change what the path *means*
# rather than what it looks like.
SUBDOMAIN_ALPHABET = (
    "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'))\n"
)
# The label alphabet, which deliberately differs: a namespace has no dot.
LABEL_ALPHABET = (
    "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))\n"
)

MUTATIONS = [
    # --- the three placements, unchecked -------------------------------------
    # These are the property stated as a mutation. Everything below perturbs a
    # rule; these remove the application of a rule, which is the defect.
    (
        "place the resource without checking it",
        '        let resource = checked_subdomain("resource", self.resource)?;',
        "        let resource = self.resource.to_string();",
        "a_resource_cannot_walk_out_either",
    ),
    (
        "place the namespace without checking it",
        '        let namespace = checked_label("namespace", namespace)?;',
        "        let namespace = namespace.to_string();",
        "a_name_may_not_begin_or_end_with_a_hyphen_in_the_namespace_either",
    ),
    (
        "place the name without checking it",
        '            let name = checked_subdomain("name", name)?;',
            "            let name = name.to_string();",
        "a_name_containing_a_slash_is_refused",
    ),
    # --- one character at a time in the subdomain alphabet -------------------
    (
        "let a name contain a slash",
        SUBDOMAIN_ALPHABET,
        "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'/'))\n",
        "a_name_containing_a_slash_is_refused",
    ),
    (
        "let a name contain a percent",
        SUBDOMAIN_ALPHABET,
        "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'%'))\n",
        "a_name_containing_a_percent_is_refused_rather_than_escaped",
    ),
    (
        "let a name carry a query",
        SUBDOMAIN_ALPHABET,
        "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'?'))\n",
        "a_name_carrying_a_query_or_a_fragment_is_refused",
    ),
    (
        "let a name carry a control character",
        SUBDOMAIN_ALPHABET,
        "        .any(|_| false)\n",
        "a_name_containing_a_control_character_is_refused",
    ),
    (
        "accept an uppercase name rather than refusing it",
        SUBDOMAIN_ALPHABET,
        "        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))\n",
        "uppercase_is_refused_rather_than_lowercased",
    ),
    # --- the label alphabet, which is where a namespace is refused differently -
    (
        "let a namespace contain a dot",
        LABEL_ALPHABET,
        "        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'))\n",
        "a_namespace_with_a_dot_is_refused_even_though_a_name_may_have_one",
    ),
    # --- the empty-segment refusals ------------------------------------------
    (
        "let a name be empty",
        "    if value.is_empty() {\n        return Err(ApiError::EmptySegment { what });\n    }\n    if value.len() > 253 {",
        "    if value.len() > 253 {",
        "an_empty_resource_is_refused",
    ),
    (
        "let a namespace be empty",
        "    if value.is_empty() {\n        return Err(ApiError::EmptySegment { what });\n    }\n    if value.len() > 63 {",
        "    if value.len() > 63 {",
        "an_empty_namespace_is_refused",
    ),
    # --- the length bounds ----------------------------------------------------
    (
        "drop the length bound on a name",
        "    if value.len() > 253 {",
        "    if false {",
        "a_name_longer_than_the_bound_is_refused",
    ),
    (
        "drop the length bound on a namespace",
        "    if value.len() > 63 {",
        "    if false {",
        "a_namespace_longer_than_a_label_is_refused",
    ),
    # --- the hyphen rules, which are two implementations of one idea ----------
    (
        "let a namespace begin or end with a hyphen",
        "    if value.starts_with('-') || value.ends_with('-') {\n        return Err(ApiError::NotANamespace(value.to_string()));\n    }\n    Ok(value.to_string())",
        "    Ok(value.to_string())",
        "a_name_may_not_begin_or_end_with_a_hyphen_in_the_namespace_either",
    ),
    (
        "let a name's labels begin or end with a hyphen",
        "        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {",
        "        if label.is_empty() {",
        "a_name_may_not_begin_or_end_with_a_hyphen",
    ),
    # --- the verb/name agreement, which is the other half of the property ----
    (
        "let a get address a collection",
        "        matches!(self, Verb::Get | Verb::Delete)",
        "        matches!(self, Verb::Delete)",
        "get_and_list_share_a_method_but_not_a_shape",
    ),
    (
        # Re-attributed by the merge. The mutation is the second author's and was
        # correct; the row it was filed against is not. Under this mutation `Get`
        # still takes a name and `List` still does not, so
        # `get_and_list_share_a_method_but_not_a_shape` stays GREEN -- and what
        # actually breaks is that `delete` stops requiring a name, so a `delete`
        # with no name builds a collection path and addresses every pod in the
        # namespace. Filed against the row that notices.
        "let a delete address a collection",
        "        matches!(self, Verb::Get | Verb::Delete)",
        "        matches!(self, Verb::Get)",
        "a_delete_without_a_name_is_refused",
    ),
    (
        # The other arm of the agreement, which neither harness had: a `list`
        # that takes a name addresses one object at a path that reads like a
        # collection, and the API server answers `404` for reasons unrelated to
        # what the agent got wrong.
        "let a list address one object",
        "            (false, Some(_)) => return Err(ApiError::UnexpectedName(self.verb)),",
        "            (false, Some(_)) => {}",
        "a_list_with_a_name_is_refused_rather_than_addressing_an_object",
    ),
    (
        "let a get with no name through as a list",
        "            (true, None) => return Err(ApiError::MissingName(self.verb)),",
        "            (true, None) => {}",
        "a_get_without_a_name_is_refused_rather_than_becoming_a_list",
    ),
    # --- the methods ----------------------------------------------------------
    (
        "create becomes a get",
        '            Verb::Create => "POST",',
        '            Verb::Create => "GET",',
        "create_is_a_post_and_delete_is_a_delete",
    ),
    (
        "delete becomes a get",
        '            Verb::Delete => "DELETE",',
        '            Verb::Delete => "GET",',
        "create_is_a_post_and_delete_is_a_delete",
    ),
    (
        "a get becomes a post",
        '            Verb::Get => "GET",',
        '            Verb::Get => "POST",',
        "a_namespaced_get_is_the_documented_path",
    ),
    # --- the two placements the absolute rows are there to catch --------------
    # The cheap ones, kept first-equal in spirit so the report shows them being
    # cheap: a row pinning an exact string catches a wrong version in one line.
    (
        "address a different API version",
        '                path.push_str("/api/v1/namespaces/");',
        '                path.push_str("/api/v2/namespaces/");',
        "a_namespaced_get_is_the_documented_path",
    ),
    (
        # The cluster-scoped arm is the one that grants authority without a
        # namespace, so a prefix added here is a namespace the caller never named
        # and a resource inside it.
        "give a cluster-scoped resource somebody else's namespace",
        '            Scope::Cluster => path.push_str("/api/v1/"),',
        '            Scope::Cluster => path.push_str("/api/v1/namespaces/default/"),',
        "a_cluster_scoped_object_drops_the_namespace_prefix",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "k8s::request::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = REQUEST
    f.MUTATIONS[:] = MUTATIONS
    original = REQUEST.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert REQUEST.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
