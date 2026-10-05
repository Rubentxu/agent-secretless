#!/usr/bin/env python3
"""Falsification for R2.F.1, the registry challenge, realm and scope core.

Five phases over one file, because the three properties are three separate
questions about the same module and a reader should be able to see which one a
survivor belongs to. The phases are named in the output and tallied separately;
the totals are one line each rather than one number that hides all five.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise. This harness
adds a fifth bucket for a snippet it could not find: see `run_phase`.

**This module has twenty-nine rows and files twenty-seven mutations. Six of the
twenty-nine have no mutation of their own, and the reasons are worth stating
rather than folding into a total.**

`the_service_is_not_the_registry_host` measures the *absence* of an
inference: the `service` parameter is read and the realm's host is not used to
derive one. A mutation would not be a line someone could write — it would be
writing the inference, which is why the row's own assertion is that the two
strings differ for Docker Hub.

`a_bare_label_realm_is_refused` cannot be turned red by any mutation, and the
reason is the type: `asv_domain::Authority` has no public constructor from a
raw string, so accepting `localhost` would mean not holding an `Authority`.
That is a stronger claim than "there is no test for it".

`a_token_response_yields_its_scope_and_never_its_token` is compiler-refused for
the same shape of reason: `granted_scope_from_token_response` returns a
`RegistryScope`, which has two fields and neither is a token, so a mutation
that copies the token out of the body does not compile against this API. The
row still measures the property — it renders the returned scope and asserts the
token bytes are absent from it — and it is what would go red the day the return
type grows a field.

`a_trailing_crlf_never_reaches_the_realm` is filed as compound, and the
campaign is why. See the finding below.

`the_challenge_docker_hub_sends_is_read` is positive: it exists so that the
twenty-eight refusals cannot be satisfied by a parser that refuses everything.
Every mutation below turns it red as a side effect, so filing one against it
would measure the same line twice.

`the_scope_asked_for_comes_from_the_operation_and_not_the_challenge` has no
line of its own either, and this is stated rather than papered over: the
property is that `scope_to_request` takes an operation and a repository and has
no parameter that could carry a challenge. The campaign turns the row red with
the `for_operation` mutation, which is why it appears in the narrowing phase
even though it reads like a challenge row.
`a_wide_grant_from_the_token_endpoint_is_still_narrowed` is the same story on
the other side of the flow, and is turned red by the ceiling mutation below.

**The mutation to read first is the one that takes the ceiling.** `narrow`
returns the required scope, having first established that the grant covers it.
Returning `granted` instead — one word — is a working connector that hands a
pull a token that can also push, and every other check in the file still
passes. The grant is wider on every real registry, so this is not a
hypothetical: `repository:library/alpine:pull,push` is in the challenge Docker
Hub actually sends, and the same string comes back from the token endpoint.

**The second is the name grammar.** A scope reads
`repository:<name>:<actions>`, so a repository name carrying a colon closes the
name early and the rest is read as actions. `library/app:pull,repository:admin/
secret:pull` is not a repository with an odd name, it is a request for two
scopes, the second of which belongs to somebody else. The grammar is what makes
the `:` mean exactly one thing, and the row that pins it is the one that tries
the injection.

**Two defects were found by this campaign rather than by reading the code, and
both are about the tests.**

`a_repository_name_outside_the_spec_is_refused` originally asserted only
`is_err()` for each hostile name. Turning the trailing-separator refusal into a
*different* refusal — same outcome, different reason — left the row green,
which is precisely the accidental survival the campaign exists to find. The row
now names the reason it refused, so that mutation is red.

`a_control_character_in_the_header_is_refused` originally used a trailing CRLF
as its fixture and stayed green with the `is_control` guard deleted. The guard
was not what refused that header: the parameter scanner names `\r` a malformed
parameter name, so the row was green for a reason unrelated to the code it
claimed to measure. It is now split in two — a control character *inside* a
value, which does depend on the guard, and a separate row that records the
trailing-CRLF outcome and says which mechanism actually stops it. A row that
passes for the wrong reason is worse than no row, because it is counted.

**A third defect was in this harness, and it is filed as a bucket rather than a
result.** The first run put a snippet it could not find into
`green (SURVIVOR)`, which reported an indentation typo in this file as though
the row had survived a mutation. Both are a "no" and only one is a statement
about the code, so `harness error` is now a bucket of its own, it fails the
run, and the five buckets still partition it.

Run:  python3 registry_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

REGISTRY = f.REPO / "crates/connector-http/src/registry.rs"

# (label, old, new, test that must go red)
CHALLENGE_MUTATIONS = [
    (
        "accept a challenge that names no realm",
        "realm: realm.ok_or(ChallengeError::MissingRealm)?,",
        "realm: realm.unwrap_or_default(),",
        "a_challenge_without_a_realm_is_refused",
    ),
    (
        # A `Basic` challenge names a realm too. Following one is how a client
        # ends up posting a password to a host the user never approved.
        "accept a scheme that is not Bearer",
        "if !scheme.eq_ignore_ascii_case(\"Bearer\") {\n            return Err(ChallengeError::NotBearer {\n                found: scheme.to_string(),\n            });\n        }",
        "if scheme.eq_ignore_ascii_case(\"NotBearer\") {\n            return Err(ChallengeError::NotBearer {\n                found: scheme.to_string(),\n            });\n        }",
        "a_challenge_that_is_not_bearer_is_refused",
    ),
    (
        # RFC 7235 schemes are case-insensitive, so a case-sensitive comparison
        # refuses a header a registry may legally send.
        "compare the scheme case-sensitively",
        "if !scheme.eq_ignore_ascii_case(\"Bearer\") {\n",
        "if scheme != \"Bearer\" {\n",
        "a_challenge_that_is_not_bearer_is_refused",
    ),
    (
        # Last-one-wins is a decision the sender chose: two realms, and this
        # side picks the one that comes second.
        "let the last value of a repeated parameter win",
        "            if slot.is_some() {",
        "            if false {",
        "a_repeated_parameter_is_refused_rather_than_last_one_winning",
    ),
    (
        # Reading to end-of-input treats a truncated header as if it were
        # complete, which is how a cut-off `realm` becomes a shorter one.
        "accept a quoted value that is never closed",
        "            if i >= bytes.len() {\n                return Err(ChallengeError::Malformed(format!(\n                    \"the value of {key:?} is never closed\"\n                )));\n            }",
        "            if false {\n                return Err(ChallengeError::Malformed(format!(\n                    \"the value of {key:?} is never closed\"\n                )));\n            }",
        "an_unclosed_quote_is_refused",
    ),
    (
        # A control character inside the value is read verbatim without the
        # guard, control and all, and the header parses.
        "accept a control character in the header",
        "if header.chars().any(|c| c.is_control()) {",
        "if false {",
        "a_control_character_inside_a_value_is_refused",
    ),
]

# (label, old, new, test that must go red)
REALM_MUTATIONS = [
    (
        # The realm chooses where the broker sends the next request. Over plain
        # http, the bearer in that request travels in the clear.
        "follow a realm that is not https",
        "if url.scheme() != \"https\" {",
        "if false {",
        "a_plaintext_realm_is_refused",
    ),
    (
        # `https://user:pass@auth.docker.io/token` is a password in a URL, and
        # the request that follows carries a credential nobody chose to hold.
        "accept a realm carrying credentials",
        "if !url.username().is_empty() || url.password().is_some() {",
        "if false {",
        "a_realm_carrying_credentials_is_refused",
    ),
    (
        # A query is where a relay puts its own identifier.
        "accept a realm carrying a query",
        "if url.query().is_some() {",
        "if false {",
        "a_realm_carrying_a_query_is_refused",
    ),
    (
        # A fragment never reaches a server, so a realm carrying one means the
        # sender is relying on the two sides disagreeing about it.
        "accept a realm carrying a fragment",
        "if url.fragment().is_some() {",
        "if false {",
        "a_realm_carrying_a_fragment_is_refused",
    ),
    (
        # Port 8443 is a listener this transport never vetted, and it is enough
        # to send the token request somewhere the policy never looked.
        "accept a realm on any port",
        "        if let Some(named) = url.port() {\n            if named != port {",
        "        if let Some(named) = url.port() {\n            if false {",
        "a_realm_on_another_port_is_refused",
    ),
    (
        # Forcing loopback on here would make every loopback realm reachable in
        # production, whatever the caller passed.
        "resolve the realm with loopback forced on",
        "let resolved = resolve_and_pin(&vetted.authority, port, policy)?;\n",
        "let resolved = resolve_and_pin(&vetted.authority, port, AddressPolicy { allow_loopback: true })?;\n",
        "a_realm_that_resolves_to_loopback_is_refused",
    ),
    (
        # A `Realm` whose addresses were never checked is the SSRF the whole
        # vetting exists to prevent, wearing the type that says it was.
        "vet the realm without resolving or checking it",
        "let resolved = resolve_and_pin(&vetted.authority, port, policy)?;\n        Ok(Self {",
        "let resolved = ResolvedAudience { authority: vetted.authority.clone(), port, addresses: vec![] };\n        Ok(Self {",
        "a_vetted_realm_reports_the_addresses_it_was_checked_against",
    ),
]

# (label, old, new, test that must go red)
#
# Two rows about the same line, and they are filed as two because they are two
# different claims: that the production policy refuses a literal realm, and
# that the refusal is the policy's rather than a rule about the spelling. The
# second row would pass just as well if `vet` refused every literal forever.
POLICY_MUTATIONS = [
    (
        # The metadata address is the one an SSRF wants, and the useful
        # literals to refuse first are loopback, RFC1918 and link-local.
        "resolve a literal realm under a policy that permits loopback",
        "let resolved = resolve_and_pin(&vetted.authority, port, policy)?;\n",
        "let resolved = resolve_and_pin(&vetted.authority, port, AddressPolicy { allow_loopback: true })?;\n",
        "an_address_literal_realm_is_refused",
    ),
    (
        # Same mutation, filed against the row that says the decision belongs
        # to the policy: with loopback forced on, a literal stops being refused
        # even though nothing about its shape changed.
        "let the shape of a literal decide, whatever the policy says",
        "let resolved = resolve_and_pin(&vetted.authority, port, policy)?;\n        Ok(Self {",
        "let resolved = resolve_and_pin(&vetted.authority, port, AddressPolicy { allow_loopback: true })?;\n        Ok(Self {",
        "the_same_literal_is_vetted_by_the_policy_and_not_by_its_shape",
    ),
]

# (label, old, new, test that must go go red)
SCOPE_MUTATIONS = [
    (
        # An operation naming two actions is how a read becomes a write without
        # anyone writing a "push".
        "name every action for one operation",
        "        actions.insert(operation.action().to_string());",
        "        actions.insert(\"pull\".to_string());\n        actions.insert(\"push\".to_string());",
        "an_operation_names_exactly_one_action",
    ),
    (
        # The injection, in the form a caller would try: a name carrying the
        # scope separator and a second scope behind it.
        "stop checking the repository name",
        "        for component in raw.split('/') {\n            check_component(component)?;\n        }",
        "        for component in raw.split('/') {\n            let _ = check_component(component);\n        }",
        "a_repository_name_cannot_inject_actions_into_a_scope",
    ),
    (
        # The first version of the row it files against only asserted `is_err`,
        # so turning this refusal into a different refusal stayed green.
        "report a trailing separator as a bad character",
        "            return Err(ScopeError::TrailingSeparator {\n                component: component.to_string(),\n            });",
        "            return Err(ScopeError::NameCharacter {\n                component: component.to_string(),\n                byte: b'-',\n            });",
        "a_repository_name_outside_the_spec_is_refused",
    ),
    (
        "stop enforcing the length limit",
        "if raw.len() > MAX_REPOSITORY_NAME {",
        "if false {",
        "a_repository_name_outside_the_spec_is_refused",
    ),
    (
        "stop enforcing ascii names",
        "if !raw.is_ascii() {",
        "if false {",
        "a_repository_name_outside_the_spec_is_refused",
    ),
    (
        # Splitting on the first colon reads `repository:alpine:pull,repository:admin:pull`
        # as a grant for `alpine` covering an action called
        # `pull,repository:admin:pull`, which is nobody's scope and everybody's
        # bypass.
        "split a scope on its first colon rather than its last",
        "            .rsplit_once(':')",
        "            .split_once(':')",
        "a_scope_read_off_the_wire_goes_through_the_same_grammar",
    ),
    (
        "accept a scope for something that is not a repository",
        "            if raw.contains(':') && !raw.starts_with(\"repository:\") {",
        "            if false {",
        "a_scope_read_off_the_wire_goes_through_the_same_grammar",
    ),
]

# (label, old, new, test that must go red)
NARROWING_MUTATIONS = [
    (
        # The mutation to read first. The grant is wider on every real registry,
        # so taking the ceiling is not a corner case: a pull comes back with a
        # token that can also push, and every other check still passes.
        "use the grant as the effective scope",
        "    Ok(required.clone())",
        "    Ok(granted.clone())",
        "the_effective_scope_is_the_intersection_and_not_the_wider_one",
    ),
    (
        # A grant for one action used for an operation needing two.
        "stop requiring the grant to cover the operation",
        "    if !granted.actions.is_superset(&required.actions) {",
        "    if false {",
        "a_grant_that_does_not_cover_the_operation_is_refused",
    ),
    (
        # A token for `library/other` is not a token for `library/alpine`.
        "compare only the actions, not the repository",
        "    if required.repository != granted.repository {",
        "    if false {",
        "a_grant_for_another_repository_is_refused",
    ),
    (
        # The same `for_operation` mutation, filed against the row that has no
        # line of its own: the scope asked for is only as narrow as the
        # operation names it.
        "name every action for one operation (asked-for scope)",
        "        actions.insert(operation.action().to_string());",
        "        actions.insert(\"pull\".to_string());\n        actions.insert(\"push\".to_string());",
        "the_scope_asked_for_comes_from_the_operation_and_not_the_challenge",
    ),
    (
        # A response with no scope is a refusal, not a default. Assuming the
        # grant because the endpoint stayed quiet is the bug this module exists
        # to prevent.
        #
        # The snippet is wrapped across three lines because `rustfmt` decided
        # so, and the harness reports a snippet it cannot find as its own
        # bucket rather than as a survivor — which is how this one was caught
        # instead of being quietly counted as a row that resisted.
        "assume a grant when the response carries no scope",
        "    let scope = value.get(\"scope\").and_then(Value::as_str).ok_or_else(|| {\n        ScopeError::NoScopeInTokenResponse(\"the response carries no scope\".into())\n    })?;",
        "    let scope = value.get(\"scope\").and_then(Value::as_str).unwrap_or(\"repository:library/alpine:pull\");",
        "a_token_response_without_a_scope_is_refused",
    ),
]


def run_phase(path: Path, mutations: list, title: str) -> tuple[int, dict, list]:
    """Apply `mutations` to one file and return the five-bucket tally.

    Deliberately a thin re-use of the base harness's `run_test` rather than a
    fork of its summary logic: the buckets partition the run, and a summary
    that does not partition is the one number nobody checks.

    **A snippet that does not appear exactly once is a defect in this file, not
    a result, and it gets its own bucket for that reason.** The first run of
    this campaign put a not-found snippet into `green (SURVIVOR)`, which
    reported a typo in a harness as though the row had survived a mutation.
    Both readings are a "no", and only one of them is a statement about the
    code, so they are counted separately and both fail the run.
    """
    original = path.read_text()
    buckets = {
        "red": 0,
        "compiler-refused": 0,
        "green (SURVIVOR)": 0,
        "measured nothing": 0,
        "harness error": 0,
    }
    problems: list = []
    try:
        for label, old, new, test in mutations:
            if original.count(old) != 1:
                buckets["harness error"] += 1
                problems.append(
                    (label, test, f"snippet counts {original.count(old)}, want 1 -- harness defect")
                )
                print(
                    f"SKIP  {label!r}: snippet is not unique ({original.count(old)})",
                    flush=True,
                )
                continue
            path.write_text(original.replace(old, new, 1))
            try:
                verdict, out = f.run_test(test)
            finally:
                path.write_text(original)
            if verdict == "red":
                buckets["red"] += 1
                print(f"ok    [{title}] {label}\n      -> {test} went red", flush=True)
            elif verdict == "green":
                buckets["green (SURVIVOR)"] += 1
                problems.append((label, test, "the row stayed green"))
                print(f"SURVIVOR  [{title}] {label}\n      -> {test} stayed GREEN  <-- the finding", flush=True)
            elif verdict == "refused":
                buckets["compiler-refused"] += 1
                first = next(
                    (ln.strip() for ln in out.splitlines() if ln.strip().startswith("error")), "?"
                )
                print(f"ok*   [{title}] {label}\n      -> {test}: refused by the compiler\n         {first}", flush=True)
            else:
                buckets["measured nothing"] += 1
                problems.append((label, test, verdict))
                print(f"BAD   [{title}] {label}\n      -> {test}: {verdict}", flush=True)
    finally:
        path.write_text(original)
    assert path.read_text() == original, f"{path} was not restored"
    assert sum(buckets.values()) == len(mutations), (buckets, len(mutations))
    return len(mutations), buckets, problems


# (prefix, mutations, phase title)
PHASES = [
    ("registry::tests::", CHALLENGE_MUTATIONS, "R2.F.1 challenge"),
    ("registry::tests::", REALM_MUTATIONS, "R2.F.1 realm"),
    ("registry::tests::", POLICY_MUTATIONS, "R2.F.1 address policy"),
    ("registry::tests::", SCOPE_MUTATIONS, "R2.F.1 scope"),
    ("registry::tests::", NARROWING_MUTATIONS, "R2.F.1 narrowing"),
]


def main() -> int:
    f.CARGO_TARGET = "--lib"
    f.PACKAGE = "asv-connector-http"
    f.TEST_PREFIX = "registry::tests::"
    f.MUTATIONS[:] = CHALLENGE_MUTATIONS
    f.STS = REGISTRY

    total = sum(len(m) for _, m, _ in PHASES)
    print(f"# falsifying R2.F.1 with {total} mutations across {len(PHASES)} phases\n")

    tally = {}
    problems = []
    for index, (prefix, mutations, title) in enumerate(PHASES, start=1):
        f.TEST_PREFIX = prefix
        f.STS = REGISTRY
        print(f"## phase {index} -- {title} ({REGISTRY.relative_to(f.REPO)})")
        _, buckets, found = run_phase(REGISTRY, mutations, f"{title}")
        tally[title] = buckets
        problems += found
        print()

    merged = {}
    for buckets in tally.values():
        for key, value in buckets.items():
            merged[key] = merged.get(key, 0) + value
    assert sum(merged.values()) == total, (merged, total)

    print(f"mutations: {total}  (the five buckets partition the run)")
    for name, count in merged.items():
        print(f"  {name:<22}: {count}")
    print()
    for title, buckets in tally.items():
        line = ", ".join(f"{k}={v}" for k, v in buckets.items() if v)
        print(f"  {title}: {line or 'none'}")

    for label, test, why in problems:
        print(f"\nFINDING: {label}\n  test: {test}\n  {why}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
