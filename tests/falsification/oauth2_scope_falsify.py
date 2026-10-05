#!/usr/bin/env python3
"""Falsification for the OAuth2 scope as a Cedar policy resource (R2.B.2d).

The change hands a policy a *set* — the scope a registration carries — so that
`resource.scope == ["pods:read"]` is a sentence the schema accepts. Three
independent things had to become true, and a campaign that only measures the
first is how a change like this ships broken:

* **mechanism** — the `Set` reaches Cedar at all, with the type the schema
  declares. This is the defect the previous commit left behind: `Api::audience`
  was declared and never supplied, and the same mistake one level down would be
  invisible the same way, because a denial is what a policy denial looks like.
* **normalisation** — a scope list means the same thing to the issuer that
  refuses an escalation, and to the policy that reads it. Two spellings of
  "what a scope list is" is a divergence waiting for the day one is edited.
* **reachability** — the value Cedar sees is the *deployment's*. The policy
  crate can prove the engine works; only the broker's own wiring can prove what
  it puts in it, and a broker that supplied the audience instead would leave
  every policy-crate row green while refusing every real call.

Run:  python3 oauth2_scope_falsify.py mechanism
      python3 oauth2_scope_falsify.py normalisation
      python3 oauth2_scope_falsify.py reachability
      python3 oauth2_scope_falsify.py vertical
      python3 oauth2_scope_falsify.py comparison
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f

POLICY = f.REPO / "crates/policy/src/lib.rs"
DOMAIN = f.REPO / "crates/domain/src/lib.rs"
BROKER = f.REPO / "crates/broker/src/lib.rs"
BINDING = f.REPO / "crates/broker/src/oauth2_binding.rs"

# The comparison the policy and the broker have to agree about. One line, and it
# was wrong in the direction that refuses valid grants rather than the direction
# that accepts invalid ones — so nothing about the *security* of the check
# changed when it was fixed, only whether a correct deployment worked at all.
# That asymmetry is why the row is worth a mutation: a check that can only fail
# closed is the kind nobody thinks to test.
COMPARISON = [
    (
        "compare the granted scope as text again",
        '''        if asv_domain::scope_set(&reported.scope)
            != asv_domain::scope_set(&self.deployment.registered_scope)
        {''',
        "        if reported.scope != self.deployment.registered_scope {",
        "a_grant_the_provider_spells_differently_is_the_same_grant_to_both_layers",
    ),
    (
        # The other direction the same line could break: normalise only one
        # side, which is not a subtle drift but the exact half-fix a future edit
        # would produce if someone "simplified" the deployment side away.
        "normalise only the side the provider sent",
        '''        if asv_domain::scope_set(&reported.scope)
            != asv_domain::scope_set(&self.deployment.registered_scope)
        {''',
        '''        if asv_domain::scope_set(&reported.scope) != self.deployment.registered_scope {''',
        "a_grant_the_provider_spells_differently_is_the_same_grant_to_both_layers",
    ),
    (
        # And the one that matters most: normalise *nothing* would be a
        # hardening, so the mutation worth filing is the opposite one — a check
        # that accepts a grant the operator never declared. Removing the
        # comparison entirely is what "make this less noisy" looks like when
        # somebody has just been shown a false refusal.
        "drop the scope comparison altogether",
        '''        if asv_domain::scope_set(&reported.scope)
            != asv_domain::scope_set(&self.deployment.registered_scope)
        {
            return Err(IdentityError::ScopeWider {
                expected: self.deployment.registered_scope.clone(),
                granted: reported.scope,
            });
        }''',
        "",
        "a_provider_granting_less_than_the_deployment_declares_is_refused",
    ),
]

# The Set declaration, the Set arm, and the constructor. Each of these is a
# different way the attribute can be *declared* and not *supplied*, or supplied
# with the wrong shape — and each fails closed, so each is invisible without a
# row that asserts the positive case.
SCHEMA_SHAPE = '''      "OAuth2Client": {
        "shape": {
          "type": "Record",
          "attributes": {
            "scope": {
              "type": "Set",
              "element": { "type": "String" }
            }
          }
        }
      }'''

SCHEMA_NO_SHAPE = '      "OAuth2Client": {}'

SCHEMA_WRONG_ELEMENT = '''      "OAuth2Client": {
        "shape": {
          "type": "Record",
          "attributes": {
            "scope": {
              "type": "Set",
              "element": { "type": "Long" }
            }
          }
        }
      }'''

# Re-derived from the file after `cargo fmt`, because a snippet written by hand
# and a snippet that no longer matches are the same thing: the harness reports
# "snippet not unique" and the mutation measures nothing. Three of the six
# mechanism mutations said exactly that on the first full run, which is the
# guard working and the reason this comment is here rather than the shorthand.
SET_ARM = '''        Resource::OAuth2Client { scope, .. } => {
            vec![(
                "scope",
                ResourceAttribute::Set(asv_domain::scope_set(scope)),
            )]
        }'''

MECHANISM = [
    (
        # The mistake `Api` already made once, repeated: declare the field and
        # supply nothing. With `scope` required by the schema the store refuses
        # the entity, so every OAuth2 identity call is denied — and a denial is
        # indistinguishable from a policy that said no.
        "declare the scope and supply no attribute at all",
        SET_ARM,
        "        Resource::OAuth2Client { .. } => Vec::new(),",
        "a_scope_condition_separates_a_read_only_client_from_a_read_write_one",
    ),
    (
        # The most plausible-looking wrong fix. A `String` satisfies the name
        # `scope` and builds fine; it fails at the schema, because the schema
        # says Set. If the schema were edited to say String instead, this would
        # compile, load, and deny every membership test forever — the exact
        # shape of the bug `3477a0b` was written to remove, one level down.
        "supply the scope as text instead of as a set",
        SET_ARM,
        '''        Resource::OAuth2Client { scope, .. } => {
            vec![("scope", ResourceAttribute::Text(scope.to_string()))]
        }''',
        "a_scope_condition_separates_a_read_only_client_from_a_read_write_one",
    ),
    (
        # Splitting is the whole model. Without it the "set" is one member
        # containing a space, and `resource.scope == ["read:pods"]` stops
        # matching a registration the operator declared as two tokens.
        #
        # **Filed against the row that owns it, after this mutation survived the
        # row it was first filed against.** The first target was
        # `a_scope_condition_separates_a_read_only_client_from_a_read_write_one`,
        # which asks only `contains` / `!contains` — and every one of its cases
        # has the same outcome whether the set is split or not: `"pods:read"` is
        # one member either way, and `"pods:read pods:delete"` contains neither
        # token either way. A row that cannot tell two implementations apart is a
        # row that measures nothing about this one, however many cases it has.
        # The row that *does* answer the question asserts the members themselves.
        "keep the whole scope string as a single set member",
        "ResourceAttribute::Set(asv_domain::scope_set(scope))",
        "ResourceAttribute::Set(vec![scope.to_string()])",
        "a_resource_entity_carries_exactly_what_its_schema_declares",
    ),
    (
        # The schema is the other half of the contract, and this is the pair
        # nothing else checks: an attribute the schema does not declare is
        # refused, and a declared attribute nothing supplies is also refused.
        "drop the shape so the attribute is undeclared",
        SCHEMA_SHAPE,
        SCHEMA_NO_SHAPE,
        "a_resource_entity_carries_exactly_what_its_schema_declares",
    ),
    (
        # Same name, wrong element type. The store checks types, so this is
        # refused rather than silently mismatched — which is the property worth
        # measuring, because "the Set of Strings" and "the Set of Longs" are
        # both a Set in the schema and only one of them is a scope.
        "declare the set's element as a number",
        SCHEMA_SHAPE,
        SCHEMA_WRONG_ELEMENT,
        "a_resource_entity_carries_exactly_what_its_schema_declares",
    ),
    (
        # `new_set` over `new_string` members. The other constructor for a
        # value that looks like a set is `new_string`, which is a valid Cedar
        # string that no `contains` will ever find anything in.
        "build the value as a string literal",
        '''                ResourceAttribute::Set(members) => RestrictedExpression::new_set(
                    members.into_iter().map(RestrictedExpression::new_string),
                ),''',
        '''                ResourceAttribute::Set(members) => RestrictedExpression::new_string(
                    members.join(" "),
                ),''',
        "a_scope_condition_separates_a_read_only_client_from_a_read_write_one",
    ),
]

# One definition of "what a scope list is". The issuer calls it, the policy
# calls it, and the two answering differently about a reordering is the failure
# — one end would call it an escalation and the other would call it clean.
NORMALISATION = [
    (
        # A reordering is not an escalation. The broker's comparison and the
        # policy's Set must agree, or a registration the operator wrote in a
        # different order than the IdP echoes it back is refused by one and
        # permitted by the other.
        "stop sorting the scope list",
        '''    let mut parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts.sort();
    parts.dedup();
    parts''',
        '''    let parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts''',
        "scope_order_and_repetition_are_one_grant_to_both_the_policy_and_the_issuer",
    ),
    (
        # `split(' ')` is the tempting one-character edit, and it is wrong twice:
        # an operator's YAML or JSON carries indentation, and a scope token that
        # is empty is a member that is present and matches nothing.
        "split on a single space instead of on whitespace",
        "scope.split_whitespace().map(str::to_string).collect()",
        "scope.split(' ').map(str::to_string).collect()",
        "scope_order_and_repetition_are_one_grant_to_both_the_policy_and_the_issuer",
    ),
    (
        # Duplicates are one grant. Without the dedup, a scope written twice is a
        # two-member set, and `resource.scope == ["read:pods"]` stops matching
        # the registration the operator actually declared.
        "stop removing duplicate scope tokens",
        '''    let mut parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts.sort();
    parts.dedup();
    parts''',
        '''    let mut parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts.sort();
    parts''',
        "scope_order_and_repetition_are_one_grant_to_both_the_policy_and_the_issuer",
    ),
]

# The wiring in the broker. Every policy-crate row stays green through all of
# these, which is exactly why they exist as mutations: they are the one-word
# edits that break the product while the engine keeps working.
REACHABILITY = [
    (
        # The most likely wrong edit in the whole change: both fields are
        # strings, the schema accepts a URL as readily as a scope token, and no
        # policy-crate row can tell. Every membership test then fails closed and
        # every real OAuth2 identity call is denied.
        "supply the audience where the scope belongs",
        "                scope: binding.deployment.registered_scope.clone(),",
        "                scope: binding.deployment.audience.clone(),",
        "a_rule_about_the_registered_scope_follows_the_registration_and_nothing_else",
    ),
    (
        # And the other direction: an empty scope satisfies no membership test
        # and no set equality, so every OAuth2 call is refused — again with
        # every policy-crate row green.
        "supply an empty scope",
        "                scope: binding.deployment.registered_scope.clone(),",
        "                scope: String::new(),",
        "a_rule_about_the_registered_scope_follows_the_registration_and_nothing_else",
    ),
    (
        # This one is the independence claim rather than a bug: the request must
        # not be able to influence the scope, so the value has to come off the
        # deployment. Substituting the entity name puts the *credential wire id*
        # in the scope, which is a string Cedar will happily accept as a
        # one-member set and no rule will ever ask for.
        #
        # **Re-filed, because its row stopped existing.** The first target was
        # `a_registration_whose_audience_mentions_the_scope...`, which measured
        # the substring property at the broker's level; a rewrite of the row
        # block dropped it, and the harness reported `no-run` rather than a
        # falsification. That is twice in one campaign that a mutation outlived
        # the row it was written against — the other being the unsplit-set
        # mutation, which survived because the row could not tell the two
        # implementations apart. The lesson is not about these two rows; it is
        # that a campaign's mutation list is coupled to its row list, and a row
        # block rewritten for clarity silently un-measures whatever pointed at
        # it. The property the dropped row carried — that membership is equality
        # on whole tokens — is still measured, by
        # `the_oauth2_scope_is_the_registration_s_and_a_rule_cannot_reach_anything_else`.
        "supply the credential id as the scope",
        "                scope: binding.deployment.registered_scope.clone(),",
        "                scope: credential.to_wire().to_string(),",
        "a_scope_rule_can_require_a_client_to_carry_exactly_one_grant",
    ),
]

# The same defect as the third mechanism mutation, measured one level up. The
# harness mutates one file and runs one target, and nothing requires them to be
# the same crate — so this changes the *policy* crate's Set arm while the row
# under test is the broker's own end-to-end vertical. That is the direction the
# other two mechanism mutations cannot reach: a defect in the engine that the
# engine's own rows all agree with, caught by the row that runs the product.
VERTICAL = [
    (
        "keep the whole scope string as a single set member, seen from the broker",
        "ResourceAttribute::Set(asv_domain::scope_set(scope))",
        "ResourceAttribute::Set(vec![scope.to_string()])",
        "a_scope_rule_can_require_a_client_to_carry_exactly_one_grant",
    ),
    (
        # Same level, opposite end: the repeated-token case in that row is the
        # one that says a repeated scope is one grant, so it is the row that
        # fails if the normalisation ever stops deduplicating.
        #
        # **SURVIVOR, and it is a result rather than a gap — kept deliberately.**
        # Cedar's `Set` collapses duplicate members, so an unsplit,
        # undeduplicated `"read:pods  read:pods"` reaches the evaluator as
        # `{read:pods}` and `== ["read:pods"]` holds. The dedup inside
        # `scope_set` is therefore **unobservable through the policy**: no rule
        # and no row can tell the two implementations apart, and one that claimed
        # to would be claiming a property Cedar's type provides on its own.
        #
        # The dedup is not decoration, it is just load-bearing somewhere else:
        # the *issuer* compares the requested scope against the granted one as
        # sets before a token exists, and there a duplicate really would read as
        # a narrowing — `read read` requested, `read` granted, same grant — so
        # that comparison's rows (`the_issuer_refuses_a_widened_grant_before_any_
        # token_exists` and its neighbours) are where this property is measured.
        # Deleting this mutation would hide that the two layers are protected by
        # different mechanisms, which is the thing worth knowing.
        "treat a repeated scope token as two grants, seen from the broker",
        "ResourceAttribute::Set(asv_domain::scope_set(scope))",
        '''ResourceAttribute::Set(
                scope.split_whitespace().map(str::to_string).collect(),
            )''',
        "a_scope_rule_can_require_a_client_to_carry_exactly_one_grant",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "mechanism"
    f.PACKAGE = "asv-policy"
    f.TEST_PREFIX = "tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = POLICY
    mutations = MECHANISM
    if mode == "normalisation":
        # The mutation is in `asv-domain`; the row that measures it lives in
        # `asv-policy`, because the assertion is about the two agreeing rather
        # than about the function on its own. The first version of this mode
        # pointed the target at `asv-domain` and the harness reported `no-run`
        # three times — which is the outcome it exists to produce, and the
        # reason a campaign that reports "0 survivors" without a
        # "measured nothing" column is not a campaign.
        f.TEST_PREFIX = "tests::"
        f.STS = DOMAIN
        mutations = NORMALISATION
    elif mode == "reachability":
        f.PACKAGE = "asv-broker"
        f.TEST_PREFIX = ""
        f.CARGO_TARGET = "--test r2b2_oauth2_vertical"
        f.STS = BROKER
        mutations = REACHABILITY
    elif mode == "comparison":
        f.PACKAGE = "asv-broker"
        f.TEST_PREFIX = ""
        f.CARGO_TARGET = "--test r2b2_oauth2_vertical"
        f.STS = BINDING
        mutations = COMPARISON
    elif mode == "vertical":
        f.PACKAGE = "asv-broker"
        f.TEST_PREFIX = ""
        f.CARGO_TARGET = "--test r2b2_oauth2_vertical"
        f.STS = POLICY
        mutations = VERTICAL
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
