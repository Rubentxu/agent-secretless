#!/usr/bin/env python3
"""Falsification for the Cedar resource-attribute mechanism.

The change is small and the risk is asymmetric, so the mutations are aimed at
the two directions it could go wrong in:

* **fidelity** -- the attribute is supplied but the documented rule still does
  not match, which is the defect this exists to remove;
* **reachability** -- supplying the attribute lets a policy reach a host D6
  never approved, which would be a new exposure created by a fix.

The second is the one that matters most. A fidelity fix that widened the
reachable set would be a far worse outcome than the bug it fixed, so there is a
mutation for each way the allowlist check could be bypassed.

Run:  python3 policy_attrs_falsify.py attributes
      python3 policy_attrs_falsify.py allowlist
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

POLICY = f.REPO / "crates/policy/src/lib.rs"

# Everything about *supplying* the attribute. The first mutation is the exact bug
# this change was born from -- it is in this file because the version of it that
# was written without knowing Cedar's API would have shipped.
ATTRIBUTES = [
    (
        # `from_str` parses a Cedar *expression*. `api.github.com` becomes a
        # path reference to a non-existent entity, and every Api authorization
        # fails closed with `invalid member access`. This is the real bug, and
        # it is invisible without this row because the decision is still a
        # denial -- a quiet one.
        "parse the attribute value as a cedar expression",
        "            let value = match value {\n"
        "                ResourceAttribute::Text(text) => RestrictedExpression::new_string(text),\n"
        "                ResourceAttribute::Set(members) => RestrictedExpression::new_set(\n"
        "                    members.into_iter().map(RestrictedExpression::new_string),\n"
        "                ),\n"
        "            };\n"
        "            resource_attrs.insert(name.to_string(), value);",
        "            let value = match value {\n"
        "                ResourceAttribute::Text(text) => RestrictedExpression::from_str(&text).expect(\"a literal\"),\n"
        "                ResourceAttribute::Set(members) => RestrictedExpression::new_set(\n"
        "                    members.into_iter().map(RestrictedExpression::new_string),\n"
        "                ),\n"
        "            };\n"
        "            resource_attrs.insert(name.to_string(), value);",
        "the_documented_audience_rule_now_matches_and_only_its_own_audience",
    ),
    (
        # The mechanism itself. `Entities::empty()` is what the original code
        # passed, and it is the reason every attribute was unreachable: Cedar
        # resolves a resource's attributes from the store handed to
        # `is_authorized`, not from the `Request`.
        "hand the authorizer an empty entity store again",
        "            .is_authorized(&request, &self.policies, &entities)",
        "            .is_authorized(&request, &self.policies, &Entities::empty())",
        "the_documented_audience_rule_now_matches_and_only_its_own_audience",
    ),
    (
        # The value the rule compares against. Supplying the right attribute
        # with the wrong value is indistinguishable from no attribute at all
        # from the policy's point of view, and it is the mutation that looks
        # most like a working fix.
        "supply the audience but blank it",
        '        Resource::Api { audience } => {\n'
        '            vec![("audience", ResourceAttribute::Text(audience.to_string()))]\n'
        '        }',
        '        Resource::Api { .. } => {\n'
        '            vec![("audience", ResourceAttribute::Text(String::new()))]\n'
        '        }',
        "the_documented_audience_rule_now_matches_and_only_its_own_audience",
    ),
    (
        # Supplying nothing, i.e. reverting to the declared-but-absent field.
        "supply no attribute at all",
        '        Resource::Api { audience } => {\n'
        '            vec![("audience", ResourceAttribute::Text(audience.to_string()))]\n'
        '        }',
        "        Resource::Api { .. } => Vec::new(),",
        "a_resource_entity_carries_exactly_what_its_schema_declares",
    ),
    (
        # Passing `None` skips the schema check, so an attribute the schema
        # never declared would be accepted, and no policy can reference such an
        # attribute -- so nothing would look wrong while the mechanism quietly
        # stopped working.
        # Filed against the doctored-schema row, not the direct-Cedar one. The
        # direct row calls `Entities::from_entities` itself, so it proves Cedar
        # refuses an undeclared attribute while saying nothing about whether the
        # *production* path passes the schema -- and a correctly-named attribute
        # is accepted with or without it, so nothing else could tell. The
        # doctored schema makes the difference observable: the production path
        # then supplies an attribute that schema does not declare.
        "build the entity store without the schema",
        "            Entities::from_entities(vec![entity], Some(&self.schema))",
        "            Entities::from_entities(vec![entity], None)",
        "a_schema_that_does_not_declare_the_supplied_attribute_is_refused",
    ),
]


# The direction that must NOT change. Every mutation here is a way the new
# attribute could be used to widen what a policy reaches, and each is filed
# against the row that measures it.
ALLOWLIST = [
    (
        # The check itself. `Api` resources with an unapproved audience must
        # still be refused in Rust, before Cedar, whatever the policy says and
        # whatever the attribute contains.
        "approve an unapproved audience because the rule matched",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            if !audience_is_approved(audience) {\n"
        "                return Ok(false);\n"
        "            }\n"
        "        }",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            let _ = audience_is_approved(audience);\n"
        "        }",
        "audience_attributes_do_not_widen_the_reachable_set",
    ),
    (
        # The subtler version: keep the check but let the *policy* decide. Cedar
        # would then evaluate `resource.audience == "evil.example"` for a host
        # that only got this far because the Rust gate was relaxed, and a policy
        # that says "any Api" would allow it. This is the direction a future
        # edit would plausibly take while trying to make a rule more flexible.
        "let the policy answer the approval question instead of rust",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            if !audience_is_approved(audience) {\n"
        "                return Ok(false);\n"
        "            }\n"
        "        }",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            if audience.as_str() == \"idp.example.com\" {\n"
        "                return Ok(false);\n"
        "            }\n"
        "        }",
        "audience_attributes_do_not_widen_the_reachable_set",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "attributes"
    f.TEST_PREFIX = "tests::"
    f.PACKAGE = "asv-policy"
    f.CARGO_TARGET = "--lib"
    f.STS = POLICY
    if mode == "allowlist":
        mutations = ALLOWLIST
    else:
        mutations = ATTRIBUTES
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
