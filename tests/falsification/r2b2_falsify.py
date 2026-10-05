#!/usr/bin/env python3
"""Falsification for R2.B.2's product-surface rows.

Same four-bucket accounting as the other harnesses. These rows are about the
broker's decision about a *derived* identity, so the mutations that matter are
the ones that would let a request act as a registered OAuth2 client without the
operator having said yes -- or that would let the answer through without being
checked against what the operator declared.

Four passes, one per file, because a campaign that mutates one file cannot see a
row whose evidence lives in another. `policy` in particular is the pass that
matters most: it is the one that would show whether the allowlist was quietly
widened to make this work.

Run:  python3 r2b2_falsify.py broker
      python3 r2b2_falsify.py binding
      python3 r2b2_falsify.py policy
      python3 r2b2_falsify.py independence
      python3 r2b2_falsify.py selfreport
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

LIB = f.REPO / "crates/broker/src/lib.rs"
BINDING = f.REPO / "crates/broker/src/oauth2_binding.rs"
POLICY = f.REPO / "crates/policy/src/lib.rs"
SELFREPORT_FILE = f.REPO / "crates/broker/src/selfreport.rs"

# The policy decision is the control, so removing it is the mutation that
# matters most: it is the difference between "an operator permitted this client"
# and "the code path exists".
BROKER = [
    (
        "ask no policy before acting as a registered client",
        "        self.authorize_verb(\n"
        "            session,\n"
        "            peer,\n"
        "            Action::OAuth2Identity,\n"
        "            Resource::OAuth2Client {\n"
        '                credential: credential.to_wire(),\n'
        "                audience: binding.deployment.audience.clone(),\n"
        "            },\n"
        "        )?;",
        "        let _ = (session, peer, &binding.deployment.audience);",
        "a_stock_policy_refuses_the_operation_before_any_socket",
    ),
    (
        # The reachability of a registration nobody configured. The message this
        # replaces names exactly what an operator needs to see, so a fallback is
        # not a convenience -- it is a grant nobody made.
        "use the first configured client when the request names none",
        "        match self\n"
        "            .oauth2\n"
        "            .iter()\n"
        "            .find(|binding| binding.deployment.serves(credential))\n"
        "        {\n"
        "            Some(binding) => Ok(binding),\n"
        "            None => {",
        "        match self\n"
        "            .oauth2\n"
        "            .iter()\n"
        "            .find(|binding| binding.deployment.serves(credential))\n"
        "        {\n"
        "            Some(binding) => Ok(binding),\n"
        "            None if !self.oauth2.is_empty() => Ok(&self.oauth2[0]),\n"
        "            None => {",
        "a_credential_no_registration_names_is_refused_before_any_socket",
    ),
    (
        # `authorize_github` and `authorize_aws` open with the same two guards,
        # so the snippet is anchored on the line only `authorize_oauth2` has.
        # Without that the harness counts two matches and measures nothing --
        # which is what "not unique" means here, and why it is a skip and not a
        # pass.
        "act without asking whether the session belongs to this peer",
        "        if !self.session_owned_by(session, peer)? {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "session is not owned by the authenticated peer".into(),\n'
        "            }));\n"
        "        }\n"
        "        if self.secrets.is_none() {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.oauth2_binding(credential)?;",
        "        if false {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "session is not owned by the authenticated peer".into(),\n'
        "            }));\n"
        "        }\n"
        "        if false {\n"
        "            return Err(Box::new(Response::Error {\n"
        "                code: ErrorCode::Denied,\n"
        '                message: "no credential store is open, so no brokered operation can run".into(),\n'
        "            }));\n"
        "        }\n"
        "        let binding = self.oauth2_binding(credential)?;",
        "a_session_this_peer_does_not_own_is_refused_before_any_socket",
    ),
    (
        # The wire id is parsed before the authorization so that "you called me
        # wrong" stays distinguishable from "not granted". Collapsing the parse
        # into the lookup makes a typo look like a denial, which is the specific
        # confusion the two error codes exist to prevent.
        "answer a malformed id as though it were not granted",
        "            let credential = match CredentialId::from_wire(&credential) {\n"
        "                Ok(id) => id,\n"
        "                Err(_) => {\n"
        "                    return Response::Error {\n"
        '                        code: ErrorCode::InvalidRequest,\n'
        '                        message: "the credential is not a vault id".into(),\n'
        "                    }\n"
        "                }\n"
        "            };\n"
        "            let binding = match state.authorize_oauth2(session, peer, &credential) {",
        "            let credential = CredentialId::from_wire(&credential)\n"
        "                .unwrap_or_else(|_| CredentialId::new());\n"
        "            let binding = match state.authorize_oauth2(session, peer, &credential) {",
        "a_malformed_credential_is_invalid_request_not_denied",
    ),
    (
        # A scope disagreement reported as a plain provider failure. The code is
        # right either way, but the *message* is the operator's only route to
        # the fact that their IdP registration has drifted, so losing the
        # specific wording loses the actionable part.
        "report a scope disagreement without naming either string",
        '                Err(crate::oauth2_binding::IdentityError::ScopeWider { expected, granted }) => {\n'
        "                    Response::Error {\n"
        "                        code: ErrorCode::Upstream,\n"
        "                        message: format!(\n"
        '                            "the OAuth2 provider granted scope {granted:?} but the deployment \\\n'
        "                             declares {expected:?}; the operator's configuration no longer \\\n"
        '                             describes this credential\'s authority"\n'
        "                        ),\n"
        "                    }\n"
        "                }",
        "                Err(crate::oauth2_binding::IdentityError::ScopeWider { .. }) => {\n"
        "                    Response::Error {\n"
        "                        code: ErrorCode::Upstream,\n"
        '                        message: "the OAuth2 provider refused the call".into(),\n'
        "                    }\n"
        "                }",
        "the_broker_refuses_a_widened_grant_that_reaches_it",
    ),
]


# The binding is the operator's declaration, and the comparison at the end of
# `identity` is the thing that makes the answer verified rather than relayed.
# Both halves of that are here: a sloppy match, and a comparison that stopped
# comparing.
BINDING_MUTATIONS = [
    (
        "treat any credential as the configured one",
        "        &self.credential == credential",
        "        let _ = credential;\n        true",
        "a_credential_no_registration_names_is_refused_before_any_socket",
    ),
    (
        # **The control the whole block is for.** Relaying whatever the provider
        # granted is the failure: the operator's configuration would stop
        # describing the authority in play, and nothing downstream would notice
        # because the answer would look exactly like a correct one.
        "relay the granted scope instead of comparing it",
        "        if reported.scope != self.deployment.expected_scope {\n"
        "            return Err(IdentityError::ScopeWider {\n"
        "                expected: self.deployment.expected_scope.clone(),\n"
        "                granted: reported.scope,\n"
        "            });\n"
        "        }",
        "        if reported.scope == \"\\u{0}\" {\n"
        "            return Err(IdentityError::Malformed(\"no scope\".into()));\n"
        "        }",
        "the_broker_refuses_a_widened_grant_that_reaches_it",
    ),
    (
        # Same comparison, other side. A grant *narrower* than configured is the
        # safe direction for confidentiality and the wrong one for an operator
        # who wrote a policy on the assumption the broker holds what it declared.
        "relay the audience instead of comparing it",
        "        if reported.audience != self.deployment.audience {\n"
        "            return Err(IdentityError::AudienceMismatch {\n"
        "                expected: self.deployment.audience.clone(),\n"
        "                reported: reported.audience,\n"
        "            });\n"
        "        }",
        "        if reported.audience == \"\\u{0}\" {\n"
        "            return Err(IdentityError::Malformed(\"no audience\".into()));\n"
        "        }",
        "a_deployment_pointing_at_another_audience_is_refused",
    ),
    (
        # A token that is not a bearer token cannot be presented. Substituting
        # U+FFFD would send a header the resource never minted, turning a
        # refusal into a confusing 401 -- the row measures that the strict path
        # is the one taken.
        "present a token that is not valid utf-8",
        "        let token = std::str::from_utf8(token.expose())\n"
        "            .map_err(|_| IdentityError::Port(\n"
        '                "the OAuth2 port returned a token that is not valid UTF-8".into(),\n'
        "            ))?\n"
        "            .to_string();",
        "        let token = String::from_utf8_lossy(token.expose()).to_string();",
        "a_token_that_is_not_a_bearer_token_is_refused_rather_than_substituted",
    ),
    (
        # The request path. A resource that answers 404 is not a resource that
        # granted anything, and reporting it as an identity would be reporting
        # authority nobody issued.
        "treat a non-2xx resource answer as an identity",
        "        if !status.is_success() {\n",
        "        if false {\n",
        "a_resource_answered_with_a_refusal_is_reported_as_one",
    ),
]


# **The pass that measures the allowlist, aimed at the rows where its harm lands.**
#
# The first version of this pass pointed the widening mutations at OAuth2 rows,
# and all three survived. That was a defect in the *campaign*, not a finding about
# the code: the harm of widening `ALLOWED_AUDIENCES` falls on GitHub and AWS,
# which share the `Api` resource type, so an OAuth2 row cannot possibly go red
# however far the list is stretched. A campaign that reports three survivors
# without asking *why* would have looked like a finding and been an artefact of
# where the arrow was aimed.
#
# So the two dangerous mutations target the policy crate's own row, which is the
# one that actually asserts an unapproved audience is denied. Package and target
# are switched per mode in `main` for the same reason.
POLICY_MUTATIONS = [
    (
        "let a policy name any host as an Api audience",
        'pub(crate) const ALLOWED_AUDIENCES: &[&str] = &["api.github.com", "sts.amazonaws.com"];',
        'pub(crate) const ALLOWED_AUDIENCES: &[&str] = &[\n'
        '    "api.github.com",\n'
        '    "sts.amazonaws.com",\n'
        '    "idp.example.com",\n'
        '    "evil.example",\n'
        "] ;".replace("] ;", "];"),
        "unapproved_audience_is_denied_even_though_it_canonicalizes",
    ),
    (
        # The other way to widen it: stop checking. Silent, and the reason D6
        # exists, so it gets its own mutation.
        "approve every audience",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            if !audience_is_approved(audience) {\n"
        "                return Ok(false);\n"
        "            }\n"
        "        }",
        "        if let Resource::Api { audience } = &request.resource {\n"
        "            let _ = audience_is_approved(audience);\n"
        "        }",
        "unapproved_audience_is_denied_even_though_it_canonicalizes",
    ),
]


# **The measurement that the OAuth2 surface does not depend on the allowlist at
# all -- and this one is expected to SURVIVE, which is the whole point.**
#
# `Resource::OAuth2Client` is a separate type that never reaches
# `audience_is_approved`, so stretching the list cannot make an OAuth2 request
# work and cannot break one either. A survivor here is the *correct* answer, and
# it is the load-bearing measurement of R2.B.2's central design decision: the
# generic-IdP surface was made reachable by giving it its own resource type
# rather than by widening a list that GitHub and AWS depend on.
#
# The first version of this campaign filed the same mutation under the heading
# "would catch the mistake this block was most likely to make", implying it
# should go red. It does not, and treating that as a defect to fix would have
# meant either mutating the code until the arrow landed or deleting a mutation
# that documents the design. The honest record is a survivor with a reason.
INDEPENDENCE_MUTATIONS = [
    (
        "widen the allowlist and nothing else",
        'pub(crate) const ALLOWED_AUDIENCES: &[&str] = &["api.github.com", "sts.amazonaws.com"];',
        'pub(crate) const ALLOWED_AUDIENCES: &[&str] =\n'
        '    &["api.github.com", "sts.amazonaws.com", "idp.example.com"];',
        "an_agent_names_the_operation_and_gets_the_resource_own_answer",
    ),
]


# The advertisement is a promise to an agent, so the mutations that matter are
# the ones that break it: an operation nobody is told about, and a name that
# tells them it returns something.
SELFREPORT_MUTATIONS = [
    (
        "build the operation and never announce it",
        '        "oauth2.identity".to_string(),\n',
        "",
        "the_advertised_capability_is_the_one_this_file_calls",
    ),
    (
        # Named after the HTTP method rather than after what the caller gets.
        # `selfreport::no_advertised_capability_names_a_retrieval` refuses this
        # spelling as a substring match; this row is the same rule at the
        # surface, and it is here so the substring check is not the only thing
        # standing between the two.
        "announce it under a name that reads like a retrieval",
        '        "oauth2.identity".to_string(),\n',
        '        "oauth2.get_identity".to_string(),\n',
        "the_advertised_capability_is_the_one_this_file_calls",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "broker"
    f.TEST_PREFIX = ""
    f.CARGO_TARGET = "--test r2b2_oauth2_vertical"
    if mode == "selfreport":
        f.STS = SELFREPORT_FILE
        mutations = SELFREPORT_MUTATIONS
    elif mode == "binding":
        f.STS = BINDING
        mutations = BINDING_MUTATIONS
    elif mode == "policy":
        # The policy crate's own rows, in its own lib tests: this is where an
        # unapproved audience is actually asserted to be denied.
        f.STS = POLICY
        f.PACKAGE = "asv-policy"
        f.CARGO_TARGET = "--lib"
        # `--exact` needs the module path, and the first run of this pass
        # reported `no-run` for both mutations because it passed the bare name.
        # `no-run` is the honest bucket -- nothing was measured -- but the cause
        # was the harness's own addressing, not the code, and saying so is the
        # difference between a campaign that finds things and one that reports
        # its own typos as findings.
        f.TEST_PREFIX = "tests::"
        mutations = POLICY_MUTATIONS
    elif mode == "independence":
        f.STS = POLICY
        f.CARGO_TARGET = "--test r2b2_oauth2_vertical"
        mutations = INDEPENDENCE_MUTATIONS
    else:
        f.STS = LIB
        mutations = BROKER
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
