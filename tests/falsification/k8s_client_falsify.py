#!/usr/bin/env python3
"""Falsification for R2.D.3.1, the transport that opens the socket.

Same four-bucket accounting as the other harnesses, and the same `no-run`
outcome, because a row that never executed is indistinguishable from a row that
passed unless the harness is built so it cannot say otherwise.

**Not every row in this module is falsifiable, and the six that are not are
counted as such rather than quietly folded into the total.**

The client has seventeen rows. This campaign files eleven mutations. The other
six are unreachable by a single-site edit, in three distinct groups, and saying
"not covered" without saying *which kind* of not-covered is the same
overstatement in a different font.

**Two are positive.** `a_get_reaches_the_origin_with_the_bearer_header_assembled_from_the_port`
and `a_client_that_never_sent_anything_would_fail_this`. They catch the client
being useless rather than leaky, and a client that never sends anything is not
one edit away — it needs the send removed *and* the returns reworked.

**Two are structural**, asserting a property this file does not implement.
`a_client_is_refused_when_the_audience_is_a_private_address` and
`a_client_is_refused_when_the_port_is_zero` re-assert `PinnedClient`'s own
refusals. They are kept because a client that assembled its own transport
instead of borrowing the pinned one would silently lose both and they would
catch that — but no edit *here* can undo them, because `assemble` has exactly
one call into the transport and it is the one that checks. Falsifying them
belongs to `transport.rs`, which already has the rows.

**Two need a compound edit.** `a_lend_error_means_no_header_and_no_request` and
`no_refusal_this_client_produces_contains_the_token` are both real rows that
this campaign cannot reach with one edit, and the reasons are worth the space.

The first has *two* defences between a failed `lend` and a socket — the `?` on
the call, and the sink's own refusal to hand over a header it was never fed.
The campaign's first pass filed the mutation that removes the `?` against this
row and reported a survivor, which was the right measurement and the wrong
conclusion: removing one of two defences does not break the property, it
degrades the *diagnosis*. That is a real defect, and
`a_lend_refusal_names_the_cause_rather_than_the_consequence` is the row that
catches it, added because the campaign found the gap rather than because
someone thought of it up front. This row itself is now only breakable by
removing both defences at once.

The second is a correction of a misfiling, and it is recorded rather than
quietly dropped. The mutation filed against it put the *response body* into the
oversized-body refusal, on the theory that it would repeat the token. It does
not: the token is in the request header and never in the response. The row
stayed green because the mutation did not do what its label claimed. Reaching
this row needs a mutation that *adds* a format site for the token somewhere —
a plausible future guard such as "token longer than 4 KiB" whose message
includes the value — and a row that exercises it. Two sites, so it is filed as
compound rather than as a green row.

**The redirect mutation is first because it is the one that matters.** A
Kubernetes bearer token has no transform: `Authorization: Bearer <token>` *is*
the credential, so unlike an AWS signature — which can be held, replayed
against the same host, and logged without consequence — the header must never
reach a second origin. Every other provider in this workspace signs; this one
presents, and presenting is the harder case.

One more is worth naming. The mutation that turns a `403` into a client error
looks like a small tidiness change and is not one: authorization is a policy
decision made above this layer, and collapsing a refusal status into an error
destroys the status an audit record needs. The row exists so that distinction
has something holding it.

Run:  python3 k8s_client_falsify.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sts_falsify as f  # noqa: E402

CLIENT = f.REPO / "crates/broker/src/k8s/client.rs"

MUTATIONS = [
    # ---- the row that decides whether this file is a control ---------------
    (
        # Follow the redirect wherever it points. The victim origin in the row
        # is a real TLS server on a different host, so this mutation does not
        # merely change an error into a success: it delivers the ServiceAccount
        # token to an origin that was never lent it.
        "follow a redirect to another origin",
        "                    return Ok(Redirect::Hop(next));",
        "                    return Ok(Redirect::Done(K8sReply {\n"
        "                        status,\n"
        "                        body: format!(\"followed to {next}\").into_bytes(),\n"
        "                    }));",
        "a_redirect_to_another_origin_is_refused_and_the_token_never_reaches_it",
    ),
    # ---- the re-lend -------------------------------------------------------
    (
        # Answer the first hop instead of following it. A client that stops at
        # the first response would pass the cross-origin row for the wrong
        # reason, so the same-origin row is what pins that redirects still work.
        "answer the first response instead of following a same-origin hop",
        "                    return Ok(Redirect::Hop(next));",
        "                    return Ok(Redirect::Done(K8sReply {\n"
        "                        status,\n"
        "                        body: Vec::new(),\n"
        "                    }));",
        "a_same_origin_redirect_is_followed_and_the_token_is_lent_again_for_it",
    ),
    # ---- the sink ----------------------------------------------------------
    (
        # Copy rather than take. This is the mutation that matters most quietly:
        # the type still hands out a header, `accept` still refuses nothing, and
        # the credential is now reusable for as many destinations as a caller
        # can reach -- which is the one thing `take` exists to prevent.
        "copy the header out instead of taking it",
        "        self.header\n            .take()\n            .ok_or_else(|| SecretError::Unavailable(\"the port lent nothing to sign\".into()))",
        "        if self.header.is_none() {\n"
        "            return Err(SecretError::Unavailable(\"the port lent nothing to sign\".into()));\n"
        "        }\n"
        "        Ok(Zeroizing::new(self.header.as_ref().expect(\"checked\").to_vec()))",
        "the_bearer_sink_hands_the_header_over_exactly_once",
    ),
    (
        # An empty header rather than no header. `Authorization: ` with nothing
        # after it is a request the API server will answer 401, and an operator
        # reading the audit record sees a credential that was tried rather than
        # a port that was never asked.
        "hand over an empty header when the port lent nothing",
        "        self.header\n            .take()\n            .ok_or_else(|| SecretError::Unavailable(\"the port lent nothing to sign\".into()))",
        "        Ok(self\n"
        "            .header\n"
        "            .take()\n"
        "            .unwrap_or_else(|| Zeroizing::new(b\"Bearer\".to_vec())))",
        "a_sink_that_was_never_fed_refuses_to_hand_anything_over",
    ),
    # ---- the refusal before the socket -------------------------------------
    (
        # Swallow the `?`. This was first filed against
        # `a_lend_error_means_no_header_and_no_request` and came back a
        # survivor, which was the measurement working and the filing wrong: the
        # sink's own refusal to hand over an unfed header still holds, so no
        # request is sent either way. What the mutation really does is replace
        # the port's reason with a generic one — "the token file could not be
        # read" becomes "the port lent nothing to sign", which is true and
        # useless. That degradation is a real defect, and it is a defect of the
        # *diagnosis*, so it is filed against the row that names it.
        "swallow the reason the port refused to lend",
        "            port.lend(credential, &mut sink)?;",
        "            let _ = port.lend(credential, &mut sink);",
        "a_lend_refusal_names_the_cause_rather_than_the_consequence",
    ),
    # ---- the cap -----------------------------------------------------------
    (
        "buffer a body larger than the cap",
        "        if into.len() + read > MAX_REPLY_BYTES {",
        "        if false {",
        "a_body_past_the_cap_is_refused_rather_than_truncated",
    ),
    (
        # The other side of the previous row. Filed separately on purpose: a
        # cap that refused its own boundary would make the refusal above pass
        # for entirely the wrong reason, and one row cannot tell those apart.
        "refuse a body sitting exactly on the cap",
        "        if into.len() + read > MAX_REPLY_BYTES {",
        "        if into.len() + read >= MAX_REPLY_BYTES {",
        "a_body_exactly_at_the_cap_is_still_read",
    ),
    # ---- a refusal status is not a client error ---------------------------
    (
        # A tidiness change that is not one. Authorization is a policy decision
        # made above this layer; collapsing a 403 into an error destroys the
        # status the audit record needs to say what the API server decided.
        "turn a refusal status into a client error",
        "            let status = response.status().as_u16();",
        "            let status = response.status().as_u16();\n"
        "            if !(200..300).contains(&status) {\n"
        "                return Err(TransportError::RequestFailed {\n"
        "                    audience: self.audience.authority.to_string(),\n"
        "                    reason: format!(\"the API server answered {status}\"),\n"
        "                }\n"
        "                .into());\n"
        "            }",
        "a_forbidden_status_is_reported_as_a_reply_carrying_the_status",
    ),
    # ---- the pinned duplication -------------------------------------------
    (
        # `Verb::method` and `method_for` are duplicated on purpose, because
        # re-parsing a &'static str would put a panic on the path where a panic
        # drops a token mid-flight. This mutation is what would make that
        # duplication dangerous rather than merely redundant.
        "send a get as a post",
        "        super::request::Verb::Get | super::request::Verb::List => reqwest::Method::GET,",
        "        super::request::Verb::Get | super::request::Verb::List => reqwest::Method::POST,",
        "the_method_this_client_sends_is_the_method_the_request_core_names",
    ),
    # ---- the request core's refusals are not routeable around --------------
    (
        # `Get` without a name is a list wearing a get's clothes, and the
        # refusal belongs to `request`. Defaulting the path instead of asking
        # is exactly the bypass this row exists to catch: it compiles, it
        # compiles *quietly*, and the agent would get a collection when it
        # named an object.
        "route around the request core's refusals",
        "        let path = request.path()?;",
        "        let path = request.path().unwrap_or_else(|_| \"/\".to_string());",
        "the_verbs_the_request_core_refuses_are_not_made_sendable_here",
    ),
    # ---- the re-exported bound --------------------------------------------
    (
        "re-export a token bound that is not the port's",
        "pub const TOKEN_LIMIT: usize = MAX_TOKEN_BYTES;",
        "pub const TOKEN_LIMIT: usize = MAX_TOKEN_BYTES + 1;",
        "the_token_bound_this_module_re_exports_is_the_ports_own",
    ),
]


def main() -> int:
    f.TEST_PREFIX = "k8s::client::tests::"
    f.CARGO_TARGET = "--lib"
    f.STS = CLIENT
    f.MUTATIONS[:] = MUTATIONS
    original = CLIENT.read_text()
    print(f"# falsifying {f.STS.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    code = f.main()
    assert CLIENT.read_text() == original, "the file was not restored"
    return code


if __name__ == "__main__":
    sys.exit(main())
