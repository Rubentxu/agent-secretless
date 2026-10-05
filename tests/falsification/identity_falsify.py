#!/usr/bin/env python3
"""Falsification for R2.C.3 — the `GetCallerIdentity` operation.

Two lists, because two targets hold the rows. The unit rows live in the crate's
own test target and cover *what a document may say*; the socket rows live in
`r2c2b_sts_vertical.rs` and cover the one property no document can: that the
session token is inside the signature and on the wire at the same time.

Run:  python3 identity_falsify.py lib
      python3 identity_falsify.py e2e
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

IDENTITY = f.REPO / "crates/broker/src/aws/identity.rs"

# (label, old, new, test that must go red) — measured against `--lib`.
UNIT = [
    (
        "read a different field than the caller asked for",
        'let arn = sts::text_field(text, "Arn")?;',
        'let arn = sts::text_field(text, "Account")?;',
        "the_documented_session_sample_yields_the_identity_aws_prints",
    ),
    (
        "accept an ARN outside the lengths AWS documents",
        "    if !(MIN_ARN_LEN..=MAX_ARN_LEN).contains(&arn.chars().count()) {",
        "    if false {",
        "an_arn_outside_the_documented_lengths_is_refused",
    ),
    (
        "read an ErrorResponse as if it were an identity",
        "    if let Some((code, message)) = sts::read_error_response(text)? {\n"
        "        return Err(StsError::Provider { code, message });\n    }",
        "    if false {\n        return Err(StsError::Provider { code: String::new(), message: String::new() });\n    }",
        "a_provider_refusal_is_named_rather_than_read_as_an_identity",
    ),
    (
        "read a document that declares a DTD",
        '    if text.contains("<!DOCTYPE") {',
        "    if false {",
        "a_document_declaring_a_dtd_is_refused_before_it_is_read",
    ),
    (
        "read a body that is not UTF-8",
        '    let text = std::str::from_utf8(body)\n'
        '        .map_err(|_| StsError::UnrecognisedDocument("the body is not UTF-8".into()))?;',
        '    let text = std::str::from_utf8(body).unwrap_or("");',
        "a_body_that_is_not_utf8_is_refused_before_it_is_parsed",
    ),
    (
        "parse an oversized document instead of refusing it unread",
        "    if body.len() > MAX_RESPONSE_BYTES {",
        "    if false {",
        "a_response_larger_than_the_bound_is_refused_unread",
    ),
]

# `text_field` lives in `sts.rs`, so these mutate that file. The rows that catch
# them are the caller-identity ones -- which is the point: the shared reader
# grew a rule for another operation's benefit, and a rule nobody exercises is a
# rule nobody should add.
READER = [
    (
        "name a missing field as a credential field again",
        "    let raw = element(text, name).map_err(named)?;",
        "    let raw = element(text, name)?;",
        "a_missing_field_is_named",
    ),
    (
        "read an empty field as an empty string",
        "    if decoded.is_empty() {\n        return Err(StsError::Missing(name));\n    }",
        "",
        "an_empty_field_is_missing_rather_than_empty",
    ),
    (
        "hold a non-credential field to the credential whitespace rule",
        "    let decoded = decode_predefined(raw, name).map_err(named)?;",
        "    let decoded = decode_predefined(raw, name).map_err(named)?;\n"
        "    if decoded.chars().any(char::is_whitespace) {\n"
        "        return Err(StsError::Missing(name));\n    }",
        "an_arn_containing_whitespace_is_not_refused_the_way_a_credential_is",
    ),
]

# Mutations whose row lives in the socket test target. Filed here rather than in
# `UNIT` because the row is the only thing that can turn a mutation red, and
# running a socket row under `--lib` measures nothing -- which is exactly what
# the first version of this file did, and the harness reported as `no-run`
# rather than passing off as green.
SOCKET = [
    (
        # Two sites, so the parameter is still used and the replacement stays a
        # valid expression. The first version of this mutation wrote
        # `&[],\n let _ = session_token;` into an argument list, which is not
        # valid there: the harness reported a compiler refusal, and calling that
        # a structural guarantee would have been the harness flattering itself.
        "drop the session token from the request entirely",
        [
            (
                "        let headers = signed_headers(\n",
                "        let _ = session_token;\n        let headers = signed_headers(\n",
            ),
            (
                "            &[(SESSION_TOKEN_HEADER, std::str::from_utf8(session_token).map_err(\n"
                "                |_| StsError::IncompleteRequest(\"a session token that is not UTF-8\"),\n"
                "            )?)],\n",
                "            &[],\n",
            ),
        ],
        [
            (
                "        let headers = signed_headers(\n",
                "        let _ = session_token;\n        let headers = signed_headers(\n",
            ),
            (
                "            &[(SESSION_TOKEN_HEADER, std::str::from_utf8(session_token).map_err(\n"
                "                |_| StsError::IncompleteRequest(\"a session token that is not UTF-8\"),\n"
                "            )?)],\n",
                "            &[],\n",
            ),
        ],
        "a_session_signed_request_signs_the_session_token_and_sends_it",
    ),
    (
        "post a body that is not the documented one",
        'const BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";',
        'const BODY: &str = "Action=AssumeRole&Version=2011-06-15";',
        "a_session_signed_request_signs_the_session_token_and_sends_it",
    ),
    (
        "sign the identity call for the wrong service",
        "            self.client.config().region.clone(),\n            STS_SERVICE,",
        "            self.client.config().region.clone(),\n            \"s3\",",
        "a_session_signed_request_signs_the_session_token_and_sends_it",
    ),
    (
        # The mistake a "helpful" debug header makes. The session's secret key is
        # derived into the signature and the signer is dropped before the send,
        # so it never has to be on the wire -- and putting it there is exactly
        # the leak the row exists to catch.
        "put the session's secret key in a request header",
        "            )?)],\n        );",
        "            )?), (\"x-amz-debug\", std::str::from_utf8(secret_access_key)\n"
        "                .map_err(|_| StsError::IncompleteRequest(\"a key that is not UTF-8\"))?)],\n"
        "        );",
        "neither_the_long_lived_nor_the_session_secret_reaches_the_wire",
    ),
    (
        # The one that matters most for an agent: a failed call that still
        # answers. A caller that cannot tell a refusal from an identity is a
        # caller acting on a role it does not have.
        "hand the caller an identity even when the call failed",
        "    match call.answered {\n        Some(answer) => answer,",
        "    match call.answered.clone() {\n        Some(Err(_)) => Ok(CallerIdentity {\n"
        "            arn: \"arn:aws:sts::123456789012:assumed-role/demo/asv-session\".into(),\n"
        "            user_id: \"ARO123EXAMPLE123:asv-session\".into(),\n"
        "            account: \"123456789012\".into(),\n        }),\n"
        "        Some(answer) => answer,",
        "a_refusal_on_the_identity_call_is_named",
    ),
]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "unit"
    f.TEST_PREFIX = "aws::identity::tests::"
    f.CARGO_TARGET = "--lib"
    if mode == "reader":
        # `text_field` is in `sts.rs`; the rows that catch it are the
        # caller-identity ones, so the file and the prefix differ on purpose.
        f.STS = f.REPO / "crates/broker/src/aws/sts.rs"
        mutations = READER
    elif mode == "socket":
        f.STS = IDENTITY
        f.TEST_PREFIX = ""
        f.CARGO_TARGET = "--test r2c2b_sts_vertical"
        mutations = SOCKET
    else:
        f.STS = IDENTITY
        mutations = UNIT
    f.MUTATIONS[:] = mutations
    print(f"# falsifying {f.STS.relative_to(f.REPO)} [{mode}] with {len(mutations)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
