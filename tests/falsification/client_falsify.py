#!/usr/bin/env python3
"""Falsification for the R2.C.2.b client rows.

Same four-bucket accounting as the other two harnesses. These rows are about a
socket, so the mutations that matter are the ones that would let a request leave
unsigned, let a signature reach another origin, or send something other than the
bytes the signature was computed over.

Run:  python3 client_falsify.py
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

CLIENT = f.REPO / "crates/broker/src/aws/client.rs"

MUTATIONS = [
    # ---- the key's window -------------------------------------------------
    (
        # Was a mutation referencing a symbol that does not exist, so it never
        # compiled -- a vacuous mutation reported as a compiler refusal, which is
        # the harness flattering itself. This one compiles: the sink is handed
        # the key and declines to build the signer, so the property "the signer
        # is built inside `lend`" is what goes missing.
        "accept the key without building the signer inside the sink",
        "        self.signer = Some(",
        "        let _ = key;\n        self.signer = None;\n        #[allow(unreachable_code)]\n        let _ = Some(",
        "a_session_arrives_over_a_real_socket_without_the_long_lived_key_leaving",
    ),
    (
        "swallow a failure to lend and report it as something else",
        "            secrets.lend(credential, &mut sink)?;",
        "            let _ = secrets.lend(credential, &mut sink);",
        "a_credential_the_vault_will_not_lend_never_reaches_the_socket",
    ),
    # ---- what the signature covers ---------------------------------------
    # Re-spelled for the unified header list. The two mutations below used to
    # target the send chain and the `SignRequest` literals separately, which is
    # exactly the pair of places the unification removed -- so a harness whose
    # snippets no longer match the source would be measuring nothing.
    (
        "put a payload hash on the wire other than the body's",
        '        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),',
        '        ("x-amz-content-sha256".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),',
        "the_signature_commits_to_the_body_that_was_actually_sent",
    ),
    (
        # Renamed rather than re-pointed: the old label said "out of the signed
        # header list", which described a list that no longer exists. With one
        # list, leaving the hash out leaves it out of both, and that is what the
        # row now pins.
        "leave the payload hash out of the signature and the request together",
        '        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),\n',
        "",
        "the_request_is_a_post_to_the_path_and_host_that_were_signed",
    ),
    (
        # The drift direction the unification was for. Before it, a header could
        # be sent without being signed and nothing caught it: the old row
        # checked `x-amz-content-sha256` was *both*, but there was no row saying
        # every header the provider requires signed actually was. This is the
        # mutation that the new row exists to catch.
        "send a header the signature does not cover",
        "        .map(|(name, value)| Header::new(name, value))",
        "        .filter(|(name, _)| !name.eq_ignore_ascii_case(\"x-amz-content-sha256\"))\n"
        "        .map(|(name, value)| Header::new(name, value))",
        "every_header_the_provider_requires_signed_is_signed",
    ),
    (
        # The session path, where the same drift is the mistake the AWS
        # documentation warns about: the token has to be *signed* as well as
        # sent, because Example 2 of GetCallerIdentity signs with
        # x-amz-security-token inside SignedHeaders. The mutation lives here
        # rather than in the identity harness because `sign_with` is in this
        # file, and a mutation aimed at code the harness does not edit measures
        # nothing.
        "send the session token without signing it",
        "        .map(|(name, value)| Header::new(name, value))",
        "        .filter(|(name, _)| !name.eq_ignore_ascii_case(\"x-amz-security-token\"))\n"
        "        .map(|(name, value)| Header::new(name, value))",
        "a_session_signed_request_signs_the_session_token_and_sends_it",
    ),
    (
        # The date was signed from `amz_date` and sent from `signed.amz_date`,
        # with a doc comment claiming a caller could not send one and sign
        # another. With one list they are the same value by construction; this
        # pins that the value on the wire is the one that was stamped.
        "stamp a date the request does not carry",
        '        ("x-amz-date".to_string(), amz_date.to_string()),',
        '        ("x-amz-date".to_string(), "20191109T000000Z".to_string()),',
        "the_request_is_a_post_to_the_path_and_host_that_were_signed",
    ),
    # ---- the Host header -------------------------------------------------
    (
        "leave a non-default port out of the Host header",
        "            port => format!(\"{}:{port}\", self.audience.authority),",
        "            port => self.audience.authority.to_string(),",
        "the_request_is_a_post_to_the_path_and_host_that_were_signed",
    ),
    # ---- the redirect policy ----------------------------------------------
    (
        "offer a hop even for a non-redirect answer",
        "                Some(next) if status.is_redirection() => Ok(Redirect::Hop(next)),",
        "                Some(next) => Ok(Redirect::Hop(next)),",
        "a_success_carrying_a_location_is_not_followed_as_a_redirect",
    ),
    (
        "refuse to follow any redirect, so the cross-origin row passes by accident",
        "                Some(next) if status.is_redirection() => Ok(Redirect::Hop(next)),",
        "                Some(_) => Err(StsClientError::UnreadableStatus { status: 0 }),",
        "a_same_origin_redirect_is_followed_and_the_signature_is_recomputed_for_the_hop",
    ),
    # ---- the response -----------------------------------------------------
    (
        "flatten a named provider refusal into a status",
        "            Err(error @ StsError::Provider { .. }) => Err(StsClientError::Request(error)),",
        "            Err(error @ StsError::Provider { .. }) => {\n"
        "                let _ = error;\n"
        "                Err(StsClientError::UnreadableStatus { status })\n"
        "            }",
        "a_provider_refusal_is_named_rather_than_flattened_to_a_status",
    ),
    (
        "blame the credential for a shape the client cannot read",
        "            Err(_) if !(200..300).contains(&status) => {\n"
        "                Err(StsClientError::UnreadableStatus { status })\n"
        "            }",
        "            Err(_) if !(200..300).contains(&status) => Err(StsClientError::Request(\n"
        "                StsError::Missing(\"a response this client cannot read\"),\n"
        "            )),",
        "a_refusal_the_client_cannot_read_is_a_status_and_not_a_blame",
    ),
    (
        # Known and recorded as NOT MEASURED, in the test file's own header and
        # in the roadmap. It is the *second* size bound -- the one that checks
        # the bytes after reading them.
        #
        # **This mutation was a survivor until this row existed.** The fake
        # origin declared a `content-length` on every response, so the first
        # bound fired first and this branch was never reached: the mutation
        # stayed green for a reason that had nothing to do with the bound. The
        # fixture gained `OriginResponse::chunked` to close exactly that gap and
        # nothing called it, so the branch had no row at all. It is filed against
        # `a_response_that_never_declares_its_size_is_refused_by_the_read_bound`,
        # which frames its body chunked so a client cannot size it in advance --
        # the case where this bound is the only thing bounding memory.
        "drop the post-read transport bound on the response",
        "        if bytes.len() > MAX_RESPONSE_BYTES {",
        "        if false {",
        "a_response_that_never_declares_its_size_is_refused_by_the_read_bound",
    ),
]


def main() -> int:
    f.STS = CLIENT
    f.TEST_PREFIX = ""
    f.CARGO_TARGET = "--test r2c2b_sts_vertical"
    f.MUTATIONS[:] = [
        (m[0], m[1], m[1], m[2]) if len(m) == 3 else m for m in MUTATIONS
    ]
    print(f"# falsifying {CLIENT.relative_to(f.REPO)} with {len(MUTATIONS)} mutations\n")
    return f.main()


if __name__ == "__main__":
    sys.exit(main())
