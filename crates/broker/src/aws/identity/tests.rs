//! R2.C.3 — reading `sts:GetCallerIdentity`.
//!
//! The two accepted documents are the AWS reference's own samples, copied
//! verbatim from its Example 1 (an IAM user) and Example 2 (temporary
//! credentials from `AssumeRole`). Example 2 is the one this whole block is
//! about, because it is the shape a session-signed request produces.
//!
//! No socket here: these are properties of *what a document may say*, and a
//! socket would only make them slower to falsify. The call itself is measured in
//! `r2c2b_sts_vertical.rs`.

use asv_broker::aws::identity::parse_caller_identity;
use asv_broker::aws::sts::{StsError, MAX_RESPONSE_BYTES};

/// AWS's Example 2, verbatim: called with temporary credentials.
const SESSION_SAMPLE: &str = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/my-role-name/my-role-session-name</Arn>
    <UserId>ARO123EXAMPLE123:my-role-session-name</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"#;

/// AWS's Example 1, verbatim: called by an IAM user.
const USER_SAMPLE: &str = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/Alice</Arn>
    <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"#;

#[test]
fn the_documented_session_sample_yields_the_identity_aws_prints() {
    let identity = parse_caller_identity(SESSION_SAMPLE.as_bytes())
        .expect("the documented sample is a document this reader knows");
    assert_eq!(
        identity.arn,
        "arn:aws:sts::123456789012:assumed-role/my-role-name/my-role-session-name"
    );
    assert_eq!(identity.user_id, "ARO123EXAMPLE123:my-role-session-name");
    assert_eq!(identity.account, "123456789012");
}

#[test]
fn the_documented_user_sample_is_read_by_the_same_rules() {
    // Two samples rather than one, because a reader tuned to a single document
    // is a reader that has been fitted to its fixture. The temporary-credentials
    // case and the long-lived-user case differ in the shape of the ARN and the
    // UserId, and both have to come out the same way.
    let identity = parse_caller_identity(USER_SAMPLE.as_bytes())
        .expect("the documented user sample is a document this reader knows");
    assert_eq!(identity.arn, "arn:aws:iam::123456789012:user/Alice");
    assert_eq!(identity.user_id, "AIDACKCEVSQ6C2EXAMPLE");
    assert_eq!(identity.account, "123456789012");
}

#[test]
fn a_credential_document_is_not_read_as_an_identity() {
    // The AssumeRole response is a success document too, and it has no `<Arn>`.
    // A reader that returned defaults for missing fields would answer "which
    // identity is this" with three empty strings, which is worse than a refusal:
    // it looks like an answer.
    let body = r#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
    <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
    <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
    <SessionToken>FQoGZXIvYXdzEBYaDEXAMPLE</SessionToken>
    <Expiration>2019-11-09T13:34:41Z</Expiration>
  </Credentials></AssumeRoleResult></AssumeRoleResponse>"#;
    match parse_caller_identity(body.as_bytes()) {
        Err(StsError::Missing("Arn")) => {}
        other => panic!("a credential document was read as an identity: {other:?}"),
    }
}

#[test]
fn a_provider_refusal_is_named_rather_than_read_as_an_identity() {
    // An `AccessDenied` document has no `<Arn>` either, so without the error
    // check this would be reported as a missing field and the operator would go
    // looking for a malformed document instead of an IAM decision.
    let body = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: alice is not authorized to perform: sts:GetCallerIdentity</Message>
  </Error>
  <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
</ErrorResponse>"#;
    match parse_caller_identity(body.as_bytes()) {
        Err(StsError::Provider { code, .. }) => assert_eq!(code, "AccessDenied"),
        other => panic!("a refusal was read as an identity: {other:?}"),
    }
}

#[test]
fn an_arn_outside_the_documented_lengths_is_refused() {
    // AWS documents 20..=2048 for the Arn. A reader that did not check would
    // report an identity nobody could act on -- and an ARN that arrived
    // truncated by something upstream is exactly how that happens.
    let short = SESSION_SAMPLE.replace(
        "arn:aws:sts::123456789012:assumed-role/my-role-name/my-role-session-name",
        "arn:aws:sts::1:x",
    );
    assert!(
        matches!(
            parse_caller_identity(short.as_bytes()),
            Err(StsError::UnrecognisedDocument(_))
        ),
        "a nineteen-character ARN was accepted"
    );

    let long_arn = format!("arn:aws:iam::123456789012:role/{}", "a".repeat(2100));
    let long = SESSION_SAMPLE.replace(
        "arn:aws:sts::123456789012:assumed-role/my-role-name/my-role-session-name",
        &long_arn,
    );
    assert!(
        matches!(
            parse_caller_identity(long.as_bytes()),
            Err(StsError::UnrecognisedDocument(_))
        ),
        "an ARN past the documented maximum was accepted"
    );
}

#[test]
fn a_missing_field_is_named() {
    // Which of the three is absent matters: an identity without an account is a
    // different question from one without an ARN, and both are worth refusing.
    let body = SESSION_SAMPLE.replace(
        "    <UserId>ARO123EXAMPLE123:my-role-session-name</UserId>\n",
        "",
    );
    match parse_caller_identity(body.as_bytes()) {
        Err(StsError::Missing("UserId")) => {}
        other => panic!("a missing UserId was not named: {other:?}"),
    }
}

#[test]
fn an_empty_field_is_missing_rather_than_empty() {
    let body = SESSION_SAMPLE.replace(">123456789012<", "><");
    match parse_caller_identity(body.as_bytes()) {
        Err(StsError::Missing("Account")) => {}
        other => panic!("an empty Account was read as an empty string: {other:?}"),
    }
}

#[test]
fn a_duplicated_field_is_a_refusal_and_not_a_first_one_wins() {
    // Two ARNs in one document has been shaped by something, and picking one is
    // how an identity gets reported that AWS never said. The same rule the
    // credential reader uses, and the reason there is one reader.
    let body = SESSION_SAMPLE.replace(
        "    <Account>123456789012</Account>",
        "    <Arn>arn:aws:iam::999999999999:user/Mallory</Arn>\n    <Account>123456789012</Account>",
    );
    assert!(
        matches!(
            parse_caller_identity(body.as_bytes()),
            Err(StsError::UnrecognisedDocument(_))
        ),
        "a document with two ARNs was read, taking the first"
    );
}

#[test]
fn an_arn_containing_whitespace_is_not_refused_the_way_a_credential_is() {
    // A deliberate contrast with the credential rule. `<Message>` and any
    // future text field legitimately contain spaces, and a reader that applied
    // "a credential never contains whitespace" to every field would refuse
    // documents AWS actually sends. This row exists so that unifying the two
    // rules later is a deliberate act with a red test, rather than a tidy-up
    // that silently breaks a provider response.
    let body = SESSION_SAMPLE.replace(
        "ARO123EXAMPLE123:my-role-session-name",
        "ARO123EXAMPLE123:my role session name",
    );
    let identity = parse_caller_identity(body.as_bytes())
        .expect("whitespace in a non-credential field is not a credential problem");
    assert_eq!(identity.user_id, "ARO123EXAMPLE123:my role session name");
}

#[test]
fn a_document_declaring_a_dtd_is_refused_before_it_is_read() {
    let body = SESSION_SAMPLE.replace(
        "<GetCallerIdentityResponse",
        "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>\n<GetCallerIdentityResponse",
    );
    assert!(
        matches!(
            parse_caller_identity(body.as_bytes()),
            Err(StsError::UnrecognisedDocument(_))
        ),
        "a document declaring a DTD was read"
    );
}

#[test]
fn a_body_that_is_not_utf8_is_refused_before_it_is_parsed() {
    let mut body = SESSION_SAMPLE.as_bytes().to_vec();
    body.push(0xff);
    assert!(
        matches!(
            parse_caller_identity(&body),
            Err(StsError::UnrecognisedDocument(_))
        ),
        "a body that is not UTF-8 was read"
    );
}

#[test]
fn a_response_larger_than_the_bound_is_refused_unread() {
    let body = format!("{SESSION_SAMPLE}{}", " ".repeat(MAX_RESPONSE_BYTES));
    assert!(
        matches!(
            parse_caller_identity(body.as_bytes()),
            Err(StsError::ResponseTooLarge)
        ),
        "an oversized document was parsed rather than refused unread"
    );
}
