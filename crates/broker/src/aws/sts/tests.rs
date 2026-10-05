//! R2.C.2.a — the `sts:AssumeRole` encodings, against the vectors AWS publishes.
//!
//! # The oracle
//!
//! Every expected value below was computed **first** by
//! `$TMPDIR/sts_reference.py`, an implementation written from the AWS Query API
//! documentation and from the two specifications the code claims to implement —
//! `application/x-www-form-urlencoded` and RFC 3339 to the second. It never
//! reads this crate. That is not ceremony: the failure mode of a credential
//! encoder is a body AWS silently rejects, or a session minted from a mangled
//! document, and a test graded against this implementation's own output would
//! have agreed with every one of those.
//!
//! If a vector here ever disagrees with the code, **the vector is not edited**.
//! Which side is wrong gets worked out, for the reason the SigV4 rows spell
//! out: "make the test pass" on a protocol encoder is how a provider starts
//! answering `SignatureDoesNotMatch` for a reason nobody can find.
//!
//! # The rows after the vectors
//!
//! The vectors establish that the encodings are right, and every one of them is
//! a document that should be accepted. They cannot establish the *property*,
//! which is about the documents that must be refused. Those rows are the ones
//! that would have caught a reader willing to mint a session out of anything
//! that arrives on the socket.

use std::time::{Duration, SystemTime};

use asv_broker::aws::sts::{
    parse_assume_role, AssumeRole, AwsSecretSink, AwsSession, StsError, API_VERSION,
    MAX_RESPONSE_BYTES,
};

const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/demo";
const SESSION_NAME: &str = "asv-session";

/// The AWS-documented `SessionToken` from the `AssumeRole` reference page, with
/// the display folding taken out.
///
/// The documented value is printed across five indented lines, and it is worth
/// being explicit about why that is *not* what arrives on a socket. The session
/// token becomes the `x-amz-security-token` request header, and a header value
/// cannot contain a newline, so a folded token could not be used by anything,
/// including AWS's own SDKs. The folding is a property of the documentation
/// page. The reader below does not rely on that argument to be safe: it
/// refuses a credential field containing whitespace, which is what
/// `a_credential_field_the_documentation_folded_is_refused` pins.
const SAMPLE_SESSION_TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdWQLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";

const SAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY";
const SAMPLE_ACCESS_KEY: &str = "ASIAIOSFODNN7EXAMPLE";

/// `2019-11-09T13:34:41Z`, the instant in the documented sample, in seconds
/// since the epoch. From the oracle.
const SAMPLE_EXPIRATION: u64 = 1_573_306_481;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn request() -> AssumeRole {
    AssumeRole::new(ROLE_ARN, SESSION_NAME, 3600, None).expect("the fixture is complete")
}

/// The documented sample response, with the four fields supplied so a row can
/// vary exactly one of them and watch the reader's answer change.
fn response_with(access_key: &str, secret: &str, token: &str, expiration: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/{SESSION_NAME}</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:{SESSION_NAME}</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{access_key}</AccessKeyId>
      <SecretAccessKey>{secret}</SecretAccessKey>
      <SessionToken>{token}</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
"#
    )
}

/// The documented sample, unmodified.
fn sample() -> String {
    response_with(
        SAMPLE_ACCESS_KEY,
        SAMPLE_SECRET,
        SAMPLE_SESSION_TOKEN,
        "2019-11-09T13:34:41Z",
    )
}

fn parse(body: &str) -> Result<AwsSession, StsError> {
    parse_assume_role(body.as_bytes(), &request(), at(SAMPLE_EXPIRATION - 3600))
}

// ============================================================ the request side

#[test]
fn the_body_is_the_form_encoding_aws_expects() {
    // Oracle `bodies.plain`.
    assert_eq!(
        request().form_body(),
        "Action=AssumeRole\
         &DurationSeconds=3600\
         &RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdemo\
         &RoleSessionName=asv-session\
         &Version=2011-06-15"
    );
}

#[test]
fn the_parameters_are_ordered_by_name_and_not_by_the_order_they_were_written() {
    // `ExternalId` sorts between `DurationSeconds` and `RoleArn`. A body built in
    // declaration order instead would put it last, hash differently, and be
    // refused by the provider for a reason that reads as a signing bug.
    let with_external_id =
        AssumeRole::new(ROLE_ARN, SESSION_NAME, 900, Some("ext-123".into())).unwrap();
    // Oracle `bodies.with_external_id`.
    assert_eq!(
        with_external_id.form_body(),
        "Action=AssumeRole\
         &DurationSeconds=900\
         &ExternalId=ext-123\
         &RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdemo\
         &RoleSessionName=asv-session\
         &Version=2011-06-15"
    );
}

#[test]
fn the_payload_hash_is_the_sha256_of_exactly_those_bytes() {
    // The hash SigV4 puts in the canonical request is taken over the body as it
    // goes on the wire, so a mismatch between the two is a `SignatureDoesNotMatch`
    // with no other symptom. Oracle `bodies.*.sha256`.
    let plain = request();
    assert_eq!(
        plain.payload_hash(),
        "d61a9eb7ea5c05ac972df25002cebe88992cef0156ec2f4d0e274ee12dc10d76"
    );
    assert_eq!(
        AssumeRole::new(ROLE_ARN, SESSION_NAME, 900, Some("ext-123".into()))
            .unwrap()
            .payload_hash(),
        "eb4042e2e7a0fcf432d2858f2409371e32c009df3befb8550156a496a2c4ecc6"
    );
    // Oracle `bodies.every_escaping_rule`: a space in the role ARN, which the
    // documented pattern admits, and a literal `+` `,` `=` `@` `.` in the
    // session name. One body, every escaping rule.
    assert_eq!(
        AssumeRole::new(
            "arn:aws:iam::123456789012:role/demo role",
            "asv+session,with=chars.@-_",
            43_200,
            Some("a&b=c".into()),
        )
        .unwrap()
        .payload_hash(),
        "7926729f7d299c9b93ea4667a1be0fe78bda4164f5a2afd9903bbc8e3dcdeb7d"
    );
}

#[test]
fn a_space_is_a_plus_and_a_plus_is_escaped() {
    // The one pair of rules that share an encoder and disagree about it:
    // `x-www-form-urlencoded` says a space is `+`, and says an actual `+` is
    // `%2B`. Getting it backwards mangles every field carrying either, and the
    // mangling is invisible in the signature — it just produces a body AWS
    // refuses.
    //
    // The space is in the role ARN rather than the session name because that is
    // the only one of the three whose documented pattern admits U+0020; the
    // reader refuses a whitespace-bearing session name outright, which
    // `a_session_name_carrying_whitespace_is_refused` pins. The encoder still
    // has to be right, and a space in an ARN is a real case rather than a
    // convenient one.
    let body = AssumeRole::new(
        "arn:aws:iam::123456789012:role/demo role",
        "asv+session",
        3600,
        None,
    )
    .unwrap()
    .form_body();
    assert!(
        body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdemo+role"),
        "a space in the ARN did not become a plus: {body}"
    );
    assert!(
        body.contains("RoleSessionName=asv%2Bsession"),
        "a literal plus was not escaped: {body}"
    );
}

#[test]
fn the_api_version_is_the_one_aws_serves() {
    assert_eq!(API_VERSION, "2011-06-15");
}

#[test]
fn a_duration_no_role_chain_can_have_is_refused_before_anything_is_sent() {
    // Documented range is 900..=43200. A caller asking for a year is refused
    // here rather than becoming a round trip and an `AccessDenied` that reads
    // like an IAM problem.
    for asked in [0, 1, 899, 43_201, u32::MAX] {
        let outcome = AssumeRole::new(ROLE_ARN, SESSION_NAME, asked, None);
        assert_eq!(
            outcome.err(),
            Some(StsError::IncompleteRequest("duration")),
            "{asked} seconds was not refused"
        );
    }
    for allowed in [900, 3600, 43_200] {
        assert!(
            AssumeRole::new(ROLE_ARN, SESSION_NAME, allowed, None).is_ok(),
            "{allowed} seconds is inside the documented range and was refused"
        );
    }
}

#[test]
fn a_name_too_short_to_be_one_is_refused_here_and_not_at_aws() {
    // Documented: `RoleArn` 20..=2048, `RoleSessionName` 2..=64,
    // `ExternalId` 2..=1224. The empty check these replace let a one-character
    // session name through, which AWS rejects.
    assert!(AssumeRole::new("x", SESSION_NAME, 3600, None).is_err());
    assert!(AssumeRole::new(ROLE_ARN, "a", 3600, None).is_err());
    assert!(AssumeRole::new(ROLE_ARN, &"a".repeat(65), 3600, None).is_err());
    assert!(AssumeRole::new(ROLE_ARN, SESSION_NAME, 3600, Some("x".into())).is_err());
    // A role ARN one character under the documented minimum.
    assert!(AssumeRole::new(&"a".repeat(19), SESSION_NAME, 3600, None).is_err());
    assert!(AssumeRole::new(&"a".repeat(20), SESSION_NAME, 3600, None).is_ok());
}

#[test]
fn a_session_name_carrying_whitespace_is_refused() {
    // AWS's documented pattern for `RoleSessionName` has no space in it, and
    // "asv session" is the single most likely typo there is. It is worth
    // refusing here because the versioned character classes are left to AWS on
    // purpose, and "no whitespace" is both documented and stable.
    for bad in ["asv session", "asv\tsession", "asv\nsession", "asv\rsession"] {
        assert!(
            AssumeRole::new(ROLE_ARN, bad, 3600, None).is_err(),
            "{bad:?} carries whitespace and was accepted"
        );
    }
}

// =========================================================== the response side

#[test]
fn the_documented_sample_response_yields_a_session() {
    let session = parse(&sample()).expect("the documented sample parses");

    assert_eq!(session.access_key_id, SAMPLE_ACCESS_KEY);
    // The three values reach a sink, and this is the only way to get them out.
    let mut sink = Recorder::default();
    session
        .with_signing_values(&mut sink)
        .expect("a sink accepts what it was handed");
    assert_eq!(sink.access_key, SAMPLE_ACCESS_KEY.as_bytes());
    assert_eq!(sink.secret, SAMPLE_SECRET.as_bytes());
    assert_eq!(sink.token, SAMPLE_SESSION_TOKEN.as_bytes());
    // The role the session is for is echoed from the request, so a receipt can
    // say what authority was exercised without asking the provider again.
    assert_eq!(session.role_arn, ROLE_ARN);
    assert_eq!(session.role_session_name, SESSION_NAME);
}

#[test]
fn the_expiration_is_the_documented_instant_to_the_second() {
    let session = parse(&sample()).expect("the documented sample parses");
    assert_eq!(session.expires_at, at(SAMPLE_EXPIRATION));
}

#[test]
fn a_session_is_usable_before_its_expiry_and_not_at_or_after_it() {
    let session = parse(&sample()).expect("the documented sample parses");

    assert!(session.usable_at(at(SAMPLE_EXPIRATION - 1), Duration::ZERO));
    // At the instant it expires it is not usable, even with no margin asked
    // for: a caller handed a credential that dies this second is handed a
    // credential that fails at the provider.
    assert!(!session.usable_at(at(SAMPLE_EXPIRATION), Duration::ZERO));
    assert!(!session.usable_at(at(SAMPLE_EXPIRATION + 1), Duration::ZERO));
    // And a margin the caller asks for is subtracted, so the credential is
    // dropped before it is spent on a request that cannot land.
    assert!(!session.usable_at(at(SAMPLE_EXPIRATION - 5), Duration::from_secs(10)));
    assert!(session.usable_at(at(SAMPLE_EXPIRATION - 30), Duration::from_secs(10)));
}

#[test]
fn a_session_that_expired_before_it_was_used_is_refused_rather_than_served() {
    // The document is complete and the credential is gone. Serving it anyway
    // would be the worst outcome available: a confident answer that fails at
    // the provider, attributed to something else.
    let outcome = parse_assume_role(
        sample().as_bytes(),
        &request(),
        at(SAMPLE_EXPIRATION + 1),
    );
    assert_eq!(
        outcome.err(),
        Some(StsError::AlreadyExpired("2019-11-09T13:34:41Z".into()))
    );
}

#[test]
fn an_expiration_outside_the_one_documented_shape_is_refused() {
    // The oracle's acceptance set. Everything AWS documents is `Z`, to the
    // second; offsets, fractional seconds and a leap second are all refused
    // rather than approximated, because a timestamp read wrongly is a
    // credential believed valid after it is not.
    let refused = [
        "2015-08-04T06:51:37+00:00",
        "2015-08-04T06:51:37.500Z",
        "2015-08-04 06:51:37Z",
        "2015-13-04T06:51:37Z",
        "2015-08-32T06:51:37Z",
        "2015-08-04T24:00:00Z",
        "2015-08-04T06:60:00Z",
        "2015-08-04T06:51:60Z",
        "2015-08-04T06:51:37",
        "2015-8-04T06:51:37Z",
        "not-a-date",
        "",
    ];
    for stamp in refused {
        let body = response_with(
            SAMPLE_ACCESS_KEY,
            SAMPLE_SECRET,
            SAMPLE_SESSION_TOKEN,
            stamp,
        );
        let outcome = parse_assume_role(
            body.as_bytes(),
            &request(),
            at(SAMPLE_EXPIRATION - 3600),
        );
        assert!(
            matches!(outcome, Err(StsError::MalformedExpiration(_))),
            "{stamp:?} was accepted as an instant"
        );
    }
}

#[test]
fn an_instant_past_the_32_bit_boundary_is_still_read_correctly() {
    // 2038-01-19T03:14:08Z is 2147483648, one second past what a 32-bit second
    // counter can hold. A `u32` of seconds here would wrap, and the credential
    // would be believed to have expired in 1970.
    let body = response_with(
        SAMPLE_ACCESS_KEY,
        SAMPLE_SECRET,
        SAMPLE_SESSION_TOKEN,
        "2038-01-19T03:14:08Z",
    );
    let session = parse_assume_role(body.as_bytes(), &request(), at(SAMPLE_EXPIRATION))
        .expect("a far-future instant is a valid one");
    assert_eq!(session.expires_at, at(2_147_483_648));

    // And a date far enough out that even the day count overflows 32 bits.
    let body = response_with(
        SAMPLE_ACCESS_KEY,
        SAMPLE_SECRET,
        SAMPLE_SESSION_TOKEN,
        "9999-12-31T23:59:59Z",
    );
    let session = parse_assume_role(body.as_bytes(), &request(), at(SAMPLE_EXPIRATION))
        .expect("a year 9999 instant is a valid one");
    assert_eq!(session.expires_at, at(253_402_300_799));
}

#[test]
fn a_provider_refusal_is_named_rather_than_flattened() {
    // A wrong role ARN is a configuration fix, a denied call is an IAM
    // decision and a throttle is a retry. "The provider said no" sends an
    // operator to none of them.
    let body = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: arn:aws:iam::123456789012:user/demo is not authorized to perform: sts:AssumeRole</Message>
  </Error>
  <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
</ErrorResponse>"#;
    match parse(body) {
        Err(StsError::Provider { code, message }) => {
            assert_eq!(code, "AccessDenied");
            assert!(message.contains("sts:AssumeRole"), "the message was lost: {message}");
        }
        other => panic!("a provider refusal was not named: {other:?}"),
    }
}

#[test]
fn an_error_response_is_never_mistaken_for_credentials() {
    // The error fixture carries `<Code>`, `<Message>`, `<Type>` and `<RequestId>`.
    // A reader that searched for the four credential names without first
    // recognising the error document would report a missing field and send an
    // operator to fix a role ARN that is fine.
    //
    // **This row covers the error direction only.** The `<Error` sniff has a
    // second direction, and it is the dangerous one: a *successful* document has
    // no `<Code>`, so a reader that stopped sniffing would go looking for one,
    // miss, and report the success as `Provider { code: "Unknown" }`. That is
    // what
    // `the_documented_sample_response_yields_a_session` catches, by expecting a
    // session where the mutated reader returns a refusal — which is why deleting
    // the sniff turns *that* row red and not this one.
    let body = r#"<ErrorResponse>
  <Error><Type>Sender</Type><Code>Throttling</Code><Message>slow down</Message></Error>
  <RequestId>abc</RequestId>
</ErrorResponse>"#;
    assert!(matches!(
        parse(body),
        Err(StsError::Provider { .. })
    ));
}

#[test]
fn a_document_this_reader_does_not_know_is_refused() {
    for body in [
        "",
        "not xml at all",
        "<html><body>502 Bad Gateway</body></html>",
        "<AssumeRoleResponse><AssumeRoleResult/></AssumeRoleResponse>",
        r#"{"Credentials":{"AccessKeyId":"ASIA"}}"#,
    ] {
        assert!(
            parse(body).is_err(),
            "{body:?} was read as an STS document"
        );
    }
}

#[test]
fn a_response_larger_than_the_bound_is_refused_unread() {
    // The bound is not about AWS, whose response is well under a kilobyte. It
    // is about the reader refusing to look at something it did not expect.
    let padding = "x".repeat(MAX_RESPONSE_BYTES);
    let body = sample().replace("</AssumeRoleResponse>", &format!("<P>{padding}</P></AssumeRoleResponse>"));
    assert!(
        body.len() > MAX_RESPONSE_BYTES,
        "the fixture has to actually exceed the bound to mean anything"
    );
    assert_eq!(
        parse(&body).err(),
        Some(StsError::ResponseTooLarge),
        "an oversized body was parsed anyway"
    );
    // One byte under the bound is a document this reader is willing to read,
    // and this one is read: the bound is the thing that stops the work, not the
    // shape of the document. An element this reader does not know is ignored
    // rather than refused, which is the correct direction — the four fields it
    // was asked for are all there and unambiguous.
    let just_under = "x".repeat(MAX_RESPONSE_BYTES - sample().len() - 20);
    let body = sample().replace(
        "</AssumeRoleResponse>",
        &format!("<P>{just_under}</P></AssumeRoleResponse>"),
    );
    assert!(body.len() <= MAX_RESPONSE_BYTES);
    let session = parse(&body).expect("a document under the bound is read");
    assert_eq!(session.access_key_id, SAMPLE_ACCESS_KEY);
}

#[test]
fn a_credential_field_left_empty_is_missing_rather_than_empty() {
    // An empty string is a credential that will be sent and will fail at the
    // provider; naming the field is the difference between a diagnosis and a
    // puzzle.
    for (access_key, secret, token, field) in [
        ("", SAMPLE_SECRET, SAMPLE_SESSION_TOKEN, "AccessKeyId"),
        (SAMPLE_ACCESS_KEY, "", SAMPLE_SESSION_TOKEN, "SecretAccessKey"),
        (SAMPLE_ACCESS_KEY, SAMPLE_SECRET, "", "SessionToken"),
    ] {
        let body = response_with(access_key, secret, token, "2019-11-09T13:34:41Z");
        assert_eq!(
            parse(&body).err(),
            Some(StsError::Missing(field)),
            "an empty {field} was not named"
        );
    }
}

#[test]
fn an_absent_credential_field_is_missing_too() {
    let body = sample().replace("<SessionToken>", "<SessionTokenRenamed>");
    assert_eq!(parse(&body).err(), Some(StsError::Missing("SessionToken")));
}

// ============================================ what the reader must refuse

#[test]
fn a_document_declaring_a_dtd_is_refused_before_it_is_read() {
    // The Query API emits no DTD. A document carrying one has been shaped by
    // something, and a reader that ignores the declaration is one step away
    // from honouring it.
    //
    // **The declaration has to be the only thing wrong with the document.** The
    // first version of this row declared an entity *and* referenced it, so the
    // undefined-entity rule refused it too — and the row stayed green with the
    // DTD check deleted. That is a row measuring two properties and proving
    // neither on its own. Here the declaration is never referenced and every
    // credential field is the one the reader is supposed to accept, so the DTD
    // rule is the only thing that can send this document out.
    let body = format!(
        r#"<!DOCTYPE AssumeRoleResponse [
  <!ENTITY harmless SYSTEM "file:///etc/passwd">
]>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>{SAMPLE_ACCESS_KEY}</AccessKeyId>
      <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>
      <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
    );
    match parse(&body) {
        Err(StsError::UnrecognisedDocument(why)) => assert!(
            why.contains("DTD"),
            "the refusal did not name the DTD, so some other rule caught it: {why}"
        ),
        other => panic!("a document declaring an external entity was read: {other:?}"),
    }
}

#[test]
fn an_external_entity_reference_is_never_resolved_into_a_credential() {
    // The same attack without the declaration. This reader implements no entity
    // mechanism, so it cannot expand one; the row is here because "cannot
    // expand" is a claim and this is the measurement of it.
    let body = response_with(
        "&xxe;",
        SAMPLE_SECRET,
        SAMPLE_SESSION_TOKEN,
        "2019-11-09T13:34:41Z",
    );
    let outcome = parse(&body);
    assert!(
        outcome.is_err(),
        "an undefined entity was turned into a credential: {outcome:?}"
    );
    // And the refusal has to be a refusal, not a credential holding the literal
    // text: an access key that reads `&xxe;` would be a 200-shaped answer to a
    // probe.
    if let Err(StsError::UnrecognisedDocument(why)) = &outcome {
        assert!(!why.is_empty(), "the refusal says nothing about why");
    } else {
        panic!("the refusal was not the documented one: {outcome:?}");
    }
}

#[test]
fn an_ampersand_a_credential_cannot_contain_is_refused_rather_than_kept() {
    // One rule for the whole reader: a document it does not understand is
    // refused, not guessed at. A duplicated field, an unclosed tag, a
    // non-UTF-8 byte and now an undefined entity all take the same exit. The
    // one place that guessed would be the one place to look when a probe comes
    // back with a 200.
    let body = response_with(
        "ASIA&",
        SAMPLE_SECRET,
        SAMPLE_SESSION_TOKEN,
        "2019-11-09T13:34:41Z",
    );
    assert!(
        parse(&body).is_err(),
        "a bare ampersand became part of an access key"
    );
}

#[test]
fn a_credential_field_the_documentation_folded_is_refused() {
    // The documented sample prints the session token across five indented lines.
    // The argument for why that cannot arrive on a socket is in
    // `SAMPLE_SESSION_TOKEN`: the token becomes an HTTP header value, and a
    // header value cannot contain a newline. This row is the belt to that
    // braces, and it is the row that matters, because a reader that trims or
    // un-folds quietly would mint a session whose token is wrong by exactly the
    // whitespace it decided to remove.
    let folded = SAMPLE_SESSION_TOKEN
        .as_bytes()
        .chunks(64)
        .map(|chunk| format!("       {}\n", String::from_utf8_lossy(chunk)))
        .collect::<String>();
    let body = response_with(
        SAMPLE_ACCESS_KEY,
        SAMPLE_SECRET,
        &folded,
        "2019-11-09T13:34:41Z",
    );
    let outcome = parse(&body);
    assert!(
        outcome.is_err(),
        "a folded token was accepted as a credential: {outcome:?}"
    );
}

#[test]
fn a_duplicated_credential_field_is_a_refusal_and_not_a_first_one_wins() {
    // Two `AccessKeyId` elements means something shaped the document, and
    // guessing which one was meant is how a signature gets committed to the
    // wrong value. Which of the two wins is not a question this reader has an
    // answer to.
    for (first, second) in [
        (SAMPLE_ACCESS_KEY, "ASIAOTHERKEY"),
        ("", SAMPLE_ACCESS_KEY),
        (SAMPLE_ACCESS_KEY, ""),
    ] {
        let body = format!(
            "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
             <AccessKeyId>{first}</AccessKeyId>\
             <AccessKeyId>{second}</AccessKeyId>\
             <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
             <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
             <Expiration>2019-11-09T13:34:41Z</Expiration>\
             </Credentials></AssumeRoleResult></AssumeRoleResponse>"
        );
        assert!(
            parse(&body).is_err(),
            "two AccessKeyId elements were read as one credential ({first:?}/{second:?})"
        );
    }
}

#[test]
fn a_credential_field_nested_inside_itself_is_refused() {
    let body = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId><AccessKeyId>{SAMPLE_ACCESS_KEY}</AccessKeyId></AccessKeyId>\
         <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
         <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
         <Expiration>2019-11-09T13:34:41Z</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    assert!(
        parse(&body).is_err(),
        "a nested AccessKeyId was read as the inner value"
    );
}

#[test]
fn a_duplicated_field_hidden_in_a_comment_is_still_a_duplicated_field() {
    // This reader is comment-unaware, which is a documented limitation rather
    // than a hidden one. The direction it fails in is the safe one: a tag
    // inside a comment still counts towards "more than once", so a comment
    // cannot smuggle a second credential past the rule above.
    let body = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId>{SAMPLE_ACCESS_KEY}</AccessKeyId>\
         <!-- <AccessKeyId>ASIAOTHERKEY</AccessKeyId> -->\
         <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
         <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
         <Expiration>2019-11-09T13:34:41Z</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    assert!(
        parse(&body).is_err(),
        "a commented-out credential was not counted, so a comment can hide one"
    );
}

#[test]
fn an_unclosed_field_is_refused_rather_than_read_to_the_end_of_the_document() {
    let body = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId>{SAMPLE_ACCESS_KEY}\
         <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
         <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
         <Expiration>2019-11-09T13:34:41Z</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    assert!(
        parse(&body).is_err(),
        "an unclosed field was read to the end of the document"
    );
}

#[test]
fn a_multibyte_character_beside_a_tag_is_read_whole_and_does_not_bring_the_reader_down() {
    // A reader pointed at a socket must not panic on what a socket can send, and
    // must not slice a character in half to do it. The byte after
    // `<AccessKeyId>` here is the first byte of a two-byte `é`, and the version
    // of this reader that indexed one byte past the opening tag landed inside
    // it and took the process down.
    //
    // What it reads is still not *accepted* as a credential by anything but this
    // function: the reader's job is to hand back the characters between the
    // tags, and the row is that it hands back exactly these, the two-byte
    // character included and nothing truncated off either end.
    let body = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId>é{SAMPLE_ACCESS_KEY}</AccessKeyId>\
         <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
         <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
         <Expiration>2019-11-09T13:34:41Z</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    let session = parse(&body).expect("a multibyte character beside a tag is text, and text is readable");
    assert_eq!(
        session.access_key_id,
        format!("é{SAMPLE_ACCESS_KEY}"),
        "the value was not read exactly, which is what slicing mid-character looks like"
    );
}

#[test]
fn the_five_predefined_entities_are_decoded_because_a_credential_may_need_them() {
    // The reason entity decoding exists at all: a value that has to survive a
    // round trip through XML gets escaped, and decoding only the five the
    // specification defines is decoding everything that can appear without
    // implementing a mechanism.
    for (raw, expected) in [
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&#65;", "A"),
        ("&#x41;", "A"),
    ] {
        let body = response_with(
            raw,
            SAMPLE_SECRET,
            SAMPLE_SESSION_TOKEN,
            "2019-11-09T13:34:41Z",
        );
        let session = parse(&body)
            .unwrap_or_else(|e| panic!("{raw:?} is a defined entity and did not decode: {e}"));
        assert_eq!(session.access_key_id, expected, "{raw:?} decoded wrongly");
    }
}

#[test]
fn an_escaped_tag_in_a_credential_is_text_and_not_structure() {
    // The order matters: the closing tag is found in the raw text and only then
    // is the content decoded, so an entity that looks like a tag cannot become
    // one. Decoding first would let a document move its own boundaries.
    let body = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId>&lt;AccessKeyId&gt;{SAMPLE_ACCESS_KEY}&lt;/AccessKeyId&gt;</AccessKeyId>\
         <SecretAccessKey>{SAMPLE_SECRET}</SecretAccessKey>\
         <SessionToken>{SAMPLE_SESSION_TOKEN}</SessionToken>\
         <Expiration>2019-11-09T13:34:41Z</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    let session = parse(&body).expect("an escaped tag is text, and text is readable");
    assert_eq!(
        session.access_key_id,
        format!("<AccessKeyId>{SAMPLE_ACCESS_KEY}</AccessKeyId>")
    );
}

#[test]
fn a_body_that_is_not_utf8_is_refused_before_it_is_parsed() {
    let mut body = sample().into_bytes();
    let field_at = body
        .windows(9)
        .position(|w| w == b"AccessKey")
        .expect("the fixture has the field");
    body[field_at] = 0xff;
    assert_eq!(
        parse_assume_role(&body, &request(), at(SAMPLE_EXPIRATION - 3600)).err(),
        Some(StsError::UnrecognisedDocument("the body is not UTF-8".into())),
    );
}

// ==================================================== the secretless property

#[test]
fn printing_a_session_shows_the_receipt_and_not_the_credential() {
    // An operator reading a receipt needs to know which role and which key id;
    // neither of those is the secret. The two that are have no business in a
    // log line, an error message or a panic report.
    let session = parse(&sample()).expect("the documented sample parses");
    let printed = format!("{session:?}");

    for secret in [SAMPLE_SECRET, SAMPLE_SESSION_TOKEN] {
        assert!(
            !printed.contains(secret),
            "a secret reached the Debug output: {printed}"
        );
    }
    for public in [SAMPLE_ACCESS_KEY, ROLE_ARN, SESSION_NAME] {
        assert!(
            printed.contains(public),
            "the receipt lost {public}: {printed}"
        );
    }
}

#[test]
fn the_three_signing_values_have_no_public_getter() {
    // What the type can be asked for is enumerable by hand and pinned here, so
    // a future `secret_access_key()` added "for logging" has to change this
    // file. `access_key_id` is public because a receipt needs it; the two that
    // are secret are not, and the only route out is a sink.
    let session = parse(&sample()).expect("the documented sample parses");
    let mut sink = Recorder::default();
    session.with_signing_values(&mut sink).expect("hand it over");

    // Field access is what a getter would exist to serve, and the compiler is
    // what says no. These are the public fields, in the order they are declared.
    let _public: (&str, SystemTime, &str, &str) = (
        session.access_key_id.as_str(),
        session.expires_at,
        session.role_arn.as_str(),
        session.role_session_name.as_str(),
    );
    // The secret pair is `Zeroizing` and private: the only way to observe them
    // is the sink, and the sink is the only thing that gets them.
    assert_eq!(sink.calls, 1, "the sink was handed the values more than once");
}

#[derive(Default)]
struct Recorder {
    access_key: Vec<u8>,
    secret: Vec<u8>,
    token: Vec<u8>,
    calls: usize,
}

impl AwsSecretSink for Recorder {
    fn accept(
        &mut self,
        access_key_id: &[u8],
        secret_access_key: &[u8],
        session_token: &[u8],
    ) -> Result<(), StsError> {
        self.access_key = access_key_id.to_vec();
        self.secret = secret_access_key.to_vec();
        self.token = session_token.to_vec();
        self.calls += 1;
        Ok(())
    }
}
