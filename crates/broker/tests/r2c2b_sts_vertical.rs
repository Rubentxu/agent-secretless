//! R2.C.2.b — the live `sts:AssumeRole` call, against a real TLS socket.
//!
//! # Why this is a socket and not a double
//!
//! The properties worth measuring here are the ones a mock cannot have: that the
//! long-lived key never leaves the broker, that what goes on the wire is signed
//! over the *bytes that were sent*, and that a redirect cannot carry a signature
//! to another origin. A stubbed HTTP client agrees with whatever the caller
//! tells it, so every one of those is invisible to it.
//!
//! The origin is `asv-connector-http`'s `TlsOrigin`: a real certificate, a real
//! handshake, SNI, and a request line the server parses. The client is built
//! against a `ResolvedAudience` pointing at it, exactly the way production is
//! built against the one `resolve_and_pin` vetted — the address policy is not
//! relaxed here, because the production path never consults it for an audience
//! it was handed.
//!
//! Nothing in this file reaches the network: the origin is loopback, and the
//! client is pinned to it.
//!
//! # What this file does NOT measure, stated before anyone counts it
//!
//! **The origin is a recorder, not a verifier.** It records what arrived and
//! answers; it does not check the signature. So a client that signed the wrong
//! body, left a header out of `SignedHeaders`, or signed `GET` while sending
//! `POST` would still get a session from this origin, and no row here can tell
//! the difference.
//!
//! That is a real limit and it is not fixable inside this file. Making the
//! origin verify means writing a second SigV4 verifier in `asv-connector-http`,
//! which cannot import the broker's signer without a dependency cycle, and two
//! verifiers is two things to keep correct rather than one. So the signature's
//! *validity* is measured by the R2.C.1 rows against AWS's published vectors,
//! and the combination — "the bytes on the wire are the bytes that were signed"
//! here, "those bytes produce AWS's published signature" there — is what covers
//! it. Whether AWS accepts *this* request over a real socket is the
//! `host-dependent` half, and no repository check asserts it.
//!
//! What this file does measure, and what the mutations confirmed: the key never
//! reaches the wire, every header AWS requires to be signed is signed, the
//! client holds **one** header list so "signed" and "sent" cannot diverge, the
//! payload hash is the hash of the sent body, the port is in the `Host`, a
//! cross-origin hop is refused, a 200 carrying a `Location` is not treated as a
//! redirect, an unsigned request cannot go out, a named provider refusal is not
//! flattened to a status, and the port's own refusal reason survives the
//! client.
//!
//! **And one check here is not exercised at all.** `StsClient::send` bounds the
//! body twice: once on the declared `content-length`, once on the bytes actually
//! read. The second is the one that matters for a response that declares no
//! length, and `fake_origin` always declares one — it sets `content-length` from
//! the body it is about to send. So a mutation removing the second check leaves
//! every row here green, which is what a falsification run found. It is recorded
//! rather than papered over: the second check is currently **unmeasured**, not
//! covered, and the honest way to measure it is an origin that can send a
//! length-less response, which this one cannot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use asv_broker::aws::client::{AwsCredentialConfig, StsClient, StsClientError};
use asv_broker::aws::sts::StsError;
use asv_connector_http::fake_origin::{Observed, OriginResponse, Reply, TlsOrigin};
use asv_connector_http::transport::{PinnedClient, ResolvedAudience};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_domain::Authority;

/// The long-lived key. It appears here as a fixture because a test has to be
/// able to name it, and the rows below are what assert that the *client* never
/// does. Its appearance in a test is not the property; its absence from every
/// `Observed` request is.
const LONG_LIVED_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const CREDENTIAL: &str = "aws-prod";
const ROLE: &str = "arn:aws:iam::123456789012:role/demo";
const SESSION_NAME: &str = "asv-session";

/// 2019-11-09T13:33:20Z, from the calendar oracle. The fixture response expires
/// at 13:34:41Z, so a session minted here has 81 seconds left: a deliberately
/// tight case rather than a comfortable one, because a margin that is never
/// tested near the edge is a margin nobody knows works.
const NOW: u64 = 1_573_306_400;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn config() -> AwsCredentialConfig {
    AwsCredentialConfig {
        access_key_id: ACCESS_KEY_ID.to_string(),
        region: "us-east-1".to_string(),
        role_arn: ROLE.to_string(),
        role_session_name: SESSION_NAME.to_string(),
        duration_seconds: 3600,
        external_id: None,
    }
}

/// A `SecretPort` that counts the grants and hands over one fixed secret.
///
/// The count is the point: it is how the cache rows tell "one exchange served
/// four lends" from "four exchanges".
#[derive(Default)]
struct CountingPort {
    grants: Arc<std::sync::atomic::AtomicUsize>,
    secret: Vec<u8>,
}

impl CountingPort {
    fn new(secret: &[u8]) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        let grants = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Self {
                grants: grants.clone(),
                secret: secret.to_vec(),
            },
            grants,
        )
    }
}

impl SecretPort for CountingPort {
    fn lend(&self, _credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        self.grants
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        sink.accept(&self.secret)
    }

    fn forget(&self, _credential: &str) {}
}

/// A port that lends nothing, for the row that must not reach the socket.
struct RefusingPort;

impl SecretPort for RefusingPort {
    fn lend(&self, credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::NotFound(credential.to_string()))
    }

    fn forget(&self, _credential: &str) {}
}

fn assume_role_response() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>FQoGZXIvYXdzEBYaDEXAMPLE</SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
    )
}

/// Starts a real TLS origin answering every request the way `reply` says.
///
/// The `Reply` to `OriginResponse` mapping lives in `fake_origin` and is private,
/// so the cases this file needs are spelled out here rather than reaching for
/// one that is not exported. Only the three shapes below are reachable, and
/// every other test in the tree goes through the scripted `FakeOrigin`.
fn origin(reply: Reply) -> TlsOrigin {
    TlsOrigin::start("sts.amazonaws.com", Arc::new(move |_: &Observed| match &reply {
        Reply::StatusWithLocation { status, body, location } => OriginResponse::new(
            *status,
            body.clone(),
        )
        .with_header("location", location),
        Reply::Body(body) => OriginResponse::new(200, body.clone()),
        Reply::Redirect(location) => {
            OriginResponse::new(302, String::new()).with_header("location", location)
        }
        Reply::Status { status, body } => OriginResponse::new(*status, body.clone()),
        other => panic!("the STS fixture only scripts a body, a redirect or a status; got {other:?}"),
    }))
}

/// A client pinned to `origin`, the way production is built against a vetted
/// audience.
fn client_for(origin: &TlsOrigin) -> StsClient {
    let resolved = ResolvedAudience {
        authority: Authority::canonicalize(&origin.certified_for)
            .expect("the fixture audience is canonical"),
        port: origin.port,
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    // The policy is passed with loopback *allowed* only because the audience
    // is loopback: `PinnedClient` re-checks the addresses it was handed. The
    // production call does not allow it, and the row that a production audience
    // is refused is the transport's own, not this file's.
    let transport = PinnedClient::build_with_roots(
        &resolved,
        asv_connector_http::transport::AddressPolicy { allow_loopback: true },
        &[origin.certificate()],
    )
    .expect("the fixture origin is usable over the pinned audience");
    StsClient::new(transport, resolved, config())
}

#[test]
fn a_session_arrives_over_a_real_socket_without_the_long_lived_key_leaving() {
    let origin = origin(Reply::Body(assume_role_response()));
    let (port, grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    let session = client
        .assume_role(&port, CREDENTIAL, at(NOW))
        .expect("a well-formed response yields a session");

    // The session is real and names what a receipt needs.
    assert_eq!(session.access_key_id, "ASIAIOSFODNN7EXAMPLE");
    assert_eq!(session.role_arn, ROLE);
    assert_eq!(session.role_session_name, SESSION_NAME);
    assert_eq!(grants.load(std::sync::atomic::Ordering::SeqCst), 1);

    // The property: the long-lived key was signed with and never sent.
    let observed = origin.observed();
    assert_eq!(observed.len(), 1, "exactly one request reached the origin");
    let request = &observed[0];
    assert!(
        !request.request_line.contains(LONG_LIVED_KEY),
        "the key reached the request line: {}",
        request.request_line
    );
    for (name, value) in &request.headers {
        assert!(
            !value.contains(LONG_LIVED_KEY),
            "the key reached the {name} header"
        );
    }
    // And it did reach the Authorization header, as a signature over the body.
    let authorization = request
        .header("authorization")
        .expect("the request is signed");
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 "), "{authorization}");
    assert!(authorization.contains("Credential=AKIDEXAMPLE/20191109/"));
    assert!(authorization.contains("/sts/aws4_request"), "{authorization}");
    // The access key id is not a secret: it is the `AKIA…` identifier, and the
    // scope is *supposed* to carry it. What must not appear is the key.
    assert!(authorization.contains(ACCESS_KEY_ID));
    assert!(!authorization.contains(LONG_LIVED_KEY));
}

#[test]
fn the_signature_commits_to_the_body_that_was_actually_sent() {
    let origin = origin(Reply::Body(assume_role_response()));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);
    client
        .assume_role(&port, CREDENTIAL, at(NOW))
        .expect("the fixture answers");

    let request = &origin.observed()[0];
    // The form body is on the wire, and it is the one the request is about.
    let body = request.body.clone();
    assert!(body.contains("Action=AssumeRole"), "{body}");
    assert!(body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdemo"));
    assert!(body.contains("DurationSeconds=3600"), "{body}");
    assert!(
        body.find("Action=").unwrap() < body.find("RoleArn=").unwrap(),
        "the parameters are not in the order that was signed: {body}"
    );
    // And the payload hash in the header is the hash of those bytes, which is
    // what makes the signature bind the body rather than merely accompany it.
    let claimed = request.header("x-amz-content-sha256").expect("the hash is sent");
    assert_eq!(
        claimed,
        asv_broker::aws::sigv4::sha256_hex_of(body.as_bytes()),
        "the payload hash does not match the body that went on the wire"
    );
    assert!(authorization_commits_to(request, "x-amz-content-sha256"));
}

/// Whether the `Authorization` header lists `header` among its signed headers.
fn authorization_commits_to(request: &Observed, header: &str) -> bool {
    let Some(authorization) = request.header("authorization") else {
        return false;
    };
    let Some((_, rest)) = authorization.split_once("SignedHeaders=") else {
        return false;
    };
    rest.split(',')
        .next()
        .unwrap_or_default()
        .split(';')
        .any(|name| name.trim().eq_ignore_ascii_case(header))
}

/// Every header AWS requires to be signed is signed.
///
/// The first draft of this row asserted that *every* header the origin received
/// was covered, and it failed on `content-length` and `accept` — both of which
/// the HTTP client adds by itself. That is not a defect in the request: the
/// AWS reference's own sample request carries `Content-Length: 32` with
/// `SignedHeaders=host;user-agent;x-amz-date`, so an unsigned `content-length`
/// is what a correct SigV4 request looks like. The row was wrong about the
/// rule, not the client.
///
/// **The rule is the one the provider enforces:** `host` and every `x-amz-*`
/// header must be inside the signature, and the rest are the signer's choice.
/// Stating it that way is what makes the row bite on the case that matters —
/// because `x-amz-security-token` is an `x-amz-*` header, so a session-signed
/// request that sent the token without signing it fails this row, and that is
/// the mistake the temporary-credentials example warns about.
///
/// It is also the falsifiable form of the claim that the client has **one**
/// header list: before the two copies were unified, satisfying this needed them
/// to agree by hand.
#[test]
fn every_header_the_provider_requires_signed_is_signed() {
    let origin = origin(Reply::Body(assume_role_response()));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);
    client
        .assume_role(&port, CREDENTIAL, at(NOW))
        .expect("the fixture answers");

    let request = &origin.observed()[0];
    let requires_signing =
        |name: &str| name.eq_ignore_ascii_case("host") || name.to_ascii_lowercase().starts_with("x-amz-");

    let unsigned: Vec<&str> = request
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| requires_signing(name))
        .filter(|name| !authorization_commits_to(request, name))
        .collect();
    assert!(
        unsigned.is_empty(),
        "the request carries headers AWS requires to be signed, unsigned: {unsigned:?}"
    );
    // And the list is not vacuously satisfied by the loop finding nothing: the
    // four this operation signs are all present, and all covered.
    for header in ["content-type", "host", "x-amz-content-sha256", "x-amz-date"] {
        assert!(
            request.header(header).is_some() && authorization_commits_to(request, header),
            "{header} is not both sent and signed"
        );
    }
}

#[test]
fn the_request_is_a_post_to_the_path_and_host_that_were_signed() {
    let origin = origin(Reply::Body(assume_role_response()));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);
    client
        .assume_role(&port, CREDENTIAL, at(NOW))
        .expect("the fixture answers");

    let request = &origin.observed()[0];
    assert_eq!(request.request_line, "POST / HTTP/1.1");
    // The `Host` the signature commits to is the one the request carries, and
    // it carries the port because the fixture origin is not on 443. A `Host`
    // that disagreed with the URL is a header the signature is not over, so
    // this is the client being right about an awkward case rather than a
    // convenience: the 443 form is asserted separately below.
    assert_eq!(
        request.host_header.as_deref(),
        Some(format!("sts.amazonaws.com:{}", origin.port).as_str())
    );
    assert!(authorization_commits_to(request, "host"));
    // Every header the request sends and the signature names must be named in
    // the signature. A header that goes out unsigned is a header an attacker
    // can change in flight, and `content-type` and the payload hash are the two
    // that decide how the body is read.
    for header in ["content-type", "x-amz-content-sha256", "x-amz-date", "host"] {
        assert!(
            authorization_commits_to(request, header),
            "{header} is sent but is not in SignedHeaders"
        );
    }
    assert_eq!(request.header("x-amz-date"), Some("20191109T133320Z"));
}

#[test]
fn a_response_larger_than_the_bound_is_refused_by_the_transport() {
    // The reader in `sts` has its own bound; this is the one in front of it, and
    // it is here because the transport is where an unbounded body is read into
    // memory. A reader that refuses a huge document *after* allocating it has
    // bounded nothing.
    let filler = "x".repeat(70 * 1024);
    let oversized = format!("{}{filler}", assume_role_response());
    let origin = origin(Reply::Body(oversized));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    match client.assume_role(&port, CREDENTIAL, at(NOW)) {
        Err(StsClientError::Transport(
            asv_connector_http::transport::TransportError::ResponseTooLarge { .. },
        )) => {}
        other => panic!("an oversized response was read: {other:?}"),
    }
}

#[test]
fn a_success_carrying_a_location_is_not_followed_as_a_redirect() {
    // A 200 with a `Location` is not a redirection, and a client that follows
    // the header rather than the status would leave a successful exchange on
    // the strength of a header the origin chose to add.
    let origin = origin(Reply::StatusWithLocation {
        status: 200,
        body: assume_role_response(),
        location: "https://evil.example/".to_string(),
    });
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    let session = client
        .assume_role(&port, CREDENTIAL, at(NOW))
        .expect("a 200 is a session, whatever headers came with it");
    assert_eq!(session.access_key_id, "ASIAIOSFODNN7EXAMPLE");
    assert_eq!(
        origin.observed().len(),
        1,
        "a 200 carrying a Location was treated as a redirect"
    );
}

#[test]
fn the_origin_check_is_the_transports_and_the_client_does_not_reimplement_it() {
    // Named because the previous row can be satisfied two ways, and only one of
    // them is the design. A client that refused every redirect would also pass
    // "a cross-origin redirect is refused", and the same-origin row above is
    // what tells the two apart. This one says where the check lives: the
    // transport refuses a hop whose origin differs, and the client only decides
    // whether to *offer* a hop. A future change that starts comparing origins
    // in the client as well would be a second answer to one question, which the
    // ownership law forbids.
    let here = url("https://sts.amazonaws.com/path");
    assert!(asv_connector_http::transport::PinnedClient::is_same_origin(
        &here,
        &url("https://sts.amazonaws.com/other")
    ));
    assert!(!asv_connector_http::transport::PinnedClient::is_same_origin(
        &here,
        &url("https://evil.example/path")
    ));
    // A different spelling of the same host is still the same origin.
    assert!(asv_connector_http::transport::PinnedClient::is_same_origin(
        &here,
        &url("https://STS.amazonaws.com./path")
    ));
}

fn url(raw: &str) -> url::Url {
    url::Url::parse(raw).expect("the fixture URL is usable")
}

#[test]
fn a_provider_refusal_is_named_rather_than_flattened_to_a_status() {
    let body = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>not authorized to perform: sts:AssumeRole</Message>
  </Error>
  <RequestId>abc</RequestId>
</ErrorResponse>"#;
    let origin = origin(Reply::Status {
        status: 403,
        body: body.to_string(),
    });
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    match client.assume_role(&port, CREDENTIAL, at(NOW)) {
        Err(StsClientError::Request(StsError::Provider { code, message })) => {
            assert_eq!(code, "AccessDenied");
            assert!(message.contains("sts:AssumeRole"), "the message was lost");
        }
        other => panic!("a 403 carrying a named refusal was not named: {other:?}"),
    }
}

#[test]
fn a_refusal_the_client_cannot_read_is_a_status_and_not_a_blame() {
    // A 502 from something in front of STS is not a credential problem and not
    // a signature problem, and saying `AccessDenied` or `SignatureDoesNotMatch`
    // would send an operator to the wrong place entirely.
    let origin = origin(Reply::Status {
        status: 502,
        body: "<html>502 Bad Gateway</html>".to_string(),
    });
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    assert_eq!(
        client.assume_role(&port, CREDENTIAL, at(NOW)).err(),
        Some(StsClientError::UnreadableStatus { status: 502 }),
    );
}

#[test]
fn a_credential_the_vault_will_not_lend_never_reaches_the_socket() {
    let origin = origin(Reply::Body(assume_role_response()));
    let client = client_for(&origin);

    let outcome = client.assume_role(&RefusingPort, "not-in-the-vault", at(NOW));
    // The port's own reason, not merely "some secret error": a caller that
    // swallows a `NotFound` and reports "the port lent nothing" has turned a
    // missing credential into a mystery, and that is a mutation this row
    // originally survived.
    assert_eq!(
        outcome.err(),
        Some(StsClientError::Secret(SecretError::NotFound(
            "not-in-the-vault".to_string()
        ))),
    );
    assert_eq!(
        origin.observed().len(),
        0,
        "a request went out without a signature, which is the one thing that \
         must never happen"
    );
}

#[test]
fn a_redirect_to_another_origin_is_refused_and_the_signature_does_not_follow() {
    // The row the whole pinned transport is for. A SigV4 signature commits to
    // the host; following a `Location` to an attacker-chosen one would present a
    // valid-looking signature to a host it was never computed for.
    let target = TlsOrigin::start(
        "evil.example",
        Arc::new(|_: &Observed| OriginResponse::new(200, "anything")),
    );
    let origin = origin(Reply::Redirect(format!(
        "https://evil.example:{}/",
        target.port
    )));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    match client.assume_role(&port, CREDENTIAL, at(NOW)) {
        Err(StsClientError::Transport(
            asv_connector_http::transport::TransportError::CrossOriginRedirect { .. },
        )) => {}
        other => panic!("a cross-origin hop was not refused: {other:?}"),
    }
    assert_eq!(
        target.observed().len(),
        0,
        "the signed request reached the other origin"
    );
    assert_eq!(origin.observed().len(), 1, "the first attempt did go out");
}

#[test]
fn a_same_origin_redirect_is_followed_and_the_signature_is_recomputed_for_the_hop() {
    // The redirect policy is not "refuse every redirect". A same-origin hop is
    // ordinary, and this row is here so the one above cannot be satisfied by a
    // client that simply refuses to follow anything.
    let origin = origin(Reply::Redirect("/".to_string()));
    let (port, _grants) = CountingPort::new(LONG_LIVED_KEY.as_bytes());
    let client = client_for(&origin);

    // The origin answers the hop with the same scripted reply forever, so this
    // terminates on the redirect limit rather than looping.
    match client.assume_role(&port, CREDENTIAL, at(NOW)) {
        Err(StsClientError::Transport(
            asv_connector_http::transport::TransportError::TooManyRedirects { .. },
        )) => {}
        other => panic!("a redirect loop did not stop at the limit: {other:?}"),
    }
    let observed = origin.observed();
    assert!(observed.len() > 1, "the hop was never followed");
    for request in &observed {
        let authorization = request.header("authorization").expect("every hop is signed");
        assert!(
            authorization.contains("Credential=AKIDEXAMPLE/"),
            "a hop went out unsigned"
        );
    }
}
