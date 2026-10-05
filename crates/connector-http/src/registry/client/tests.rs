//! Rows for the registry request loop that need no socket.
//!
//! The rows that do need one live in `wire_tests`, and the split is the same
//! one the transport uses: a mock cannot tell you whether a header survived a
//! handshake, and a handshake cannot tell you whether a scope was widened
//! before it was put on the wire.

use super::*;
use crate::transport::{AddressPolicy, PinnedClient, ResolvedAudience};
use asv_domain::Authority;

/// A reference is interpolated into a URL path, so a reference that could
/// step out of its own repository is a pull from somewhere else.
///
/// Mutation: drop the character checks, or check only for `/`.
#[test]
fn a_reference_cannot_step_out_of_its_own_repository() {
    for hostile in [
        "..",
        "../blobs/sha256:0",
        "latest/../other",
        "latest/../../v2/admin/manifests/x",
        "/absolute",
        "a b",
        "latest?x=1",
        "latest#f",
        "latest%2f..",
        "..;x",
    ] {
        assert!(
            ImageReference::parse(hostile).is_err(),
            "{hostile:?} must not become a reference"
        );
    }
    for legal in ["latest", "v1.2.3", "main-line", "_underscore", "a", "0"] {
        assert!(
            ImageReference::parse(legal).is_ok(),
            "{legal:?} is a legal tag"
        );
    }
}

/// A digest is content-addressed, so a malformed one is a lookup that would
/// either fail at the registry or, worse, address a blob the caller did not
/// name. Uppercase is refused as well: `sha256` digests are lowercase hex, and
/// accepting both would mean two spellings of one address.
///
/// Mutation: accept any `sha256:` prefix, or allow uppercase hex.
#[test]
fn a_digest_reference_is_a_real_sha256_and_nothing_else() {
    let good = "sha256:".to_string() + &"a".repeat(64);
    assert!(matches!(
        ImageReference::parse(&good),
        Ok(ImageReference::Digest(_))
    ));
    for hostile in [
        String::from("sha256:"),
        String::from("sha256:abc"),
        format!("sha256:{}", "a".repeat(63)),
        format!("sha256:{}", "a".repeat(65)),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "g".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
    ] {
        assert!(
            ImageReference::parse(&hostile).is_err(),
            "{hostile} must be refused"
        );
    }
    // The reason `sha512:` is refused is the rule above it: a name containing
    // the digest separator is a digest, and this one is not one.
    assert!(matches!(
        ImageReference::parse(&format!("sha512:{}", "a".repeat(64))),
        Err(ReferenceError::MalformedDigest)
    ));
}

/// The over-long reference is refused for a reason of its own, so a row about
/// tag grammar cannot satisfy it by accident.
///
/// Mutation: drop the length check, or return the tag error for it.
#[test]
fn an_over_long_reference_is_refused_as_a_length() {
    let long = "a".repeat(MAX_REFERENCE_LENGTH + 1);
    assert!(matches!(
        ImageReference::parse(&long),
        Err(ReferenceError::TooLong {
            len,
            max: MAX_REFERENCE_LENGTH
        }) if len == MAX_REFERENCE_LENGTH + 1
    ));
    assert!(ImageReference::parse(&"a".repeat(MAX_REFERENCE_LENGTH)).is_ok());
}

/// The path is built from the two checked halves and nothing else, so there is
/// no third spelling a caller could get in.
///
/// Mutation: build the path by concatenating a caller-supplied string.
#[test]
fn the_manifest_path_is_built_from_the_two_checked_halves() {
    let repository = RepositoryName::parse("library/alpine").expect("valid");
    for (reference, expected) in [
        ("latest", "/v2/library/alpine/manifests/latest"),
        (
            &format!("sha256:{}", "b".repeat(64)),
            &format!("/v2/library/alpine/manifests/sha256:{}", "b".repeat(64)),
        ),
    ] {
        let reference = ImageReference::parse(reference).expect("valid");
        assert_eq!(manifest_path(&repository, &reference), expected);
    }
}

/// The mutation to read first in this file. The query string is what the token
/// endpoint actually sees, so this is where the challenge's `scope` would leak
/// into a request if anywhere did.
///
/// Mutation: pass `challenge.requested_scope()` instead of `asked`.
#[test]
fn the_token_query_carries_the_asked_scope_and_not_the_challenges() {
    let repository = RepositoryName::parse("library/alpine").expect("valid");
    let asked = scope_to_request(RegistryOperation::Pull, &repository);

    // The challenge Docker Hub actually sends, read for its scope.
    let challenge = BearerChallenge::parse(
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull,push""#,
    )
    .expect("reads");
    assert_eq!(
        challenge.requested_scope(),
        Some("repository:library/alpine:pull,push"),
        "the fixture only means something while the challenge still asks for both"
    );

    let query = token_query(challenge.service(), &asked);
    assert_eq!(
        query,
        vec![
            ("service".to_string(), "registry.docker.io".to_string()),
            (
                "scope".to_string(),
                "repository:library/alpine:pull".to_string()
            ),
        ]
    );
    assert!(
        !query.iter().any(|(_, v)| v.contains("push")),
        "the challenge's extra action must not reach the token endpoint: {query:?}"
    );
}

/// A push asks for a push and a pull for a pull, and the two never share a
/// query string.
///
/// Mutation: have `token_query` append every action.
#[test]
fn the_token_query_names_the_operation_and_not_the_operation_set() {
    let repository = RepositoryName::parse("library/alpine").expect("valid");
    for (operation, action) in [
        (RegistryOperation::Pull, "pull"),
        (RegistryOperation::Push, "push"),
    ] {
        let asked = scope_to_request(operation, &repository);
        let query = token_query(None, &asked);
        assert_eq!(
            query,
            vec![(
                "scope".to_string(),
                format!("repository:library/alpine:{action}")
            )]
        );
    }
}

/// The push body is the agent's data and it is forwarded whole, byte for byte.
///
/// This row is here rather than in `wire_tests` because of how it was found.
/// It started as a wire row comparing the body the fake origin recorded, and
/// the campaign turned it green under a mutation that re-encodes the body with
/// `String::from_utf8_lossy` -- because the fixture reads bodies as text, so the
/// row and the mutation were lossy in the same way and agreed with each other.
/// The fix is not a stricter comparison on a lossy reading; it is to read the
/// bytes out of the built request, where they are still bytes.
///
/// Mutation: `String::from_utf8_lossy(body).as_bytes().to_vec()` in `build_request`.
#[test]
fn a_push_body_reaches_the_request_byte_for_byte() {
    let body = vec![0x1fu8, 0x00, 0xff, 0xfe, b'{', b'}', 0xc3, 0x28];
    let client = pinned_client();
    let request = build_request(
        &client,
        &loopback_audience(),
        reqwest::Method::PUT,
        &manifest_path(&repository(), &reference()),
        Some(&body),
        None,
    )
    .expect("a request is built");

    let sent = request
        .body()
        .expect("a PUT with a body carries one")
        .as_bytes()
        // A body that arrived as a stream rather than as bytes is a body this
        // row cannot read, and an unread body is a body nobody checked.
        .expect("the body is bytes rather than a stream");
    assert_eq!(sent, body.as_slice(), "the body was changed on the way out");
}

/// And the bearer is attached only when there is a token, which is the pair
/// that matters: a header always present spends a credential on requests
/// nobody authenticated.
///
/// Mutation: build the header unconditionally.
#[test]
fn the_bearer_is_attached_only_when_there_is_a_token() {
    let client = pinned_client();
    let path = manifest_path(&repository(), &reference());

    let anonymous = build_request(
        &client,
        &loopback_audience(),
        reqwest::Method::GET,
        &path,
        None,
        None,
    )
    .expect("built");
    assert_eq!(
        anonymous.headers().get(reqwest::header::AUTHORIZATION),
        None
    );

    let authenticated = build_request(
        &client,
        &loopback_audience(),
        reqwest::Method::GET,
        &path,
        None,
        Some("issued-token"),
    )
    .expect("built");
    assert_eq!(
        authenticated
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer issued-token")
    );
}

/// A client for the rows above. Building it resolves nothing and connects to
/// nothing: `PinnedClient::build` only vets the addresses it is handed.
fn pinned_client() -> PinnedClient {
    PinnedClient::build(
        &loopback_audience(),
        AddressPolicy {
            allow_loopback: true,
        },
    )
    .expect("a pinned client builds")
}

fn loopback_audience() -> ResolvedAudience {
    ResolvedAudience {
        authority: Authority::canonicalize("localhost.test").expect("a two-label name"),
        port: 443,
        addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
    }
}

fn repository() -> RepositoryName {
    RepositoryName::parse("library/alpine").expect("valid")
}

fn reference() -> ImageReference {
    ImageReference::parse("latest").expect("valid")
}
