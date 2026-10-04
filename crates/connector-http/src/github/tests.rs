//! UAT-007 — cross-origin redirect.
//! `a_cross_origin_redirect_never_sends_the_credential_to_the_target` and
//! `a_cross_origin_redirect_never_reaches_the_other_origin`: a redirect is not a licence to
//! present the credential to whoever asked for it.
//! Tests for the semantic GitHub surface.
//!
//! These run against a real TLS origin with a real certificate, because the
//! claims being checked are about what goes on the wire: that the credential
//! arrives as an `Authorization` header, that a cross-origin hop never carries
//! it, and that nothing the broker returns contains it.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use super::*;
use crate::fake_origin::{self, Reply};
use crate::transport::ResolvedAudience;
use zeroize::Zeroize;

/// A port that records every request it lends a credential to.
///
/// The recording is the point of the type: `with_credential` is the only way
/// to reach a secret here, and this records that the read happened per
/// attempt rather than once per operation.
struct RecordingPort {
    /// The bytes this port will lend. Distinct from any real credential so a
    /// leak in a test failure is unmistakable.
    secret: String,
    /// Every `credential` name it was asked for, in order.
    lent: Mutex<Vec<String>>,
}

impl RecordingPort {
    fn new(secret: &str) -> Arc<Self> {
        Arc::new(Self {
            secret: secret.to_string(),
            lent: Mutex::new(Vec::new()),
        })
    }

    fn read_count(&self) -> usize {
        self.lent.lock().expect("uncontended").len()
    }
}

impl SecretPort for RecordingPort {
    /// A fixture holding nothing derived, so a deletion has nothing to drop.
    ///
    /// Written out rather than left to a default, because the trait requires
    /// this on purpose: a port that never considered revocation is the exact
    /// shape of bug that made `DeleteCredential` a no-op for cached tokens.
    fn forget(&self, _credential: &str) {}

    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        self.lent
            .lock()
            .expect("uncontended")
            .push(credential.to_string());
        sink.accept(self.secret.as_bytes())
    }
}

/// A port that refuses every credential, standing in for an unlock failure.
struct ClosedPort;

impl SecretPort for ClosedPort {
    /// A fixture holding nothing derived, so a deletion has nothing to drop.
    ///
    /// Written out rather than left to a default, because the trait requires
    /// this on purpose: a port that never considered revocation is the exact
    /// shape of bug that made `DeleteCredential` a no-op for cached tokens.
    fn forget(&self, _credential: &str) {}

    fn lend(&self, credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::Unavailable(credential.to_string()))
    }
}

/// A port that has no such credential, as distinct from one that cannot open
/// it. The two must stay tellable apart: the broker answers them differently.
struct AbsentPort;

impl SecretPort for AbsentPort {
    /// A fixture holding nothing derived, so a deletion has nothing to drop.
    ///
    /// Written out rather than left to a default, because the trait requires
    /// this on purpose: a port that never considered revocation is the exact
    /// shape of bug that made `DeleteCredential` a no-op for cached tokens.
    fn forget(&self, _credential: &str) {}

    fn lend(&self, credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::NotFound(credential.to_string()))
    }
}

/// A client pointed at a live fake origin, with the loopback address allowed.
///
/// `AddressPolicy { allow_loopback: true }` is a test-only setting. The
/// production path leaves it off, which is the whole reason these tests are
/// explicit about turning it on.
fn client_for(origin: &fake_origin::FakeOrigin, port: Arc<dyn SecretPort>) -> GithubClient {
    let resolved = ResolvedAudience {
        authority: Authority::canonicalize(&origin.certified_for).expect("a valid authority"),
        port: origin.port,
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    GithubClient::pinned_to(
        resolved,
        AddressPolicy {
            allow_loopback: true,
        },
        port,
    )
    .trusting(vec![origin.certificate()])
}

fn issue_body() -> String {
    serde_json::json!({
        "number": 7,
        "title": "the title",
        "body": "the body",
        "state": "open",
        // Fields the broker does not promise to forward. If one of these turns
        // up in an `IssueSummary`, the read is leaking more than M4-R9 allows.
        "labels": ["bug", "urgent"],
        "assignee": { "login": "someone" },
        "author_association": "MEMBER",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// validate_repo
// ---------------------------------------------------------------------------

/// The repository string is attacker-supplied and becomes part of a URL path.
/// Every way of smuggling a path separator, a traversal segment, a query, a
/// fragment or a percent-encoded byte has to be refused before it is joined.
#[test]
fn a_repository_reference_cannot_escape_its_path_segment() {
    for hostile in [
        "",
        "/",
        "owner",
        "owner/",
        "/repo",
        "a/b/c",
        "a/b/../c",
        "owner/..",
        "owner/.",
        "../..",
        "owner/repo?admin=true",
        "owner/repo#frag",
        "owner/repo%2f..%2fadmin",
        "owner/re po",
        "owner/repo\nX-Injected: 1",
        "owner/re:po",
        "owner/re\\po",
        "owner/../other",
        "öwner/repo",
        "owner/repo/../../etc/passwd",
    ] {
        assert!(
            validate_repo(hostile).is_err(),
            "{hostile:?} must be refused"
        );
    }
}

/// The positive cases, so the refusal set above is not passing because the
/// parser refuses everything.
#[test]
fn an_ordinary_repository_reference_is_accepted() {
    for good in [
        "rubentxu/agent-secretless",
        "a/b",
        "owner.name/repo_name",
        "owner/repo.js",
        "A1/b2",
    ] {
        assert!(validate_repo(good).is_ok(), "{good:?} must be accepted");
    }
}

/// A component over GitHub's own limit is refused before it reaches a URL.
#[test]
fn an_over_long_repository_component_is_refused() {
    let long = "a".repeat(101);
    assert!(validate_repo(&format!("owner/{long}")).is_err());
    assert!(validate_repo(&format!("{long}/repo")).is_err());
    // Exactly at the limit is fine, which is what makes the limit a boundary
    // rather than a blanket refusal.
    let at_limit = "a".repeat(100);
    assert!(validate_repo(&format!("owner/{at_limit}")).is_ok());
}

/// The path is assembled from the validated parts, so the shapes the three
/// operations use are pinned here rather than discovered through a live server.
#[test]
fn each_operation_targets_the_documented_github_path() {
    let repo = validate_repo("owner/name").expect("valid");
    assert_eq!(repo.issue_path(7), "/repos/owner/name/issues/7");
    assert_eq!(repo.issues_path(), "/repos/owner/name/issues");
    assert_eq!(repo.releases_path(), "/repos/owner/name/releases");
}

// ---------------------------------------------------------------------------
// read_issue
// ---------------------------------------------------------------------------

/// M4-R9's happy path, over real TLS with a real certificate: three fields
/// come back and the credential is on the wire exactly once.
#[test]
fn reading_an_issue_returns_the_three_promised_fields() {
    let origin = fake_origin::start(Reply::Json(issue_body()));
    let port = RecordingPort::new("canary-read-9f2a");
    let client = client_for(&origin, port.clone());

    let summary = client
        .read_issue("cred-1", "owner/repo", 7)
        .expect("the read succeeds");

    assert_eq!(summary.title, "the title");
    assert_eq!(summary.body, "the body");
    assert_eq!(summary.state, "open");

    // The credential reached the origin as an `Authorization` header.
    let seen = origin.last().expect("the origin saw a request");
    assert_eq!(
        seen.header("authorization"),
        Some("token canary-read-9f2a"),
        "the real credential must be the one sent upstream"
    );
    assert_eq!(seen.method(), "GET");
    assert_eq!(seen.path(), "/repos/owner/repo/issues/7");
    assert_eq!(port.read_count(), 1, "one read for one operation");
}

/// M4-R1's forward direction: the *answer* must not carry the credential. The
/// summary is built from three named fields, so this also proves nothing else
/// rides along.
#[test]
fn a_read_answer_carries_no_credential_and_no_extra_fields() {
    let origin = fake_origin::start(Reply::Json(issue_body()));
    let port = RecordingPort::new("canary-answer-31cc");
    let client = client_for(&origin, port.clone());

    let summary = client
        .read_issue("cred-1", "owner/repo", 7)
        .expect("the read succeeds");

    let rendered = format!("{summary:?}");
    assert!(
        !rendered.contains("canary-answer-31cc"),
        "the credential leaked into the answer: {rendered}"
    );
    // The upstream body's other fields are simply not part of the type.
    for absent in ["labels", "assignee", "author_association", "urgent"] {
        assert!(
            !rendered.contains(absent),
            "{absent} must not be forwarded: {rendered}"
        );
    }
    let _ = port;
}

/// A `null` body is a real GitHub answer for an issue with no description. The
/// read must succeed and report it as empty rather than fail.
#[test]
fn a_null_issue_body_reads_as_empty_rather_than_failing() {
    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({ "title": "t", "body": null, "state": "closed" }).to_string(),
    ));
    let client = client_for(&origin, RecordingPort::new("canary-null"));

    let summary = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect("a null body is not a failure");
    assert_eq!(summary.body, "");
    assert_eq!(summary.state, "closed");
}

/// An upstream that omits a promised field is an error, not a silently empty
/// answer. Returning `""` for a missing `state` would let an agent read
/// "closed" and "the field did not exist" as the same thing.
#[test]
fn a_missing_promised_field_is_an_error_rather_than_an_empty_answer() {
    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({ "title": "t", "body": "b" }).to_string(),
    ));
    let client = client_for(&origin, RecordingPort::new("canary-missing"));

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a missing state is not a successful read");
    assert!(
        matches!(error, GithubError::Upstream { ref detail, .. } if detail == "state"),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// M4-R5: the credential never crosses an origin
// ---------------------------------------------------------------------------

/// The load-bearing test for M4-R5. The credential must not reach the second
/// origin, and the second origin must not even be contacted: the denial happens
/// before the hop, not after it.
#[test]
fn a_cross_origin_redirect_never_sends_the_credential_to_the_target() {
    let attacker = fake_origin::start(Reply::Body("stolen".to_string()));
    let source = fake_origin::start(Reply::Redirect(format!(
        "https://api.github.com:{}/collect",
        attacker.port
    )));
    let port = RecordingPort::new("canary-cross-origin-77a1");
    let client = client_for(&source, port.clone());

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a cross-origin hop must be denied");

    assert!(
        matches!(
            error,
            GithubError::Transport(TransportError::CrossOriginRedirect { .. })
        ),
        "got {error:?}"
    );
    assert_eq!(
        attacker.connections(),
        0,
        "the cross-origin host must never receive a connection, let alone a credential"
    );
    // The credential was read once, for the first attempt, and only that.
    assert_eq!(port.read_count(), 1);
}

/// A same-origin hop is followed, and the credential is re-read for it. D8
/// wants the read per operation; a hop is a separate request, so it gets its
/// own read. What it must never do is inherit the first attempt's header
/// silently, and re-reading is what makes that observable.
#[test]
fn a_same_origin_hop_is_followed_with_a_fresh_credential_read() {
    let origin = fake_origin::start(Reply::Sequence(vec![
        Reply::Redirect("/repos/owner/repo/issues/7/moved".to_string()),
        Reply::Json(issue_body()),
    ]));
    let port = RecordingPort::new("canary-same-origin-4d5e");
    let client = client_for(&origin, port.clone());

    let summary = client
        .read_issue("cred-1", "owner/repo", 7)
        .expect("a same-origin hop is permitted");

    assert_eq!(summary.title, "the title");
    assert_eq!(
        port.read_count(),
        2,
        "one read per attempt, not per operation"
    );
    assert_eq!(
        origin.observed().len(),
        2,
        "both attempts reached the origin"
    );
    // Every attempt carried the credential, including the hop.
    for seen in origin.observed() {
        assert_eq!(
            seen.header("authorization"),
            Some("token canary-same-origin-4d5e")
        );
    }
}

// ---------------------------------------------------------------------------
// create operations
// ---------------------------------------------------------------------------

/// An issue is created with a real POST body, and the answer is only the two
/// promised fields.
#[test]
fn creating_an_issue_posts_the_title_and_body_and_returns_its_identity() {
    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({
            "number": 42,
            "html_url": "https://github.com/owner/repo/issues/42",
            "title": "stored",
        })
        .to_string(),
    ));
    let client = client_for(&origin, RecordingPort::new("canary-create-0a3f"));

    let created = client
        .create_issue("cred-1", "owner/repo", "the title", "the body")
        .expect("the create succeeds");

    assert_eq!(created.number, 42);
    assert_eq!(created.url, "https://github.com/owner/repo/issues/42");

    let seen = origin.last().expect("the origin saw a request");
    assert_eq!(seen.method(), "POST");
    assert_eq!(seen.path(), "/repos/owner/repo/issues");
    assert_eq!(
        seen.header("authorization"),
        Some("token canary-create-0a3f")
    );
    let body: serde_json::Value = serde_json::from_str(&seen.body).expect("a JSON body");
    assert_eq!(body["title"], "the title");
    assert_eq!(body["body"], "the body");
}

/// Agent-supplied text is data, not JSON structure. A title containing a quote
/// and a brace must arrive as one string, not as two keys.
#[test]
fn an_agent_supplied_title_cannot_break_out_of_the_json_body() {
    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({ "number": 1, "html_url": "u" }).to_string(),
    ));
    let client = client_for(&origin, RecordingPort::new("canary-inject-6b7c"));

    let hostile = r#"a","admin":true,"x":"#;
    client
        .create_issue("cred-1", "owner/repo", hostile, "body")
        .expect("the create succeeds");

    let seen = origin.last().expect("the origin saw a request");
    let body: serde_json::Value = serde_json::from_str(&seen.body).expect("a JSON body");
    assert_eq!(
        body.as_object().map(|o| o.len()),
        Some(2),
        "the body must have exactly the two keys the operation sets: {body}"
    );
    assert_eq!(body["title"], hostile);
    assert!(
        body.get("admin").is_none(),
        "an injected key must not become part of the request"
    );
}

/// A release echoes the tag back, because GitHub does not always echo it and
/// an agent that asked for `v1` needs to be told `v1`.
#[test]
fn creating_a_release_reports_the_tag_that_was_requested() {
    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({ "html_url": "https://github.com/owner/repo/releases/tag/v1" })
            .to_string(),
    ));
    let client = client_for(&origin, RecordingPort::new("canary-release-2e8f"));

    let created = client
        .create_release("cred-1", "owner/repo", "v1", "First", "notes")
        .expect("the create succeeds");

    assert_eq!(created.tag, "v1");
    let seen = origin.last().expect("the origin saw a request");
    assert_eq!(seen.path(), "/repos/owner/repo/releases");
    let body: serde_json::Value = serde_json::from_str(&seen.body).expect("a JSON body");
    assert_eq!(body["tag_name"], "v1");
}

// ---------------------------------------------------------------------------
// failure paths
// ---------------------------------------------------------------------------

/// M4-R6: if the credential cannot be unlocked, the operation fails. It must
/// not proceed unauthenticated, and the origin must see nothing.
#[test]
fn an_unlockable_credential_fails_the_operation_without_contacting_the_origin() {
    let origin = fake_origin::start(Reply::Json(issue_body()));
    let client = client_for(&origin, Arc::new(ClosedPort));

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a closed port cannot authenticate a read");
    // The port's `SecretError` reaches the caller as its own variant rather
    // than as a transport failure: no request was made, so "the wire said no"
    // would be a lie, and the broker needs `NotFound` and `Unavailable` to be
    // tellable apart without parsing a message.
    assert!(
        matches!(error, GithubError::Secret(SecretError::Unavailable(_))),
        "got {error:?}"
    );
    // And the re-worded error must not carry the credential's own name: the
    // port named it, and a name in an error string is a name in a log.
    assert!(
        !error.to_string().contains("cred-1"),
        "the credential name leaked into {error:?}"
    );
    assert_eq!(
        origin.connections(),
        0,
        "an unauthenticated read must not reach the provider"
    );
}

/// A missing credential is a different answer from a locked one, and the two
/// have to be distinguishable without reading a message.
#[test]
fn a_missing_credential_is_reported_as_missing_not_as_a_transport_failure() {
    let origin = fake_origin::start(Reply::Json(issue_body()));
    let client = client_for(&origin, Arc::new(AbsentPort));

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a vault with no such credential cannot authenticate a read");
    assert!(
        matches!(error, GithubError::Secret(SecretError::NotFound(_))),
        "got {error:?}"
    );
    assert_eq!(origin.connections(), 0);
}

/// The `Authorization` header is built in a `Zeroizing` buffer, so the token
/// does not outlive the request in freed heap.
///
/// Asserted on the *type* rather than on the bytes that were in it. Reading
/// the buffer after the drop would be undefined behaviour, and an allocator is
/// under no obligation to hand the same pages back: a test that passed on one
/// run and failed on the next would be worse than no test. What can be
/// checked, and what this checks, is that the value handed to reqwest is the
/// scrubbing wrapper rather than a plain `String` — a `String` satisfies every
/// other test in this file, so nothing else would notice the difference.
#[test]
fn the_authorization_header_is_wrapped_so_it_is_scrubbed_on_drop() {
    const SECRET: &str = "canary-zeroize-6f1d";

    let header: Zeroizing<String> =
        authorization_header(SECRET.as_bytes()).expect("a utf-8 secret is usable");
    // The value is right...
    assert_eq!(&*header, format!("token {SECRET}").as_str());
    // ...and it is the scrubbing wrapper, checked through a generic bound that
    // `String` does not satisfy. This is the whole assertion; the drop below is
    // there so the claim is about a value that has actually been dropped.
    fn assert_scrubs_on_drop<T: Zeroize>(_: &T) {}
    assert_scrubs_on_drop(&header);
    drop(header);
}

/// A 404 is reported as a failure with its status, not as an empty issue.
#[test]
fn an_upstream_error_status_is_not_reported_as_a_successful_read() {
    // The body carries a marker that must not appear in the error. A provider
    // body is attacker-influenced content by definition: anything GitHub
    // chooses to put in an error, it also puts there for a request an agent
    // made. Relaying it turns an error report into a channel, and this is the
    // assertion that would notice.
    const CANARY_IN_BODY: &str = "MUST-NOT-BE-RELAYED-4c8e";
    let origin = fake_origin::start(Reply::Status {
        status: 404,
        body: format!(r#"{{"message":"Not Found","detail":"{CANARY_IN_BODY}"}}"#),
    });
    let client = client_for(&origin, RecordingPort::new("canary-404"));

    let error = client
        .read_issue("cred-1", "owner/repo", 999)
        .expect_err("a 404 is not a read");
    assert!(
        matches!(
            error,
            GithubError::Transport(TransportError::RequestFailed { .. })
        ),
        "got {error:?}"
    );
    // The status is reported, because that is the actionable part...
    assert!(
        error.to_string().contains("404"),
        "the status must be reported: {error}"
    );
    // ...and the body is not, at either `Display` or `Debug`. A `Debug` that
    // leaked would be the worse of the two, because a panic message or a
    // `tracing` field prints it without anybody choosing to.
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains(CANARY_IN_BODY),
            "the provider's body was relayed: {rendered}"
        );
    }
}

/// A response body past the cap is refused. The agent gets an error, not a
/// truncated field that looks like real data.
#[test]
fn an_oversized_upstream_body_is_refused_rather_than_buffered() {
    let huge = "x".repeat((MAX_RESPONSE_BYTES + 1024) as usize);
    let origin = fake_origin::start(Reply::Json(format!(
        r#"{{"title":"t","body":"{huge}","state":"open"}}"#
    )));
    let client = client_for(&origin, RecordingPort::new("canary-huge"));

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a body past the cap is refused");
    assert!(
        matches!(
            error,
            GithubError::Transport(TransportError::ResponseTooLarge { .. })
        ),
        "got {error:?}"
    );
}

/// A hostile `Location` is not turned into a hop. The origin check in
/// `follow_same_origin` is what decides, and a `Location` this code cannot
/// parse is a denial rather than a best guess.
#[test]
fn a_redirect_without_a_usable_location_is_denied() {
    let origin = fake_origin::start(Reply::StatusWithoutLocation { status: 302 });
    let client = client_for(&origin, RecordingPort::new("canary-noloc"));

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a redirect with no Location is a dead end");
    assert!(
        matches!(error, GithubError::Transport(TransportError::RequestFailed { ref reason, .. })
            if reason.contains("302") && reason.contains("Location")),
        "got {error:?}"
    );
}

/// The credential is read once per attempt, so a redirect budget blow-up does
/// not become a credential-read amplification.
#[test]
fn a_redirect_loop_stops_on_the_hop_budget_rather_than_the_credential() {
    let origin = fake_origin::start(Reply::Redirect("/loop".to_string()));
    let port = RecordingPort::new("canary-loop-1a2b");
    let client = client_for(&origin, port.clone());

    let error = client
        .read_issue("cred-1", "owner/repo", 1)
        .expect_err("a redirect loop must terminate");

    assert!(
        matches!(
            error,
            GithubError::Transport(TransportError::TooManyRedirects { .. })
        ),
        "got {error:?}"
    );
    assert_eq!(
        port.read_count(),
        crate::transport::MAX_REDIRECTS + 1,
        "exactly one credential read per permitted attempt"
    );
}

// ---------------------------------------------------------------------------
// structural claims
// ---------------------------------------------------------------------------

/// D2's one-way dependency, as an executable claim: this crate must not be
/// able to open a vault. If someone adds `asv-vault` here to "just reach the
/// secret directly", this test is the thing that has to be deleted, and the
/// deletion is visible in review.
#[test]
fn this_crate_has_no_vault_dependency() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("the manifest is readable");
    assert!(
        !text.contains("asv-vault"),
        "asv-vault must stay out of the connector: the secret reaches it through SecretPort"
    );
}

/// Guards the harness. If `FakeOrigin` stopped answering, every test above
/// could pass for the wrong reason.
#[test]
fn the_fake_origin_really_serves_the_json_it_was_given() {
    let origin = fake_origin::start(Reply::Json(issue_body()));
    let client = client_for(&origin, RecordingPort::new("canary-harness"));

    let summary = client
        .read_issue("cred-1", "owner/repo", 7)
        .expect("the harness answers");
    assert_eq!(summary.title, "the title");
    assert!(origin.connections() >= 1);
    let seen = origin.last().expect("the harness recorded the request");
    assert_eq!(seen.method(), "GET");
    assert!(
        seen.header("authorization").is_some(),
        "a silent Observed would make every header assertion vacuous"
    );
}
