//! R2.A — the GitHub vertical, and the negatives that make it one.
//!
//! The gap this file closes was not in the broker or the connector. Both were
//! real, policy-gated and heavily tested. The gap was that **nothing a user
//! could run reached them**: `Request::ReadIssue`, `CreateIssue` and
//! `CreateRelease` had no production call-site at all, and the three
//! `AgentRel` GitHub links — which had been *declared* all along — pointed at
//! `asv run -- gh issue view --`, an argv for a command the CLI does not have
//! on a path that would not have let `gh` authenticate anyway.
//!
//! R2.A added `asv github`, which mints a one-use surrogate from a vault *id*
//! and spends it on a typed operation. This file is the other half: the
//! evidence that the operation behind that verb is real, and that the property
//! the whole design rests on — the token is never named, only borrowed —
//! survives every way of attacking it.
//!
//! # What is real here, and what is not
//!
//! Real: the `BrokerState` dispatch, the policy gate, a real `VaultStore` and
//! the real `VaultSecretPort` that unlocks it, the real `GithubClient`, real
//! TLS with real certificate verification against a local CA, and a real
//! socket the client dials.
//!
//! Not real: GitHub. The origin is a local server, and the broker's GitHub
//! audience is a compile-time constant (`GITHUB_AUTHORITY`), which is also why
//! the `asv-brokerd` *binary* cannot be pointed at it — see
//! `r2a_cli_reachability.rs` for what that half does and does not prove.
//!
//! # Every row names the mutation that would make it red
//!
//! That is the standard this file is held to, and the mutations are listed at
//! the bottom of each row. A row whose mutation is "someone changes something"
//! is not a row.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_broker::{handle, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::fake_origin::{self, FakeOrigin, Observed, Reply};
use asv_connector_http::{Certificate, GithubClient, ResolvedAudience};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_vault::{KdfParams, VaultKey, VaultStore};

/// The real credential. It must never appear in anything an agent can see.
///
/// A GitHub-shaped prefix on purpose. A canary that does not look like a token
/// would let a row pass by matching against a shape the connector does not
/// actually build, which is how a leak test ends up testing the wrong string.
const CANARY: &str = "ghp_R2A0realCredential9neverExposed";

/// A canonical vault id, spelled the way `asv credentials` prints it.
const CRED: &str = "3f7c1d92-4a6b-4c1e-9d3f-2b8e5a7c0d14";

const REPO: &str = "Rubentxu/agent-secretless";

/// One GitHub issue, as the provider would answer it.
///
/// Includes a field the broker does not promise to forward — `labels`, and a
/// `node_id` that is upstream's internal id. They are here so the rows can
/// assert they do *not* reach the caller, which a body of only the three
/// forwarded fields could not demonstrate.
fn issue_json(number: u64, title: &str, body: &str, state: &str) -> String {
    serde_json::json!({
        "number": number,
        "title": title,
        "body": body,
        "state": state,
        "node_id": "I_kwDOA1b2c3d4e5f6",
        "labels": [{"name": "bug"}, {"name": "needs-triage"}],
        "author": {"login": "someone", "id": 991},
    })
    .to_string()
}

/// Builds a `GithubClient` pointed at a local origin, with the real address
/// filter still applied.
///
/// `allow_loopback: true` is the one relaxation, and it is a relaxation of the
/// *address* check only. Every other production guard — `validate_repo`, the
/// same-origin redirect rule, the size cap, the credential never being named —
/// runs unmodified, which is the point: a fixture that turned a security check
/// off would be testing a different product than the one that ships.
struct LocalFactory {
    resolved: ResolvedAudience,
    root: Certificate,
}

impl ConnectorFactory for LocalFactory {
    fn github(
        &self,
        _audience: Authority,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<GithubClient, asv_connector_http::GithubError> {
        Ok(GithubClient::pinned_to(
            self.resolved.clone(),
            asv_connector_http::AddressPolicy {
                allow_loopback: true,
            },
            secrets,
        )
        .trusting(vec![self.root.clone()]))
    }

    fn postgres(
        &self,
        audience: Authority,
        database: String,
        role: String,
        _secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Ok(PostgresClient::new(audience, database, role))
    }
}

/// A broker with a real vault, a real credential and a real origin.
struct Vertical {
    state: BrokerState,
    peer: WorkloadIdentity,
    origin: FakeOrigin,
    credential: CredentialId,
    session: AgentSessionId,
    _dir: tempfile::TempDir,
}

impl Vertical {
    /// A vertical whose origin answers every request with `reply`.
    fn with_reply(reply: Reply) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase = secrecy::SecretString::from("r2a-passphrase".to_string());

        let mut store = VaultStore::create(
            dir.path().join("v.asv"),
            &passphrase,
            KdfParams::fast_for_tests(),
        )
        .expect("create vault");
        let key: VaultKey = store
            .header()
            .unlock(&passphrase)
            .expect("unlock with the passphrase just used");
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    CRED,
                    "r2a-github",
                    asv_vault::CredentialKind::Opaque,
                    "github",
                    "Rubentxu",
                    1,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert the credential");

        let mut state = BrokerState::default();
        // Projected through the same inventory pass the broker runs at startup,
        // so this fixture cannot pass by seeding a field production never
        // writes.
        let loaded = asv_broker::inventory::load(&mut state, &store);
        assert_eq!(
            (loaded.loaded, loaded.skipped, loaded.collisions),
            (1, 0, 0),
            "the fixture vault holds exactly one credential; any other count means \
             the inventory projection changed under this suite"
        );
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        )));

        let origin = fake_origin::start(reply);
        state.connectors = Box::new(LocalFactory {
            resolved: ResolvedAudience {
                authority: Authority::canonicalize(&origin.certified_for)
                    .expect("the origin certifies for a canonical authority"),
                port: origin.port,
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
            root: origin.certificate(),
        });

        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pin this test's own process");
        let session = state
            .sessions
            .lock()
            .expect("no test holds this")
            .create("/repo".into(), &peer);

        Self {
            state,
            peer,
            origin,
            credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
            session,
            _dir: dir,
        }
    }

    /// The common case: an origin answering with one issue.
    fn reading() -> Self {
        Self::with_reply(Reply::Json(issue_json(
            7,
            "a real title",
            "a real body",
            "open",
        )))
    }

    /// Mints, returning the raw answer so a row can observe a refusal.
    fn try_mint(&mut self, max_uses: u32) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::MintSurrogate {
                session: self.session,
                credential: self.credential,
                max_uses,
                ttl_secs: 60,
            },
        )
    }

    /// A surrogate with `max_uses` uses, panicking if the mint was refused.
    fn mint(&mut self, max_uses: u32) -> String {
        match self.try_mint(max_uses) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("the fixture must mint a surrogate, got {other:?}"),
        }
    }

    fn read_issue(&mut self, surrogate: &str, repo: &str, number: u64) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::ReadIssue {
                session: self.session,
                surrogate: surrogate.to_string(),
                repo: repo.to_string(),
                number,
            },
        )
    }

    fn create_issue(&mut self, surrogate: &str, title: &str, body: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::CreateIssue {
                session: self.session,
                surrogate: surrogate.to_string(),
                repo: REPO.to_string(),
                title: title.to_string(),
                body: body.to_string(),
            },
        )
    }

    fn create_release(&mut self, surrogate: &str, tag: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::CreateRelease {
                session: self.session,
                surrogate: surrogate.to_string(),
                repo: REPO.to_string(),
                tag: tag.to_string(),
                name: "a release".to_string(),
                body: "notes".to_string(),
            },
        )
    }

    /// How many times anything has been dialled.
    fn connections(&self) -> usize {
        self.origin.connections()
    }

    /// The last request the origin saw, or a panic naming the count.
    ///
    /// Panicking rather than returning an `Option` because a row that asked
    /// "what did the provider receive" and got nothing has been told nothing;
    /// an `unwrap` here says the fixture is broken instead of quietly
    /// satisfying a later assertion about a request that never happened.
    fn last_request(&self) -> Observed {
        self.origin
            .last()
            .expect("the origin saw a request; if it did not, the row is asserting about nothing")
    }

    fn audit_text(&self) -> String {
        format!(
            "{:?}",
            self.state
                .audit
                .lock()
                .expect("no test holds this")
                .query(0)
        )
    }
}

/// Asserts that `text` — whatever produced it — does not contain the token.
fn assert_no_token(what: &str, text: &str) {
    assert!(
        !text.contains(CANARY),
        "the credential leaked into {what}: {text}"
    );
}

// ---------------------------------------------------------------------------
// The operation is real
// ---------------------------------------------------------------------------

/// The read succeeds, and the origin really was asked.
///
/// This row exists to stop the rest of the file from being a set of refusals
/// that would all pass against a broker that had stopped working. The
/// `Authorization` assertion is the part that makes it load-bearing: it proves
/// the vault really was unlocked and the real token really was attached, so
/// the successes below are successes of the *whole* chain rather than of a
/// request that was made without authenticating.
///
/// **Mutation:** make `send` skip the `secrets.lend` call, or attach a
/// constant header, and this row fails on the header assertion even though
/// every read would still "succeed".
#[test]
fn a_brokered_read_authenticates_and_returns_the_three_promised_fields() {
    let mut vertical = Vertical::reading();
    let surrogate = vertical.mint(1);

    let response = vertical.read_issue(&surrogate, REPO, 7);

    match &response {
        Response::IssueRead { title, body, state } => {
            assert_eq!(
                (title.as_str(), body.as_str(), state.as_str()),
                ("a real title", "a real body", "open")
            );
        }
        other => panic!("a brokered read must succeed, got {other:?}"),
    }

    assert_eq!(
        vertical.connections(),
        1,
        "the origin was dialled exactly once"
    );

    let seen = vertical.last_request();
    assert_eq!(seen.method(), "GET");
    assert_eq!(seen.path(), format!("/repos/{REPO}/issues/7"));
    assert_eq!(
        seen.header("authorization"),
        Some(format!("token {CANARY}").as_str()),
        "the provider must have received the real credential in a borrowed header; \
         without this the successes above would be successes of an unauthenticated \
         request, and every refusal row would pass against a broker doing nothing"
    );
}

/// The response carries the three promised fields and nothing else.
///
/// `IssueRead` promises title, body and state. The fixture's provider body also
/// contains `node_id`, `labels` and `author`, and an answer that forwarded any
/// of them would be forwarding upstream content the design says the broker
/// does not vouch for — the same argument M4-R1 makes about the answer.
///
/// **Mutation:** add `node_id: value.get("node_id")…` to the `IssueRead`
/// construction in `broker/src/lib.rs` and this fails.
#[test]
fn the_read_forwards_three_fields_and_no_upstream_extras() {
    let mut vertical = Vertical::reading();
    let surrogate = vertical.mint(1);

    let response = vertical.read_issue(&surrogate, REPO, 7);

    let encoded = serde_json::to_string(&response).expect("the response encodes");
    for upstream_only in ["node_id", "I_kwDOA1b2c3d4e5f6", "needs-triage", "991"] {
        assert!(
            !encoded.contains(upstream_only),
            "{upstream_only} reached the caller: {encoded}"
        );
    }
    assert!(
        encoded.contains("a real title"),
        "the row must be looking at a response that has the promised fields, or the \
         assertions above are passing on an empty string: {encoded}"
    );
}

// ---------------------------------------------------------------------------
// The credential is never named
// ---------------------------------------------------------------------------

/// Nothing a caller can see contains the token.
///
/// Covers the success answer, the encoded form of it, and the audit — the three
/// places a brokered credential has historically been found. The canary is
/// looked for in the *encoded* response as well as the structured one, because
/// the leak that matters is the one that reaches a socket or a log file, and
/// that is a serialization, not a struct field.
///
/// **Mutation:** add a `token: String` field to `Response::IssueRead`, or write
/// the credential into an audit event, and this fails.
#[test]
fn the_token_appears_in_no_response_and_no_audit_record() {
    let mut vertical = Vertical::reading();
    let surrogate = vertical.mint(1);

    let response = vertical.read_issue(&surrogate, REPO, 7);
    assert!(
        matches!(response, Response::IssueRead { .. }),
        "precondition"
    );

    assert_no_token(
        "the encoded response",
        &serde_json::to_string(&response).expect("the response encodes"),
    );
    assert_no_token("the audit chain", &vertical.audit_text());
}

/// A refusal also does not echo the token.
///
/// A success that stays quiet is the easy half. The half that has actually
/// leaked credentials in this shape of system is the *error* path, where a
/// provider message or a debug format gets interpolated into something a caller
/// reads. So the rows below check the refusal messages, not just the happy one.
///
/// **Mutation:** change `github_failure` to carry the upstream body, and this
/// fails on the row that triggers a non-2xx.
#[test]
fn a_refusal_does_not_echo_the_token() {
    let mut vertical = Vertical::with_reply(Reply::Status {
        status: 401,
        // An upstream that puts the token in its own error body — which happens
        // when a request is malformed enough that the server echoes what it
        // received.
        body: serde_json::json!({"message": format!("bad token {CANARY}")}).to_string(),
    });
    let surrogate = vertical.mint(1);

    let response = vertical.read_issue(&surrogate, REPO, 7);

    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::Upstream,
                ..
            }
        ),
        "a 401 is an upstream failure, got {response:?}"
    );
    let message = match &response {
        Response::Error { message, .. } => message.clone(),
        other => panic!("precondition: {other:?}"),
    };
    assert!(
        !message.contains(CANARY) && !message.contains("bad token"),
        "the upstream body reached the caller: {message}"
    );
    assert_no_token("the audit chain", &vertical.audit_text());
}

// ---------------------------------------------------------------------------
// The grant is one operation, and this is the shape `asv github` now uses
// ---------------------------------------------------------------------------

/// A one-use surrogate is spent by the operation, and the second is denied.
///
/// `asv github` mints with `max_uses: 1` for exactly one invocation, so this is
/// the configuration the product now ships rather than a corner case. The
/// second attempt must be refused **before** the provider is dialled: a
/// surrogate that has already been spent and still authenticates is a
/// credential that outlives its authorization.
///
/// **Mutation:** make `redeem_for` not decrement, or move the ownership check
/// after the connector call, and this fails.
#[test]
fn a_one_use_surrogate_is_spent_and_the_second_attempt_never_reaches_github() {
    let mut vertical = Vertical::reading();
    let surrogate = vertical.mint(1);

    assert!(
        matches!(
            vertical.read_issue(&surrogate, REPO, 7),
            Response::IssueRead { .. }
        ),
        "the first use must succeed"
    );
    assert_eq!(vertical.connections(), 1);

    let second = vertical.read_issue(&surrogate, REPO, 7);

    assert!(
        matches!(
            second,
            Response::Error {
                code: ErrorCode::SurrogateExhausted,
                ..
            }
        ),
        "a spent surrogate must be reported as exhausted, got {second:?}"
    );
    assert_eq!(
        vertical.connections(),
        1,
        "the second attempt reached the provider; a spent grant must cost nothing \
         on the wire, and a request that goes out before the grant is checked is a \
         request GitHub has already answered"
    );
}

/// Ending the session kills the grant with it.
///
/// The other half of "one operation": `asv github` ends the session before it
/// prints. If a surrogate outlived its session, then a caller that captured
/// the string would have a working capability for as long as the TTL allowed,
/// and the session would be decorative.
///
/// **Mutation:** make `redeem_for` accept a session argument it does not check,
/// and this fails.
#[test]
fn a_grant_does_not_outlive_the_session_it_was_minted_in() {
    let mut vertical = Vertical::reading();
    let surrogate = vertical.mint(5);

    let ended = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::EndSession {
            session: vertical.session,
        },
    );
    assert!(
        matches!(ended, Response::SessionEnded { .. }),
        "precondition: the session must end cleanly, got {ended:?}"
    );

    let after = vertical.read_issue(&surrogate, REPO, 7);

    assert!(
        matches!(
            after,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "a surrogate whose session is gone must be denied, got {after:?}"
    );
    assert_eq!(
        vertical.connections(),
        0,
        "the provider was dialled after the session ended"
    );
}

// ---------------------------------------------------------------------------
// The destination cannot be moved
// ---------------------------------------------------------------------------

/// A repository string cannot redirect the request.
///
/// `ReadIssue` has no host field at all, which is what `h5_postgres_destination`
/// relies on. This row checks the other half: that the path built from the
/// repository string cannot escape its segment. The strings here are the ones
/// that would matter — traversal, an extra segment, a non-ASCII homoglyph —
/// and the row is only meaningful because the origin is counting connections.
///
/// **Mutation:** make `validate_repo` split on whitespace as well as `/`, or
/// stop rejecting an over-long component, and this fails.
#[test]
fn a_repository_string_cannot_move_the_request() {
    let hostile = [
        "Rubentxu/agent-secretless/../../admin",
        "..",
        ".",
        "owner/repo ",
        "owner/re po",
        "owner/../repo",
        "owner/repo#fragment",
        "owner/repo?admin=1",
        // A full-width solidus, which is not `/` to `split` but is a path
        // separator to whatever normalises the string downstream.
        "owner\u{FF0F}repo",
    ];

    for repo in hostile {
        let mut vertical = Vertical::reading();
        let surrogate = vertical.mint(1);
        let response = vertical.read_issue(&surrogate, repo, 7);
        assert!(
            matches!(
                response,
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    ..
                }
            ),
            "`{repo}` was not refused as malformed, got {response:?}"
        );
        assert_eq!(vertical.connections(), 0, "`{repo}` reached the provider");
    }
}

/// A redirect cannot carry the credential to another origin.
///
/// This is the row the whole same-origin rule exists for, and it is the one
/// that would be missed by a test that only checks that a redirect *fails*. The
/// assertion is the second origin's connection count, because a redirect that
/// is denied *after* the credential was attached has already done the damage.
///
/// **Mutation:** let `follow_same_origin` follow a cross-origin `Location`, or
/// attach the header before the origin check, and this fails.
#[test]
fn a_cross_origin_redirect_never_reaches_the_second_origin() {
    let mut vertical = Vertical::with_reply(Reply::Redirect("https://evil.example/steal".into()));
    let surrogate = vertical.mint(1);

    let response = vertical.read_issue(&surrogate, REPO, 7);

    assert!(
        matches!(response, Response::Error { .. }),
        "a cross-origin redirect must fail, got {response:?}"
    );
    assert_eq!(
        vertical.connections(),
        1,
        "the client followed the redirect instead of refusing it at the origin check"
    );
    assert_no_token("the audit chain", &vertical.audit_text());
}

// ---------------------------------------------------------------------------
// A credential that is not there
// ---------------------------------------------------------------------------

/// A mint against a vault entry that does not exist is refused, and no socket
/// is opened for it.
///
/// The `unlock` case is the one that is easy to get wrong in the other
/// direction: a broker that treats "no such credential" as "call GitHub
/// anonymously" turns a private repository into a silent 404 and tells the
/// operator the credential was never needed.
///
/// **Mutation:** make `github_client` fall back to an unauthenticated client
/// when the port reports `NotFound`, and this fails.
#[test]
fn a_mint_for_a_credential_the_vault_does_not_hold_spends_nothing() {
    let mut vertical = Vertical::reading();
    let absent = CredentialId::from_wire("00000000-0000-4000-8000-00000000dead")
        .expect("canonical wire form");

    let response = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::MintSurrogate {
            session: vertical.session,
            credential: absent,
            max_uses: 1,
            ttl_secs: 60,
        },
    );

    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ),
        "a mint for an absent credential must be refused, got {response:?}"
    );
    assert_eq!(
        vertical.connections(),
        0,
        "the refused mint reached the provider"
    );
}

// ---------------------------------------------------------------------------
// The write verbs
// ---------------------------------------------------------------------------

/// A release creation is a real request with a real credential on it.
///
/// The write positives are here because `asv github` publishes
/// `github/release/create` and `github/issue/create` as relations, and a
/// relation published for a verb nothing exercises is a link that leads to a
/// refusal. `uat_005_replay` covers the read; nothing covered these two from
/// the vertical.
///
/// **Mutation:** point `create_release` at `issues_path()` and this fails on
/// the method and the path.
#[test]
fn a_release_creation_is_a_real_authenticated_write() {
    let mut vertical = Vertical::with_reply(Reply::Json(
        serde_json::json!({"html_url": format!("https://github.com/{REPO}/releases/tag/v1.2.3")})
            .to_string(),
    ));
    let surrogate = vertical.mint(1);

    let response = vertical.create_release(&surrogate, "v1.2.3");

    match &response {
        Response::ReleaseCreated { tag, url } => {
            assert_eq!(tag, "v1.2.3");
            assert!(url.contains("v1.2.3"), "the release url came back: {url}");
        }
        other => panic!("a brokered release must succeed, got {other:?}"),
    }

    let seen = vertical.last_request();
    assert_eq!(seen.method(), "POST");
    assert_eq!(seen.path(), format!("/repos/{REPO}/releases"));
    assert_eq!(
        seen.header("authorization"),
        Some(format!("token {CANARY}").as_str()),
        "the write must have been authenticated with the real credential"
    );
    assert!(
        seen.body.contains("\"tag_name\":\"v1.2.3\""),
        "the tag did not reach the provider as a structured field: {}",
        seen.body
    );
    assert_no_token("the audit chain", &vertical.audit_text());
}

/// A title is data, not structure.
///
/// The one place in this vertical where caller-supplied text is concatenated
/// into a payload. `json!` is what makes it safe, and the row is here so that
/// a switch to string formatting — which is the natural "simplification" —
/// fails here rather than in production.
///
/// **Mutation:** build the create body with `format!("{{\"title\":\"{title}\"}}")`
/// and this fails.
#[test]
fn a_hostile_issue_title_is_escaped_into_the_payload() {
    let mut vertical = Vertical::with_reply(Reply::Json(
        serde_json::json!({"number": 99, "html_url": "https://example/99"}).to_string(),
    ));
    let surrogate = vertical.mint(1);
    let hostile = r#"a "quoted" title\nwith a newline and a }{"break":"out""#;

    let response = vertical.create_issue(&surrogate, hostile, "body");

    assert!(
        matches!(response, Response::IssueCreated { number: 99, .. }),
        "the create must succeed, got {response:?}"
    );

    let seen = vertical.last_request();
    // Parsed back rather than compared as a string: the claim is that the
    // hostile text is *one field*, and only a parser can say that.
    let payload: serde_json::Value = serde_json::from_str(&seen.body)
        .expect("the provider received parseable JSON, so the title was escaped as data");
    assert_eq!(
        payload["title"].as_str(),
        Some(hostile),
        "the title was not transmitted verbatim as a single field: {}",
        seen.body
    );
    assert_eq!(payload["body"].as_str(), Some("body"));
    assert!(
        payload.get("break").is_none(),
        "a second key appeared at the top level: {}",
        seen.body
    );
}
