//! H3 — three of the thirteen Cedar actions never reached the engine.
//!
//! `POLICY_TEXT` names thirteen actions. Three of them were never handed to
//! `PolicyEngine::authorize` anywhere in production code:
//!
//! | action | evaluated where |
//! |---|---|
//! | `github_issue_read` | `authorize_surrogate_mint`, for a `Generic` credential |
//! | `github_issue_create` | **nowhere** |
//! | `github_release_create` | **nowhere** |
//! | `postgres_connect` | **nowhere** |
//! | `postgres_read` | `authorize_surrogate_mint` (Database) and `pg_policy::classify` |
//! | the four other `postgres_*` write verbs | `pg_policy::classify` |
//!
//! The four `postgres.authorize` call sites in the broker are the mint gate, the
//! statement gate, the audit explanation, and the bridge's own `ConnectPolicy`
//! — which is a different type and names no Cedar action. `Request::PostgresConnect`
//! called `authorize_postgres`, which checks ownership and whether a vault is
//! open, and then went straight to `postgres_connect`.
//!
//! # What the mint gate does and does not substitute for
//!
//! H2 put one `policy.authorize` call at mint, using the **read** verb as the
//! representative, and the comment beside it said:
//!
//! > The per-verb decisions still happen at the operation itself, where the
//! > verb is known exactly.
//!
//! That is the claim this file falsifies. On the GitHub path the per-verb
//! decision did not happen at the operation — it did not happen at all. So an
//! operator who permitted `github_issue_read` and denied `github_issue_create`
//! got a token and then, with it, an issue creation the policy had refused.
//!
//! Under the **default** policy nothing here is observable: the default permits
//! the GitHub trio and `postgres_connect` unconditionally. The failure is
//! silent, and it only bites an operator who has tightened the policy — which
//! is the posture the spec tells them to adopt. That is why every case below
//! installs a policy that is narrower than the default.
//!
//! # The control, and why it is a positive assertion
//!
//! Each deny case is paired with a permit case on the *same* fixture, and the
//! permit case does not assert `code != Denied`. It asserts that the request
//! reached the connector factory, detected by a marker string the fake factory
//! puts in its error. A `Denied` in a deny case that could also be explained by
//! a closed vault, a wrong fixture or a malformed request would pass for the
//! wrong reason; a marker only appears if the request survived the gate.
//!
//! Nothing here touches the network. The factory refuses before any I/O, and
//! the PostgreSQL control never gets past the missing-runtime check, so the
//! suite is hermetic and deterministic in both directions.

use std::sync::Arc;

use asv_broker::{handle, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::{GithubClient, GithubError, SecretPort};
use asv_domain::{AgentSessionId, Authority, CredentialId, CredentialKind, CredentialMetadata};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_policy::PolicyEngine;
use asv_vault::{KdfParams, VaultKey, VaultStore};
use secrecy::SecretString;

/// The marker the fake factory puts in its refusal.
///
/// Asserted positively: a response carrying this string is a request that got
/// past the policy gate and into the connector. Anything else on the permit
/// arm is a failure, because a hermetic fixture has exactly one way to reach
/// the factory.
const REACHED_THE_FACTORY: &str = "h3-probe: the request left the policy gate";

/// Permits exactly one verb. Narrower than the default on purpose, because the
/// default permits everything these tests are about to forbid.
const READ_ONLY: &str = r#"
permit (principal, action == Action::"github_issue_read", resource is Api);
permit (principal, action == Action::"postgres_read", resource is Database);
"#;

/// The control policy's twin: a read permit *plus* nothing else, so a
/// `Database`-class token can be minted and then offered to GitHub.
const READ_ONLY_NO_GITHUB: &str = r#"
permit (principal, action == Action::"postgres_read", resource is Database);
"#;

/// Forbids everything.
///
/// `forbid` rather than an empty set: an empty set also denies, but an explicit
/// rule is one the engine demonstrably evaluated, so a failure here is evidence
/// about the gate rather than about a missing policy.
const DENY_EVERYTHING: &str = "forbid(principal, action, resource);";

/// Permits the database read verb and the connect verb, and nothing else.
///
/// `postgres_connect` is in here so that the *other* test can remove exactly
/// one permit and watch the connect stop working.
const PG_WITH_CONNECT: &str = r#"
permit (principal, action == Action::"postgres_connect", resource is Database);
permit (principal, action == Action::"postgres_read", resource is Database);
"#;

/// The same policy with the connect permit deleted.
///
/// One rule removed, everything else identical. This is the shape an operator
/// uses when they want to stop a session from opening a socket at all.
const PG_WITHOUT_CONNECT: &str = r#"
permit (principal, action == Action::"postgres_read", resource is Database);
"#;

/// A factory that refuses every GitHub request with a recognisable marker.
///
/// It is installed instead of the live factory so that "the request reached the
/// connector" is decidable without a network, and so a test can never pass by
/// accident because GitHub happened to be slow.
struct GateProbe;

impl ConnectorFactory for GateProbe {
    fn github(
        &self,
        _audience: Authority,
        _secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError> {
        Err(GithubError::Upstream {
            audience: "gate-probe".into(),
            detail: REACHED_THE_FACTORY.into(),
        })
    }
}

struct Harness {
    state: BrokerState,
    peer: WorkloadIdentity,
    session: AgentSessionId,
    credential: CredentialId,
    /// Held so the vault file outlives the broker that reads it.
    _dir: tempfile::TempDir,
}

/// A broker with a real vault, a real pinned session, one credential, and a
/// connector that reports whether anything reached it.
fn harness(kind: CredentialKind) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let passphrase = SecretString::from("h3-vault-passphrase".to_string());
    let store = VaultStore::create(
        dir.path().join("v.asv"),
        &passphrase,
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");
    let key: VaultKey = store.header().unlock(&passphrase).expect("unlock");

    let mut state = BrokerState::default();
    // A vault is open but empty. Nothing in this file lends a secret: the deny
    // cases are refused before the vault is consulted, and the permit cases are
    // answered by the factory, which refuses before it would lend. An empty
    // vault therefore cannot be the explanation for any assertion here, and a
    // `None` would have been — which is exactly the vacuous pass to avoid.
    state.secrets = Some(Arc::new(VaultSecretPort::new(
        Arc::new(std::sync::Mutex::new(store)),
        Arc::new(key),
    )));
    state.connectors = Box::new(GateProbe);

    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("the test pins its own process");
    let session = state.sessions.create("/repo".to_string(), &peer);

    let metadata = CredentialMetadata::new("h3-gate", kind);
    let credential = metadata.id;
    state.credentials.push(metadata);

    Harness {
        state,
        peer,
        session,
        credential,
        _dir: dir,
    }
}

impl Harness {
    fn policy(&mut self, text: &str) {
        self.state.policy =
            PolicyEngine::from_policy_text(text).expect("the fixture policy is valid");
    }

    /// Asks for a surrogate and returns the raw answer.
    ///
    /// Separate from [`Self::mint`] because the mint gate has a deny arm of
    /// its own, and a test that needs to observe that refusal must not go
    /// through a helper that panics on it.
    fn try_mint(&mut self) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::MintSurrogate {
                session: self.session,
                credential: self.credential,
                max_uses: 4,
                ttl_secs: 300,
            },
        )
    }

    fn mint(&mut self) -> String {
        match self.try_mint() {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("the fixture must mint, or no case below means anything: {other:?}"),
        }
    }

    fn read_issue(&mut self, surrogate: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::ReadIssue {
                session: self.session,
                surrogate: surrogate.into(),
                repo: "acme/app".into(),
                number: 7,
            },
        )
    }

    fn create_issue(&mut self, surrogate: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::CreateIssue {
                session: self.session,
                surrogate: surrogate.into(),
                repo: "acme/app".into(),
                title: "t".into(),
                body: "b".into(),
            },
        )
    }

    fn create_release(&mut self, surrogate: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::CreateRelease {
                session: self.session,
                surrogate: surrogate.into(),
                repo: "acme/app".into(),
                tag: "v1".into(),
                name: "n".into(),
                body: "b".into(),
            },
        )
    }

    fn postgres_connect(&mut self) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PostgresConnect {
                session: self.session,
                host: "db.internal".into(),
                host_addr: "127.0.0.1".into(),
                port: 5432,
                database: "app".into(),
                role: "readonly".into(),
            },
        )
    }
}

/// Asserts a denial that names the verb the operator refused.
///
/// The verb is asserted, not just the code. `Denied` is what a closed vault, a
/// session the peer does not own and a spent surrogate all answer, so the code
/// alone cannot tell this refusal from any of those. The message is what makes
/// the refusal attributable to the policy.
fn assert_policy_denial(response: Response, verb: &str) {
    match response {
        Response::Error { code, message } => {
            assert_eq!(
                code,
                ErrorCode::Denied,
                "the refusal must be Denied: {message}"
            );
            assert!(
                message.contains(verb),
                "the refusal must name the refused verb `{verb}`, or an operator \
                 cannot tell which rule fired. Got: {message}"
            );
        }
        other => panic!("expected a policy denial for {verb}, got {other:?}"),
    }
}

/// Asserts the request got past the gate and into the connector.
///
/// A positive assertion on purpose. `code != Denied` would also be satisfied by
/// a broker that had no vault, a malformed request, or a fixture that never
/// minted; the marker appears only if the operation ran.
fn assert_reached_the_connector(response: Response) {
    match response {
        Response::Error { message, .. } => assert!(
            message.contains(REACHED_THE_FACTORY),
            "the request should have reached the connector factory. Got: {message}"
        ),
        other => panic!(
            "expected the factory's refusal, meaning the request passed the gate, got {other:?}"
        ),
    }
}

// --- GitHub: the per-verb decision that never happened ---------------------

/// The control for all three GitHub cases.
///
/// Under the **default** policy every verb of the trio reaches the connector.
/// If this fails, the denials below would be explicable by a fixture that
/// cannot perform a GitHub operation at all.
#[test]
fn the_default_policy_permits_every_github_verb() {
    let mut h = harness(CredentialKind::GenericSecret);
    let surrogate = h.mint();

    assert_reached_the_connector(h.read_issue(&surrogate));
    assert_reached_the_connector(h.create_issue(&surrogate));
    assert_reached_the_connector(h.create_release(&surrogate));
}

/// A read-only policy must not yield an issue creation.
///
/// This is the scenario M6-R5 states for the database and that the GitHub path
/// never got. The policy permits reading and says nothing else, so issuance
/// succeeds and the creation is the operation the operator refused.
#[test]
fn a_policy_that_permits_read_only_refuses_issue_create() {
    let mut h = harness(CredentialKind::GenericSecret);
    h.policy(READ_ONLY);
    let surrogate = h.mint();

    // The read arm is the control for this exact policy: it is permitted, so
    // it must still work while the creation is refused.
    assert_reached_the_connector(h.read_issue(&surrogate));
    assert_policy_denial(h.create_issue(&surrogate), "github.issue.create");
}

/// The same policy, the other write verb.
#[test]
fn a_policy_that_permits_read_only_refuses_release_create() {
    let mut h = harness(CredentialKind::GenericSecret);
    h.policy(READ_ONLY);
    let surrogate = h.mint();

    assert_policy_denial(h.create_release(&surrogate), "github.release.create");
}

/// A `Database`-class token is the one case where the read verb at mint and
/// the verb at the operation differ, so it is the only way to observe the
/// `github_issue_read` arm of the operation gate at all.
///
/// The mint evaluates `postgres_read`, which the policy permits. The operation
/// evaluates `github_issue_read`, which it does not. Without an evaluation
/// point at the operation the token would have been accepted and dialled.
#[test]
fn a_database_surrogate_cannot_reach_a_verb_the_policy_does_not_permit() {
    let mut h = harness(CredentialKind::DatabaseCredential);
    h.policy(READ_ONLY_NO_GITHUB);
    let surrogate = h.mint();

    assert_policy_denial(h.read_issue(&surrogate), "github.issue.read");
}

// --- PostgreSQL: the permit rule that was never consulted ------------------

/// The control for the two connect cases.
#[test]
fn the_default_policy_permits_the_postgres_connect() {
    let mut h = harness(CredentialKind::DatabaseCredential);
    h.policy(PG_WITH_CONNECT);

    // Not `Upstream`-shaped by accident either: with no runtime installed the
    // connect stops at the runtime check, which is the last thing before any
    // I/O. Whatever it answers, it is not the policy.
    match h.postgres_connect() {
        Response::Error { message, .. } => assert!(
            !message.contains("policy"),
            "the permitted connect must not be refused by policy: {message}"
        ),
        other => panic!("unexpected success from a broker with no runtime: {other:?}"),
    }
}

/// Deleting one `permit` line must stop the connect.
///
/// `PG_WITHOUT_CONNECT` differs from `PG_WITH_CONNECT` by exactly one rule.
/// The statement path is unaffected, which is the point: a `Database` class
/// token still mints and a query is still evaluated, so the refusal below is
/// the connect gate and not a fixture that stopped working.
#[test]
fn removing_the_connect_permit_stops_the_connect() {
    let mut h = harness(CredentialKind::DatabaseCredential);
    h.policy(PG_WITHOUT_CONNECT);

    assert_policy_denial(h.postgres_connect(), "postgres.connect");
}

/// The sanity check on the deny harness itself.
///
/// With `forbid` installed, a mint is refused. This guards the other direction
/// of vacuity: if a policy engine in this fixture stopped evaluating anything,
/// this test would go red and the connect denial above would be known to be
/// about the connect rather than about a gate that answers `Allow` to
/// everything.
#[test]
fn a_policy_that_forbids_everything_stops_the_mint() {
    let mut h = harness(CredentialKind::GenericSecret);
    h.policy(DENY_EVERYTHING);

    assert_policy_denial(h.try_mint(), "github.issue.read");
}
