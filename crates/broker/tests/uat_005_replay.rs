//! UAT-005 — placeholder replay outside the session.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`, gated by M4 per backlog
//! item `bl-bl-01M3KYNZMQ0003877X9M0FY740`):
//!
//! > Copy surrogate to:
//! > - ordinary shell outside ASV,
//! > - another ASV session,
//! > - direct provider request.
//! > Expected: provider rejects it; broker rejects wrong session.
//!
//! The three vectors fail for three different reasons, and that is the
//! whole point of the UAT. Testing one of them and calling the requirement
//! met is how a replay defence gets a false green.
//!
//! | Vector | Why it fails | Who enforces it |
//! |---|---|---|
//! | another ASV session | the surrogate is bound to the session that minted it | broker, in `redeem` |
//! | direct provider request | the surrogate is not a GitHub credential at all | GitHub, by construction |
//! | ordinary shell | the token is a bearer string, so a shell *can* present it | nobody — see below |
//!
//! # The honest part
//!
//! The third vector is not a defence and pretending otherwise would be the
//! most damaging thing this file could do. A surrogate is a bearer token:
//! copied into a shell it is still a string, and a string can be sent
//! anywhere. What makes it harmless is the *shape* of what it authorises —
//! it is accepted only by the broker, only for the session that minted it,
//! and it never authenticates to GitHub. The property worth asserting is
//! therefore "a replayed surrogate buys its holder nothing", not "a
//! replayed surrogate is rejected everywhere".
//!
//! The broker half of the "another session" vector is already covered by
//! `a_surrogate_from_another_session_of_the_same_peer_is_refused` in the
//! unit suite. It is repeated here at the integration level because UAT-005
//! is an end-to-end claim and the unit test does not exercise the provider
//! boundary.
//!
//! A live GitHub is deliberately not contacted. "The provider rejects it" is
//! established structurally — the surrogate is a distinct namespace of
//! random bytes that is never sent as `Authorization` — and a test that
//! needed a real provider would be a test that skips in CI.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_broker::{handle, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::fake_origin::{self, Observed, Reply};
use asv_connector_http::{Certificate, GithubClient, ResolvedAudience};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_vault::{KdfParams, VaultKey, VaultStore};

/// The real credential. It must never appear in anything an agent can see.
const CANARY: &str = "ghp_UAT005_real_credential_never_exposed";

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

struct Fixture {
    state: BrokerState,
    peer: WorkloadIdentity,
    origin: fake_origin::FakeOrigin,
    _dir: tempfile::TempDir,
}

/// `(fixture, session, surrogate)`.
fn live() -> (Fixture, AgentSessionId, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = VaultStore::create(
        dir.path().join("v.asv"),
        &secrecy::SecretString::from("uat005-pass".to_string()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");
    let key: VaultKey = store
        .header()
        .unlock(&secrecy::SecretString::from("uat005-pass".to_string()))
        .expect("unlock");

    let mut state = BrokerState::default();
    // The inventory is projected the way the broker projects it at startup,
    // from a record the vault actually holds. An earlier version of this
    // fixture seeded `state.credentials` directly through a test-only helper,
    // so the suite exercised a population path production never takes.
    const CRED: &str = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";
    let credential = CredentialId::from_wire(CRED).expect("canonical wire form");
    store
        .insert(
            &key,
            asv_vault::CredentialMetadata::new(
                CRED,
                "uat005",
                asv_vault::CredentialKind::Opaque,
                "github",
                "o",
                1,
            ),
            SecretBytes::new(CANARY.as_bytes().to_vec()),
        )
        .expect("insert");
    let loaded = asv_broker::inventory::load(&mut state, &store);
    assert_eq!(
        (loaded.loaded, loaded.skipped, loaded.collisions),
        (1, 0, 0),
        "the fixture vault holds exactly one canonical credential, so any other \
         count means the projection changed under this suite"
    );

    state.secrets = Some(Arc::new(VaultSecretPort::new(
        Arc::new(std::sync::Mutex::new(store)),
        Arc::new(key),
    )));

    let origin = fake_origin::start(Reply::Json(
        serde_json::json!({"number": 1, "title": "t", "body": "b", "state": "open"}).to_string(),
    ));
    state.connectors = Box::new(LocalFactory {
        resolved: ResolvedAudience {
            authority: Authority::canonicalize(&origin.certified_for).expect("authority"),
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
    peer.pin_pidfd().expect("pin self");
    let session = state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("/repo".into(), &peer);

    let minted = handle(
        &mut state,
        &peer,
        Request::MintSurrogate {
            session,
            credential,
            max_uses: 3,
            ttl_secs: 300,
        },
    );
    let surrogate = match minted {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("the fixture must mint, got {other:?}"),
    };

    (
        Fixture {
            state,
            peer,
            origin,
            _dir: dir,
        },
        session,
        surrogate,
    )
}

/// Vector 1: another ASV session. Already unit-covered; repeated here so
/// the UAT is end-to-end and so the provider boundary is part of the claim.
#[test]
fn a_surrogate_copied_into_another_session_buys_nothing() {
    let (mut fixture, _session, surrogate) = live();
    let other = fixture
        .state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("/other".into(), &fixture.peer);

    let response = handle(
        &mut fixture.state,
        &fixture.peer,
        Request::ReadIssue {
            session: other,
            surrogate: surrogate.clone(),
            repo: "o/r".into(),
            number: 1,
        },
    );

    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "a surrogate from another session must be denied, got {response:?}"
    );
    assert_eq!(
        fixture.origin.connections(),
        0,
        "the request reached the provider; the session binding is enforced in the \
         broker and the provider must never see a replayed token"
    );
}

/// Vector 2: direct provider request. The surrogate is presented to the
/// origin *instead of* a real credential, exactly as a copied token would
/// be, and the origin is a stand-in for GitHub's own validation.
#[test]
fn a_surrogate_sent_straight_to_the_provider_is_not_a_credential() {
    let (mut fixture, session, surrogate) = live();

    // Use the surrogate once legitimately, so we can see what the provider
    // actually received on the wire.
    let ok = handle(
        &mut fixture.state,
        &fixture.peer,
        Request::ReadIssue {
            session,
            surrogate: surrogate.clone(),
            repo: "o/r".into(),
            number: 1,
        },
    );
    assert!(
        matches!(ok, Response::IssueRead { .. }),
        "the legitimate use must succeed, or the capture below proves nothing: {ok:?}"
    );

    let sent: Vec<Observed> = fixture.origin.observed();
    let last = sent.last().expect("the origin saw a request");

    let auth = last
        .header("authorization")
        .expect("an authenticated request must carry Authorization");
    assert!(
        !auth.contains(&surrogate),
        "the surrogate reached the provider as a credential. This is the UAT's central \
         claim and it has just failed: {auth:?}"
    );
    assert!(
        auth.contains(CANARY),
        "the real credential is what the broker lent, so it must be present on the \
         wire; if it is not, the read did not authenticate and the assertion above is \
         vacuous. Got {auth:?}"
    );
}

/// Vector 3: the ordinary shell. Not a rejection — a demonstration that a
/// copied token is inert outside the broker.
#[test]
fn a_surrogate_in_an_ordinary_shell_is_inert() {
    let (_fixture, _session, surrogate) = live();

    // Structurally: the token's namespace is disjoint from a GitHub
    // credential's. A GitHub bearer token is `ghp_` + 36 base62 characters;
    // if the surrogate does not have that shape, presenting it to GitHub
    // cannot authenticate, and the "provider rejects it" clause of the UAT
    // holds without contacting anyone.
    assert!(
        !surrogate.starts_with("ghp_"),
        "the surrogate must not be mistakable for a GitHub credential: {surrogate}"
    );

    // And the broker is the only thing that accepts it, which is the
    // property that makes the shell case harmless. A token with no broker
    // behind it has no session, and therefore no authority.
    let mut without_broker = BrokerState::default();
    let orphan_peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    let response = handle(
        &mut without_broker,
        &orphan_peer,
        Request::ReadIssue {
            session: AgentSessionId::new(),
            surrogate,
            repo: "o/r".into(),
            number: 1,
        },
    );
    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "a token with no broker behind it must be denied, got {response:?}"
    );
}

/// The canary, the real credential, must not appear in anything a replaying
/// agent could observe: not the response, not the broker's `Debug`, not the
/// error messages a wrong-session replay produces.
#[test]
fn no_replay_path_exposes_the_real_credential() {
    let (mut fixture, _session, surrogate) = live();
    let other = fixture
        .state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("/other".into(), &fixture.peer);

    let response = handle(
        &mut fixture.state,
        &fixture.peer,
        Request::ReadIssue {
            session: other,
            surrogate,
            repo: "o/r".into(),
            number: 1,
        },
    );

    let rendered_response = format!("{response:?}");
    let rendered_state = format!("{:?}", fixture.state);
    assert!(
        !rendered_response.contains(CANARY),
        "the denial leaked the credential: {rendered_response}"
    );
    assert!(
        !rendered_state.contains(CANARY),
        "BrokerState::Debug leaked the credential: {rendered_state}"
    );
}

/// Vector 4 — the **success** path. Added because the leak assertions above
/// only ever ran against a request that was *refused*.
///
/// `no_replay_path_exposes_the_real_credential` renders the `Response` and
/// `BrokerState` after a denial, and a denial is the cheap case: the handler
/// returned early, so the credential was never lent and there was nothing to
/// leak. The path where a credential genuinely crosses into a request and a
/// real origin answers it is the one that had no leak assertion at all.
///
/// That is the shape of the gap this closes: the existing tests prove the
/// failure path is clean, and the success path was the one nobody looked at.
#[test]
fn a_successful_operation_leaks_the_credential_to_nothing_it_renders() {
    let (mut fixture, session, surrogate) = live();

    let response = handle(
        &mut fixture.state,
        &fixture.peer,
        Request::ReadIssue {
            session,
            surrogate,
            repo: "o/r".into(),
            number: 1,
        },
    );
    assert!(
        matches!(response, Response::IssueRead { .. }),
        "the legitimate operation must succeed, or the assertions below prove \
         nothing: {response:?}"
    );

    // The provider really was reached, so a credential really was lent. Without
    // this the leak assertions could be satisfied by a broker that never
    // touched the vault at all.
    assert_eq!(
        fixture.origin.connections(),
        1,
        "the origin saw no request, so nothing was lent and the leak \
         assertions below would be vacuous"
    );

    let rendered_response = format!("{response:?}");
    let rendered_state = format!("{:?}", fixture.state);
    assert!(
        !rendered_response.contains(CANARY),
        "a successful response carried the credential: {rendered_response}"
    );
    assert!(
        !rendered_state.contains(CANARY),
        "BrokerState::Debug carried the credential after a successful lend: \
         {rendered_state}"
    );
}

/// Vector 5 — the audit record of an operation that used a credential.
///
/// The argument for this is structural: `AuditEventDto` has no field that
/// could hold secret bytes, and the record is appended in the `handle`
/// wrapper so every variant is audited once. Both are good reasons, and both
/// are the kind of reason that stops being true when an enum grows a variant.
///
/// So this pins the shape *and* the content: the operation is recorded, the
/// record verifies against its own hash chain, and the serialized event does
/// not carry the credential.
#[test]
fn a_credentialed_operation_is_audited_without_the_credential() {
    let (mut fixture, session, surrogate) = live();

    let response = handle(
        &mut fixture.state,
        &fixture.peer,
        Request::ReadIssue {
            session,
            surrogate,
            repo: "o/r".into(),
            number: 1,
        },
    );
    assert!(
        matches!(response, Response::IssueRead { .. }),
        "the operation must succeed to be worth auditing: {response:?}"
    );

    let records = fixture
        .state
        .audit
        .lock()
        .expect("no test holds this")
        .query(0);
    assert!(
        !records.is_empty(),
        "a credentialed operation left no audit record, so the claim that the \
         broker records the operation without the secret is unfalsifiable"
    );

    // The record is a chain link, not a line in a log: a broker that wrote
    // the event could still have written it wrong.
    fixture
        .state
        .audit
        .lock()
        .expect("no test holds this")
        .verify()
        .expect("the audit chain verifies after a credentialed operation");

    // Serialized, not just held: an in-memory `Debug` is a different surface
    // from what the durable audit file will contain.
    for record in &records {
        let rendered = serde_json::to_string(&record.event).expect("the event serializes");
        assert!(
            !rendered.contains(CANARY),
            "an audit event carried the credential: {rendered}"
        );
    }

    // And the record is the *operation*, not a placeholder.
    let handled = records.iter().any(|r| {
        matches!(
            r.event,
            asv_ipc_protocol::AuditEventDto::RequestHandled { .. }
        )
    });
    assert!(
        handled,
        "no RequestHandled event among {records:?}: the operation was not \
         recorded as an operation"
    );
}
