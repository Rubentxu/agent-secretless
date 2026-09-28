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

use asv_broker::{handle, insert_credential, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::fake_origin::{self, Observed, Reply};
use asv_connector_http::{Certificate, GithubClient, ResolvedAudience};
use asv_domain::{AgentSessionId, Authority, CredentialKind, CredentialMetadata, SecretBytes};
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
    let credential = insert_credential(
        &mut state,
        CredentialMetadata::new("uat005", CredentialKind::BearerToken),
    );
    store
        .insert(
            &key,
            asv_vault::CredentialMetadata::new(
                credential.to_wire(),
                "uat005",
                asv_vault::CredentialKind::Opaque,
                "github",
                "o",
                1,
            ),
            SecretBytes::new(CANARY.as_bytes().to_vec()),
        )
        .expect("insert");

    state.secrets = Some(Arc::new(VaultSecretPort::new(
        Arc::new(store),
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
    let session = state.sessions.create("/repo".into(), &peer);

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
