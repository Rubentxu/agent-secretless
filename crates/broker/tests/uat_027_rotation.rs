//! UAT-027 / M4-R7 — secret rotation under a live session.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`):
//!
//! > Rotate underlying token while session/policy references stable
//! > credential ID. Expected: subsequent operations use new token without
//! > modifying agent config.
//!
//! And M4-S7, which states the same thing as a broker property:
//!
//! > **Given** a live session referencing a credential ID
//! > **When** the underlying token is rotated
//! > **Then** subsequent operations use the new token unchanged in agent config
//!
//! # Why this needs its own test
//!
//! Rotation is claimed structurally, by design decision D8: the broker stores
//! a `CredentialId` and re-reads the secret per operation through
//! `VaultStore::with_secret`. If that claim is true there is no cache to
//! invalidate and no surrogate to reissue — rotation is a vault-level event
//! the agent never observes.
//!
//! That claim is easy to assert and easy to quietly break. A future change
//! that cached the decrypted token, or that pinned a surrogate to secret
//! material instead of to the id, would leave every other M4 test green while
//! silently violating R7. This file is the one that goes red when that
//! happens.
//!
//! # What "the agent did not have to change" is measured as
//!
//! The test holds the *same* surrogate value across the rotation and reads
//! the `Authorization` header the origin actually received, before and after.
//! Two failure modes are separated by that observation:
//!
//! - the broker kept using the old token → the second read still carries
//!   `OLD_TOKEN`;
//! - rotation invalidated the session or the surrogate → the second read
//!   fails outright rather than returning a body.
//!
//! Both are visible from the origin side, without trusting broker internals.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_broker::ConnectorFactory;
use asv_broker::{handle, insert_credential, BrokerState, VaultSecretPort};
use asv_connector_http::fake_origin::{self, Reply};
use asv_connector_http::{AddressPolicy, GithubClient, ResolvedAudience};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialKind, CredentialMetadata, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{Request, Response};
use asv_vault::{KdfParams, VaultKey, VaultStore};
use secrecy::SecretString;

/// The token the vault holds before and after the rotation. They are
/// deliberately distinct, obviously invalid, and never printed: the assertions
/// below compare them, they do not log them.
const OLD_TOKEN: &str = "ghp_UAT027_old_token_value";
const NEW_TOKEN: &str = "ghp_UAT027_new_token_value";

fn passphrase() -> SecretString {
    SecretString::from("uat027-passphrase".to_string())
}

fn issue_json() -> String {
    serde_json::json!({
        "number": 1,
        "title": "a title",
        "body": "a body",
        "state": "open",
        "html_url": "https://github.com/o/r/issues/1",
    })
    .to_string()
}

/// A connector factory pointing the fixed approved audience at the local fake
/// origin, exactly as the other M4 integration tests do.
struct LocalFactory {
    resolved: ResolvedAudience,
    root: asv_connector_http::Certificate,
}

impl ConnectorFactory for LocalFactory {
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<GithubClient, asv_connector_http::GithubError> {
        assert_eq!(
            audience.as_str(),
            self.resolved.authority.as_str(),
            "the broker must use the fixed api.github.com audience; this factory \
             redirects it to the local origin, so a mismatch means the broker named \
             its own host"
        );
        Ok(GithubClient::pinned_to(
            self.resolved.clone(),
            AddressPolicy {
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
    session: AgentSessionId,
    /// Kept as an `Arc` because the broker's secret port holds one. Rotation
    /// needs `&mut self` — it rewrites the record in place — so the test
    /// reopens the vault from disk to do it, which is also the more faithful
    /// shape: in production the rotation is a vault-side event that the broker
    /// is never told about, and R7 is exactly the claim that it does not need
    /// to be told.
    store: Arc<VaultStore>,
    key: Arc<VaultKey>,
    path: std::path::PathBuf,
    origin: fake_origin::FakeOrigin,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("v.asv");
        let mut store = VaultStore::create(&vault_path, &passphrase(), KdfParams::fast_for_tests())
            .expect("create vault");
        let key: VaultKey = store.header().unlock(&passphrase()).expect("unlock");

        let mut state = BrokerState::default();
        let credential = insert_credential(
            &mut state,
            CredentialMetadata::new("uat027", CredentialKind::BearerToken),
        );
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    credential.to_wire(),
                    "uat027",
                    asv_vault::CredentialKind::Opaque,
                    "github",
                    "o/r",
                    1,
                ),
                SecretBytes::new(OLD_TOKEN.as_bytes().to_vec()),
            )
            .expect("insert credential");

        let store = Arc::new(store);
        let key = Arc::new(key);
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));

        let origin = fake_origin::start(Reply::Json(issue_json()));
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
        let session = state.sessions.create("/repo".to_string(), &peer);

        Self {
            state,
            peer,
            session,
            store,
            key,
            path: vault_path,
            origin,
            _dir: dir,
        }
    }

    /// The credential id the agent's configuration and the Cedar policy both
    /// reference. Held as a value, never re-derived from the vault, because
    /// the requirement is that *this* id keeps working.
    fn credential_id(&self) -> asv_domain::CredentialId {
        self.state.credentials[0].id
    }

    fn mint(&mut self, max_uses: u32) -> String {
        let credential = self.credential_id();
        match handle(
            &mut self.state,
            &self.peer,
            Request::MintSurrogate {
                session: self.session,
                credential,
                max_uses,
                ttl_secs: 600,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("expected a minted surrogate, got {other:?}"),
        }
    }

    /// One brokered read, returning the `Authorization` header the origin
    /// actually received for it.
    fn read_authorization(&mut self, surrogate: &str) -> Option<String> {
        let response = handle(
            &mut self.state,
            &self.peer,
            Request::ReadIssue {
                session: self.session,
                surrogate: surrogate.to_string(),
                repo: "o/r".into(),
                number: 1,
            },
        );
        assert!(
            matches!(response, Response::IssueRead { .. }),
            "the read must succeed: {response:?}"
        );
        self.origin
            .last()
            .expect("the origin saw the read")
            .header("authorization")
            .map(|value| value.to_string())
    }

    /// Rotates the vault entry under the stable id, by reopening the vault
    /// file and writing the new secret through the vault's own API.
    ///
    /// The broker's `Arc<VaultStore>` is deliberately *not* the handle used
    /// here: it was opened before the rotation, and reusing it would mean
    /// rotating through the same mutable borrow the broker reads from. A
    /// reopen is both the correct signature and the honest model — the
    /// rotation lands on disk, and the running broker is simply unaware.
    fn rotate(&self, new_token: &str, at: u64) {
        let mut reopened = VaultStore::open(&self.path, &passphrase())
            .expect("the vault file reopens while the broker holds a handle");
        reopened
            .rotate(
                &self.key,
                &self.credential_id().to_wire(),
                SecretBytes::new(new_token.as_bytes().to_vec()),
                at,
            )
            .expect("rotate the underlying token");
    }
}

fn auth_header(token: &str) -> String {
    // GitHub's own scheme for a personal access token, and what
    // `authorization_header` in the connector builds. Not `Bearer`: asserting
    // the wrong scheme here would have made this test a restatement of
    // nothing.
    format!("token {token}")
}

/// The requirement, stated as one test: the same surrogate, the same session
/// and the same credential id, before and after the token underneath changes.
#[test]
fn rotation_under_a_live_session_keeps_the_same_surrogate_and_uses_the_new_token() {
    let mut fixture = Fixture::new();
    let surrogate = fixture.mint(4);

    let before = fixture.read_authorization(&surrogate);
    assert_eq!(
        before.as_deref(),
        Some(auth_header(OLD_TOKEN).as_str()),
        "the read before rotation must carry the original token"
    );

    fixture.rotate(NEW_TOKEN, 1_700_000_000);

    let after = fixture.read_authorization(&surrogate);
    assert_eq!(
        after.as_deref(),
        Some(auth_header(NEW_TOKEN).as_str()),
        "the read after rotation must carry the NEW token, through the same surrogate"
    );
    assert!(
        !after.as_deref().unwrap_or_default().contains(OLD_TOKEN),
        "the rotated-out token must not survive anywhere in the new request"
    );
}

/// The half of R7 that is easy to claim by accident. If rotation rewrote the
/// id, or made the old id unresolvable, the agent's configuration and the
/// Cedar policy written against it would be stale — the bytes might still flow
/// for one operation while every later mint fails.
///
/// This asserts the id is *stable and still resolvable* from the vault after
/// the rotation, which is the property the policy actually depends on.
#[test]
fn the_credential_id_stays_stable_and_resolvable_across_rotation() {
    let mut fixture = Fixture::new();
    let surrogate = fixture.mint(4);
    let id_before = fixture.credential_id();

    fixture.rotate(NEW_TOKEN, 1_700_000_001);

    // The same id still resolves, and it resolves to the new secret. Read
    // through `with_secret`, whose closure borrows the plaintext for the
    // duration of the call — which is the shape R7 depends on.
    let resolved = fixture
        .store
        .with_secret(&fixture.key, &id_before.to_wire(), |secret| secret.to_vec())
        .expect("the original id must still resolve after rotation");
    assert_eq!(
        resolved,
        NEW_TOKEN.as_bytes(),
        "the stable id must now yield the new secret"
    );

    // And the broker still mints against that very same id, so a session and a
    // policy pinned to it keep working without the agent changing anything.
    assert_eq!(
        fixture.credential_id(),
        id_before,
        "rotation must not rewrite the credential id"
    );
    let fresh = fixture.mint(2);
    assert_eq!(
        fixture.read_authorization(&fresh).as_deref(),
        Some(auth_header(NEW_TOKEN).as_str()),
        "a fresh surrogate on the unchanged id must already use the new token"
    );
    assert_eq!(
        fixture.read_authorization(&surrogate).as_deref(),
        Some(auth_header(NEW_TOKEN).as_str()),
        "and so must the pre-rotation surrogate"
    );
}
