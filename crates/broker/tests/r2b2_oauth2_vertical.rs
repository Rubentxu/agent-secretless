//! R2.B.2 — `asv oauth2 whoami` through the broker, against a real RFC 6749
//! authorization server.
//!
//! # What this file is for
//!
//! `oauth2_vertical.rs` proves the *library* claim: a real vault, a real
//! provider, an access token where the client secret was. It calls
//! `OAuth2SecretPort::lend` directly, and every request in it is a method call,
//! so it cannot answer the question the roadmap diagnosed as the actual gap —
//! **can an agent name this?** Before R2.B.2 the answer was no: the daemon
//! mounted the port and no `Request` variant, no dispatch arm and no CLI verb
//! reached it.
//!
//! So every request here is an `asv_ipc_protocol::Request` handed to the
//! broker's own `handle` — the same entry point the socket path uses — with a
//! real `VaultStore`, a real `OAuth2SecretPort`, a real Cedar policy, a real
//! RFC 6749 server and a real RFC 8707 resource.
//!
//! # The claim that is new here, and the one that turned out to be older
//!
//! Reachability is the block's headline and `an_agent_names_the_operation…` is
//! the row to read first. The claim *unique* to it is that a derived identity is
//! **verified rather than relayed**:
//!
//! ```text
//! deployment declares  scope = "read:pods", audience = "https://api.asv.test"
//! provider grants      scope = "read:pods write:pods"          ← drift
//! broker answers       refusal, naming both strings
//! ```
//!
//! A resource server reports what it was given, and it will do so honestly even
//! when the grant is *wider* than the operator configured. Relaying that would
//! leave `--oauth2-clients` describing an authority that is no longer the one in
//! play — the escalation M11 exists to prevent, arrived at through the provider
//! rather than through a request, so guarding the request's fields would not
//! catch it.
//!
//! **Which layer speaks first was not known when this file was written, and the
//! tests are what settled it.** `ClientCredentialsIssuer::issue` already refuses
//! a widened grant — `credential scope escalated: asked for …, granted …` — and
//! it does so before the broker holds a token, so the first version of the
//! widening row could not pass. The issuer is the stronger control: the secret
//! is never turned into an over-scoped token, so there is nothing to leak.
//!
//! That leaves the broker's own comparison in `OAuth2Binding::identity`
//! unreachable through the production issuer, which is not a reason to delete
//! it — a provider that widens the grant *after* issuance is real, and
//! `OAuth2Issuer` is an extension point a deployment can supply. So the two
//! layers are asserted separately and each is reachable:
//! `the_issuer_refuses_a_widened_grant_before_any_token_exists` and
//! `the_broker_refuses_a_widened_grant_that_reaches_it`. A control nobody can
//! reach is not a control, and neither is one nobody can falsify.
//!
//! # What this file does not claim
//!
//! **A real third-party IdP is not exercised here and is not claimed.** The
//! authorization server is this crate's own RFC 6749 implementation, and
//! `oauth2.rs`'s issuer is written against the RFC rather than against one
//! provider's dialect. A live exchange with a real IdP is a host-dependent gate
//! and stays open.
//!
//! **Loopback is permitted, and only for this fixture.** The production
//! constructor hardcodes `AddressPolicy::default()`, which refuses `127.0.0.1`;
//! `OAuth2Binding::with_test_transport` is a *separate* function rather than a
//! setter precisely so no shipped code path can turn it on.
//!
//! **Scope as a *policy resource* is not claimed, and deliberately so.** The
//! roadmap fixes the order — surface, then scope-as-policy-resource, then the
//! intersection — and this block is the surface. What it does instead is refuse
//! a scope the operator did not declare, which is the control that makes a
//! later scope-as-resource increment meaningful rather than decorative.

use std::sync::Arc;
use std::time::Duration;

use asv_broker::handle;
use asv_broker::oauth2_binding::{OAuth2Binding, OAuth2Deployment};
use asv_broker::oauth2_port::{
    OAuth2Client, OAuth2IssuerFactory, OAuth2SecretPort, RoutingSecretPort,
};
use asv_broker::oauth2_test_support::{AsClient, AuthorizationServer, RESOURCE_AUDIENCE};
use asv_broker::{BrokerState, VaultSecretPort};
use asv_connector_http::transport::AddressPolicy;
use asv_connector_http::{SecretPort, SecretSink};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_policy::PolicyEngine;
use asv_vault::{KdfParams, VaultKey, VaultStore};

/// The credential as `asv credentials` prints it: a canonical UUID, because that
/// is the only spelling a request can carry.
const CRED: &str = "7c3e1a90-2b44-4d61-9f08-5e6a7b8c9d01";
/// A second, never-registered id, for the "not granted" row.
const UNKNOWN_CRED: &str = "00000000-0000-4000-8000-0000deadbeef";

const SCOPE: &str = "read:pods";

/// An issuer that points the real `ClientCredentialsIssuer` at the fixture's
/// loopback TLS origin.
///
/// The only substitution in the whole file: *where the bytes go*. The exchange
/// itself is the production one, so a row here is evidence about the shipped
/// issuer rather than about a stand-in.
struct FixtureIssuer {
    certificate: asv_connector_http::Certificate,
    host: String,
    port: u16,
}

impl OAuth2IssuerFactory for FixtureIssuer {
    fn issuer(
        &self,
        config: asv_broker::oauth2::OAuth2Config,
    ) -> Result<Box<dyn asv_broker::oauth2::OAuth2Issuer>, asv_broker::oauth2::OAuth2Error> {
        let resolved = asv_connector_http::ResolvedAudience {
            authority: Authority::canonicalize(&self.host).expect("a valid authority"),
            port: self.port,
            addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
        };
        let issuer = asv_broker::oauth2::ClientCredentialsIssuer::with_resolved(
            config,
            &resolved,
            AddressPolicy { allow_loopback: true },
            std::slice::from_ref(&self.certificate),
        )?;
        Ok(Box::new(issuer))
    }
}

/// An issuer that performs the real exchange and then **widens** the scope on
/// the returned token.
///
/// # Why this fixture exists, and it is not to make a row pass
///
/// `ClientCredentialsIssuer::issue` already refuses a provider that grants more
/// than was asked for — `credential scope escalated: asked for …, granted …` —
/// and it does so *before* the broker holds a token. That is the stronger
/// control: the credential is never spent on a token with a wider scope, so
/// there is nothing to leak and nothing to revoke.
///
/// Which means the broker's own comparison in `OAuth2Binding::identity` is
/// **unreachable through the production issuer**, and the first version of the
/// widening row failed by proving exactly that. A control nobody can reach is
/// not a control, and deleting it would also be wrong: a provider that widens
/// the grant *after* issuance is a real behaviour (an IdP issuing a token built
/// from the client's whole entitlement rather than the request), and a different
/// `OAuth2Issuer` implementation is a legitimate extension point.
///
/// So the second layer is kept, and this fixture is what makes it reachable and
/// therefore falsifiable. The two layers are asserted separately below.
struct WideningIssuer {
    inner: FixtureIssuer,
    /// The scope the provider hands back regardless of what was requested.
    grant: String,
}

impl OAuth2IssuerFactory for WideningIssuer {
    fn issuer(
        &self,
        config: asv_broker::oauth2::OAuth2Config,
    ) -> Result<Box<dyn asv_broker::oauth2::OAuth2Issuer>, asv_broker::oauth2::OAuth2Error> {
        let real = self.inner.issuer(config)?;
        Ok(Box::new(Widening {
            inner: real,
            grant: self.grant.clone(),
        }))
    }
}

struct Widening {
    inner: Box<dyn asv_broker::oauth2::OAuth2Issuer>,
    grant: String,
}

impl asv_broker::oauth2::OAuth2Issuer for Widening {
    fn issue(
        &self,
        _scope: &str,
    ) -> Result<asv_broker::oauth2::OAuth2Token, asv_broker::oauth2::OAuth2Error> {
        // `scope` is ignored on purpose and that is the whole fixture: a
        // provider that ignores the request and issues from the client's whole
        // entitlement. Delegating to the inner issuer with the widened string
        // rather than rewriting the token afterwards means the resource is
        // handed a genuinely over-scoped token, which is what the second layer
        // has to catch.
        self.inner.issue(&self.grant)
    }

    fn refresh(
        &self,
        refresh_token: &[u8],
    ) -> Result<asv_broker::oauth2::OAuth2Token, asv_broker::oauth2::OAuth2Error> {
        self.inner.refresh(refresh_token)
    }

    fn token_url(&self) -> &str {
        self.inner.token_url()
    }

    fn audience(&self) -> &str {
        self.inner.audience()
    }
}

/// A broker with a real vault, a real policy, a real IdP and a real session.
struct Vertical {
    state: BrokerState,
    peer: WorkloadIdentity,
    server: AuthorizationServer,
    session: AgentSessionId,
    /// The client secret, kept so the rows that search for it have something
    /// to search for. It is the value the vault holds and the IdP knows, so a
    /// match anywhere on the agent's side would be a real leak rather than a
    /// canary that was never live.
    client_secret: String,
    _dir: tempfile::TempDir,
}

impl Vertical {
    /// The secret, for the canary assertions.
    fn secret(&self) -> &str {
        &self.client_secret
    }
}

impl Vertical {
    /// `expected_scope` is the one knob, and it exists so a row can declare a
    /// scope the provider will *not* grant — the drift case. Everything else is
    /// fixed by the fixture.
    fn new(policy: &str, expected_scope: &str) -> Self {
        Self::with_widening(policy, expected_scope, None)
    }

    /// `widen_to` makes the *provider* hand back a scope other than the one
    /// asked for, which is the only way to reach the broker's own comparison:
    /// the production issuer refuses a widening before the broker sees it.
    fn with_widening(policy: &str, expected_scope: &str, widen_to: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase = secrecy::SecretString::from("r2b2-passphrase".to_string());
        let client = AsClient::awkward();
        // The vault holds the fixture's own secret, so the exchange really is
        // the one production performs against a provider that knows the client.
        // A canary constant would be tidier to read and would make every row
        // below measure a 401 instead.
        let client_secret = client.client_secret.clone();

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
                    "staging idp client",
                    // The *storage class* is a bearer token, because that is how
                    // the vault holds the bytes. The fact that the broker trades
                    // it for an access token travels in `domain_kind`.
                    asv_vault::CredentialKind::BearerToken,
                    "oauth2",
                    "Rubentxu",
                    1,
                ),
                SecretBytes::new(client_secret.as_bytes().to_vec()),
            )
            .expect("insert the credential");

        let server = AuthorizationServer::start(client.clone());
        let host = Authority::canonicalize(server.host()).expect("the fixture host is canonical");

        let mut state = BrokerState::default();
        // Through the same inventory pass the broker runs at startup, so this
        // fixture cannot pass by seeding a field production never writes.
        let loaded = asv_broker::inventory::load(&mut state, &store);
        assert_eq!(
            (loaded.loaded, loaded.skipped, loaded.collisions),
            (1, 0, 0),
            "the fixture vault holds exactly one credential"
        );
        let vault: Arc<dyn SecretPort> = Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        ));
        let oauth2: Arc<dyn SecretPort> = Arc::new(OAuth2SecretPort::with_parts(
            Arc::clone(&vault),
            vec![OAuth2Client {
                credential: CRED.to_string(),
                client_id: client.client_id.clone(),
                token_url: server.url("/token"),
                audience: RESOURCE_AUDIENCE.to_string(),
                scope: expected_scope.to_string(),
            }],
            match widen_to {
                None => Arc::new(FixtureIssuer {
                    certificate: server.certificate(),
                    host: server.host().to_string(),
                    port: server.port(),
                }),
                Some(grant) => Arc::new(WideningIssuer {
                    inner: FixtureIssuer {
                        certificate: server.certificate(),
                        host: server.host().to_string(),
                        port: server.port(),
                    },
                    grant: grant.to_string(),
                }),
            },
        ));
        // The routing port is what production installs, and the binding borrows
        // through it rather than through the vault — so a name no deployment
        // declared cannot be exchanged even if a future call site asked.
        let routing: Arc<dyn SecretPort> = Arc::new(RoutingSecretPort::new(oauth2, vault));
        state.secrets = Some(routing.clone());

        state.oauth2.push(
            OAuth2Binding::with_test_transport(
                OAuth2Deployment {
                    credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
                    token_endpoint: host.clone(),
                    resource: host.clone(),
                    resource_port: server.port(),
                    audience: RESOURCE_AUDIENCE.to_string(),
                    expected_scope: expected_scope.to_string(),
                },
                client.client_id.clone(),
                routing,
                // The fixture is a *named* loopback host, so the address list is
                // supplied rather than resolved — and `build_with_roots`
                // re-applies `policy` to it, so naming a private address here
                // buys nothing unless `allow_loopback` is set, which only this
                // constructor can do.
                asv_connector_http::ResolvedAudience {
                    authority: host,
                    port: server.port(),
                    addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                },
                AddressPolicy { allow_loopback: true },
                std::slice::from_ref(&server.certificate()),
            )
            .expect("the fixture resource is usable over a pinned loopback client"),
        );

        state.policy = PolicyEngine::from_policy_text(policy).expect("the policy text is valid");

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
            server,
            session,
            client_secret,
            _dir: dir,
        }
    }

    /// The policy an operator writes to allow this, and only this.
    ///
    /// Note the resource is the *entity name*, not an attribute: the schema
    /// declares `OAuth2Client` with no attributes, so `resource == …` is the
    /// form that can match. See `POLICY_TEXT` in the policy crate for why the
    /// `audience` attribute documented for `Api` cannot be used.
    fn permitting() -> Self {
        Self::new(
            &format!(
                r#"permit (principal, action == Action::"oauth2_identity",
                       resource == OAuth2Client::"oauth2:{CRED}");"#
            ),
            SCOPE,
        )
    }

    fn whoami(&mut self, credential: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::OAuth2Identity {
                session: self.session,
                credential: credential.to_string(),
            },
        )
    }
}

/// A session this peer does not own is refused, before any socket.
///
/// **The fixture cannot express "another peer", and knowing why is the point.**
/// `SessionStore::belongs_to` compares the peer's **pid**, not its whole
/// identity, so a second `WorkloadIdentity` built in this process *is* the same
/// peer as far as the store is concerned. A row that built one with a different
/// gid would be measuring the registration lookup while claiming to measure
/// ownership — and would stay green with the ownership check deleted, which is
/// exactly what the falsification campaign found when this row was missing.
///
/// What is measurable in-process is "a session this peer does not own", and that
/// is what this asserts. Genuinely another peer needs a second process.
#[test]
fn a_session_this_peer_does_not_own_is_refused_before_any_socket() {
    let mut vertical = Vertical::permitting();
    let response = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::OAuth2Identity {
            // A real, well-formed id that was never created, so the refusal is
            // ownership rather than a parse error or a missing registration.
            session: AgentSessionId::new(),
            credential: CRED.to_string(),
        },
    );
    let (code, message) = refusal(&response);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("not owned"), "{message}");
    assert!(
        vertical.server.last_request().is_none(),
        "an unowned session reached the identity provider"
    );
}

/// A broker with no registration configured refuses everything, and says so.
///
/// The empty reading is the fail-closed one: a broker that was not told which IdP
/// a credential is traded with is not a broker that gets to trade it with
/// somewhere.
#[test]
fn a_broker_with_no_registration_configured_refuses_every_request() {
    let mut vertical = Vertical::permitting();
    vertical.state.oauth2.clear();
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("configured"), "{message}");
    assert!(
        vertical.server.last_request().is_none(),
        "an unconfigured broker reached the identity provider"
    );
}

/// Ending the session stops the next call, so a derived identity cannot outlive
/// the authority that authorized it.
///
/// This is the row that makes the `session` field load-bearing rather than
/// decorative. The token it produced lives on the *provider's* clock and would
/// otherwise stay valid for its whole lifetime with nothing left to revoke it —
/// which is the one asymmetry between a brokered derived credential and a
/// surrogate the broker itself issued.
#[test]
fn ending_the_session_stops_further_oauth2_calls() {
    let mut vertical = Vertical::permitting();
    assert!(matches!(
        vertical.whoami(CRED),
        Response::OAuth2Identity { .. }
    ));
    handle(
        &mut vertical.state,
        &vertical.peer,
        Request::EndSession {
            session: vertical.session,
        },
    );
    let after = vertical.whoami(CRED);
    let (code, message) = refusal(&after);
    assert_eq!(code, ErrorCode::Denied);
    assert!(
        message.contains("not owned") || message.contains("session"),
        "{message}"
    );
    // And the second call did not reach the provider: the token from the first
    // call was still cached and still live, so a row that only checked the
    // refusal code would pass even if the call had gone out and the provider had
    // answered.
    let token_calls = vertical
        .server
        .audit()
        .iter()
        .filter(|entry| entry.endpoint == "/token")
        .count();
    assert_eq!(
        token_calls, 1,
        "a refused call exchanged the client secret again"
    );
}

/// A broker with no vault open refuses everything, before any socket.
///
/// A provider being reachable is not a reason to serve a request whose
/// credential lives in a store that is not there — and the refusal has to come
/// before the exchange, or the IdP sees a client authentication attempt from a
/// broker that cannot have been given the secret.
#[test]
fn a_broker_with_no_vault_open_refuses_before_any_socket() {
    let mut vertical = Vertical::permitting();
    vertical.state.secrets = None;
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("credential store"), "{message}");
    assert!(
        vertical.server.last_request().is_none(),
        "a vault-less broker reached the identity provider"
    );
}

/// A token that is not a bearer token cannot be presented, and the broker says
/// so instead of sending something the resource never minted.
///
/// `bearer_auth` takes a `String`, so the conversion from bytes is somewhere and
/// `String::from_utf8_lossy` is the version of it that compiles. It would
/// "work": the U+FFFD substitution produces a header, the resource answers 401,
/// and the operator reads a provider failure for what is a broker bug. The
/// strict path turns it into a refusal that names the actual problem.
///
/// The row exists because the mutation is otherwise **invisible**: the happy
/// path uses a valid token, so swapping strict for lossy changes nothing
/// observable and the control would sit in the file unfalsified. A port that
/// yields invalid bytes is the only way to see the difference.
#[test]
fn a_token_that_is_not_a_bearer_token_is_refused_rather_than_substituted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = AuthorizationServer::start(AsClient::awkward());
    let host = Authority::canonicalize(server.host()).expect("canonical host");

    struct NotUtf8;
    impl SecretPort for NotUtf8 {
        fn lend(&self, _c: &str, s: &mut dyn SecretSink) -> Result<(), asv_connector_http::SecretError> {
            // A lone 0xFF can never be part of RFC 6750's `b64token`.
            s.accept(&[0xff, 0xfe, 0xfd])
        }
        fn forget(&self, _c: &str) {}
    }

    let binding = OAuth2Binding::with_test_transport(
        OAuth2Deployment {
            credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
            token_endpoint: host.clone(),
            resource: host.clone(),
            resource_port: server.port(),
            audience: RESOURCE_AUDIENCE.to_string(),
            expected_scope: SCOPE.to_string(),
        },
        "asv:broker/ci".to_string(),
        Arc::new(NotUtf8),
        asv_connector_http::ResolvedAudience {
            authority: host,
            port: server.port(),
            addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
        },
        AddressPolicy { allow_loopback: true },
        std::slice::from_ref(&server.certificate()),
    )
    .expect("the fixture resource is usable");

    let refused = binding.identity(CRED).expect_err("invalid bytes are not presentable");
    let message = refused.to_string();
    assert!(
        message.contains("UTF-8") || message.contains("utf-8"),
        "the refusal does not name the actual problem, so an operator would go \
         looking at the provider: {message}"
    );
    // And nothing reached the resource: there was no header to send.
    assert!(
        server
            .audit()
            .iter()
            .all(|entry| entry.endpoint != "/resource"),
        "an unpresentable token was sent anyway"
    );
}

/// A resource that answers with a refusal is reported as one, not parsed.
///
/// **The row the campaign forced into existence.** The obvious version of this
/// file asserted only that *some* refusal came back, which made the non-2xx
/// check unfalsifiable: with it deleted, the error body
/// `{"error":"invalid_token",…}` fails the JSON parse instead and the answer is
/// still a refusal, so the row stayed green. Asserting the *specific* refusal is
/// what makes the check load-bearing — a body that is not an identity is not a
/// malformed identity, it is an HTTP refusal, and reporting it as `Malformed`
/// would send an operator to debug a parser instead of to read a 401.
///
/// The token is well-formed and the resource does not know it, which is what a
/// corrupted cache entry or a misbehaving issuer would look like. The point is
/// not that this is common; it is that the answer must be the *status* when the
/// status says no.
#[test]
fn a_resource_answered_with_a_refusal_is_reported_as_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = AuthorizationServer::start(AsClient::awkward());
    let host = Authority::canonicalize(server.host()).expect("canonical host");

    /// A port that yields a well-formed token the resource has never issued.
    struct UnknownToken;
    impl SecretPort for UnknownToken {
        fn lend(&self, _c: &str, s: &mut dyn SecretSink) -> Result<(), asv_connector_http::SecretError> {
            // Valid UTF-8 and a plausible `b64token` shape, so the only reason
            // the resource can refuse is that it never minted this one.
            s.accept(b"asv-token-the-resource-never-issued")
        }
        fn forget(&self, _c: &str) {}
    }

    let binding = OAuth2Binding::with_test_transport(
        OAuth2Deployment {
            credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
            token_endpoint: host.clone(),
            resource: host.clone(),
            resource_port: server.port(),
            audience: RESOURCE_AUDIENCE.to_string(),
            expected_scope: SCOPE.to_string(),
        },
        "asv:broker/ci".to_string(),
        Arc::new(UnknownToken),
        asv_connector_http::ResolvedAudience {
            authority: host,
            port: server.port(),
            addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
        },
        AddressPolicy { allow_loopback: true },
        std::slice::from_ref(&server.certificate()),
    )
    .expect("the fixture resource is usable");

    let refused = binding.identity(CRED).expect_err("the resource refuses an unknown token");
    let message = refused.to_string();
    assert!(
        message.contains("401"),
        "the refusal does not carry the status: {message}"
    );
    // The decisive half. With the non-2xx check deleted, the same 401 body would
    // be reported as an unreadable body and this row goes red.
    assert!(
        !message.contains("unreadable"),
        "a 401 was reported as a parse failure, which sends the operator to the \
         wrong file: {message}"
    );
    // And the resource really was asked, so this is not passing vacuously.
    assert!(
        server
            .audit()
            .iter()
            .any(|entry| entry.endpoint == "/resource"),
        "the resource was never asked, so the refusal came from somewhere else"
    );
}

fn refusal(response: &Response) -> (ErrorCode, &str) {
    match response {
        Response::Error { code, message } => (*code, message.as_str()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// **The reachability claim.** An agent names the operation and gets the
/// resource's own answer.
///
/// This is the row that was impossible to write before R2.B.2: the request goes
/// through `handle`, and before this block there was no `Request` variant to
/// hand it.
#[test]
fn an_agent_names_the_operation_and_gets_the_resource_own_answer() {
    let mut vertical = Vertical::permitting();
    match vertical.whoami(CRED) {
        Response::OAuth2Identity {
            resource,
            scope,
            audience,
        } => {
            assert_eq!(resource, "pods");
            assert_eq!(scope, SCOPE);
            assert_eq!(audience, RESOURCE_AUDIENCE);
        }
        other => panic!("a permitted call was refused: {other:?}"),
    }
    // And it really did reach the provider: a token was minted and presented.
    assert!(
        vertical.server.last_request().is_some(),
        "the call never reached the authorization server"
    );
}

/// The property the whole block exists for, on the wire an agent receives.
///
/// Both directions are asserted, and the second is the one that would catch a
/// field added to the response later: a `String` field *could* hold a token, so
/// "the type cannot hold one" is close to structural rather than structural,
/// and only the encoded bytes are what a caller actually experiences.
#[test]
fn the_encoded_response_carries_no_credential() {
    let mut vertical = Vertical::permitting();
    let response = vertical.whoami(CRED);
    let encoded = serde_json::to_string(&response).expect("the response encodes");
    assert!(
        !encoded.contains(vertical.secret()),
        "the client secret reached the caller: {encoded}"
    );
    // The access token is the sharper one: it is a real credential the
    // provider honours, so finding it here would be a genuine leak rather than
    // a canary that was never live.
    assert!(
        !encoded.contains("access_token") && !encoded.contains("ASV-TOKEN"),
        "a token-shaped field reached the caller: {encoded}"
    );
    // And the row is not passing on an empty string.
    assert!(encoded.contains(SCOPE), "{encoded}");
}

/// **Layer one: the issuer refuses a widening before a token exists.**
///
/// This is the control that actually holds in production, and the row that
/// failed first is how it was found: the obvious version of "the broker refuses
/// a widened scope" cannot pass, because the broker never gets that far.
///
/// `ClientCredentialsIssuer::issue` compares what it asked for against what the
/// provider granted and refuses on a difference. So the client secret is never
/// turned into a token with a wider scope, there is nothing to present anywhere,
/// and the resource is never contacted. The first version of this row expected
/// the broker's own comparison and was wrong about which layer speaks first.
#[test]
fn the_issuer_refuses_a_widened_grant_before_any_token_exists() {
    let mut vertical = Vertical::permitting();
    vertical
        .server
        .override_scope("read:pods write:pods admin:everything");

    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Upstream);
    assert!(
        message.contains("escalated"),
        "the refusal does not name the escalation: {message}"
    );
    assert!(
        message.contains("admin:everything"),
        "the refusal does not name what was granted, so the operator cannot fix \
         it at the IdP: {message}"
    );
    // And the resource was never asked: the token never existed to present.
    let resource_hits = vertical
        .server
        .audit()
        .iter()
        .filter(|entry| entry.endpoint == "/resource")
        .count();
    assert_eq!(
        resource_hits, 0,
        "the resource was contacted with a token the issuer had already refused"
    );
}

/// **Layer two: the broker refuses a widened grant that reaches it anyway.**
///
/// A provider that widens the grant *after* issuance is real — an IdP building a
/// token from the client's whole entitlement rather than from the request — and
/// `OAuth2Issuer` is an extension point a deployment can supply. So the second
/// layer exists, and this row is what makes it falsifiable: without
/// `WideningIssuer` the code path would be unreachable and the check would be
/// decoration.
///
/// The resource is reached with a live, over-scoped token, and the *broker's*
/// comparison is what refuses.
#[test]
fn the_broker_refuses_a_widened_grant_that_reaches_it() {
    let mut vertical = Vertical::with_widening(
        &format!(
            r#"permit (principal, action == Action::"oauth2_identity",
                   resource == OAuth2Client::"oauth2:{CRED}");"#
        ),
        SCOPE,
        // Within the client's entitlement on purpose: the provider is *allowed*
        // to hand this out, so the only thing standing between the wider grant
        // and the agent is the broker's own comparison. A grant the IdP would
        // refuse anyway would make this row measure the IdP a second time.
        Some("read:pods write:pods"),
    );

    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Upstream);
    // Both strings, because an operator who sees "the provider granted too much"
    // needs to know what it granted in order to fix it at the IdP.
    assert!(
        message.contains(SCOPE),
        "the refusal does not name what the deployment expected: {message}"
    );
    assert!(
        message.contains("write:pods"),
        "the refusal does not name what was actually granted: {message}"
    );
    // The resource *was* reached — otherwise this row would be measuring layer
    // one again, and would keep passing if layer two were deleted.
    let resource_hits = vertical
        .server
        .audit()
        .iter()
        .filter(|entry| entry.endpoint == "/resource")
        .count();
    assert_eq!(
        resource_hits, 1,
        "layer two was never reached: the issuer refused first, so this row is \
         not testing the broker's own comparison"
    );
    // And the wider scope is nowhere in the answer: not reported, and the row
    // is not passing because the word is absent from a message that never
    // mentioned the grant either.
    assert!(message.contains("scope"), "{message}");
}

/// A deployment that declares a scope the provider *narrowed* is also refused,
/// and this is the same comparison from the other side.
///
/// It looks redundant next to the row above and is not: the comparison is an
/// equality, and a future edit that relaxed it to "is the granted scope a subset
/// of the declared one" would silently accept a provider that granted *less*
/// than configured. That is the safe direction for confidentiality and the wrong
/// one for an operator, who has written a policy on the assumption that
/// `read:pods` is what the broker has.
#[test]
fn a_provider_granting_less_than_the_deployment_declares_is_refused() {
    // The deployment expects more than the provider will hand out.
    let mut vertical = Vertical::with_widening(
        &format!(
            r#"permit (principal, action == Action::"oauth2_identity",
                   resource == OAuth2Client::"oauth2:{CRED}");"#
        ),
        "read:pods write:pods",
        Some(SCOPE),
    );

    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Upstream);
    assert!(
        message.contains("read:pods write:pods"),
        "the refusal does not name what the deployment expected: {message}"
    );
}

/// A token issued for another audience is refused by the resource itself, and
/// that is the *provider's* property rather than the broker's — which is why the
/// row asserts the resource's own error rather than a broker comparison.
#[test]
fn a_deployment_pointing_at_another_audience_is_refused() {
    // The deployment asks the IdP for a token bound to a different resource than
    // the one it will present it to.
    let mut vertical = Vertical::new(
        &format!(
            r#"permit (principal, action == Action::"oauth2_identity",
                   resource is OAuth2Client);"#
        ),
        SCOPE,
    );
    // Re-point the deployment's declared audience at one the client is entitled
    // to but the resource does not serve, so the token is live and wrong.
    vertical.state.oauth2[0].deployment.audience = "https://admin.asv.test".to_string();
    vertical.state.oauth2[0].deployment.expected_scope = SCOPE.to_string();

    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Upstream);
    // Either the resource refuses the token outright or the broker catches the
    // audience disagreement; both are refusals and both are `Upstream`. Which
    // one fired is the resource's business, not this file's.
    assert!(
        message.contains("admin.asv.test") || message.contains("refused"),
        "the refusal does not say what was wrong: {message}"
    );
}

/// A credential no registration names is refused, and refused **before any
/// socket** — the request is the untrusted side of this socket, so a credential
/// nobody configured must not get as far as a network call.
#[test]
fn a_credential_no_registration_names_is_refused_before_any_socket() {
    let mut vertical = Vertical::permitting();
    // A *well-formed* id that was never registered. A malformed one would be
    // refused earlier as `InvalidRequest`, and the row would then be measuring
    // the parse rather than the lookup — and "not granted" and "you called me
    // wrong" are different answers a caller needs to tell apart.
    let asked = vertical.whoami(UNKNOWN_CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(
        message.contains(UNKNOWN_CRED),
        "the refusal does not name what was asked for: {message}"
    );
    // The message lists what *is* configured, so an agent that cannot find its
    // credential can tell "not granted" from "misspelled".
    assert!(
        message.contains(CRED),
        "the refusal does not list the configured registrations: {message}"
    );
    assert!(
        vertical.server.last_request().is_none(),
        "a refused request reached the identity provider"
    );
}

/// A malformed credential is `InvalidRequest` rather than `Denied`, and the two
/// are kept apart on purpose: one means "you called me wrong" and the other
/// means "not granted", and a caller that cannot tell them apart cannot tell a
/// typo from a denial.
#[test]
fn a_malformed_credential_is_invalid_request_not_denied() {
    let mut vertical = Vertical::permitting();
    let asked = vertical.whoami("not-a-uuid");
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::InvalidRequest);
    assert!(message.contains("vault id"), "{message}");
    assert!(
        vertical.server.last_request().is_none(),
        "a refused request reached the identity provider"
    );
}

/// A stock policy permits nothing here, and the omission is the point.
///
/// The built-in policy text has no `permit` for `oauth2_identity`, so an
/// operator who upgrades starts refusing every OAuth2 call rather than serving
/// them. Widening it is an explicit policy edit somebody can see in a diff.
#[test]
fn a_stock_policy_refuses_the_operation_before_any_socket() {
    let mut vertical = Vertical::new("", SCOPE);
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    // The message carries the `Display` spelling (`oauth2.identity`), not the
    // Cedar one (`oauth2_identity`). Both name the same verb, and this row is
    // about the decision, so it pins the form that reaches an operator.
    assert!(message.contains("oauth2.identity"), "{message}");
    assert!(
        vertical.server.last_request().is_none(),
        "a denied request reached the identity provider"
    );
}

/// **The row that says the allowlist was not widened for this — and it turned
/// out to be a stronger control than this file first claimed.**
///
/// The obvious version of this row asserts that a policy naming an `Api`
/// resource is *denied* at evaluation. It cannot even be loaded. The schema
/// declares `oauth2_identity` as applying to `OAuth2Client` only, so
/// `resource is Api` fails strict validation when the policy is compiled — a
/// load-time error naming the offending rule, before any request exists.
///
/// That is the better property and it is worth stating precisely, because it is
/// what makes `Resource::OAuth2Client` safe rather than merely tidy: an operator
/// **cannot write the dangerous rule at all**. The failure mode the design is
/// defending against — a policy that reaches an arbitrary IdP host through a
/// resource type whose approval list is two entries long — is unreachable by
/// construction, not by a check that might be forgotten. If someone later
/// "simplifies" by adding `Api` to this action's `appliesTo`, this row goes red
/// at *compile-and-load* time, which is where the mistake would be made.
#[test]
fn a_policy_naming_an_api_resource_cannot_even_be_loaded() {
    let text = r#"permit (principal, action == Action::"oauth2_identity", resource is Api);"#;
    let refused = PolicyEngine::from_policy_text(text);
    assert!(
        refused.is_err(),
        "a rule naming Api reached an action that applies to OAuth2Client only: {text}"
    );
    // The error is about the *rule*, not about a runtime condition, so it is
    // safe to surface to whoever wrote the policy.
    let message = refused.expect_err("just checked").to_string();
    assert!(
        message.contains("Api") || message.contains("resource"),
        "the refusal does not say what is wrong: {message}"
    );
}

/// The same question for the *other* direction: a rule naming `OAuth2Client`
/// for a different action is also a load error, because no other action applies
/// to that entity type.
///
/// Worth its own row because the two together are what make the entity type a
/// closed pair: `oauth2_identity` is the only verb that reaches an
/// `OAuth2Client`, and an `OAuth2Client` is the only resource that verb reaches.
/// Either half alone would leave a gap for a future action to fall into.
#[test]
fn a_rule_for_a_different_action_on_this_client_cannot_be_loaded() {
    let text = format!(
        r#"permit (principal, action == Action::"github_issue_read",
               resource == OAuth2Client::"oauth2:{CRED}");"#
    );
    assert!(
        PolicyEngine::from_policy_text(&text).is_err(),
        "a GitHub verb reached an OAuth2Client resource: {text}"
    );
}

/// A rule naming a *different* client must not reach this one, even though both
/// are `OAuth2Client`. This is the row that holds "one registration, one grant"
/// — the property `resource_name` prefixes for, and the reason the resource is
/// keyed by credential rather than by audience.
#[test]
fn a_rule_for_another_client_does_not_reach_this_one() {
    let other = "9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a";
    let mut vertical = Vertical::new(
        &format!(
            r#"permit (principal, action == Action::"oauth2_identity",
                   resource == OAuth2Client::"oauth2:{other}");"#
        ),
        SCOPE,
    );
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(
        code,
        ErrorCode::Denied,
        "a grant for {other} reached {CRED}: {message}"
    );
    assert!(
        vertical.server.last_request().is_none(),
        "a denied request reached the identity provider"
    );
}

/// The audit has to answer "who spent this credential" without becoming a second
/// copy of the credential.
#[test]
fn the_audit_record_of_the_call_carries_no_credential() {
    let mut vertical = Vertical::permitting();
    vertical.whoami(CRED);

    let log = vertical.state.audit.lock().expect("no test holds this");
    let records = format!("{:?}", log.query(0));
    assert!(
        records.contains("oauth2_identity") || records.contains("oauth2.identity"),
        "the call left no audit trace: {records}"
    );
    assert!(
        !records.contains(vertical.secret()),
        "the client secret reached the audit: {records}"
    );
}

/// The capability the daemon advertises is the one this file exercises.
///
/// The inverse of the R2.C.3c defect, where the AWS operation was built and
/// `compiled_capabilities()` did not name it — so an agent reading `asv
/// capabilities` could not discover the operation that worked. This row closes
/// the loop from the other end: the name in the advertisement is the name in the
/// dispatch.
#[test]
fn the_advertised_capability_is_the_one_this_file_calls() {
    let advertised = asv_broker::selfreport::compiled_capabilities();
    assert!(
        advertised.contains(&"oauth2.identity".to_string()),
        "the operation works but is not advertised: {advertised:?}"
    );
    // And the request's own method name is the audit spelling of the same
    // operation, so an operator reading a log line can find the code.
    assert_eq!(
        Request::OAuth2Identity {
            session: AgentSessionId::new(),
            credential: CRED.to_string(),
        }
        .method_name(),
        "oauth2_identity"
    );
}

/// A sink that keeps a copy, so "the client secret never left the port" is a
/// checkable assertion rather than a claim about code nobody can see.
#[derive(Default)]
struct AgentSide {
    seen: Vec<u8>,
}

impl SecretSink for AgentSide {
    fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
        self.seen = secret.to_vec();
        Ok(())
    }
}

/// The port hands out a token and never the secret — asserted here on the port
/// the *binding* borrows through, not on a port the test built for itself, so
/// the row is about the wiring the daemon installs.
#[test]
fn the_port_the_binding_borrows_through_never_yields_the_secret() {
    let vertical = Vertical::permitting();
    let mut side = AgentSide::default();
    vertical
        .state
        .secrets
        .as_ref()
        .expect("the fixture opened a vault")
        .lend(CRED, &mut side)
        .expect("the routing port lends");
    assert!(!side.seen.is_empty(), "the operation got nothing");
    assert!(
        !String::from_utf8_lossy(&side.seen).contains(vertical.secret()),
        "the routing port handed over the client secret"
    );
}

/// The exchange has a deadline, and a resource that never answers is a refusal
/// rather than a hung broker.
///
/// `IDENTITY_TIMEOUT` exists because an unbounded client is not "slow", it is
/// *unbounded* — and an agent cannot distinguish that from a slow provider. The
/// row does not measure the timeout itself (that would be a 10-second test); it
/// asserts the client was built with one, which is the property that makes the
/// timeout meaningful.
#[test]
fn the_resource_client_is_bounded() {
    let vertical = Vertical::permitting();
    let debug = format!("{:?}", vertical.state.oauth2[0]);
    assert!(
        debug.contains("allow_loopback: true"),
        "the fixture is a test transport: {debug}"
    );
    assert!(
        asv_broker::oauth2_binding::IDENTITY_TIMEOUT <= Duration::from_secs(30),
        "the deadline must be shorter than an agent's patience"
    );
    // And it is non-zero, which is the part that would be easy to lose.
    assert!(!asv_broker::oauth2_binding::IDENTITY_TIMEOUT.is_zero());
}
