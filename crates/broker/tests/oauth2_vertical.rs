//! The M11 vertical: a client secret in a real vault, a real provider, and an
//! operation that receives a short-lived token instead of the secret.
//!
//! `oauth2_provider.rs` proves the issuer behaves against a real provider, and
//! `oauth2_port.rs` (in the library) proves the port's plumbing. Neither of them
//! is the claim M11 needs, and the claim is not a sum of the two. It is:
//!
//! ```text
//! vault ──▶ OAuth2SecretPort ──▶ provider ──▶ access token ──▶ operation
//!   │
//!   └── the client secret stops here
//! ```
//!
//! So this file uses the *real* [`VaultSecretPort`] over a real encrypted vault
//! rather than a fixed secret, and the only substitution is which provider the
//! issuer talks to. Everything between the vault's bytes and the sink's bytes
//! is the code that ships.
//!
//! The `the_agent_never_receives_the_client_secret` test is the one to read
//! first. Everything else is a reason to believe it survives contact with
//! caching, expiry and a provider that stops answering.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asv_broker::oauth2::{OAuth2Config, OAuth2Error, OAuth2Issuer};
use asv_broker::oauth2_port::{OAuth2Client, OAuth2IssuerFactory, OAuth2SecretPort};
use asv_broker::oauth2_test_support::{AsClient, AuthorizationServer, RESOURCE_AUDIENCE};
use asv_broker::VaultSecretPort;
use asv_connector_http::{AddressPolicy, ResolvedAudience, SecretError, SecretPort, SecretSink};
use asv_domain::{Authority, SecretBytes};
use asv_vault::{CredentialKind, CredentialMetadata, KdfParams, VaultStore};

/// The secret as it is stored. Fixed rather than random so "this exact string
/// never appears on the agent's side" is a checkable assertion rather than a
/// hope about entropy.
const CLIENT_SECRET: &str = "ASV-CANARY-oauth2-client-secret-DO-NOT-LEAK";

const CREDENTIAL_ID: &str = "oauth2-cred-1";

fn passphrase() -> secrecy::SecretString {
    secrecy::SecretString::from("test-passphrase".to_string())
}

/// A real encrypted vault holding the client secret under `CREDENTIAL_ID`.
fn vault_port(dir: &tempfile::TempDir, secret: &str) -> Arc<dyn SecretPort> {
    let path = dir.path().join("vault.asv");
    let mut store =
        VaultStore::create(&path, &passphrase(), KdfParams::fast_for_tests()).expect("create");
    let key = store.header().unlock(&passphrase()).expect("unlock");
    let mut metadata = CredentialMetadata::new(
        CREDENTIAL_ID,
        "k8s client credentials",
        // The *storage class* is a bearer token: that is how the vault holds
        // the bytes, and pretending the vault has an OAuth2 storage class
        // would be inventing one. The operator's choice travels in
        // `domain_kind`, which is the field that exists for exactly this.
        CredentialKind::BearerToken,
        "k8s",
        "asv-broker",
        1,
    );
    metadata.domain_kind = Some(asv_domain::CredentialKind::OAuth2);
    store
        .insert(&key, metadata, SecretBytes::new(secret.as_bytes().to_vec()))
        .expect("insert");
    Arc::new(VaultSecretPort::new(
        Arc::new(Mutex::new(store)),
        Arc::new(key),
    ))
}

/// Counts grants, because a deterministic or a cached answer can look identical
/// from the bytes and only the count distinguishes them.
#[derive(Default)]
struct Grants(AtomicUsize);

/// An issuer factory pointed at the fixture, which is the *only* substitution
/// this file makes.
struct FixtureIssuer {
    port: u16,
    host: String,
    certificate: asv_connector_http::Certificate,
    grants: Arc<Grants>,
}

impl OAuth2IssuerFactory for FixtureIssuer {
    fn issuer(&self, config: OAuth2Config) -> Result<Box<dyn OAuth2Issuer>, OAuth2Error> {
        self.grants.0.fetch_add(1, Ordering::SeqCst);
        let resolved = ResolvedAudience {
            authority: Authority::canonicalize(&self.host).expect("a valid authority"),
            port: self.port,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        let issuer = asv_broker::oauth2::ClientCredentialsIssuer::with_resolved(
            config,
            &resolved,
            AddressPolicy {
                allow_loopback: true,
            },
            std::slice::from_ref(&self.certificate),
        )?;
        Ok(Box::new(issuer))
    }
}

/// The whole vertical, assembled.
struct Vertical {
    _dir: tempfile::TempDir,
    server: AuthorizationServer,
    port: OAuth2SecretPort,
    grants: Arc<Grants>,
}

fn vertical(ttl: Duration, margin: Duration, as_client: &AsClient) -> Vertical {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = AuthorizationServer::with_ttl(as_client.clone(), ttl);
    let grants = Arc::new(Grants::default());
    let factory = Arc::new(FixtureIssuer {
        port: server.port(),
        host: server.host().to_string(),
        certificate: server.certificate(),
        grants: Arc::clone(&grants),
    });
    let port = OAuth2SecretPort::with_parts(
        vault_port(&dir, &as_client.client_secret),
        vec![OAuth2Client {
            credential: CREDENTIAL_ID.to_string(),
            client_id: as_client.client_id.clone(),
            token_url: server.url("/token"),
            audience: RESOURCE_AUDIENCE.to_string(),
            scope: "read:pods".to_string(),
        }],
        factory,
    )
    .with_margin(margin);
    Vertical {
        _dir: dir,
        server,
        port,
        grants,
    }
}

/// Stands in for the header builder on the agent's side: it keeps the bytes
/// because the whole point is to look at them afterwards.
#[derive(Default)]
struct AgentSide {
    seen: Vec<u8>,
    accepts: usize,
}

impl SecretSink for AgentSide {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        self.seen = secret.to_vec();
        self.accepts += 1;
        Ok(())
    }
}

fn resource_client(server: &AuthorizationServer) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(server.certificate())
        .resolve(
            server.host(),
            format!("127.0.0.1:{}", server.port())
                .parse()
                .expect("loopback addr"),
        )
        .timeout(Duration::from_secs(5))
        .build()
        .expect("a resource client")
}

fn at_resource(server: &AuthorizationServer, token: &[u8]) -> u16 {
    resource_client(server)
        .get(server.url("/resource"))
        .header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(token)),
        )
        .send()
        .expect("TLS completes")
        .status()
        .as_u16()
}

/// **The claim.** What the agent receives is a credential the provider really
/// issued, and it is not the secret that was sitting in the vault.
#[test]
fn the_agent_never_receives_the_client_secret() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    let mut agent = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut agent).expect("lend");

    assert_eq!(agent.accepts, 1);
    assert!(!agent.seen.is_empty(), "the operation got nothing");
    assert_ne!(
        agent.seen,
        CLIENT_SECRET.as_bytes(),
        "the client secret reached the agent"
    );
    assert!(
        !String::from_utf8_lossy(&agent.seen).contains(CLIENT_SECRET),
        "the client secret is inside what the agent received"
    );

    // And it is not merely different: the provider accepts it, which a canary
    // would not be.
    assert_eq!(
        at_resource(&v.server, &agent.seen),
        200,
        "what the agent received is not a credential the provider honours"
    );
}

/// The provider's own record says a confidential client authenticated, and it
/// says which client and which scope — so the vertical is legible from the
/// other end, not only from ours.
#[test]
fn the_providers_record_shows_the_broker_authenticating_and_the_agent_not() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    let mut agent = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut agent).expect("lend");

    let audit = v.server.audit();
    let authenticated = audit
        .iter()
        .find(|entry| entry.outcome == "authenticated")
        .expect("the provider authenticated someone");
    assert_eq!(
        authenticated.client_id.as_deref(),
        Some("asv:broker/ci"),
        "the broker authenticated as the registered client"
    );
    let issued = audit
        .iter()
        .find(|entry| entry.outcome == "issued")
        .expect("a token was issued");
    assert_eq!(issued.scope.as_deref(), Some("read:pods"));

    // Now let the operation use what it received, so the record can be read
    // from the other end: the served entry carries the fingerprint of the same
    // token the agent got.
    assert_eq!(at_resource(&v.server, &agent.seen), 200);
    let served = v
        .server
        .audit()
        .into_iter()
        .find(|entry| entry.outcome == "served")
        .expect("the resource served the token");
    assert_eq!(served.token_fingerprint, issued.token_fingerprint);
    // And no entry anywhere carries the secret.
    assert!(!format!("{:?}", v.server.audit()).contains(CLIENT_SECRET));
}

/// The cache is what makes this usable and what would make it dangerous, so
/// both halves are checked: one grant for two operations inside the lifetime,
/// and a new grant once the token is retired.
#[test]
fn a_token_is_reused_inside_its_lifetime_and_replaced_outside_it() {
    let v = vertical(Duration::from_secs(1), Duration::ZERO, &AsClient::awkward());

    let mut first = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut first).expect("first");
    let mut second = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut second).expect("second");
    assert_eq!(
        v.grants.0.load(Ordering::SeqCst),
        1,
        "one grant, two operations"
    );
    assert_eq!(first.seen, second.seen);
    assert_eq!(at_resource(&v.server, &first.seen), 200);

    // Past the token's own lifetime the cached copy must not be served, and the
    // replacement must be a token the provider still honours.
    std::thread::sleep(Duration::from_millis(1200));
    let mut third = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut third).expect("third");
    assert_eq!(v.grants.0.load(Ordering::SeqCst), 2, "a new grant");
    assert_ne!(first.seen, third.seen, "the retired token is gone");
    assert_eq!(
        at_resource(&v.server, &first.seen),
        401,
        "the retired token really is dead at the provider"
    );
    assert_eq!(at_resource(&v.server, &third.seen), 200);
}

/// The margin retires a token before it dies, so an operation never receives a
/// credential that expires while it is being used.
#[test]
fn a_token_is_retired_before_it_expires() {
    // A one-second token and a margin of 30 seconds: every token arrives
    // already inside its own safety margin, so nothing is ever served from the
    // cache and every operation gets a fresh one.
    let v = vertical(
        Duration::from_secs(1),
        Duration::from_secs(30),
        &AsClient::awkward(),
    );
    let mut first = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut first).expect("first");
    let mut second = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut second).expect("second");
    assert_eq!(
        v.grants.0.load(Ordering::SeqCst),
        2,
        "a token shorter than the margin must never be cached"
    );
    assert_eq!(at_resource(&v.server, &first.seen), 200);
    assert_eq!(at_resource(&v.server, &second.seen), 200);
}

/// A provider that stops answering must stop the operation, not produce a
/// credential. The sink is not reached, which is the observable that matters.
#[test]
fn a_provider_that_stops_answering_stops_the_operation() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    v.server.set_offline(true);

    let mut agent = AgentSide::default();
    assert!(matches!(
        v.port.lend(CREDENTIAL_ID, &mut agent),
        Err(SecretError::Unavailable(_))
    ));
    assert_eq!(
        agent.accepts, 0,
        "an operation must not receive anything when the provider refuses"
    );
}

/// A revocation the broker has not heard about yet is bounded by the token's
/// lifetime, and `forget` is how an operator makes it immediate. Checked as a
/// pair, because either half alone is satisfiable by a port that simply never
/// cached anything.
#[test]
fn forgetting_a_credential_takes_effect_at_once() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    let mut first = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut first).expect("first");
    assert_eq!(v.grants.0.load(Ordering::SeqCst), 1);

    v.port.forget(CREDENTIAL_ID);
    let mut second = AgentSide::default();
    v.port.lend(CREDENTIAL_ID, &mut second).expect("second");
    assert_eq!(
        v.grants.0.load(Ordering::SeqCst),
        2,
        "a new grant was asked for"
    );
    assert_ne!(first.seen, second.seen);
    assert_eq!(at_resource(&v.server, &second.seen), 200);
}

/// A provider that grants more than the operator configured is refused before
/// the operation receives anything.
#[test]
fn an_escalated_scope_never_reaches_the_operation() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    v.server
        .override_scope("read:pods write:pods admin:everything");

    let mut agent = AgentSide::default();
    assert!(matches!(
        v.port.lend(CREDENTIAL_ID, &mut agent),
        Err(SecretError::Unavailable(message)) if message.contains("scope escalated"),
    ));
    assert_eq!(agent.accepts, 0, "nothing may reach the operation");
}

/// A credential the port is not registered for is `NotFound`, and the sink is
/// not reached.
#[test]
fn an_unregistered_credential_is_refused_before_the_vault_is_opened() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    let mut agent = AgentSide::default();
    assert!(matches!(
        v.port.lend("no-such-credential", &mut agent),
        Err(SecretError::NotFound(_))
    ));
    assert_eq!(agent.accepts, 0);
}

/// A vault whose secret does not match the registered client fails the
/// authentication, so the vertical cannot be satisfied by a mismatched pair
/// quietly falling back to something else.
#[test]
fn a_vault_secret_that_does_not_match_the_client_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let as_client = AsClient::awkward();
    let server = AuthorizationServer::start(as_client.clone());
    let grants = Arc::new(Grants::default());
    let factory = Arc::new(FixtureIssuer {
        port: server.port(),
        host: server.host().to_string(),
        certificate: server.certificate(),
        grants: Arc::clone(&grants),
    });
    // The vault holds a different secret than the provider was told about.
    let port = OAuth2SecretPort::with_parts(
        vault_port(&dir, "not-the-registered-secret"),
        vec![OAuth2Client {
            credential: CREDENTIAL_ID.to_string(),
            client_id: as_client.client_id.clone(),
            token_url: server.url("/token"),
            audience: RESOURCE_AUDIENCE.to_string(),
            scope: "read:pods".to_string(),
        }],
        factory,
    )
    .with_margin(Duration::ZERO);

    let mut agent = AgentSide::default();
    assert!(matches!(
        port.lend(CREDENTIAL_ID, &mut agent),
        Err(SecretError::Unavailable(_))
    ));
    assert_eq!(agent.accepts, 0);
    assert_eq!(server.audit_with_outcome("bad_credentials").len(), 1);
}

/// The port lists only what it was configured with, which is what an operator
/// reads to answer "which credentials does this broker trade for tokens".
#[test]
fn the_port_answers_only_for_what_it_was_configured_with() {
    let v = vertical(
        Duration::from_secs(300),
        Duration::ZERO,
        &AsClient::awkward(),
    );
    assert_eq!(v.port.credentials(), vec![CREDENTIAL_ID.to_string()]);
}
