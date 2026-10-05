//! The registry loop against real sockets: a real `401`, a real token exchange
//! and a real retry.
//!
//! These rows exist because the properties R2.F.1 decides are properties of
//! what goes on the wire. A unit test can prove that `narrow` intersects and
//! that `token_query` names the operation; it cannot prove that the first
//! request carries no `Authorization`, that the long credential reaches the
//! `realm` and nothing else, or that a hostile realm never gets a connection.
//! All three are only visible here.
//!
//! Two origins, both on loopback under the same name, because the realm is
//! vetted through `resolve_and_pin` and so has to be a name that resolves. The
//! name has two labels because `Authority::canonicalize` refuses a bare one.
//! The port is the origin's own, which is why `Realm::vet_reaching` exists and
//! why the row that says it is production-only is written the way it is.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use asv_domain::Authority;

use super::*;
use crate::fake_origin::{Observed, OriginResponse, Reply, TlsOrigin};
use crate::github::SecretError;
use crate::transport::ResolvedAudience;

const NAME: &str = "localhost.localdomain";
const CREDENTIAL: &str = "registry-credential";
const SECRET: &str = "hunter2-the-registry-password";
const TOKEN: &str = "issued-token-value";

/// A port that hands out one secret and records every name it was asked for.
struct RecordingPort {
    lent: Mutex<Vec<String>>,
}

impl RecordingPort {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            lent: Mutex::new(Vec::new()),
        })
    }

    fn lent(&self) -> Vec<String> {
        self.lent.lock().expect("uncontended").clone()
    }
}

impl SecretPort for RecordingPort {
    /// A fixture holding nothing derived. A real port caches the token it
    /// redeemed, and that cache is what `forget` has to be able to drop --
    /// which is why this fixture says so rather than leaving it to a default.
    fn forget(&self, _credential: &str) {}

    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        self.lent
            .lock()
            .expect("uncontended")
            .push(credential.to_string());
        sink.accept(SECRET.as_bytes())
    }
}

/// A port that refuses every credential, standing in for a locked vault.
struct ClosedPort;

impl SecretPort for ClosedPort {
    fn forget(&self, _credential: &str) {}

    fn lend(&self, credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::Unavailable(credential.to_string()))
    }
}

fn policy() -> AddressPolicy {
    AddressPolicy {
        allow_loopback: true,
    }
}

fn pinned_to(origin: &TlsOrigin) -> ResolvedAudience {
    ResolvedAudience {
        authority: Authority::canonicalize(NAME).expect("a two-label name"),
        port: origin.port,
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

fn client_for(roots: &[&TlsOrigin], port: Arc<dyn SecretPort>) -> RegistryClient {
    let realm_port = roots
        .get(1)
        .map(|origin| origin.port)
        .unwrap_or(roots[0].port);
    RegistryClient::trusting(
        port,
        CREDENTIAL,
        policy(),
        roots.iter().map(|o| o.certificate()).collect(),
    )
    .reaching_realm_on(realm_port)
    .reaching_realm_at(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
}

fn repository() -> RepositoryName {
    RepositoryName::parse("library/alpine").expect("valid")
}

fn reference() -> ImageReference {
    ImageReference::parse("latest").expect("valid")
}

/// A realm that grants everything the challenge asked for, which is what a
/// real token endpoint does and the reason the narrowing has to be this side's
/// job.
fn token_origin(scope: &str, status: u16) -> TlsOrigin {
    let body = format!(r#"{{"token":"{TOKEN}","expires_in":300,"scope":"{scope}"}}"#);
    TlsOrigin::start(
        NAME,
        Arc::new(move |_| OriginResponse::json(status, body.clone())),
    )
}

/// A registry that refuses anything without a bearer and serves the manifest
/// to anything with one.
fn registry_origin(realm_url: &str) -> TlsOrigin {
    let challenge = format!(
        r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:library/alpine:pull,push""#
    );
    TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let has_bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if has_bearer {
                OriginResponse::new(200, r#"{"schemaVersion":2}"#)
                    .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
            } else {
                OriginResponse::new(401, "").with_header("www-authenticate", &challenge)
            }
        }),
    )
}

/// The whole loop, against two real origins.
///
/// This is the row the module exists for. It is also the row that would fail if
/// the challenge's `scope` were forwarded: the token endpoint's own record of
/// what it was asked for is in its request line, and the assertion reads that
/// rather than the code that built it.
///
/// Mutation: pass the challenge's scope to `token_url`.
#[test]
fn a_challenge_carries_the_broker_to_a_narrowed_token_and_back() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let port = RecordingPort::new();
    let client = client_for(
        &[&registry, &realm],
        Arc::clone(&port) as Arc<dyn SecretPort>,
    );

    let read = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("the loop completes");

    assert_eq!(read.body, br#"{"schemaVersion":2}"#);
    assert_eq!(
        read.content_type.as_deref(),
        Some("application/vnd.oci.image.manifest.v1+json")
    );

    // The registry saw two requests: one anonymous, one with the token.
    let seen = registry.observed();
    assert_eq!(seen.len(), 2, "{seen:#?}");
    assert!(
        !seen[0]
            .headers
            .iter()
            .any(|(name, _)| name == "authorization"),
        "the first request must carry no credential: {:?}",
        seen[0].headers
    );
    assert_eq!(
        seen[1]
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str()),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    // The token endpoint was asked for the operation's scope, not the
    // challenge's, and it granted a wider one that nothing used.
    let asked = realm.observed();
    assert_eq!(asked.len(), 1, "{asked:#?}");
    assert!(
        asked[0]
            .request_line
            .contains("scope=repository%3Alibrary%2Falpine%3Apull")
            || asked[0]
                .request_line
                .contains("scope=repository:library/alpine:pull"),
        "{}",
        asked[0].request_line
    );
    assert!(
        !asked[0].request_line.contains("push"),
        "the challenge's extra action reached the token endpoint: {}",
        asked[0].request_line
    );

    // One lend, for one exchange.
    assert_eq!(port.lent(), vec![CREDENTIAL.to_string()]);
}

/// The long-lived credential goes to the realm and nowhere else. The registry
/// is the party the agent is talking to, and a broker that showed it the vault
/// password would have given away the one thing the token was there to avoid.
///
/// Mutation: attach the credential to the registry request, or lend it twice.
#[test]
fn the_stored_credential_reaches_the_realm_and_nothing_else() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let port = RecordingPort::new();
    let client = client_for(
        &[&registry, &realm],
        Arc::clone(&port) as Arc<dyn SecretPort>,
    );

    client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("the loop completes");

    let encoded = base64::engine::general_purpose::STANDARD.encode(SECRET.as_bytes());
    let basic = format!("Basic {encoded}");

    for observed in registry.observed() {
        assert!(
            !observed.headers.iter().any(|(_, value)| value == &basic),
            "the registry saw the stored credential"
        );
        assert!(
            !observed
                .headers
                .iter()
                .any(|(_, value)| value.contains(SECRET)),
            "the registry saw the stored credential in the clear"
        );
    }
    let asked = realm.observed();
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0]
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str()),
        Some(basic.as_str())
    );
}

/// A realm that grants less than the operation needs stops the operation. The
/// token is in memory when this returns, and the row is what says it was not
/// spent.
///
/// Mutation: return the granted scope's token regardless of `narrow`.
#[test]
fn a_grant_that_does_not_cover_the_operation_never_reaches_the_retry() {
    let realm = token_origin("repository:library/alpine:pull", 200);
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    // The challenge in `registry_origin` names `pull,push`, so this is a pull
    // the realm would have allowed -- the push is what it refuses.
    let error = client
        .put_manifest(&pinned_to(&registry), &repository(), &reference(), b"{}")
        .expect_err("a grant of pull cannot push");

    assert!(
        matches!(
            error,
            RegistryError::Scope(ScopeError::InsufficientGrant { .. })
        ),
        "{error}"
    );
    assert_eq!(
        registry.observed().len(),
        1,
        "the retry was built anyway: {:#?}",
        registry.observed()
    );
}

/// A grant for a different repository is the confused deputy, and the refusal
/// has to happen before the retry rather than after it.
///
/// Mutation: compare only the actions in `narrow`.
#[test]
fn a_grant_for_another_repository_never_reaches_the_retry() {
    let realm = token_origin("repository:someone/else:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("a grant for another repository covers nothing");

    assert!(
        matches!(
            error,
            RegistryError::Scope(ScopeError::WrongRepository { .. })
        ),
        "{error}"
    );
    assert_eq!(registry.observed().len(), 1);
}

/// A realm the vetting refuses never receives a connection, so the listener an
/// attacker would want to reach is never spoken to.
///
/// The realm here is named over plain http, which `Realm::vet` refuses before
/// it looks at the host at all. The loopback refusal is **not** filed here and
/// the reason is worth stating: `RegistryClient` carries one address policy for
/// both the registry and the realm, and in this fixture the registry is on
/// loopback, so a row that turned the policy off for the realm would have had
/// no registry to talk to. That refusal is measured where the policy can be
/// set on its own -- `a_realm_that_resolves_to_loopback_is_refused` in
/// `registry::tests`, with a production policy and a name that resolves.
///
/// Mutation: follow the realm anyway, or build the token request before the
/// vetting.
#[test]
fn a_realm_the_vetting_refuses_never_receives_a_connection() {
    let trap = TlsOrigin::start(NAME, Arc::new(|_| OriginResponse::json(200, "{}")));
    // The trap is reachable, and the challenge names it in the clear.
    let trap_url = trap.url("/token").replacen("https://", "http://", 1);
    let registry = registry_origin(&trap_url);
    let client = client_for(
        &[&registry, &trap],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("a plaintext realm is not a token endpoint");

    assert!(
        matches!(error, RegistryError::Realm(RealmError::NotHttps { .. })),
        "{error}"
    );
    assert_eq!(trap.connections(), 0, "the trap was reached");
    assert_eq!(registry.observed().len(), 1, "a retry was built anyway");
}

/// The loop only exists to answer a challenge. A registry that answers `200`
/// to an anonymous pull never gets a credential lent, because a broker that
/// opened the vault for a request nobody authenticated would be doing work for
/// no reason and handing its password to a registry that had not asked.
///
/// Mutation: lend before the first request, or retry even on success.
#[test]
fn an_anonymous_pull_never_opens_the_vault() {
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(|_| {
            OriginResponse::new(200, r#"{"schemaVersion":2}"#)
                .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
        }),
    );
    let port = RecordingPort::new();
    let client = client_for(&[&registry], Arc::clone(&port) as Arc<dyn SecretPort>);

    let read = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("an anonymous pull needs no token");
    assert_eq!(read.body, br#"{"schemaVersion":2}"#);

    assert!(port.lent().is_empty(), "the vault was opened anyway");
    assert_eq!(registry.observed().len(), 1, "there was no second attempt");
    assert!(
        !registry.observed()[0]
            .headers
            .iter()
            .any(|(name, _)| name == "authorization"),
        "the anonymous request carried a credential"
    );
}

/// A `401` with no `WWW-Authenticate` is a refusal, not a puzzle. A client
/// that guessed a token endpoint would be inventing a credential source, and
/// inventing one on a registry's say-so is how a redirect becomes an SSRF.
///
/// Mutation: fall back to a default realm.
#[test]
fn a_refusal_without_a_challenge_is_not_a_puzzle() {
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(|_| OriginResponse::new(401, "credentials required")),
    );
    let client = client_for(&[&registry], RecordingPort::new() as Arc<dyn SecretPort>);

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("no challenge, no token");

    assert!(matches!(error, RegistryError::NoChallenge), "{error}");
    assert_eq!(registry.observed().len(), 1);
}

/// A registry that keeps refusing after a valid token is reported as what it
/// is, rather than as an empty manifest.
///
/// Mutation: return the body whatever the status is.
#[test]
fn a_second_refusal_is_reported_and_not_read_as_a_manifest() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let challenge = format!(
        r#"Bearer realm="{}",service="registry.docker.io",scope="repository:library/alpine:pull,push""#,
        realm.url("/token")
    );
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(move |_| OriginResponse::new(401, "").with_header("www-authenticate", &challenge)),
    );
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("a second refusal is not a manifest");

    assert!(
        matches!(
            error,
            RegistryError::UnexpectedStatus {
                status: 401,
                expected: 200
            }
        ),
        "{error}"
    );
    // And it stopped: one challenge, one exchange, no third attempt.
    assert_eq!(registry.observed().len(), 2);
}

/// A locked vault stops the operation at the exchange rather than sending an
/// unauthenticated retry and calling it a refusal.
///
/// Mutation: treat a failed lend as an empty token.
#[test]
fn a_locked_vault_stops_the_exchange() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        Arc::new(ClosedPort) as Arc<dyn SecretPort>,
    );

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("no credential, no token");

    assert!(matches!(error, RegistryError::Secret(_)), "{error}");
    assert_eq!(
        realm.connections(),
        0,
        "the token endpoint was reached anyway"
    );
    assert_eq!(registry.observed().len(), 1);
}

/// A token endpoint that refuses is reported with the status it refused with,
/// because "the token request failed" and "the token endpoint said 403" lead
/// the operator to different places.
///
/// Mutation: collapse every non-success into one error.
#[test]
fn a_refusing_token_endpoint_names_its_status() {
    let realm = token_origin("repository:library/alpine:pull,push", 403);
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect_err("a refusing token endpoint stops the loop");

    assert!(
        matches!(error, RegistryError::TokenEndpointRefused { status: 403 }),
        "{error}"
    );
    assert_eq!(registry.observed().len(), 1, "a retry was built anyway");
}

/// The push half of the surface, which is the one that can write. It has to
/// work, or "a pull became a push" would be the only outcome this client
/// offers.
///
/// Mutation: keep expecting `200` for a `PUT`.
#[test]
fn a_push_asks_for_a_push_and_takes_the_answered_manifest() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let challenge = format!(
        r#"Bearer realm="{}",service="registry.docker.io",scope="repository:library/alpine:pull,push""#,
        realm.url("/token")
    );
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let has_bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if has_bearer {
                OriginResponse::new(201, "")
                    .with_header("location", "/v2/library/alpine/manifests/latest")
            } else {
                OriginResponse::new(401, "").with_header("www-authenticate", &challenge)
            }
        }),
    );
    let port = RecordingPort::new();
    let client = client_for(
        &[&registry, &realm],
        Arc::clone(&port) as Arc<dyn SecretPort>,
    );

    client
        .put_manifest(
            &pinned_to(&registry),
            &repository(),
            &reference(),
            br#"{"schemaVersion":2}"#,
        )
        .expect("the push half of the loop completes");

    let asked = realm.observed();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0]
            .request_line
            .contains("scope=repository%3Alibrary%2Falpine%3Apush")
            || asked[0]
                .request_line
                .contains("scope=repository:library/alpine:push"),
        "{}",
        asked[0].request_line
    );
    assert!(
        !asked[0].request_line.contains("pull"),
        "{}",
        asked[0].request_line
    );

    let seen = registry.observed();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[1].request_line.starts_with("PUT "),
        "{}",
        seen[1].request_line
    );
    assert_eq!(seen[1].body, r#"{"schemaVersion":2}"#);
}

/// The scripted origin answers the same thing every time, so this row is a
/// check that the `WithHeaders` reply really does reach the wire -- the reason
/// that variant was added to the fixture in the first place.
///
/// Mutation: drop the headers when building the response.
#[test]
fn a_reply_can_carry_the_header_a_registry_would() {
    let origin = TlsOrigin::start(
        NAME,
        Arc::new(|_| {
            OriginResponse::new(401, "").with_header(
                "www-authenticate",
                r#"Bearer realm="https://auth.docker.io/token""#,
            )
        }),
    );
    let resolved = pinned_to(&origin);
    let client = PinnedClient::build_with_roots(&resolved, policy(), &[origin.certificate()])
        .expect("builds");
    let url = client
        .url(&resolved, "/v2/x/manifests/latest")
        .expect("url");

    let response = client.client().get(url).send().expect("answers");
    assert_eq!(response.status(), 401);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some(r#"Bearer realm="https://auth.docker.io/token""#)
    );
    // And the scripted shape still works, so the new variant did not displace
    // the one the rest of the crate's tests use.
    let scripted = crate::fake_origin::start(Reply::Json("{}".to_string()));
    assert!(
        scripted.url("/x").starts_with("https://"),
        "the scripted origin still builds a URL"
    );
}
