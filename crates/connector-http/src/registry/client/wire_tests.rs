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

/// A realm that says nothing about how long its token lives, which is a shape
/// the specification permits and this client has to survive.
fn forgetful_token_origin(scope: &str) -> TlsOrigin {
    let body = format!(r#"{{"token":"{TOKEN}","scope":"{scope}"}}"#);
    TlsOrigin::start(
        NAME,
        Arc::new(move |_| OriginResponse::json(200, body.clone())),
    )
}

/// The scope a request line asked for, decoded.
///
/// `reqwest` percent-encodes the query, and a fixture that guessed the encoding
/// would be a fixture that only works for the spelling it guessed.
fn asked_scope(request_line: &str) -> String {
    request_line
        .split("scope=")
        .nth(1)
        // The query ends at the `&` and at the space before `HTTP/1.1`, and
        // both of those were part of the scope the first version built -- which
        // is a reminder that a fixture which reads the wire is a fixture that
        // has to read the wire correctly.
        .and_then(|rest| rest.split(['&', ' ']).next())
        .unwrap_or("")
        .replace("%3A", ":")
        .replace("%2F", "/")
}

/// A realm that grants exactly the scope it was asked for.
///
/// An earlier version widened the grant with the second action, so that a pull
/// and a push could both be covered by one exchange -- and a scope is one
/// `repository:<name>:<actions>`, so a grant naming two repositories is not a
/// grant, it is a parse error the row then blamed on the client. Returning
/// what was asked is also what a real endpoint does, and it leaves the
/// narrowing in R2.F.1 to be the thing under test rather than this fixture.
fn exact_token_origin() -> TlsOrigin {
    TlsOrigin::start(
        NAME,
        Arc::new(|observed: &Observed| {
            let asked = asked_scope(&observed.request_line);
            OriginResponse::json(
                200,
                format!(r#"{{"token":"{TOKEN}","expires_in":300,"scope":"{asked}"}}"#),
            )
        }),
    )
}

/// A registry that answers both halves of the surface, so one client can be
/// asked to pull and then to push against the same origin.
fn both_ways_origin(realm_url: &str) -> TlsOrigin {
    let challenge = format!(
        r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:library/alpine:pull,push""#
    );
    TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if !bearer {
                return OriginResponse::new(401, "").with_header("www-authenticate", &challenge);
            }
            if observed.request_line.starts_with("PUT ") {
                OriginResponse::new(201, "")
            } else {
                OriginResponse::new(200, r#"{"schemaVersion":2}"#)
                    .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
            }
        }),
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

// ------------------------------------------------------------------ the cache

/// A pull is dozens of requests. Redeeming a token for each of them is not a
/// connector, it is a load generator pointed at the token endpoint.
///
/// The row counts the token endpoint's connections rather than the client's
/// state, because the thing being claimed is about the wire.
///
/// Mutation: skip the cache lookup, or store nothing after a redemption.
#[test]
fn un_token_se_canjea_una_vez_para_varias_peticiones() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    for _ in 0..4 {
        client
            .get_manifest(&pinned_to(&registry), &repository(), &reference())
            .expect("each read completes");
    }

    // Two requests per read: the anonymous one and the authenticated retry.
    assert_eq!(registry.observed().len(), 8, "the reads did not all happen");
    assert_eq!(
        realm.observed().len(),
        1,
        "the token endpoint was asked {} times",
        realm.observed().len()
    );
}

/// A token redeemed for a pull is not reachable from a push, which is the whole
/// reason the action is in the cache key. Docker Hub grants `pull,push` to a
/// pull, so the token this client holds genuinely can push -- and the client
/// must still not hand it to the push path.
///
/// Mutation: drop `action` from the key.
#[test]
fn un_token_cacheado_para_un_pull_nunca_sirve_para_un_push() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = both_ways_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("the pull completes");
    client
        .put_manifest(&pinned_to(&registry), &repository(), &reference(), b"{}")
        .expect("the push completes");

    assert_eq!(
        realm.observed().len(),
        2,
        "the push reused the pull's token, which carries a push grant"
    );
    // And the push asked for a push, so the second redemption was not a
    // widened one either.
    let asked = realm.observed();
    assert!(
        asked[1].request_line.contains("push"),
        "{}",
        asked[1].request_line
    );
    assert!(
        !asked[1].request_line.contains("pull"),
        "{}",
        asked[1].request_line
    );
}

/// A token for one repository is not a token for another, and the cache has to
/// know that rather than the token endpoint having to be asked twice to prove
/// it.
///
/// Mutation: drop `repository` from the key.
#[test]
fn un_token_de_otro_repositorio_no_se_reutiliza() {
    let realm = exact_token_origin();
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    for name in ["library/alpine", "library/other", "library/alpine"] {
        client
            .get_manifest(
                &pinned_to(&registry),
                &RepositoryName::parse(name).expect("valid"),
                &reference(),
            )
            .unwrap_or_else(|e| panic!("{name} could not be read: {e}"));
    }

    // Two redemptions for three reads: `library/alpine` twice, `library/other`
    // once. The registry challenged for `library/alpine` on all three, and the
    // read of `library/other` still asked the token endpoint for
    // `library/other` -- which is property 1 of R2.F.1 measured on the wire
    // rather than in memory.
    assert_eq!(
        realm.observed().len(),
        2,
        "the second repository reused a token"
    );
    let observed = realm.observed();
    let asked: Vec<&str> = observed.iter().map(|o| o.request_line.as_str()).collect();
    assert!(
        asked
            .iter()
            .any(|line| line.contains("library%2Fother") || line.contains("library/other")),
        "the read of library/other never asked for it: {asked:?}"
    );
}

/// A deleted credential stops being served, which is the obligation
/// `SecretPort::forget` exists to place on this side of the port.
///
/// Mutation: make `forget` a no-op, or clear more than the named credential.
#[test]
fn una_credencial_retirada_deja_de_servirse() {
    let realm = token_origin("repository:library/alpine:pull,push", 200);
    let registry = registry_origin(&realm.url("/token"));
    let port = RecordingPort::new();
    let client = client_for(
        &[&registry, &realm],
        Arc::clone(&port) as Arc<dyn SecretPort>,
    );

    client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("the first read completes");
    assert_eq!(client.cached_tokens(), 1);

    // The port is told first, then the token it redeemed is dropped: the order
    // matters, because a port that is told and a client that still answers is
    // a deleted credential that keeps working.
    port.forget(CREDENTIAL);
    client.forget(CREDENTIAL);
    assert_eq!(
        client.cached_tokens(),
        0,
        "the token outlived the credential"
    );

    client
        .get_manifest(&pinned_to(&registry), &repository(), &reference())
        .expect("the second read completes");
    assert_eq!(
        realm.observed().len(),
        2,
        "the read after the deletion was served from a token that should be gone"
    );
}

/// A token endpoint that does not say how long its token lives gets no cache,
/// because a guessed lifetime for a credential this side cannot watch is how a
/// cache becomes a way to serve something the provider has withdrawn.
///
/// Mutation: store a token whose response carried no `expires_in`.
#[test]
fn un_token_sin_expires_in_no_se_cachea() {
    let realm = forgetful_token_origin("repository:library/alpine:pull,push");
    let registry = registry_origin(&realm.url("/token"));
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    for _ in 0..3 {
        client
            .get_manifest(&pinned_to(&registry), &repository(), &reference())
            .expect("each read completes");
    }

    assert_eq!(client.cached_tokens(), 0, "an un-timed token was cached");
    assert_eq!(
        realm.observed().len(),
        3,
        "a token with no stated end was served more than once"
    );
}

// -------------------------------------------------------------------- blobs

/// A registry that answers the challenge, and then serves one fixed blob body
/// for anything under `/blobs/`.
///
/// The body is a parameter rather than a constant because the rows below differ
/// only in which bytes the registry claims, and a fixture that could only serve
/// one of them would make the disagreement the one case untested.
fn blob_origin(realm_url: &str, layer: Vec<u8>) -> TlsOrigin {
    let challenge = format!(
        r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:library/alpine:pull""#
    );
    TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let has_bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if !has_bearer {
                return OriginResponse::new(401, "").with_header("www-authenticate", &challenge);
            }
            OriginResponse::bytes(200, layer.clone()).with_header(
                "content-type",
                "application/vnd.oci.image.layer.v1.tar+gzip",
            )
        }),
    )
}

/// A registry that answers the challenge, serves one fixed blob body, and
/// *asserts in a header* a digest that is not the one those bytes have.
///
/// The header is the whole point, so it is not optional: a fixture that only
/// served mismatched bytes would let a client that reads
/// `Docker-Content-Digest` pass this row by accident.
fn lying_origin(realm_url: &str, layer: Vec<u8>, claimed: String) -> TlsOrigin {
    let challenge = format!(
        r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:library/alpine:pull""#
    );
    TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let has_bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if !has_bearer {
                return OriginResponse::new(401, "").with_header("www-authenticate", &challenge);
            }
            OriginResponse::bytes(200, layer.clone()).with_header("docker-content-digest", &claimed)
        }),
    )
}

/// A blob arrives and the bytes are the bytes, over a real socket, with the
/// digest they actually have.
///
/// This is the positive half. Without it, a `get_blob` that always returned
/// `Err` would satisfy every refusal row in this section.
///
/// Mutation: return the bytes as a `String`, which silently replaces anything
/// that is not valid UTF-8 and is the mistake the next row exists to catch.
#[test]
fn un_blob_que_cumple_su_digest_llega_como_sono_sus_bytes() {
    // A gzip layer starts 0x1f 0x8b and is otherwise not text at all.
    let layer: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00, 0x41, 0x0a];
    let realm = exact_token_origin();
    let registry = blob_origin(&realm.url("/token"), layer.clone());
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let read = client
        .get_blob(
            &pinned_to(&registry),
            &repository(),
            &ContentDigest::of(&layer),
        )
        .expect("a blob that carries its digest is not a failure");

    assert_eq!(read.bytes, layer, "the bytes were altered in transit");
    assert_eq!(
        read.digest,
        ContentDigest::of(&layer),
        "the returned digest is not the one the bytes have"
    );
    assert_eq!(
        read.media_type.as_deref(),
        Some("application/vnd.oci.image.layer.v1.tar+gzip"),
        "the registry's own type for the layer was dropped"
    );
}

/// A registry that answers a blob request with bytes it does not have is
/// refused, and the refusal says which bytes arrived.
///
/// This is the row the whole method exists for. A registry is the party that
/// names the digest; if its claim is not checked against the bytes, a hostile
/// or broken registry can hand over different layers and every later
/// verification will agree, because the manifest will name the digests of
/// whatever arrived.
///
/// Mutation: return the body without comparing it, or compare the request
/// digest against itself.
#[test]
fn un_blob_que_no_cumple_su_digest_no_se_instala() {
    let asked_for = ContentDigest::of(b"the-layer-the-manifest-named");
    let served = b"a-completely-different-layer".to_vec();
    let realm = exact_token_origin();
    let registry = blob_origin(&realm.url("/token"), served.clone());
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_blob(&pinned_to(&registry), &repository(), &asked_for)
        .expect_err("bytes that do not carry the digest asked for must not be returned");

    // The refusal has to name *both* digests. A message that only says
    // "mismatch" is a message that leaves the operator to work out which side
    // lied, and a corrupt mirror and a tampered layer want opposite responses.
    assert!(
        matches!(&error, RegistryError::Blob(BlobError::DigestMismatch { expected, found })
            if expected == &asked_for.to_string()
                && found == &ContentDigest::of(&served).to_string()),
        "the refusal did not name the digest asked for and the digest arrived: {error:?}"
    );
}

/// A digest the registry *claims* in a header does not stand in for the hash
/// of the bytes it sent.
///
/// This is the row that the previous third row should have been. It is not a
/// rephrasing of "the mismatch is refused" -- it is the one shape that refusal
/// alone would not catch. A registry that answers with bytes the caller did not
/// ask for can simply assert the digest it was asked for in
/// `Docker-Content-Digest`, and a client that believes the header agrees with
/// itself: the claim matches the request, the request matches the manifest, and
/// the manifest was never checked against the layer either. Nothing in the
/// protocol stops the assertion, so only hashing the body closes it.
///
/// The header is therefore a claim to be ignored, not a second source of truth.
///
/// Mutation: take the digest from the response header instead of hashing the
/// body.
#[test]
fn el_digest_que_el_registry_afirma_en_una_cabecera_no_sustituye_al_hash() {
    let asked_for = ContentDigest::of(b"the-layer-the-manifest-named");
    let served = b"an-entirely-different-layer".to_vec();
    let realm = exact_token_origin();
    let registry = lying_origin(&realm.url("/token"), served, asked_for.to_string());
    let client = client_for(
        &[&registry, &realm],
        RecordingPort::new() as Arc<dyn SecretPort>,
    );

    let error = client
        .get_blob(&pinned_to(&registry), &repository(), &asked_for)
        .expect_err("a header saying the right digest is not a reason to install the wrong bytes");

    // And the error has to name the bytes that actually arrived, not the ones
    // the registry said it sent. A `found` that echoes the header would pass a
    // `matches!` on the variant while telling the operator nothing.
    assert!(
        matches!(&error, RegistryError::Blob(BlobError::DigestMismatch { expected, found })
            if expected == &asked_for.to_string()
                && found == &ContentDigest::of(b"an-entirely-different-layer").to_string()
                && found != expected),
        "the refusal repeated the registry's own claim instead of naming the bytes: {error:?}"
    );
}
