//! Rows for the Kubernetes transport.
//!
//! The property under test is the one that is *not* the same as AWS's. An AWS
//! request is signed, and a signature can be held; a Kubernetes bearer token
//! cannot be, because the header **is** the credential. So most of these rows
//! are about where the token is allowed to be, and about what happens when the
//! origin tries to move it somewhere else.
//!
//! The origin is a real TLS server in every case. No row here is satisfied by
//! a mock, because "the header was built correctly" is only observable at the
//! socket.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_connector_http::fake_origin::{Observed, OriginResponse, TlsOrigin};
use asv_connector_http::transport::{AddressPolicy, ResolvedAudience};
use asv_domain::Authority;

use super::super::request::{ApiRequest, Scope, Verb};
use super::super::{K8sSecretPort, MAX_TOKEN_BYTES};
use super::{method_for, BearerSink, K8sClient, K8sClientError, MAX_REPLY_BYTES};
use asv_connector_http::SecretSink;

const API_HOST: &str = "kubernetes.default.svc";
const OTHER_HOST: &str = "attacker.example";
const NS: &str = "default";
const TOKEN: &[u8] = b"eyJhbGciOiJSUzI1NiJ9.fixture-service-account-token";

/// Writes a token to a file the port can be built over.
fn token_file(contents: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "asv-k8s-client-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("token");
    std::fs::write(&path, contents).expect("write token");
    path
}

fn port() -> K8sSecretPort {
    K8sSecretPort::new(token_file(TOKEN)).expect("absolute path")
}

/// An origin that answers with one fixed reply and records what it saw.
fn origin<F>(certified_for: &str, handler: F) -> TlsOrigin
where
    F: Fn(&Observed) -> OriginResponse + Send + Sync + 'static,
{
    TlsOrigin::start(certified_for, Arc::new(handler))
}

fn audience_for(origin: &TlsOrigin) -> ResolvedAudience {
    ResolvedAudience {
        authority: Authority::canonicalize(&origin.certified_for).expect("canonical audience"),
        port: origin.port,
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

fn client_for(origin: &TlsOrigin) -> K8sClient {
    K8sClient::new_with_roots(
        audience_for(origin),
        AddressPolicy {
            allow_loopback: true,
        },
        Some(std::time::Duration::from_secs(5)),
        &[origin.certificate()],
    )
    .expect("the fixture origin is usable over the pinned audience")
}

fn get(secret: &str) -> ApiRequest<'_> {
    ApiRequest {
        verb: Verb::Get,
        scope: Scope::Namespaced { namespace: NS },
        resource: "secrets",
        name: Some(secret),
    }
}

fn header_of(observed: &Observed, name: &str) -> Option<String> {
    observed
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

/// # The positive rows
///
/// A client that never sends anything passes every refusal below, so these come
/// first: they are what make the refusals mean something.

#[test]
fn a_get_reaches_the_origin_with_the_bearer_header_assembled_from_the_port() {
    let origin = origin(API_HOST, |_| {
        OriginResponse::json(200, r#"{"kind":"Secret"}"#)
    });
    let client = client_for(&origin);

    let reply = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect("a well-formed get");

    assert!(reply.is_success(), "status {}", reply.status);
    let seen = origin.last().expect("the origin saw a request");
    assert_eq!(
        header_of(&seen, "authorization").as_deref(),
        Some("Bearer eyJhbGciOiJSUzI1NiJ9.fixture-service-account-token")
    );
    assert!(
        seen.request_line
            .starts_with("GET /api/v1/namespaces/default/secrets/db-credentials"),
        "{}",
        seen.request_line
    );
}

#[test]
fn a_client_that_never_sent_anything_would_fail_this() {
    // The counterpart of the row above, and the reason it is not decorative.
    // If a future change made `send` return `Ok` without opening a socket, this
    // fails while every refusal below still passes.
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let client = client_for(&origin);
    client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect("send");
    assert_eq!(
        origin.observed().len(),
        1,
        "exactly one request reached the origin"
    );
}

/// # The token must not travel
///
/// The row that decides whether this file is a security control or a
/// convenience wrapper.

#[test]
fn a_redirect_to_another_origin_is_refused_and_the_token_never_reaches_it() {
    // The first origin redirects to a *different* host. The transport is the
    // thing that has to notice, and the assertion that matters is on the
    // second origin: it must have seen nothing at all, token or otherwise.
    let victim = origin(OTHER_HOST, |_| {
        OriginResponse::json(200, r#"{"stolen":true}"#)
    });
    let victim_port = victim.port;
    let target = format!("https://{OTHER_HOST}:{victim_port}/collect");
    let api = origin(API_HOST, move |_| {
        OriginResponse::new(302, "").with_header("location", target.as_str())
    });
    let client = client_for(&api);

    let err = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect_err("a cross-origin redirect must be refused");

    assert!(
        matches!(err, K8sClientError::Transport(_)),
        "expected a transport refusal, got {err:?}"
    );
    assert!(
        victim.observed().is_empty(),
        "the token's own origin was reached: {:?}",
        victim.observed()
    );
}

#[test]
fn a_same_origin_redirect_is_followed_and_the_token_is_lent_again_for_it() {
    // The redirect stays on the pinned origin, so following it is correct. What
    // is being pinned here is the *re-lend*: the second attempt must obtain its
    // own copy from the port rather than reusing the first attempt's, because
    // the first attempt's sink is already dropped and zeroized by the time the
    // second one runs.
    let origin = origin(API_HOST, |observed| {
        if observed
            .request_line
            .contains("/api/v1/namespaces/default/secrets/db-credentials")
        {
            OriginResponse::new(302, "")
                .with_header("location", "/api/v1/namespaces/default/secrets/renamed")
        } else {
            OriginResponse::json(200, r#"{"kind":"Secret","metadata":{"name":"renamed"}}"#)
        }
    });
    let client = client_for(&origin);

    let reply = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect("a same-origin redirect is followed");

    assert!(reply.is_success());
    let seen = origin.observed();
    assert_eq!(seen.len(), 2, "both attempts reached the origin: {seen:?}");
    for request in &seen {
        assert_eq!(
            header_of(request, "authorization").as_deref(),
            Some("Bearer eyJhbGciOiJSUzI1NiJ9.fixture-service-account-token"),
            "every attempt carries a bearer header of its own"
        );
    }
}

/// # The sink hands the header over once
///
/// `take` is the whole reason the header is not just a local variable that a
/// later line could reuse.

#[test]
fn the_bearer_sink_hands_the_header_over_exactly_once() {
    let mut sink = BearerSink::new();
    sink.accept(TOKEN).expect("a well-formed token");
    assert!(sink.take().is_ok(), "the first take yields the header");
    assert!(
        sink.take().is_err(),
        "a second take must fail rather than re-yield the same credential"
    );
}

#[test]
fn a_sink_that_was_never_fed_refuses_to_hand_anything_over() {
    let mut sink = BearerSink::new();
    assert!(
        sink.take().is_err(),
        "a port that lent nothing must not produce an empty bearer header"
    );
}

#[test]
fn a_lend_error_means_no_header_and_no_request() {
    // The port is built over a path that does not exist, so `lend` refuses
    // before any sink is fed. The origin must see nothing: the refusal has to
    // happen before the socket, which is what makes an authorization worth
    // having.
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let client = client_for(&origin);
    let missing = K8sSecretPort::new("/nonexistent/asv/k8s/token").expect("absolute");

    let err = client
        .send(&missing, "k8s/default", &get("db-credentials"))
        .expect_err("an unreadable token is a refusal");

    assert!(matches!(err, K8sClientError::Secret(_)), "{err:?}");
    assert!(origin.observed().is_empty(), "nothing was sent");
}

/// # The refusal has to name the real cause
///
/// This row exists because the campaign found that the one above it could not
/// see a whole class of defect.
///
/// There are **two** defences between a failed `lend` and a socket: the `?` on
/// the call, and the sink's own refusal to hand over a header it was never fed.
/// Swallowing the `?` removes the first and leaves the second standing, so the
/// row above stays green — correctly, as to *whether* a request was sent, and
/// wrongly about everything an operator is told.
///
/// What the mutation actually introduces is a misdiagnosis. "The credential
/// could not be lent: the token file could not be read" becomes "the port lent
/// nothing to sign", which is true and useless: a missing mount, a permission
/// problem and a token with a control character in it are three different
/// pieces of work, and the operator is left with a message that names none of
/// them. This is the same defect the port itself had, one layer up, and it is
/// worth a row for that reason alone.
#[test]
fn a_lend_refusal_names_the_cause_rather_than_the_consequence() {
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let client = client_for(&origin);
    let missing = K8sSecretPort::new("/nonexistent/asv/k8s/token").expect("absolute");

    let err = client
        .send(&missing, "k8s/default", &get("db-credentials"))
        .expect_err("an unreadable token is a refusal");

    assert!(
        format!("{err}").contains("could not be read"),
        "the refusal must carry the port's own reason, not a generic one: {err}"
    );
    assert!(
        !format!("{err}").contains("lent nothing to sign"),
        "a generic consequence is not a diagnosis: {err}"
    );
}

/// # The transport keeps its rows
///
/// The refusals [`PinnedClient`](asv_connector_http::transport::PinnedClient)
/// already makes. They are re-asserted here rather than inherited, because a
/// client that assembled a request around a pinned client is exactly where a
/// bypass would be introduced by accident.

#[test]
fn a_client_is_refused_when_the_audience_is_a_private_address() {
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let mut audience = audience_for(&origin);
    // 10.0.0.1 is RFC 1918. The production policy does not allow loopback and
    // never allows this; the row is here because a client that built its own
    // transport instead of using the pinned one would not notice.
    audience.addresses = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

    let err = K8sClient::new(audience, AddressPolicy::default(), None)
        .err()
        .expect("a private address must be refused");

    assert!(matches!(err, K8sClientError::Transport(_)), "{err:?}");
}

#[test]
fn a_client_is_refused_when_the_port_is_zero() {
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let mut audience = audience_for(&origin);
    audience.port = 0;

    let err = K8sClient::new(
        audience,
        AddressPolicy {
            allow_loopback: true,
        },
        None,
    )
    .err()
    .expect("port 0 never connects");

    assert!(matches!(err, K8sClientError::Transport(_)), "{err:?}");
}

#[test]
fn a_body_past_the_cap_is_refused_rather_than_truncated() {
    // Truncating would hand the caller a JSON document that fails to parse,
    // and the error would be about the document rather than about an origin
    // that is too large to be the API server.
    let oversized = "x".repeat(MAX_REPLY_BYTES + 1);
    let origin = origin(API_HOST, move |_| {
        OriginResponse::json(200, oversized.clone())
    });
    let client = client_for(&origin);

    let err = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect_err("an oversized body is refused");

    assert!(matches!(err, K8sClientError::Transport(_)), "{err:?}");
    assert!(
        format!("{err}").contains("larger than"),
        "the refusal has to name the cap: {err}"
    );
}

#[test]
fn a_body_exactly_at_the_cap_is_still_read() {
    // The other side of the previous row. A cap that refused its own boundary
    // would make the refusal above pass for the wrong reason.
    let at_cap = "x".repeat(MAX_REPLY_BYTES);
    let origin = origin(API_HOST, move |_| OriginResponse::new(200, at_cap.clone()));
    let client = client_for(&origin);

    let reply = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect("a body exactly at the cap is read");

    assert_eq!(reply.body.len(), MAX_REPLY_BYTES);
}

/// # A refusal status is a reply, not a client error
///
/// The distinction matters because authorization is a policy decision made
/// above this layer. A `403` is the API server answering, and collapsing it
/// into a client error would lose the status an audit record needs.

#[test]
fn a_forbidden_status_is_reported_as_a_reply_carrying_the_status() {
    let origin = origin(API_HOST, |_| {
        OriginResponse::json(403, r#"{"kind":"Status","code":403}"#)
    });
    let client = client_for(&origin);

    let reply = client
        .send(&port(), "k8s/default", &get("db-credentials"))
        .expect("403 is an answer, not a client failure");

    assert_eq!(reply.status, 403);
    assert!(!reply.is_success());
}

/// # The duplication is pinned, not hoped for
///
/// `method_for` repeats `Verb::method` so the HTTP method can be built without
/// a parse that can panic on the one path where a panic drops a token
/// mid-flight. Repetition is only acceptable if something would notice it
/// drifting, and this is that something.

#[test]
fn the_method_this_client_sends_is_the_method_the_request_core_names() {
    for verb in [Verb::Get, Verb::List, Verb::Create, Verb::Delete] {
        assert_eq!(
            method_for(verb).as_str(),
            verb.method(),
            "{verb:?} sends a different method here than the request core says"
        );
    }
}

#[test]
fn the_verbs_the_request_core_refuses_are_not_made_sendable_here() {
    // `Get` without a name is a list wearing a get's clothes. The refusal
    // belongs to the request core; this row pins that the client cannot be used
    // to route around it.
    let origin = origin(API_HOST, |_| OriginResponse::json(200, "{}"));
    let client = client_for(&origin);
    let nameless = ApiRequest {
        verb: Verb::Get,
        scope: Scope::Namespaced { namespace: NS },
        resource: "secrets",
        name: None,
    };

    let err = client
        .send(&port(), "k8s/default", &nameless)
        .expect_err("a nameless get is refused");

    assert!(matches!(err, K8sClientError::Request(_)), "{err:?}");
    assert!(origin.observed().is_empty(), "nothing was sent");
}

/// # Nothing here leaks the token into a diagnostic

#[test]
fn no_refusal_this_client_produces_contains_the_token() {
    // Each arm is provoked deliberately. A row that only checked one of them
    // would be a row about one arm.
    let origin = origin(API_HOST, |_| OriginResponse::json(200, ""));
    let client = client_for(&origin);
    let port = port();

    let mut rendered = Vec::new();

    // A well-formed request that the origin answers, so the success path's
    // types get rendered too.
    if let Ok(reply) = client.send(&port, "k8s/default", &get("db-credentials")) {
        rendered.push(format!("{reply:?}"));
    }
    // A request the core refuses.
    let nameless = ApiRequest {
        verb: Verb::Get,
        scope: Scope::Namespaced { namespace: NS },
        resource: "secrets",
        name: None,
    };
    if let Err(err) = client.send(&port, "k8s/default", &nameless) {
        rendered.push(format!("{err}"));
        rendered.push(format!("{err:?}"));
    }
    // A credential the port cannot read.
    let missing = K8sSecretPort::new("/nonexistent/asv/k8s/token").expect("absolute");
    if let Err(err) = client.send(&missing, "k8s/default", &get("db-credentials")) {
        rendered.push(format!("{err}"));
        rendered.push(format!("{err:?}"));
    }

    assert!(
        !rendered.is_empty(),
        "the rows above must have produced output"
    );
    let token = String::from_utf8_lossy(TOKEN);
    for text in &rendered {
        assert!(
            !text.contains(token.as_ref()),
            "a diagnostic repeated the token: {text}"
        );
    }
}

/// The port's own bound, named here so a row can assert the two agree rather
/// than each carrying its own number.
#[test]
fn the_token_bound_this_module_re_exports_is_the_ports_own() {
    assert_eq!(super::TOKEN_LIMIT, MAX_TOKEN_BYTES);
}
