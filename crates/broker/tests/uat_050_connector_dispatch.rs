//! UAT-050 — the broker dispatches on the request type, not a provider string.
//! M6-R1 — the broker dispatches on the request type, not a provider string.
//!
//! This suite was written ahead of the spec and originally took a number
//! nothing reserved, which it said so in this header. It is now normative:
//! UAT-050 is defined in `14-UAT-ADVERSARIAL.md` and owned by M6. The
//! decision is recorded rather than quietly applied — the suite always proved
//! the property, and the gap was that the roadmap could not gate on a test
//! whose id the spec did not recognise. What was provisional was the *number*,
//! never the property.
//!
use std::sync::Arc;

use asv_broker::{handle, BrokerState, LiveConnectorFactory};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_domain::AgentSessionId;
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};

fn self_peer() -> WorkloadIdentity {
    WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    })
}

/// A vault that is open but holds nothing.
///
/// Presence is what these tests need, not a credential. The broker refuses a
/// brokered operation when no store is open, so without this the request is
/// denied before it ever reaches a connector and the test learns nothing about
/// routing. With it, the request gets as far as the connector.
struct OpenVault;

impl SecretPort for OpenVault {
    /// A fixture holding nothing derived, so a deletion has nothing to drop.
    ///
    /// Written out rather than left to a default, because the trait requires
    /// this on purpose: a port that never considered revocation is the exact
    /// shape of bug that made `DeleteCredential` a no-op for cached tokens.
    fn forget(&self, _credential: &str) {}

    fn lend(&self, _credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::NotFound("no credential in this test".into()))
    }
}

/// A broker with a session owned by `peer`, a vault open, one declared
/// destination, and no async runtime.
///
/// No runtime means the PostgreSQL branch fails at a point unique to it, and
/// the vault being open means the request gets far enough to reach it.
///
/// The declared destination is not decoration: H5's destination gate runs
/// before the transport, so a factory with the default empty list would refuse
/// at the gate and these tests would pass without ever observing the routing
/// they are about. `db.example` at loopback is declared for exactly that reason.
fn broker_with_session(peer: &WorkloadIdentity) -> (BrokerState, AgentSessionId) {
    let state = BrokerState {
        connectors: Box::new(LiveConnectorFactory {
            destinations: vec![asv_broker::PgDestination::new(
                "db.example",
                "127.0.0.1".parse().expect("a literal address"),
            )
            .expect("a canonical host")],
            ..LiveConnectorFactory::default()
        }),
        secrets: Some(Arc::new(OpenVault)),
        ..Default::default()
    };
    let session = state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("/repo".into(), peer);
    (state, session)
}

/// True when `response` is the PostgreSQL branch's own refusal.
///
/// The message is written by the PostgreSQL path and by no other, so it is a
/// discriminator read from outside the broker rather than a test hook.
fn reached_postgres(response: &Response) -> bool {
    matches!(
        response,
        Response::Error { message, .. } if message.contains("postgres transport")
    )
}

/// A PostgreSQL request reaches the PostgreSQL branch.
///
/// The proof is the refusal's own text: "no async runtime" is something only
/// the PostgreSQL path can say. A dispatcher that routed this request to the
/// HTTP connector, or that matched the word "postgres" in some field, would
/// answer with something else.
#[test]
fn m6_r1_a_postgres_request_routes_to_postgres() {
    let peer = self_peer();
    let (mut state, session) = broker_with_session(&peer);

    let response = handle(
        &mut state,
        &peer,
        Request::PostgresConnect {
            session,
            host: "db.example".into(),
            host_addr: "127.0.0.1".into(),
            port: 5432,
            database: "asv".into(),
            role: "app".into(),
        },
    );

    assert_eq!(
        response,
        Response::Error {
            code: ErrorCode::Upstream,
            message: "the broker has no async runtime for the postgres transport".into(),
        },
        "a PostgresConnect request did not reach the PostgreSQL branch"
    );
}

/// The scenario's negative half: an HTTP request does not become PostgreSQL
/// because a provider name appears in a string.
///
/// This is the half the superseded test could not express. `db.example` is a
/// deliberately PostgreSQL-flavoured host: if routing were done by matching a
/// provider string anywhere in the request, this is the request that would be
/// misrouted. It must reach the GitHub branch, and the GitHub branch refuses
/// it for its own reasons.
#[test]
fn m6_r1_an_http_request_naming_a_provider_does_not_route_to_postgres() {
    let peer = self_peer();
    let (mut state, session) = broker_with_session(&peer);

    // The repo is named after the provider this must NOT route to, and the
    // surrogate is a well-formed value so the request is refused for the
    // reason a real one would be, not for a malformed field.
    let response = handle(
        &mut state,
        &peer,
        Request::CreateRelease {
            session,
            surrogate: "asv_surrogate_not_a_real_one".into(),
            repo: "postgres".into(),
            tag: "v1.0.0".into(),
            name: "release".into(),
            body: "body".into(),
        },
    );

    assert!(
        !reached_postgres(&response),
        "an HTTP request whose repo is named \"postgres\" was routed to the \
         PostgreSQL connector: routing is matching a provider string"
    );
}

/// Routing is decided by the request variant, before any credential exists.
///
/// Two requests that differ only in their variant reach different branches.
/// If the broker matched a provider string, identical strings in different
/// variants would land in the same place.
#[test]
fn m6_r1_routing_follows_the_request_variant() {
    let peer = self_peer();

    // Same peer, same session-owning broker, two different request families.
    let (mut pg_state, pg_session) = broker_with_session(&peer);
    let pg_response = handle(
        &mut pg_state,
        &peer,
        Request::PostgresConnect {
            session: pg_session,
            host: "db.example".into(),
            host_addr: "127.0.0.1".into(),
            port: 5432,
            database: "asv".into(),
            role: "app".into(),
        },
    );

    let (mut http_state, http_session) = broker_with_session(&peer);
    let http_response = handle(
        &mut http_state,
        &peer,
        // The repo carries the same host the PostgreSQL request used.
        Request::ReadIssue {
            session: http_session,
            surrogate: "asv_surrogate_not_a_real_one".into(),
            repo: "db.example".into(),
            number: 1,
        },
    );

    assert!(
        reached_postgres(&pg_response),
        "the PostgreSQL request did not reach the PostgreSQL branch"
    );
    assert!(
        !reached_postgres(&http_response),
        "an HTTP request reached the PostgreSQL branch: the same host string \
         routed differently, which means the variant is not what decided it"
    );
}
