//! UAT-050 — M6-R1: the broker dispatches on the request type, not a provider string.
//!
//! ## Why this file exists
//!
//! M6-R1 requires that the `ConnectorFactory` "MUST dispatch on a typed
//! audience enum, MUST NOT grow per-provider methods, and MUST NOT match the
//! audience string", and its first scenario says a request "routes to
//! PostgreSQL; an HTTP URL with 'postgres' does not".
//!
//! The M6 verification report recorded that requirement as "implemented and
//! proven". It was not proven. The test offered as proof,
//! `uat_039_m6_s1_dispatch_by_tag_routes_postgres_only`, calls
//! `PgFactory::postgres` **directly** and asserts the returned client has the
//! role and database it was handed. That asserts a constructor returns its own
//! arguments. It never sends a request, never enters `handle`, and cannot
//! distinguish typed dispatch from string matching — the property M6-R1 is
//! about is not on the path it exercises.
//!
//! This file exercises the property where it lives: a `Request` goes in
//! through `handle`, the same entry point every agent request uses, and the
//! answer says which connector ran.
//!
//! ## The discriminator
//!
//! `BrokerState` exposes `runtime` and the broker refuses a PostgreSQL connect
//! with a named message when there is no async runtime, while a GitHub request
//! never consults it. That difference is the observation: it tells us which
//! branch of the dispatcher executed, from outside the broker, with no test
//! hook added to production code for the purpose.
//!
//! These tests need no server and no vault. They assert routing, not
//! connectivity; the live transport is proven by `uat033_broker`.

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
    fn lend(&self, _credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::NotFound("no credential in this test".into()))
    }
}

/// A broker with a session owned by `peer`, a vault open, and no async runtime.
///
/// No runtime means the PostgreSQL branch fails at a point unique to it, and
/// the vault being open means the request gets far enough to reach it.
fn broker_with_session(peer: &WorkloadIdentity) -> (BrokerState, AgentSessionId) {
    let mut state = BrokerState {
        connectors: Box::new(LiveConnectorFactory::default()),
        secrets: Some(Arc::new(OpenVault)),
        ..Default::default()
    };
    let session = state.sessions.create("/repo".into(), peer);
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
            host_addr: "93.184.216.34".into(),
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
            host_addr: "93.184.216.34".into(),
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
