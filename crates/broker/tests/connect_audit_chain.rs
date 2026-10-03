//! What the CONNECT listener writes into the audit chain, and what it must not
//! (V1-C2).
//!
//! The chain is the artefact that is hashed, exported and shipped. The operator
//! log is not. That difference is the whole subject of this file, and it exists
//! because of a finding rather than a principle: `parse_connect_target` builds
//! `BridgeError::Protocol(format!("{authority} has no port"))` from the bytes a
//! client sent, so `ConnectionResult::Refused(reason)` carries
//! attacker-controlled text. Writing that into a durable chain would let any
//! client place bytes of their choosing — a secret-shaped string included — in
//! a file that leaves the machine.
//!
//! So these tests pin two things, and the second is the one that would have
//! shipped broken:
//!
//! 1. a CONNECT outcome lands in the chain, and the chain still verifies;
//! 2. a refusal carrying a canary leaves **no** canary in the chain, while
//!    still leaving a class an operator can count.

use std::sync::{Arc, Mutex};

use asv_broker::audit::AuditLog;
use asv_broker::connect_listener::{
    ConnectionOutcome, ConnectionResult, DiscardReport, ListenerReport,
};
use asv_broker::connect_runtime::ChainReport;
use asv_broker::tls_bridge::{AuthorityEndpoint, BridgeError, CancelReason};
use asv_domain::Authority;

/// The string this file is really about. If it appears in the chain, a client
/// chose where it went.
const CANARY: &str = "ASV-CANARY-7d1e4b06-AUDIT-CHAIN";

fn target(host: &str, port: u16) -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(host).expect("canonical host"), port)
        .expect("valid endpoint")
}

fn refused(reason: &str) -> ConnectionOutcome {
    ConnectionOutcome {
        target: Some(target("example.test", 443)),
        session: Some("s-1".into()),
        result: ConnectionResult::Refused(reason.into()),
    }
}

fn report(log: &Arc<Mutex<AuditLog>>) -> ChainReport {
    ChainReport::new(Arc::new(DiscardReport), Arc::clone(log))
}

/// A refusal is recorded, the class survives, and **the canary does not**.
///
/// The reason string is exactly what `parse_connect_target` would produce for
/// a hostile request line, which is the shape the finding took.
#[test]
fn a_refusal_is_recorded_as_a_class_and_never_quotes_the_reason() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));
    let reason = format!("malformed CONNECT request: {CANARY} has no port");

    report(&log).record(refused(&reason));

    let rendered = {
        let log = log.lock().expect("nobody holds this");
        assert!(
            log.verify().is_ok(),
            "an appended record must not break the chain it belongs to"
        );
        format!("{:?}", log.query(0))
    };
    assert!(
        !rendered.contains(CANARY),
        "the refusal reason reached the durable chain, and a client chooses \
         those bytes: {rendered}"
    );
    assert!(
        rendered.contains("malformed_request"),
        "the class must be recorded, or an operator cannot count refusals by \
         cause: {rendered}"
    );
}

/// The canary also has to survive the **inner head**, which is a different read
/// with a different error path.
///
/// `read_inner_head` reports through `BridgeError::Protocol` too, and a
/// substitution refusal reaches the same string. A leak guard that only covers
/// the CONNECT head would pass while the relay still writes one.
#[test]
fn a_relay_failure_reason_does_not_reach_the_chain_either() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));

    for reason in [
        format!("no credential in the request: {CANARY}"),
        format!("surrogate not redeemable: {CANARY}"),
        format!("{CANARY}: the origin hung up"),
    ] {
        report(&log).record(ConnectionOutcome {
            target: Some(target("example.test", 443)),
            session: None,
            result: ConnectionResult::Refused(reason),
        });
    }

    let rendered = format!("{:?}", log.lock().expect("nobody holds this").query(0));
    assert!(
        !rendered.contains(CANARY),
        "a relay failure reason reached the chain: {rendered}"
    );
    assert_eq!(
        log.lock().expect("nobody holds this").query(0).len(),
        3,
        "every refusal is still recorded; refusing to record is not the same \
         as recording without the secret"
    );
}

/// A connection discarded before it said where it was going is still a record.
///
/// `None` is a real state and not a gap — a silent client, a malformed request
/// line — and a chain that omits it is a chain with holes exactly where an
/// operator would look for "who is probing this socket".
#[test]
fn a_connection_with_no_destination_is_still_recorded() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));
    report(&log).record(ConnectionOutcome {
        target: None,
        session: None,
        result: ConnectionResult::Cancelled(CancelReason::DeadlineElapsed),
    });

    let rendered = format!("{:?}", log.lock().expect("nobody holds this").query(0));
    assert!(rendered.contains("head_deadline"), "{rendered}");
    assert!(
        !rendered.contains("s-1"),
        "no session was proven: {rendered}"
    );
}

/// Cancellation and refusal are different facts and must not collapse.
///
/// An operator who revoked a session and then reads `refused` will go looking
/// for a client that misbehaved, rather than for the policy that worked.
#[test]
fn cancellation_and_refusal_are_distinguishable_in_the_chain() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));
    let report = report(&log);

    report.record(ConnectionOutcome {
        target: Some(target("example.test", 443)),
        session: Some("s-1".into()),
        result: ConnectionResult::Cancelled(CancelReason::SessionRevoked),
    });
    report.record(ConnectionOutcome {
        target: Some(target("example.test", 443)),
        session: Some("s-2".into()),
        result: ConnectionResult::Refused("destination not allowed".into()),
    });

    let rendered = format!("{:?}", log.lock().expect("nobody holds this").query(0));
    assert!(rendered.contains("session_revoked"), "{rendered}");
    assert!(rendered.contains("destination_not_allowed"), "{rendered}");
}

/// The completed case is recorded as itself, and carries no class that could be
/// mistaken for a refusal.
#[test]
fn a_completed_tunnel_is_recorded_as_completed() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));
    report(&log).record(ConnectionOutcome {
        target: Some(target("example.test", 443)),
        session: Some("s-1".into()),
        result: ConnectionResult::Completed,
    });
    let rendered = format!("{:?}", log.lock().expect("nobody holds this").query(0));
    assert!(rendered.contains("completed"), "{rendered}");
    assert!(
        !rendered.contains("refused") && !rendered.contains("cancelled"),
        "a completed tunnel must not read as a failure: {rendered}"
    );
    // Whose it was. A chain that says a tunnel completed without saying whose
    // cannot answer the question it is kept for, and it cannot be joined up
    // with the `CredentialSubstituted` record the relay writes for the same
    // event — the two halves of one thing with nothing to relate them.
    assert!(
        rendered.contains("s-1"),
        "the session is not in the record: {rendered}"
    );
}

/// The chain survives being appended to many times, and verifies at the end.
///
/// A chain that only works for one record is a chain nobody would trust to
/// answer "was this credential spent", which is the question it exists for.
#[test]
fn a_long_chain_of_connect_outcomes_still_verifies() {
    let log = Arc::new(Mutex::new(AuditLog::new(0)));
    let report = report(&log);
    for i in 0..64 {
        report.record(ConnectionOutcome {
            target: Some(target("example.test", 443)),
            session: Some(format!("s-{i}")),
            result: if i % 3 == 0 {
                ConnectionResult::Refused("malformed CONNECT request: nope".into())
            } else {
                ConnectionResult::Completed
            },
        });
    }
    let log = log.lock().expect("nobody holds this");
    assert_eq!(log.query(0).len(), 64);
    assert!(
        log.verify().is_ok(),
        "a 64-record CONNECT chain must verify"
    );
}

/// A `BridgeError` classifies without rendering, and the classes stay distinct.
///
/// The rendering is what carries client bytes, so this asserts the *other*
/// half: that classifying did not collapse every failure into one bucket, which
/// is what a lazy `_ => "other"` would do.
#[test]
fn distinct_bridge_errors_classify_distinctly() {
    use asv_broker::connect_runtime::refusal_class;
    let classes: std::collections::BTreeSet<&str> = [
        BridgeError::Protocol("x".into()),
        BridgeError::NoLeaf("x".into()),
        BridgeError::Io("x".into()),
        BridgeError::Handshake("x".into()),
    ]
    .iter()
    .map(refusal_class)
    .collect();
    assert_eq!(
        classes.len(),
        4,
        "four different failures produced {classes:?}; an operator cannot \
         count refusals by cause if the causes share a name"
    );
    assert!(
        !classes.contains(&"other"),
        "a known variant fell through to the catch-all: {classes:?}"
    );
}
