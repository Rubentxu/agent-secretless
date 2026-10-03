//! C2.8 — the hop from "a session ended" to "its tunnels are cancelled".
//!
//! # Why this file exists when C1.1 already proves revocation
//!
//! `revoking_an_established_session_tears_down_its_tunnel` (C1.1, in
//! `uat_010_connect_substitution.rs`) builds a real bridge, proves a real
//! session, establishes a real tunnel, calls `ShutdownSignal::revoke` and
//! watches the relay come back `Cancelled(SessionRevoked)`. It is a good test
//! and it is green.
//!
//! It is also green against a broker that never revokes anything, **because it
//! revokes the signal itself.** It reaches into the mechanism at exactly the
//! point where the product is supposed to reach for it on its own, and a test
//! that does the subject's job cannot tell a working product from a working
//! mechanic. Every claim in this block about the mechanism was true while the
//! product had no path to it at all: `ShutdownSignal::revoke` had zero callers
//! outside tests, and the signal itself was a local in `main.rs` that
//! `BrokerState` could not even name.
//!
//! The vertical cannot cover the gap either, and for a structural reason worth
//! writing down: `asv run` stops its shim *before* it ends its session, and a
//! dead shim drops its sockets. So end to end, a tunnel closing when a session
//! ends is equally consistent with the shim dying and with the broker
//! cancelling — `connect_vertical_e2e.rs` measures that a tunnel does not
//! outlive its session, and says in its own doc comment that it cannot say
//! who closed it.
//!
//! What is left is the wiring, and the wiring is only observable from inside
//! the product. That is what this file is.
//!
//! # What "observable" means here
//!
//! `BrokerState` owns the `ShutdownSignal` the CONNECT listener cancels
//! against. Ending a session has to mark that session revoked in it, so a relay
//! blocked on a connection will report `SessionRevoked` on its next poll. The
//! assertions below are on that state, and each one is paired with a control
//! that has to fail for the right reason:
//!
//! | assertion | control that would otherwise satisfy it |
//! |---|---|
//! | a live session is not revoked | asked *before* `EndSession`, so a signal that revokes everything cannot pass |
//! | ending it revokes it | the pre-check above |
//! | ending A does not revoke B | B is asserted live *after* A ended |
//! | a denied `EndSession` revokes nothing | the stranger's target is asserted unrevoked after the denial |
//!
//! No network, no vault, no process. The subject is a field that has to be
//! written to, and a test that cannot fail when that write is deleted is
//! decoration — so the first version of this file was written *before* the
//! write, and watched fail.

use asv_broker::{handle, BrokerState};
use asv_domain::AgentSessionId;
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{Request, Response};

fn peer(pid: i32) -> WorkloadIdentity {
    WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32 + pid,
        uid: 1000,
        gid: 1000,
    })
}

fn open(state: &mut BrokerState, who: &WorkloadIdentity) -> AgentSessionId {
    match handle(
        state,
        who,
        Request::CreateSession {
            workspace: "/repo".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    }
}

fn revoked(state: &BrokerState, session: &AgentSessionId) -> bool {
    state.shutdown.is_revoked(session.to_string().as_str())
}

/// Ending a session cancels the tunnels that session authorised.
///
/// The control comes first on purpose. A `ShutdownSignal` that revoked
/// everything on sight would satisfy the assertion at the bottom of this test
/// without `EndSession` having done anything at all, and a revoked-from-birth
/// signal is exactly what a wrong implementation of this looks like.
#[test]
fn ending_a_session_revokes_the_tunnels_it_authorised() {
    let mut state = BrokerState::default();
    let session = open(&mut state, &peer(0));

    assert!(
        !revoked(&state, &session),
        "a live session is already revoked, so the assertion after `EndSession` would \
         be satisfied by a signal that revokes every session it is asked about"
    );

    assert_eq!(
        handle(&mut state, &peer(0), Request::EndSession { session }),
        Response::SessionEnded { session }
    );

    assert!(
        revoked(&state, &session),
        "the session ended and its tunnels are still up: nothing told the CONNECT \
         path, so a relay blocked on one of its connections keeps copying the real \
         credential to the destination for a session that no longer exists"
    );
}

/// Revocation is scoped to the session that ended.
///
/// `revoke` takes a session id precisely so it can be scoped, and a global
/// "revoke everything" would be indistinguishable from a correct one until
/// somebody needed two sessions at once. The shim runs one session per `asv
/// run`, so this is the shape a CI job or a shared broker actually has.
#[test]
fn ending_one_session_does_not_revoke_another() {
    let mut state = BrokerState::default();
    let doomed = open(&mut state, &peer(0));
    let survivor = open(&mut state, &peer(0));

    assert_eq!(
        handle(
            &mut state,
            &peer(0),
            Request::EndSession { session: doomed }
        ),
        Response::SessionEnded { session: doomed }
    );

    assert!(revoked(&state, &doomed), "the session that ended");
    assert!(
        !revoked(&state, &survivor),
        "ending one session cancelled another session's tunnel; an agent that is \
         still running would lose its working connections when a sibling session \
         is torn down"
    );
}

/// A refused `EndSession` revokes nothing.
///
/// The ordering is the whole of this test. `EndSession` revokes a session's
/// surrogates and its tunnels, and it is guarded: a peer cannot end another
/// peer's session, precisely so that one process cannot strip another's
/// authority. A revoke placed *before* the ownership check would hand every
/// peer on the socket the ability to destroy any session it can name — turning
/// a denial-of-service defence into a denial-of-service primitive, one tunnel
/// at a time.
///
/// So the revoke has to come after `sessions!(state).end(session)` reported
/// honestly, and this is the test that says so. It is a falsification of an
/// ordering, not of a value: a signal revoked by a denied request would show
/// up here and nowhere else.
#[test]
fn a_refused_end_session_revokes_nothing() {
    let mut state = BrokerState::default();
    let owner = peer(1);
    let stranger = peer(2);
    let session = open(&mut state, &owner);

    let refused = handle(&mut state, &stranger, Request::EndSession { session });
    assert!(
        matches!(&refused, Response::Error { .. }),
        "a stranger ended a session it does not own: {refused:?}"
    );
    assert!(
        !revoked(&state, &session),
        "a refused `EndSession` still cancelled the session's tunnels, so any peer on \
         the socket could destroy any session it can name without owning it"
    );

    // And the owner can still do it for real, or the refusal above would also
    // be satisfied by a handler that revoked nothing ever.
    assert_eq!(
        handle(&mut state, &owner, Request::EndSession { session }),
        Response::SessionEnded { session }
    );
    assert!(revoked(&state, &session), "the rightful owner");
}

/// A default broker is not already shutting down.
///
/// This is here because the three tests above would all still pass with a
/// `Default` that started *stopped*: `ShutdownSignal::cancel_reason` checks
/// shutdown before revocation, so every session in every test broker would look
/// cancelled and the wiring would look perfect. A default that is pre-revoked
/// or pre-stopped is the silent version of the same defect this file is about
/// — a broker that reports a property it has not got — and it is exactly the
/// kind that every other test in the suite would be green through.
///
/// **What this file cannot check, stated plainly.** It cannot see `main.rs`. A
/// broker that built a *second* signal there and handed that one to the
/// listener would pass all four of these tests, because they only ever look at
/// `state.shutdown`. The one test that can see it is the vertical,
/// `a_tunnel_does_not_outlive_the_session_that_authorised_it`: it launches the
/// real binary, and a second signal there is a tunnel that never dies.
///
/// That is worth stating rather than papering over, because the first version
/// of this file had a test here that claimed to cover it by asserting the
/// state's signal is revoked. It was checking a field against itself, and a
/// green tick from it said nothing at all about `main.rs`.
#[test]
fn a_default_broker_is_serving_and_revoking_nothing() {
    let state = BrokerState::default();
    assert!(
        !state.shutdown.is_stopped(),
        "a broker that has not been asked to shut down reports that it has; every \
         tunnel would be cancelled on sight and the revocation tests above would \
         pass without `EndSession` doing anything"
    );
    assert!(
        !state
            .shutdown
            .is_revoked("00000000-0000-4000-8000-000000000000"),
        "a fresh broker reports an unknown session as revoked"
    );
}
