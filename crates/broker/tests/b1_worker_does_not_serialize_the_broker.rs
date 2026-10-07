//! B1: one slow worker must not serialise the broker.
//!
//! # The claim these rows measure
//!
//! `BrokerState::handle` is the function every connection funnels through, and
//! the accept loop's thread-per-connection design only buys anything if
//! `handle` itself can be entered by two agents at once. Row one of this block
//! measured the *loop* (`b1_runtime_safety.rs`). This file measures the
//! function underneath it, against the slowest thing a broker does: a worker
//! that takes seconds to finish.
//!
//! # What the first row found
//!
//! `Request::RunIsolated` takes the audit lock *before* calling
//! `worker::spawn` and holds it until `spawn` returns:
//!
//! ```text
//! let audit = state.audit.clone();
//! let Ok(mut guard) = audit.lock() else { ... };
//! match crate::worker::spawn(&view, &worker, opts, &mut guard) { ... }
//! ```
//!
//! `spawn` does not return until the child has exited or timed out. So the
//! audit lock is held for the entire lifetime of the worker — seconds or
//! minutes. And `handle` appends an audit record for *every* request before it
//! returns:
//!
//! ```text
//! let _ = audit_chain!(state).append(event, now_secs());
//! ```
//!
//! Those two facts compose into a global stall. Any second agent — one ending a
//! session, one asking for metadata, one pinging — blocks on the audit append
//! until an unrelated worker finishes. The session store is per-field and
//! correctly locked; the audit log is the single remaining serialisation point,
//! and it is held across the slowest call in the protocol.
//!
//! That is the row below, and it is red against this tree.
//!
//! # The second row is a different kind of claim
//!
//! `RunIsolated`'s comment says the caller's timeout "can only shorten" the
//! runtime's own ceiling, because a client able to raise it "would make the
//! lifetime cap advisory for the one verb that hands out a real credential".
//! `worker::spawn` reads the value with no comparison against anything:
//!
//! ```text
//! let timeout = opts.timeout.unwrap_or(DEFAULT_WORKER_TIMEOUT);
//! ```
//!
//! `unwrap_or` supplies the default when the caller sends nothing. It does not
//! bound a caller that sends something large. A comment about a ceiling is not
//! a ceiling, and this one is load-bearing: it is the reason the lifetime cap is
//! allowed to be short.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asv_broker::isolated_exec::{
    EgressPolicy, LandlockProfile, Redactor, SeccompProfile, SecretInjectionPlan, WorkerRegistry,
    WorkerTemplate,
};
use asv_broker::worker::DEFAULT_WORKER_TIMEOUT;
use asv_broker::{handle, BrokerState};
use asv_domain::AgentSessionId;
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};

/// How long the second agent may wait while the worker is still running.
///
/// Half of the run below. A broker that serialises cannot answer until the
/// worker is killed at `RUN_FOR`, so the two designs are separated by more than
/// 4x, which is wide enough that a loaded host cannot drift across it and still
/// call the result a measurement.
const CONCURRENT_ANSWER: Duration = Duration::from_secs(2);

/// How long the blocked worker is asked to run, in milliseconds.
///
/// Longer than [`CONCURRENT_ANSWER`] by a wide margin so the row's timing is a
/// statement about the broker rather than about how long a worker happened to
/// take, and shorter than the sleeper's own lifetime so the run ends by timeout
/// on every path.
const RUN_FOR_MS: u64 = 9_000;

/// How long the sleeper ignores its own timeout and keeps running.
///
/// Used by the lifetime-cap row, where the *worker's own duration* is the
/// discriminator: if the cap holds, the run is killed at
/// [`DEFAULT_WORKER_TIMEOUT`] and answers with a timeout; if it does not, the
/// worker simply finishes and answers with its output. The row therefore needs
/// no run longer than this, which is what keeps the falsification cheap.
const SLEEPER_LIFETIME: u64 = 30;

/// Headroom over the cap for the lifetime row's assertion.
///
/// The cap is a timeout, not a stopwatch: the child has to be signalled and
/// reaped before `handle` can answer. Ten seconds of headroom is far more than
/// that needs and far less than [`SLEEPER_LIFETIME`], so the two designs cannot
/// both satisfy the budget.
const CAP_HEADROOM: Duration = Duration::from_secs(10);

fn template(name: &str, binary: &str, args: &[&str]) -> WorkerTemplate {
    WorkerTemplate {
        name: name.into(),
        binary: binary.into(),
        arguments: args.iter().map(|s| s.to_string()).collect(),
        secret_injection: SecretInjectionPlan::None,
        egress_policy: EgressPolicy::Deny,
        landlock_profile: LandlockProfile::default(),
        seccomp_profile: SeccompProfile::ClosedAllowList,
        redactor: Redactor::empty(),
    }
}

/// A peer whose process is pinned, which `RunIsolated` requires before it will
/// hand a process tree anything.
fn pinned_peer() -> WorkloadIdentity {
    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("pidfd_open on self");
    assert!(peer.is_pidfd_pinned(), "the fixture must be pinned");
    peer
}

/// Refuse the host that cannot run these rows, loudly.
///
/// These rows spawn a real isolated child. A host without unprivileged user
/// namespaces cannot, and returning early would report that as a *pass* — the
/// failure R1 was reopened for. Reported as a failure instead, so "could not
/// run" is never "ran and was correct".
fn require_userns(row: &str) {
    let available = std::process::Command::new("unshare")
        .args(["-Ur", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        available,
        "UNAVAILABLE_SUBSTRATE: {row} spawns a real isolated worker, which needs \
         unprivileged user namespaces. Reported as a failure rather than a \
         return, because a return is reported as a pass."
    );
}

fn open_session(state: &BrokerState, peer: &WorkloadIdentity) -> AgentSessionId {
    match handle(
        state,
        peer,
        Request::CreateSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            workspace: "/repo".to_string(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    }
}

fn run_request(session: AgentSessionId, worker: &str, timeout_ms: u64) -> Request {
    Request::RunIsolated {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        session,
        worker: worker.to_string(),
        args: Vec::new(),
        credential: None,
        timeout_ms: Some(timeout_ms),
    }
}

/// **A worker that is still running does not delay another agent's EndSession.**
///
/// This is the exit criterion "worker bloqueado no bloquea EndSession", and it
/// is measured at `handle` rather than at the socket because the socket adds a
/// thread and a deadline and hides which of the two sides was slow.
///
/// The second half of the assertion is the one that carries the meaning.
/// Asserting only that `EndSession` returned would pass on a broker where the
/// run had already finished — the answer would be prompt for the boring reason
/// that there was nothing left to wait for. So the row also requires the worker
/// to still be running at the instant `EndSession` answered.
#[test]
fn a_blocked_worker_does_not_delay_end_session() {
    require_userns("a_blocked_worker_does_not_delay_end_session");

    // Two identities for the same process. They describe one peer, which is what
    // ownership is keyed on, and `WorkloadIdentity` is not `Copy` — so the run
    // thread takes its own rather than sharing a reference across a `move`.
    let runner = pinned_peer();
    let observer = pinned_peer();
    let state = Arc::new(BrokerState {
        workers: Arc::new(WorkerRegistry::new(vec![template(
            "sleeper",
            "/bin/sleep",
            &[&SLEEPER_LIFETIME.to_string()],
        )])),
        ..BrokerState::default()
    });

    // Two sessions, both owned by this peer. The run is charged to one and the
    // revocation is asked about the other, so the row measures latency and not
    // the effect of ending the session the worker is still running under.
    let run_session = open_session(&state, &runner);
    let other_session = open_session(&state, &observer);

    let (tx, rx) = mpsc::channel();
    let worker_state = Arc::clone(&state);
    let worker = std::thread::spawn(move || {
        let response = handle(
            &worker_state,
            &runner,
            run_request(run_session, "sleeper", RUN_FOR_MS),
        );
        tx.send(response).ok();
    });

    // Setup, not measurement: give the run a moment to actually be in flight
    // before the clock below starts. The elapsed time this row asserts on is
    // measured from *after* this sleep, so a slow host cannot make it look
    // serial.
    std::thread::sleep(Duration::from_millis(250));

    let started = Instant::now();
    let response = handle(
        &state,
        &observer,
        Request::EndSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session: other_session,
        },
    );
    let elapsed = started.elapsed();

    assert!(
        matches!(response, Response::SessionEnded { .. }),
        "a second agent could not end its session while a worker ran: {response:?}"
    );
    assert!(
        elapsed < CONCURRENT_ANSWER,
        "EndSession took {elapsed:?}. The worker was still running, so this is the \
         shape of a broker that serialises on it rather than one that serves \
         concurrently: the run is charged a {RUN_FOR_MS}ms lifetime, and nothing \
         about ending an unrelated session should wait for it."
    );
    // The witness. If the run had already finished, the timing above would be
    // measuring an empty broker and the row would pass for the wrong reason.
    assert!(
        rx.try_recv().is_err(),
        "the worker had already finished before EndSession answered, so this row \
         proved only that a broker with nothing to wait for is responsive."
    );
    // And the revocation itself, not only the answer. `SessionEnded` is a
    // response shape; it is not evidence the store changed. A broker that
    // answered promptly and revoked nothing would satisfy everything above,
    // which is the DoD criterion "revocation works under load" failing in the
    // way a timing assertion cannot see. Ending it a second time is therefore
    // the probe: a session that was really ended is gone, and its owner gets
    // the same refusal they would get for revoking twice.
    let repeated = handle(
        &state,
        &observer,
        Request::EndSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session: other_session,
        },
    );
    assert!(
        matches!(
            repeated,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ),
        "the first EndSession answered SessionEnded and the session is still \
         there to be ended again: {repeated:?}. The answer was not a revocation."
    );

    worker.join().expect("the run thread must not panic");
}

/// **A caller cannot raise the worker's lifetime cap.**
///
/// The comment on the `timeout_ms` arm says this value "can only shorten" the
/// runtime's ceiling. This row is that claim.
///
/// The discriminator is the worker's own lifetime rather than the value sent:
/// the run asks for ten minutes and the worker sleeps thirty seconds, so a
/// broker that honours the request answers with the worker's output at thirty
/// seconds, and a broker that caps it kills the worker at
/// [`DEFAULT_WORKER_TIMEOUT`] and answers with a timeout. The row asserts both
/// halves, because either alone is weaker — a fast answer would pass the budget
/// check on a broker that refused the request outright for some unrelated
/// reason.
#[test]
fn a_caller_cannot_raise_the_worker_lifetime_cap() {
    require_userns("a_caller_cannot_raise_the_worker_lifetime_cap");

    let peer = pinned_peer();
    let state = BrokerState {
        workers: Arc::new(WorkerRegistry::new(vec![template(
            "sleeper",
            "/bin/sleep",
            &[&SLEEPER_LIFETIME.to_string()],
        )])),
        ..BrokerState::default()
    };
    let session = open_session(&state, &peer);

    let started = Instant::now();
    let response = handle(
        &state,
        &peer,
        // Ten minutes, against a worker that lives thirty seconds and a cap of
        // ten. A cap that is not enforced answers `completed`; an enforced one
        // cannot.
        run_request(session, "sleeper", 600_000),
    );
    let elapsed = started.elapsed();

    let budget = DEFAULT_WORKER_TIMEOUT + CAP_HEADROOM;
    assert!(
        elapsed < budget,
        "a caller asked for a 10-minute worker against a {DEFAULT_WORKER_TIMEOUT:?} \
         cap and the run took {elapsed:?}. The arm's comment says this value can \
         only shorten the ceiling; a broker that agrees cannot spend longer than \
         the cap plus reaping time."
    );
    match response {
        Response::Error { code, message } => {
            assert_eq!(
                code,
                ErrorCode::Upstream,
                "the capped run should be refused as an upstream timeout, not as \
                 something else: {message}"
            );
        }
        other => panic!(
            "the caller's 10-minute request was honoured and the worker ran to its \
             own completion: {other:?}. The lifetime cap is advisory exactly when \
             a client can raise it, and this verb is the one that hands out a real \
             credential."
        ),
    }
}
