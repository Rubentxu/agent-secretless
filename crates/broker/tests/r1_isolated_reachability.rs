//! R1 — the isolated runtime is reachable from a product surface.
//!
//! The exit criterion for R1 is a test that starts at the product surface, not
//! at `WorkerRegistry`. This file is that test, and it exists because the
//! property was false in a way nothing had noticed.
//!
//! # What was measured before this file existed
//!
//! `worker::spawn` was `pub`, `isolated_exec` was a `pub mod`, and the entire
//! isolation pipeline behind it — namespaces, Landlock, seccomp, the lifetime
//! cap, process-tree teardown, the redactor — had **no production call site**.
//! Its only callers were `uat_021`, `uat_022` and `uat_040`, all of which build
//! their own registry and call `spawn` directly.
//!
//! Meanwhile the one command the product ships for running a tool holding a
//! credential, `asv run`, does `std::process::Command::new(program)` in the CLI
//! process: no namespace, no Landlock, no seccomp, no timeout, no tree
//! teardown, no redaction. So the runtime that was heavily tested had no
//! caller, and the surface that had callers was not the tested one. Both halves
//! of that sentence are the reason R1 exists.
//!
//! # What this file is allowed to assert
//!
//! It drives the broker's public `handle` with a real `Request`, against real
//! registered templates, and observes a real child process. Every row below
//! therefore has to survive the whole chain: request → session ownership →
//! pidfd pin → registry lookup → credential resolution → `worker::spawn` →
//! namespaces → child → reaper → redactor → typed response → audit.
//!
//! # What it deliberately does not do
//!
//! It does not start a second executor, a second shell, or a second sandbox. The
//! only spawn in this file is the one `worker::spawn` performs, and the only
//! way to get a child to exist is for a template to have been registered by
//! the operator. A test that reached the same child by another route would be
//! evidence for a different product.

use asv_broker::audit::AuditLog;
use asv_broker::isolated_exec::{
    EgressPolicy, LandlockProfile, Redactor, SeccompProfile, SecretInjectionPlan, WorkerRegistry,
    WorkerTemplate,
};
use asv_broker::{handle, BrokerState, ISOLATED_POSTURE};
use asv_domain::AgentSessionId;
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{AuditEventDto, ErrorCode, Request, Response};

/// A vault that lends one known value. The value is a fixture constant and not
/// a real credential, which is the only reason it can sit in a source file.
const LENT: &[u8] = b"asv1-fixture-value-that-must-never-come-back";

struct FixturePort;

impl asv_connector_http::SecretPort for FixturePort {
    /// A fixture holding nothing derived, so a deletion has nothing to drop.
    ///
    /// Written out rather than left to a default, because the trait requires
    /// this on purpose: a port that never considered revocation is the exact
    /// shape of bug that made `DeleteCredential` a no-op for cached tokens.
    fn forget(&self, _credential: &str) {}

    fn lend(
        &self,
        _credential: &str,
        sink: &mut dyn asv_connector_http::SecretSink,
    ) -> Result<(), asv_connector_http::SecretError> {
        // Keyed on nothing: the vault is addressed by wire id, and a fixture
        // that tried to match the label returned "not found" and lent the
        // empty string, which made the redaction row pass without the child
        // ever having held anything. A fixture that cannot be addressed wrong
        // is the honest shape for this row.
        sink.accept(LENT)
    }
}

/// A worker that is handed a credential and prints it, which is what an
/// accidentally verbose tool does.
fn echo_secret_template() -> WorkerTemplate {
    WorkerTemplate {
        name: "leaky".into(),
        binary: "/bin/sh".into(),
        arguments: vec!["-c".into(), "printf %s \"$LEAK_TEST\"".into()],
        secret_injection: SecretInjectionPlan::EnvVar {
            name: "LEAK_TEST".into(),
        },
        egress_policy: EgressPolicy::Deny,
        landlock_profile: LandlockProfile::default(),
        seccomp_profile: SeccompProfile::ClosedAllowList,
        redactor: Redactor::empty(),
    }
}

/// A peer whose process is pinned. The pin is real: `pin_pidfd` on this very
/// process, because the verb hands a process tree a credential and D4's bar is
/// the one the surrogate path already meets.
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

fn unpinned_peer() -> WorkloadIdentity {
    let peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    assert!(!peer.is_pidfd_pinned(), "the fixture must be unpinned");
    peer
}

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

fn state_with(workers: Vec<WorkerTemplate>) -> BrokerState {
    let mut state = BrokerState::default();
    state.workers = std::sync::Arc::new(WorkerRegistry::new(workers));
    state
}

/// A broker that declares no workers at all, which is the state of every real
/// broker on a machine whose operator has not written a worker file.
fn state_without_workers() -> BrokerState {
    BrokerState::default()
}

fn open_session(state: &mut BrokerState, peer: &WorkloadIdentity) -> AgentSessionId {
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

/// Unprivileged user namespaces are what the isolation hook needs. Probed
/// rather than assumed, because a suite that skipped would be a suite that
/// reported green while examining nothing.
fn userns_available() -> bool {
    if std::path::Path::new("/proc/sys/kernel/unprivileged_userns_clone").exists() {
        let v = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .unwrap_or_default()
            .trim()
            .to_string();
        if v == "0" {
            return false;
        }
    }
    std::process::Command::new("unshare")
        .args(["-Ur", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A peer that is genuinely not this process.
///
/// Two `WorkloadIdentity` built from this process's own pid and uid describe
/// the *same* peer, so using one as the intruder would have tested nothing:
/// `belongs_to` would answer true, correctly, and the row would have been a
/// green assertion about the wrong thing. The intruder is pid 1's identity,
/// which is a different process on any machine this runs on.
fn stranger() -> WorkloadIdentity {
    WorkloadIdentity::from_peer(PeerCredentials {
        pid: 1,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    })
}

fn request(session: AgentSessionId, worker: &str, args: &[&str]) -> Request {
    Request::RunIsolated {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        session,
        worker: worker.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        credential: None,
        timeout_ms: Some(60_000),
    }
}

/// Refuse the host that cannot run these rows, loudly.
///
/// These rows used to `eprintln!` and `return`, which Cargo reports as
/// **passed**. A row that examined nothing and a row that passed were
/// indistinguishable in the output, which is the same failure as the one R1
/// was reopened for: a claim nothing measured. It also made the deficit
/// invisible to the suite-size guard, because a `return` produces a passing
/// test rather than an ignored one.
///
/// The distinction that matters: `unshare -Ur` failing is **`UNAVAILABLE
/// SUBSTRATE`**, a host that cannot run the row. A row that runs and fails is
/// **`FAIL`**. Neither is `PASS`, and the full gate keeps them apart on
/// purpose. A release requirement that cannot run is not a pass.
fn require_userns(row: &str) {
    if !userns_available() {
        panic!(
            "UNAVAILABLE_SUBSTRATE: {row} needs unprivileged user namespaces, which \
             this host does not provide. Reported as a failure rather than a \
             return, because a return is reported as a pass."
        );
    }
}

/// The exit test. A request on the public surface produces a real isolated
/// child and a typed answer carrying the posture label.
#[test]
fn r1_a_request_on_the_public_surface_runs_a_real_isolated_process() {
    require_userns("r1_a_request_on_the_public_surface_runs_a_real_isolated_process");
    let peer = pinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    let response = handle(
        &mut state,
        &peer,
        request(session, "echoer", &["hello-from-r1"]),
    );

    match response {
        Response::IsolatedResult {
            worker,
            outcome,
            exit_code,
            stdout,
            posture,
            ..
        } => {
            assert_eq!(worker, "echoer");
            assert_eq!(
                String::from_utf8_lossy(&stdout).trim(),
                "hello-from-r1",
                "the child's own output has to come back, or nothing downstream \
                 of this verb means anything"
            );
            assert_eq!(outcome, "completed");
            assert_eq!(exit_code, Some(0));
            assert_eq!(
                posture, ISOLATED_POSTURE,
                "every run carries its posture: a caller that has to go looking \
                 for whether it is on the strong path will assume the strong one"
            );
        }
        other => panic!("expected an isolated result, got {other:?}"),
    }
}

/// The arguments a caller sends reach the child as arguments.
///
/// This is the row that makes "no accidental `sh -c`" a measured property
/// rather than a type-level claim about a DTO. A caller cannot send a command
/// line here, so this asserts the consequence: a string that *looks* like a
/// shell fragment arrives at the child as one literal argument.
#[test]
fn r1_caller_arguments_reach_the_child_as_arguments() {
    require_userns("r1_caller_arguments_reach_the_child_as_arguments");
    let peer = pinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    let hostile = "sh -c 'id > /tmp/asv-r1-should-not-exist'";
    let response = handle(&mut state, &peer, request(session, "echoer", &[hostile]));

    match response {
        Response::IsolatedResult { stdout, .. } => {
            assert_eq!(
                String::from_utf8_lossy(&stdout).trim(),
                hostile,
                "the string must arrive whole; a split here would be a shell"
            );
            assert!(
                !std::path::Path::new("/tmp/asv-r1-should-not-exist").exists(),
                "nothing was executed: the string was an argument, not a command"
            );
        }
        other => panic!("expected an isolated result, got {other:?}"),
    }
}

// ------------------------------------------------------------------ refusals

/// An unregistered name is refused, and the refusal is the caller's error
/// rather than a policy decision.
#[test]
fn r1_an_unregistered_worker_is_refused_before_anything_executes() {
    let peer = pinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    let response = handle(&mut state, &peer, request(session, "not-registered", &[]));

    match response {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::InvalidRequest);
            assert!(
                message.contains("nothing was executed"),
                "the refusal has to say that, because a caller told only \
                 'invalid request' cannot tell a refused spawn from a typo"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A broker with no worker file runs nothing. The default is a denial, and it
/// is the accurate state of every broker whose operator wrote no worker file.
#[test]
fn r1_a_broker_with_no_declared_workers_runs_nothing() {
    let peer = pinned_peer();
    let mut state = state_without_workers();
    let session = open_session(&mut state, &peer);

    match handle(&mut state, &peer, request(session, "echoer", &[])) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The pidfd bar. This verb hands a process tree a real credential, so an
/// unpinned peer is refused for the same reason surrogate minting is.
#[test]
fn r1_an_unpinned_session_is_refused() {
    require_userns("r1_an_unpinned_session_is_refused");
    let peer = unpinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    match handle(&mut state, &peer, request(session, "echoer", &["nope"])) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::Denied);
            assert!(
                message.contains("pinned"),
                "the refusal names the condition, not just the verb"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A session belongs to the peer that opened it. A stranger naming it is
/// refused, which is the same first check every other session-scoped verb makes
/// and the reason the ordering in the dispatcher matters.
#[test]
fn r1_a_session_the_peer_does_not_own_is_refused() {
    let owner = pinned_peer();
    let stranger = stranger();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &owner);

    match handle(&mut state, &stranger, request(session, "echoer", &["nope"])) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ----------------------------------------------------------------- the audit

/// The run is in the audit chain, and the record names the worker, the
/// outcome and the posture — not the arguments and not the output.
#[test]
fn r1_an_isolated_run_is_recorded_in_the_audit_chain() {
    require_userns("r1_an_isolated_run_is_recorded_in_the_audit_chain");
    let peer = pinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    let _ = handle(&mut state, &peer, request(session, "echoer", &["audited"]));

    let records = state.audit.lock().expect("audit lock").query(0);
    let spawns: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.event, AuditEventDto::WorkerSpawned { .. }))
        .collect();
    assert_eq!(
        spawns.len(),
        1,
        "exactly one spawn record, not zero and not two"
    );
    match &spawns[0].event {
        AuditEventDto::WorkerSpawned {
            worker,
            outcome,
            posture,
            ..
        } => {
            assert_eq!(worker, "echoer");
            assert_eq!(outcome, "ok");
            assert_eq!(posture, ISOLATED_POSTURE);
        }
        other => panic!("expected a worker-spawned record, got {other:?}"),
    }
}

/// A refused run is also audited. The refusal is the evidence an operator
/// needs; a chain that only records successes is a chain that cannot answer
/// "what tried to run".
#[test]
fn r1_a_refused_isolated_run_is_also_audited() {
    let peer = pinned_peer();
    let mut state = state_with(vec![template("echoer", "/bin/echo", &[])]);
    let session = open_session(&mut state, &peer);

    let _ = handle(&mut state, &peer, request(session, "not-registered", &[]));

    let records = state.audit.lock().expect("audit lock").query(0);
    // The refusal is recorded by the dispatcher's own wrapper before the
    // worker layer sees it, so what matters is that the request is in the
    // chain at all rather than which layer wrote it.
    let named = records.iter().any(|r| match &r.event {
        AuditEventDto::RequestHandled { method, .. } => method == "run_isolated",
        _ => false,
    });
    assert!(
        named,
        "the refusal is in the chain; got {:?}",
        records.iter().map(|r| &r.event).collect::<Vec<_>>()
    );
}

/// The audit log's own capacity, asserted here so the fixture is honest about
/// the type it builds rather than about the broker.
#[test]
fn r1_the_audit_log_type_is_the_one_the_broker_holds() {
    let log = AuditLog::new(8);
    assert!(log.query(0).is_empty(), "a fresh chain is empty");
}

// ------------------------------------------------- the credential coming back

/// A credential the broker lent to a worker does not come back out of it.
///
/// This is the row that made the second half of R1 necessary. The runtime
/// resolves the injected secret into `secret_bytes`, hands it to the child, and
/// zeroizes its own copy — and then redacts the child's output with a redactor
/// built from the *template*, which has no way to know the value. So a tool
/// that echoes its own environment hands the credential straight back through
/// `IsolatedResult`, and the caller receives the very bytes the broker
/// resolved a moment earlier.
///
/// The ADR-0008 caveat is about a process *transforming* a secret, which
/// redaction cannot help with. Echoing is not a transformation: it is the
/// identity, and redaction is exactly the right tool for it. If this row is
/// red, the isolation pipeline is not merely weaker than the strong path, it
/// is a credential exfiltration path with a sandbox attached.
#[test]
fn r1_a_lent_credential_does_not_come_back_in_the_response() {
    require_userns("r1_a_lent_credential_does_not_come_back_in_the_response");
    let peer = pinned_peer();
    let mut state = state_with(vec![echo_secret_template()]);
    state.secrets = Some(std::sync::Arc::new(FixturePort));
    let credential =
        asv_domain::CredentialMetadata::new("fixture", asv_domain::CredentialKind::GenericSecret);
    // The reference a caller sends is the credential's wire id, which is what
    // the vault is keyed by — not its label.
    let credential_ref = credential.id.to_wire();
    state
        .credentials
        .lock()
        .expect("not poisoned")
        .push(credential);
    let session = open_session(&mut state, &peer);

    let response = handle(
        &mut state,
        &peer,
        Request::RunIsolated {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            worker: "leaky".into(),
            args: vec![],
            credential: Some(credential_ref),
            timeout_ms: Some(60_000),
        },
    );

    match response {
        Response::IsolatedResult { stdout, .. } => {
            let echoed = String::from_utf8_lossy(&stdout).into_owned();
            assert!(
                !echoed.contains(std::str::from_utf8(LENT).unwrap()),
                "the worker echoed the credential the broker lent it, and the \
                 broker returned it to the caller verbatim: {echoed:?}"
            );
        }
        other => panic!("expected an isolated result, got {other:?}"),
    }
}

/// The credential the redaction row depends on actually arrives.
///
/// Paired with the row above, and the pair is what makes either of them
/// meaningful on its own. `r1_a_lent_credential_does_not_come_back_in_the_response`
/// passes trivially if the child was handed nothing, because `printf %s ""`
/// prints nothing; this one fails loudly if injection breaks, because it
/// measures what the child received rather than what the broker withheld.
///
/// Reporting the length rather than the value is the point: the assertion
/// cannot itself become a place the secret is written down.
#[test]
fn r1_the_injected_credential_reaches_the_child() {
    require_userns("r1_the_injected_credential_reaches_the_child");
    let peer = pinned_peer();
    let mut template = echo_secret_template();
    template.arguments = vec!["-c".into(), r#"printf %s "$LEAK_TEST" | wc -c"#.into()];
    let mut state = state_with(vec![template]);
    state.secrets = Some(std::sync::Arc::new(FixturePort));
    let credential =
        asv_domain::CredentialMetadata::new("fixture", asv_domain::CredentialKind::GenericSecret);
    let credential_ref = credential.id.to_wire();
    state
        .credentials
        .lock()
        .expect("not poisoned")
        .push(credential);
    let session = open_session(&mut state, &peer);

    let response = handle(
        &mut state,
        &peer,
        Request::RunIsolated {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            worker: "leaky".into(),
            args: vec![],
            credential: Some(credential_ref),
            timeout_ms: Some(60_000),
        },
    );

    match response {
        Response::IsolatedResult { stdout, .. } => {
            let reported = String::from_utf8_lossy(&stdout);
            let reported = reported.trim();
            assert_eq!(
                reported,
                LENT.len().to_string(),
                "the child must have received the credential in full: a broken \
                 injection would also make the redaction row pass, and for the \
                 wrong reason"
            );
        }
        other => panic!("expected an isolated result, got {other:?}"),
    }
}
