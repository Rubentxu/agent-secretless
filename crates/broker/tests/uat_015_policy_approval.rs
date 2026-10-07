//! UAT-015 — policy approval
//!
//! The high-risk action blocks; an admitted control-plane peer approves the
//! exact request; the approval is spent once and cannot be replayed. The
//! whole flow runs over the IPC handlers rather than the policy engine alone,
//! because the property at stake is the *gate*: what an agent cannot do, and
//! what the operator can.
//!
//! ## Why this is a file of its own
//!
//! The claim is the file's leading comment, which is the only claim
//! `tools/check-gates.py` counts — a UAT proven by a test buried inside a
//! large `src/` file cannot be claimed at all, because the scanner reads the
//! first 2000 bytes. It also means the claim is the strongest statement the
//! test can make: this file exists to be UAT-015.
//!
//! ## What holds the boundary
//!
//! Not the socket — the custody contract on `admission::Enrolment`. The
//! enrolled list is the operator's own binaries; an agent binary must never
//! enter it. Every test here enrols *this* binary honestly, so an assertion
//! cannot be satisfied by a peer that was never admitted in the first place.

use asv_broker::admission::{admit_control_plane, sha256, Enrolment, ProcFs};
use asv_broker::{handle, BrokerState};
use asv_domain::{Action, Resource};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{Request, Response};
use asv_policy::{AuthorizationRequest, PolicyContext};

/// This test binary, enrolled as it really is on this machine at this moment
/// — the same construction the broker's own unit fixture uses, because a
/// fabricated enrolment would make every assertion below vacuous.
fn enrolment_of_this_binary() -> Enrolment {
    let path = std::fs::read_link("/proc/self/exe").expect("this process has an exe");
    let bytes = std::fs::read(&path).expect("the test binary is readable");
    Enrolment::empty().enrol(path, sha256(&bytes))
}

/// A live, pidfd-pinned peer: all three ADR-0015 conditions are satisfiable by
/// the process running this test, and it is the one that gets enrolled.
fn operator_peer() -> WorkloadIdentity {
    let mut identity = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    identity
        .pin_pidfd()
        .expect("the test process is live and pinnable");
    assert!(
        identity.is_pidfd_pinned(),
        "an unpinned fixture would test the closed door instead of the gate"
    );
    identity
}

fn protected_push(session: asv_domain::AgentSessionId, peer_uid: u32) -> AuthorizationRequest {
    AuthorizationRequest {
        session,
        action: Action::GitPush,
        resource: Resource::Repository {
            owner: "acme".into(),
            name: "app".into(),
        },
        context: PolicyContext {
            workspace: "/repo".into(),
            protected_ref: Some("main".into()),
            request_digest: Some("release-digest".into()),
            peer_uid,
        },
    }
}

#[test]
fn the_protected_push_blocks_until_the_operator_approves_it() {
    let mut state = BrokerState {
        control_plane: enrolment_of_this_binary(),
        ..BrokerState::default()
    };
    let operator = operator_peer();

    // The control. Without this the mint assertion below could be satisfied
    // by NotEnrolled and the test would prove nothing about the gate.
    admit_control_plane(&operator, &state.control_plane, &ProcFs)
        .expect("this fixture must be admitted, or every assertion below is vacuous");

    let session = match handle(
        &mut state,
        &operator,
        Request::CreateSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            workspace: "/repo".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    };
    let request = protected_push(session, operator.credentials.uid);

    // 1. Blocked: no human has approved anything yet.
    let blocked = match handle(
        &mut state,
        &operator,
        Request::Authorize {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: request.clone(),
            capability: None,
            approval: None,
        },
    ) {
        Response::Authorization { explanation } => explanation,
        other => panic!("expected a decision, got {other:?}"),
    };
    assert!(
        matches!(
            blocked.decision,
            asv_domain::Decision::RequireApproval { .. }
        ),
        "the protected-main push must block on approval, got {:?}",
        blocked.decision
    );

    // 2. The operator approves exactly this request, and gets the approval.
    let approval = match handle(
        &mut state,
        &operator,
        Request::SubmitApproval {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: request.clone(),
            ttl_secs: 60,
        },
    ) {
        Response::ApprovalIssued { approval } => approval,
        other => panic!("an admitted operator must be able to mint: {other:?}"),
    };
    assert_eq!(approval.session, request.session);
    assert_eq!(approval.action, request.action);
    assert_eq!(approval.request_digest, request.context.request_digest);
    assert_eq!(
        approval.remaining_uses, 1,
        "UAT-015 is 'allow once': the budget is the property, not a default"
    );

    // 3. The agent presents the id: the push goes through.
    let spent = match handle(
        &mut state,
        &operator,
        Request::Authorize {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: request.clone(),
            capability: None,
            approval: Some(approval.id),
        },
    ) {
        Response::Authorization { explanation } => explanation,
        other => panic!("expected the approved push to be evaluated, got {other:?}"),
    };
    assert!(
        matches!(spent.decision, asv_domain::Decision::Allow),
        "the approved push must be allowed, got {:?}",
        spent.decision
    );

    // 4. "Allow once" cannot be replayed after use.
    let replay = match handle(
        &mut state,
        &operator,
        Request::Authorize {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: request.clone(),
            capability: None,
            approval: Some(approval.id),
        },
    ) {
        Response::Authorization { explanation } => explanation,
        other => panic!("expected the replay to be evaluated, got {other:?}"),
    };
    assert!(
        matches!(
            replay.decision,
            asv_domain::Decision::Deny { ref reason } if reason == "approval consumed"
        ),
        "the replay must be refused as consumed, got {:?}",
        replay.decision
    );
}

#[test]
fn an_approval_is_spent_only_on_the_request_it_describes() {
    let mut state = BrokerState {
        control_plane: enrolment_of_this_binary(),
        ..BrokerState::default()
    };
    let operator = operator_peer();
    admit_control_plane(&operator, &state.control_plane, &ProcFs)
        .expect("this fixture must be admitted");

    let session = match handle(
        &mut state,
        &operator,
        Request::CreateSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            workspace: "/repo".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    };

    // Two approvals for two different requests. The ids are not
    // interchangeable: this is the property that stops an approval from
    // becoming a blank cheque for whatever the agent asks next.
    let mut other = protected_push(session, operator.credentials.uid);
    other.context.request_digest = Some("other-digest".into());
    let other_approval = match handle(
        &mut state,
        &operator,
        Request::SubmitApproval {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: other,
            ttl_secs: 60,
        },
    ) {
        Response::ApprovalIssued { approval } => approval,
        other => panic!("the second mint must succeed: {other:?}"),
    };

    let mismatch = match handle(
        &mut state,
        &operator,
        Request::Authorize {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: protected_push(session, operator.credentials.uid),
            capability: None,
            approval: Some(other_approval.id),
        },
    ) {
        Response::Authorization { explanation } => explanation,
        other => panic!("expected the mismatching spend to be evaluated, got {other:?}"),
    };
    assert!(
        matches!(
            mismatch.decision,
            asv_domain::Decision::Deny { ref reason } if reason == "approval mismatch"
        ),
        "spending an approval on a request it does not describe must mismatch, got {:?}",
        mismatch.decision
    );
}

#[test]
fn a_peer_that_is_not_enrolled_can_neither_approve_nor_read_audit() {
    // The other half of UAT-015, and the half the gate exists for: a peer
    // with no enrolment is refused at the admission, and the refusal names
    // the ADR-0015 condition that failed rather than asserting a reason this
    // broker cannot evaluate.
    let mut state = BrokerState::default();
    let stranger = operator_peer();

    match handle(
        &mut state,
        &stranger,
        Request::SubmitApproval {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request: protected_push(asv_domain::AgentSessionId::new(), stranger.credentials.uid),
            ttl_secs: 60,
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, asv_ipc_protocol::ErrorCode::Denied, "{message}");
            assert!(message.contains("refused:"), "{message}");
        }
        other => panic!("an unenrolled peer minted an approval: {other:?}"),
    }

    match handle(
        &mut state,
        &stranger,
        Request::AuditQuery {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            since_secs: 0,
        },
    ) {
        Response::Error { code, .. } => assert_eq!(code, asv_ipc_protocol::ErrorCode::Denied),
        other => panic!("an unenrolled peer read the audit log: {other:?}"),
    }

    // And the refused attempts are themselves recorded: an agent probing the
    // control plane is auditable evidence, not a silent no-op.
    assert!(
        state
            .audit
            .lock()
            .expect("no test holds this")
            .query(0)
            .len()
            >= 2,
        "both refused attempts must be in the log"
    );
    assert_eq!(
        state.audit.lock().expect("no test holds this").verify(),
        Ok(())
    );
}
