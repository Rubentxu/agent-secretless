//! H2, second half: the issuance gate is not decorative.
//!
//! `h2_github_policy_bypass` proves the *class binding* — a database-class
//! surrogate cannot back a GitHub call. This file proves the other half: that
//! `MintSurrogate` really consults the policy engine.
//!
//! # Why this file has to exist
//!
//! The default policy **permits** the GitHub trio unconditionally
//! (`crates/policy/src/lib.rs:34-39`). So under the default policy the
//! issuance gate returns `Allow` every time, and every test that mints a
//! surrogate through it passes whether or not the gate exists. Deleting
//! `authorize_surrogate_mint` outright would leave the entire suite green.
//!
//! That is the same failure shape as the `exportability`/`human_only` defect
//! this repository already shipped once: a green test that asserts nothing.
//! The only way to observe a deny branch that the default policy never
//! reaches is to install a policy that denies, and watch the refusal happen.
//!
//! # The control
//!
//! Every case here is paired. The deny case is meaningless without the permit
//! case proving the *same fixture* mints successfully under the default
//! policy — otherwise "the mint was refused" could be explained by an absent
//! credential, an unpinned session or a malformed request, and the test would
//! pass for reasons that have nothing to do with policy.

use std::path::PathBuf;

use asv_broker::{handle, BrokerState};
use asv_domain::{CredentialKind, CredentialMetadata};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_policy::PolicyEngine;

/// A policy that forbids everything.
///
/// `forbid` rather than an empty policy: an empty policy set also denies
/// everything, but a rule that explicitly forbids is a rule the engine
/// actually *evaluated*, so a failure here is evidence about the gate and not
/// about a policy set that happened to be missing.
const DENY_EVERYTHING: &str = "forbid(principal, action, resource);";

struct Harness {
    state: BrokerState,
    peer: WorkloadIdentity,
    session: asv_domain::AgentSessionId,
    credential: asv_domain::CredentialId,
}

/// Builds a broker with a pinned peer, a live session and one credential.
///
/// `wired` as in the connection is real: the peer pins itself, the session
/// belongs to that peer, and the credential exists in the mirror. A mint that
/// is refused from here is refused by policy and by nothing else.
fn harness(kind: CredentialKind) -> Harness {
    let mut state = BrokerState::default();
    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("the test pins its own process");
    let session = state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("/repo".to_string(), &peer);

    let metadata = CredentialMetadata::new("h2-issuance", kind);
    let credential = metadata.id;
    state
        .credentials
        .lock()
        .expect("not poisoned")
        .push(metadata);

    Harness {
        state,
        peer,
        session,
        credential,
    }
}

impl Harness {
    fn mint(&mut self) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::MintSurrogate {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
                session: self.session,
                credential: self.credential,
                max_uses: 2,
                ttl_secs: 300,
            },
        )
    }

    fn forbid_everything(&mut self) {
        self.state.policy = PolicyEngine::from_policy_text(DENY_EVERYTHING)
            .expect("a forbid-everything policy is valid against the built-in schema");
    }
}

/// The control for the deny case, and the reason the deny case means anything.
///
/// Under the **default** policy the very same fixture mints. If this failed,
/// the denial in the next test would be explicable by anything at all in the
/// setup and the gate would be unproven.
#[test]
fn the_default_policy_permits_a_mint() {
    let mut h = harness(CredentialKind::GenericSecret);
    match h.mint() {
        Response::SurrogateMinted { .. } => {}
        other => panic!(
            "the control must mint under the default policy, or the denial \
             below proves nothing: {other:?}"
        ),
    }
}

/// The finding: the policy is consulted at issuance, and a denial is a real
/// denial.
///
/// This is the half of H2 that no other test can reach. The class binding is
/// proven in `h2_github_policy_bypass`; this proves the *policy* is no longer
/// decorative on the GitHub path.
#[test]
fn a_policy_that_denies_refuses_the_mint() {
    let mut h = harness(CredentialKind::GenericSecret);
    // Same fixture, same credential, same peer — only the policy differs.
    h.forbid_everything();

    match h.mint() {
        Response::Error { code, message } => {
            assert_eq!(
                code,
                ErrorCode::Denied,
                "a refusing policy must answer Denied: {message}"
            );
            // The reason is Cedar's, forwarded verbatim, so a policy author can
            // see which clause fired. If the broker invented its own wording
            // the operator would be debugging the wrong text.
            assert!(
                !message.is_empty(),
                "the refusal must carry a reason the operator can act on"
            );
        }
        other => panic!(
            "H2 is NOT fixed: the policy forbids everything and the broker \
             still minted — {other:?}"
        ),
    }
}

/// The gate refuses *before* it creates anything.
///
/// A denial that still pushed a record into the registry would leave a live
/// token behind an error, which is the exact shape of a control that reports
/// failure while the capability survives.
#[test]
fn a_refused_mint_leaves_no_token_behind() {
    let mut h = harness(CredentialKind::GenericSecret);
    h.forbid_everything();

    assert!(
        matches!(h.mint(), Response::Error { .. }),
        "the fixture must refuse, or this test proves nothing"
    );
    assert_eq!(
        h.state.surrogates.lock().expect("no test holds this").len(),
        0,
        "a refused mint must not leave a live surrogate in the registry"
    );
}

/// A database-class credential is asked about the database verb.
///
/// This is the branch that keeps the class decision honest in both directions:
/// the gate is not simply "always ask about GitHub", which would make a
/// database credential unmintable and hide the class mapping behind a
/// convenient default.
#[test]
fn a_database_credential_is_evaluated_against_the_database_verb() {
    // A policy that permits the database read but forbids everything else.
    // The class is `Database`, so the mint must succeed; if the broker asked
    // about the GitHub verb instead, this would be denied and the test fails.
    let db_only = r#"
    permit(principal, action == Action::"postgres_read", resource is Database);
    forbid(principal, action, resource) when { !(action == Action::"postgres_read" && resource is Database) };
    "#;
    let mut h = harness(CredentialKind::DatabaseCredential);
    h.state.policy = PolicyEngine::from_policy_text(db_only)
        .expect("the database-only policy is valid against the built-in schema");

    match h.mint() {
        Response::SurrogateMinted { .. } => {}
        other => panic!(
            "a database-class credential must be evaluated against the \
             database verb, and the default-permitting case must still mint: \
             {other:?}"
        ),
    }
}

/// The same fixture, asked about the wrong verb, is refused.
///
/// The control for the test above, and the falsification of "the gate ignores
/// the class and always permits": with the class mapping inverted, the same
/// database credential must be denied.
#[test]
fn the_class_decides_which_verb_the_policy_is_asked_about() {
    // Permits the GitHub read and forbids the database read.
    let gh_only = r#"
    permit(principal, action == Action::"github_issue_read", resource is Api);
    forbid(principal, action, resource) when { !(action == Action::"github_issue_read" && resource is Api) };
    "#;
    let mut h = harness(CredentialKind::DatabaseCredential);
    h.state.policy = PolicyEngine::from_policy_text(gh_only)
        .expect("the github-only policy is valid against the built-in schema");

    match h.mint() {
        Response::Error { code, .. } => assert_eq!(
            code,
            ErrorCode::Denied,
            "a database credential must not be minted against a policy that \
             only permits the GitHub verb"
        ),
        other => panic!(
            "the class did not reach the policy: a database-class credential \
             was minted under a GitHub-only policy — {other:?}"
        ),
    }
}

/// Sanity: the harness really is wired, so a green suite here means something.
#[test]
fn the_harness_really_does_have_a_credential() {
    let h = harness(CredentialKind::GenericSecret);
    assert_eq!(
        h.state.credentials.lock().expect("not poisoned").len(),
        1,
        "exactly one credential"
    );
    assert!(
        h.state
            .sessions
            .lock()
            .expect("no test holds this")
            .is_pinned(h.session),
        "the session is pinned"
    );
    let _ = PathBuf::new();
}
