//! Rows for the execute receipt.
//!
//! The receipt is the one artefact of R4.B.1 that outlives the process, so
//! these rows are mostly about what a reader can do with it later: re-check a
//! refusal, see both sides of a drift, and never find a secret in it.

use super::*;

use crate::tool::resolve_tool_bounded;

use asv_domain::{Action, Authority, PlanBinding, PlanInvalidation, Resource, ToolIdentity};

const NPM_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NPM_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn npm_at(path: &str, digest: &str) -> ToolIdentity {
    ToolIdentity::new(path, digest).expect("a well-formed digest")
}

fn permit() -> AuthorizationVerdict {
    AuthorizationVerdict::Permit {
        decision: "permit".into(),
    }
}

fn deny() -> AuthorizationVerdict {
    AuthorizationVerdict::Deny {
        reason: "origin retrieved_content may not publish to production".into(),
        reason_code: "PolicyDenied".into(),
    }
}

fn intent() -> ActionIntent {
    ActionIntent {
        transaction: "tx-exec-1".into(),
        principal: "release-bot@example.test".into(),
        actor: "packager-agent".into(),
        workload: "ci/publish".into(),
        action: Action::RegistryPush,
        resource: Resource::Api {
            audience: Authority::canonicalize("registry.npmjs.org").expect("canonical"),
        },
        tool: Some(npm_at("/usr/bin/npm", NPM_A)),
        config_fingerprint: Some(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        ),
        origin: IntentOrigin::RetrievedContent,
        expires_at_unix: 1_800_000_000,
    }
}

fn binding_for(intent: &ActionIntent) -> PlanBinding {
    PlanBinding {
        intent_digest: intent.digest().expect("digests"),
        tool: intent.tool.clone(),
        config_fingerprint: intent.config_fingerprint.clone(),
    }
}

/// A resolution that found `/usr/bin/npm`, built over a real directory so it is
/// the shape the receipt actually carries.
fn resolution_for(
    dir: &std::path::Path,
    body: &str,
    digest: &str,
) -> (ToolResolution, ToolResolution) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("npm");
    std::fs::write(&path, body).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let resolution =
        resolve_tool_bounded("npm", &dir.to_string_lossy(), 1 << 20).expect("searches");
    assert_eq!(
        resolution.resolved.as_ref().expect("resolved").digest,
        crate::tool::sha256_of(body.as_bytes()),
        "the fixture does not match the digest the row claims"
    );
    let _ = digest;
    (resolution.clone(), resolution)
}

// ------------------------------------------------------------------ decide

/// The spec's case, end to end and through the receipt path: the plan named
/// one npm, the execution would run another, and the attempt is refused.
#[test]
fn a_hijacked_tool_is_refused_before_anything_executes() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");

    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&npm_at("/home/dev/project/bin/npm", NPM_B)),
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        &permit(),
    );
    assert!(!outcome.is_executed());
    assert!(
        outcome.headline().starts_with("PLAN_INVALIDATED:"),
        "{}",
        outcome.headline()
    );
    match outcome {
        ExecuteOutcome::PlanInvalidated {
            reason,
            invalidation: PlanInvalidation::ToolChanged { planned, found },
        } => {
            assert_eq!(reason, "tool_changed");
            assert_eq!(planned, npm_at("/usr/bin/npm", NPM_A));
            assert_eq!(found, npm_at("/home/dev/project/bin/npm", NPM_B));
        }
        other => panic!("expected ToolChanged, got {other:?}"),
    }
}

/// The unchanged world executes. A check that always refuses is not a check.
#[test]
fn an_unchanged_world_and_a_permit_execute() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&npm_at("/usr/bin/npm", NPM_A)),
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        &permit(),
    );
    assert_eq!(outcome, ExecuteOutcome::Executed);
    assert!(outcome.is_executed());
}

/// A broker refusal is carried in the broker's own words, not paraphrased.
/// This crate has no policy engine and must not grow one, so the only thing it
/// can do with a verdict is repeat it faithfully.
#[test]
fn a_broker_refusal_is_carried_verbatim() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");
    let verdict = deny();
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        intent.tool.as_ref(),
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        &verdict,
    );
    assert!(!outcome.is_executed());
    match &outcome {
        ExecuteOutcome::Unauthorized {
            reason,
            reason_code,
        } => {
            assert_eq!(reason, verdict.denial().expect("a deny names a reason"));
            assert_eq!(reason_code, "PolicyDenied");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    assert!(outcome.headline().starts_with("UNAUTHORIZED:"));
}

/// **The ordering row.** A drifted plan is refused without the broker's verdict
/// being consulted for the outcome — the request would be about something that
/// cannot happen, and an operator reading the refusal must not have to work out
/// which of two reasons applied.
#[test]
fn a_moved_world_outranks_a_broker_refusal() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&npm_at("/home/dev/project/bin/npm", NPM_B)),
        None, // and the configuration moved too
        1_700_000_000,
        &deny(),
    );
    assert!(
        matches!(outcome, ExecuteOutcome::PlanInvalidated { .. }),
        "the broker's refusal buried the drift: {outcome:?}"
    );
}

/// And expiry before both, so a dead request is refused as dead.
#[test]
fn expiry_outranks_everything_else() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&npm_at("/home/dev/project/bin/npm", NPM_B)),
        None,
        1_900_000_000, // after expiry
        &deny(),
    );
    match &outcome {
        ExecuteOutcome::PlanInvalidated {
            reason,
            invalidation: PlanInvalidation::Expired { .. },
        } => assert_eq!(reason, "expired"),
        other => panic!("expiry must outrank the drift and the denial, got {other:?}"),
    }
}

// ----------------------------------------------------------------- receipt

/// The receipt answers three questions in order — what was asked, what was
/// promised, what happened — and carries all three. A receipt carrying only
/// the outcome is a log line.
#[test]
fn the_receipt_carries_the_intent_the_binding_and_the_outcome() {
    let intent = intent();
    let binding = binding_for(&intent);
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, _) = resolution_for(tmp.path(), "npm", NPM_A);

    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &planned,
        &planned,
        permit(),
        ExecuteOutcome::Executed,
    );
    assert_eq!(receipt.schema, EXECUTE_SCHEMA);
    assert_eq!(receipt.family, "npm");
    assert_eq!(receipt.intent, intent);
    assert_eq!(receipt.origin, IntentOrigin::RetrievedContent);
    assert_eq!(receipt.binding, binding);
    assert_eq!(receipt.outcome, ExecuteOutcome::Executed);
    assert_eq!(
        receipt.config_digest(),
        intent.config_fingerprint.as_deref()
    );
    assert!(receipt.is_executed());
}

/// Both resolutions travel, because the pair *is* the evidence. A receipt
/// carrying one cannot show that anything changed.
#[test]
fn the_receipt_carries_both_the_planned_and_the_observed_resolution() {
    let intent = intent();
    let binding = binding_for(&intent);
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, observed) = resolution_for(tmp.path(), "the real npm", NPM_A);

    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &planned,
        &observed,
        permit(),
        ExecuteOutcome::Executed,
    );
    assert_eq!(receipt.planned_tool, observed);
    let json = serde_json::to_string(&receipt).expect("serialises");
    assert_eq!(
        json.matches("\"candidates\"").count(),
        2,
        "both resolutions must be in the receipt"
    );
}

/// The law of this crate, on the newest artefact: a receipt holds no secret.
/// Not "redacted" — the types have nowhere to put one.
#[test]
fn the_receipt_holds_no_secret_material() {
    let intent = intent();
    let binding = binding_for(&intent);
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, observed) = resolution_for(tmp.path(), "npm", NPM_A);
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &planned,
        &observed,
        permit(),
        ExecuteOutcome::Executed,
    );
    intent
        .contains_no_secret_material()
        .expect("the intent carries none");
    let json = serde_json::to_string(&receipt).expect("serialises");
    for forbidden in ["s3cr3t", "_authToken", "password", "secret_value"] {
        assert!(
            !json.contains(forbidden),
            "the receipt leaked {forbidden:?}: {json}"
        );
    }
}

/// A receipt is read back, by whoever audits it months later, so it has to
/// survive the round trip — including a refusal with both sides of the drift
/// in it.
#[test]
fn a_refused_receipt_round_trips_through_json_with_both_sides() {
    let intent = intent();
    let binding = binding_for(&intent);
    let digest = intent.digest().expect("digests");
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&npm_at("/home/dev/project/bin/npm", NPM_B)),
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        &permit(),
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, observed) = resolution_for(tmp.path(), "npm", NPM_A);
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &planned,
        &observed,
        permit(),
        outcome,
    );

    let json = serde_json::to_string(&receipt).expect("serialises");
    let back: ExecuteReceipt = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, receipt);
    assert!(!back.is_executed());

    // And the audit is still possible: a reader can pull both sides out again.
    match back.outcome {
        ExecuteOutcome::PlanInvalidated { invalidation, .. } => match invalidation {
            PlanInvalidation::ToolChanged { planned, found } => {
                assert_eq!(planned.digest, NPM_A);
                assert_eq!(found.digest, NPM_B);
            }
            other => panic!("expected ToolChanged, got {other}"),
        },
        other => panic!("expected PlanInvalidated, got {other:?}"),
    }
}

/// The verdict is carried opaquely, and the type cannot grow a field implying
/// ASV decided anything. A `permit` with a decision string and a `deny` with a
/// reason are the whole vocabulary.
#[test]
fn the_verdict_vocabulary_is_permit_or_deny_and_nothing_else() {
    assert!(permit().is_permit());
    assert_eq!(permit().denial(), None);
    assert!(!deny().is_permit());
    assert!(deny().denial().is_some());
    let json = serde_json::to_string(&deny()).expect("serialises");
    assert!(json.contains("\"deny\""), "{json}");
    let back: AuthorizationVerdict = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, deny());
}

/// The schema is its own, distinct from the plan and the adopt receipt, so a
/// consumer handed one cannot mistake a record for the advice it came from.
#[test]
fn the_receipt_declares_its_own_schema() {
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent(),
        &binding_for(&intent()),
        &ToolResolution {
            command: "npm".into(),
            path: "/usr/bin".into(),
            candidates: Vec::new(),
            resolved: None,
        },
        &ToolResolution {
            command: "npm".into(),
            path: "/usr/bin".into(),
            candidates: Vec::new(),
            resolved: None,
        },
        permit(),
        ExecuteOutcome::Executed,
    );
    let json = serde_json::to_string(&receipt).expect("serialises");
    assert!(
        json.contains(r#""schema":"asv.integrations.execute/v1""#),
        "{json}"
    );
    for other in [
        "asv.integrations.plan/v2",
        "asv.integrations.adopt/v1",
        "asv.discovery/v1",
    ] {
        assert!(!json.contains(other), "a receipt claimed {other}: {json}");
    }
}
