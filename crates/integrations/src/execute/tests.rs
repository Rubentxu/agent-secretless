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

/// A plan over the curl fixture's `.curlrc`, which is what the receipt rows
/// carry. Real `CurlFile`s would drag the whole discovery into a test whose
/// subject is the receipt's shape.
fn curl_plan() -> crate::plan::IntegrationPlan {
    crate::plan::IntegrationPlan::new("curl", Vec::new(), 0)
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
    let plan = curl_plan();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, _) = resolution_for(tmp.path(), "npm", NPM_A);

    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &plan,
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
    let plan = curl_plan();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, observed) = resolution_for(tmp.path(), "the real npm", NPM_A);

    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &plan,
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
    let plan = curl_plan();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (planned, observed) = resolution_for(tmp.path(), "npm", NPM_A);
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &plan,
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
    let plan = curl_plan();
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
        &plan,
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
///
/// **Asserted on the top-level field, not on the whole document.** An earlier
/// version of this row forbade the *string* `asv.integrations.plan/v2` anywhere
/// in the receipt, which was true for the wrong reason — the receipt simply did
/// not carry a plan. It now does, deliberately, and the nested plan has its own
/// schema string. What has to stay true is that the receipt does not *claim*
/// to be a plan, and that is a question about one field.
///
/// The row was written before the receipt carried a plan and had to be
/// rewritten rather than deleted, because the property it protects is real and
/// the version of it that failed was the version that could not see its own
/// subject.
#[test]
fn the_receipt_declares_its_own_schema() {
    let intent = intent();
    let plan = curl_plan();
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding_for(&intent),
        &plan,
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
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parses");

    assert_eq!(
        parsed["schema"], "asv.integrations.execute/v1",
        "the receipt must claim its own schema"
    );
    // The nested plan keeps its own schema, and the two do not collide.
    assert_eq!(parsed["plan"]["schema"], crate::plan::PLAN_SCHEMA);
    assert_ne!(
        parsed["schema"], parsed["plan"]["schema"],
        "a receipt and the plan it carries must not share a schema string"
    );
    for other in ["asv.integrations.adopt/v1", "asv.discovery/v1"] {
        assert!(!json.contains(other), "a receipt claimed {other}: {json}");
    }
}

/// **The property R4.B.1 claimed and did not have.** The receipt said it was
/// re-checkable, and it did not carry the plan — so a reader could see that an
/// operation was authorized and could not see *which credential* it would
/// spend. The row is the receipt carrying it, asserted rather than described.
#[test]
fn the_receipt_carries_the_plan_it_was_checked_against() {
    let intent = intent();
    let binding = binding_for(&intent);
    let plan = crate::plan::IntegrationPlan::new("npm", Vec::new(), 3);
    let none = ToolResolution {
        command: "npm".into(),
        path: "/usr/bin".into(),
        candidates: Vec::new(),
        resolved: None,
    };
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &plan,
        &none,
        &none,
        permit(),
        ExecuteOutcome::Executed,
    );
    assert_eq!(receipt.plan, plan, "the receipt lost the plan");
    assert_eq!(receipt.plan.inventory_size, 3, "and its inventory with it");

    let json = serde_json::to_string(&receipt).expect("serialises");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parses");
    assert_eq!(parsed["plan"]["inventory_size"], 3, "not in the document");
    let back: ExecuteReceipt = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back.plan, plan, "and it did not survive a round trip");
}

/// An execution that is authorized and binds nothing is a real state, and it is
/// not the same as one that spends a credential. A reader who has to count
/// `Binding::Bound` arms by hand will eventually stop counting.
#[test]
fn an_execution_that_binds_nothing_says_so() {
    let intent = intent();
    let binding = binding_for(&intent);
    let empty = crate::plan::IntegrationPlan::new("npm", Vec::new(), 0);
    let none = ToolResolution {
        command: "npm".into(),
        path: "/usr/bin".into(),
        candidates: Vec::new(),
        resolved: None,
    };
    let receipt = ExecuteReceipt::new(
        "npm",
        &intent,
        &binding,
        &empty,
        &none,
        &none,
        permit(),
        ExecuteOutcome::Executed,
    );
    assert!(
        !receipt.bound_anything(),
        "an empty inventory must not read as a binding"
    );
    assert_eq!(receipt.bound_count(), 0);
    assert_eq!(receipt.unbound_count(), 0, "there were no selectors at all");
    assert!(
        receipt.credentials_at_stake().is_empty(),
        "nothing may be reported as at stake when nothing bound"
    );
    // And it is authorized anyway — which is precisely the fact that has to be
    // visible rather than inferred, because the two together are the case a
    // reader most needs to notice.
    assert!(receipt.is_executed());
    assert_eq!(receipt.plan.inventory_size, 0);
}

// ------------------------------------------------- a plan that binds something

/// A `.curlrc` on disk and the inventory one credential, so the rows below run
/// against a plan that actually resolved a binding rather than an empty one.
///
/// The empty case has its own row, and an empty case is the easy one: a
/// receipt that reports nothing bound is right by default. These are the rows
/// that would notice if "bound" stopped meaning anything.
fn bound_receipt(inventory: &[asv_domain::CredentialMetadata]) -> ExecuteReceipt {
    use crate::Adapter as _;
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let rc = home.join(".curlrc");
    std::fs::write(&rc, "user = \"deploy:s3cr3t-value\"\n").expect("write");
    std::fs::set_permissions(
        &rc,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("chmod");

    let discovery = crate::Curl
        .discover(&crate::FingerprintPolicy::strict(), &home, tmp.path())
        .expect("the fixture is readable and ours");
    let plan = crate::plan::plan_curl(&discovery, inventory);

    let intent = intent();
    let binding = binding_for(&intent);
    let none = ToolResolution {
        command: "curl".into(),
        path: "/usr/bin".into(),
        candidates: Vec::new(),
        resolved: None,
    };
    ExecuteReceipt::new(
        "curl",
        &intent,
        &binding,
        &plan,
        &none,
        &none,
        permit(),
        ExecuteOutcome::Executed,
    )
}

fn one_bearer(label: &str) -> Vec<asv_domain::CredentialMetadata> {
    vec![asv_domain::CredentialMetadata::new(
        label,
        asv_domain::CredentialKind::BearerToken,
    )]
}

/// The positive half: one selector, one credential, and the receipt names it.
///
/// **On the label, which this row asserts is *present*.** The first version of
/// it forbade the label, on the reasoning that a label is "half the pair an
/// attacker needs" — which confuses a credential *label* with a credential
/// *user name*. `deploy-token` is the operator's own name for a vault entry and
/// is what every R3 vertical already prints; design §7 is explicit that a
/// binding is not a label, meaning the opposite: a receipt that can name a
/// credential id with no way to recognise it is a receipt nobody can act on.
///
/// What must not appear is what came out of the `.curlrc`: the value, and the
/// user name curl would authenticate as. Those are asserted below, and they are
/// the distinction the row was trying to make before it confused the two.
#[test]
fn a_bound_plan_names_the_credential_the_execution_would_spend() {
    let receipt = bound_receipt(&one_bearer("deploy-token"));
    assert_eq!(receipt.plan.entries.len(), 1, "precondition: one selector");
    assert!(receipt.bound_anything());
    assert_eq!(receipt.bound_count(), 1);
    assert_eq!(receipt.unbound_count(), 0);
    assert_eq!(receipt.credentials_at_stake().len(), 1);

    let json = serde_json::to_string(&receipt).expect("serialises");
    // The handle is there, and the label is there: an operator reading this
    // months later needs to recognise which vault entry this was.
    assert!(
        json.contains("deploy-token"),
        "the label is missing: {json}"
    );
    // What came out of the tool's file is not.
    assert!(
        !json.contains("s3cr3t-value"),
        "the password leaked into the receipt: {json}"
    );
    assert!(
        !json.contains("deploy\":"),
        "the user name leaked into the receipt: {json}"
    );
    // The id is what the accessor returns, and it is the only thing it returns.
    let ids = receipt.credentials_at_stake();
    assert_eq!(ids.len(), 1);
    assert!(
        json.contains(&ids[0].to_string()),
        "the id the accessor reports is not in the document"
    );
}

/// **Ambiguity is not a binding, and this is the row that says so.** Two
/// credentials of one shape cannot be told apart by anything in the inventory,
/// so `plan` refuses to choose. A receipt that counted `Ambiguous` as bound
/// would report a spend that cannot happen — worse than reporting none,
/// because it looks like an answer.
#[test]
fn an_ambiguous_binding_is_not_reported_as_a_spend() {
    let receipt = bound_receipt(&[
        asv_domain::CredentialMetadata::new(
            "deploy-token",
            asv_domain::CredentialKind::BearerToken,
        ),
        asv_domain::CredentialMetadata::new("ci-token", asv_domain::CredentialKind::BearerToken),
    ]);
    assert!(!receipt.bound_anything());
    assert_eq!(receipt.bound_count(), 0);
    assert!(
        receipt.credentials_at_stake().is_empty(),
        "an ambiguous binding was reported as a decided spend"
    );
    assert_eq!(
        receipt.unbound_count(),
        1,
        "but the selector is still named"
    );
    // And the receipt says *which* case it was, rather than leaving the reader
    // to infer it from a count of zero.
    assert!(
        matches!(
            receipt.plan.entries[0].binding,
            crate::plan::Binding::Ambiguous { .. }
        ),
        "{:?}",
        receipt.plan.entries[0].binding
    );
}

/// Nothing usable is also not a binding, and it is a different case again:
/// `unbound_count` counts selectors, not refusals, so a receipt can say "one
/// selector, nothing bound" and a reader can tell that from "no selectors".
#[test]
fn a_selector_nothing_could_serve_is_counted_as_unbound_not_absent() {
    let receipt = bound_receipt(&[]);
    assert_eq!(receipt.plan.entries.len(), 1, "the selector is still there");
    assert_eq!(receipt.bound_count(), 0);
    assert_eq!(
        receipt.unbound_count(),
        1,
        "a selector that bound nothing must be counted, not dropped"
    );
    assert!(receipt.credentials_at_stake().is_empty());
}

/// The two counts add up to the number of selectors, always. A receipt whose
/// arithmetic does not close is a receipt whose counts cannot both be right.
#[test]
fn the_two_counts_always_add_up_to_the_selectors() {
    for inventory in [
        Vec::new(),
        one_bearer("deploy-token"),
        vec![
            asv_domain::CredentialMetadata::new(
                "deploy-token",
                asv_domain::CredentialKind::BearerToken,
            ),
            asv_domain::CredentialMetadata::new(
                "ci-token",
                asv_domain::CredentialKind::BearerToken,
            ),
        ],
    ] {
        let receipt = bound_receipt(&inventory);
        assert_eq!(
            receipt.bound_count() + receipt.unbound_count(),
            receipt.plan.entries.len(),
            "inventory of {} credentials",
            inventory.len()
        );
    }
}
