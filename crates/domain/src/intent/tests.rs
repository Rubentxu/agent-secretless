//! Rows for the intent module, kept beside the code that has to survive them.
//!
//! The rows here are organised around one question: **what has to be true for
//! `PLAN_INVALIDATED` to be reachable at all?** A check that returns `Ok` when
//! it should refuse is the worst outcome available here, because it looks
//! exactly like the success it replaced — so most of what follows constructs a
//! world that has drifted and asserts that the drift is *named*.

use super::*;

use crate::Authority;

const NPM_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NPM_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn npm_at(path: &str, digest: &str) -> ToolIdentity {
    ToolIdentity::new(path, digest).expect("a well-formed digest")
}

fn api_resource() -> Resource {
    Resource::Api {
        audience: Authority::canonicalize("registry.npmjs.org").expect("a canonical host"),
    }
}

/// The intent the spec's worked example is about: publishing a package with
/// npm, out of a working directory, against a resolved `.npmrc`.
fn sample_intent() -> ActionIntent {
    ActionIntent {
        transaction: "tx-0001".into(),
        principal: "release-bot@example.test".into(),
        actor: "packager-agent".into(),
        workload: "ci/publish".into(),
        action: crate::Action::RegistryPush,
        resource: api_resource(),
        tool: Some(npm_at("/usr/bin/npm", NPM_A)),
        config_fingerprint: Some(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        ),
        origin: IntentOrigin::RetrievedContent,
        expires_at_unix: 1_800_000_000,
    }
}

/// The same intent with one field replaced, so a digest row can name the field
/// it is perturbing.
fn with_field<F: FnOnce(&mut ActionIntent)>(f: F) -> ActionIntent {
    let mut intent = sample_intent();
    f(&mut intent);
    intent
}

fn digest_of(intent: &ActionIntent) -> String {
    intent.digest().expect("serialises")
}

// -------------------------------------------------------------- determinism

/// The digest is the whole agreement between a planner and an executor, so it
/// has to be a function of the intent and nothing else. Computed twice, in two
/// calls, over two independently-built-but-equal intents.
#[test]
fn the_digest_is_a_function_of_the_intent_and_nothing_else() {
    let a = sample_intent();
    let b = sample_intent();
    assert_eq!(digest_of(&a), digest_of(&a), "not reproducible");
    assert_eq!(digest_of(&a), digest_of(&b), "not a function of the value");
}

/// Every field has to participate. A digest that ignored one field would let a
/// caller change the operation, the tool or the expiry and still present the
/// plan as answering the intent it was built for.
#[test]
fn every_field_of_the_intent_changes_the_digest() {
    let baseline = digest_of(&sample_intent());
    let perturbations: Vec<(&str, ActionIntent)> = vec![
        (
            "transaction",
            with_field(|i| i.transaction = "tx-0002".into()),
        ),
        (
            "principal",
            with_field(|i| i.principal = "someone-else@example.test".into()),
        ),
        ("actor", with_field(|i| i.actor = "another-agent".into())),
        ("workload", with_field(|i| i.workload = "ci/other".into())),
        (
            "action",
            with_field(|i| i.action = crate::Action::RegistryPull),
        ),
        (
            "resource",
            with_field(|i| {
                i.resource = Resource::Api {
                    audience: Authority::canonicalize("registry.example.test").expect("valid"),
                }
            }),
        ),
        (
            "tool",
            with_field(|i| i.tool = Some(npm_at("/usr/local/bin/npm", NPM_A))),
        ),
        ("tool.to_none", with_field(|i| i.tool = None)),
        (
            "tool.digest",
            with_field(|i| i.tool = Some(npm_at("/usr/bin/npm", NPM_B))),
        ),
        (
            "config_fingerprint",
            with_field(|i| {
                i.config_fingerprint = Some(
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .into(),
                )
            }),
        ),
        (
            "config_fingerprint.to_none",
            with_field(|i| i.config_fingerprint = None),
        ),
        (
            "origin",
            with_field(|i| i.origin = IntentOrigin::HumanDirect),
        ),
        (
            "expires_at_unix",
            with_field(|i| i.expires_at_unix = 1_800_000_001),
        ),
    ];
    for (field, perturbed) in perturbations {
        assert_ne!(
            digest_of(&perturbed),
            baseline,
            "changing `{field}` did not change the digest, so the plan would still \
             answer this intent"
        );
    }
}

/// The bytes the digest is taken over are pinned.
///
/// The value below is not a copy of whatever the implementation printed: it is
/// `sha256` over the JSON that `serde_json` is specified to write for this
/// struct — fields in declaration order, no whitespace, snake_case enums,
/// externally-tagged enum variants — recomputed outside the crate. If someone
/// adds a field to `ActionIntent`, this row goes red, and that is the point:
/// a field nobody re-pins is a field nobody checked for secrets either.
#[test]
fn the_digest_is_taken_over_exactly_these_bytes() {
    let expected = concat!(
        // {"transaction":…,"principal":…,"actor":…,"workload":…,
        r#"{"transaction":"tx-0001","principal":"release-bot@example.test","#,
        r#""actor":"packager-agent","workload":"ci/publish","#,
        // Action::RegistryPush serialises snake_case; Resource::Api is an
        // externally-tagged variant carrying an Authority, which is
        // `#[serde(transparent)]`.
        r#""action":"registry_push","resource":{"api":{"audience":"registry.npmjs.org"}},"#,
        // ToolIdentity is a struct of `path` and `digest` in that order.
        r#""tool":{"path":"/usr/bin/npm","#,
        r#""digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
        r#""config_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","#,
        r#""origin":"retrieved_content","expires_at_unix":1800000000}"#
    );
    // The bytes are pinned first, so the row above is not comparing two values
    // that came out of the same code path. If `serde_json` ever reorders,
    // re-spaces or renames, this is the assert that says so, and it says which
    // bytes moved rather than only that some hash changed.
    assert_eq!(
        serde_json::to_string(&sample_intent()).expect("serialises"),
        expected,
        "the serialised bytes changed; if the change is intentional, re-derive \
         this row out of band — it is the thing that notices a new field"
    );
    assert_eq!(
        digest_of(&sample_intent()),
        // Derived outside the crate: `sha256sum` over the 458 bytes above,
        // parsed with a stock JSON parser to confirm they are well-formed and
        // that the key order is the declaration order. Pinned as a literal so
        // this row does not compare two values that came out of one code path.
        "sha256:9bf0248bdf5f4dc789c2352145120e5b787e2736334bfc914bdf0dcc27b56db4",
        "the digest is not sha256 over the pinned bytes"
    );
    assert_eq!(
        digest_of(&sample_intent()),
        sha256_of(expected),
        "the digest is not sha256 over the pinned bytes"
    );
}

/// `sha256` over text, spelled out here so the expected value above is derived
/// by the same primitive the code uses and not by an assumption about it.
fn sha256_of(text: &str) -> String {
    format!("sha256:{:x}", sha2::Sha256::digest(text.as_bytes()))
}

// ------------------------------------------------------------ tool identity

/// A digest that is not a digest must not be constructible. A `ToolIdentity`
/// carrying `"A"` compares unequal to everything and reads in a receipt like a
/// value that was computed.
#[test]
fn a_malformed_tool_digest_is_refused() {
    for malformed in [
        "",
        "A",
        "sha256:",
        "aaaa",
        // Right prefix, too short.
        "sha256:aaaa",
        // Right length, no prefix.
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Right length and prefix, uppercase hex.
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        // One character too long.
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Non-hex character inside a full-length body.
        "sha256:gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // A digest algorithm this codebase does not use.
        "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Surrounding whitespace, which would defeat a textual comparison.
        " sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
        // A trailing newline, which is what a file read leaves behind.
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ] {
        assert!(
            ToolIdentity::new("/usr/bin/npm", malformed).is_err(),
            "must refuse {malformed:?}"
        );
    }
}

/// The positive half, because a constructor that refuses everything is also a
/// constructor that cannot build a plan.
#[test]
fn a_well_formed_tool_digest_is_accepted() {
    let id = ToolIdentity::new("/usr/bin/npm", NPM_A).expect("valid");
    assert_eq!(id.path, PathBuf::from("/usr/bin/npm"));
    assert_eq!(id.digest, NPM_A);
}

/// The two fields are both load-bearing, and each one failing looks like a
/// different incident to whoever reads the refusal.
#[test]
fn a_tool_matches_only_on_both_path_and_bytes() {
    let planned = npm_at("/usr/bin/npm", NPM_A);
    assert!(
        planned.matches(&npm_at("/usr/bin/npm", NPM_A)),
        "identical tools"
    );

    assert!(
        !planned.matches(&npm_at("/usr/local/bin/npm", NPM_A)),
        "same bytes at a different path is the spec's npm case"
    );
    assert!(
        !planned.matches(&npm_at("/usr/bin/npm", NPM_B)),
        "same path with different bytes is a replaced binary"
    );
}

/// `tool_identity_for` is the boundary where a caller's bytes become an
/// identity, so its output has to be exactly what `ToolIdentity::new` accepts
/// and nothing looser.
#[test]
fn tool_identity_for_digests_the_bytes_it_is_given() {
    let id = tool_identity_for(Path::new("/usr/bin/npm"), b"#!/usr/bin/env node\n").expect("ok");
    assert_eq!(id.path, PathBuf::from("/usr/bin/npm"));
    assert_eq!(id.digest, sha256_of("#!/usr/bin/env node\n"));
    // And it is a digest the rest of the module will accept, not merely a
    // string that happens to have been produced.
    assert!(npm_at("/usr/bin/npm", &id.digest).matches(&id));
}

// -------------------------------------------------------------- no secrets

/// Every field is an id, a name, an enum or a digest, so there is nowhere for a
/// secret to be. The row exists because that is a property of the *shape*, and
/// a later field holding a token would compile, serialise and hash silently.
#[test]
fn an_ordinary_intent_carries_no_secret_material() {
    sample_intent()
        .contains_no_secret_material()
        .expect("no field is long enough to be a credential");
}

/// The bound is 512 bytes, which is past any principal path or service-account
/// name and well under a token. Each field is checked on its own so the refusal
/// names which one.
#[test]
fn a_field_long_enough_to_be_a_credential_is_named_in_the_refusal() {
    let cases: Vec<(&str, ActionIntent)> = vec![
        ("principal", with_field(|i| i.principal = "x".repeat(513))),
        ("actor", with_field(|i| i.actor = "x".repeat(513))),
        ("workload", with_field(|i| i.workload = "x".repeat(513))),
        (
            "transaction",
            with_field(|i| i.transaction = "x".repeat(513)),
        ),
        (
            "tool.path",
            with_field(|i| {
                i.tool = Some(npm_at(&"x".repeat(4097), NPM_A));
            }),
        ),
    ];
    for (field, intent) in cases {
        let leak = intent
            .contains_no_secret_material()
            .expect_err("a 513-byte field must be refused");
        assert_eq!(leak.field, field);
    }
}

/// The boundary itself: 512 is allowed, 513 is not. An off-by-one here would
/// either refuse a legitimate long principal path or admit a token.
#[test]
fn the_length_bound_is_exactly_512_bytes() {
    let at = with_field(|i| i.principal = "x".repeat(512));
    at.contains_no_secret_material().expect("512 is allowed");
    let over = with_field(|i| i.principal = "x".repeat(513));
    assert!(over.contains_no_secret_material().is_err(), "513 is not");
}

/// And the serialised form really does reach the digest — a shape check that
/// did not run over the bytes being hashed would be checking nothing.
#[test]
fn the_secret_check_sees_the_same_bytes_the_digest_covers() {
    let intent = with_field(|i| i.principal = "x".repeat(513));
    let serialised = serde_json::to_string(&intent).expect("serialises");
    assert!(
        serialised.contains(&"x".repeat(513)),
        "fixture is wrong: the field did not reach the serialised form"
    );
    assert!(
        intent.contains_no_secret_material().is_err(),
        "the check must see what the digest covers"
    );
}

// ------------------------------------------------------------ the spec case

/// §3 of the identity/authority document, verbatim in shape:
///
/// ```text
/// plan:   /usr/bin/npm      sha256=A
/// execute: ~/project/bin/npm sha256=B
/// => PLAN_INVALIDATED
/// ```
///
/// This is the row the block exists for. Everything else here is machinery.
#[test]
fn the_specs_npm_example_is_invalidated_and_names_both_sides() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");

    let executing = npm_at("/home/dev/project/bin/npm", NPM_B);
    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            Some(&executing),
            intent.config_fingerprint.as_deref(),
            1_700_000_000,
            intent.expires_at_unix,
        )
        .expect_err("a different tool must invalidate the plan");

    match refusal {
        PlanInvalidation::ToolChanged {
            ref planned,
            ref found,
        } => {
            assert_eq!(planned.path, PathBuf::from("/usr/bin/npm"));
            assert_eq!(planned.digest, NPM_A);
            assert_eq!(found.path, PathBuf::from("/home/dev/project/bin/npm"));
            assert_eq!(found.digest, NPM_B);
        }
        other => panic!("expected ToolChanged, got {other}"),
    }
    assert!(
        refusal.to_string().starts_with("PLAN_INVALIDATED:"),
        "the refusal has to be greppable: {refusal}"
    );
    assert!(
        refusal.to_string().contains("/usr/bin/npm")
            && refusal.to_string().contains("/home/dev/project/bin/npm"),
        "the refusal has to name both sides"
    );
}

/// The unchanged world is the other half, and it is the half a broken
/// implementation gets wrong in the other direction: a check that always
/// refuses is not a check.
#[test]
fn an_unchanged_world_executes() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    plan.check_execution(
        &intent.digest().expect("digests"),
        intent.tool.as_ref(),
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        intent.expires_at_unix,
    )
    .expect("nothing moved");
}

/// Same path, different bytes is the *other* incident, and an operator's next
/// move is different: a different path is a `PATH` problem, a replaced binary
/// is worth an alarm. Conflating them loses that distinction.
#[test]
fn a_replaced_binary_is_reported_separately_from_a_different_path() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    let swapped = npm_at("/usr/bin/npm", NPM_B);
    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            Some(&swapped),
            intent.config_fingerprint.as_deref(),
            1_700_000_000,
            intent.expires_at_unix,
        )
        .expect_err("changed bytes must invalidate");
    match refusal {
        PlanInvalidation::ToolBytesChanged {
            path,
            planned_digest,
            found_digest,
        } => {
            assert_eq!(path, PathBuf::from("/usr/bin/npm"));
            assert_eq!(planned_digest, NPM_A);
            assert_eq!(found_digest, NPM_B);
        }
        other => panic!("expected ToolBytesChanged, got {other}"),
    }
}

/// The configuration the plan was built against is part of the promise. An
/// `.npmrc` that gained a registry line between plan and execute is exactly
/// the failure the config fingerprint exists to catch.
#[test]
fn a_configuration_that_moved_invalidates_the_plan() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");

    let moved = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            intent.tool.as_ref(),
            Some(moved),
            1_700_000_000,
            intent.expires_at_unix,
        )
        .expect_err("a moved configuration must invalidate");
    assert!(
        matches!(refusal, PlanInvalidation::ConfigChanged { .. }),
        "expected ConfigChanged, got {refusal}"
    );
    assert!(refusal.to_string().contains(&moved[..20]), "{refusal}");
}

/// The config check has to be symmetric about `None`, or "the plan had no
/// configuration and now there is one" passes silently.
#[test]
fn appearing_and_disappearing_configuration_both_invalidate() {
    let with_config = sample_intent();
    let without_config = with_field(|i| i.config_fingerprint = None);
    let digest = without_config.digest().expect("digests");

    let bound_with = PlanBinding::for_intent(&with_config).expect("binds");
    assert!(
        matches!(
            bound_with.check_execution(
                &with_config.digest().expect("digests"),
                with_config.tool.as_ref(),
                None,
                1_700_000_000,
                with_config.expires_at_unix,
            ),
            Err(PlanInvalidation::ConfigChanged {
                planned: Some(_),
                found: None
            })
        ),
        "a configuration that vanished must invalidate"
    );

    let bound_without = PlanBinding::for_intent(&without_config).expect("binds");
    assert!(
        matches!(
            bound_without.check_execution(
                &digest,
                without_config.tool.as_ref(),
                with_config.config_fingerprint.as_deref(),
                1_700_000_000,
                without_config.expires_at_unix,
            ),
            Err(PlanInvalidation::ConfigChanged {
                planned: None,
                found: Some(_)
            })
        ),
        "a configuration that appeared must invalidate"
    );
}

/// A plan may only be presented with the intent it answers. Otherwise the
/// operator reads "the tool was right" when the request underneath was not.
#[test]
fn a_plan_presented_with_a_different_intent_is_refused() {
    let planned = sample_intent();
    let other = with_field(|i| i.transaction = "tx-0002".into());
    let plan = PlanBinding::for_intent(&planned).expect("binds");
    let refusal = plan
        .check_execution(
            &other.digest().expect("digests"),
            planned.tool.as_ref(),
            planned.config_fingerprint.as_deref(),
            1_700_000_000,
            planned.expires_at_unix,
        )
        .expect_err("a different intent must not execute against this plan");
    match refusal {
        PlanInvalidation::IntentMismatch { planned, found } => {
            assert_eq!(planned, plan.intent_digest);
            assert_eq!(found, other.digest().expect("digests"));
        }
        other => panic!("expected IntentMismatch, got {other}"),
    }
}

/// Expiry is checked **first**, so an expired intent is refused on a request
/// where the tool also moved, and the caller is not left having to work out
/// which of two reasons applied.
#[test]
fn expiry_is_reported_before_any_drift() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    let wrong_tool = npm_at("/home/dev/project/bin/npm", NPM_B);

    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            Some(&wrong_tool),
            None, // the configuration moved too
            1_900_000_000,
            intent.expires_at_unix,
        )
        .expect_err("expired");
    assert!(
        matches!(refusal, PlanInvalidation::Expired { .. }),
        "expiry must win over every other reason, got {refusal}"
    );
}

/// `now == expires_at` is expired. An off-by-one here extends every intent by a
/// whole second, which sounds harmless until an intent is minted with a very
/// near expiry on purpose.
#[test]
fn the_expiry_boundary_is_inclusive() {
    let intent = sample_intent();
    assert!(
        !intent.is_expired(intent.expires_at_unix - 1),
        "one second early"
    );
    assert!(intent.is_expired(intent.expires_at_unix), "at the instant");
    assert!(
        intent.is_expired(intent.expires_at_unix + 1),
        "one second late"
    );
}

/// A tool-agnostic intent is legitimate — the plan says nothing about which
/// executable — so `None` on both sides executes.
#[test]
fn an_intent_that_named_no_tool_executes_when_none_resolves() {
    let intent = with_field(|i| i.tool = None);
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    plan.check_execution(
        &intent.digest().expect("digests"),
        None,
        intent.config_fingerprint.as_deref(),
        1_700_000_000,
        intent.expires_at_unix,
    )
    .expect("tool-agnostic is not a mismatch");
}

/// The asymmetry is deliberate but must not be silent: a plan that committed to
/// no tool cannot have one silently appear, because the plan no longer
/// describes what will run.
#[test]
fn a_tool_appearing_under_a_tool_agnostic_plan_is_still_a_refusal() {
    let intent = with_field(|i| i.tool = None);
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    let resolved = npm_at("/usr/bin/npm", NPM_A);
    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            Some(&resolved),
            intent.config_fingerprint.as_deref(),
            1_700_000_000,
            intent.expires_at_unix,
        )
        .expect_err("an appearing tool must invalidate");
    assert!(
        refusal
            .to_string()
            .contains("(no tool named by the intent)"),
        "the refusal has to say which side had one: {refusal}"
    );
}

/// And the mirror: the plan named a tool and the execution could not resolve
/// it. Resolving to nothing is not resolving to the plan.
#[test]
fn a_tool_that_stops_resolving_is_a_refusal() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    let refusal = plan
        .check_execution(
            &intent.digest().expect("digests"),
            None,
            intent.config_fingerprint.as_deref(),
            1_700_000_000,
            intent.expires_at_unix,
        )
        .expect_err("an unresolved tool must invalidate");
    assert!(
        refusal
            .to_string()
            .contains("(unresolved at execution time)"),
        "{refusal}"
    );
}

// ------------------------------------------------------------------ binding

/// A binding takes its tool and configuration from the intent rather than from
/// a caller that could pass something else, so it cannot describe a world the
/// intent did not ask about.
#[test]
fn a_binding_takes_the_tool_and_configuration_from_its_intent() {
    let intent = sample_intent();
    let plan = PlanBinding::for_intent(&intent).expect("binds");
    assert_eq!(plan.intent_digest, intent.digest().expect("digests"));
    assert_eq!(plan.tool, intent.tool);
    assert_eq!(plan.config_fingerprint, intent.config_fingerprint);
}

/// Re-binding a drifted intent yields a *different* digest, so a plan cannot be
/// presented against an intent that has been edited underneath it.
#[test]
fn rebinding_a_changed_intent_produces_a_different_binding() {
    let before = PlanBinding::for_intent(&sample_intent()).expect("binds");
    let after = PlanBinding::for_intent(&with_field(|i| i.expires_at_unix += 60)).expect("binds");
    assert_ne!(before.intent_digest, after.intent_digest);
}

// ---------------------------------------------------------------- wire names

/// These strings reach receipts and audit logs. A renamed variant that
/// compiles and silently changes what a stored receipt says is the failure
/// this row exists to make loud.
#[test]
fn every_invalidation_reason_has_a_pinned_wire_name() {
    let cases: Vec<(&str, PlanInvalidation)> = vec![
        (
            "tool_changed",
            PlanInvalidation::ToolChanged {
                planned: npm_at("/usr/bin/npm", NPM_A),
                found: npm_at("/home/dev/project/bin/npm", NPM_B),
            },
        ),
        (
            "tool_bytes_changed",
            PlanInvalidation::ToolBytesChanged {
                path: PathBuf::from("/usr/bin/npm"),
                planned_digest: NPM_A.into(),
                found_digest: NPM_B.into(),
            },
        ),
        (
            "config_changed",
            PlanInvalidation::ConfigChanged {
                planned: Some(NPM_A.into()),
                found: None,
            },
        ),
        (
            "intent_mismatch",
            PlanInvalidation::IntentMismatch {
                planned: NPM_A.into(),
                found: NPM_B.into(),
            },
        ),
        (
            "expired",
            PlanInvalidation::Expired {
                expires_at_unix: 1_800_000_000,
                now_unix: 1_900_000_000,
            },
        ),
    ];
    for (expected, invalidation) in cases {
        assert_eq!(invalidation.wire_name(), expected);
        assert!(
            invalidation.to_string().starts_with("PLAN_INVALIDATED:"),
            "every refusal has to carry the spec's token: {invalidation}"
        );
    }
}

/// Same reasoning for the origin: a policy names it, and a rename that
/// compiles would leave every written rule matching nothing.
#[test]
fn every_origin_has_a_pinned_wire_name() {
    let cases = [
        (IntentOrigin::HumanDirect, "human_direct"),
        (IntentOrigin::ScheduledWorkflow, "scheduled_workflow"),
        (IntentOrigin::TrustedTool, "trusted_tool"),
        (IntentOrigin::RetrievedContent, "retrieved_content"),
        (IntentOrigin::UntrustedToolOutput, "untrusted_tool_output"),
        (IntentOrigin::DelegatedAgent, "delegated_agent"),
    ];
    for (origin, expected) in cases {
        assert_eq!(origin.wire_name(), expected);
    }
}

/// Only the two attacker-influenced origins. This is a convenience so a policy
/// author does not have to remember which two of six they are — and the doc
/// says it is not a control on its own, so it is worth a row that says what it
/// does and does not cover.
#[test]
fn only_the_attacker_influenced_origins_are_flagged() {
    assert!(IntentOrigin::RetrievedContent.may_be_influenced_by_content());
    assert!(IntentOrigin::UntrustedToolOutput.may_be_influenced_by_content());
    for trusted in [
        IntentOrigin::HumanDirect,
        IntentOrigin::ScheduledWorkflow,
        IntentOrigin::TrustedTool,
        IntentOrigin::DelegatedAgent,
    ] {
        assert!(
            !trusted.may_be_influenced_by_content(),
            "{trusted:?} must not be flagged: it was not chosen by content"
        );
    }
}

// --------------------------------------------------------------- round trips

/// An intent crosses a boundary — hashed, stored in a receipt, read by an
/// operator — so it has to come back out of JSON unchanged, digest included.
#[test]
fn an_intent_round_trips_through_json_with_its_digest() {
    let intent = sample_intent();
    let json = serde_json::to_string(&intent).expect("serialises");
    let back: ActionIntent = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, intent);
    assert_eq!(
        back.digest().expect("digests"),
        intent.digest().expect("digests"),
        "a round trip that changes the digest would break every stored plan"
    );
}

/// A plan binding round-trips for the same reason: it is what a receipt carries
/// so a reader can re-check it later.
#[test]
fn a_plan_binding_round_trips_through_json() {
    let plan = PlanBinding::for_intent(&sample_intent()).expect("binds");
    let json = serde_json::to_string(&plan).expect("serialises");
    let back: PlanBinding = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, plan);
}
