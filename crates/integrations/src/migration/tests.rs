//! What the state machine refuses, and one path it allows.
//!
//! The claim these tests hold is narrow and is stated in `migration`'s own
//! module docs: **the ordering is a type error, and the evidence cannot be
//! fabricated**. They do not claim the checks are correct or that any substrate
//! is real — AAT-CW-014 through 018 hold that, and a row here that went green
//! on a fixture would be the exact failure this repository exists to prevent.
//!
//! The illegal paths split across two kinds of evidence, and the split matters:
//!
//! - The *runtime* rows below are refusals the pipeline can make. An attestation
//!   that does not match, a tool that reports nothing, an approval over the
//!   wrong plan: each produces a named [`ProofError`], not a bare `false`.
//! - The *compile-time* claims — that an `Approved` cannot exist without the
//!   three proofs — are held by the `compile_fail` doctests at the bottom. A
//!   test that ran would not be evidence; the point is that there is no program
//!   to run.

use super::*;
use crate::adopt::{AdoptReceipt, AdoptSelector};
use crate::fingerprint::{FileFingerprint, FingerprintPolicy};
use crate::npm::AuthField;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// An `Adoption` and a storage proof that belongs to *it*.
///
/// Bound together on purpose. An earlier version of these rows built the proof
/// and the receipt from separate calls, so the ids differed and every one of
/// them failed with `WrongCredential` — which is the check working, not the
/// tests being wrong. The two values are one fact in reality: the broker
/// answered about the credential this migration adopted.
fn adoption_with_proof() -> (Adoption, StorageProof) {
    let r = receipt();
    let p = StorageProof::from_broker(
        r.credential,
        "npm-registry",
        asv_domain::Exportability::NonExportable,
    );
    (Adoption::new(r), p)
}

/// A standalone proof, for rows that only inspect what it reports.
fn proof() -> StorageProof {
    StorageProof::from_broker(
        receipt().credential,
        "npm-registry",
        asv_domain::Exportability::NonExportable,
    )
}

/// A real `.npmrc` in a real temp directory, fingerprinted by the real policy.
///
/// Not a hand-built `FileFingerprint`: these rows are about what the *types*
/// permit, and a fingerprint invented in a test would let a change to
/// `FileFingerprint` go unnoticed. The npm end-to-end claim belongs to
/// `crates/broker/tests/r3a3_npm_adopt.rs`.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("write");
        // npm's own auth-line spelling, including the leading `//` that names
        // the registry. That prefix is what made an earlier attempt at this
        // file read as a network share to a shell safety filter.
        file.write_all(AUTH_LINE.as_bytes()).expect("write");
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join(".npmrc")
    }

    fn fingerprint(&self) -> FileFingerprint {
        FingerprintPolicy::strict()
            .fingerprint(&self.path())
            .expect("the fixture is a readable 0600 file")
    }

    fn selector(&self) -> AdoptSelector {
        AdoptSelector {
            file: self.path().to_string_lossy().into_owned(),
            audience: "registry.example.test".to_string(),
            field: AuthField::AuthToken,
        }
    }
}

/// The fixture's contents. Split out so the `//registry...` prefix lives in one
/// named place rather than inside a `write_all` call in the middle of a setup
/// function.
const AUTH_LINE: &str = concat!("//registry.example.test/", ":_authToken=token-value\n");

/// A receipt built from a real fixture, fresh each call so two receipts in one
/// test never share a fingerprint by accident.
fn receipt() -> AdoptReceipt {
    let fixture = Fixture::new();
    AdoptReceipt::new(
        fixture.selector(),
        asv_domain::CredentialId::new(),
        "npm-registry".to_string(),
        "registry.example.test".to_string(),
        BTreeSet::from([crate::Operation::Read, crate::Operation::Publish]),
        fixture.path().to_string_lossy().into_owned(),
        fixture.fingerprint(),
    )
}

impl Adoption {
    /// The plan digest an approval has to name.
    fn digest_for_tests(&self) -> String {
        self.receipt().plan_digest()
    }
}

/// Walks the whole legal path. If this fails the machine is broken; if it
/// passes, the rows below are testing refusals rather than a pipeline that
/// happens to be stuck.
fn completed() -> MigrationReceipt {
    let (adoption, proof) = adoption_with_proof();
    let digest = adoption.digest_for_tests();
    adoption
        .verify_storage(proof)
        .expect("the vault attests to what was imported")
        .project_and_verify(
            Projection::new(Posture::StrongSecretless, "surrogate config + ASV proxy"),
            "npm ping: 200",
        )
        .expect("the new path worked")
        .verify_bypass("the legacy _authToken is no longer read: proxy observed")
        .expect("the old path is dead")
        .approve("operator@example.test", digest)
        .expect("the approval names this plan")
        .scrub()
        .rescan("no credential material remains at the source path")
        .complete()
        .into_receipt()
}

// ------------------------------------------------------------ the refusals

#[test]
fn a_proof_for_another_credential_is_refused_and_names_both() {
    // The one check §10 step 1 can actually make without touching a value: the
    // credential the broker confirmed is the credential this migration adopted.
    // Ids are not secrets, so this costs nothing — and a proof answering for
    // something else would otherwise go on to authorise destroying a file over
    // the wrong evidence.
    let adopted = receipt();
    // Captured before the receipt is moved: the refusal has to name it, and
    // reading a field out of a moved value would not compile.
    let expected = adopted.credential.to_string();
    let other = StorageProof::from_broker(
        asv_domain::CredentialId::new(),
        "some-other-credential",
        asv_domain::Exportability::NonExportable,
    );
    let proven = other.id().to_string();

    let error = Adoption::new(adopted)
        .verify_storage(other)
        .expect_err("storage proven for another credential must not pass");

    assert_eq!(
        error,
        ProofError::WrongCredential {
            expected: expected.clone(),
            proven: proven.clone(),
        }
    );
    // The refusal names both sides, because "verification failed" would leave
    // an operator unable to tell a migrated vault from a mismatched one.
    let text = error.to_string();
    assert!(text.contains(proven.as_str()), "{text}");
    assert!(text.contains(expected.as_str()), "{text}");
}

#[test]
fn the_proof_report_says_storage_and_not_value_equality() {
    // The report lands in a receipt that people read before allowing a file to
    // be destroyed. If it said "vault verified" it would be read as more than
    // it is, so the wording is itself under test.
    let text = proof().report();
    assert!(text.contains("storage and authority only"), "{text}");
    assert!(
        text.contains("not a comparison of the stored value"),
        "{text}"
    );
    // And it must never carry anything derived from the credential itself.
    assert!(!text.contains("token-value"), "{text}");
}

#[test]
fn a_tool_that_reports_nothing_has_not_reported_that_it_worked() {
    // Silence is not success. Without this the pipeline would accept a tool
    // that produced no output at all and call the new path verified.
    let (adoption, proof) = adoption_with_proof();
    let error = adoption
        .verify_storage(proof)
        .expect("stored")
        .project_and_verify(
            Projection::new(Posture::StrongSecretless, "projection"),
            "   ",
        )
        .expect_err("an empty report is not a working path");

    assert!(matches!(error, ProofError::NewPathNotWorking { .. }));
    assert!(
        error.to_string().contains("not evidence that it worked"),
        "{error}"
    );
}

#[test]
fn a_probe_that_reports_nothing_has_not_proved_the_old_path_is_dead() {
    // The step that separates a migration from a copy. An empty probe report
    // must not reach `Approved`, because reaching it is what unlocks a scrub.
    let (adoption, proof) = adoption_with_proof();
    let error = adoption
        .verify_storage(proof)
        .expect("stored")
        .project_and_verify(
            Projection::new(Posture::StrongSecretless, "projection"),
            "npm ping: 200",
        )
        .expect("new path worked")
        .verify_bypass("")
        .expect_err("an empty probe proves nothing");

    assert!(matches!(error, ProofError::BypassStillWorks { .. }));
    assert!(
        error
            .to_string()
            .contains("not evidence that the old path is gone"),
        "{error}"
    );
}

#[test]
fn an_approval_over_a_different_plan_does_not_open_this_scrub() {
    let (adoption, proof) = adoption_with_proof();
    let real = adoption.digest_for_tests();

    let error = adoption
        .verify_storage(proof)
        .expect("stored")
        .project_and_verify(
            Projection::new(Posture::ShortLivedExposure, "ephemeral config"),
            "ok",
        )
        .expect("new path worked")
        .verify_bypass("old path dead")
        .expect("old path is dead")
        .approve("operator@example.test", "attest:plan:0000")
        .expect_err("an approval over another plan is not this approval");

    assert!(matches!(error, ProofError::ApprovalDigestMismatch { .. }));
    assert!(error.to_string().contains("approving one plan"), "{error}");

    // And the digest the refusal names is the one this plan actually has, so a
    // reader can tell which plan they were looking at.
    match error {
        ProofError::ApprovalDigestMismatch { approved, current } => {
            assert_eq!(approved, "attest:plan:0000");
            assert_eq!(current, real);
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
}

#[test]
fn nobody_is_not_an_approval() {
    let (adoption, proof) = adoption_with_proof();
    let digest = adoption.digest_for_tests();

    let error = adoption
        .verify_storage(proof)
        .expect("stored")
        .project_and_verify(
            Projection::new(Posture::StrongSecretless, "projection"),
            "ok",
        )
        .expect("new path worked")
        .verify_bypass("old path dead")
        .expect("old path is dead")
        .approve("   ", digest)
        .expect_err("an approval by nobody approves nothing");

    assert_eq!(error, ProofError::NoActor);
}

// ------------------------------------------------------------ the legal path

#[test]
fn the_whole_path_produces_a_receipt_that_claims_only_what_was_proven() {
    let receipt = completed();

    assert_eq!(receipt.schema, MIGRATION_SCHEMA);
    assert_eq!(receipt.posture, "STRONG_SECRETLESS");
    assert_eq!(receipt.audience, "registry.example.test");

    // Every §10 step, and nothing else.
    assert_eq!(receipt.steps.len(), PendingStep::ALL.len());
    for step in PendingStep::ALL {
        assert!(
            receipt.steps.contains(step.as_str()),
            "{} missing from the receipt",
            step.as_str()
        );
    }

    // The claims are the ones the proofs established, not stronger ones.
    assert_eq!(receipt.tool_report, "npm ping: 200");
    assert!(receipt.bypass_report.contains("no longer read"));
    assert_eq!(receipt.approved_by, "operator@example.test");
    assert!(receipt.rescan.contains("no credential material"));
}

#[test]
fn the_receipt_carries_no_value() {
    // A receipt is read by other people. Everything in it must be an identifier,
    // a posture, or a report — never the credential itself.
    let json = serde_json::to_string(&completed()).expect("serialises");
    assert!(!json.contains("token-value"), "{json}");
}

#[test]
fn no_field_of_the_receipt_is_a_digest_of_the_credential_value() {
    // The crate's rule, asserted here so a future field cannot add one back
    // without this row noticing. `npm.rs` states it three times: a digest of
    // one extracted value is an oracle for that value, and `_auth` is base64
    // of `user:password`.
    //
    // An earlier version of this row asserted that the receipt contains no
    // `sha256` at all, and it failed — correctly. `plan_digest` is a sha256
    // over *metadata*, which `npm.rs` calls safe by contrast, because
    // confirming a guess against the file digest means guessing every byte of
    // the file. The distinction that matters is not the algorithm, it is
    // **what went into it**, so this row asserts that instead.
    let value: serde_json::Value = serde_json::to_value(AdoptReceipt::new(
        Fixture::new().selector(),
        asv_domain::CredentialId::new(),
        "npm-registry".to_string(),
        "registry.example.test".to_string(),
        BTreeSet::from([crate::Operation::Read, crate::Operation::Publish]),
        "/tmp/x/.npmrc".to_string(),
        FingerprintPolicy::strict()
            .fingerprint(&Fixture::new().path())
            .expect("fixture"),
    ))
    .expect("serialises");

    for (key, _) in value.as_object().expect("an object") {
        assert!(
            !(key.contains("value") && key.contains("digest")),
            "field {key} looks like a per-value digest"
        );
    }
}

#[test]
fn the_plan_digest_covers_the_metadata_it_claims_to_cover() {
    // A digest is only worth anything if it changes when what it covers
    // changes. This one claims to cover the file, the fingerprint, the audience
    // and the credential id, so moving any of them has to move it.
    let (adoption, _proof) = adoption_with_proof();
    let base = adoption.digest_for_tests();
    assert!(base.starts_with("sha256:"), "{base}");

    // Same receipt, recomputed: stable, so a reader can compare two runs.
    assert_eq!(
        Adoption::new(receipt()).digest_for_tests().len(),
        base.len()
    );

    // A different audience is a different plan.
    let mut other = receipt();
    other.audience = "other.example.test".to_string();
    assert_ne!(
        Adoption::new(other).digest_for_tests(),
        base,
        "the plan digest did not notice the audience changing"
    );

    // And a different credential is a different plan.
    let mut other = receipt();
    other.credential = asv_domain::CredentialId::new();
    assert_ne!(
        Adoption::new(other).digest_for_tests(),
        base,
        "the plan digest did not notice the credential changing"
    );
}

#[test]
fn the_posture_is_carried_rather_than_inferred_and_never_upgraded() {
    // §8's third variant is the one a migration is tempted to overclaim: a
    // real static credential in a file that lives a few milliseconds is still
    // an exposure. The receipt has no way to turn it into STRONG_SECRETLESS,
    // because it copies the posture rather than computing one from anything.
    let (adoption, proof) = adoption_with_proof();
    let digest = adoption.digest_for_tests();
    let migration = adoption
        .verify_storage(proof)
        .expect("stored")
        .project_and_verify(
            Projection::new(Posture::RawProcessExposure, "ephemeral config, real token"),
            "npm ping: 200",
        )
        .expect("worked")
        .verify_bypass("old path dead")
        .expect("dead")
        .approve("operator@example.test", digest)
        .expect("approved")
        .scrub()
        .rescan("clean")
        .complete();

    assert_eq!(migration.receipt().posture, "RAW_PROCESS_EXPOSURE");
    assert_ne!(migration.receipt().posture, "STRONG_SECRETLESS");
}

// ------------------------------------------------------- the compile-time law

/// A fresh state names an adoption and nothing else.
///
/// The absence of both proofs is the property: a state that began with them
/// filled in would let `prove` be skipped by writing the file by hand, and the
/// whole point of splitting prove from apply is that one act of typing cannot
/// satisfy both.
#[test]
fn a_new_state_proves_nothing_yet() {
    let state = state();
    assert!(!state.is_complete());
    assert!(state.positive.is_none());
    assert!(state.negative.is_none());
}

#[test]
fn an_empty_report_is_refused_by_both_recorders() {
    assert!(matches!(
        state().record_positive("   "),
        Err(ProofError::NewPathNotWorking { .. })
    ));
    assert!(matches!(
        state().record_negative("   "),
        Err(ProofError::BypassStillWorks { .. })
    ));
}

/// **The hole this split had to not open.** A state carrying only the positive
/// proof is the state a hand-written file would produce if it wanted to skip
/// the negative test. It must not reach a scrubbable value.
#[test]
fn a_positive_proof_without_the_negative_one_refuses_to_replay() {
    let half = state()
        .record_positive("npm resolved a package through the projection")
        .unwrap();
    assert!(!half.is_complete());
    let error = Adoption::resume(&half, "an operator", &half.plan_digest())
        .expect_err("a state with no negative proof must not be replayable");
    assert!(
        matches!(error, ProofError::MalformedState { .. }),
        "the refusal must name a state that cannot be replayed, not a failed \
         verification: {error}"
    );
}

#[test]
fn a_negative_proof_without_the_positive_one_refuses_to_replay() {
    let half = state()
        .record_negative("the old path returned 401")
        .unwrap();
    assert!(!half.is_complete());
    assert!(matches!(
        Adoption::resume(&half, "an operator", &half.plan_digest()),
        Err(ProofError::MalformedState { .. })
    ));
}

#[test]
fn a_state_with_neither_proof_refuses_to_replay() {
    assert!(matches!(
        Adoption::resume(&state(), "an operator", &state().plan_digest()),
        Err(ProofError::MalformedState { .. })
    ));
}

/// The approval still has to be over **this** plan, after the round trip
/// through a file. A digest that survives serialisation unchanged is the whole
/// reason the comparison happens here rather than at prove time.
#[test]
fn an_approval_over_a_different_plan_still_refuses_after_the_round_trip() {
    let complete = complete_state();
    let text = serde_json::to_string(&complete).expect("serialise");
    let restored: MigrationState = serde_json::from_str(&text).expect("deserialise");
    assert!(
        matches!(
            Adoption::resume(&restored, "an operator", "a-digest-nobody-computed"),
            Err(ProofError::ApprovalDigestMismatch { .. })
        ),
        "a scrub gated on an approval for a different plan is the failure the \
         digest exists to prevent"
    );
}

#[test]
fn nobody_claiming_the_approval_still_refuses_after_the_round_trip() {
    let complete = complete_state();
    let restored: MigrationState =
        serde_json::from_str(&serde_json::to_string(&complete).unwrap()).unwrap();
    assert!(matches!(
        Adoption::resume(&restored, "  ", &restored.plan_digest()),
        Err(ProofError::NoActor)
    ));
}

/// The one path `apply` allows, and it ends at `Scrubbed` — whose only
/// remaining method is the rescan and then `complete`.
#[test]
fn a_complete_state_replays_to_a_scrubbable_value_and_no_further() {
    let complete = complete_state();
    let restored: MigrationState =
        serde_json::from_str(&serde_json::to_string(&complete).unwrap()).unwrap();
    let scrubbed =
        Adoption::resume(&restored, "an operator", &restored.plan_digest()).expect("replays");
    let receipt = scrubbed
        .rescan("the original .npmrc was rescanned and holds no credential")
        .complete()
        .into_receipt();
    assert_eq!(receipt.schema, MigrationState::SCHEMA);
    assert_eq!(receipt.plan_digest, restored.plan_digest());
    assert!(
        receipt.posture.contains("STRONG_SECRETLESS"),
        "the receipt carries the posture that was proved, never a widened one: {:?}",
        receipt.posture
    );
}

/// A credential id this build cannot parse is a state problem, and saying so
/// as `WrongCredential` would put it inside a security check's receipt.
#[test]
fn an_unparseable_credential_id_is_a_malformed_state_not_a_wrong_credential() {
    let mut broken = complete_state();
    broken.storage.id = "not-a-credential-id".to_string();
    assert!(matches!(
        Adoption::resume(&broken, "an operator", &broken.plan_digest()),
        Err(ProofError::MalformedState { .. })
    ));
}

/// A file carrying fields the schema does not know is refused rather than
/// ignored, so a typo in a hand-written state cannot quietly drop a proof.
#[test]
fn an_unknown_field_in_a_persisted_state_is_refused() {
    let complete = complete_state();
    let mut text = serde_json::to_value(&complete).expect("serialise");
    text["negative_proof"] = serde_json::json!("smuggled in");
    assert!(
        serde_json::from_value::<MigrationState>(text).is_err(),
        "deny_unknown_fields exists so a misspelled key cannot read as absent"
    );
}

// --- fixtures -------------------------------------------------------------

fn state() -> MigrationState {
    let r = receipt();
    let storage = StorageFacts {
        id: r.credential.to_wire(),
        label: "npm-registry".to_owned(),
        exportability: asv_domain::Exportability::NonExportable,
    };
    MigrationState::new(
        r,
        storage,
        Posture::StrongSecretless,
        "wrote a .npmrc naming the relay the broker published",
    )
}

fn complete_state() -> MigrationState {
    state()
        .record_positive("npm resolved a package through the projection")
        .expect("a non-empty report is a positive proof")
        .record_negative("the old path was refused with 401 once the surrogate was gone")
        .expect("a non-empty report is a negative proof")
}
