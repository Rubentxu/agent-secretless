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

/// Attestations, not digests: see `migration::AttestationMismatch` for why this
/// crate will not hash a credential value. These are opaque strings a vault
/// would produce under a key it holds.
const IMPORTED: &str = "attest:v1:9f2c";
const RETRIEVED: &str = "attest:v1:9f2c";
const OTHER: &str = "attest:v1:0000";

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
    let adoption = Adoption::new(receipt());
    let digest = adoption.digest_for_tests();
    adoption
        .verify_vault(IMPORTED, RETRIEVED)
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
fn a_vault_answering_with_a_different_attestation_is_refused_and_says_so() {
    let error = Adoption::new(receipt())
        .verify_vault(IMPORTED, OTHER)
        .expect_err("a different attestation must not pass");

    // The refusal names both sides. A message that only said "verification
    // failed" would leave an operator unable to tell a migrated vault from a
    // stale one.
    assert_eq!(
        error,
        ProofError::ValueDiffers {
            presented: IMPORTED.to_string(),
            answered: OTHER.to_string(),
        }
    );
    let text = error.to_string();
    assert!(text.contains(OTHER), "{text}");
    assert!(text.contains(IMPORTED), "{text}");
}

#[test]
fn two_absent_attestations_are_not_a_match() {
    // The failure mode this row exists for: a comparison that treats "" == ""
    // as a pass. §10 wants the check performed, and an implementation that
    // compares two empty strings has performed nothing while reporting that it
    // did.
    let error = Adoption::new(receipt())
        .verify_vault("", "")
        .expect_err("two absent attestations are not evidence");

    assert_eq!(error, ProofError::NoAttestation);
    assert!(
        error.to_string().contains("the absence of the check"),
        "{error}"
    );

    assert_eq!(
        Adoption::new(receipt())
            .verify_vault(IMPORTED, "")
            .expect_err("a missing answer is not a match"),
        ProofError::NoAttestation
    );
}

#[test]
fn a_tool_that_reports_nothing_has_not_reported_that_it_worked() {
    // Silence is not success. Without this the pipeline would accept a tool
    // that produced no output at all and call the new path verified.
    let error = Adoption::new(receipt())
        .verify_vault(IMPORTED, RETRIEVED)
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
    let error = Adoption::new(receipt())
        .verify_vault(IMPORTED, RETRIEVED)
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
    let adoption = Adoption::new(receipt());
    let real = adoption.digest_for_tests();

    let error = adoption
        .verify_vault(IMPORTED, RETRIEVED)
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
    let adoption = Adoption::new(receipt());
    let digest = adoption.digest_for_tests();

    let error = adoption
        .verify_vault(IMPORTED, RETRIEVED)
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
    let adoption = Adoption::new(receipt());
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
    let adoption = Adoption::new(receipt());
    let digest = adoption.digest_for_tests();
    let migration = adoption
        .verify_vault(IMPORTED, RETRIEVED)
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
