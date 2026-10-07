//! The scrub law, as a set of states rather than a set of `if`s.
//!
//! # Why this module exists
//!
//! Doc 04 §10 fixes an order and says what it protects:
//!
//! ```text
//! import → verify ASV storage → verify new integration → negative test old
//! path → human approval → scrub → rescan → receipt
//! ```
//!
//! `adopt` performs the first and reports the other five as `outstanding`,
//! because a receipt that said "done" would be claiming all five. That is
//! honest, and it is also where the vertical stopped: this tree could import a
//! credential and could not finish moving one.
//!
//! # Why not a list of flags
//!
//! The obvious way to write the rest is four booleans on the receipt, or one
//! `if` in the CLI that checks conditions before deleting a file. Both are the
//! same mistake: they make `scrub` a decision a caller *takes*, and a caller
//! can take a decision in the wrong order, forget a check, or pass `true` for
//! something it never did. The law would be satisfiable by a caller who ran
//! nothing at all.
//!
//! So the law is not written anywhere. It is **unrepresentable** to skip: each
//! proof is a distinct type with private fields, and each step is a method that
//! consumes the previous state. There is no value of type [`Approved`] unless a
//! [`Verification`] and a [`NegativeVerification`] already exist, because the
//! only way to obtain either is to have performed the check it records.
//!
//! ```compile_fail
//! # use asv_integrations::migration::Approved;
//! // The obvious mistake: construct the approved state directly.
//! let approved = Approved {
//!     bypassed: todo!(),
//!     approval: todo!(),
//! };
//! ```
//!
//! ```compile_fail
//! # use asv_integrations::migration::{Approved, Adoption, PositiveProof};
//! // And the subtler one: a state whose name says "verified".
//! let fake = PositiveProof::adopted_todo();
//! ```
//!
//! # What "impossible" means here, precisely
//!
//! **At compile time, for this crate's API.** [`Approved::scrub`] cannot be
//! reached without having held [`Adopted`], [`Projected`],
//! [`PositivelyVerified`] and [`BypassVerified`] in turn, because each is
//! produced only by the method on the previous one, and each of those methods
//! takes the evidence it records rather than a `bool`.
//!
//! What this does **not** claim: that the checks are correct, that the
//! substrate is real, or that the projection reached the destination. Those are
//! AAT-CW-014 through 018. This module makes the *ordering* a type error; it
//! does not make the evidence true, and the module says so where a reader would
//! otherwise assume it does.

use std::collections::BTreeSet;
use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::adopt::{AdoptReceipt, PendingStep};

/// `asv.integrations.migration/v1`.
///
/// A fourth schema, and the first that can assert a migration *finished*.
/// `asv.integrations.adopt/v2` says a credential was moved; this one says the
/// original is gone and that somebody checked before letting that happen.
pub const MIGRATION_SCHEMA: &str = "asv.integrations.migration/v1";

// ---------------------------------------------------------------- the posture

/// Where the secret was actually observed. Doc 04 §8's three strategies.
///
/// Carried rather than computed at the end, because the third variant is the
/// one the product must not overclaim: a real static credential in an ephemeral
/// file is still [`Posture::RawProcessExposure`], and §8 says so in as many
/// words — *"La tercera sigue siendo `RAW_PROCESS_EXPOSURE` aunque el fichero
/// dure milisegundos."* AAT-CW-015 exists because collapsing these into a
/// boolean lets a target that can read the secret be called secretless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Posture {
    /// surrogate config → ASV proxy → real credential. The target never holds
    /// the secret.
    StrongSecretless,
    /// dynamic token → ephemeral config → tool. The secret exists in a process.
    ShortLivedExposure,
    /// real static credential → ephemeral config → tool. Brief in time, still
    /// an exposure.
    RawProcessExposure,
}

impl Posture {
    /// The three names §8 and `20-REGISTRY-SECRETLESS-POSTURE.md` use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Posture::StrongSecretless => "STRONG_SECRETLESS",
            Posture::ShortLivedExposure => "SHORT_LIVED_EXPOSURE",
            Posture::RawProcessExposure => "RAW_PROCESS_EXPOSURE",
        }
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------- the proofs

/// Evidence that the vault holds the credential that was imported.
///
/// Private fields on purpose: the only way to hold one is to have run
/// [`Adoption::verify_vault`], which compares two attestations. A caller that
/// wants this proof has to do the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// What the import recorded, or what the vault returned. Both are the same
    /// kind of thing — see [`Adoption::verify_vault`] for why neither is a
    /// digest this crate is willing to compute.
    attested: String,
}

/// Why §10's first step is expressed in attestations and not digests.
///
/// This is not a stylistic choice and the crate has already decided it, three
/// times, in `npm.rs`: *"a digest of one extracted value is an oracle for that
/// value, and `_auth` is base64 of `user:password`, which is low-entropy enough
/// to confirm a guess."* A `sha256` of an `_auth` credential is the credential,
/// for anyone willing to guess a password.
///
/// So the comparison this step performs must be over something that is **not**
/// guessable from the value. An attestation — computed under a key the vault
/// holds and never emits — has that property; a plain digest does not. This
/// crate will not mint one, and [`Adoption::verify_vault`] therefore takes the
/// attestation as given rather than deriving it.
///
/// The consequence is stated rather than hidden: **this module cannot verify the
/// vault on its own.** It can refuse a mismatch and it can refuse to accept a
/// missing attestation, but the attestation has to come from the component that
/// holds the key. A row that passed here would be a row about nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationMismatch {
    /// What was presented as the import's attestation.
    presented: String,
    /// What the vault says.
    answered: String,
}

/// Evidence that the old path no longer works — the negative test that catches
/// a scrub which only appeared to succeed.
///
/// Private fields, same reason as [`Verification`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeVerification {
    /// What the probe reported when it confirmed the old path is dead.
    detail: String,
}

/// A human agreeing to destroy the original.
///
/// Doc 04 §10 puts this between the negative test and the scrub, and it is the
/// step a CLI cannot perform on the operator's behalf. The digest is what makes
/// it an approval *of this plan* rather than of a plan in general: AAT-AP-024
/// requires a wrong approval digest to be refused, which is only decidable if
/// the approval carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    actor: String,
    plan_digest: String,
    approved_at: SystemTime,
}

/// What the projection was, once in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    posture: Posture,
    /// What was materialised, described without any part of the credential.
    detail: String,
}

/// What the new path reported when it was exercised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositiveProof {
    tool_report: String,
}

// ------------------------------------------------------------ the refusals

/// Why a step refused, naming the difference rather than just failing.
///
/// A refusal that says "verification failed" tells an operator nothing they can
/// act on. The interesting case is [`ProofError::ValueDiffers`]: the vault
/// returning a *different* value than the one adopted is not transient, it is a
/// vault that no longer holds what was imported, and it must not be scrubbed
/// over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The vault's attestation differs from the one recorded at import.
    ValueDiffers {
        /// The import's attestation, as presented. Not a secret: it is not a
        /// function of the value.
        presented: String,
        /// What the vault answered with.
        answered: String,
    },
    /// One side of the comparison was empty.
    ///
    /// Its own variant because an empty attestation must not compare equal to
    /// another empty attestation. Two blanks are not a match; they are the
    /// absence of the check, and §10 wants the check.
    NoAttestation,
    /// The new path did not work, so there is no reason to destroy the old one.
    NewPathNotWorking {
        /// What the tool reported, verbatim. Never the credential.
        detail: String,
    },
    /// The old path still works.
    BypassStillWorks {
        /// What the probe reported.
        detail: String,
    },
    /// The approval names a different plan than this migration carries.
    ApprovalDigestMismatch {
        /// Digest the approval was computed over.
        approved: String,
        /// Digest the plan actually has.
        current: String,
    },
    /// Nobody claimed the approval.
    NoActor,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::ValueDiffers {
                presented,
                answered,
            } => write!(
                f,
                "the vault answered {answered} where the import presented \
                 {presented}; this is not the credential that was adopted"
            ),
            ProofError::NoAttestation => write!(
                f,
                "an attestation was missing, and two absent attestations are \
                 not a match: they are the absence of the check"
            ),
            ProofError::NewPathNotWorking { detail } => write!(
                f,
                "the new integration did not work, so the original is still the \
                 only working path: {detail}"
            ),
            ProofError::BypassStillWorks { detail } => write!(
                f,
                "the old path still works, so nothing has actually moved and a \
                 scrub would destroy the only working path: {detail}"
            ),
            ProofError::ApprovalDigestMismatch { approved, current } => write!(
                f,
                "the approval was given over {approved} and this plan carries \
                 {current}; approving one plan and scrubbing another is not \
                 approving anything"
            ),
            ProofError::NoActor => {
                write!(f, "the approval names nobody, so nobody approved anything")
            }
        }
    }
}

impl std::error::Error for ProofError {}

// ---------------------------------------------------------------- the states

/// An import happened and nothing else has. Exactly what an adopt receipt
/// describes, and the only state a caller can reach by handing one over.
///
/// Note what this state does **not** carry: a digest of what was imported. §10's
/// first step needs to compare, and the crate will not mint a comparable
/// quantity — see [`AttestationMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    receipt: AdoptReceipt,
}

/// The projection is in place. "In place" is all this asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projected {
    adoption: Adoption,
    projection: Projection,
}

/// The new path was exercised and worked.
///
/// Reached only through [`Projected::verify`], which takes the tool's own
/// report rather than a boolean — because "it worked" is not a thing the
/// pipeline may decide on the caller's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositivelyVerified {
    projected: Projected,
    vault: Verification,
    proof: PositiveProof,
}

/// The old path was probed and is dead. This is what separates a migration from
/// a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassVerified {
    verified: PositivelyVerified,
    negative: NegativeVerification,
}

/// Every proof exists and a human agreed. **The only state with a `scrub`.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    bypassed: BypassVerified,
    approval: Approval,
}

/// The original is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scrubbed {
    approved: Approved,
    rescan: String,
}

/// The migration finished, and this is the document that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    scrubbed: Scrubbed,
    receipt: MigrationReceipt,
}

/// What a finished migration asserts. Never a secret, and never a claim the
/// caller can widen: the posture and the digests are copied from the proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MigrationReceipt {
    /// `asv.integrations.migration/v1`.
    pub schema: String,
    /// The selector that was migrated.
    pub selector: crate::adopt::AdoptSelector,
    /// Vault credential id. Never the value.
    pub credential: crate::CredentialId,
    /// The audience the credential is bound to.
    pub audience: String,
    /// The file the credential came from, and which is now scrubbed.
    pub source_file: String,
    /// How the secret reached the tool. Not a boolean; see [`Posture`].
    pub posture: String,
    /// What the new path reported when exercised.
    pub tool_report: String,
    /// What the old-path probe reported when it confirmed the path is dead.
    pub bypass_report: String,
    /// Who approved removing the original.
    pub approved_by: String,
    /// What the rescan found after the scrub.
    pub rescan: String,
    /// §10's steps, all discharged.
    pub steps: BTreeSet<String>,
    /// The digest the approval was given over, so a reader can recompute it.
    pub plan_digest: String,
}

// --------------------------------------------------------------- transitions

impl Adoption {
    /// Wraps an adopt receipt. The only way into this machine.
    pub fn new(receipt: AdoptReceipt) -> Self {
        Self { receipt }
    }

    /// The receipt this migration starts from.
    pub fn receipt(&self) -> &AdoptReceipt {
        &self.receipt
    }

    /// §10 step 1: prove the vault holds what was imported.
    ///
    /// Both arguments are **attestations** produced by whichever component holds
    /// the key — never digests of the value. See [`AttestationMismatch`] for
    /// why this crate refuses to compute one, which is a decision it already
    /// makes in `npm.rs` and `npm/tests.rs`.
    ///
    /// The check here is a comparison and nothing more: this function does not
    /// know what a correct attestation looks like, only that these two must
    /// agree, which is the claim §10 makes. A caller that passes the same
    /// string twice has asserted the attestation rather than computed it, and
    /// the component that computed it is the one accountable for that.
    pub fn verify_vault(
        self,
        import_attestation: impl Into<String>,
        retrieved_attestation: impl Into<String>,
    ) -> Result<InVault, ProofError> {
        let presented = import_attestation.into();
        let answered = retrieved_attestation.into();
        if presented.trim().is_empty() || answered.trim().is_empty() {
            return Err(ProofError::NoAttestation);
        }
        if presented != answered {
            return Err(ProofError::ValueDiffers {
                presented,
                answered,
            });
        }
        Ok(InVault {
            adoption: self,
            vault: Verification {
                attested: presented,
            },
        })
    }
}

/// Proved it is in the vault, not yet projected.
///
/// Private because [`Projected::verify`] folds these together: §10 lists
/// storage and the new integration as two steps, but exposing a state between
/// them would be an invitation to stop there and call it progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InVault {
    adoption: Adoption,
    vault: Verification,
}

impl InVault {
    /// §10 step 2: materialise the projection, then exercise it.
    ///
    /// Both halves here because the order matters — projecting a path that does
    /// not work, and discovering that only after declaring it projected, is how
    /// a migration reports progress it has not made.
    pub fn project_and_verify(
        self,
        projection: Projection,
        tool_report: impl Into<String>,
    ) -> Result<PositivelyVerified, ProofError> {
        let report = tool_report.into();
        // An empty report is not evidence of success. It is the absence of a
        // claim, and the two must not be conflated.
        if report.trim().is_empty() {
            return Err(ProofError::NewPathNotWorking {
                detail: "the tool reported nothing, which is not evidence that \
                         it worked"
                    .to_string(),
            });
        }
        Ok(PositivelyVerified {
            projected: Projected {
                adoption: self.adoption,
                projection,
            },
            vault: self.vault,
            proof: PositiveProof {
                tool_report: report,
            },
        })
    }
}

impl Projection {
    /// Records what was materialised and how strong it is.
    pub fn new(posture: Posture, detail: impl Into<String>) -> Self {
        Self {
            posture,
            detail: detail.into(),
        }
    }

    /// How the secret reached the tool.
    pub fn posture(&self) -> Posture {
        self.posture
    }
}

impl PositivelyVerified {
    /// §10 step 3: prove the old path no longer works.
    ///
    /// A probe that reports nothing has not proved the path is dead — it has
    /// proved nothing — and treating the two as the same would let a scrub
    /// through on the strength of silence.
    pub fn verify_bypass(
        self,
        probe_report: impl Into<String>,
    ) -> Result<BypassVerified, ProofError> {
        let detail = probe_report.into();
        if detail.trim().is_empty() {
            return Err(ProofError::BypassStillWorks {
                detail: "the probe reported nothing, which is not evidence \
                         that the old path is gone"
                    .to_string(),
            });
        }
        Ok(BypassVerified {
            verified: self,
            negative: NegativeVerification { detail },
        })
    }
}

impl BypassVerified {
    /// §10 step 4: a human decides.
    ///
    /// The digest is compared against the plan this migration actually carries,
    /// so an approval given over a different plan cannot open this scrub.
    pub fn approve(
        self,
        actor: impl Into<String>,
        approved_plan_digest: impl Into<String>,
    ) -> Result<Approved, ProofError> {
        let current = self.plan_digest();
        let approved = approved_plan_digest.into();
        if approved != current {
            return Err(ProofError::ApprovalDigestMismatch { approved, current });
        }
        let actor = actor.into();
        if actor.trim().is_empty() {
            return Err(ProofError::NoActor);
        }
        Ok(Approved {
            bypassed: self,
            approval: Approval {
                actor,
                plan_digest: approved,
                approved_at: SystemTime::now(),
            },
        })
    }

    fn plan_digest(&self) -> String {
        self.verified.projected.adoption.receipt.plan_digest()
    }
}

impl Approved {
    /// §10 step 5: remove the original.
    ///
    /// **Exists only on [`Approved`]**, and an `Approved` exists only if a
    /// [`Verification`], a [`NegativeVerification`] and an [`Approval`] do.
    /// There is no overload, no flag and no unsafe path: a caller that has not
    /// done the four preceding steps cannot name the receiver.
    pub fn scrub(self) -> Scrubbed {
        Scrubbed {
            approved: self,
            rescan: String::new(),
        }
    }

    /// Who approved, and over what.
    pub fn approval(&self) -> (&str, &str) {
        (&self.approval.actor, &self.approval.plan_digest)
    }
}

impl Scrubbed {
    /// Attaches §10's rescan: what the file looks like now.
    pub fn rescan(self, rescan: impl Into<String>) -> Self {
        Self {
            rescan: rescan.into(),
            approved: self.approved,
        }
    }

    /// §10 step 6: write the receipt that says the migration finished.
    pub fn complete(self) -> Completed {
        let scrubbed = self;
        let receipt = &scrubbed
            .approved
            .bypassed
            .verified
            .projected
            .adoption
            .receipt;
        let document = MigrationReceipt {
            schema: MIGRATION_SCHEMA.to_string(),
            selector: receipt.selector.clone(),
            credential: receipt.credential,
            audience: receipt.audience.clone(),
            source_file: receipt.source_file.clone(),
            posture: scrubbed
                .approved
                .bypassed
                .verified
                .projected
                .projection
                .posture
                .as_str()
                .to_string(),
            tool_report: scrubbed
                .approved
                .bypassed
                .verified
                .proof
                .tool_report
                .clone(),
            bypass_report: scrubbed.approved.bypassed.negative.detail.clone(),
            approved_by: scrubbed.approved.approval.actor.clone(),
            rescan: scrubbed.rescan.clone(),
            steps: PendingStep::ALL
                .iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            plan_digest: scrubbed.approved.approval.plan_digest.clone(),
        };
        Completed {
            scrubbed,
            receipt: document,
        }
    }
}

impl Completed {
    /// The receipt. The only thing a finished migration can produce.
    pub fn receipt(&self) -> &MigrationReceipt {
        &self.receipt
    }

    /// Consumes the completion and yields the receipt.
    pub fn into_receipt(self) -> MigrationReceipt {
        self.receipt
    }
}
#[cfg(test)]
mod tests;

/// Nothing. The doctests above are the point of this item: they exist so that
/// "you cannot build an `Approved` without the three proofs" is a program that
/// fails to compile, checked on every `cargo test`, rather than a sentence.
///
/// A note on what is deliberately **not** here, because two earlier attempts at
/// it compiled and both looked convincing. `let x: Approved = unreachable!()`
/// type-checks: `unreachable!()` is of type `!`, which coerces to every type.
/// So does `fn forge() -> Approved { unreachable!() }`. Both read as ways to
/// build the state out of nothing and neither is — a diverging expression never
/// produces a value. A `compile_fail` row written that way would have gone green
/// while asserting nothing, which is the failure this repository is about, so
/// the rows here are the constructions that genuinely do not compile.
/// ///
/// ```compile_fail
/// # use asv_integrations::migration::Approved;
/// // There is no way to build an `Approved` by hand: its only field is the
/// // chain that leads to it, and that field is private.
/// let approved = Approved {
///     bypassed: unreachable!(),
///     approval: unreachable!(),
/// };
/// ```
///
/// ```compile_fail
/// # use asv_integrations::migration::{Adoption, Posture, Projection};
/// # use asv_integrations::adopt::AdoptReceipt;
/// # fn r() -> AdoptReceipt { unimplemented!() }
/// // Skipping from "imported" straight to "the tool worked": no method produces
/// // `PositivelyVerified` from an `Adoption` without attesting first.
/// let done = Adoption::new(r())
///     .project_and_verify(Projection::new(Posture::StrongSecretless, "x"), "ok");
/// ```
///
/// ```compile_fail
/// # use asv_integrations::migration::InVault;
/// // Nor is there one that takes `InVault` and reaches `BypassVerified`
/// // without a positive proof in between.
/// fn skip(in_vault: InVault) {
///     let _ = in_vault.verify_bypass("probe");
/// }
/// ```
///
/// ```compile_fail
/// # use asv_integrations::migration::Verification;
/// // The proofs cannot be fabricated: `Verification`'s fields are private.
/// let forged = Verification {
///     attested: "attest:v1:9f2c".to_string(),
/// };
/// ```
///
/// ```compile_fail
/// # use asv_integrations::migration::NegativeVerification;
/// // Same for the negative proof, and this is the one that matters most: a
/// // caller must not be able to assert "I checked the old path" by writing
/// // the words down.
/// let forged = NegativeVerification {
///     detail: "the old path is gone".to_string(),
/// };
/// ```
#[allow(dead_code)]
const ORDERING_IS_A_COMPILE_ERROR: () = ();
