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
//! reached without having held [`Adoption`], [`InVault`],
//! [`PositivelyVerified`] and [`BypassVerified`] in turn, because each is
//! produced only by the method on the previous one, and each of those methods
//! takes the evidence it records rather than a `bool`.
//!
//! What this does **not** claim: that the checks are correct, that the
//! substrate is real, or that the projection reached the destination. Those are
//! AAT-CW-014 through 018. This module makes the *ordering* a type error; it
//! does not make the evidence true, and the module says so where a reader would
//! otherwise assume it does.
//!
//! # Why step 1 is a storage proof and not a comparison
//!
//! §10's first step is "verify ASV storage". An earlier version of this module
//! took two attestations — what the import recorded and what the vault answered
//! — and compared them, because a digest of the credential was refused for the
//! reason `npm.rs` gives three times: *a digest of one extracted value is an
//! oracle for that value, and `_auth` is base64 of `user:password`.* That
//! reasoning holds, and it left the step with nothing it could actually ask for.
//!
//! So the step asks the question the vault can answer without touching a value:
//! **does the broker still hold this credential, and may this principal read
//! it?** That is the broker's `VerifyStorage` verb, and the answer is a set of
//! facts the broker produces over the socket as a peer it admitted — not a
//! string the caller supplies twice. This crate does not depend on the
//! protocol, so the proof is built from plain `asv-domain` facts and it is the
//! caller's job to have obtained them from the broker; see [`StorageProof`] for
//! what that does and does not establish, including the part of §10 it
//! deliberately does not cover.

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

/// What the broker said when asked whether it still holds the credential.
///
/// **This is a fact about storage and authority, and that is all it is.** No
/// field here is derived from the credential's value, and none can be: a digest
/// of one extracted value is an oracle for that value, and an `_auth`
/// credential is base64 of `user:password`, low-entropy enough to confirm a
/// guess. `npm.rs` says so three times; this is the fourth place it is obeyed.
///
/// # What it establishes
///
/// The broker, having admitted the caller as a control-plane peer, found a
/// credential with this id in the vault. That is the whole of §10's first step
/// as the vault can answer it, and it is not nothing: it catches a vault that
/// was never written, a credential that was deleted or rotated away, and an id
/// that was never the one adopted.
///
/// # What it does not establish
///
/// - **Not that the stored value equals the imported one.** No comparison
///   happened, for the reason above. Nothing downstream may let this receipt
///   imply otherwise.
/// - **Not the audience binding.** The vault's credential record has no
///   audience field — `CreateCredential` carries label, kind, provider, account
///   and the secret, and nothing else — so an audience question could only be
///   answered from a document the caller brought, which would make this the
///   operator attesting their own import. Putting audience in the inventory is
///   its own change with its own place in the plan.
/// - **Not that anybody checked.** A proof of the *shape* is constructible
///   outside the broker, because Rust cannot stop a caller building a struct.
///   What the product guarantees is structural and narrower: no command path
///   obtains one except by asking the broker, and with no broker there is no
///   proof, therefore no `Approved`, therefore no scrub. That property is a
///   test, not a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProof {
    id: crate::CredentialId,
    label: String,
    exportability: asv_domain::Exportability,
}

impl StorageProof {
    /// Builds the proof from what the broker answered.
    ///
    /// The arguments are `asv-domain` types rather than a protocol response
    /// because this crate does not depend on the IPC protocol, and adding that
    /// dependency so a struct could be built one function call earlier would
    /// be the wrong trade. The consequence is stated in the type's
    /// documentation and repeated by the command: **whoever calls this owes
    /// the reader the statement that the facts came from the broker.**
    pub fn from_broker(
        id: crate::CredentialId,
        label: impl Into<String>,
        exportability: asv_domain::Exportability,
    ) -> Self {
        Self {
            id,
            label: label.into(),
            exportability,
        }
    }

    /// The credential the broker confirmed it holds.
    pub fn id(&self) -> &crate::CredentialId {
        &self.id
    }

    /// The operator's label for it. Never a value.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// How the broker holds it.
    pub fn exportability(&self) -> asv_domain::Exportability {
        self.exportability
    }

    /// One line naming exactly what was proved, for the receipt.
    ///
    /// Phrased as what it is rather than what it might suggest: the receipt is
    /// read by people deciding whether a file may be destroyed, and a sentence
    /// that said "vault verified" would be read as more than this is.
    pub fn report(&self) -> String {
        format!(
            "the broker holds credential {} (label {:?}, exportability {:?}), as \
             answered over the socket; this is storage and authority only, not \
             a comparison of the stored value against the imported one",
            self.id, self.label, self.exportability,
        )
    }
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
    /// The broker confirmed a credential that is not the one this migration
    /// adopted.
    ///
    /// Its own variant because this is the one real check step 1 can make
    /// without a digest: ids are not secrets, and a receipt that answered for
    /// a different credential would otherwise carry this migration's name.
    WrongCredential {
        /// The credential the adopt receipt says was imported.
        expected: String,
        /// The credential the broker confirmed it holds.
        proven: String,
    },
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
    /// The persisted state could not be replayed.
    ///
    /// Its own variant rather than one borrowed from a proof: a state that does
    /// not parse is not a failed *verification*, and reporting it as one would
    /// put a migration's data problem inside the receipt of a security check.
    MalformedState {
        /// What was wrong with it.
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
            ProofError::WrongCredential { expected, proven } => write!(
                f,
                "the broker confirmed credential {proven}, and this migration \
                 adopted {expected}; storage was proven for something else"
            ),
            ProofError::MalformedState { detail } => write!(
                f,
                "this migration's persisted state cannot be replayed, so it has \
                 not proved what a scrub needs proved: {detail}"
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
    storage: StorageProof,
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

    /// §10 step 1: the broker confirms it still holds what was imported.
    ///
    /// One check, and it is a real one: **the credential the broker confirmed is
    /// the credential this migration adopted.** Ids are not secrets, so comparing
    /// them costs nothing, and a proof that answered for a different credential
    /// would otherwise go on to authorise destroying a file over the wrong
    /// evidence.
    ///
    /// What is deliberately absent is any comparison of the credential's value.
    /// [`StorageProof`] gives the reason and the rest of what this does not
    /// prove, and the refusal is not a gap to be filled later by a digest: a
    /// digest of one extracted value is an oracle for that value.
    pub fn verify_storage(self, proof: StorageProof) -> Result<InVault, ProofError> {
        if proof.id != self.receipt.credential {
            return Err(ProofError::WrongCredential {
                expected: self.receipt.credential.to_string(),
                proven: proof.id.to_string(),
            });
        }
        Ok(InVault {
            adoption: self,
            storage: proof,
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
    storage: StorageProof,
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
            storage: self.storage,
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
/// Splitting `prove` from `apply` puts a file between them, and a file is the
/// one thing that can reconstruct a state without running the constructor that
/// produces it. So the durable artefact holds **facts**, and none of the
/// machine derives `Deserialize`:
///
/// ```compile_fail
/// # use asv_integrations::migration::PositivelyVerified;
/// // There is no way to read a position back out of a file. A caller that
/// // could would hold `PositivelyVerified` — and therefore `BypassVerified`,
/// // `Approved` and `scrub` — without the positive proof ever having run.
/// let state: PositivelyVerified = serde_json::from_str("{}").unwrap();
/// ```
///
/// The facts do serialise: [`MigrationState`] is the thing that crosses the
/// process boundary, and [`Adoption::resume`] is the only route from it back to
/// a proof — by running the same constructors in the same order.
/// ///
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
/// # use asv_integrations::migration::InVault;
/// // Nor can a storage proof be forged into the state that unlocks the rest of
/// // the chain: `InVault`'s fields are private and only `Adoption::verify_storage`
/// // produces one.
/// let forged = InVault {
///     adoption: todo!(),
///     storage: todo!(),
/// };
/// ```
///
/// **An earlier version of this row built a `Verification`**, a struct with
/// private fields and no public constructor, and it looked like a strong
/// claim. It was replaced when step 1 became a broker-answered fact set,
/// because `StorageProof` *does* have a constructor — `from_broker` — and so
/// no compile-time claim about forging it survives. Leaving the old row in
/// place would have been the quiet failure this repository exists to prevent:
/// a `compile_fail` doctest naming a type that no longer exists fails to
/// compile for that reason alone, and would have gone on passing whether or
/// not the ordering law held. The claim that replaced it is the one that is
/// actually true, and it is about the state rather than the evidence.
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

// ---------------------------------------------------------------------------
// The durable artefact
// ---------------------------------------------------------------------------

/// What the broker said it holds, in the shape a file can carry.
///
/// A copy rather than `StorageProof` itself: `StorageProof` deliberately has no
/// `Deserialize`, and giving it one would let a caller build a verified storage
/// fact out of a file. The value of the ordering law is that it cannot be
/// reconstructed around the type system, so this type holds **strings**, and
/// [`Adoption::resume`] is the only thing that turns them back into proofs —
/// by running the same constructors, in the same order, with the same checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFacts {
    /// The credential's wire id, as the broker minted it.
    pub id: String,
    /// The operator's label for it. Never a value.
    pub label: String,
    /// How the broker holds it.
    pub exportability: asv_domain::Exportability,
}

/// The migration state a `prove` run writes and an `apply` run reads.
///
/// **It can be incomplete, and that is fine.** What it must not be is a way to
/// *skip* a step: [`Adoption::resume`] refuses at the first proof that is
/// absent, because each state in this module can only be built from the one
/// before it. Persisting facts is safe. Persisting *positions* would not be,
/// which is why no state-machine type here derives `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationState {
    /// `asv.integrations.migration/v1`.
    pub schema: String,
    /// The adoption this migration continues.
    pub receipt: crate::AdoptReceipt,
    /// What the broker answered about storage.
    pub storage: StorageFacts,
    /// How strong the materialised path is.
    pub posture: Posture,
    /// A line naming what was projected, for the receipt.
    pub projection_detail: String,
    /// The positive proof: what the tool reported when it was exercised
    /// through the new path. `None` until it has actually reported something.
    pub positive: Option<String>,
    /// The negative proof: what the probe reported when it confirmed the old
    /// path is dead. `None` until it has actually reported something.
    pub negative: Option<String>,
}

impl MigrationState {
    /// `asv.integrations.migration/v1`.
    pub const SCHEMA: &'static str = "asv.integrations.migration/v1";

    /// The state a migration starts in: adopted, and nothing proved yet.
    ///
    /// No positive or negative proof, on purpose. A state that started with
    /// proofs already in it would let `prove` be skipped by writing the file by
    /// hand, and the point of splitting `prove` from `apply` is that the two
    /// cannot both be satisfied by one act of typing.
    pub fn new(
        receipt: crate::AdoptReceipt,
        storage: StorageFacts,
        posture: Posture,
        projection_detail: impl Into<String>,
    ) -> Self {
        Self {
            schema: Self::SCHEMA.to_owned(),
            receipt,
            storage,
            posture,
            projection_detail: projection_detail.into(),
            positive: None,
            negative: None,
        }
    }

    /// Records the positive proof, refusing an empty one.
    pub fn record_positive(self, report: impl Into<String>) -> Result<Self, ProofError> {
        let report = report.into();
        if report.trim().is_empty() {
            return Err(ProofError::NewPathNotWorking {
                detail: "the tool reported nothing, which is not evidence that \
                         it worked"
                    .to_string(),
            });
        }
        Ok(Self {
            positive: Some(report),
            ..self
        })
    }

    /// Records the negative proof, refusing an empty one.
    pub fn record_negative(self, report: impl Into<String>) -> Result<Self, ProofError> {
        let report = report.into();
        if report.trim().is_empty() {
            return Err(ProofError::BypassStillWorks {
                detail: "the probe reported nothing, which is not evidence \
                         that the old path is gone"
                    .to_string(),
            });
        }
        Ok(Self {
            negative: Some(report),
            ..self
        })
    }

    /// Whether both proofs are present. **Necessary, not sufficient**: a
    /// complete state still has to replay through every constructor.
    pub fn is_complete(&self) -> bool {
        self.positive.is_some() && self.negative.is_some()
    }

    /// The plan digest an approval has to name.
    pub fn plan_digest(&self) -> String {
        self.receipt.plan_digest()
    }
}

impl Adoption {
    /// Replays a persisted state through the same gates, and returns the value
    /// whose only remaining method is `scrub`.
    ///
    /// This is the whole of `apply`, and it is one function rather than a handful
    /// of commands precisely so that no path reaches `Approved` without going
    /// through all four constructors. Every refusal below is the same refusal
    /// the live chain makes — an absent proof fails here for the same reason
    /// `project_and_verify` refuses an empty report — so a hand-written state
    /// file cannot buy a weaker migration than a run one.
    ///
    /// ## What the caller still owes
    ///
    /// `Scrubbed::rescan` takes what the rescan found, as a string, because the
    /// rescan happens *after* this returns and this function has no file to look
    /// at. That is the one link in the chain still an assertion rather than a
    /// measurement, and it is named here rather than left for a reader to assume
    /// otherwise.
    pub fn resume(
        state: &MigrationState,
        actor: &str,
        approved_plan_digest: &str,
    ) -> Result<Scrubbed, ProofError> {
        let id = crate::CredentialId::from_wire(&state.storage.id).map_err(|e| {
            ProofError::MalformedState {
                detail: format!("the persisted credential id is not one this build accepts: {e}"),
            }
        })?;

        let adoption = Adoption::new(state.receipt.clone());
        let in_vault = adoption.verify_storage(StorageProof::from_broker(
            id,
            state.storage.label.clone(),
            state.storage.exportability,
        ))?;

        let positive = state
            .positive
            .as_deref()
            .ok_or_else(|| ProofError::MalformedState {
                detail: "this state carries no positive proof, so the new path was never \
                         exercised; run `asv integrations migrate npm prove` first"
                    .to_string(),
            })?;
        let verified = in_vault.project_and_verify(
            Projection::new(state.posture, state.projection_detail.clone()),
            positive,
        )?;

        let negative = state
            .negative
            .as_deref()
            .ok_or_else(|| ProofError::MalformedState {
                detail: "this state carries no negative proof, so nothing established that \
                         the old path stopped working; run the prove step first"
                    .to_string(),
            })?;
        let bypassed = verified.verify_bypass(negative)?;

        let approved = bypassed.approve(actor, approved_plan_digest)?;
        Ok(approved.scrub())
    }
}
