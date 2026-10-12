//! R4.B.1: the receipt for one `discover → intent → plan → authorize → execute`
//! attempt.
//!
//! # Why the receipt lives here and the driver does not
//!
//! The receipt is the only artefact that outlives the process, and everything
//! worth checking about it — that it holds no secret, that it says what was
//! promised *and* what was found, that a refusal is readable without the log —
//! is a property of the **type**. Putting it in this crate makes those rows
//! runnable without a broker, a vault or a network.
//!
//! What it deliberately does not do is decide anything. The policy verdict
//! arrives from the broker over IPC and is carried here as an opaque
//! [`AuthorizationVerdict`]; this crate has no policy engine and must not grow
//! one, because a second authority is the failure this whole project is about.
//!
//! # What a receipt has to answer
//!
//! An operator reading one is asking three questions, in this order:
//!
//! 1. *What was asked for?* — the [`ActionIntent`], in full.
//! 2. *What was promised about the world?* — the [`PlanBinding`].
//! 3. *What happened?* — the [`ExecuteOutcome`].
//!
//! All three travel together. A receipt carrying only the outcome is a log
//! line; one carrying the intent and the outcome without the binding cannot be
//! checked later, because there is nothing to check it against.

use serde::{Deserialize, Serialize};

use asv_domain::{ActionIntent, IntentOrigin, PlanBinding, PlanInvalidation};

use crate::plan::IntegrationPlan;
use crate::tool::ToolResolution;

/// `asv.integrations.execute/v1`.
///
/// A distinct schema from `asv.integrations.plan/v2` and
/// `asv.integrations.adopt/v1`. A receipt is a record that something was
/// *decided*, and a consumer handed one must not be able to mistake it for the
/// advice it came from.
pub const EXECUTE_SCHEMA: &str = "asv.integrations.execute/v1";

/// What the broker said.
///
/// **Opaque on purpose.** This crate does not evaluate policy and must not
/// start: the broker holds the engine, the policy set and the session, and a
/// second evaluator is a second authority. The verdict arrives as text and
/// travels as text, so this type cannot grow a field that implies ASV decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationVerdict {
    /// The broker permits this intent.
    Permit { decision: String },
    /// The broker refuses it, and says why in its own words.
    Deny { reason: String, reason_code: String },
}

impl AuthorizationVerdict {
    /// Whether the broker permitted it.
    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Permit { .. })
    }

    /// The reason a refusal names, or `None` for a permit.
    pub fn denial(&self) -> Option<&str> {
        match self {
            Self::Permit { .. } => None,
            Self::Deny { reason, .. } => Some(reason),
        }
    }
}

/// What the CLI actually attempted, after `decide` cleared the way.
///
/// Carries the result of one [`std::process::Command`] invocation: the exit
/// code if the process ran, the truncated output if it produced any, and the
/// error string if it never started. **The attempt is the contract**: a
/// receipt that says `Executed` without this is a receipt that claims
/// "ran" without evidence that anything ran, which is the bug R4.B.1 left
/// behind and what the v0.39.0 fix removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExecutionAttempt {
    /// The exit code of the spawned process, or `None` if it never exited
    /// (e.g. it was killed by a signal or the process table refused to wait).
    pub exit_code: Option<i32>,
    /// The process exit status as the platform reports it. Same meaning as
    /// `exit_code` on Unix: the raw `ExitStatus`. Kept alongside the `i32`
    /// because a reader that only has the JSON does not have `ExitStatus`.
    pub signal: Option<String>,
    /// `stdout`, truncated to a small budget. The point of the truncation is
    /// the receipt, not the log: a multi-megabyte stream is not what an
    /// operator reads while triaging.
    pub stdout_truncated: Option<String>,
    /// `stderr`, truncated identically.
    pub stderr_truncated: Option<String>,
    /// `Some(message)` if the process never started (fork failed, executable
    /// not found, permission denied). `None` if it ran, regardless of its
    /// exit code.
    pub spawn_error: Option<String>,
    /// The arguments passed to the executable, in order, with the executable
    /// itself as `argv[0]`. **A receipt without the argv is a receipt that
    /// cannot be replayed**, which is the same class of disagreement this
    /// whole module exists to make impossible.
    pub argv: Vec<String>,
}

impl ExecutionAttempt {
    /// Whether the process ran to completion with a zero exit code. A receipt
    /// that says `executed` and returns `true` here is the only receipt that
    /// means "the world actually saw the command".
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && self.spawn_error.is_none()
    }
}

/// What happened when the execution was checked against the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteOutcome {
    /// **R4.B.1 split "the broker said yes" from "the process ran."** Before
    /// v0.39.0, `decide` produced `Executed` on a `Permit`, and the CLI
    /// carried that forward into the receipt without invoking the binary.
    /// The split makes that failure mode unrepresentable: an outcome that has
    /// not run yet cannot carry an `ExecutionAttempt`, and one that has must.
    ///
    /// `AuthorizedForExecution` is the verdict `decide` reaches when the
    /// world still matches and the broker permits. The CLI then attempts the
    /// execution and upgrades the outcome to `Executed` or downgrades it to
    /// `NotExecuted`; the receipt carries the final form.
    AuthorizedForExecution,
    /// The process ran. Carries the attempt so a reader can see what
    /// happened, not only that `decide` cleared the way.
    Executed { execution: ExecutionAttempt },
    /// The process was authorised but never ran. The reason is the
    /// platform's own (`os error 13 (permission denied)`, `No such file or
    /// directory`) so an operator can act on it without re-running.
    NotExecuted { reason: String, reason_code: String },
    /// The broker refused.
    Unauthorized { reason: String, reason_code: String },
    /// The world moved, and this names how.
    ///
    /// **Carrying the `PlanInvalidation` rather than a reason string** is the
    /// whole reason the domain enum exists: a refusal an operator cannot act
    /// on is a refusal that gets worked around, and `planned`/`found` is the
    /// diagnosis.
    PlanInvalidated {
        /// [`PlanInvalidation::wire_name`], lifted out so a consumer can match
        /// on it without destructuring the invalidation. Owned rather than
        /// `&'static str` because a receipt is deserialised as well as
        /// written, and a borrowed wire name cannot come back in.
        reason: String,
        invalidation: PlanInvalidation,
    },
}

impl ExecuteOutcome {
    /// Whether the binary actually ran. **Renamed from the v0.38.0 meaning,
    /// which was "the broker said yes":** a receipt that wants the old
    /// meaning now needs [`Self::was_authorized`].
    ///
    /// The rename is the fix. A `Permit` verdict without an `ExecutionAttempt`
    /// cannot pass this gate, because the type no longer admits one.
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed { .. })
    }

    /// Whether the broker said yes and the world still matched. The CLI uses
    /// this to decide whether to attempt the execution; the receipt uses it
    /// to decide whether to carry an attempt at all.
    pub fn was_authorized(&self) -> bool {
        matches!(self, Self::AuthorizedForExecution | Self::Executed { .. })
    }

    /// The one-line form an operator reads.
    pub fn headline(&self) -> String {
        match self {
            Self::AuthorizedForExecution => "authorized (not yet executed)".into(),
            Self::Executed { execution } => {
                if execution.succeeded() {
                    "executed (exit 0)".into()
                } else if let Some(ref e) = execution.spawn_error {
                    format!("NOT_EXECUTED: {e}")
                } else {
                    format!("executed (exit {:?})", execution.exit_code)
                }
            }
            Self::NotExecuted { reason, .. } => format!("NOT_EXECUTED: {reason}"),
            Self::Unauthorized { reason, .. } => format!("UNAUTHORIZED: {reason}"),
            Self::PlanInvalidated { invalidation, .. } => invalidation.to_string(),
        }
    }
}

/// Everything one attempt produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExecuteReceipt {
    /// `asv.integrations.execute/v1`, set by [`ExecuteReceipt::new`].
    pub schema: String,
    pub family: String,
    /// The intent, in full, so the receipt is self-contained.
    pub intent: ActionIntent,
    /// Where the instruction came from, lifted out of the intent because it is
    /// the field a reader looks for first and a policy writes rules on.
    pub origin: IntentOrigin,
    /// What the plan promised about the world.
    pub binding: PlanBinding,
    /// The plan itself, with every binding it resolved.
    ///
    /// **Added because the receipt claimed to be re-checkable and was not.**
    /// A receipt that names a credential but not the binding that named it
    /// leaves a reader unable to ask the only question that matters — *which
    /// credential, for which audience, under which operations* — and the claim
    /// on the receipt was a claim about a document that did not contain the
    /// answer. Carrying the whole plan also means "nothing was bound" is a
    /// fact an auditor can read rather than an absence they have to infer from
    /// a field that is not there.
    ///
    /// It is the same `IntegrationPlan` the command printed and the same value
    /// `bind_to` was called with, not a summary of it: a receipt carrying a
    /// *rendering* of the plan would be re-checkable only against the renderer.
    pub plan: IntegrationPlan,
    /// The executable the plan resolved, and every directory that was searched
    /// to find it.
    pub planned_tool: ToolResolution,
    /// The executable found at execution time.
    ///
    /// Separate from `planned_tool` rather than merged into it because the
    /// pair *is* the evidence: a receipt carrying one resolution cannot show
    /// that anything changed.
    pub observed_tool: ToolResolution,
    /// What the broker said.
    pub authorization: AuthorizationVerdict,
    /// What happened.
    pub outcome: ExecuteOutcome,
}

impl ExecuteReceipt {
    /// Assembles a receipt from a checked attempt.
    ///
    /// Takes the observed resolution as an argument rather than re-resolving
    /// here, so the resolution the receipt shows is the one the check actually
    /// used. A receipt that resolved the tool a second time for its own
    /// convenience would be a receipt reporting on a moment nobody checked.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: impl Into<String>,
        intent: &ActionIntent,
        binding: &PlanBinding,
        plan: &IntegrationPlan,
        planned_tool: &ToolResolution,
        observed_tool: &ToolResolution,
        authorization: AuthorizationVerdict,
        outcome: ExecuteOutcome,
    ) -> Self {
        Self {
            schema: EXECUTE_SCHEMA.to_string(),
            family: family.into(),
            intent: intent.clone(),
            origin: intent.origin,
            binding: binding.clone(),
            plan: plan.clone(),
            planned_tool: planned_tool.clone(),
            observed_tool: observed_tool.clone(),
            authorization,
            outcome,
        }
    }

    /// The configuration digest the plan and the execution agreed on.
    pub fn config_digest(&self) -> Option<&str> {
        self.binding.config_fingerprint.as_deref()
    }

    /// Whether this attempt may proceed.
    pub fn is_executed(&self) -> bool {
        self.outcome.is_executed()
    }

    /// Whether the plan bound a credential to at least one selector.
    ///
    /// **Its own question, asked before any other.** An execution that is
    /// authorized and binds nothing is a real state — the vault was empty, or
    /// the operator asked for a machine with nothing in it — and it is *not*
    /// the same as an execution that spends a credential. A reader who has to
    /// count `Binding::Bound` arms by hand to tell them apart will eventually
    /// stop counting.
    pub fn bound_anything(&self) -> bool {
        self.bound_count() > 0
    }

    /// How many selectors the plan bound a credential to.
    pub fn bound_count(&self) -> usize {
        self.plan
            .entries
            .iter()
            .filter(|entry| matches!(entry.binding, crate::plan::Binding::Bound { .. }))
            .count()
    }

    /// How many selectors the plan could not bind.
    pub fn unbound_count(&self) -> usize {
        self.plan.entries.len().saturating_sub(self.bound_count())
    }

    /// The credential ids this execution would spend, in plan order.
    ///
    /// Ids and not labels or values: an id is a handle an operator can act on,
    /// and a value has no business being in this document.
    pub fn credentials_at_stake(&self) -> Vec<asv_domain::CredentialId> {
        self.plan
            .entries
            .iter()
            .filter_map(|entry| match &entry.binding {
                crate::plan::Binding::Bound { credential, .. } => Some(*credential),
                _ => None,
            })
            .collect()
    }

    /// The same credentials with the names the operator gave them.
    ///
    /// **Both halves, because neither is enough on its own.** A `uuid` is a
    /// handle somebody can paste into `asv credentials delete`, and it is
    /// nothing a person can recognise on a screen; `deploy-token` is instantly
    /// recognisable and cannot be acted on without the id. The prose is read by
    /// somebody deciding whether to press on, and the document is read by
    /// somebody deciding whether to act — so this returns both, and the caller
    /// prints both.
    ///
    /// Found by running the chain against a live broker: the prose was naming
    /// the credential by id alone, and the label the operator had typed into
    /// `add-credential` never appeared anywhere outside the JSON.
    pub fn credentials_named(&self) -> Vec<(String, asv_domain::CredentialId)> {
        self.plan
            .entries
            .iter()
            .filter_map(|entry| match &entry.binding {
                crate::plan::Binding::Bound {
                    credential, label, ..
                } => Some((label.clone(), *credential)),
                _ => None,
            })
            .collect()
    }
}

/// Checks an attempt and says what happened, in the order the questions matter.
///
/// **Expiry first, then the world, then the broker.** A caller reading a
/// refusal should not have to work out why a tool looked different on a
/// request that was already dead, and a broker should not be asked to authorise
/// an execution that has already been invalidated locally — the request would
/// be for something that cannot happen.
///
/// The order is the same one [`PlanBinding::check_execution`] uses, deliberately
/// rather than incidentally: this function adds the broker as a third question
/// and must not reorder the first two. A caller reading a refusal should not
/// have to work out why a tool looked different on a request that was already
/// dead.
pub fn decide(
    intent: &ActionIntent,
    intent_digest: &str,
    binding: &PlanBinding,
    observed_tool: Option<&asv_domain::ToolIdentity>,
    observed_config: Option<&str>,
    now_unix: u64,
    authorization: &AuthorizationVerdict,
) -> ExecuteOutcome {
    // `intent_digest` is a parameter rather than recomputed here for the same
    // reason `check_execution` takes one: an earlier version of this function
    // called `intent.digest()` and unwrapped the error into `""`, which would
    // have turned a failure to digest into an `IntentMismatch` between two
    // empty strings. A refusal that names nothing is worse than a crash.
    if let Err(invalidation) = binding.check_execution(
        intent_digest,
        observed_tool,
        observed_config,
        now_unix,
        intent.expires_at_unix,
    ) {
        return ExecuteOutcome::PlanInvalidated {
            reason: invalidation.wire_name().to_string(),
            invalidation,
        };
    }
    match authorization {
        AuthorizationVerdict::Permit { .. } => ExecuteOutcome::AuthorizedForExecution,
        AuthorizationVerdict::Deny {
            reason,
            reason_code,
        } => ExecuteOutcome::Unauthorized {
            reason: reason.clone(),
            reason_code: reason_code.clone(),
        },
    }
}
#[cfg(test)]
#[path = "execute/tests.rs"]
mod tests;
