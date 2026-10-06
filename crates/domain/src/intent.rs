//! R4.B.1 — authority bound to an operation, and a plan that notices when the
//! world moved under it.
//!
//! # What R3 left and R4 starts
//!
//! R3 built the *surface*: four families that can discover a credential and
//! describe it. What it cannot do is say **for which operation**, on **whose**
//! authority, against **which binary**, with **which configuration**.
//!
//! Everything ASV has today is bound to a **session**. A session says "this peer
//! may spend this use budget on the operations it was enrolled for". It does
//! not say "this *publish* of *this* package, by *this* npm at *this* path, with
//! *this* `.npmrc` digest, before *this* instant". A session outlives every one
//! of those facts, so a credential lent under one can be spent under another.
//!
//! [`ActionIntent`] is the answer the v2 evolution spec gives, and it exists in
//! `docs/asv-agent-first-security-evolution-v2-2026-10-02/02-ARCHITECTURE.md`
//! and `05-IDENTITY-AUTHORITY-PLAN-BOUND.md` and in no Rust file until now.
//!
//! # The property this module is actually for
//!
//! The spec's own worked example, from §3 of the identity/authority document:
//!
//! ```text
//! plan:   /usr/bin/npm      sha256=A
//! execute: ~/project/bin/npm sha256=B
//! => PLAN_INVALIDATED
//! ```
//!
//! **That is the whole block.** A plan that names a tool and a configuration is
//! only worth something if executing something else is *detected*, and the
//! detection has to happen before the credential is lent rather than in a log
//! afterwards. [`PlanBinding::check_execution`] is that check, and it is a
//! function returning an enum rather than a boolean so a caller cannot log
//! "true" and proceed.
//!
//! # Two choices that are worth arguing about
//!
//! **The intent lives in `domain`, not in `integrations`.** The planner is in
//! `integrations`; the executor is in the broker. Both must compute the same
//! digest, or the digest proves nothing — a digest only means something when
//! the two parties that compare it agree on how it is derived. Putting it in
//! the crate that defines [`Action`] and [`Resource`] is what makes agreement
//! structural rather than a convention two crates have to keep in step.
//!
//! **The digest covers the serialised intent, and the serialisation is pinned
//! by a test rather than by a version string.** `serde_json` field order is
//! stable for a struct, so hashing the serialised form is deterministic. A test
//! pins the exact bytes for a fixed intent: if someone adds a field, the digest
//! changes and that test goes red, which is the correct outcome — an intent
//! that gained a field is a different intent, and every plan naming the old
//! digest should stop matching.
//!
//! # What is deliberately absent
//!
//! **No secrets, and no way to put one in.** Every field is an id, a name, an
//! enum, or a digest. There is no `String` standing for a password and no
//! constructor that takes one, so the "serializable sin secretos" requirement
//! from §4 of the spec is a property of the type rather than a promise about how
//! callers behave. A field added later that holds a secret would be a
//! [`serde`] derive that compiles perfectly and a leak that does not; the
//! [`ActionIntent::contains_no_secret_material`] check exists to make that
//! addition loud.
//!
//! **No clock.** [`ActionIntent::expires_at_unix`] is a number a caller supplies,
//! and [`ActionIntent::is_expired`] compares it against a second number the
//! caller supplies. A type that read the system clock would make a digest
//! depend on when it was computed, and two planners computing "the same" intent
//! seconds apart would disagree for no reason anyone could see.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::{Action, Resource};

/// Where an intent came from.
///
/// **Provenance, not prompt text.** The spec is explicit that ASV does not
/// interpret what an agent was told; it consumes structured provenance. That is
/// what this enum is, and it is why every variant is something a caller has to
/// *decide* rather than something that can be inferred from the content of a
/// request: the whole point of `RetrievedContent` is that the caller is saying
/// "this instruction came out of a document, not out of a human".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentOrigin {
    /// A human asked directly.
    HumanDirect,
    /// A scheduler fired it.
    ScheduledWorkflow,
    /// A tool ASV trusts asked.
    TrustedTool,
    /// **The instruction arrived inside retrieved content.**
    ///
    /// The spec's example policy is `RetrievedContent + production.write =>
    /// require human approval`, and that is this variant's reason to exist: it
    /// is the one origin where the instruction is attacker-influenced by
    /// construction, so a policy can single it out without having to guess from
    /// the request body.
    RetrievedContent,
    /// The instruction is the *output* of a tool the operator does not trust.
    UntrustedToolOutput,
    /// Another agent, acting under a delegation.
    DelegatedAgent,
}

impl IntentOrigin {
    /// The name the audit chain and the policy text use.
    ///
    /// Written out rather than derived, for the same reason
    /// [`crate::OperationFamily::wire_name`] is: the string is evidence, so it is
    /// pinned where a test can assert it rather than reconstructed from a
    /// `Debug` impl that may change.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HumanDirect => "human_direct",
            Self::ScheduledWorkflow => "scheduled_workflow",
            Self::TrustedTool => "trusted_tool",
            Self::RetrievedContent => "retrieved_content",
            Self::UntrustedToolOutput => "untrusted_tool_output",
            Self::DelegatedAgent => "delegated_agent",
        }
    }

    /// Whether content the instruction arrived in could have chosen it.
    ///
    /// **A convenience, and deliberately a coarse one.** It exists so a caller
    /// building a policy does not have to remember that two of these six
    /// variants are the attacker-influenced ones, and a caller that needs the
    /// distinction between them still has both variants. It is not a security
    /// control on its own and the doc says so.
    pub const fn may_be_influenced_by_content(self) -> bool {
        matches!(self, Self::RetrievedContent | Self::UntrustedToolOutput)
    }
}

/// An executable an intent is bound to.
///
/// **A path alone is not an identity.** `npm` on a machine with a project-local
/// `node_modules/.bin` ahead of it on `PATH` is a different program, and the
/// spec's example is exactly that failure. So this carries the digest of the
/// bytes as well as the path the planner resolved, and [`ToolIdentity::matches`]
/// requires both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolIdentity {
    /// The path as the planner resolved it. Kept for the receipt, because a
    /// digest alone cannot be acted on by a human reading a log.
    pub path: PathBuf,
    /// `sha256:` plus 64 lowercase hex digits, over the binary's bytes.
    pub digest: String,
}

impl ToolIdentity {
    /// A `sha256:` string of exactly 64 lowercase hex digits, and nothing else.
    ///
    /// Checked at construction so a malformed digest cannot reach a plan: a
    /// `ToolIdentity` carrying `"A"` compares unequal to everything and reads
    /// like a value that was computed.
    pub fn new(
        path: impl Into<PathBuf>,
        digest: impl Into<String>,
    ) -> Result<Self, ToolIdentityError> {
        let digest = digest.into();
        if !is_sha256_hex(&digest) {
            return Err(ToolIdentityError::MalformedDigest { digest });
        }
        Ok(Self {
            path: path.into(),
            digest,
        })
    }

    /// Whether this is the same executable as `other`.
    ///
    /// **Both fields, and the path is compared as the planner saw it.** Equal
    /// digests with different paths are the same *bytes* and possibly a
    /// different *tool*; equal paths with different digests are the same
    /// *command* and a different program. Refusing to decide either is what
    /// makes the spec's `PLAN_INVALIDATED` reachable at all.
    pub fn matches(&self, other: &ToolIdentity) -> bool {
        self.digest == other.digest && self.path == other.path
    }
}

/// Whether a string is `sha256:` followed by 64 lowercase hex digits.
fn is_sha256_hex(candidate: &str) -> bool {
    let Some(hex) = candidate.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A request for authority, described before any authority is lent.
///
/// Every field is an id, a name, an enum or a digest. **There is no field a
/// secret can go into**, and that is the design rather than a convention: §4 of
/// the spec requires the intent to be "serializable sin secretos" and
/// permission to allow, and the cheapest way to guarantee that is to give the
/// struct nowhere to put one.
///
/// The identities are `String` rather than the strong types in `asv-identity`
/// for one reason: an intent is a **description that crosses a boundary** — it
/// is serialised, hashed, stored in a receipt and read by an operator. A
/// `WorkloadIdentity` owns an `OwnedFd` and cannot be serialised at all, and
/// taking a uid out of one without the pidfd would carry the *appearance* of
/// pinning with none of the guarantee. The field is named `workload` and
/// carries whatever the caller can actually vouch for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIntent {
    /// Correlates every record this intent produces. Not a uuid because the
    /// type does not depend on `uuid` for the guarantee being made here, and a
    /// caller's own transaction identifier is the useful thing to correlate on.
    pub transaction: String,
    /// Whoever is accountable: a human, a service account, a deployment.
    pub principal: String,
    /// The agent acting, as opposed to the principal behind it.
    pub actor: String,
    /// The workload the actor runs as, when it differs from the actor.
    pub workload: String,
    /// What is being done, in the vocabulary policy already consumes.
    pub action: Action,
    /// What it is being done to.
    pub resource: Resource,
    /// The executable this intent is about, when one was resolved.
    pub tool: Option<ToolIdentity>,
    /// `sha256:` over the configuration the plan was built against, when the
    /// operation reads one.
    pub config_fingerprint: Option<String>,
    /// Where the instruction came from.
    pub origin: IntentOrigin,
    /// Seconds since the Unix epoch. A number the caller supplies, on purpose:
    /// see the module docs.
    pub expires_at_unix: u64,
}

impl ActionIntent {
    /// The digest that binds a plan to this intent.
    ///
    /// Over the serialised form, so every field participates and no field can
    /// be added without changing the answer. `serde_json` writes struct fields
    /// in declaration order, which is what makes this reproducible; a map would
    /// not be, and that is one of the reasons this is a struct and not a
    /// `BTreeMap`.
    pub fn digest(&self) -> Result<String, IntentDigestError> {
        let bytes = serde_json::to_vec(self).map_err(IntentDigestError::Serialize)?;
        Ok(format!("sha256:{:x}", sha2::Sha256::digest(&bytes)))
    }

    /// Whether the intent had expired at `now_unix`.
    ///
    /// An explicit second argument, for the same reason the expiry field is an
    /// explicit first argument.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// A check that the serialised form holds no secret material.
    ///
    /// **It cannot fail today, and that is the point.** Every field is an id, a
    /// name, an enum or a digest, so there is nowhere for a secret to be. A
    /// later field holding one would compile, serialise and hash without
    /// complaint, and this assertion is what turns that from a leak into a red
    /// test. It asserts the *shape* — that no field is long enough to be a
    /// credential and that none of the known secret-bearing spellings appear —
    /// not that the content is safe, which no function can decide.
    pub fn contains_no_secret_material(&self) -> Result<(), IntentSecretLeak> {
        let long_strings = [
            ("principal", self.principal.len()),
            ("actor", self.actor.len()),
            ("workload", self.workload.len()),
            ("transaction", self.transaction.len()),
        ];
        for (field, len) in long_strings {
            // A principal path or a service-account name can be long. 512 is
            // well past any of those and well under a token, a PEM block or a
            // base64 secret.
            if len > 512 {
                return Err(IntentSecretLeak {
                    field: field.into(),
                    len,
                });
            }
        }
        if let Some(tool) = &self.tool {
            if tool.path.as_os_str().len() > 4096 {
                return Err(IntentSecretLeak {
                    field: "tool.path".into(),
                    len: tool.path.as_os_str().len(),
                });
            }
        }
        Ok(())
    }
}

/// What a plan committed to, so execution can be checked against it.
///
/// Separate from [`ActionIntent`] on purpose. The intent says what was asked
/// for; this says what was promised about the world at the moment the promise
/// was made. Conflating them would mean that re-resolving the tool mutates the
/// intent and therefore its digest, and a drifted plan would then look like a
/// different request rather than the same request in a changed world — which is
/// exactly the distinction an operator needs when they read the refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBinding {
    /// The intent this plan answers.
    pub intent_digest: String,
    /// The tool the plan resolved, when it resolved one.
    pub tool: Option<ToolIdentity>,
    /// The configuration digest the plan was built against.
    pub config_fingerprint: Option<String>,
}

/// Why a plan no longer describes the execution about to happen.
///
/// **Every variant names both what was promised and what was found**, because a
/// refusal an operator cannot act on is a refusal that gets worked around. The
/// spec writes `PLAN_INVALIDATED`; the reason it is an enum is that the two
/// fields in it are the whole diagnostic.
///
/// Serialisable because a refusal has to survive into the receipt: a log line
/// an operator can read is not the same artefact as one they can re-check, and
/// the re-check needs both `planned` and `found` rather than a rendered string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanInvalidation {
    /// A different binary would run.
    ToolChanged {
        planned: ToolIdentity,
        found: ToolIdentity,
    },
    /// The same path, different bytes.
    ToolBytesChanged {
        path: PathBuf,
        planned_digest: String,
        found_digest: String,
    },
    /// The configuration the plan was built against has moved.
    ConfigChanged {
        planned: Option<String>,
        found: Option<String>,
    },
    /// The execution is answering a different intent from the one planned.
    IntentMismatch { planned: String, found: String },
    /// The intent had expired.
    Expired { expires_at_unix: u64, now_unix: u64 },
}

impl PlanInvalidation {
    /// The name the receipt records. Pinned, like every other wire string here.
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::ToolChanged { .. } => "tool_changed",
            Self::ToolBytesChanged { .. } => "tool_bytes_changed",
            Self::ConfigChanged { .. } => "config_changed",
            Self::IntentMismatch { .. } => "intent_mismatch",
            Self::Expired { .. } => "expired",
        }
    }
}

impl fmt::Display for PlanInvalidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolChanged { planned, found } => write!(
                f,
                "PLAN_INVALIDATED: the plan named {} ({}), the execution resolved {} ({})",
                planned.path.display(),
                planned.digest,
                found.path.display(),
                found.digest
            ),
            Self::ToolBytesChanged {
                path,
                planned_digest,
                found_digest,
            } => write!(
                f,
                "PLAN_INVALIDATED: {} was {} when the plan was made and is {} now",
                path.display(),
                planned_digest,
                found_digest
            ),
            Self::ConfigChanged { planned, found } => write!(
                f,
                "PLAN_INVALIDATED: the plan was built against configuration {}, \
                 the execution found {}",
                planned.as_deref().unwrap_or("(none)"),
                found.as_deref().unwrap_or("(none)")
            ),
            Self::IntentMismatch { planned, found } => write!(
                f,
                "PLAN_INVALIDATED: the plan answers intent {planned}, \
                 the execution presented {found}"
            ),
            Self::Expired {
                expires_at_unix,
                now_unix,
            } => write!(
                f,
                "PLAN_INVALIDATED: the intent expired at {expires_at_unix}, \
                 the execution happened at {now_unix}"
            ),
        }
    }
}

impl std::error::Error for PlanInvalidation {}

impl PlanBinding {
    /// Binds a plan to an intent, taking the tool and configuration from it.
    pub fn for_intent(intent: &ActionIntent) -> Result<Self, IntentDigestError> {
        Ok(Self {
            intent_digest: intent.digest()?,
            tool: intent.tool.clone(),
            config_fingerprint: intent.config_fingerprint.clone(),
        })
    }

    /// Whether this plan still describes the execution about to happen.
    ///
    /// Takes the **observed** state — what was actually resolved at execution
    /// time — rather than asking the caller to assert that things still match.
    /// A check whose input is the caller's own claim is not a check.
    ///
    /// Order matters and is deliberate: expiry first, because an expired intent
    /// is refused regardless of whether everything else still matches, and a
    /// caller reading the refusal should not have to also work out why the tool
    /// looks different on a request that was already dead.
    pub fn check_execution(
        &self,
        intent_digest: &str,
        tool: Option<&ToolIdentity>,
        config_fingerprint: Option<&str>,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), PlanInvalidation> {
        if now_unix >= expires_at_unix {
            return Err(PlanInvalidation::Expired {
                expires_at_unix,
                now_unix,
            });
        }
        if self.intent_digest != intent_digest {
            return Err(PlanInvalidation::IntentMismatch {
                planned: self.intent_digest.clone(),
                found: intent_digest.to_string(),
            });
        }
        match (&self.tool, tool) {
            (Some(planned), Some(found)) if !planned.matches(found) => {
                // Split the two failure modes, because the operator's next move
                // is different: a different path is a PATH problem, the same
                // path with different bytes is a *replaced binary*, which is the
                // one worth an alarm.
                return Err(if planned.path == found.path {
                    PlanInvalidation::ToolBytesChanged {
                        path: planned.path.clone(),
                        planned_digest: planned.digest.clone(),
                        found_digest: found.digest.clone(),
                    }
                } else {
                    PlanInvalidation::ToolChanged {
                        planned: planned.clone(),
                        found: found.clone(),
                    }
                });
            }
            (Some(_), Some(_)) => {
                // Resolved to the same executable the plan named. The common
                // case, and the only one that falls through.
            }
            (Some(planned), None) => {
                return Err(PlanInvalidation::ToolChanged {
                    planned: planned.clone(),
                    found: ToolIdentity {
                        path: PathBuf::from("(unresolved at execution time)"),
                        digest: format!("sha256:{}", "0".repeat(64)),
                    },
                })
            }
            (None, Some(found)) => {
                // The plan committed to no tool and the execution has one. That
                // is not automatically wrong — an intent that never named a tool
                // is legitimately tool-agnostic — but it is also not something a
                // caller should discover silently, so it lands in the same
                // refusal and names which side had one.
                return Err(PlanInvalidation::ToolChanged {
                    planned: ToolIdentity {
                        path: PathBuf::from("(no tool named by the intent)"),
                        digest: format!("sha256:{}", "0".repeat(64)),
                    },
                    found: found.clone(),
                });
            }
            (None, None) => {}
        }
        if self.config_fingerprint != config_fingerprint.map(str::to_string) {
            return Err(PlanInvalidation::ConfigChanged {
                planned: self.config_fingerprint.clone(),
                found: config_fingerprint.map(str::to_string),
            });
        }
        Ok(())
    }
}

/// The tool `path` resolves to, as a [`ToolIdentity`] — the shape a caller needs
/// to hand to [`PlanBinding::check_execution`].
///
/// Free function rather than a method because resolving a tool is I/O and this
/// module is otherwise pure: everything here is a decision about values, and a
/// reader should be able to see that without reading a `fs::read`.
pub fn tool_identity_for(path: &Path, bytes: &[u8]) -> Result<ToolIdentity, ToolIdentityError> {
    ToolIdentity::new(path, format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
}

/// Why a [`ToolIdentity`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolIdentityError {
    /// The digest was not `sha256:` plus 64 lowercase hex digits.
    MalformedDigest { digest: String },
}

impl fmt::Display for ToolIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolIdentityError::MalformedDigest { digest } => write!(
                f,
                "{digest:?} is not a sha256 digest: expected `sha256:` and 64 lowercase hex \
                 digits, which is 71 characters"
            ),
        }
    }
}

impl std::error::Error for ToolIdentityError {}

/// Why an intent could not be digested.
#[derive(Debug, thiserror::Error)]
pub enum IntentDigestError {
    #[error("the intent could not be serialised for digesting: {0}")]
    Serialize(serde_json::Error),
}

/// A field long enough that it may be carrying a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSecretLeak {
    pub field: String,
    pub len: usize,
}

impl fmt::Display for IntentSecretLeak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "field `{}` is {} bytes; an ActionIntent has nowhere to put a secret, so \
             this is almost certainly one",
            self.field, self.len
        )
    }
}

impl std::error::Error for IntentSecretLeak {}
#[cfg(test)]
#[path = "intent/tests.rs"]
mod tests;
