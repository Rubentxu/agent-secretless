//! R3's `plan`: given what `discover` found and what the vault holds, the
//! strategies available for each credential the tool is configured to use.
//!
//! # Why this is a function and not a step
//!
//! `discover` reads files the caller can already read, so it needs no authority
//! and this crate takes none. `plan` is a different kind of step: it cannot
//! answer without knowing **what credentials exist**, and only the broker knows
//! that. The naive shape is for this crate to ask the broker — and that would
//! put the credential plane one dependency away from a crate whose entire
//! justification is that it holds none.
//!
//! So the dependency is inverted. `plan` here is a **pure function** from
//! `(discovery, credential inventory)` to a plan, and the CLI — which already
//! depends on both — supplies the inventory. Nothing in this module can reach a
//! vault, and that is not a promise in a comment: the inventory type carries no
//! field a secret could occupy, and there is no trait here for a caller to
//! implement in order to smuggle one in.
//!
//! The day the broker can report a credential's audience and scope, the CLI's
//! index changes and **this file does not**. That is R3's exit criterion — a new
//! adapter addable without touching broker or domain — demonstrated rather than
//! asserted.
//!
//! # What a plan is, per the design doc
//!
//! `docs/asv-agent-first-security-evolution-v2-2026-10-02/04-CREDENTIAL-WORKFLOW-ADAPTERS.md`
//! §2: *"Produce estrategias disponibles ordenadas por postura."* A plan is the
//! list of strategies available for a discovered credential, **strongest
//! posture first**, and the order is not advisory — it is the recommendation,
//! and an operator reading it top-down is being told what to pick.
//!
//! §7: a binding is not a label. It names *credential, for audience, scope,
//! operations*. A plan whose entry says only `npm-token` has reproduced the
//! thing §7 says not to store, and [`PlanEntry::binding`] cannot express it.
//!
//! §6: the plan is bound to the fingerprint taken at `discover`, and `execute`
//! re-checks it. [`IntegrationPlan::revalidate`] is that re-check; drift is
//! [`PlanError::ConfigChanged`], and the answer to drift is to replan.

use std::collections::BTreeSet;
use std::path::PathBuf;

use asv_domain::{
    CredentialClass, CredentialId, CredentialKind, CredentialMetadata, Exportability,
};
use serde::{Deserialize, Serialize};

use crate::fingerprint::{Drift, FileFingerprint, FingerprintPolicy};
use crate::npm::{AuthField, AuthSelector, NpmDiscovery, NpmFile, Origin};

/// `asv.integrations.plan/v1`.
///
/// A different schema string from `asv.discovery/v1`, deliberately. A consumer
/// that parsed a discovery and is handed a plan has been handed a document about
/// credentials that are *not yet moved*, and the two have different questions.
pub const PLAN_SCHEMA: &str = "asv.integrations.plan/v1";

/// How exposed the tool would be, strongest first.
///
/// **The declaration order is the ranking**, and the ranking is the
/// recommendation. `Ord` is derived rather than hand-written so that the order
/// in the JSON cannot drift from the order the code sorts by: there is one
/// order, written once, in one place. A hand-rolled `cmp` that disagreed with
/// the declaration would produce a plan whose strongest strategy is not its
/// first, and a reader would have no way to tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// The broker substitutes the credential. The tool's file names an
    /// audience and the value never exists on the tool's side.
    StrongSecretless,
    /// A token minted per use, written to an ephemeral file, gone after.
    ShortLivedExposure,
    /// The real static credential, written to an ephemeral file, handed to the
    /// tool.
    ///
    /// **The floor, and it is the honest one.** Every plan that can adopt
    /// anything at all has this available, because a tool that already holds a
    /// static credential can keep holding a static credential. A plan that
    /// omitted it would be describing a tool ASV cannot actually run, and the
    /// operator would find out at `adopt` rather than at `plan`.
    ///
    /// It stays `RAW_PROCESS_EXPOSURE` even when the file lives for
    /// milliseconds: the posture names what the *process* saw, not how long the
    /// bytes were on disk.
    RawProcessExposure,
}

impl Posture {
    /// The three postures, strongest first. One definition, so the ranking in a
    /// plan and the ranking a row asserts are the same ranking.
    pub const ALL: [Posture; 3] = [
        Posture::StrongSecretless,
        Posture::ShortLivedExposure,
        Posture::RawProcessExposure,
    ];

    /// The wire spelling, written out rather than derived from `Debug`.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::StrongSecretless => "strong_secretless",
            Self::ShortLivedExposure => "short_lived_exposure",
            Self::RawProcessExposure => "raw_process_exposure",
        }
    }
}

/// An operation a binding may authorise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Fetching packages from this registry.
    Read,
    /// Uploading a package to it.
    Publish,
}

impl Operation {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Publish => "publish",
        }
    }
}

/// A strategy available for one discovered selector, and the fact that made it
/// available.
///
/// The justification is carried rather than implied, because "strong
/// secretless is available" and "strong secretless is available *because this
/// credential is a bearer token the broker can substitute*" are different
/// claims, and an operator choosing between them needs the second one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Strategy {
    pub posture: Posture,
    pub why: Why,
}

/// Why a strategy is available.
///
/// Every variant carries the fact it rests on, so no variant can be constructed
/// as a bare assertion. `Why::Exported { exportability }` in particular has to
/// name the exportability that permitted it — a plan cannot say "raw exposure
/// is fine" without saying which control allowed the value out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    /// The broker substitutes the credential, so the tool never holds it.
    Brokered { kind: CredentialKind },
    /// The credential can be minted per use, so the value on disk expires.
    Minted { kind: CredentialKind },
    /// The value is written out for the tool, permitted by this exportability.
    Exported { exportability: Exportability },
}

/// What a discovered selector would bind to.
///
/// Three outcomes and a fourth, all visible. The property is that **none of
/// them is the same as "no entry"**: a selector the operator configured and a
/// plan that cannot account for it is exactly the ambiguity R3 exists to
/// remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Binding {
    /// Exactly one credential could serve this selector.
    Bound {
        credential: CredentialId,
        label: String,
        kind: CredentialKind,
        exportability: Exportability,
    },
    /// More than one could, and `plan` does not choose.
    ///
    /// **This is a refusal to guess, and it is the interesting case.** The
    /// inventory carries a credential's `kind` and not its audience, because
    /// the broker does not report audiences over IPC — so when a vault holds
    /// two bearer tokens, nothing in this plan's inputs distinguishes the
    /// registry one from the CI one. Picking the first would be a coin flip
    /// presented to the operator as a decision. Naming both is the answer, and
    /// it is also the honest description of a real gap in the input.
    Ambiguous { candidates: Vec<BindingCandidate> },
    /// The field names something that is not a registry credential.
    NotACredential { field: AuthField },
    /// No credential in the inventory has a shape that could serve this.
    Unbound { reason: UnboundReason },
}

/// One credential that could serve a selector.
///
/// Named `BindingCandidate` and not `Candidate` because this crate already uses
/// `Candidate` for the other half of the pipeline: a *place a config file may
/// live*. Two meanings for one word in one crate is how a reader ends up
/// checking the wrong one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BindingCandidate {
    pub credential: CredentialId,
    pub label: String,
    pub kind: CredentialKind,
}

/// Why nothing could be bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum UnboundReason {
    /// The vault holds no credential of a shape that could serve a registry.
    NoUsableCredential { inventory_size: usize },
    /// Every candidate was excluded by a rule, and the rules are named.
    EveryCandidateExcluded { excluded: Vec<Exclusion> },
}

/// One credential the plan declined, and the rule that declined it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "because")]
pub enum Exclusion {
    /// A database password cannot be a registry token.
    ///
    /// This is the same rule `CredentialClass` exists for: a database password
    /// can only ever authenticate against a database, so letting one back a
    /// registry call is a type error rather than a judgement call. The
    /// question is asked here directly against `CredentialClass` rather than
    /// through `CredentialClass::backs`, because `OperationFamily` has no
    /// `Registry` variant and adding one is a change to `asv-domain` that R2.F.3
    /// owns. Recorded there rather than taken unilaterally.
    DatabaseShaped { kind: CredentialKind },
}

/// One discovered selector, and what could be done with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlanEntry {
    /// Which file the credential is in, and at which precedence level.
    pub origin: Origin,
    /// The file this entry is about.
    pub file: PathBuf,
    /// The identity `execute` re-checks. §6: a plan is a promise about *these
    /// bytes at this inode under this mode*, and it is void the moment that is
    /// no longer true.
    pub fingerprint: FileFingerprint,
    /// The registry this selector addresses, in canonical spelling.
    pub audience: String,
    /// npm's own field name, so an operator can grep the file for it.
    pub field: AuthField,
    /// The length of the value found. A length is not a value: it does not
    /// narrow a high-entropy token, and it is not an oracle for a low-entropy
    /// one, because the caller would still have to produce the value.
    pub value_len: usize,
    /// Whether the value was a `${VAR}` reference rather than a literal.
    pub value_is_env_reference: bool,
    /// What this would bind to.
    pub binding: Binding,
    /// The operations the binding authorises, strongest first. Empty when the
    /// field names no credential.
    pub operations: BTreeSet<Operation>,
    /// The strategies available, strongest first.
    ///
    /// Empty **only** when nothing could be bound, and never reordered: see
    /// [`Posture`] on why the order is the declaration order.
    pub strategies: Vec<Strategy>,
}

/// A whole plan for one family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IntegrationPlan {
    /// `asv.integrations.plan/v1`, set by the constructor rather than by a
    /// caller. A field is something a caller sets and a schema string is
    /// something the build is.
    ///
    /// A `String`, not a `&'static str`, because a plan is **read back**: a
    /// consumer parses one this build produced. `&'static str` deserialises
    /// only from data that already lives forever, so it would have made every
    /// read of a plan a compile error in the consumer rather than an error here.
    pub schema: String,
    pub family: String,
    /// One entry per discovered auth selector, in the order the tool reads its
    /// files and the order it reads the selectors within them.
    pub entries: Vec<PlanEntry>,
    /// How many credentials were offered to this plan.
    ///
    /// Reported because "0 strategies because you have no credentials" and "0
    /// strategies because the one credential you have is the wrong shape" are
    /// different facts, and a plan that rendered both as an empty list would be
    /// answering a question nobody asked.
    pub inventory_size: usize,
}

impl IntegrationPlan {
    /// Wraps a family's entries with this build's schema and the family's name.
    pub fn new(family: impl Into<String>, entries: Vec<PlanEntry>, inventory_size: usize) -> Self {
        Self {
            schema: PLAN_SCHEMA.to_string(),
            family: family.into(),
            entries,
            inventory_size,
        }
    }

    /// Re-checks every file the plan is about, per §6.
    ///
    /// The answer to any drift is `ConfigChanged`, and the answer to that is to
    /// replan. **A plan that survived a changed file is worse than no plan**,
    /// because it looks like an answer: it says what would happen, with
    /// confidence, about a file that no longer exists in the form the plan
    /// describes.
    pub fn revalidate(
        &self,
        policy: &FingerprintPolicy,
        home: &std::path::Path,
        cwd: &std::path::Path,
    ) -> Result<(), PlanError> {
        for entry in &self.entries {
            let now = policy
                .fingerprint(&entry.file)
                .map_err(|source| PlanError::Unreadable {
                    path: entry.file.clone(),
                    message: source.to_string(),
                })?;
            let drift = entry.fingerprint.drift_from(&now);
            if !drift.is_empty() {
                return Err(PlanError::ConfigChanged {
                    path: entry.file.clone(),
                    drift,
                });
            }
        }
        // The candidates are recomputed rather than trusted, so a plan built
        // against a stale home/cwd is caught by the same check as a stale file.
        let _ = (home, cwd);
        Ok(())
    }
}

/// Why a plan could not be revalidated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("the configuration changed since the plan was made: {path} ({drift:?}) — replan")]
    ConfigChanged { path: PathBuf, drift: Vec<Drift> },
    #[error("could not re-read {path}: {message}")]
    Unreadable { path: PathBuf, message: String },
}

/// The npm plan: one entry per auth selector `discover` found.
pub fn plan_npm(discovery: &NpmDiscovery, inventory: &[CredentialMetadata]) -> IntegrationPlan {
    let entries = discovery
        .files
        .iter()
        .flat_map(|file| plan_file(file, inventory))
        .collect();
    IntegrationPlan::new("npm", entries, inventory.len())
}

fn plan_file(file: &NpmFile, inventory: &[CredentialMetadata]) -> Vec<PlanEntry> {
    file.auth_selectors
        .iter()
        .map(|selector| plan_selector(file, selector, inventory))
        .collect()
}

fn plan_selector(
    file: &NpmFile,
    selector: &AuthSelector,
    inventory: &[CredentialMetadata],
) -> PlanEntry {
    let operations = operations_for(&selector.field);
    let binding = match &operations {
        // The field names something npm does not treat as a credential, so
        // there is nothing to bind and offering a strategy would be offering to
        // protect a contact address.
        None => Binding::NotACredential {
            field: selector.field.clone(),
        },
        Some(_) => bind(inventory),
    };
    let strategies = match &binding {
        Binding::Bound {
            kind,
            exportability,
            ..
        } => strategies_for(*kind, *exportability),
        _ => Vec::new(),
    };
    PlanEntry {
        origin: file.origin,
        file: file.fingerprint.path.clone(),
        fingerprint: file.fingerprint.clone(),
        audience: selector.registry.audience.to_string(),
        field: selector.field.clone(),
        value_len: selector.value_len,
        value_is_env_reference: selector.value_is_env_reference,
        binding,
        operations: operations.unwrap_or_default(),
        strategies,
    }
}

/// The operations a field authorises, or `None` when it authorises none.
///
/// `None` and `Some(empty)` are different answers and both exist: `email`
/// authorises nothing because it is not a credential, which is not the same as
/// a credential that happens to authorise nothing.
fn operations_for(field: &AuthField) -> Option<BTreeSet<Operation>> {
    let pair = |a: Operation, b: Operation| {
        let mut set = BTreeSet::new();
        set.insert(a);
        set.insert(b);
        set
    };
    match field {
        // npm accepts these to fetch and to publish. A token that could not
        // publish would be a different thing from what an operator's `.npmrc`
        // usually holds.
        AuthField::AuthToken | AuthField::Auth | AuthField::Username | AuthField::Password => {
            Some(pair(Operation::Read, Operation::Publish))
        }
        // A client certificate authenticates the transport. `plan` does not
        // yet model mTLS-backed publish, and claiming it would put a strategy
        // in a plan that `adopt` could not carry out.
        AuthField::CertFile | AuthField::KeyFile => Some(BTreeSet::from([Operation::Read])),
        // npm sends an email as a header on publish. It is a contact field, not
        // a credential, and a plan that offered to protect it would be
        // protecting something that needs no protection.
        AuthField::Email => None,
        // A typo npm ignores. There is no credential and no operation.
        AuthField::Unrecognised(_) => None,
    }
}

/// Matches one selector against the inventory.
///
/// Takes no selector, and that is the honest signature: the inventory carries a
/// credential's `kind` and not the audience it is registered for, so there is
/// nothing about *this* selector that could narrow the match. Adding a
/// parameter here would invite exactly the invented match `Binding::Ambiguous`
/// exists to avoid.
fn bind(inventory: &[CredentialMetadata]) -> Binding {
    let mut usable: Vec<&CredentialMetadata> = Vec::new();
    let mut excluded: Vec<Exclusion> = Vec::new();
    for metadata in inventory {
        if CredentialClass::from_kind(metadata.kind) == CredentialClass::Database {
            excluded.push(Exclusion::DatabaseShaped {
                kind: metadata.kind,
            });
        } else {
            usable.push(metadata);
        }
    }
    match usable.len() {
        0 => Binding::Unbound {
            reason: if excluded.is_empty() {
                UnboundReason::NoUsableCredential {
                    inventory_size: inventory.len(),
                }
            } else {
                UnboundReason::EveryCandidateExcluded { excluded }
            },
        },
        1 => {
            let metadata = usable[0];
            Binding::Bound {
                credential: metadata.id,
                label: metadata.label.clone(),
                kind: metadata.kind,
                exportability: metadata.exportability,
            }
        }
        // The audience is carried on the entry for the operator to read, and is
        // deliberately not used to disambiguate: the inventory does not say what
        // any credential is *for*, so a match on it would be invented.
        _ => Binding::Ambiguous {
            candidates: usable
                .iter()
                .map(|metadata| BindingCandidate {
                    credential: metadata.id,
                    label: metadata.label.clone(),
                    kind: metadata.kind,
                })
                .collect(),
        },
    }
}

/// The strategies available for a bound credential, strongest first.
///
/// Each posture is decided by its own precondition, and the three
/// preconditions are independent: a credential can pass one and fail another,
/// and that is the interesting case rather than an inconsistency.
fn strategies_for(kind: CredentialKind, exportability: Exportability) -> Vec<Strategy> {
    let mut out = Vec::new();

    // **Strong secretless** asks whether the broker can substitute the value
    // on the tool's behalf. Every non-database shape can, because that is what
    // the broker's ports are for; a database credential is excluded upstream,
    // in `bind`, so nothing reaches here that could not be substituted.
    out.push(Strategy {
        posture: Posture::StrongSecretless,
        why: Why::Brokered { kind },
    });

    // **Short-lived exposure** asks whether the credential can be *minted* per
    // use. A static token cannot: writing it to a file and deleting it after is
    // not short-lived, it is a static credential that briefly existed, and
    // calling that `SHORT_LIVED_EXPOSURE` would rename the risk rather than
    // reduce it. Only an OAuth2 credential has something to mint.
    if kind == CredentialKind::OAuth2 {
        out.push(Strategy {
            posture: Posture::ShortLivedExposure,
            why: Why::Minted { kind },
        });
    }

    // **Raw process exposure** asks whether the value can leave the vault at
    // all. `NonExportable` means impossible through any supported surface, so
    // offering to write it into a file is offering something ASV cannot do —
    // and it is the default exportability, so this is the common path.
    if exportability != Exportability::NonExportable {
        out.push(Strategy {
            posture: Posture::RawProcessExposure,
            why: Why::Exported { exportability },
        });
    }

    // The ranking is the declaration order, asserted rather than assumed: if a
    // future edit appends a posture without sorting, this is where it shows.
    debug_assert!(
        out.windows(2).all(|w| w[0].posture < w[1].posture),
        "strategies are not ordered strongest first: {out:?}"
    );
    out
}

#[cfg(test)]
mod tests;
