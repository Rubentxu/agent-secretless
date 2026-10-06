//! Credential workflow adapters — R3: npm, and the first proof that a second
//! family needs nothing outside this crate.
//!
//! # What this crate is for
//!
//! ASV protects work that happens on a machine. A tool that needs a credential
//! — `npm publish`, `mvn deploy`, `gradle uploadArchives` — keeps that
//! credential in a file, and the file is the leak: `~/.npmrc` at `0644`, a
//! `settings.xml` in a repository, a `.netrc` whose mode nobody has checked
//! since 2019. R3 moves the credential into the vault and leaves behind
//! something that names it.
//!
//! The pipeline is fixed and every family implements the same stages:
//!
//! ```text
//! discover ─→ safe parse ─→ plan ─→ adopt
//!     │            │         │         │
//!  read the     no secret  the binding  write the projection,
//!  tool's       reaches    an operator  never the credential
//!  config       the report can read      itself
//! ```
//!
//! **This crate is `discover`, `safe parse`, `plan` and `adopt`.** What it is
//! not is anything that *fetches*: `plan` takes its inventory as an argument
//! rather than reaching the broker, and the one place here that holds a
//! credential — [`adopt`]'s extraction — is the step whose entire job is to
//! produce one, and which therefore cannot ask a vault to send it a secret
//! first. See [`adopt`] for why the order of the stages is what makes that
//! safe.
//!
//! `plan` is here as a **function**, not as a step that reaches the vault: it
//! takes a discovery and a credential inventory and returns an
//! [`plan::IntegrationPlan`]. The CLI supplies the inventory, so a second
//! adapter adds a planner to this crate and nothing anywhere else. See
//! [`plan`] for why the dependency is inverted that way.
//!
//! # The laws this crate obeys
//!
//! **No second authority.** Tooling config semantics belong to ASV, and this
//! crate is where that lives. It does not depend on the broker, the vault, the
//! policy engine or the connectors — a discovery step that could reach a vault
//! would be a step that could be *made* to, and `discover` has no reason to
//! hold authority. Its only dependency is `asv-domain`, for the credential
//! and authority vocabulary. `plan` keeps the same law by taking its input
//! rather than fetching it.
//!
//! **A report that cannot be wrong.** Every field in a report is either derived
//! from the file or an explicit absence. Nothing is defaulted, nothing is
//! inferred, and a value this crate cannot describe is reported as undescribed
//! rather than dropped. A dropped line reads identically to a line that was
//! never there, and that is the one ambiguity a security report cannot have.
//!
//! **The report holds no secret.** Not "redacted", not "masked" — the report's
//! types have nowhere to put one. See [`npm`] for why that is a type-level
//! property rather than a filter, and why there is deliberately no per-value
//! digest.
//!
//! # What `discover` is not
//!
//! It is not a check that your tooling setup is good. It cannot tell you a token
//! is about to expire, that a scope is writable, or that a registry is the one
//! you meant — those are `plan`'s questions, and `plan` answers them from the
//! *inventory you hand it*, which is metadata and never a value. `discover`
//! reports what is on disk, and every claim it makes is one a re-read would
//! either confirm or contradict.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod adopt;
pub mod curl;
pub mod fingerprint;
pub mod gradle;
pub mod maven;
pub mod npm;
pub mod plan;
pub mod registry_audience;

pub use adopt::{
    selector_for, AdoptError, AdoptReceipt, AdoptSelector, NpmAdoption, PendingStep, ADOPT_SCHEMA,
};
pub use curl::{
    Curl, CurlCredential, CurlCredentialEntry, CurlDiscovery, CurlError, CurlFile, CurlOption,
};
pub use fingerprint::{Drift, FileFingerprint, FingerprintError, FingerprintPolicy};
pub use gradle::{Gradle, GradleDiscovery, GradleError};
pub use maven::{Maven, MavenDiscovery, MavenError};
pub use npm::{Npm, NpmDiscovery, NpmError};
pub use plan::{
    plan_npm, Binding, BindingCandidate, Exclusion, IntegrationPlan, Operation, PlanEntry,
    PlanError, Posture, Strategy, UnboundReason, Why, PLAN_SCHEMA,
};
pub use registry_audience::{RegistryAudience, RegistryAudienceError};

// `adopt` names a vault credential in its receipt, so the handle type belongs
// at this crate's root rather than making every consumer reach into
// `asv-domain` for it. `Operation` is deliberately *not* re-exported from here:
// it is this crate's own vocabulary, defined by `plan`.
pub use asv_domain::CredentialId;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One family of tool configuration.
///
/// A trait with an associated `Report` rather than a `serde_json::Value` per
/// family, because the thing an adapter adds is *knowledge about a tool*, and
/// a `Value` is where that knowledge goes to be untyped. Adding Maven means
/// adding a module here and a variant to [`AnyReport`]; it does not mean
/// touching the broker, the domain or anything else, which is R3's exit gate.
pub trait Adapter {
    /// The family as an agent names it: `npm`.
    const FAMILY: &'static str;

    /// What this family's report is. No `dyn`-safety needed — dispatch is a
    /// `match` on [`AnyReport`], which is closed and checked.
    type Report: Serialize;

    /// Why this family could not produce a report at all, as opposed to a report
    /// carrying findings. The two are separate on purpose: a family that has
    /// nothing to say and a family that could not look are different facts, and
    /// collapsing them is how a tool ends up reporting "no credentials found"
    /// when it means "I could not read the file".
    type Error: std::error::Error;

    /// Where this family's configuration may be, in the order the tool itself
    /// reads them.
    ///
    /// Takes `home` and `cwd` as arguments rather than reading the environment.
    /// An `Adapter` that resolved its own paths would resolve *this process's*
    /// paths, and a report about the caller's configuration is not a report
    /// about the project.
    fn candidates(home: &Path, cwd: &Path) -> Vec<Candidate>;

    /// Describe what is on disk.
    fn discover(
        &self,
        policy: &FingerprintPolicy,
        home: &Path,
        cwd: &Path,
    ) -> Result<Self::Report, Self::Error>;
}

/// One place a family's configuration may live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    /// Which of the tool's precedence levels this is. Carried so a report can
    /// say *which* file won, which is the question an operator actually has
    /// when a project config and a user config disagree.
    ///
    /// **This was `npm::Origin`, and that was a real block on R3's exit
    /// criterion.** The exit criterion says a new adapter must be addable
    /// without touching the broker, the domain -- or, as it turned out, without
    /// touching *this crate's shared types*. A second family could only have
    /// borrowed npm's three levels or forced a change here, and the honest
    /// reading is that the criterion was untested with one family.
    ///
    /// Lifted to the crate because the levels are genuinely shared -- a project
    /// config, a user config, and something the tool installation brought --
    /// and a family whose vocabulary does not fit adds a case rather than
    /// bending this one.
    pub origin: Origin,
}

/// Where a configuration file sits in a tool's own precedence.
///
/// Shared across families because the *shape* is shared: every tool on this
/// list reads a project-level file, a user-level file, and possibly one its own
/// installation carries. A family with a different shape gets its own level
/// here rather than borrowing another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// In the working directory, overriding the others.
    Project,
    /// In the user's home directory.
    User,
    /// In the tool installation's own configuration.
    Global,
    /// In the tool installation's configuration, where the tool and the
    /// operating system disagree about the name for it. Maven reads
    /// `$MAVEN_HOME/conf/settings.xml` and does not call it "global".
    Tool,
}

/// A discovery report, in the one shape the CLI prints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    /// `asv.discovery/v1`. Named because this crosses into agent context and a
    /// consumer needs to know which shape it is looking at before it parses it.
    ///
    /// A `String` rather than a `&'static str`: this type derives `Deserialize`,
    /// and `&'static str` can only be deserialised from data that already lives
    /// forever, so a `&'static str` here would mean *the derive does not
    /// compile for any runtime input*. It did compile, because `Deserialize` is
    /// only instantiated when something asks for it — which is exactly the
    /// failure mode where a derive looks fine and the type is unusable. Found
    /// when `adopt` needed to read a plan back.
    pub schema: String,
    pub family: String,
    pub report: AnyReport,
}

/// The only version this build produces.
///
/// A constructor rather than a public field, because a field is something a
/// caller sets and a schema string is something the *build* is: a report that
/// claimed a version it does not have would be the one lie in a document whose
/// whole job is to be believed.
pub const DISCOVERY_SCHEMA: &str = "asv.discovery/v1";

impl Discovery {
    /// Wraps a family's report with this build's schema and the family's name.
    pub fn new(family: impl Into<String>, report: AnyReport) -> Self {
        Self {
            schema: DISCOVERY_SCHEMA.to_string(),
            family: family.into(),
            report,
        }
    }
}

/// The per-family report.
///
/// A closed enum rather than a map of strings. A map would let a caller read a
/// field it cannot type-check, and `discover`'s output is something an agent
/// acts on; the cost of the enum is one variant per family, paid in one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnyReport {
    Npm(NpmDiscovery),
    Maven(MavenDiscovery),
    Gradle(GradleDiscovery),
    Curl(CurlDiscovery),
}

/// Something discovery noticed that the operator should see.
///
/// Findings are how a refusal is reported without failing the whole run: an
/// unreadable project `.npmrc` does not make the user one useless, and an
/// operator needs to know it was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// What the finding is about — a path, or a config key.
    pub subject: String,
    pub message: String,
}

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The subject was not read, and nothing about it is being claimed.
    Refused,
    /// Read and described, with something an operator should decide about.
    Warning,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema string is part of the contract with every consumer, and a
    /// change to it is a change to what an agent may assume about the report.
    #[test]
    fn the_report_declares_the_schema_it_actually_has() {
        let report = Discovery::new("npm", AnyReport::Npm(NpmDiscovery { files: Vec::new() }));
        let json = serde_json::to_string(&report).expect("the report serialises");
        assert!(json.contains(r#""schema":"asv.discovery/v1""#), "{json}");
        assert!(json.contains(r#""family":"npm""#), "{json}");
    }
}
