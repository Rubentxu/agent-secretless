//! Core domain types for ASV.
//!
//! Scope note (M0, `docs/15-ROADMAP.md`): this crate carries the types that
//! define the *boundaries* of the security model, not the behaviour. Two
//! properties are load-bearing and must not be weakened:
//!
//! 1. Every identifier is a newtype, so a `CredentialId` can never be passed
//!    where an `AgentSessionId` is expected (P7, `docs/00-VISION-AND-PRINCIPLES.md`).
//! 2. [`IntegrationPosture`] is a closed enum, so an integration can never be
//!    silently relabelled as stronger than it is (ADR-0014, R10 release gate).

pub mod secret;

pub use secret::{SecretBytes, SecretPurpose};

use core::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a fresh random identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Rehydrates an identifier from its wire form.
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Returns the underlying UUID.
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

opaque_id!(
    /// Stable handle for a stored credential.
    ///
    /// Policies reference this identifier, never a token string, so rotating a
    /// credential does not require reconfiguring any agent (M0 spec §12 of
    /// `docs/07-VAULT-CRYPTO-MEMORY.md`, UAT-027).
    CredentialId
);

opaque_id!(
    /// Handle for one `asv run` session.
    AgentSessionId
);

opaque_id!(
    /// Authorization state for a bounded action. A grant is not a credential.
    CapabilityId
);

opaque_id!(
    /// Reference to a human approval decision.
    ApprovalId
);

/// Classification of a credential. Extensible per FR-001, but never a
/// `HashMap<String, String>`: an explicit enum is what lets policy reason about
/// a credential's capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ApiKey,
    BearerToken,
    OAuth2,
    UsernamePassword,
    SshPrivateKey,
    X509ClientIdentity,
    AwsAccessKey,
    DatabaseCredential,
    GenericSecret,
}

/// Whether a human may ever obtain the raw value (FR-002).
///
/// `NonExportable` is the default and the one agents should get. The agent
/// surfaces have no retrieval API at all (ADR-0001), so this enum governs the
/// human control plane only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exportability {
    /// Impossible through any supported UI or CLI once stored.
    NonExportable,
    /// Reveal requires explicit human re-authentication and is time-limited.
    HumanOnly,
    /// Explicit opt-in. Still never exposed through agent CLI or MCP.
    Exportable,
}

impl Default for Exportability {
    /// Defaults to the safe posture, per FR-002.
    fn default() -> Self {
        Self::NonExportable
    }
}

/// Non-secret metadata about a stored credential.
///
/// Deliberately separate from any secret-bearing payload: this is the shape
/// that is safe to list over IPC, show in the dashboard, and write to audit
/// records (FR-015, `docs/11-AUDIT-OBSERVABILITY.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub label: String,
    pub kind: CredentialKind,
    pub exportability: Exportability,
}

impl CredentialMetadata {
    /// Creates metadata with the default `NonExportable` exportability.
    pub fn new(label: impl Into<String>, kind: CredentialKind) -> Self {
        Self {
            id: CredentialId::new(),
            label: label.into(),
            kind,
            exportability: Exportability::default(),
        }
    }
}

/// The honest label for how much a given integration actually protects.
///
/// ADR-0014 and release gate R10 exist to stop the product from implying that
/// a degraded mechanism is equivalent to a signing/proxy path.
///
/// The variants are declared strongest-first for readability, but the `Ord`
/// impl below is written by hand. A derived `Ord` would order by *declaration*
/// position, which silently means "stronger posture sorts lower" — exactly
/// backwards for any comparison that picks the best available mechanism
/// (`docs/04-SHELL-FIRST-INTEGRATION.md` §6). Making the ranking explicit means
/// reordering the variants cannot quietly change the security semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrationPosture {
    /// The real secret never enters the agent process tree (SP-01).
    StrongSecretless,
    /// A short-lived derived token reaches the client. Reduced risk, not
    /// non-disclosure (ADR-0005, `docs/19-ALTERNATIVES-AND-REJECTIONS.md` §12).
    ShortLivedExposure,
    /// A worker outside agent control holds the credential. Network and
    /// filesystem confinement are the actual controls, not output filtering
    /// (ADR-0008, UAT-022).
    IsolatedProcessExposure,
    /// The target process can read, transform and exfiltrate the credential.
    RawProcessExposure,
    /// ASV cannot help for this tool, and says so instead of pretending.
    Unsupported,
}

impl IntegrationPosture {
    /// Security ranking, strongest first. Larger means stronger.
    const fn rank(self) -> u8 {
        match self {
            Self::StrongSecretless => 4,
            Self::ShortLivedExposure => 3,
            Self::IsolatedProcessExposure => 2,
            Self::RawProcessExposure => 1,
            Self::Unsupported => 0,
        }
    }
}

impl Ord for IntegrationPosture {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for IntegrationPosture {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An operation a session may attempt. Semantic operations are preferred over
/// a generic omnipotent `http.request` (`docs/02-THREAT-MODEL.md` §7).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    GitFetch,
    GitPush,
    SshConnect,
    HttpRequest,
    PostgresConnect,
    GitHubIssueCreate,
    GitHubReleaseCreate,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::GitFetch => "git.fetch",
            Self::GitPush => "git.push",
            Self::SshConnect => "ssh.connect",
            Self::HttpRequest => "http.request",
            Self::PostgresConnect => "postgres.connect",
            Self::GitHubIssueCreate => "github.issue.create",
            Self::GitHubReleaseCreate => "github.release.create",
        };
        f.write_str(s)
    }
}

/// The thing being acted upon, e.g. a repository or a database.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Repository { owner: String, name: String },
    Database { name: String, role: String },
    Host { hostname: String },
    Api { audience: String },
}

/// Authorization outcome. Deny is the default; there is no implicit allow
/// (ADR-0004, P6 fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum Decision {
    Allow,
    Deny { reason: String },
    RequireApproval { approval: ApprovalId },
}

impl Decision {
    /// Whether this decision permits the operation to proceed without a human.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Errors that are safe to show to a caller.
///
/// Every variant carries identifiers and context, never secret values
/// (`docs/17-IMPLEMENTATION-BOOTSTRAP.md` §9). The `Debug` derive is therefore
/// safe by construction: no variant can hold a [`SecretBytes`].
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("credential not found: {0}")]
    CredentialNotFound(CredentialId),

    #[error("session not found: {0}")]
    SessionNotFound(AgentSessionId),

    #[error("capability expired: {0}")]
    CapabilityExpired(CapabilityId),

    #[error("denied: {reason}")]
    Denied { reason: String },

    #[error("approval required before this operation can proceed")]
    ApprovalRequired,

    #[error("integration is not supported for this tool: {0}")]
    IntegrationUnsupported(String),

    #[error("session is no longer valid: {0}")]
    SessionExpired(AgentSessionId),
}

/// Result alias for domain operations.
pub type DomainResult<T> = Result<T, DomainError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exportability_defaults_to_non_exportable() {
        let m = CredentialMetadata::new("github-work", CredentialKind::BearerToken);
        assert_eq!(m.exportability, Exportability::NonExportable);
    }

    /// Newtypes must not be interchangeable: this is the P7 compile-time guard.
    #[test]
    fn identifier_newtypes_are_distinct() {
        let cred = CredentialId::new();
        let session = AgentSessionId::new();
        assert_ne!(cred.to_string(), session.to_string());
        // The real assertion is that these are different types; if someone
        // collapses them to a bare Uuid, this file stops compiling.
        let _typed: CredentialId = cred;
        let _typed: AgentSessionId = session;
    }

    /// ADR-0014: posture ordering must keep degraded modes strictly below
    /// strong-secretless, so a comparison can never promote a weak mechanism.
    #[test]
    fn posture_ordering_never_promotes_a_weaker_mode() {
        assert!(IntegrationPosture::StrongSecretless > IntegrationPosture::ShortLivedExposure);
        assert!(
            IntegrationPosture::ShortLivedExposure > IntegrationPosture::IsolatedProcessExposure
        );
        assert!(
            IntegrationPosture::IsolatedProcessExposure > IntegrationPosture::RawProcessExposure
        );
        assert!(IntegrationPosture::RawProcessExposure > IntegrationPosture::Unsupported);
    }

    /// Audit records must never be able to carry secret material. Metadata is
    /// serializable on purpose; the type simply has nowhere to put a secret.
    #[test]
    fn credential_metadata_round_trips_without_secret_fields() {
        let m = CredentialMetadata::new("deploy-key", CredentialKind::SshPrivateKey);
        let json = serde_json::to_string(&m).expect("metadata is serializable");
        assert!(json.contains("deploy-key"));
        assert!(
            !json.contains("secret"),
            "metadata must not gain a secret field"
        );

        let back: CredentialMetadata = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back, m);
    }

    /// P6: an absent decision is never an allow.
    #[test]
    fn deny_is_the_only_non_allowing_outcome() {
        assert!(Decision::Allow.is_allowed());
        assert!(!Decision::Deny {
            reason: "no policy".into()
        }
        .is_allowed());
        assert!(
            !Decision::RequireApproval {
                approval: ApprovalId::new()
            }
            .is_allowed(),
            "require-approval must not read as allowed"
        );
    }

    /// Error rendering is the path a user sees. It must stay informative about
    /// *which* thing failed without ever carrying material.
    #[test]
    fn domain_errors_render_identifiers_not_secrets() {
        let id = CredentialId::new();
        let rendered = DomainError::CredentialNotFound(id).to_string();
        assert!(rendered.contains(&id.to_string()));
        assert!(!rendered.contains("secret"));
    }
}
