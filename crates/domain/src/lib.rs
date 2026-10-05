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

            /// Returns the wire form, as owned text.
            ///
            /// Allocated per call, which is the honest shape here: `uuid`'s
            /// `Hyphenated` is a *formatter* that renders on demand and keeps no
            /// buffer, so there is no slice to borrow and no way to get one
            /// without inventing one. An earlier attempt to force a borrow with
            /// `String::leak` would have traded an allocation for a leak, and
            /// a leak is the worse of the two by a wide margin.
            ///
            /// Returns `String` rather than `&str` precisely so the compiler
            /// keeps saying so at every call site instead of letting a `&'static
            /// str` look like a free borrow.
            pub fn to_wire(&self) -> String {
                self.0.to_string()
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

        /// Parses the wire form back into an identifier.
        ///
        /// Added in ADR-0019's cycle, and the reason is that an id nobody can
        /// read back is not an id. `asv run` hands a child its session id as
        /// a string in the environment; before this, the only way to get a
        /// `SessionId` was `new()`, so a child holding the string had no way
        /// to name its own session in a request. `ASV_SESSION_ID` would have
        /// been a slightly-more-real string that still resolved to nothing —
        /// the pid problem again, one layer up.
        ///
        /// The parse is strict and total: the wire form is a hyphenated UUID
        /// and anything else is refused rather than coerced.
        impl std::str::FromStr for $name {
            type Err = $crate::OpaqueIdParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(text)
                    .map(Self)
                    .map_err(|_| $crate::OpaqueIdParseError)
            }
        }
    };
}

/// What it means to hand back something that is not a wire-form id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("identifier must be a canonical lowercase hyphenated UUID")]
pub struct OpaqueIdParseError;

opaque_id!(
    /// Stable handle for a stored credential.
    ///
    /// Policies reference this identifier, never a token string, so rotating a
    /// credential does not require reconfiguring any agent (M0 spec §12 of
    /// `docs/07-VAULT-CRYPTO-MEMORY.md`, UAT-027).
    CredentialId
);

impl CredentialId {
    /// Rehydrates a credential id only from its canonical wire spelling.
    ///
    /// The vault keys credentials by a `String` (`asv_vault::CredentialMetadata`
    /// `id`), while this type is a `Uuid`, so something has to stand between
    /// them. Doing it here rather than in the broker keeps `uuid` out of every
    /// consumer's dependency list and keeps the decision about what a valid
    /// credential id looks like next to the type that defines one. Uppercase,
    /// compact, braced, and other alternate UUID spellings are rejected.
    ///
    /// Only [`CredentialId`] gets this. The other ids in this module are minted
    /// by the broker and never parsed from caller-supplied text, and leaving
    /// them without a parse is the point: an id that cannot be reconstructed
    /// from bytes is an id that cannot be guessed either.
    pub fn from_wire(text: &str) -> Result<Self, CredentialIdParseError> {
        let uuid = uuid::Uuid::parse_str(text).map_err(|_| CredentialIdParseError)?;
        let id = Self(uuid);
        if id.to_wire() != text {
            return Err(CredentialIdParseError);
        }
        Ok(id)
    }
}

/// A credential ID must use its exact canonical wire spelling. The error is
/// intentionally input-free so malformed text cannot leak through diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credential id must be a canonical lowercase hyphenated UUID")]
pub struct CredentialIdParseError;

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

opaque_id!(
    /// Handle for a broker-minted surrogate token (M4 design D3).
    ///
    /// The surrogate is the credential-shaped string the agent presents to the
    /// broker. It stands in for a [`CredentialId`] in the wire and session
    /// records, which is exactly why it is a separate newtype: an agent holding
    /// one has no handle on the credential behind it (ADR-0011).
    SurrogateId
);

/// A canonicalized, DNS-only authority that a policy may name (M4 design D5).
///
/// Canonicalization is a **type**, not a helper function, on purpose. A
/// `canonicalize()` free function is a convention a call-site can forget, and
/// a forgotten call turns an allowlist comparison into a spelling contest
/// (`API.GITHUB.COM` vs `api.github.com`). The only constructor here is
/// fallible, so a non-canonical audience cannot be represented at all.
///
/// Accepted form is a bare lowercase ASCII DNS name with a single optional
/// trailing dot. Everything else is rejected rather than guessed:
///
/// - userinfo (`user@host`) — hides which host is really meant;
/// - `..` and empty labels;
/// - percent-encoding, which can hide the label separator;
/// - non-ASCII (IDNA is *denied*, not supported — see the design's open
///   question; a decision, not an omission);
/// - IPv6 literals, which have no DNS resolution to pin;
/// - any scheme, and any non-default port.
///
/// The type carries no secret, so `Debug`/`Display` stay safe by construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Authority(String);

impl Authority {
    /// Canonicalizes `raw` into an authority, or explains why it cannot.
    ///
    /// The rules are the single source of truth for "the same host" in this
    /// codebase; the Cedar allowlist and the connector's address pinning both
    /// consume the result.
    pub fn canonicalize(raw: &str) -> Result<Self, AuthorityError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(AuthorityError::Empty);
        }
        if trimmed != raw {
            // Leading/trailing whitespace is never a legitimate host spelling
            // and accepting it would let `"api.github.com "` slip past a
            // textual allowlist comparison.
            return Err(AuthorityError::SurroundingWhitespace {
                input: raw.to_string(),
            });
        }
        if !trimmed.is_ascii() {
            return Err(AuthorityError::NotAscii {
                input: raw.to_string(),
            });
        }
        if trimmed.contains('@') {
            return Err(AuthorityError::UserInfo {
                input: raw.to_string(),
            });
        }
        if trimmed.contains('%') {
            return Err(AuthorityError::PercentEncoded {
                input: raw.to_string(),
            });
        }
        if trimmed.contains('/') || trimmed.contains(':') {
            return Err(AuthorityError::NotBareHost {
                input: raw.to_string(),
            });
        }
        if trimmed.starts_with('[') || trimmed.ends_with(']') {
            return Err(AuthorityError::IpLiteral {
                input: raw.to_string(),
            });
        }

        let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if without_trailing_dot.is_empty() {
            return Err(AuthorityError::Empty);
        }

        let mut labels = Vec::new();
        for label in without_trailing_dot.split('.') {
            if label.is_empty() {
                return Err(AuthorityError::EmptyLabel {
                    input: raw.to_string(),
                });
            }
            if label.len() > 63 {
                return Err(AuthorityError::LabelTooLong {
                    input: raw.to_string(),
                });
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(AuthorityError::MalformedLabel {
                    input: raw.to_string(),
                });
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(AuthorityError::MalformedLabel {
                    input: raw.to_string(),
                });
            }
            labels.push(label.to_ascii_lowercase());
        }

        if labels.len() < 2 {
            // A single label is not a routable authority; denying it keeps the
            // allowlist from ever naming a bare `localhost`-style shortcut.
            return Err(AuthorityError::SingleLabel {
                input: raw.to_string(),
            });
        }

        Ok(Self(labels.join(".")))
    }

    /// The canonical lowercase ASCII form, e.g. `api.github.com`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Authority {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A CONNECT destination: a canonical host and a port, parsed from a request
/// line the way the broker will read it.
///
/// This is the *one* reading of a CONNECT request line. The broker needs it to
/// authorise a destination and to know which destination a session proof is
/// bound to; a session-local shim needs it to know which destination to mint
/// that proof for. Those two must agree byte for byte, because the proof's
/// nonce is a hash over the canonical host and port, and a parser that
/// disagreed by so much as a trailing dot would not fail loudly — it would
/// fail as "no proof ever verifies", which is the same error a dozen unrelated
/// mistakes produce.
///
/// So the parse lives beside [`Authority::canonicalize`], which is already the
/// single source of truth for "the same host" in this codebase, rather than
/// being restated by each side that needs an answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectTarget {
    authority: Authority,
    port: u16,
}

impl ConnectTarget {
    /// Parses `CONNECT host:port HTTP/1.1`.
    ///
    /// Only a bare `host:port`. A bracketed IPv6 literal is refused rather
    /// than unbracketed, because `rsplit_once(':')` on `[::1]:443` leaves a
    /// host that `Authority::canonicalize` rejects anyway, and pretending to
    /// understand it would only mean the two sides could disagree about it.
    pub fn from_request_line(line: &str) -> Result<Self, ConnectTargetError> {
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        if method != "CONNECT" {
            return Err(ConnectTargetError::NotConnect {
                method: method.to_string(),
            });
        }
        let authority = parts.next().ok_or(ConnectTargetError::NoAuthority)?;
        let (host, port) =
            authority
                .rsplit_once(':')
                .ok_or_else(|| ConnectTargetError::NoPort {
                    authority: authority.to_string(),
                })?;
        let port: u16 = port
            .parse()
            .map_err(|_| ConnectTargetError::NonNumericPort {
                authority: authority.to_string(),
            })?;
        if port == 0 {
            return Err(ConnectTargetError::ZeroPort);
        }
        let authority = Authority::canonicalize(host).map_err(ConnectTargetError::Authority)?;
        Ok(Self { authority, port })
    }

    /// The canonical host.
    pub fn host(&self) -> &str {
        self.authority.as_str()
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The canonical [`Authority`].
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
}

impl fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.authority, self.port)
    }
}

/// Why a CONNECT request line did not name a destination.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectTargetError {
    #[error("request method is {method:?}, not CONNECT")]
    NotConnect { method: String },
    #[error("CONNECT request names no authority")]
    NoAuthority,
    #[error("CONNECT authority {authority:?} carries no port")]
    NoPort { authority: String },
    #[error("CONNECT authority {authority:?} has a non-numeric port")]
    NonNumericPort { authority: String },
    #[error("CONNECT authority has port 0, which is not a service")]
    ZeroPort,
    #[error("CONNECT host is not a usable authority: {0}")]
    Authority(#[from] AuthorityError),
}

/// Why an authority could not be canonicalized. Every variant names a shape
/// that is either ambiguous or unsupported, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("authority is empty")]
    Empty,
    #[error("authority is not plain ASCII: {input:?}")]
    NotAscii { input: String },
    #[error("authority has leading or trailing whitespace: {input:?}")]
    SurroundingWhitespace { input: String },
    #[error("authority must not carry userinfo: {input:?}")]
    UserInfo { input: String },
    #[error("authority must not be percent-encoded: {input:?}")]
    PercentEncoded { input: String },
    #[error("authority must be a bare host, without scheme or port: {input:?}")]
    NotBareHost { input: String },
    #[error("IPv6 literals are not supported as authorities: {input:?}")]
    IpLiteral { input: String },
    #[error("authority has an empty label: {input:?}")]
    EmptyLabel { input: String },
    #[error("authority label is longer than 63 bytes: {input:?}")]
    LabelTooLong { input: String },
    #[error("authority label is malformed: {input:?}")]
    MalformedLabel { input: String },
    #[error("authority must have at least two labels: {input:?}")]
    SingleLabel { input: String },
}

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

/// Which family of brokered operation a credential may back.
///
/// Coarser than [`CredentialKind`] on purpose, and deliberately so. A
/// [`CredentialKind::GenericSecret`] or [`CredentialKind::BearerToken`] does
/// not say what the secret is *for* — a GitHub PAT and an arbitrary API key
/// have the same shape — so pretending to tell them apart would be a guess
/// with security consequences. [`CredentialClass::Generic`] says "the shape
/// does not constrain this", and the policy decides what is allowed.
///
/// [`CredentialClass::Database`] is the case where the shape genuinely does
/// constrain the answer. A database password can only ever authenticate
/// against a database, so letting one back a GitHub call is a type error, not
/// a judgement call, and is refused as one (H2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    /// The secret's shape places no constraint on the operation it may back.
    Generic,
    /// A secret whose shape admits exactly one family: database operations.
    Database,
}

impl CredentialClass {
    /// Derives the class from the credential's kind.
    ///
    /// Total by construction: every `CredentialKind` maps somewhere, so adding
    /// a kind is a compile error here rather than a silent fallthrough to a
    /// permissive class at some call site.
    pub fn from_kind(kind: CredentialKind) -> Self {
        match kind {
            // `UsernamePassword` is a database login, not an SSH or HTTP
            // identity: the broker hands it to `PostgresClient` and to
            // nothing else.
            CredentialKind::DatabaseCredential | CredentialKind::UsernamePassword => Self::Database,
            CredentialKind::ApiKey
            | CredentialKind::BearerToken
            | CredentialKind::OAuth2
            | CredentialKind::SshPrivateKey
            | CredentialKind::X509ClientIdentity
            | CredentialKind::AwsAccessKey
            | CredentialKind::GenericSecret => Self::Generic,
        }
    }

    /// Whether a credential of this class may back `family`.
    ///
    /// `Generic` backs everything; every other class backs exactly its own
    /// family. Written as an explicit table rather than a `matches!` on
    /// equality so that the denying arm is visible in the source: a reader
    /// must be able to see that `Database` on `GitHub` is `false` by
    /// construction, not by accident of how the enum was written.
    pub fn backs(&self, family: OperationFamily) -> bool {
        match (self, family) {
            (Self::Generic, _) => true,
            (Self::Database, OperationFamily::Database) => true,
            (Self::Database, OperationFamily::GitHub) => false,
        }
    }
}

/// A family of brokered operations, used to ask what a surrogate may back.
///
/// Coarser than [`Action`] because the question being asked is not "is this
/// exact verb allowed" — the policy answers that — but "is this token even the
/// right *shape* for this operation", which is answered before any policy is
/// consulted and costs a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationFamily {
    /// `ReadIssue`, `CreateIssue`, `CreateRelease`.
    GitHub,
    /// `PostgresConnect`, `PostgresQuery`.
    Database,
}

impl OperationFamily {
    /// The name the audit chain records for this family.
    ///
    /// Written out rather than derived, for the same reason `action_name` is:
    /// the string is evidence, so it is pinned here where a test can assert it
    /// rather than reconstructed from a `Debug` impl that may change.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Database => "postgres",
        }
    }
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
    /// Read one issue's non-secret metadata (M4-R9, design v2).
    ///
    /// Read is a *semantic* operation on purpose: UAT-030 requires brokered
    /// reads end to end, and a generic `HttpRequest` is not authorizable.
    GitHubIssueRead,
    GitHubReleaseCreate,
    /// The remaining M6-R5 database verbs.
    ///
    /// `PostgresConnect` alone cannot express M6-R5: the spec requires a
    /// policy that allows `connect` but denies `create_table`, which is
    /// impossible if every statement rides on the gateway verb. These five
    /// mirror `asv_connector_pg::DbAction` one-for-one, so the connector
    /// derives the action from the statement and Cedar evaluates it without
    /// the connector changing (M6-R5, "policy change needs no edit").
    ///
    /// A new variant is a breaking change to the policy grammar: it breaks
    /// every `PolicySet` whose schema omits the action, and Cedar rejects
    /// the unknown action at evaluation time rather than denying it, so the
    /// failure is loud.
    PostgresRead,
    PostgresInsert,
    PostgresCreateTable,
    PostgresDropTable,
    PostgresAlterTable,
    /// Declare that a `(authority, port)` may be `CONNECT`-ed at all, and under
    /// which operation family the substitution runs (C2.6).
    ///
    /// This is the action a `ConnectRoute` is authorized against when the
    /// route file is loaded, so the file is a *declaration* and this action is
    /// the *permission*. Keeping them separate is the whole point: a route file
    /// that names a host the policy does not permit is refused at load, so
    /// editing the config cannot widen what the policy allows.
    ///
    /// The default policy text deliberately has **no** `permit` for it, which
    /// means a stock broker refuses every declared route. That is the
    /// fail-closed reading, and widening it is an operator's explicit policy
    /// edit rather than a side effect of writing a config file.
    ConnectRoute,
    /// Asks AWS which identity a request is actually acting as (M11-R2.C.3).
    ///
    /// A *semantic* operation, for the reason every other one here is: a
    /// generic "sign this for this host" verb is not authorizable, and a SigV4
    /// signature is bound to a host, a path and a body — so a caller who could
    /// name the host could present a valid-looking signature to a destination it
    /// was never signed for. The agent names an operation from a closed set and
    /// the broker decides the role, the region and the audience.
    ///
    /// Read-only and parameterless, which is why it is the first one: it is the
    /// only AWS API that answers *which identity is this request acting as*, and
    /// answering that needs no addressing and no body.
    ///
    /// Note what it is **not** evidence of. AWS documents that this operation
    /// requires no permissions and returns the same information when access is
    /// denied, so a provider that answers it has not checked a signature. The
    /// permission being authorized here is the broker's own, and it is what
    /// stops an agent from naming a credential it was not granted.
    AwsStsCallerIdentity,
    /// Asks an OAuth2-protected resource which derived identity a request is
    /// actually acting as (M11-R2.B.2).
    ///
    /// The same shape as [`Self::AwsStsCallerIdentity`] and for the same
    /// reason: it is the operation that answers *which identity is this request
    /// acting as*, and it is read-only and parameterless so the whole question
    /// is answerable without the agent addressing anything.
    ///
    /// **Named for what the agent gets back rather than after the HTTP method.**
    /// The resource is reached with a `GET`, but a name containing "get" or
    /// "introspect" reads like a retrieval and invites the reading that the
    /// agent is being handed a token to use. It is not: the answer is three
    /// non-secret strings the *resource* printed, and the client secret never
    /// leaves the broker.
    ///
    /// Note what it is **not** evidence of, in the same way AWS is not. A
    /// resource server that accepts a token and prints its scope has verified
    /// the token is live and bound to that audience; it has not checked that
    /// the scope is *narrower* than the operator configured. That is why the
    /// broker compares the answer against the deployment and refuses a
    /// mismatch, rather than relaying whatever was granted.
    OAuth2Identity,
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
            Self::GitHubIssueRead => "github.issue.read",
            Self::GitHubReleaseCreate => "github.release.create",
            Self::PostgresRead => "postgres.read",
            Self::PostgresInsert => "postgres.insert",
            Self::PostgresCreateTable => "postgres.create_table",
            Self::PostgresDropTable => "postgres.drop_table",
            Self::PostgresAlterTable => "postgres.alter_table",
            Self::ConnectRoute => "connect.route",
            Self::AwsStsCallerIdentity => "aws.sts.caller_identity",
            Self::OAuth2Identity => "oauth2.identity",
        };
        f.write_str(s)
    }
}

/// The thing being acted upon, e.g. a repository or a database.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Repository {
        owner: String,
        name: String,
    },
    Database {
        name: String,
        role: String,
    },
    Host {
        hostname: String,
    },
    /// An API audience. The field is an [`Authority`], not a `String`, so an
    /// uncanonical audience cannot be constructed (M4 design D5).
    Api {
        audience: Authority,
    },
    /// One registered OAuth2 client, addressed by the vault credential that
    /// holds its client secret (M11-R2.B.2).
    ///
    /// **A distinct variant rather than an `Api`, and the distinction is the
    /// control.** `Api` is gated by `ALLOWED_AUDIENCES`, a two-entry list of
    /// first-party hosts. OAuth2's whole point is reaching IdPs that are not on
    /// any list, so the two requirements genuinely conflict, and resolving it by
    /// widening the list would be a real regression rather than a compromise:
    /// `audience_is_approved` gates *every* `Api`, so admitting arbitrary IdP
    /// hosts there would let any policy text name `evil.example` as an
    /// audience and have it approved — reopening, for GitHub and AWS, the exact
    /// hole D6 closes.
    ///
    /// ## Why the reachability property still holds without the list
    ///
    /// [`ALLOWED_AUDIENCES`](crate) exists to stop *policy text* from widening
    /// the reachable host set. For OAuth2 the reachable set cannot be widened by
    /// policy at all: the audience and the token endpoint both come from
    /// `--oauth2-clients`, which is operator configuration read and validated at
    /// startup. A policy can only allow or deny one of those already-declared
    /// clients, so the guarantee is obtained *structurally* — the deployment
    /// declares, the request proposes, and the broker answers with the declared
    /// entry — instead of by enumeration. Enumeration is the weaker mechanism
    /// here, because a list long enough to be a product is a list nobody
    /// maintains.
    ///
    /// ## Why the audience is a `String` and not an `Authority`
    ///
    /// Because an RFC 8707 resource indicator is a **URI**, not a host:
    /// `https://api.asv.test`, with a scheme and a path. `Authority` exists (D5)
    /// so that an uncanonical audience cannot be constructed, and it does that
    /// for a host. Reusing it for a URI would mean either a new canonicalization
    /// rule inside `Authority` — widening a type whose entire value is that it
    /// means one thing — or a mangled string. The audience is *not*
    /// request-supplied, so it cannot be attacker-chosen here; it is operator
    /// text that the broker compares against what the resource reports, and a
    /// comparison needs no type that forbids construction.
    ///
    /// Keyed by the credential's wire id rather than by the audience, matching
    /// [`Self::Database`], which is addressed by `(name, role)` rather than by
    /// the address it connects to. The authority being delegated is the client
    /// registration; two registrations may legitimately share one audience, and a
    /// policy that cannot tell them apart cannot grant one without the other.
    OAuth2Client {
        /// The vault credential's wire id. The *reference* the request named,
        /// resolved broker-side against the configured registrations — never a
        /// secret and never a token.
        credential: String,
        /// The RFC 8707 resource indicator the operator declared, reported so a
        /// policy author can see it. Carried for the audit trail and for `asv
        /// explain`; it is **not** consulted by `audience_is_approved`, because
        /// this variant is deliberately outside that list.
        audience: String,
        /// The scope the operator registered, as the RFC 6749 §3.3 list it is
        /// written in: space-delimited, order-insensitive, a set.
        ///
        /// **This is the scope the identity call is being made under**, so it
        /// is what a policy can reason about: the engine splits it and hands
        /// Cedar a `Set`, which is what makes `resource.scope.contains("pods:read")
        /// && !resource.scope.contains("pods:delete")` a sentence the schema
        /// accepts. A `String` attribute could not express the second half — see
        /// [`scope_set`] for why substring matching is the wrong answer rather
        /// than a weaker one.
        ///
        /// Never request-supplied, and that is structural rather than
        /// disciplinary: the broker builds this from the registration it holds,
        /// and `authorize_oauth2` passes the *deployment's* string. An agent
        /// cannot ask for a scope, so it cannot ask for a wider one.
        scope: String,
    },
}

/// A scope string as the canonical set RFC 6749 §3.3 defines it.
///
/// `scope` on the wire is a space-delimited **list**, so `read write` and
/// `write read` are the same grant, and `read read` is the same grant as
/// `read`. Three separate questions in this tree need that one answer, and they
/// need it *identically*:
///
/// 1. the issuer, refusing a grant that is not the one it asked for;
/// 2. the broker, comparing what a resource server reports;
/// 3. the policy engine, building the `Set` a Cedar rule tests with `contains`.
///
/// Two spellings of this function is the defect, not a duplication to be tidied:
/// if the issuer sorted and the policy engine did not, a reordering would be an
/// escalation at one end and a clean set at the other, and both would be right
/// about their own input. So there is one definition, here, and the two callers
/// that used to have their own import it.
///
/// Sorted and deduplicated rather than merely split, so the value Cedar
/// receives is canonical: a `Set` whose order depends on how the operator typed
/// the file is a value two operators would spell differently and compare
/// differently, and `contains` is the only operation on it that must agree.
///
/// Whitespace, not `split(' ')`: an operator's YAML or JSON carries the
/// indentation, and a scope parsed into an empty token is a scope token that
/// matches nothing while still being present.
pub fn scope_set(scope: &str) -> Vec<String> {
    let mut parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts.sort();
    parts.dedup();
    parts
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

    #[test]
    fn credential_id_wire_form_is_canonical_and_round_trips() {
        const CANONICAL: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let id = CredentialId::from_wire(CANONICAL).expect("canonical UUID is accepted");
        assert_eq!(id.to_wire(), CANONICAL);

        let uppercase = CANONICAL.to_ascii_uppercase();
        let compact = CANONICAL.replace('-', "");
        let braced = format!("{{{CANONICAL}}}");
        let malformed = "not-a-uuid".to_string();
        for (label, candidate) in [
            ("uppercase", uppercase),
            ("compact", compact),
            ("braced", braced),
            ("malformed", malformed),
        ] {
            let parsed = CredentialId::from_wire(&candidate);
            assert!(
                parsed.is_err(),
                "accepted noncanonical UUID spelling ({label})"
            );
            if let Err(error) = parsed {
                assert!(
                    !error.to_string().contains(&candidate),
                    "parse diagnostics must not echo candidate text ({label})"
                );
            }
        }
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

    // --- CU-1.1 RED: Authority (design v2 D5) and M4-R9 (D6) -----------------

    /// D5: case and one trailing dot are presentation only. The two spellings
    /// below are the same authority, so they must produce equal values —
    /// otherwise an allowlist comparison becomes a spelling contest.
    #[test]
    fn authority_treats_case_and_trailing_dot_as_equivalent() {
        let plain = Authority::canonicalize("api.github.com").expect("valid authority");
        let shouty = Authority::canonicalize("API.GITHUB.COM").expect("valid authority");
        let dotted = Authority::canonicalize("api.github.com.").expect("valid authority");
        assert_eq!(plain, shouty);
        assert_eq!(plain, dotted);
        assert_eq!(plain.as_str(), "api.github.com");
    }

    /// D5 rejection rules. Each input here is a *syntactic* ambiguity or an
    /// unsupported shape, so it must fail construction. A rejected authority is
    /// a runtime deny; an authority that does not exist as a type is a compile
    /// error, and both are the point.
    ///
    /// Note what is deliberately **absent**: an unapproved but well-formed host
    /// like `evil.example`. Canonicalization answers "is this one host
    /// spelling?"; the audience allowlist (design D6, task 1.2) answers "is
    /// this host approved?". Collapsing the two layers here would put a
    /// security decision in a syntax helper.
    #[test]
    fn authority_rejects_every_syntactically_ambiguous_shape() {
        for hostile in [
            "user@evil.example",     // userinfo: a real-looking prefix, different host
            "api.github.com..",      // empty label
            "api%2egithub.com",      // percent-encoding hides the dot
            "apí.github.com",        // non-ASCII: IDNA is unsupported, not guessed
            "api.github.com..evil",  // empty label mid-name
            "api..example",          // empty label
            "-api.github.com",       // label may not start with a hyphen
            "api.github-.com",       // label may not end with a hyphen
            "api_github.com",        // underscore is not a DNS label character
            "[::1]",                 // IPv6 literal, no DNS resolution to pin
            "http://api.github.com", // plaintext scheme
            "api.github.com:443",    // explicit port: the canonical form is bare
            "api.github.com:8443",   // non-default port
            "",                      // empty
            "   ",                   // whitespace only
            " api.github.com",       // leading whitespace
            "api.github.com ",       // trailing whitespace
            ".",                     // root only
        ] {
            assert!(
                Authority::canonicalize(hostile).is_err(),
                "must reject {hostile:?}"
            );
        }
    }

    /// The other half of the D5/D6 split: a well-formed host that nobody
    /// approved must canonicalize cleanly, so the *allowlist* is the only place
    /// that decides whether it is reachable. This test exists to stop a future
    /// "just also check the allowlist here" shortcut from silently collapsing
    /// the two layers.
    #[test]
    fn a_well_formed_unapproved_host_canonicalizes_and_is_not_special_cased() {
        let evil = Authority::canonicalize("evil.example").expect("syntactically valid");
        assert_eq!(evil.as_str(), "evil.example");
        assert_ne!(
            evil,
            Authority::canonicalize("api.github.com").expect("valid"),
            "canonicalization must not decide approval"
        );
    }

    /// A root label cannot be spelled twice, and a suffix trick must not
    /// canonicalize *into* an approved host. The allowlist compares equality,
    /// but the canonical form must at least never be a superstring.
    #[test]
    fn canonical_form_cannot_acquire_an_approved_suffix() {
        let lookalike = Authority::canonicalize("api.github.com.evil.example").expect("valid");
        let approved = Authority::canonicalize("api.github.com").expect("valid");
        assert_ne!(lookalike, approved);
        assert!(
            !approved.as_str().ends_with(lookalike.as_str()),
            "an approved authority must not share a suffix with a lookalike"
        );
    }

    /// D6: the action name is what Cedar matches on, so a mis-spelled action
    /// silently stops matching anything. Every variant must have a stable,
    /// non-empty, snake-dotted name — the regression this test exists to pin
    /// is the catch-all arm that used to collapse non-Git/SSH actions to
    /// "unsupported".
    #[test]
    fn every_action_has_a_stable_non_empty_name() {
        for action in [
            Action::GitFetch,
            Action::GitPush,
            Action::SshConnect,
            Action::HttpRequest,
            Action::PostgresConnect,
            Action::GitHubIssueCreate,
            Action::GitHubIssueRead,
            Action::GitHubReleaseCreate,
        ] {
            let name = action.to_string();
            assert!(!name.is_empty(), "{action:?} has no action name");
            assert!(
                !name.contains("unsupported"),
                "{name:?} is a deny-by-omission"
            );
            assert!(
                name.split('.').count() >= 2,
                "{name:?} must be a dotted action path"
            );
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'_'),
                "{name:?} must be lower-snake, no spaces or capitals"
            );
        }
        assert_eq!(Action::GitHubIssueRead.to_string(), "github.issue.read");
        assert_eq!(Action::GitHubIssueCreate.to_string(), "github.issue.create");
    }

    /// M4-R9: an Api resource carries an already-canonical audience, so the
    /// uncanonical spelling can never be built at all.
    #[test]
    fn api_resource_cannot_carry_an_uncanonical_audience() {
        let audience = Authority::canonicalize("API.GITHUB.COM.").expect("valid");
        let resource = Resource::Api {
            audience: audience.clone(),
        };
        match &resource {
            Resource::Api { audience: held } => assert_eq!(held.as_str(), "api.github.com"),
            other => panic!("expected Api, got {other:?}"),
        }
    }

    /// A surrogate is a handle, not a secret-bearing string. Like every other
    /// identifier it stays a distinct newtype so it cannot be passed where a
    /// `CredentialId` is expected (P7).
    #[test]
    fn surrogate_id_is_distinct_from_credential_id() {
        let surrogate = SurrogateId::new();
        let credential = CredentialId::new();
        assert_ne!(surrogate.to_string(), credential.to_string());
        let _typed: SurrogateId = surrogate;
        let _typed: CredentialId = credential;
    }
}

#[cfg(test)]
mod connect_target_tests {
    use super::*;

    fn target(line: &str) -> Result<ConnectTarget, ConnectTargetError> {
        ConnectTarget::from_request_line(line)
    }

    /// The whole point of the type: the shim and the broker must read the same
    /// destination, and the destination is a *canonical* host.
    #[test]
    fn a_plain_connect_line_yields_a_canonical_host_and_port() {
        let t = target("CONNECT api.example.com:443 HTTP/1.1").expect("parses");
        assert_eq!(t.host(), "api.example.com");
        assert_eq!(t.port(), 443);
        assert_eq!(t.to_string(), "api.example.com:443");
    }

    #[test]
    fn case_and_a_trailing_dot_reach_the_same_destination() {
        let plain = target("CONNECT api.example.com:443 HTTP/1.1").expect("parses");
        for spelling in [
            "CONNECT API.Example.COM:443 HTTP/1.1",
            "CONNECT api.example.com.:443 HTTP/1.1",
            "CONNECT API.EXAMPLE.COM.:443 HTTP/1.1",
        ] {
            let other = target(spelling).expect("parses");
            assert_eq!(other, plain, "{spelling} must reach the same destination");
        }
    }

    /// A host that differs only in case must produce the *same* nonce, or a
    /// proof minted for one spelling is refused for the other and the symptom
    /// is a signature that verifies nowhere.
    #[test]
    fn the_spelling_of_a_host_cannot_change_the_nonce() {
        let a = target("CONNECT API.Example.COM:443 HTTP/1.1").expect("parses");
        let b = target("CONNECT api.example.com:443 HTTP/1.1").expect("parses");
        assert_eq!(a.host(), b.host());
    }

    #[test]
    fn a_request_that_is_not_a_connect_is_refused() {
        for line in [
            "GET / HTTP/1.1",
            "get / HTTP/1.1",
            "POST http://example.com/ HTTP/1.1",
            "",
        ] {
            assert!(
                matches!(target(line), Err(ConnectTargetError::NotConnect { .. })),
                "{line:?} must not name a destination"
            );
        }
    }

    #[test]
    fn a_connect_without_a_usable_port_is_refused() {
        assert!(matches!(
            target("CONNECT api.example.com HTTP/1.1"),
            Err(ConnectTargetError::NoPort { .. })
        ));
        assert!(matches!(
            target("CONNECT api.example.com:https HTTP/1.1"),
            Err(ConnectTargetError::NonNumericPort { .. })
        ));
        assert!(matches!(
            target("CONNECT api.example.com:0 HTTP/1.1"),
            Err(ConnectTargetError::ZeroPort)
        ));
        let too_wide = "CONNECT api.example.com:99999 HTTP/1.1";
        assert!(
            matches!(
                target(too_wide),
                Err(ConnectTargetError::NonNumericPort { .. })
            ),
            "a port that does not fit in u16 is not a port: {too_wide:?}"
        );
    }

    /// The last colon wins, so a host carrying a colon cannot smuggle a port
    /// past the reader. A bracketed IPv6 literal lands here and is refused
    /// rather than half-understood.
    #[test]
    fn a_host_carrying_a_colon_cannot_smuggle_a_port() {
        // `rsplit_once(':')` takes the *last* colon, so this splits into host
        // `api.example.com:443` and port `extra`. The port is rejected first,
        // which is the right order: a non-numeric port is not a host question.
        let smuggled = "CONNECT api.example.com:443:extra HTTP/1.1";
        assert!(
            matches!(
                target(smuggled),
                Err(ConnectTargetError::NonNumericPort { .. })
            ),
            "a host carrying a colon must not smuggle a port past the reader: {smuggled:?}"
        );
        let bracketed = "CONNECT [::1]:443 HTTP/1.1";
        assert!(
            matches!(target(bracketed), Err(ConnectTargetError::Authority(_))),
            "a bracketed literal is refused, not unbracketed: {bracketed:?}"
        );
    }

    #[test]
    fn a_connect_with_no_authority_is_refused() {
        // A bare `CONNECT` with nothing after it. `CONNECT HTTP/1.1` is *not*
        // this case: the next whitespace-separated token is the version, and
        // it is refused as a portless authority, which is a different
        // rejection. The first version of this test assumed otherwise.
        assert!(matches!(
            target("CONNECT"),
            Err(ConnectTargetError::NoAuthority)
        ));
        assert!(matches!(
            target("CONNECT HTTP/1.1"),
            Err(ConnectTargetError::NoPort { .. })
        ));
    }
}
