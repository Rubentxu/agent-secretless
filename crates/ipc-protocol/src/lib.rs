//! UAT-031 — untrusted DTO cannot become a secret-bearing domain type.
//! The evidence is this module's own decoder suite: `unknown_method_is_rejected`,
//! `every_forbidden_method_name_fails_to_decode`, `malformed_input_fails_closed`,
//! `oversized_message_is_rejected_before_parsing` and `metadata_dto_has_no_secret_field`.
//! Versioned broker IPC.
//!
//! M0 Exit requires: "untrusted DTOs cannot deserialize into secret-bearing
//! domain types". This module is where that is enforced, and the enforcement is
//! structural rather than conventional:
//!
//! - Nothing in this crate implements [`serde::Serialize`] for a **secret-bearing
//!   domain type**, because [`asv_domain::SecretBytes`] has no such impl to call.
//!   ADR-0016 added [`OpaqueSecret`], which does serialize, and it is worth being
//!   precise about why that is not the same thing: it is an opaque byte wrapper
//!   owned by this crate, not a domain type, it grants no field-level access, and
//!   its `Debug` redacts. What the M0 requirement protects against — an untrusted
//!   DTO quietly becoming a live `SecretBytes` or a `VaultKey` — is unchanged,
//!   because nothing here deserializes into either.
//! - Requests are an **externally tagged enum of closed shapes**, never a
//!   generic `{"type": "...", "payload": <opaque>}` bag. There is no path by
//!   which a client can name a type the broker has not explicitly allowed
//!   (`docs/03-ARCHITECTURE.md` §6, "explicit method allowlist").
//! - The wire format in M0 is JSON. The spec deliberately leaves CBOR/postcard/
//!   protobuf open pending fuzz ergonomics, so JSON is used here only to get the
//!   boundary right; the decoder is length-bounded and the method set is closed.

use asv_domain::{
    AgentSessionId, ApprovalId, CapabilityId, CredentialId, CredentialKind, Exportability,
};
use asv_policy::{Approval, AuthorizationRequest, ExplainResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Where the broker socket lives, derived from the running user rather than
/// hardcoded. See the module docs for why the rule lives in the protocol crate
/// and why the broker may not pass an override.
pub mod socket;

/// Secret material on the wire, carried by [`Request::CreateCredential`].
///
/// It exists because the alternative was worse, and the reasoning belongs next
/// to the type rather than in a commit message.
///
/// `Request` derives `Debug`, so a bare `Vec<u8>` field would be rendered by
/// any `{:?}` — including the one `assert_eq!` prints when two requests fail
/// to match. A newtype whose `Debug` redacts closes both at once. A
/// hand-written `Debug` for the whole enum would have been the other way to
/// do it: the compiler enforces that match's exhaustiveness, but nothing stops
/// the variant added next month from being formatted.
///
/// The wrapper is deliberately narrow:
///
/// - [`OpaqueSecret::expose`] is the only read path, and is named to be
///   conspicuous in a stack trace.
/// - the buffer is zeroized on drop, so a decoded request that is refused
///   leaves nothing behind.
/// - `Debug` reports the length and nothing else: a length is operationally
///   useful, a secret is not.
///
/// It is not a secret-bearing *domain* type. Nothing deserializes into
/// [`asv_domain::SecretBytes`] or a vault key, which is the property the M0
/// requirement is actually about.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueSecret(zeroize::Zeroizing<Vec<u8>>);

/// Hand-written rather than derived.
///
/// `Zeroizing<Vec<u8>>` has no serde impls unless the whole workspace turns on
/// `zeroize/serde`, and this crate should not decide that for every other
/// consumer of the dependency to get one local newtype onto the wire. The
/// delegation is the whole of it: the bytes in, the same bytes out, and the
/// `Zeroizing` wrapper still owns the buffer's lifetime.
impl Serialize for OpaqueSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpaqueSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Self::new)
    }
}

impl OpaqueSecret {
    /// Wraps `bytes` as secret material, consuming and zeroizing the original.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// The single read path. See this type's documentation for the contract.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for OpaqueSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpaqueSecret(<redacted, {} bytes>)", self.0.len())
    }
}

/// Protocol version. A mismatch is a hard failure, never a downgrade
/// (`docs/03-ARCHITECTURE.md` §6, version negotiation).
///
/// v2 added the M4 semantic surface. v3 adds the M6 PostgreSQL surface
/// (`PostgresConnect`, `PostgresQuery`, `PostgresRevoke`). The bump is
/// required, not cosmetic: the new variants are how an agent reaches a
/// non-HTTP database at all, so a v2 agent talking to a v3 broker would
/// find no way to express the request and would fail with an
/// unknown-method error rather than a version error. Failing at the gate
/// is the point.
/// v4 adds `RegisterSessionKey` (ADR-0019). The bump is required, not
/// cosmetic: it is the only way a client without kernel peer credentials —
/// which is every CONNECT client, measured — can be bound to a session, so
/// a v3 agent talking to a v4 broker would have no way to express the
/// binding and would fail with an unknown-method error rather than a
/// version error. Failing at the gate is the point.
/// A surrogate minted for one route when a session opened.
///
/// `label` is the operator's own name for the credential, taken from the vault
/// metadata rather than from the route file: it is the string that becomes an
/// environment variable the child reads, and the operator's spelling is the one
/// they will recognise when it goes wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSurrogate {
    /// The credential's label, as the operator wrote it.
    pub label: String,
    /// The token the child presents in place of the credential.
    pub token: String,
    /// The host and port this surrogate may be spent on.
    pub destination: String,
    /// How many operations remain.
    pub max_uses: u32,
}

/// The OS identity the broker is running as, and whether it is the one the
/// installation declared.
///
/// Three states, not two, and the third is the point:
///
/// * `declared_uid: None` — nobody declared an identity. This is every
///   development run and every unpackaged deployment, and it is **not**
///   dedicated. The socket is `0600` and the process is undumpable, both real
///   and both stopping at the edge of the invoking user's own processes.
/// * `declared_uid: Some(uid)` where `uid` matches — a broker is running as the
///   identity its installation named, and it refuses to start otherwise.
/// * `declared_uid: Some(other)` — **unreachable on a running broker**, because
///   `identity::check` treats a declaration that is not honoured as always
///   fatal. It is spelled out so that a peer can tell the two `Some` cases
///   apart rather than inferring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerIdentity {
    /// The uid the broker's writes and its socket belong to, from `geteuid()`.
    pub uid: u32,
    /// What the installation declared, if it declared anything.
    pub declared_uid: Option<u32>,
    /// Whether the declared identity is the one in force.
    pub dedicated: bool,
}

impl BrokerIdentity {
    /// The honest construction for a measurement, with `dedicated` derived
    /// rather than passed.
    ///
    /// Taking `dedicated` as an argument would let a caller build a report that
    /// says "dedicated" about a broker that declared a different uid, which is
    /// precisely the claim this field exists to stop being unfalsifiable.
    pub fn measured(uid: u32, declared_uid: Option<u32>) -> Self {
        Self {
            uid,
            declared_uid,
            dedicated: declared_uid == Some(uid),
        }
    }
}

/// Bumped to 8 for `RunIsolated` / `IsolatedResult`.
///
/// A `u16` that only ever goes up, and a bump is a deliberate protocol change
/// rather than a refactor: an old peer cannot read the new field and a new peer
/// must not read an old answer as a missing one, which is what `None` here
/// would mean.
///
/// The bump is not cosmetic. Before it, a client that could not isolate
/// anything had exactly one way to run a tool holding a credential, and it was
/// the unisolated one; a peer speaking protocol 7 does not know this verb
/// exists, and a broker that answered its absence with something else would be
/// inventing an operation it does not have.
/// The protocol version this build speaks.
///
/// **Every request carries it, and it is checked before anything else happens.**
/// The version used to live only on `Ping` and `AgentInfo`, which made the
/// handshake real for those two verbs and advisory for the other twenty-five:
/// a client and a broker could disagree about what `CreateSession` meant and
/// never find out, because nothing compared the two numbers before the broker
/// evaluated a capability. `check_version` was the function that should have
/// closed that and had no production caller at all — only its own tests.
///
/// So the field is on the wire for all twenty-seven variants and the check
/// runs once, ahead of the dispatcher. That is why this is 11 and not 10: a
/// request that decodes is a request that named its version, and a client that
/// does not fails to decode rather than being answered under a reading of the
/// protocol it never agreed to.
pub const PROTOCOL_VERSION: u16 = 11;

/// Hard ceiling on a single inbound message. Bounded allocation is required for
/// any IPC that faces an untrusted peer (`docs/17-IMPLEMENTATION-BOOTSTRAP.md` §9).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Methods this broker exposes in M0.
///
/// The list is intentionally short. `docs/17-IMPLEMENTATION-BOOTSTRAP.md` §4
/// names exactly these, and notably omits every secret-returning method. Adding
/// a variant here is a security-relevant change and must reference an ADR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and version negotiation.
    Ping { protocol: u16 },
    /// Asks the broker to describe itself.
    ///
    /// Added in DX2 because `asv doctor` had two facts it could not report:
    /// whether the running broker disabled `PR_SET_DUMPABLE`, and which
    /// product version it was built as. `Ping` carries a protocol number and
    /// nothing else, so the CLI could only answer "unknown" for both — and
    /// 09-IMPLEMENTATION-GUIDE.md §2 permits widening IPC precisely for "a
    /// fact that the broker is the only authority able to know".
    ///
    /// Read-only, carries no session and no secret, and is answered before
    /// any authorisation decision: a caller that cannot reach the broker at
    /// all is the case this exists to serve, and requiring a session to learn
    /// whether a session is possible would be circular.
    AgentInfo { protocol: u16 },
    /// Opens a bounded agent session.
    CreateSession { protocol: u16, workspace: String },
    /// Binds a public signing key to a live session (ADR-0019).
    ///
    /// The reason this exists is measured, not assumed: `SO_PEERCRED`
    /// returns `pid=0 uid=-1 gid=-1` on a connected `AF_INET` socket, so a
    /// client arriving over TCP — an ordinary HTTP client behind
    /// `HTTPS_PROXY` — carries no kernel identity at all. Without a key
    /// bound to its session, a CONNECT client cannot prove which session it
    /// is, and a surrogate is only redeemable through the session that
    /// minted it, so substitution on that path is impossible.
    ///
    /// The key is public. Binding it proves *ownership* of the session's
    /// signer, not a secret: the private half never leaves the client and
    /// is what makes a later proof unforgeable.
    ///
    /// A session accepts one key, once, and never a different one. That is
    /// the property that stops a second registration from silently
    /// re-pointing an already-issued session at another key.
    RegisterSessionKey {
        protocol: u16,
        session: AgentSessionId,
        public_key_blob: Vec<u8>,
    },
    /// Closes a session and invalidates its grants.
    EndSession {
        protocol: u16,
        session: AgentSessionId,
    },
    /// Returns credential *metadata* only. Never values (ADR-0001).
    ListCredentialMetadata { protocol: u16 },
    /// Runs a registered compatibility worker under the M10 isolation
    /// pipeline (ADR-0008, M10).
    ///
    /// This is the request that makes the isolated runtime reachable, and
    /// every field in it is chosen for what it refuses to carry.
    ///
    /// **There is no program here.** The caller names a *worker*, and the
    /// binary, its arguments, its sandbox and its egress policy come from the
    /// registry the operator built at install time. A request that carried a
    /// program path would be a general "run this with a credential" verb, and
    /// the registry is the thing that makes the set of runnable things a
    /// statement rather than an inventory.
    ///
    /// **There are no secret bytes here.** `credential` is a *reference*: the
    /// broker resolves it inside the spawn, so the value never crosses the
    /// socket, is never in a `Debug` of this request, and never reaches the
    /// caller. The one request that does carry a secret is
    /// `CreateCredential`, and it is the reason this one is not it.
    ///
    /// **The posture is weaker than `asv run` and the response says so.**
    /// ADR-0008: a process that legitimately holds a bearer secret can encode
    /// or transform it, so redaction cannot provide non-disclosure. This is
    /// `ISOLATED_PROCESS_EXPOSURE`, the compatibility fallback for a legacy
    /// tool that cannot use a surrogate — never the strong path.
    RunIsolated {
        protocol: u16,
        /// The session this run is charged to. Required: an isolated worker
        /// that could not be revoked by ending a session would outlive the
        /// authority that authorised it.
        session: AgentSessionId,
        /// Tool identity — the registered worker name.
        worker: String,
        /// Arguments appended after the template's own. Elements, never a
        /// shell string: a caller that could pass `sh -c "..."` would be
        /// asking the broker to honour a command line rather than a program.
        args: Vec<String>,
        /// Credential *reference* to inject, resolved broker-side at spawn.
        credential: Option<String>,
        /// Requested lifetime. The broker clamps it; `None` takes the
        /// runtime's own short default, which is not a value the caller can
        /// raise.
        timeout_ms: Option<u64>,
    },
    /// Plants a new credential in the vault (ADR-0016).
    ///
    /// The only request in this protocol that carries secret material, and it
    /// is the reason the protocol's `Debug` story has to stay as narrow as it
    /// is. Three properties are deliberate:
    ///
    /// - **The broker mints the id.** The caller names the credential; it
    ///   cannot address a record it did not create, and the request cannot be
    ///   shaped to collide with an existing one.
    /// - **The secret is bytes, never a path.** A path would put plaintext on
    ///   disk, and the vault is encrypted at rest; a brief copy in a buffer
    ///   the broker zeroizes at the decode boundary is the smaller exposure.
    /// - **Admission decides whether it happens.** ADR-0015's three
    ///   conditions are evaluated before anything is written, and an agent
    ///   session is refused by the first of them.
    ///
    /// The decode necessarily precedes that decision — the request type is
    /// not knowable without parsing — so a refused caller still causes these
    /// bytes to be materialised briefly in a zeroized buffer. They reach
    /// neither the vault, nor the inventory, nor a response, nor a log.
    CreateCredential {
        protocol: u16,
        label: String,
        kind: CredentialKind,
        provider: String,
        account: String,
        /// The secret. Carried in a redacting wrapper, never a bare `Vec<u8>`:
        /// see [`OpaqueSecret`].
        secret: OpaqueSecret,
    },
    /// Deletes a credential record.
    DeleteCredential { protocol: u16, id: CredentialId },

    /// Doc 04 §10 step 1: does the vault still hold what `adopt` put there?
    ///
    /// This asks about **storage and authority**, never about value. There is
    /// no digest of a credential in this request and none may be added to it:
    /// a digest of one extracted value is an oracle for that value, and an
    /// `_auth` credential is base64 of `user:password`, low-entropy enough to
    /// confirm a guess. `npm.rs` states that three times; this is the fourth
    /// place it is honoured, and the reason the answer below is a set of facts
    /// rather than a comparison.
    ///
    /// **It does not verify the audience binding, and must not be read as
    /// doing so.** The vault's `CredentialMetadata` has no audience field:
    /// `CreateCredential` above carries label, kind, provider, account and the
    /// secret, and nothing else. An audience-bound question could therefore
    /// only be answered from a document the caller supplied, which would make
    /// this the operator attesting their own import — precisely the thing §10
    /// requires somebody else to check before the original is destroyed.
    ///
    /// Putting audience in the inventory is a real change to the credential
    /// record and it has its own place in the plan. Until it lands, this verb
    /// proves storage and says so, and the migration receipt is written to
    /// match: it claims what was proved here and not one word more.
    VerifyStorage { protocol: u16, id: CredentialId },
    /// Evaluates a bounded authorization request without exposing secrets.
    Authorize {
        protocol: u16,
        request: AuthorizationRequest,
        capability: Option<CapabilityId>,
        approval: Option<ApprovalId>,
    },
    /// Explains a decision without consuming grants or approvals.
    ExplainAuthorization {
        protocol: u16,
        request: AuthorizationRequest,
    },
    /// Records an exact human approval for a bounded request.
    SubmitApproval {
        protocol: u16,
        request: AuthorizationRequest,
        ttl_secs: u64,
    },
    /// Mints a short-lived surrogate for an already-authorized session (M4 D3).
    ///
    /// The broker returns a bearer-shaped string the agent may present instead
    /// of a `CredentialId`. Minting is not authorization: it requires a
    /// pinned session, but the *operation* the surrogate will later stand in
    /// for is still evaluated by [`Request::Authorize`] at use time.
    MintSurrogate {
        protocol: u16,
        session: AgentSessionId,
        /// The credential the surrogate will stand in for. The agent never
        /// learns the secret behind this id, and the surrogate is useless
        /// without it.
        credential: CredentialId,
        /// How many operations this surrogate may authorize. Bounded because an
        /// unbounded surrogate is a permanent credential with extra steps.
        max_uses: u32,
        /// Lifetime in seconds, capped by [`MAX_SURROGATE_TTL_SECS`].
        ttl_secs: u64,
    },
    /// Releases a surrogate before its natural expiry.
    RevokeSurrogate {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
    },
    /// Semantic GitHub issue read (M4-R9). Read-only and provider-shaped, so
    /// the policy engine evaluates `github.issue.read` rather than a
    /// catch-all HTTP verb.
    ReadIssue {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        /// `owner/repo`, validated before any byte leaves the process.
        repo: String,
        number: u64,
    },
    /// Semantic GitHub issue creation.
    CreateIssue {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        repo: String,
        title: String,
        body: String,
    },
    /// Semantic GitHub release creation.
    CreateRelease {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        repo: String,
        tag: String,
        name: String,
        body: String,
    },
    /// Semantic OCI registry read (M11-R2.F.3).
    ///
    /// **The `registry` field selects a *declaration*, it is not a
    /// destination.** That distinction is the entire control, and it is worth
    /// stating precisely because the field looks like an agent-chosen host and
    /// is not: the broker resolves it by exact equality against what the
    /// operator declared, and everything downstream — the authority that gets
    /// dialled, the authority Cedar authorizes, the credential that is lent —
    /// comes from that declaration. A registry the deployment did not declare
    /// is refused before a credential is lent and before the policy engine is
    /// consulted.
    ///
    /// The failure this avoids is the one where the field *is* a destination:
    /// then the declaration becomes a filter over hosts the agent picked, and
    /// the operator's rule — `resource.authority == "..." &&
    /// resource.repository == "..."` — silently inverts into "allow everything
    /// except". Same policy text, opposite meaning.
    ///
    /// This is the same bargain `--oauth2-clients` strikes, where the request
    /// names a credential id and the broker answers with the *declared*
    /// registration rather than anything the request supplied.
    ///
    /// The surrogate is present for the reason it is on every other provider
    /// request: a session alone is not a credential, and the one that reaches
    /// the registry is derived from a session-bound token.
    PullManifest {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        /// Selects a declared registry by equality. Never dialed, never
        /// authorized, and never forwarded: only the declaration it resolves to
        /// is.
        registry: String,
        /// The OCI repository, as the registry's own grammar spells it. Parsed
        /// and refused before it becomes part of a URL, in the broker and again
        /// in the connector — neither is the other's job.
        repository: String,
        /// A tag or a digest. **A tag is a mutable name**, and the broker does
        /// not pretend otherwise: it resolves to whatever the registry currently
        /// holds, which is why the manifest that comes back carries the digest
        /// the agent can then pin.
        reference: String,
    },
    /// Semantic OCI registry read, continued (M11-R2.F.3).
    ///
    /// A separate request rather than an offset into `PullManifest` because the
    /// two are authorized against different things: a manifest read is about the
    /// repository, and a blob read is about one content address inside it. An
    /// agent that may read `library/alpine` has not thereby been granted every
    /// digest that repository has ever published, and a policy rule that cannot
    /// tell the two apart cannot say which it meant.
    PullBlob {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        registry: String,
        repository: String,
        /// `sha256:` plus 64 lowercase hex digits, and refused at the edge
        /// rather than normalized: a digest that is *nearly* a digest is a
        /// different content address.
        digest: String,
    },
    /// Semantic OCI registry write, continued (M11-R2.F.4).
    ///
    /// **Every field on a write is agent-supplied and that is the point.** The
    /// body, the reference and the digest all come from the caller, so this is
    /// the request where a mistake is *published* rather than read: a manifest
    /// that goes to `library/alpine:latest` overwrites what an operator's users
    /// will pull next. It is therefore the request that most needs the declared
    /// authority rather than the request's, and the one where
    /// `Action::RegistryPush` earns its existence separately from
    /// `RegistryPull`.
    ///
    /// A separate request from `PushBlob` for the same reason `PullBlob` is
    /// separate from `PullManifest`: the policy resource is the same shape but
    /// the operation is not, and a rule that permits one must not permit the
    /// other.
    PushManifest {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        /// Selects a declared registry by equality. Never dialed.
        registry: String,
        repository: String,
        /// A tag or a digest. **Writing by tag is a choice with consequences**,
        /// and the broker does not soften it: the bytes are refused as
        /// unverifiable, but what a tag now points at is the registry's answer,
        /// and an operator who does not want that writes by digest.
        reference: String,
        /// The manifest bytes, verbatim. Not parsed here on purpose: this
        /// protocol carries bytes, and a broker that re-serialised an image
        /// manifest would be publishing something the caller never signed.
        manifest: Vec<u8>,
    },
    /// Semantic OCI registry blob write (M11-R2.F.4).
    ///
    /// The `digest` is not decorative and not redundant with `bytes`: it is the
    /// address the caller claims for the content, the broker recomputes the
    /// content's address from the bytes and refuses a mismatch, and the registry
    /// is asked to store the bytes *under the caller's address*. A push where
    /// those three can disagree is a push that publishes content under an
    /// address it does not have.
    PushBlob {
        protocol: u16,
        session: AgentSessionId,
        surrogate: String,
        registry: String,
        repository: String,
        digest: String,
        bytes: Vec<u8>,
    },
    /// Asks AWS which identity the request would act as (M11-R2.C.3).
    ///
    /// **This request has no surrogate, and that is the whole difference from
    /// the three above.** A surrogate is a bearer token the agent holds, which
    /// is the right shape for GitHub and exactly the wrong one here: an AWS
    /// session is three values, and handing the agent a session token would be
    /// the weaker property wearing the same label. So the agent names a
    /// *credential* and the broker resolves it, mints a session, signs, and
    /// answers with what the provider said. Nothing the agent can hold here is
    /// a credential, because the response type has no field one could go in.
    ///
    /// **There is no audience, no region and no role in it, and that is
    /// deliberate.** All three are operator configuration, read from the
    /// deployment that owns the credential. A request that named its own
    /// destination would be a request that could move a signed call to wherever
    /// it liked, and SigV4 signs the host — so a request-supplied audience would
    /// make the signature mean nothing.
    AwsCallerIdentity {
        protocol: u16,
        /// The session this call is charged to. Required for the same reason as
        /// every other session-bearing request: an AWS call that could not be
        /// revoked by ending a session would outlive the authority that
        /// authorized it.
        session: AgentSessionId,
        /// A vault credential *reference*, resolved broker-side. Not a secret,
        /// not an access key id, and not a session token — and a reference that
        /// names nothing is refused rather than defaulted, because a default
        /// would be a credential the operator never granted.
        credential: String,
    },
    /// Asks an OAuth2-protected resource which derived identity this request
    /// acts as (M11-R2.B.2).
    ///
    /// **The agent names a credential and nothing else, and that is the whole
    /// claim.** Four things are operator configuration read from
    /// `--oauth2-clients` — the token endpoint, the RFC 8707 audience, the
    /// scope and the resource's own URL — and *none of them has a field here*.
    /// That is deliberate and it is the property, not an omission: a request
    /// that could name its own scope would be a request that named its own
    /// authority, and the escalation refusal in [`asv_domain::Action`] exists
    /// precisely so the broker does not take the agent's word for what it needs.
    ///
    /// Compare `AwsCallerIdentity`, which is silent on all three of its own
    /// un-nameable parameters for the same reason. The two operations are the
    /// same shape because the problem is the same shape: a derived credential
    /// the agent must not hold, and a provider identity it may ask about.
    OAuth2Identity {
        protocol: u16,
        /// The session this call is charged to, for the reason every
        /// session-bearing request carries one: a derived identity the broker
        /// cannot revoke on `EndSession` would outlive the grant.
        session: AgentSessionId,
        /// A vault credential *reference*, resolved broker-side against the
        /// registered clients. Naming one that was never registered is a
        /// refusal, never a default — a default would be a grant nobody made.
        credential: String,
    },
    /// Operator audit query (R9). Refused for agent sessions: audit readers
    /// must not be audit writers, and the human control plane that will own
    /// this channel ships separately. The variant exists on the wire so the
    /// CLI can get a precise refusal instead of an unknown-method error.
    AuditQuery {
        protocol: u16,
        /// Return only records newer than this many seconds.
        since_secs: u64,
    },
    /// M6-R1: open a PostgreSQL session for a typed audience.
    ///
    /// The agent names the audience, the database, and the role. It never
    /// names a credential: the broker decides which vault entry backs this
    /// (database, role) pair, so an agent cannot ask for a role it was not
    /// granted by phrasing the request differently (M6-R3).
    PostgresConnect {
        protocol: u16,
        session: AgentSessionId,
        /// The canonical server name. This is the name the server certificate
        /// must match, so it is not merely a DNS hint.
        host: String,
        /// The address the broker pinned for `host`. Sent explicitly so the
        /// client cannot re-resolve and reach a different address after the
        /// broker's policy check passed.
        host_addr: String,
        port: u16,
        database: String,
        role: String,
    },
    /// M6-R5: run one statement on an open PostgreSQL session.
    ///
    /// Exactly one statement. The broker parses it, derives the
    /// [`asv_domain::Action`], and evaluates policy *before* the statement
    /// reaches the server, so a denied verb never leaves the process.
    PostgresQuery {
        protocol: u16,
        session: AgentSessionId,
        sql: String,
    },
    /// M6-R4: tear a PostgreSQL session down before its natural end.
    ///
    /// Revoke is a separate verb rather than a query because it must succeed
    /// even if policy would deny the current statement, and because the agent
    /// must be able to give up access without knowing a valid statement.
    PostgresRevoke {
        protocol: u16,
        session: AgentSessionId,
    },
}

/// Broker responses. Every variant is safe to return to an agent: none of them
/// can hold secret material, by construction rather than by review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong {
        protocol: u16,
    },
    /// The broker's own description of itself.
    ///
    /// Every field is a fact about the process that answered, observed from
    /// inside it. None of them can be inferred by the caller: `dumpable` is a
    /// `prctl` on *this* pid, and a CLI reading `/proc/<pid>/status` would be
    /// reading a field that another same-uid process can influence, which is
    /// the property the whole broker is built to refuse.
    BrokerInfo {
        protocol: u16,
        product_version: String,
        /// `PR_SET_DUMPABLE` is 0 in the answering process.
        dumpable_disabled: bool,
        /// `PR_SET_NO_NEW_PRIVS` is set.
        no_new_privs: bool,
        /// A live Landlock ruleset is restricting this process.
        landlock_installed: bool,
        /// A live seccomp-bpf deny-list is installed.
        seccomp_installed: bool,
        /// The kernel offers cgroup v2, and a session slice was created.
        cgroup_v2: bool,
        /// Which OS identity the broker is actually running as, and whether that
        /// is the identity the installation declared.
        ///
        /// **This is a measured field and it is the reason it exists on the
        /// wire.** The broker's protections — a `0600` socket, an undumpable
        /// process, Landlock, seccomp — are all real, and all of them live
        /// inside the *invoking user's* boundary, so a second program running as
        /// that user is in the same uid and outside the reach of
        /// `PR_SET_DUMPABLE` as far as this broker's `/proc/<pid>/mem` is
        /// concerned. Before this field that fact lived in a gate-row footnote,
        /// which is the one place nobody reads. `asv doctor` can now answer a
        /// measured question about it, and the honest answer on a development
        /// machine is "not dedicated" rather than "unknown".
        ///
        /// `None` means **this report did not measure an identity**, which is
        /// the same reading as `connect_listen: None` and for the same reason: a
        /// broker assembled without the launch contract genuinely has no
        /// answer, and "not measured" must not be read as "dedicated".
        identity: Option<BrokerIdentity>,
        /// Where this broker's CONNECT listener is bound, as `addr:port`, or
        /// `None` when it is not running.
        ///
        /// Added so `asv run` can start a session's shim without being told
        /// where to point it. `None` is the honest default: a broker with no
        /// listener has no address to report, and a client that guessed one
        /// would forward every CONNECT to something that is not a broker.
        connect_listen: Option<String>,
        /// Capabilities this build actually compiled in, as wire names.
        ///
        /// Derived from the running process rather than from the roadmap, per
        /// R9 in `11-RISKS-OPEN-QUESTIONS.md`: "capabilities derived from the
        /// runtime; not from the roadmap or from types that exist but have no
        /// complete path."
        capabilities: Vec<String>,
    },
    SessionCreated {
        session: AgentSessionId,
        /// One surrogate per authorized route (C2.7-D).
        ///
        /// Minted here rather than on request because the session frontend is
        /// what owns the session's capabilities, and a child that had to ask
        /// for its own token would be a second protocol inside the one the
        /// proxy already needs. Empty is a normal answer: a broker with no route
        /// table mints nothing, and a session in it has nothing to present.
        surrogates: Vec<SessionSurrogate>,
    },
    SessionEnded {
        session: AgentSessionId,
    },
    /// A session's public signing key is bound to it (ADR-0019).
    ///
    /// Carries a public key and nothing secret. The caller is the peer
    /// that created the session, over the same kernel-authenticated socket
    /// that created it, so the binding is to a session that peer owns.
    SessionKeyRegistered {
        session: AgentSessionId,
    },
    CredentialMetadata {
        entries: Vec<CredentialMetadataDto>,
    },
    CredentialDeleted {
        id: CredentialId,
    },
    /// The broker answered [`Request::VerifyStorage`]: it holds this credential
    /// and the calling principal is entitled to read it.
    ///
    /// Every field is something the caller could already see from an inventory
    /// listing. That is the point, not a shortfall: the value of this response
    /// is that the **broker** said it, over the socket, as a peer the broker
    /// admitted — not that the numbers are secret.
    ///
    /// What it does not say, and what nothing downstream may let it imply: that
    /// the stored bytes are the bytes `adopt` imported. No comparison happened
    /// here, because computing one would need a digest of a credential value.
    /// See the request's documentation for why that is refused rather than
    /// deferred.
    StorageVerified {
        id: CredentialId,
        label: String,
        exportability: Exportability,
    },
    /// A credential was planted in the vault and is now mintable.
    ///
    /// Carries the id and the operator's label, never the secret: the caller
    /// supplied it and does not need it echoed, and a response is the one place
    /// an agent is guaranteed to read.
    CredentialCreated {
        id: CredentialId,
        label: String,
    },
    Authorization {
        explanation: ExplainResult,
    },
    ApprovalIssued {
        approval: Approval,
    },
    /// A freshly minted surrogate. This is the only response that ever carries
    /// a credential-shaped string, and it carries a *surrogate*, never a
    /// secret: the broker keeps the real credential in-process.
    SurrogateMinted {
        surrogate: String,
        /// Absolute expiry, as a UNIX timestamp in seconds. Absolute rather
        /// than a duration so a client cannot extend a grant by resetting a
        /// local timer.
        expires_at: u64,
        max_uses: u32,
    },
    SurrogateRevoked {
        surrogate: String,
    },
    /// The three fields M4-R9 promises for a read, and nothing else. Notably
    /// absent: the raw provider body, which could carry anything upstream
    /// chose to add to it.
    IssueRead {
        title: String,
        body: String,
        state: String,
    },
    IssueCreated {
        number: u64,
        url: String,
    },
    ReleaseCreated {
        tag: String,
        url: String,
    },
    /// A manifest, and the digests it names (M11-R2.F.3).
    ///
    /// **The body is base64 of bytes, not text**, because a manifest is JSON
    /// in practice but nothing in the protocol promises that, and a `String`
    /// field would make the connector's own "read it as text and hope" failure
    /// the broker's to make instead of the connector's to refuse. The agent
    /// gets what came off the wire plus the digest it was verified against, and
    /// it can pin the blobs it wants next by that digest.
    ManifestRead {
        /// The manifest as it came off the wire.
        body: Vec<u8>,
        /// The digest the *reference* resolved to, which is what the agent
        /// should pin. A tag read reports the digest the registry gave; it is
        /// the one value here that survives the registry moving the tag.
        digest: String,
        /// The registry's own declared media type, when it declared one.
        media_type: Option<String>,
    },
    /// A blob, its bytes, and the digest they were verified to have.
    ///
    /// The digest is a field and not a return value because "which bytes are
    /// these" is not a question a caller should be able to leave unanswered. The
    /// connector refuses a mismatch and never constructs one of these, so an
    /// agent holding this has bytes that carry the digest it asked for.
    BlobRead {
        bytes: Vec<u8>,
        digest: String,
    },
    /// A blob the registry accepted, under the address it was sent to.
    ///
    /// **The digest is recomputed from the bytes this side sent**, so the
    /// address in this answer is one the broker checked rather than one it
    /// forwarded. It says what was published, not what the registry confirmed
    /// it kept — a registry answering `201` having stored something else is
    /// outside what this protocol can observe without reading it back, and
    /// pretending otherwise would be a stronger claim than the wire supports.
    BlobPushed {
        digest: String,
        bytes: usize,
    },
    /// A manifest the registry accepted.
    ///
    /// `reference` echoes what was written to, because a tag is a mutable name
    /// and the caller should not have to remember which one it sent.
    ManifestPushed {
        reference: String,
        digest: String,
        bytes: usize,
    },
    /// What AWS says the request is acting as, and nothing else (M11-R2.C.3).
    ///
    /// **There is no field here that could hold a credential, and that is the
    /// property rather than a consequence of it.** All three are things AWS
    /// itself prints in CloudTrail: the ARN names the role and the session, the
    /// user id is AWS's own identifier for the assumed identity, and the account
    /// is a twelve-digit number. There is no secret access key, no session
    /// token, and no `OpaqueSecret` wrapper because there is nothing to wrap.
    ///
    /// A refusal does not come back as one of these with empty fields: it comes
    /// back as [`ErrorCode::Denied`] or [`ErrorCode::Upstream`], so an agent can
    /// never mistake "I could not ask" for "I am nobody".
    AwsCallerIdentity {
        /// For example `arn:aws:sts::123456789012:assumed-role/demo/asv-session`.
        arn: String,
        user_id: String,
        account: String,
    },
    /// Which derived OAuth2 identity this request acted as (M11-R2.B.2).
    ///
    /// The exact analogue of the AWS answer above, and the analogy is the point:
    /// both are the strings the *provider itself* prints, both are non-secret by
    /// the provider's own account of them, and neither has a field a credential
    /// could go in. There is no access token here and no client secret, and
    /// there is no `OpaqueSecret` wrapper because there is nothing to wrap.
    ///
    /// ## Why these three fields are checked before they are returned
    ///
    /// `scope` and `audience` are what the *resource* reported, and a resource
    /// will faithfully report whatever the IdP granted — including more than the
    /// operator configured. Relaying that unchecked would mean the operator's
    /// `--oauth2-clients` entry silently stops describing the authority the
    /// broker is actually exercising, which is the escalation M11 exists to
    /// prevent, arrived at through a provider rather than through a request. So
    /// the broker compares both against the deployment and answers
    /// [`ErrorCode::Upstream`] on a mismatch. These two fields are therefore a
    /// *verified* claim about the deployment, not a transcript of the provider.
    ///
    /// A refusal never arrives as one of these with empty fields; it arrives as
    /// [`ErrorCode::Denied`] or [`ErrorCode::Upstream`], so an agent cannot
    /// mistake "I could not ask" for "I have no scopes".
    OAuth2Identity {
        /// The resource the token was accepted by, as the resource spells it.
        resource: String,
        /// The granted scope, verified equal to what the deployment declared.
        scope: String,
        /// The RFC 8707 resource indicator the token was bound to, verified
        /// equal to what the deployment declared.
        audience: String,
    },
    /// Answer to an audit query. Records are metadata-only by construction;
    /// `dropped` counts retention evictions so loss is never silent.
    AuditRecords {
        records: Vec<AuditRecordDto>,
        /// `event_hash` of the newest record, or the genesis hash on an empty
        /// log. A verifier pins the chain to this value.
        chain_head: String,
        dropped: u64,
    },
    /// A PostgreSQL session is open.
    ///
    /// Carries an opaque session handle and the identifiers the broker chose.
    /// No password, no connection string, and no root certificate path: the
    /// agent learns where it is connected and nothing that would let it
    /// authenticate on its own (M6-R2).
    PostgresConnected {
        session: AgentSessionId,
        database: String,
        role: String,
    },
    /// One statement's result.
    ///
    /// `rows` holds the result set as text and `row_count` its length, so a
    /// client can tell an empty result from a failed query. The broker returns
    /// the statement's own output and nothing derived from the credential.
    PostgresResult {
        row_count: usize,
        rows: Vec<String>,
    },
    /// The session was torn down. `backend_terminated` reports whether the
    /// broker observed the server drop the connection, which is the only
    /// evidence that satisfies M6-R4: a broker-side latch would pass the same
    /// test whether or not the socket died.
    PostgresRevoked {
        session: AgentSessionId,
        backend_terminated: bool,
    },
    /// An isolated worker finished. Both streams are the **redacted** bytes
    /// the runtime captured, never the raw pipe, so a worker that echoes its
    /// injected secret does not hand it back through the response.
    ///
    /// `posture` is carried on every run rather than documented once, because
    /// a caller that has to go looking for whether it is on the strong path or
    /// the compatibility path will assume the strong one.
    IsolatedResult {
        worker: String,
        /// The terminal state as the runtime named it: exited, signalled,
        /// timed out, or killed with the tree.
        outcome: String,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration_ms: u64,
        /// Always `ISOLATED_PROCESS_EXPOSURE` (ADR-0008).
        posture: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// Hard ceiling on a surrogate's lifetime, in seconds (M4 D3).
///
/// The agent proposes a TTL and the broker clamps it here. A client that could
/// choose an unbounded TTL would make the whole expiry mechanism advisory, so
/// this constant is not a default the broker falls back to, it is a limit the
/// broker enforces over the client's request.
pub const MAX_SURROGATE_TTL_SECS: u64 = 3600;

/// Hard ceiling on a surrogate's use budget.
///
/// One is the common case and two already covers a retry, so the original
/// ceiling was **8**: a surrogate was minted by an operator, for one
/// operation, and a longer tail was the shape ADR-0011 exists to avoid.
///
/// That model changed under it. `CreateSession` now mints one surrogate per
/// authorized route and hands it to a child that may issue a stream of
/// requests, so a budget of eight is not a backstop — it is the product. A
/// `curl` session gets eight credentialed operations and then every further
/// request is refused as exhausted, which no ordinary client can live with.
///
/// The ceiling follows the broker's own declared intent rather than a number
/// invented here, and `session_mint_survives_the_protocol_ceiling` in
/// `crates/broker/src/lib.rs` fails if the two ever diverge again — silently,
/// through `clamp`, which is how this went unnoticed until a session
/// demonstrated it by completing exactly eight tunnels out of the sixty-four
/// it was asked for.
///
/// **Raised from 32 on a measurement, not on a hunch.** A budget of 32 is a
/// third of a trivial install: `npm install --loglevel=http express` on a
/// throwaway package, 65 packages, makes **93** HTTPS requests. A client would
/// have been refused at request 33 — a third of the way through the smallest
/// workload anyone would call a build. 8192 leaves a session enough authority
/// for a large build and still refuses it rather than becoming unbounded, and
/// the number is a *spend* budget: the bound on how many credentialed
/// operations one session may perform, which is a security boundary and not a
/// throughput tuning knob.
///
/// It is deliberately larger than one tunnel's own `max_requests`, so the
/// session budget is what bounds a session and a single connection is bounded
/// below it. The reverse — a per-tunnel cap tighter than the session ceiling —
/// would mean a tunnel failing for a reason that has nothing to do with the
/// session it belongs to.
///
/// **And that paragraph was reasoning about a number the session did not get.**
/// It says "the session budget is what bounds a session", as though the session
/// minting through `CreateSession` received this ceiling. It did not: that path
/// mints what `SESSION_SURROGATE_MAX_USES` says, and the constant was 32. So the
/// ceiling was raised correctly and the product was still refused at request 33
/// of a measured 93, and the tunnel's own cap of 4096 was a number no connection
/// could ever reach. The ceiling here was never the bound; it was the bound's
/// ceiling. `SESSION_SURROGATE_MAX_USES` is now this constant, and
/// `a_session_surrogate_pays_for_a_workload_that_was_actually_run` in
/// `crates/broker/src/lib.rs` spends the grant so the two cannot drift apart
/// again — a comparison of constants would not have caught it, because 32 was
/// not wrong against this constant.
pub const MAX_SURROGATE_USES: u32 = 8192;

/// Serializable view of credential metadata.
///
/// A DTO, not the domain type, so that the wire shape can evolve independently
/// and so that adding a field to the domain cannot accidentally start
/// transmitting something new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadataDto {
    pub id: Uuid,
    pub label: String,
    pub kind: CredentialKind,
    pub exportability: Exportability,
}

impl From<&asv_domain::CredentialMetadata> for CredentialMetadataDto {
    fn from(m: &asv_domain::CredentialMetadata) -> Self {
        Self {
            id: *m.id.as_uuid(),
            label: m.label.clone(),
            kind: m.kind,
            exportability: m.exportability,
        }
    }
}

/// Wire shape of one audited broker operation (R9).
///
/// Metadata only: method, session id, peer uid, pinning evidence, outcome and
/// the security posture of the handler path. There is no field that can carry
/// a request argument or a secret; that is the shape-level canary guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecordDto {
    pub seq: u64,
    /// Hex hash of the previous record (genesis: 64 zeros).
    pub prev_hash: String,
    /// UNIX seconds.
    pub ts: u64,
    /// sha256 over `seq || prev_hash || ts || canonical event`.
    pub event_hash: String,
    pub event: AuditEventDto,
}

/// What happened, tagged for stable wire evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEventDto {
    /// One authenticated request was handled.
    RequestHandled {
        method: String,
        /// Present only for session-scoped methods.
        session: Option<String>,
        peer_uid: u32,
        /// pidfd pinning evidence ("pidfd-pinned" | "peercred-only").
        pinned: bool,
        /// "ok" or the error code name.
        outcome: String,
        /// Security posture of the handler path.
        posture: String,
    },
    /// M10R-R6: an isolated worker run reached a terminal state —
    /// completed, failed, timed out, or was refused before exec.
    /// Metadata only by construction: every field is a wire name or a
    /// count; there is no field that could carry secret bytes.
    WorkerSpawned {
        /// Registered template name (or the refused name).
        worker: String,
        /// EgressPolicy wire name ("deny" | "allow_list").
        egress: String,
        /// SecretInjectionPlan wire name ("env_var" | "file" | "none").
        injection: String,
        /// Always `ISOLATED_PROCESS_EXPOSURE` for worker runs.
        posture: String,
        /// "ok" | "failed" | "timeout" | "refused" | "error" | "signaled".
        /// `signaled` means the child died from a signal (e.g. SIGSYS under
        /// the seccomp deny-list, or SIGKILL after the timeout grace). It was
        /// missing here while the broker already emitted it, so a consumer
        /// validating against this vocabulary would reject a real record.
        outcome: String,
        /// Child exit code when the child ran and exited; `None` for
        /// signals, timeouts and refusals.
        exit_code: Option<i32>,
        /// Bytes the worker wrote to stdout, including any discarded past the
        /// limit. `None` on paths that never reached a run.
        bytes_stdout: Option<u64>,
        /// Bytes the worker wrote to stderr, including any discarded past the
        /// limit. `None` on paths that never reached a run.
        bytes_stderr: Option<u64>,
        /// True when an output bound stopped the read.
        ///
        /// Carried because `outcome` alone cannot say it: a run capped at the
        /// limit and a run that simply finished are the same process exit, and
        /// a consumer reading only `outcome` would take a truncated prefix for
        /// the whole of the output. Counts, never content.
        output_limit_hit: Option<bool>,
    },
    /// A credential was substituted on the CONNECT path, or refused there
    /// (ADR-0019).
    ///
    /// Its own variant because `RequestHandled` cannot say the thing that
    /// matters here: a substitution is not a verb a client invoked, and
    /// folding it into `RequestHandled` would file it under whatever method
    /// name the relay happened to be standing in for. What an operator needs
    /// to read afterwards is *which destination received a real credential,
    /// on whose authority*.
    ///
    /// Metadata only by construction: an opaque session id, a `host:port`
    /// and a wire name. There is **no field that could hold secret bytes**,
    /// which is the property this record exists to guarantee — a variant with
    /// a spare field would stop being safe the first time someone used it.
    CredentialSubstituted {
        /// The session whose key signed the proof, resolved by signature.
        session: String,
        /// The authorised destination, `host:port`.
        destination: String,
        /// The operation family the credential was spent on, or
        /// `"unresolved"` when the surrogate was refused before the family
        /// was established.
        family: String,
        /// "substituted" or "refused".
        outcome: String,
    },
    /// A CONNECT connection reached a terminal state on the proxy path
    /// (M9 / V1-C2).
    ///
    /// Its own variant because `CredentialSubstituted` records the *credential*
    /// event and this records the *connection*, and an operator debugging a
    /// proxy needs both. A connection refused before any substitution was
    /// attempted produces no `CredentialSubstituted` record at all, so a chain
    /// carrying only that variant shows a gap exactly where the refusal was.
    ///
    /// **`detail` is a class, never the error's own text.** `BridgeError` is
    /// `Display` and several of its variants interpolate bytes the client sent
    /// — `parse_connect_target` builds `Protocol(format!("{authority} has no
    /// port"))` from the request line — so writing the rendered reason into a
    /// hashed, exported chain would let any client place bytes of their
    /// choosing, a secret-shaped string included, into a durable artefact. The
    /// class is derived from the error's kind; the full text stays in the
    /// operator log, which is not the thing that leaves the machine.
    ///
    /// Metadata only by construction: a `host:port` taken from the *parsed*
    /// target rather than the request line, an opaque session id, and two wire
    /// names. There is no field that could hold secret bytes.
    ConnectHandled {
        /// `host:port` from the parsed target, or empty when the client never
        /// said where it was going. Empty is a fact, not a gap, and is why the
        /// field is a `String` with a documented empty value rather than an
        /// `Option` a consumer would have to unwrap.
        destination: String,
        /// The session the proof resolved to, when one was proven.
        session: Option<String>,
        /// "completed" | "refused" | "cancelled".
        outcome: String,
        /// A class ("malformed_request", "destination_not_allowed",
        /// "session_revoked", …), never the error's text.
        detail: String,
    },
}

impl Request {
    /// Stable wire name of this method. Used by the broker's audit records so
    /// an operator can tell which handler produced an entry.
    pub fn method_name(&self) -> &'static str {
        match self {
            Request::Ping { .. } => "ping",
            Request::AgentInfo { .. } => "agent_info",
            Request::CreateSession { .. } => "create_session",
            Request::RegisterSessionKey { .. } => "register_session_key",
            Request::EndSession { .. } => "end_session",
            Request::ListCredentialMetadata { .. } => "list_credential_metadata",
            Request::DeleteCredential { .. } => "delete_credential",
            // Named separately rather than folded into a credential verb: §10
            // step 1 is a gate a human later relies on, and an audit log that
            // called it something else would make the gate untraceable.
            Request::VerifyStorage { .. } => "verify_storage",
            Request::Authorize { .. } => "authorize",
            Request::ExplainAuthorization { .. } => "explain_authorization",
            Request::SubmitApproval { .. } => "submit_approval",
            Request::MintSurrogate { .. } => "mint_surrogate",
            Request::RevokeSurrogate { .. } => "revoke_surrogate",
            Request::ReadIssue { .. } => "read_issue",
            Request::CreateIssue { .. } => "create_issue",
            Request::CreateRelease { .. } => "create_release",
            // The two halves of an OCI pull get their own audit names, because
            // "a pull" is not a question an operator can act on: a repository
            // being read is a policy decision, and one content address inside it
            // being read is a different one.
            Request::PullManifest { .. } => "registry_pull_manifest",
            Request::PullBlob { .. } => "registry_pull_blob",
            Request::PushManifest { .. } => "registry_push_manifest",
            Request::PushBlob { .. } => "registry_push_blob",
            Request::OAuth2Identity { .. } => "oauth2_identity",
            Request::AuditQuery { .. } => "audit_query",
            Request::PostgresConnect { .. } => "postgres_connect",
            Request::PostgresQuery { .. } => "postgres_query",
            Request::PostgresRevoke { .. } => "postgres_revoke",
            Request::CreateCredential { .. } => "create_credential",
            Request::RunIsolated { .. } => "run_isolated",
            Request::AwsCallerIdentity { .. } => "aws_caller_identity",
        }
    }

    /// The protocol version this request declared.
    ///
    /// Total over the enum rather than optional, and that is the point: a
    /// function that could return `None` would be a function whose `None` the
    /// caller has to handle, and the caller that does not handle it is how
    /// twenty-five verbs ended up with no version gate at all. Every arm here
    /// is a compile error if a future variant forgets the field.
    pub fn protocol(&self) -> u16 {
        match self {
            Request::Ping { protocol }
            | Request::AgentInfo { protocol }
            | Request::CreateSession { protocol, .. }
            | Request::RegisterSessionKey { protocol, .. }
            | Request::EndSession { protocol, .. }
            | Request::ListCredentialMetadata { protocol }
            | Request::RunIsolated { protocol, .. }
            | Request::CreateCredential { protocol, .. }
            | Request::DeleteCredential { protocol, .. }
            | Request::VerifyStorage { protocol, .. }
            | Request::Authorize { protocol, .. }
            | Request::ExplainAuthorization { protocol, .. }
            | Request::SubmitApproval { protocol, .. }
            | Request::MintSurrogate { protocol, .. }
            | Request::RevokeSurrogate { protocol, .. }
            | Request::ReadIssue { protocol, .. }
            | Request::CreateIssue { protocol, .. }
            | Request::CreateRelease { protocol, .. }
            | Request::PullManifest { protocol, .. }
            | Request::PullBlob { protocol, .. }
            | Request::PushManifest { protocol, .. }
            | Request::PushBlob { protocol, .. }
            | Request::AwsCallerIdentity { protocol, .. }
            | Request::OAuth2Identity { protocol, .. }
            | Request::AuditQuery { protocol, .. }
            | Request::PostgresConnect { protocol, .. }
            | Request::PostgresQuery { protocol, .. }
            | Request::PostgresRevoke { protocol, .. } => *protocol,
        }
    }
}

/// Stable, non-leaky error codes (`docs/10-CLI-MCP-API.md` §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Peer credentials could not be established.
    Unauthenticated,
    /// Protocol version mismatch.
    VersionMismatch,
    /// Message exceeded `MAX_MESSAGE_BYTES`.
    MessageTooLarge,
    /// The requested method does not exist.
    UnknownMethod,
    /// Policy denied the operation.
    Denied,
    /// The request was well-formed but semantically invalid.
    InvalidRequest,
    /// The surrogate's time window has passed.
    ///
    /// Split from `Denied` for the agent's benefit, not the operator's: "your
    /// token ran out of time" and "your token was never valid" both mean "mint
    /// a new one", but only one of them is worth a bug report. Collapsing them
    /// would make a working integration look broken.
    SurrogateExpired,
    /// The surrogate's use budget is spent.
    ///
    /// Separate from `SurrogateExpired` for the same reason, and with a second
    /// audience: a caller that always exhausts its budget has a budgeting
    /// bug, and the distinct code is what makes that visible.
    SurrogateExhausted,
    /// The provider answered, or failed to, in a way the broker relays.
    ///
    /// Not `Internal`. The broker did its job and the network or the provider
    /// did not, and an agent that cannot tell those apart will retry a
    /// non-retryable failure or file a bug against the broker for a DNS
    /// timeout.
    Upstream,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("message of {size} bytes exceeds the {max} byte limit")]
    MessageTooLarge { size: usize, max: usize },

    #[error("client speaks protocol {client}, broker speaks {broker}")]
    VersionMismatch { client: u16, broker: u16 },

    #[error("malformed request: {0}")]
    Malformed(String),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
}

/// Length-bounded JSON decoder.
///
/// This is the choke point for all untrusted input. It checks the size bound
/// before handing bytes to serde, so a hostile peer cannot make the broker
/// allocate unbounded memory.
pub fn decode_request(input: &[u8]) -> Result<Request, ProtocolError> {
    if input.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            size: input.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let request: Request =
        serde_json::from_slice(input).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    Ok(request)
}

/// Encodes a response with the same size bound, so a response can never grow
/// past what a client agreed to accept.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        serde_json::to_vec(response).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    Ok(bytes)
}

/// Rejects any request whose protocol version the broker does not implement.
/// Rejects any request whose protocol version the broker does not implement.
///
/// Total, and called ahead of the dispatcher rather than inside two arms of it.
/// The previous version matched only `Request::Ping`, so the check was real for
/// one verb and absent for the rest — and had no production caller at all,
/// being exercised only by the tests beside it. A total check that nothing
/// calls is the same hole with better coverage, so the caller is the broker's
/// `handle` and it runs before a single capability is evaluated.
pub fn check_version(request: &Request) -> Result<(), ProtocolError> {
    let client = request.protocol();
    if client != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            client,
            broker: PROTOCOL_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "ASV-CANARY-8d3a5b0c-DO-NOT-LEAK";

    /// M0 Exit: untrusted DTOs cannot become secret-bearing domain types.
    ///
    /// A JSON document that tries to smuggle secret material in must be
    /// rejected as malformed rather than partially accepted.
    #[test]
    fn unknown_method_is_rejected() {
        let payload = br#"{"method":"get_secret","id":"anything"}"#;
        let err = decode_request(payload).expect_err("get_secret must not decode");
        assert!(matches!(err, ProtocolError::Malformed(_)), "got {err:?}");
        assert!(!String::from_utf8_lossy(payload).contains("ok"), "sanity");
    }

    /// The forbidden-method names from `docs/10-CLI-MCP-API.md` §5 must not
    /// resolve to anything in the protocol, by any casing or nesting.
    #[test]
    fn every_forbidden_method_name_fails_to_decode() {
        let forbidden = [
            "get_secret",
            "GetSecret",
            "export_secret_for_agent",
            "get_decrypted_payload",
            "run_arbitrary_command_with_secret",
        ];
        for name in forbidden {
            let payload = format!(r#"{{"method":"{name}"}}"#);
            let result = decode_request(payload.as_bytes());
            assert!(
                result.is_err(),
                "forbidden method {name} unexpectedly decoded: {result:?}"
            );
        }
    }

    /// A canary value placed in any field must never survive into a response.
    #[test]
    fn canary_in_request_never_reaches_a_response() {
        let payload = format!(
            r#"{{"method":"create_session","protocol":{PROTOCOL_VERSION},"workspace":"{CANARY}"}}"#
        );
        let request = decode_request(payload.as_bytes()).expect("valid request");
        let response = match &request {
            Request::CreateSession { .. } => Response::SessionCreated {
                session: AgentSessionId::new(),
                surrogates: Vec::new(),
            },
            other => panic!("unexpected request {other:?}"),
        };
        let encoded = encode_response(&response).expect("encodes");
        let text = String::from_utf8(encoded).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "canary crossed the DTO boundary: {text}"
        );
    }

    /// Size bounds must be enforced before parsing, not after.
    #[test]
    fn oversized_message_is_rejected_before_parsing() {
        let huge = vec![b'a'; MAX_MESSAGE_BYTES + 1];
        let err = decode_request(&huge).expect_err("oversized must be rejected");
        assert!(
            matches!(err, ProtocolError::MessageTooLarge { .. }),
            "got {err:?}"
        );
        // Not a parse error: the bound fired first, which is the point.
        assert!(!matches!(err, ProtocolError::Malformed(_)));
    }

    /// Truncated and garbage input must fail closed, never panic.
    #[test]
    fn malformed_input_fails_closed() {
        for payload in [
            &b""[..],
            &b"{"[..],
            &b"[]"[..],
            &b"null"[..],
            &b"{\"method\":\"ping\""[..],
            &[0xff, 0xfe, 0xfd][..],
        ] {
            assert!(
                decode_request(payload).is_err(),
                "malformed payload unexpectedly accepted: {payload:?}"
            );
        }
    }

    /// Version negotiation is a hard gate with no downgrade path.
    ///
    /// The accepted version is `PROTOCOL_VERSION`, not a literal: pinning the
    /// number here would make every future bump fail this test for a reason
    /// that has nothing to do with negotiation, and the fix would be to
    /// rewrite the test rather than the gate.
    #[test]
    fn version_mismatch_is_rejected() {
        let current = format!(r#"{{"method":"ping","protocol":{PROTOCOL_VERSION}}}"#);
        let ok = decode_request(current.as_bytes()).expect("current version decodes");
        assert!(check_version(&ok).is_ok());

        let old = decode_request(br#"{"method":"ping","protocol":0}"#).expect("decodes");
        let err = check_version(&old).expect_err("v0 must be rejected");
        assert!(
            matches!(
                err,
                ProtocolError::VersionMismatch {
                    client: 0,
                    broker: PROTOCOL_VERSION
                }
            ),
            "got {err:?}"
        );
    }

    /// The metadata DTO is the only credential shape that crosses the wire,
    /// and it has no field capable of carrying material.
    #[test]
    fn metadata_dto_has_no_secret_field() {
        let m = asv_domain::CredentialMetadata::new("github-work", CredentialKind::BearerToken);
        let dto = CredentialMetadataDto::from(&m);
        let json = serde_json::to_string(&dto).expect("dto serializes");
        assert!(json.contains("github-work"));
        assert!(!json.to_lowercase().contains("secret"));
        assert!(!json.to_lowercase().contains("value"));
        assert!(!json.to_lowercase().contains("payload"));
    }

    /// Each version bump must be a hard boundary. If a v2 client could reach
    /// a v3 broker, the failure would surface as a denied call rather than as
    /// a version error, and the cause would be misattributed. The pinned
    /// numbers move on every bump; the property does not.
    #[test]
    fn each_version_bump_is_a_hard_boundary() {
        for old in [1, 2] {
            let request =
                decode_request(format!(r#"{{"method":"ping","protocol":{old}}}"#).as_bytes())
                    .expect("decodes");
            assert!(
                check_version(&request).is_err(),
                "a v{old} client must not be served by a v{PROTOCOL_VERSION} broker"
            );
        }
        let current = decode_request(
            format!(r#"{{"method":"ping","protocol":{PROTOCOL_VERSION}}}"#).as_bytes(),
        )
        .expect("decodes");
        assert!(check_version(&current).is_ok());
    }

    /// Every M4 method must round-trip with its fields intact. A rename or a
    /// dropped field here would silently change the wire contract that the
    /// broker and the agent both compile against.
    #[test]
    fn the_m4_methods_round_trip_on_the_wire() {
        let session = AgentSessionId::new();
        let credential = CredentialId::new();
        for request in [
            Request::MintSurrogate {
                protocol: PROTOCOL_VERSION,
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
            Request::RevokeSurrogate {
                protocol: PROTOCOL_VERSION,
                session,
                surrogate: "asv1_abc".into(),
            },
            Request::ReadIssue {
                protocol: PROTOCOL_VERSION,
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                number: 7,
            },
            Request::CreateIssue {
                protocol: PROTOCOL_VERSION,
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                title: "t".into(),
                body: "b".into(),
            },
            Request::CreateRelease {
                protocol: PROTOCOL_VERSION,
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                tag: "v1".into(),
                name: "n".into(),
                body: "b".into(),
            },
        ] {
            let json = serde_json::to_string(&request).expect("serializes");
            assert!(
                json.len() <= MAX_MESSAGE_BYTES,
                "{json} exceeds the message bound"
            );
            let decoded: Request = serde_json::from_str(&json).expect("round-trips");
            assert_eq!(decoded, request);
        }
    }

    /// Every M6 method must round-trip with its fields intact, for the same
    /// reason the M4 test exists: a renamed or dropped field would silently
    /// change the contract both sides compile against.
    #[test]
    fn the_m6_postgres_methods_round_trip_on_the_wire() {
        let session = AgentSessionId::new();
        for request in [
            Request::PostgresConnect {
                protocol: PROTOCOL_VERSION,
                session,
                host: "pg.local.test".into(),
                host_addr: "127.0.0.1".into(),
                port: 5432,
                database: "app".into(),
                role: "app".into(),
            },
            Request::PostgresQuery {
                protocol: PROTOCOL_VERSION,
                session,
                sql: "select 1".into(),
            },
            Request::PostgresRevoke {
                protocol: PROTOCOL_VERSION,
                session,
            },
        ] {
            let json = serde_json::to_string(&request).expect("serializes");
            assert!(
                json.len() <= MAX_MESSAGE_BYTES,
                "{json} exceeds the message bound"
            );
            let decoded: Request = serde_json::from_str(&json).expect("round-trips");
            assert_eq!(decoded, request);
        }
    }

    /// M6-R2: no PostgreSQL response may carry a credential.
    ///
    /// This walks the variants rather than trusting the doc comment, for the
    /// same reason the M4 test does. The two fields most likely to regress
    /// here are a connection string and a certificate path: both look like
    /// harmless configuration and both can carry enough to authenticate.
    #[test]
    fn m6_responses_carry_no_secret_field() {
        for response in [
            Response::PostgresConnected {
                session: AgentSessionId::new(),
                database: "app".into(),
                role: "app".into(),
            },
            Response::PostgresResult {
                row_count: 1,
                rows: vec!["1".into()],
            },
            Response::PostgresRevoked {
                session: AgentSessionId::new(),
                backend_terminated: true,
            },
        ] {
            let json = serde_json::to_string(&response).expect("serializes");
            let lowered = json.to_lowercase();
            for forbidden in [
                "password",
                "pgpassword",
                "passfile",
                "conninfo",
                "sslrootcert",
                "sslkey",
                "secret",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "{json} leaks a credential-bearing field: {forbidden}"
                );
            }
        }
    }

    /// A response must never be able to carry secret material. This walks the
    /// M4 responses rather than trusting the doc comment on the enum, because
    /// a doc comment is exactly the kind of claim that rots when a variant is
    /// added.
    #[test]
    fn m4_responses_carry_no_secret_field() {
        for response in [
            Response::SurrogateMinted {
                surrogate: "asv1_abc".into(),
                expires_at: 1,
                max_uses: 1,
            },
            Response::SurrogateRevoked {
                surrogate: "asv1_abc".into(),
            },
            Response::IssueRead {
                title: "t".into(),
                body: "b".into(),
                state: "open".into(),
            },
            Response::IssueCreated {
                number: 1,
                url: "u".into(),
            },
            Response::ReleaseCreated {
                tag: "v1".into(),
                url: "u".into(),
            },
            Response::AwsCallerIdentity {
                arn: "arn:aws:sts::123456789012:assumed-role/demo/asv-session".into(),
                user_id: "ARO123EXAMPLE123:asv-session".into(),
                account: "123456789012".into(),
            },
        ] {
            let json = serde_json::to_string(&response).expect("serializes");
            let lowered = json.to_lowercase();
            for forbidden in ["secret", "token", "password", "private_key"] {
                assert!(
                    !lowered.contains(forbidden),
                    "{forbidden} leaked into {json}"
                );
            }
        }
    }

    /// A pinned-in-value test on two constants cannot fail in a useful way: it
    /// either compiles or it does not, so asserting `TTL > 0` here proves
    /// nothing an `if` at the mint site would not. The caps are checked where
    /// they are actually enforced instead, in
    /// `asv_broker::surrogate` (`a_surrogate_dies_exactly_at_its_expiry` and
    /// `a_client_cannot_mint_a_surrogate_that_outlives_the_cap`).
    #[test]
    fn a_mint_request_always_fits_inside_the_wire_bound() {
        // What *is* worth asserting here is the shape: every field a client
        // controls has to be representable without a broker-side truncation
        // surprise, so a full-size request must still be a normal request.
        let request = Request::MintSurrogate {
            protocol: PROTOCOL_VERSION,
            session: AgentSessionId::new(),
            credential: CredentialId::new(),
            max_uses: MAX_SURROGATE_USES,
            ttl_secs: MAX_SURROGATE_TTL_SECS,
        };
        let json = serde_json::to_string(&request).expect("serializes");
        assert!(json.len() < MAX_MESSAGE_BYTES / 2, "{json}");
    }
}
