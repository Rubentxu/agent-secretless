//! Broker request handling.
//!
//! Kept separate from `main.rs` so the authorization-relevant logic is testable
//! without spawning a process. The M0 broker is intentionally thin: it
//! establishes identity, enforces the protocol boundary, and holds session
//! state. Vault access and connectors are M1 and M4.

use asv_connector_http::{validate_repo, AddressPolicy, GithubClient, GithubError, SecretPort};
use asv_connector_pg::{LiveConnectorConfig, PgError, PostgresClient, TlsRoots};
use asv_domain::{
    Action, AgentSessionId, Authority, CredentialClass, CredentialId, CredentialMetadata, Decision,
    OperationFamily, Resource,
};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{AuditEventDto, ErrorCode, Request, Response, PROTOCOL_VERSION};
use asv_policy::{AuthorizationRequest, PolicyContext, PolicyEngine};
// The row renderer is imported from the session module rather than redefined so
// the wire separator is defined in exactly one place and a client-side renderer
// cannot drift from it.
use pg_session::render_row;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub mod admission;
pub mod audit;
pub mod connect_listener;
pub mod connect_routes;
pub mod connect_runtime;
pub mod harden;
pub mod http_frame;
pub mod identity;
pub mod inventory;
pub mod isolated_exec;
pub mod oauth2;
/// The RFC 6749 authorization server the OAuth2 tests run against.
///
/// Feature-gated rather than `#[cfg(test)]` because the assertions that matter
/// live in the integration tests, and a test binary cannot see a module the
/// library only compiled for itself. Off by default: a production broker must
/// not be able to link a server that hands out tokens.
#[cfg(any(test, feature = "test-support"))]
pub mod oauth2_test_support;
pub mod pg_policy;
pub mod pg_session;
pub mod recovery;
pub mod selfreport;
pub mod surrogate;
pub mod tls_bridge;
pub mod vault_port;
pub mod worker;

pub use pg_session::{BorrowedSecret, PgRuntime, PgSessionError, PgSessionMap, StatementOutcome};
pub use surrogate::{
    now_secs, SubstitutionPort, SurrogateError, SurrogateLendError, SurrogateLending,
    SurrogateRegistry,
};
pub use vault_port::{VaultSecretPort, VaultWritePort};

/// In-memory session table. M1 replaces this with persistent, encrypted state;
/// M0 only needs it to prove the lifecycle boundary.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: HashMap<AgentSessionId, SessionRecord>,
}

#[derive(Debug)]
struct SessionRecord {
    workspace: String,
    peer_pid: i32,
    /// Whether the peer's process could be pinned with a pidfd (M4 D4).
    ///
    /// Directed requirement, not a global deny: `main.rs` deliberately makes
    /// an unpinned peer a log-and-continue case, so refusing here would revert
    /// a documented M0 decision. What D4 requires is narrower, and this field
    /// is what makes it enforceable: a surrogate is a credential-shaped token,
    /// so minting one for a process we can only weakly attribute is the case
    /// that actually deserves a refusal.
    pinned: bool,
    /// The session's public signing key, bound once (ADR-0019).
    ///
    /// Public material, so it is not a secret and this is not a second
    /// `SecretPort`. It is here because a CONNECT client has no kernel
    /// identity to check — measured: `SO_PEERCRED` on `AF_INET` returns the
    /// unavailable sentinel — and this key is the only thing that lets the
    /// bridge resolve such a client to a session.
    ///
    /// `None` means no key was ever registered, and the bridge refuses
    /// rather than guessing. Set exactly once: see `register_key`.
    public_key: Option<Vec<u8>>,
    /// Counters this session has already spent, so a captured proof cannot be
    /// presented twice. See [`ReplayWindow`].
    ///
    /// Lives beside the key because the key is what makes the counter
    /// meaningful: a counter with no key behind it authorises nothing, and a
    /// key with no counter behind it accepts a proof forever.
    ///
    /// Inside the record, not beside it, and that is the point.
    ///
    /// `EndSession` removes the record, so the window is freed with it and
    /// there is no second map to keep in step. It also means one lock: the
    /// `Arc<Mutex<SessionStore>>` the port already holds covers the key and the
    /// window together, so there is no lock-ordering law to state and no new
    /// class of deadlock to reason about. An earlier version put the window
    /// behind its own `Mutex` because the trait method could only take
    /// `&self`; the trait was the wrong shape, not the state.
    proof_counters: ReplayWindow,
}

/// The set of counters a session has already spent, held as a sliding window.
///
/// **Why a window and not the highest counter seen.** A strict "reject anything
/// at or below the highest" rule is the textbook version and it is wrong here:
/// two CONNECTs from one session can be in flight at once, so a client that
/// legitimately signs counters 7 and 8 in parallel can have 8 arrive first.
/// A fixed replay window: one highest counter and a bitmap of what has been
/// spent below it.
///
/// **Why a bitmap and not a set of spent counters.** A set grows for the life
/// of a session, and the counters are attacker-supplied numbers, so an
/// unbounded set is a memory-growth lever handed to anyone who can complete a
/// proof. A `u128` of bits is sixteen bytes per session, fixed, with no
/// allocation on the hot path and no pruning loop — and "is this counter
/// already spent" becomes a shift and a mask rather than a tree walk.
///
/// **Why a window and not the highest counter seen.** The strict rule —
/// refuse anything at or below the highest — refuses 7 when 8 landed first,
/// which a client issuing two CONNECTs concurrently produces legitimately.
/// That is a liveness bug wearing a security costume, and one the honest
/// client cannot distinguish from an attack. The bitmap remembers a bounded
/// run below the highest, so an out-of-order arrival inside the window is
/// recognised as a replay and an arrival outside it is refused as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayWindow {
    /// The largest counter accepted so far. `None` until the first proof.
    ///
    /// An `Option` rather than a sentinel like `u64::MAX`: the first version
    /// used a sentinel, and the age of the first counter came out as
    /// `u64::MAX - counter` — far older than the window — so every session's
    /// *first* proof was refused as stale. Five tests caught it. The sentinel
    /// saved eight bytes and cost the whole property.
    highest: Option<u64>,
    /// Bit `i` set means counter `highest - 1 - i` has been spent.
    ///
    /// Bit 0 is therefore the counter just below the highest, and the bitmap
    /// is indexed from the newest, not the oldest, so advancing `highest` is a
    /// shift rather than a rebuild.
    seen: u128,
}

impl ReplayWindow {
    /// How many spent counters below the highest are remembered.
    ///
    /// A client with N CONNECTs in flight is out of order by at most N
    /// counters, so the window only has to exceed the worst plausible spread.
    /// 128 is generous for a path where each tunnel costs a TLS handshake, and
    /// it is exactly the width of the bitmap, so there is no tuning knob: the
    /// memory and the policy are the same number.
    const CAPACITY: u32 = 128;

    /// A window that has never seen a counter. `u64::MAX` is unreachable as a
    /// real counter in any session that has not already accepted `u64::MAX`
    /// proofs, and the first `accept` overwrites it.
    const EMPTY: Self = Self {
        highest: None,
        seen: 0,
    };

    /// Records `counter` as spent and reports whether it was fresh.
    ///
    /// `false` means this counter is a replay or is too old to distinguish
    /// from one. Call this **after** the signature has verified and never
    /// before: consuming a counter for a proof that did not verify would let
    /// anyone who cannot sign walk the session's counters forward until the
    /// honest client's real counter looked stale — a denial delivered by a
    /// party that never proved anything.
    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            return true;
        };
        if counter > highest {
            // Advancing shifts the window: everything the bitmap remembered
            // moves one slot further from the new highest, and the old highest
            // itself becomes spent at bit `shift - 1`.
            //
            // **That index is the whole bug this line used to have.** Bit `i`
            // means `highest - 1 - i`, so the previous highest — which has just
            // been spent, and which is `counter - shift` — lands at
            // `counter - 1 - i`, i.e. `i = shift - 1`. Marking bit 0 instead is
            // only right when `shift` is 1, where the two expressions coincide.
            //
            // With a shift of two, bit 0 names `counter - 1`: a counter that
            // has never been presented, and which the next honest client to
            // use it is refused as a replay. Measured against the real broker,
            // 64 concurrent CONNECTs from one session lost 17 legitimate
            // proofs exactly this way — a liveness bug in security machinery,
            // invisible to a test that only ever tried one counter out of order.
            let shift = (counter - highest) as u32;
            self.seen = if shift >= Self::CAPACITY {
                0
            } else {
                (self.seen << shift) | (1u128 << (shift - 1))
            };
            self.highest = Some(counter);
            return true;
        }
        let age = highest - counter;
        if age == 0 {
            // The highest counter has, by construction, already been spent:
            // accepting it is what moved `highest` here.
            return false;
        }
        if age > Self::CAPACITY as u64 {
            // Older than the bitmap reaches. Refused rather than accepted.
            //
            // The first version of this window *accepted* a stale counter, on
            // the reasoning that an honest client cannot be that far behind.
            // That reasoning is about the honest client, and the caller is
            // precisely the thing that is not assumed honest: an attacker
            // replaying an old captured proof presents exactly such a counter.
            return false;
        }
        let bit = 1u128 << (age - 1);
        if self.seen & bit != 0 {
            // Already spent: this exact counter is being presented twice.
            return false;
        }
        // Inside the window, never seen: legitimately out of order.
        self.seen |= bit;
        true
    }
}

/// Why a key registration was refused.
///
/// The variants are distinct because an operator reading the audit log has
/// to tell "you are not the owner of this session" apart from "this
/// session already has a key" — the first is an attack, the second is a
/// bug, and a single `Denied` would erase that difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyRegistrationError {
    /// No such session, or the caller does not own it.
    #[error("not the owner of this session")]
    NotOwner,
    /// The session already has a key bound.
    ///
    /// Re-registration is refused rather than overwritten so a second
    /// registration cannot re-point a live session at a key the broker has
    /// already issued proofs against.
    #[error("session already has a key bound")]
    AlreadyRegistered,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a session bound to the calling peer's PID.
    pub fn create(&mut self, workspace: String, peer: &WorkloadIdentity) -> AgentSessionId {
        let id = AgentSessionId::new();
        self.sessions.insert(
            id,
            SessionRecord {
                workspace,
                peer_pid: peer.credentials.pid,
                pinned: peer.is_pidfd_pinned(),
                public_key: None,
                proof_counters: ReplayWindow::EMPTY,
            },
        );
        id
    }

    /// Binds a public signing key to a session the caller owns (ADR-0019).
    ///
    /// The ownership check is the same one every other session-scoped verb
    /// makes, and it runs first: a caller that does not own the session
    /// must not be able to bind a key to it, because a key it controls is a
    /// key the bridge will later accept proofs from.
    ///
    /// The blob is stored verbatim. It is not validated here on purpose —
    /// this method answers "does this caller own this session, and has this
    /// session already answered", and mixing in a parse would make a
    /// malformed blob look like an ownership problem. A blob that does not
    /// verify against anything simply never resolves a proof.
    pub fn register_key(
        &mut self,
        id: AgentSessionId,
        peer: &WorkloadIdentity,
        public_key_blob: Vec<u8>,
    ) -> Result<(), KeyRegistrationError> {
        let Some(record) = self.sessions.get_mut(&id) else {
            return Err(KeyRegistrationError::NotOwner);
        };
        if record.peer_pid != peer.credentials.pid {
            return Err(KeyRegistrationError::NotOwner);
        }
        if record.public_key.is_some() {
            return Err(KeyRegistrationError::AlreadyRegistered);
        }
        record.public_key = Some(public_key_blob);
        Ok(())
    }

    /// The key bound to a session, if it has one.
    pub fn public_key_of(&self, id: AgentSessionId) -> Option<&[u8]> {
        self.sessions
            .get(&id)
            .and_then(|record| record.public_key.as_deref())
    }

    /// Whether the session's peer was pidfd-pinned when it was opened (M4 D4).
    ///
    /// Recorded at creation rather than queried later: pinning is evidence
    /// about the connection that opened the session, and a later query would
    /// describe a different moment. A session opened unpinned stays unpinned,
    /// which is the conservative direction.
    pub fn is_pinned(&self, id: AgentSessionId) -> bool {
        self.sessions.get(&id).is_some_and(|record| record.pinned)
    }

    /// Returns the workspace a session was opened against.
    pub fn workspace_of(&self, id: AgentSessionId) -> Option<&str> {
        self.sessions.get(&id).map(|r| r.workspace.as_str())
    }
    /// Returns the PID that opened a session.
    ///
    /// M1 uses this to bind a session to the launching process, and M7 uses it
    /// to correlate a session with cgroup evidence. Reading it here keeps the
    /// field honest instead of a placeholder waiting for a future milestone.
    pub fn peer_pid_of(&self, id: AgentSessionId) -> Option<i32> {
        self.sessions.get(&id).map(|r| r.peer_pid)
    }

    pub fn belongs_to(&self, id: AgentSessionId, peer: &WorkloadIdentity) -> bool {
        self.sessions
            .get(&id)
            .map(|record| record.peer_pid == peer.credentials.pid)
            .unwrap_or(false)
    }

    /// Ends a session. Returns whether it existed, so a caller can distinguish
    /// "revoked" from "never existed" instead of silently succeeding.
    pub fn end(&mut self, id: AgentSessionId) -> bool {
        self.sessions.remove(&id).is_some()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Count of live sessions whose peer was pidfd-pinned at creation.
    ///
    /// This is the UAT-030 zero-live-pin counter. R3 ("PID reuse mitigated
    /// with pidfd/launch record") requires that a broker holding a pin for a
    /// peer cannot outlive the session the pin is bound to: every pin must
    /// releases when the session ends. `pin_count` is the observable
    /// surface that makes that property testable from outside the crate.
    pub fn pin_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|record| record.pinned)
            .count()
    }
}

/// Resolves a CONNECT client's session proof (ADR-0019).
///
/// This is the piece that makes a client with no kernel identity — an ordinary
/// `HTTPS_PROXY` CLI — attributable to a session. Measured, not assumed:
/// `SO_PEERCRED` on a connected `AF_INET` socket returns the unavailable
/// sentinel (`pid=0 uid=-1 gid=-1`), so there is nothing else to check.
///
/// Two independent layers, and the second is the one that carries the
/// property:
///
/// 1. the presented blob **selects** a candidate — the session that
///    registered exactly those key bytes;
/// 2. the signature over the nonce is verified against **that session's
///    registered key**, never against the bytes the client presented.
///
/// Layer 1 alone would be an assertion: any client that learned another
/// session's public blob could claim it. The blobs are public by
/// construction — the agent hands them to `ssh-add -L` — so "can I present
/// this blob?" is a question with no security content, and only layer 2
/// turns it into a fact.
///
/// The cost of layer 1 is a linear scan of the live session table. That is
/// deliberate: an index keyed on the blob would be a second place to keep
/// session keys, and the table is bounded by concurrent sessions, not by
/// anything an attacker chooses.
/// Why a session proof was refused.
///
/// `Err` rather than `None`, and the variants are distinct for the same
/// reason the key-registration ones are: whoever is refused has to be able to
/// tell "that was a replay" from "that was too old" from "you are not you",
/// because those three call for completely different responses. A single
/// `None` collapses a client's counter bug and an attacker's captured proof
/// into the same silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRejection {
    /// No registered key matches the presented blob, or the signature does not
    /// verify against the key the broker did register.
    NoSuchSession,
    /// This counter has already been spent: the proof is a replay.
    Replayed,
    /// This counter is older than the window reaches, so it can no longer be
    /// told apart from a replay and is refused.
    TooOld,
}

impl SessionStore {
    /// Decides whether `proof` authorises `target`, and spends its counter.
    ///
    /// One operation on purpose. Deriving the nonce, choosing the key to
    /// verify against, and consuming the counter are three decisions that
    /// only mean anything together, and splitting them across a caller and a
    /// resolver is how a future caller ends up verifying a proof against the
    /// wrong nonce. The first version of this took `(key, nonce, signature)`
    /// and trusted the caller to have built the nonce correctly — and a test
    /// written against that boundary failed to fail, because the resolver
    /// verifies the bytes it is handed and has no idea what they were *for*.
    ///
    /// `target` is a parameter rather than something recovered from the nonce
    /// for the same reason: the caller cannot supply a nonce, so it cannot
    /// supply a nonce for the wrong destination.
    pub fn authenticate(
        &mut self,
        proof: &crate::tls_bridge::SessionProof,
        target: &crate::tls_bridge::AuthorityEndpoint,
    ) -> Result<AgentSessionId, ProofRejection> {
        let nonce = crate::tls_bridge::proof_nonce(&proof.key, target, proof.counter);

        // Find the session this proof is for. Identity is decided here and
        // nowhere else, and never against a key the client chose.
        let (id, registered) = self
            .sessions
            .iter()
            .find_map(|(id, record)| {
                let registered = record.public_key.as_deref()?;
                // The comparison is defence in depth, not the control: the
                // signature is verified against each session's *own* key, so a
                // stranger's blob fails everywhere. A falsification run
                // confirmed it by removing this line and watching the suite
                // stay green. It stays because it makes the intent legible and
                // because skipping candidates is less work than verifying
                // every one — not on a claim that it decides anything.
                if registered != proof.key {
                    return None;
                }
                Some((*id, registered.to_vec()))
            })
            .ok_or(ProofRejection::NoSuchSession)?;

        if !asv_ssh_agent::verify_proof(&registered, &nonce, &proof.signature) {
            return Err(ProofRejection::NoSuchSession);
        }

        // Verify first, spend second. The ordering is load-bearing: a proof
        // that does not verify must never reach the window, or anyone who
        // cannot sign could walk this session's counters forward until the
        // honest client's real counter looked stale.
        let record = self
            .sessions
            .get_mut(&id)
            .ok_or(ProofRejection::NoSuchSession)?;
        let fresh = record.proof_counters.accept(proof.counter);
        if !fresh {
            // Distinguish "already spent" from "too old to tell", because the
            // first is a replay and the second is a client that has fallen
            // behind, and a client needs to be able to tell them apart.
            let age = record
                .proof_counters
                .highest
                .unwrap_or(0)
                .saturating_sub(proof.counter);
            return Err(if age > ReplayWindow::CAPACITY as u64 {
                ProofRejection::TooOld
            } else {
                ProofRejection::Replayed
            });
        }
        Ok(id)
    }
}

/// One destination a deployment has declared it will lend a database
/// credential to (H5).
///
/// Both halves are here because they are one decision. An allowlist keyed on
/// the host alone still lets a request keep the declared name and swap the
/// address the broker dials, so the credential is lent to the attacker with the
/// right name attached — and the TLS server name, which is what the certificate
/// is checked against, is itself a function of the destination.
///
/// `host` is stored already canonicalised, so a comparison against it cannot be
/// defeated by a spelling that only looks like the declared one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgDestination {
    /// The canonical name the server certificate must match.
    pub host: Authority,
    /// The literal address the broker will dial.
    pub addr: IpAddr,
}

impl PgDestination {
    /// Declares a destination, canonicalising the host.
    ///
    /// Returns the `AuthorityError` rather than panicking: a deployment with a
    /// typo in its configuration should fail to start loudly, not at the first
    /// connect attempt, and the caller decides how loudly.
    pub fn new(host: &str, addr: IpAddr) -> Result<Self, asv_domain::AuthorityError> {
        Ok(Self {
            host: Authority::canonicalize(host)?,
            addr,
        })
    }
}

/// Builds the GitHub client for one operation.
///
/// Exists as a trait for the same reason [`vault_port::VaultSecretPort`] lives
/// on this side of the boundary: the broker is the only crate that may hold
/// both a secret port and a connector, and it is also the only crate that can
/// be pointed at a fake origin in a test. Injecting the factory means the
/// production path and the test path run the *same* authorisation, redeeming
/// and response-shaping code, and the only thing a test substitutes is where
/// the bytes go.
pub trait ConnectorFactory {
    /// Builds a client for `audience` that lends from `secrets`.
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError>;

    /// The roots a live PostgreSQL connection should trust.
    ///
    /// A method on the trait rather than a field read through a downcast,
    /// because a trust decision that only the concrete production type can
    /// answer is a trust decision the rest of the broker cannot see. Every
    /// factory answers it, and the default is the platform store.
    fn pg_roots(&self) -> TlsRoots {
        TlsRoots::system()
    }

    /// The name a live PostgreSQL certificate must match.
    ///
    /// `None` means the request's own `host` is used. A factory that pins the
    /// name its certificates are issued for answers `Some`, and that answer
    /// wins: a request that names a different host must not be able to move
    /// the certificate check to a name of its choosing.
    ///
    /// On the trait for the same reason as [`Self::pg_roots`]. A trust anchor
    /// that only the production type can express is a trust anchor the rest of
    /// the broker cannot see, and the certificate name is half of the same
    /// decision.
    fn pg_server_name(&self) -> Option<String> {
        None
    }

    /// The destinations this broker will lend a database credential to. Empty
    /// refuses every connect (H5).
    ///
    /// The default is empty rather than "whatever the request says", and that
    /// is the whole point of the method. `PostgresConnect` carries `host` and
    /// `host_addr` from the agent; the credential is looked up by
    /// `(database, role)`; the connector authorises on `(database, role)`; and
    /// `Resource::Database` has no destination in it. Before this, an operator
    /// who granted `postgres_read` on `app`/`readonly` had granted it on
    /// whatever host the agent then named, and the broker dialled it. The
    /// product's central claim is that the broker decides where a credential
    /// goes, and a destination the agent picked is not that.
    ///
    /// A deployment declares its destinations, a request proposes one, and the
    /// broker answers with the *declared* entry — so the certificate name and
    /// the dialled address are the ones the deployment wrote down rather than
    /// the ones the request supplied. Mirrors `ALLOWED_AUDIENCES` in the policy
    /// crate, which is the same control for the GitHub audience.
    fn pg_destinations(&self) -> &[PgDestination] {
        &[]
    }

    /// Builds a PostgreSQL client for the requested audience, database,
    /// and role. The factory does not authorise the (database, role)
    /// pair; the connector does, before any I/O (M6-R3).
    ///
    /// The default implementation refuses every audience, because a
    /// factory with no way to reach a server cannot honestly claim to
    /// have connected. [`LiveConnectorFactory`] overrides it with the
    /// real transport; tests override it with one pointed at `fake_pg`.
    fn postgres(
        &self,
        _audience: Authority,
        _database: String,
        _role: String,
        _secrets: Arc<dyn SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Err(PgError::UnsupportedInThisBuild)
    }
}

/// The production factory: real DNS, real TLS, public addresses only.
#[derive(Debug, Clone, Default)]
pub struct LiveConnectorFactory {
    /// The roots a live PostgreSQL connection trusts.
    ///
    /// `None` is the platform store, which is the right default for a public
    /// database. A deployment that issues its own certificates supplies the
    /// root explicitly rather than having the connector look for one, because a
    /// connector that goes looking for a trust anchor is a connector whose trust
    /// decision nobody wrote down.
    pub roots: Option<TlsRoots>,
    /// The destinations this deployment will lend a database credential to
    /// (H5).
    ///
    /// Empty is the default and refuses every `PostgresConnect`, which is the
    /// fail-closed reading: a deployment that has not said where it lends is
    /// not a deployment that gets to lend wherever it is asked. A request
    /// proposing a destination is matched against this list, and the *declared*
    /// entry is what the broker uses.
    pub destinations: Vec<PgDestination>,
    /// The name a certificate must match, when the factory has one.
    ///
    /// Superseded for the PostgreSQL path by [`Self::destinations`], which
    /// carries the name together with the address it belongs to. Kept because
    /// the trust decision is still worth being able to state on its own, and
    /// because a factory with a name and no destination cannot reach the
    /// connector at all — the two are now required together, and a test that
    /// set only this one would have been a configuration that silently did
    /// nothing.
    ///
    /// This used to be a public field that nothing read: `postgres_connect`
    /// took the name from the request every time, so a deployment that
    /// configured a different name here got the request's name anyway. A test
    /// that set both to the same value could not tell. It is read now, and
    /// `a_factory_name_overrides_the_request_host` is what keeps it honest.
    pub server_name: Option<String>,
}

impl ConnectorFactory for LiveConnectorFactory {
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError> {
        // 443 is GitHub's HTTPS port, stated here rather than inherited from a
        // config value the caller does not control.
        Ok(GithubClient::new(
            audience,
            443,
            AddressPolicy::default(),
            secrets,
        ))
    }

    /// Builds a real client, refusing an audience this factory cannot reach.
    ///
    /// Two refusals, and the difference between them is the point. An
    /// authority that is not a `host:port` is a malformed *request* and is
    /// reported as one. An authority that parses but names no address we can
    /// connect to is a *reachability* failure, and it is `UnsupportedInThisBuild`
    /// rather than a denial, because nothing about it is the agent's fault.
    ///
    /// The returned [`PostgresClient`] carries the authority and the pair the
    /// broker authorised. It does not open a socket: the socket is opened in
    /// [`BrokerState::postgres_connect`], after the session and the pair have
    /// both been checked, so a refused request never reaches a server.
    fn postgres(
        &self,
        audience: Authority,
        database: String,
        role: String,
        _secrets: Arc<dyn SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        // The credential is not taken here. `PostgresClient` never holds a
        // password, so the value the agent could influence has no field to
        // land in. The password is lent later, for the connect call only, and
        // is gone before the next request is dispatched.
        if database.is_empty() || role.is_empty() {
            return Err(PgError::InvalidAudience(
                "a database and a role are both required".into(),
            ));
        }
        Ok(PostgresClient::new(audience, database, role))
    }

    /// The roots this factory was configured with, or the platform store.
    fn pg_roots(&self) -> TlsRoots {
        self.roots.clone().unwrap_or_else(TlsRoots::system)
    }

    /// The pinned certificate name, when the deployment configured one.
    fn pg_server_name(&self) -> Option<String> {
        self.server_name.clone()
    }

    fn pg_destinations(&self) -> &[PgDestination] {
        &self.destinations
    }
}

/// Broker-side state. M0 has no vault, so credential metadata is an in-memory
/// list seeded by tests; M1 makes it encrypted and persistent.
pub struct BrokerState {
    /// The agent sessions, shared with the CONNECT listener.
    ///
    /// `Arc<Mutex<…>>` for the same reason `surrogates` is: the listener
    /// resolves a CONNECT proof against this store, and a second store would
    /// answer "no such session" for every session the socket path had just
    /// opened. The first version of the wiring handed the listener a fresh
    /// `SessionStore::new()`, which compiled, bound, served and refused
    /// everything — a proxy that looks alive and can never establish a tunnel.
    pub sessions: Arc<Mutex<SessionStore>>,
    pub credentials: Vec<CredentialMetadata>,
    pub policy: PolicyEngine,
    /// M4: the tokens an agent holds instead of credentials (D3).
    ///
    /// `Arc<Mutex<…>>` rather than owned, and the reason is correctness rather
    /// than convenience. `relay_substituted` redeems a surrogate in the *same*
    /// registry `MintSurrogate` mints into, so the CONNECT listener and this
    /// socket path must not hold two registries: a token minted over the socket
    /// would simply be unknown to the CONNECT path, and the product would fail
    /// in a way no test describes and no log line explains.
    ///
    /// The lock is the decision `connect_listener` deliberately declined to
    /// make. It is a coarse one, taken for the length of one registry
    /// operation and never for the length of a tunnel — holding it across a
    /// relay would let one slow client freeze minting and revoking for every
    /// other agent.
    pub surrogates: Arc<Mutex<SurrogateRegistry>>,
    /// M4 CU-2.2: the secret-bearing side of the broker. `None` means no vault
    /// is open, and every semantic operation then refuses. That is the
    /// fail-closed reading: a broker that cannot reach a credential must not
    /// fall back to a direct or anonymous call.
    pub secrets: Option<Arc<dyn SecretPort>>,
    /// M4 CU-2.2: how to reach GitHub. Injected so a test can point the very
    /// same authorisation path at a local origin.
    pub connectors: Box<dyn ConnectorFactory>,
    /// M6: the live PostgreSQL sessions the broker holds open.
    ///
    /// Separate from `sessions`, which records *agent* sessions and outlives
    /// them. This map holds a socket, and a socket has to be reachable from the
    /// synchronous `handle` entry point that every request goes through, so the
    /// live session lives behind its own lock rather than in the agent table.
    ///
    /// Keyed by `AgentSessionId` and checked against the peer's pid on every
    /// use, so a second agent cannot name a session it does not own.
    pub postgres: PgSessionMap,
    /// M6: the runtime the live PostgreSQL transport is driven on.
    ///
    /// `None` on a broker that was never given one, and every PostgreSQL
    /// operation then refuses. That is the fail-closed reading, and it is
    /// better than the alternative: a runtime created here would spawn threads
    /// whose lifetime the request path does not control, and a socket outliving
    /// the broker that opened it is a credential outliving its owner.
    pub runtime: Option<PgRuntime>,
    /// R9: tamper-evident log of every handled request. One record per
    /// `handle` call, appended by the public wrapper (not by the inner
    /// dispatcher), so the audit cannot be bypassed by a new variant.
    /// The audit chain, shared with the CONNECT listener.
    ///
    /// `Arc<Mutex<…>>` for the same reason the session store and the surrogate
    /// registry are: a substitution recorded by `relay_substituted` on the
    /// proxy path and one recorded by the socket path have to land in the same
    /// chain, because two chains each verify on their own and say nothing about
    /// what the other did. An operator asking "who spent this credential" would
    /// otherwise have to check two files, and the answer would be whichever one
    /// they happened to open.
    pub audit: Arc<Mutex<audit::AuditLog>>,
    /// The principals enrolled as the human control plane, per ADR-0015.
    ///
    /// Empty by default, and empty is the state every broker on this machine
    /// is actually in. That is deliberate: the three verbs that need this
    /// derive their refusal from the admission verdict rather than asserting
    /// it in a message, and an empty record makes the verdict a denial, so
    /// wiring it in opens nothing.
    pub control_plane: admission::Enrolment,
    /// ADR-0016: the only way a credential enters the vault from a running
    /// broker. `None` means no vault write path is configured and
    /// `CreateCredential` refuses, for the same fail-closed reason `secrets`
    /// defaults to `None` rather than fabricating a port.
    pub vault_writer: Option<Arc<VaultWritePort>>,
    /// DX2: what this process knows about itself, for `Request::AgentInfo`.
    ///
    /// Populated by `main` from the `harden::install` result it already had in
    /// hand. Before this field existed that result was logged and dropped, so
    /// the facts existed for the length of one `tracing::info!` and were gone
    /// afterwards — which is why `asv doctor` had to answer "unknown" for
    /// them. The default is fail-closed rather than optimistic: a broker built
    /// without the harden profile reports the protections as absent, because
    /// a process that did not set them has not got them.
    pub self_report: selfreport::SelfReport,
    /// The CONNECT routes the operator declared, C2.6.
    ///
    /// In state rather than a local in `main`, because `CreateSession` has to
    /// mint one surrogate per route (C2.7-D) and it has no other way to learn
    /// which credentials this broker is willing to tunnel to. Holding the table
    /// here rather than re-reading the file is also what keeps one table: a
    /// second copy parsed from the same path is a second set of answers, and
    /// two answers can differ.
    pub connect_routes: Arc<crate::connect_routes::ConnectRouteSet>,
    /// The signal the CONNECT path cancels tunnels against, C2.8.
    ///
    /// In state rather than a local in `main`, and the reason is not tidiness.
    /// `ShutdownSignal::revoke` is the only thing that tears down an
    /// established tunnel when its session goes away, and for the whole
    /// history of this path it had **no caller outside tests**: the broker
    /// built a signal, handed it to the listener, and had no way to name it
    /// again from the socket handler. Ending a session killed its surrogates —
    /// so no *new* tunnel could be authorised — while every tunnel already
    /// established kept relaying the real credential to its destination for a
    /// session that no longer existed. The session lifetime was advisory for
    /// exactly the case it exists to bound.
    ///
    /// The mechanism was proven and still did not help:
    /// `revoking_an_established_session_tears_down_its_tunnel` cancels a live
    /// tunnel, and it does it by revoking the signal itself, so it passed
    /// against a broker that never revokes anything. Holding the signal here
    /// is what makes the wiring observable at all — see
    /// `connect_session_revocation_wiring.rs`.
    pub shutdown: Arc<crate::connect_listener::ShutdownSignal>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(SessionStore::default())),
            credentials: Vec::new(),
            policy: PolicyEngine::default(),
            surrogates: Arc::new(Mutex::new(SurrogateRegistry::default())),
            // Fail-closed by construction: the only way a semantic operation
            // can run is for something to have opened a vault and said so.
            // There is no `Default` that fabricates a port.
            secrets: None,
            connectors: Box::new(LiveConnectorFactory::default()),
            postgres: PgSessionMap::default(),
            runtime: None,
            audit: Arc::new(Mutex::new(audit::AuditLog::default())),
            control_plane: admission::Enrolment::empty(),
            vault_writer: None,
            self_report: selfreport::SelfReport::default(),
            // Closed by default, the same posture the listener itself ships
            // with: a broker that was given no route file mints nothing, and a
            // session in it has nothing to present.
            connect_routes: Arc::new(crate::connect_routes::ConnectRouteSet::default()),
            // Nothing is stopped and nothing is revoked. A broker that has not
            // been asked to shut down must not behave as though it had, and a
            // default that started revoked would make `EndSession`'s effect
            // unmeasurable — the wiring tests need to see a session go from
            // live to revoked, and a broker born revoked cannot show that.
            shutdown: Arc::new(crate::connect_listener::ShutdownSignal::new()),
        }
    }
}

impl std::fmt::Debug for BrokerState {
    /// Hand-written because the two `dyn` fields are not `Debug`, and deriving
    /// would either fail or force `Debug` onto the traits for no gain.
    ///
    /// What it prints is deliberately thin: whether a vault is open is useful
    /// in a crash report, and what that vault contains is not something a
    /// `Debug` should be in a position to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerState")
            .field("sessions", &self.sessions)
            .field("credentials", &self.credentials.len())
            .field("surrogates", &self.surrogates.lock().ok().map(|r| r.len()))
            .field("vault_open", &self.secrets.is_some())
            .field("postgres_open", &self.postgres.len())
            .finish_non_exhaustive()
    }
}

/// Borrow the surrogate registry inside `handle_inner`, or return the poison
/// response.
///
/// A macro rather than seven hand-written three-line matches, because the
/// alternative is the failure this refactor exists to prevent: one
/// `.lock().unwrap()` added in a hurry by someone who did not read the
/// poisoning note on the accessor.
macro_rules! surrogates {
    ($state:expr) => {
        match $state.surrogates() {
            Ok(guard) => guard,
            Err(poisoned) => return Response::from(poisoned),
        }
    };
}

/// The audit chain, under the same discipline as the registry.
macro_rules! audit_chain {
    ($state:expr) => {
        match $state.audit_chain() {
            Ok(guard) => guard,
            Err(poisoned) => return Response::from(poisoned),
        }
    };
}

/// The session store, under the same discipline as the registry.
macro_rules! sessions {
    ($state:expr) => {
        match $state.sessions_store() {
            Ok(guard) => guard,
            Err(poisoned) => return Response::from(poisoned),
        }
    };
}

/// Handles one authenticated request and audits the outcome (R9).
///
/// `peer` is kernel-attested by the caller before we get here. There is no code
/// path that reaches this function without a `WorkloadIdentity`, which is what
/// makes ADR-0003 structural instead of aspirational.
///
/// The audit append lives in *this* wrapper, not in the inner dispatcher: every
/// existing and future request variant is recorded exactly once, and a new
/// variant cannot forget to audit because the wrapper does not dispatch.
/// Mint one surrogate per authorized route for a session that has just opened.
///
/// This is the hop that makes CONNECT usable by a process that has never heard
/// of Agent Secretless. `SubstitutingHandler` redeems a surrogate per tunnel,
/// so without a token the child is holding, the broker authenticates the
/// session, authorizes the route, terminates TLS — and then refuses to
/// substitute, every time, for a reason that names neither the child nor the
/// route.
///
/// Two refusals are counted as outcomes rather than errors, and the difference
/// matters:
///
/// - A route whose credential is not in this broker's inventory is **skipped**.
///   The vault is the operator's; a route may name a credential they have not
///   stored here, and refusing to open the session would make one stale route
///   cost every session.
/// - A route the *policy* refuses to mint for is a hard error, because the
///   policy is the authority and a silent skip would let an operator read "the
///   session opened" as "every route I declared is in force".
///
/// One credential named by two routes is minted once and reported for both
/// destinations. Two surrogates for one credential would be two budget counters
/// for one secret, which is the confusion the counter was meant to remove.
fn mint_session_surrogates(
    state: &mut BrokerState,
    session: AgentSessionId,
    peer: &WorkloadIdentity,
) -> Vec<asv_ipc_protocol::SessionSurrogate> {
    let routes = state.connect_routes.clone();
    if routes.is_empty() {
        return Vec::new();
    }

    // Minting is a capability grant, so it goes through the same checks the
    // `MintSurrogate` verb applies rather than around them. A session that
    // cannot mint through the socket cannot mint because it opened a session.
    let pinned = state
        .sessions
        .lock()
        .map(|sessions| sessions.is_pinned(session))
        .unwrap_or(false);
    if !pinned {
        tracing::warn!(
            "no surrogates minted: this session is not pidfd-pinned, and minting a \
             credential-shaped token for a weakly attributed process is refused"
        );
        return Vec::new();
    }

    let Ok(mut registry) = state.surrogates.lock() else {
        tracing::error!("the surrogate registry is poisoned; no surrogate minted");
        return Vec::new();
    };

    let mut minted: Vec<asv_ipc_protocol::SessionSurrogate> = Vec::new();
    // One credential named by two routes is minted once. Two surrogates for one
    // secret would be two budget counters for one value, which is the exact
    // confusion the session counter exists to remove.
    let mut spent: Vec<CredentialId> = Vec::new();

    for route in routes.routes() {
        let credential = route.credential();
        if spent.contains(&credential) {
            continue;
        }

        let Some(metadata) = state.credentials.iter().find(|c| c.id == credential) else {
            tracing::warn!(
                destination = %route.endpoint(),
                "route names a credential this broker has not loaded; no surrogate minted"
            );
            continue;
        };

        let class = CredentialClass::from_kind(metadata.kind);
        if let Err(response) = state.authorize_surrogate_mint(session, peer, class) {
            // The policy refused. Say so rather than dropping the route quietly.
            tracing::warn!(
                destination = %route.endpoint(),
                reason = ?response,
                "policy refused to mint for a declared route"
            );
            continue;
        }

        match registry.mint(
            session,
            credential,
            class,
            SESSION_SURROGATE_TTL_SECS,
            SESSION_SURROGATE_MAX_USES,
            now_secs(),
        ) {
            Ok((token, _expires_at, remaining)) => {
                spent.push(credential);
                minted.push(asv_ipc_protocol::SessionSurrogate {
                    label: metadata.label.clone(),
                    token,
                    destination: route.endpoint().to_string(),
                    max_uses: remaining,
                });
            }
            Err(error) => {
                tracing::warn!(destination = %route.endpoint(), ?error, "could not mint");
            }
        }
    }
    minted
}

/// The lifetime of a surrogate minted at session open.
///
/// Bounded, because an unbounded surrogate is a permanent credential with extra
/// steps — the same reasoning `MintSurrogate` documents. The session's own
/// lifetime is the real bound; this is the backstop for a session that outlives
/// the operator's expectation of it.
const SESSION_SURROGATE_TTL_SECS: u64 = 3600;

/// How many operations one session-minted surrogate may authorize.
///
/// This and [`asv_ipc_protocol::MAX_SURROGATE_USES`] are two numbers that used
/// to disagree, and the disagreement was invisible: `SurrogateRegistry::mint`
/// clamps into the protocol's ceiling, so a broker asking for 32 was served 8
/// with no error, no log line, and no test — the wire reported the clamped
/// value honestly, so every reader believed it.
///
/// The cost was that a session could perform **eight** credentialed operations,
/// which is not a backstop but a product limit no ordinary client survives. The
/// concurrency measurement found it: 64 CONNECTs from one session completed
/// exactly eight. `session_mint_survives_the_protocol_ceiling` is the test that
/// makes the two numbers unable to drift apart again.
///
/// **Raising it from 8 to 32 fixed the clamp and not the limit.** The 93-request
/// measurement — the one that says what a client actually spends — was already
/// in the tree, and 32 is a third of it. A trivial `npm install express` died at
/// request 33 with the client's own token refused, which reads as a replay
/// attack or a routing bug and is neither: it is the budget. Nothing in the
/// product could carry 93 requests, so the per-tunnel limit of 4096 was a number
/// no connection could ever reach.
///
/// The grant is now the protocol's own ceiling, and not as a way of saying
/// "unlimited": `MAX_SURROGATE_USES` is already what a session may obtain
/// through `MintSurrogate` over the socket, so this removes a discrepancy
/// between two paths to the same grant rather than opening a new one. What
/// still bounds a session is unchanged and is what always was — its TTL, its
/// own revocability, and `EndSession`, which drops every token it holds.
///
/// `pub(crate)` so `tls_bridge`'s limit tests can compare the tunnel's budget
/// against the one that is actually granted. The comparison spans two modules
/// and a private constant would have left it unwriteable, which is how the
/// previous version ended up checking the wrong ceiling.
pub(crate) const SESSION_SURROGATE_MAX_USES: u32 = asv_ipc_protocol::MAX_SURROGATE_USES;

/// How many operations a session opened through `CreateSession` is granted.
///
/// A function rather than only a constant because the number is already public
/// information — `SessionSurrogate::max_uses` and `SurrogateMinted::max_uses`
/// both report it to the client that asked — and a fact the wire carries is a
/// fact an integration test is entitled to check against. A test that hard-codes
/// the number instead would be asserting its own copy of the policy, which is
/// how the previous version of this assertion came to pin 32 forever.
pub fn session_surrogate_budget() -> u32 {
    SESSION_SURROGATE_MAX_USES
}

pub fn handle(state: &mut BrokerState, peer: &WorkloadIdentity, request: Request) -> Response {
    let response = handle_inner(state, peer, request);

    // The record is metadata-only by construction: `AuditEventDto` has no
    // field that could carry request arguments or secret material, so the
    // canary guarantee does not depend on this call site being careful.
    let outcome = match &response {
        Response::Error { code, .. } => error_code_name(*code),
        _ => "ok".to_string(),
    };
    let event = AuditEventDto::RequestHandled {
        method: request_method_name(state, &response),
        session: None,
        peer_uid: peer.credentials.uid,
        pinned: peer.is_pidfd_pinned(),
        outcome,
        posture: "SERVICE_BROKERED".to_string(),
    };
    let _ = audit_chain!(state).append(event, now_secs());
    response
}

/// Wire name of the method that produced `response`. The request has been
/// consumed by the dispatcher, so the method is recovered from the response
/// shape; unknown shapes (future variants) audit as "other" rather than lying.
fn request_method_name(_state: &BrokerState, response: &Response) -> String {
    match response {
        Response::Pong { .. } => "ping".into(),
        Response::BrokerInfo { .. } => "agent_info".into(),
        Response::SessionCreated { .. } => "create_session".into(),
        Response::SessionEnded { .. } => "end_session".into(),
        Response::SessionKeyRegistered { .. } => "register_session_key".into(),
        Response::CredentialMetadata { .. } => "list_credential_metadata".into(),
        Response::CredentialDeleted { .. } => "delete_credential".into(),
        Response::CredentialCreated { .. } => "create_credential".into(),
        Response::Authorization { .. } => "authorize/explain".into(),
        Response::ApprovalIssued { .. } => "submit_approval".into(),
        Response::SurrogateMinted { .. } => "mint_surrogate".into(),
        Response::SurrogateRevoked { .. } => "revoke_surrogate".into(),
        Response::IssueRead { .. } => "read_issue".into(),
        Response::IssueCreated { .. } => "create_issue".into(),
        Response::ReleaseCreated { .. } => "create_release".into(),
        Response::AuditRecords { .. } => "audit_query".into(),
        Response::PostgresConnected { .. } => "postgres_connect".into(),
        Response::PostgresResult { .. } => "postgres_query".into(),
        Response::PostgresRevoked { .. } => "postgres_revoke".into(),
        Response::Error { .. } => "(error)".into(),
    }
}

/// Stable name of an error code for audit records.
fn error_code_name(code: ErrorCode) -> String {
    let name = match code {
        ErrorCode::Unauthenticated => "UNAUTHENTICATED",
        ErrorCode::VersionMismatch => "VERSION_MISMATCH",
        ErrorCode::MessageTooLarge => "MESSAGE_TOO_LARGE",
        ErrorCode::UnknownMethod => "UNKNOWN_METHOD",
        ErrorCode::Denied => "DENIED",
        ErrorCode::InvalidRequest => "INVALID_REQUEST",
        ErrorCode::SurrogateExpired => "SURROGATE_EXPIRED",
        ErrorCode::SurrogateExhausted => "SURROGATE_EXHAUSTED",
        ErrorCode::Upstream => "UPSTREAM",
    };
    name.to_string()
}

/// The pre-R9 dispatcher. Unchanged in behavior; every request reaches it
/// exactly once, through the auditing wrapper above.
fn handle_inner(state: &mut BrokerState, peer: &WorkloadIdentity, request: Request) -> Response {
    // A connection whose process could not be pinned is still usable, but the
    // weaker evidence is recorded rather than hidden.
    let evidence_note = if peer.is_pidfd_pinned() {
        "pidfd-pinned"
    } else {
        "peercred-only"
    };
    tracing::debug!(%evidence_note, pid = peer.credentials.pid, "authenticated request");

    match request {
        Request::Ping { protocol } | Request::AgentInfo { protocol } => {
            if protocol != PROTOCOL_VERSION {
                return Response::Error {
                    code: ErrorCode::VersionMismatch,
                    message: format!(
                        "client speaks protocol {protocol}, broker speaks {PROTOCOL_VERSION}"
                    ),
                };
            }
            match request {
                Request::AgentInfo { .. } => {
                    let r = &state.self_report;
                    Response::BrokerInfo {
                        protocol: PROTOCOL_VERSION,
                        product_version: r.product_version.clone(),
                        dumpable_disabled: r.dumpable_disabled,
                        no_new_privs: r.no_new_privs,
                        landlock_installed: r.landlock_installed,
                        seccomp_installed: r.seccomp_installed,
                        cgroup_v2: r.cgroup_v2,
                        identity: r.identity,
                        connect_listen: r.connect_listen.clone(),
                        capabilities: r.capabilities.clone(),
                    }
                }
                _ => Response::Pong {
                    protocol: PROTOCOL_VERSION,
                },
            }
        }

        Request::CreateSession { workspace } => {
            let id = sessions!(state).create(workspace, peer);
            Response::SessionCreated {
                session: id,
                surrogates: mint_session_surrogates(state, id, peer),
            }
        }

        Request::RegisterSessionKey {
            session,
            public_key_blob,
        } => {
            // A key is what the bridge will later accept a session proof
            // from, so binding one to a session is a grant of the same
            // weight as the session itself: whoever controls the key controls
            // what the bridge resolves a CONNECT client to. The ownership
            // check is therefore not a formality, and it lives in
            // `register_key` next to the once-only rule so the two cannot
            // drift apart.
            match sessions!(state).register_key(session, peer, public_key_blob) {
                Ok(()) => Response::SessionKeyRegistered { session },
                Err(KeyRegistrationError::NotOwner) => Response::Error {
                    code: ErrorCode::Denied,
                    message: "session key registration refused: not the session owner".into(),
                },
                Err(KeyRegistrationError::AlreadyRegistered) => Response::Error {
                    code: ErrorCode::Denied,
                    message: "session key registration refused: already registered".into(),
                },
            }
        }

        Request::EndSession { session } => {
            // Ending a session is not the requesting peer's decision alone.
            // `EndSession` revokes the session's policy grants and kills its
            // surrogates, so a peer that could end any session id could deny
            // another agent its access — and, because the session is the unit
            // of authority, strip a grant it never held. Every other
            // session-scoped verb here (Authorize, MintSurrogate,
            // RevokeSurrogate, the GitHub trio) checks ownership for exactly
            // that reason; this arm was the outlier.
            //
            // Existence is checked BEFORE ownership, on purpose. The two
            // refusals mean different things and an operator has to be able
            // to tell them apart: "no such session" is a client error and
            // keeps UAT-014's revoke-observability, while "not owned" is a
            // denial. Checking ownership first would answer "not owned" to an
            // owner who simply revoked twice, which is both wrong and a
            // misleading thing to audit.
            let Some(owner_pid) = sessions!(state).peer_pid_of(session) else {
                // Fail closed: an unknown session is an error, not a no-op.
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("no such session: {session}"),
                };
            };
            if owner_pid != peer.credentials.pid {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            if sessions!(state).end(session) {
                state.policy.revoke_session(session);
                // The session's surrogates die with it. Leaving them live would
                // make the session lifetime advisory: an agent could keep
                // spending a token after the session that authorized it is gone.
                surrogates!(state).revoke_session(session);
                // And so do its *tunnels*, C2.8. Killing the surrogates only
                // stops the next tunnel: one already established is a live
                // connection to a destination that is being handed the real
                // credential, and nothing in the relay ever asks whether the
                // session behind it still exists. Measured before this line
                // existed — the destination still held its connection 20 s
                // after the session ended, with `asv run` already exited and
                // the shim already dead, so nothing else on the path was going
                // to close it.
                //
                // Inside the ownership guard and inside the branch that
                // actually ended the session, because a revoke placed earlier
                // would let any peer on the socket destroy any session it can
                // name without owning it. The reversal of that is a test:
                // `a_refused_end_session_revokes_nothing`.
                state.shutdown.revoke(session.to_string().as_str());
                Response::SessionEnded { session }
            } else {
                // Unreachable while the session is known to exist, kept so a
                // future change to the store cannot make this a silent no-op.
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("no such session: {session}"),
                }
            }
        }

        Request::ListCredentialMetadata => Response::CredentialMetadata {
            entries: state.credentials.iter().map(Into::into).collect(),
        },

        Request::CreateCredential {
            label,
            kind,
            provider,
            account,
            secret,
        } => {
            // ADR-0015, evaluated before anything is written and for the same
            // reason the other three control-plane verbs evaluate it: the
            // refusal is computed, not asserted. An agent session is refused by
            // the first condition, which is the whole point of planting a
            // credential behind this door rather than on the agent socket.
            if let Err(denial) =
                admission::admit_control_plane(peer, &state.control_plane, &admission::ProcFs)
            {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: format!("credential creation refused: {denial}"),
                };
            }

            // A broker with no vault open cannot write to one. Same
            // fail-closed reading as every other secret operation: no
            // fallback, because a fallback here would be "accept the secret and
            // keep it somewhere that is not the encrypted vault".
            let Some(writer) = state.vault_writer.as_ref() else {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "credential creation refused: this broker has no vault write \
                              path configured"
                        .into(),
                };
            };

            // The broker mints the handle. The operator names the credential;
            // it cannot address a record it did not create, so the request
            // cannot be shaped to collide with an existing one.
            let id = CredentialId::new();

            // The vault's storage vocabulary has five kinds and the domain's
            // has nine. What changed is not the count but the honesty of the
            // mapping: the four extra now have a storage class *and* record
            // the kind the operator actually named, so a read gives back what
            // was asked for. That is why the refusal this replaced is gone —
            // it existed to stop an `ApiKey` being written as a `BearerToken`
            // and read back as something the operator never chose, and the
            // label is what makes that impossible.
            let vault_kind = inventory::vault_kind(kind);
            // Recorded only when the storage class does not already say it, so
            // a record whose two fields agree carries no redundant copy. An
            // `api_key` held as a `BearerToken` says both; a `bearer_token`
            // held as a `BearerToken` says one thing, once.
            let domain_kind = if kind == inventory::kind_of(vault_kind) {
                None
            } else {
                Some(kind)
            };

            let metadata = asv_vault::CredentialMetadata::new(
                id.to_wire(),
                label,
                vault_kind,
                provider,
                account,
                now_secs(),
            );
            // Set after construction rather than in `new`, which is the shape
            // every existing caller already has: a new parameter there would be
            // a compile error at each of the dozen call sites in the vault's
            // own tests, for a value most of them do not have an opinion about.
            let mut metadata = metadata;
            metadata.domain_kind = domain_kind;

            // The vault's `insert` is the transaction: it writes the file or it
            // does not, and on failure the in-memory body is restored to match
            // the file rather than diverging from it. That is `v0.18.1`'s work
            // being spent here, and it is why this call can be treated as the
            // point of no return rather than a best effort.
            let bytes = secret.expose().to_vec();
            let stored = match writer.create(metadata.clone(), asv_domain::SecretBytes::new(bytes))
            {
                Ok(id) => id,
                Err(error) => {
                    // The error is the vault's, and names no secret. The
                    // submitted bytes have already been zeroized by the
                    // `OpaqueSecret` this request owned.
                    return Response::Error {
                        code: ErrorCode::InvalidRequest,
                        message: format!("credential could not be stored: {error}"),
                    };
                }
            };

            // Only now does the broker's inventory learn about it, and the
            // order is the requirement: the file is the source of truth and the
            // in-memory list follows it. Updating it first would produce a
            // broker advertising a credential the file does not have.
            if let Some(projected) = inventory::project_one(&metadata) {
                state.credentials.push(projected);
            }

            Response::CredentialCreated {
                id: CredentialId::from_wire(&stored).unwrap_or(id),
                label: metadata.label,
            }
        }

        Request::DeleteCredential { id } => {
            // ADR-0015, evaluated before the id is looked at and for the same
            // reason the create verb evaluates it. Two properties of *where*
            // this check sits, both deliberate:
            //
            // A refused caller learns nothing about the id. The denial is
            // computed from the peer's process evidence alone — pin, cgroup,
            // enrolment — and the string never interpolates `id`, so an
            // unadmitted peer asking about a credential that exists and one
            // that does not receives byte-identical answers. The oracle that
            // made this an existence probe is closed by the placement, not by
            // a comparison further down.
            //
            // The comment this replaces claimed the vault write path was
            // absent. It was not: `VaultWritePort::remove` has existed since
            // the create path landed, and the refusal below is now only ever
            // reached when a condition genuinely holds.
            if let Err(denial) =
                admission::admit_control_plane(peer, &state.control_plane, &admission::ProcFs)
            {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: format!("credential deletion refused: {denial}"),
                };
            }

            // Admitted. A broker with no vault open cannot revoke in one, and
            // the answer says exactly that — which, unlike the old message, is
            // true at the moment it is printed.
            let Some(writer) = state.vault_writer.as_ref() else {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "credential deletion refused: this broker has no vault write path"
                        .into(),
                };
            };

            // The file is the source of truth, so it goes first and it goes
            // alone. Nothing below has run yet, which is what makes a refused
            // write leave the inventory and the token table exactly as they
            // were — the same invariant the create path established, and the
            // reason the mirror can never advertise a credential the file
            // still holds.
            // `to_wire`, not a `Uuid` re-render: the create verb keys the
            // vault by `to_wire()` and the vault is a `String`-keyed map, so
            // this must be the same spelling that wrote the record rather than
            // an independently formatted one that would simply not find it.
            match writer.remove(&id.to_wire()) {
                Err(asv_vault::VaultError::NotFound(_)) => {
                    // Reported, not swallowed, and *only* to a caller
                    // admission has already accepted. That peer is the
                    // operator's own enrolled principal, holding a pidfd and
                    // outside every broker slice; it can already call
                    // `ListCredentialMetadata` and read the whole inventory, so
                    // this discloses nothing it does not hold. Answering
                    // `CredentialDeleted` instead would tell the operator a
                    // revocation happened when nothing was revoked.
                    return Response::Error {
                        code: ErrorCode::InvalidRequest,
                        message: "no such credential".into(),
                    };
                }
                Err(error) => {
                    // The vault's own error, verbatim. It names a condition
                    // and no secret; rewording it would hide which failure
                    // mode an operator is looking at.
                    return Response::Error {
                        code: ErrorCode::Upstream,
                        message: format!("credential could not be removed: {error}"),
                    };
                }
                Ok(()) => {}
            }

            // The write succeeded, so the mirror may now follow it.
            state.credentials.retain(|c| c.id != id);

            // And the tokens that stood for it go with it. The vault alone
            // would have made them useless; this is what stops the registry
            // from still reporting them as live, and the count is what tells
            // the operator how much was in flight when they pulled the plug.
            let revoked = surrogates!(state).revoke_credential(id);
            if revoked > 0 {
                tracing::info!(%revoked, "surrogates revoked with their credential");
            }

            Response::CredentialDeleted { id }
        }

        Request::Authorize {
            mut request,
            capability,
            approval,
        } => {
            if !sessions!(state).belongs_to(request.session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            bind_peer_identity(&mut request, peer);
            Response::Authorization {
                explanation: state.policy.authorize(&request, capability, approval),
            }
        }

        Request::ExplainAuthorization { mut request } => {
            if !sessions!(state).belongs_to(request.session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            bind_peer_identity(&mut request, peer);
            Response::Authorization {
                explanation: state.policy.explain(&request),
            }
        }

        Request::SubmitApproval { request, ttl_secs } => {
            // UAT-015: the broker blocks a high-risk action until a human
            // approves, and ADR-0015 is what makes "a human" decidable: the
            // peer must pass control-plane admission, which means it is the
            // operator's own enrolled binary — pin, cgroup and enrolment all
            // checked against process evidence. An agent binary is not in
            // that list and never may be (see the custody contract on
            // [`admission::Enrolment`]); that operational rule, not the
            // socket, is what keeps an agent from minting the approval it is
            // being asked to earn.
            //
            // The policy engine does the rest and has always done it: the
            // mint binds the approval to exactly this request (session,
            // action, resource, request digest), `authorize` re-checks that
            // binding, expiry and the use budget on every presentation, and
            // the budget is spent only on the allow path.
            //
            // APPROVAL_REMAINING_USES is 1 on purpose: UAT-015's "allow
            // once" cannot be replayed after use, and a one-use budget
            // makes the replay structurally `ApprovalConsumed` rather than
            // a matter of operator discipline. Making it configurable is a
            // wire change and is deliberately out of scope.
            if let Err(denial) =
                admission::admit_control_plane(peer, &state.control_plane, &admission::ProcFs)
            {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: format!("approval refused: {denial}"),
                };
            }
            let approval = state
                .policy
                .issue_approval(&request, ttl_secs, APPROVAL_REMAINING_USES);
            Response::ApprovalIssued { approval }
        }

        Request::MintSurrogate {
            session,
            credential,
            max_uses,
            ttl_secs,
        } => {
            if !sessions!(state).belongs_to(session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            // D4, directed requirement: the rest of the broker treats an
            // unpinned peer as a weaker-but-usable connection, but minting a
            // credential-shaped token for a process we can only weakly
            // attribute is the case worth refusing.
            if !sessions!(state).is_pinned(session) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "surrogate minting requires a pidfd-pinned session".into(),
                };
            }
            // The class is resolved from the credential's own metadata rather
            // than from `provider`, which is a free-form string: `uat_027`
            // stores `"o/r"` there. `CredentialKind` is a closed enum, and the
            // lookup was happening anyway, so the class is free.
            let Some(metadata) = state.credentials.iter().find(|c| c.id == credential) else {
                // An unknown credential would mint a token that always fails
                // later. Refusing here reports the real problem instead.
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "credential is not available".into(),
                };
            };
            let class = CredentialClass::from_kind(metadata.kind);

            // H2: the policy is consulted *here*, once, at issuance — not on
            // every operation. Before this, the GitHub path consulted nothing,
            // so an operator who tightened `POLICY_TEXT` observed no change
            // at all; the enforcement point did not exist.
            //
            // Mint is the right place because a surrogate *is* a capability:
            // authorization belongs where the capability is created, and the
            // created record is what redemption checks. It is also the only
            // place it is affordable — `uat_030_perf` times 100 `ReadIssue`
            // calls, so a per-operation Cedar evaluation lands inside the
            // measured loop, while a mint happens once in fixture setup.
            if let Err(response) = state.authorize_surrogate_mint(session, peer, class) {
                return *response;
            }

            match surrogates!(state).mint(
                session,
                credential,
                class,
                ttl_secs,
                max_uses,
                now_secs(),
            ) {
                Ok((surrogate, expires_at, granted)) => {
                    // The token is never logged. Only its budget and its
                    // lifetime, which are the facts an operator needs.
                    tracing::info!(
                        %session,
                        expires_at,
                        max_uses = granted,
                        "surrogate minted"
                    );
                    Response::SurrogateMinted {
                        surrogate,
                        expires_at,
                        max_uses: granted,
                    }
                }
                Err(error) => Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: error.to_string(),
                },
            }
        }

        Request::RevokeSurrogate { session, surrogate } => {
            if !sessions!(state).belongs_to(session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            if surrogates!(state).revoke(&surrogate, session) {
                Response::SurrogateRevoked { surrogate }
            } else {
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "no such surrogate for this session".into(),
                }
            }
        }

        Request::AuditQuery { since_secs } => {
            // R9 separation of duties: audit readers must not be audit
            // writers. This verb reads and never mutates — the records come
            // from the same log whose chain `AuditLog::verify` checks, so a
            // reader sees exactly what the verifier would see, with no
            // second source and no write path in reach. Admission is the
            // same predicate as the other control-plane verbs, and the
            // dispatcher records the query itself: an agent probing the
            // audit channel is refused and the refusal is an audited event.
            if let Err(denial) =
                admission::admit_control_plane(peer, &state.control_plane, &admission::ProcFs)
            {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: format!("audit query refused: {denial}"),
                };
            }
            // One acquisition, three reads. `std::sync::Mutex` is not
            // reentrant: the three `audit_chain!` temporaries a struct
            // literal would create stay alive until the end of the
            // expression, so the second `lock()` blocks this thread forever
            // on a mutex it already holds. The guard is also what makes the
            // three fields consistent with each other — records, head and
            // drop count are one snapshot of one chain, not three reads that
            // could straddle an append.
            let chain = audit_chain!(state);
            Response::AuditRecords {
                // The chain head and the eviction count ride along so a
                // verifier can pin the chain and loss is never silent.
                records: chain.query(since_secs),
                chain_head: chain.head().to_string(),
                dropped: chain.dropped(),
            }
        }

        // The three semantic operations are the only paths from a surrogate to
        // a real credential, so they share one preamble: same ownership check,
        // same vault requirement, same argument validation, same policy
        // evaluation, and the surrogate spent in the same place. Splitting them
        // into three near-copies is how one of them ends up skipping the
        // ownership check — and H3 is what that looks like when the missing
        // step is the policy one: the trio ran the first three and never named
        // the verb they were performing.
        Request::ReadIssue {
            session,
            surrogate,
            repo,
            number,
        } => {
            if let Err(denial) = state.authorize_github(session, peer, &repo) {
                return *denial;
            }
            match surrogates!(state).redeem_for(
                &surrogate,
                session,
                OperationFamily::GitHub,
                now_secs(),
            ) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.read_issue(&credential.to_wire(), &repo, number) {
                        Ok(issue) => Response::IssueRead {
                            title: issue.title,
                            body: issue.body,
                            state: issue.state,
                        },
                        // The provider's own body is never forwarded. M4-R1
                        // promises the three fields and nothing else, and an
                        // upstream body can carry anything the provider chose
                        // to put in it.
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }

        Request::CreateIssue {
            session,
            surrogate,
            repo,
            title,
            body,
        } => {
            if let Err(denial) =
                state.authorize_github_write(session, peer, Action::GitHubIssueCreate, &repo)
            {
                return *denial;
            }
            match surrogates!(state).redeem_for(
                &surrogate,
                session,
                OperationFamily::GitHub,
                now_secs(),
            ) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.create_issue(&credential.to_wire(), &repo, &title, &body) {
                        Ok(issue) => Response::IssueCreated {
                            number: issue.number,
                            url: issue.url,
                        },
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }

        Request::CreateRelease {
            session,
            surrogate,
            repo,
            tag,
            name,
            body,
        } => {
            if let Err(denial) =
                state.authorize_github_write(session, peer, Action::GitHubReleaseCreate, &repo)
            {
                return *denial;
            }
            match surrogates!(state).redeem_for(
                &surrogate,
                session,
                OperationFamily::GitHub,
                now_secs(),
            ) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.create_release(&credential.to_wire(), &repo, &tag, &name, &body) {
                        Ok(release) => Response::ReleaseCreated {
                            tag: release.tag,
                            url: release.url,
                        },
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }
        Request::PostgresConnect {
            session,
            host,
            host_addr,
            port,
            database,
            role,
        } => {
            // H5: the destination is resolved before anything else, and what
            // comes back is the deployment's own entry. `server_name` below is
            // the declared host, not `host` from the request, so the
            // certificate check and the dialled address cannot both be
            // attacker-chosen while the pair happens to be declared.
            let destination = match state.pg_destination(&host, &host_addr) {
                Ok(destination) => destination.clone(),
                Err(denial) => return *denial,
            };
            if let Err(denial) = state.authorize_postgres_connect(session, peer, &database, &role) {
                return *denial;
            }
            state.postgres_connect(
                session,
                destination.host.as_str(),
                &destination.addr.to_string(),
                port,
                database,
                role,
            )
        }
        Request::PostgresQuery { session, sql } => {
            if let Err(denial) = state.authorize_postgres(session, peer) {
                return *denial;
            }
            // M6-R5: the statement's action is decided before the statement
            // reaches the socket, not after. A gate that runs once the server
            // has already executed is not a gate.
            match state.authorize_postgres_statement(session, peer, &sql) {
                Ok(()) => state.postgres_query(session, &sql),
                Err(denial) => *denial,
            }
        }
        Request::PostgresRevoke { session } => {
            // Revoke of a session that was never opened is a no-op, not an
            // error: the agent is trying to give up access, and failing that
            // would leave it believing it still holds a session. The session
            // id is echoed back rather than invented, so the agent can match
            // the reply to what it asked for.
            //
            // `backend_terminated` comes from what the socket did, not from
            // the fact that a revoke was asked for. A session that was never
            // open has no backend, and saying `true` would be a teardown
            // nobody observed.
            if let Err(denial) = state.authorize_postgres(session, peer) {
                return *denial;
            }
            let terminated = state.postgres_revoke(session);
            Response::PostgresRevoked {
                session,
                backend_terminated: terminated,
            }
        }
    }
}

/// The audience every semantic GitHub operation goes to.
///
/// One constant, not a request field. An agent that could name the host would
/// be able to point a credential at any endpoint that presents a valid
/// certificate for it, which is the generic HTTP escape hatch M4-R9 rules out.
const GITHUB_AUTHORITY: &str = "api.github.com";

/// The use budget of every approval the broker mints. UAT-015's "allow once"
/// cannot be replayed after use; a one-use budget makes the replay
/// structurally `ApprovalConsumed` (the policy denies it) instead of a matter
/// of operator discipline. Making it configurable is a wire change and is
/// deliberately out of scope — see the `SubmitApproval` handler.
const APPROVAL_REMAINING_USES: u32 = 1;

/// The surrogate registry's lock was poisoned by a panic in another thread.
///
/// A distinct type rather than a `String` so no call site can turn it into a
/// plausible-looking message by accident, and so the two questions — "did the
/// operation fail" and "is the broker's own state trustworthy" — cannot be
/// collapsed into one `io::Error` at the bottom of a long function.
#[derive(Debug, thiserror::Error)]
#[error("the surrogate registry is poisoned; a previous operation panicked mid-update and the broker must restart")]
pub struct RegistryPoisoned;

/// What an authorisation helper returns when the session store cannot be read.
///
/// A `const fn` returning a value rather than a constant, because `Response` is
/// not a const-constructible type here; named so the two failure sites say the
/// same thing in the same words.
fn poison_response() -> asv_ipc_protocol::Response {
    asv_ipc_protocol::Response::Error {
        code: asv_ipc_protocol::ErrorCode::Upstream,
        message: "the broker's session store is poisoned; restart required".into(),
    }
}

impl From<RegistryPoisoned> for asv_ipc_protocol::Response {
    fn from(_: RegistryPoisoned) -> Self {
        asv_ipc_protocol::Response::Error {
            code: asv_ipc_protocol::ErrorCode::Upstream,
            message: "the broker's surrogate registry is poisoned; restart required".into(),
        }
    }
}

impl BrokerState {
    /// Borrow the surrogate registry.
    ///
    /// A poisoned lock is an **error, not a recovery**. The tempting
    /// `unwrap_or_else(PoisonError::into_inner)` says "the data may be
    /// half-updated but let us carry on", and for a registry that is the wrong
    /// trade: a panic between decrementing a token's budget and returning can
    /// leave a surrogate already spent and still reported as live, and
    /// "sometimes deny" beats "occasionally hand out a token that should have
    /// been spent".
    ///
    /// There is no third option that keeps the availability: recovering from
    /// poison would need the registry to be rebuildable from the audit chain,
    /// which it is not. So the broker refuses, loudly, until it is restarted —
    /// and an operator is told it was restarted.
    pub fn surrogates(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, SurrogateRegistry>, RegistryPoisoned> {
        self.surrogates.lock().map_err(|_| RegistryPoisoned)
    }

    /// Borrow the session store, with the same poisoning rule as the registry
    /// and for the same reason: a store updated halfway through a `create` or a
    /// `register_key` is not a store to keep answering questions from.
    pub fn sessions_store(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, SessionStore>, RegistryPoisoned> {
        self.sessions.lock().map_err(|_| RegistryPoisoned)
    }

    /// Borrow the audit chain, with the same poisoning rule as the other two.
    ///
    /// A chain that cannot be extended is not a chain: an append that silently
    /// went nowhere would leave a verified log missing exactly the records an
    /// incident is looking for.
    pub fn audit_chain(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, audit::AuditLog>, RegistryPoisoned> {
        self.audit.lock().map_err(|_| RegistryPoisoned)
    }

    /// The one policy consultation on the surrogate path, performed at mint
    /// time rather than at every operation (H2).
    ///
    /// The class picks the action and resource that get evaluated. A database
    /// class is asked about the database read verb; anything else is asked
    /// about the GitHub read verb, because the credential's shape is the only
    /// signal available and the policy is what actually decides.
    ///
    /// The read verb is used as the representative in both cases on purpose.
    /// Minting does not commit the holder to a specific verb, and asking the
    /// policy about the narrowest one would refuse a token that is perfectly
    /// usable for a broader one it is also permitted to do. The per-verb
    /// decisions still happen at the operation itself, where the verb is
    /// known exactly.
    fn authorize_surrogate_mint(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        class: CredentialClass,
    ) -> Result<(), Box<Response>> {
        let (action, resource) = match class {
            CredentialClass::Database => (
                Action::PostgresRead,
                Resource::Database {
                    name: String::new(),
                    role: String::new(),
                },
            ),
            // The audience is the compile-time allowlist constant, not
            // anything the caller supplied: `ALLOWED_AUDIENCES` in the policy
            // crate is what makes a GitHub call reachable at all, and a
            // policy that could widen it from a mint request would reopen the
            // hole this closes. The same reasoning and the same constant as
            // `Self::github_resource`, which the operations use.
            CredentialClass::Generic => (Action::GitHubIssueRead, self.github_resource()?),
        };

        // The verdict, shaped as the mint gate's own refusal. The wording is
        // the mint gate's because "minting a surrogate" is what an operator is
        // deciding about, and the bare verb would read as if the GitHub call
        // had already happened. The reason after the colon is still Cedar's,
        // so the operator can see which clause fired.
        let verb = action.to_string();
        match self.evaluate(session, peer, action, resource) {
            Decision::Allow => Ok(()),
            Decision::Deny { reason } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!("policy denied minting a surrogate for {verb}: {reason}"),
            })),
            Decision::RequireApproval { approval } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!(
                    "policy requires approval {approval} to mint a surrogate for {verb}"
                ),
            })),
        }
    }

    /// The checks every brokered GitHub operation shares, before anything is
    /// spent or sent, including the policy decision for the exact verb (H3).
    ///
    /// Four steps, in this order, and the order is the contract:
    ///
    /// 1. Ownership. A session not owned by this peer must not even learn
    ///    whether a vault is open.
    /// 2. A vault. A broker with no vault must refuse rather than reach GitHub
    ///    unauthenticated.
    /// 3. `repo`. Validated here rather than at the call site so that its
    ///    `InvalidRequest` precedence is fixed once: `redeem` consumes a use,
    ///    and an agent that sends `owner/repo/../../admin` must be refused on
    ///    its own argument *and* not charged, which also means it must be
    ///    refused before any policy runs, or a typo would be reported as a
    ///    permissions problem.
    ///
    /// The policy is **not** consulted here. Where it is, and why not here, is
    /// [`Self::authorize_github_write`].
    fn authorize_github(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        repo: &str,
    ) -> Result<(), Box<Response>> {
        // Read through an explicit guard rather than `self.sessions.belongs_to`:
        // a poisoned store must not answer this question at all, and the
        // tempting collapse — treat it as "not owned" — is only correct by
        // accident. It would also be wrong for a *different* caller that
        // wanted the inverse, which is exactly how a fail-closed check turns
        // into an open one.
        let Ok(store) = self.sessions_store() else {
            return Err(Box::new(poison_response()));
        };
        if !store.belongs_to(session, peer) {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into(),
            }));
        }
        if self.secrets.is_none() {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                // Explicit about *why* there is no degraded path. The
                // alternative reading of a missing vault is "call GitHub
                // anonymously", and for a private repository that quietly
                // becomes "act as if the credential were not needed".
                message: "no credential store is open, so no brokered operation can run".into(),
            }));
        }
        if let Err(error) = validate_repo(repo) {
            return Err(Box::new(Response::Error {
                code: ErrorCode::InvalidRequest,
                message: error.to_string(),
            }));
        }
        Ok(())
    }

    /// The policy decision for a GitHub operation that goes **beyond** the
    /// capability its surrogate was minted for (H3).
    ///
    /// # Why the read verb is not re-asked here
    ///
    /// `authorize_surrogate_mint` already evaluated `github_issue_read` for a
    /// `Generic` credential, and that is the same verb `ReadIssue` performs. A
    /// token that exists was therefore minted under read permission, so asking
    /// the same question again inside the token's lifetime grants nothing, and
    /// it costs a Cedar evaluation on every read — which is the loop
    /// `uat_030_perf` times 100 times, against NFR-PERF-001.
    ///
    /// That is also the argument for why the *write* verbs must be asked. The
    /// mint asked about reading. `POLICY_TEXT` has three separate GitHub verbs
    /// so an operator can separate reading from writing, and a rule about a
    /// verb nothing ever asks about is not a control: before H3 an operator who
    /// permitted `github_issue_read` and said nothing about writing got an
    /// issue creation and a published release, because the mint's read verdict
    /// was standing in for a decision nobody had made.
    ///
    /// So the rule this function enforces: **the mint gate is the capability
    /// grant, and anything past it is re-checked where it is used.** A
    /// consequence worth stating: a policy that permits writing but not
    /// reading cannot obtain a token at all, because the mint is what mints.
    fn authorize_github_write(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        action: Action,
        repo: &str,
    ) -> Result<(), Box<Response>> {
        self.authorize_github(session, peer, repo)?;
        self.authorize_verb(session, peer, action, self.github_resource()?)
    }

    /// The policy resource every GitHub operation is evaluated against.
    ///
    /// The audience is the compile-time allowlist constant, not anything the
    /// caller supplied: `ALLOWED_AUDIENCES` in the policy crate is what makes a
    /// GitHub call reachable at all, and a policy that could widen it from a
    /// request would reopen the hole `GITHUB_AUTHORITY` closes. Shared with
    /// [`Self::authorize_surrogate_mint`] so there is one place where that
    /// argument is written down.
    fn github_resource(&self) -> Result<Resource, Box<Response>> {
        Authority::canonicalize(GITHUB_AUTHORITY)
            .map(|audience| Resource::Api { audience })
            .map_err(|error| {
                Box::new(Response::Error {
                    code: ErrorCode::Denied,
                    message: format!("github audience is not canonical: {error}"),
                })
            })
    }

    /// Evaluates one `AuthorizationRequest` and turns the decision into the
    /// refusal shape the IPC contract uses.
    ///
    /// A function per call site, because the *wording* of a denial is part of
    /// the contract for a policy author: Cedar's reason is forwarded verbatim
    /// in every arm, so the operator can see which clause fired, and the verb
    /// is named in every arm for the same reason. Two call sites existed with
    /// their own copies, and the third — the one H3 added — had to be written
    /// a fourth time to keep the two copies honest.
    fn authorize_verb(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        action: Action,
        resource: Resource,
    ) -> Result<(), Box<Response>> {
        let verb = action.to_string();
        match self.evaluate(session, peer, action, resource) {
            Decision::Allow => Ok(()),
            Decision::Deny { reason } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!("policy denied {verb}: {reason}"),
            })),
            Decision::RequireApproval { approval } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!("policy requires approval {approval} for {verb}"),
            })),
        }
    }

    /// The one place an `AuthorizationRequest` is assembled for a semantic
    /// operation.
    ///
    /// Returns the bare `Decision` so that each gate can word its own refusal;
    /// the request itself is identical every time, and the three fields below
    /// are the only per-request inputs. `workspace` and `peer_uid` are
    /// rebinded from kernel-attested facts by the caller before they arrive
    /// here, so a policy author reasons about who the peer *is* rather than
    /// about what the request body claimed.
    fn evaluate(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        action: Action,
        resource: Resource,
    ) -> Decision {
        // An unreadable store is a **denial**, not an empty workspace. The
        // difference matters: this function returns a `Decision`, and a
        // workspace of `""` is a value the policy engine is entitled to allow
        // for some resources. A store that cannot be read must not be able to
        // produce an allow, so the refusal is made here rather than being
        // left to a downstream default.
        let Ok(store) = self.sessions_store() else {
            return Decision::Deny {
                reason: "the broker's session store is poisoned; restart required".into(),
            };
        };
        let workspace = store.workspace_of(session).unwrap_or_default().to_string();
        let request = AuthorizationRequest {
            session,
            action,
            resource,
            context: PolicyContext {
                workspace,
                protected_ref: None,
                request_digest: None,
                peer_uid: peer.credentials.uid,
            },
        };
        self.policy.authorize(&request, None, None).decision
    }

    /// The checks every brokered PostgreSQL operation shares, before
    /// anything is spent or sent.
    ///
    /// Same shape as [`BrokerState::authorize_github`] and for the same
    /// reasons: ownership first, then the vault. A session the peer does not
    /// own must not learn whether a vault is open, and a broker with no vault
    /// must refuse rather than connect unauthenticated. A PostgreSQL server
    /// that accepts an anonymous connection is not a reason to try one.
    fn authorize_postgres(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
    ) -> Result<(), Box<Response>> {
        // Read through an explicit guard rather than `self.sessions.belongs_to`:
        // a poisoned store must not answer this question at all, and the
        // tempting collapse — treat it as "not owned" — is only correct by
        // accident. It would also be wrong for a *different* caller that
        // wanted the inverse, which is exactly how a fail-closed check turns
        // into an open one.
        let Ok(store) = self.sessions_store() else {
            return Err(Box::new(poison_response()));
        };
        if !store.belongs_to(session, peer) {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into(),
            }));
        }
        if self.secrets.is_none() {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "no credential store is open, so no brokered operation can run".into(),
            }));
        }
        Ok(())
    }

    /// The gateway verb, gated (H3).
    ///
    /// `POLICY_TEXT` has carried `permit (principal, action ==
    /// Action::"postgres_connect", resource is Database)` since M6, with a
    /// comment explaining at length why the gateway must stay permitted. It
    /// was never evaluated: `Request::PostgresConnect` called
    /// [`Self::authorize_postgres`], which checks ownership and whether a
    /// vault is open, and then opened the socket. Deleting that permit line
    /// from the policy changed nothing, which is the test
    /// `removing_the_connect_permit_stops_the_connect` and which is also why
    /// the rule's own comment was a description of an intention rather than of
    /// a behaviour.
    ///
    /// This matters more than its size suggests, because the connect is the
    /// only place the password is materialised: `postgres_connect` lends it to
    /// the TLS handshake. `postgres_read` and the write verbs gate what the
    /// socket may then be *used* for, so before this the operator's only lever
    /// over lending the credential at all was to deny every statement — which
    /// refuses the connect too, but by a rule that does not say it is doing
    /// that.
    ///
    /// The resource is the pair the *request* names, because there is no
    /// recorded connection yet — that is what the connect is for. The
    /// statement path uses [`Self::database_resource`], which reads the
    /// connection the connect already made, so a query cannot lie about which
    /// database it is on. Here the request is the only description of the
    /// pair available, and the credential is looked up by exactly that pair a
    /// few lines later in `postgres_connect`, so the resource and the
    /// credential cannot drift apart.
    fn authorize_postgres_connect(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        database: &str,
        role: &str,
    ) -> Result<(), Box<Response>> {
        // Ownership and the vault first, for the same reasons as
        // `authorize_github`: a peer that does not own the session must not
        // learn anything about the policy.
        self.authorize_postgres(session, peer)?;
        self.authorize_verb(
            session,
            peer,
            Action::PostgresConnect,
            Resource::Database {
                name: database.to_string(),
                role: role.to_string(),
            },
        )
    }

    /// Resolves a requested destination against the deployment's declaration
    /// (H5), and answers with the *declared* entry rather than the request's.
    ///
    /// Order matters and is the guarantee: this runs before the policy and long
    /// before [`Self::postgres_connect`] asks the vault for anything, so a
    /// destination the deployment never wrote down costs the agent nothing —
    /// no policy evaluation, no credential borrow, no socket.
    ///
    /// Three things are refused, and the third is why this is not a string
    /// comparison:
    ///
    /// 1. No destinations declared at all. A broker that has not been told where
    ///    it may lend is not a broker that gets to lend wherever it is asked.
    /// 2. A host or address that matches no declared pair.
    /// 3. A spelling that only looks like a declared host — userinfo,
    ///    percent-encoding, an IP literal in place of a name, a subdomain
    ///    suffix. [`Authority::canonicalize`] rejects those outright, and the
    ///    declared hosts went through the same function, so a legitimate
    ///    alternative spelling of a real host still matches.
    fn pg_destination(&self, host: &str, host_addr: &str) -> Result<&PgDestination, Box<Response>> {
        // Syntax before configuration, and the order is the contract. A
        // malformed address is a statement about the *request*, and it has to
        // stay that way whatever the deployment happens to be configured with:
        // reporting "this broker has no destinations" to a caller who sent
        // nonsense answers a question they did not ask and describes the
        // broker's setup to a peer that gets to choose its next move. It also
        // silently disables the existing guarantee that a malformed address is
        // refused as `InvalidRequest` before the credential is lent.
        let addr: IpAddr = host_addr.parse().map_err(|error| {
            Box::new(Response::Error {
                code: ErrorCode::InvalidRequest,
                message: format!("host_addr is not an IP address: {error}"),
            })
        })?;
        // An unusable host name is also the request's fault, so it is answered
        // as `Denied` about the name rather than as a deployment question.
        let requested = Authority::canonicalize(host).map_err(|error| {
            Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!("host is not a usable server name: {error}"),
            })
        })?;

        // Configuration last, now that the request is known to be well formed.
        let declared = self.connectors.pg_destinations();
        if declared.is_empty() {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "this broker has no declared PostgreSQL destinations, \
                           so it will not lend a credential to any of them"
                    .into(),
            }));
        }
        declared
            .iter()
            .find(|d| d.host == requested && d.addr == addr)
            .ok_or_else(|| {
                Box::new(Response::Error {
                    code: ErrorCode::Denied,
                    message: format!(
                        "this broker does not lend database credentials to that \
                         destination. It lends to {} declared destination(s), and \
                         the request named one that is not among them.",
                        declared.len()
                    ),
                })
            })
    }

    /// Opens a live PostgreSQL session and records it.
    ///
    /// The credential is lent here, for the handshake, and the borrow ends
    /// with this call. That is the whole M6-R2 shape: the broker holds the
    /// password long enough to authenticate and the agent never sees it, at
    /// any point, in any form.
    #[allow(clippy::too_many_arguments)]
    fn postgres_connect(
        &mut self,
        session: AgentSessionId,
        host: &str,
        host_addr: &str,
        port: u16,
        database: String,
        role: String,
    ) -> Response {
        // The address is parsed before anything else borrows a credential, so a
        // malformed request never reaches the vault. The parse is strict: an
        // address that is not a literal is refused rather than resolved, since
        // resolving here would undo the pinning the request just did.
        let address: IpAddr = match host_addr.parse() {
            Ok(address) => address,
            Err(error) => {
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("host_addr is not an IP address: {error}"),
                }
            }
        };
        let Some(runtime) = self.runtime.clone() else {
            // No runtime means the broker cannot drive an async transport. The
            // refusal names the reason rather than pretending the server is
            // unreachable.
            return Response::Error {
                code: ErrorCode::Upstream,
                message: "the broker has no async runtime for the postgres transport".into(),
            };
        };
        let config = LiveConnectorConfig::new(
            address,
            port,
            // The name the certificate must match. The request carries it
            // separately from the address on purpose: a client that derived the
            // name from the address would be checking a string, not a
            // certificate.
            //
            // A configured factory name wins over the request's. When a
            // deployment has pinned the name its certificates are issued for,
            // a request that names something else must not be able to move the
            // check, and the only way to guarantee that is for the name to not
            // come from the request at all.
            self.connectors
                .pg_server_name()
                .unwrap_or_else(|| host.to_string()),
            self.pg_roots(),
            database,
            role,
        );
        let Some(secrets) = self.secrets.clone() else {
            return Response::Error {
                code: ErrorCode::Denied,
                message: "no credential store is open, so no brokered operation can run".into(),
            };
        };
        let credential = self.credential_for(&config.database, &config.role);
        // The sink owns the borrowed bytes for exactly as long as the call
        // needs them, and zeroizes when it is dropped. Nothing else in the
        // broker ever holds the password, so there is no second place to scrub
        // and no window in which it is merely "going to be cleared".
        let mut sink = BorrowedSecret::default();
        if secrets.lend(&credential, &mut sink).is_err() {
            return Response::Error {
                code: ErrorCode::InvalidRequest,
                message: "no credential is registered for this database and role".into(),
            };
        }
        let database = config.database.clone();
        let role = config.role.clone();
        // `block_on` drives the handshake to completion on the runtime the
        // broker already owns, so the returned session belongs to that runtime
        // and is usable by the next request.
        let outcome =
            runtime.block_on(
                self.postgres
                    .spawn(&runtime, session, &config, sink.expose()),
            );
        // The borrow ends here. `sink` drops at the end of the function and
        // zeroizes, whether the connect succeeded or failed.
        match outcome {
            Ok(()) => Response::PostgresConnected {
                session,
                database,
                role,
            },
            Err(error) => pg_failure(error),
        }
    }

    /// Decides one SQL statement against the policy, before it is sent.
    ///
    /// M6-R5 requires a Cedar policy to authorise or deny PostgreSQL actions
    /// without a connector change, and to keep doing so after the policy
    /// changes. Both need this to exist: the policy vocabulary has the five
    /// database verbs, and nothing consulted them. Without this call the verbs
    /// were decoration, and the scenario "a policy allowing `connect` but not
    /// `create_table`" was satisfied by no test and by no code.
    ///
    /// The order is deliberate. Ownership and the vault come first, in
    /// [`Self::authorize_postgres`], because a peer that does not own the
    /// session must not learn anything about the policy. Then the statement
    /// is classified, and a statement that cannot be placed is denied without
    /// consulting the policy at all: there is no action to evaluate, so there
    /// is no decision to report.
    ///
    /// The refusal for an unplaceable statement is [`ErrorCode::Denied`],
    /// not `InvalidRequest`. The request was well-formed; what is missing is
    /// the authority to run it, and reporting it as a bad request would tell
    /// the agent to rephrase a statement that no phrasing can be allowed.
    fn authorize_postgres_statement(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
        sql: &str,
    ) -> Result<(), Box<Response>> {
        let Some(action) = pg_policy::classify(sql).action() else {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!(
                    "this statement is not one the broker will classify, so it is denied: {sql}"
                ),
            }));
        };
        let Ok(store) = self.sessions_store() else {
            return Err(Box::new(poison_response()));
        };
        // `unwrap_or_default` is kept for the *absent session* case, which is
        // the broker's existing behaviour; the unreadable case never reaches
        // it, because the guard above has already returned.
        let workspace = store.workspace_of(session).unwrap_or_default().to_string();
        let request = AuthorizationRequest {
            session,
            action: action.as_policy_action(),
            resource: self.database_resource(session, peer),
            context: PolicyContext {
                workspace,
                protected_ref: None,
                request_digest: None,
                peer_uid: peer.credentials.uid,
            },
        };
        match self.policy.authorize(&request, None, None).decision {
            Decision::Allow => Ok(()),
            Decision::Deny { reason } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                // The reason is Cedar's, not the broker's. Rewriting it would
                // hide which policy clause fired, and a policy author
                // debugging a denial needs exactly that.
                message: format!("policy denied {}: {reason}", action.as_policy_str()),
            })),
            Decision::RequireApproval { approval } => Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: format!(
                    "policy requires approval {approval} for {}",
                    action.as_policy_str()
                ),
            })),
        }
    }

    /// The `(database, role)` this session is connected to, as a policy
    /// resource.
    ///
    /// `None` when the session has no recorded connection, which is the
    /// state a `PostgresQuery` on a closed session finds. Cedar then sees a
    /// resource no policy matches, and a default-deny policy denies it, so an
    /// unknown session is refused by the policy rather than by a special
    /// case here.
    fn database_resource(&self, session: AgentSessionId, _peer: &WorkloadIdentity) -> Resource {
        match self.postgres.connected(session) {
            Some((database, role)) => Resource::Database {
                name: database,
                role,
            },
            None => Resource::Database {
                name: String::new(),
                role: String::new(),
            },
        }
    }

    /// Runs one statement on a live session.
    fn postgres_query(&mut self, session: AgentSessionId, sql: &str) -> Response {
        let Some(runtime) = self.runtime.clone() else {
            return Response::Error {
                code: ErrorCode::Upstream,
                message: "the broker has no async runtime for the postgres transport".into(),
            };
        };
        match runtime.block_on(self.postgres.query(session, sql.to_string())) {
            Ok(outcome) => Response::PostgresResult {
                row_count: outcome.rows.len(),
                rows: outcome.rows.iter().map(|row| render_row(row)).collect(),
            },
            Err(error) => pg_failure(error),
        }
    }

    /// Revokes a live session and reports whether the teardown was observed.
    ///
    /// Returns `false` for a session that was never open. That is not a
    /// conservative default bolted on: a session that does not exist has no
    /// backend, so there is nothing that could have been terminated, and
    /// reporting `true` would be claiming an observation nobody made.
    fn postgres_revoke(&mut self, session: AgentSessionId) -> bool {
        let Some(runtime) = self.runtime.clone() else {
            return false;
        };
        matches!(
            runtime.block_on(self.postgres.revoke(session)),
            Ok(asv_connector_pg::Teardown::ServerClosed)
        )
    }

    /// The vault entry that backs a `(database, role)` pair.
    ///
    /// The *broker* maps the pair to a credential, never the agent. An agent
    /// that could name the credential would be able to ask for the one it was
    /// not granted, which is exactly the substitution M6-R3 rules out. The
    /// label is derived here and nowhere else, so there is no second place that
    /// could decide which secret a pair gets.
    fn credential_for(&self, database: &str, role: &str) -> String {
        format!("pg/{database}/{role}")
    }

    /// The roots a live PostgreSQL connection trusts.
    ///
    /// Read from the factory rather than hardcoded, because a factory that was
    /// given a root and then had it ignored is worse than one that refused to
    /// take it: the deployment would believe it had pinned a trust anchor while
    /// every connection quietly used the platform store. A factory that has
    /// none configured gets the platform store, which is the correct default
    /// for a public database.
    fn pg_roots(&self) -> TlsRoots {
        self.connectors.pg_roots()
    }

    /// Builds the client for one operation, refusing if the broker has no vault.
    fn github_client(&self) -> Result<GithubClient, Box<Response>> {
        // `Response` is boxed in the error position because it carries two
        // `String`s inline; a `Result<GithubClient, Response>` would make every
        // `?` in the operation bodies copy a struct that has no business being
        // that large on a path that usually succeeds.
        let secrets = self.secrets.as_ref().ok_or_else(|| {
            Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "no credential store is open, so no brokered operation can run".into(),
            })
        })?;
        let authority = Authority::canonicalize(GITHUB_AUTHORITY).map_err(|error| {
            Box::new(Response::Error {
                code: ErrorCode::Upstream,
                message: format!("the GitHub authority is not usable: {error}"),
            })
        })?;
        self.connectors
            .github(authority, Arc::clone(secrets))
            .map_err(|error| Box::new(github_failure(error)))
    }
}

/// Why a PostgreSQL operation failed, as an IPC answer.
///
/// A session that is gone is `Denied`, because the agent is being told its grant
/// is not there. A revoked session is `Denied` too, and deliberately not a
/// distinct code: an agent that lost access for any reason gets the same
/// answer, so it cannot use the code to learn whether a session ever existed.
///
/// The transport message is passed through because it is the connector's own
/// text and it never carries the password. It is not re-worded to be vaguer: an
/// operator reading "permission denied for database x" learns more from that
/// than from a generic failure, and the message is already free of secrets.
fn pg_failure(error: PgSessionError) -> Response {
    use PgSessionError::*;
    let code = match error {
        NoSuchSession | Revoked => ErrorCode::Denied,
        Transport(_) => ErrorCode::Upstream,
    };
    Response::Error {
        code,
        message: error.to_string(),
    }
}

/// Why a surrogate was refused, as an IPC answer.
///
/// `Expired` and `Exhausted` are separate codes: one says "mint a new token",
/// the other says "you spent it, mint a new token", and an operator reading a
/// log needs to tell them apart.
///
/// `WrongClass` is `Denied` and not `InvalidRequest` for the same reason
/// `WrongSession` is: the request was well-formed and the token was real, so
/// telling the agent to rephrase it would be advice no phrasing can satisfy
/// (H2).
fn surrogate_failure(error: SurrogateError) -> Response {
    use SurrogateError::*;
    let code = match error {
        Unknown | WrongSession | WrongClass => ErrorCode::Denied,
        Expired => ErrorCode::SurrogateExpired,
        Exhausted => ErrorCode::SurrogateExhausted,
    };
    Response::Error {
        code,
        // `SurrogateError`'s messages name the token's *properties*, never the
        // token and never the credential behind it.
        message: error.to_string(),
    }
}

/// Why a GitHub operation failed, as an IPC answer.
///
/// A credential the vault does not know is a provider-independent failure, so
/// it does not become `Upstream` either: the agent is not the problem, the
/// broker's own store is. It is reported as `InvalidRequest` rather than
/// `Denied` because `Denied` reads as "you are not allowed", and the agent
/// demonstrably was: it presented a token this broker minted. The message
/// carries the real cause, and it carries no credential name.
///
/// `Repo` is the one case that is the agent's own fault, and it is the only
/// one answered as such.
fn github_failure(error: GithubError) -> Response {
    let (code, message) = match error {
        GithubError::Repo(error) => (ErrorCode::InvalidRequest, error.to_string()),
        GithubError::Secret(asv_connector_http::SecretError::NotFound(_)) => (
            ErrorCode::InvalidRequest,
            "the credential this surrogate stands for is no longer in the vault".to_string(),
        ),
        GithubError::Secret(_) => (
            ErrorCode::InvalidRequest,
            "the credential could not be unlocked".to_string(),
        ),
        // Every transport failure keeps its own reason. The provider's body is
        // not part of it: an error an agent can read is also a place upstream
        // content would land.
        GithubError::Transport(error) => (ErrorCode::Upstream, error.to_string()),
        GithubError::Upstream { audience, detail } => (
            ErrorCode::Upstream,
            format!("{audience} answered without {detail}"),
        ),
    };
    Response::Error { code, message }
}

/// Rebinds the client-declared identity context to kernel-attested facts.
///
/// `PolicyContext.peer_uid` arrives inside the request body, so it is
/// attacker-controlled: nothing stopped a caller from claiming `uid: 0` while
/// running as an unprivileged user, and policy decisions that referenced the
/// uid would have been made against a lie. The broker knows the real uid from
/// `SO_PEERCRED`, so the declared value is overwritten rather than trusted.
fn bind_peer_identity(request: &mut AuthorizationRequest, peer: &WorkloadIdentity) {
    request.context.peer_uid = peer.credentials.uid;
}

/// Registers a credential in the broker's in-memory inventory, writing nothing.
///
/// The name used to be `insert_credential`, and it was a lie: this pushes
/// metadata into a `Vec` and touches no vault, while a broker holding a real
/// one would answer `entries: []` — which is exactly what
/// `FND-broker-ignores-vault-inventory` was. The production path that actually
/// plants a credential is `Request::CreateCredential` through
/// [`crate::VaultWritePort`]; renaming this is what stops the next reader from
/// mistaking an inventory push for a write.
///
/// Test-only, and gated rather than merely documented because the absence of
/// this being wired to a vault is what that finding was. Production projects the
/// inventory through [`crate::inventory::load`], and so does the create verb
/// through [`crate::inventory::project_one`].
///
/// It stays available to this module's unit tests, which exercise broker
/// request handling against hand-built state and have no vault to read. What
/// is closed is the production surface: the production binary target never
/// compiled it, and now neither does the library.
#[cfg(test)]
pub fn register_inventory_credential(
    state: &mut BrokerState,
    metadata: CredentialMetadata,
) -> asv_domain::CredentialId {
    let id = metadata.id;
    state.credentials.push(metadata);
    id
}

/// The registry, for a test that wants to look at it.
///
/// `unwrap`, and deliberately so: production treats a poisoned lock as a hard
/// failure (see `BrokerState::surrogates`), but a poisoned lock in a test means
/// a test panicked while holding it, and the panic that follows is the one
/// that names the real culprit. Carrying the production discipline into the
/// tests would replace a clear message with "the broker's surrogate registry is
/// poisoned".
///
/// At the crate root rather than inside `mod tests` because `mod
/// surrogate_tests` is a sibling, not a child, and both reach it through their
/// own `use super::*`.
#[cfg(test)]
fn reg(state: &BrokerState) -> std::sync::MutexGuard<'_, SurrogateRegistry> {
    state
        .surrogates
        .lock()
        .expect("the test poisoned its own registry")
}

/// The session store, for a test. `unwrap`, for the reason `reg` gives.
#[cfg(test)]
fn sess(state: &BrokerState) -> std::sync::MutexGuard<'_, SessionStore> {
    state
        .sessions
        .lock()
        .expect("the test poisoned its own session store")
}

/// The audit chain, for a test. `unwrap`, for the reason `reg` gives.
#[cfg(test)]
fn aud(state: &BrokerState) -> std::sync::MutexGuard<'_, audit::AuditLog> {
    state
        .audit
        .lock()
        .expect("the test poisoned its own audit chain")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_connector_http::{SecretError, SecretSink};
    use asv_domain::CredentialId;
    use asv_domain::CredentialKind;
    use asv_identity::PeerCredentials;
    use asv_policy::{AuthorizationRequest, PolicyContext};
    use ed25519_dalek::Signer;

    fn peer() -> WorkloadIdentity {
        WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        })
    }

    /// A peer that is this process under a different pid — the shape a
    /// second agent on the same box has.
    fn stranger() -> WorkloadIdentity {
        WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32 + 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        })
    }

    /// A destination to aim a proof at. `asv.test` is used throughout, and it
    /// never resolves: these tests never open a socket, and a proof is about
    /// identity rather than connectivity.
    fn target() -> crate::tls_bridge::AuthorityEndpoint {
        crate::tls_bridge::AuthorityEndpoint::new(
            asv_domain::Authority::canonicalize("asv.test").expect("authority"),
            443,
        )
        .expect("endpoint")
    }

    /// What a real client sends: the blob, a counter, and a signature over the
    /// nonce the broker will rebuild. Building it here rather than signing a
    /// raw byte string is the point — it is the shape the wire actually has,
    /// and a test that signs arbitrary bytes would not notice if the broker
    /// derived the nonce from something else.
    fn proof_for(key: &ed25519_dalek::SigningKey, counter: u64) -> crate::tls_bridge::SessionProof {
        let blob = asv_ssh_agent::public_key_blob(&key.verifying_key());
        let nonce = crate::tls_bridge::proof_nonce(&blob, &target(), counter);
        crate::tls_bridge::SessionProof {
            signature: key.sign(&nonce).to_bytes().to_vec(),
            key: blob,
            counter,
        }
    }

    /// A session with a registered key, and the key to sign as that session.
    fn session_with_key(
        workspace: &str,
        seed: u8,
    ) -> (SessionStore, AgentSessionId, ed25519_dalek::SigningKey) {
        let peer = peer();
        let mut store = SessionStore::new();
        let session = store.create(workspace.into(), &peer);
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        store
            .register_key(
                session,
                &peer,
                asv_ssh_agent::public_key_blob(&key.verifying_key()),
            )
            .expect("register the key");
        (store, session, key)
    }

    /// A captured proof, presented twice, is refused the second time.
    ///
    /// This is the property the counter exists for. Before it, the identical
    /// `(key, destination)` pair verified forever, so a proof observed on the
    /// wire was good for the life of the session and for every surrogate that
    /// session held.
    #[test]
    fn a_proof_replayed_with_the_same_counter_is_refused() {
        let (mut store, session, key) = session_with_key("replay", 9);
        let proof = proof_for(&key, 1);
        assert_eq!(
            store.authenticate(&proof, &target()).ok(),
            Some(session),
            "the first presentation must succeed or the rest proves nothing"
        );
        assert_eq!(
            store.authenticate(&proof, &target()),
            Err(ProofRejection::Replayed),
            "the identical proof authenticated twice"
        );
    }

    /// A proof captured from an earlier tunnel, replayed after a later one.
    ///
    /// **This is the case the bitmap exists for, and it was the one that was
    /// missing.** The first replay test presented the same counter twice in a
    /// row, which the `age == 0` shortcut catches before the bitmap is
    /// consulted at all — so a mutation that disabled the duplicate-bit check
    /// entirely left the suite green. The bitmap only ever decides for a
    /// counter *below* the highest, which is exactly what an attacker
    /// replaying an old captured proof presents, and which no test was
    /// driving.
    #[test]
    fn an_earlier_proof_replayed_after_a_later_one_is_refused() {
        let (mut store, session, key) = session_with_key("old", 15);
        let first = proof_for(&key, 1);
        assert_eq!(store.authenticate(&first, &target()).ok(), Some(session));
        // A later tunnel moves the window on, so counter 1 is now below the
        // highest and only the bitmap can recognise it.
        assert_eq!(
            store.authenticate(&proof_for(&key, 2), &target()).ok(),
            Some(session)
        );
        assert_eq!(
            store.authenticate(&first, &target()),
            Err(ProofRejection::Replayed),
            "a proof captured from an earlier tunnel authenticated again"
        );
    }

    /// Out-of-order arrivals inside the window are legitimate, not replays.
    ///
    /// The strict alternative — refuse anything at or below the highest
    /// counter seen — turns two CONNECTs a client issued concurrently into
    /// one tunnel and one spurious denial, and the denial is indistinguishable
    /// from an attack to whoever has to debug it.
    #[test]
    fn a_counter_arriving_out_of_order_inside_the_window_is_accepted() {
        let (mut store, session, key) = session_with_key("ooo", 11);
        // 8 arrives first, then 7: the classic concurrent client.
        assert_eq!(
            store.authenticate(&proof_for(&key, 8), &target()).ok(),
            Some(session)
        );
        assert_eq!(
            store.authenticate(&proof_for(&key, 7), &target()).ok(),
            Some(session),
            "a legitimate out-of-order counter was refused as a replay"
        );
    }

    /// The budget the broker asks for has to survive the protocol's ceiling.
    ///
    /// `SurrogateRegistry::mint` clamps into `MAX_SURROGATE_USES`, and a clamp
    /// that lowers what you asked for is indistinguishable from one that does
    /// not. The broker asked for 32 and was served 8, with no error and no log
    /// line, and the wire reported the clamped value so every reader — the
    /// CLI, the audit, the tests — believed it.
    ///
    /// A session that can perform eight credentialed operations is not a
    /// backstop. It is a product limit, and it is what made 64 concurrent
    /// tunnels complete exactly eight.
    #[test]
    fn session_mint_survives_the_protocol_ceiling() {
        let (store, session, _key) = session_with_key("budget-ceiling", 3);
        let _ = store;
        let mut registry = SurrogateRegistry::default();
        let (_, _, granted) = registry
            .mint(
                session,
                CredentialId::from_wire("00000000-0000-4000-8000-000000000001").expect("wire id"),
                CredentialClass::Generic,
                60,
                SESSION_SURROGATE_MAX_USES,
                0,
            )
            .expect("mint");
        assert_eq!(
            granted, SESSION_SURROGATE_MAX_USES,
            "the protocol ceiling silently reduced the session budget from {}\
             to {granted}; a session can then perform {granted} operations and \
             no more, which is a product limit wearing the clothes of a backstop",
            SESSION_SURROGATE_MAX_USES
        );
    }

    /// The same claim, spent rather than compared: a session's surrogate has to
    /// survive a workload that was actually run.
    ///
    /// The two tests above compare numbers, which is the right shape for a
    /// clamp — a clamp changes a number without changing behaviour until
    /// something spends it. This one spends it. It redeems the token the way
    /// `SubstitutionPort` does, once per request, and counts.
    ///
    /// The measurement is `npm install --loglevel=http express`: 65 packages, 93
    /// requests, 2.1 MiB. At the budget this used to carry (32) that workload
    /// died at request 33, and the client saw its own token refused — which
    /// reads as a replay or a routing fault and is neither. The headroom is
    /// tenfold, the same ratio the per-tunnel limits are held to, because the
    /// measurement is a *trivial* install and the trivial one is the floor.
    #[test]
    fn a_session_surrogate_pays_for_a_workload_that_was_actually_run() {
        const MEASURED_REQUESTS: usize = 93;
        let (store, session, _key) = session_with_key("workload-budget", 3);
        let _ = store;
        let mut registry = SurrogateRegistry::default();
        let (token, _, _) = registry
            .mint(
                session,
                CredentialId::from_wire("00000000-0000-4000-8000-000000000001").expect("wire id"),
                CredentialClass::Generic,
                SESSION_SURROGATE_TTL_SECS,
                SESSION_SURROGATE_MAX_USES,
                0,
            )
            .expect("mint");

        let wanted = MEASURED_REQUESTS * 10;
        let mut funded = 0usize;
        for request in 0..wanted {
            match registry.redeem_for(&token, session, OperationFamily::GitHub, 0) {
                Ok(_) => funded += 1,
                Err(error) => panic!(
                    "request {request} of a workload measured at {MEASURED_REQUESTS} \
                     requests was refused ({error:?}); the session's surrogate paid for \
                     {funded} of them. The client sees its own token refused and has no \
                     way to tell a budget from a replay",
                ),
            }
        }
        assert_eq!(funded, wanted, "the budget is not the one it claims to be");
    }

    /// The same property for the **TTL**, which had none.
    ///
    /// `mint` clamps both arguments, silently: `let ttl = ttl_secs.clamp(1,
    /// MAX_SURROGATE_TTL_SECS)`. The uses clamp had a test and was found and
    /// fixed; the TTL clamp is the same line of code and had nobody looking at
    /// it, so it was live the whole time — the broker asking for an hour and
    /// every surrogate it minted living fifteen minutes, with the wire
    /// reporting the clamped number and nothing in the log saying otherwise.
    ///
    /// It matters for the relay rather than in the abstract. A surrogate is
    /// minted once per session and spent once per request, so the TTL is the
    /// wall-clock budget for a whole workload: at fifteen minutes a large build
    /// has its credential authority expire in the middle, and the failure looks
    /// like a client problem rather than like a ceiling.
    #[test]
    fn a_session_surrogate_survives_the_protocol_ceiling_on_time_too() {
        let (store, session, _key) = session_with_key("ttl-ceiling", 3);
        let _ = store;
        let mut registry = SurrogateRegistry::default();
        let (_, expires_at, _) = registry
            .mint(
                session,
                CredentialId::from_wire("00000000-0000-4000-8000-000000000001").expect("wire id"),
                CredentialClass::Generic,
                SESSION_SURROGATE_TTL_SECS,
                SESSION_SURROGATE_MAX_USES,
                0,
            )
            .expect("mint");
        assert_eq!(
            expires_at, SESSION_SURROGATE_TTL_SECS,
            "the protocol ceiling silently cut the surrogate lifetime from {}s to \
             {expires_at}s; every surrogate the broker mints then dies at a quarter \
             of the time the broker asked for, in the middle of whatever workload \
             it was meant to cover",
            SESSION_SURROGATE_TTL_SECS
        );
    }

    /// The same property, with a **gap** between the arrivals.
    ///
    /// The test above is the case the window was written for, and it is the one
    /// case that happens to work: 8 then 7 is a shift of one, and a shift of one
    /// puts the previous highest at bit 0, which is where the code marks it. A
    /// gap of two or more puts the previous highest somewhere else entirely,
    /// and the marking lands on a counter nobody has spent.
    ///
    /// This is not a hypothetical ordering. Measured against the real broker,
    /// 64 concurrent CONNECTs from one session complete eight of them and the
    /// broker refuses seventeen *legitimate* proofs as `Replayed` — counters 3,
    /// 8, 12, 16, 19 and a dozen more, each presented exactly once. The
    /// honest client paying for a concurrent burst is the only party in the
    /// window's own words: a liveness bug wearing a security costume.
    #[test]
    fn a_counter_arriving_out_of_order_after_a_gap_is_accepted() {
        let (mut store, session, key) = session_with_key("gap", 11);
        // A gap of two, then the counter that falls inside it.
        assert_eq!(
            store.authenticate(&proof_for(&key, 2), &target()).ok(),
            Some(session)
        );
        assert_eq!(
            store.authenticate(&proof_for(&key, 4), &target()).ok(),
            Some(session)
        );
        assert_eq!(
            store.authenticate(&proof_for(&key, 3), &target()).ok(),
            Some(session),
            "a legitimate counter that fell into a gap between two arrivals was \
             refused as a replay"
        );
        // And one further below, which the same reasoning covers.
        assert_eq!(
            store.authenticate(&proof_for(&key, 5), &target()).ok(),
            Some(session)
        );
        assert_eq!(
            store.authenticate(&proof_for(&key, 1), &target()).ok(),
            Some(session),
            "a legitimate counter below the lowest seen was refused as a replay"
        );
    }

    /// The same counter twice is still a replay, at every gap.
    ///
    /// The point of the fix that the test above motivates: closing a hole in
    /// the out-of-order path must not open one in the replay path. Without this
    /// a window that accepts everything is a window that catches nothing.
    #[test]
    fn a_counter_replayed_after_a_gap_is_still_refused() {
        let (mut store, _session, key) = session_with_key("gap-replay", 11);
        for counter in [2u64, 4, 4] {
            let _ = store.authenticate(&proof_for(&key, counter), &target());
        }
        assert!(
            store.authenticate(&proof_for(&key, 4), &target()).is_err(),
            "the same counter was accepted twice, which is the replay the window exists \
             to refuse"
        );
    }

    /// A counter older than the window is refused, and says so distinctly.
    ///
    /// The first version of this test did not reach the branch it named, and
    /// the falsification run is what proved it: it accepted 1, then 500, then
    /// replayed 1 — but accepting 500 had already *remembered* 1, so the
    /// "already spent" arm caught it and the stale arm was never entered.
    /// Disabling the stale arm left the suite green. Reaching it needs a
    /// counter old enough to have fallen out of a `BTreeSet`-shaped window,
    /// which a `u128` bitmap reaches after 128 counters.
    #[test]
    fn a_counter_older_than_the_window_is_refused_rather_than_accepted() {
        let (mut store, _session, key) = session_with_key("stale", 12);
        for counter in 0..1_000u64 {
            store
                .authenticate(&proof_for(&key, counter), &target())
                .expect("a fresh counter authenticates");
        }
        assert_eq!(
            store.authenticate(&proof_for(&key, 0), &target()),
            Err(ProofRejection::TooOld),
            "a counter far below the window was accepted, which reopens the \
             replay the window exists to close"
        );
    }

    /// The window is a fixed sixteen bytes, whatever an attacker does.
    #[test]
    fn the_window_does_not_grow_with_the_number_of_proofs() {
        let mut window = ReplayWindow::EMPTY;
        let before = std::mem::size_of::<ReplayWindow>();
        for counter in 0..100_000u64 {
            window.accept(counter);
        }
        assert_eq!(
            std::mem::size_of_val(&window),
            before,
            "the window grew with the number of counters"
        );
    }

    /// A proof that does not verify must not be able to spend a counter.
    ///
    /// This is the ordering, and it is the half that is easy to get
    /// backwards. If an unverified proof could reach the window, anyone who
    /// could not sign could walk the session's counters forward one at a time
    /// until the honest client's real counter looked stale — a denial of
    /// service delivered by a party that never proved anything, and one the
    /// honest client cannot tell from an attack.
    #[test]
    fn a_proof_that_does_not_verify_cannot_spend_a_counter() {
        let (mut store, session, key) = session_with_key("nospend", 13);
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        // Correct blob, wrong signature: the broker must not spend on it.
        let mut forged = proof_for(&key, 1);
        forged.signature = stranger
            .sign(&crate::tls_bridge::proof_nonce(&forged.key, &target(), 1))
            .to_bytes()
            .to_vec();
        assert_eq!(
            store.authenticate(&forged, &target()),
            Err(ProofRejection::NoSuchSession),
            "a forged proof authenticated"
        );
        // The honest client's counter 1 must still be available.
        assert_eq!(
            store.authenticate(&proof_for(&key, 1), &target()).ok(),
            Some(session),
            "a forged proof burned the honest client's counter: counter poisoning"
        );
    }

    /// Ending a session takes its replay window with it.
    ///
    /// The window lives inside the record, so this is not a property anything
    /// has to maintain — it is what happens. The test exists because the
    /// alternative (a window keyed outside the session table) is a map that
    /// has to be cleaned up in step, and a map that is not cleaned up is a
    /// leak that no test would notice until someone measured memory.
    #[test]
    fn ending_a_session_releases_its_replay_window() {
        let (mut store, session, key) = session_with_key("end", 14);
        store
            .authenticate(&proof_for(&key, 1), &target())
            .expect("first proof");
        assert!(store.end(session), "the session existed");
        assert_eq!(
            store.authenticate(&proof_for(&key, 1), &target()),
            Err(ProofRejection::NoSuchSession),
            "an ended session still resolved a proof"
        );
    }

    /// ADR-0019's binding. These pin the two properties the bridge depends
    /// on: only the owner may bind, and a live session never changes the
    /// key it was bound to.
    #[test]
    fn the_session_owner_binds_its_key_and_a_stranger_cannot() {
        let mut state = BrokerState::default();
        let session = match handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: "/tmp/project".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected a session, got {other:?}"),
        };

        let refused = handle(
            &mut state,
            &stranger(),
            Request::RegisterSessionKey {
                session,
                public_key_blob: b"attacker-key".to_vec(),
            },
        );
        assert!(
            matches!(
                refused,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "a stranger bound a key to a session it does not own: {refused:?}"
        );
        assert_eq!(
            sess(&state).public_key_of(session),
            None,
            "the refused registration left a key behind"
        );

        let accepted = handle(
            &mut state,
            &peer(),
            Request::RegisterSessionKey {
                session,
                public_key_blob: b"owner-key".to_vec(),
            },
        );
        assert_eq!(
            accepted,
            Response::SessionKeyRegistered { session },
            "the owner could not bind its own key"
        );
        assert_eq!(sess(&state).public_key_of(session), Some(&b"owner-key"[..]));
    }

    #[test]
    fn a_live_session_never_changes_the_key_it_was_bound_to() {
        let mut state = BrokerState::default();
        let session = match handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: "/tmp/project".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected a session, got {other:?}"),
        };
        handle(
            &mut state,
            &peer(),
            Request::RegisterSessionKey {
                session,
                public_key_blob: b"first".to_vec(),
            },
        );

        // Even the owner cannot re-point a session the bridge has already
        // issued proofs for.
        let second = handle(
            &mut state,
            &peer(),
            Request::RegisterSessionKey {
                session,
                public_key_blob: b"second".to_vec(),
            },
        );
        assert!(
            matches!(
                second,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "a second registration was accepted: {second:?}"
        );
        assert_eq!(
            sess(&state).public_key_of(session),
            Some(&b"first"[..]),
            "the key changed under a live session"
        );
    }

    #[test]
    fn registering_a_key_for_a_session_that_does_not_exist_is_refused() {
        let mut state = BrokerState::default();
        let ghost = AgentSessionId::new();
        let outcome = handle(
            &mut state,
            &peer(),
            Request::RegisterSessionKey {
                session: ghost,
                public_key_blob: b"key".to_vec(),
            },
        );
        assert!(
            matches!(
                outcome,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "a key was bound to a session that does not exist: {outcome:?}"
        );
        assert_eq!(sess(&state).public_key_of(ghost), None);
    }

    #[test]
    fn every_handled_request_is_audited_once() {
        let mut state = BrokerState::default();
        handle(
            &mut state,
            &peer(),
            Request::Ping {
                protocol: PROTOCOL_VERSION,
            },
        );
        handle(&mut state, &peer(), Request::ListCredentialMetadata);
        handle(
            &mut state,
            &peer(),
            Request::EndSession {
                session: AgentSessionId::new(),
            },
        );
        let records = aud(&state).query(0);
        assert_eq!(records.len(), 3, "one record per handle call");
        assert_eq!(records[0].seq, 0);
        assert_eq!(records[2].seq, 2);
        assert_eq!(aud(&state).verify(), Ok(()));
        // Outcome classification: the EndSession on an unknown session is an
        // error and must be audited as such, not as ok.
        match &records[2].event {
            asv_ipc_protocol::AuditEventDto::RequestHandled { outcome, .. } => {
                assert_eq!(outcome, "INVALID_REQUEST");
            }
            other => panic!("unexpected audit variant: {other:?}"),
        }
    }

    #[test]
    fn audit_query_is_denied_for_every_agent_peer() {
        let mut state = BrokerState::default();
        let resp = handle(&mut state, &peer(), Request::AuditQuery { since_secs: 0 });
        match resp {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::Denied);
                // Stronger than the old "operator control plane" substring:
                // the refusal now derives from ADR-0015's admission rule, so
                // it must name which of the three conditions failed. `peer()`
                // is built by `from_peer` and is therefore unpinned, so
                // condition 3 is the one that bites.
                assert!(message.contains("refused:"), "{message}");
                assert!(message.contains("pidfd-pinned"), "{message}");
            }
            other => panic!("audit query must never succeed for an agent peer: {other:?}"),
        }
        // And the probe itself was recorded: the refused attempt is evidence.
        assert_eq!(aud(&state).query(0).len(), 1);
    }

    /// The other half of the audit-query contract: an *admitted* control-plane
    /// peer reads the real log — the same chain `verify` checks, never a copy
    /// — and the read leaves the chain intact. R9's separation holds by shape:
    /// this verb has no write path in reach.
    #[test]
    fn an_admitted_peer_reads_the_audit_chain_and_it_still_verifies() {
        let mut state = BrokerState {
            control_plane: enrolment_of_this_binary(),
            ..BrokerState::default()
        };
        let operator = admitted_peer();
        admission::admit_control_plane(&operator, &state.control_plane, &admission::ProcFs)
            .expect("this fixture must be admitted, or the test below is vacuous");

        // Traffic so the log has records, and one of them is the audited read
        // itself: query(0) returns every record, including the one this
        // request just wrote.
        let _ = handle(
            &mut state,
            &operator,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        );
        match handle(&mut state, &operator, Request::AuditQuery { since_secs: 0 }) {
            Response::AuditRecords { records, .. } => {
                // The records are real: the create_session traffic above is
                // in them, metadata only. (The event's session field is None
                // here: the session is created BY that request, so the
                // audited method does not name one yet.)
                let saw_session = records.iter().any(|r| match &r.event {
                    asv_ipc_protocol::AuditEventDto::RequestHandled { method, .. } => {
                        method == "create_session"
                    }
                    other => panic!("unexpected audit variant: {other:?}"),
                });
                assert!(
                    saw_session,
                    "the read must return the real log: {records:?}"
                );
            }
            other => panic!("an admitted peer must read the audit log: {other:?}"),
        }
        // The dispatcher recorded the read itself AFTER the handler queried,
        // so the log now carries it — and the chain still verifies with the
        // read's own event inside.
        let after = aud(&state).query(0);
        let read_audited = after.iter().any(|r| match &r.event {
            asv_ipc_protocol::AuditEventDto::RequestHandled { method, .. } => {
                method == "audit_query"
            }
            other => panic!("unexpected audit variant: {other:?}"),
        });
        assert!(read_audited, "the read itself must be audited: {after:?}");
        assert_eq!(aud(&state).verify(), Ok(()));
    }

    #[test]
    fn canary_in_request_fields_never_reaches_audit_records() {
        const CANARY: &str = "ASV-CANARY-7f3c9a11-BROKER-AUDIT";
        let mut state = BrokerState::default();
        handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: CANARY.to_string(),
            },
        );
        for r in aud(&state).query(0) {
            let serialized = serde_json::to_string(&r).expect("dto serializes");
            assert!(!serialized.contains(CANARY), "canary leaked into audit");
        }
    }

    #[test]
    fn ping_reports_the_broker_protocol_version() {
        let mut state = BrokerState::default();
        let resp = handle(
            &mut state,
            &peer(),
            Request::Ping {
                protocol: PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            resp,
            Response::Pong {
                protocol: PROTOCOL_VERSION
            }
        );
    }

    /// A stale client must be rejected, not served in a degraded mode.
    #[test]
    fn version_mismatch_is_an_error_response() {
        let mut state = BrokerState::default();
        let resp = handle(&mut state, &peer(), Request::Ping { protocol: 0 });
        match resp {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::VersionMismatch),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn session_lifecycle_is_observable() {
        let mut state = BrokerState::default();
        let session = match handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        assert_eq!(sess(&state).len(), 1);

        assert_eq!(
            handle(&mut state, &peer(), Request::EndSession { session }),
            Response::SessionEnded { session }
        );
        assert!(sess(&state).is_empty());

        // Second revoke must report honestly instead of pretending.
        match handle(&mut state, &peer(), Request::EndSession { session }) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("double revoke must fail, got {other:?}"),
        }
    }

    /// A peer cannot end another peer's session.
    ///
    /// `EndSession` revokes the session's policy grants and kills its
    /// surrogates, so an unguarded arm let any process on the socket strip
    /// another agent's authority. The two refusals stay distinguishable:
    /// this one is a denial because the session exists and belongs to
    /// somebody else, which is not the same answer as "no such session".
    #[test]
    fn ending_another_peers_session_is_denied_and_leaves_it_alive() {
        let mut state = BrokerState::default();
        let owner = peer();
        let intruder = WorkloadIdentity::from_peer(PeerCredentials {
            pid: owner.credentials.pid + 1,
            uid: owner.credentials.uid,
            gid: owner.credentials.gid,
        });
        let session = sess(&state).create("/repo".into(), &owner);

        match handle(&mut state, &intruder, Request::EndSession { session }) {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::Denied, "{message}");
                assert!(
                    message.contains("not owned"),
                    "the refusal must name the ownership rule: {message}"
                );
            }
            other => panic!("a foreign peer ended the session: {other:?}"),
        }

        // The denial must not have half-applied: the session is still live,
        // so its grants and surrogates still work.
        assert_eq!(sess(&state).len(), 1, "the session survived the denial");
        assert!(sess(&state).belongs_to(session, &owner));

        // And the rightful owner can still end it.
        assert_eq!(
            handle(&mut state, &owner, Request::EndSession { session }),
            Response::SessionEnded { session }
        );
        assert!(sess(&state).is_empty());
    }

    #[test]
    fn protected_push_requires_exact_single_use_approval() {
        let mut state = BrokerState::default();
        let peer = peer();
        let session = match handle(
            &mut state,
            &peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: Some("main".into()),
                request_digest: Some("release-digest".into()),
                peer_uid: peer.credentials.uid,
            },
        };

        // The agent path cannot mint an approval, so the gate holds closed.
        let unapproved = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: None,
            },
        );
        assert!(
            matches!(&unapproved, Response::Authorization { explanation } if !explanation.decision.is_allowed()),
            "a protected push without approval was not gated: {unapproved:?}"
        );

        // The human control plane issues the approval out of band; M3 grants it
        // directly against the policy engine rather than over the agent IPC.
        let approval = state.policy.issue_approval(&request, 60, 1);

        let first = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: Some(approval.id),
            },
        );
        assert!(
            matches!(first, Response::Authorization { explanation } if explanation.decision.is_allowed())
        );

        let replay = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request,
                capability: None,
                approval: Some(approval.id),
            },
        );
        assert!(
            matches!(replay, Response::Authorization { explanation } if !explanation.decision.is_allowed())
        );
    }

    /// H1: an agent must not be able to mint its own approval. UAT-015 requires
    /// "broker blocks until approval" from a human, and the ADR-0004 consequence
    /// note says approval validity is *supplied* as trusted context, not that the
    /// agent supplies it. If this test fails, an agent can approve itself.
    #[test]
    fn agent_cannot_submit_its_own_approval() {
        let mut state = BrokerState::default();
        let agent_peer = peer();
        let session = match handle(
            &mut state,
            &agent_peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: Some("main".into()),
                request_digest: Some("release-digest".into()),
                peer_uid: agent_peer.credentials.uid,
            },
        };
        match handle(
            &mut state,
            &agent_peer,
            Request::SubmitApproval {
                request: request.clone(),
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => {
                panic!("agent minted its own approval, defeating the approval gate: {other:?}")
            }
        }
    }

    /// UAT-015 — policy approval, end to end: the high-risk action blocks
    /// until an admitted control-plane peer approves it; the approval binds
    /// the exact request; "allow once" cannot be replayed after use.
    ///
    /// H1 is the gate this closes, and its history explains the shape. The
    /// verb used to refuse unconditionally after a *successful* admission —
    /// "admission granted, but approvals have no path to the policy engine
    /// yet" — because wiring it here was feared as self-approval. What makes
    /// minting here safe is not the socket but the custody contract on
    /// [`admission::Enrolment`]: the enrolled list is the operator's own
    /// binaries and an agent binary must never enter it. The test above pins
    /// the unenrolled refusal; this one must not be satisfiable by the boring
    /// reason, so it asserts admission genuinely succeeds before anything
    /// else.
    ///
    /// Every step asserts content, not just shape: the mint carries the
    /// exact binding (session, action, digest, budget), the spend allows
    /// once, the replay comes back `ApprovalConsumed`, and an approval spent
    /// on a request it does not describe comes back `ApprovalMismatch` —
    /// ids are not interchangeable, which is the property that keeps the
    /// approval path from reopening the hole by another route.
    #[test]
    fn an_admitted_operator_mints_an_approval_the_agent_can_spend_once() {
        // UAT-015 — policy approval, end to end over the IPC handlers:
        // a high-risk request is blocked until an admitted control-plane peer
        // approves it; the approval binds the exact request; one use; the
        // replay is refused as consumed.
        let mut state = BrokerState {
            control_plane: enrolment_of_this_binary(),
            ..BrokerState::default()
        };
        let operator = admitted_peer();

        // The control, and the reason this test is not a duplicate of the
        // unenrolled one above: prove admission genuinely succeeds here.
        // Without this the mint assertion below could be satisfied by
        // `NotEnrolled` and would prove nothing about the path under test.
        admission::admit_control_plane(&operator, &state.control_plane, &admission::ProcFs)
            .expect("this fixture must be admitted, or the test below is vacuous");

        // The agent's session: same peer for simplicity of the fixture — the
        // session belongs to whoever created it, and the operator here plays
        // both sides. Custody of the enrolment is what makes the operator the
        // operator; the socket is shared by design (see admission docs).
        let session = match handle(
            &mut state,
            &operator,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: Some("main".into()),
                request_digest: Some("release-digest".into()),
                peer_uid: operator.credentials.uid,
            },
        };

        // 1. Without an approval the high-risk request is blocked, with a
        //    decision that names what it wants.
        let blocked = match handle(
            &mut state,
            &operator,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: None,
            },
        ) {
            Response::Authorization { explanation } => explanation,
            other => panic!("expected an authorization decision, got {other:?}"),
        };
        assert!(
            matches!(
                blocked.decision,
                asv_domain::Decision::RequireApproval { .. }
            ),
            "the protected-main push must block on approval first, got {:?}",
            blocked.decision
        );

        // 2. The admitted operator submits the approval for exactly this
        //    request and gets the minted approval back.
        let approval = match handle(
            &mut state,
            &operator,
            Request::SubmitApproval {
                request: request.clone(),
                ttl_secs: 60,
            },
        ) {
            Response::ApprovalIssued { approval } => approval,
            other => panic!("an admitted operator must be able to mint: {other:?}"),
        };
        assert_eq!(approval.session, request.session);
        assert_eq!(approval.action, request.action);
        assert_eq!(approval.request_digest, request.context.request_digest);
        assert_eq!(approval.remaining_uses, APPROVAL_REMAINING_USES);

        // 3. The agent presents the approval id: the push goes through, once.
        let spent = match handle(
            &mut state,
            &operator,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: Some(approval.id),
            },
        ) {
            Response::Authorization { explanation } => explanation,
            other => panic!("expected the approved push to be evaluated, got {other:?}"),
        };
        assert!(
            matches!(spent.decision, asv_domain::Decision::Allow),
            "the approved push must be allowed, got {:?}",
            spent.decision
        );

        // 4. Allow once: the replay is refused as consumed, and the refusal
        //    is the policy's own reason, reached over the same handler.
        let replay = match handle(
            &mut state,
            &operator,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: Some(approval.id),
            },
        ) {
            Response::Authorization { explanation } => explanation,
            other => panic!("expected the replay to be evaluated, got {other:?}"),
        };
        assert!(
            matches!(
                replay.decision,
                asv_domain::Decision::Deny { ref reason } if reason == "approval consumed"
            ),
            "the replay must be refused as consumed, got {:?}",
            replay.decision
        );

        // 5. The binding is exact: an approval is only ever spent on the
        //    request it describes. A different digest must mismatch even
        //    with a fresh approval minted for that other request — the
        //    ids are not interchangeable.
        let mut other_request = request.clone();
        other_request.context.request_digest = Some("other-digest".into());
        let other_approval = match handle(
            &mut state,
            &operator,
            Request::SubmitApproval {
                request: other_request.clone(),
                ttl_secs: 60,
            },
        ) {
            Response::ApprovalIssued { approval } => approval,
            other => panic!("the second mint must also succeed: {other:?}"),
        };
        let mismatch = match handle(
            &mut state,
            &operator,
            Request::Authorize {
                request,
                capability: None,
                approval: Some(other_approval.id),
            },
        ) {
            Response::Authorization { explanation } => explanation,
            other => panic!("expected the mismatching spend to be evaluated, got {other:?}"),
        };
        assert!(
            matches!(
                mismatch.decision,
                asv_domain::Decision::Deny { ref reason } if reason == "approval mismatch"
            ),
            "spending an approval on a request it does not describe must \
             mismatch, got {:?}",
            mismatch.decision
        );
    }

    /// H2: `PolicyContext.peer_uid` arrives inside the request body, so it is
    /// attacker-controlled. The broker must overwrite it with the
    /// kernel-attested uid before policy sees it, otherwise any uid-aware rule
    /// would be decided against a lie the caller invented.
    #[test]
    fn policy_context_peer_uid_is_overwritten_by_kernel_evidence() {
        let mut state = BrokerState::default();
        let agent_peer = peer();
        let session = match handle(
            &mut state,
            &agent_peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let real_uid = agent_peer.credentials.uid;
        let mut request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: None,
                request_digest: None,
                peer_uid: 0,
            },
        };
        assert_eq!(request.context.peer_uid, 0, "client declared a forged uid");

        bind_peer_identity(&mut request, &agent_peer);

        assert_eq!(
            request.context.peer_uid, real_uid,
            "forged peer_uid survived into the policy context"
        );
        assert_ne!(request.context.peer_uid, 0);
    }

    /// Metadata listing is the only credential surface, and it must be empty by
    /// default rather than seeded with anything resembling a value.
    #[test]
    fn listing_credentials_returns_metadata_only() {
        let mut state = BrokerState::default();
        let id = register_inventory_credential(
            &mut state,
            CredentialMetadata::new("github-work", CredentialKind::BearerToken),
        );

        let resp = handle(&mut state, &peer(), Request::ListCredentialMetadata);
        let entries = match resp {
            Response::CredentialMetadata { entries } => entries,
            other => panic!("expected metadata, got {other:?}"),
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, *id.as_uuid());
        assert_eq!(entries[0].label, "github-work");

        let json = serde_json::to_string(&entries).expect("serializes");
        assert!(!json.to_lowercase().contains("secret"));
    }

    /// Credential deletion is a closed door for agent peers, and it is a
    /// closed door that answers the same way whether or not the id exists.
    ///
    /// The previous behaviour answered `InvalidRequest` for an unknown id and
    /// `CredentialDeleted` for a known one, which made deletion an existence
    /// oracle: an agent could enumerate the operator's credentials by
    /// watching which ids came back deleted. One unconditional refusal closes
    /// that and the denial-of-service with it.
    #[test]
    fn credential_deletion_is_refused_and_does_not_confirm_existence() {
        let mut state = BrokerState::default();
        let known = register_inventory_credential(
            &mut state,
            CredentialMetadata::new("github-work", asv_domain::CredentialKind::BearerToken),
        );
        let ghost = CredentialId::new();

        // Identical refusal for an id that exists and one that does not. If
        // these ever differ again, the difference is an oracle.
        //
        // The two messages are compared to *each other*, byte for byte, and
        // collecting them is what makes that possible. This test used to
        // assert only that both messages contained "refused:" and
        // "pidfd-pinned", which any pair of messages differing in every other
        // byte also satisfies — an oracle with the id appended passes it.
        // Falsification mutation M5, which appends the id to the refusal, came
        // back green against the old version of this test; that is how the gap
        // was found, and the comparison below is what closes it.
        let mut refusals = Vec::new();
        for (label, id) in [("known", known), ("ghost", ghost)] {
            match handle(&mut state, &peer(), Request::DeleteCredential { id }) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Denied, "{label}");
                    // The refusal must name the admission condition that
                    // failed. That is a separate property from the oracle
                    // property asserted below, so both are checked.
                    assert!(
                        message.contains("refused:") && message.contains("pidfd-pinned"),
                        "{label}: the refusal must name which admission condition \
                         failed: {message}"
                    );
                    refusals.push(message);
                }
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
        assert_eq!(
            refusals[0], refusals[1],
            "the two refusals differ in a byte, which is exactly the existence \
             oracle this verb must not be"
        );
        assert!(
            !refusals[0].contains(&known.to_wire()),
            "the refusal echoed the id back to an unadmitted caller: {}",
            refusals[0]
        );

        // The refusal did not touch the store: the credential is still there,
        // so a denied delete cannot be mistaken for a revocation.
        assert!(
            state.credentials.iter().any(|c| c.id == known),
            "a refused deletion must leave the credential in place"
        );

        // And the attempt itself is auditable: an agent probing this verb is
        // exactly the event an operator needs to see.
        let records = aud(&state).query(0);
        assert_eq!(records.len(), 2, "both refusals are recorded");
        for record in &records {
            match &record.event {
                asv_ipc_protocol::AuditEventDto::RequestHandled { outcome, .. } => {
                    assert_eq!(outcome, "DENIED");
                }
                other => panic!("unexpected audit variant: {other:?}"),
            }
        }
    }

    // ---------------------------------------------------------------------
    // The granted path of `DeleteCredential`.
    //
    // Everything above this line is about the closed door; everything below is
    // about the door being open, which is the half that had never existed.
    // ---------------------------------------------------------------------

    /// A peer that is admitted as the control plane **without a single fake**.
    ///
    /// The obvious way to test the granted branch is to inject an admission
    /// stub, and it is refused here for a reason that is not taste: a seam able
    /// to answer "this caller is enrolled" is a seam that could also be wired
    /// to a test double in production, and the whole point of ADR-0015 is that
    /// the human's identity is never self-asserted.
    ///
    /// So each condition is obtained honestly instead:
    ///
    /// 1. *pidfd-pinned* — a real `pidfd_open` on this live test process.
    /// 2. *not under broker control* — by observation, not by stubbing.
    ///    `parse_cgroup_membership` reports only segments carrying the broker's
    ///    slice prefix, and a test process is in no broker slice, so the
    ///    condition holds for the same reason it holds for a human's shell.
    /// 3. *positively enrolled* — the enrolment record is the operator-held
    ///    input the ADR makes authoritative, so a test may set it. It is set
    ///    from this binary's real `/proc/self/exe` and the real SHA-256 of
    ///    those bytes, which means the check cannot pass by agreeing with a
    ///    fake: it has to agree with the file the kernel points at.
    fn admitted_peer() -> WorkloadIdentity {
        let mut identity = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        identity
            .pin_pidfd()
            .expect("the test process is live and pinnable");
        assert!(
            identity.is_pidfd_pinned(),
            "the fixture must be pinned or it tests the closed door"
        );
        identity
    }

    /// The enrolment that admits [`admitted_peer`]: this test binary, as it
    /// really is on this machine at this moment.
    fn enrolment_of_this_binary() -> admission::Enrolment {
        let path = std::fs::read_link("/proc/self/exe").expect("this process has an exe");
        let bytes = std::fs::read(&path).expect("the test binary is readable");
        admission::Enrolment::empty().enrol(path, admission::sha256(&bytes))
    }

    /// A real encrypted vault holding one credential, wired into a
    /// `BrokerState` the way a running broker wires it: a `VaultWritePort` and
    /// a `SecretPort` over the *same* store instance, the inventory loaded from
    /// the file, and this binary enrolled as the control plane.
    ///
    /// Returns the `TempDir` too, so the vault outlives the test rather than
    /// being dropped underneath the assertions.
    fn wired_vault() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        BrokerState,
        CredentialId,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.asv");
        let pass = secrecy::SecretString::from("delete-write-through".to_string());
        let mut store =
            asv_vault::VaultStore::create(&path, &pass, asv_vault::KdfParams::fast_for_tests())
                .expect("create vault");
        let key = store.header().unlock(&pass).expect("unlock");

        let id = CredentialId::new();
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    id.to_wire(),
                    "github-work",
                    asv_vault::CredentialKind::BearerToken,
                    "github",
                    "acct",
                    1,
                ),
                asv_domain::secret::SecretBytes::new(b"the-secret".to_vec()),
            )
            .expect("insert");

        let store = Arc::new(std::sync::Mutex::new(store));
        let key = Arc::new(key);

        let mut state = BrokerState::default();
        // The inventory is loaded from the file, exactly as production loads
        // it, so these tests start from the state a real broker is in rather
        // than from a hand-built mirror that could be wrong in a way the test
        // would then happily confirm.
        crate::inventory::load(&mut state, &store.lock().expect("lock"));
        state.vault_writer = Some(Arc::new(VaultWritePort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));
        state.control_plane = enrolment_of_this_binary();

        assert!(
            state.credentials.iter().any(|c| c.id == id),
            "the fixture must actually have loaded the credential it claims to hold"
        );
        (dir, path, state, id)
    }

    /// REQ-1. The revocation reaches the **file**, and that is the whole
    /// finding: the defect was a delete that removed a credential from the
    /// running broker and left it in the vault, so the next restart undid the
    /// revocation.
    ///
    /// The check is made from a *second* `VaultStore` opened on the same path
    /// after the delete. A store sharing the first one's memory would prove
    /// nothing about the file, and asserting on the live handle is the exact
    /// mistake this test exists to avoid.
    #[test]
    fn an_admitted_delete_reaches_the_vault_file() {
        let (_dir, path, mut state, id) = wired_vault();
        let pass = secrecy::SecretString::from("delete-write-through".to_string());
        let peer = admitted_peer();

        let before = asv_vault::VaultStore::open(&path, &pass).expect("open before");
        let revision_before = before.revision();
        assert_eq!(before.list().len(), 1, "the fixture holds one credential");

        match handle(&mut state, &peer, Request::DeleteCredential { id }) {
            Response::CredentialDeleted { id: reported } => {
                assert_eq!(reported, id, "the broker reported a different id");
            }
            other => panic!("expected a deletion, got {other:?}"),
        }

        // A different process's worth of state: a fresh handle, decrypted
        // from the file, with nothing of the running broker's memory in it.
        let after = asv_vault::VaultStore::open(&path, &pass).expect("open after");
        assert!(
            after.list().is_empty(),
            "the credential is gone from memory but still in the file — the P1"
        );
        assert!(
            after.revision() > revision_before,
            "a write that does not advance the revision is not a write: {revision_before} -> {}",
            after.revision()
        );
    }

    /// REQ-2. The inventory follows the file and never the reverse: a broker
    /// must not advertise, or mint against, a credential the file no longer
    /// has. The mirror image of the create path's original defect.
    #[test]
    fn an_admitted_delete_takes_the_credential_out_of_the_inventory() {
        let (_dir, _path, mut state, id) = wired_vault();
        let peer = admitted_peer();

        handle(&mut state, &peer, Request::DeleteCredential { id });

        assert!(
            !state.credentials.iter().any(|c| c.id == id),
            "the mirror still advertises a deleted credential"
        );
        match handle(&mut state, &peer, Request::ListCredentialMetadata) {
            Response::CredentialMetadata { entries } => {
                assert!(
                    entries.is_empty(),
                    "the operator still sees a credential that is not in the vault"
                );
            }
            other => panic!("expected metadata, got {other:?}"),
        }
    }

    /// REQ-2, ordering. Nothing may follow the file until the file has
    /// actually changed. A refused write must leave the mirror and the token
    /// table exactly as they were, or the two drift and a credential the vault
    /// never had starts being advertised.
    ///
    /// The refused write is produced honestly, without a stubbing seam: the id
    /// is in the inventory but not in the file, which is precisely the state
    /// this ordering is supposed to survive.
    #[test]
    fn a_refused_write_leaves_the_inventory_and_the_tokens_alone() {
        let (_dir, _path, mut state, _id) = wired_vault();
        let peer = admitted_peer();

        // A credential the broker advertises and the file does not hold.
        let ghost = register_inventory_credential(
            &mut state,
            CredentialMetadata::new("never-written", CredentialKind::BearerToken),
        );
        let session = sess(&state).create("/repo".to_string(), &peer);
        let (surrogate, _) = {
            let (token, _, _) = reg(&state)
                .mint(session, ghost, CredentialClass::Generic, 60, 2, now_secs())
                .expect("mint");
            (token, ())
        };
        assert_eq!(reg(&state).len(), 1, "a token is in flight");

        match handle(&mut state, &peer, Request::DeleteCredential { id: ghost }) {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
                assert_eq!(message, "no such credential");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        assert!(
            state.credentials.iter().any(|c| c.id == ghost),
            "a write that never happened must not change the mirror"
        );
        assert_eq!(
            reg(&state).len(),
            1,
            "a write that never happened must not revoke a live token"
        );
        assert_eq!(
            reg(&state).redeem_for(&surrogate, session, OperationFamily::GitHub, now_secs()),
            Ok(ghost),
            "the token must still work: nothing was actually revoked"
        );
    }

    /// REQ-3, both halves. A token minted before the revocation stops working
    /// *and* stops being counted as live.
    ///
    /// These are separate properties and the first one is not this change's
    /// doing: the lender already fails closed because `with_secret` gates on
    /// the in-memory body, which the write emptied. The second half is what
    /// `revoke_credential` adds, and a test that only asserted the first would
    /// pass against a registry still lying about what is live.
    #[test]
    fn tokens_minted_before_a_revocation_stop_working_and_stop_counting() {
        let (_dir, _path, mut state, id) = wired_vault();
        let peer = admitted_peer();

        let session = sess(&state).create("/repo".to_string(), &peer);
        let (surrogate, _, _) = reg(&state)
            .mint(session, id, CredentialClass::Generic, 60, 5, now_secs())
            .expect("mint");
        assert_eq!(reg(&state).len(), 1, "the token is live before");

        // The secret really is reachable through the port before the delete,
        // so the assertion after it is about the delete and not about a
        // fixture that was never wired.
        {
            let mut sink = RecordingSink::default();
            let port = state
                .secrets
                .as_ref()
                .expect("the fixture wires a secret port")
                .as_ref();
            port.lend(&id.to_wire(), &mut sink).expect("lends before");
            assert_eq!(sink.seen, b"the-secret");
        }

        handle(&mut state, &peer, Request::DeleteCredential { id });

        // Half one: it cannot get the secret.
        {
            let mut sink = RecordingSink::default();
            let port = state.secrets.as_ref().expect("still wired").as_ref();
            let error = port
                .lend(&id.to_wire(), &mut sink)
                .expect_err("a revoked credential must not lend");
            assert!(matches!(error, SecretError::NotFound(_)), "{error:?}");
            assert_eq!(sink.accepts, 0, "the sink ran without a secret");
        }

        // Half two: the registry stopped calling it live.
        assert_eq!(
            reg(&state).len(),
            0,
            "the registry still reports a token for a credential that is gone"
        );
        assert_eq!(
            reg(&state).redeem_for(&surrogate, session, OperationFamily::GitHub, now_secs()),
            Err(SurrogateError::Unknown)
        );
    }

    /// REQ-6. An admitted caller asking about an id that is not there is told
    /// the truth, and is never told a revocation happened when none did.
    ///
    /// This is not an oracle, and the distinction is the design. The oracle
    /// property belongs to the *refused* case, which cannot reach this code at
    /// all; a caller that gets here is the operator's own enrolled principal
    /// and can already read the whole inventory through
    /// `ListCredentialMetadata`. Answering "that succeeded" would be the only
    /// dishonest option here.
    #[test]
    fn an_admitted_caller_is_told_a_ghost_id_does_not_exist() {
        let (_dir, _path, mut state, id) = wired_vault();
        let peer = admitted_peer();
        let ghost = CredentialId::new();

        let response = handle(&mut state, &peer, Request::DeleteCredential { id: ghost });

        match response {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
                assert_eq!(message, "no such credential");
            }
            other => panic!(
                "a delete of an id that does not exist must not read as a revocation: {other:?}"
            ),
        }
        // And the real credential is untouched by the failed attempt.
        assert!(
            state.credentials.iter().any(|c| c.id == id),
            "a refused delete must not remove anything"
        );
    }

    /// REQ-5. The refusal the old code produced claimed the vault write path
    /// was missing while it was present, which is the kind of lie that costs an
    /// operator an afternoon. Both branches that can still be reached must
    /// name a condition that is true when it is printed.
    #[test]
    fn no_refusal_claims_a_capability_the_broker_actually_has() {
        // An unpinned peer, which is the state every other test runs in.
        let mut state = BrokerState::default();
        let message = match handle(
            &mut state,
            &peer(),
            Request::DeleteCredential {
                id: CredentialId::new(),
            },
        ) {
            Response::Error { message, .. } => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(
            !message.contains("does not have yet"),
            "the refusal claims a missing capability the code does not lack: {message}"
        );
        assert!(
            !message.contains("still requires the vault write path"),
            "the refusal claims a missing capability the code does not lack: {message}"
        );
        // It names a real condition instead, and that condition is the one
        // that actually failed.
        assert!(message.contains("pidfd-pinned"), "{message}");

        // The admitted-but-no-vault branch, whose claim *is* true because
        // there genuinely is no writer. Built in one expression rather than
        // assigned after `default()`, so the state under test is visible in
        // the fixture rather than one line away from it.
        let mut unwired = BrokerState {
            control_plane: enrolment_of_this_binary(),
            ..BrokerState::default()
        };
        let message = match handle(
            &mut unwired,
            &admitted_peer(),
            Request::DeleteCredential {
                id: CredentialId::new(),
            },
        ) {
            Response::Error { message, .. } => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(
            message.contains("no vault write path"),
            "an unwired broker must say so plainly: {message}"
        );
        assert!(
            unwired.vault_writer.is_none(),
            "the fixture must really be unwired for that claim to be true"
        );
    }

    /// REQ-4, the second denial. The anti-oracle test above pins a peer that
    /// fails the *pin* condition; this one fails the *enrolment* condition,
    /// which is the branch a real agent on a real machine would hit once it
    /// somehow carried a pin. Both must answer identically for an id that
    /// exists and one that does not, and both must leave the vault alone.
    #[test]
    fn a_pinned_but_unenrolled_peer_learns_nothing_either() {
        let (_dir, _path, mut state, id) = wired_vault();
        // Pinned — condition 3 passes — but the enrolment record is empty, so
        // condition 2 is the one that fails. That is the branch a real agent
        // on a real machine would hit if it ever carried a pin.
        let peer = admitted_peer();
        state.control_plane = admission::Enrolment::empty();

        let ghost = CredentialId::new();
        let mut messages = Vec::new();
        for (label, target) in [("known", id), ("ghost", ghost)] {
            match handle(&mut state, &peer, Request::DeleteCredential { id: target }) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Denied, "{label}");
                    messages.push(message);
                }
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
        assert_eq!(
            messages[0], messages[1],
            "the two answers differ, which is an existence oracle"
        );
        assert!(
            !messages[0].contains(&id.to_wire()),
            "the refusal leaked the id: {}",
            messages[0]
        );
        assert!(
            state.credentials.iter().any(|c| c.id == id),
            "a refused deletion must leave the credential in place"
        );
    }

    /// A sink that keeps the bytes it is handed, so a test can assert the
    /// secret was or was not lent. The real connector sink scrubs on drop;
    /// this one has to hold them long enough to look at.
    #[derive(Default)]
    struct RecordingSink {
        seen: Vec<u8>,
        accepts: u32,
    }

    impl SecretSink for RecordingSink {
        fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
            self.seen = secret.to_vec();
            self.accepts += 1;
            Ok(())
        }
    }

    /// A canary in any request field must not reach the response bytes.
    #[test]
    fn canary_never_crosses_the_response_boundary() {
        const CANARY: &str = "ASV-CANARY-5b2f8a31-DO-NOT-LEAK";
        let mut state = BrokerState::default();
        let resp = handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: CANARY.into(),
            },
        );
        let bytes = asv_ipc_protocol::encode_response(&resp).expect("encodes");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "canary leaked into response: {text}"
        );
    }
}

/// The M4 session-bound surrogate tests. These drive the real `handle` entry
/// point rather than the registry directly, because the questions that matter
/// here are about the broker's decisions, not about the registry's internals.
#[cfg(test)]
mod surrogate_tests {
    use super::*;
    use asv_domain::CredentialId;
    use asv_domain::CredentialKind;
    use asv_identity::PeerCredentials;
    use asv_ipc_protocol::MAX_SURROGATE_USES;

    /// A peer whose process is pinned, which is the precondition D4 puts on
    /// minting. The pin is real: `pin_pidfd` on this very process.
    fn pinned_peer() -> WorkloadIdentity {
        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pidfd_open on self");
        assert!(peer.is_pidfd_pinned(), "the fixture must be pinned");
        peer
    }

    /// The weaker state: kernel-attested credentials, no pidfd. M0 treats this
    /// as usable, and D4 keeps that decision.
    fn unpinned_peer() -> WorkloadIdentity {
        let peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        assert!(!peer.is_pidfd_pinned(), "the fixture must be unpinned");
        peer
    }

    fn state_with_credential() -> (BrokerState, CredentialId) {
        let mut state = BrokerState::default();
        let metadata = CredentialMetadata::new("github-work", CredentialKind::BearerToken);
        let id = register_inventory_credential(&mut state, metadata);
        (state, id)
    }

    fn mint(state: &mut BrokerState, peer: &WorkloadIdentity) -> (AgentSessionId, String) {
        let session = sess(state).create("/repo".to_string(), peer);
        let credential = state.credentials[0].id;
        match handle(
            state,
            peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => (session, surrogate),
            other => panic!("expected a minted surrogate, got {other:?}"),
        }
    }

    /// The defect this pins: `MintSurrogate` validates against
    /// `state.credentials`, and until this cycle nothing in production ever
    /// filled that list. Every other surrogate test seeds it with
    /// `insert_credential`, which is why 584 green assertions never noticed
    /// that a real broker could mint nothing at all.
    ///
    /// So this test builds the list the way a running broker does — from a real
    /// vault on disk, through the inventory loader — and mints against it.
    #[test]
    fn a_credential_loaded_from_a_real_vault_can_mint_a_surrogate() {
        const ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = secrecy::SecretString::from("mint-from-vault".to_string());
        let mut store = asv_vault::VaultStore::create(
            dir.path().join("v.asv"),
            &pass,
            asv_vault::KdfParams::fast_for_tests(),
        )
        .expect("create vault");
        let key = store.header().unlock(&pass).expect("unlock");
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    ID,
                    "from-the-vault",
                    asv_vault::CredentialKind::BearerToken,
                    "github",
                    "acct",
                    1,
                ),
                asv_domain::secret::SecretBytes::new(b"secret".to_vec()),
            )
            .expect("insert");

        let mut state = BrokerState::default();
        let loaded = crate::inventory::load(&mut state, &store);
        assert_eq!(
            loaded,
            crate::inventory::InventoryLoad {
                loaded: 1,
                skipped: 0,
                collisions: 0,
            },
            "the vault credential must have loaded"
        );

        let peer = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);
        let credential = state.credentials[0].id;
        assert_eq!(
            credential.to_wire(),
            ID,
            "the loaded handle must be the id the vault stored"
        );

        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { .. } => {}
            other => panic!("a vault credential must be mintable, got {other:?}"),
        }
    }

    /// And the guard that was doing the wrong job for the right reason: a
    /// credential the broker has never heard of is still refused, so loading the
    /// inventory did not turn the check into a rubber stamp.
    #[test]
    fn minting_still_refuses_a_credential_the_broker_does_not_hold() {
        let mut state = BrokerState::default();
        let peer = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);
        let unknown = CredentialId::new();
        let unknown_wire = unknown.to_wire();

        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential: unknown,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::Error { message, .. } => {
                assert!(
                    message.contains("credential is not available"),
                    "unexpected refusal: {message}"
                );
                assert!(
                    !message.contains(&unknown_wire),
                    "unknown credential diagnostics must not echo the handle"
                );
            }
            other => panic!("an unknown credential must be refused, got {other:?}"),
        }
    }

    /// D4's directed requirement: an unpinned session is still usable for
    /// everything M0 allowed, but it cannot mint a credential-shaped token.
    /// Without this test, "directed" is indistinguishable from "global deny".
    #[test]
    fn an_unpinned_session_can_still_create_and_end_sessions() {
        let mut state = BrokerState::default();
        let peer = unpinned_peer();
        let session = match handle(
            &mut state,
            &peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session, .. } => session,
            other => panic!("expected creation, got {other:?}"),
        };
        assert!(
            !sess(&state).is_pinned(session),
            "the fixture session is unpinned"
        );
        assert_eq!(
            handle(&mut state, &peer, Request::EndSession { session }),
            Response::SessionEnded { session },
            "M0 behaviour must be preserved for an unpinned peer"
        );
    }

    /// And the narrow refusal that D4 actually asks for.
    #[test]
    fn an_unpinned_peer_cannot_mint_a_surrogate() {
        let (mut state, credential) = state_with_credential();
        let peer = unpinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("an unpinned peer must be refused, got {other:?}"),
        }
        assert!(
            reg(&state).is_empty(),
            "a refused mint must leave no token behind"
        );
    }

    /// A pinned peer mints successfully, and the response carries a token that
    /// is recognisably a surrogate rather than anything credential-shaped.
    #[test]
    fn a_pinned_peer_mints_a_bounded_surrogate() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);
        assert!(token.starts_with("asv1_"), "{token}");
        assert_eq!(reg(&state).len(), 1);

        // The session ends, the token dies with it. This is the property that
        // makes the session a real boundary rather than bookkeeping.
        assert_eq!(
            handle(&mut state, &peer, Request::EndSession { session }),
            Response::SessionEnded { session }
        );
        assert_eq!(
            reg(&state).len(),
            0,
            "ending a session must revoke its surrogates"
        );
    }

    /// A session owned by another peer must not mint, even with a valid
    /// credential id. The session check runs before the credential lookup, so
    /// the answer is a denial and never "no such credential", which would
    /// confirm the id exists.
    #[test]
    fn a_session_cannot_be_used_by_a_stranger() {
        let (mut state, credential) = state_with_credential();
        let owner = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &owner);

        // A different PID, so `belongs_to` is false.
        let stranger = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32 + 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        match handle(
            &mut state,
            &stranger,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("a stranger must be refused, got {other:?}"),
        }
        assert!(reg(&state).is_empty());
    }

    /// Minting against a credential the broker does not hold would produce a
    /// token that always fails later, which reads as a broker bug rather than
    /// a client error.
    #[test]
    fn an_unknown_credential_is_refused_at_mint_time() {
        let mut state = BrokerState::default();
        let peer = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential: CredentialId::new(),
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("an unknown credential must be refused, got {other:?}"),
        }
        assert!(reg(&state).is_empty());
    }

    /// A client asking for an absurd budget is clamped, and the clamped value
    /// is what comes back. The agent can then budget its own calls against the
    /// real number instead of the one it asked for.
    #[test]
    fn a_client_cannot_widen_its_own_surrogate_budget() {
        let (mut state, credential) = state_with_credential();
        let peer = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: u32::MAX,
                ttl_secs: u64::MAX,
            },
        ) {
            Response::SurrogateMinted {
                max_uses,
                expires_at,
                surrogate,
            } => {
                assert_eq!(max_uses, MAX_SURROGATE_USES);
                assert!(surrogate.starts_with("asv1_"));
                assert!(expires_at > 0);
            }
            other => panic!("expected a clamped mint, got {other:?}"),
        }
    }

    /// Revoke is session-scoped, and revoking something you do not own reports
    /// honestly instead of pretending it worked.
    #[test]
    fn revoke_is_scoped_to_the_owning_session() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);

        // A stranger's revoke, under their own session, must not touch it.
        let other_session = sess(&state).create("/other".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::RevokeSurrogate {
                session: other_session,
                surrogate: token.clone(),
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("a cross-session revoke must fail, got {other:?}"),
        }
        assert_eq!(reg(&state).len(), 1, "the token is untouched");

        // The owner can.
        assert_eq!(
            handle(
                &mut state,
                &peer,
                Request::RevokeSurrogate {
                    session,
                    surrogate: token.clone(),
                }
            ),
            Response::SurrogateRevoked { surrogate: token }
        );
        assert!(reg(&state).is_empty());
    }

    /// A broker with no vault open refuses all three semantic operations, and
    /// refuses them as a *denial* rather than as "no such method".
    ///
    /// CU-2.2 wired these operations, so `UnknownMethod` is no longer the
    /// honest answer and keeping it would have meant preserving a weaker
    /// guarantee than the code now makes. The guarantee that survives, and is
    /// stronger, is the one that matters: no vault means no brokered call, ever,
    /// and no fallback to an anonymous or direct request. The response is
    /// `Denied` precisely so a caller can tell "this broker cannot do that" from
    /// "you asked for something that does not exist".
    #[test]
    fn semantic_operations_are_denied_while_no_vault_is_open() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);

        for request in [
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                number: 1,
            },
            Request::CreateIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                title: "t".into(),
                body: "b".into(),
            },
            Request::CreateRelease {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                tag: "v1".into(),
                name: "n".into(),
                body: "b".into(),
            },
        ] {
            match handle(&mut state, &peer, request) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Denied, "got {message:?}");
                    // The refusal has to say *why*, or an operator reads
                    // "denied" as a policy decision and goes looking for a
                    // policy that does not exist.
                    assert!(
                        message.contains("credential store"),
                        "the denial must name the missing vault, got {message:?}"
                    );
                }
                other => panic!("a vaultless broker must not answer {other:?}"),
            }
        }
        // And crucially, an unattempted call must not have spent the budget.
        assert_eq!(reg(&state).len(), 1, "the token is still live");
    }

    /// A minted token is the only credential-shaped string the broker emits,
    /// and the response must not also leak the underlying credential id.
    #[test]
    fn minting_leaks_no_credential_material() {
        const CANARY: &str = "ASV-CANARY-9f2c-DO-NOT-LEAK";
        let mut state = BrokerState::default();
        let metadata = CredentialMetadata::new(CANARY, CredentialKind::BearerToken);
        let credential = register_inventory_credential(&mut state, metadata);
        let peer = pinned_peer();
        let session = sess(&state).create("/repo".to_string(), &peer);

        let response = handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        );
        let bytes = asv_ipc_protocol::encode_response(&response).expect("encodes");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "the credential label leaked into the mint response: {text}"
        );
        assert!(
            !text.contains(&credential.as_uuid().to_string()),
            "the credential id leaked into the mint response: {text}"
        );
    }

    /// Teardown leaves nothing live. UAT-030 asserts this, so the invariant is
    /// pinned where the state actually lives.
    #[test]
    fn teardown_leaves_no_surrogate_behind() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, _) = mint(&mut state, &peer);
        assert_eq!(reg(&state).len(), 1, "one token is live");
        handle(&mut state, &peer, Request::EndSession { session });
        assert!(reg(&state).is_empty(), "and none after teardown");
        assert!(sess(&state).is_empty(), "and no session either");
    }
}

/// End-to-end tests for the brokered GitHub path (M4 CU-2.2).
///
/// These are the tests that matter most for this work item, because they are
/// the only ones that cross every boundary at once: an IPC request in, a
/// surrogate redeemed, a credential unlocked from a real encrypted vault, an
/// authenticated request out over real TLS, and a response shaped back. Each
/// layer has its own unit tests, and every one of them would still pass if the
/// layers were wired to each other wrongly.
#[cfg(test)]
mod e2e {
    use super::*;

    use asv_connector_http::fake_origin::{self, Reply};
    use asv_connector_http::{AddressPolicy, Certificate, GithubClient, ResolvedAudience};
    use asv_domain::secret::SecretBytes;
    use asv_identity::PeerCredentials;
    use asv_vault::{KdfParams, VaultKey, VaultStore};
    use secrecy::SecretString;

    use std::net::{IpAddr, Ipv4Addr};

    /// The secret the vault holds. Every assertion below is about this exact
    /// string appearing where it should and nowhere else.
    const CANARY: &str = "ASV-CANARY-e2e-5c1a-DO-NOT-LEAK";

    /// A factory that points the connector at a local TLS origin.
    ///
    /// Built per origin because the certificate and the port differ, and
    /// because sharing one across tests would let them observe each other's
    /// requests.
    struct LocalFactory {
        resolved: ResolvedAudience,
        root: Certificate,
    }

    impl ConnectorFactory for LocalFactory {
        fn github(
            &self,
            _audience: Authority,
            secrets: Arc<dyn SecretPort>,
        ) -> Result<GithubClient, GithubError> {
            // Loopback is allowed here and only here. The production factory
            // never sets it, which is the whole reason this substitution is
            // visible in the source rather than hidden in a config value.
            Ok(GithubClient::pinned_to(
                self.resolved.clone(),
                AddressPolicy {
                    allow_loopback: true,
                },
                secrets,
            )
            .trusting(vec![self.root.clone()]))
        }

        // M6-T7: test factory does not route to a fake_pg; production
        // shape is enough for the existing HTTP tests. Any test that
        // exercises the broker-side PostgreSQL flow installs a
        // factory whose postgres routes to fake_pg explicitly.
        fn postgres(
            &self,
            audience: Authority,
            database: String,
            role: String,
            _secrets: Arc<dyn SecretPort>,
        ) -> Result<PostgresClient, PgError> {
            Ok(PostgresClient::new(audience, database, role))
        }
    }

    fn pass() -> SecretString {
        SecretString::from("test-passphrase".to_string())
    }

    /// A broker with a real vault open, a credential registered under `id`, a
    /// pinned peer, and a minted surrogate pointing at the local origin.
    ///
    /// Returns the state, the peer, the session, the token, the origin *and*
    /// the vault's directory. The directory has to outlive the call: the
    /// broker holds no file handle, it re-opens the vault by path on every
    /// lend, so a `TempDir` dropped here would turn every operation into an
    /// "io error: no such file". The tests therefore keep it alive and drop it
    /// last, which is the same lifetime a real deployment has.
    #[allow(clippy::type_complexity)]
    fn brokered(
        reply: Reply,
    ) -> (
        BrokerState,
        WorkloadIdentity,
        AgentSessionId,
        String,
        fake_origin::FakeOrigin,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = VaultStore::create(
            dir.path().join("v.asv"),
            &pass(),
            KdfParams::fast_for_tests(),
        )
        .expect("create");
        let key: VaultKey = store.header().unlock(&pass()).expect("unlock");

        // The vault's record id has to be the same string the broker will ask
        // for. The broker registers the id it mints a surrogate over, and the
        // vault is keyed by that id's wire form.
        // `CredentialMetadata::new` here is the *domain* one, which mints a
        // fresh UUID. The vault is then keyed by that id's wire form, so the
        // string the broker redeems a surrogate to is the string the vault can
        // unlock. Qualifying both types matters: the domain and the vault each
        // have their own `CredentialKind` and `CredentialMetadata`, and an
        // unqualified import silently picks the wrong pair.
        let mut state = BrokerState::default();
        let credential = register_inventory_credential(
            &mut state,
            asv_domain::CredentialMetadata::new(
                "github-e2e",
                asv_domain::CredentialKind::BearerToken,
            ),
        );
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    credential.to_wire(),
                    "e2e",
                    asv_vault::CredentialKind::Opaque,
                    "github",
                    "a",
                    1,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert");

        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        )));

        let origin = fake_origin::start(reply);
        state.connectors = Box::new(LocalFactory {
            resolved: ResolvedAudience {
                authority: Authority::canonicalize(&origin.certified_for).expect("authority"),
                port: origin.port,
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
            root: origin.certificate(),
        });

        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pidfd_open on self");
        let session = sess(&state).create("/repo".to_string(), &peer);
        let token = match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("expected a token, got {other:?}"),
        };
        (state, peer, session, token, origin, dir)
    }

    fn issue_json() -> String {
        serde_json::json!({
            "number": 7,
            "title": "a title",
            "body": "a body",
            "state": "open",
            "html_url": "https://github.com/o/r/issues/7",
            // A field the broker must not forward. If it ever appears in a
            // response, the "three fields and nothing else" promise is broken.
            "secret_sauce": "MUST-NOT-BE-FORWARDED"
        })
        .to_string()
    }

    /// The whole path works: a surrogate becomes an authenticated request that
    /// the provider answers, and the agent gets the three promised fields.
    #[test]
    fn a_read_issue_sends_the_credential_and_returns_only_the_promised_fields() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert_eq!(
            response,
            Response::IssueRead {
                title: "a title".into(),
                body: "a body".into(),
                state: "open".into(),
            },
            "the read must return exactly the three promised fields"
        );

        let sent = origin.last().expect("the provider was contacted");
        assert_eq!(sent.method(), "GET");
        assert_eq!(sent.path(), "/repos/o/r/issues/7");
        // The credential really travelled, and only to the provider.
        assert_eq!(
            sent.header("authorization"),
            Some(format!("token {CANARY}").as_str()),
            "the request was not authenticated with the vaulted credential"
        );
        // And the response never carried the secret back to the agent.
        assert!(
            !format!("{response:?}").contains(CANARY),
            "the response leaked the credential: {response:?}"
        );
        assert!(
            !format!("{response:?}").contains("MUST-NOT-BE-FORWARDED"),
            "the response forwarded an unpromised field: {response:?}"
        );
    }

    /// Creating an issue spends exactly one use, and the second attempt with
    /// the same token fails as exhausted.
    #[test]
    fn a_create_issue_spends_one_use_and_a_second_attempt_is_exhausted() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        let request = |surrogate: String| Request::CreateIssue {
            session,
            surrogate,
            repo: "o/r".into(),
            title: "t".into(),
            body: "b".into(),
        };

        let first = handle(&mut state, &peer, request(token.clone()));
        assert_eq!(
            first,
            Response::IssueCreated {
                number: 7,
                url: "https://github.com/o/r/issues/7".into()
            }
        );

        let second = handle(&mut state, &peer, request(token.clone()));
        // max_uses was 2, so the second call is the last one that can work.
        assert!(
            !matches!(second, Response::Error { .. }),
            "the second use was refused: {second:?}"
        );

        let third = handle(&mut state, &peer, request(token));
        assert_eq!(
            third,
            Response::Error {
                code: ErrorCode::SurrogateExhausted,
                message: third_message(&third)
            },
            "the budget was not enforced"
        );
        assert_eq!(
            origin.connections(),
            2,
            "the refused call reached the provider"
        );
    }

    /// A surrogate minted for one session is refused from another, and the
    /// refusal costs nothing.
    ///
    /// The second session belongs to the *same* peer on purpose: this is the
    /// test for `redeem`'s `WrongSession` check, which is the one an attacker
    /// hits by running two sessions of their own and moving a token between
    /// them. The different-peer case is a separate guarantee (that the session
    /// is not owned by the caller) and has its own test above.
    #[test]
    fn a_surrogate_from_another_session_of_the_same_peer_is_refused() {
        let (mut state, peer, _session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        let other = sess(&state).create("/other".to_string(), &peer);

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session: other,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        // Refused for belonging to another session, and the message says so
        // rather than claiming the token is unknown: the broker does know it,
        // and a message that hid that would cost an agent a debugging session.
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "surrogate was minted for a different session".into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a foreign session reached the provider"
        );
    }

    /// A session belonging to another process is refused before anything else.
    #[test]
    fn a_session_belonging_to_another_process_is_refused() {
        let (mut state, peer, _session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        // A different pid, which is what `belongs_to` actually compares. A
        // same-pid-different-uid fixture would not exercise the check: the
        // broker records the pid at session creation and compares pids, so
        // two identities for one process are one peer as far as it is
        // concerned. Pinning is not required for a refusal, which is the
        // point: an unpinned stranger is still a stranger.
        let mut stranger = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32 + 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        stranger.pin_pidfd().ok();
        let foreign = sess(&state).create("/theirs".to_string(), &stranger);

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session: foreign,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        // Note the direction: `handle` is given `peer`, and the session belongs
        // to `stranger`. The check is on who owns the session, not on who is
        // calling.
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a foreign peer reached the provider"
        );
    }

    /// The broker's own validation runs before the token is redeemed, which is
    /// the only thing the connector's cannot do.
    ///
    /// A `max_uses` of one makes the difference observable: with the broker's
    /// check removed, the connector still refuses the malformed repository and
    /// the caller still sees `InvalidRequest`, but by then `redeem` has already
    /// spent the only use, so the legitimate call below is refused as
    /// `SurrogateExhausted`. Two layers returning the same code for the same
    /// input is exactly the arrangement that hides a missing check, so the
    /// budget is what this test actually asserts.
    #[test]
    fn a_malformed_repo_does_not_spend_the_only_use() {
        // The token from the fixture is re-minted below with a single use, so
        // the fixture's two-use one is not bound here.
        let (mut state, peer, session, _token, origin, _dir) = brokered(Reply::Json(issue_json()));
        // Re-mint with a single use. `brokered` grants two so other tests can
        // make two calls; here one is the whole point.
        state.surrogates = Arc::new(Mutex::new(SurrogateRegistry::default()));
        let credential = state.credentials[0].id;
        let token = match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("expected a token, got {other:?}"),
        };

        let refused = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r/../../admin".into(),
                number: 7,
            },
        );
        assert_eq!(
            refused,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                message: "repository must be `owner/repo` with non-empty ASCII path components"
                    .into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a malformed repo reached the provider"
        );

        // The one use is still there. If the broker validated after redeeming,
        // this would be `SurrogateExhausted`.
        let ok = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );
        assert!(
            matches!(ok, Response::IssueRead { .. }),
            "the refused call spent the budget: {ok:?}"
        );
    }

    /// A token that does not exist never reaches the provider, and the error
    /// says nothing about what does exist.
    #[test]
    fn an_unknown_token_never_reaches_the_provider() {
        let (mut state, peer, session, _token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: "asv1_not-a-real-token".into(),
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "no surrogate matches the presented token".into()
            }
        );
        assert_eq!(origin.connections(), 0);
    }

    /// Ending the session revokes every surrogate it minted, so a token that
    /// was valid a moment ago is now refused.
    #[test]
    fn ending_a_session_revokes_its_surrogates() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let before = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                number: 7,
            },
        );
        assert!(
            matches!(before, Response::IssueRead { .. }),
            "got {before:?}"
        );

        handle(&mut state, &peer, Request::EndSession { session });

        let after = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );
        // The session itself is gone, so the refusal is about ownership, not
        // about the token. Both refusals are `Denied` and neither reaches the
        // provider; which of the two fired is not the point of the test, and
        // asserting on the exact wording here would only pin an implementation
        // detail of the session store.
        assert_eq!(
            after,
            Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into()
            }
        );
        assert_eq!(
            origin.connections(),
            1,
            "the post-revocation call reached the provider"
        );
    }

    /// The provider's error is relayed as an upstream failure, and the
    /// provider's own body is not.
    #[test]
    fn an_upstream_failure_is_reported_as_upstream_and_carries_no_body() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Status {
            status: 404,
            body: "{\"message\":\"MUST-NOT-BE-FORWARDED\"}".into(),
        });

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        match response {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::Upstream);
                assert!(
                    message.contains("404"),
                    "the status must be reported: {message}"
                );
                assert!(
                    !message.contains("MUST-NOT-BE-FORWARDED"),
                    "the provider's body was relayed: {message}"
                );
            }
            other => panic!("a 404 must be an error, got {other:?}"),
        }
        assert_eq!(origin.connections(), 1);
    }

    /// A creation sends a JSON body built from the agent's text, and the
    /// broker forwards only the two identity fields back.
    #[test]
    fn a_create_release_sends_the_tag_and_returns_only_tag_and_url() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(
            serde_json::json!({
                "tag_name": "v1.2.3",
                "html_url": "https://github.com/o/r/releases/v1.2.3",
                "upload_url": "MUST-NOT-BE-FORWARDED"
            })
            .to_string(),
        ));

        let response = handle(
            &mut state,
            &peer,
            Request::CreateRelease {
                session,
                surrogate: token,
                repo: "o/r".into(),
                tag: "v1.2.3".into(),
                name: "Release".into(),
                body: "notes".into(),
            },
        );

        assert_eq!(
            response,
            Response::ReleaseCreated {
                tag: "v1.2.3".into(),
                url: "https://github.com/o/r/releases/v1.2.3".into(),
            }
        );

        let sent = origin.last().expect("the provider was contacted");
        assert_eq!(sent.method(), "POST");
        assert_eq!(sent.path(), "/repos/o/r/releases");
        let body = sent.body.as_str();
        assert!(body.contains("\"tag_name\":\"v1.2.3\""), "body was {body}");
        assert_eq!(
            sent.header("authorization"),
            Some(format!("token {CANARY}").as_str())
        );
        assert!(
            !format!("{response:?}").contains("MUST-NOT-BE-FORWARDED"),
            "an unpromised field was forwarded: {response:?}"
        );
    }

    /// A token cannot be used to reach anything but GitHub. The broker builds
    /// the client for a fixed authority, so there is no request field that
    /// could redirect the credential elsewhere.
    #[test]
    fn the_request_cannot_choose_the_audience() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert!(
            matches!(response, Response::IssueRead { .. }),
            "got {response:?}"
        );
        let sent = origin.last().expect("the provider was contacted");
        // The only host that saw the credential is the one the broker chose.
        assert_eq!(origin.connections(), 1);
        assert_eq!(sent.path(), "/repos/o/r/issues/7");
    }

    /// The message of an error response, for use in an expected value.
    fn third_message(response: &Response) -> String {
        match response {
            Response::Error { message, .. } => message.clone(),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A broker with no runtime, for the refusals that do not need one.
    fn bare() -> BrokerState {
        BrokerState::default()
    }

    /// Declares `db.example` as a destination, so a test whose subject is a
    /// *later* check can get past the destination gate (H5) and reach it.
    ///
    /// Without this every inline PostgreSQL refusal test would exercise the
    /// destination gate instead of the thing it was written to prove, and would
    /// go on passing for the wrong reason.
    fn declares_db_example(state: &mut BrokerState) {
        state.connectors = Box::new(LiveConnectorFactory {
            destinations: vec![
                PgDestination::new("db.example", "93.184.216.34".parse().unwrap())
                    .expect("a canonical host"),
            ],
            ..LiveConnectorFactory::default()
        });
    }

    /// A peer whose pid is the current process, which is what the session
    /// store records, so ownership checks pass.
    fn self_peer() -> WorkloadIdentity {
        WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        })
    }

    #[test]
    fn postgres_without_a_runtime_refuses_rather_than_connecting() {
        // The refusal names the missing runtime. A broker that said "connection
        // refused" here would be sending an operator to look at the network,
        // when the actual cause is a broker that was never given a runtime.
        let mut state = bare();
        declares_db_example(&mut state);
        let peer = self_peer();
        let session = sess(&state).create("/repo".into(), &peer);
        state.secrets = Some(Arc::new(RefusingPort));
        let response = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: "db.example".into(),
                host_addr: "93.184.216.34".into(),
                port: 5432,
                database: "asv".into(),
                role: "app".into(),
            },
        );
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Upstream,
                message: "the broker has no async runtime for the postgres transport".into(),
            }
        );
    }

    #[test]
    fn postgres_without_a_session_is_denied_before_anything_else() {
        // Ownership is checked before the vault, so a peer that does not own
        // the session learns nothing about whether a credential store is open.
        let mut state = bare();
        let peer = self_peer();
        state.secrets = Some(Arc::new(RefusingPort));
        let response = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session: AgentSessionId::new(),
                sql: "select 1".into(),
            },
        );
        assert_eq!(
            third_message(&response),
            "session is not owned by the authenticated peer"
        );
    }

    #[test]
    fn postgres_without_a_vault_refuses_rather_than_connecting_anonymously() {
        // A PostgreSQL server that would accept an anonymous connection is not
        // a reason to try one. The broker holds the credential or it does
        // nothing.
        let mut state = bare();
        let peer = self_peer();
        let session = sess(&state).create("/repo".into(), &peer);
        let response = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: "select 1".into(),
            },
        );
        assert_eq!(
            third_message(&response),
            "no credential store is open, so no brokered operation can run"
        );
    }

    #[test]
    fn a_malformed_address_is_refused_before_the_credential_is_lent() {
        // The parse happens first, so a bad address never reaches the vault.
        // A port that lends nothing records the calls it saw, and the test
        // asserts it saw none.
        let mut state = bare();
        let peer = self_peer();
        let session = sess(&state).create("/repo".into(), &peer);
        let port = Arc::new(CountingPort::default());
        state.secrets = Some(port.clone());
        let response = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: "db.example".into(),
                host_addr: "not-an-ip".into(),
                port: 5432,
                database: "asv".into(),
                role: "app".into(),
            },
        );
        assert!(matches!(
            response,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(
            port.calls(),
            0,
            "the vault was asked for a credential the request never earned"
        );
    }

    #[test]
    fn revoking_a_session_that_was_never_open_reports_no_teardown() {
        // The session exists and is owned, so the request is allowed to
        // proceed, and the answer is "nothing was terminated". Reporting
        // `true` here would be claiming an observation nobody made: there was
        // no backend to observe.
        let mut state = bare();
        let peer = self_peer();
        let session = sess(&state).create("/repo".into(), &peer);
        state.secrets = Some(Arc::new(RefusingPort));
        let response = handle(&mut state, &peer, Request::PostgresRevoke { session });
        assert_eq!(
            response,
            Response::PostgresRevoked {
                session,
                backend_terminated: false,
            }
        );
    }

    #[test]
    fn a_query_on_a_session_that_was_never_open_is_denied() {
        let mut state = bare();
        let peer = self_peer();
        let session = sess(&state).create("/repo".into(), &peer);
        state.secrets = Some(Arc::new(RefusingPort));
        state.runtime = Some(test_runtime());
        let response = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: "select 1".into(),
            },
        );
        assert_eq!(
            third_message(&response),
            "no open postgres session for this request"
        );
    }

    /// A runtime for a test that needs one but does no I/O.
    fn test_runtime() -> PgRuntime {
        static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        let runtime = RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime")
        });
        PgRuntime::from_handle(runtime.handle().clone())
    }

    /// A port that lends nothing, so a test that reaches it fails loudly rather
    /// than passing for the wrong reason.
    struct RefusingPort;

    impl SecretPort for RefusingPort {
        fn lend(
            &self,
            credential: &str,
            _sink: &mut dyn asv_connector_http::SecretSink,
        ) -> Result<(), asv_connector_http::SecretError> {
            Err(asv_connector_http::SecretError::NotFound(
                credential.to_string(),
            ))
        }
    }

    /// A port that counts how many times it was asked for a credential.
    #[derive(Default)]
    struct CountingPort {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingPort {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SecretPort for CountingPort {
        fn lend(
            &self,
            credential: &str,
            _sink: &mut dyn asv_connector_http::SecretSink,
        ) -> Result<(), asv_connector_http::SecretError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(asv_connector_http::SecretError::NotFound(
                credential.to_string(),
            ))
        }
    }
}
