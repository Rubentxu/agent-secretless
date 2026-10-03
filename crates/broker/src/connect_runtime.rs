//! The production ports the CONNECT listener needs, and nothing else.
//!
//! `connect_listener` owns a lifecycle. It takes four ports as trait objects and
//! deliberately settles none of them, because "how does one connection obtain a
//! credential" is a question about how the broker owns its state, and answering
//! it inside a module about accepting sockets would put two responsibilities in
//! one file and one set of tests. This is the other half of that decision.
//!
//! Three ports, three shapes:
//!
//! * [`SessionLeafSource`] mints from **one** broker-scoped CA. The
//!   `LeafSource` port takes a host and not a session, so a port that wanted
//!   per-session CAs could not express it; that limitation is stated on the
//!   type rather than left to be discovered.
//! * [`SystemUpstream`] resolves through the host's resolver. The bridge has
//!   already authorised the target against its allow-list before anything here
//!   runs, so this is a dial and not a policy decision.
//! * [`SubstitutingHandler`] is the [`ConnectionHandler`] the broker installs.
//!   It takes the surrogate registry **already shared with the socket path**,
//!   because a token minted by `MintSurrogate` over that socket has to be
//!   redeemable here or the product does not work.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asv_connector_http::SecretPort;

use crate::surrogate::{SubstitutionPort, SurrogateRegistry};
use crate::tls_bridge::{
    issue_leaf, AuthorityEndpoint, BridgeError, EstablishedTunnel, LeafError, LeafSource,
    RelayLimits, SessionCa, SubstitutionAudit, SubstitutionRecord, VerifiedLeaf,
};

use crate::connect_listener::{
    ConnectionHandler, ConnectionOutcome, ConnectionResult, ListenerReport,
};

/// Resolves CONNECT proofs against the broker's **own** session table.
///
/// `SessionStore` implements `SessionProofs` directly, but the listener cannot
/// hold the store itself: `BrokerState` owns it, and the socket path needs it
/// too. So the port is the same store behind the same lock, consulted through
/// a borrow rather than a copy.
///
/// This exists because the alternative is a `SessionStore::new()`. That
/// compiles, binds, accepts, refuses every proof and reports every refusal
/// correctly — a proxy that looks completely alive and can never establish a
/// tunnel. A test that only checked "the listener answers" would have called
/// that working. What makes the difference observable is the *reason* the
/// answer is refused, which is why [`ChainReport`] logs it and why the wiring
/// test asserts on the reason rather than on a status.
pub struct SharedSessions {
    store: Arc<Mutex<crate::SessionStore>>,
}

impl SharedSessions {
    pub fn new(store: Arc<Mutex<crate::SessionStore>>) -> Self {
        Self { store }
    }
}

impl std::fmt::Debug for SharedSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately does not print the store. `SessionStore`'s `Debug` is
        // its own decision, and this port adds no fact an operator needs that
        // it does not already carry.
        f.debug_struct("SharedSessions").finish_non_exhaustive()
    }
}

impl crate::tls_bridge::SessionProofs for SharedSessions {
    fn authenticate(
        &self,
        proof: &crate::tls_bridge::SessionProof,
        target: &crate::tls_bridge::AuthorityEndpoint,
    ) -> Result<asv_domain::AgentSessionId, crate::ProofRejection> {
        // One lock, one operation. `SessionStore::authenticate` derives the
        // nonce, verifies against the registered key and spends the counter
        // under this guard, so the key and its replay window can never be
        // read from one state and written to another.
        //
        // A poisoned store authenticates nobody, which is the fail-closed
        // answer and is indistinguishable on the wire from the refusal a
        // stranger's proof gets. A broker whose own state is unreadable must
        // not be able to *grant*.
        let mut store = self
            .store
            .lock()
            .map_err(|_| crate::ProofRejection::NoSuchSession)?;
        crate::SessionStore::authenticate(&mut store, proof, target)
    }
}

/// Issues every leaf from one broker-scoped session CA.
///
/// # Why one CA and not one per session
///
/// `LeafSource::issue_for` receives a host and an `Instant`. It does **not**
/// receive the session, because when it was written the bridge had not yet
/// resolved one — `serve_connect` calls it after the proof, but the port
/// signature was fixed first. So a port that wanted to choose a CA per session
/// has nothing to choose with, and the only honest reading is one CA for the
/// listener.
///
/// That is a real narrowing of ADR-0012's session-scoped framing, and it is
/// written here rather than discovered later. What it does *not* do is weaken
/// the property the session carries: the tunnel's session is still resolved
/// from a signature, a surrogate is still redeemable only in the session that
/// minted it, and a revocation still names a session. What is shared is the
/// certificate authority, not the identity.
pub struct SessionLeafSource {
    ca: Arc<SessionCa>,
}

impl SessionLeafSource {
    pub fn new(ca: Arc<SessionCa>) -> Self {
        Self { ca }
    }

    /// The DER-encoded root a client must trust.
    ///
    /// Handed out rather than served: ADR-0012 makes the CA session-scoped and
    /// the trust distribution is M14's problem, not this module's. Exposing it
    /// here is what lets `asv-brokerd` write it next to the socket.
    pub fn root_der(&self) -> &[u8] {
        &self.ca.root_der
    }
}

impl std::fmt::Debug for SessionLeafSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `SessionCa` prints no key material, so delegating is safe and keeps
        // the session id visible in a log line that mentions the source.
        f.debug_struct("SessionLeafSource")
            .field("ca", &self.ca)
            .finish()
    }
}

impl LeafSource for SessionLeafSource {
    fn issue_for(&self, host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError> {
        let certificate = issue_leaf(&self.ca, host, now)?;
        // `from_certificate` can only fail assembling the presenting material
        // for a certificate that was just minted, which is a broker fault and
        // not a reason to refuse this host. Mapped into a `LeafError` so the
        // port keeps the shape the trait declares rather than widening it to
        // the bridge's own error type.
        VerifiedLeaf::from_certificate(&self.ca, certificate)
            .map_err(|e| LeafError::LeafMaterial(host.to_string(), e.to_string()))
    }
}

/// Resolves an authorised target through the host resolver.
///
/// A dial, not a policy decision: `Bridge::handle_connect` has already refused
/// anything outside `ConnectPolicy`, so every target reaching this function was
/// on the allow-list before DNS was consulted. That ordering is the point — a
/// resolver that could reach anywhere would turn the allow-list into a
/// suggestion, and the bridge's own check is what makes it a decision.
///
/// The loop over addresses is deliberate. A name that resolves to both an
/// IPv6 and an IPv4 address is common, and returning the first would make the
/// broker's reachability depend on the order the system resolver happened to
/// produce. Returning every address would need a different port signature, so
/// the choice made here is the one a client would make: the first that the
/// kernel accepts.
#[derive(Debug, Default)]
pub struct SystemUpstream;

impl SystemUpstream {
    /// Every address the target resolves to, in resolver order.
    pub fn candidates(&self, target: &AuthorityEndpoint) -> Result<Vec<SocketAddr>, BridgeError> {
        let host = target.authority.as_str();
        let addrs: Vec<SocketAddr> = (host, target.port)
            .to_socket_addrs()
            .map_err(|e| BridgeError::Io(format!("cannot resolve {host}:{}: {e}", target.port)))?
            .collect();
        if addrs.is_empty() {
            return Err(BridgeError::Io(format!(
                "{host}:{} resolved to no address",
                target.port
            )));
        }
        Ok(addrs)
    }
}

impl crate::tls_bridge::UpstreamResolver for SystemUpstream {
    fn resolve(&self, target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        self.candidates(target)?
            .into_iter()
            .next()
            .ok_or_else(|| BridgeError::Io("no address".into()))
    }
}

/// Substitutes one credential into one tunnel.
///
/// Holds the registry behind the same `Arc<Mutex<…>>` the socket path uses, and
/// takes the lock for the length of one registry operation — never for the
/// length of a tunnel. A `SurrogateRegistry::redeem_for` is a hash lookup and a
/// budget decrement; holding this lock across a relay would let one client that
/// is slow to send its request freeze minting and revoking for every other
/// agent.
pub struct SubstitutingHandler {
    surrogates: Arc<Mutex<SurrogateRegistry>>,
    secrets: Arc<dyn SecretPort>,
    /// The broker's own chain, shared with the socket path.
    ///
    /// Shared because a substitution recorded on the socket path and one
    /// recorded here have to be the same chain: two chains would each verify
    /// alone and say nothing about what the other did.
    audit: Arc<Mutex<crate::audit::AuditLog>>,
    /// Which family and credential this tunnel may spend, per destination.
    ///
    /// C2.6. This used to be a pair of constants on the handler
    /// (`OperationFamily::GitHub`, `"github"`), which meant the bridge held the
    /// policy: every tunnel through one listener substituted a GitHub
    /// credential, and the destination had no say in it. A route declares its
    /// own family and credential and the policy authorized the route at load,
    /// so the family follows the destination instead of the process.
    ///
    /// Shared and immutable. The reload path swaps a whole table rather than
    /// mutating one, so no tunnel can observe a half-applied change.
    routes: Arc<crate::connect_routes::ConnectRouteSet>,
    limits: RelayLimits,
}

impl SubstitutingHandler {
    /// Build a handler over a registry the socket path also holds.
    ///
    /// Takes the `Arc` rather than a `&mut SurrogateRegistry` so the two paths
    /// cannot end up with two registries. That is the whole reason this type
    /// exists rather than a `SubstitutionPort` built inline per connection: two
    /// registries would mean a token minted over the socket is unknown here,
    /// and the failure would be a `WrongSession`-shaped refusal with nothing to
    /// explain it.
    pub fn new(
        surrogates: Arc<Mutex<SurrogateRegistry>>,
        secrets: Arc<dyn SecretPort>,
        audit: Arc<Mutex<crate::audit::AuditLog>>,
        routes: Arc<crate::connect_routes::ConnectRouteSet>,
    ) -> Self {
        Self {
            surrogates,
            secrets,
            audit,
            routes,
            limits: RelayLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: RelayLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl std::fmt::Debug for SubstitutingHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubstitutingHandler")
            .field("routes", &self.routes)
            .field("limits", &self.limits)
            .field("secrets", &"<a secret port>")
            .finish()
    }
}

impl ConnectionHandler for SubstitutingHandler {
    fn run(&self, mut tunnel: EstablishedTunnel) -> Result<(), BridgeError> {
        // Which family and credential this tunnel may spend is the *route's*
        // answer, looked up by the destination the CONNECT actually named. Not
        // a handler constant, and not anything the client supplied: the target
        // came from the parsed CONNECT head and the table is what the policy
        // authorized at load.
        //
        // The lookup is a second gate rather than a formality. The bridge's own
        // `ConnectPolicy` already refused a destination with no route, so this
        // arm should be unreachable — and it is written to fail closed anyway,
        // because the alternative is a handler that substitutes a default family
        // for a destination it does not recognise. If the two gates ever
        // disagree, this one is the one that holds.
        let route = self.routes.route_for(&tunnel.target).ok_or_else(|| {
            BridgeError::Io(
                "no authorized route for this destination; the broker's policy and its \
                 route table disagree"
                    .into(),
            )
        })?;
        let family = route.operation_family();
        let credential = route.credential();

        // One lock, one registry operation, released before any I/O. The
        // borrow cannot outlive this block: `SubstitutionPort` holds `&mut`,
        // and holding the guard across `relay_substituted` would serialise
        // every tunnel in the broker behind whichever one is slowest to speak.
        let outcome = {
            let mut registry = self.surrogates.lock().map_err(|_| {
                // A poisoned registry is a broker fault, not a client one, and
                // the reason an operator needs is the panic that poisoned it —
                // not a message about the connection they happened to be
                // holding at the time.
                BridgeError::Io(
                    "the surrogate registry is poisoned; the broker must restart".into(),
                )
            })?;
            let mut port =
                SubstitutionPort::new(&mut registry, self.secrets.as_ref(), family, credential);
            // The registry guard is released at the end of this block; the
            // audit handle is the shared log itself rather than a guard, so the
            // relay records into the same chain the socket path appends to and
            // takes the chain's lock once per record instead of once per
            // tunnel.
            let mut audit =
                SharedSubstitutionAudit::new(Arc::clone(&self.audit), crate::surrogate::now_secs());
            tunnel.relay_substituted(&mut port, &mut audit, self.limits)
        }?;
        tracing::info!(
            session = %tunnel.session,
            destination = %tunnel.target.authority,
            port = tunnel.target.port,
            forwarded = outcome.forwarded,
            returned = outcome.returned,
            "CONNECT tunnel relayed"
        );
        Ok(())
    }
}

/// Classify a CONNECT failure as a wire name, without quoting the failure.
///
/// **This function exists because the obvious thing is a leak.** `BridgeError`
/// is `Display`, and several of its variants interpolate bytes the *client*
/// sent: `parse_connect_target` builds `Protocol(format!("{authority} has no
/// port"))` and `Protocol(format!("{host}: {e}"))` from the request line. So
/// `ConnectionResult::Refused(reason)` carries attacker-controlled text, and
/// writing that into the durable audit chain would let any client put bytes of
/// their choosing — a secret-shaped string included — into a file that gets
/// exported, hashed and shipped.
///
/// The chain therefore gets a class, and the class is derived from the error's
/// *kind*, never from its rendering. What an operator loses is the exact
/// wording; what they keep is the ability to count, alert on and correlate
/// refusals by cause, which is what an audit chain is for. The full text stays
/// in the operator log, which is the surface that already exists to hold
/// diagnostic detail and is not the artefact that leaves the machine.
pub fn refusal_class(error: &BridgeError) -> &'static str {
    match error {
        BridgeError::Connect(_) => "connect_rejected",
        BridgeError::Redirect(_) => "redirect_rejected",
        BridgeError::Leaf(_) => "leaf_unavailable",
        BridgeError::Protocol(_) => "malformed_request",
        BridgeError::NoLeaf(_) => "leaf_unavailable",
        BridgeError::Io(_) => "io_error",
        BridgeError::Handshake(_) => "tls_failure",
        BridgeError::Substitution(_) => "substitution_refused",
        BridgeError::Cancelled(_) => "cancelled",
        _ => "other",
    }
}

/// The outcome of one CONNECT, as the audit chain records it.
///
/// Three wire names and a class, none of which is the error's own text. Kept
/// next to [`refusal_class`] so the two cannot drift apart: adding a
/// `BridgeError` variant without adding a class here would fall into `_ =>
/// "other"` and an operator would see every new failure lumped together.
pub fn outcome_wire_name(result: &ConnectionResult) -> &'static str {
    match result {
        ConnectionResult::Completed => "completed",
        ConnectionResult::Refused(_) => "refused",
        ConnectionResult::Cancelled(_) => "cancelled",
    }
}

/// Records substitutions into the broker's own audit chain.
///
/// [`crate::audit::SubstitutionRecorder`] borrows `&mut AuditLog` and is the
/// right shape for a caller that already holds the log exclusively. The relay
/// runs on a detached task per tunnel, so this takes the shared handle and
/// locks **per record** rather than holding the lock across the relay — the
/// same rule the surrogate registry follows, for the same reason: a lock held
/// for the length of a tunnel is a lock one slow client holds for everyone.
pub struct SharedSubstitutionAudit {
    log: Arc<Mutex<crate::audit::AuditLog>>,
    ts: u64,
}

impl SharedSubstitutionAudit {
    pub fn new(log: Arc<Mutex<crate::audit::AuditLog>>, ts: u64) -> Self {
        Self { log, ts }
    }
}

impl std::fmt::Debug for SharedSubstitutionAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSubstitutionAudit")
            .finish_non_exhaustive()
    }
}

impl SubstitutionAudit for SharedSubstitutionAudit {
    fn record(&mut self, record: SubstitutionRecord) -> Result<(), BridgeError> {
        let SubstitutionRecord {
            session,
            destination,
            family,
            outcome,
        } = record;
        // A poisoned chain is a broker fault, and the substitution has already
        // happened by the time this runs — so the tunnel's outcome is right and
        // the record is lost. Reported rather than swallowed: an operator who
        // is told "the audit chain is poisoned" can act, and one who is told
        // nothing cannot.
        let mut log = self.log.lock().map_err(|_| {
            BridgeError::Io("the audit chain is poisoned; the broker must restart".into())
        })?;
        log.append(
            asv_ipc_protocol::AuditEventDto::CredentialSubstituted {
                session: session.to_string(),
                destination,
                family: family.to_string(),
                outcome: outcome.to_string(),
            },
            self.ts,
        );
        Ok(())
    }
}

/// Turns a listener outcome into an operator-facing line and an audit record.
///
/// The two carry different things on purpose. The line carries the reason,
/// because that is the surface an operator reads while something is going
/// wrong. The record carries only the class, because the chain is the artefact
/// that is hashed, exported and shipped, and the reason is attacker-controlled
/// text — see [`refusal_class`].
pub struct ChainReport {
    inner: Arc<dyn ListenerReport>,
    log: Arc<Mutex<crate::audit::AuditLog>>,
}

impl ChainReport {
    pub fn new(inner: Arc<dyn ListenerReport>, log: Arc<Mutex<crate::audit::AuditLog>>) -> Self {
        Self { inner, log }
    }
}

impl std::fmt::Debug for ChainReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainReport").finish_non_exhaustive()
    }
}

impl ListenerReport for ChainReport {
    fn record(&self, outcome: ConnectionOutcome) {
        let destination = outcome
            .target
            .as_ref()
            .map(|t| format!("{}:{}", t.authority, t.port))
            .unwrap_or_else(|| "<no destination read>".into());
        let verdict = outcome_wire_name(&outcome.result);
        let detail = match &outcome.result {
            ConnectionResult::Completed => "completed".to_string(),
            ConnectionResult::Refused(reason) => refusal_class_from_text(reason).to_string(),
            ConnectionResult::Cancelled(reason) => cancellation_class(*reason).to_string(),
        };
        match &outcome.result {
            ConnectionResult::Completed => {
                tracing::info!(%destination, session = ?outcome.session, "CONNECT completed");
            }
            ConnectionResult::Refused(reason) => {
                tracing::warn!(%destination, session = ?outcome.session, %reason, "CONNECT refused");
            }
            ConnectionResult::Cancelled(reason) => {
                tracing::info!(%destination, session = ?outcome.session, %reason, "CONNECT cancelled");
            }
        }

        // The destination in the *record* is the parsed one, never the raw
        // request line, and it is absent rather than empty when the client
        // never said where it was going. `None` is a fact here; `""` would be a
        // value a reader could mistake for a host.
        match self.log.lock() {
            Ok(mut log) => {
                log.append(
                    asv_ipc_protocol::AuditEventDto::ConnectHandled {
                        destination: outcome
                            .target
                            .as_ref()
                            .map(|t| format!("{}:{}", t.authority, t.port))
                            .unwrap_or_default(),
                        session: outcome.session.clone(),
                        outcome: verdict.to_string(),
                        detail,
                    },
                    crate::surrogate::now_secs(),
                );
            }
            Err(_) => {
                tracing::error!(
                    "the audit chain is poisoned; a CONNECT outcome was produced and \
                     not recorded"
                );
            }
        }
        self.inner.record(outcome);
    }
}

/// Recover a class from a rendered refusal, for the case where only the string
/// survived.
///
/// `ConnectionResult::Refused` carries a `String` rather than the error, so
/// the class cannot be recomputed at the far end — the kind is gone. Rather
/// than widen `ConnectionResult` to carry both (which would change the type
/// `connect_listener` produces and every test that matches on it), the class
/// is matched back out of the text by its stable prefix.
///
/// This is a compromise and it is recorded as one: the audit chain is written
/// from the string, so a future `BridgeError` whose `Display` does not begin
/// with one of these prefixes lands in `"other"`. The prefixes are the error
/// format strings, which are far more stable than an enum discriminant would
/// be in a protocol crate.
fn refusal_class_from_text(reason: &str) -> &'static str {
    if reason.starts_with("malformed CONNECT request") {
        "malformed_request"
    } else if reason.starts_with("destination not allowed") {
        "destination_not_allowed"
    } else if reason.starts_with("no session proof") || reason.starts_with("session") {
        "proof_rejected"
    } else if reason.starts_with("no leaf") || reason.contains("leaf") {
        "leaf_unavailable"
    } else if reason.contains("poisoned") {
        "broker_fault"
    } else {
        "other"
    }
}

/// The audit class for a cancellation, by match rather than by text search.
///
/// It was a search over `CancelReason`'s `Display` output, and it was already
/// wrong: a test supplied `"head deadline elapsed"` where the code produces
/// `"read deadline elapsed"`, and the chain recorded `other` without anyone
/// noticing. A class derived by searching a human-readable message is a class
/// that changes when somebody improves the message — and, worse, a class that
/// is wrong whenever a caller words it differently.
fn cancellation_class(reason: crate::tls_bridge::CancelReason) -> &'static str {
    match reason {
        crate::tls_bridge::CancelReason::Shutdown => "shutdown",
        crate::tls_bridge::CancelReason::SessionRevoked => "session_revoked",
        crate::tls_bridge::CancelReason::DeadlineElapsed => "head_deadline",
    }
}
