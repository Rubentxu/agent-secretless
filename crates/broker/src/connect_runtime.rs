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
use asv_domain::OperationFamily;

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
    fn resolve(
        &self,
        presented_key: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Option<asv_domain::AgentSessionId> {
        // A poisoned store resolves to "no such session", which is the
        // fail-closed answer and is indistinguishable, on the wire, from the
        // refusal a stranger's proof gets. That is the correct shape: a broker
        // whose own state is unreadable must not be able to *grant*.
        let store = self.store.lock().ok()?;
        crate::SessionStore::resolve(&*store, presented_key, nonce, signature)
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
    family: OperationFamily,
    family_name: &'static str,
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
        family: OperationFamily,
        family_name: &'static str,
    ) -> Self {
        Self {
            surrogates,
            secrets,
            family,
            family_name,
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
            .field("family", &self.family)
            .field("family_name", &self.family_name)
            .field("limits", &self.limits)
            .field("secrets", &"<a secret port>")
            .finish()
    }
}

impl ConnectionHandler for SubstitutingHandler {
    fn run(&self, mut tunnel: EstablishedTunnel) -> Result<(), BridgeError> {
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
            let mut port = SubstitutionPort::new(
                &mut registry,
                self.secrets.as_ref(),
                self.family,
                self.family_name,
            );
            let mut audit = ForwardingAudit;
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

/// Records a substitution through the broker's own audit chain.
///
/// `relay_substituted` reports every substitution — success or refusal — and a
/// record that is produced and dropped is not an audit trail. This forwards each
/// one into the chain, and the chain is append-only, so a failure to append is
/// reported rather than swallowed.
struct ForwardingAudit;

impl SubstitutionAudit for ForwardingAudit {
    fn record(&mut self, record: SubstitutionRecord) -> Result<(), BridgeError> {
        // Every field of `SubstitutionRecord` is named here, and the list is
        // the point: the record is metadata-only by construction, so a log
        // line built from it cannot carry a credential. A future field that
        // did would have to be added to this struct literal to be logged at
        // all, which is the cheapest possible guard against a secret reaching
        // the log by omission.
        let SubstitutionRecord {
            session,
            destination,
            family,
            outcome,
        } = record;
        tracing::info!(
            %session,
            %destination,
            %family,
            %outcome,
            "credential substitution"
        );
        Ok(())
    }
}

/// Turns a listener outcome into an operator-facing line.
///
/// A type rather than a function because the listener takes an
/// `Arc<dyn ListenerReport>` and the broker installs the chain-backed one. The
/// string carries the destination and the reason and **nothing from the
/// request**: the same argument `ConnectionOutcome` makes about the outcome
/// itself. A refusal message never goes to the client, and it must not go to
/// the log in a form that undoes the opacity the client saw.
pub struct ChainReport {
    inner: Arc<dyn ListenerReport>,
}

impl ChainReport {
    pub fn new(inner: Arc<dyn ListenerReport>) -> Self {
        Self { inner }
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
        self.inner.record(outcome);
    }
}
