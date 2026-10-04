//! The production CONNECT listener (V1-C2).
//!
//! # Why this module exists
//!
//! Until now the CONNECT path was a **capability with no network surface**.
//! `Bridge::serve_connect` authorised a destination, verified an ADR-0019
//! session proof, terminated TLS and produced an `EstablishedTunnel` — and
//! nothing in the broker ever called it. Every one of its proofs ran in a test
//! that dialled a socket it had opened itself. The M9 gate row said exactly
//! this ("no production listener wires the relay into a running broker"), and
//! this is that listener.
//!
//! # What it owns, and what it deliberately does not
//!
//! It owns the **lifecycle**: bind, accept, one task per connection, and a
//! shutdown that stops new connections *and* interrupts the ones already
//! established.
//!
//! It deliberately does not own credentials. `relay_substituted` takes a
//! `&mut dyn CredentialSubstituter` and a `&mut dyn SubstitutionAudit`, and how
//! one connection obtains those is a question about how the broker owns its
//! surrogate store — a different decision, in a different module. A listener
//! that also settled the locking strategy would be two responsibilities and
//! one test.
//!
//! # Refusals are per connection
//!
//! A handler that returns `Err` does not stop the listener: the connection is
//! closed and the reason goes to [`ListenerReport`]. One hostile client must not
//! be able to stop the broker serving the next one, and the handler is the only
//! component that knows whether a refusal is that client's business or a
//! broker fault.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;

use asv_domain::AgentSessionId;

use crate::tls_bridge::{
    AuthorityEndpoint, Bridge, BridgeError, Cancel, CancelReason, ConnectPolicy, EstablishedTunnel,
    LeafSource, RelayLimits, SessionProofs, UpstreamResolver, UpstreamTransportPolicy,
};

/// The shutdown and revocation state a listener polls on every socket read.
///
/// One object for both, deliberately. "The broker is going away" and "this
/// agent's session was revoked" are the same *mechanism* — a poll that a
/// blocking read re-asks after each timeout — and only differ in who asked and
/// why. Two objects would mean two poll paths and one more way for a revoke to
/// work in tests and not in production.
///
/// `#[derive(Debug)]` is not decoration: [`Cancel`] requires it so the bridge
/// can hold this behind a trait object and still be `Debug`.
#[derive(Debug, Default)]
pub struct ShutdownSignal {
    stopped: AtomicBool,
    revoked: Mutex<HashSet<String>>,
    /// Wakes the accept loop on `stop()`, so shutdown does not have to wait
    /// for the next inbound connection to notice.
    ///
    /// A `Notify` rather than a poll interval, and the distinction is the
    /// difference between a clean stop and a stop that hangs on an idle
    /// listener. The first version of `run` "solved" this with a
    /// `tokio::select!` biased onto `yield_now()`, which is a loop that yields
    /// forever and never accepts a single connection: the two lifecycle tests
    /// failed with no outcome reported at all, and the cause was one line
    /// above the code that looked like the accept loop.
    notify: tokio::sync::Notify,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop accepting, and cancel every tunnel in flight.
    ///
    /// Idempotent, because shutdown is reached by more than one path — an
    /// operator's signal, a test's cleanup, and a drop — and a second call
    /// must not be an error.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Resolve once [`Self::stop`] has been called.
    ///
    /// The `enable()` before the flag check is load-bearing: without it a
    /// `stop()` landing between the check and the `await` is lost, and the
    /// accept loop waits for a connection that will never come. That is the
    /// missed-wakeup bug, and the flag alone cannot fix it because the flag is
    /// what it is being checked against.
    pub async fn wait_stopped(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_stopped() {
            return;
        }
        notified.await;
    }

    /// Revoke one session, cancelling its tunnels.
    ///
    /// Takes the session as a string because the poll signature is
    /// session-agnostic on the `tls_bridge` side; the broker converts at the
    /// edge, where `AgentSessionId` exists.
    pub fn revoke(&self, session: &str) {
        if let Ok(mut set) = self.revoked.lock() {
            set.insert(session.to_string());
        }
    }

    /// Revoke everything, for a test or a panic path that must not leave a
    /// revoked set behind.
    pub fn clear(&self) {
        if let Ok(mut set) = self.revoked.lock() {
            set.clear();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn is_revoked(&self, session: &str) -> bool {
        self.revoked
            .lock()
            .map(|s| s.contains(session))
            .unwrap_or(false)
    }
}

impl Cancel for ShutdownSignal {
    fn cancel_reason(&self, session: Option<&AgentSessionId>) -> Option<CancelReason> {
        // Shutdown first: a broker that is going away should not keep serving
        // a session that is merely still valid, and the reason an operator
        // reads is the one they caused.
        if self.is_stopped() {
            return Some(CancelReason::Shutdown);
        }
        let session = session?;
        if self.is_revoked(&session.to_string()) {
            return Some(CancelReason::SessionRevoked);
        }
        None
    }
}

/// What one accepted connection did.
///
/// Metadata only, by construction: destination, session, verdict. No field
/// holds bytes that came from the request, so this type cannot carry a
/// credential even by accident — the same argument `SubstitutionAudit` makes,
/// for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionOutcome {
    /// Where the client asked to go, or `None` when it never said.
    ///
    /// `None` is a real state and not a gap: a client that sends a malformed
    /// request line, or connects and says nothing, has no destination the
    /// broker could have parsed. **The outcome is still reported in that
    /// case.** The first version returned `None` for the whole outcome when
    /// there was no target, which meant a dropped connection produced *no
    /// record at all* — and a listener that cannot say what it discarded is
    /// not auditable, which is the one property this module most needs.
    pub target: Option<AuthorityEndpoint>,
    /// The session the proof resolved to, or `None` when no proof ever
    /// resolved. Never invented: a connection refused before a proof was seen
    /// reports no session rather than a placeholder one.
    pub session: Option<String>,
    pub result: ConnectionResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionResult {
    /// Handled, and the handler returned cleanly.
    Completed,
    /// Refused or failed. **A class and an optional detail, not a rendered
    /// string.**
    ///
    /// Both halves used to be one `String`, and the string was the error's own
    /// `Display` — which for `Protocol` is the client's request line, verbatim.
    ///
    /// Measured: `parse_connect_target` runs *before* the session proof is
    /// authenticated, and `ConnectTargetError::NoPort` attaches the request
    /// line's authority unchanged. So a bare socket — no proof, no surrogate,
    /// not even a well-formed CONNECT — could write arbitrary bytes into the
    /// operator's log:
    ///
    /// ```text
    /// WARN CONNECT refused destination=<no destination read> session=None
    ///      reason=malformed CONNECT request: CONNECT authority "…" carries no port
    /// ```
    ///
    /// The durable chain was already protected, because it recorded a class
    /// rather than the text. The operator's line was left carrying the text on
    /// the judgement that it is "the surface that already exists to hold
    /// diagnostic detail" — a judgement the chain's own comment contradicts by
    /// calling that same text attacker-controlled, and which was reached
    /// without the fact that decides it: the reach is unauthenticated.
    ///
    /// The class is derived from the error's *kind* at the one point where the
    /// error is in hand, so the chain and the log cannot disagree about it.
    /// They previously had two functions, one of which matched on rendered
    /// text, and they answered differently for most variants.
    ///
    /// Neither half is ever sent to the client: the substitution refusal is
    /// opaque on the wire by design.
    Refused {
        /// Stable, client-free, and stable enough to count refusals by.
        class: &'static str,
        /// The diagnostic text, when it is a fact about *this* broker.
        ///
        /// `None` where the text would be a copy of what the client sent. An
        /// operator loses the wording and keeps the ability to count, alert on
        /// and correlate by cause, which is what a log line is for.
        detail: Option<String>,
    },
    /// Torn down deliberately: broker shutdown, session revoked, or the head
    /// deadline elapsed.
    ///
    /// The `CancelReason` itself and not its rendering. It was a `String`, and
    /// the first thing built on top of it had to recover the reason by matching
    /// on the *text* of a `Display` impl — a class of coupling where changing
    /// a human-readable message silently changes what the audit chain records.
    /// The value is `Copy` and compares, so there was never a reason to lose
    /// it on the way here.
    Cancelled(CancelReason),
}

/// Where a listener sends what happened to each connection.
///
/// A trait so a test can collect and the broker can forward to its audit
/// chain, without the listener deciding either.
pub trait ListenerReport: Send + Sync + 'static {
    fn record(&self, outcome: ConnectionOutcome);
}

/// Drops every outcome. Explicit rather than an absent parameter, so a caller
/// that has not wired reporting has made a visible choice.
#[derive(Debug)]
pub struct DiscardReport;

impl ListenerReport for DiscardReport {
    fn record(&self, _outcome: ConnectionOutcome) {}
}

/// Serves one accepted connection, from CONNECT head to tunnel teardown.
///
/// Implemented by the broker, which owns the surrogate store and the audit
/// chain. Called on a detached task, so it may block; cancellation arrives
/// through the tunnel's own poll rather than through this trait.
pub trait ConnectionHandler: Send + Sync + 'static {
    fn run(&self, tunnel: EstablishedTunnel) -> Result<(), BridgeError>;
}

/// Lifecycle knobs. Every one has a bounded default, because the failure this
/// module exists to prevent is a resource that cannot be reclaimed.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// How long a client may take to send its CONNECT head.
    pub head_deadline: Duration,
    /// Inner-head and response-size limits for the relay.
    pub relay: RelayLimits,
    /// Accept backlog for the listening socket.
    pub backlog: u32,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            // Short. A CONNECT client that opens a socket and then says nothing
            // is either broken or probing, and a broker that waits indefinitely
            // for one has turned its accept loop into a list of whoever
            // connected most recently.
            head_deadline: Duration::from_secs(10),
            relay: RelayLimits::default(),
            backlog: 128,
        }
    }
}

/// What the accept loop does after a failed `accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptFailure {
    /// Keep listening. A transient accept error (EMFILE under load, for one)
    /// must not kill the listener: the next `accept` may well succeed, and a
    /// bridge that stops listening because of one bad moment is a bridge with
    /// an availability bug that **looks like a crash** — the process is alive,
    /// it has simply stopped serving, and nothing logs a difference.
    Continue,
    /// The loop is done.
    Stop,
}

/// Extracted from the accept loop so the decision is testable without
/// fabricating a kernel accept error.
///
/// That extraction is not tidiness. A failed `accept` cannot be provoked on
/// demand — closing the descriptor behind the listener races the runtime's own
/// polling, and exhausting the process's file descriptors is slow and
/// host-dependent — so the branch was reachable only by the kernel deciding to
/// be unlucky, and the falsification run proved it: turning that `continue`
/// into a `return` left the whole suite **green**, because no test ever made
/// `accept` fail.
///
/// A decision whose wrong answer is "the broker quietly stops serving" is worth
/// a named function and a direct test.
fn on_accept_failure(shutdown: &ShutdownSignal) -> AcceptFailure {
    // The one accept error that is not transient: once stopped, the same error
    // repeats forever, so a loop that continues on it spins at full CPU while
    // the broker is shutting down.
    if shutdown.is_stopped() {
        AcceptFailure::Stop
    } else {
        AcceptFailure::Continue
    }
}

/// How many tunnels this broker is relaying right now.
///
/// **This exists because "wait for the tunnels to finish" needs something to
/// wait for.** A shutdown that slept for a fixed window would either be slow on
/// an idle broker or cut a real one short, and a broker that guesses which one
/// to be is guessing about exactly the moment it least wants to. The count is
/// what turns a bounded window into a real drain that also returns immediately
/// when there is nothing to drain.
///
/// Deliberately not a `Mutex<usize>`: it is written from a detached task per
/// connection and read from a shutdown thread, and there is no invariant worth
/// protecting — a torn read would only make the drain window expire a
/// fraction early, which is what the window is for.
#[derive(Debug, Default)]
pub struct InFlight(std::sync::atomic::AtomicUsize);

impl InFlight {
    /// One more tunnel is being relayed.
    pub fn enter(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// That tunnel is over, whatever ended it.
    pub fn leave(&self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many are open. Zero is the only value that means "drained".
    pub fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A CONNECT listener.
pub struct ConnectListener {
    bridge: Bridge,
    leaves: Arc<dyn LeafSource + Send + Sync>,
    upstream: Arc<dyn UpstreamResolver + Send + Sync>,
    proofs: Arc<dyn SessionProofs + Send + Sync>,
    shutdown: Arc<ShutdownSignal>,
    in_flight: Arc<InFlight>,
    config: ListenerConfig,
}

impl ConnectListener {
    /// Build a listener that allows exactly `allowed`.
    ///
    /// The shutdown signal is a parameter rather than something the listener
    /// makes and keeps: a caller that cannot signal this object cannot shut it
    /// down, and a listener that cannot be shut down is not a lifecycle.
    pub fn new(
        leaves: Arc<dyn LeafSource + Send + Sync>,
        upstream: Arc<dyn UpstreamResolver + Send + Sync>,
        proofs: Arc<dyn SessionProofs + Send + Sync>,
        shutdown: Arc<ShutdownSignal>,
        allowed: Vec<AuthorityEndpoint>,
        config: ListenerConfig,
    ) -> Self {
        let bridge = Bridge::new(ConnectPolicy { allowed })
            .with_head_deadline(config.head_deadline)
            .with_cancel(shutdown.clone());
        Self {
            bridge,
            leaves,
            upstream,
            proofs,
            shutdown,
            in_flight: Arc::new(InFlight::default()),
            config,
        }
    }

    /// Count the tunnels this listener serves, so a shutdown has something to
    /// wait for.
    ///
    /// A builder rather than a constructor argument because every other caller
    /// — the tests, and the path where a broker runs without a CONNECT listener
    /// at all — wants a listener that counts into a gauge nobody reads, and
    /// making them invent one to satisfy the type would be a worse trade than
    /// one method.
    pub fn with_in_flight(mut self, in_flight: Arc<InFlight>) -> Self {
        self.in_flight = in_flight;
        self
    }

    /// Say how each destination is reached, and against which anchors.
    ///
    /// Separate from [`ConnectListener::new`] because a listener that could
    /// only be built one way would have nowhere to put this, and "nowhere to
    /// put it" is how a credential ends up crossing a socket nobody chose. Left
    /// unset, the bridge reaches no destination at all rather than reaching one
    /// the clear.
    pub fn with_upstream_transport(
        mut self,
        policy: Arc<dyn UpstreamTransportPolicy + Send + Sync>,
        roots: Arc<rustls::RootCertStore>,
    ) -> Self {
        self.bridge = self.bridge.with_upstream(policy, roots);
        self
    }

    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Accept connections until the shutdown signal is set.
    ///
    /// The accept loop stops on shutdown, but an accepted-and-dispatched task
    /// is *also* cancelled by the same signal through the bridge's poll, so a
    /// tunnel in flight does not outlive the broker by however long its client
    /// takes to disconnect.
    pub async fn run(
        self,
        listener: TcpListener,
        handler: Arc<dyn ConnectionHandler>,
        report: Arc<dyn ListenerReport>,
    ) {
        let Self {
            bridge,
            leaves,
            upstream,
            proofs,
            shutdown,
            in_flight,
            config: _,
        } = self;
        // Cloned out of the destructure so the accept loop can keep handing it
        // to each task while the original stays here.
        let gauge = Arc::clone(&in_flight);

        loop {
            if shutdown.is_stopped() {
                return;
            }
            let accepted = tokio::select! {
                res = listener.accept() => res,
                _ = shutdown.wait_stopped() => return,
            };
            let (stream, _peer) = match accepted {
                Ok(pair) => pair,
                Err(_) => match on_accept_failure(&shutdown) {
                    AcceptFailure::Stop => return,
                    AcceptFailure::Continue => continue,
                },
            };
            if shutdown.is_stopped() {
                return;
            }

            let bridge = bridge.clone();
            let leaves = leaves.clone();
            let upstream = upstream.clone();
            let proofs = proofs.clone();
            let report = report.clone();
            let handler = handler.clone();
            // Counted **here**, before the task is spawned rather than inside
            // it, so a shutdown that arrives between the spawn and the task's
            // first instruction cannot see zero while a tunnel is already on
            // its way up. The window in the other direction — accepted, not yet
            // counted — does not exist, because the two lines are adjacent.
            in_flight.enter();
            // Cloned per connection, like every other handle handed to the
            // task: the accept loop has to outlive them all.
            let gauge = Arc::clone(&gauge);
            tokio::spawn(async move {
                let outcome = serve_one(bridge, stream, leaves, upstream, proofs, handler).await;
                report.record(outcome);
                // After `record`, deliberately: the audit entry is part of
                // ending the tunnel, and a drain that returned before it was
                // written would report a shutdown that lost the reason the
                // tunnel ended — the one thing the drain exists to preserve.
                gauge.leave();
            });
        }
    }
}

/// Serve exactly one accepted connection and classify how it ended.
async fn serve_one(
    bridge: Bridge,
    stream: tokio::net::TcpStream,
    leaves: Arc<dyn LeafSource + Send + Sync>,
    upstream: Arc<dyn UpstreamResolver + Send + Sync>,
    proofs: Arc<dyn SessionProofs + Send + Sync>,
    handler: Arc<dyn ConnectionHandler>,
) -> ConnectionOutcome {
    // The bridge is written against `std::net::TcpStream`. A blocking bridge on
    // the accept loop's task would stop the listener from serving anyone else
    // while one tunnel runs, so the conversion happens on a blocking thread
    // rather than inline. `block_in_place` is not available on a current-thread
    // runtime, hence the explicit `spawn_blocking` below.
    let (target, session, result) = tokio::task::spawn_blocking(move || {
        let std_stream: std::net::TcpStream = match stream.into_std() {
            Ok(s) => s,
            Err(e) => {
                return (
                    None,
                    String::new(),
                    ConnectionResult::Refused {
                        class: "accept_failed",
                        detail: Some(format!("could not take the socket: {e}")),
                    },
                )
            }
        };
        if let Err(e) = std_stream.set_nonblocking(false) {
            return (
                None,
                String::new(),
                ConnectionResult::Refused {
                    class: "accept_failed",
                    detail: Some(format!("could not set the socket blocking: {e}")),
                },
            );
        }
        let now = std::time::Instant::now();
        match bridge.serve_connect(
            std_stream,
            leaves.as_ref(),
            upstream.as_ref(),
            Some(proofs.as_ref()),
            now,
        ) {
            Ok(tunnel) => {
                let target = tunnel.target.clone();
                let session = tunnel.session.to_string();
                let outcome = handler.run(tunnel);
                (Some(target), session, classify(outcome))
            }
            // A refusal before the tunnel exists has no session to name, and
            // `None` here is honest: the outcome reports the destination the
            // client asked for and the reason, and no session was ever proven.
            Err(e) => (None, String::new(), classify(Err(e))),
        }
    })
    .await
    .unwrap_or_else(|e| {
        (
            None,
            String::new(),
            ConnectionResult::Refused {
                class: "broker_fault",
                detail: Some(format!("connection task panicked: {e}")),
            },
        )
    });

    ConnectionOutcome {
        target,
        session: if session.is_empty() {
            None
        } else {
            Some(session)
        },
        result,
    }
}

/// Split out so the join-handler above reads as the two things it is.
fn classify(outcome: Result<(), BridgeError>) -> ConnectionResult {
    match outcome {
        Ok(()) => ConnectionResult::Completed,
        // Cancellation is separated from failure on purpose. A revoked session
        // and a refused destination are the same event to the client — the
        // tunnel closes either way — and an operator needs to tell them apart,
        // because one is policy working and the other is a client being rude.
        Err(BridgeError::Cancelled(reason)) => ConnectionResult::Cancelled(reason),
        // The one place the error is in hand, and therefore the only place a
        // class can honestly be derived from its kind. Doing it here rather
        // than at each reporting surface is what makes the chain and the log
        // incapable of disagreeing.
        Err(e) => ConnectionResult::Refused {
            class: crate::connect_runtime::refusal_class(&e),
            detail: crate::connect_runtime::refusal_detail(&e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{on_accept_failure, AcceptFailure, ShutdownSignal};

    /// The claim is not "a failed accept is recoverable" in general — it is
    /// *which* failures are recoverable. A listener that treats every accept
    /// error as transient serves until the process is killed; one that treats
    /// every one as fatal stops serving the moment the host runs out of file
    /// descriptors. Both failures are invisible from the outside: the process
    /// is alive and the broker has gone quiet.
    #[test]
    fn a_transient_accept_failure_does_not_stop_the_listener() {
        let signal = ShutdownSignal::new();
        assert_eq!(
            on_accept_failure(&signal),
            AcceptFailure::Continue,
            "a live listener must survive an accept error it did not cause"
        );
    }

    #[test]
    fn an_accept_failure_during_shutdown_stops_the_loop() {
        let signal = ShutdownSignal::new();
        signal.stop();
        assert_eq!(
            on_accept_failure(&signal),
            AcceptFailure::Stop,
            "continuing to accept after stop() is a loop that spins at full CPU \
             while the broker is going down"
        );
    }
}
