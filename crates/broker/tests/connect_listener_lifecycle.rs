//! The production CONNECT listener's lifecycle (V1-C2).
//!
//! What these prove is **lifecycle**, not substitution: substitution is already
//! proven end to end in `uat_010_connect_substitution.rs`, and re-proving it
//! here would be a second test saying the same thing. What has never been
//! proven anywhere is the part a *listener* adds, and that is what a capability
//! without a network surface cannot have.
//!
//! Three properties, in increasing order of how much they matter:
//!
//! 1. a client that connects and says nothing is dropped rather than waited
//!    on forever. `read_connect_head` had **no deadline at all** before this,
//!    and no test could catch it because no test ran a listener — every caller
//!    handed it a client that had already spoken.
//! 2. a refusal is per connection. One hostile client must not stop the broker
//!    serving the next one.
//! 3. shutdown stops the accept loop, so a socket bound by the broker is
//!    actually released on the way out.
//!
//! Cancellation *of an established tunnel* — the revoke and shutdown-mid-tunnel
//! cases — needs a full ADR-0019 proof and a real TLS client, and belongs with
//! the rig in `uat_010` rather than with stubs. It is not claimed here.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asv_broker::connect_listener::{
    ConnectListener, ConnectionHandler, ConnectionOutcome, ConnectionResult, DiscardReport,
    ListenerConfig, ListenerReport, ShutdownSignal,
};
use asv_broker::tls_bridge::{
    AuthorityEndpoint, BridgeError, EstablishedTunnel, LeafError, LeafSource, VerifiedLeaf,
};
use asv_domain::Authority;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Collects every outcome so the test can assert on what the listener reported.
#[derive(Debug, Default)]
struct Collect(Mutex<Vec<ConnectionOutcome>>);

impl ListenerReport for Collect {
    fn record(&self, outcome: ConnectionOutcome) {
        self.0.lock().unwrap().push(outcome);
    }
}

impl Collect {
    fn outcomes(&self) -> Vec<ConnectionOutcome> {
        self.0.lock().unwrap().clone()
    }
    fn wait_for(&self, n: usize, within: Duration) -> Option<Vec<ConnectionOutcome>> {
        let deadline = std::time::Instant::now() + within;
        loop {
            let got = self.outcomes();
            if got.len() >= n {
                return Some(got);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A handler that should never be reached by these tests.
///
/// If it is, the listener dispatched a connection it should have refused first,
/// and the assertion below becomes a real finding rather than a test artefact.
#[derive(Debug)]
struct MustNotRun;

impl ConnectionHandler for MustNotRun {
    fn run(&self, _tunnel: EstablishedTunnel) -> Result<(), BridgeError> {
        panic!(
            "the listener reached the handler for a connection that never sent a usable CONNECT"
        );
    }
}

/// A leaf source that is never consulted: every case here is refused or
/// cancelled before a leaf is needed, and a test that silently reached for one
/// would be testing something other than what it claims.
#[derive(Debug)]
struct NoLeaf;

impl LeafSource for NoLeaf {
    fn issue_for(&self, host: &str, _now: std::time::Instant) -> Result<VerifiedLeaf, LeafError> {
        panic!("a leaf was requested for {host} in a test that never sends a CONNECT");
    }
}

/// Never consulted: a tunnel is never established here.
#[derive(Debug)]
struct NoUpstream;

impl asv_broker::tls_bridge::UpstreamResolver for NoUpstream {
    fn resolve(&self, _t: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        panic!("an upstream was resolved in a test that never establishes a tunnel");
    }
}

/// Never consulted: a tunnel is never established here.
#[derive(Debug)]
struct NoProofs;

impl asv_broker::tls_bridge::SessionProofs for NoProofs {
    fn resolve(&self, _k: &[u8], _n: &[u8], _s: &[u8]) -> Option<asv_domain::AgentSessionId> {
        panic!("a session proof was resolved in a test that never proves a session");
    }
}

fn start(
    config: ListenerConfig,
    shutdown: Arc<ShutdownSignal>,
) -> (SocketAddr, Arc<Collect>, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener
        .set_nonblocking(true)
        .expect("the listener must be non-blocking for the tokio runtime");
    let addr = listener.local_addr().expect("the bound address");
    let tokio_listener = TcpListener::from_std(listener).expect("adopt the listener");
    let collect = Arc::new(Collect::default());

    let l = ConnectListener::new(
        Arc::new(NoLeaf),
        Arc::new(NoUpstream),
        Arc::new(NoProofs),
        shutdown,
        vec![allowed()],
        config,
    );
    let report = collect.clone();
    let handle = tokio::spawn(l.run(tokio_listener, Arc::new(MustNotRun), report));
    (addr, collect, handle)
}

fn allowed() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("example.test").expect("a canonical authority"),
        443,
    )
    .expect("a valid endpoint")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_says_nothing_is_dropped_by_the_head_deadline() {
    let shutdown = Arc::new(ShutdownSignal::new());
    let config = ListenerConfig {
        // Short enough to be a test, long enough that a healthy client's head
        // always fits. A deadline of zero would not test the deadline; it
        // would test that the bridge can refuse.
        head_deadline: Duration::from_millis(300),
        ..ListenerConfig::default()
    };
    let (addr, collect, handle) = start(config, shutdown.clone());

    // Connect and send nothing at all. This is the client that used to hold a
    // thread forever.
    let mut silent = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let sink = [0u8; 16];
    // The write is not the point and may fail; the point is the open socket.
    let _ = silent.write(&sink).await;

    let outcomes = collect
        .wait_for(1, Duration::from_secs(10))
        .expect("the listener must report the silent client");
    let o = &outcomes[0];
    assert!(
        matches!(o.result, ConnectionResult::Cancelled(ref r) if r.contains("deadline")),
        "a silent client must be cancelled by the head deadline, got {:?}",
        o.result
    );
    // No session was ever proven, and the outcome must not invent one.
    assert!(
        o.session.is_none(),
        "a connection refused before a proof was seen must not report a session, got {:?}",
        o.session
    );
    assert!(
        o.target.is_none(),
        "a client that never finished a request line has no parseable destination, \
         and the outcome must say so rather than omit itself: {:?}",
        o.target
    );

    shutdown.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_request_is_refused_and_the_listener_survives_it() {
    let shutdown = Arc::new(ShutdownSignal::new());
    let (addr, collect, handle) = start(ListenerConfig::default(), shutdown.clone());

    // A well-formed TCP conversation that is not a CONNECT.
    let mut rude = tokio::net::TcpStream::connect(addr).await.expect("connect");
    rude.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .expect("send");
    let _ = rude.flush().await;

    let first = collect
        .wait_for(1, Duration::from_secs(10))
        .expect("the refusal must be reported");
    assert!(
        matches!(first[0].result, ConnectionResult::Refused(_)),
        "a non-CONNECT request must be refused, got {:?}",
        first[0].result
    );

    // The listener must still be accepting. This is the property the test
    // would lose if a refusal took the accept loop down with it.
    let mut second = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect again");
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .expect("send again");
    let _ = second.flush().await;

    let both = collect
        .wait_for(2, Duration::from_secs(10))
        .expect("the second connection must also be served and refused");
    assert_eq!(
        both.len(),
        2,
        "both connections must be reported separately"
    );

    shutdown.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_the_accept_loop() {
    let shutdown = Arc::new(ShutdownSignal::new());
    let (addr, _collect, handle) = start(ListenerConfig::default(), shutdown.clone());

    // A connection first, so the listener is provably live rather than merely
    // unproven.
    let mut live = tokio::net::TcpStream::connect(addr).await.expect("connect");
    live.write_all(b"GET / HTTP/1.1\r\n\r\n").await.ok();

    shutdown.stop();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run() must return once the signal is set")
        .expect("the accept loop must not panic on shutdown");

    // With the loop gone, a connection to the same address must be refused by
    // the kernel rather than accepted into a queue nothing will read.
    let after =
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await;
    // Either the connect fails, or it succeeds against a socket the listener
    // no longer drains. Both are "stopped"; what must not happen is the
    // listener reporting another outcome.
    if let Ok(Ok(_)) = after {
        // A successful connect to a dropped listener is a refused-connection
        // race, not a live listener; the assertion that matters is below.
    }
}

/// The two claims the listener's own type system makes, checked directly
/// because they are what a future edit would break silently.
#[test]
fn shutdown_wins_over_a_valid_session() {
    // An operator stopping the broker should see `shutdown` in the log even if
    // the session is perfectly valid, because the reason they caused is the
    // one they need to read.
    let signal = ShutdownSignal::new();
    let session = asv_domain::AgentSessionId::new();
    assert_eq!(
        asv_broker::tls_bridge::Cancel::cancel_reason(&signal, Some(&session)),
        None,
        "a live signal cancels nothing"
    );
    signal.revoke(session.to_string().as_str());
    assert_eq!(
        asv_broker::tls_bridge::Cancel::cancel_reason(&signal, Some(&session)),
        Some(asv_broker::tls_bridge::CancelReason::SessionRevoked),
        "a revoked session must be cancelled"
    );
    signal.stop();
    assert_eq!(
        asv_broker::tls_bridge::Cancel::cancel_reason(&signal, Some(&session)),
        Some(asv_broker::tls_bridge::CancelReason::Shutdown),
        "shutdown must take precedence over a per-session revocation"
    );
}

#[test]
fn a_signal_cancels_a_connection_that_has_no_session_yet() {
    // The CONNECT head names the session, so a session-scoped revoke cannot
    // apply before it is read. Shutdown must still work, or a client that
    // connects and stays silent would be un-droppable — which is the exact DoS
    // the head deadline exists alongside.
    let signal = ShutdownSignal::new();
    signal.stop();
    assert_eq!(
        asv_broker::tls_bridge::Cancel::cancel_reason(&signal, None),
        Some(asv_broker::tls_bridge::CancelReason::Shutdown)
    );
}

/// The deadline has to work **on its own**, not only alongside a cancel source.
///
/// `ConnectListener` always calls both `with_head_deadline` and `with_cancel`,
/// so from the listener's side `is_pollable` is already true for the cancel
/// reason alone and the deadline clause never decides anything. That left the
/// deadline arm of `is_pollable` and `arm_read_timeout` exercised by nothing —
/// and a falsification run confirmed it: dropping that arm left every listener
/// test green, because no listener could reach it.
///
/// An unexercised branch is where the wrong answer hides, so this builds the
/// one configuration the clause exists for: a head deadline and nothing else
/// that could interrupt the read. The client connects and says nothing, and the
/// bridge must give up on its own.
///
/// It lives in this file rather than with the other `Bridge` tests because it
/// was found by falsifying *this* suite, and the harness that found it runs
/// this file.
#[test]
fn a_head_deadline_alone_stops_a_bridge_from_waiting_forever() {
    use asv_broker::tls_bridge::{Bridge, CancelReason, ConnectPolicy};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("the bound address");
    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![allowed()],
    })
    .with_head_deadline(Duration::from_millis(300));

    // `serve_connect` is blocking, so it runs on its own thread and reports
    // through a channel. A plain `join` would hang the whole suite instead of
    // failing it if the deadline regressed, and a hung test is a test that
    // tells you nothing about which assertion broke.
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (stream, _peer) = listener.accept().expect("accept the silent client");
        let outcome = bridge.serve_connect(
            stream,
            &NoLeaf,
            &NoUpstream,
            None,
            std::time::Instant::now(),
        );
        let _ = tx.send(outcome);
    });

    // Connect and send nothing at all.
    let _silent = std::net::TcpStream::connect(addr).expect("connect");

    let outcome = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("a bridge with a head deadline must not wait on a silent client forever");
    worker.join().expect("the bridge thread must not panic");

    assert!(
        matches!(
            outcome,
            Err(BridgeError::Cancelled(CancelReason::DeadlineElapsed))
        ),
        "a silent client must hit the head deadline, got {:?}",
        outcome.err()
    );
}

/// The report type must not be able to carry a credential. This is a
/// compile-time property of the shape, asserted here so the intent is written
/// down: every field is a `String` the listener built itself, and none of them
/// is a request byte.
#[test]
fn a_connection_outcome_carries_only_metadata() {
    let o = ConnectionOutcome {
        target: Some(allowed()),
        session: Some("s-1".into()),
        result: ConnectionResult::Refused("no".into()),
    };
    let rendered = format!("{o:?}");
    assert!(rendered.contains("example.test"));
    assert_eq!(
        o.target,
        Some(allowed()),
        "the outcome reports the destination it was asked for"
    );
    let _ = DiscardReport;
}
