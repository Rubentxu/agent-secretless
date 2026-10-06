//! Two claims about the accept loop that no row measured, written against the
//! loop as it is now: a thread per connection, bounded by an in-flight cap.
//!
//! ## Why these rows exist at all
//!
//! `idle_connection_does_not_block_the_broker.rs` predates the change and its
//! module doc still says `main.rs` "calls `serve` on the accepted stream
//! before it accepts again". That was true when it was written and is false now.
//! Its row still passes either way, because `PATIENCE` is 20s and the socket
//! deadline is 5s: a broker that answers the second peer *after* the first
//! times out is indistinguishable, to that row, from one that answers it
//! immediately. So the property the refactor was made for had no row, and the
//! row that claims to cover it does not.
//!
//! `CONNECTION_IO_TIMEOUT` is 5 seconds. That number is what makes row one
//! falsifiable rather than decorative: a broker that serialises waits for the
//! silent peer to time out before it can answer the honest one, so an honest
//! answer inside two seconds is a statement about concurrency, not about how
//! fast loopback is.
//!
//! ## What row two is and is not claiming
//!
//! The cap refuses rather than queues. It refuses **everyone** past the
//! limit, including an honest agent, which is the deliberate trade named in
//! `main.rs`: a visible refusal beats an invisible stall. This row asserts the
//! refusal happens and happens promptly. It does not assert that refusing an
//! honest peer is *right* -- whether the cap should distinguish an agent from a
//! flood is a design question this row deliberately leaves open rather than
//! settling by accident.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// Must mirror `CONNECTION_IO_TIMEOUT` in `crates/broker/src/main.rs`.
///
/// The rows below derive their bounds from it, so a change to the deadline
/// that is not mirrored here turns these rows into decoration.
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Must mirror `MAX_IN_FLIGHT_CONNECTIONS` in `crates/broker/src/main.rs`.
const MAX_IN_FLIGHT_CONNECTIONS: usize = 64;

/// How long an honest client may wait while a silent peer is still open.
///
/// Half the socket deadline, deliberately. A broker that serves the silent
/// peer first cannot answer this client until that deadline has elapsed, so
/// this bound separates the two designs with room on both sides: loopback
/// answers in microseconds, serialised serving takes at least five seconds.
const HONEST_CLIENT_PATIENCE: Duration = Duration::from_secs(2);

struct Sandbox {
    dir: PathBuf,
    vault: PathBuf,
    passphrase: PathBuf,
    sock: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-concurrent-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");
        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("concurrent-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
        VaultStore::create(
            &vault,
            &SecretString::new(value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");
        Self {
            dir,
            vault,
            passphrase,
            sock,
        }
    }

    fn start(&self) -> Child {
        let broker = Command::new(asv_broker::binary::locate("asv-brokerd"))
            .arg(&self.sock)
            .arg("--vault")
            .arg(&self.vault)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn asv-brokerd");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.sock.exists() {
            assert!(
                Instant::now() < deadline,
                "the broker never created its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        broker
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A connected socket that writes nothing and is then held open.
///
/// Dropping these in a batch is what keeps the broker's workers inside the
/// cap: a silent peer is the only kind of peer that stays in flight.
fn silent_connections(sock: &std::path::Path, how_many: usize) -> Vec<UnixStream> {
    (0..how_many)
        .map(|_| UnixStream::connect(sock).expect("connect a silent peer"))
        .collect()
}

/// Sends a real `AgentInfo` and reports the elapsed time and whether the broker
/// answered with something parseable.
fn ask_and_time(sock: &std::path::Path) -> (Duration, bool) {
    let started = Instant::now();
    let mut stream = UnixStream::connect(sock).expect("connect an honest peer");
    let _ = stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT + Duration::from_secs(5)));
    let payload = serde_json::to_vec(&asv_ipc_protocol::Request::AgentInfo {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
    })
    .expect("serialize the request");
    if stream.write_all(&payload).is_err() {
        return (started.elapsed(), false);
    }
    let _ = stream.flush();
    let mut buf = vec![0u8; 64 * 1024];
    let answered = match stream.read(&mut buf) {
        Ok(n) if n > 0 => serde_json::from_slice::<serde_json::Value>(&buf[..n]).is_ok(),
        // EOF or an error is not an answer. A refused connection lands here,
        // which is the whole point of row two.
        _ => false,
    };
    (started.elapsed(), answered)
}

/// **The row the refactor was made for.** A peer that connects and says
/// nothing must not delay the next peer by the socket deadline.
///
/// Falsifiable because the two designs differ by seconds, not by microseconds:
/// serialised serving cannot answer until the silent peer's 5s read expires,
/// so `HONEST_CLIENT_PATIENCE` of 2s is unreachable for it.
#[test]
fn an_honest_client_is_answered_while_a_silent_peer_is_still_open() {
    let sandbox = Sandbox::new("honest");
    let _broker = sandbox.start();

    // Held open for the whole row. Dropped at the end of this scope.
    let _silent = silent_connections(&sandbox.sock, 1);
    // Let the broker accept and start serving it before the honest peer
    // arrives, so the row cannot pass by racing ahead of the accept loop.
    std::thread::sleep(Duration::from_millis(250));

    let (elapsed, answered) = ask_and_time(&sandbox.sock);

    // Printed rather than only asserted, because the assertion alone cannot be
    // told apart from a vacuous one: a bound that nothing ever approaches is
    // indistinguishable from a bound that is simply far away. This number is
    // what makes the row re-derivable from the run rather than taken on trust.
    eprintln!("honest peer answered in {elapsed:?} (bound {HONEST_CLIENT_PATIENCE:?})");

    assert!(
        answered,
        "the honest peer got no parseable answer while a silent peer held a connection \
         open ({elapsed:?} elapsed)"
    );
    assert!(
        elapsed < HONEST_CLIENT_PATIENCE,
        "the honest peer waited {elapsed:?}, which is longer than {HONEST_CLIENT_PATIENCE:?} \
         and therefore means the broker served the silent peer first. \
         A serialised accept loop cannot answer before \
         {CONNECTION_IO_TIMEOUT:?}, so this is the broker queueing rather than \
         serving connections concurrently."
    );
}

/// **The row that the cap is not a one-way ratchet.** A slot has to come back.
///
/// Rows one and two are both satisfiable by a counter that only ever counts
/// up: fill the cap once and every later connection is refused, and both rows
/// pass. Only a row that releases a slot and then expects the next peer to be
/// admitted can see a missing `fetch_sub`, which is the failure that turns a
/// broker into one that refuses every agent for the rest of the process's
/// life after a single busy minute.
///
/// Bounded by retry rather than by a sleep: the slot comes back when the
/// broker's read on the closed peer returns, and how long that takes is not
/// something this test should assert. What it asserts is that the slot comes
/// back *at all*, inside a window far longer than a loopback close needs.
#[test]
fn a_slot_comes_back_when_a_peer_finishes() {
    let sandbox = Sandbox::new("release");
    let _broker = sandbox.start();

    let mut silent = silent_connections(&sandbox.sock, MAX_IN_FLIGHT_CONNECTIONS);
    std::thread::sleep(Duration::from_millis(500));

    // The over-limit peer is refused while the cap is full. This is row two,
    // and it is repeated here so that a broker which refuses unconditionally
    // cannot pass by never giving a slot back.
    assert!(
        !ask_and_time(&sandbox.sock).1,
        "the cap admitted a peer while all {MAX_IN_FLIGHT_CONNECTIONS} were still open; \
         nothing to release in this row"
    );

    // Close one of the held sockets. The broker's read returns 0 and its worker
    // finishes, which is where the slot comes back.
    drop(silent.pop());

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut admitted = false;
    while Instant::now() < deadline {
        if ask_and_time(&sandbox.sock).1 {
            admitted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(
        admitted,
        "after a held peer closed, no new peer was admitted within 10s. The cap is \
         counting up and never counting down: a counter that never releases its slots \
         refuses every agent for the rest of the process's life once it is full."
    );
}
///
/// Falsifiable in two directions: a broker with no cap would answer the
/// over-limit peer (or hold it until the deadline), and a broker that queued
/// instead of refusing would answer it later rather than never.
#[test]
fn a_burst_past_the_in_flight_cap_is_refused_rather_than_queued() {
    let sandbox = Sandbox::new("cap");
    let _broker = sandbox.start();

    // Fill the cap. These are held for the whole row, so the broker's workers
    // stay occupied and the next peer is genuinely over the limit rather than
    // arriving into a slot that just freed.
    let _silent = silent_connections(&sandbox.sock, MAX_IN_FLIGHT_CONNECTIONS);
    std::thread::sleep(Duration::from_millis(500));

    let (elapsed, answered) = ask_and_time(&sandbox.sock);

    eprintln!(
        "over-limit peer turned away in {elapsed:?} after {MAX_IN_FLIGHT_CONNECTIONS} \
         were in flight (socket deadline {CONNECTION_IO_TIMEOUT:?})"
    );

    assert!(
        !answered,
        "a peer past the in-flight cap of {MAX_IN_FLIGHT_CONNECTIONS} was answered \
         ({elapsed:?} elapsed). The cap is supposed to refuse rather than queue, so an \
         answer here means the cap is not holding."
    );
    assert!(
        elapsed < CONNECTION_IO_TIMEOUT,
        "the over-limit peer took {elapsed:?} to be turned away, which is at or beyond the \
         {CONNECTION_IO_TIMEOUT:?} socket deadline. That is a peer being served and then \
         abandoned, not a refusal: a refusal is immediate, and the difference between \
         'refused' and 'waited its turn' is exactly what this row is for."
    );
}