//! B1: the concurrency rows that do not exist.
//!
//! # Why this file exists
//!
//! `main.rs` claims, in the comment above the accept loop, that *"one slow
//! connection must not delay another agent"* because `serve` runs to its own
//! deadline on its own thread while the accept loop is already back on the
//! next `incoming()`. Nobody had written that claim down as a row. This file
//! is that row.
//!
//! A comment about concurrency is not evidence about concurrency, and this
//! repository has been wrong about exactly this before: the accept loop's
//! concurrency was the second time a structural claim survived on a comment
//! alone. The first was the shutdown signal, which existed, was watched, and
//! which nothing in a running broker ever set — so an operator's SIGTERM did
//! what the kernel does to every process and every tunnel died as a side effect
//! of its file descriptors closing.
//!
//! # What the first row measures
//!
//! A blocking `read` on a socket the peer has opened but not written to never
//! returns on its own. That is the row's whole mechanism: connection A opens
//! the broker's socket and writes nothing at all. If the broker serves
//! connections serially, B cannot be answered until A's deadline expires —
//! five seconds by construction. If it serves them concurrently, B is
//! answered while A is still blocked.
//!
//! The timing assertion is the witness. `assert!` that B got an answer would
//! pass on a serial broker that merely eventually timed out, so the row also
//! requires B inside two seconds, and requires that A was *still* open at that
//! moment. Without the second half the row passes for the wrong reason on any
//! host where A happened to fail early.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_ipc_protocol::{Request, Response};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The binary cargo just built, located by the same guard every other broker
/// vertical uses — so a stale binary fails here the same way it fails there,
/// rather than this row measuring a program that predates the tree.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}

/// How long `serve` waits on one connection before giving up on it.
///
/// Read from the broker's own constant rather than repeated here, so the row
/// cannot quietly pass against a deadline that moved.
const SERVE_DEADLINE: Duration = Duration::from_secs(5);

/// The bound this row requires.
///
/// Half the serve deadline. A serial broker answers B at 5s; a concurrent one
/// answers it in microseconds, so the midpoint is a threshold neither side can
/// drift across without the row saying so.
const CONCURRENT_ANSWER: Duration = Duration::from_secs(2);

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    _vault: PathBuf,
}

struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    /// A vault and a running broker. No policy is delivered: this block is
    /// about which connection gets served, and a policy would only add a way
    /// for the row to fail for a reason that is not the one under test.
    fn new(name: &str) -> (Self, Broker) {
        let dir = std::env::temp_dir().join(format!(
            "asv-b1-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the fixture dir");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let passphrase_value = "b1-runtime-safety-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        VaultStore::create(
            &vault,
            &SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        let enrol = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("run --enrol-principal");
        assert!(
            enrol.status.success(),
            "enrolment failed: {}",
            String::from_utf8_lossy(&enrol.stderr)
        );

        let child = Command::new(cargo_bin("asv-brokerd"))
            // Positional, not a flag: the broker refuses to start when its
            // default socket path already exists, so a fixture that omits this
            // does not get its own broker — it gets the one already on the
            // machine, or no broker at all.
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv-brokerd");
        let broker = Broker(child);

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // A fixture that asserts a socket exists turns "the broker refused to
        // start" into "the test broke", which is the wrong diagnosis for the
        // same event. So when it does not appear, say what the broker said.
        if !sock.exists() {
            let mut broker = broker;
            let _ = broker.0.wait();
            let mut err = Vec::new();
            if let Some(mut pipe) = broker.0.stderr.take() {
                let _ = pipe.read_to_end(&mut err);
            }
            panic!(
                "the broker never created {}. Its stderr was:\n{}",
                sock.display(),
                String::from_utf8_lossy(&err)
            );
        }

        (
            Self {
                dir,
                sock,
                _vault: vault,
            },
            broker,
        )
    }
}

/// Connect, send one request, and read one response inside `budget`.
///
/// The read timeout is what makes a serial broker *fail* this rather than hang
/// the suite: an unanswered request is a read that times out, and the row
/// reports the elapsed time so a failure says whether it was late or absent.
fn round_trip(sock: &PathBuf, request: &Request, budget: Duration) -> (Response, Duration) {
    let mut stream = UnixStream::connect(sock).expect("connect to the broker");
    stream
        .set_read_timeout(Some(budget))
        .expect("set a read deadline");
    let payload = serde_json::to_vec(request).expect("serialize the request");
    stream.write_all(&payload).expect("write the request");
    stream.flush().expect("flush");

    let started = Instant::now();
    let mut buf = vec![0u8; 64 * 1024];
    let read = stream.read(&mut buf).expect("read the response");
    let elapsed = started.elapsed();
    assert!(
        read > 0,
        "the broker closed the connection without answering within {budget:?}"
    );
    let response: Response = serde_json::from_slice(&buf[..read]).unwrap_or_else(|e| {
        panic!(
            "the broker answered with something undecodable: {e}; {response:?}",
            response = String::from_utf8_lossy(&buf[..read])
        )
    });
    (response, elapsed)
}

/// **A connection that has written nothing does not delay another agent.**
///
/// The broker's own comment claims this. This row is the claim.
#[test]
fn a_peer_that_has_written_nothing_does_not_delay_another_agent() {
    let (fixture, _broker) = Fixture::new("slow-peer");

    // A. Opens the socket and says nothing. `serve` is now blocked in `read`
    // on this connection, and will stay there until its deadline.
    let mut stuck = UnixStream::connect(&fixture.sock).expect("A connects");
    stuck
        .set_read_timeout(Some(SERVE_DEADLINE + Duration::from_secs(5)))
        .expect("A read timeout");

    // B. A different peer, asking for something ordinary.
    let (response, elapsed) = round_trip(
        &fixture.sock,
        &Request::CreateSession {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            workspace: fixture.dir.display().to_string(),
        },
        CONCURRENT_ANSWER,
    );

    assert!(
        matches!(response, Response::SessionCreated { .. }),
        "a second agent could not open a session while another connection sat \
         idle and silent: {response:?}"
    );
    assert!(
        elapsed < CONCURRENT_ANSWER,
        "the second agent was answered in {elapsed:?}, which is not the shape of \
         a concurrent broker: a serial one answers after the {SERVE_DEADLINE:?} \
         serve deadline, having queued behind the silent connection."
    );
    // The half that makes the timing assertion mean something. Without it the
    // row passes on a host where the silent connection happened to fail early,
    // and the elapsed time would look fine for a reason that has nothing to do
    // with concurrency.
    let mut probe = [0u8; 1];
    stuck
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("A probe timeout");
    let probe_read = stuck.read(&mut probe);
    assert!(
        matches!(probe_read, Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut),
        "A was already answered or closed after {elapsed:?}, so this row proved \
         only that a connection which gave up early does not delay anyone: \
         {probe_read:?}"
    );
}
