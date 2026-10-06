//! The broker serves connections one at a time, and a peer that opens one and
//! says nothing must not stop the next peer being served.
//!
//! ## What this is about
//!
//! `main.rs` accepts in a loop and calls `serve` on the accepted stream before
//! it accepts again. `serve` blocks on a `read`. So the broker's availability
//! depends on every peer finishing its exchange, and a peer that connects and
//! then writes nothing holds that read open for as long as it likes.
//!
//! That is not a remote attack — the socket is `0600` in a `0700` directory, so
//! the peer shares the uid the installation already gave the broker. It is also
//! not hypothetical: any process that crashes mid-exchange, or a client killed
//! between `connect` and `write`, is exactly this peer. The fix is a deadline
//! on the socket (`CONNECTION_IO_TIMEOUT` in `main.rs`) rather than a claim that
//! well-behaved peers finish on their own.
//!
//! ## What makes this row falsifiable
//!
//! The row asserts a *second*, healthy connection is answered while the first is
//! still open and still silent. Without the deadline the second connection is
//! never accepted, because the loop has not come back around, and this test
//! hangs rather than failing — so it is bounded, and the bound is what the
//! mutation of removing `set_read_timeout` will exhaust.
//!
//! The bound is generous relative to what it has to cover (a loopback `AgentInfo`
//! answered in microseconds) because the failure it must distinguish is "the
//! broker is stuck" from "the broker answered", and a tight bound would make
//! the second indistinguishable from the first on a loaded machine.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// How long a healthy second client may wait for its answer before this row
/// calls the broker stuck.
///
/// Larger than any loopback round trip by orders of magnitude. It is bounded so
/// that removing the deadline produces a *failure* rather than a hung suite: a
/// test that hangs is worse than one that fails, because it takes the whole
/// run with it and reports nothing.
const PATIENCE: Duration = Duration::from_secs(20);

fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}

/// A working directory with a real vault, a real passphrase and a socket path.
struct Sandbox {
    dir: PathBuf,
    vault: PathBuf,
    passphrase: PathBuf,
    sock: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-idle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");
        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("idle-{tag}-passphrase");
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

    /// Starts the broker and returns the guard that keeps it alive.
    fn start(&self) -> Child {
        let broker = Command::new(cargo_bin("asv-brokerd"))
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

/// Asks the broker to describe itself, bounded, and reports whether it answered.
fn answered_within(sock: &Path, patience: Duration) -> bool {
    let deadline = Instant::now() + patience;
    let Ok(mut stream) = UnixStream::connect(sock) else {
        return false;
    };
    // Never block past `patience`, whatever the broker does. Without this the
    // row would hang rather than fail, which is the outcome it exists to
    // prevent.
    let _ = stream.set_read_timeout(Some(patience));
    let payload = serde_json::to_vec(&asv_ipc_protocol::Request::AgentInfo {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
    })
    .expect("serialize the request");
    if stream.write_all(&payload).is_err() {
        return false;
    }
    let _ = stream.flush();

    let mut buf = vec![0u8; 64 * 1024];
    // One read, not a loop. All three arms of that match returned, so the
    // `while` around it could only ever run once -- `clippy::never_loop` is
    // right, and it is the deny lint rather than a warning that says so. The
    // deadline guard survives the loop's removal because the guard was the
    // part that was doing something: `patience` can elapse between setting the
    // timeout above and reaching the read, and refusing the read then is
    // exactly what the loop did. The read itself is already bounded by
    // `set_read_timeout(Some(patience))`, so a second attempt would only ever
    // re-arm the same deadline against the same stream.
    if Instant::now() >= deadline {
        return false;
    }
    match stream.read(&mut buf) {
        Ok(0) => false,
        Ok(n) => serde_json::from_slice::<serde_json::Value>(&buf[..n]).is_ok(),
        Err(_) => false,
    }
}

/// A peer that connects and never writes must not stop the next peer being
/// served.
///
/// Two clients, in this order:
///
/// 1. **the silent one** — connects and is then deliberately never written to,
///    and held open for the rest of the row;
/// 2. **the honest one** — a normal `AgentInfo`, which must be answered.
///
/// Without a deadline on the connection the broker is still inside the first
/// client's `read` when the second arrives, never returns to `accept`, and the
/// second client is answered by nothing. That is the whole failure: a single
/// idle socket, from a process the installation already trusts enough to share
/// the uid, and every agent in the system can no longer reach a credential.
///
/// The mutation that puts this red is deleting the `set_read_timeout` call in
/// `serve`, or setting it to `None`. With that gone the row exhausts `PATIENCE`
/// and fails rather than hanging, which is why the bound exists.
#[test]
fn an_idle_connection_does_not_stop_the_next_client_being_served() {
    let sandbox = Sandbox::new("blocked");
    let mut broker = sandbox.start();

    // The silent peer. Held in a binding so it is dropped at the end of the
    // row and not before: dropping it early would close the connection and let
    // the broker's `read` return, which is the very thing being tested.
    let silent = match UnixStream::connect(&sandbox.sock) {
        Ok(stream) => stream,
        Err(error) => panic!("connect the silent peer: {error}"),
    };

    // Give the broker time to accept the silent peer and block in its read.
    // Without this the second client can be answered before the first is even
    // accepted, and the row would pass on a broker that has the defect.
    std::thread::sleep(Duration::from_millis(500));

    let answered = answered_within(&sandbox.sock, PATIENCE);

    let _ = silent;
    let _ = broker.kill();
    let _ = broker.wait();
    let _ = std::fs::remove_dir_all(&sandbox.dir);

    assert!(
        answered,
        "a peer that connected and said nothing stopped every other client from \
         being served for {PATIENCE:?}. The broker serves connections one at a \
         time, so one idle socket takes the whole service down — and an idle \
         socket is what a client killed between `connect` and `write` leaves \
         behind, no attacker required."
    );
}