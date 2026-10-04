//! The broker leaves on `SIGTERM`, and `SIGINT`.
//!
//! ## Why this test exists
//!
//! `crates/broker/src/main.rs::install_ordered_shutdown` installs a handler
//! that stores a flag, and a watcher thread that notices the flag within 50 ms,
//! stops the accept loop, waits up to `SHUTDOWN_DRAIN` (5 s) for tunnels in
//! flight, and then calls `std::process::exit(0)`. The comment on that function
//! records what it replaced: a broker where an operator's `SIGTERM` did what
//! the kernel does to every process, killing it and taking every tunnel down
//! as a side effect of file descriptors closing — a tunnel that ends with no
//! recorded reason.
//!
//! Every other test in this package that spawns `asv-brokerd` cleans up with
//! `Child::kill`, which is `SIGKILL`. That is correct for a fixture and fatal
//! as an assertion: `SIGKILL` cannot distinguish a broker that left because it
//! was told to from a broker that had to be taken away. So the property the
//! ordered-shutdown work exists to provide had **no test anywhere**, and the
//! first evidence that it might be missing was a broker process that outlived
//! `timeout 8` by an hour.
//!
//! That process turned out to be running a binary built before the current
//! wiring, so it is not evidence of a defect — and "not evidence of a defect"
//! is not the same as "measured". This test is the measurement.
//!
//! ## What it does not establish
//!
//! **That a tunnel drains in an orderly way.** A broker with nothing in flight
//! has nothing to drain, so the drain window is entered and left immediately.
//! The tunnel-mid-shutdown ordering is measured by `connect_listener_lifecycle`
//! against the listener, which is where that behaviour lives.
//!
//! **That the exit is clean in the presence of work.** Same reason.
//!
//! **Anything about a system service.** `asv-brokerd.dedicated.service` stops
//! with `SIGTERM` too, but installing and stopping the unit needs a system
//! account and `sudo`, and is tracked as the host-dependent half of C1-R.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// How long the broker may take to come up and create its socket.
const BOOT: Duration = Duration::from_secs(15);

/// How long the broker may take to leave after a signal.
///
/// The design allows 50 ms for the watcher to notice, up to `SHUTDOWN_DRAIN`
/// (5 s) for the drain, and then an immediate `exit`. Ten seconds is generous
/// enough not to be flaky on a loaded machine and short enough that a broker
/// which never leaves fails the test rather than hanging the suite.
const LEAVE: Duration = Duration::from_secs(10);

/// A broker this test owns. `SIGKILL` on the way out, because a fixture that
/// has already been signalled should be gone; if it is not, the test above
/// already failed and said so.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A real vault on disk, so the broker reaches the state an operator runs it
/// in rather than the no-vault path that refuses everything.
fn write_vault(dir: &std::path::Path) {
    const PASSPHRASE: &str = "brokerd-sigterm-passphrase";
    std::fs::create_dir_all(dir).expect("create broker dir");
    let passphrase = dir.join("passphrase.txt");
    std::fs::write(&passphrase, format!("{PASSPHRASE}\n")).expect("write passphrase");
    VaultStore::create(
        dir.join("vault.asv"),
        &SecretString::new(PASSPHRASE.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");
}

/// Spawns a broker, waits until it is serving, and returns it with its socket.
fn start_broker(tag: &str) -> (Broker, std::path::PathBuf) {
    // One directory per instance: cargo runs the tests in this binary on
    // threads inside one process, so a path keyed on the pid alone would hand
    // two tests the same socket.
    let dir = std::env::temp_dir().join(format!(
        "asv-sigterm-{tag}-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    write_vault(&dir);
    let socket = dir.join("broker.sock");

    let child = Command::new(env!("CARGO_BIN_EXE_asv-brokerd"))
        .arg(&socket)
        .arg("--vault")
        .arg(dir.join("vault.asv"))
        .arg("--passphrase-file")
        .arg(dir.join("passphrase.txt"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn asv-brokerd");
    let broker = Broker(child);

    let deadline = Instant::now() + BOOT;
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket.exists(),
        "the broker did not create {} within {BOOT:?}; it never came up, so a \
         later failure would say nothing about the signal",
        socket.display()
    );

    // And it is serving, not merely bound: a broker that cannot answer a Ping
    // is not one whose exit on a signal is worth measuring.
    let request = serde_json::json!({
        "method": "ping",
        "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
    });
    let mut stream = UnixStream::connect(&socket).expect("connect to the broker");
    stream
        .write_all(&serde_json::to_vec(&request).expect("serialize ping"))
        .expect("write ping");
    stream.flush().expect("flush ping");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read pong");
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).expect("parse pong");
    assert!(
        response.get("error").is_none(),
        "the broker answered a ping with an error: {response}"
    );

    (broker, dir)
}

/// Sends `signal` and reports whether the broker left on its own within
/// `LEAVE`, with the status it left with.
fn leaves_after(signal: i32, broker: &mut Child) -> Option<std::process::ExitStatus> {
    // `kill` and not `Child::kill`: the whole claim is about this signal, and
    // the test helper for the other one would answer a different question.
    let sent = unsafe { libc::kill(broker.id() as libc::pid_t, signal) };
    assert_eq!(
        sent,
        0,
        "could not signal the broker: {}",
        std::io::Error::last_os_error()
    );

    let deadline = Instant::now() + LEAVE;
    while Instant::now() < deadline {
        if let Some(status) = broker.try_wait().expect("poll the broker") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// A broker told to stop stops. `SIGTERM` is the signal a service manager and
/// `asv run` send; `SIGINT` is the one an operator presses at a terminal, and
/// the two are installed by the same two lines, so they are measured by the
/// same test rather than one of them being assumed from the other.
#[test]
fn a_signalled_broker_leaves_on_its_own() {
    for (tag, signal, name) in [
        ("term", libc::SIGTERM, "SIGTERM"),
        ("int", libc::SIGINT, "SIGINT"),
    ] {
        let (mut broker, dir) = start_broker(tag);
        let status = leaves_after(signal, &mut broker.0);

        let Some(status) = status else {
            // Say what it is still doing, because "it did not exit" without
            // more is the least useful sentence a test can end on.
            let state = std::fs::read_to_string(format!("/proc/{}/status", broker.0.id()))
                .unwrap_or_else(|e| format!("<unreadable: {e}>"));
            let state_line = state
                .lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or("<no state line>");
            panic!(
                "the broker did not leave within {LEAVE:?} after {name}.\n\
                 {state_line}\n\
                 It caught the signal and did nothing with it, which is the \
                 failure this test exists to catch: every other broker fixture \
                 in this package cleans up with SIGKILL and cannot tell the \
                 two apart."
            );
        };

        assert!(
            status.success(),
            "the broker left on {name} with {status:?}, not by exiting cleanly \
             on its own; a signal that killed it by default action is the \
             kernel tearing it down, which is the behaviour the ordered \
             shutdown path exists to replace"
        );

        // The socket is the broker's promise that it is listening; a process
        // that left through `exit(0)` does not take it away with it.
        assert!(
            dir.join("broker.sock").exists(),
            "the broker left on {name} but left its socket behind, so the next \
             broker on this path would find a stale file and refuse to bind"
        );
    }
}
