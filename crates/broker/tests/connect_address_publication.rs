//! C2.7-B — the broker must publish the CONNECT address it actually bound.
//!
//! `asv run` starts a session shim and has to point it somewhere. If it were
//! told the address by a flag, two sources of truth would exist and they could
//! disagree — and the disagreement is *silent*. The shim would forward every
//! CONNECT to a port where no broker is listening, and the session would simply
//! never tunnel. Nothing would print an error; `curl` would report a
//! connection failure that reads exactly like a network problem.
//!
//! So the broker reports the address, and the property under test is the one
//! that makes that safe: **the address it reports is the one it bound**.
//!
//! ## Why port 0 is the interesting case
//!
//! The listener binds a kernel-chosen port, so the test asks for port 0 — the
//! one request whose answer differs from the string that was passed in. A
//! broker that echoed `--connect-listen 127.0.0.1:0` would satisfy a test that
//! only checked "something was reported", and would send every session to port
//! 0, which is not a thing a client can connect to.
//!
//! The second assertion closes the remaining gap: the reported address must
//! actually accept a TCP connection. An address that parses and has a plausible
//! port is still not proof that anything is listening, and a stale or
//! half-initialised value would parse perfectly.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// Stops the broker when the test ends, however it ends.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Locates a workspace binary through the one locator, which also refuses one
/// older than the sources of the package that produces it.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}
/// Ask the broker to describe itself, over its real socket.
fn agent_info(sock: &std::path::Path) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    let payload = serde_json::to_vec(&asv_ipc_protocol::Request::AgentInfo {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
    })
    .expect("serialize");
    stream.write_all(&payload).expect("write");
    stream.flush().expect("flush");

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read");
    assert!(n > 0, "broker closed without answering AgentInfo");
    serde_json::from_slice(&buf[..n]).expect("parse response")
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    _broker: Broker,
}

impl Fixture {
    /// A broker with a vault and a CONNECT listener on a kernel-chosen port.
    fn with_connect_listener(tag: &str, connect: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-addr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("addr-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");

        VaultStore::create(
            &vault,
            &SecretString::new(value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        let broker = Broker(
            Command::new(cargo_bin("asv-brokerd"))
                .arg(&sock)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&passphrase)
                .arg("--connect-listen")
                .arg(connect)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn asv-brokerd"),
        );

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the broker never created its socket");

        Self {
            dir,
            sock,
            _broker: broker,
        }
    }
}

#[test]
fn the_published_connect_address_is_the_one_that_was_bound() {
    // Port 0: the kernel chooses, so the answer cannot equal the request.
    let f = Fixture::with_connect_listener("bound", "127.0.0.1:0");
    let reported = agent_info(&f.sock);

    let address = reported["connect_listen"]
        .as_str()
        .expect("a broker with a CONNECT listener must report one")
        .to_owned();

    assert_ne!(
        address, "127.0.0.1:0",
        "the broker reported the address it was asked for, not the one it bound"
    );

    let parsed: std::net::SocketAddr = address
        .parse()
        .unwrap_or_else(|e| panic!("the reported address {address:?} does not parse: {e}"));
    assert_ne!(
        parsed.port(),
        0,
        "a reported port of 0 is not connectable; the value is the request echoed back"
    );

    // Parsing and a plausible port are still not proof. Something has to be
    // listening, or every session this address is handed to will fail in a way
    // that reads like a network fault.
    TcpStream::connect_timeout(&parsed, Duration::from_secs(5)).unwrap_or_else(|e| {
        panic!("the broker reported {address}, but nothing accepts there: {e}")
    });

    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn a_broker_with_no_connect_listener_reports_none() {
    // The listener is opt-in. Reporting an address that nothing serves would be
    // worse than reporting none: `asv run` would start a shim that forwards
    // every CONNECT into a closed port, and the session would look broken
    // rather than unconfigured.
    // No `--connect-routes` and, more to the point, no `--connect-listen`:
    // this broker is built by hand because the fixture always passes the flag.
    let dir = std::env::temp_dir().join(format!("asv-addr-none-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the working dir");
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let sock = dir.join("broker.sock");
    let value = "addr-none-passphrase".to_owned();
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    VaultStore::create(
        &vault,
        &SecretString::new(value.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");

    let _broker = Broker(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn asv-brokerd"),
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(sock.exists(), "the broker never created its socket");

    let reported = agent_info(&sock);
    assert!(
        reported["connect_listen"].is_null(),
        "a broker with no CONNECT listener reported {:?}",
        reported["connect_listen"]
    );

    std::fs::remove_dir_all(&dir).ok();
}
