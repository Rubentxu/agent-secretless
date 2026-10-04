//! End-to-end M0 check: a real broker process, a real Unix socket, a real CLI
//! process, and real kernel peer credentials.
//!
//! This is the M0 exit criterion "broker and CLI communicate using kernel peer
//! credentials" exercised through the actual binaries rather than through
//! in-process fakes. Unit tests already cover the handlers; what they cannot
//! cover is the socket, the fd permissions, and the fact that a separate process
//! really is identified from the kernel.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// A broker process that is killed on drop, so a failing test cannot leave a
/// daemon listening on a socket path.
struct BrokerGuard(Child);

impl Drop for BrokerGuard {
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
fn unique_socket(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("asv-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("broker.sock")
}

/// Sends one request and reads one response over the socket.
fn roundtrip(
    sock: &std::path::Path,
    request: &asv_ipc_protocol::Request,
) -> asv_ipc_protocol::Response {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    let payload = serde_json::to_vec(request).expect("serialize");
    stream.write_all(&payload).expect("write request");
    stream.flush().expect("flush");

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read response");
    assert!(n > 0, "broker closed without responding");
    serde_json::from_slice(&buf[..n]).expect("parse response")
}

#[test]
fn cli_and_broker_communicate_over_a_real_socket() {
    let sock = unique_socket("e2e");
    let _ = std::fs::remove_file(&sock);

    let broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn broker"),
    );

    // Wait for the socket to appear rather than sleeping a fixed amount.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker did not create its socket");

    // --- the real CLI process must be able to talk to it -------------------
    let out = Command::new(cargo_bin("asv"))
        .args(["--socket", sock.to_str().unwrap(), "status"])
        .output()
        .expect("run asv status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "asv status failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("broker reachable"),
        "unexpected status output: {stdout}"
    );

    // --- a session created by one process is visible to the next ----------
    let created = roundtrip(
        &sock,
        &asv_ipc_protocol::Request::CreateSession {
            workspace: "/tmp/project".into(),
        },
    );
    let session = match created {
        asv_ipc_protocol::Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    };

    let out = Command::new(cargo_bin("asv"))
        .args(["--socket", sock.to_str().unwrap(), "credentials"])
        .output()
        .expect("run asv credentials");
    assert!(out.status.success(), "credentials listing should succeed");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no credentials stored"),
        "M0 broker should start with an empty vault"
    );

    let ended = roundtrip(&sock, &asv_ipc_protocol::Request::EndSession { session });
    assert_eq!(ended, asv_ipc_protocol::Response::SessionEnded { session });

    let _ = std::fs::remove_file(&sock);
    drop(broker);
}

/// The forbidden method must fail end to end, through a real socket, in a real
/// broker process, not just in the decoder unit test.
#[test]
fn forbidden_method_is_refused_by_a_running_broker() {
    let sock = unique_socket("forbidden");
    let _ = std::fs::remove_file(&sock);

    let broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn broker"),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker did not create its socket");

    let mut stream = UnixStream::connect(&sock).expect("connect");
    stream
        .write_all(br#"{"method":"get_secret"}"#)
        .expect("write hostile frame");
    stream.flush().expect("flush");

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        text.to_lowercase().contains("unknownmethod") || text.to_lowercase().contains("error"),
        "broker should refuse an unknown method, got: {text}"
    );
    assert!(
        !text.contains("secret_value") && !text.contains("ghp_"),
        "a refusal must not echo anything resembling a credential: {text}"
    );

    let _ = std::fs::remove_file(&sock);
    drop(broker);
}

/// The broker must refuse to start on an existing socket rather than hijacking
/// or destroying a running instance (ADR-0002 trust-domain separation).
#[test]
fn broker_refuses_to_hijack_an_existing_socket() {
    let sock = unique_socket("hijack");
    let _ = std::fs::remove_file(&sock);

    let first = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn first broker"),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "first broker did not start");

    let second = Command::new(cargo_bin("asv-brokerd"))
        .arg(&sock)
        .output()
        .expect("run second broker");
    assert!(
        !second.status.success(),
        "a second broker must not take over an existing socket"
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("already exists"),
        "the refusal should say why: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let _ = std::fs::remove_file(&sock);
    drop(first);
}
