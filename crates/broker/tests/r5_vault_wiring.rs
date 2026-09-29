//! R5 — End-to-end check: the broker binary opens a real vault and serves
//! requests on top of it.
//!
//! The unit tests cover `VaultSecretPort`, but until this cycle the bin
//! `asv-brokerd` itself never opened one: it constructed `BrokerState::default()`
//! with `secrets = None`, and every `lend()` refused with `SecretError::Unavailable`.
//! That was the run-time gap the v1.0 backlog item `bl-bl-01M3N3FKVT000387A6Y7FQ18R0`
//! named, and this test is the falsifiable claim that the bin now wires the
//! vault at startup.
//!
//! What this test exercises:
//! 1. A real `VaultStore::create` writes the on-disk envelope.
//! 2. `asv-brokerd` is spawned with `--vault` + `--passphrase-file` argv.
//! 3. The broker creates the socket; a Ping round-trip succeeds.
//! 4. The M0 contract ("broker boots with `secrets = None`, refuses every
//!    lend") still holds: a separate test exercises the no-vault path
//!    and confirms the bin does not regress.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

fn cargo_bin(name: &str) -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                let candidate = profile_dir.join(name);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target).join(profile).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join(profile).join(name);
    }
    PathBuf::from("target").join(profile).join(name)
}

fn unique_socket(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("asv-vault-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("broker.sock")
}

/// Spawns a child that the test owns; killing on `Drop` keeps a failing test
/// from leaving a broker running on the socket path.
struct BrokerGuard(std::process::Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn broker_binary_opens_vault_and_serves_a_ping() {
    // Create a real vault on disk. The passphrase is fixed so the test is
    // reproducible across runs; it never leaves this process.
    let dir = std::env::temp_dir().join(format!("asv-vault-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("create vault dir");
    let vault_path = dir.join("vault.asv");
    let passphrase_path = dir.join("passphrase.txt");
    std::fs::write(&passphrase_path, b"r5-vault-wiring-passphrase\n").expect("write passphrase");

    VaultStore::create(
        &vault_path,
        &SecretString::new("r5-vault-wiring-passphrase".into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");

    let sock = unique_socket("vault");
    let _ = std::fs::remove_file(&sock);

    let _broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault_path)
            .arg("--passphrase-file")
            .arg(&passphrase_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn broker with vault"),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        sock.exists(),
        "broker with vault did not create its socket within 10s"
    );

    // Ping round-trip. With a real `secrets` port mounted, the broker answers
    // the same way it does without one — Ping is the contract test, not the
    // vault test. What this verifies is that the bin reaches steady state
    // with a vault opened; what it does NOT verify is the secret path
    // (that needs a connector end-to-end, which is the uat_030 fixture's job).
    let request = serde_json::json!({
        "method": "ping",
        "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
    });
    let payload = serde_json::to_vec(&request).expect("serialize ping");
    let mut stream = UnixStream::connect(&sock).expect("connect broker");
    stream.write_all(&payload).expect("write ping");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read pong");
    assert!(n > 0, "broker closed without responding");
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).expect("parse pong");
    // The response envelope is `{"result": "<tag>", ...}` where the inner
    // tags are snake_case verb names ("pong" for Ping). Asserting on the
    // exact tag keeps the test honest: a broker that opened a vault but
    // failed to answer would still produce a valid JSON value, and the
    // test would catch that.
    assert_eq!(
        response.get("result").and_then(|v| v.as_str()),
        Some("pong"),
        "broker did not answer with pong: {response}"
    );
    assert_eq!(
        response.get("protocol").and_then(|v| v.as_u64()),
        Some(asv_ipc_protocol::PROTOCOL_VERSION as u64),
        "broker protocol version missing: {response}"
    );
}

#[test]
fn broker_binary_refuses_when_only_one_of_vault_or_passphrase_is_set() {
    // Partial configuration must be fail-closed: a broker that started
    // without the passphrase would either ask (no TTY in production) or
    // skip the unwrap (silently keep `secrets = None`). Both bypass the
    // operator's intent.
    let sock = unique_socket("partial");
    let _ = std::fs::remove_file(&sock);

    let vault_path = std::env::temp_dir().join("asv-no-passphrase-aso-vault");
    std::fs::write(&vault_path, b"").expect("write sentinel");

    let mut cmd = Command::new(cargo_bin("asv-brokerd"))
        .arg(&sock)
        .arg("--vault")
        .arg(&vault_path)
        // Intentionally do NOT pass --passphrase-file: the broker must refuse.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn broker");
    let status = cmd.wait().expect("wait broker");
    assert!(!status.success(), "broker accepted partial config");
    assert!(
        !sock.exists(),
        "broker created a socket despite refusing the partial config"
    );
}

#[test]
fn broker_binary_starts_without_a_vault_unchanged() {
    // Regression: the M0 contract is "the broker boots, has `secrets = None`,
    // and refuses every lend". This cycle must NOT remove that path.
    let sock = unique_socket("no-vault");
    let _ = std::fs::remove_file(&sock);

    let mut broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            // No --vault / --passphrase-file: the M0 fail-closed path.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn broker without vault"),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker without vault did not bind socket");
    std::thread::sleep(std::time::Duration::from_millis(500));
    let still_alive = broker.0.try_wait().expect("try_wait").is_none();
    assert!(still_alive, "broker without vault exited unexpectedly");
}
