//! Ephemeral B1.10 check — the recovery journal is wired into a real brokerd
//! and its startup reconciliation is operator-visible (M13 / UAT-035).
//!
//! Scenario 1 (the crash shape, deterministically): the journal file is seeded
//! with the bytes a killed process would have left — two in-flight intents —
//! and the broker must reconcile BOTH against its loaded inventory at startup
//! (`recovered_journal_intents == 2` on the wire), say so in its own log in
//! operator language, and restart the journal empty.
//!
//! Scenario 2 (no false intents): a clean mutation (a delete refused as
//! "no such credential") exercises the intent-and-clear protocol; after a
//! SIGKILL and a restart the reconciled count is 0, because clean mutations
//! leave no stale intents behind.
//!
//! Torn-write and corrupt-record replay discipline is the module's own and is
//! pinned by UAT-035 (`uat_035_crash_recovery.rs`) plus the parent's unit
//! rows; this check pins the WIRING. Retires with block B1.10 per
//! `docs/plans/b1-delivery-roadmap.md`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn seed_journal(path: &std::path::Path) {
    let mut journal = asv_broker::recovery::RecoveryJournal::new();
    // An added credential the vault does NOT hold: the crash landed between
    // the intent and the write. The reconciliation must say did-not-complete.
    journal
        .append(
            asv_broker::recovery::JournalKind::CredentialAdded,
            b"11111111-2222-4333-8444-555566667777".to_vec(),
        )
        .unwrap();
    // A revoked credential the vault does not hold either: the reconciliation
    // must say the revocation completed. (The vault here is fresh; both ids
    // are absent by construction, which is exactly what the two warn lines
    // below must disagree about.)
    journal
        .append(
            asv_broker::recovery::JournalKind::CredentialRevoked,
            b"99999999-8888-4777-8666-555566667777".to_vec(),
        )
        .unwrap();
    std::fs::write(path, journal.as_bytes()).expect("seed journal");
}

fn request(sock: &std::path::Path, body: serde_json::Value) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    stream
        .write_all(&serde_json::to_vec(&body).expect("serialize request"))
        .expect("send request");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read response");
    assert!(n > 0, "broker closed the connection without responding");
    serde_json::from_slice(&buf[..n]).expect("response is JSON")
}

fn wait_for_socket(sock: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker did not create its socket within 10s");
}

fn spawn_broker(
    brokerd: &std::path::Path,
    sock: &std::path::Path,
    dir: &std::path::Path,
) -> Command {
    let mut cmd = Command::new(brokerd);
    cmd.arg(sock)
        .arg("--vault")
        .arg(dir.join("vault.asv"))
        .arg("--passphrase-file")
        .arg(dir.join("pass.txt"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

#[test]
fn the_journal_is_wired_reconciled_and_operator_visible() {
    let dir = std::env::temp_dir().join(format!("asv-b10-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::write(dir.join("pass.txt"), b"b1-10-journal\n").expect("write pass");
    // A real, empty vault: the seeded intents are both absent from it, which
    // is what makes the two reconciliation lines disagree on purpose.
    let mut store = asv_vault::VaultStore::create(
        &dir.join("vault.asv"),
        &secrecy::SecretString::from("b1-10-journal".to_string()),
        asv_vault::KdfParams::fast_for_tests(),
    )
    .expect("create vault");
    drop(store);

    let journal_path = dir.join("mutations.journal"); // the vault-sibling default
    seed_journal(&journal_path);

    let sock = dir.join("b10.sock");
    let _ = std::fs::remove_file(&sock);

    // --- Scenario 1: startup reconciliation of a crash-shaped journal ---
    let mut broker1 = spawn_broker(&cargo_bin::cargo_bin("asv-brokerd"), &sock, &dir)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn brokerd");
    wait_for_socket(&sock);

    let pong = request(
        &sock,
        serde_json::json!({
            "method": "ping",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
        }),
    );
    assert_eq!(
        pong["recovered_journal_intents"],
        serde_json::json!(2),
        "both seeded intents must be reconciled at startup: {pong}"
    );

    // The journal restarts empty after reconciliation.
    assert!(
        std::fs::read(&journal_path)
            .expect("read journal")
            .is_empty(),
        "reconciled intents must not survive in the journal file"
    );

    // Operator language on the broker's own stdout (tracing goes to stdout).
    broker1.kill().expect("kill broker1");
    let out1 = broker1.wait_with_output().expect("reap broker1");
    let log1 = String::from_utf8_lossy(&out1.stdout).to_string();
    assert!(
        log1.contains("DID NOT COMPLETE"),
        "the interrupted creation must be named for the operator:\n{log1}"
    );
    assert!(
        log1.contains("COMPLETED (the vault no longer holds it)"),
        "the completed revocation must be named for the operator:\n{log1}"
    );

    // --- Scenario 2: clean mutations leave no stale intents ---
    let _ = std::fs::remove_file(&sock);
    let mut broker2 = spawn_broker(&cargo_bin::cargo_bin("asv-brokerd"), &sock, &dir)
        .stdout(Stdio::null())
        .spawn()
        .expect("respawn brokerd");
    wait_for_socket(&sock);

    // A real mutation attempt through the intent-and-clear protocol: this id
    // does not exist, so the vault refuses it — and the journal must still be
    // empty afterwards, because a clean outcome clears its own intent.
    let refused = request(
        &sock,
        serde_json::json!({
            "method": "delete_credential",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
            "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        }),
    );
    assert_eq!(
        refused["result"],
        serde_json::json!("error"),
        "the seeded credential does not exist: {refused}"
    );
    assert!(
        std::fs::read(&journal_path)
            .expect("read journal")
            .is_empty(),
        "a mutation that returned (either way) must clear its own intent"
    );

    // SIGKILL — the crash the journal exists for — and a restart: nothing was
    // in flight, so the reconciled count must be 0, never a phantom intent.
    broker2.kill().expect("kill broker2");
    broker2.wait().expect("reap broker2");
    let _ = std::fs::remove_file(&sock);
    let mut broker3 = spawn_broker(&cargo_bin::cargo_bin("asv-brokerd"), &sock, &dir)
        .stdout(Stdio::null())
        .spawn()
        .expect("respawn brokerd after kill");
    wait_for_socket(&sock);
    let pong = request(
        &sock,
        serde_json::json!({
            "method": "ping",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
        }),
    );
    assert_eq!(
        pong["recovered_journal_intents"],
        serde_json::json!(0),
        "clean mutations must leave no intents to reconcile: {pong}"
    );

    broker3.kill().expect("kill broker3");
    broker3.wait().ok();
    std::fs::remove_dir_all(&dir).ok();
}

mod cargo_bin {
    /// Same resolution the `cargo_bin!` macro performs, without adding a
    /// dependency: artifacts live in the target profile directory next to
    /// this test binary's own `deps` folder.
    pub fn cargo_bin(name: &str) -> std::path::PathBuf {
        let mut path = std::env::current_exe().expect("current exe");
        while path.file_name().is_some() {
            path = path.parent().map(|p| p.to_path_buf()).unwrap_or(path);
            if path.file_name().is_some_and(|f| f == "deps") {
                break;
            }
        }
        let profile = path.parent().expect("profile dir");
        let candidate = profile.join(name);
        assert!(
            candidate.exists(),
            "{name} not found at {} — build it first (cargo build -p asv-broker)",
            candidate.display()
        );
        candidate
    }
}
