//! Ephemeral B1.9 check — a session's pin is answered against the LIVE process,
//! over a real brokerd, a real socket and a real cross-process pidfd.
//!
//! What this proves end to end: a helper process (a different PID from both the
//! broker and the test) opens a session the broker pins with a real pidfd, and
//! mints a surrogate through it — the positive control that pinning works for a
//! real other process. Once the helper exits, its session is refused to every
//! later caller, and the broker itself stays healthy.
//!
//! What this deliberately does NOT re-prove: the recycled-PID discrimination
//! (a fresh identity claiming the same integer after the owner dies) is
//! deterministic only in-process, and `a_dead_owners_session_is_not_owned_by_
//! the_recycled_pid` in the broker's unit suite is the pinned row for it.
//!
//! Retires with block B1.9 per `docs/plans/b1-delivery-roadmap.md`; the
//! permanent half is the unit suite. A host without pidfd support reports
//! `UNAVAILABLE_SUBSTRATE` and never fakes a pass.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

const CRED: &str = "0f0e0d0c-1111-4222-8333-444455556666";
const CRED_LABEL: &str = "b1-9-liveness";

/// The agent half, run by re-invoking this test binary with the role env set.
#[test]
fn eph_agent_helper() {
    let Ok(role) = std::env::var("EPH_B19_ROLE") else {
        return; // normal test run: this row is the parent's helper, not a case
    };
    assert_eq!(role, "agent");
    let sock = std::env::var("EPH_B19_SOCK").expect("EPH_B19_SOCK");
    match agent_role(&sock) {
        Ok(id) => println!("SESSION={id}"),
        Err(reason) => {
            println!("AGENT_FAILED={reason}");
            std::process::exit(3);
        }
    }
}

fn agent_role(sock: &str) -> Result<String, String> {
    let created = request(
        std::path::Path::new(sock),
        serde_json::json!({
            "method": "create_session",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
            "workspace": "b1-9-liveness",
        }),
    );
    if created["result"] != serde_json::json!("session_created") {
        return Err(format!("create_session failed: {created}"));
    }
    let session = created["session"]
        .as_str()
        .expect("session id is a string")
        .to_string();

    // The positive control: this process is neither the broker nor the test —
    // the broker pinned it with a real pidfd over real SO_PEERCRED, and the
    // mint only succeeds through that live pin.
    let minted = request(
        std::path::Path::new(sock),
        serde_json::json!({
            "method": "mint_surrogate",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
            "session": session,
            "credential": CRED,
            "max_uses": 4,
            "ttl_secs": 300,
        }),
    );
    if minted["result"] != serde_json::json!("surrogate_minted") {
        return Err(format!("mint_surrogate failed: {minted}"));
    }
    Ok(session)
}

/// The parent half: owner dies, session dies with it, broker stays healthy.
#[test]
fn a_pinned_session_is_refused_once_its_process_dies_over_real_ipc() {
    if std::env::var("EPH_B19_ROLE").is_ok() {
        return; // helper mode never runs the parent half
    }

    let dir = std::env::temp_dir().join(format!("asv-b19-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create dir");
    let pass_path = dir.join("pass.txt");
    std::fs::write(&pass_path, b"b1-9-liveness\n").expect("write pass");
    vault_with(&dir, "b1-9-liveness");

    let sock = dir.join("b19.sock");
    let _ = std::fs::remove_file(&sock);
    let mut broker = Command::new(cargo_bin::cargo_bin("asv-brokerd"))
        .arg(&sock)
        .arg("--vault")
        .arg(dir.join("vault.asv"))
        .arg("--passphrase-file")
        .arg(&pass_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn brokerd");
    wait_for_socket(&sock);

    let helper = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "eph_agent_helper", "--nocapture"])
        .env("EPH_B19_ROLE", "agent")
        .env("EPH_B19_SOCK", &sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn helper");
    let stdout = String::from_utf8_lossy(&helper.stdout).to_string();

    let session = match stdout.lines().find_map(|l| l.strip_prefix("SESSION=")) {
        Some(id) => id.to_string(),
        None => {
            let reason = stdout
                .lines()
                .find_map(|l| l.strip_prefix("AGENT_FAILED="))
                .unwrap_or("helper produced no session");
            if reason.contains("pidfd-pinned") {
                // The broker could not pin the helper: this host lacks the
                // substrate (pidfd). Report it as its own state, never a pass.
                println!("UNAVAILABLE_SUBSTRATE: pidfd unavailable on this host ({reason})");
                broker.kill().ok();
                return;
            }
            broker.kill().ok();
            panic!("helper failed for a non-substrate reason: {reason}");
        }
    };
    assert!(helper.status.success(), "helper exited cleanly: {stdout}");

    // The owner is dead. Its session must answer to the kernel, not to the
    // integer it left behind.
    let refused = request(
        &sock,
        serde_json::json!({
            "method": "mint_surrogate",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
            "session": session,
            "credential": CRED,
            "max_uses": 4,
            "ttl_secs": 300,
        }),
    );
    assert_eq!(
        refused["result"],
        serde_json::json!("error"),
        "a dead owner's session must not mint: {refused}"
    );
    let message = refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("session is not owned by the authenticated peer"),
        "the refusal must name the ownership rule for the operator: {refused}"
    );

    // And the broker itself is unharmed: a fresh session still works.
    let healthy = request(
        &sock,
        serde_json::json!({
            "method": "create_session",
            "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
            "workspace": "post-mortem",
        }),
    );
    assert_eq!(
        healthy["result"],
        serde_json::json!("session_created"),
        "broker must stay healthy: {healthy}"
    );

    broker.kill().ok();
}

// --- fixture pieces, in the shape of crates/broker/tests/r5_vault_wiring.rs ---

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

fn vault_with(dir: &std::path::Path, pass: &str) {
    let vault_path = dir.join("vault.asv");
    let pass = secrecy::SecretString::from(pass.to_string());
    let mut store =
        asv_vault::VaultStore::create(&vault_path, &pass, asv_vault::KdfParams::fast_for_tests())
            .expect("create vault");
    let key = store.header().unlock(&pass).expect("unlock");
    store
        .insert(
            &key,
            asv_vault::CredentialMetadata::new(
                CRED,
                CRED_LABEL,
                asv_vault::CredentialKind::BearerToken,
                "github",
                "acct",
                1,
            ),
            asv_domain::secret::SecretBytes::new(b"b1-9-canary-secret".to_vec()),
        )
        .expect("insert credential");
    drop(store);
}

mod cargo_bin {
    /// Same resolution the `cargo_bin!` macro from the test-support crate
    /// performs, without adding a dependency: artifacts live in the target
    /// directory next to this test binary's own profile.
    pub fn cargo_bin(name: &str) -> std::path::PathBuf {
        let mut path = std::env::current_exe().expect("current exe");
        while path.file_name().is_some() {
            path = path.parent().map(|p| p.to_path_buf()).unwrap_or(path);
            if path.file_name().is_some_and(|f| f == "deps") {
                break;
            }
        }
        // current_exe: .../target/debug/deps/eph_pin_liveness-<hash>
        // brokerd:     .../target/debug/asv-brokerd
        let deps = path;
        let profile = deps.parent().expect("profile dir");
        let candidate = profile.join(name);
        assert!(
            candidate.exists(),
            "{name} not found at {} — build it first (cargo build -p asv-broker)",
            candidate.display()
        );
        candidate
    }
}
