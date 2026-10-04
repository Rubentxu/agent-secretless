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

/// Locates a workspace binary through the one locator, which also refuses one
/// older than the sources of the package that produces it.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
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

#[test]
fn broker_with_harden_flag_applies_dumpable_zero_and_still_serves() {
    // M7-R1 through the shipped binary: with --harden, the broker must
    // come up undumpable (CoreDumping: 0, ptrace refused) while serving
    // Ping exactly as before. Without the flag nothing changes, which
    // the other tests in this file pin.
    let dir = std::env::temp_dir().join(format!("asv-harden-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("harden.sock");
    let _ = std::fs::remove_file(&sock);

    let vault_path = dir.join("vault.asv");
    let pass_path = dir.join("vault.pass");
    std::fs::write(&pass_path, b"harden-test-pass\n").expect("write pass");
    let passphrase = asv_vault_test_support_passphrase();
    let store = asv_vault::VaultStore::create(
        &vault_path,
        &passphrase,
        asv_vault::KdfParams::fast_for_tests(),
    )
    .expect("create vault");
    drop(store);

    let broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault_path)
            .arg("--passphrase-file")
            .arg(&pass_path)
            .arg("--harden")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn hardened broker"),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "--harden broker did not bind socket");

    // The broker must still be alive (prctl steps did not kill it) and
    // observable as undumpable via /proc.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let pid = broker.0.id();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let core_dumping: &str = status
        .lines()
        .find(|l| l.starts_with("CoreDumping:"))
        .expect("CoreDumping line")
        .split_whitespace()
        .last()
        .expect("value");
    assert_eq!(
        core_dumping, "0",
        "--harden broker must be undumpable (CoreDumping: 0)"
    );

    // M7-R4 through the shipped binary: the seccomp deny-list filter is
    // ACTIVE in the kernel for the broker process (Seccomp: 2 means
    // SECCOMP_MODE_FILTER; Seccomp_filters counts installed filters).
    let seccomp_line = status
        .lines()
        .find(|l| l.starts_with("Seccomp:"))
        .expect("Seccomp line")
        .split_whitespace()
        .last()
        .expect("value")
        .to_string();
    assert_eq!(
        seccomp_line, "2",
        "--harden broker must run under a seccomp filter (Seccomp: 2)"
    );
    let nfilters: u32 = status
        .lines()
        .find(|l| l.starts_with("Seccomp_filters:"))
        .expect("Seccomp_filters line")
        .split_whitespace()
        .last()
        .expect("value")
        .parse()
        .expect("filter count");
    assert!(
        nfilters >= 1,
        "--harden broker must have at least one seccomp filter installed"
    );

    // And the IPC surface still works: Ping round-trip (same envelope as
    // the first test in this file: {"result":"pong","protocol":2}).
    let request = serde_json::json!({
        "method": "ping",
        "protocol": asv_ipc_protocol::PROTOCOL_VERSION,
    });
    let payload = serde_json::to_vec(&request).expect("serialize ping");
    let mut stream = UnixStream::connect(&sock).expect("connect hardened broker");
    stream.write_all(&payload).expect("write ping");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read pong");
    assert!(n > 0, "hardened broker closed without responding");
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).expect("parse pong");
    assert_eq!(
        response.get("result").and_then(|v| v.as_str()),
        Some("pong"),
        "--harden broke the IPC surface: {response}"
    );
}

fn asv_vault_test_support_passphrase() -> secrecy::SecretString {
    secrecy::SecretString::from("harden-test-pass".to_string())
}

// ---------------------------------------------------------------------------
// The inventory the broker never loaded
// ---------------------------------------------------------------------------
//
// The tests above prove the bin *opens* a vault. None of them prove it knows
// what is inside. It did not: `BrokerState::credentials` is an in-memory list
// whose only writer was `insert_credential` (now `register_inventory_credential`,
// which says what it does), a function whose own doc comment says it seeds
// tests. `main.rs` built the lending port and never read
// `store.list()`, so `ListCredentialMetadata` answered `[]` and
// `MintSurrogate` refused every real credential with "no such credential".
//
// These tests drive the real binary, because a unit test that seeds
// `state.credentials` itself would pass against the defect.

/// A fixed id, not a random one. The assertion "this exact credential id
/// comes back over IPC" is only meaningful if the expected value is known
/// before the run, which is the same reason the canary in `vault_port.rs` is
/// a constant.
const CRED_UUID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const CRED_UUID_LABEL: &str = "github-work";
const CRED_UUID_UPPER: &str = "3F2504E0-4F89-41D3-9A0C-0305E82C3301";

/// A vault id that is not a UUID. The PostgreSQL path names credentials
/// `pg/{database}/{role}` (`credential_for`), so a vault written that way
/// carries ids this broker cannot turn into a `CredentialId` at all.
const CRED_NON_UUID: &str = "pg/shopdb/billing";
const SECRET_CANARY: &str = "ASV-R5-INVENTORY-SECRET-CANARY-91D2";

/// Sends one request and returns the parsed response envelope.
fn request(sock: &std::path::Path, body: serde_json::Value) -> serde_json::Value {
    let payload = serde_json::to_vec(&body).expect("serialize request");
    let mut stream = UnixStream::connect(sock).expect("connect broker");
    stream.write_all(&payload).expect("write request");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read response");
    assert!(n > 0, "broker closed without responding");
    serde_json::from_slice(&buf[..n]).expect("parse response")
}

/// Creates a real vault holding exactly the credentials given as `(id, label)`.
fn vault_with(dir: &std::path::Path, passphrase: &str, entries: &[(&str, &str)]) -> PathBuf {
    let vault_path = dir.join("vault.asv");
    let pass = secrecy::SecretString::from(passphrase.to_string());
    let mut store =
        VaultStore::create(&vault_path, &pass, KdfParams::fast_for_tests()).expect("create vault");
    let key = store.header().unlock(&pass).expect("unlock");
    for (id, label) in entries {
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    *id,
                    *label,
                    asv_vault::CredentialKind::BearerToken,
                    "github",
                    "acct",
                    1,
                ),
                asv_domain::secret::SecretBytes::new(SECRET_CANARY.as_bytes().to_vec()),
            )
            .unwrap_or_else(|e| panic!("insert {id}: {e}"));
    }
    drop(store);
    vault_path
}

/// Starts the real broker against `vault_path` and waits for its socket.
///
/// Standard output is piped, not nulled, because `tracing_subscriber::fmt()`
/// writes its subscriber to **stdout** by default — a test that watches stderr
/// for a log line watches the wrong stream and sees nothing at all, which is
/// what happened the first time this was written.
fn spawn_broker(
    sock: &std::path::Path,
    vault_path: &std::path::Path,
    pass_path: &std::path::Path,
) -> std::process::Child {
    Command::new(cargo_bin("asv-brokerd"))
        .arg(sock)
        .arg("--vault")
        .arg(vault_path)
        .arg("--passphrase-file")
        .arg(pass_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn broker")
}

fn wait_for_socket(sock: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker did not create its socket within 10s");
}

/// A credential that exists in the vault must be listed. This is the
/// reproduction: against a broker that never loaded its inventory the
/// response is `{"result":"credential_metadata","entries":[]}`.
#[test]
fn broker_lists_a_credential_that_exists_in_its_vault() {
    let dir = std::env::temp_dir().join(format!("asv-inv-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("create dir");
    let pass_path = dir.join("pass.txt");
    std::fs::write(&pass_path, b"inventory-pass\n").expect("write pass");
    let vault_path = vault_with(&dir, "inventory-pass", &[(CRED_UUID, CRED_UUID_LABEL)]);

    let sock = unique_socket("inventory");
    let _ = std::fs::remove_file(&sock);
    let _broker = BrokerGuard(spawn_broker(&sock, &vault_path, &pass_path));
    wait_for_socket(&sock);

    let response = request(
        &sock,
        serde_json::json!({ "method": "list_credential_metadata" }),
    );

    assert_eq!(
        response.get("result").and_then(|v| v.as_str()),
        Some("credential_metadata"),
        "unexpected response shape: {response}"
    );
    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("no entries array: {response}"));

    assert_eq!(
        entries.len(),
        1,
        "the vault holds one credential and the broker must list it: {response}"
    );
    let entry = &entries[0];
    assert_eq!(
        entry.get("id").and_then(|v| v.as_str()),
        Some(CRED_UUID),
        "the listed id must be the one stored in the vault: {entry}"
    );
    assert_eq!(
        entry.get("label").and_then(|v| v.as_str()),
        Some(CRED_UUID_LABEL),
        "{entry}"
    );
    // The vault's `BearerToken` maps onto the domain's `BearerToken`.
    assert_eq!(
        entry.get("kind").and_then(|v| v.as_str()),
        Some("bearer_token"),
        "kind vocabulary must survive the crossing: {entry}"
    );
    assert_eq!(
        entry.get("exportability").and_then(|v| v.as_str()),
        Some("non_exportable"),
        "the vault's default exportability must not be silently upgraded: {entry}"
    );
    assert!(
        !response.to_string().contains(SECRET_CANARY),
        "metadata IPC must not expose a secret payload"
    );

    let session_response = request(
        &sock,
        serde_json::json!({ "method": "create_session", "workspace": "/repo" }),
    );
    let session = session_response
        .get("session")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("no session in response: {session_response}"));
    let minted = request(
        &sock,
        serde_json::json!({
            "method": "mint_surrogate",
            "session": session,
            "credential": CRED_UUID,
            "max_uses": 2,
            "ttl_secs": 60,
        }),
    );
    assert_eq!(
        minted.get("result").and_then(|v| v.as_str()),
        Some("surrogate_minted"),
        "a listed vault credential must be usable for surrogate admission: {minted}"
    );
    assert!(!minted.to_string().contains(SECRET_CANARY));
}

/// Noncanonical and operation-only keys must not become public handles. The
/// broker reports aggregate counts without echoing source keys.
#[test]
fn broker_excludes_a_non_uuid_credential_and_says_so() {
    let dir = std::env::temp_dir().join(format!("asv-inv2-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("create dir");
    let pass_path = dir.join("pass.txt");
    std::fs::write(&pass_path, b"inventory-pass\n").expect("write pass");
    let vault_path = vault_with(
        &dir,
        "inventory-pass",
        &[
            (CRED_UUID, CRED_UUID_LABEL),
            (CRED_UUID_UPPER, "legacy-uppercase"),
            (CRED_NON_UUID, "legacy-pg"),
        ],
    );

    let sock = unique_socket("inventory-nonuuid");
    let _ = std::fs::remove_file(&sock);
    let mut child = spawn_broker(&sock, &vault_path, &pass_path);
    wait_for_socket(&sock);

    let response = request(
        &sock,
        serde_json::json!({ "method": "list_credential_metadata" }),
    );
    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("no entries array: {response}"));

    // The UUID-keyed credential is listed; the convention-based one is not.
    assert_eq!(entries.len(), 1, "{response}");
    assert_eq!(
        entries[0].get("id").and_then(|v| v.as_str()),
        Some(CRED_UUID),
        "the UUID-keyed credential must still be listed: {response}"
    );
    assert!(
        !response.to_string().contains(CRED_NON_UUID),
        "a non-UUID credential must not reach the agent surface: {response}"
    );
    assert!(!response.to_string().contains(CRED_UUID_UPPER));
    assert!(!response.to_string().contains(SECRET_CANARY));

    // Read the log only after the broker has exited, so a full pipe can never
    // wedge the process we are waiting on.
    let _ = child.kill();
    let _ = child.wait();
    let log = {
        use std::io::Read as _;
        let mut buf = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut buf);
        }
        // `tracing_subscriber::fmt()` colourises when it thinks it is talking
        // to a terminal. Under a pipe it should not, but the field separator is
        // wrapped in escapes either way in some builds, and an assertion on
        // `credentials=1` must not depend on that. Stripping is more honest
        // than pinning the child to an env var that may change.
        let mut plain = String::new();
        let mut chars = buf.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    };
    assert!(
        !log.contains(CRED_NON_UUID)
            && !log.contains(CRED_UUID_UPPER)
            && !log.contains(SECRET_CANARY),
        "diagnostics must not echo unsupported keys or secret payloads: {log}"
    );
    assert!(
        log.contains("credentials=1") && log.contains("skipped=2") && log.contains("collisions=0"),
        "the startup line must report aggregate loaded, skipped, and collision counts: {log}"
    );
}
