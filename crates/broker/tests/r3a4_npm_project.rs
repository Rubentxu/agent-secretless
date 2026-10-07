//! R3 B2.1 — `asv integrations project npm`, against a broker that is really up.
//!
//! ## Why a separate file
//!
//! The twelve property tests in `asv_integrations::project` all run in one
//! process, and three of them would pass identically if the verb were never
//! wired to a broker at all. What they cannot see is the hop this verb exists
//! to cross: the relay address is not a constant in the source, it is something
//! **the broker published**, and a writer that read the wrong field would
//! produce a `.npmrc` naming a port nothing is listening on. Nothing short of a
//! real `asv-brokerd` answers that question.
//!
//! ## Exactly what this file proves, and what it does not
//!
//! It proves the file gets written, that it names the address the broker
//! actually published, that the surrogate lands in `_authToken`, and that the
//! mode is 0600 — and that a `.npmrc` holding someone else's credential is
//! refused with the original left intact.
//!
//! It does **not** prove that npm reaches a registry through it. That needs a
//! surviving surrogate and a real npm, which is the next hop. Writing the file
//! is not the vertical; pretending the file is the vertical is how this project
//! has twice written down a green that was not one.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_broker::binary::locate;
use asv_domain::CredentialId;
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

const LABEL: &str = "npm-token";
const REGISTRY: &str = "registry.npmjs.org";
const REAL: &str = "npm-the-real-registry-token";

fn cargo_bin(name: &str) -> PathBuf {
    locate(name)
}

struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A broker with a credential in its vault and a published CONNECT listener.
///
/// The listener is bound to `127.0.0.1:0` and the address is read back out of
/// the broker's own self-report rather than assumed, because `bind` still holds
/// the literal `:0` the kernel was asked for and publishing that would hand
/// every caller a port nobody is listening on.
///
/// The route declares `"upstream": "cleartext"`, so no `--connect-roots` is
/// needed and this file tests the projection rather than the TLS anchor
/// decision, which is B5's and is tested elsewhere.
fn broker_with_a_published_relay(dir: &Path) -> (Broker, PathBuf, String) {
    let sock = dir.join("broker.sock");
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let value = "projection-fixture-passphrase";
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    let secret = SecretString::new(value.to_string().into());
    VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");

    let enrolled = Command::new(cargo_bin("asv-brokerd"))
        .arg("--vault")
        .arg(&vault)
        .arg("--enrol-principal")
        .arg(cargo_bin("asv"))
        .output()
        .expect("enrol the CLI as a principal");
    assert!(
        enrolled.status.success(),
        "enrolment failed: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );

    // A planting broker on the stock policy, only to get a credential into the
    // vault and learn the id the route file has to name.
    let plant = Broker(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the planting broker"),
    );
    wait_for(&sock, "the planting broker never created its socket");

    let mut add = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&sock)
        .arg("add-credential")
        .arg("--label")
        .arg(LABEL)
        .arg("--kind")
        .arg("bearer_token")
        .arg("--provider")
        .arg("npm")
        .arg("--account")
        .arg(REGISTRY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run add-credential");
    {
        let mut stdin = add.stdin.take().expect("stdin");
        stdin.write_all(REAL.as_bytes()).expect("write the secret");
        stdin.write_all(b"\n").expect("terminate");
        drop(stdin);
    }
    let added = add.wait_with_output().expect("add-credential finishes");
    assert!(
        added.status.success(),
        "add-credential failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let planted = String::from_utf8_lossy(&added.stdout).into_owned();
    drop(plant);
    let credential = planted
        .split_whitespace()
        .nth(1)
        .filter(|word| word.contains('-'))
        .unwrap_or_else(|| panic!("could not read the minted id from: {planted}"))
        .to_owned();
    assert!(CredentialId::from_wire(&credential).is_ok());
    let _ = std::fs::remove_file(&sock);

    let routes = dir.join("routes.json");
    std::fs::write(
        &routes,
        format!(
            r#"[{{
  "authority": "{REGISTRY}",
  "port": 443,
  "operation_family": "registry",
  "credential": "{credential}",
  "minimum_posture": "STRONG_SECRETLESS",
  "upstream": "cleartext"
}}]"#
        ),
    )
    .expect("write the route file");

    let policy = dir.join("policy.cedar");
    std::fs::write(
        &policy,
        format!(
            r#"permit (principal, action == Action::"connect_route", resource == Host::"host:{REGISTRY}");
"#
        ),
    )
    .expect("write the policy file");

    // The broker's tracing goes to a **file**, not to a pipe. uat_028 measured
    // that an undrained stderr pipe is backpressure: sshd wrote 18 KB per
    // connection into an 8 KB buffer and the process stalled. The same lesson
    // applies to any long-lived process a test spawns.
    let transcript = dir.join("broker.log");
    let log = std::fs::File::create(&transcript).expect("create the transcript");
    let errlog = log.try_clone().expect("clone the transcript handle");

    let broker = Broker(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .arg("--connect-listen")
            .arg("127.0.0.1:0")
            .arg("--connect-routes")
            .arg(&routes)
            .arg("--policy")
            .arg(&policy)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errlog))
            .spawn()
            .expect("spawn the tunnelling broker"),
    );
    wait_for(&sock, "the broker never created its socket");

    let relay = published_relay(&transcript);
    (broker, sock, relay)
}

/// The address the broker says it bound, read out of its own transcript.
///
/// **Not** a convenience: the broker logs `tcp.local_addr()` rather than the
/// string it was asked to bind, and `bind` still holds the literal `:0` the
/// kernel was given. Reading the readback is therefore the whole point — a
/// projection writer that echoed its input would disagree with this line.
///
/// Nothing in the CLI surfaces `connect_listen`: `start_session_shim` consumes
/// it (`main.rs:1311`) and no verb prints it. The transcript is the only place
/// a client can read what the broker published, which is worth knowing and is
/// why this is a comment rather than a silent assumption.
fn published_relay(transcript: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = std::fs::read_to_string(transcript) {
            let plain = strip_ansi(&text);
            if let Some(line) = plain.lines().find(|l| l.contains("CONNECT listener bound")) {
                let token = line
                    .split_whitespace()
                    .find(|word| word.contains("127.0.0.1:"))
                    .unwrap_or_else(|| {
                        panic!("the broker logged a bound line with no address in it: {line}")
                    });
                return token.trim_start_matches("bound=").to_owned();
            }
        }
        assert!(
            Instant::now() < deadline,
            "the broker never logged a bound CONNECT listener. Transcript:\n{}",
            std::fs::read_to_string(transcript).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `tracing` colours its output, so the address in the log is written as
/// `bound=\x1b[1m127.0.0.1:44283\x1b[0m` and does not start with the digits.
/// Stripped rather than pattern-matched around, so the assertion below is
/// about the address and not about how the logger was configured.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c == 'm' {
                break;
            }
        }
    }
    out
}

fn wait_for(sock: &Path, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(sock.exists(), "{message}");
}

fn project(sock: &Path, npmrc: &Path, session: &str, surrogate: &str) -> std::process::Output {
    Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(sock)
        .arg("integrations")
        .arg("project")
        .arg("npm")
        .arg("--audience")
        .arg(REGISTRY)
        .arg("--label")
        .arg(LABEL)
        .arg("--file")
        .arg(npmrc)
        .arg("--json")
        .env("ASV_SESSION_ID", session)
        .env(
            format!("ASV_SURROGATE_{}", LABEL.replace('-', "_").to_uppercase()),
            surrogate,
        )
        .output()
        .expect("run asv integrations project npm")
}

#[test]
fn the_projection_names_the_relay_the_broker_published_and_carries_no_registry_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_broker, sock, relay) = broker_with_a_published_relay(dir.path());
    let npmrc = dir.path().join(".npmrc");
    let surrogate = "asv-surrogate-0123456789abcdef";

    let out = project(&sock, &npmrc, "session-under-test", surrogate);
    assert!(
        out.status.success(),
        "the verb refused to write: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let written = std::fs::read_to_string(&npmrc).expect("the file this verb wrote");
    assert!(
        written.contains(&format!("https-proxy=http://{relay}\n")),
        "the file must name the address the broker published, not one this test guessed: {written}"
    );
    assert!(
        written.contains(&format!("registry=https://{REGISTRY}\n")),
        "{written}"
    );
    assert!(
        written.contains(&format!("//{REGISTRY}/:_authToken={surrogate}\n")),
        "npm refuses an unscoped _authToken outright (ERR_INVALID_AUTH), so writing one here \
         would produce a file npm cannot load: {written}"
    );
    assert!(
        !written.contains(REAL),
        "the registry token reached a file on disk: {written}"
    );

    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&npmrc)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "a world-readable .npmrc is one nobody asked for"
    );
}

#[test]
fn a_second_run_refreshes_its_own_surrogate_rather_than_refusing_its_own_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_broker, sock, relay) = broker_with_a_published_relay(dir.path());
    let npmrc = dir.path().join(".npmrc");

    let first = project(&sock, &npmrc, "session-under-test", "surrogate-one");
    assert!(first.status.success(), "{:?}", first.status);
    let second = project(&sock, &npmrc, "session-under-test", "surrogate-two");
    assert!(
        second.status.success(),
        "the command must be re-runnable: what it wrote last time is itself an auth field, and \
         refusing that would make a good configuration unfixable without deleting it by hand: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let written = std::fs::read_to_string(&npmrc).expect("read back");
    assert!(written.contains(&format!("https-proxy=http://{relay}\n")));
    assert!(
        written.contains(&format!("//{REGISTRY}/:_authToken=surrogate-two\n")),
        "{written}"
    );
    assert!(!written.contains("surrogate-one"), "the stale one is gone");
}

#[test]
fn a_configuration_holding_someone_elses_token_is_refused_and_survives_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_broker, sock, _relay) = broker_with_a_published_relay(dir.path());
    let npmrc = dir.path().join(".npmrc");
    // Scoped, because that is the only spelling npm accepts: an unscoped
    // `_authToken` is refused with ERR_INVALID_AUTH, so no operator's file
    // would ever hold one.
    let original = format!("registry=https://{REGISTRY}\n//{REGISTRY}/:_authToken=the-real-one\n");
    std::fs::write(&npmrc, &original).expect("seed a foreign credential");

    let out = project(&sock, &npmrc, "session-under-test", "surrogate-one");
    assert!(
        !out.status.success(),
        "overwriting a credential this product did not write is the scrub, and §10 puts four \
         gates in front of that"
    );
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("already_carries_credential"), "{said}");
    assert_eq!(
        std::fs::read_to_string(&npmrc).expect("still there"),
        original,
        "a refused write must leave the original byte for byte"
    );
}
