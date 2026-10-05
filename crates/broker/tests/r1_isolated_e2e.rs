//! R1 — the exit gate, driven through the real binaries.
//!
//! `r1_isolated_reachability.rs` proves the operation works when the request is
//! handed to the broker in-process. This file proves the other half: that an
//! operator can start a broker, declare a worker in a file, and have
//! `asv run-isolated` come back with what the isolated child printed.
//!
//!     asv run-isolated            the product surface
//!         -> unix socket          versioned IPC, protocol 8
//!         -> asv-brokerd          session, pidfd, registry from --workers
//!         -> worker::spawn        namespaces, landlock, seccomp
//!         -> /bin/echo            a real child
//!         -> [REDACTED] posture   a typed answer, labelled
//!
//! Nothing in this file reaches into the broker's types. It starts a process
//! and runs a command, which is the only way to observe the part that matters:
//! that the chain a user would actually walk is the chain that was built.
//!
//! # The negative is the load-bearing half
//!
//! `a_broker_declared_no_workers_runs_nothing` starts a broker with no
//! `--workers` and asks for the same worker. If the positive row passed because
//! the broker ignored the file and ran something else, this row would pass too
//! — it is what makes the first row mean "the file was read".

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}

struct Broker(std::process::Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn userns_available() -> bool {
    std::process::Command::new("unshare")
        .args(["-Ur", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Refuse the host that cannot run these rows, loudly.
///
/// These rows used to `eprintln!` and `return`, which Cargo reports as
/// **passed**. A row that examined nothing and a row that passed were
/// indistinguishable in the output, which is the same failure as the one R1
/// was reopened for: a claim nothing measured.
///
/// The distinction that matters: `unshare -Ur` failing is **`UNAVAILABLE
/// SUBSTRATE`**, a host that cannot run the row. A row that runs and fails is
/// **`FAIL`**. Neither is `PASS`, and the full gate keeps them apart on
/// purpose. A release requirement that cannot run is not a pass.
fn require_userns(row: &str) {
    if !userns_available() {
        panic!(
            "UNAVAILABLE_SUBSTRATE: {row} needs unprivileged user namespaces, which \
             this host does not provide. Reported as a failure rather than a \
             return, because a return is reported as a pass."
        );
    }
}

/// A temp directory that cleans itself, so a failing row leaves a readable
/// message rather than a pile.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(base).join(format!("asv-r1-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    Scratch(dir)
}

/// Prepares a vault and enrols the CLI, the same ordering the CONNECT vertical
/// uses: enrolment writes to the vault and the broker reads that record at
/// startup, so enrolling a running broker is the ordering mistake this comment
/// exists to prevent.
fn vault_and_principal(dir: &Path) -> (PathBuf, PathBuf) {
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("pass");
    let value = format!("r1-e2e-passphrase-{}", std::process::id());
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    let secret = SecretString::new(value.into());
    VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");

    let enrolled = Command::new(cargo_bin("asv-brokerd"))
        .arg("--vault")
        .arg(&vault)
        .arg("--enrol-principal")
        .arg(cargo_bin("asv"))
        .output()
        .expect("enrol the CLI");
    assert!(
        enrolled.status.success(),
        "enrolment failed: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    (vault, passphrase)
}

fn start_broker(
    dir: &Path,
    vault: &Path,
    passphrase: &Path,
    workers: Option<&Path>,
) -> (Broker, PathBuf) {
    let sock = dir.join("broker.sock");
    let mut command = Command::new(cargo_bin("asv-brokerd"));
    command
        .arg(&sock)
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-file")
        .arg(passphrase);
    if let Some(file) = workers {
        command.arg("--workers").arg(file);
    }
    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the broker");

    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(sock.exists(), "the broker never created its socket");
    (Broker(child), sock)
}

fn run_isolated(sock: &Path, worker: &str, args: &[&str]) -> std::process::Output {
    Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(sock)
        .arg("run-isolated")
        .arg(worker)
        .arg("--")
        .args(args)
        .output()
        .expect("run asv run-isolated")
}

/// The exit row. An operator wrote a worker into a file, the broker read it,
/// and the isolated child's output came back through the product's own command.
#[test]
fn an_operator_declared_worker_runs_and_answers_through_the_cli() {
    require_userns("an_operator_declared_worker_runs_and_answers_through_the_cli");
    let dir = scratch("declared");
    let (vault, passphrase) = vault_and_principal(&dir.0);

    let workers = dir.0.join("workers.json");
    std::fs::write(
        &workers,
        r#"{"worker":[
              {"name":"echoer","binary":"/bin/echo","egress":"deny","seccomp":"closed"}
            ]}"#,
    )
    .expect("write the workers file");

    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&workers));

    let out = run_isolated(&sock, "echoer", &["hello-from-the-cli"]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "asv run-isolated failed: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("hello-from-the-cli"),
        "the isolated child's output did not come back: {stdout:?}"
    );
    // The posture travels on the same line as the result, because a caller
    // reading only the output of a run that touched a credential has no other
    // way to learn it was on the weaker path.
    assert!(
        stdout.contains("ISOLATED_PROCESS_EXPOSURE"),
        "the run did not name its posture: {stdout:?}"
    );
}

/// The negative that gives the row above its meaning.
#[test]
fn a_broker_declared_no_workers_runs_nothing() {
    let dir = scratch("empty");
    let (vault, passphrase) = vault_and_principal(&dir.0);
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, None);

    let out = run_isolated(&sock, "echoer", &["should-not-run"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "a broker with no workers file must run nothing, and it answered: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("echoer"),
        "the refusal names what was refused: {stderr:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("should-not-run"),
        "nothing was executed"
    );
}

/// A worker the file does not declare is refused by name.
#[test]
fn a_worker_the_file_does_not_declare_is_refused() {
    require_userns("a_worker_the_file_does_not_declare_is_refused");
    let dir = scratch("undeclared");
    let (vault, passphrase) = vault_and_principal(&dir.0);
    let workers = dir.0.join("workers.json");
    std::fs::write(
        &workers,
        r#"{"worker":[{"name":"echoer","binary":"/bin/echo"}]}"#,
    )
    .expect("write the workers file");
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&workers));

    let out = run_isolated(&sock, "not-declared", &[]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "an undeclared worker must not run");
    assert!(
        stderr.contains("not-declared"),
        "the refusal names the worker: {stderr:?}"
    );
}

/// A broker that cannot read its workers file does not start.
///
/// Fail-closed at the door, because the alternative is a broker that runs with
/// the subset of declarations that happened to parse — an authority the
/// operator did not write.
#[test]
fn a_broker_whose_workers_file_is_unreadable_does_not_start() {
    let dir = scratch("unreadable");
    let (vault, passphrase) = vault_and_principal(&dir.0);
    let bad = dir.0.join("workers.json");
    std::fs::write(&bad, "{ this is not a workers file").expect("write the broken file");

    let out = Command::new(cargo_bin("asv-brokerd"))
        .arg(dir.0.join("broker.sock"))
        .arg("--vault")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--workers")
        .arg(&bad)
        .output()
        .expect("run the broker");

    assert!(
        !out.status.success(),
        "a broker with an unreadable workers file must not start"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("workers file rejected"),
        "the refusal says what was wrong: {stderr:?}"
    );
    assert!(
        !dir.0.join("broker.sock").exists(),
        "and it left no socket behind"
    );
}

/// A file that asks for an egress the runtime refuses on every call is refused
/// at the file, not at the call. The operator should not have to discover this
/// by running their worker.
#[test]
fn a_file_asking_for_unenforceable_egress_is_refused_at_the_file() {
    let dir = scratch("egress");
    let (vault, passphrase) = vault_and_principal(&dir.0);
    let bad = dir.0.join("workers.json");
    std::fs::write(
        &bad,
        r#"{"worker":[{"name":"chatty","binary":"/bin/echo","egress":"allow"}]}"#,
    )
    .expect("write the file");

    let out = Command::new(cargo_bin("asv-brokerd"))
        .arg(dir.0.join("broker.sock"))
        .arg("--vault")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--workers")
        .arg(&bad)
        .output()
        .expect("run the broker");

    assert!(!out.status.success(), "the file must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("egress"),
        "the refusal names the offending key: {stderr:?}"
    );
}

/// A misspelled key is an error, not a default.
///
/// A file with `seccomp: "close"` must not quietly get the production profile
/// by way of an unrecognised field: the operator wrote something and the
/// broker decided what it meant.
#[test]
fn a_misspelled_key_is_refused_rather_than_defaulted() {
    let dir = scratch("typo");
    let (vault, passphrase) = vault_and_principal(&dir.0);
    let bad = dir.0.join("workers.json");
    std::fs::write(
        &bad,
        r#"{"worker":[{"name":"echoer","binary":"/bin/echo","seccomp_profile":"closed"}]}"#,
    )
    .expect("write the file");

    let out = Command::new(cargo_bin("asv-brokerd"))
        .arg(dir.0.join("broker.sock"))
        .arg("--vault")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--workers")
        .arg(&bad)
        .output()
        .expect("run the broker");

    assert!(
        !out.status.success(),
        "an unrecognised key must not be silently dropped"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("workers file rejected"),
        "the refusal says the file was rejected: {stderr:?}"
    );
}
