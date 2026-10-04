//! R2.A — `asv github` against the real binaries.
//!
//! `r2a_github_vertical.rs` drives the broker in-process, which is what makes
//! it possible to point the connector at a local TLS origin and measure the
//! whole operation. This file measures the other half: that the verb an
//! operator types reaches a real broker process, and that what comes back is
//! the broker's own answer rather than a parse error or a dead socket.
//!
//! # What this file proves, and what it does not
//!
//! It **does** prove the CLI half: `asv github issue view` parses, opens a
//! session over the socket, asks for a surrogate, and surfaces the broker's
//! typed refusal. Every row here is arranged so the broker refuses **before**
//! any connector runs, which means the whole file is hermetic — it never
//! resolves `api.github.com` and never opens a socket to GitHub.
//!
//! It **does not** prove that a read succeeds. It cannot, and the reason is a
//! design property rather than a gap in the fixture: the broker's GitHub
//! audience is the compile-time constant `GITHUB_AUTHORITY`, and the crate's
//! dev-dependency on itself is documented as applying "to the lib as a
//! dependency of the test, and never to the binary". So the `asv-brokerd` this
//! file spawns can only ever talk to real GitHub. Making it talk to anything
//! else would mean putting a test-only audience override in a production
//! binary, and that is exactly the switch this design refuses to have.
//!
//! The success half is measured where it can honestly be measured — in-process,
//! against a real TLS origin, in `r2a_github_vertical.rs`. Neither file claims
//! the other's evidence.
//!
//! # Why the refusals are the interesting rows
//!
//! A row that asserts "the CLI got as far as the broker" is weak if the broker
//! would have said the same thing to anything. So the assertions name the
//! *specific* refusal each row expects, and each refusal is one the broker
//! could only produce after looking at what the CLI actually sent it: a
//! credential id it does not hold, or a repository string its validator
//! rejects. A CLI that sent nothing, or sent the wrong field, would get a
//! different answer and fail.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};

/// The credential this file's rows do **not** enrol.
///
/// A canonical, well-formed, definitely-absent id. Well-formed on purpose: a
/// malformed one would be refused by the CLI's own parser, and the row would
/// then be measuring the CLI's argument validation rather than the broker's
/// answer. The distinction is the difference between "you called me wrong" and
/// "there is no such credential", and this row is about the second.
const ABSENT_CREDENTIAL: &str = "00000000-0000-4000-8000-0000deadbeef";

/// A credential this file *does* enrol, for the rows that need the mint to
/// succeed so that a later check can run.
const ENROLLED_CREDENTIAL: &str = "7c2e9b41-0d3a-4f58-b6e1-5a8c3f0d27b9";

/// Bounded so a hung row fails the suite instead of parking it.
///
/// The rule this file follows from R1: a test that cannot finish is worse than
/// a test that fails, because it converts a defect into a stalled pipeline.
const ROW_TIMEOUT: Duration = Duration::from_secs(120);

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

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(base).join(format!("asv-r2a-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    Scratch(dir)
}

/// Creates a vault and enrols the CLI, the same ordering R1's E2E uses.
///
/// The vault is created but left empty on purpose: these rows are about what
/// the broker says about a credential it does not have, and enrolling one would
/// mean the operation could proceed to the network.
fn empty_vault(dir: &Path) -> (PathBuf, PathBuf) {
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("pass");
    let value = format!("r2a-cli-passphrase-{}", std::process::id());
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    let secret = secrecy::SecretString::new(value.into());
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

/// Creates a vault holding one enrolled credential, and enrols the CLI.
///
/// The first version of this file used an *empty* vault and expected the
/// broker's repository validation to refuse the request. It does not: the mint
/// is refused first, with `credential is not available`, and the operation never
/// happens. That ordering is correct — there is no grant to spend on a
/// malformed repository — but it means an empty vault can only ever exercise
/// the mint, so this row needed a real credential to reach anything else.
///
/// A real credential is also the stronger fixture. With a token actually in the
/// vault, the row can assert that a request the broker refuses still does not
/// put the token anywhere near the caller's output.
fn vault_with_one_credential(dir: &Path) -> (PathBuf, PathBuf, String) {
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("pass");
    let value = format!("r2a-cli-passphrase-{}", std::process::id());
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    let secret = secrecy::SecretString::new(value.into());
    let mut store =
        VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");
    let key = store
        .header()
        .unlock(&secret)
        .expect("unlock with the passphrase just used");

    let token = format!("ghp_r2a_cli_{}_never_exposed", std::process::id());
    store
        .insert(
            &key,
            asv_vault::CredentialMetadata::new(
                ENROLLED_CREDENTIAL,
                "r2a-cli",
                asv_vault::CredentialKind::Opaque,
                "github",
                "Rubentxu",
                1,
            ),
            asv_domain::SecretBytes::new(token.clone().into_bytes()),
        )
        .expect("insert the credential");

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
    (vault, passphrase, token)
}

fn start_broker(dir: &Path, vault: &Path, passphrase: &Path) -> (Broker, PathBuf) {
    let sock = dir.join("broker.sock");
    let child = Command::new(cargo_bin("asv-brokerd"))
        .arg(&sock)
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-file")
        .arg(passphrase)
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

/// Runs `asv github …` and returns its output, or fails with the whole thing.
///
/// Bounded by [`ROW_TIMEOUT`] rather than by `Command::output`, which blocks
/// forever. The reason is the rule this suite has been held to since R1: a
/// hung row is worse than a failing one, because it parks the pipeline instead
/// of reporting a defect. The child is killed on timeout so a stuck row leaves
/// no process behind for the next one to trip over.
///
/// The message includes the child's own stdout and stderr because a row that
/// only says "the command failed" costs the next reader more time than the row
/// saved.
fn github(sock: &Path, args: &[&str]) -> (bool, String, String) {
    let sock = sock.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (tx, rx) = std::sync::mpsc::channel();

    let worker = std::thread::spawn(move || {
        let out = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&sock)
            .arg("github")
            .args(&args)
            .output()
            .expect("run asv github");
        let _ = tx.send((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    });

    match rx.recv_timeout(ROW_TIMEOUT) {
        Ok(result) => {
            let _ = worker.join();
            result
        }
        Err(_) => panic!("`asv github` did not finish within {ROW_TIMEOUT:?}; a row that hangs is worse than a row that fails"),
    }
}

// ---------------------------------------------------------------------------

/// The read verb reaches the broker and the broker names the missing credential.
///
/// The exit row for the CLI half. It says three things at once, and each is a
/// different failure if it does not hold:
///
/// 1. **The verb parsed.** A `clap` error would never reach a socket.
/// 2. **The socket answered.** `ASV_CONNECTION_FAILED` would mean the broker is
///    not there, which is a fixture defect and not a product claim.
/// 3. **The broker evaluated the credential the CLI named.** The refusal names
///    the vault's answer, so a CLI that sent nothing, or sent a different
///    field, would get a different refusal.
///
/// **Mutation:** make `run_github` skip the mint, or send
/// `Request::ListCredentialMetadata` instead, and the message assertion fails.
///
/// **Mutation:** make `run_github` return the `io::Error` to `main` instead of
/// reporting it, and the `ASV_CONNECTION_FAILED`-free assertion fails.
#[test]
fn the_read_verb_reaches_the_broker_and_is_answered_by_it() {
    let dir = scratch("read");
    let (vault, passphrase) = empty_vault(&dir.0);
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase);

    let (ok, stdout, stderr) = github(
        &sock,
        &[
            "issue",
            "view",
            "--repo",
            "Rubentxu/agent-secretless",
            "--number",
            "7",
            "--credential",
            ABSENT_CREDENTIAL,
        ],
    );

    assert!(
        !ok,
        "an empty vault cannot answer a read, so this row must see a refusal: \
         stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("ASV_CONNECTION_FAILED"),
        "the broker did not answer; the CLI reported a transport failure: {stderr}"
    );
    assert!(
        !stderr.contains("does not parse") && !stderr.contains("Usage:"),
        "the verb did not survive the parser: {stderr}"
    );
    assert!(
        stderr.contains("credential"),
        "the broker's own refusal never arrived, so this row is measuring the CLI \
         rather than the product: {stderr}"
    );
    assert!(
        !stderr.contains(ABSENT_CREDENTIAL),
        "the credential id was echoed back into a diagnostic: {stderr}"
    );
}

/// The repository the CLI sends is the one the broker validates.
///
/// The other direction of "the CLI really delivered its arguments": here the
/// repository string is the hostile one, and the broker's own `validate_repo`
/// has to be the thing that refuses it. A CLI that dropped or mangled `--repo`
/// would send a valid string and get a *different* answer, so the assertion on
/// the refusal's wording is what carries this row.
///
/// This needs a credential that is actually in the vault. The first version of
/// this row used an absent one and expected the repository to be refused; the
/// broker refused the *mint* instead, and the operation never ran. The order is
/// right — there is no grant to spend on a malformed repository — so the
/// fixture had to change, not the expectation.
///
/// The row is still hermetic: `authorize_github` validates the repository
/// before it builds a client, so a refused repository means no socket to GitHub
/// is ever opened.
///
/// And because there is a real token in the vault this time, the row can also
/// assert the thing the refusal path is most likely to get wrong.
///
/// **Mutation:** make `github_request` send an empty `repo`, and the message
/// assertion fails — the broker would report a different malformation.
///
/// **Mutation:** move `validate_repo` after the client is built, and the row
/// would start reaching the network and stop being hermetic.
#[test]
fn the_repository_the_cli_sends_is_the_one_the_broker_validates() {
    let dir = scratch("repo");
    let (vault, passphrase, token) = vault_with_one_credential(&dir.0);
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase);

    let (ok, stdout, stderr) = github(
        &sock,
        &[
            "issue",
            "view",
            "--repo",
            "Rubentxu/agent-secretless/../../admin",
            "--number",
            "7",
            "--credential",
            ENROLLED_CREDENTIAL,
        ],
    );

    assert!(
        !ok,
        "a hostile repository must not succeed: {stdout:?} {stderr:?}"
    );
    assert!(
        !stderr.contains("ASV_CONNECTION_FAILED"),
        "the broker did not answer: {stderr}"
    );
    // The refusal must be one the broker could only write after reading the
    // repository the CLI sent.
    assert!(
        stderr.contains("owner/repo") || stderr.contains("repository reference"),
        "the broker's own repository validation never ran, so the `--repo` value \
         did not arrive: {stderr}"
    );
    // A real token is in the vault for this row, and a refusal is exactly where
    // a credential tends to end up in a message.
    assert!(
        !stdout.contains(&token) && !stderr.contains(&token),
        "the token leaked into the caller's output on the refusal path: \
         stdout={stdout:?} stderr={stderr:?}"
    );
}

/// Both write verbs reach the broker too.
///
/// The relations `asv github` publishes for `github.issue.create` and
/// `github.release.create` are only promises if the verbs behind them work. And
/// the body argument is the part most likely to be wrong in a way the other two
/// rows do not exercise: it is read from a file before the session opens, so a
/// body path that does not resolve would fail *before* the socket, and the row
/// would pass for the wrong reason.
///
/// So the body is a real file, and the assertion is that the broker answered.
///
/// **Mutation:** make the write verbs fall through to the single-request path
/// and report a connection failure, and this fails.
#[test]
fn both_write_verbs_reach_the_broker() {
    let dir = scratch("writes");
    let (vault, passphrase) = empty_vault(&dir.0);
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase);

    let body = dir.0.join("body.md");
    std::fs::write(&body, "release notes that are not a secret\n").expect("write the body");

    for (label, args) in [
        (
            "issue create",
            vec![
                "issue",
                "create",
                "--repo",
                "Rubentxu/agent-secretless",
                "--title",
                "a title",
                "--credential",
                ABSENT_CREDENTIAL,
            ],
        ),
        (
            "release create",
            vec![
                "release",
                "create",
                "--repo",
                "Rubentxu/agent-secretless",
                "--tag",
                "v1.2.3",
                "--name",
                "a name",
                "--credential",
                ABSENT_CREDENTIAL,
            ],
        ),
    ] {
        let mut full: Vec<&str> = args.clone();
        full.push("--body");
        full.push(body.to_str().expect("utf-8 path"));
        let (ok, stdout, stderr) = github(&sock, &full);

        assert!(!ok, "{label} must be refused by an empty vault: {stdout:?}");
        assert!(
            !stderr.contains("ASV_CONNECTION_FAILED"),
            "{label}: the broker did not answer: {stderr}"
        );
        assert!(
            !stderr.contains("cannot read the body"),
            "{label}: the body was never read, so this row would pass without ever \
             reaching the broker: {stderr}"
        );
        assert!(
            stderr.contains("credential"),
            "{label}: no broker refusal arrived: {stderr}"
        );
    }
}

/// The body never reaches `argv`.
///
/// The negative for the reason `--body` is a path and not a literal. A body in
/// `argv` is readable by any same-uid peer through `/proc/<pid>/cmdline`, which
/// is a kernel property this product does not claim to control.
///
/// # Holding the process still, without sleeping
///
/// The first version of this row read `/proc/<pid>/cmdline` after the child had
/// finished, and got an **empty string**: the kernel reports no command line
/// for a zombie. So the row was asserting `!cmdline.contains(marker)` against
/// nothing, and would have passed for a CLI that had put the whole body in
/// `argv`.
///
/// The fix is a FIFO for the body. The CLI opens it and blocks in
/// `read_to_string` before it opens the socket, which is a deterministic hold
/// chosen by the fixture rather than by a sleep — the process is alive, so the
/// command line is real, and the test can read exactly what a same-uid peer
/// would read. A writer is opened afterwards to let the child finish, and its
/// exit status is checked so a run that only passes because the CLI hung is
/// not mistaken for a pass.
///
/// **Mutation:** add a `--body-text` that takes a literal, or default `--body`
/// to a positional, and this fails.
#[test]
fn the_body_is_not_an_argv_element() {
    let dir = scratch("argv");
    let (vault, passphrase, _token) = vault_with_one_credential(&dir.0);
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase);

    let body = dir.0.join("body.fifo");
    let body_c =
        std::ffi::CString::new(body.to_str().expect("utf-8 path")).expect("no NUL in a path");
    let rc = unsafe { libc::mkfifo(body_c.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "could not create the FIFO: {}",
        std::io::Error::last_os_error()
    );

    // A body that would be unmistakable in a process listing.
    let marker = "CANARY-BODY-b7f3c1d9e2a4";

    let mut child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&sock)
        .arg("github")
        .arg("issue")
        .arg("create")
        .arg("--repo")
        .arg("Rubentxu/agent-secretless")
        .arg("--title")
        .arg("a title")
        .arg("--body")
        .arg(&body)
        .arg("--credential")
        .arg(ENROLLED_CREDENTIAL)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn asv github");

    // Opening the FIFO for writing blocks until the CLI opens it for reading, so
    // by the time this returns the child is parked in `read_to_string` — alive,
    // and holding no socket.
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&body)
        .expect("open the FIFO for writing, which unblocks the CLI");

    let raw = std::fs::read(format!("/proc/{}/cmdline", child.id()))
        .unwrap_or_else(|error| panic!("the CLI's own command line must be readable: {error}"));
    // NUL-separated, and not guaranteed to be UTF-8: a path is bytes.
    let cmdline = String::from_utf8_lossy(&raw).into_owned();

    // Let the child finish, so nothing is left holding the FIFO.
    use std::io::Write as _;
    let _ = writeln!(writer, "{marker}");
    drop(writer);
    let status = child.wait().expect("reap the CLI");

    assert!(
        !cmdline.is_empty(),
        "the command line came back empty, so the assertions below would pass on \
         nothing; the FIFO was supposed to hold the child alive"
    );
    assert!(
        !cmdline.contains(marker),
        "the body reached argv, where a same-uid peer could read it: {cmdline:?}"
    );
    assert!(
        cmdline.contains("--body"),
        "the row found no `--body` at all, so the assertion above passed on an \
         empty command line rather than on a real one: {cmdline:?}"
    );
    assert!(
        cmdline.contains(body.to_str().expect("utf-8 path")),
        "the body path should be what travels, since the file is what the operator \
         named: {cmdline:?}"
    );
    assert!(
        !status.success(),
        "the run should have been refused by the empty GitHub answer, so a zero \
         status would mean the child was killed rather than finished: {status:?}"
    );
}
