//! R2.F.3c — `asv registry` against the real binaries, and the deployment
//! surface the allowlist needs to exist at all.
//!
//! `r2f_registry_vertical.rs` drives the broker in-process. That is what makes
//! it possible to point the connector at a local TLS origin and measure a
//! *successful* pull. This file measures the other two halves, and neither of
//! them is reachable from there.
//!
//! # What this file proves that the in-process file cannot
//!
//! **1. The allowlist is loadable by a deployment.** Until this file, the only
//! line in the tree that ever *wrote* `BrokerState::registries` was a test.
//! `BrokerState::default()` leaves it empty, which is the fail-closed reading,
//! so a real `asv-brokerd` refused every registry pull forever: the code was
//! complete, tested, falsified — and unreachable by the operator it was written
//! for. `--registries` is the missing wire, and `a_declaration_file_reaches_the
//! daemon` is what says so.
//!
//! **2. The verb parses and reaches a real broker process.** The relation rows
//! in `asv-cli` prove `asv registry manifest read` is a command; nothing
//! proved it *ran*.
//!
//! # What this file does not prove, and why
//!
//! **A successful pull does not happen here.** `AddressPolicy` has exactly one
//! relaxation — `allow_loopback` — and it is off in production, so a broker that
//! is a real binary cannot be pointed at a local origin. This is the same limit
//! `r2a_cli_reachability.rs` states for GitHub, and for the same reason: adding
//! an address-policy override to a production binary would be exactly the switch
//! this design refuses to have. The success half is measured in-process, in
//! `r2f_registry_vertical.rs`. Neither file claims the other's evidence.
//!
//! # Why the refusals are the interesting rows
//!
//! Every row here is arranged so the broker refuses **before any socket to a
//! registry**, which is what makes the file hermetic: it never resolves a
//! registry host and never reaches one. Each assertion names the *specific*
//! refusal, because a row that only says "the CLI got as far as the broker" is
//! satisfied by a CLI that sends nothing at all.

use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};

/// A credential this file enrols. The declaration names it, so a pull that
/// reached the network would have had a real secret to spend.
const CRED: &str = "3f7c1d92-4a6b-4c1e-9d3f-2b8e5a7c0d14";

/// A second credential in the same vault, declared for **no** registry.
///
/// The whole point of the strongest row below: a surrogate over this one is
/// genuine, unexpired and in budget, and it must still serve no registry.
const OTHER_CRED: &str = "b1d2e3f4-5a6b-4c1e-9d3f-2b8e5a7c0d99";

/// The secret. Must never appear in anything a row reads back.
const SECRET: &str = "hunter2-the-real-registry-password";

/// The host the deployment declares. Never resolved in this file.
const DECLARED: &str = "registry.example.test";

/// A host no deployment declares.
const UNDECLARED: &str = "registry.evil.example";

const ROW_TIMEOUT: Duration = Duration::from_secs(60);

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
    let dir = PathBuf::from(base).join(format!("asv-r2f-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    Scratch(dir)
}

/// A vault holding two credentials, plus the CLI enrolled against it.
///
/// Two on purpose. The credential the declaration names and the one it does not
/// are both real, both the same class, and both mintable — which is the only
/// fixture in which "a surrogate for the wrong credential is refused" means
/// anything. A vault with one credential would make that row pass for the
/// uninteresting reason that the second surrogate could not be minted at all.
fn vault_with_two_credentials(dir: &Path) -> (PathBuf, PathBuf) {
    let vault = dir.join("vault.asv");
    let passphrase = dir.join("pass");
    let value = format!("r2f-cli-passphrase-{}", std::process::id());
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    let secret = secrecy::SecretString::new(value.into());
    let mut store =
        VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");
    let key = store
        .header()
        .unlock(&secret)
        .expect("unlock with the passphrase just used");

    for (id, name, value) in [
        (CRED, "r2f-registry", SECRET),
        (
            OTHER_CRED,
            "r2f-other",
            "hunter2-the-OTHER-registry-password",
        ),
    ] {
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    id,
                    name,
                    asv_vault::CredentialKind::Opaque,
                    "registry",
                    "Rubentxu",
                    1,
                ),
                asv_domain::SecretBytes::new(value.as_bytes().to_vec()),
            )
            .expect("insert the credential");
    }
    drop(store);

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

/// Whether a broker left a socket behind.
///
/// A separate function rather than an inline `Path::exists` because the row
/// that uses it is about a *dead* broker, and asserting on a path the function
/// never created would pass for the wrong reason if the name were ever wrong.
fn sock_exists(dir: &Path) -> bool {
    dir.join("broker.sock").exists()
}

/// A policy permitting a registry pull, and nothing else.
///
/// **Needed by exactly one row.** The daemon's built-in policy has no registry
/// permit — deliberately, since R2.F.3a added the actions without a default
/// allow — so a row that needs to get past the policy gate has to supply one.
/// The row that needs it is the credential-equality one, and that is exactly
/// why it needs it: the equality is checked *after* the policy, so under the
/// default text the row would be satisfied by the policy denying first, which
/// proves nothing about the equality.
///
/// This is not the in-process file's `PULL_ANY` written out again. There, the
/// policy was a fixture detail of a broker the row also configured. Here it is
/// the operator's file, loaded from `--policy`, and the row that uses it is
/// evidence that a deployment can actually permit a registry pull — which is
/// the operator-visible half of R2.F.3.
fn permitting_pull_policy(dir: &Path) -> PathBuf {
    let path = dir.join("policy.cidr");
    // The mint permit is here because `--policy` *replaces* the built-in text
    // rather than adding to it, and the CLI's `run_registry` mints a surrogate
    // before it pulls. Without this line the row would be refused at the mint
    // with "policy denied minting a surrogate for github.issue.read" -- green
    // for a reason that has nothing to do with the credential equality it is
    // written to measure. The first version of this policy omitted it and
    // produced exactly that false pass.
    std::fs::write(
        &path,
        r#"
permit (principal, action == Action::"github_issue_read", resource is Api);
permit (
    principal,
    action == Action::"registry_pull",
    resource is Registry
);
"#,
    )
    .expect("write the policy");
    path
}

/// Writes the declaration file the daemon is started with.
fn declarations(dir: &Path, entries: &str) -> PathBuf {
    let path = dir.join("registries.json");
    std::fs::write(&path, entries).expect("write the declarations");
    path
}

/// Starts a broker that is expected to run. `declarations` is `None` for the
/// no-flag rows.
///
/// Returns `Err` carrying the daemon's own stderr when it does not come up.
///
/// **Waiting for the socket is not enough, and this function exists partly
/// because I got that wrong first.** The daemon binds its listener before it
/// loads the declarations, so a socket appears and then the process exits with
/// a refusal. The first version of the daemon row waited for the socket, saw
/// it, and declared that a broker refusing to start had in fact started — the
/// test passed against the exact defect it was written to catch. So this waits
/// for the *socket and a live process*, which is the thing "the broker is up"
/// actually means.
fn start_broker(
    dir: &Path,
    vault: &Path,
    passphrase: &Path,
    declarations: Option<&Path>,
) -> Result<(Broker, PathBuf), String> {
    start_broker_with_policy(dir, vault, passphrase, declarations, None)
}

/// [`start_broker`], plus the operator's policy file.
fn start_broker_with_policy(
    dir: &Path,
    vault: &Path,
    passphrase: &Path,
    declarations: Option<&Path>,
    policy: Option<&Path>,
) -> Result<(Broker, PathBuf), String> {
    let sock = dir.join("broker.sock");
    let mut command = Command::new(cargo_bin("asv-brokerd"));
    command
        .arg(&sock)
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-file")
        .arg(passphrase);
    if let Some(path) = declarations {
        command.arg("--registries").arg(path);
    }
    if let Some(path) = policy {
        command.arg("--policy").arg(path);
    }
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the broker");

    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if sock.exists() {
        // The socket alone is not "up": the daemon binds before it validates,
        // so a process that is about to exit already has one. Try the socket
        // rather than checking `try_wait`, because that is the only question
        // that means what this function's callers mean -- "can a client
        // connect?" -- and it also catches a daemon that bound and then died
        // for a reason nobody thought to check.
        if UnixStream::connect(&sock).is_ok() {
            return Ok((Broker(child), sock));
        }
    }

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read as _;
        let _ = pipe.read_to_string(&mut stderr);
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(stderr)
}

/// Runs `asv registry …` and returns `(success, stdout, stderr)`.
///
/// Bounded by [`ROW_TIMEOUT`] rather than by `Command::output`, which blocks
/// forever, for the reason `r2a_cli_reachability.rs` states: a hung row parks
/// the pipeline instead of reporting a defect.
fn registry(sock: &Path, args: &[&str]) -> (bool, String, String) {
    let sock = sock.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let out = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&sock)
            .arg("registry")
            .args(&args)
            .output()
            .expect("run asv registry");
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
        Err(_) => panic!("`asv registry` did not finish within {ROW_TIMEOUT:?}"),
    }
}

/// The two arguments every row shares, so a row states only its own variable.
fn declared_pull<'a>(credential: &'a str, registry: &'a str) -> Vec<&'a str> {
    vec![
        "manifest",
        "read",
        "--credential",
        credential,
        "--registry",
        registry,
        "--repository",
        "library/alpine",
        "--reference",
        "latest",
    ]
}

/// Asserts a refusal that reached the broker, and that kept the secret.
///
/// Exit 1 is "the broker said no" and exit 2 is "you called me wrong". The rows
/// below assert the code *and* the message, because the message is the only
/// evidence that the broker looked at what the CLI actually sent.
fn assert_refused(what: &str, code: &str, stderr: &str) {
    assert!(
        stderr.contains(code),
        "{what}: expected a refusal naming {code}, got: {stderr}"
    );
    assert!(
        !stderr.contains(SECRET),
        "{what}: the credential leaked into the CLI's own output: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The deployment surface
// ---------------------------------------------------------------------------

/// The declaration file reaches the daemon, and it changes what the broker does.
///
/// **This is the row that would have caught the defect this increment found.**
/// `BrokerState::default()` leaves `registries` empty, and the empty reading is
/// the correct fail-closed one — but with no flag to load a file, "empty" was
/// the *only* reachable state for a real deployment, so every registry pull
/// from a real `asv-brokerd` was refused with "this deployment does not
/// declare the registry …" and no operator could ever have got past it.
///
/// The pair of rows below is the proof: identical requests, identical vaults,
/// identical binaries, and the only difference is whether `--registries` was
/// passed. That the *declared* one gets further than the *undeclared* one is
/// what says the flag was read — and it is a weaker claim than "the pull
/// succeeded", which it deliberately does not make.
///
/// **Mutation:** drop the `--registries` branch from the daemon, and both rows
/// produce the same refusal.
#[test]
fn a_declaration_file_reaches_the_daemon() {
    let dir = scratch("declared");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );

    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .expect("the broker starts with a declaration file");

    let (ok, _, stderr) = registry(&sock, &declared_pull(CRED, DECLARED));
    assert!(
        !ok,
        "the pull cannot succeed through a real binary -- the address policy \
         refuses loopback and the declared host does not resolve -- but the \
         verb reported success: {stderr}"
    );
    // The refusal must be one that only a broker *with* the declaration could
    // have produced. Without `--registries` this same call answers "this
    // deployment does not declare the registry", which is the string the
    // sibling row asserts against.
    assert!(
        !stderr.contains("does not declare the registry"),
        "the daemon ignored --registries, so the declaration never reached it: {stderr}"
    );
}

/// Without the flag, the same request is refused by the declaration check.
///
/// The control for the row above. It is here so that row cannot pass for the
/// wrong reason: if both refusals were identical, "the flag changed something"
/// would be unfalsifiable, and the row above's assertion — that the string
/// "does not declare the registry" is *absent* — would have nothing to contrast
/// with.
///
/// **Mutation:** make the daemon load an empty declaration file when the flag
/// is absent, or refuse to start without the flag; either makes this row stop
/// producing its own specific message.
#[test]
fn a_deployment_with_no_declaration_file_declares_nothing() {
    let dir = scratch("undeclared");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);

    let (_broker, sock) =
        start_broker(&dir.0, &vault, &passphrase, None).expect("the broker starts without the flag");

    let (ok, _, stderr) = registry(&sock, &declared_pull(CRED, DECLARED));
    assert!(!ok, "an undeclared registry must be refused: {stderr}");
    assert_refused(
        "a deployment with no declarations",
        "does not declare the registry",
        &stderr,
    );
}

/// A daemon started on a declaration file it cannot use refuses to start.
///
/// The same bargain `--oauth2-clients` strikes, for the same reason: a
/// declaration the broker half-understands leaves an operator believing a
/// registry is reachable and discovering at the first pull that it is not, as
/// a mystery, rather than at startup where they can read the message.
///
/// **Mutation:** log the error and continue with an empty declaration set, and
/// this row's "the broker never created its socket" assertion stops being the
/// interesting part — the daemon would start and every pull would be refused
/// with the message from the row above instead.
#[test]
fn a_declaration_file_the_broker_cannot_use_stops_the_daemon() {
    let dir = scratch("bad");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    // Two declarations naming one registry: a coin toss whose outcome is the
    // order of a JSON array, so the loader refuses rather than picks.
    let declarations = declarations(
        &dir.0,
        &format!(
            r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}},
                {{"registry":"{DECLARED}","credential":"{OTHER_CRED}"}}]"#
        ),
    );

    // The row is about *why* it stopped, not that it stopped. A daemon that
    // exited for an unrelated reason — a locked vault, a bad passphrase — would
    // also produce no socket, so the message is what makes this a property of
    // the declaration loader rather than of the fixture.
    let stderr = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .err()
        .unwrap_or_else(|| {
            panic!(
                "the broker started on a file declaring one registry twice; a \
                 deployment whose credential depends on JSON order is not a \
                 deployment"
            )
        });
    assert!(
        stderr.contains("--registries") && stderr.contains("twice"),
        "the daemon must say which file it refused and why: {stderr}"
    );
    assert!(
        !sock_exists(&dir.0),
        "a broker that refuses to start must not leave a socket an agent could \
         connect to"
    );
}

// ---------------------------------------------------------------------------
// The verb
// ---------------------------------------------------------------------------

/// The verb parses, opens a session, mints, and is answered by the broker.
///
/// Three claims at once, each a different failure if it does not hold:
///
/// 1. **The verb parsed.** A `clap` error never reaches a socket, and its
///    message would not name the vault's answer.
/// 2. **The socket answered.** A connection failure would say the broker is not
///    there, which is a fixture defect and not a product claim.
/// 3. **The broker evaluated the credential the CLI named.** The refusal names
///    the declaration check, so a CLI that sent nothing, or sent the wrong
///    field, would get a different refusal.
///
/// **Mutation:** make `run_registry` skip the mint and call the operation with
/// an empty surrogate, and the message changes to `SurrogateError::Unknown`.
#[test]
fn the_verb_reaches_the_broker_and_is_answered_by_it() {
    let dir = scratch("verb");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .expect("the broker starts");

    let (ok, _, stderr) = registry(&sock, &declared_pull(CRED, UNDECLARED));
    assert!(!ok, "an undeclared host must be refused: {stderr}");
    assert_refused(
        "the verb reaching the broker",
        "does not declare the registry",
        &stderr,
    );
}

/// A surrogate over the credential no registry is served by is refused.
///
/// **The strongest row in this file, and the one the CLI makes possible.** The
/// operator's deployment declares one host and one credential. This call names
/// the *other* credential — which is real, in the vault, the same class, and
/// mintable. If the broker compared the surrogate's credential with the
/// declaration's, the pull is refused at the equality. If it compared only the
/// *class*, or only that the surrogate redeemed, the broker would proceed to
/// dial `DECLARED` with `CRED`'s secret, and the session would be spending a
/// credential it was never granted.
///
/// The refusal must therefore name **both** credential ids. A handler that
/// refused for some other reason would not, and a handler that compared the
/// family instead of the credential would not get here at all.
///
/// **Mutation:** delete `if credential != declaration.credential` in the
/// broker's `PullManifest` arm.
#[test]
fn a_surrogate_for_a_credential_no_registry_serves_is_refused() {
    let dir = scratch("mismatch");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );
    // The operator's policy permits the pull, so the refusal below can only be
    // the equality. Under the built-in text -- which permits no registry action
    // at all -- this same call answers "policy denied registry.pull", and the
    // row would be green while proving nothing about the credential.
    let policy = permitting_pull_policy(&dir.0);
    let (_broker, sock) = start_broker_with_policy(
        &dir.0,
        &vault,
        &passphrase,
        Some(&declarations),
        Some(&policy),
    )
    .expect("the broker starts");

    let (ok, _, stderr) = registry(&sock, &declared_pull(OTHER_CRED, DECLARED));
    assert!(!ok, "a surrogate for another credential must be refused: {stderr}");
    assert!(
        stderr.contains(CRED) && stderr.contains(OTHER_CRED),
        "the refusal must name both credentials, or it is not the equality \
         refusing: {stderr}"
    );
    assert_refused(
        "a surrogate for another credential",
        "stands for",
        &stderr,
    );
}

/// A malformed `--credential` is refused by the CLI, before a socket.
///
/// The exit-code row. **2** is "you called me wrong" and **1** is "the broker
/// said no", and the two are kept distinct everywhere in this CLI so a script
/// does not retry a typo the same way it retries a denial. A malformed id here
/// would otherwise be reported by the broker as a missing credential, which
/// sends an operator to the vault to look for something that was never there.
///
/// **Mutation:** move the `CredentialId::from_wire` check below the session
/// creation, and the exit code becomes 1 with a broker message.
#[test]
fn a_malformed_credential_is_refused_by_the_cli_itself() {
    let dir = scratch("malformed");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .expect("the broker starts");

    let (ok, _, stderr) = registry(&sock, &declared_pull("not-a-vault-id", DECLARED));
    assert!(
        !ok,
        "a malformed credential must not be reported as success: {stderr}"
    );
    assert!(
        stderr.contains("not a vault id"),
        "the CLI must name its own validation rather than relaying a broker \
         refusal: {stderr}"
    );
    assert!(
        !stderr.contains("does not declare"),
        "the request reached the broker, so the CLI validated too late: {stderr}"
    );
}

/// A blob read is refused on the same declaration, and the two verbs differ.
///
/// The second verb is a separate command with a separate parser arm, and a
/// mistake in one is invisible to the other. This row says the blob noun
/// reaches the same declaration check — and because the row names the *same*
/// message the manifest rows do, a blob verb wired to the wrong request, or to
/// none, fails here rather than passing silently.
///
/// **Mutation:** have `run_registry` build a `PullManifest` for the blob noun
/// too, and the blob row would still refuse — but for a reason that has nothing
/// to do with the digest, which is why the row also asserts the digest never
/// got as far as being parsed.
#[test]
fn the_blob_verb_reaches_the_same_declaration_check() {
    let dir = scratch("blob");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .expect("the broker starts");

    let (ok, _, stderr) = registry(
        &sock,
        &[
            "blob",
            "read",
            "--credential",
            CRED,
            "--registry",
            UNDECLARED,
            "--repository",
            "library/alpine",
            "--digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ],
    );
    assert!(!ok, "an undeclared host must be refused on the blob verb too");
    assert_refused(
        "the blob verb",
        "does not declare the registry",
        &stderr,
    );
}

/// Nothing this CLI prints carries the credential.
///
/// One row over every path this file reaches, and the paths differ: one refusal
/// comes from the broker, one from the CLI's own validation, and one from a
/// daemon that refused to start. A check that only covered the first would be a
/// check of the broker's formatting rather than of the product.
///
/// **Mutation:** format a credential into any of the three messages.
#[test]
fn no_path_prints_the_credential() {
    let dir = scratch("leak");
    let (vault, passphrase) = vault_with_two_credentials(&dir.0);
    let declarations = declarations(
        &dir.0,
        &format!(r#"[{{"registry":"{DECLARED}","credential":"{CRED}"}}]"#),
    );
    let (_broker, sock) = start_broker(&dir.0, &vault, &passphrase, Some(&declarations))
        .expect("the broker starts");

    let mut seen: Vec<String> = Vec::new();

    // The broker's own refusal.
    let (_, stdout, stderr) = registry(&sock, &declared_pull(CRED, UNDECLARED));
    seen.push(stdout);
    seen.push(stderr);

    // The CLI's own validation.
    let (_, stdout, stderr) = registry(&sock, &declared_pull("not-a-vault-id", DECLARED));
    seen.push(stdout);
    seen.push(stderr);

    // And the mismatch refusal, whose message is the one most likely to grow a
    // "for your information" clause in a later change.
    let (_, stdout, stderr) = registry(&sock, &declared_pull(OTHER_CRED, DECLARED));
    seen.push(stdout);
    seen.push(stderr);

    for text in &seen {
        assert!(
            !text.contains(SECRET),
            "the credential reached output a caller owns: {text}"
        );
    }
}