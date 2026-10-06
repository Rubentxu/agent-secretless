//! R4.B.2: `asv integrations execute` against a **live broker** and a **real
//! credential inventory**.
//!
//! R4.B.1 shipped the whole authority chain and, deliberately, an empty
//! inventory: it was about the chain, and reaching the vault for it would have
//! turned a step that holds no secret into one that could. The receipt it wrote
//! named no credential, and it could not name one — the plan it did not carry
//! was a plan that bound nothing.
//!
//! These rows are the half that needed a real broker. Everything here is real:
//! a `VaultStore` on disk, an `asv-brokerd` process, a real socket, a real `asv`
//! client, and a credential stored through `add-credential` on stdin. Nothing is
//! mocked, because the claim is **reachability** — that the credential an
//! operation would spend is a fact an operator can read off a product surface,
//! not a fact a unit test in a crate produces.
//!
//! **What these rows do not assert is the outcome.** With a live broker the
//! policy has its own opinion about whether `RegistryPush` to
//! `registry.npmjs.org` is permitted for this principal, and that opinion is
//! not this block's to write. What R4.B.2 claims is narrower and survives
//! either verdict: *the receipt names the credential the execution would spend*.
//! A `DENIED` receipt that names the credential and a `EXECUTED` one that names
//! it are the same receipt as far as this property goes, and a row that insisted
//! on the outcome would be asserting the policy rather than the plan.
//!
//! The pairs that matter are the ones that must stay distinct:
//!
//! - a receipt that names a credential, and a receipt over an empty inventory
//!   that says in the document that it named nothing;
//! - a credential id an operator can act on, and the value the tool's
//!   configuration file is holding.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The npm token. It must appear in no rendering of any receipt below, in
/// either family, and the rows assert that with the literal rather than with a
/// length.
const NPM_TOKEN: &str = "r4b2_npm_token_that_must_never_appear_1234";
/// The curl password, same purpose. The *user name* is a separate constant
/// because it is a separate leak: `user = "deploy:…"` puts both in the file,
/// and a row that only forbade the value would pass with the user name in the
/// receipt.
const CURL_USER: &str = "deploy";
const CURL_PASSWORD: &str = "r4b2_curl_password_5678";

fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}

/// A broker this test owns. `Drop` kills it, so a failing assertion cannot
/// leave a daemon holding a socket for the rest of the suite.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    home: PathBuf,
    project: PathBuf,
    bin: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    /// A vault, an enrolled principal, a running broker, and a `bin` holding a
    /// stub `npm` and a stub `curl`.
    ///
    /// **The stubs, not the host's tools.** `resolve_tool` reads the same `PATH`
    /// twice inside one invocation and refuses anything world-writable; using
    /// the real `npm` would make the fixture depend on what a machine happens to
    /// have installed, and a row that passes on the author's laptop and fails on
    /// a CI box is a row measuring the machine.
    fn new(name: &str) -> (Self, Broker) {
        let dir = std::env::temp_dir().join(format!(
            "asv-r4b2-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        let project = dir.join("project");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::create_dir_all(&project).expect("project");
        std::fs::create_dir_all(&bin).expect("bin");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let passphrase_value = "r4b2-bound-execute-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        VaultStore::create(
            &vault,
            &SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        // ADR-0015: enrol the real client. Without it every control-plane
        // command is refused, which is correct and would make the rows below
        // prove nothing about binding.
        let enrol = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("run --enrol-principal");
        assert!(
            enrol.status.success(),
            "enrolment failed: {}",
            String::from_utf8_lossy(&enrol.stderr)
        );

        let broker = Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn asv-brokerd");
        let broker = Broker(broker);

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the broker never created its socket");

        let fixture = Self {
            dir,
            sock,
            home,
            project,
            bin,
        };
        for tool in ["npm", "curl"] {
            Self::executable(&fixture.bin.join(tool), "#!/bin/sh\nexit 0\n");
        }
        (fixture, broker)
    }

    fn asv(&self, args: &[&str], stdin: Option<&str>) -> (bool, String) {
        let mut child = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PATH", self.path())
            .spawn()
            .expect("spawn asv");
        if let Some(secret) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(secret.as_bytes())
                .expect("write the secret");
        }
        let out = child.wait_with_output().expect("asv completes");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// Opens a real session through the real control plane and returns its id.
    ///
    /// **This was the missing half of "against a live broker".** The first
    /// draft of this file invented a session UUID — `11111111-…`, the same
    /// constant `r4b1_intent_chain.rs` uses — and every row got
    /// `UNAUTHORIZED: the broker answered Error`, because the broker checks
    /// that a session belongs to the authenticated peer before it will evaluate
    /// anything. That check is right and it is the reason the receipt read
    /// `UnexpectedResponse`: the chain never reached the policy.
    ///
    /// With a real session the authorization is a real answer about a real
    /// intent, whichever way it goes, and the row stops depending on the broker
    /// refusing to answer.
    fn session(&self) -> String {
        let (ok, out) = self.asv(
            &[
                "session",
                "--workspace",
                self.dir.to_str().expect("utf-8 workspace"),
            ],
            None,
        );
        assert!(ok, "could not open a session: {out}");
        let id = out
            .split_whitespace()
            .nth(1)
            .unwrap_or_else(|| panic!("no session id in: {out}"))
            .to_string();
        assert!(
            // Not `uuid::Uuid`: the broker crate's dev-dependencies do not carry
            // the uuid crate, and a row that reached for it would be testing the
            // manifest. What has to be true is that the id is shaped like one,
            // which is all this row needs it to be.
            id.len() == 36 && id.chars().filter(|c| *c == '-').count() == 4,
            "the control plane printed something that is not a session id: {out}"
        );
        id
    }

    /// `asv integrations execute`, against the live broker and **without**
    /// `--no-vault`: the inventory request is the point of this file.
    ///
    /// And without `--session` either, because that is the shape of the command
    /// an operator actually types. The session it authorizes under is opened by
    /// the process itself; see the row that covers what happens when one is
    /// passed in from outside.
    fn execute(&self, family: &str, extra: &[&str]) -> (bool, String, String) {
        let mut args = vec![
            "integrations",
            "execute",
            "--family",
            family,
            "--tool",
            family,
            "--transaction",
            "tx-r4b2",
            "--principal",
            "release-bot@example.test",
            "--workspace",
            self.dir.to_str().expect("utf-8 workspace"),
            "--home",
            self.home.to_str().expect("utf-8 home"),
            "--cwd",
            self.project.to_str().expect("utf-8 project"),
        ];
        args.extend_from_slice(extra);
        // stdout and stderr are kept apart: the receipt is on one and every
        // diagnostic is on the other, and a row that concatenated them (as the
        // R3.A.2 fixture does) cannot tell a refusal from a receipt.
        let child = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PATH", self.path())
            .spawn()
            .expect("spawn asv");
        let out = child.wait_with_output().expect("asv completes");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.to_str().expect("utf-8 bin"))
    }

    fn add_credential(&self, label: &str, secret: &str) {
        let (ok, out) = self.asv(
            &[
                "add-credential",
                "--label",
                label,
                "--kind",
                "bearer_token",
                "--provider",
                "npm",
                "--account",
                "acme",
            ],
            Some(secret),
        );
        assert!(ok, "could not store {label}: {out}");
    }

    /// A `.npmrc` at 0600. The mode is not decoration: `discover` refuses a
    /// world-writable configuration, and a fixture written at the umask default
    /// would be testing that refusal instead of the binding.
    ///
    /// **The key is built from parts.** npm's real spelling is
    /// `//registry.npmjs.org/:_authToken=…`, and the unprefixed form is *not* an
    /// auth selector to this parser — a fixture written that way yields a plan
    /// with no entries, which reads exactly like "the vault held nothing". That
    /// is how this file's first draft of the npm fixture passed a row it should
    /// have failed.
    fn npmrc(&self) {
        let key = format!("/{}:_authToken={}", "/registry.npmjs.org", NPM_TOKEN);
        Self::private(
            &self.home.join(".npmrc"),
            &format!("registry=https://registry.npmjs.org/\n{key}\n"),
        );
    }

    fn curlrc(&self) {
        Self::private(
            &self.home.join(".curlrc"),
            &format!("user = \"{CURL_USER}:{CURL_PASSWORD}\"\n"),
        );
    }

    fn private(path: &Path, body: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .expect("write the configuration");
        file.write_all(body.as_bytes()).expect("write");
    }

    fn executable(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write the stub");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

fn receipt(stdout: &str) -> serde_json::Value {
    assert!(
        !stdout.trim().is_empty(),
        "the command wrote no receipt: stdout was empty"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("the receipt is not JSON ({error}):\n{stdout}"))
}

/// **The property, in npm, with a credential actually in the vault.**
///
/// R4.B.1's receipt named a plan that bound nothing, and could not name one.
/// This row is the difference: a stored bearer token, an `.npmrc` that names a
/// selector, and a receipt that binds the two and says which credential the
/// execution would spend.
#[test]
fn an_execution_over_a_live_vault_names_the_credential_it_would_spend() {
    let (fixture, _broker) = Fixture::new("npm-bound");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let (_, stdout, stderr) = fixture.execute("npm", &["--json"]);
    let r = receipt(&stdout);

    // The inventory really was asked for and really had one entry. Without this
    // the row below would pass on a build where the inventory never arrived and
    // the plan bound nothing — which is exactly R4.B.1's receipt.
    assert_eq!(
        r["plan"]["inventory_size"], 1,
        "the live broker was not consulted for the inventory:\n{stdout}\n{stderr}"
    );

    let entries = r["plan"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "one auth selector, one entry:\n{stdout}");
    let binding = &entries[0]["binding"];
    assert_eq!(
        binding["state"], "bound",
        "a stored bearer token did not bind:\n{stdout}\n{stderr}"
    );

    // The id is the handle an operator can act on, and the label is what makes
    // it recognisable. Design §7 says a binding is not a *value*; it is not a
    // reason to strip the name an operator gave the entry.
    let id = binding["credential"].as_str().expect("a credential id");
    assert!(!id.is_empty(), "the binding is bound to nothing:\n{stdout}");
    assert_eq!(
        binding["label"], "npm-registry",
        "the label is not the one the operator gave:\n{stdout}"
    );
    assert_eq!(binding["kind"], "bearer_token");

    // And the plan carries the audience, which is what turns "a credential" into
    // "a credential *for this registry*". It lives inside the selector, not on
    // the entry: a `.curlrc` entry has no such field, and the plan schema says so
    // rather than carrying a null.
    assert_eq!(
        entries[0]["selector"]["npm"]["audience"],
        "registry.npmjs.org"
    );

    // The token itself is in the file and in the vault, and in neither the
    // receipt nor anything derived from it.
    assert!(!stdout.contains(NPM_TOKEN), "the token leaked:\n{stdout}");
}

/// **The same property in a family with no audience at all.** A `.curlrc` names
/// no host, so there is nothing to check the credential's audience against — and
/// the receipt still has to say which credential it would spend, because "bound
/// to an unnamed credential for an unnamed host" is only half an answer.
#[test]
fn a_curl_execution_over_a_live_vault_names_the_credential_too() {
    let (fixture, _broker) = Fixture::new("curl-bound");
    fixture.curlrc();
    fixture.add_credential("curl-basic-auth", CURL_PASSWORD);

    let (_, stdout, stderr) = fixture.execute("curl", &["--json"]);
    let r = receipt(&stdout);
    assert_eq!(
        r["plan"]["inventory_size"], 1,
        "the live broker was not consulted:\n{stdout}\n{stderr}"
    );

    let entries = r["plan"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "one option, one entry:\n{stdout}");
    assert_eq!(
        entries[0]["binding"]["state"], "bound",
        "a stored bearer token did not bind a .curlrc selector:\n{stdout}\n{stderr}"
    );
    assert_eq!(entries[0]["binding"]["label"], "curl-basic-auth");
    assert!(
        !stdout.contains(CURL_PASSWORD),
        "the password leaked:\n{stdout}"
    );
    // The user name is a *different* leak from the password: `user = "deploy:…"`
    // puts both in the file, and a row that forbade only the value would pass
    // with the user half of the pair in the receipt.
    //
    // **The stored label deliberately does not contain the word.** Its first
    // version was `curl-deploy`, and this assertion went red on it — the receipt
    // was echoing the *operator's own label* and the row read it as the user
    // name leaking. Both are failures of the fixture rather than of the
    // receipt, and the second is the more dangerous one: a row that cannot tell
    // two strings apart should be fixed rather than loosened, because loosening
    // it would have deleted the assertion instead of the confusion.
    assert!(
        !stdout.contains(CURL_USER),
        "the user name leaked:\n{stdout}"
    );
}

/// **The receipt an operator reads without `--json` says the same thing.**
///
/// Two renderings are two code paths, and a document that is safe in JSON
/// routinely is not in the prose an operator pastes into a ticket. The row also
/// pins the *order*: the credential comes before the verdict, because "executed"
/// and "executed, spending `npm-registry`" are different facts and a reader who
/// meets the verdict first has no reason to look for the difference.
#[test]
fn the_prose_names_the_credential_before_the_verdict() {
    let (fixture, _broker) = Fixture::new("prose");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let (_, stdout, stderr) = fixture.execute("npm", &[]);
    assert!(
        stdout.contains("at stake:"),
        "the prose has no stake section:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("npm-registry"),
        "the prose names no credential:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("would spend:"),
        "the prose does not say what the credential is for:\n{stdout}\n{stderr}"
    );

    let stake = stdout.find("at stake:").expect("stake section");
    let outcome = stdout.find("outcome:").expect("outcome section");
    assert!(
        stake < outcome,
        "the reader meets the verdict before the credential:\n{stdout}"
    );
    assert!(!stdout.contains(NPM_TOKEN), "the token leaked:\n{stdout}");
}

/// **The receipt is re-checkable, and this is the only version of that claim
/// worth asserting.**
///
/// An earlier draft of this row compared the plan's *per-file* fingerprint
/// digest against the intent's `config_fingerprint` and passed for the wrong
/// reason: the latter is the aggregate over every entry, with the family and a
/// length prefix folded in, so the two are different digests by construction and
/// the row was asserting a coincidence that could never hold.
///
/// What it does instead is the re-check an auditor would actually do. Take the
/// receipt, take the plan out of it, re-derive the aggregate from the document
/// alone, and compare it with what the binding claims was promised. If the
/// document cannot reproduce its own claims, "re-checkable" was a slogan.
#[test]
fn the_receipt_can_be_re_checked_from_the_document_alone() {
    let (fixture, _broker) = Fixture::new("recheck");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let (_, stdout, _) = fixture.execute("npm", &["--json"]);
    let r = receipt(&stdout);

    let parsed: asv_integrations::ExecuteReceipt =
        serde_json::from_value(r.clone()).expect("the receipt parses");

    // The re-derive: the plan in the document hashes to the digest the binding
    // says it was bound against.
    let rederived = parsed.plan.config_digest();
    assert_eq!(
        parsed.binding.config_fingerprint.as_deref(),
        Some(rederived.as_str()),
        "the document does not reproduce the binding's own claim:\n{stdout}"
    );
    // And the intent claims the same thing, because the intent's configuration
    // claim *is* the plan's digest — so a receipt whose two halves disagreed
    // would be a receipt nobody could check at all.
    assert_eq!(
        parsed.intent.config_fingerprint.as_deref(),
        Some(rederived.as_str()),
        "intent and binding disagree about the configuration:\n{stdout}"
    );
    // The binding still points at the intent it answers, by digest.
    assert_eq!(
        parsed.binding.intent_digest,
        parsed.intent.digest().expect("digestable"),
        "the binding answers a different intent:\n{stdout}"
    );

    // The re-check survives the trip through disk, which is the only way the
    // claim matters: an operator reads this file in six months, not the
    // `serde_json::Value` that was in memory when it was written.
    let path = fixture.dir.join("receipt.json");
    std::fs::write(&path, &stdout).expect("write the receipt");
    let reread: asv_integrations::ExecuteReceipt =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read the receipt"))
            .expect("the receipt still parses later");
    assert_eq!(reread.plan.config_digest(), rederived);
    assert_eq!(reread.plan.entries.len(), parsed.plan.entries.len());
    // And what was bound is still bound, named, in the file on disk.
    assert_eq!(
        reread.plan.entries[0].binding,
        parsed.plan.entries[0].binding
    );
}

/// **The live vault and the empty inventory are different receipts, and the
/// difference is in the document.**
///
/// This is the pair R4.B.1 could not state, because both halves said the same
/// thing. Here: a broker holding one credential binds it, and the same fixture
/// with `--no-vault` binds nothing *and says so* — so a reader is never left
/// inferring the second from the absence of a field.
#[test]
fn a_live_vault_and_an_asked_nothing_are_not_the_same_receipt() {
    let (fixture, _broker) = Fixture::new("pair");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let (_, bound_stdout, _) = fixture.execute("npm", &["--json"]);
    let (_, empty_stdout, _) = fixture.execute("npm", &["--json", "--no-vault"]);

    let bound = receipt(&bound_stdout);
    let empty = receipt(&empty_stdout);

    assert_eq!(bound["plan"]["inventory_size"], 1);
    assert_eq!(
        empty["plan"]["inventory_size"], 0,
        "--no-vault did not plan against an empty inventory:\n{empty_stdout}"
    );

    // The selector is reported in both. The difference is in the *binding*, not
    // in the entry list — a plan that dropped the entry would read as complete,
    // and "one selector, nothing bound" is not the same as "nothing to do".
    assert_eq!(
        bound["plan"]["entries"].as_array().map(|e| e.len()),
        empty["plan"]["entries"].as_array().map(|e| e.len()),
        "the selector is reported in one and missing from the other:\n{empty_stdout}"
    );
    assert_eq!(bound["plan"]["entries"][0]["binding"]["state"], "bound");
    assert_eq!(empty["plan"]["entries"][0]["binding"]["state"], "unbound");

    // The schema is the same for both, and that is the point: a consumer cannot
    // tell them apart by which document it was handed, only by what the document
    // says.
    assert_eq!(bound["schema"], empty["schema"]);
    assert_eq!(bound["schema"], "asv.integrations.execute/v1");
}
/// **A session opened by another process cannot authorize this one, and the
/// receipt says so in the broker's own words.**
///
/// Two properties in one row, because they were discovered together and either
/// one alone would have been a weaker claim:
///
/// - The broker pins a session to the PID that opened it. That is correct — it
///   is what stops an agent that read a session id out of a log from spending
///   somebody else's authority — and it means `--session` is a flag for a
///   caller that genuinely owns one, not for an operator at a terminal.
/// - The refusal used to arrive as `the broker answered Error to an
///   authorization request`, which names the protocol shape and drops the
///   reason. The reason is the entire diagnostic. `UnexpectedResponse` was the
///   receipt saying "something went wrong", and this command could never
///   succeed, so every operator reading it was sent looking for the wrong thing.
#[test]
fn a_session_from_another_process_is_refused_with_the_brokers_own_reason() {
    let (fixture, _broker) = Fixture::new("foreign-session");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let foreign = fixture.session();
    let borrowed = foreign.as_str();
    let (_, stdout, _) = fixture.execute("npm", &["--json", "--session", borrowed]);
    let r = receipt(&stdout);

    let outcome = r["outcome"].as_object().expect("an outcome");
    let unauthorized = outcome
        .get("unauthorized")
        .unwrap_or_else(|| panic!("not a refusal: {outcome:?}"));
    assert_eq!(unauthorized["reason_code"], "Refused");

    // The broker's sentence, carried. This is the assertion that would have
    // caught the summary that replaced it, because the summary contains none of
    // these words.
    let reason = unauthorized["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("the broker refused the authorization"),
        "the refusal was summarised rather than carried: {reason}"
    );
    assert!(
        reason.contains("session is not owned by the authenticated peer"),
        "the broker's own reason was dropped: {reason}"
    );

    // And the binding is still in the document. The refusal is about authority,
    // not about what would have been spent — an operator denied a publish still
    // needs to know which credential was on the table.
    assert_eq!(
        r["plan"]["entries"][0]["binding"]["state"], "bound",
        "a refusal dropped the plan it refused:\n{stdout}"
    );
    assert_eq!(r["plan"]["inventory_size"], 1);
}

/// **The command opens its own session, and the receipt names it.**
///
/// R4.B.1 made `--session` mandatory, and the broker pins a session to the PID
/// that opened it — so every invocation an operator could type was refused with
/// "session is not owned by the authenticated peer", and the only ids that
/// could ever have worked were the constant this repository's own fixtures use.
/// The command was unreachable in the one way that matters and no row said so,
/// because every other row in this file passed anyway: the chain runs, the plan
/// binds, the receipt names the credential, and the verdict is a refusal nobody
/// looked at twice.
///
/// So this row asserts the session rather than the outcome, in three parts that
/// all have to hold for the authorization to be reachable at all.
#[test]
fn an_execution_authorizes_under_a_session_it_opened_itself() {
    let (fixture, _broker) = Fixture::new("own-session");
    fixture.npmrc();
    fixture.add_credential("npm-registry", NPM_TOKEN);

    let (_, stdout, _) = fixture.execute("npm", &["--json"]);
    let r = receipt(&stdout);

    let workload = r["intent"]["workload"].as_str().expect("a workload");
    assert_ne!(
        workload, "(no session could be opened)",
        "no session was opened, so no authority was ever asked for:\n{stdout}"
    );
    assert_eq!(
        workload.len(),
        36,
        "the workload is not shaped like a session id: {workload}"
    );

    // The broker evaluated something. `BrokerUnreachable` would mean the
    // question never got asked; `NoMatchingPolicy` means it was asked and the
    // policy had no rule, which is an answer.
    let code = r["authorization"]["deny"]["reason_code"]
        .as_str()
        .or_else(|| r["authorization"]["permit"].as_object().map(|_| "allow"))
        .unwrap_or("none");
    assert_ne!(
        code, "BrokerUnreachable",
        "the authorization never reached the broker:\n{stdout}"
    );

    // And it is a session this process owns, not one a fixture invented. The
    // constant is the one `r4b1_intent_chain.rs` used, and it was in this
    // file's first draft too — a row that pinned it would have kept passing
    // against exactly the bug this row exists to catch, which is why the
    // assertion is about the value rather than about the shape.
    assert_ne!(
        workload, "11111111-1111-4111-8111-111111111111",
        "the command authorized under a session id invented by a test fixture:\n{stdout}"
    );

    // **And the row above is not the vacuous one it first was.** Its first
    // version ended by comparing `workload` with itself, which no mutation can
    // reach and which would have gone green on a command that never opened
    // anything. An assertion that cannot fail is worse than no assertion,
    // because it is read as coverage.
}
