//! R3.A.3: `asv integrations adopt` end to end, against a real broker.
//!
//! This is the first stage where a credential actually moves, so the rows here
//! are about what a mistake costs. Everything is real: a real `VaultStore` on
//! disk, a real `asv-brokerd` process, a real socket, a real `asv` client and a
//! real `.npmrc` holding a real token.
//!
//! The claim the file is built around is deliberately narrow and deliberately
//! strong: **after an import the credential is in the vault and the file is
//! byte-identical to how it was.** Doc 04 §10 puts a vault verification, an
//! integration verification, a negative bypass test and a human approval between
//! an import and a scrub, and none of those happen in this command — so a
//! command that also scrubbed would be skipping four steps and a human while
//! looking like the whole of the migration.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};

/// A token that must appear in no rendering of an import.
const TOKEN: &str = "npm_AdoptVerticalMustNeverAppear789";

fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}

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
    npmrc: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new(name: &str) -> (Self, Broker) {
        let dir = std::env::temp_dir().join(format!(
            "asv-r3a3-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let npmrc = dir.join(".npmrc");
        let passphrase_value = "r3a3-adopt-vertical-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        VaultStore::create(
            &vault,
            &secrecy::SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        // ADR-0015: enrol the real client. Without it the control-plane
        // commands are refused, which is correct and would make every row below
        // prove nothing.
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

        let fixture = Self { dir, sock, npmrc };
        fixture.write_npmrc(&format!(
            "registry=https://registry.npmjs.org/\n\
             //registry.npmjs.org/:_authToken={TOKEN}\n"
        ));
        (fixture, broker)
    }

    /// Written at 0600: a world-writable configuration is refused before its
    /// value is read, and a fixture at the umask default would be testing that
    /// refusal instead of the import.
    fn write_npmrc(&self, contents: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.npmrc)
            .expect("write .npmrc");
        file.write_all(contents.as_bytes()).expect("write");
    }

    fn npmrc_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.npmrc).expect("read the .npmrc back")
    }

    fn asv(&self, args: &[&str]) -> (bool, String) {
        let out = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn asv");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// `asv integrations plan npm --json`, written where `adopt --from-plan`
    /// can find it. The two stages are wired to each other on purpose: the
    /// fingerprint `adopt` checks against has to be the one `plan` recorded, or
    /// §6 is not enforced at all.
    ///
    /// `plan` is given a **home directory**, not a file: it resolves the tool's
    /// own candidate paths, and `--file` is an `adopt` flag that does not exist
    /// on it. Passing the wrong one produced a usage error rather than a plan,
    /// which is the right behaviour and the reason this row failed first.
    fn plan_to(&self, path: &std::path::Path) {
        let (ok, out) = self.asv(&[
            "integrations",
            "plan",
            "npm",
            "--json",
            "--no-vault",
            "--home",
            self.dir.to_str().expect("utf-8"),
        ]);
        assert!(ok, "plan failed: {out}");
        std::fs::write(path, out).expect("write the plan");
    }

    /// `asv integrations adopt npm ...`, with a plan this fixture wrote.
    fn adopt(&self, plan: &std::path::Path, audience: &str, label: &str, json: bool) -> (bool, String) {
        let mut args = vec![
            "integrations".to_string(),
            "adopt".to_string(),
            "npm".to_string(),
            "--file".to_string(),
            self.npmrc.to_string_lossy().into_owned(),
            "--audience".to_string(),
            audience.to_string(),
            "--field".to_string(),
            "_authToken".to_string(),
            "--label".to_string(),
            label.to_string(),
            "--from-plan".to_string(),
            plan.to_string_lossy().into_owned(),
        ];
        if json {
            args.push("--json".to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.asv(&refs)
    }
}

/// **The headline claim: the credential is in the vault and the file is exactly
/// as it was.** Both halves are checked on the same run, because either alone
/// would be a different and weaker claim — a credential moved with the file
/// already scrubbed has skipped four steps of §10, and a file untouched with
/// nothing in the vault has not moved anything.
#[test]
fn a_credential_moves_into_the_vault_and_the_file_is_left_alone() {
    let (fixture, _broker) = Fixture::new("move");
    let plan = fixture.dir.join("plan.json");
    fixture.plan_to(&plan);
    let before = fixture.npmrc_bytes();

    let (ok, out) = fixture.adopt(&plan, "registry.npmjs.org", "npm-registry", false);
    assert!(ok, "adopt failed: {out}");
    assert!(!out.contains(TOKEN), "the token reached the output: {out}");

    // The credential is really in the vault, not merely reported to be.
    let (ok, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(ok, "listing failed: {listing}");
    assert!(
        listing.contains("npm-registry"),
        "the credential did not reach the vault: {listing}"
    );

    assert_eq!(
        fixture.npmrc_bytes(),
        before,
        "adopt modified the file it imported from; §10 puts four steps and a human \
         approval before a scrub, and none of them happened here"
    );
}

/// **The receipt names the binding and claims nothing beyond what it did.**
/// §10's five remaining steps are listed as outstanding, so an import can never
/// be mistaken for a completed migration.
#[test]
fn the_receipt_names_the_binding_and_leaves_the_scrub_outstanding() {
    let (fixture, _broker) = Fixture::new("receipt");
    let plan = fixture.dir.join("plan.json");
    fixture.plan_to(&plan);

    let (ok, out) = fixture.adopt(&plan, "registry.npmjs.org", "npm-registry", true);
    assert!(ok, "adopt failed: {out}");

    assert!(
        out.contains("asv.integrations.adopt/v1"),
        "the receipt does not declare its schema: {out}"
    );
    assert!(
        out.contains("registry.npmjs.org"),
        "the receipt names no audience: {out}"
    );
    assert!(out.contains("npm-registry"), "the receipt names no credential: {out}");
    assert!(out.contains("\"read\""), "no read operation named: {out}");
    assert!(
        out.contains("human_approval"),
        "the receipt does not say a human still has to approve the scrub: {out}"
    );
    assert!(
        out.contains("negative_bypass_test"),
        "the receipt does not say the negative test is still outstanding: {out}"
    );
    assert!(!out.contains(TOKEN), "the token reached the receipt: {out}");
}

/// **§6, reachable from the product.** The plan recorded one fingerprint and the
/// import checks against it, so a configuration that changed in between is
/// refused — and, because the import is what moves the credential, the refusal
/// has to leave the vault empty rather than half-filled.
#[test]
fn a_configuration_that_changed_since_the_plan_imports_nothing() {
    let (fixture, _broker) = Fixture::new("drift");
    let plan = fixture.dir.join("plan.json");
    fixture.plan_to(&plan);

    fixture.write_npmrc(
        "registry=https://registry.npmjs.org/\n\
         //registry.npmjs.org/:_authToken=npm_A_COMPLETELY_DIFFERENT_VALUE\n",
    );

    let (ok, out) = fixture.adopt(&plan, "registry.npmjs.org", "npm-registry", true);
    assert!(!ok, "a changed configuration was imported: {out}");
    assert!(
        out.contains("config_changed"),
        "the refusal does not name its reason: {out}"
    );

    let (_, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(
        !listing.contains("npm-registry"),
        "something was imported despite the refusal: {listing}"
    );
}

/// **A `${VAR}` has no value in the file to move.** Importing the name would
/// store a credential that cannot work and would look like a success.
#[test]
fn an_environment_reference_imports_nothing() {
    let (fixture, _broker) = Fixture::new("envref");
    fixture.write_npmrc("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n");
    let plan = fixture.dir.join("plan.json");
    fixture.plan_to(&plan);

    let (ok, out) = fixture.adopt(&plan, "registry.npmjs.org", "npm-registry", true);
    assert!(!ok, "a reference was imported as a credential: {out}");
    assert!(out.contains("env_reference"), "the reason is not named: {out}");

    let (_, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(
        !listing.contains("npm-registry"),
        "something was imported despite the refusal: {listing}"
    );
}

/// **A selector for another registry is not this credential.** Asking to adopt
/// `other.example.test` must not be served the value written for
/// `registry.example.test` — that was a real bug in `extract`, caught by the
/// crate row of the same name.
#[test]
fn a_selector_for_another_registry_imports_nothing() {
    let (fixture, _broker) = Fixture::new("audience");
    let plan = fixture.dir.join("plan.json");
    fixture.plan_to(&plan);

    let (ok, out) = fixture.adopt(&plan, "other.example.test", "wrong-registry", true);
    assert!(!ok, "a selector for one registry was served another's credential: {out}");

    let (_, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(
        !listing.contains("wrong-registry"),
        "the wrong credential was imported: {listing}"
    );
}

/// **The plan is what makes the import checkable.** Without it the command
/// cannot tell a configuration that changed since the operator planned from one
/// that did not, and refuses rather than pretending.
#[test]
fn an_import_with_no_plan_is_refused_rather_than_guessed() {
    let (fixture, _broker) = Fixture::new("noplan");
    let (ok, out) = fixture.asv(&[
        "integrations",
        "adopt",
        "npm",
        "--file",
        fixture.npmrc.to_str().expect("utf-8"),
        "--audience",
        "registry.npmjs.org",
        "--field",
        "_authToken",
        "--label",
        "npm-registry",
    ]);
    assert!(!ok, "an unchecked import was allowed: {out}");
    assert!(
        out.contains("--from-plan"),
        "the refusal does not say what would make it safe: {out}"
    );

    let (_, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(
        !listing.contains("npm-registry"),
        "something was imported despite the refusal: {listing}"
    );
}

/// **A misspelled field names no credential**, so the command refuses before
/// anything is read rather than importing something npm would never send.
#[test]
fn a_misspelled_field_imports_nothing() {
    let (fixture, _broker) = Fixture::new("typo");
    let (ok, out) = fixture.asv(&[
        "integrations",
        "adopt",
        "npm",
        "--file",
        fixture.npmrc.to_str().expect("utf-8"),
        "--audience",
        "registry.npmjs.org",
        "--field",
        "_authTokne",
        "--label",
        "npm-registry",
    ]);
    assert!(!ok, "a misspelled field was accepted: {out}");

    let (_, listing) = fixture.asv(&["credentials", "--json"]);
    assert!(
        !listing.contains("npm-registry"),
        "something was imported despite the refusal: {listing}"
    );
}