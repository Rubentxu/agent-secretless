//! R3.A.2: `asv integrations plan npm` end to end, against a real broker.
//!
//! Everything here is real: a real `VaultStore` on disk, a real `asv-brokerd`
//! process, a real socket, a real `asv` client, and a real `.npmrc` carrying a
//! real token. Nothing is mocked, because the claim this test makes is about
//! **reachability** — that the plan stage is a product surface an operator can
//! actually run, not a function in a crate that no binary calls.
//!
//! The rows answer three questions an operator would ask, in the order they
//! would ask them:
//!
//! 1. *What credentials am I configuring?* — the selectors are named, in npm's
//!    own precedence, including the ones that are not credentials at all.
//! 2. *What could ASV do about each?* — the postures, strongest first, and
//!    **never a posture ASV cannot deliver**.
//! 3. *Where did the secret go?* — nowhere; the plan is printed and the token is
//!    still only in the file it was already in.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// A token that must appear in no rendering of a plan.
const TOKEN: &str = "npm_PlanVerticalMustNeverAppear123";

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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    /// A vault, an enrolled principal, a running broker, and a two-file npm
    /// configuration. The setup is shared because every row needs it, and a row
    /// that re-derived it would be a second copy of the same fragile sequence.
    fn new(name: &str) -> (Self, Broker) {
        let dir = std::env::temp_dir().join(format!(
            "asv-r3a2-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        let project = dir.join("project");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::create_dir_all(&project).expect("project");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let passphrase_value = "r3a2-plan-vertical-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        VaultStore::create(
            &vault,
            &SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        // ADR-0015: enrol the real client. Without it the control-plane
        // commands are refused, which is correct behaviour and would make every
        // row below prove nothing.
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
        };
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

    /// `asv integrations plan npm [--json] ...`, against this fixture.
    fn plan(&self, extra: &[&str]) -> (bool, String) {
        let mut args = vec![
            "integrations",
            "plan",
            "npm",
            "--home",
            self.home.to_str().expect("utf-8 home"),
            "--cwd",
            self.project.to_str().expect("utf-8 project"),
        ];
        args.extend_from_slice(extra);
        self.asv(&args, None)
    }

    /// Writes an `.npmrc` at 0600. The mode is not decoration: the plan would
    /// refuse a world-writable file, and a fixture written at the umask default
    /// would be testing that refusal instead of the plan.
    fn npmrc(dir: &Path, contents: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.join(".npmrc");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("write .npmrc");
        file.write_all(contents.as_bytes()).expect("write");
    }

    /// The shape every row in this file works with: one user file carrying a
    /// real token against the public registry and one against a local one, plus
    /// an auth-selector `email`, and one project file carrying the same
    /// public-registry token.
    ///
    /// The `email` is written as `//host/:email`, not as a bare `email=` line.
    /// A bare one is a *setting* and produces no auth selector at all, so a
    /// fixture written that way silently tests one selector fewer than it
    /// appears to — which is exactly how this row first failed.
    fn populate(&self) {
        Self::npmrc(
            &self.home,
            &format!(
                "registry=https://registry.npmjs.org/\n\
                 //registry.npmjs.org/:_authToken={TOKEN}\n\
                 //localhost:4873/:_authToken={TOKEN}\n\
                 //registry.npmjs.org/:email=ops@example.test\n"
            ),
        );
        Self::npmrc(
            &self.project,
            &format!("//registry.npmjs.org/:_authToken={TOKEN}\n"),
        );
    }

    fn add_credential(&self, label: &str, kind: &str, secret: &str) {
        let (ok, out) = self.asv(
            &[
                "add-credential",
                "--label",
                label,
                "--kind",
                kind,
                "--provider",
                "npm",
                "--account",
                "acme",
            ],
            Some(secret),
        );
        assert!(ok, "could not store {label}: {out}");
    }
}

/// **The property the stage exists for, through the real binary and a real
/// broker: the plan reaches the operator with no credential in it.**
///
/// Both renderings are checked, because they are different code paths and a
/// document that is safe in JSON routinely is not in a log line an operator
/// pastes into a ticket.
#[test]
fn an_operator_plans_npm_and_no_credential_reaches_the_report() {
    let (fixture, _broker) = Fixture::new("leak");
    fixture.populate();
    fixture.add_credential("npm-registry", "bearer_token", TOKEN);

    for json in ["--json", ""] {
        let (ok, out) = fixture.plan(
            &[json]
                .iter()
                .copied()
                .filter(|a| !a.is_empty())
                .collect::<Vec<_>>(),
        );
        assert!(ok, "plan failed: {out}");
        assert!(!out.is_empty(), "plan printed nothing for {json:?}");
        assert!(
            !out.contains(TOKEN),
            "the token reached the {json:?} rendering:\n{out}"
        );
    }
}

/// **A stored credential produces a binding, and it is the strongest posture
/// first.** A plan that cannot name anything is not advice, it is a shrug.
#[test]
fn a_stored_credential_is_offered_strong_secretless_first() {
    let (fixture, _broker) = Fixture::new("bind");
    fixture.populate();
    fixture.add_credential("npm-registry", "bearer_token", TOKEN);

    let (ok, out) = fixture.plan(&["--json"]);
    assert!(ok, "plan failed: {out}");

    assert!(
        out.contains("strong_secretless"),
        "a bearer token can be brokered, so the strongest posture is on offer:\n{out}"
    );
    // And the *weakest* is not: `add-credential` stores with the default
    // `NonExportable`, so ASV could not write the value out even if asked.
    assert!(
        !out.contains("raw_process_exposure"),
        "a non-exportable credential must not be offered raw exposure:\n{out}"
    );
    // The binding names the credential rather than only the label it was given,
    // which is the whole of what §7 asks for.
    assert!(
        out.contains("npm-registry"),
        "the binding names no credential:\n{out}"
    );
    assert!(
        out.contains("registry.npmjs.org"),
        "the binding names no audience:\n{out}"
    );
}

/// **The empty inventory is a first-run answer, not a degraded one.** An
/// operator who has configured npm and not yet adopted it needs to be told what
/// they *would* adopt, and that question is answerable with nothing stored.
#[test]
fn planning_with_nothing_stored_still_answers_the_question() {
    let (fixture, _broker) = Fixture::new("empty");
    fixture.populate();

    let (ok, out) = fixture.plan(&["--json"]);
    assert!(ok, "plan failed with an empty vault: {out}");
    assert!(
        out.contains("asv.integrations.plan/v2"),
        "the empty plan does not declare its schema:\n{out}"
    );
    // Every selector is still reported. The absence is in the *binding*, not in
    // the entry list — a plan that dropped them would read as complete. Three
    // tokens, one `email` that names no credential: four selectors, four
    // entries, and the count is what distinguishes "reported as unbound" from
    // "not mentioned".
    assert_eq!(
        out.matches("\"state\"").count(),
        4,
        "four auth selectors must produce four entries:\n{out}"
    );
    assert_eq!(
        out.matches("\"unbound\"").count(),
        3,
        "three tokens with nothing behind them:\n{out}"
    );
    assert_eq!(
        out.matches("\"not_a_credential\"").count(),
        1,
        "the email selector names no credential npm will authenticate with:\n{out}"
    );
}

/// **`--no-vault` runs with no broker at all.** The first-run answer does not
/// require a running daemon, which is what makes it usable before an operator
/// has decided to adopt anything.
#[test]
fn the_first_run_answer_needs_no_broker() {
    let (fixture, _broker) = Fixture::new("novault");
    fixture.populate();
    // Point the socket somewhere nothing is listening: if the command reached
    // for the broker, this would fail rather than answer.
    let (ok, out) = {
        let child = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(fixture.dir.join("nothing-listening.sock"))
            .args([
                "integrations",
                "plan",
                "npm",
                "--no-vault",
                "--json",
                "--home",
            ])
            .arg(&fixture.home)
            .arg("--cwd")
            .arg(&fixture.project)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv");
        let out = child.wait_with_output().expect("asv completes");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    };
    assert!(ok, "--no-vault reached for the broker anyway: {out}");
    assert!(out.contains("asv.integrations.plan/v2"), "{out}");
}

/// **Two credentials of the same shape come back `ambiguous`, not resolved.**
///
/// This is the honest answer and the most interesting one: the broker reports a
/// credential's kind but not the audience it is registered for, so nothing in
/// `plan`'s inputs can say which of two bearer tokens is the registry one.
#[test]
fn two_credentials_of_one_shape_are_reported_rather_than_one_chosen() {
    let (fixture, _broker) = Fixture::new("ambiguous");
    fixture.populate();
    fixture.add_credential("npm-registry", "bearer_token", TOKEN);
    fixture.add_credential("ci-pipeline", "bearer_token", "npm_AnotherTokenForCI456");

    let (ok, out) = fixture.plan(&["--json"]);
    assert!(ok, "plan failed: {out}");
    assert!(
        out.contains("ambiguous"),
        "two bearer tokens were silently resolved to one:\n{out}"
    );
    assert!(
        out.contains("npm-registry") && out.contains("ci-pipeline"),
        "both candidates are named, so the operator can choose:\n{out}"
    );
}

/// **A database credential is excluded by name.** It is the one exclusion the
/// plan can justify from the inventory alone, because `CredentialClass` is a
/// property of the shape rather than of the audience.
#[test]
fn a_database_credential_is_excluded_by_name() {
    let (fixture, _broker) = Fixture::new("database");
    fixture.populate();
    fixture.add_credential(
        "postgres",
        "database_credential",
        "hunter2-not-a-registry-token",
    );

    let (ok, out) = fixture.plan(&["--json"]);
    assert!(ok, "plan failed: {out}");
    assert!(
        out.contains("database_shaped"),
        "the exclusion is not named, so the operator cannot see why:\n{out}"
    );
    assert!(
        !out.contains("strong_secretless"),
        "a database password was offered as a registry credential:\n{out}"
    );
}

/// **An unknown family exits non-zero and says what this build knows**, in the
/// same shape as `discover`. A family that is merely absent must not read as a
/// family with nothing to say.
#[test]
fn an_unknown_family_is_refused_with_the_list_of_what_this_build_knows() {
    let (fixture, _broker) = Fixture::new("unknown");
    fixture.populate();

    let (ok, out) = fixture.asv(&["integrations", "plan", "gradle"], None);
    assert!(!ok, "an unknown family exited zero: {out}");
    assert!(
        out.contains("npm"),
        "the refusal does not say what is supported: {out}"
    );
    assert!(!out.contains(TOKEN), "the refusal leaked the token:\n{out}");
}
