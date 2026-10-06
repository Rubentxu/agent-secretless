//! R4.B.3: the half R4.B.2 could not reach — an `execute` that is **permitted**.
//!
//! R4.B.2 shipped seven rows against a live broker and every one of them ended
//! in a refusal, which it named as a deliberate choice: the policy has its own
//! opinion about `registry.push` and a row that insisted on the outcome would
//! be asserting the policy instead of the plan. That was true and it left the
//! central property of R4 half-proven. A receipt that names a credential on the
//! **denied** path is worth having; a receipt that names one on the **permitted**
//! path is the thing an operator actually acts on, and nothing here had ever
//! watched it happen.
//!
//! Two families, two different answers, and both are the design working:
//!
//! - **curl** reaches authorization. `action_for("curl")` is `Action::HttpRequest`
//!   and `resource_for("curl")` is `Resource::Host`; the Cedar schema applies
//!   `http_request` to `Host`, and `audience_is_approved` gates `Api` and only
//!   `Api`. An operator who delivers a policy through `--policy` can therefore
//!   permit it, and this file does exactly that.
//!
//! - **A vertical can only falsify a mutation if the binary it spawns contains
//!   it.** `crates/broker` did not depend on `asv-cli`, so `cargo test -p
//!   asv-broker` ran whatever `asv` was sitting in the target directory. The
//!   staleness guard in `binary.rs` watched `crates/cli/src` alone, which says
//!   nothing about a change in `asv-integrations` — and a mutation that made
//!   `decide` refuse every permitted execution left the row below **green**,
//!   because the binary it measured predated the change. Found by the
//!   falsification campaign; both halves are fixed, and this file is one of the
//!   rows that says so.
//!
//! - **npm cannot be permitted by any policy at all.** `action_for("npm")` is
//!   `Action::RegistryPush` and `resource_for("npm")` is `Resource::Api`, and the
//!   schema applies `registry_push` to `Registry` and not to `Api`. That pair has
//!   no rule that can match it in either direction. It is not a missing policy
//!   and it is not a closed default: it is a pair of values that no Cedar text
//!   can name. Two rows here exist to hold that down rather than to work around
//!   it.
//!
//! Everything is real: a `VaultStore` on disk, an `asv-brokerd` process with a
//! policy the test writes to a file and passes through `--policy`, a real socket,
//! a real `asv`, and credentials stored through `add-credential` on stdin.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

const NPM_TOKEN: &str = "r4b3_npm_token_that_must_never_appear_9012";
/// The curl user name, and **chosen so that it collides with nothing else in
/// the receipt**.
///
/// R4.B.2's first version of this row used `deploy` and fired on the operator's
/// own credential label. This one used `release` and fired on
/// `release-bot@example.test`, the `--principal` every row here passes. Both
/// were the fixture arguing with itself rather than the receipt leaking, and
/// both were fixed by moving the string rather than by loosening the assertion:
/// a row that cannot tell a user name from a principal is not evidence that the
/// user name is absent, it is evidence that the row cannot answer the question.
const CURL_USER: &str = "svc-publisher";
const CURL_PASSWORD: &str = "r4b3_curl_password_3456";

/// A policy that permits curl's operation, and nothing else.
///
/// **`Host` and not `Api`, and that is the whole of what makes the row work.**
/// `audience_is_approved` reads a two-entry first-party list and gates `Api`;
/// `Host` is not on that path, so an operator-delivered rule naming `Host` is
/// reachable where the same rule naming `Api` would never be evaluated.
const CURL_POLICY: &str = r#"
permit (
    principal,
    action == Action::"http_request",
    resource is Host
);
"#;

/// A policy that tries, in every form the schema allows, to permit npm.
///
/// It is written to fail, and the reason it is written at all is that a claim
/// like "npm cannot be permitted" needs the strongest reasonable opposing
/// argument tested against it rather than asserted. Three attempts:
///
/// 1. the action this build actually asks for, on the resource type it
///    actually asks for — which does not load, because `registry_push` does not
///    apply to `Api`;
/// 2. `registry_push` on `Registry`, the pairing the schema does allow — which
///    loads and never matches, because the build asks for `Api`;
/// 3. `http_request` on `Api`, the shape a policy author would reach for if they
///    read the audience out of an `.npmrc` — which loads and never matches for the
///    same reason.
///
/// **Which of the three a broker refuses is itself part of the answer**, and the
/// rows below report whichever it is rather than assuming a refusal means the
/// third case.
const NPM_POLICY_ATTEMPTS: &[(&str, &str)] = &[
    (
        "the-pair-this-build-asks-for",
        r#"
permit (principal, action == Action::"registry_push", resource is Api);
"#,
    ),
    (
        "the-pair-the-schema-allows",
        r#"
permit (principal, action == Action::"registry_push", resource is Registry);
"#,
    ),
    (
        "the-shape-a-policy-author-reaches-for",
        r#"
permit (principal, action == Action::"http_request", resource is Api);
"#,
    ),
];

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
    home: PathBuf,
    project: PathBuf,
    bin: PathBuf,
    policy: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    /// A vault, an enrolled client, stub tools, and a broker started **with the
    /// policy in `policy`**.
    ///
    /// The stubs rather than the host's tools, for the reason R4.B.2 gave: the
    /// resolver reads the same `PATH` twice inside one invocation, and a row that
    /// passes on one machine and fails on another is measuring the machine.
    fn new(name: &str, policy: &str) -> (Self, Broker) {
        let dir = std::env::temp_dir().join(format!(
            "asv-r4b3-{name}-{}-{:?}",
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
        let policy_path = dir.join("policy.cedar");
        let passphrase_value = "r4b3-permitted-execute-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        std::fs::write(&policy_path, policy).expect("write the policy");
        VaultStore::create(
            &vault,
            &SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

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

        // `--policy` is the operator's own lever, and this is the first row in
        // this repository to use it. The broker validates the text against its
        // own schema at load and refuses to start on anything malformed rather
        // than running with a policy nobody could have meant.
        let broker = Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .arg("--policy")
            .arg(&policy_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv-brokerd");
        let broker = Broker(broker);

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            sock.exists(),
            "the broker never created its socket; a policy it refuses to load exits \
             before the socket exists"
        );

        let fixture = Self {
            dir,
            sock,
            home,
            project,
            bin,
            policy: policy_path,
        };
        for tool in ["npm", "curl"] {
            Self::executable(&fixture.bin.join(tool), "#!/bin/sh\nexit 0\n");
        }
        (fixture, broker)
    }

    /// Starts a broker against a policy and returns what it said, **without**
    /// asserting that it started.
    ///
    /// A broker that refuses a policy exits non-zero and leaves no socket, and a
    /// fixture that asserted a socket would turn "the policy did not load" into
    /// "the test broke" — which is the wrong diagnosis for the same failure the
    /// first npm row is trying to distinguish from the other two.
    fn try_start(name: &str, policy: &str) -> (Option<(Self, Broker)>, String) {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&started);
        // `Fixture::new` asserts, so it cannot be used here; this probes the
        // same startup and reports instead.
        let dir = std::env::temp_dir().join(format!(
            "asv-r4b3-{name}-{}-{:?}",
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
        let policy_path = dir.join("policy.cedar");
        let passphrase_value = "r4b3-permitted-execute-passphrase";
        std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");
        std::fs::write(&policy_path, policy).expect("write the policy");
        VaultStore::create(
            &vault,
            &SecretString::new(passphrase_value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");
        let _ = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("run --enrol-principal");

        let mut child = Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .arg("--policy")
            .arg(&policy_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv-brokerd");

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if sock.exists() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            for tool in ["npm", "curl"] {
                Self::executable(&bin.join(tool), "#!/bin/sh\nexit 0\n");
            }
            return (
                Some((
                    Self {
                        dir,
                        sock,
                        home,
                        project,
                        bin,
                        policy: policy_path,
                    },
                    Broker(child),
                )),
                String::new(),
            );
        }
        // It did not start: collect what it said and clean up by hand, since no
        // `Broker` was ever constructed to do it in `Drop`.
        let _ = child.kill();
        let out = child.wait_with_output().expect("collect the refusal");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
        (None, said)
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

    /// `asv integrations execute`, against the broker this fixture started and
    /// without `--no-vault`.
    fn execute(&self, family: &str, extra: &[&str]) -> (String, String, i32) {
        let mut args = vec![
            "integrations",
            "execute",
            "--family",
            family,
            "--tool",
            family,
            "--transaction",
            "tx-r4b3",
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
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
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

/// **The property R4.B.2 could not state: a PERMITTED execution names the
/// credential it would spend.**
///
/// Everything in the chain is the same as R4.B.2's; the only difference is a
/// policy file. That is the point: the receipt's ability to name a credential
/// cannot depend on whether the authorization went well, and the only way to
/// know that is to run the branch that went well.
#[test]
fn a_permitted_execution_names_the_credential_it_would_spend() {
    let (fixture, _broker) = Fixture::new("permitted-curl", CURL_POLICY);
    fixture.curlrc();
    fixture.add_credential("curl-deploy", CURL_PASSWORD);

    let (stdout, stderr, code) = fixture.execute("curl", &["--json"]);
    let r = receipt(&stdout);

    // The outcome is the thing this file exists for. R4.B.2 asserted the binding
    // and deliberately left the verdict alone; asserting it here is asserting
    // that the operator's policy was reached and applied, which is a fact about
    // the wiring rather than about the policy's content.
    assert!(
        r["outcome"] == "executed",
        "the execution was not permitted:\n{stdout}\nstderr: {stderr}"
    );
    assert!(
        r["authorization"]["permit"].is_object(),
        "the verdict was not a permit:\n{stdout}"
    );
    assert_eq!(code, 0, "a permitted execution must exit zero: {stderr}");

    // And it names the credential, on this branch, the way it named it on the
    // denied one. Same accessor, same answer.
    let entries = r["plan"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "one option, one entry:\n{stdout}");
    assert_eq!(
        entries[0]["binding"]["state"], "bound",
        "a permitted execution bound nothing:\n{stdout}"
    );
    assert_eq!(entries[0]["binding"]["label"], "curl-deploy");
    assert_eq!(r["plan"]["inventory_size"], 1);

    // Neither secret rides along on the branch where somebody was about to
    // spend one.
    assert!(
        !stdout.contains(CURL_PASSWORD),
        "the password leaked:\n{stdout}"
    );
    assert!(
        !stdout.contains(CURL_USER),
        "the user name leaked:\n{stdout}"
    );
}

/// **The same receipt can be re-checked on the permitted branch.**
///
/// R4.B.2 proved this over a denial. A reader is more likely to keep a receipt
/// from an operation that *ran* than one that was refused, so this is the copy
/// that most needs to survive on its own.
#[test]
fn a_permitted_receipt_can_be_re_checked_from_the_document_alone() {
    let (fixture, _broker) = Fixture::new("permitted-recheck", CURL_POLICY);
    fixture.curlrc();
    fixture.add_credential("curl-deploy", CURL_PASSWORD);

    let (stdout, _, _) = fixture.execute("curl", &["--json"]);
    let parsed: asv_integrations::ExecuteReceipt =
        serde_json::from_str(stdout.trim()).expect("the receipt parses");

    assert!(parsed.is_executed());
    let rederived = parsed.plan.config_digest();
    assert_eq!(
        parsed.binding.config_fingerprint.as_deref(),
        Some(rederived.as_str()),
        "the document does not reproduce the binding's own claim:\n{stdout}"
    );
    assert_eq!(
        parsed.credentials_at_stake().len(),
        1,
        "a permitted execution spent nothing:\n{stdout}"
    );
    // The named credential is the one the operator gave, not a stray id.
    let (label, id) = parsed
        .credentials_named()
        .into_iter()
        .next()
        .expect("a named credential");
    assert_eq!(label, "curl-deploy");
    let json = serde_json::to_string(&parsed).expect("serialises");
    assert!(
        json.contains(&id.to_string()),
        "the id the accessor reports is not in the document"
    );
}

/// **The npm half, and it is a refusal that no policy can undo.**
///
/// Three policies, each written to permit npm, in every pairing the schema
/// allows. None of them produces a permitted execution, and the reason differs
/// between them — which is why the row reports what the broker *did* rather than
/// assuming the one case it is arguing for.
#[test]
fn npm_cannot_be_permitted_by_any_policy_the_schema_accepts() {
    let mut refusals = Vec::new();
    for (label, policy) in NPM_POLICY_ATTEMPTS {
        let (started, said) = Fixture::try_start(label, policy);
        match started {
            // The broker refuses to load it: `registry_push` does not apply to
            // `Api`, and a rule naming a pair the schema does not allow fails
            // strict validation rather than being quietly ignored.
            None => refusals.push(format!(
                "{label}: refused at load, {}",
                said.lines().find(|l| !l.trim().is_empty()).unwrap_or("?")
            )),
            Some((fixture, _broker)) => {
                fixture.npmrc();
                fixture.add_credential("npm-registry", NPM_TOKEN);
                let (stdout, stderr, _) = fixture.execute("npm", &["--json"]);
                let r = receipt(&stdout);
                assert!(
                    r["outcome"] != "executed",
                    "a policy permitted npm, which this row says is impossible:\n{stdout}"
                );
                // The binding still happened. What is missing is the authority,
                // and the two are independent facts: a receipt that lost the
                // plan on the denied branch would be a second bug hiding inside
                // this one.
                assert_eq!(
                    r["plan"]["entries"][0]["binding"]["state"], "bound",
                    "the refusal dropped the plan it refused:\n{stdout}"
                );
                assert_eq!(r["plan"]["inventory_size"], 1, "stderr: {stderr}");
                refusals.push(format!(
                    "{label}: loaded, refused at evaluation, {}",
                    r["authorization"]["deny"]["reason_code"]
                ));
            }
        }
    }
    assert_eq!(
        refusals.len(),
        NPM_POLICY_ATTEMPTS.len(),
        "not every policy was exercised: {refusals:?}"
    );
    // At least one of them must have loaded. If every one were refused at
    // startup the row would be measuring the validator rather than the
    // evaluation, and "no policy can permit npm" would still be true for a
    // different reason than the one it is claiming.
    assert!(
        refusals
            .iter()
            .any(|line| line.contains("refused at evaluation")),
        "no policy got far enough to be refused by the policy engine: {refusals:?}"
    );
}

/// **The two families differ because of the pair, not because of the policy.**
///
/// One policy file, two families, one permitted and one not. Everything else is
/// held constant: the same broker, the same vault, the same one-credential
/// inventory, the same bound plan. If this row ever goes green for both, the
/// distinction this file draws is not in the code.
#[test]
fn the_same_policy_permits_curl_and_refuses_npm() {
    let (fixture, _broker) = Fixture::new("pair", CURL_POLICY);
    fixture.curlrc();
    fixture.npmrc();
    fixture.add_credential("curl-deploy", CURL_PASSWORD);

    let (curl_out, _, curl_code) = fixture.execute("curl", &["--json"]);
    let (npm_out, _, _) = fixture.execute("npm", &["--json"]);

    let curl = receipt(&curl_out);
    let npm = receipt(&npm_out);

    assert!(
        curl["outcome"] == "executed",
        "curl was not permitted by the policy that permits it:\n{curl_out}"
    );
    assert!(
        npm["outcome"] != "executed",
        "npm was permitted:\n{npm_out}"
    );
    assert_eq!(curl_code, 0);

    // Both bound a credential from the same inventory, so the difference is
    // upstream of the plan and downstream of nothing else.
    assert_eq!(curl["plan"]["inventory_size"], 1);
    assert_eq!(npm["plan"]["inventory_size"], 1);
    assert_eq!(curl["plan"]["entries"][0]["binding"]["state"], "bound");
    assert_eq!(npm["plan"]["entries"][0]["binding"]["state"], "bound");

    // The intents name different actions and different resource types, and a
    // reader diagnosing a refusal needs to see that rather than infer it.
    assert_ne!(curl["intent"]["action"], npm["intent"]["action"]);
    assert_ne!(
        curl["intent"]["resource"]["host"],
        npm["intent"]["resource"]["audience"]
    );
}

/// **The receipt says which policy decided, and it is not the built-in one.**
///
/// This row exists because running the block found the opposite: the engine
/// writes `rule: "m3-default-policy"` unconditionally, in
/// `PolicyEngine::result`, for every decision it produces regardless of where
/// the text came from. So an operator who delivered their own policy through
/// `--policy`, and then reads a receipt authorising an operation, is told the
/// built-in default decided it.
///
/// That is the same defect class this repository treats as first-rate — a
/// document that asserts something the reader can act on, and which the code
/// contradicts. Here the contradiction is inside the artefact itself: the
/// operator's policy is the thing that has to be correct, and the receipt points
/// at a different one.
///
/// The denial matters as much as the permit. A refusal is exactly where an
/// operator goes looking for which rule refused them, so the name has to be
/// right in both directions or the field is worse than absent.
#[test]
fn the_receipt_names_the_policy_that_decided_rather_than_the_built_in() {
    let (fixture, _broker) = Fixture::new("rule-name", CURL_POLICY);
    fixture.curlrc();
    fixture.add_credential("curl-deploy", CURL_PASSWORD);

    let (stdout, stderr, _) = fixture.execute("curl", &["--json"]);
    let r = receipt(&stdout);
    assert_eq!(r["outcome"], "executed", "stderr: {stderr}");

    let decision = r["authorization"]["permit"]["decision"]
        .as_str()
        .expect("a decision string");
    assert!(
        !decision.contains("m3-default-policy"),
        "the receipt credits the built-in policy for a decision the operator's \
         own policy made: {decision}\n{stdout}"
    );
    // And it says which one did, in a way an operator can match against the file
    // they delivered rather than a bare "a policy".
    //
    // The expectation is read off the fixture rather than spelled out as
    // `"policy.cedar"`, because a literal here would keep passing if the
    // fixture ever started writing the policy under a different name: the row
    // would go on asserting the name it used to use while the broker named the
    // new one, and it would go on passing, because the assertion was about a
    // string in this file rather than about the path the operator delivered.
    let delivered = fixture.policy.display().to_string();
    assert!(
        decision.contains(&delivered),
        "the receipt does not name the delivered policy ({delivered}): \
         {decision}\n{stdout}"
    );
}
