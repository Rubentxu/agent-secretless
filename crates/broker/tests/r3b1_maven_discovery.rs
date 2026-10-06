//! R3.B's reachability rows: the command an operator actually types, for a
//! second family.
//!
//! # Why this file is in the broker's test directory
//!
//! The same reason as `r3a_npm_discovery.rs`: `asv_broker::binary::locate`
//! refuses a binary older than the sources that produced it, and reimplementing
//! the locator would mean reimplementing the one piece of it that must not be.
//! It asserts on the command's **text output** and depends on nothing from
//! `asv-integrations` — the crate's own rows cover the types, this covers the
//! wiring, and the wiring is the part a library row cannot see.
//!
//! # What these rows prove that npm's cannot
//!
//! npm's vertical could reach a vault; Maven's cannot, because Maven's scope in
//! R3 is `discover` and `discover` holds no authority. So the second family
//! buys a negative the first one had no way to state: **`discover` produces the
//! same report whether or not a credential exists anywhere in the system.** The
//! report is a function of the file and of nothing else, and a vault full of
//! secrets changes not one byte of it.
//!
//! That is the property worth having, because it is the one that makes the
//! later stages safe to write: the step that decides *which* credential a
//! server id refers to runs before anything in this report has a value.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const PASSWORD: &str = "hunter2-not-a-real-secret";
const PROXY_PASSWORD: &str = "proxy-pass-not-real";
const ARTIFACTORY_KEY: &str = "AKCp8REALLYWELLFAKEKEY0123";

fn settings_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>/var/cache/m2</localRepository>
  <servers>
    <server>
      <id>acme-releases</id>
      <username>deploy-bot</username>
      <password>{PASSWORD}</password>
      <configuration>
        <httpHeaders>
          <property>
            <name>X-JFrog-Art-Api</name>
            <value>{ARTIFACTORY_KEY}</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
    <server>
      <id>acme-from-env</id>
      <username>deploy-bot</username>
      <password>${{env.ACME_DEPLOY_TOKEN}}</password>
    </server>
    <server>
      <id>acme-anonymous</id>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>acme-internal</id>
      <url>https://deploy-bot:{PROXY_PASSWORD}@mirror.acme.test/maven</url>
      <mirrorOf>external:*,!acme-releases</mirrorOf>
    </mirror>
  </mirrors>
  <proxies>
    <proxy>
      <id>acme-proxy</id>
      <active>true</active>
      <protocol>https</protocol>
      <host>proxy.acme.test</host>
      <port>3128</port>
      <username>proxy-user</username>
      <password>{PROXY_PASSWORD}</password>
    </proxy>
  </proxies>
</settings>"#
    )
}

struct Account {
    root: tempfile::TempDir,
}

impl Account {
    fn with_settings() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        let m2 = home.join(".m2");
        std::fs::create_dir_all(&m2).expect("create .m2");
        let path = m2.join("settings.xml");
        std::fs::write(&path, settings_xml()).expect("write settings.xml");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        Self { root }
    }

    fn home_dir(&self) -> PathBuf {
        self.root.path().join("home")
    }

    /// Runs the command and returns `(stdout, stderr, success)`.
    fn discover(&self, extra: &[&str]) -> (String, String, bool) {
        let out = Command::new(asv_broker::binary::locate("asv"))
            .arg("integrations")
            .arg("discover")
            .arg("--family")
            .arg("maven")
            .arg("--cwd")
            .arg(self.root.path())
            .arg("--home")
            .arg(self.home_dir())
            .args(extra)
            .output()
            .expect("run asv integrations discover");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.success(),
        )
    }
}

/// Writes a `settings.xml` an operator did not lock down.
fn write_world_writable(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write settings.xml");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
}

#[test]
fn an_operator_types_the_command_and_gets_a_report_with_no_credential_in_it() {
    let account = Account::with_settings();

    for rendering in [&["--json"][..], &[].as_slice()] {
        let label = if rendering.is_empty() { "prose" } else { "json" };
        let (stdout, stderr, ok) = account.discover(rendering);
        assert!(ok, "{label}: the command failed: {stderr}");
        assert!(!stdout.is_empty(), "{label}: the command printed nothing");

        // The envelope is named, so a consumer knows what it is looking at
        // before it parses it. **JSON only**: `asv.discovery/v1` is a wire
        // contract and prose is for a person, and an earlier version of this
        // row asserted it in both — which asked the prose renderer to print a
        // schema string at nobody in particular.
        assert!(stdout.contains("maven"), "{label}: the family is missing: {stdout}");
        if label == "json" {
            assert!(
                stdout.contains("asv.discovery/v1"),
                "{label}: the schema is missing: {stdout}"
            );
        }

        // **The property**, against three secrets this process can see, so the
        // check is a substring match and not a judgement about report shape.
        // The mirror URL is in that list because it is the one nobody greps
        // for: `https://user:pass@host` is a supported Maven form.
        for secret in [PASSWORD, PROXY_PASSWORD, ARTIFACTORY_KEY] {
            assert!(
                !stdout.contains(secret),
                "{label}: {secret:?} reached the report: {stdout}"
            );
        }
    }
}

/// The `<id>` is Maven's audience, and it is the one field the report cannot
/// withhold: without it a binding has nothing to be made against.
///
/// Both renderings, because the prose and the JSON make different promises and
/// an operator may be reading either one.
#[test]
fn the_report_names_the_server_id_because_a_pom_refers_to_it() {
    let account = Account::with_settings();

    let (stdout, stderr, ok) = account.discover(&["--json"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("acme-releases"), "{stdout}");
    assert!(stdout.contains("acme-from-env"), "{stdout}");

    let (prose, stderr, ok) = account.discover(&[]);
    assert!(ok, "{stderr}");
    assert!(prose.contains("server  acme-releases"), "{prose}");
}

/// The environment reference is *named*, because the name is what tells an
/// operator which variable to project — and it is not resolved, because the
/// environment is the caller's and not the file's.
#[test]
fn the_environment_reference_is_named_and_not_resolved() {
    let account = Account::with_settings();

    // Deliberately set, so a resolver here would find it and the row would
    // catch that. `std::env::set_var` is what makes this row able to fail.
    std::env::set_var("ACME_DEPLOY_TOKEN", "a-value-the-report-must-never-contain");

    let (stdout, stderr, ok) = account.discover(&["--json"]);
    std::env::remove_var("ACME_DEPLOY_TOKEN");

    assert!(ok, "{stderr}");
    assert!(stdout.contains("ACME_DEPLOY_TOKEN"), "{stdout}");
    assert!(
        !stdout.contains("a-value-the-report-must-never-contain"),
        "the environment was resolved into the report: {stdout}"
    );
}

/// **The row npm's vertical had no way to write.**
///
/// The `<configuration>` block is where Artifactory and Nexus keep an API key,
/// and the report describes it without reading it. Prose *and* JSON are checked,
/// because the prose is where a library row's guarantee is most likely to leak:
/// an adapter that is safe when serialised and unsafe when printed is safe in
/// exactly the place nobody reads.
#[test]
fn an_unmodelled_configuration_is_named_in_both_renderings() {
    let account = Account::with_settings();

    let (json, stderr, ok) = account.discover(&["--json"]);
    assert!(ok, "{stderr}");
    assert!(
        json.contains("configuration"),
        "the undescribed element was dropped from the report: {json}"
    );

    let (prose, stderr, ok) = account.discover(&[]);
    assert!(ok, "{stderr}");
    assert!(
        prose.contains("configuration"),
        "the undescribed element was dropped from the prose: {prose}"
    );
}

/// A refusal is a finding, and the report survives it.
///
/// The absence line matters as much as the finding: an earlier version printed
/// "no settings.xml was found" *and* the refusal, which is two claims and one
/// of them false — the file was found, and it was refused.
#[test]
fn a_world_writable_settings_file_is_refused_without_losing_the_run() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("home");
    let m2 = home.join(".m2");
    std::fs::create_dir_all(&m2).expect("create .m2");
    write_world_writable(&m2.join("settings.xml"), &settings_xml());

    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--family")
        .arg("maven")
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(&home)
        .output()
        .expect("run asv");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The command still succeeds: one unsafe file does not make the tool
    // unconfigured, and an operator who sees a non-zero exit reads it as "Maven
    // is not set up" — the answer most will accept and none should.
    assert!(out.status.success(), "{stderr}");
    assert!(
        !stdout.contains("no settings.xml was found"),
        "a refusal was reported as an absence: {stdout}"
    );
    assert!(
        stderr.contains("mode 0666") || stdout.contains("mode 0666"),
        "the refusal was not reported: {stdout}{stderr}"
    );
    assert!(
        !stdout.contains(PASSWORD),
        "a refused file was still described: {stdout}"
    );
}

/// **R3's exit criterion, as a fact rather than a claim.**
///
/// The criterion is that a new adapter is addable without touching broker,
/// domain or the wire protocol. This row cannot prove that by itself — a fact
/// about a diff is not a fact a single crate can observe — so what it *does*
/// is pin the half that is observable: the whole family is reachable from one
/// product command, with no broker, no socket, no session and no vault.
///
/// The other half is the diff, and it is checked at commit time: adding Maven
/// changed `crates/integrations`, one match arm in the CLI, and nothing in
/// `crates/broker/src`, `crates/domain/src` or `crates/ipc-protocol/src`. If a
/// future family needs one of those, the criterion was wrong and this row is
/// where it would have started to show.
#[test]
fn the_whole_family_is_reachable_without_a_broker_or_a_vault() {
    let account = Account::with_settings();

    // No socket argument is passed and none has a default here: `discover`
    // takes `--family`, `--cwd`, `--home` and the rendering, and that is the
    // entire surface. If Maven's discovery ever grew a dependency on the
    // broker, this invocation would fail on a missing argument rather than on
    // anything to do with Maven.
    let (stdout, stderr, ok) = account.discover(&["--json"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("\"servers\""), "{stdout}");

    // And an unknown family is still refused rather than falling through to a
    // default, so "this build knows maven" is a checked claim.
    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--family")
        .arg("gradle")
        .arg("--cwd")
        .arg(account.root.path())
        .arg("--home")
        .arg(account.home_dir())
        .output()
        .expect("run asv");
    assert!(
        !out.status.success(),
        "a family this build does not know was accepted: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}