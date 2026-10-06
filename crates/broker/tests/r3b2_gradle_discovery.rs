//! The Gradle family, reached from the product surface.
//!
//! # Why this file is in the broker's test directory
//!
//! For the same reason `r3a_npm_discovery.rs` and `r3b1_maven_discovery.rs` are:
//! it uses `asv_broker::binary::locate` to find the real `asv` binary, and it
//! asserts over what an **operator** sees when they type the command. The
//! crate's own rows cover the types; this covers the family being *reachable*.
//!
//! # The row that carries the exit criterion
//!
//! `the_whole_family_is_reachable_without_a_broker_or_a_vault` is not a
//! convenience. R3's exit criterion says a new adapter must be addable without
//! touching broker or domain, and this is the assertion that would notice if a
//! future change quietly violated it: the command runs with no broker, no
//! socket, no session and no vault, so anything it needed from those would
//! show up here as a failure rather than as a design nobody reviewed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SETTINGS: &str = r"storeUser=acme-deploy
storePassword=${ORG_GRADLE_PROJECT_acmeDeploy}
keyAlias=release-2026
org.gradle.jvmargs=-Xmx2g
org.gradle.daemon.idletimeout=3600000
";

/// A working directory and a home, with a project-level properties file in the
/// first and nothing in the second.
struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn with_properties() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("gradle.properties");
        std::fs::write(&path, SETTINGS).expect("write gradle.properties");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod the file to what Gradle writes");
        Self { root }
    }

    fn with_unlocked_properties() -> Self {
        let project = Self::with_properties();
        let path = project.root.path().join("gradle.properties");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("make it world-writable");
        project
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
            .arg("gradle")
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

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// An operator types the command and gets a report with no credential in it.
///
/// The password here is a `${…}` reference, so the report must name the
/// variable and must **not** print a length for the 44 characters standing in
/// for it.
#[test]
fn an_operator_types_the_command_and_gets_a_report_with_no_credential_in_it() {
    let project = Project::with_properties();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(stdout.contains("storePassword"), "the key is named");
    assert!(
        stdout.contains("ORG_GRADLE_PROJECT_acmeDeploy"),
        "and the variable it defers to is named: {stdout}"
    );
    assert!(
        stdout.contains("from ${ORG_GRADLE_PROJECT_acmeDeploy}"),
        "and the reference is printed in Gradle's own syntax, because the name \
         is not the secret: {stdout}"
    );
}

/// **A literal password, not a reference.** The row above proves the variable
/// name travels; this proves the value does not. A fixture holding only a
/// `${…}` reference cannot test the property, because there is no value in the
/// file to leak.
#[test]
fn a_literal_password_never_reaches_the_report_in_either_rendering() {
    let root = tempfile::tempdir().expect("tempdir");
    let properties = root.path().join("gradle.properties");
    std::fs::write(&properties, "storePassword=c0rrect-horse-battery-staple\n").expect("write");
    chmod(&properties, 0o600);

    let cwd = root.path().to_str().expect("utf-8 path").to_string();
    let home = root
        .path()
        .join("home")
        .to_str()
        .expect("utf-8 path")
        .to_string();
    let secret = "c0rrect-horse-battery-staple";

    let run = |extra: &[&str]| -> String {
        let out = Command::new(asv_broker::binary::locate("asv"))
            .args(["integrations", "discover", "--family", "gradle"])
            .arg("--cwd")
            .arg(&cwd)
            .arg("--home")
            .arg(&home)
            .args(extra)
            .output()
            .expect("run asv");
        assert!(
            out.status.success(),
            "discovery failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let prose = run(&[]);
    assert!(!prose.contains(secret), "the prose leaked it: {prose}");
    assert!(
        prose.contains(&format!("{} bytes", secret.len())),
        "and the length is still reported, because the number is what an \
         operator needs: {prose}"
    );

    let text = run(&["--json"]);
    assert!(!text.contains(secret), "the JSON leaked it: {text}");
}

/// **The property unique to this family, asserted end to end.**
///
/// A JVM flag is not a credential. A prose report that listed it among the
/// credentials would be claiming a secret where there is a heap size, and the
/// operator would learn to distrust the count.
#[test]
fn a_jvm_flag_is_not_reported_as_a_credential_in_the_prose_either() {
    let project = Project::with_properties();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(
        stdout.contains("not described by this adapter"),
        "the undescribed keys are named as such, not folded into the credential list: {stdout}"
    );
    assert!(
        stdout.contains("org.gradle.jvmargs"),
        "and the flag itself is still reported: {stdout}"
    );
}

/// The two claims stay apart in the prose: an alias is an alias.
#[test]
fn a_key_alias_is_labelled_as_an_alias_rather_than_as_a_secret() {
    let project = Project::with_properties();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(stdout.contains("keyAlias"), "{stdout}");
    assert!(
        stdout.contains("SigningKeyAlias"),
        "and the report says what kind of thing it is: {stdout}"
    );
}

/// JSON only. The prose printer is exercised above; this asserts the wire form
/// carries no value either.
#[test]
fn the_json_report_carries_no_credential() {
    let project = Project::with_properties();
    let (stdout, stderr, ok) = project.discover(&["--json"]);
    assert!(ok, "the command failed: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("the JSON report parses");
    let text = serde_json::to_string(&value).expect("re-serialise");
    assert!(
        !text.contains("ORG_GRADLE_PROJECT_acmeDeploy}"),
        "only the variable's name travels: {text}"
    );
}

/// The policy Gradle inherits from npm: refuse the file, keep the run.
///
/// A world-writable properties file is exactly the situation where a password
/// is exposed, and an operator has to be told it was skipped rather than have
/// the report read as complete.
#[test]
fn a_world_writable_properties_file_is_refused_without_losing_the_run() {
    let project = Project::with_unlocked_properties();
    let (_stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the run itself still succeeds: {stderr}");
    assert!(
        stderr.to_lowercase().contains("refus") || stderr.contains("writable"),
        "and the operator is told the file was not trusted, on stderr: {stderr}"
    );
}

/// R3's exit criterion, asserted as a row.
///
/// The command runs with no broker, no socket, no session and no vault. If a
/// future family needed any of those to be reachable, this fails rather than
/// the dependency arriving unnoticed.
#[test]
fn the_whole_family_is_reachable_without_a_broker_or_a_vault() {
    let project = Project::with_properties();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "no broker was needed, and none was asked for: {stderr}");
    assert!(stdout.contains("gradle"), "{stdout}");
}

/// The family is dispatchable by the name an agent would type, and a family
/// that does not exist is still refused by name rather than defaulting.
#[test]
fn the_family_is_reachable_and_an_unknown_one_is_still_refused() {
    let project = Project::with_properties();
    let (_, _, ok) = project.discover(&[]);
    assert!(ok);

    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--family")
        // A sentinel that cannot become a real family. `maven` was used here
        // once and was right until Maven existed; a row wired to a *future*
        // family has a shelf life and its expiry looks like a defect elsewhere.
        .arg("a-family-this-build-does-not-have")
        .arg("--cwd")
        .arg(project.root.path())
        .arg("--home")
        .arg(project.home_dir())
        .output()
        .expect("run the refusal path");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "an unknown family is refused, not defaulted: {stderr}"
    );
    assert!(stderr.contains("npm"), "and the error names what it knows");
    assert!(stderr.contains("maven"));
    assert!(stderr.contains("gradle"));
}

/// A file Gradle itself would never have, and which the adapter refuses
/// rather than half-reading.
#[test]
fn a_file_that_is_not_a_properties_file_is_refused_and_the_run_still_succeeds() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("gradle.properties");
    std::fs::write(&path, "thisisnotanentry\n").expect("write");
    chmod(&path, 0o600);

    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--family")
        .arg("gradle")
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(root.path().join("home"))
        .output()
        .expect("run asv");
    assert!(
        out.status.success(),
        "one unreadable file does not make the family unreadable"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("separator") || stderr.to_lowercase().contains("refus"),
        "and the operator is told why the file was skipped: {stderr}"
    );
}

/// The absence of a properties file is not a sentence an operator needs, and
/// with nothing to report the prose must not claim one was found.
#[test]
fn a_project_with_no_gradle_file_gets_an_empty_report_and_no_findings() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--family")
        .arg("gradle")
        .arg("--json")
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(root.path().join("home"))
        .output()
        .expect("run asv");
    assert!(out.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the report is still JSON");
    assert!(
        value["report"]["gradle"]["findings"]
            .as_array()
            .expect("findings")
            .is_empty(),
        "nothing found is not something to be told about: {value}"
    );
}
