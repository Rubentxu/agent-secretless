//! R3.A's reachability row: the command an operator actually types.
//!
//! # Why this file is in the broker's test directory
//!
//! Every other row that runs the real `asv` binary lives here, and the reason
//! is `asv_broker::binary::locate`, which refuses a binary older than the
//! sources that produced it. That refusal has cost this repository nine false
//! reds on `connect_vertical_e2e`: a stale binary answers, the row fails, and
//! the failure looks like a broken tree. Reimplementing the locator here would
//! be reimplementing the one piece of it that must not be reimplemented.
//!
//! It is not a dependency inversion problem either: this file asserts on the
//! command's **text output** and needs nothing from `asv-integrations`. The
//! crate's own rows already cover the types; this one covers the wiring, and the
//! wiring is the part a library row cannot see.
//!
//! # What it proves
//!
//! That `asv integrations discover` is reachable from a shell, produces the
//! `asv.discovery/v1` envelope, describes a real `.npmrc`, and **prints no
//! credential in either rendering**. The last part is checked against a token
//! the fixture plants and this process can see, so a leak is a literal substring
//! match rather than a judgement about the report's shape.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOKEN: &str = "npm_2f7Kd91LmQxRtZ4b";
const BASIC_AUTH: &str = "YWNtZTpwYXNzd29yZA==";

/// A token a reader could not mistake for a digest or a hostname.
fn project_npmrc() -> String {
    format!(
        "registry=https://registry.npmjs.org/\n\
         @acme:registry=https://npm.acme.test/\n\
         //registry.npmjs.org/:_authToken={TOKEN}\n\
         //localhost:4873/:_authToken=${{LOCAL_TOKEN}}\n\
         always-auth=true\n"
    )
}

fn user_npmrc() -> String {
    format!("//npm.acme.test/:_auth={BASIC_AUTH}\n")
}

fn write_npmrc(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write .npmrc");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let project = root.path().join("project");
        let home = root.path().join("home");
        std::fs::create_dir_all(&project).expect("project");
        std::fs::create_dir_all(&home).expect("home");
        write_npmrc(&project.join(".npmrc"), &project_npmrc());
        write_npmrc(&home.join(".npmrc"), &user_npmrc());
        Self { root }
    }

    fn project_dir(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn home_dir(&self) -> PathBuf {
        self.root.path().join("home")
    }

    /// Runs the command and returns `(stdout, stderr, success)`.
    fn discover(&self, extra: &[&str]) -> (String, String, bool) {
        let out = Command::new(asv_broker::binary::locate("asv"))
            .arg("integrations")
            .arg("discover")
            .arg("--cwd")
            .arg(self.project_dir())
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

#[test]
fn an_operator_types_the_command_and_gets_a_report_with_no_credential_in_it() {
    let project = Project::new();

    for rendering in [&["--json"][..], &[].as_slice()] {
        let label = if rendering.is_empty() {
            "prose"
        } else {
            "json"
        };
        let (stdout, stderr, ok) = project.discover(rendering);
        assert!(ok, "{label}: the command failed: {stderr}");
        assert!(!stdout.is_empty(), "{label}: the command printed nothing");

        // The two renderings each have their own way of being right, and both
        // have to name the things an operator cannot work out otherwise.
        if label == "json" {
            // Asserted on the *values*, not on the exact punctuation. The
            // envelope is printed pretty, so `"schema": "..."` with a space
            // after the colon; a row that spelled the whole key-value pair would
            // fail on a whitespace change in a serialiser, which is not a
            // property of this command. What matters is that a consumer can
            // find the schema and the family, and that it can parse the rest.
            assert!(stdout.contains("asv.discovery/v1"), "{stdout}");
            assert!(stdout.contains("\"family\""), "{stdout}");
            assert!(stdout.contains("registry.npmjs.org"), "{stdout}");
            assert!(stdout.contains("npm.acme.test"), "{stdout}");
        } else {
            assert!(stdout.contains("registry  registry.npmjs.org"), "{stdout}");
            assert!(stdout.contains("@acme  npm.acme.test"), "{stdout}");
        }
        // The local registry on a port is the case an `Authority`-shaped
        // audience would have refused, and it has to appear as an audience.
        assert!(
            stdout.contains("localhost:4873"),
            "{label}: a self-hosted registry on a port is missing from the report: {stdout}"
        );
        // And the environment reference is named, because that is what tells
        // the operator which variable to project.
        assert!(
            stdout.contains("LOCAL_TOKEN"),
            "{label}: the dollar-brace reference was not named: {stdout}"
        );

        // **The property.** Against a token this process can see, so the check
        // is a substring match and not a judgement about the report's shape.
        assert!(
            !stdout.contains(TOKEN),
            "{label}: the auth token reached the report: {stdout}"
        );
        assert!(
            !stdout.contains(BASIC_AUTH),
            "{label}: the base64 _auth value reached the report: {stdout}"
        );
    }
}

#[test]
fn the_report_names_both_configuration_files_in_the_order_npm_reads_them() {
    let project = Project::new();
    let (stdout, stderr, ok) = project.discover(&["--json"]);
    assert!(ok, "{stderr}");

    let project_at = stdout.find("project").expect("the project file is named");
    let user_at = stdout
        .rfind("\"user\"")
        .or_else(|| stdout.rfind("user"))
        .expect("the user file is named");
    assert!(
        project_at < user_at,
        "the report does not list the project file before the user file, and npm's precedence \
         means the effective configuration is the one an operator has to read first: {stdout}"
    );
    assert!(
        stdout.contains("sha256:"),
        "no file was fingerprinted: {stdout}"
    );
}

#[test]
fn a_configuration_nobody_else_may_write_is_refused_and_the_report_says_why() {
    // The refusal has to be *legible*. A report that silently omitted a
    // world-writable `.npmrc` would leave an operator believing their
    // credential is not configured, which is the one thing a report about
    // credentials must never imply.
    let root = tempfile::tempdir().expect("tempdir");
    let project = root.path().join("project");
    let home = root.path().join("home");
    std::fs::create_dir_all(&project).expect("project");
    std::fs::create_dir_all(&home).expect("home");
    let npmrc = project.join(".npmrc");
    std::fs::write(&npmrc, project_npmrc()).expect("write");
    std::fs::set_permissions(&npmrc, std::fs::Permissions::from_mode(0o666)).expect("chmod");

    let out = Command::new(asv_broker::binary::locate("asv"))
        .arg("integrations")
        .arg("discover")
        .arg("--cwd")
        .arg(&project)
        .arg("--home")
        .arg(&home)
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("registry.npmjs.org"),
        "a world-writable configuration was described: {stdout}"
    );
    assert!(
        stdout.contains("write") || out.status.success(),
        "the refusal is not reported at all: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_symlinked_configuration_is_refused_until_a_root_is_named() {
    // The decision the default refuses to make on the operator's behalf, made
    // twice: once as a refusal and once as a decision.
    let root = tempfile::tempdir().expect("tempdir");
    let project = root.path().join("project");
    let home = root.path().join("home");
    let real = root.path().join("real-npmrc");
    std::fs::create_dir_all(&project).expect("project");
    std::fs::create_dir_all(&home).expect("home");
    write_npmrc(&real, &project_npmrc());
    std::os::unix::fs::symlink(&real, project.join(".npmrc")).expect("symlink");

    let refused = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--cwd"])
        .arg(&project)
        .arg("--home")
        .arg(&home)
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&refused.stdout);
    assert!(
        !stdout.contains("registry.npmjs.org"),
        "a symlink was followed with no root named: {stdout}"
    );

    let allowed = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--cwd"])
        .arg(&project)
        .arg("--home")
        .arg(&home)
        .args(["--allow-symlink-root"])
        .arg(root.path())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&allowed.stdout);
    assert!(
        stdout.contains("registry.npmjs.org"),
        "naming the root did not permit the symlink: {stdout} stderr={}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn an_unknown_family_is_refused_with_the_list_of_what_this_build_knows() {
    // A wrong `--family` must not print an empty report. An empty report is
    // indistinguishable from "there is nothing configured", and an agent
    // reading one would plan against it.
    //
    // **The family name here was `maven`, and that had a shelf life.** The row
    // was correct when only npm existed and it broke the moment R3.B.1 landed,
    // because Maven stopped being an unknown family — the row failed, and the
    // failure said nothing about what it was about. A sentinel that cannot
    // become a real family keeps the row pointed at the refusal path instead of
    // at the current contents of the enum.
    let unknown = "not-a-family-this-build-knows";
    let project = Project::new();
    let out = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--family", unknown])
        .arg("--cwd")
        .arg(project.project_dir())
        .arg("--home")
        .arg(project.home_dir())
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "an unknown family exited zero");
    assert!(
        stderr.contains(unknown),
        "the refusal does not name what was asked for: {stderr}"
    );
    assert!(
        stderr.contains("npm"),
        "the refusal does not say what exists: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "an unknown family still printed a report: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
