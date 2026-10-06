//! The curl family, reached from the product surface.
//!
//! # Why this file is in the broker's test directory
//!
//! For the same reason `r3a_npm_discovery.rs`, `r3b1_maven_discovery.rs` and
//! `r3b2_gradle_discovery.rs` are: it runs the real `asv` binary and asserts
//! over what an **operator** sees when they type the command. The crate's own
//! rows cover the parser; this covers the family being *reachable* and the
//! report saying something an operator can act on.
//!
//! # What is different about this family, and what these rows are for
//!
//! curl takes **one** `.curlrc` and never opens the rest. npm, Maven and Gradle
//! merge every layer they find, so for those a report can be a loop over files.
//! Here the loop has to carry state, and the state is which file won.
//!
//! So the rows below are not a retread of the other families' rows with a
//! different extension. Two of them assert a property **no other family has**:
//! a credential in the losing file is not reported as the operator's credential,
//! and it is not reported as absent either.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

/// A home and a working directory, with a `.curlrc` in one of them.
struct Project {
    root: tempfile::TempDir,
}

impl Project {
    /// A project `.curlrc` holding a literal credential and some ordinary flags.
    fn with_project_rc() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(".curlrc");
        std::fs::write(
            &path,
            "# the operator's curl defaults\n\
             silent\n\
             max-time = 30\n\
             user = \"deploy:s3cr3t-from-the-project\"\n",
        )
        .expect("write .curlrc");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod to what curl writes");
        Self { root }
    }

    fn home_dir(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn discover(&self, extra: &[&str]) -> (String, String, bool) {
        self.discover_family("curl", extra)
    }

    fn discover_family(&self, family: &str, extra: &[&str]) -> (String, String, bool) {
        let out = Command::new(asv_broker::binary::locate("asv"))
            .arg("integrations")
            .arg("discover")
            .arg("--family")
            .arg(family)
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

/// **The row that carries R3's exit criterion.** No broker, no socket, no
/// session, no vault — the command runs on its own, so anything a future change
/// made it depend on would fail here rather than pass unremarked.
#[test]
fn the_whole_family_is_reachable_without_a_broker_or_a_vault() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(!stdout.contains("no adapter for"), "{stdout}");
}

/// The literal password in the file must not reach the report. The username is
/// not printed either: a report that prints usernames hands out the half of the
/// pair an attacker needs to target.
#[test]
fn a_literal_credential_never_reaches_the_report() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(
        !stdout.contains("s3cr3t-from-the-project"),
        "the password was printed: {stdout}"
    );
    assert!(
        !stdout.contains("deploy:"),
        "the pair was printed whole: {stdout}"
    );
    // The two questions, answered as two numbers.
    assert!(stdout.contains("credential  user"), "{stdout}");
    assert!(stdout.contains("password   23 bytes"), "{stdout}");
}

/// **The property no other family has.** curl takes the first existing file and
/// never opens the rest, so a credential in the losing file is invisible to a
/// user who has both. A report that merged them — or that listed the losing file
/// as empty — would be describing a configuration curl never runs.
///
/// The shadowing is between the two **home** candidates, because that is the
/// only shadowing curl has: `$XDG_CONFIG_HOME/curlrc` wins over `$HOME/.curlrc`.
#[test]
fn a_credential_in_the_file_curl_would_never_read_is_reported_as_shadowed() {
    let project = Project::with_project_rc();

    let home = project.home_dir();
    std::fs::create_dir_all(home.join(".config")).expect("create the config dir");

    // curl's second entry, and the one that wins.
    let xdg_rc = home.join(".config").join("curlrc");
    std::fs::write(&xdg_rc, "user = \"xdguser:xdg-secret\"\n").expect("write");
    std::fs::set_permissions(&xdg_rc, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    // curl's third entry, which curl would never open once the second exists.
    let dot_rc = home.join(".curlrc");
    std::fs::write(&dot_rc, "user = \"dotuser:dot-secret\"\n").expect("write");
    std::fs::set_permissions(&dot_rc, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");

    assert!(
        stdout.contains("shadowed by"),
        "the losing file is named as losing rather than as empty: {stdout}"
    );
    assert!(
        stdout.contains("not read"),
        "and it says plainly that it was not read: {stdout}"
    );
    assert!(
        !stdout.contains("dot-secret"),
        "the shadowed file is never opened, so its credential can never be \
         printed: {stdout}"
    );
    // And the winner is named as the winner, by path. This is the operator's
    // actual question — "which of my two files is the live one" — and the
    // report answering it is the whole reason the family exists.
    assert!(
        stdout.contains("shadowed by") && stdout.contains(".config/curlrc"),
        "the winner is named so the operator knows which file curl uses: {stdout}"
    );
}

/// **The limit this family cannot cross, stated in the report rather than in a
/// doc comment nobody opens.** `$CURL_HOME/.curlrc` sorts ahead of everything
/// resolvable here, and honouring it would mean reading this process's
/// environment — which `discover` takes `home` and `cwd` as arguments to avoid.
#[test]
fn the_report_says_the_environment_paths_were_not_examined() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(
        stdout.contains("CURL_HOME") && stdout.contains("XDG_CONFIG_HOME"),
        "the two paths curl reads first are named, so a user who set one knows \
         their configuration is not in this list: {stdout}"
    );
}

/// The bulk of a real `.curlrc` is flags and timeouts, and the report has to say
/// so separately from the credentials. Printing one merged list is how an
/// operator learns to ignore the report.
#[test]
fn the_options_this_adapter_does_not_model_are_reported_separately() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(
        stdout.contains("other option(s) not described"),
        "the unmodelled lines are counted apart from the credentials: {stdout}"
    );
    assert!(stdout.contains("silent"), "{stdout}");
    assert!(stdout.contains("max-time"), "{stdout}");
}

/// The compound credential has three shapes, and only the first is the ordinary
/// one. `user = alice` is a real and reachable configuration: curl sends an
/// empty password, which is a fact and not the same as "no password was set".
#[test]
fn a_user_with_no_password_is_reported_as_absent_rather_than_zero_bytes() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join(".curlrc");
    std::fs::write(&path, "user = alice\n").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let out = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--family", "curl"])
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(root.path().join("home"))
        .output()
        .expect("run asv integrations discover");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    assert!(
        stdout.contains("empty password"),
        "the empty password is named rather than reported as a length: {stdout}"
    );
}

/// An unknown family is refused by name, and the message lists what this build
/// actually knows. A message that fell behind the enum would send an operator
/// looking for a family that exists.
#[test]
fn an_unknown_family_is_refused_and_the_list_of_known_ones_is_current() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover_family("not-a-family", &[]);
    assert!(!ok, "an unknown family must not exit zero");
    let message = format!("{stdout}{stderr}");
    assert!(message.contains("no adapter for"), "{message}");
    for family in ["npm", "maven", "gradle", "curl"] {
        assert!(
            message.contains(family),
            "the refusal names `{family}`: {message}"
        );
    }
}
/// **The row that fixes the bug this family shipped with.**
///
/// A first version of the adapter listed the project `.curlrc` first, because
/// every other family here reads a project file and `Origin::Project` already
/// existed to name it. That made the project file shadow the home file, and the
/// report told an operator their credential lived in the one curl never reads
/// automatically.
///
/// The rows above cannot see this: each uses a home file *or* a project file,
/// so both orderings give the same answer. This one puts a credential in
/// **both** and asks which one won.
#[test]
fn the_home_file_wins_because_curl_never_reads_a_project_file_on_its_own() {
    let project = Project::with_project_rc();

    let xdg = project.home_dir().join(".config");
    std::fs::create_dir_all(&xdg).expect("create the config dir");
    let home_rc = xdg.join("curlrc");
    std::fs::write(&home_rc, "user = \"homeuser:home-secret\"\n").expect("write");
    std::fs::set_permissions(&home_rc, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");

    let home_at = stdout
        .find(".config/curlrc")
        .unwrap_or_else(|| panic!("the home file is not listed: {stdout}"));
    let project_at = stdout
        .rfind(".curlrc")
        .expect("the project file is not listed");

    assert!(
        home_at < project_at,
        "curl reads the home file first, and the project file is not in the lookup \
         at all: {stdout}"
    );
    assert!(
        stdout.contains("--config"),
        "the project file says it needs an explicit --config to be read: {stdout}"
    );
}

/// A project file with no home file beside it is still reported — as something
/// curl needs `--config` to reach, not as the effective configuration.
#[test]
fn a_project_file_alone_is_reported_and_labelled_not_auto_discovered() {
    let project = Project::with_project_rc();
    let (stdout, stderr, ok) = project.discover(&[]);
    assert!(ok, "the command failed: {stderr}");
    assert!(stdout.contains("--config"), "{stdout}");
    assert!(
        !stdout.contains("/home/"),
        "nothing home-relative exists, so the lookup is empty and the project file \
         is the only thing shown: {stdout}"
    );
}

/// **A `.curlrc` past the ceiling is refused, and the run still says something
/// useful about the rest.** The ceiling is checked against the byte length
/// *before* the file is materialised, so this is a refusal rather than a
/// truncated read — and a truncated read would be the far worse outcome, since
/// the credential-bearing option could be the one that got cut.
#[test]
fn a_curlrc_past_the_size_ceiling_is_refused_rather_than_truncated() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join(".config")).expect("create the config dir");

    // Well past the ceiling, and the credential is at the **front** so a
    // truncating reader would report one while silently dropping the rest.
    //
    // Written as a literal rather than `asv_integrations::curl::MAX_CURLRC_BYTES`
    // because this crate does not depend on `asv-integrations`, and adding that
    // dependency so a test can name a constant would be the test reaching past
    // the product surface it is here to exercise. **Must mirror
    /// `MAX_CURLRC_BYTES` in `crates/integrations/src/curl.rs`** (1 << 18); this
    // is twice it, so a ceiling that moved would need this number to move too.
    const TWICE_THE_CEILING: usize = 1 << 19;

    let oversized = format!(
        "user = \"deploy:{}\"\nsilent\n",
        "x".repeat(TWICE_THE_CEILING)
    );
    let path = home.join(".config").join("curlrc");
    std::fs::write(&path, oversized).expect("write an oversized .curlrc");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let out = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--family", "curl"])
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(&home)
        .output()
        .expect("run asv integrations discover");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    // **The run still succeeds.** A family that aborted on the first refused
    // file would exit non-zero and report nothing about the other two paths,
    // which is how "one oversized file" becomes "curl is not configured".
    assert!(
        out.status.success(),
        "a refusal is a finding, not a run failure: {stderr}"
    );

    // The refusal is visible. Findings go to stderr by design — `print_findings`
    // is shared with the other families and a consumer parsing stdout must not
    // have to strip diagnostics out of its stream.
    assert!(
        stderr.contains("ceiling"),
        "the refusal is named rather than the file being skipped in silence: \
         stdout={stdout} stderr={stderr}"
    );

    // Nothing from inside the file, because nothing inside it was read.
    assert!(
        !stdout.contains("credential"),
        "a refused file contributes no credential row, truncated or otherwise: \
         {stdout}"
    );
}

/// **The line ceiling, at the product surface.** The crate's own rows already
/// cover the parser; this proves the ceiling is a property of the adapter an
/// operator reaches and not only of a function a mutation campaign can call.
#[test]
fn a_curlrc_past_the_line_ceiling_is_refused_rather_than_partly_read() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join(".config")).expect("create the config dir");

    // **Must mirror `MAX_CURLRC_LINES`** in
    // `crates/integrations/src/curl.rs`, plus one to be past it. 4096 lines of
    // seven bytes is about 28 KiB, comfortably inside the size ceiling, so this
    // row fails for the reason it names and not for the neighbouring one.
    let mut content = String::from("silent\n".repeat(4097));
    content.push_str("user = \"deploy:one-secret-too-many\"\n");

    let path = home.join(".config").join("curlrc");
    std::fs::write(&path, content).expect("write a .curlrc past the line ceiling");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let out = Command::new(asv_broker::binary::locate("asv"))
        .args(["integrations", "discover", "--family", "curl"])
        .arg("--cwd")
        .arg(root.path())
        .arg("--home")
        .arg(&home)
        .output()
        .expect("run asv integrations discover");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        out.status.success(),
        "a refusal is a finding, not a failure: {stderr}"
    );
    assert!(
        stderr.contains("line ceiling"),
        "the refusal names the line ceiling rather than the byte one: \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stdout.contains("credential"),
        "a refused file contributes no credential row: {stdout}"
    );
}
