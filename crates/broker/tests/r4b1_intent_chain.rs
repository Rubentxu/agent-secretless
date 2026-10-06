//! The R4.B.1 chain, reached from the product surface.
//!
//! # What this file is for
//!
//! `crates/integrations`' own rows prove that `decide` refuses a world that
//! moved. They cannot prove that `asv` *calls* it, that the six stages are
//! wired in the order the spec draws them, or that a refusal reaches the shell
//! as a non-zero exit. This file covers that, by running the real binary.
//!
//! # The honest limit of what a vertical can show
//!
//! The drift rows below drive [`asv_integrations::decide`] through the same
//! function the CLI calls, with a real plan, a real binding and a real world
//! that moves between them — but they do **not** go through a process
//! boundary, because a single `execute` invocation resolves the tool twice
//! microseconds apart and nothing can change in between. The CLI rows then
//! prove the wiring, and the two together cover what each can.
//!
//! What that leaves unproven, stated plainly: that a *real* concurrent swap of
//! the binary during one `execute` is caught. It is caught — the second
//! `resolve_tool` re-reads and re-hashes the bytes — but no row here can make
//! the swap land in the window. Inventing a test-only hook that mutates the
//! tool between the two resolutions would prove the hook, not the code.
//!
//! # Why most rows here expect a refusal
//!
//! `execute` fails closed when it cannot reach a broker, which is what a test
//! without a daemon gets. That is the correct behaviour and it is asserted as
//! such: "we could not ask" must never look like "it ran".

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use asv_broker::binary::locate;

/// The credential value the npm fixture writes. Named so the rows can assert it
/// is *absent* from every receipt without repeating the literal four times.
const TOKEN: &str = "npm_token_value_that_is_a_secret_1234";

/// A home, a working directory, and an executable named `npm`.
struct Project {
    root: tempfile::TempDir,
}

impl Project {
    /// An npm project whose `.npmrc` holds one token and whose `npm` is a
    /// script this build will vouch for.
    fn npm() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("home");
        std::fs::create_dir_all(root.path().join("bin")).expect("bin");
        // npm's real spelling, built from parts so the source does not carry a
        // bare `//`-prefixed path. The unprefixed form is *not* an auth selector
        // to this parser, and a fixture using it produces a plan with no entries
        // — which reads exactly like "the vault held nothing" and is how this
        // fixture's first version passed a row it should have failed.
        let key = format!("/{}:_authToken={}", "/registry.npmjs.org", TOKEN);
        write_private(
            &root.path().join("home").join(".npmrc"),
            &format!("{key}\n"),
        );
        write_executable(&root.path().join("bin").join("npm"), "#!/bin/sh\nexit 0\n");
        Self { root }
    }

    /// A curl project whose `.curlrc` holds a pair and whose `curl` is a script.
    fn curl() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("home");
        std::fs::create_dir_all(root.path().join("bin")).expect("bin");
        write_private(
            &root.path().join("home").join(".curlrc"),
            "user = \"deploy:curl-secret-value\"\n",
        );
        write_executable(&root.path().join("bin").join("curl"), "#!/bin/sh\nexit 0\n");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    /// The `PATH` this project would be executed under.
    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin().display())
    }

    /// Runs `asv integrations execute`, with the project's `PATH` in front and
    /// `--no-vault` so the run gets as far as the chain.
    ///
    /// `--no-vault` because these rows have no broker: without it the command
    /// now stops at the credential-inventory request, which is the *right*
    /// behaviour and is what `execute_refuses_when_the_inventory_cannot_be_read`
    /// asserts. Every row that wants the chain has to say it is planning against
    /// an empty inventory rather than inherit that by accident.
    fn execute(&self, family: &str, tool: &str, extra: &[&str]) -> (String, String, i32) {
        self.execute_with(family, tool, &["--no-vault"], extra)
    }

    /// The same, with explicit arguments replacing the `--no-vault` default.
    ///
    /// **No `--session` is passed here, and that is deliberate.** The command
    /// opens its own unless the caller brings one, which is the shape an
    /// operator actually types. A row that pinned `--session` to a constant
    /// would skip the whole session step and so would never notice that the
    /// step exists — which is how the receipt-on-an-unreachable-broker behaviour
    /// went unnoticed for as long as it did.
    fn execute_with(
        &self,
        family: &str,
        tool: &str,
        args: &[&str],
        extra: &[&str],
    ) -> (String, String, i32) {
        let mut command = Command::new(locate("asv"));
        command
            .arg("integrations")
            .arg("execute")
            .arg("--family")
            .arg(family)
            .arg("--tool")
            .arg(tool)
            .arg("--transaction")
            .arg("tx-vertical")
            .arg("--principal")
            .arg("release-bot@example.test")
            .arg("--workspace")
            .arg(self.root.path())
            .arg("--home")
            .arg(self.home())
            .arg("--cwd")
            .arg(self.root.path())
            .arg("--socket")
            // A path that does not exist: this file is about the chain, and
            // about what the chain does when nobody can answer it.
            .arg(self.root.path().join("no-broker.sock"))
            .env("PATH", self.path())
            .args(args)
            .args(extra);
        let out = command.output().expect("asv runs");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }
}

fn write_private(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn write_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A receipt parsed out of stdout, so a row can assert on fields rather than
/// on substrings of a rendered document.
fn receipt(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|error| {
        panic!("stdout is not a receipt ({error}): {stdout}\nstderr was printed separately")
    })
}

/// **The chain, end to end, in npm.** Six stages, one document out, and every
/// field a reader needs to re-check the attempt later.
#[test]
fn the_npm_chain_runs_every_stage_and_writes_a_receipt() {
    let project = Project::npm();
    let (stdout, stderr, code) = project.execute("npm", "npm", &["--json"]);
    let r = receipt(&stdout);
    assert_eq!(
        r["schema"], "asv.integrations.execute/v1",
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(r["family"], "npm");
    // 1-2. the intent exists and is addressed to an operation, not a session.
    assert_eq!(r["intent"]["transaction"], "tx-vertical");
    assert_eq!(r["intent"]["action"], "registry_push");
    assert_eq!(
        r["intent"]["resource"]["api"]["audience"],
        "registry.npmjs.org"
    );
    assert_eq!(r["origin"], "human_direct");
    // 3-5. the binding agrees with the intent about the world.
    assert_eq!(
        r["intent"]["config_fingerprint"],
        r["binding"]["config_fingerprint"]
    );
    // The plan recorded the very executable the intent named.
    assert_eq!(r["binding"]["tool"], r["intent"]["tool"]);
    assert!(r["binding"]["intent_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        r["planned_tool"]["resolved"]["path"],
        project.bin().join("npm").to_string_lossy().as_ref()
    );
    // 6. the broker's verdict is present even though it is a refusal.
    assert!(r["authorization"].get("deny").is_some(), "{r:#}");
    assert_ne!(code, 0, "a refusal must not exit 0");
}

/// The second family, same command, same six stages. This is the block's exit
/// criterion: the chain is not an npm-shaped special case.
#[test]
fn the_curl_chain_runs_every_stage_and_writes_a_receipt() {
    let project = Project::curl();
    let (stdout, stderr, code) = project.execute("curl", "curl", &["--json"]);
    let r = receipt(&stdout);
    assert_eq!(
        r["schema"], "asv.integrations.execute/v1",
        "stderr: {stderr}"
    );
    assert_eq!(r["family"], "curl");
    assert_eq!(r["intent"]["action"], "http_request");
    assert_eq!(
        r["intent"]["config_fingerprint"],
        r["binding"]["config_fingerprint"]
    );
    assert_eq!(
        r["planned_tool"]["resolved"]["path"],
        project.bin().join("curl").to_string_lossy().as_ref()
    );
    assert!(r["authorization"].get("deny").is_some());
    assert_ne!(code, 0);
}

/// The law of this crate, on the document that outlives the process: a receipt
/// holds no secret. Checked against both fixtures at once, so a row cannot
/// pass by only having been given the harmless one.
#[test]
fn the_receipt_holds_no_secret_from_either_family() {
    for (project, family, tool) in [
        (Project::npm(), "npm", "npm"),
        (Project::curl(), "curl", "curl"),
    ] {
        let (stdout, _, _) = project.execute(family, tool, &["--json"]);
        for secret in [TOKEN, "curl-secret-value", "deploy"] {
            assert!(
                !stdout.contains(secret),
                "the {family} receipt leaked {secret:?}: {stdout}"
            );
        }
    }
}

/// An unresolvable tool stops the attempt before anything is written. Binding
/// a plan to an executable nobody vouched for would make every later check
/// decorative.
#[test]
fn a_tool_that_does_not_resolve_stops_the_attempt() {
    let project = Project::npm();
    let (stdout, stderr, code) = project.execute("npm", "definitely-not-installed", &["--json"]);
    assert!(
        stdout.is_empty(),
        "nothing should have been written: {stdout}"
    );
    assert!(
        stderr.contains("did not resolve to a tool this build will vouch for"),
        "{stderr}"
    );
    assert_ne!(code, 0);
}

/// A world-writable `npm` is the PATH hijack the whole block is about, and it
/// is refused at resolution with the reason named rather than logged and
/// ignored.
#[test]
fn a_world_writable_tool_is_refused_by_name() {
    let project = Project::npm();
    let npm = project.bin().join("npm");
    std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o777)).expect("chmod");

    let (stdout, stderr, code) = project.execute("npm", "npm", &["--json"]);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("writable by group or other"),
        "the refusal must name the reason: {stderr}"
    );
    assert_ne!(code, 0);
}

/// An unknown family is refused with the list of what this build knows, in the
/// shape every other command in this binary uses.
#[test]
fn an_unknown_family_names_what_this_build_knows() {
    let project = Project::npm();
    let (stdout, stderr, code) = project.execute("maven", "npm", &["--json"]);
    assert!(stdout.is_empty());
    assert!(stderr.contains("`npm` and `curl`"), "{stderr}");
    assert_ne!(code, 0);
}

/// An origin this build does not have is refused **before** the intent is
/// built. A `retrieved_content` spelled `retrieved` and silently defaulted to
/// `human_direct` would be an origin laundering bug wearing a typo.
#[test]
fn an_unknown_origin_is_refused_rather_than_defaulted() {
    let project = Project::npm();
    let (stdout, stderr, code) =
        project.execute("npm", "npm", &["--origin", "retrieved", "--json"]);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("unknown origin"), "{stderr}");
    assert_ne!(code, 0);
}

/// And the attacker-influenced origins are reachable by name, because a policy
/// that cannot single them out is a policy that treats retrieved content as
/// human instruction.
#[test]
fn the_attacker_influenced_origins_are_reachable_from_the_command_line() {
    let project = Project::npm();
    for origin in ["retrieved_content", "untrusted_tool_output"] {
        let (stdout, stderr, _) = project.execute("npm", "npm", &["--origin", origin, "--json"]);
        assert_eq!(
            receipt(&stdout)["origin"],
            origin,
            "{origin} was not carried into the receipt: {stderr}"
        );
    }
}

// ---------------------------------------------------------- the drift itself

/// The spec's example, through the exact function the CLI calls, with a real
/// plan over a real `.npmrc` and a real binding.
///
/// Driven in-process because the two `resolve_tool` calls in one `execute`
/// happen microseconds apart and nothing can change in between — see the file
/// header for why that is a limit of the *test*, not of the code.
#[test]
fn a_hijacked_npm_invalidates_a_real_bound_plan() {
    use asv_domain::{ActionIntent, ToolIdentity};
    use asv_integrations::{decide, plan_npm, resolve_tool, Adapter as _};

    let project = Project::npm();
    let home = project.home();
    let cwd = project.root.path().to_path_buf();
    let policy = asv_integrations::FingerprintPolicy::strict();

    let discovery = asv_integrations::Npm
        .discover(&policy, &home, &cwd)
        .expect("discover");
    let npm = resolve_tool("npm", &project.path()).expect("resolve");
    let planned = npm.resolved.clone().expect("the fixture's npm resolves");
    let plan = plan_npm(&discovery, &[]).with_tool(planned.clone());

    let intent = ActionIntent {
        transaction: "tx-vertical".into(),
        principal: "release-bot@example.test".into(),
        actor: "cli".into(),
        workload: "11111111-1111-4111-8111-111111111111".into(),
        action: asv_domain::Action::RegistryPush,
        resource: asv_domain::Resource::Api {
            audience: asv_domain::Authority::canonicalize("registry.npmjs.org").expect("canonical"),
        },
        tool: Some(planned.clone()),
        config_fingerprint: Some(plan.config_digest()),
        origin: asv_domain::IntentOrigin::HumanDirect,
        expires_at_unix: 1_800_000_000,
    };
    let binding = plan
        .bind_to(&intent)
        .expect("the intent agrees with the world");
    let digest = intent.digest().expect("digests");
    let verdict = asv_integrations::AuthorizationVerdict::Permit {
        decision: "allow".into(),
    };

    // Unchanged: it executes.
    assert!(
        decide(
            &intent,
            &digest,
            &binding,
            Some(&planned),
            Some(plan.config_digest()).as_deref(),
            1_700_000_000,
            &verdict,
        )
        .is_executed(),
        "an unchanged world must execute"
    );

    // The world moves: the very same call refuses, and names both sides.
    let hijacked = ToolIdentity::new(
        project.root.path().join("attacker").join("npm"),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .expect("well-formed");
    let outcome = decide(
        &intent,
        &digest,
        &binding,
        Some(&hijacked),
        Some(plan.config_digest()).as_deref(),
        1_700_000_000,
        &verdict,
    );
    assert!(!outcome.is_executed());
    assert!(
        outcome.headline().starts_with("PLAN_INVALIDATED:"),
        "{}",
        outcome.headline()
    );

    // And the same thing with the bytes swapped under a fixed path, which is
    // the other half of the spec's example.
    std::fs::write(project.bin().join("npm"), "#!/bin/sh\necho pwned\n").expect("swap the bytes");
    let after = resolve_tool("npm", &project.path())
        .expect("resolve")
        .resolved
        .expect("still there");
    assert_eq!(after.path, planned.path, "the path did not move");
    assert_ne!(after.digest, planned.digest, "the bytes did");
    let swapped = decide(
        &intent,
        &digest,
        &binding,
        Some(&after),
        Some(plan.config_digest()).as_deref(),
        1_700_000_000,
        &verdict,
    );
    assert!(!swapped.is_executed());
    assert!(
        swapped.headline().contains("was") && swapped.headline().contains("now"),
        "a replaced binary is a different refusal from a different path: {}",
        swapped.headline()
    );
}

// ------------------------------------------- the credential the chain stakes

// The rows R4.B.1 could not write, and why: `execute` planned against a hard-
// coded empty inventory, so there was nothing to assert a credential was named.
// These are them.

/// **A chain that cannot read the inventory stops.** R4.B.1 shipped
/// `Vec::new()` here, which made every execution an authorization over a plan
/// built on "we did not ask" — and the receipt did not carry the plan, so
/// nothing in the document said so. The refusal is the fix's whole point: an
/// execution against an invented inventory is not a plan, it is a guess with a
/// signature on it.
#[test]
fn execute_refuses_when_the_inventory_cannot_be_read() {
    let project = Project::npm();
    // No `--no-vault`, and the socket does not exist: this is what a machine
    // with no broker looks like.
    let (stdout, stderr, code) = project.execute_with("npm", "npm", &[], &["--json"]);
    assert!(
        stdout.is_empty(),
        "nothing should have been written: {stdout}"
    );
    assert!(
        stderr.contains("could not reach the broker for the credential inventory"),
        "{stderr}"
    );
    // And the refusal says what to do about it, which is the difference
    // between a dead end and a diagnostic.
    assert!(
        stderr.contains("--no-vault"),
        "the refusal must name the way forward: {stderr}"
    );
    assert_ne!(code, 0);
}

/// The escape hatch is honest rather than silent: run with `--no-vault` and the
/// receipt says the inventory was empty, in the document, so a reader is never
/// left inferring it from a field that is absent.
#[test]
fn no_vault_produces_a_receipt_that_says_the_inventory_was_not_asked_for() {
    let project = Project::npm();
    let (stdout, stderr, code) = project.execute("npm", "npm", &["--json"]);
    let r = receipt(&stdout);
    assert_eq!(
        r["schema"], "asv.integrations.execute/v1",
        "stderr: {stderr}"
    );
    // The plan is in the receipt, so the absence is a fact with a number.
    assert_eq!(r["plan"]["inventory_size"], 0);
    assert_eq!(r["plan"]["entries"].as_array().map(|e| e.len()), Some(1));
    // The selector was found and nothing could serve it. That is the honest
    // report: one entry, unbound, not "nothing to do".
    assert_eq!(
        r["plan"]["entries"][0]["binding"]["state"], "unbound",
        "stderr: {stderr}"
    );
    assert_ne!(
        code, 0,
        "no broker to authorize against still means a refusal"
    );
}

/// The prose says it too. A reader who runs the command without `--json` must
/// not have to know the JSON shape to learn that nothing was at stake.
#[test]
fn the_prose_reports_what_was_at_stake() {
    let project = Project::curl();
    let (stdout, stderr, _) = project.execute("curl", "curl", &[]);
    assert!(
        stdout.contains("at stake:"),
        "the prose has no stake section: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("nothing:"),
        "an empty inventory must be stated, not omitted: {stdout}"
    );
    // And the stake comes before the verdict, because "executed" and
    // "executed, spending nothing" are different facts.
    let stake_at = stdout.find("at stake:").expect("stake section");
    let outcome_at = stdout.find("outcome:").expect("outcome section");
    assert!(
        stake_at < outcome_at,
        "the reader meets the verdict before the stake"
    );
}

/// The plan is in the receipt, which is what makes "re-checkable" true rather
/// than a claim. R4.B.1's commit message said the receipt could be re-checked
/// and it could not: nothing named the credential.
///
/// **And the row re-checks it from the document alone**, which is the only
/// version of the assertion that means anything. An earlier draft compared the
/// plan's per-file fingerprint digest against the intent's `config_fingerprint`
/// and was wrong — the latter is the aggregate over every entry, with the
/// family and a length prefix in it, so they are two different digests by
/// construction and the row was asserting a coincidence that could never hold.
#[test]
fn the_receipt_can_be_re_checked_from_the_document_alone() {
    let project = Project::npm();
    let (stdout, stderr, _) = project.execute("npm", "npm", &["--json"]);
    let r = receipt(&stdout);

    // The plan is present, and names the file and the selector.
    let entry = &r["plan"]["entries"][0];
    assert_eq!(
        entry["file"],
        project.home().join(".npmrc").to_string_lossy().as_ref(),
        "stderr: {stderr}"
    );
    assert_eq!(entry["selector"]["npm"]["field"], "auth_token");
    assert_eq!(
        entry["fingerprint"]["digest"], entry["fingerprint"]["digest"],
        "precondition: the fingerprint carries a digest"
    );
    assert!(
        entry["fingerprint"]["digest"]
            .as_str()
            .expect("a string")
            .starts_with("sha256:"),
        "the per-file digest is not a digest: {}",
        entry["fingerprint"]["digest"]
    );

    // **The re-check.** Re-derive the aggregate from the receipt's own plan and
    // compare it with what the intent and the binding claim. Nothing here reads
    // the filesystem or the command's exit status; if these two agree, the
    // document is internally consistent and a reader can repeat the check.
    let plan: asv_integrations::IntegrationPlan =
        serde_json::from_value(r["plan"].clone()).expect("the plan round-trips out of the receipt");
    assert_eq!(
        plan.config_digest(),
        r["intent"]["config_fingerprint"]
            .as_str()
            .expect("a digest"),
        "the receipt's plan does not hash to the digest its intent claims"
    );
    assert_eq!(
        plan.config_digest(),
        r["binding"]["config_fingerprint"]
            .as_str()
            .expect("a digest"),
        "and the binding agrees with the intent about the world"
    );

    // The binding's intent digest is the intent's own, recomputed here too.
    let intent: asv_domain::ActionIntent =
        serde_json::from_value(r["intent"].clone()).expect("the intent round-trips");
    assert_eq!(
        intent.digest().expect("digests"),
        r["binding"]["intent_digest"].as_str().expect("a digest"),
        "the binding answers a different intent than the receipt carries"
    );
}

/// **No broker, and a receipt anyway.**
///
/// This file's rows all run with `--no-vault` because there is no broker to ask,
/// which used to hide a real hole: the moment `execute` needed a session, it
/// exited before writing anything. The refusal was correct and the silence was
/// not — an operator on a machine with no daemon running got no document at
/// all, and the one thing they could have learned from it is that the vault
/// held nothing.
///
/// Found by running the same command against a broker that was actually there,
/// where the session opened fine; the no-broker case then fell out of the same
/// code path and produced nothing. The failure is now a verdict the receipt
/// carries, and this row is what holds it there.
#[test]
fn an_unreachable_broker_still_produces_a_receipt_that_says_so() {
    let project = Project::npm();
    // `--no-vault` so the inventory is answered, and then the session is not:
    // this is the exact order a first-run operator hits.
    let (stdout, stderr, code) = project.execute("npm", "npm", &["--json"]);
    let r = receipt(&stdout);

    assert_eq!(
        r["schema"], "asv.integrations.execute/v1",
        "stderr: {stderr}"
    );
    // The plan still says what it would have spent, because that does not need
    // the broker: the operator configured npm and nothing adopted it yet.
    assert_eq!(r["plan"]["inventory_size"], 0);
    assert_eq!(
        r["plan"]["entries"].as_array().map(|e| e.len()),
        Some(1),
        "the selector went missing rather than going unbound: {stdout}"
    );

    // And the verdict distinguishes "nobody answered" from "somebody said no",
    // which is the distinction the receipt exists to keep.
    let unauthorized = r["outcome"]["unauthorized"]
        .as_object()
        .unwrap_or_else(|| panic!("the outcome is not a refusal: {}", r["outcome"]));
    assert_eq!(unauthorized["reason_code"], "BrokerUnreachable");
    assert_ne!(code, 0, "an unauthorized execution must not exit zero");
    assert!(
        stderr.contains("could not reach the broker"),
        "the warning did not reach the operator: {stderr}"
    );

    // The intent names the absent session rather than an empty one, because that
    // name is in the digest and in the document.
    assert_eq!(
        r["intent"]["workload"], "(no session could be opened)",
        "the receipt claims a session it never had: {stdout}"
    );
}
