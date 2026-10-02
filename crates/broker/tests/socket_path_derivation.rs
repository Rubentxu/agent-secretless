//! The CLI and the broker must agree on where the socket is, and neither may
//! decide that for itself.
//!
//! The defect this pins down was a literal: `/run/user/1000/asv/broker.sock`
//! written independently into `crates/broker/src/main.rs` and
//! `crates/cli/src/main.rs`. Two copies of one fact, and both were correct for
//! exactly one account on one machine. A user on any other uid got a broker
//! that could not bind and a CLI that dialed a directory that does not exist
//! — and the symptom, a failed connection, is indistinguishable from a broker
//! that is merely not running. That indistinguishability is why this is a
//! test and not a code comment.
//!
//! Fixing the literal is not sufficient. The two callers could still drift
//! again, and a future change that hardcodes a *different* uid — or points the
//! CLI at a fixed path "just for the tests" — would reintroduce the same class
//! of bug with a different number in it. So this scans the callers for the
//! shape of the mistake rather than for the one instance of it.
//!
//! ## Why a source scan, and not a behavioural test
//!
//! The honest answer is that a behavioural test is not available here. The
//! symptom only exists on a host whose uid is not the one the literal names,
//! and the machine this is developed on *is* uid 1000. A behavioural assertion
//! here would pass against the broken code and pass against the fixed code
//! alike, which is worse than no test: it would report coverage that does not
//! exist. The arithmetic is covered properly as a total function in
//! `asv_ipc_protocol::socket`'s own unit tests, where the uid is a parameter
//! and can be chosen; what is left to pin is that both callers go through it.
//!
//! A test that can only ever see a clean tree is untested, so the scanners
//! below are themselves run against deliberately broken sources, exactly as
//! `uat_017_env_scan.rs` does for its own.

use std::path::{Path, PathBuf};

/// The two programs that must derive the socket from the same function.
///
/// A new third caller — a tray icon, a test harness — is a new entry in this
/// list, which is the point: the scan grows with the callers instead of
/// quietly missing one.
const CALLERS: &[&str] = &["crates/broker/src/main.rs", "crates/cli/src/main.rs"];

/// The shared derivation both callers are required to route through.
const SHARED_DERIVATION: &str = "asv_ipc_protocol::socket";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("broker crate lives at <root>/crates/broker")
        .to_path_buf()
}

fn caller_source(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Line numbers of any `/run/user/<digits>` literal — a runtime directory with
/// the account number written into it.
///
/// Scanned as a shape rather than as the known literal, so that a *different*
/// hardcoded uid is caught too. That is the failure that would otherwise
/// arrive quietly, on a machine whose uid happens to match, and never in
/// review because the number looks plausible.
fn hardcoded_runtime_dirs(source: &str) -> Vec<(usize, String)> {
    const PREFIX: &str = "/run/user/";
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or(line);
        let mut from = 0;
        while let Some(offset) = code[from..].find(PREFIX) {
            let start = from + offset + PREFIX.len();
            let digits: String = code[start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                found.push((index + 1, format!("{PREFIX}{digits}")));
            }
            from = start;
        }
    }
    found
}

/// Strips line comments before a substring is looked for.
///
/// The callers explain *why* they do what they do, and that reasoning names
/// the very things the scanners below hunt — the hardcoded path, the env
/// variable. Without this, documenting the defect would trip the guard against
/// it, and the incentive would be to delete the explanation. This is the same
/// allowance `uat_017_env_scan.rs` makes, and for the same reason: a mention is
/// not a call.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_caller_hardcodes_a_runtime_directory() {
    for caller in CALLERS {
        let findings = hardcoded_runtime_dirs(&code_only(&caller_source(caller)));
        assert!(
            findings.is_empty(),
            "{caller} writes an account number into a runtime directory. That number is \
             correct for one account and wrong for every other, and the resulting failure \
             looks like a broker that is not running:\n  {:?}",
            findings
        );
    }
}

#[test]
fn both_callers_route_through_the_shared_derivation() {
    for caller in CALLERS {
        let source = caller_source(caller);
        assert!(
            source.contains(SHARED_DERIVATION),
            "{caller} does not call `{SHARED_DERIVATION}`. Two callers that each decide \
             where the socket is can disagree, and a CLI dialling one path while the broker \
             listens on another is indistinguishable from an outage."
        );
    }
}

/// The asymmetry is deliberate and must stay deliberate.
///
/// The broker is forbidden from reading the environment by
/// `uat_017_env_scan.rs`, so it takes the uid rule. The CLI is exempt from that
/// scan — `asv run` has to read the environment in order to scrub it — so it
/// may consult `XDG_RUNTIME_DIR`. Both land on the same path whenever the
/// runtime directory is the spec default.
///
/// If this ever inverts, the broker has acquired an environment read that
/// someone will have to argue about in a different review than the one that
/// introduced it.
#[test]
fn only_the_cli_may_consult_the_runtime_directory_variable() {
    let broker = code_only(&caller_source("crates/broker/src/main.rs"));
    assert!(
        !broker.contains("XDG_RUNTIME_DIR"),
        "the broker now reads XDG_RUNTIME_DIR. `uat_017_env_scan.rs` forbids env reads in \
         the broker because they are how a credential-shaped fallback sneaks back in; a \
         read that looks harmless here is the exact shape that test exists to refuse."
    );
    let cli = code_only(&caller_source("crates/cli/src/main.rs"));
    assert!(
        cli.contains("XDG_RUNTIME_DIR"),
        "the CLI stopped consulting XDG_RUNTIME_DIR. The override is why a user on a \
         non-default runtime directory finds the broker without reading a manual."
    );
}

// --- falsification of the scanners above -----------------------------------
//
// A scanner that only ever sees a clean tree is untested. Each one below is
// run against a source containing exactly the thing it claims to catch.

#[test]
fn the_runtime_dir_scanner_detects_a_hardcoded_uid() {
    for literal in [
        "let p = \"/run/user/1000/asv/broker.sock\";",
        "let p = \"/run/user/4242/asv/broker.sock\";",
        "let p = \"/run/user/0/asv\";",
    ] {
        let findings = hardcoded_runtime_dirs(literal);
        assert_eq!(
            findings.len(),
            1,
            "the scanner must flag the hardcoded uid in {literal:?}, got {findings:?}"
        );
    }
}

/// A uid written with the pieces assembled at runtime is still a hardcoded uid,
/// and a path with no account number in it is not. Refusing the first would
/// make the scanner useless; flagging the second would make it noise.
#[test]
fn the_runtime_dir_scanner_is_not_fooled_in_either_direction() {
    let assembled = "let p = \"/run/user/\" + &uid.to_string();";
    let findings = hardcoded_runtime_dirs(assembled);
    assert!(
        findings.is_empty(),
        "an assembled path names no account, so it is not the defect: {findings:?}"
    );

    let no_uid = "let d = \"/run/user\"; let s = \"/asv/broker.sock\";";
    assert!(
        hardcoded_runtime_dirs(no_uid).is_empty(),
        "a path with no account number is not the defect"
    );
}

/// A mention inside a comment is not a path. The most common way this scanner
/// could produce noise is a comment explaining the very defect it hunts.
#[test]
fn a_commented_out_literal_is_not_a_finding() {
    let source = "// the old default was /run/user/1000/asv/broker.sock\nlet p = derived();";
    assert!(
        hardcoded_runtime_dirs(source).is_empty(),
        "a comment is not a call: {:?}",
        hardcoded_runtime_dirs(source)
    );
}
