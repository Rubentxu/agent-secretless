//! Rows for the tool resolver.
//!
//! Every row builds its own `PATH` out of a temporary directory. That is not
//! tidiness: the interesting cases — a hijack earlier in the list, a symlink,
//! a world-writable candidate — are all about *ordering*, and a row that read
//! the developer's real `PATH` could not assert any of them, because the answer
//! would depend on which machine ran it. A row that passes everywhere is a row
//! that measured nothing.

use super::*;

use std::os::unix::fs::PermissionsExt;

/// A `PATH` built from named directories, in the order given.
fn path_of(dirs: &[&std::path::Path]) -> String {
    dirs.iter()
        .map(|d| d.to_str().expect("utf-8 temp path"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Writes `body` as an executable at `dir/name`, mode `0o755` unless given.
fn write_tool(dir: &std::path::Path, name: &str, body: &str, mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

// -------------------------------------------------------------- first wins

/// The spec's premise is that `PATH` order decides which program runs, so the
/// resolver has to agree with the shell about that order or the whole check is
/// measuring the wrong thing.
#[test]
fn the_first_directory_holding_the_command_wins() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    std::fs::create_dir(&first).expect("mkdir");
    std::fs::create_dir(&second).expect("mkdir");
    write_tool(&first, "npm", "first", 0o755);
    write_tool(&second, "npm", "second", 0o755);

    let path = path_of(&[&first, &second]);
    let resolution = resolve_tool("npm", &path).expect("resolves");

    let identity = resolution.resolved.as_ref().expect("found");
    assert_eq!(
        identity.path,
        first.join("npm").canonicalize().expect("real")
    );
    assert_eq!(
        identity.digest,
        sha256_of(b"first"),
        "the second directory must not be consulted"
    );
    // And the search stopped, so the later directory is not in the report.
    // Reporting it would claim a directory was searched that was not.
    assert_eq!(
        resolution.candidates.len(),
        1,
        "the search stopped at the winner: {:?}",
        resolution.candidates
    );
}

/// Two directories, two different programs under the same name: swapping the
/// bytes at the winning path is the R4 case the spec names, and it is exactly
/// what `ToolBytesChanged` exists to catch.
#[test]
fn the_same_path_with_different_bytes_is_a_different_tool() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    let path = path_of(&[&dir]);

    write_tool(&dir, "npm", "the real npm", 0o755);
    let before = resolve_tool("npm", &path).expect("resolves");
    let planned = before.resolved.expect("found");

    write_tool(&dir, "npm", "the other npm", 0o755);
    let after = resolve_tool("npm", &path).expect("resolves");
    let found = after.resolved.expect("found");

    assert_eq!(planned.path, found.path, "the path did not move");
    assert_ne!(planned.digest, found.digest, "the bytes did");
    assert!(!planned.matches(&found), "so it is a different executable");
}

// ---------------------------------------------------------------- symlinks

/// `/usr/bin/npm` is a symlink on every package-manager-built system. A
/// resolver that refuses symlinks cannot resolve a tool on a real machine, so
/// this row is the reason the fingerprint policy's blanket refusal is not
/// reused here.
#[test]
fn a_symlink_resolves_to_the_file_that_would_actually_run() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let bin = tmp.path().join("bin");
    let lib = tmp.path().join("lib");
    std::fs::create_dir(&bin).expect("mkdir");
    std::fs::create_dir(&lib).expect("mkdir");

    let real = write_tool(&lib, "npm-cli.js", "#!/usr/bin/env node\n", 0o755);
    std::os::unix::fs::symlink(&real, bin.join("npm")).expect("symlink");

    let path = path_of(&[&bin]);
    let resolution = resolve_tool("npm", &path).expect("resolves");
    let identity = resolution
        .resolved
        .as_ref()
        .expect("a symlink is not a refusal");

    // The identity names the file that runs, not the link's spelling. A receipt
    // printing `/usr/bin/npm` would name a symlink, and the operator reading
    // it would have no way to tell which bytes those were.
    assert_eq!(identity.path, real.canonicalize().expect("real"));
    assert_ne!(
        identity.path,
        bin.join("npm"),
        "the reported path is the resolved file, not the link as it sat on PATH"
    );
}

/// A symlink aimed somewhere else entirely is the PATH hijack wearing a
/// disguise. Resolving it does not make it acceptable: the resolved path is
/// *different from where the operator expected*, which is the drift the plan
/// binding refuses.
#[test]
fn a_symlink_pointing_elsewhere_resolves_to_its_target_and_is_visible() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let bin = tmp.path().join("bin");
    let attacker = tmp.path().join("attacker");
    std::fs::create_dir(&bin).expect("mkdir");
    std::fs::create_dir(&attacker).expect("mkdir");

    let evil = write_tool(&attacker, "npm", "not npm", 0o755);
    std::os::unix::fs::symlink(&evil, bin.join("npm")).expect("symlink");

    let resolution = resolve_tool("npm", &path_of(&[&bin])).expect("resolves");
    let identity = resolution.resolved.expect("resolved");
    assert_eq!(
        identity.path,
        attacker.join("npm").canonicalize().expect("real"),
        "the report must show where the link actually landed"
    );
}

// --------------------------------------------------------------- refusals

/// An executable other people can replace is not the executable that was
/// planned. This is the refusal the whole module exists to make, and it is
/// checked **before** hashing rather than reported afterwards.
#[test]
fn an_executable_writable_by_group_or_other_is_refused() {
    for (mode, label) in [(0o777, "world-writable"), (0o775, "group-writable")] {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path().join("bin");
        std::fs::create_dir(&dir).expect("mkdir");
        write_tool(&dir, "npm", "hijackable", mode);

        let resolution = resolve_tool("npm", &path_of(&[&dir])).expect("search completes");
        assert!(
            resolution.resolved.is_none(),
            "{label} executable must not resolve"
        );
        assert!(
            matches!(
                resolution.candidates[0].outcome,
                CandidateOutcome::UntrustedWritable { .. }
            ),
            "{label}: {:?}",
            resolution.candidates[0].outcome
        );
    }
}

/// A world-readable executable is ordinary — every `/usr/bin` binary is — so
/// the refusal must be about *writing*, not reading. A policy that got this
/// backwards would resolve nothing on a normal machine.
#[test]
fn a_world_readable_executable_is_not_refused() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    write_tool(&dir, "npm", "ordinary", 0o755);

    let resolution = resolve_tool("npm", &path_of(&[&dir])).expect("search completes");
    assert!(resolution.resolved.is_some(), "0o755 must resolve");
}

/// A directory is not a tool, and a fifo is not a file whose bytes can be
/// hashed. Both resolve to nothing rather than to a hang or a partial digest.
#[test]
fn something_that_is_not_a_regular_file_does_not_resolve() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    std::fs::create_dir(dir.join("npm")).expect("mkdir");

    let resolution = resolve_tool("npm", &path_of(&[&dir])).expect("search completes");
    assert!(resolution.resolved.is_none());
    assert!(
        matches!(
            resolution.candidates[0].outcome,
            CandidateOutcome::NotARegularFile { .. }
        ),
        "{:?}",
        resolution.candidates[0].outcome
    );
}

/// A dangling symlink is not the same fact as "that directory had nothing",
/// and a report that conflated them would hide a broken install behind a
/// clean-looking search.
#[test]
fn a_dangling_symlink_is_unreadable_rather_than_absent() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let bin = tmp.path().join("bin");
    std::fs::create_dir(&bin).expect("mkdir");
    std::os::unix::fs::symlink(tmp.path().join("gone"), bin.join("npm")).expect("symlink");

    let resolution = resolve_tool("npm", &path_of(&[&bin])).expect("search completes");
    assert!(resolution.resolved.is_none());
    assert!(
        matches!(
            resolution.candidates[0].outcome,
            CandidateOutcome::Unreadable { .. }
        ),
        "a link to nothing is not the same as no link: {:?}",
        resolution.candidates[0].outcome
    );
}

/// A dead directory on `PATH` is ordinary — everybody has one — so it must not
/// stop the search.
#[test]
fn a_dead_directory_is_skipped_and_the_search_continues() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let live = tmp.path().join("live");
    std::fs::create_dir(&live).expect("mkdir");
    write_tool(&live, "npm", "found", 0o755);
    let dead = tmp.path().join("dead");

    let resolution = resolve_tool("npm", &path_of(&[&dead, &live])).expect("search completes");
    assert!(resolution.resolved.is_some(), "the search must continue");
    assert_eq!(
        resolution.candidates.len(),
        2,
        "both directories are reported"
    );
    assert_eq!(resolution.candidates[0].outcome, CandidateOutcome::Absent);
}

/// Not found anywhere is a refusal, and an empty `PATH` is a refusal too.
#[test]
fn a_command_that_is_nowhere_resolves_to_nothing() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let resolution = resolve_tool("npm", &path_of(&[tmp.path()])).expect("search completes");
    assert!(resolution.resolved.is_none());
    assert_eq!(resolution.candidates[0].outcome, CandidateOutcome::Absent);

    assert!(resolve_tool("npm", "")
        .expect("search completes")
        .resolved
        .is_none());
    assert!(matches!(
        resolve_tool("", "/usr/bin").expect_err("no command"),
        ToolResolveError::NoCommand
    ));
}

/// A command name is a name, so an empty one has nothing to look for.
#[test]
fn an_empty_command_is_refused_before_any_io() {
    assert!(matches!(
        resolve_tool("", "/usr/bin:/bin").expect_err("refused"),
        ToolResolveError::NoCommand
    ));
}

// --------------------------------------------------------------- reporting

/// The law of this crate: a report that cannot be wrong. The `PATH` that was
/// searched has to be in the report verbatim, because a resolution that cannot
/// be re-run because it does not say how it searched is not evidence.
#[test]
fn the_report_names_the_path_it_searched_and_the_command_it_was_asked_for() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    write_tool(&dir, "npm", "x", 0o755);

    let path = path_of(&[&dir]);
    let resolution = resolve_tool("npm", &path).expect("resolves");
    assert_eq!(resolution.command, "npm");
    assert_eq!(resolution.path, path);
    assert_eq!(resolution.candidates[0].directory, dir);
    assert_eq!(resolution.candidates[0].candidate, dir.join("npm"));
}

/// Every candidate is reported in the order consulted, so a reader can see
/// which directory would have won and what stood between it and the answer.
#[test]
fn every_consulted_directory_is_reported_in_order() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let c = tmp.path().join("c");
    for d in [&a, &b, &c] {
        std::fs::create_dir(d).expect("mkdir");
    }
    write_tool(&b, "npm", "hijack", 0o777); // refused
    write_tool(&c, "npm", "real", 0o755); // chosen

    let resolution = resolve_tool("npm", &path_of(&[&a, &b, &c])).expect("search completes");
    assert_eq!(resolution.candidates.len(), 3);
    assert_eq!(resolution.candidates[0].directory, a);
    assert!(matches!(
        resolution.candidates[1].outcome,
        CandidateOutcome::UntrustedWritable { .. }
    ));
    assert!(matches!(
        resolution.candidates[2].outcome,
        CandidateOutcome::Chosen { .. }
    ));
}

/// A refused candidate does **not** stop the search. Refusing to resolve a
/// tool because some earlier `PATH` entry held a world-writable copy would make
/// the module useless on the machines it exists to protect — the whole point
/// is to *report* the hijack, not to shrug and find nothing.
#[test]
fn a_refused_candidate_does_not_stop_the_search() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).expect("mkdir");
    std::fs::create_dir(&b).expect("mkdir");
    write_tool(&a, "npm", "hijack", 0o777);
    write_tool(&b, "npm", "real", 0o755);

    let resolution = resolve_tool("npm", &path_of(&[&a, &b])).expect("search completes");
    assert!(
        resolution.resolved.is_some(),
        "the search must continue past a refusal"
    );
    assert_eq!(resolution.resolved.expect("found").path, b.join("npm"));
}

/// An empty entry in `PATH` means the current directory, to every tool that
/// reads it. Honouring it as an empty directory instead would be a resolver
/// that quietly searches somewhere the shell does not.
#[test]
fn an_empty_path_entry_means_the_current_directory() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    write_tool(tmp.path(), "npm", "cwd", 0o755);

    let resolution = resolve_tool("npm", &format!(":{}", tmp.path().display())).expect("resolves");
    assert_eq!(resolution.candidates[0].directory, PathBuf::from("."));
    assert_eq!(resolution.candidates[0].outcome, CandidateOutcome::Absent);
    assert!(resolution.resolved.is_some(), "the second entry still runs");
}

// -------------------------------------------------------------- round trip

/// The resolution travels into a receipt and back out of it, so it has to
/// survive JSON. A report that only serialises in one direction is a report a
/// reader of the receipt cannot use.
#[test]
fn a_resolution_round_trips_through_json() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    write_tool(&dir, "npm", "round trip", 0o755);

    let resolution = resolve_tool("npm", &path_of(&[&dir])).expect("resolves");
    let json = serde_json::to_string(&resolution).expect("serialises");
    let back: ToolResolution = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, resolution);
    assert_eq!(back.resolved, resolution.resolved);
}

/// The identity this module produces must be one the domain accepts, because
/// that is what a plan binds to. A digest the resolver emits and the domain
/// refuses would be a report no plan could use.
#[test]
fn the_identity_this_module_produces_is_one_the_domain_accepts() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    write_tool(&dir, "npm", "domain-check", 0o755);

    let identity = resolve_tool("npm", &path_of(&[&dir]))
        .expect("search completes")
        .resolved
        .expect("found");
    let rebuilt =
        asv_domain::ToolIdentity::new(identity.path.clone(), identity.digest.clone()).expect("ok");
    assert_eq!(rebuilt, identity);
}

/// Hashing is streamed, so the digest of a file larger than the read buffer is
/// still the digest of the whole file. A row with a small file could not tell
/// an implementation that hashed only the first chunk from one that did not.
#[test]
fn a_file_larger_than_the_read_buffer_is_hashed_whole() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");

    let body = "npm".repeat(HASH_CHUNK * 3);
    write_tool(&dir, "npm", &body, 0o755);

    let identity = resolve_tool("npm", &path_of(&[&dir]))
        .expect("search completes")
        .resolved
        .expect("found");
    assert_eq!(identity.digest, sha256_of(body.as_bytes()));
}

/// The size cap is a refusal rather than a truncation, because a digest of the
/// first N bytes is a digest of something that is not the file — and an
/// implementation that hashed a prefix would compare it against a full-file
/// digest and never match, which is a bug that looks like drift.
///
/// Exercised through the bounded entry point rather than by allocating 512 MiB,
/// and the two sides of the boundary are checked separately so an off-by-one
/// that admitted everything above the limit would be caught.
#[test]
fn the_size_cap_is_a_refusal_and_not_a_truncation() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let dir = tmp.path().join("bin");
    std::fs::create_dir(&dir).expect("mkdir");
    let body = "x".repeat(4096);
    write_tool(&dir, "npm", &body, 0o755);
    let path = path_of(&[&dir]);

    // At the limit: resolved, and the digest is of the *whole* file.
    let at = resolve_tool_bounded("npm", &path, body.len() as u64).expect("search completes");
    assert_eq!(
        at.resolved.expect("at the limit resolves").digest,
        sha256_of(body.as_bytes())
    );

    // One byte under the limit: refused, and named as too large rather than
    // reported as absent or unreadable.
    let over = resolve_tool_bounded("npm", &path, body.len() as u64 - 1).expect("search completes");
    assert!(over.resolved.is_none(), "above the limit must not resolve");
    assert!(
        matches!(
            over.candidates[0].outcome,
            CandidateOutcome::TooLarge { bytes } if bytes == body.len() as u64
        ),
        "the refusal must name the size: {:?}",
        over.candidates[0].outcome
    );

    // And the shipped entry point uses the documented constant.
    assert!(
        MAX_TOOL_BYTES >= 4096,
        "the shipped cap must admit a real tool"
    );
}
