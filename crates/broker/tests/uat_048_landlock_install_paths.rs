//! UAT-048 — Landlock scopes the operator's declared paths, not whole hierarchies.
//! Landlock ruleset scopes the operator's declared paths, not whole hierarchies.
//!
//! Not a normative UAT: `14-UAT-ADVERSARIAL.md` defines UAT-001..UAT-034 and
//! UAT-048 is not among them. The real anchor is backlog item
//! `bl-bl-01M3PS45V9000387DJAFC0YK00` (P2, m7-seccomp-landlock / verify).
//!
//! Backlog item `bl-bl-01M3PS45V9000387DJAFC0YK00` (P2, m7-seccomp-landlock
//! / verify): the Landlock allow set was a static list of whole hierarchies
//! which included `/home` and `/var/home` in full, read AND write.
use std::io::Write;
use std::path::{Path, PathBuf};

use asv_broker::harden::{self, InstallPaths};

/// Skip loudly when the kernel has no Landlock, and never quietly.
///
/// These four scenarios are the only evidence that the narrowed ruleset
/// both allows what it should and denies what it should. A silent skip
/// would turn a sandbox regression into a green test run, so a skip is
/// reported on stderr and the caller is told the assertions did not run.
fn require_landlock(test: &str) -> bool {
    if harden::landlock_supported() {
        return true;
    }
    eprintln!(
        "SKIPPED {test}: this kernel has no Landlock ABI, so the ruleset \
         assertions did not run. This is an honest gap, not a pass."
    );
    false
}

/// A scratch root that the static system set does NOT already allow.
///
/// This is the whole reason the suite is trustworthy, and getting it
/// wrong is what made `uat_048_undeclared_sibling_is_denied` red.
///
/// `std::env::temp_dir()` is `/tmp` on any host that does not set
/// `TMPDIR`, and `/tmp` is in `STATIC_WRITE_HIERARCHIES`: every process
/// is granted read+write there regardless of what the operator declared.
/// A suite whose scratch lived under it could never observe a denial —
/// the "undeclared" sibling was statically declared all along. The test
/// did not detect a sandbox leak; it contradicted the ruleset, and it
/// has been red since it was born in e59e229.
///
/// The root is anchored at the workspace target directory instead, which
/// is per-checkout, writable, and outside every static hierarchy. The
/// assertion below turns "outside the static set" from an assumption
/// into a checked precondition: if a future change ever widens a static
/// hierarchy over the target directory, this suite fails with that as
/// the stated cause instead of silently becoming vacuous.
fn scratch_root(tag: &str) -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).to_path_buf();
    assert!(
        !harden::statically_allowed(&base),
        "the scratch root {} is inside a static allow-listed hierarchy, so \
         these ruleset assertions would be vacuous: the sandbox already \
         grants it and no denial could ever be observed",
        base.display()
    );
    let dir = base.join(format!("asv-uat048-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch root");
    dir
}

/// Run `body` in a forked child and reap it, returning whether it passed.
///
/// `body` returns `Result<(), String>`; the child exits 0 on Ok and 1 on
/// Err, and the Err text goes to stderr so a failure is diagnosable.
fn child_passes<F>(body: F) -> bool
where
    F: FnOnce() -> Result<(), String>,
{
    // SAFETY: `body` must not capture anything that is unsafe across a
    // fork. These closures only touch paths and the harden API, no
    // threads, no handles opened before the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let code = match body() {
            Ok(()) => 0,
            Err(msg) => {
                let _ = writeln!(std::io::stderr(), "child failed: {msg}");
                1
            }
        };
        std::process::exit(code);
    }
    let mut raw: libc::c_int = 0;
    // SAFETY: `raw` is a valid status word; options 0 blocks until the
    // child is reaped, which is exactly what this test needs.
    let waited = unsafe { libc::waitpid(pid, &mut raw, 0) };
    assert_eq!(waited, pid, "waitpid did not reap the child");
    libc::WIFEXITED(raw) && libc::WEXITSTATUS(raw) == 0
}

fn assert_child_ok(label: &str, body: impl FnOnce() -> Result<(), String>) {
    assert!(
        child_passes(body),
        "{label}: the sandboxed child did not pass its assertions"
    );
}

/// The declared directory stays writable after the ruleset installs.
///
/// This is the regression that matters: if the allow set is too narrow the
/// broker cannot open its own vault, and it fails at runtime in a way that
/// looks like a permissions bug rather than a sandbox bug.
#[test]
fn uat_048_declared_path_is_writable_after_restriction() {
    if !require_landlock("<NAME>") {
        return;
    }
    let root = scratch_root("declared");
    assert_child_ok("declared path writable", move || {
        let data = root.join("vault.bin");
        let paths = InstallPaths::with_write_paths([root.clone()]);
        harden::install_with(paths).map_err(|e| e.to_string())?;
        // Landlock is installed and irreversible at this point. If the
        // declared path had been dropped, this write fails with EACCES.
        std::fs::write(&data, b"sealed").map_err(|e| format!("write to declared path: {e}"))?;
        let back = std::fs::read(&data).map_err(|e| format!("read back: {e}"))?;
        if back != b"sealed" {
            return Err("round-trip mismatch".into());
        }
        Ok(())
    });
}

/// A path the operator did NOT declare is not writable.
///
/// This is the narrowing assertion. Before InstallPaths the whole home
/// hierarchy was writable; now an undeclared sibling directory is denied,
/// which is what makes the ruleset worth having.
#[test]
fn uat_048_undeclared_sibling_is_denied() {
    if !require_landlock("<NAME>") {
        return;
    }
    let base = scratch_root("sibling");
    let allowed = base.join("allowed");
    let denied = base.join("denied");
    std::fs::create_dir_all(&allowed).expect("allowed dir");
    std::fs::create_dir_all(&denied).expect("denied dir");
    assert_child_ok("undeclared path denied", move || {
        let paths = InstallPaths::with_write_paths([allowed.clone()]);
        harden::install_with(paths).map_err(|e| e.to_string())?;
        std::fs::write(allowed.join("ok"), b"x").map_err(|e| format!("allowed write: {e}"))?;
        // The denial is the point. Landlock denies by absence of a rule,
        // so the write must fail; if it ever succeeds the ruleset leaked.
        match std::fs::write(denied.join("nope"), b"x") {
            Ok(()) => Err("undeclared directory was writable".into()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
            Err(e) => Err(format!("unexpected error kind for denial: {e}")),
        }
    });
}

/// A file path is upgraded to its parent directory.
///
/// `--vault` and `--audit-file` name FILES, and Landlock grants rules on
/// directory handles. Passing the file through unchanged would either fail
/// to open or grant nothing, so the parent is used instead. Without this
/// the wiring in main.rs would be decorative.
#[test]
fn uat_048_file_path_uses_its_parent_directory() {
    if !require_landlock("<NAME>") {
        return;
    }
    let dir = scratch_root("filepath");
    let vault = dir.join("vault.asv");
    std::fs::write(&vault, b"envelope").expect("seed vault file");
    assert_child_ok("file path upgrades to parent", move || {
        let paths = InstallPaths::with_write_paths([vault.clone()]);
        harden::install_with(paths).map_err(|e| e.to_string())?;
        // Reading the file that was passed in proves the parent rule
        // applied, since the rule was requested for the file itself.
        let body = std::fs::read(&vault).map_err(|e| format!("read declared file: {e}"))?;
        if body != b"envelope" {
            return Err("declared file content mismatch".into());
        }
        Ok(())
    });
}

/// Declaring a path that does not exist does not widen the ruleset.
///
/// A missing path cannot produce a file descriptor, so no rule is added.
/// The install still succeeds; the path is reported on stderr instead of
/// being silently ignored. Silently widening here would be the worst
/// possible failure mode for a sandbox, so the test pins the narrow
/// behaviour: the rule set is unchanged and the install is not fatal.
#[test]
fn uat_048_missing_path_is_skipped_not_widened() {
    if !require_landlock("<NAME>") {
        return;
    }
    let base = scratch_root("missing");
    let real = base.join("real");
    std::fs::create_dir_all(&real).expect("real dir");
    assert_child_ok("missing path skipped", move || {
        let cfg_paths = InstallPaths::with_write_paths([real.clone(), base.join("does-not-exist")]);
        let cfg = harden::install_with(cfg_paths).map_err(|e| e.to_string())?;
        // The existing declared path still works, so the missing entry did
        // not disturb the rest of the ruleset.
        std::fs::write(real.join("ok"), b"x").map_err(|e| format!("write real: {e}"))?;
        // And the missing directory is still absent, not created and not
        // silently allowed into existence.
        assert!(!base.join("does-not-exist").exists());
        let _ = cfg;
        Ok(())
    });
}
