//! Where a test finds a binary, and why it is allowed to refuse one.
//!
//! ## The failure this exists to make impossible
//!
//! Ten integration tests in this package drive `asv`, the CLI, which belongs to
//! **another** package. Cargo builds the binaries of the package under test, so
//! `asv-brokerd` is always current for these tests. Cargo does not build the
//! binaries of a package a test merely *invokes*, so `asv` is whatever happens
//! to be on disk.
//!
//! That is not theoretical. A full workspace run reported eight failures in
//! `connect_vertical_e2e`: the tunnel never completed, curl answered `000`, and
//! every message pointed at the CONNECT proxy. The `asv` binary was eight hours
//! older than the protocol change it was being measured against, and the broker
//! beside it was freshly built. Rebuilding the workspace turned the same eight
//! failures into ten passes with no code change at all.
//!
//! The cost of that failure mode is not the rebuild. It is that a stale
//! fixture produces a message that reads exactly like a real defect, and an
//! agent that trusts the message goes looking for a regression that does not
//! exist.
//!
//! ## Why not `CARGO_BIN_EXE_*`
//!
//! Cargo sets `CARGO_BIN_EXE_<name>` for integration tests of the package that
//! **produces** the binary. It is the right mechanism and it does not apply
//! here: these tests live in `asv-broker` and want `asv`, which `asv-cli`
//! produces. Cargo sets no environment variable for it, which is the same fact
//! as "cargo did not build it".
//!
//! ## What the check is, and what it is not
//!
//! A modification time is a weak signal and this is a narrow use of it. It says
//! "this binary predates a source file of the package that builds it", which is
//! a sufficient condition for "this binary does not contain that change". It is
//! not a proof of staleness in the other direction: a binary can be newer than
//! every source and still be the wrong one, and a fresh git checkout makes
//! every source newer than every binary until something is built. Both of those
//! cases are handled by the remedy the message gives, which is to build.
//!
//! What it is not allowed to become is a check that passes a broken fixture.
//! A test that cannot refuse is a test that cannot measure.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The package that produces each binary a test in this package may ask for.
///
/// Explicit rather than derived: the whole point is to know which sources a
/// given binary is supposed to contain, and a convention inferred from a name
/// would be wrong the first time a binary is renamed.
fn producing_package(name: &str) -> Option<&'static str> {
    match name {
        // `asv` comes from `asv-cli`. This is the one that bit.
        "asv" => Some("cli"),
        // `asv-brokerd` comes from this package, so cargo has just built it and
        // there is nothing to check.
        "asv-brokerd" => None,
        _ => None,
    }
}

/// Finds `name` in the target directory, and refuses one that is older than the
/// sources of the package that produces it.
///
/// # Panics
///
/// When the binary cannot be found, or when it is older than the sources of its
/// package. Both messages name the command that fixes them, because a test that
/// ends on "could not locate asv" sends the reader back to the same place twice.
pub fn locate(name: &str) -> PathBuf {
    let binary = find(name).unwrap_or_else(|| {
        panic!(
            "could not locate the {name} binary.\n\
             Build the whole workspace first: `cargo build --workspace`. \
             A test that invokes a binary of another package depends on it \
             existing, and cargo does not build those for you."
        )
    });

    if let Some(package) = producing_package(name) {
        assert_not_stale(&binary, name, package);
    }
    binary
}

/// The same search the ten per-file copies performed, kept here so that fixing
/// it fixes all of them.
fn find(name: &str) -> Option<PathBuf> {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    // Beside the test binary is the most reliable answer: cargo puts a package's
    // binaries in the profile directory the test binary's `deps` lives in.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.join(name));
            }
        }
    }
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(dir).join(profile).join(name));
    }
    candidates.push(PathBuf::from("target").join(profile).join(name));
    candidates.into_iter().find(|p| p.exists())
}

/// Panics with a message that names the remedy when `binary` predates the
/// newest source file of `package`.
fn assert_not_stale(binary: &Path, name: &str, package: &str) {
    let Some(built) = modified(binary) else {
        // No readable timestamp: say so rather than guessing, because a
        // freshness check that silently passes when it cannot run is the same
        // defect in the opposite direction.
        panic!(
            "cannot read the modification time of {}, so this client cannot \
             tell whether it is current.\n\
             Rebuild with `cargo build --workspace`.",
            binary.display()
        );
    };
    let sources = crate_root().join("crates").join(package).join("src");
    let Some(newest) = newest_source(&sources) else {
        return;
    };
    if built >= newest.0 {
        return;
    }
    panic!(
        "the {name} binary at {} was built at {}, and {} is newer than it.\n\
         That binary does not contain that change, and a test that measures it \
         is measuring the wrong program. This is what eight `connect_vertical_e2e` \
         failures looked like once: curl answered 000 and every message pointed \
         at the tunnel.\n\
         Run `cargo build --workspace` and try again. If the binary is current \
         and this still fires, then a source file was touched without being \
         built, and that is worth saying out loud.",
        binary.display(),
        humantime(built),
        newest.1.display(),
    );
}

/// The repository root, derived from this file's location at compile time.
fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

/// The newest `.rs` file under `dir`, with its path.
fn newest_source(dir: &Path) -> Option<(SystemTime, PathBuf)> {
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Some(time) = modified(&path) {
                    let newer = match &newest {
                        None => true,
                        Some((best, _)) => time > *best,
                    };
                    if newer {
                        newest = Some((time, path));
                    }
                }
            }
        }
    }
    newest
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// A timestamp as `HH:MM:SS`, which is the resolution that makes "eight hours
/// older" legible at a glance.
fn humantime(time: SystemTime) -> String {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let clock = seconds % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        clock / 3600,
        (clock % 3600) / 60,
        clock % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The locator finds the binary that cargo just built for this package.
    #[test]
    fn it_finds_a_binary_of_this_package() {
        let found = locate("asv-brokerd");
        assert!(found.is_file(), "{} is not a file", found.display());
    }

    /// **The check this module exists for.** A binary deliberately made older
    /// than its package's sources is refused, and the message says what to do.
    ///
    /// The mutation is on a file this test creates, so it cannot leave the tree
    /// modified.
    #[test]
    fn a_binary_older_than_its_sources_is_refused() {
        let dir = std::env::temp_dir().join(format!("asv-binary-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the fixture dir");
        let binary = dir.join("asv");
        std::fs::write(&binary, b"not really the CLI").expect("write the fixture binary");
        let now = SystemTime::now();
        set_modified(
            &binary,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
        );

        // The panic is the assertion, and its payload is half of it: a refusal
        // that does not say what to do sends the reader back to the same place
        // they just left.
        let refusal = catch_panic(|| {
            assert_not_stale(&binary, "asv", "cli");
        });
        assert!(
            refusal.is_some(),
            "a binary from 1970 was accepted as current; the freshness check is \
             not running and every e2e in this package is measuring whatever \
             happens to be on disk"
        );
        let message = refusal.expect("checked above");
        assert!(
            message.contains("cargo build --workspace"),
            "the refusal does not name the remedy: {message}"
        );
        assert!(
            message.contains("asv"),
            "the refusal does not name the binary it refused: {message}"
        );

        set_modified(&binary, now);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A binary newer than its sources is accepted. Without this the check could
    /// pass by refusing everything, which is not the same as being right.
    #[test]
    fn a_binary_newer_than_its_sources_is_accepted() {
        let dir = std::env::temp_dir().join(format!("asv-binary-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the fixture dir");
        let binary = dir.join("asv");
        std::fs::write(&binary, b"current").expect("write the fixture binary");
        let accepted = catch_panic(|| {
            assert_not_stale(&binary, "asv", "cli");
        });
        assert!(
            accepted.is_none(),
            "a binary written a moment ago was refused: {}",
            accepted.unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Runs `body` with the default panic hook silenced and returns the message
    /// it panicked with, or `None` if it did not panic.
    ///
    /// The hook has to go, or every one of these runs prints a backtrace to the
    /// test output for a panic the test is asking for on purpose.
    fn catch_panic<F: FnOnce() + std::panic::UnwindSafe>(body: F) -> Option<String> {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(body);
        std::panic::set_hook(hook);
        match outcome {
            Ok(()) => None,
            Err(payload) => Some(
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "<a payload that was not a string>".to_string()),
            ),
        }
    }

    /// Sets a file's modification time, which is the only way to build a fixture
    /// that is genuinely older than a source rather than merely written first.
    fn set_modified(path: &Path, time: SystemTime) {
        let seconds = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time after the epoch")
            .as_secs() as i64;
        let c =
            std::ffi::CString::new(path.to_string_lossy().as_bytes()).expect("path without a NUL");
        // Both fields are spelled out so the fixture is exactly as old as it
        // claims to be, rather than "now" on one side and the epoch on the other.
        let times = [
            libc::timespec {
                tv_sec: seconds,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: seconds,
                tv_nsec: 0,
            },
        ];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "could not set the fixture's timestamp");
    }
}
