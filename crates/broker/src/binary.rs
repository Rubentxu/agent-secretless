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
fn producing_package(name: &str) -> Option<&'static [&'static str]> {
    match name {
        // `asv` comes from `asv-cli`. This is the one that bit.
        //
        // **Every crate it is built from, not just the one that owns the
        // binary.** This used to return `Some("cli")` and check
        // `crates/cli/src` alone, which is a guard that says nothing about the
        // code most of the verticals are actually measuring: `asv` spends most
        // of its time in `asv-integrations`, and a change to
        // `crates/integrations/src/execute.rs` left the binary stale with
        // nothing to say so.
        //
        // Found by a falsification mutation that came back green: `decide`
        // was rewritten to refuse every permitted execution, and a vertical
        // asserting `outcome == "executed"` stayed green because the binary it
        // spawned predated the mutation. The row was not weak — the program it
        // measured did not contain the change.
        //
        // The list is a plain literal rather than a read of the dependency
        // graph because the dependency graph is not available here and a
        // conservative over-approximation is what a freshness guard wants: an
        // extra crate listed costs a panic when it is genuinely newer, and a
        // missing one costs a vertical silently measuring the wrong program.
        "asv" => Some(&["cli", "domain", "integrations", "ipc-protocol"]),
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

    if let Some(packages) = producing_package(name) {
        for package in packages {
            assert_not_stale(&binary, name, package);
        }
    }
    binary
}

/// The same search the ten per-file copies performed, kept here so that fixing
/// it fixes all of them.
///
/// **No environment is read**, which is a rule rather than a preference: D9 and
/// `uat_017_env_scan` forbid `std::env::var*` in the broker's sources, because
/// every such read is a candidate anonymous fallback that bypasses the vault.
/// The first version of this function read `CARGO_TARGET_DIR`, and the guard
/// caught it — correctly, and a day earlier than a reviewer would have.
///
/// The first candidate is also the one that works: cargo puts an integration
/// test in `<target>/<profile>/deps/` and the workspace binaries in
/// `<target>/<profile>/`, so two levels up from the running test binary is the
/// directory that holds them, whatever `CARGO_TARGET_DIR` happens to be. The
/// second candidate is for a test binary run from somewhere unusual, and it
/// derives from a compile-time constant rather than from the environment.
fn find(name: &str) -> Option<PathBuf> {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.join(name));
            }
        }
    }
    candidates.push(crate_root().join("target").join(profile).join(name));
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
         Note which crate is named: it is not always `asv-cli`'s own sources, \
         because the binary is built from all of them.\n\
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

/// A timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// **The date is not decoration.** This string exists to be read by someone
/// who has just been told their measurement is invalid, and the first question
/// is always how stale. `HH:MM:SS` alone cannot answer it: a binary built a
/// minute ago and one built the previous afternoon print identically, and the
/// reader is sent to rebuild when the fact worth knowing is that the file in
/// front of them was produced under a different build configuration entirely.
///
/// That is not hypothetical. This message printed `20:12:00 UTC` about a
/// binary from the day before, sitting in a target directory cargo no longer
/// uses, while the sources it was being compared against were hours newer.
/// Nothing in the message said so.
fn humantime(time: SystemTime) -> String {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let clock = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC ({})",
        clock / 3600,
        (clock % 3600) / 60,
        clock % 60,
        age_of(time)
    )
}

/// How long ago `time` was, in the unit that makes it legible: days, hours,
/// minutes, seconds. "5 days old" and "12 minutes old" call for different
/// reactions, and a reader who has to work that out from a clock time is
/// doing arithmetic the message should have done.
fn age_of(time: SystemTime) -> String {
    let Ok(built) = time.duration_since(SystemTime::UNIX_EPOCH) else {
        return "of unknown age".to_string();
    };
    let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
        return "of unknown age".to_string();
    };
    let secs = now.saturating_sub(built).as_secs();
    if secs < 60 {
        return format!("{secs}s old");
    }
    if secs < 3_600 {
        return format!("{}m old", secs / 60);
    }
    if secs < 86_400 {
        return format!("{}h old", secs / 3_600);
    }
    format!("{}d old", secs / 86_400)
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`: exact across the whole range a
/// `SystemTime` can hold, with no lookup table and no dependency. The broker's
/// dependency policy is not a good enough reason to ship a wrong date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The guard watches every crate `asv` is built from, and this row is why
    /// that is a list rather than one name.**
    ///
    /// It returned `Some("cli")` until R4.B.3, which checked `crates/cli/src`
    /// and nothing else — so a change to `crates/integrations/src/execute.rs`,
    /// where most of what a vertical measures actually lives, left the binary
    /// stale with nothing to say so. A falsification mutation that made `decide`
    /// refuse every permitted execution came back **green** on a row asserting
    /// `outcome == "executed"`, because the binary that row spawned did not
    /// contain the change.
    ///
    /// The membership assertion is the tripwire, for the reason the `Api`
    /// allowlist row is: a guard that watches a set nothing probes stays green
    /// while the set shrinks. `domain` and `ipc-protocol` are listed for the
    /// same reason `cli` is — they are in the graph, and a conservative
    /// over-approximation costs a panic while an omission costs a vertical
    /// measuring the wrong program.
    #[test]
    fn the_freshness_guard_watches_every_crate_the_client_is_built_from() {
        let watched = producing_package("asv").expect("asv is guarded");
        for crate_name in ["cli", "domain", "integrations", "ipc-protocol"] {
            assert!(
                watched.contains(&crate_name),
                "the freshness guard does not watch crates/{crate_name}/src, so a change \
                 there leaves the `asv` binary stale with nothing to say so. Watched: \
                 {watched:?}"
            );
        }
        // And the one that is not guarded has a reason: cargo has just built it.
        assert_eq!(
            producing_package("asv-brokerd"),
            None,
            "asv-brokerd comes from this package, so there is nothing to check"
        );
    }

    /// **The staleness message says how old the binary is, and this row is
    /// why the date is in it.**
    ///
    /// The message used to render `HH:MM:SS` alone. A binary from the previous
    /// afternoon and one from a minute ago then printed the same string, and
    /// the reader is sent to rebuild either way — so the one fact that would
    /// have saved the diagnosis, that the file in front of them predates the
    /// build configuration cargo is using now, was absent from the sentence
    /// that exists to explain the failure.
    ///
    /// The row renders a timestamp the test chooses, so it cannot pass by
    /// asserting that some digits appear.
    #[test]
    fn the_staleness_message_names_the_date_and_the_age() {
        use std::time::Duration;
        // 2021-01-01T00:00:00Z. A fixed point rather than "now", so the
        // expected prefix is a fact and not a recomputation of this code.
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_609_459_200);
        let rendered = humantime(then);
        assert!(
            rendered.starts_with("2021-01-01 00:00:00 UTC"),
            "the timestamp lost its date, which is the part that says how stale \
             the binary is: {rendered}"
        );
        assert!(
            rendered.ends_with("old)"),
            "the timestamp does not say how old the binary is: {rendered}"
        );
        // The calendar conversion at the boundaries a table gets wrong: the
        // epoch, a leap day, and the century that is not one.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    }

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

    thread_local! {
        /// True only on the thread running a deliberate panic inside
        /// [`catch_panic`], and only for as long as that body is running.
        static DELIBERATE_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn silence_deliberate_panics() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if !DELIBERATE_PANIC.with(std::cell::Cell::get) {
                    previous(info);
                }
            }));
        });
    }

    /// Runs `body` and returns the message it panicked with, or `None` if it did
    /// not panic.
    ///
    /// **The deliberate panic is silenced per thread, not process-wide.** The
    /// first version took the default hook, installed a no-op, and restored the
    /// saved hook on the way out. The panic hook is global to the process and
    /// `cargo test` runs every test in this binary on its own thread, so two
    /// guards overlap by default: the second one saves the *first's* silence and
    /// restores that on its way out, and the process finishes with a hook that
    /// swallows every later panic. With two guards in this module that was the
    /// normal case rather than a corner one.
    ///
    /// The symptom is not a wrong answer. It is a **failing test that prints no
    /// reason at all**, which is the one thing a falsification campaign cannot
    /// tell apart from a mutation that was not caught: `relay_loop` reported four
    /// of its rows as "red, but not for the expected reason" when the named
    /// assertion had in fact fired.
    ///
    /// So the hook is installed once and forwards everything that is not a
    /// deliberate panic on a guarded thread. A real failure elsewhere still
    /// prints, and there is no restore step left to lose.
    fn catch_panic<F: FnOnce() + std::panic::UnwindSafe>(body: F) -> Option<String> {
        silence_deliberate_panics();
        let outcome = DELIBERATE_PANIC.with(|deliberate| {
            deliberate.set(true);
            let outcome = std::panic::catch_unwind(body);
            deliberate.set(false);
            outcome
        });
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
