//! Test helpers shared across the CLI's modules.
//!
//! Compiled only under `cfg(test)`: nothing here is reachable from the
//! binary, and test scaffolding linked into a shipped artifact is surface
//! nobody reviewed.

#![cfg(test)]

//! test possible at all. Rust runs a test binary's tests on several threads,
//! so those tests have to be serialised against each other. This is where the
//! lock lives, because `layout` and `doctor` both need it and two locks would
//! not exclude each other.

use std::sync::Mutex;

/// The thread currently allowed to touch the environment.
///
/// # Why this is not a plain `Mutex`
///
/// It started as one, and a test that calls [`with_env`] from inside another
/// [`with_env`] deadlocked: `std::sync::Mutex` is not reentrant, so the inner
/// call waited for a lock its own thread already held, and the suite hung
/// silently — no panic, no output, a process parked in `futex_do_wait`.
///
/// That is worth more than a comment. The first version of this file looked
/// like it could not deadlock, because a `Mutex` looks like the answer, and
/// the nesting was invisible at the call site: the outer `with_env` was 400
/// lines above the inner one and in a different test.
///
/// So the guard is reentrant by depth count, and `nesting_with_env_does_not_
/// deadlock` is the assertion — a deadlock cannot be caught by a test, only
/// prevented, so the test that matters is the one that finishes.
static ENV_OWNER: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

thread_local! {
    /// How many `with_env` frames this thread is inside. Zero means it does
    /// not hold the environment.
    static ENV_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Blocks until this thread owns the environment, reentrantly.
fn acquire() {
    let me = std::thread::current().id();
    let already_held = ENV_DEPTH.with(|d| d.get() > 0);
    if already_held {
        ENV_DEPTH.with(|d| d.set(d.get() + 1));
        return;
    }

    let mut owner = ENV_OWNER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Spin rather than block: the wait is bounded by the shortest environment
    // scope in the suite, which is a few milliseconds, and a `Condvar` would
    // be a second synchronisation primitive to get wrong in a test helper.
    while *owner != Some(me) && owner.is_some() {
        drop(owner);
        std::thread::sleep(std::time::Duration::from_millis(1));
        owner = ENV_OWNER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    *owner = Some(me);
    ENV_DEPTH.with(|d| d.set(1));
}

fn release() {
    let depth = ENV_DEPTH.with(|d| {
        let next = d.get().saturating_sub(1);
        d.set(next);
        next
    });
    if depth > 0 {
        return;
    }
    ENV_OWNER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
}

/// Sets environment variables for the duration of `f`, then restores them.
///
/// Restore is unconditional and runs even if `f` panics, because a leaked
/// `HOME` or `PATH` would make an unrelated test fail later with a message
/// that points nowhere near the cause.
///
/// Reentrant: nesting is a depth count, not a second acquisition. See
/// [`ENV_OWNER`].
pub fn with_env<T>(vars: &[(&str, &std::ffi::OsStr)], f: impl FnOnce() -> T) -> T {
    acquire();
    let _depth = DepthGuard;

    let saved: Vec<(&str, Option<std::ffi::OsString>)> = vars
        .iter()
        .map(|(k, _)| (*k, std::env::var_os(k)))
        .collect();

    for (key, value) in vars {
        std::env::set_var(key, value);
    }

    let out = f();

    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    out
}

/// Releases the environment however the frame exits, including a panic.
struct DepthGuard;

impl Drop for DepthGuard {
    fn drop(&mut self) {
        release();
    }
}

/// A directory under the system temp dir that removes itself when dropped.
///
/// `/tmp` is wiped between runs, so nothing here is expected to outlive the
/// test that made it, and there is no cleanup step that can be forgotten.
pub struct TempTree {
    pub path: std::path::PathBuf,
}

impl TempTree {
    pub fn new(label: &str) -> Self {
        Self::at(std::env::temp_dir(), label)
    }

    /// A tree rooted inside `base`, for tests that need the clean-HOME
    /// variables to point at it.
    pub fn at(base: impl AsRef<std::path::Path>, label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_nanos();
        let path = base
            .as_ref()
            .join(format!("asv-{label}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path).expect("can create a temp tree");
        Self { path }
    }

    pub fn sub(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Writes an executable file, the way an installer would.
pub fn write_executable(path: &std::path::Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("can create the parent directory");
    }
    std::fs::write(path, contents).expect("can write the file");
    let mut perms = std::fs::metadata(path)
        .expect("can stat what was written")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("can set the mode");
}

/// Writes a plain file with an explicit mode, for permission assertions.
pub fn write_with_mode(path: &std::path::Path, contents: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("can create the parent directory");
    }
    std::fs::write(path, contents).expect("can write the file");
    let mut perms = std::fs::metadata(path)
        .expect("can stat what was written")
        .permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).expect("can set the mode");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nesting `with_env` has to work.
    ///
    /// A deadlock cannot be caught by a test — the test hangs with it. So the
    /// assertion is only that this returns at all, and the guard against
    /// reintroducing it is that the call exists in the suite: with a
    /// non-reentrant lock it hangs, and a hanging test is louder than a
    /// failing one even if it is harder to read.
    ///
    /// The nesting is real, not hypothetical: `setup::tests` nests a
    /// `with_env` inside `in_a_clean_install`, because a test that moves the
    /// bundle has to change the resolution from inside a clean install.
    #[test]
    fn nesting_with_env_does_not_deadlock() {
        let value = with_env(
            &[("ASV_NESTING_PROBE", std::ffi::OsStr::new("outer"))],
            || {
                assert_eq!(
                    std::env::var("ASV_NESTING_PROBE").as_deref(),
                    Ok("outer"),
                    "the outer scope did not take effect"
                );
                let inner = with_env(
                    &[("ASV_NESTING_PROBE", std::ffi::OsStr::new("inner"))],
                    || std::env::var("ASV_NESTING_PROBE").expect("the inner scope took effect"),
                );

                // Read here, *inside* the outer scope. The first version of
                // this test read it after the outer scope had closed, and
                // asserted the outer value was still set — which is not a
                // reentrancy property at all, it is an assertion that a
                // closed scope leaves its variable behind. It failed, and it
                // should have: a leaked `HOME` breaks the next test in a way
                // that points nowhere near the cause.
                assert_eq!(inner, "inner");
                assert_eq!(
                    std::env::var("ASV_NESTING_PROBE").as_deref(),
                    Ok("outer"),
                    "leaving the inner scope did not restore the outer value"
                );
                inner
            },
        );
        assert_eq!(value, "inner");
    }

    /// The variable is gone entirely once both scopes close.
    #[test]
    fn the_environment_is_restored_after_nesting() {
        // A different variable from the test above. Two tests that both set
        // one and run on different threads still collide: the lock serialises
        // the scopes, not the assertions that run after them, and a
        // `remove_var` in one test reaches straight into the other's scope.
        // That collision is not hypothetical — it is the second thing this
        // file got wrong, right after the deadlock.
        with_env(
            &[("ASV_NESTING_PROBE_2", std::ffi::OsStr::new("a"))],
            || with_env(&[("ASV_NESTING_PROBE_2", std::ffi::OsStr::new("b"))], || {}),
        );
        assert!(
            std::env::var_os("ASV_NESTING_PROBE_2").is_none(),
            "the probe variable outlived the scopes that set it"
        );
    }
}
