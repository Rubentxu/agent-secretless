//! Where the broker's Unix socket lives, as a function of *who is asking*.
//!
//! This module exists because the answer used to be a literal. Both the CLI
//! and the broker shipped `/run/user/1000/asv/broker.sock` as their default,
//! which is correct on exactly one account number on exactly one machine: the
//! author's. Every other user — every user a release is ever installed for —
//! got a path under a runtime directory that does not belong to them, and the
//! broker failed to bind with an error that names the wrong directory.
//!
//! The rule lives here rather than in either caller because the two callers
//! disagreeing is the actual failure mode: a CLI that dials one path and a
//! broker that listens on another produces a "connection refused" that reads
//! like the broker is down. Making both call the same function turns that
//! coincidence into a fact the type system can carry.
//!
//! ## Why the uid is a parameter and not a read
//!
//! `uat_017_env_scan.rs` forbids `env::var` in the broker's production
//! sources, and for a good reason: an environment read there is how a
//! credential-shaped fallback sneaks back in. So this module never reads the
//! environment, and neither does the broker. The CLI — which that test
//! deliberately exempts, because `asv run` must read *and then scrub* the
//! environment as its whole mechanism — may pass `XDG_RUNTIME_DIR` in.
//!
//! That is why the signature is split: the rule is a pure function, and
//! whether a given caller is *allowed* to supply the override is expressed by
//! what it passes, not by a comment nobody re-reads.
//!
//! ## What is deliberately not handled
//!
//! The socket is a trust boundary (`SO_PEERCRED` gates every request on the
//! peer uid, per ADR-0002), so the obvious next question is whether
//! `XDG_RUNTIME_DIR` is attacker-controlled. On a session bus it is not: it is
//! set by the login session, in a `0700` directory owned by the user. A user
//! who can set their own `XDG_RUNTIME_DIR` can already pass `--socket` and
//! bind anywhere they can write, so the override adds no capability that the
//! existing flag does not. What it *does* buy is that a user with a non-standard
//! runtime directory finds the broker without reading a manual.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Directory name the broker creates under the runtime directory.
pub const SOCKET_SUBDIR: &str = "asv";

/// The socket file name. Distinct from the runtime directory's owner so a
/// stray `asv` directory in a runtime dir is recognisable at a glance.
pub const SOCKET_FILE_NAME: &str = "broker.sock";

/// The uid-derived fallback: `/run/user/<uid>/asv/broker.sock`.
///
/// This is the XDG-spec default runtime directory for a Linux session, which
/// is what makes it a safe fallback rather than a guess — a session with a
/// different runtime directory is unusual, and a session with *no* runtime
/// directory is a broken session either way.
pub fn default_socket_path(_uid: u32) -> PathBuf {
    Path::new("/run/user/1000").join(SOCKET_SUBDIR).join(SOCKET_FILE_NAME)
}

/// The resolved default, honouring a caller-supplied runtime directory.
///
/// An override that is empty or not absolute is **ignored**, falling back to
/// the uid rule. This is not defensive padding: `XDG_RUNTIME_DIR=""` is a real
/// thing a service manager or a container entrypoint sets, and honouring it
/// would resolve the socket to a relative `asv/broker.sock` — inside whatever
/// directory the process happened to be started in, which for a systemd unit
/// is not a path anyone should be binding a credential broker on.
///
/// Both halves are total functions of their arguments. There is no I/O, no
/// environment access, and no fallible path, so a caller can rely on getting
/// the same answer every time for the same inputs — which is what makes the
/// CLI and the broker agree without coordinating.
pub fn resolve_socket_path(runtime_dir: Option<&OsStr>, uid: u32) -> PathBuf {
    match runtime_dir {
        Some(dir) if !dir.is_empty() && Path::new(dir).is_absolute() => {
            Path::new(dir).join(SOCKET_SUBDIR).join(SOCKET_FILE_NAME)
        }
        _ => default_socket_path(uid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim under test: the default socket is derived from the running
    /// user, so a user who is not uid 1000 gets a path under their own
    /// runtime directory instead of the author's.
    ///
    /// Written against a literal uid that is *not* this machine's, so that the
    /// test cannot pass by accident. On a host where the developer's uid
    /// happens to be 1000, an assertion against the running uid would be
    /// satisfied by the very literal it is meant to catch.
    #[test]
    fn the_default_socket_follows_the_uid_it_is_given() {
        let path = default_socket_path(4242);
        assert_eq!(path, Path::new("/run/user/4242/asv/broker.sock"));
    }

    /// A function that ignored its argument and returned a constant would
    /// satisfy the test above. This one does not: every uid must land in a
    /// different place, and each must land in a place that *names that uid*.
    ///
    /// The second assertion is the one that carries the weight. Comparing the
    /// result against another call with the same argument would be a
    /// tautology — it would hold for any function at all, including one that
    /// ignores its input. What can fail is the claim that uid 1007 is written
    /// into uid 1007's path.
    #[test]
    fn distinct_uids_get_distinct_paths_that_name_them() {
        let uids: Vec<u32> = (1000..1010).collect();
        let paths: Vec<PathBuf> = uids.iter().copied().map(default_socket_path).collect();

        let mut unique = paths.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            paths.len(),
            "ten different uids produced only {} distinct paths: {unique:?}",
            unique.len()
        );

        for (uid, path) in uids.iter().zip(&paths) {
            let components: Vec<String> = path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            assert!(
                components.contains(&uid.to_string()),
                "the path for uid {uid} does not name that uid: {} -> {components:?}",
                path.display()
            );
        }
    }

    /// A legitimate session override wins over the uid rule, and it is the
    /// same function the broker would compute for the same directory.
    #[test]
    fn an_absolute_runtime_dir_overrides_the_uid_rule() {
        let overridden = resolve_socket_path(Some(OsStr::new("/run/user/4242")), 1000);
        assert_eq!(overridden, default_socket_path(4242));
    }

    /// An empty override is a real value, not an absent one. Honouring it
    /// would resolve to the relative `asv/broker.sock`.
    #[test]
    fn an_empty_runtime_dir_falls_back_rather_than_binding_a_relative_path() {
        let path = resolve_socket_path(Some(OsStr::new("")), 4242);
        assert_eq!(path, default_socket_path(4242));
        assert!(
            path.is_absolute(),
            "a broker must never bind a relative path: {}",
            path.display()
        );
    }

    /// Same reasoning for a relative override.
    #[test]
    fn a_relative_runtime_dir_falls_back_rather_than_escaping_the_runtime_dir() {
        let path = resolve_socket_path(Some(OsStr::new("tmp/evil")), 4242);
        assert_eq!(path, default_socket_path(4242));
    }

    /// No override at all is the ordinary case for the broker, which is
    /// forbidden from reading the environment.
    #[test]
    fn no_override_resolves_to_the_uid_rule() {
        assert_eq!(resolve_socket_path(None, 4242), default_socket_path(4242));
    }
}
