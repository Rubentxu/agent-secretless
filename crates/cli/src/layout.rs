//! Where an installation keeps its files, and how the private broker is found.
//!
//! # Why the broker is located relative to `asv` and never through `$PATH`
//!
//! `09-IMPLEMENTATION-GUIDE.md` §5 is explicit: "No buscar `asv-brokerd`
//! arbitrariamente en `$PATH` como mecanismo principal." The reason is not
//! tidiness. `asv-brokerd` is the process that holds unlocked vault keys, and
//! `asv setup` is the process that writes the unit that starts it. A lookup
//! that consults `$PATH` lets any directory earlier in the path decide which
//! binary gets to become the credential broker — a directory the user
//! inherited from a shell profile, an npm global prefix, a `go install` bin,
//! or a directory another same-uid process created. The result is a broker
//! that answers the agent socket and holds someone else's keys.
//!
//! So the resolution order is the one in §5, and `$PATH` appears in none of
//! its four steps:
//!
//! 1. an explicit install manifest, when the installer wrote one (DX4);
//! 2. a fixed layout relative to this executable — the channel this build
//!    ships through puts `asv` in `<root>/bin` and the broker in
//!    `<root>/libexec/asv`, which is what `distribution/manifest.toml`
//!    declares;
//! 3. the system package location;
//! 4. an explicit error, never a guess.
//!
//! # Why the env override still checks the owner
//!
//! `ASV_LIBEXEC_DIR` exists so a test can point at a temporary tree. Left
//! unchecked it would also let a caller redirect `setup` at a binary it
//! chose, which is the same attack as the `$PATH` lookup with a shorter
//! reach. So a candidate is only accepted when it is a regular file,
//! executable, **and owned by the uid running `setup`**. The unit `setup`
//! writes will start that binary as a long-lived secret-bearing process; the
//! bar for choosing it is not "somebody pointed at it".

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The private runtime directory name, as declared in
/// `distribution/manifest.toml` (`[layout.user].libexec`).
pub const LIBEXEC_LEAF: &str = "libexec/asv";
/// The private binary's file name.
pub const BROKER_BINARY: &str = "asv-brokerd";

/// Env override for the private runtime directory. Test seam, and the reason
/// the owner check in [`resolve_broker_binary`] exists.
pub const LIBEXEC_ENV: &str = "ASV_LIBEXEC_DIR";

/// The system package location — step 3 of the resolution order.
pub const SYSTEM_LIBEXEC: &str = "/usr/libexec/asv";

/// The set of paths one installation uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub vault: PathBuf,
    pub passphrase: PathBuf,
    pub unit: PathBuf,
    /// Where the private broker was looked for, and whether it was found.
    ///
    /// The whole `BrokerLookup`, not a path. An earlier version cached only
    /// the path and re-ran the lookup where it needed the reason, which put
    /// two sources for one decision in the same function: the precondition
    /// could accept a broker at path A while the unit it then wrote named
    /// path B. They agree in production, because `Layout` is built fresh on
    /// every invocation — and disagreeing only when something unusual
    /// happens is exactly how a bug like that survives review.
    pub broker_lookup: BrokerLookup,
    /// `--socket`, when it was given.
    ///
    /// Only the socket is overridable. A user pointing the CLI at a different
    /// broker is asking about that broker, not asking to be connected to a
    /// different vault, a different passphrase and a different service — so
    /// every other path stays where the installation put it. A `--root` flag
    /// that moved all of them at once would be a much more useful thing to
    /// have and a much more dangerous one.
    pub socket_override: Option<PathBuf>,
}

/// Builds the layout for the invoking user, following the XDG variables the
/// rest of the ecosystem already uses.
///
/// `XDG_CONFIG_HOME` and `XDG_DATA_HOME` are read here and nowhere else. That
/// is what makes a clean-HOME test possible without chroot: the test sets the
/// two variables, and the layout moves with them.
pub fn for_current_user() -> Layout {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // No HOME at all. Falling back to `/` would produce paths under the
            // root filesystem, which `setup` could then create. Refusing here is
            // better than writing a vault somewhere nobody will look.
            panic!("asv: HOME is not set; an installation has nowhere to live");
        });

    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local").join("share"));

    let config_dir = config_home.join("asv");
    let data_dir = data_home.join("asv");
    // `systemd/user` hangs off the *config home*, not off the `asv`
    // subdirectory that holds the passphrase. Building it as
    // `config_dir.join("..")` produced the literal path
    // `~/.config/asv/../systemd/user/...`, which resolves to the right place
    // and reads like a mistake in every `systemctl --user cat` an operator
    // ever runs.
    let unit_dir = config_home.join("systemd").join("user");

    Layout {
        vault: data_dir.join("vault.asv"),
        passphrase: config_dir.join("passphrase"),
        unit: unit_dir.join("asv-brokerd.service"),
        broker_lookup: lookup_broker_binary(),
        config_dir,
        data_dir,
        socket_override: None,
    }
}

/// Why a candidate binary was refused.
///
/// Separate from a boolean because the remedy differs, and the remedy is the
/// whole point of `doctor`: "not installed", "not runnable" and "owned by
/// somebody else" send an operator to three different places, and a single
/// `found: false` sends them to none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerLookup {
    Found(PathBuf),
    /// A location was resolved and the binary there is not usable by this
    /// user. [`Refusal::NotFound`] is one of these: "the path I would have
    /// used has nothing at it" is a refusal, not a success.
    Refused {
        path: PathBuf,
        reason: Refusal,
    },
}

impl BrokerLookup {
    pub fn is_found(&self) -> bool {
        matches!(self, BrokerLookup::Found(_))
    }

    pub fn path(&self) -> &Path {
        match self {
            BrokerLookup::Found(p) => p,
            BrokerLookup::Refused { path, .. } => path,
        }
    }
}

/// Every way a path can fail to be a usable private broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing at that path: the bundle was not installed there.
    NotFound,
    /// Something is there and it is not a regular file.
    NotAFile,
    /// A regular file that cannot be run.
    NotExecutable,
    /// Runnable, and owned by another uid.
    NotOwnedByThisUser { owner: u32, me: u32 },
}

impl Refusal {
    /// One line naming the state, without advice. `doctor` pairs it with a
    /// remedy; the advice belongs where the remedy is.
    pub fn explain(&self, path: &Path) -> String {
        match self {
            Refusal::NotFound => format!("no broker binary at {}", path.display()),
            Refusal::NotAFile => format!("{} is not a regular file", path.display()),
            Refusal::NotExecutable => format!("{} is not executable", path.display()),
            Refusal::NotOwnedByThisUser { owner, me } => {
                format!(
                    "{} is owned by uid {owner}, this process is uid {me}",
                    path.display()
                )
            }
        }
    }
}

/// Runs the §5 resolution order. Never consults `$PATH`.
pub fn resolve_broker_binary() -> PathBuf {
    match lookup_broker_binary() {
        BrokerLookup::Found(p) => p,
        BrokerLookup::Refused { path, .. } => path,
    }
}

/// The resolution itself, with the reason preserved.
pub fn lookup_broker_binary() -> BrokerLookup {
    // Step 1: an explicit location. This is both where DX4's installer will
    // record what it placed, and the seam a clean-HOME test uses. Checked no
    // more loosely than any other step, which is the point: a seam that
    // skipped the owner check would be a wider door than the one it replaces.
    if let Some(dir) = std::env::var_os(LIBEXEC_ENV) {
        let candidate = PathBuf::from(dir).join(BROKER_BINARY);
        return accept_or_refuse(candidate);
    }

    // Step 2: relative to this executable. The bundle lays `asv` out in
    // `<root>/bin` and the private runtime in `<root>/libexec/asv`.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(candidate) = sibling_libexec(&exe) {
            return accept_or_refuse(candidate);
        }
    }

    // Step 3: the system package.
    accept_or_refuse(PathBuf::from(SYSTEM_LIBEXEC).join(BROKER_BINARY))
}

/// "Absent" and "present but unusable" are different states with different
/// remedies, and a caller that cannot tell them apart tells the operator to
/// reinstall a bundle that is already there.
fn accept_or_refuse(candidate: PathBuf) -> BrokerLookup {
    match rejection(&candidate) {
        None => BrokerLookup::Found(candidate),
        Some(reason) => BrokerLookup::Refused {
            path: candidate,
            reason,
        },
    }
}

/// `<root>/bin/asv` → `<root>/libexec/asv/asv-brokerd`.
///
/// Returns `None` when the executable is not in a `bin` directory, which is
/// the case for a test binary under `target/` and for a `cargo install` that
/// put things somewhere else. Falling back to guessing `<root>` from an
/// arbitrary layout is how a development checkout ends up pointing at a
/// colleague's home directory.
fn sibling_libexec(exe: &Path) -> Option<PathBuf> {
    let bin_dir = exe.parent()?;
    if bin_dir.file_name() != Some(std::ffi::OsStr::new("bin")) {
        return None;
    }
    let root = bin_dir.parent()?;
    Some(root.join(LIBEXEC_LEAF).join(BROKER_BINARY))
}

/// Why this file is not a usable broker, or `None` when it is.
///
/// The first case is the one that matters. A path that does not exist is a
/// *refusal* and not a pass, and an earlier version of this function used
/// `metadata(path).ok()?` — which returns `None` both for "there is no such
/// file" and for "this file is fine", and therefore accepted a broker that
/// had never been installed. `setup` would have written a unit pointing at a
/// path with nothing behind it and `doctor` would have reported a working
/// private runtime. Existence is checked, not inferred from the absence of a
/// complaint.
fn rejection(path: &Path) -> Option<Refusal> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Some(Refusal::NotFound),
    };
    if !meta.is_file() {
        return Some(Refusal::NotAFile);
    }
    if !is_executable(&meta) {
        return Some(Refusal::NotExecutable);
    }
    // Owner check. `setup` writes a unit that will run this as a long-lived
    // process holding vault keys, so "somebody made this file" is not enough.
    // SAFETY: `geteuid` takes no arguments and has no failure mode; the
    // return value is the effective uid of the calling process.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Some(Refusal::NotOwnedByThisUser {
            owner: meta.uid(),
            me,
        });
    }
    None
}

fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

/// The permission bits of a path, or `None` when it does not exist.
///
/// Reads what the filesystem holds rather than what a write was asked for.
/// Every permission assertion in `setup` and `doctor` goes through here, so
/// "the mode is 0700" always means "the mode is 0700 now" and never "the mode
/// we passed to `chmod`".
pub fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{with_env, TempTree};

    /// The rule the whole module exists for: `$PATH` is not consulted.
    ///
    /// The decoy is what makes this more than a restatement of the code.
    /// Without one, the test passes for any implementation that never looked
    /// at `$PATH` — including one that hardcodes a path and never works. With
    /// an executable decoy first on `$PATH`, an implementation that searched
    /// there would find it and fail.
    ///
    /// The assertion is `!=`, not `== some expected path`: naming the right
    /// answer would pin this to one layout, and the property is the negative
    /// one.
    #[test]
    fn the_lookup_never_consults_path() {
        let tmp = TempTree::new("path-decoy");
        let decoy_dir = tmp.path.join("decoy-bin");
        std::fs::create_dir_all(&decoy_dir).unwrap();
        let decoy = decoy_dir.join(BROKER_BINARY);
        crate::tests_support::write_executable(&decoy, b"#!/bin/sh\nexit 0\n");

        // No override and no `bin/` parent, so the lookup has every reason to
        // fall through to a PATH search.
        let found = with_env(&[("PATH", decoy_dir.as_os_str())], lookup_broker_binary);

        assert_ne!(
            found.path(),
            decoy.as_path(),
            "the broker was resolved from $PATH; any directory earlier in the \
             path can now choose which process holds the vault keys"
        );
    }

    /// The bug this module nearly shipped.
    ///
    /// `rejection` used `metadata(path).ok()?`, which cannot distinguish "no
    /// such file" from "this file is fine" — it returns `None` for both. So a
    /// path with nothing at it resolved as [`BrokerLookup::Found`], `setup`
    /// would have written a unit pointing into an empty directory, and
    /// `doctor` would have reported a working private runtime. A missing
    /// broker is a refusal, and this is the assertion that says so.
    #[test]
    fn a_path_with_nothing_at_it_is_not_a_broker() {
        let tmp = TempTree::new("missing");
        let dir = tmp.path.join(LIBEXEC_LEAF);
        std::fs::create_dir_all(&dir).unwrap();
        let expected = dir.join(BROKER_BINARY);
        assert!(!expected.exists(), "the control: the path really is empty");

        let found = with_env(&[(LIBEXEC_ENV, dir.as_os_str())], lookup_broker_binary);

        assert_eq!(
            found,
            BrokerLookup::Refused {
                path: expected.clone(),
                reason: Refusal::NotFound,
            },
            "an empty directory resolved as a usable broker"
        );
        assert!(!found.is_found());
    }

    /// A directory named `asv-brokerd` is not a broker. The lookup is what
    /// stands between a stray directory and a unit that will not start.
    #[test]
    fn a_directory_is_not_a_broker() {
        let tmp = TempTree::new("dir-not-bin");
        let dir = tmp.path.join(LIBEXEC_LEAF);
        std::fs::create_dir_all(dir.join(BROKER_BINARY)).unwrap();

        let found = with_env(&[(LIBEXEC_ENV, dir.as_os_str())], lookup_broker_binary);
        assert_eq!(
            found,
            BrokerLookup::Refused {
                path: dir.join(BROKER_BINARY),
                reason: Refusal::NotAFile,
            }
        );
    }

    /// Present but not runnable is a different state from absent, and the
    /// operator acts differently on each: one means "the bundle is broken",
    /// the other means "the bundle was never installed".
    #[test]
    fn a_non_executable_file_is_refused_with_its_own_reason() {
        let tmp = TempTree::new("not-exec");
        let dir = tmp.path.join(LIBEXEC_LEAF);
        let file = dir.join(BROKER_BINARY);
        crate::tests_support::write_with_mode(&file, b"not a program", 0o644);

        let found = with_env(&[(LIBEXEC_ENV, dir.as_os_str())], lookup_broker_binary);
        assert_eq!(
            found,
            BrokerLookup::Refused {
                path: file,
                reason: Refusal::NotExecutable,
            }
        );
    }

    /// The accepted case, so the three refusals above are refusals rather
    /// than the lookup simply never succeeding.
    #[test]
    fn an_executable_file_owned_by_this_user_is_accepted() {
        let tmp = TempTree::new("accepted");
        let dir = tmp.path.join(LIBEXEC_LEAF);
        let file = dir.join(BROKER_BINARY);
        crate::tests_support::write_executable(&file, b"#!/bin/sh\nexit 0\n");

        let found = with_env(&[(LIBEXEC_ENV, dir.as_os_str())], lookup_broker_binary);
        assert_eq!(found, BrokerLookup::Found(file));
    }

    /// `<root>/bin/asv` finds `<root>/libexec/asv/asv-brokerd`, which is the
    /// layout `distribution/manifest.toml` declares.
    #[test]
    fn the_sibling_layout_matches_the_manifest() {
        assert_eq!(
            sibling_libexec(Path::new("/home/someone/.local/bin/asv")),
            Some(PathBuf::from(
                "/home/someone/.local/libexec/asv/asv-brokerd"
            ))
        );
    }

    /// A test binary under `target/release/deps/` is not in a `bin`
    /// directory, and guessing a `<root>` from it is how a development
    /// checkout ends up pointing at a colleague's home.
    #[test]
    fn an_executable_outside_a_bin_directory_yields_no_guess() {
        assert_eq!(
            sibling_libexec(Path::new("/build/target/release/deps/asv-9f2a")),
            None
        );
    }

    /// Every refusal explains itself differently, because the three states
    /// send an operator to three different places and one sentence would
    /// collapse them back together.
    #[test]
    fn each_refusal_says_something_different() {
        let p = Path::new("/x/asv-brokerd");
        let sentences: Vec<String> = [
            Refusal::NotFound,
            Refusal::NotAFile,
            Refusal::NotExecutable,
            Refusal::NotOwnedByThisUser { owner: 0, me: 1000 },
        ]
        .iter()
        .map(|r| r.explain(p))
        .collect();

        for (i, a) in sentences.iter().enumerate() {
            for b in &sentences[i + 1..] {
                assert_ne!(a, b, "two refusals render the same sentence: {a}");
            }
        }
    }

    /// No path in a live layout contains `..`.
    ///
    /// Found by running the binary rather than by reading it: the unit path
    /// was built as `config_dir.join("..").join("systemd")`, which resolves to
    /// the correct directory and prints as
    /// `~/.config/asv/../systemd/user/asv-brokerd.service`. Every consumer of
    /// that path — `systemctl --user cat`, the installer, a human copying it —
    /// sees a path that looks like a mistake, and a test that only checked
    /// that the file landed in the right place would have passed.
    #[test]
    fn no_layout_path_needs_to_be_normalised() {
        with_env(
            &[
                ("HOME", Path::new("/home/someone").as_os_str()),
                (
                    "XDG_CONFIG_HOME",
                    Path::new("/home/someone/.config").as_os_str(),
                ),
                (
                    "XDG_DATA_HOME",
                    Path::new("/home/someone/.local/share").as_os_str(),
                ),
            ],
            || {
                let layout = crate::layout::for_current_user();
                for (label, path) in [
                    ("config_dir", &layout.config_dir),
                    ("data_dir", &layout.data_dir),
                    ("vault", &layout.vault),
                    ("passphrase", &layout.passphrase),
                    ("unit", &layout.unit),
                ] {
                    assert!(
                        !path
                            .components()
                            .any(|c| c == std::path::Component::ParentDir),
                        "{label} is {path:?}, which has to be normalised before it reads right"
                    );
                }
                // And it is the path `distribution/manifest.toml` declares.
                assert_eq!(
                    layout.unit,
                    PathBuf::from("/home/someone/.config/systemd/user/asv-brokerd.service")
                );
            },
        );
    }
}
