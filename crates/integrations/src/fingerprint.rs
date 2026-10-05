//! What a configuration file *is* right now, and whether it may be read at all.
//!
//! # Why a fingerprint rather than a path
//!
//! R3's pipeline is `discover → plan → adopt`, and the gap between the first
//! and the last of those is a person reading a plan. A plan says "this
//! `.npmrc` declares an auth selector for `registry.npmjs.org`". The operator
//! approves it, and then the tool writes something. **Between the report and the
//! write, the file can change** — and it can change to point at a different
//! registry, a different scope, or a credential the operator never saw. That is
//! `CONFIG_CHANGED`, and the only way to detect it is to have recorded something
//! about the file at report time and compared it before acting.
//!
//! A path is not that something. A path names a file; it does not say which
//! inode, owned by whom, with which permissions, holding which bytes. So the
//! report carries a [`FileFingerprint`] with all five, and every dimension is
//! the one an attacker or a careless editor would have to change to redirect
//! the adoption.
//!
//! # What is refused, and what is only reported
//!
//! The line is **integrity, not confidentiality**, and it is worth being
//! explicit because the obvious alternative is wrong:
//!
//! - **Refused**: not a regular file; a symlink whose target is outside an
//!   explicitly allowed root; owned by a uid the caller did not name; writable
//!   by group or other.
//! - **Reported, not refused**: readable by group or other.
//!
//! The second is the interesting one. A world-readable `.npmrc` holding a token
//! *is* an exposure, and the right answer to it is not to refuse to read the
//! file — it is to move the token out of it, which is what the rest of R3 is
//! for. npm itself creates these files at `0644`; refusing them would make
//! discovery fail on almost every real machine, and a tool that cannot see the
//! file it exists to fix cannot fix it. The report carries the mode so the
//! operator is told, and `adopt` is where refusing to leave a readable token
//! behind becomes the tool's problem rather than the reader's.
//!
//! Writability is different and is refused outright: a group- or
//! world-writable config is a file whose *contents* anyone can change, so every
//! dimension of the fingerprint above can be truthful about bytes the operator
//! did not choose. The report would still be accurate and still be useless.

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The permission bits that mean "somebody who is not the owner can replace
/// this file's contents".
///
/// `0o022` — group-write and world-write. Deliberately *not* `0o077`: the read
/// bits are the operator's problem to be told about, and the module docs say
/// why refusing them would be worse than useless.
const UNTRUSTED_WRITE_BITS: u32 = 0o022;

/// A configuration file's identity at the moment it was read.
///
/// Every field is a thing that can change without the path changing, which is
/// the whole point: `revalidate` is a comparison of all five, and a plan that
/// does not compare all five has a hole in it the width of the one it skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFingerprint {
    /// The path as the caller named it, not as it resolved. The resolved form
    /// is in [`Self::resolved_path`], and keeping both is what lets a report
    /// show the operator the name they will recognise *and* the inode that was
    /// actually read.
    pub path: PathBuf,
    /// Where the bytes actually came from, after symlink resolution.
    ///
    /// Equal to [`Self::path`] in the ordinary case. Present so that a report
    /// can state the fact rather than leave the reader to assume it.
    pub resolved_path: PathBuf,
    /// `st_ino`. A rewritten file almost always has a new inode, which makes
    /// this the cheapest of the five to compare and the one that catches
    /// "someone replaced it" rather than "someone edited it".
    pub inode: u64,
    /// `st_uid` of the owner.
    pub owner_uid: u32,
    /// The permission bits only — `0o600`, not `0o100600`. The file-type bits
    /// are checked separately and a non-regular file is refused, so carrying
    /// them here would be carrying a fact that can never be true in a
    /// successful fingerprint.
    pub mode: u32,
    /// `st_size`, in bytes.
    pub size: u64,
    /// `sha256:<hex>` over the file's bytes.
    ///
    /// Over the whole file, including whatever credentials it holds. That is
    /// safe in a way a *per-value* digest would not be: confirming a guess
    /// against this would require guessing every byte of the file, including
    /// the secret. A digest of one extracted value would be an oracle for that
    /// value, so no such digest is emitted anywhere in this crate.
    pub digest: String,
}

impl FileFingerprint {
    /// Whether group or other can write this file, which discovery refuses.
    pub fn is_untrusted_writable(&self) -> bool {
        self.mode & UNTRUSTED_WRITE_BITS != 0
    }

    /// Whether group or other can read this file, which discovery reports and
    /// does **not** refuse.
    pub fn is_untrusted_readable(&self) -> bool {
        self.mode & 0o077 != 0
    }

    /// Whether this is the same file, by every dimension the report carries.
    ///
    /// A method rather than a `PartialEq` comparison because the interesting
    /// question is not "are these two structs equal" but "may the plan that was
    /// built from the first still be applied to the second", and that deserves
    /// to be answered by a name that says so. The comparison is over all five
    /// and there is no partial version of it on purpose.
    pub fn matches(&self, other: &FileFingerprint) -> bool {
        self.path == other.path
            && self.inode == other.inode
            && self.owner_uid == other.owner_uid
            && self.mode == other.mode
            && self.size == other.size
            && self.digest == other.digest
    }

    /// The dimensions that differ, named.
    ///
    /// For the operator reading a refusal. `CONFIG_CHANGED` with no detail is a
    /// question, and the answer is in here; a report that said only "changed"
    /// would send them to diff a file by hand to find out whether a credential
    /// had been swapped, which is exactly the manual step this exists to
    /// remove.
    pub fn drift_from(&self, other: &FileFingerprint) -> Vec<Drift> {
        let mut out = Vec::new();
        if self.path != other.path {
            out.push(Drift::Path);
        }
        if self.inode != other.inode {
            out.push(Drift::Inode);
        }
        if self.owner_uid != other.owner_uid {
            out.push(Drift::Owner);
        }
        if self.mode != other.mode {
            out.push(Drift::Mode);
        }
        if self.size != other.size {
            out.push(Drift::Size);
        }
        if self.digest != other.digest {
            out.push(Drift::Contents);
        }
        out
    }
}

/// One dimension of a configuration file that moved between plan and apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Drift {
    /// The file is not the one that was planned.
    Path,
    /// A different inode: the file was replaced rather than edited.
    Inode,
    /// A different owner.
    Owner,
    /// Different permission bits.
    Mode,
    /// A different length.
    Size,
    /// Same shape, different bytes — the contents changed underneath.
    Contents,
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Path => "the file is not the one that was planned",
            Self::Inode => "the file was replaced, not edited",
            Self::Owner => "the file is owned by a different user",
            Self::Mode => "the permissions changed",
            Self::Size => "the length changed",
            Self::Contents => "the contents changed",
        };
        f.write_str(text)
    }
}

/// Who may own a file this crate will read.
#[derive(Debug, Clone, Default)]
pub struct FingerprintPolicy {
    /// Roots a symlink may resolve into. **Empty by default, which refuses every
    /// symlink.**
    ///
    /// The default is the safe one and the empty one at the same time: a
    /// `.npmrc` that is a symlink is a file whose contents an operator chose to
    /// point somewhere, and this crate has no way to know whether that `somewhere`
    /// is a dotfile manager's directory, a shared checkout, or somebody's
    /// home. Naming the root is a decision an operator makes with the context
    /// this crate does not have.
    pub allowed_symlink_roots: Vec<PathBuf>,
    /// Uids that may own the file, in addition to the caller's effective uid.
    ///
    /// Also empty by default. A root-run `asv` reading an operator's config is
    /// the ordinary reason to need this, and it is a decision rather than a
    /// default because a file owned by a stranger is a file a stranger chose.
    pub allowed_owner_uids: Vec<u32>,
}

impl FingerprintPolicy {
    /// The default: no symlinks, and only the caller's own files.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Permits symlinks that resolve inside `root`.
    pub fn allowing_symlink_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.allowed_symlink_roots.push(root.into());
        self
    }

    /// Permits files owned by `uid` in addition to the caller's own.
    pub fn allowing_owner(mut self, uid: u32) -> Self {
        self.allowed_owner_uids.push(uid);
        self
    }

    /// Reads `path` and describes it, or refuses.
    ///
    /// The refusals are in the order they are cheap to detect, and every one of
    /// them is a refusal rather than a warning: a report that describes a file
    /// nobody may trust is a report an operator can act on by mistake.
    pub fn fingerprint(&self, path: &Path) -> Result<FileFingerprint, FingerprintError> {
        // `symlink_metadata` does not follow. Following here would mean the
        // symlink check below could never fire, because by the time we looked
        // the link would already be a regular file with a regular file's inode.
        let link_meta =
            std::fs::symlink_metadata(path).map_err(|error| FingerprintError::Unreadable {
                path: path.into(),
                error,
            })?;

        if link_meta.file_type().is_symlink() {
            let target =
                std::fs::canonicalize(path).map_err(|error| FingerprintError::Unreadable {
                    path: path.into(),
                    error,
                })?;
            if !self.symlink_target_allowed(&target) {
                return Err(FingerprintError::SymlinkOutsideAllowedRoot {
                    path: path.into(),
                    target,
                });
            }
        }

        // Now follow, deliberately, and check what we landed on.
        let meta = std::fs::metadata(path).map_err(|error| FingerprintError::Unreadable {
            path: path.into(),
            error,
        })?;
        if !meta.is_file() {
            return Err(FingerprintError::NotARegularFile { path: path.into() });
        }

        let euid = current_euid();
        if meta.uid() != euid && !self.allowed_owner_uids.contains(&meta.uid()) {
            return Err(FingerprintError::ForeignOwner {
                path: path.into(),
                owner: meta.uid(),
                caller: euid,
            });
        }

        let mode = meta.mode() & 0o7777;
        if mode & UNTRUSTED_WRITE_BITS != 0 {
            return Err(FingerprintError::UntrustedWritable {
                path: path.into(),
                mode,
            });
        }

        let resolved_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let digest = digest_file(path)?;

        Ok(FileFingerprint {
            path: path.to_path_buf(),
            resolved_path,
            inode: meta.ino(),
            owner_uid: meta.uid(),
            mode,
            size: meta.size(),
            digest,
        })
    }

    /// Whether `target` is a file *inside* one of the explicitly allowed roots.
    ///
    /// Compared component-wise rather than by string prefix, because
    /// `/home/u/.config` and `/home/u/.config-backup` share a string prefix and
    /// share nothing else — and a symlink allowance is exactly the place where
    /// a prefix comparison hands out more than the operator meant. That case has
    /// its own row, because it is the reason this is not `starts_with`.
    ///
    /// Strictly longer than the root as well, so a root that is itself a regular
    /// file cannot authorise a symlink pointing at itself. `canonicalize` has
    /// already made `target` absolute and symlink-free, and [`normalize`] is
    /// belt and braces for the *root*, which is caller-supplied and has not been
    /// through the kernel.
    fn symlink_target_allowed(&self, target: &Path) -> bool {
        // The normalized `PathBuf`s are bound rather than collected in place:
        // `components()` borrows the path it walks, so a temporary that dies at
        // the end of the `let` leaves the vectors holding nothing.
        let target_path = normalize(target);
        let target: Vec<_> = target_path.components().collect();
        self.allowed_symlink_roots.iter().any(|root| {
            let root_path = normalize(root);
            let root: Vec<_> = root_path.components().collect();
            target.len() > root.len()
                && target
                    .iter()
                    .zip(root.iter())
                    .all(|(inside, boundary)| inside == boundary)
        })
    }
}

/// Drops `.` and collapses `..` lexically.
///
/// `canonicalize` already returns an absolute, symlink-free path, so this is
/// belt and braces — but the comparison is written against a value a caller
/// supplied for the *root*, and that one has not been through the kernel.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// This process's effective uid, or `0` if the platform will not say.
///
/// `0` as the fallback is the *safe* direction, not the convenient one: the
/// checks that compare against it then fail, so an unanswerable question about
/// ownership refuses the file rather than admitting it. A tool that cannot tell
/// who owns a file is not entitled to read one.
fn current_euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, has no preconditions
    // and touches no memory. It is the only unsafe call in this crate, and it
    // is here rather than in a dependency because a fingerprint's answer to "is
    // this file mine" should not be a third party's.
    unsafe { libc::geteuid() }
}

fn digest_file(path: &Path) -> Result<String, FingerprintError> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).map_err(|error| FingerprintError::Unreadable {
        path: path.into(),
        error,
    })?;
    let mut hasher = Sha256::new();
    // 8 KiB: large enough that a small config is one read, small enough that a
    // pathological file cannot turn a digest into an allocation event.
    let mut buffer = vec![0u8; 8 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| FingerprintError::Unreadable {
                path: path.into(),
                error,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Why a file may not be read, or described.
///
/// Every variant is a refusal. There is deliberately no "warned and continued"
/// variant: the module docs are about which properties are worth refusing over,
/// and a warning nobody has to act on is a way of shipping a control that reads
/// as present and is not.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    #[error("cannot read {path}: {error}")]
    Unreadable {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("{path} is not a regular file")]
    NotARegularFile { path: PathBuf },
    #[error(
        "{path} is a symlink to {target}, which is outside the roots this run was allowed to \
         follow; name the root explicitly if that is where your configuration lives"
    )]
    SymlinkOutsideAllowedRoot { path: PathBuf, target: PathBuf },
    #[error("{path} is owned by uid {owner} but this process runs as uid {caller}")]
    ForeignOwner {
        path: PathBuf,
        owner: u32,
        caller: u32,
    },
    #[error(
        "{path} is mode {mode:04o}, so group or other can change which credential it selects; \
         this is refused rather than reported because a report about a file nobody else may \
         edit is true and useless"
    )]
    UntrustedWritable { path: PathBuf, mode: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn write(path: &Path, contents: &str, mode: u32) {
        std::fs::write(path, contents).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn a_plain_owner_only_file_is_described_on_every_dimension() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        write(&path, "registry=https://registry.npmjs.org/\n", 0o600);

        let fingerprint = FingerprintPolicy::strict()
            .fingerprint(&path)
            .expect("an owner-only file is readable");

        assert_eq!(fingerprint.path, path);
        assert_eq!(fingerprint.mode, 0o600);
        assert!(
            fingerprint.digest.starts_with("sha256:"),
            "{:?}",
            fingerprint.digest
        );
        assert_eq!(fingerprint.digest.len(), "sha256:".len() + 64);
        assert!(fingerprint.inode > 0);
        assert!(!fingerprint.is_untrusted_writable());
        assert!(!fingerprint.is_untrusted_readable());
    }

    #[test]
    fn the_digest_covers_the_bytes_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        write(&path, "registry=https://a.test/\n", 0o600);
        let first = FingerprintPolicy::strict()
            .fingerprint(&path)
            .expect("read");

        // Same length, different bytes: the digest has to move, or a swapped
        // registry would pass revalidation.
        write(&path, "registry=https://b.test/\n", 0o600);
        let second = FingerprintPolicy::strict()
            .fingerprint(&path)
            .expect("read");
        assert_eq!(
            first.size, second.size,
            "the fixture is meant to be the same length"
        );
        assert_ne!(
            first.digest, second.digest,
            "a same-length rewrite kept its digest"
        );
        assert_eq!(first.drift_from(&second), vec![Drift::Contents]);
        assert!(!first.matches(&second));
    }

    #[test]
    fn a_group_writable_file_is_refused_rather_than_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        write(&path, "registry=https://a.test/\n", 0o620);
        let error = FingerprintPolicy::strict()
            .fingerprint(&path)
            .expect_err("group-writable is refused");
        assert!(
            matches!(
                error,
                FingerprintError::UntrustedWritable { mode: 0o620, .. }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_world_readable_file_is_reported_and_not_refused() {
        // The distinction the module docs are about, asserted so it cannot be
        // closed by accident: npm writes these at 0644, and refusing them would
        // make discovery useless on almost every real machine.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        write(&path, "registry=https://a.test/\n", 0o644);
        let fingerprint = FingerprintPolicy::strict()
            .fingerprint(&path)
            .expect("world-readable is reported, not refused");
        assert!(fingerprint.is_untrusted_readable());
        assert!(!fingerprint.is_untrusted_writable());
    }

    #[test]
    fn a_symlink_is_refused_by_default_and_allowed_only_named_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real-npmrc");
        write(&real, "registry=https://a.test/\n", 0o600);
        let link = dir.path().join(".npmrc");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let refused = FingerprintPolicy::strict()
            .fingerprint(&link)
            .expect_err("a symlink is refused with the default policy");
        assert!(
            matches!(refused, FingerprintError::SymlinkOutsideAllowedRoot { .. }),
            "{refused}"
        );

        // Naming the root is the decision the default refuses to make for them.
        let allowed = FingerprintPolicy::strict()
            .allowing_symlink_root(dir.path())
            .fingerprint(&link)
            .expect("a symlink inside a named root is allowed");
        assert_eq!(allowed.digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_symlink_allowance_is_not_a_string_prefix() {
        // `/tmp/x/.config` and `/tmp/x/.config-backup` share a prefix and share
        // nothing else. An allowance that compared strings would hand out the
        // second one too, which is the whole failure this assertion exists for.
        let base = tempfile::tempdir().expect("tempdir");
        let allowed_root = base.path().join(".config");
        std::fs::create_dir(&allowed_root).expect("mkdir");
        let outside = base.path().join(".config-backup");
        std::fs::create_dir(&outside).expect("mkdir");

        let real = outside.join("npmrc");
        write(&real, "registry=https://a.test/\n", 0o600);
        let link = allowed_root.join("npmrc");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let error = FingerprintPolicy::strict()
            .allowing_symlink_root(&allowed_root)
            .fingerprint(&link)
            .expect_err("a sibling directory with a shared prefix is not inside the root");
        assert!(
            matches!(error, FingerprintError::SymlinkOutsideAllowedRoot { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_replacement_is_caught_by_the_inode_and_not_only_the_digest() {
        // The dimension that says "replaced" rather than "edited". Two files
        // with identical bytes have identical digests, so without the inode a
        // file swapped for an identical copy would pass every comparison.
        let dir = tempfile::tempdir().expect("tempdir");
        let first_path = dir.path().join("one");
        let second_path = dir.path().join("two");
        write(&first_path, "registry=https://a.test/\n", 0o600);
        write(&second_path, "registry=https://a.test/\n", 0o600);
        let policy = FingerprintPolicy::strict();
        let first = policy.fingerprint(&first_path).expect("read");
        let second = policy.fingerprint(&second_path).expect("read");
        assert_eq!(
            first.digest, second.digest,
            "the fixture is meant to be identical"
        );
        assert_ne!(first.inode, second.inode);
        assert_eq!(first.drift_from(&second), vec![Drift::Path, Drift::Inode]);
    }

    #[test]
    fn a_directory_is_not_a_configuration_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = FingerprintPolicy::strict()
            .fingerprint(dir.path())
            .expect_err("a directory is refused");
        assert!(
            matches!(error, FingerprintError::NotARegularFile { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_missing_file_says_so_rather_than_reporting_an_empty_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = FingerprintPolicy::strict()
            .fingerprint(&dir.path().join("absent"))
            .expect_err("an absent file is not an empty one");
        assert!(
            matches!(error, FingerprintError::Unreadable { .. }),
            "{error}"
        );
    }
}
