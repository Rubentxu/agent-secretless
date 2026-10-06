//! R4.B.1: resolving the executable an operation is about, so a plan can name
//! it and a later execution can prove it is running the same one.
//!
//! # Why this module exists and why it is not `fingerprint`
//!
//! R3's [`crate::fingerprint`] answers "what is this file right now" for a
//! **configuration file**, and its default policy refuses every symlink because
//! a `.npmrc` that is a symlink is a file whose *contents* an operator chose to
//! point somewhere. That reasoning is right for a credential file and wrong for
//! an executable, on this machine, today:
//!
//! ```text
//! /usr/bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js
//! ```
//!
//! On Fedora, on Debian, on Arch, on anything built from a package manager,
//! `npm`, `mvn`, `gradle`, `python`, `curl` and `ruby` are symlinks. A policy
//! that refuses them cannot resolve a tool on most real systems, and a resolver
//! that cannot resolve a tool cannot bind a plan to one. So this module
//! **follows** the symlink and records where it landed.
//!
//! Following is safe here for a reason that does not apply to a credential
//! file: [`ToolIdentity::path`] is the **resolved** path, so the comparison
//! that matters at execute time is between two real paths and two digests. A
//! symlink pointed at an attacker's binary resolves *away from* where the
//! operator expected, which is exactly the drift [`crate::PlanBinding`] exists
//! to catch — the attack does not gain from the link, it gains from the
//! *change*, and the change is visible.
//!
//! # The law here is the crate's law
//!
//! Same as everywhere else in R3: **a report that cannot be wrong.** Every
//! directory on `PATH` that was searched is named, every candidate that was
//! refused is named with the reason, and the chosen one is named with both its
//! path as it appeared on `PATH` and the file that actually ran. A resolution
//! that silently skipped a world-writable directory would be a report that
//! cannot be acted on, because the reader could not tell it had.
//!
//! # What is refused
//!
//! - not found anywhere on `PATH`;
//! - a directory that does not exist or is not a directory (skipped silently —
//!   every `PATH` carries a dead directory and refusing on one would make the
//!   resolver unusable);
//! - a candidate that is not a regular file once resolved (a fifo, a socket, a
//!   device node);
//! - a candidate **writable by group or other**, which is the PATH-hijack
//!   itself: an executable anyone can replace is not the executable that was
//!   planned;
//! - a candidate above [`MAX_TOOL_BYTES`], refused rather than truncated,
//!   because a digest of the first N bytes is a digest of something that is not
//!   the file.

use std::fmt;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use asv_domain::{ToolIdentity, ToolIdentityError};

/// The permission bits that mean "somebody who is not the owner can replace
/// this executable".
///
/// The same `0o022` the fingerprint policy uses, and for the same reason, but
/// arriving here from the opposite direction: a group- or world-writable
/// `npm` on `PATH` is the concrete attack the spec's `PLAN_INVALIDATED`
/// example is about.
const UNTRUSTED_WRITE_BITS: u32 = 0o022;

/// The largest executable this module will hash.
///
/// `node` is around 100 MiB and some toolchains are larger; 512 MiB is well
/// past anything real and keeps a pathological `PATH` entry from turning a
/// resolution into an out-of-memory. The refusal is a refusal and not a
/// truncation, because a digest of a prefix is a digest of a different file.
pub const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;

/// Read buffer for hashing. Streaming rather than `fs::read`, so resolving a
/// large interpreter does not mean holding it in memory.
const HASH_CHUNK: usize = 64 * 1024;

/// One entry on `PATH`, and what became of it.
///
/// Present because a resolution that only says "npm is `/usr/bin/npm`" is a
/// report that cannot be acted on: a reader cannot tell whether the directories
/// before it were empty, absent, or **refused**, and only the third is a fact
/// about the machine worth surfacing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PathCandidate {
    /// The directory as it appeared in `PATH`.
    pub directory: PathBuf,
    /// The full path that would have been executed.
    pub candidate: PathBuf,
    /// What became of it.
    pub outcome: CandidateOutcome,
}

/// Why a candidate on `PATH` did not become the executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOutcome {
    /// It ran. Only ever the last entry.
    Chosen {
        /// Where the symlink chain landed. **Not** the `candidate` path: what
        /// executes is the target, and a receipt that printed the link would
        /// name a file that never ran.
        resolved_path: PathBuf,
        bytes: u64,
    },
    /// The directory held no file of that name. Not an event.
    Absent,
    /// It was not a regular file once resolved.
    NotARegularFile { mode: u32 },
    /// Somebody other than the owner can replace it.
    UntrustedWritable { mode: u32 },
    /// Too large to hash honestly.
    TooLarge { bytes: u64 },
    /// It could not be read or resolved at all.
    Unreadable { message: String },
}

/// How a tool was resolved, and what the search found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ToolResolution {
    /// The command as the caller named it, before any `PATH` search. Kept so a
    /// receipt shows what was asked for, not only what was found.
    pub command: String,
    /// The `PATH` string the search used, verbatim. A resolution that cannot be
    /// re-run because it does not say which `PATH` it used is not evidence.
    pub path: String,
    /// Every directory consulted, in order, including the one that won.
    pub candidates: Vec<PathCandidate>,
    /// The executable, or the reason there is none.
    pub resolved: Option<ToolIdentity>,
}

/// The command line this module was asked to resolve, as a `PATH` string.
///
/// A parameter rather than a read of the process environment so a row can
/// resolve against a `PATH` it controls, and so the value that was searched
/// can be reported instead of inferred. Empty entries in a `PATH` mean the
/// current directory, and that is honoured here rather than skipped: a `PATH`
/// entry that silently meant something else would be a resolution that cannot
/// be reasoned about.
pub fn resolve_tool(command: &str, path: &str) -> Result<ToolResolution, ToolResolveError> {
    resolve_tool_bounded(command, path, MAX_TOOL_BYTES)
}

/// [`resolve_tool`] with the hashing limit as a parameter.
///
/// Exists so the size refusal can be *exercised* rather than merely asserted:
/// a row that allocated 512 MiB to prove a comparison works would not be worth
/// running, and a row that greps the source for the constant proves only that
/// the constant appears twice.
pub fn resolve_tool_bounded(
    command: &str,
    path: &str,
    max_bytes: u64,
) -> Result<ToolResolution, ToolResolveError> {
    if command.is_empty() {
        return Err(ToolResolveError::NoCommand);
    }
    // A command that is or contains a separator is a path, and resolving it
    // through `PATH` would search for a file whose *name* is `/usr/bin/npm`.
    // Callers that mean a path say so by passing an absolute one, which is
    // handled by the same code because `Path::join` on an absolute path
    // replaces the directory.
    let mut candidates = Vec::new();
    let mut chosen: Option<ToolIdentity> = None;

    for directory in path.split(':') {
        let directory = if directory.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(directory)
        };
        let candidate = directory.join(command);
        if chosen.is_some() {
            // First match wins, exactly as the shell and `execvp` do it. The
            // remaining directories are not consulted, which is why they are
            // not reported either: reporting a directory as "searched" when
            // the search had already stopped would be a lie about the search.
            break;
        }
        let outcome = inspect_candidate(&candidate, max_bytes);
        if let CandidateOutcome::Chosen {
            resolved_path: ref landed,
            ..
        } = outcome
        {
            chosen = identity_for(landed);
        }
        candidates.push(PathCandidate {
            directory,
            candidate,
            outcome,
        });
    }

    Ok(ToolResolution {
        command: command.to_string(),
        path: path.to_string(),
        candidates,
        resolved: chosen,
    })
}

/// An identity for a file this module has already agreed is safe to hash.
fn identity_for(resolved: &Path) -> Option<ToolIdentity> {
    let digest = digest_file(resolved).ok()?;
    // A digest this module produced and cannot build an identity from would be
    // a defect rather than a condition. It surfaces as `None`, which the caller
    // reads as "unresolved", rather than as a panic in the middle of a report.
    ToolIdentity::new(resolved.to_path_buf(), digest).ok()
}

fn inspect_candidate(candidate: &Path, max_bytes: u64) -> CandidateOutcome {
    // `symlink_metadata` first, so a dangling link is `Unreadable` rather than
    // being reported as absent. A `PATH` entry pointing at a removed binary is
    // a fact about the machine; "no such file" would hide which directory held
    // it.
    match std::fs::symlink_metadata(candidate) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return CandidateOutcome::Absent
        }
        Err(error) => {
            return CandidateOutcome::Unreadable {
                message: error.to_string(),
            }
        }
    }

    let resolved = match std::fs::canonicalize(candidate) {
        Ok(path) => path,
        Err(error) => {
            return CandidateOutcome::Unreadable {
                message: error.to_string(),
            }
        }
    };
    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) => meta,
        Err(error) => {
            return CandidateOutcome::Unreadable {
                message: error.to_string(),
            }
        }
    };
    if !meta.is_file() {
        return CandidateOutcome::NotARegularFile { mode: meta.mode() };
    }
    if meta.mode() & UNTRUSTED_WRITE_BITS != 0 {
        return CandidateOutcome::UntrustedWritable { mode: meta.mode() };
    }
    if meta.len() > max_bytes {
        return CandidateOutcome::TooLarge { bytes: meta.len() };
    }
    CandidateOutcome::Chosen {
        resolved_path: resolved,
        bytes: meta.len(),
    }
}

/// `sha256` over bytes, for a caller that already holds them.
///
/// Public because a receipt that records what was hashed is worth more than
/// one that records only that something was hashed, and a row can only check
/// that against the same primitive.
pub fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

/// `sha256` over a file's bytes, streamed.
fn digest_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Why a tool could not be resolved at all.
#[derive(Debug, thiserror::Error)]
pub enum ToolResolveError {
    #[error("no command was named")]
    NoCommand,
    #[error("a digest this module produced was not a digest")]
    Digest(#[from] ToolIdentityError),
}

impl fmt::Display for CandidateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chosen {
                resolved_path,
                bytes,
            } => {
                write!(f, "chosen: {} ({bytes} bytes)", resolved_path.display())
            }
            Self::Absent => write!(f, "absent"),
            Self::NotARegularFile { mode } => write!(f, "not a regular file (mode {mode:o})"),
            Self::UntrustedWritable { mode } => {
                write!(f, "writable by group or other (mode {mode:o})")
            }
            Self::TooLarge { bytes } => write!(f, "{bytes} bytes, above the hashing limit"),
            Self::Unreadable { message } => write!(f, "unreadable: {message}"),
        }
    }
}
#[cfg(test)]
#[path = "tool/tests.rs"]
mod tests;
