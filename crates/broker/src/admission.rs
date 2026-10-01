//! Control-plane admission — ADR-0015.
//!
//! Three verbs in this broker (`DeleteCredential`, `SubmitApproval`,
//! `AuditQuery`) answer a request with a message saying the operation
//! "requires the operator control plane, not an agent session". That message
//! asserts a predicate. Until this module existed, nothing computed it: there
//! was no code anywhere that could answer whether a caller was the human.
//!
//! ADR-0015 decided what the answer means. A privileged verb is admitted only
//! when **all three** hold, and refused when any one is missing:
//!
//! 1. the caller is not under broker control,
//! 2. the caller is positively enrolled against an operator-held principal,
//! 3. the caller is pidfd-pinned at decision time.
//!
//! Each condition covers another's gap, and the pairing is the whole point.
//!
//! *Condition 2 without condition 1* fails open. "Not a known agent session"
//! is satisfied by every peer this broker never enumerated — one that
//! connected directly, one whose record was dropped, one that started before
//! the broker came up. `SessionStore` records sessions the broker *knows
//! about*; absence from it is a fact about the record, not about the process.
//! So an absence test hands the capability to precisely the untracked peers
//! the boundary exists to exclude.
//!
//! *Condition 2 without condition 3* fails to a confused deputy. A principal
//! is a path plus a content digest, which binds the file, not the arguments
//! around it. An agent under broker control can run programs; without a pin,
//! the pid that was checked and the process that acts can differ.
//!
//! The checks are evaluated cheapest first — a pin is already in hand, one
//! procfs read answers the cgroup question, and hashing an executable is the
//! only step that touches bulk data. The order of evaluation is not the order
//! of the ADR's list, and none of the three is optional.

use asv_identity::WorkloadIdentity;
use sha2::Digest as _;
use sha2::Sha256;
use std::fmt;
use std::path::PathBuf;

/// Why a caller was not admitted.
///
/// One variant per ADR-0015 condition rather than a bare `bool`, because the
/// three are not interchangeable: "you are not enrolled" is an operator setup
/// problem, "you are under broker control" is the system working, and
/// "evidence unavailable" is a host that cannot answer. Collapsing them would
/// leave an operator unable to tell a misconfiguration from an attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// Condition 3: the peer's process could not be pinned, so the pid that
    /// was checked and the process that acts cannot be shown to be the same.
    Unpinned,
    /// Condition 1: the caller is inside a cgroup slice this broker created
    /// for an agent session. It is, by definition, under broker control.
    UnderBrokerControl { slice: PathBuf },
    /// Condition 2: the caller's executable is not an enrolled principal.
    NotEnrolled { path: PathBuf },
    /// The evidence could not be read at all.
    ///
    /// This is a denial, not a fallback to admitted. "We could not check"
    /// must never read as "there was nothing to check" — that is the same
    /// inference as the absence trap above, wearing a different hat.
    EvidenceUnavailable { what: &'static str, reason: String },
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::Unpinned => {
                write!(f, "control-plane admission requires a pidfd-pinned peer")
            }
            Denial::UnderBrokerControl { slice } => write!(
                f,
                "control-plane admission refused: the caller is under broker control \
                 in slice {}",
                slice.display()
            ),
            Denial::NotEnrolled { path } => write!(
                f,
                "control-plane admission refused: {} is not an enrolled control-plane principal",
                path.display()
            ),
            Denial::EvidenceUnavailable { what, reason } => write!(
                f,
                "control-plane admission refused: {what} could not be read ({reason}); \
                 an unreadable check is a denial, never a pass"
            ),
        }
    }
}

impl std::error::Error for Denial {}

/// A digest of one executable file's contents.
///
/// Named `ContentDigest` rather than `Digest` so it cannot be confused with
/// `sha2::Digest`, the trait this module uses to compute it.
pub type ContentDigest = [u8; 32];

/// A principal the operator enrolled as a control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub path: PathBuf,
    pub digest: ContentDigest,
}

/// The enrolment record: the set of principals allowed to act as the human
/// control plane, plus the slice naming convention this broker uses.
///
/// The record is passed in rather than read from disk here. ADR-0015 puts it
/// with the vault; adding that format belongs to the cycle that adds the
/// credential-write verb, and reaching for it now would drag the vault's
/// `&mut self` write seam into a cycle about deciding who may call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enrolment {
    principals: Vec<Principal>,
}

impl Enrolment {
    /// An empty record: nobody is enrolled, so every admission is refused.
    ///
    /// This is the state a broker starts in today, and it is why wiring this
    /// module to the three closed-door verbs opens nothing.
    pub fn empty() -> Self {
        Self {
            principals: Vec::new(),
        }
    }

    pub fn enrol(mut self, path: PathBuf, digest: ContentDigest) -> Self {
        self.principals.push(Principal { path, digest });
        self
    }

    pub fn principals(&self) -> &[Principal] {
        &self.principals
    }
}

/// The file an operator's enrolments live in, beside the vault.
///
/// ADR-0015 puts the enrolment record with the vault, written at enrolment and
/// read back at broker start so it survives a restart. This is that record, as
/// a sidecar rather than a field inside the encrypted body: the body's format
/// is a versioned credential map, and grafting an admission record into it
/// would couple two independent trust domains and re-encrypt the whole vault
/// every time a principal is added. ADR-0016 records the narrowing.
pub fn enrolment_path(vault_path: &std::path::Path) -> PathBuf {
    let mut name = vault_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "vault.asv".into());
    name.push(".control-plane");
    vault_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(name)
}

/// Enrols `principal` by recording its path and the digest of its contents.
///
/// The digest is read now, not at admission time, which is the property that
/// makes replacing the file at that path *revoke* the enrolment rather than
/// inherit it. An enrolment that recorded only a path would keep admitting a
/// different program forever.
///
/// The record is plain text in `sha256sum` format — the format this repository
/// already uses and re-signs for the spec pack — because a format with an
/// existing, checked-in discipline is worth more here than a bespoke one.
pub fn enrol(vault_path: &std::path::Path, principal: &std::path::Path) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let principal = std::fs::canonicalize(principal)
        .map_err(|e| format!("cannot resolve {}: {e}", principal.display()))?;
    let bytes = std::fs::read(&principal)
        .map_err(|e| format!("cannot read {}: {e}", principal.display()))?;
    let digest = crate::audit::hex_lower(&sha256(&bytes));
    let path = enrolment_path(vault_path);

    // Owner-only from the moment it exists, and a replace rather than an
    // append-in-place: this file grants the capability to plant credentials.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    writeln!(file, "{digest}  {}", principal.display())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// Reads the enrolment record, answering `Enrolment::empty()` when there is
/// none.
///
/// A missing file is the normal state, not an error: a broker with no
/// enrolments admits nobody, which is fail-closed and needs no reporting. A
/// file that exists but cannot be parsed *is* reported, because silently
/// treating a corrupt authorisation record as "nobody enrolled" would hide the
/// difference between "the operator never enrolled anyone" and "something
/// damaged the file that grants credential-write authority".
pub fn load_enrolment(vault_path: &std::path::Path) -> Result<Enrolment, String> {
    let path = enrolment_path(vault_path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Enrolment::empty()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut enrolment = Enrolment::empty();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((digest, principal)) = line.split_once("  ") else {
            return Err(format!(
                "{}:{}: not a '<digest>  <path>' record",
                path.display(),
                n + 1
            ));
        };
        enrolment = enrolment.enrol(PathBuf::from(principal), parse_digest(digest)?);
    }
    Ok(enrolment)
}

/// Decodes a hex digest, refusing anything that is not exactly 32 bytes.
///
/// A malformed record is an error, never a digest of zeroes: a record that
/// cannot be parsed must not silently admit nobody *and* must not admit
/// everybody, and it certainly must not produce a digest that some other
/// file's contents would have to collide with to be accepted.
fn parse_digest(hex: &str) -> Result<ContentDigest, String> {
    if !crate::audit::is_hex_64(hex) {
        return Err(format!("not a 64-character lowercase hex digest: {hex}"));
    }
    let mut out = [0u8; 32];
    for (n, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[n * 2..n * 2 + 2], 16)
            .map_err(|e| format!("cannot parse digest: {e}"))?;
    }
    Ok(out)
}

/// The prefix `harden.rs` gives every agent-session cgroup slice.
///
/// Re-exported from `harden` rather than restated. Two copies of this string
/// would drift silently, and the drift would be invisible in the safe
/// direction: admission would stop recognising broker slices and start
/// answering "not under broker control" about processes it had itself placed
/// under control.
pub use crate::harden::SESSION_SLICE_PREFIX;

/// What admission needs to know about a process, read from outside itself.
///
/// A trait rather than direct `/proc` calls so the hostile cases — a slice
/// that cannot be read, an executable that cannot be resolved — can be driven
/// without needing a real cgroup or a real unlinked binary.
pub trait ProcessEvidence {
    /// Every cgroup the process is a member of, as paths.
    fn cgroups(&self, pid: i32) -> Result<Vec<PathBuf>, EvidenceError>;
    /// The process's executable path and the digest of its contents.
    fn executable(&self, pid: i32) -> Result<(PathBuf, ContentDigest), EvidenceError>;
}

/// A fact about a process that could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceError {
    pub what: &'static str,
    pub reason: String,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.what, self.reason)
    }
}

/// The real `/proc` reader.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcFs;

/// The cgroup v2 unified hierarchy, which is where `harden.rs` puts slices.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

impl ProcessEvidence for ProcFs {
    fn cgroups(&self, pid: i32) -> Result<Vec<PathBuf>, EvidenceError> {
        let path = format!("/proc/{pid}/cgroup");
        let text = std::fs::read_to_string(&path).map_err(|e| EvidenceError {
            what: "/proc/<pid>/cgroup",
            reason: e.to_string(),
        })?;
        Ok(parse_cgroup_membership(&text, CGROUP_ROOT))
    }

    fn executable(&self, pid: i32) -> Result<(PathBuf, ContentDigest), EvidenceError> {
        let link = format!("/proc/{pid}/exe");
        // `read_link` rather than canonicalize: a deleted executable must
        // still resolve to the name it had, because a process running a
        // binary that was unlinked underneath it is exactly the case where a
        // content digest is the only thing left to check.
        let path = std::fs::read_link(&link).map_err(|e| EvidenceError {
            what: "/proc/<pid>/exe",
            reason: e.to_string(),
        })?;
        let bytes = std::fs::read(&path).map_err(|e| EvidenceError {
            what: "the caller's executable",
            reason: e.to_string(),
        })?;
        Ok((path, sha256(&bytes)))
    }
}

/// SHA-256 of a byte string.
pub fn sha256(bytes: &[u8]) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Parses `/proc/<pid>/cgroup` into the slice paths the process is in.
///
/// Each line is `hierarchy-id:controller-list:cgroup-path` — **three**
/// fields, not two. Splitting on the first colon leaves the controller list
/// glued to the front of the path, so the last path segment never matches the
/// slice prefix and a caller genuinely sitting in a broker slice reads as
/// outside broker control. That is the failure direction this whole module
/// exists to prevent, so the third field is taken explicitly.
///
/// The controller list is empty for the unified hierarchy this broker writes
/// (`0::/path`) and populated for the v1 lines, which are ignored here: a v1
/// line contributes a path that carries no v2 slice.
pub fn parse_cgroup_membership(contents: &str, root: &str) -> Vec<PathBuf> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            let _hierarchy = fields.next()?;
            let _controllers = fields.next()?;
            let path = fields.next()?.trim();
            if path.is_empty() {
                return None;
            }
            let name = path.rsplit('/').next()?;
            if !name.starts_with(SESSION_SLICE_PREFIX) {
                return None;
            }
            Some(PathBuf::from(root).join(path))
        })
        .collect()
}

/// The broker session slice path for a pid, built by `harden` so the name
/// admission recognises is the name the broker creates.
pub fn session_slice_path(pid: i32) -> PathBuf {
    crate::harden::session_slice_path(std::path::Path::new(CGROUP_ROOT), pid)
}

/// Decides whether `peer` may perform a control-plane verb.
///
/// Returns `Ok(())` only when all three ADR-0015 conditions hold. Any failure
/// is a `Denial` naming the condition, and no failure is ever a pass.
pub fn admit_control_plane(
    peer: &WorkloadIdentity,
    enrolment: &Enrolment,
    evidence: &dyn ProcessEvidence,
) -> Result<(), Denial> {
    // Condition 3, cheapest: the pin is already in hand if it was ever taken.
    if !peer.is_pidfd_pinned() {
        return Err(Denial::Unpinned);
    }

    let pid = peer.credentials.pid;

    // Condition 1, observed rather than inferred. The question "is this
    // process under broker control?" has an answer in procfs, so this reads
    // it instead of concluding anything from the session store.
    let slices = evidence
        .cgroups(pid)
        .map_err(|e| Denial::EvidenceUnavailable {
            what: e.what,
            reason: e.reason,
        })?;
    if let Some(slice) = slices.first() {
        return Err(Denial::UnderBrokerControl {
            slice: slice.clone(),
        });
    }

    // Condition 2, positive: the caller's own executable must be a principal
    // the operator enrolled. A pid would not do — it neither survives a
    // broker restart nor resists being reused.
    let (path, digest) = evidence
        .executable(pid)
        .map_err(|e| Denial::EvidenceUnavailable {
            what: e.what,
            reason: e.reason,
        })?;
    if !enrolment
        .principals
        .iter()
        .any(|p| p.path == path && p.digest == digest)
    {
        return Err(Denial::NotEnrolled { path });
    }

    Ok(())
}
