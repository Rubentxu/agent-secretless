//! The `asv-ebpfd` verb set.
//!
//! `parse_verb` is the closed-surface enforcement point (M7-R5, M8-R1).
//! Any input string that is not one of the eight documented verbs is
//! rejected with `VerbError::Unknown`. The function is total: no
//! input reaches the broker's privileged code path without first
//! being recognised here.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// The verbs `asv-ebpfd` accepts.
///
/// M7 surface (4):
/// - `SessionAttach` / `SessionDetach` — bind/unbind a session to a cgroup.
/// - `CgroupRead`    — read a cgroup file the broker named (read-only).
/// - `SeccompDump`   — dump the broker's current seccomp filter.
///
/// M8 surface (4, additive):
/// - `CgroupAttach` / `CgroupDetach` — attach/detach a loaded BPF program to
///   a cgroup id.
/// - `ProgramLoad` / `ProgramUnload` — load/unload a named, shipped program
///   (closed allow-list; never accepts arbitrary bytecode).
///
/// Adding a new verb is a security-relevant change: it requires an updated
/// unit test, an updated integration test, and a deliberate comment in the
/// helper's audit log. Renaming any verb is a breaking change to the
/// broker's IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    // M7 surface
    /// Bind a session to a cgroup slice.
    SessionAttach,
    /// Unbind a session from its cgroup slice.
    SessionDetach,
    /// Read a cgroup file the broker named (read-only).
    CgroupRead,
    /// Dump the broker's current seccomp filter (read-only).
    SeccompDump,
    // M8 surface
    /// Attach a loaded BPF program to a cgroup id.
    CgroupAttach,
    /// Detach a previously attached BPF program.
    CgroupDetach,
    /// Load a shipped (signed) BPF program by name.
    ProgramLoad,
    /// Unload a previously loaded BPF program.
    ProgramUnload,
}

impl Verb {
    /// The canonical wire name of the verb.
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::SessionAttach => "session.attach",
            Verb::SessionDetach => "session.detach",
            Verb::CgroupRead => "cgroup.read",
            Verb::SeccompDump => "seccomp.dump",
            Verb::CgroupAttach => "cgroup.attach",
            Verb::CgroupDetach => "cgroup.detach",
            Verb::ProgramLoad => "program.load",
            Verb::ProgramUnload => "program.unload",
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a verb was rejected by `parse_verb`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerbError {
    /// The verb string is not one of the recognised verbs.
    #[error("unknown verb: {0}")]
    Unknown(String),
    /// The verb was known and the argument type was wrong.
    #[error("invalid argument for {verb}: {detail}")]
    InvalidArgument {
        /// The verb that was called.
        verb: &'static str,
        /// Why the argument was rejected.
        detail: String,
    },
}

/// Parses a wire-format verb into the closed `Verb` enum.
///
/// `parse_verb` is the only function in the crate that turns a
/// caller-controlled string into a privileged operation. It MUST be
/// the first thing called on any incoming request.
pub fn parse_verb(input: &str) -> Result<Verb, VerbError> {
    match input {
        "session.attach" => Ok(Verb::SessionAttach),
        "session.detach" => Ok(Verb::SessionDetach),
        "cgroup.read" => Ok(Verb::CgroupRead),
        "seccomp.dump" => Ok(Verb::SeccompDump),
        "cgroup.attach" => Ok(Verb::CgroupAttach),
        "cgroup.detach" => Ok(Verb::CgroupDetach),
        "program.load" => Ok(Verb::ProgramLoad),
        "program.unload" => Ok(Verb::ProgramUnload),
        _ => Err(VerbError::Unknown(input.to_string())),
    }
}

/// Identifies a shipped BPF program by `name`. Returns `None` for any
/// input not in the table — there is intentionally no path that accepts
/// arbitrary bytecode or a path to a `.bpf.o` file.
///
/// The single entry here is the prototype `connect4-redirect-v1` from
/// M8 spec. The actual ELF body and the Aya generator are M9 scope.
pub fn program_lookup(name: &str) -> Option<ProgramId> {
    match name {
        "connect4-redirect-v1" => Some(ProgramId::Connect4RedirectV1),
        _ => None,
    }
}

/// Stable identifier for a shipped BPF program.
///
/// Each variant corresponds to exactly one shipped ELF object in the
/// broker's M9 deliverable. The variant's `as_str()` is the wire name
/// used in `program_lookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramId {
    /// `connect4-redirect-v1` — CGROUP_SOCK_ADDR program that rewrites
    /// IPv4 connect destinations inside a protected cgroup.
    Connect4RedirectV1,
}

impl ProgramId {
    /// The canonical wire name of the program.
    pub fn as_str(self) -> &'static str {
        match self {
            ProgramId::Connect4RedirectV1 => "connect4-redirect-v1",
        }
    }
}

/// Why `asv-ebpfd` failed an operation (verb-specific).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HelperError {
    /// The argument to the verb was rejected.
    #[error("argument rejected: {0}")]
    Argument(String),
}

/// Stable handle returned from `CgroupAttach`. In M9 the inner value is
/// the kernel `bpf_link` fd. In M8 it is a placeholder so the API surface
/// is documented end-to-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachHandle(pub i32);

/// Parses a wire-format cgroup id for `CgroupAttach` (M8-R3).
///
/// Accepted forms, mirroring what the helper itself emits and what
/// cgroup v2 files show:
/// - decimal: `"4660"` -> `Ok(0x1234)`
/// - `0x`-prefixed lowercase hex (the audit-line echo form):
///   `"0x1234"` -> `Ok(0x1234)`
///
/// Everything else is `VerbError::InvalidArgument` with the reason in
/// `detail`. This is where path-like inputs die: `"/sys/fs/cgroup/..."`
/// (absolute), `"../escape"` (traversal), `""` (empty), `"12x"`
/// (malformed) and values above `u64::MAX` are all rejected here, before
/// any privileged surface is reached.
pub fn parse_cgroup_id(input: &str) -> Result<u64, VerbError> {
    let reject = |detail: String| VerbError::InvalidArgument {
        verb: "cgroup.attach",
        detail,
    };
    if input.is_empty() {
        return Err(reject("empty cgroup id".to_string()));
    }
    if input.contains('/') {
        // Covers absolute paths (`/sys/fs/cgroup/...`) and traversals
        // (`../escape`): M8-R3 forbids path-based arguments outright.
        return Err(reject(format!(
            "path-like input is not a cgroup id: {input:?}"
        )));
    }
    let (digits, radix) = if let Some(hex) = input.strip_prefix("0x") {
        (hex, 16)
    } else {
        (input, 10)
    };
    if digits.is_empty() {
        return Err(reject(format!("no digits in cgroup id: {input:?}")));
    }
    u64::from_str_radix(digits, radix)
        .map_err(|e| reject(format!("malformed cgroup id {input:?}: {e}")))
}

/// Monotonic per-helper audit sequence (M8-R4).
///
/// The helper binary (M9) owns exactly one counter; every privileged
/// verb execution takes the next number immediately before emitting its
/// audit line, so the audit log can detect drops (a gap means a lost
/// line, which is itself an auditable event).
///
/// `Relaxed` ordering suffices: the number is consumed on the same
/// thread that formats and writes the line, so there is no pairing to
/// synchronize.
#[derive(Default)]
pub struct AuditCounter(AtomicU64);

impl AuditCounter {
    /// First `next()` returns 1 (the audit log is 1-based).
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Returns 1, 2, 3, ... monotonically for the life of the process.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Formats the single audit line M8-R4 requires per privileged verb.
///
/// Factored out of the `eprintln!` so tests can assert the exact shape
/// without capturing stderr.
pub fn format_audit_line(verb: &str, arg: &str, sequence: u64) -> String {
    format!("asv-ebpfd: {verb} {arg} sequence={sequence}")
}

/// Prototype for the M9 cgroup-attach syscall. In M8 the body is a
/// no-op that returns `Ok(AttachHandle(0))`. The signature and the
/// doc-comment are the authoritative ABI the M9 implementer fills in.
///
/// M9 implementation:
///   - validate `cgroup_id` is in the broker-owned set (returned from a
///     prior `CgroupRead`),
///   - call `bpf_link_create` with `BPF_LINK_TYPE_CGROUP`,
///   - on success, wrap the returned fd in `AttachHandle`,
///   - emit an audit line at `sequence=N`.
pub fn cgroup_attach_skeleton(
    cgroup_id: u64,
    program_id: ProgramId,
    sequence: u64,
) -> Result<AttachHandle, HelperError> {
    // M8: structural skeleton only — does not perform any syscall. The
    // audit line is the structural proof the surface is wired; M9 will
    // call `bpf_link_create` here and thread the real session id.
    eprintln!(
        "{}",
        format_audit_line(
            "cgroup.attach",
            &format!(
                "cgroup_id=0x{cgroup_id:x} program={} session=prototype",
                program_id.as_str()
            ),
            sequence
        )
    );
    let _ = (cgroup_id, program_id);
    Ok(AttachHandle(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_set_round_trips() {
        for verb in [
            Verb::SessionAttach,
            Verb::SessionDetach,
            Verb::CgroupRead,
            Verb::SeccompDump,
            Verb::CgroupAttach,
            Verb::CgroupDetach,
            Verb::ProgramLoad,
            Verb::ProgramUnload,
        ] {
            assert_eq!(parse_verb(verb.as_str()).unwrap(), verb);
        }
    }

    #[test]
    fn unknown_verb_is_rejected() {
        // M7-S5 + M8-S1: anything outside the closed set returns
        // VerbError::Unknown.
        for bad in [
            "",
            "session.attach ",
            "session.attach; rm -rf /",
            "BPF.LOAD",
            "bpf.load",
            "session.attach\nsession.detach",
            "任意.动词",
            "session",
            // M8-S1 additional adversarial inputs:
            "bpf.load_arbitrary",
            "BPF.LOAD",
            "cgroup.write",
            "cgroup.move",
            "cgroup.freeze",
            "cgroup.kill",
            "program.load_arbitrary",
            "program.attach_arbitrary",
        ] {
            let err = parse_verb(bad).unwrap_err();
            assert_eq!(err, VerbError::Unknown(bad.to_string()));
        }
    }

    #[test]
    fn unknown_verb_carries_the_input_unchanged() {
        // The error carries the offending string for audit. The audit
        // log records the literal input; the helper does not interpret
        // it. That is the contract that makes VerbError::Unknown safe
        // to log.
        let bad = "arbitrary.bpf_load";
        let err = parse_verb(bad).unwrap_err();
        // The exhaustive match documents that Unknown and InvalidArgument
        // are the only failure modes. We assert the Unknown branch
        // here; the InvalidArgument branch is exercised by the
        // cgroup-attach arg-validation tests below.
        match err {
            VerbError::Unknown(s) => assert_eq!(s, bad),
            VerbError::InvalidArgument { .. } => {
                panic!("Unknown verb must not produce InvalidArgument")
            }
        }
    }

    #[test]
    fn program_lookup_returns_connect4_redirect_v1_only() {
        // M8-S2: shipped name accepted; arbitrary name rejected.
        assert_eq!(
            program_lookup("connect4-redirect-v1"),
            Some(ProgramId::Connect4RedirectV1)
        );
        for bad in [
            "bpf.load_arbitrary",
            "BPF.LOAD",
            "arbitrary.o",
            "/etc/asv/bpf.so",
            "connect4-redirect-v2",
            "",
        ] {
            assert_eq!(program_lookup(bad), None);
        }
    }

    #[test]
    fn program_id_str_round_trips() {
        assert_eq!(
            program_lookup(ProgramId::Connect4RedirectV1.as_str()),
            Some(ProgramId::Connect4RedirectV1)
        );
    }

    #[test]
    fn cgroup_attach_skeleton_returns_ok_with_zero_handle() {
        // M8-S5: structural prototype returns Ok(0) without panicking.
        let handle = cgroup_attach_skeleton(0x1234, ProgramId::Connect4RedirectV1, 1)
            .expect("skeleton must succeed");
        assert_eq!(handle, AttachHandle(0));
    }

    #[test]
    fn cgroup_attach_skeleton_accepts_max_cgroup_id() {
        let handle =
            cgroup_attach_skeleton(u64::MAX, ProgramId::Connect4RedirectV1, 1).expect("ok");
        assert_eq!(handle, AttachHandle(0));
    }

    // ----- M8-R3: wire-format cgroup id parsing -------------------------

    #[test]
    fn parse_cgroup_id_accepts_decimal_and_hex() {
        assert_eq!(parse_cgroup_id("4660"), Ok(0x1234));
        assert_eq!(parse_cgroup_id("0x1234"), Ok(0x1234));
        assert_eq!(parse_cgroup_id("0"), Ok(0));
        assert_eq!(parse_cgroup_id("0x0"), Ok(0));
        assert_eq!(parse_cgroup_id(&format!("{}", u64::MAX)), Ok(u64::MAX));
    }

    #[test]
    fn parse_cgroup_id_rejects_paths_and_malformed() {
        // Spec M8-R3 scenario: path-based inputs are InvalidArgument.
        for bad in [
            "/sys/fs/cgroup/asv.slice",
            "../escape",
            "",
            "12x",
            "0x",
            " ",
            "18446744073709551616", // u64::MAX + 1
            "0xdeadbeefZZ",
        ] {
            match parse_cgroup_id(bad) {
                Err(VerbError::InvalidArgument { verb, .. }) => {
                    assert_eq!(verb, "cgroup.attach");
                }
                other => panic!("parse_cgroup_id({bad:?}) must be InvalidArgument, got {other:?}"),
            }
        }
    }

    // ----- M8-R4: monotonic audit sequence ------------------------------

    #[test]
    fn audit_counter_is_monotonic_from_one() {
        let counter = AuditCounter::new();
        assert_eq!(counter.next(), 1);
        assert_eq!(counter.next(), 2);
        assert_eq!(counter.next(), 3);
    }

    #[test]
    fn audit_line_format_carries_verb_arg_and_sequence() {
        assert_eq!(
            format_audit_line(
                "cgroup.attach",
                "cgroup_id=0x1234 program=connect4-redirect-v1",
                7
            ),
            "asv-ebpfd: cgroup.attach cgroup_id=0x1234 program=connect4-redirect-v1 sequence=7"
        );
    }
}
