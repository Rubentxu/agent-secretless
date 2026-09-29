//! The `asv-ebpfd` verb set.
//!
//! `parse_verb` is the closed-surface enforcement point (M7-R5). Any
//! input string that is not one of the four documented verbs is
//! rejected with `VerbError::Unknown`. The function is total: no
//! input reaches the broker's privileged code path without first
//! being recognised here.

use std::fmt;

/// The four verbs `asv-ebpfd` accepts.
///
/// Adding a new verb is a security-relevant change: it requires an
/// updated unit test, an updated integration test, and a deliberate
/// comment in the helper's audit log. Renaming any verb is a
/// breaking change to the broker's IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    /// Bind a session to a cgroup slice.
    SessionAttach,
    /// Unbind a session from its cgroup slice.
    SessionDetach,
    /// Read a cgroup file the broker named (read-only).
    CgroupRead,
    /// Dump the broker's current seccomp filter (read-only).
    SeccompDump,
}

impl Verb {
    /// The canonical wire name of the verb.
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::SessionAttach => "session.attach",
            Verb::SessionDetach => "session.detach",
            Verb::CgroupRead => "cgroup.read",
            Verb::SeccompDump => "seccomp.dump",
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
    /// The verb string is not one of the four recognised verbs.
    #[error("unknown verb: {0}")]
    Unknown(String),
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
        _ => Err(VerbError::Unknown(input.to_string())),
    }
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
        ] {
            assert_eq!(parse_verb(verb.as_str()).unwrap(), verb);
        }
    }

    #[test]
    fn unknown_verb_is_rejected() {
        // M7-S5: anything outside the closed set returns VerbError::Unknown.
        for bad in [
            "",
            "session.attach ",
            "session.attach; rm -rf /",
            "BPF.LOAD",
            "bpf.load",
            "session.attach\nsession.detach",
            "任意.动词",
            "session",
        ] {
            let err = parse_verb(bad).unwrap_err();
            assert_eq!(err, VerbError::Unknown(bad.to_string()));
        }
    }

    #[test]
    fn unknown_verb_carries_the_input_unchanged() {
        // The error carries the offending string for audit. The audit
        // log records the literal input; the helper does not interpret
        // it. That is the contract that makes VerbError::Unknown
        // safe to log.
        let bad = "arbitrary.bpf_load";
        let err = parse_verb(bad).unwrap_err();
        match err {
            VerbError::Unknown(s) => assert_eq!(s, bad),
        }
    }
}
