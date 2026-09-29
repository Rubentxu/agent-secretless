//! UAT-024 — privileged helper scope.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`):
//!
//! > Compromised unprivileged client asks `asv-ebpfd` to load arbitrary
//! > BPF bytecode or alter unrelated cgroups. Expected: protocol has no
//! > such operation; request rejected.
//!
//! The broker's `ConnectorFactory`-equivalent for the privileged
//! helper is the `parse_verb` function in `asv-ebpfd`. The unit test
//! in that crate covers the parser; this integration test exercises
//! the same shape from the broker's side and asserts that there is
//! no verb in the helper's vocabulary that could be repurposed for
//! arbitrary BPF load or generic cgroup writes.

use asv_ebpfd::{parse_verb, Verb, VerbError};

#[test]
fn uat_024_closed_verb_set_round_trips() {
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
fn uat_024_arbitrary_bpf_load_is_rejected() {
    // The attacker's payload would be a verb that asks the
    // privileged helper to load arbitrary BPF. There is no such
    // verb. The parser rejects every input outside the closed set.
    for bad in [
        "bpf.load",
        "bpf.load_arbitrary",
        "BPF.LOAD",
        "session.attach.bpf_load",
        "bpf",
    ] {
        let err = parse_verb(bad).unwrap_err();
        assert_eq!(err, VerbError::Unknown(bad.to_string()));
    }
}

#[test]
fn uat_024_generic_cgroup_write_is_rejected() {
    // The attacker's payload would be a verb that asks the helper
    // to write to an arbitrary cgroup. There is no such verb.
    for bad in [
        "cgroup.write",
        "cgroup.move",
        "cgroup.procs",
        "cgroup.freeze",
        "cgroup.kill",
    ] {
        let err = parse_verb(bad).unwrap_err();
        assert_eq!(err, VerbError::Unknown(bad.to_string()));
    }
}

#[test]
fn uat_024_verb_enum_has_no_load_variant() {
    // Compile-time check: the Verb enum has exactly four variants
    // and none of them is named *Load*. The exhaustive match in
    // parse_verb would fail to compile if a fifth variant were
    // added without explicit handling.
    match Verb::SessionAttach {
        Verb::SessionAttach => {}
        Verb::SessionDetach => {}
        Verb::CgroupRead => {}
        Verb::SeccompDump => {}
    }
}
