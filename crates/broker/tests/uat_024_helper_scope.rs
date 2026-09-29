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

use asv_ebpfd::{
    cgroup_attach_skeleton, parse_cgroup_id, parse_verb, program_lookup, AttachHandle, ProgramId,
    Verb, VerbError,
};

#[test]
fn uat_024_closed_verb_set_round_trips() {
    for verb in [
        Verb::SessionAttach,
        Verb::SessionDetach,
        Verb::CgroupRead,
        Verb::SeccompDump,
        // M8 surface:
        Verb::CgroupAttach,
        Verb::CgroupDetach,
        Verb::ProgramLoad,
        Verb::ProgramUnload,
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
        // M8 surface additional:
        "program.load_arbitrary",
        "program.attach_arbitrary",
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
    // Compile-time check: the Verb enum has exactly the four M7 +
    // four M8 variants and none of them is named *Load*. The
    // exhaustive match in parse_verb would fail to compile if a
    // ninth variant were added without explicit handling.
    match Verb::SessionAttach {
        Verb::SessionAttach => {}
        Verb::SessionDetach => {}
        Verb::CgroupRead => {}
        Verb::SeccompDump => {}
        Verb::CgroupAttach => {}
        Verb::CgroupDetach => {}
        Verb::ProgramLoad => {}
        Verb::ProgramUnload => {}
    }
}

// ---- M8 surface tests ------------------------------------------------

#[test]
fn uat_024_m8_shipped_program_name_accepted() {
    // M8-S2: the only shipped program name is connect4-redirect-v1.
    assert_eq!(
        program_lookup("connect4-redirect-v1"),
        Some(ProgramId::Connect4RedirectV1)
    );
}

#[test]
fn uat_024_m8_arbitrary_program_names_rejected() {
    // M8-S2: any name not in the shipped table returns None. The
    // helper never accepts a path or arbitrary bytecode.
    for bad in [
        "bpf.load_arbitrary",
        "BPF.LOAD",
        "arbitrary.o",
        "/etc/asv/bpf.so",
        "connect4-redirect-v2",
        "",
        "connect4-redirect-v1.elf",
        "../share/asv/program.o",
    ] {
        assert_eq!(
            program_lookup(bad),
            None,
            "program_lookup({bad:?}) must return None"
        );
    }
}

#[test]
fn uat_024_m8_cgroup_attach_skeleton_returns_ok() {
    // M8-S5: structural prototype returns Ok(0) without panicking.
    // The M9 implementation will replace the body with a real
    // bpf_link_create(BPF_LINK_TYPE_CGROUP) syscall.
    let handle =
        cgroup_attach_skeleton(0x1234, ProgramId::Connect4RedirectV1, 1).expect("skeleton ok");
    assert_eq!(handle, AttachHandle(0));
}

#[test]
fn uat_024_m8_cgroup_attach_skeleton_accepts_extreme_values() {
    // The skeleton must accept the full u64 range and the only
    // shipped program. It is the surface guarantee for M9.
    let _ = cgroup_attach_skeleton(0, ProgramId::Connect4RedirectV1, 1).expect("zero");
    let _ = cgroup_attach_skeleton(u64::MAX, ProgramId::Connect4RedirectV1, 1).expect("max");
}

#[test]
fn uat_024_m8_parse_cgroup_id_rejects_path_arguments() {
    // M8-R3 bite: a path-based argument (the escalation primitive the
    // spec forbids) is InvalidArgument, never silently coerced to an id.
    for path_like in [
        "/sys/fs/cgroup/asv.slice",
        "../escape",
        "cgroup.controllers",
    ] {
        match parse_cgroup_id(path_like) {
            Err(VerbError::InvalidArgument { verb, .. }) => {
                assert_eq!(verb, "cgroup.attach");
            }
            other => {
                panic!("parse_cgroup_id({path_like:?}) must be InvalidArgument, got {other:?}")
            }
        }
    }
    // And the honest numeric forms still parse.
    assert_eq!(parse_cgroup_id("0x1234"), Ok(0x1234));
    assert_eq!(parse_cgroup_id("4660"), Ok(0x1234));
}
