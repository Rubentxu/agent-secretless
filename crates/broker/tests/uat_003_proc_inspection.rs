//! UAT-003 — process memory attack against broker.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`):
//!
//! > Agent attempts: gdb -p <broker-pid>; strace -p; /proc/<broker>/mem;
//! > process_vm_readv; pidfd_getfd where practical. Expected: denied
//! > under supported hardened installation; no secret disclosure.
//!
//! The harness here runs INSIDE the broker binary's process, so the
//! asserts are about the broker's own state, not about the kernel's
//! view from outside. A separate attack scenario (live ptrace from a
//! child process) would require the broker to be a separate binary
//! and is out of scope for this unit-test harness.

use asv_broker::harden::{dumpable_is_zero, install, no_new_privs_is_set};

#[test]
fn uat_003_install_sets_dumpable_to_zero() {
    install().expect("harden::install must succeed in this test");
    assert!(
        dumpable_is_zero(),
        "PR_SET_DUMPABLE=0 must take effect for the broker's own /proc/<pid>/mem to be unreadable"
    );
}

#[test]
fn uat_003_install_sets_no_new_privs() {
    install().expect("harden::install must succeed in this test");
    assert!(
        no_new_privs_is_set(),
        "PR_SET_NO_NEW_PRIVS=1 must take effect so setuid binaries cannot gain privileges"
    );
}

#[test]
fn uat_003_install_is_repeatable() {
    // Repeated calls must remain idempotent; an attacker that can
    // cause the broker to call harden::install twice (e.g. via a
    // signal handler) MUST NOT be able to escape the protection.
    install().expect("first install");
    install().expect("second install");
    assert!(dumpable_is_zero());
    assert!(no_new_privs_is_set());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "structural: requires a child process to attempt the open; the in-process check is dumpable_is_zero"]
fn uat_003_open_proc_self_mem_returns_eacces_when_undumpable() {
    // The kernel refuses O_RDONLY on /proc/<pid>/mem for an
    // undumpable process unless the opener has CAP_SYS_PTRACE. A
    // structural test of this from the same process is unreliable
    // because the test binary is already running with whatever
    // capabilities the user has. The in-process structural check is
    // uat_003_install_sets_dumpable_to_zero; this test is left here
    // for documentation and for a future adversarial harness that
    // runs the broker as a separate binary.
    let _path = format!("/proc/{}/mem", std::process::id());
}
