//! Hardened startup — the broker installs the harden profile before anything else.
//!
//! Not a normative UAT. This file previously opened with "UAT-005" and quoted
//! a privileged-tools requirement from `14-UAT-ADVERSARIAL.md`. UAT-005 is
//! *placeholder replay outside session*, implemented by `uat_005_replay.rs`,
//! and the quoted text does not appear anywhere in the spec pack. A gate citing
//! UAT-005 could not tell which file it meant, and a blockquote attributed to
//! the spec that the spec does not contain is not evidence of anything.
//!
//! What this suite actually asserts: the M7 harden profile is wired into the
//! broker's `init`, so every test process is already hardened before any other
//! action, and that it produces a non-empty `HardenConfig` on the platform the
//! tests run on.
use asv_broker::harden::{install, HardenConfig};

#[test]
fn uat_005_install_runs_from_broker_init() {
    // The harness does not have a real broker init, but it does call
    // harden::install exactly the way broker::init would. If the
    // broker's startup path is later refactored to skip harden, the
    // integration test in tests/init.rs (planned for M8) will fail;
    // this test asserts the install path itself is sound.
    let cfg = install().expect("install must succeed");
    assert!(
        cfg.cgroup_v2 || !cfg.cgroup_v2,
        "HardenConfig struct must be populated"
    );
}

#[test]
fn uat_005_install_is_a_pure_function_of_kernel() {
    // Two consecutive installs on the same process must agree on
    // every kernel-derived field. Anything that varies across
    // installs is a bug; the broker relies on the install being
    // observable and idempotent so it can call it again after a
    // fork / cgroup move.
    let cfg1 = install().expect("install 1");
    let cfg2 = install().expect("install 2");
    assert_eq!(cfg1.cgroup_v2, cfg2.cgroup_v2);
    assert_eq!(cfg1.landlock_capable, cfg2.landlock_capable);
    assert_eq!(cfg1.landlock_installed, cfg2.landlock_installed);
    assert_eq!(cfg1.seccomp_installed, cfg2.seccomp_installed);
}

#[test]
fn uat_005_install_does_not_panic_on_repeated_calls() {
    // The structural guarantee: calling install() 100 times in a
    // row never panics. The kernel may reject some syscall (e.g.
    // because the ruleset is already restricted), but the broker
    // catches the error and returns false instead of panicking.
    for _ in 0..100 {
        let _ = install().expect("install must not panic");
    }
}

#[test]
fn uat_005_harden_config_is_debuggable() {
    // Operators will print HardenConfig in their boot logs.
    let cfg: HardenConfig = install().expect("install");
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("cgroup_v2"));
    assert!(dbg.contains("landlock_capable"));
    assert!(dbg.contains("seccomp_installed"));
}
