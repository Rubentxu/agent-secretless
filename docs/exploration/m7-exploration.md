# M7 Exploration Report

## Goal of this exploration

Decide whether M7 can land with the dependency surface already in the
broker crate, or whether new crates (notably `asv-ebpfd` and a
hardening primitive module) are required.

## Findings

### F1 — `crates/broker/src/lib.rs` references cgroup paths but does not create them

The `BrokerState` records mention cgroup evidence ("to correlate a
session with cgroup evidence"). No code creates the cgroup slice, no
code calls `prctl(PR_SET_DUMPABLE)`, no code installs a Landlock
ruleset. M7 must add these.

### F2 — `nix` is already a workspace dep

The broker already depends on `nix = { version = "0.29", features = ["socket", "uio", "user", "fs"] }`. `nix 0.29` exposes:

- `nix::sys::prctl` (M7-R1: `PR_SET_DUMPABLE`, `PR_SET_NO_NEW_PRIVS`)
- `nix::unistd::Pid` for cgroup operations
- `nix::fcntl` for file open flags

`nix` does not expose Landlock directly in 0.29 (Landlock landed in
`landlock` crate or via raw `libc::syscall`). M7 will use raw libc
for Landlock, behind a `cfg(target_os = "linux")` gate.

### F3 — A separate `asv-ebpfd` helper is described as a "skeleton"

The roadmap calls it a "privilege-separated helper skeleton", not a
shipped feature. The M7 deliverable is therefore:

1. A crate `crates/ebpfd/` with the verb set closed
   (`session.attach`, `session.detach`, `cgroup.read`, `seccomp.dump`).
2. A unit test that asserts any unknown verb is rejected.
3. Documentation describing how the helper is invoked at the
   kernel boundary.

### F4 — cgroup v2 may not be available in the build environment

This is a real risk. The unit tests must be `#[cfg(target_os = "linux")]`
and use `cfg(target_os)` to skip when cgroup v2 is absent. The CI
matrix already runs on `ubuntu-latest` which has cgroup v2 (unified
hierarchy) since 22.04. We will:

- Run a `which_cgroup_v2()` probe at startup; refuse to start if absent
  on Linux (fail-closed).
- Skip the cgroup tests with `#[cfg]` gates when the probe returns
  `None`.

### F5 — Landlock requires Linux ≥ 5.13

The crate will compile only on Linux. Tests will be gated by
`cfg(all(target_os = "linux", feature = "landlock"))`. The feature
flag is opt-in because some CI images run older kernels.

## What this exploration does not cover

- A live ptrace attack (would require two processes and a privileged
  capability). We will write a test that *asserts the broker's own
  state*, not a full live attack.
- A SELinux/AppArmor policy (out of scope for the Linux-target).
- The full eBPF redirect path (M8).

## Conclusion

M7 is implementable as a new module
`crates/broker/src/harden.rs` plus a new crate `crates/ebpfd/`. The
work is local to the broker binary plus a small helper. No
architectural surprises. The exploration is sufficient to move to
Specify.