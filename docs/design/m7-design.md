# M7 Design — Linux hardened sessions

## Goal

Land the five M7 requirements (M7-R1..R5) by adding:

1. A `harden` module in `crates/broker/` that sets `PR_SET_DUMPABLE`,
   `PR_SET_NO_NEW_PRIVS`, and creates a cgroup v2 slice.
2. A new crate `crates/ebpfd/` exposing the closed verb set
   described in M7-R5.
3. Regression tests under `crates/broker/tests/uat_003_proc_inspection.rs`,
   `crates/broker/tests/uat_023_cgroup_escape.rs`,
   `crates/broker/tests/uat_024_helper_scope.rs`.

## Crate topology

```
crates/
  broker/
    src/
      harden.rs       # NEW: PR_SET_DUMPABLE, cgroup slice, Landlock probe
      lib.rs          # calls harden::install() at startup
    tests/
      uat_003_proc_inspection.rs  # NEW
      uat_023_cgroup_escape.rs    # NEW
      uat_024_helper_scope.rs     # NEW
  ebpfd/                       # NEW crate
    Cargo.toml
    src/
      lib.rs            # closed verb set
      verbs.rs          # dispatch + log unknown
      verbs/tests.rs    # unit tests
```

## harden::install()

The function `harden::install(config: &HardenConfig) -> Result<(), HardenError>` does:

1. `prctl(PR_SET_DUMPABLE, 0)` — disable `PTRACE_ATTACH` reads of
   `/proc/<pid>/mem`.
2. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — disable setuid binaries.
3. On Linux only, attempt to create `/sys/fs/cgroup/asv.session.<id>`
   if cgroup v2 is available. The PID is added to `cgroup.procs`.
4. On Linux ≥ 5.13 (detected via `uname()`), probe Landlock. If
   absent, log a warning and continue (fail-soft on Landlock, because
   older kernels are still in use). The Landlock *install* step is a
   no-op stub in this commit; it is wired into a follow-up.
5. Returns the cgroup slice path so the broker can record it on the
   session.

The function is idempotent: repeated calls are no-ops.

## cgroup v2 detection

```rust
pub fn detect_cgroup_v2() -> Option<PathBuf> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in mountinfo.lines() {
        // unified hierarchy mount of cgroup2
        if line.contains(" cgroup2 ") {
            return Some(PathBuf::from("/sys/fs/cgroup"));
        }
    }
    None
}
```

This is a synchronous probe. The broker calls it at startup and
records the result in `HardenConfig`.

## asv-ebpfd verb set

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    SessionAttach,
    SessionDetach,
    CgroupRead,
    SeccompDump,
}

pub fn parse_verb(input: &str) -> Result<Verb, VerbError> {
    match input {
        "session.attach" => Ok(Verb::SessionAttach),
        "session.detach" => Ok(Verb::SessionDetach),
        "cgroup.read"    => Ok(Verb::CgroupRead),
        "seccomp.dump"   => Ok(Verb::SeccompDump),
        _ => Err(VerbError::Unknown(input.to_string())),
    }
}
```

`parse_verb` is the closed-surface enforcement point. The unit test
`verbs::tests::unknown_verb_is_rejected` covers M7-S5.

## Tests

### uat_003_proc_inspection.rs

The test asserts:

- `harden::dumpable_is_zero()` returns `true` after `install()`.
- `harden::no_new_privs_is_set()` returns `true` after `install()`.
- A `read_proc_mem_attempt()` helper tries to read `/proc/self/mem`
  with a 0-byte buffer. If the process is dumpable, the kernel
  accepts the open; if not, it returns EACCES.

### uat_023_cgroup_escape.rs

The test asserts:

- `harden::cgroup_path()` returns the slice path under
  `/sys/fs/cgroup/asv.session.<id>` when cgroup v2 is available.
- When cgroup v2 is unavailable (CI on macOS), the test is
  `#[ignore]`-d with a comment explaining the gate.

### uat_024_helper_scope.rs

The test asserts:

- `asv_ebpfd::parse_verb("session.attach")` is `Ok(Verb::SessionAttach)`.
- `asv_ebpfd::parse_verb("arbitrary.bpf_load")` is `Err(VerbError::Unknown)`.
- The unit test in `crates/ebpfd/src/verbs.rs` covers the same shape.

## Estimated size

- `crates/broker/src/harden.rs` ~200 LOC
- `crates/broker/tests/uat_003_*.rs` ~80 LOC
- `crates/broker/tests/uat_023_*.rs` ~50 LOC
- `crates/broker/tests/uat_024_*.rs` ~50 LOC
- `crates/ebpfd/Cargo.toml` ~30 LOC
- `crates/ebpfd/src/lib.rs` ~40 LOC
- `crates/ebpfd/src/verbs.rs` ~80 LOC
- edits to `crates/broker/src/lib.rs` ~10 LOC
- edits to `Cargo.toml` (workspace) ~3 LOC

Total ~540 LOC, much smaller than M6 because M7 is configuration and
verification rather than new connectors.