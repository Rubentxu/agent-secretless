# M7 Specification

## Scope and source

Sources: M7 roadmap (`agent-secretless-vault-spec/docs/15-ROADMAP.md`),
UAT-003/023/024 in `14-UAT-ADVERSARIAL.md`, the threat model §2,
and ADR-0002 (broker isolation).

M7 makes the broker (and the eventual `asv-ebpfd` helper) harder
to inspect or escape from the agent's process tree. It is **not** a
general-purpose sandbox; the agent still runs outside the broker.
The point is to make `gdb -p`, `strace -p`, `/proc/<pid>/mem`,
`process_vm_readv`, `pidfd_getfd`, and cgroup `move` attempts either
denied by the kernel or denied by a structural refusal on the
broker side. M8/M9 add the eBPF redirect; M7 stops at hardening.

## ADDED Requirements

### M7-R1 The broker refuses ptrace/process_vm/pidfd inspection attempts

A peer (or a process in the agent's tree) that attempts to attach to
the broker via ptrace, read its `/proc/<pid>/mem`, or call
`process_vm_readv` on the broker process MUST be denied by the broker's
own `ptrace_scope` (a `PR_SET_DUMPABLE` of 0 and a `prctl(PR_SET_NO_NEW_PRIVS)`
on its own thread) and by the kernel's `kernel.yama.ptrace_scope`.

#### Scenario M7-S1: ptrace attach is refused

- **Given** the broker is running with `PR_SET_DUMPABLE=0` and
  `kernel.yama.ptrace_scope >= 1`
- **When** a process in the agent's tree calls `ptrace(PTRACE_ATTACH, broker_pid)`
- **Then** the kernel returns EPERM
- **And** the broker process is unaffected (no SIGSTOP delivered)

### M7-R2 The broker owns a dedicated cgroup v2 slice

A `asv-session` cgroup v2 slice is created by the broker on startup;
every session record is associated with the slice's path; an agent
that tries to move itself out of the slice via `cgroup.procs` writes
is denied.

#### Scenario M7-S2: cross-cgroup move is refused

- **Given** the broker has created `/sys/fs/cgroup/asv.session.<id>`
  and added its own PID
- **When** an unprivileged agent process writes the broker's PID to
  another cgroup's `cgroup.procs`
- **Then** the kernel returns EOPNOTSUPP (the broker UID is not the
  cgroup owner) or the broker's own cgroup-watchdog detects the move
  and tears the session down

### M7-R3 The broker applies a Landlock ruleset before opening the vault

Before `VaultStore::open`, the broker installs a Landlock ruleset
that allows read access to the vault file and the public certificate
store, and denies everything else. Once installed, the ruleset is
irreversible for the process (Landlock semantics on Linux ≥ 5.13).

#### Scenario M7-S3: post-Landlock file access is restricted

- **Given** the broker has installed the M7 Landlock ruleset
- **When** the broker attempts to open any file outside the ruleset's
  allow-list
- **Then** `open()` returns EACCES or the path is denied by a
  "rule not found" error
- **And** the broker's own audits (`~/.local/state/asv/audit.jsonl`)
  record the deny

### M7-R4 The broker applies a conservative seccomp filter

The broker installs a seccomp-bpf filter (or seccomp notify, behind
the `asv-ebpfd` helper) that denies `ptrace`, `process_vm_readv`,
`kexec_load`, `bpf`, `init_module`, `finit_module`, and the
`userfaultfd`/`perf_event_open` paths that have been used as
exfiltration vectors in CVE history. The filter is verified by
`seccomp-tools dump` in the install smoke test.

#### Scenario M7-S4: seccomp filter rejects dangerous syscalls

- **Given** the broker has installed the M7 seccomp filter
- **When** a compromised broker thread calls `ptrace` or `bpf`
- **Then** the process receives SIGSYS and exits non-zero
- **And** the audit log records the offending thread's session

### M7-R5 `asv-ebpfd` has no arbitrary code-loading surface

The privileged helper `asv-ebpfd` exposes a closed verb set:
`session.attach`, `session.detach`, `cgroup.read`, `seccomp.dump`.
It does not accept arbitrary BPF bytecode, generic cgroup writes,
or any verb that could be repurposed into a privilege-escalation
primitive.

#### Scenario M7-S5: asv-ebpfd refuses unrecognised verbs

- **Given** the broker is connected to `asv-ebpfd`
- **When** any caller sends a verb other than the closed set
- **Then** `asv-ebpfd` returns `ENOENT` or `EPROTO`
- **And** the connection is closed and logged

## Verification

This milestone's exit is UAT-003, UAT-023, and UAT-024. Each is
falsified by a regression test under
`crates/broker/tests/uat_003_proc_inspection.rs`,
`crates/broker/tests/uat_023_cgroup_escape.rs`, and
`crates/broker/tests/uat_024_helper_scope.rs`.

## What is deliberately out of scope

- The full eBPF redirect path (M8 R&D gate, M9 ship).
- A SELinux/AppArmor policy (the broker targets systemd + Landlock).
- A full perf/fuzz campaign over the M7 syscalls (M13's stability work).
- macOS or Windows hardening (out of scope for the Linux target).
