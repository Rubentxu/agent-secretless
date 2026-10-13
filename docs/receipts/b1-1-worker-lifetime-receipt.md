# B1.1 Implementation Receipt — Worker lifetime, process-group reaper

## What landed

- **`crates/broker/src/worker.rs` — process-group reaper.** Three changes,
  one bug surface:
  1. `pre_exec` now calls `libc::setsid(2)` *before* `child_isolation_hook`.
     The worker becomes the leader of a fresh process group, so its PID
     is also its PGID and process-group signals reach every descendant
     the worker forked.
  2. `terminate_with_grace` uses `libc::killpg(child.id(), SIGTERM)`
     followed by `libc::killpg(child.id(), SIGKILL)` instead of
     `kill(pid)`. The grace period and the SIGKILL fallback are
     unchanged.
  3. An unconditional `libc::killpg(child.id(), SIGKILL)` fires after
     `wait_with_timeout` returns, **before** the bounded readers are
     joined. This is the safety net for the case the original bug
     describes: the leader exited cleanly before the cap, the runner
     never reaped the sleeper that inherited stdout/stderr, and the
     bounded reader was waiting for EOF that only arrives when the
     sleeper dies. SIGKILL closes the inherited FDs, the reader
     notices EOF, the join returns.
- **`crates/broker/src/isolated_exec.rs` — typed `PostureLabel` enum.**
  The `pub const POSTURE_LABEL: &str = "ISOLATED_PROCESS_EXPOSURE"`
  const is preserved (the audit row in `uat_040_posture_label_in_audit_record`
  pins the literal wire name); on top of it, a typed `PostureLabel`
  enum with two variants (`StrongSecretless`, `IsolatedProcessExposure`)
  and a `wire_name()` mapping that is a total `match` with no wildcard
  arm. `Default::default()` returns `IsolatedProcessExposure` (user-
  authorised option A for B1.1: no cgroup probe, no `degraded_reason`
  field yet). B1.3 will add the `degraded_reason` field and a
  cgroup-probe feature flag; `Default::default()` becomes the single
  switch point.
- **`crates/broker/tests/uat_040_isolated_worker_runtime.rs` — two
  new UAT-040 rows.** `uat_040_descendant_holding_stdout_does_not_block_join`
  and `uat_040_runaway_grandchild_is_killed_with_the_group`, with the
  `fd_holding_template` and `orphan_template` helpers.
- **Pre-existing test updated.** `worker::tests::timeout_sends_term_before_kill_and_reaps_worker`
  in `crates/broker/src/worker.rs` now installs its own `pre_exec`
  that calls `setsid`, satisfying the new caller contract of
  `terminate_with_grace`: the child must be the leader of its process
  group. Without that change, process-group signaling would target the
  runner's own process group and tear the test process down.

## Commits

- `171be5a` feat(broker): typed PostureLabel enum for B1.1/B1.3
- `8d9dcd9` fix(broker): reap the worker process group, not only the leader
- `e8dbaab` test(broker): UAT-040 rows for the process-group reaper

## Exit UAT

- `uat_040_descendant_holding_stdout_does_not_block_join` (new)
- `uat_040_runaway_grandchild_is_killed_with_the_group` (new)
- `uat_040_posture_label_in_audit_record` (pre-existing; pins the
  `ISOLATED_PROCESS_EXPOSURE` wire name; the enum refactor preserves
  it exactly)

## Evidence

```
$ cargo test -p asv-broker --test uat_040_isolated_worker_runtime
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.72s

$ cargo test -p asv-broker --lib timeout_sends_term
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 670 filtered out; finished in 0.06s

$ cargo clippy -p asv-broker --tests -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.10s

$ cargo fmt -p asv-broker
(no output)
```

Red→green numbers (seconds, elapsed on the failing assertion):

| test | pre-fix | post-fix |
| --- | --- | --- |
| `uat_040_descendant_holding_stdout_does_not_block_join` | 5.005 | 0.03 |
| `uat_040_runaway_grandchild_is_killed_with_the_group` | 60.01 | 0.12 |

## Honest observations

- **The full broker suite (≈1227 tests) was not run in this session.**
  `cargo test -p asv-broker` was repeatedly blocked by another agent's
  `cargo test` holding the same target-dir lock (cognicode-core,
  guard-application, etc.). The evidence above is the 18 tests of
  `uat_040` plus the one pre-existing test that the new caller
  contract required updating, plus `clippy` and `fmt` on the broker
  crate. The full suite must be re-run before the B0 release; the
  coverage of the changed surface is complete, but the rest of the
  broker is unverified in this session.
- **The decision to always use `killpg` (no `getpgid` + `kill(pid)`
  fallback) was driven by a real failure.** My first attempt added a
  `getpgid(pid)` check and a `kill(pid)` fallback for callers that did
  not use `pre_exec`+`setsid`. The fallback failed silently: in the
  exact scenario this receipt fixes, the leader is reaped by
  `wait_with_timeout` *before* my code runs, so `getpgid(leader_pid)`
  returns `-1/ESRCH`, the `pgid == pid` check is false, and the
  fallback `kill(pid)` is sent to a no-longer-existing process. The
  sleeper outlives the broker. The right answer is to assume the
  caller made the child the leader (the broker guarantees it via
  `pre_exec`) and use `killpg` always; the pre-existing test is the
  only other caller of `terminate_with_grace` and it now installs its
  own `setsid`.
- **The helper-C compilation detour was expensive and is worth
  recording.** The first three attempts to reproduce the bug in
  isolation (`/bin/sh -c "sleep 5 &"`, `perl -e 'fork; exec sleep 5'`,
  a C helper compiled in `/tmp`) all failed to reproduce, for
  different reasons: bash job control reaps the sleeper, perl sets
  CLOEXEC on the child's FD 1/2 so the kernel closes the inherited
  pipe, and the `/tmp` sticky bit denies `execve` from inside the
  landlocked broker. The form that reproduces is
  `/bin/sh -c "exec 3>&1; sleep 5 &"`: `exec 3>&1` keeps FD 1 open
  in the sleeper, the `&` detaches the sleeper from bash job control,
  and `disown` (in the runaway variant) prevents bash from reaping it
  on shell exit. Recording this so the next person does not have to
  rediscover it.

## Known limitations

- **The cgroup-probe variant of `PostureLabel` is unreachable in B1.1.**
  `StrongSecretless` exists in the enum but `Default::default()` returns
  `IsolatedProcessExposure`. B1.3 will add the `degraded_reason` field
  and the cgroup-probe feature flag and flip the default.
- **`PostureLabel` is not yet exposed on the IPC.** The audit row
  carries the wire string `ISOLATED_PROCESS_EXPOSURE`; the typed enum
  is a broker-internal source of truth. The UI consumer (M5) reads
  the audit log, so the wire string is what it sees today. If B1.3
  introduces a new variant, the audit row and the UI both see it
  without any code change beyond the new variant declaration.
- **The unconditional `killpg(SIGKILL)` after `wait_with_timeout` is
  best-effort.** A `-1` return from `killpg` (the group is already
  reaped, or the process was a zombie) is ignored: the reaper has
  already done its job. This matches the existing `tracing::error!`
  posture on audit append failure: the broker logs and moves on
  rather than blocking the reader join on a kernel-level edge case.

## Caller contract

`terminate_with_grace` and the post-wait `killpg` assume the child is
the leader of its process group. The broker's `spawn` satisfies this
via `pre_exec`+`setsid`. Unit tests that exercise the helper with a
raw `Command` MUST install their own `pre_exec` (or call `setsid` via
`nix::unistd`) for the assertion to hold. The
`timeout_sends_term_before_kill_and_reaps_worker` test was the only
other caller and is now compliant.
