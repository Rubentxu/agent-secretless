# B1.2 — Signal-mask audit (DRAFT, awaiting review)

**Status**: DRAFT — no code changes yet
**Branch**: `b1/signal-mask-audit` (off `b1/worker-lifetime` HEAD `48f29dd`)
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-2`

## What B1.2 audits

The B1.1 process-group reaper (setsid + killpg) is one half of the
worker-lifetime story. The other half is the **signal mask and
disposition** the child inherits from the broker. The M10 spec
requires that the broker "deny-list dangerous syscalls" and "fence
the worker", but it does not explicitly audit signal disposition
inheritance. B1.2 closes that gap.

Three concrete questions the audit must answer, with code
evidence:

1. **What signals does the broker have blocked or ignored at the
   time of fork?** The child inherits this state via `fork(2)` (it
   is part of the POSIX process state). If the broker has
   `SIGCHLD` set to `SIG_IGN`, the child ignores `SIGCHLD` too,
   and any grandchild it forks becomes a zombie the moment it
   exits. If the broker has `SIGTERM` blocked (mask), the
   broker's own `killpg(SIGTERM)` does not reach the child until
   the mask is unblocked.

2. **What signal disposition does the child see for `SIGPIPE`,
   `SIGHUP`, `SIGINT`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`?** These
   are the "tty / job-control" signals. The child is in a fresh
   session (setsid) and has no controlling tty, but it inherits
   the disposition the broker had at fork time. If the broker
   installed a handler for any of them, the child runs that
   handler too.

3. **What happens if the broker exits while a worker is alive?**
   The child is in a fresh session (leader). With `PR_SET_PDEATHSIG`
   unset, the kernel will NOT notify the child when its parent
   dies. This is the M10-R2 footgun: a worker outliving the broker
   (even briefly) holds the secret in memory until the next
   reaper tick. B1.1's `killpg` covers the timeout case; the
   parent-death case is uncovered.

## What B1.2 changes (proposed)

Three small changes, each with a unit test:

### 1. Reset signal mask in pre_exec

`pre_exec` calls `sigprocmask(SIG_SETMASK, &empty_set, NULL)` to
clear every signal the broker had blocked. Justification: the
broker should not have any signals blocked (a clean daemon has an
empty mask) but the audit is the test that proves it. If a
future change ever blocks SIGTERM in the broker, the audit
catches it as a test failure.

```rust
unsafe {
    cmd.pre_exec(move || {
        if libc::setsid() == -1 { /* ... */ }
        // B1.2: empty the signal mask. The broker is a clean
        // daemon; if a future change blocks a signal here, this
        // audit fails.
        let empty = std::mem::zeroed::<libc::sigset_t>();
        if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) == -1 {
            // Same marker path as the other pre_exec failures.
            return Err(std::io::Error::last_os_error());
        }
        // ... rest of pre_exec
    });
}
```

### 2. Reset signal handlers to SIG_DFL in pre_exec

`pre_exec` iterates over `SIGHUP`, `SIGINT`, `SIGTERM`, `SIGPIPE`,
`SIGTSTP`, `SIGTTIN`, `SIGTTOU`, `SIGCHLD` and calls
`sigaction(sig, &default_action, NULL)` to drop any handler the
broker installed. Justification: a daemon should not have signal
handlers (signals are an attack surface), and a worker that
inherits them runs user code with the broker's handlers.

`SIGCHLD` is special: setting it to `SIG_DFL` (which is "ignore"
on Linux) is the right default for the worker because the broker
is the one calling `wait(2)`. But the audit must verify the
*broker* did not have `SIGCHLD` set to `SIG_IGN` (a common
pattern for double-fork daemons), because that would turn
grandchildren into zombies.

### 3. `PR_SET_PDEATHSIG` in pre_exec

`pre_exec` calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` so the kernel
delivers `SIGKILL` to the child if its parent (the broker) dies.
Justification: closes the "broker dies, worker outlives" gap. The
process-group reaper still covers the timeout case; this is the
parent-death case. The two together are the symmetric form of
"broker owns the worker's lifetime".

```rust
// B1.2: ask the kernel to deliver SIGKILL if the broker dies
// before us. Async-signal-safe (prctl is in the safe set).
if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
    return Err(std::io::Error::last_os_error());
}
```

## What B1.2 does NOT do

- **It does not change the seccomp deny-list.** Seccomp already
  blocks the dangerous syscalls (ptrace, kexec_load, bpf, etc).
  B1.2 is about POSIX signal state, not kernel capabilities.
- **It does not change the landlock profile.** Same reason.
- **It does not change `terminate_with_grace` or `killpg`.** B1.1
  covered that. B1.2 is upstream of the reaper, in the pre-exec
  hook.
- **It does not add a new IPC field or audit row.** The signal
  audit is internal state; if a worker dies from the new
  `PR_SET_PDEATHSIG` after a broker crash, the audit row already
  reports it as `Signaled` (outcome) with `SIGKILL` implicit in
  the cause. M5 UI consumers can be updated later if they want
  to surface the parent-death case.

## Test plan

- `pre_exec_resets_signal_mask_to_empty`: spawn a worker with
  `/bin/sh -c "trap '' TERM; kill -0 $$"`, then read the worker's
  `/proc/<pid>/status` `SigBlk` line in the parent and assert it
  is `0000000000000000`. Pre-conditions for this test: the
  broker has no signals blocked (asserted by
  `broker_signal_mask_is_empty_at_spawn`).
- `pre_exec_resets_signal_handlers_to_default`: spawn a worker
  that records `/proc/<pid>/status` `SigCgt` (caught signals)
  into a file, then assert the file does not list any signal
  the broker would have caught.
- `pr_set_pdeathsig_is_set_in_pre_exec`: spawn a worker, kill
  its parent (the test process) with SIGKILL, assert the worker
  exits within a tight bound. This is a self-killing test —
  the test process must fork a sub-test that re-execs the broker
  binary's child spawn path, or use a child-of-child approach.
  This is the most invasive of the three tests; if it cannot be
  written cleanly, it is dropped and replaced with a static
  check that `prctl(PR_SET_PDEATHSIG, SIGKILL)` was called
  during pre_exec by inspecting the worker's `/proc/<pid>/status`
  `parent` field after `setsid` — if the parent is not the
  broker, the pre_exec must have set the death signal (verified
  by absence of grandchildren).

## Risk and reversibility

- All three changes are in `pre_exec`, which runs in the forked
  child between fork and exec — POSIX async-signal-safe context.
  `sigprocmask`, `sigaction`, and `prctl` are all in the
  async-signal-safe set on Linux.
- The branch is off `b1/worker-lifetime`, not `main`. The PR
  can be reverted by deleting the worktree; `b1/worker-lifetime`
  is unchanged.
- If the audit uncovers a real broker-side issue (e.g. a future
  change blocks SIGTERM), the failure is loud: a worker that
  cannot be SIGTERM'd hangs until SIGKILL grace expires. That is
  the same shape as the B1.1 problem, and the B1.1 process-group
  reaper covers it.

## Estimated diff

- ~40 lines in `pre_exec` (sigprocmask + sigaction loop +
  prctl).
- ~150 lines in tests (3 new UAT-040 rows, helpers, and
  /proc/<pid>/status parsing).
- ~150 lines for the receipt.

## Awaiting user review

- [ ] User confirms "B1.2" is what was meant by "adelante apruebo"
- [ ] User confirms the three changes are the right shape (the
      sigprocmask/sigaction loop is the most invasive)
- [ ] User confirms the test plan is acceptable (the
      `pr_set_pdeathsig_is_set_in_pre_exec` test is the risky one)
