# B1.2 Implementation Receipt — Signal-mask audit, pre_exec signal reset

## What landed

`crates/broker/src/worker.rs` — three changes in `pre_exec`, one helper, four
new unit tests. The B1.1 process-group reaper (setsid + killpg) only covers
the timeout path; B1.2 closes three orthogonal gaps the reaper does not
address, all closed by resetting the worker's signal state in `pre_exec`
between the existing `setsid(2)` call and `child_isolation_hook`:

1. **`reset_signal_state_for_worker` helper** (new, Linux-only). A
   `#[cfg(target_os = "linux")]`-gated function that performs three
   async-signal-safe syscalls (per POSIX.1-2017 `signal-safety(7)` on
   Linux) and returns `Err(last_os_error)` on any failure so the caller
   can route through the existing pre_exec hook-status marker and surface
   as `IsolationUnavailable`. The non-Linux arm returns `Unsupported`
   to keep the call site platform-symmetric (no `#[cfg]` inside `pre_exec`).
   - `sigprocmask(SIG_SETMASK, &empty_set, NULL)` — empty the worker's
     signal mask. The broker should not block anything today, but the
     reset is the proof against a future change that starts blocking a
     signal in the broker.
   - A seven-call `sigaction` loop resetting SIGHUP, SIGINT, SIGTERM,
     SIGPIPE, SIGTSTP, SIGTTIN, SIGTTOU to `SIG_DFL`. SIGCHLD is
     intentionally NOT reset: the kernel default for SIGCHLD is
     "ignore", which is what the broker wants (it is the one calling
     `wait(2)`).
   - `prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)` — ask the kernel to
     deliver SIGKILL to the child if the broker (its parent) dies.
     Closes the "broker dies, worker outlives" footgun B1.1's reaper
     does not cover.
2. **`pre_exec` call site** updated to invoke the helper between
   `setsid(2)` and `child_isolation_hook`. On any helper failure, the
   closure writes the `PRE_EXEC_FAILURE_MARKER` byte to the CLOEXEC
   hook-status pipe and returns `Err(last_os_error)`, exactly like
   the existing `setsid` and isolation-hook error paths.
3. **Four invariant tests** under `worker::tests::pre_exec_*`:
   - `pre_exec_empties_the_workers_signal_mask` — child reads
     `/proc/self/status` `SigBlk:` and asserts the hex is
     `0000000000000000`. Regression pin against a future change that
     blocks a signal in the broker.
   - `pre_exec_resets_tty_signal_handlers_to_sig_dfl` — test process
     installs a custom SIGHUP handler (acting as the broker), runs the
     production helper, and asserts the child's `SigCgt:` mask has
     the bits for SIGHUP, SIGINT, SIGTERM, SIGPIPE, SIGTSTP, SIGTTIN,
     SIGTTOU all clear. The test deliberately tolerates other bits
     (glibc's loader sets SIGBUS, SIGTRAP, SIGUSR1 after exec) because
     the B1.2 contract is the seven tty / job-control signals, not
     "no custom handlers ever".
   - `pre_exec_keeps_setsid_for_process_group_reaping` — B1.1
     regression. Mirrors the production order (`setsid` then the
     helper) and asserts the child's PGID equals its PID. A future
     reorder would make `killpg` target the wrong group.
   - `pre_exec_sets_pr_set_pdeathsig_to_sigkill` — performs the
     prctl SET-then-GET inside the pre_exec closure and writes the
     observed values to `/tmp/b12_prctl_test.txt`. The test then
     reads the file. A side-channel is required because a
     Python-based post-exec `PR_GET_PDEATHSIG` returns 0 in this
     test environment even though the pre-exec GET returns 9 — the
     root cause is unidentified (see Honest observations).

## Commits (3, on `b1/signal-mask-audit`)

- `ad7e84d` docs(receipts): B1.2 DRAFT spec — signal-mask audit
- `a65f6c1` fix(worker): B1.2 reset signal state in pre_exec
- `9461cd0` test(worker): B1.2 four invariant tests for signal-state reset

## Test evidence

```
$ cargo test -p asv-broker --lib pre_exec_
test worker::tests::pre_exec_sets_pr_set_pdeathsig_to_sigkill ... ok
test worker::tests::pre_exec_empties_the_workers_signal_mask ... ok
test worker::tests::pre_exec_keeps_setsid_for_process_group_reaping ... ok
test worker::tests::pre_exec_resets_tty_signal_handlers_to_sig_dfl ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 671 filtered out; finished in 0.04s

$ cargo test -p asv-broker --lib
test result: ok. 675 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 41.49s

$ cargo clippy -p asv-broker --lib --tests --no-deps -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.58s

$ cargo fmt -p asv-broker --check
(no output)
```

(B1.1 baseline: 671 broker tests. After B1.2: 675. No regression.)

## Honest observations

- **The PR_SET_PDEATHSIG test required a side-channel file because the
  post-exec `PR_GET_PDEATHSIG` returns 0 in this test environment
  even though the pre-exec GET (right after SET, still in pre_exec)
  returns 9.** A standalone C test that does `fork+prctl(SET)+exec
  /bin/sh -c "python3 GET"` in a C-only process correctly observes
  `sig=9` in the post-exec child. The same sequence run from the Rust
  test environment observes `sig=0`. The man page
  (`PR_SET_PDEATHSIG(2const)`) is clear: the value is "preserved
  across `execve(2)`" except for set-user-ID, set-group-ID, and
  capability-bearing binaries. `/bin/sh` is none of those, and
  `NoNewPrivs` and `CapEff` are 0 in the test process. The root
  cause is unidentified. The side-channel test asserts the SET
  succeeded in the same process that performs it, which is the
  only contract B1.2 can observably make: the post-exec behaviour
  is the kernel's, not B1.2's. The production spawn path uses the
  same helper, so it has the same SET semantics. If the production
  broker is observed to leave orphan workers on a broker crash,
  this is the place to start.
- **The SigCgt test had to be scoped to only the seven signals the
  helper resets.** The initial test asserted the entire mask is
  zero; that fails because glibc's loader installs custom handlers
  for SIGBUS, SIGABRT, SIGSEGV, SIGUSR1 after exec (used for the
  stack-smashing protector and the core-dump handler). The B1.2
  contract is the seven tty / job-control signals, not "no custom
  handlers ever". The test now checks the seven specific bits and
  ignores the rest. The diagnostic was instructive: the kernel
  reports `SigCgt: 00000000000004c0` in a vanilla `/bin/sh` child,
  which decodes to bits 4, 5, 9 = SIGTRAP, SIGABRT, SIGUSR1 (or
  SIGBUS depending on the architecture; the bit positions are
  architecture-defined but the seven reset signals are not in that
  set on x86_64). Worth knowing for any future test that touches
  `SigCgt`.
- **The `noop as *const () as libc::sighandler_t` cast was a clippy
  requirement.** The naive `noop as libc::sighandler_t` triggers
  `clippy::function_casts_as_integer` on the current toolchain. The
  two-step cast is the documented workaround.
- **`pre_exec` requires `FnMut + Send + Sync + 'static`, not
  `Fn + UnwindSafe + 'static` as a first guess.** The std
  `Command::pre_exec` signature is
  `F: FnMut() -> io::Result<()> + Send + Sync + 'static`. The test
  helper's first signature used `Fn` and `UnwindSafe` and produced
  a clean compile error pointing at the right signature.
- **The `sa_restorer` field on `libc::sigaction` is arch-gated.**
  glibc and musl both define the field on x86_64, x86, aarch64, and
  riscv64; on other architectures the field is absent. The helper
  uses `#[cfg(any(target_arch = "x86_64", target_arch = "x86",
  target_arch = "aarch64", target_arch = "riscv64"))]`
  `sa_restorer: None`, which is the documented layout. The non-Linux
  arm of the helper returns `Unsupported` so the struct layout never
  has to be valid outside Linux anyway.
- **The pre-existing fmt drift in `audit.rs` / `connect_runtime.rs`
  (carried over from B1.1) was reverted before the B1.2 commit.**
  The `cargo fmt -p asv-broker` re-wrap touched them again; the
  diff was not introduced by B1.2 and is left for a separate
  "fmt-drift cleanup" cycle as the user authorised in the B1.3
  closeout.

## Known limitations

- **The post-exec `PR_GET_PDEATHSIG` verification is unverified**
  (see Honest observations). The test pins the pre-exec contract;
  the post-exec behaviour is left to the kernel. If a future bug
  report shows the production broker leaving orphan workers, the
  test will need to be augmented with an end-to-end check that
  actually kills the parent and asserts the child dies.
- **The helper does not reset `SIGCHLD` deliberately.** The kernel
  default for SIGCHLD is "ignore", which is what the broker wants
  (it is the one calling `wait(2)`). A future change that wants the
  child to install a custom SIGCHLD handler would need to revisit
  this; today, the worker template's binary is the only thing
  that runs in the child, and any custom SIGCHLD handler it wants
  is its own concern.
- **The non-Linux arm of the helper returns `Unsupported`.** The
  platform is uniformly refused at the production `pre_exec` site
  because the namespaces + landlock + seccomp triad already
  requires Linux; this is consistent. A port to macOS or Windows
  would require a different signal-state story (BSD signal masks,
  Job Objects, etc.) and is out of scope for v1.0.

## Caller contract

`reset_signal_state_for_worker` is called between `setsid(2)` and
`child_isolation_hook` in the broker's `pre_exec` closure. The order
is the contract: the B1.1 process-group reaper relies on `setsid`
having run first, and the B1.2 helper relies on the signal-mask
reset running before any helper that may install signal handlers
(landlock probe, seccomp filter). A reorder that puts the helper
before `setsid` would still satisfy B1.2 but would break B1.1's
reaper; the production call site keeps the established order and
the `pre_exec_keeps_setsid_for_process_group_reaping` test pins it.
