# B1.3 Implementation Receipt — cgroup-probe + degraded_reason

**Status**: implementation complete; awaiting user review
**Branch**: `b1/cgroup-probe-and-degraded-reason`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-3`
**Off**: `b1/worker-lifetime` HEAD `48f29dd` (B1.1 baseline)
**Commits**: 3 — `6e31fc5` (spec), `5bc2eba` (code 1/2), `a1a8afe` (code 2/2)

## What B1.3 ships

A runtime-aware posture decision. Where B1.1's `PostureLabel::default()`
was the B1.1 honest posture (`IsolatedProcessExposure`) with no path
to `StrongSecretless`, B1.3 introduces:

1. A `DegradedReason` enum (closed Rust enum, three variants:
   `CgroupV2Unavailable`, `SliceCreationFailed`, `NonLinux`) with a
   `&'static str` wire format.
2. A `strong_secretless_enabled(harden: &HardenConfig) -> bool`
   predicate that returns true iff `harden.cgroup_v2` AND
   `harden.slice_created`. Both must hold: a kernel with cgroup v2
   mounted but a slice-creation failure is NOT strong, the worker
   would run outside the fence the operator asked for.
3. An `effective_posture(harden: &HardenConfig) -> (PostureLabel,
   Option<DegradedReason>)` accessor returning the runtime label
   and, when the label is `IsolatedProcessExposure`, the reason
   it had to fall back.
4. A `degraded_reason: Option<String>` field on the
   `AuditEventDto::WorkerSpawned` IPC DTO, with a closed-vocabulary
   doc-comment listing the three wire values.
5. The `audit_worker` function in `crates/broker/src/worker.rs` now
   takes a `harden: Option<&HardenConfig>` parameter and computes
   the runtime posture from it. When the harness has no HardenConfig
   (test path), the B1.1 contract is preserved: `ISOLATED_PROCESS_EXPOSURE`
   + `degraded_reason: None`.

## Feature-flag policy (deliberate)

`PostureLabel::default()` is intentionally **not** updated to call
`effective_posture`. The default stays `IsolatedProcessExposure` for
one more release, pinned by the
`default_posture_label_is_still_isolated_process_exposure` unit
test. The reason is recorded in the doc-comment of the
`Default` impl and in the unit test:

> A default-flip would change every audit row on a cgroup-fence
> host without an operator opt-in. The opt-in is a follow-up.
> The plumbing is in place; flipping the default is a one-liner
> once the operator opt-in exists.

A real broker that wants the runtime posture today calls
`effective_posture(&harden_config)` explicitly. Tests do the same
thing through the B1.3 unit tests in `isolated_exec::tests`.

## Diff

| File | Change |
|---|---|
| `crates/broker/src/isolated_exec.rs` | +191, -5 — `DegradedReason` enum, `strong_secretless_enabled`, `effective_posture`, 6 new unit tests |
| `crates/broker/src/worker.rs` | +104, -7 — `audit_worker` takes `harden: Option<&HardenConfig>`, all 10 call sites updated, narrow `#[allow(clippy::too_many_arguments)]` |
| `crates/broker/tests/uat_040_isolated_worker_runtime.rs` | +73, -16 — `uat_040_posture_label_in_audit_record` replaced with `uat_040_posture_label_remains_isolated_process_exposure_in_test_path` (stronger, also pins `degraded_reason: None`) |
| `crates/ipc-protocol/src/lib.rs` | +31, -1 — `degraded_reason: Option<String>` field on `WorkerSpawned`; stale "Always ISOLATED_PROCESS_EXPOSURE" doc-comment fixed |

Total: 4 files, ~400 lines.

## Evidence

```
$ cargo build -p asv-broker --lib
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.05s

$ cargo build --workspace
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 35.55s

$ cargo test -p asv-broker --no-fail-fast
   1238 tests passed, 0 failed, 0 ignored
   (was 1232 in b1/worker-lifetime baseline; +6 B1.3 unit tests)

$ cargo test -p asv-broker --test uat_040_isolated_worker_runtime
   20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.82s
   (was 20; the B1.1 row was replaced by a stronger B1.3 row, net zero)

$ cargo clippy -p asv-broker --lib --tests -- -D warnings
   clean

$ cargo fmt -p asv-broker -p asv-ipc-protocol --check
   clean on the 3 files B1.3 modifies
   (pre-existing fmt drift in audit.rs / connect_runtime.rs in
   b1/worker-lifetime is NOT introduced by this branch; those
   files are untouched)
```

## New unit tests (in `isolated_exec::tests`)

| Test | What it pins |
|---|---|
| `degraded_reason_wire_names_are_stable` | The 3 wire strings — a rename is a breaking change for every audit consumer |
| `strong_secretless_enabled_requires_both_conditions` | 4-row truth table over `(cgroup_v2, slice_created)` |
| `effective_posture_returns_strong_when_cgroup_fence_present` | (true, true) → `(StrongSecretless, None)` |
| `effective_posture_returns_isolated_with_reason_when_cgroup_v2_missing` | (false, _) → `(IsolatedProcessExposure, Some(CgroupV2Unavailable \| NonLinux))` (cfg-gated) |
| `effective_posture_returns_isolated_with_reason_when_slice_creation_failed` | (true, false) → `(IsolatedProcessExposure, Some(SliceCreationFailed))` |
| `default_posture_label_is_still_isolated_process_exposure` | The B1.3 feature-flag default — pinned so a future flip is a deliberate change |

## Honest observations

- **`audit_worker` crossed clippy's `too_many_arguments` threshold.**
  It went from 7 to 8 arguments (added `harden`). I chose to add
  a narrow `#[allow(clippy::too_many_arguments)]` and document
  the deferred struct refactor rather than do the refactor now.
  The function is private (not part of the public surface), the
  allow is scoped, and the honest answer to clippy's complaint
  is to bundle the per-run fields into a struct — that refactor
  touches every call site and is bigger than B1.3's scope.
- **The `binary.rs:163` staleness guard bit me again.** After the
  IPC DTO change, the CLI binary in the target dir was older than
  the new source, and the first full broker run had spurious
  failures. `cargo build --workspace` (35.55s) refreshed the
  binary, the second run was clean. The same caveat B1.1
  documented: any time the CLI sources change, `cargo build
  --workspace` must precede `cargo test -p asv-broker`.
- **`cargo fmt --all` reformatted 4 files I did not touch**
  (audit.rs, connect_runtime.rs, cli/main.rs, integrations/lib.rs).
  These were pre-existing rustfmt drifts in `b1/worker-lifetime`
  that B1.1's fmt pass did not catch. I reverted the unrelated
  changes before committing so the B1.3 diff is minimal.
- **The runtime-aware audit row in the production path requires
  `BrokerState` to hand a `HardenConfig` to `audit_worker`.**
  That wiring is not in this commit — the production path
  currently passes `None` like the test paths, so every real
  broker still emits `ISOLATED_PROCESS_EXPOSURE` + `None` until
  the BrokerState refactor lands. The plumbing is in place; a
  follow-up wires it. The unit tests already prove the
  `effective_posture` decision is correct.

## What is NOT in this commit

- No `cargo publish`. No tag. No dist manifest change. The branch
  is off `b1/worker-lifetime` and lands on its own.
- No default-flip. `PostureLabel::default()` stays
  `IsolatedProcessExposure`. The opt-in is a follow-up.
- No `BrokerState.self_report` wiring into `audit_worker`. The
  call sites pass `None`; the runtime-aware path is exercised
  by the unit tests only. Wiring it through is a one-liner when
  the refactor lands.
- No UAT-040 row for the runtime posture. The existing
  `uat_040_posture_label_remains_isolated_process_exposure_in_test_path`
  pins the test-path contract; a runtime row would require
  changing the `spawn` signature to take a HardenConfig, which
  is a bigger refactor.

## Awaiting user review

- [ ] User confirms "B1.3" was indeed what was meant by "adelante apruebo"
- [ ] User reviews the feature-flag default-flip policy
- [ ] User reviews the `Option<String>` IPC field shape (vs enum at IPC boundary)
- [ ] User decides whether B1.4 is the right next step (default-flip opt-in) or whether to merge B1.3 first
