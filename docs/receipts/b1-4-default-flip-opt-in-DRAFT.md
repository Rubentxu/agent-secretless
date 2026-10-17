# B1.4 — default-flip opt-in for runtime-aware posture (DRAFT, approved)

**Status**: DRAFT (design approved by user on 2026-10-13; implementation in flight)
**Branch**: `b1/default-flip-opt-in`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-4`
**Off**: `b1/worker-lifetime` HEAD `9315507` (B1.1 + B1.2 + B1.3 merged)
**Author**: Jcode (autonomous, user pre-approved with "adelante apruebo, intenta paralelizar"; user said "si" on 2026-10-13 to proceed with the design as drafted, including the 3 open questions)

## What B1.4 ships

B1.4 makes the runtime-aware posture B1.3 introduced actually fire in
production. Where B1.3 added the `effective_posture(harden)` accessor
and the `degraded_reason` IPC field, B1.3 deliberately left the
opt-in policy and the `BrokerState → audit_worker` wiring as a
follow-up. B1.4 is that follow-up.

Concretely:

1. **A new operator-facing CLI flag, `--runtime-posture-aware`**, in
   `crates/broker/src/main.rs`. Absent by default, so a deployment
   that does not ask for the runtime posture keeps the B1.1 honest
   label (`ISOLATED_PROCESS_EXPOSURE` + `degraded_reason: None`).
   This is the **opt-in**: the audit row's posture flips only when
   the operator asks, in the launch contract, for it to.

2. **`HardenConfig` plumbed through `BrokerState` into
   `audit_worker`.** Today every `audit_worker` call site passes
   `None` (B1.3 deliberately did not wire the production path). B1.4
   adds `pub harden_config: Option<HardenConfig>` to `BrokerState`,
   `main` populates it from the same `cfg` variable that already
   feeds `SelfReport::from_harden`, and the single caller of
   `worker::spawn` in `lib.rs:2188` now hands `Some(&harden_config)`
   to `audit_worker` **iff the operator opted in** (i.e. the flag
   is set). The flag is the only thing that flips the audit row;
   the HardenConfig was already there.

3. **`effective_posture_for_audit` accessor in
   `crates/broker/src/isolated_exec.rs`.** Wraps the existing
   `effective_posture(harden)` and decides what the audit row sees
   given the opt-in. Two policy variants:
   - **Opt-out (not what B1.4 ships)**: every audit row reflects
     runtime posture. Rejected because a default-flip changes every
     audit row on a cgroup-fence host without an operator act, which
     is exactly what B1.3 refused to do unilaterally.
   - **Opt-in (B1.4 ships this)**: with the flag **off**, the audit
     row keeps the B1.1 honest label (`IsolatedProcessExposure`,
     `degraded_reason: None`). With the flag **on**, the audit row
     reflects the runtime decision: `StrongSecretless` + `None` on
     a cgroup-fence host, `IsolatedProcessExposure` + a
     `DegradedReason` on a host without one. The plumbing is
     identical to the unit-test path B1.3 already exercises; the
     flag is the only thing the production call site branches on.

4. **The B1.3 test that pinned the default, stays.** The
   `default_posture_label_is_still_isolated_process_exposure` test
   in `isolated_exec::tests` is the regression guard: a future
   change that flips `PostureLabel::default()` to call
   `effective_posture` directly is a breaking change to the
   default-deploy contract, and that test is the canary. B1.4
   keeps the test and adds a sibling that pins
   `effective_posture_for_audit(flag_off) == B1.1 default` and
   `effective_posture_for_audit(flag_on) == effective_posture(harden)`.

5. **One new UAT-040 row**: `uat_040_runtime_posture_opt_in_flips_audit_row`,
   proving the production-path wiring end-to-end. The test
   installs a `BrokerState` with a synthetic HardenConfig where
   `cgroup_v2 = true, slice_created = true`, runs `worker::spawn`
   with the opt-in flag **off** and asserts the audit row's
   posture is `ISOLATED_PROCESS_EXPOSURE`; then re-runs with the
   opt-in flag **on** and asserts the audit row's posture is
   `STRONG_SECRETLESS`. This is the test that fails if either
   the flag plumbing is wrong or the `BrokerState.harden_config`
   is not threaded into the audit call.

## Why an opt-in, not a default-flip

B1.3's doc-comment on `Default for PostureLabel` says it
explicitly: a default-flip "would change every audit row on a
cgroup-fence host without an operator opt-in". The honest
reading of that statement is: the operator has the cgroup fence
in mind, the operator has launched the broker with `--harden`,
and the operator's downstream tooling (logs, dashboards, audit
alerts) is calibrated to the B1.1 `ISOLATED_PROCESS_EXPOSURE`
label. A default-flip is a behaviour change for the operator's
tooling too, and the operator is the only person who can decide
they are ready for it. The opt-in is the operator's
acknowledgement. The flag's name (`--runtime-posture-aware`) is
deliberately verbose and not "strong" — the operator is opting
into *reflecting the measured posture*, not into a stronger
posture, because the posture is whatever the kernel gave them
and not what the broker promised.

## What stays B1.1 by design

- `PostureLabel::default()` is **not** updated. The B1.3 test
  `default_posture_label_is_still_isolated_process_exposure` is
  the regression guard, and the `Default` impl continues to
  return `IsolatedProcessExposure`.
- The unit tests in `isolated_exec::tests` continue to call
  `effective_posture(harden)` directly. The new
  `effective_posture_for_audit(harden, opt_in)` is the
  production-side wrapper; the unit tests bypass it on purpose,
  because the unit tests are exercising the posture decision
  itself, not the opt-in policy.
- The `audit_worker` `#[allow(clippy::too_many_arguments)]` from
  B1.3 stays. B1.4 does not change the audit_worker signature
  (the only thing that changes is the value the production call
  site hands in for `harden`).

## File-by-file diff estimate

| File | Change |
|---|---|
| `crates/broker/src/main.rs` | +14, -2 — new `let mut runtime_posture_aware = false;` (mirrors `harden`), one match arm for `--runtime-posture-aware`, one place that hands the cfg to the BrokerState builder |
| `crates/broker/src/lib.rs` | +6, -1 — `BrokerState.harden_config: Option<HardenConfig>`, default `None`, the single caller of `worker::spawn` reads `state.harden_config.as_ref()` and threads it through a new `worker::spawn` parameter (or via a wrapper, see Open Questions) |
| `crates/broker/src/worker.rs` | +3, -3 — `pub fn spawn` signature gains `harden: Option<&HardenConfig>` and the eight `audit_worker` call sites change to pass `harden` instead of `None`. The test-side `audit_worker` callers continue to pass `None` (they have no HardenConfig). |
| `crates/broker/src/isolated_exec.rs` | +38, -1 — new `effective_posture_for_audit(harden, opt_in: bool) -> (PostureLabel, Option<DegradedReason>)`; +2 new unit tests pinning the off/on contract |
| `crates/broker/tests/uat_040_isolated_worker_runtime.rs` | +60, -0 — `uat_040_runtime_posture_opt_in_flips_audit_row` |

Total: ~5 files, ~120 net new lines, ~6 new tests (5 unit + 1 UAT).

## Acceptance criteria

- [ ] `cargo test -p asv-broker --lib` is green, 681+5 = 686 tests
      (681 baseline + 5 new isolated_exec unit tests; the UAT is
      a separate test binary).
- [ ] `cargo test -p asv-broker --test uat_040_isolated_worker_runtime`
      is green, 21 tests (20 baseline + 1 new UAT row).
- [ ] `cargo clippy -p asv-broker --lib --tests -- -D warnings` is
      clean on the 5 files B1.4 touches.
- [ ] `cargo fmt -p asv-broker --check` is clean on the 5 files
      B1.4 modifies (the pre-existing drift in `audit.rs` /
      `connect_runtime.rs` is not B1.4's concern).
- [ ] The B1.3 regression test
      `default_posture_label_is_still_isolated_process_exposure`
      still passes (proves the default was not flipped).
- [ ] The B1.1 regression test
      `pre_exec_keeps_setsid_for_process_group_reaping` still
      passes (B1.4 does not touch the pre_exec closure).
- [ ] The B1.2 regression test
      `pre_exec_empties_the_workers_signal_mask` still passes
      (B1.4 does not touch the pre_exec closure).
- [ ] `uat_017_env_scan.rs` still passes (B1.4 does not introduce
      `std::env::var*` reads; the opt-in is a CLI flag, like
      every other operator setting).
- [ ] A broker launched with no flag continues to emit
      `ISOLATED_PROCESS_EXPOSURE` on every audit row (B1.1
      contract preserved).
- [ ] A broker launched with `--runtime-posture-aware` on a
      cgroup-fence host emits `STRONG_SECRETLESS`; on a
      non-cgroup-fence host emits `ISOLATED_PROCESS_EXPOSURE` +
      `degraded_reason = cgroup_v2_unavailable`.

## Open questions

- **Question 1: `worker::spawn` signature or thread `harden`
  through the call site?** Two options:
  - (a) Add a parameter to `pub fn spawn(registry, name, opts,
    audit, harden: Option<&HardenConfig>)`. Every test that
    calls `worker::spawn` directly gains a `None` arg. About
    6 call sites change. Cleanest semantically.
  - (b) Add `pub fn spawn_with_harden(...)` and keep
    `spawn(...)` as a thin wrapper that passes `None`. No
    test changes; production path uses `spawn_with_harden`.
    More code; less churn for tests.
  - **Default**: (a). The signature change is small and the
    function is internal. Tests are easy to update.

- **Question 2: Should the audit row's posture flip at the
  unit-test call sites, or stay B1.1?** B1.3 left the
  unit-test path on `None` deliberately. B1.4 inherits that:
  the new `effective_posture_for_audit(harden, opt_in)` is
  exercised by the production path's call site; the unit
  tests in `isolated_exec::tests` continue to test the
  posture decision itself. The opt-in is a policy that
  belongs at the call site, not in `effective_posture`.

- **Question 3: should the B1.1 baseline label read
  `ISOLATED_PROCESS_EXPOSURE` even when the kernel has
  cgroup v2 but the broker was launched without
  `--harden`?** Yes. A broker that did not install the
  harden profile has not measured cgroup v2 (it never
  called `detect_cgroup_v2`); the `harden_config` field on
  `BrokerState` is `None`; the audit row keeps the B1.1
  default. This is the same fail-closed reading
  `SelfReport::default()` takes.

## Awaiting user review

- [ ] User confirms the opt-in flag name (`--runtime-posture-aware`)
      is the right phrasing (alternatives considered:
      `--audit-runtime-posture`, `--reflect-runtime-posture`).
- [ ] User confirms B1.4 is the right next step after the
      B1.1+B1.2+B1.3 merges, or wants a different block
      (B2 is the other open worktree).
- [ ] User decides whether the `--harden` flag should
      auto-enable `--runtime-posture-aware` (deferred:
      a packaged install that uses `--harden` will
      probably also want the runtime posture, but the
      flags are separate today and coupling them is
      outside B1.4's scope).
