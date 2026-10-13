# B1.4 Implementation Receipt — default-flip opt-in (CLI flag)

**Status**: implementation complete; awaiting user review
**Branch**: `b1/default-flip-opt-in`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-4`
**Off**: `b1/worker-lifetime` HEAD `9f867b8` (B1.1 + B1.2 + B1.3 merged)
**Commits**: 5 — `f276f3e` (DRAFT spec), `4dcc589` (spec approved), `4b6f6e2` (code 1/2: plumbing), `39d1b6b` (code 2/2: tests + fmt fix), plus the housekeeping commit that pays the B1.2 clippy ratchet drift (see "Honest observations" below)

## What B1.4 ships

The operator-facing wire that B1.3 deliberately did not provide. Where
B1.3 added the `effective_posture(harden)` accessor and the
`degraded_reason` IPC field but left the policy in `PostureLabel::default()`,
B1.4 ships the policy as an explicit, audited, opt-in flag.

Concretely:

1. **A new operator-facing CLI flag, `--runtime-posture-aware`**, in
   `crates/broker/src/main.rs`. Absent by default. This is the only
   thing that flips the audit row; the `HardenConfig` was already
   there from B1.3.

2. **`HardenConfig` plumbed through `BrokerState` into
   `worker::spawn` and `audit_worker`.** `BrokerState` gains
   `pub harden_config: Option<HardenConfig>` and
   `pub runtime_posture_aware: bool` (both default to
   `None` / `false`). `main` populates `harden_config` from the
   same `cfg` variable that already feeds `SelfReport::from_harden`,
   and `runtime_posture_aware` from the new flag. The single
   production caller of `worker::spawn` in `lib.rs:2223` reads both
   fields and passes them down.

3. **`effective_posture_for_audit(harden, opt_in) -> (PostureLabel,
   Option<DegradedReason>)`** accessor in
   `crates/broker/src/isolated_exec.rs`. The 2x2 truth table:
   - `(None, _)` → `(PostureLabel::default(), None)` — no harden
     profile installed, runtime posture is unknown.
   - `(Some(_), false)` → `(PostureLabel::default(), None)` — harden
     profile installed, operator did not opt in.
   - `(Some(h), true)` → `effective_posture(h)` — operator opted
     in; reflect the runtime decision.

   `audit_worker` calls this accessor instead of `effective_posture`
   directly. The B1.1 default label is preserved in the two
   "opt-out" cells; the B1.3 runtime decision is reflected in the
   "opt-in" cell.

4. **`worker::spawn` and `audit_worker` take the new parameters
   end-to-end.** `audit_worker` is now 9 arguments
   (`#[allow(clippy::too_many_arguments)]` widened from 8 to 9).
   The 8 internal call sites in `worker.rs` and the 1 production
   call site in `lib.rs:2223` all pass `harden, opt_in`. The 20
   `spawn(` calls in `uat_040_isolated_worker_runtime.rs` pass
   `None, false` (test path: no harden, no opt-in).

5. **`--harden` is independent of `--runtime-posture-aware`.** A
   deployment that wants the fence without the audited posture
   (or vice versa) can ask for either. The flag-name and
   independence question was raised in the DRAFT spec and
   shipped as drafted (no override from user).

## Diff

| File | Change |
|---|---|
| `crates/broker/src/isolated_exec.rs` | +85, -3 — `effective_posture_for_audit` accessor, 5 new unit tests, 1 fmt fix in the B1.4 block |
| `crates/broker/src/worker.rs` | +57, -25 (B1.4 code 1/2) — `pub fn spawn` and `audit_worker` take `harden: Option<&HardenConfig>` + `opt_in: bool`; 8 call sites updated; `audit_worker` calls `effective_posture_for_audit`; unused `PostureLabel` import removed; `#[allow(clippy::too_many_arguments)]` widened from 8 to 9 with doc update |
| `crates/broker/src/lib.rs` | +9, -1 — `BrokerState` gains `pub harden_config: Option<HardenConfig>` and `pub runtime_posture_aware: bool`; default impl sets both to `None`/`false`; the one production caller of `worker::spawn` (line 2223) reads both fields |
| `crates/broker/src/main.rs` | +12, -1 — `let mut runtime_posture_aware = false;` mirroring `harden`; new match arm `--runtime-posture-aware`; `measured_harden: Option<HardenConfig>` stashed outside `if harden` so it survives into the `BrokerState::default()` builder; `state.harden_config = measured_harden;` and `state.runtime_posture_aware = runtime_posture_aware;` next to existing `state.self_report` assignment |
| `crates/broker/tests/uat_040_isolated_worker_runtime.rs` | +111, -16 (B1.4 code 1/2 + 2/2) — 20 `spawn(` calls updated to pass `None, false`; new row `uat_040_runtime_posture_opt_in_flips_audit_row` exercising the production path end-to-end |

Total: 5 files touched by B1.4, ~280 lines net.

## Evidence

```
$ cargo build --workspace
   Finished `dev` profile [unoptimized + debuginfo] target(s) in ~35s (workspace build refreshed the CLI binary)

$ cargo test -p asv-broker --lib
   686 passed, 0 failed, 0 ignored
   (was 681 in b1/worker-lifetime baseline; +5 B1.4 unit tests
    in isolated_exec::tests; the +1 UAT-040 row is counted
    in the integration test, not --lib)

$ cargo test -p asv-broker --test uat_040_isolated_worker_runtime
   21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   (was 20; +1 B1.4 row `uat_040_runtime_posture_opt_in_flips_audit_row`)

$ cargo test -p asv-broker --test uat_017_env_scan
   4 passed; 0 failed
   (the opt-in is a CLI flag, no std::env::var* reads in production
    — uat_017's negative-assertion contract holds)

$ cargo clippy -p asv-broker --all-targets
   1 warning (pre-existing: B1.2 commit 9461cd0 / 9f867b8 base;
              the B1.4 housekeeping commit pays it)

$ python3 scripts/check-clippy-ratchet.py
   clippy warnings: 0 (baseline 0)
   PASS  (after the B1.4 housekeeping commit pays the B1.2 lint)

$ cargo fmt --all -- --check
   11 diffs (all pre-existing in b1/worker-lifetime; none
   introduced by B1.4; the B1.4-only fmt regression at
   isolated_exec.rs:198 was fixed in 39d1b6b)
```

## New tests

### Unit tests in `isolated_exec::tests` (5)

| Test | What it pins |
|---|---|
| `effective_posture_for_audit_with_no_harden_returns_b11_default` | `(None, opt_in=false)` and `(None, opt_in=true)` both → `(PostureLabel::default(), None)` — the runtime posture is unknown when no HardenConfig is present, regardless of the flag |
| `effective_posture_for_audit_with_opt_in_off_returns_b11_default` | `(Some(strong_harden), false)` → default; `(Some(degraded_harden), false)` → default — the operator must opt in for the runtime posture to surface |
| `effective_posture_for_audit_with_opt_in_on_reflects_strong` | `(Some(strong_harden), true)` → `(StrongSecretless, None)` — the cgroup-fence strong path |
| `effective_posture_for_audit_with_opt_in_on_reflects_degraded` | `(Some(degraded_harden), true)` → `(IsolatedProcessExposure, Some(<cfg-gated reason>))` — the `degraded_reason` is surfaced when the operator opts in on a host without the fence |
| `effective_posture_for_audit_with_opt_in_on_reflects_slice_failure` | `(Some(slice_failed_harden), true)` → `(IsolatedProcessExposure, Some(SliceCreationFailed))` — the kernel-mounted-but-slice-failed case is degraded, not strong |

### UAT-040 row (1)

| Test | What it pins |
|---|---|
| `uat_040_runtime_posture_opt_in_flips_audit_row` | End-to-end: `asv_broker::worker::spawn` is called with a synthetic `HardenConfig{cgroup_v2: true, slice_created: true, ...}` (strong-path input). First call: `opt_in=false` → audit row carries `ISOLATED_PROCESS_EXPOSURE` + `None`. Second call: `opt_in=true` against the same registry → audit row carries `STRONG_SECRETLESS` + `None`. The test fails if either (a) the opt-in flag has no effect (the off and on rows carry the same posture), which is the regression guard for the `BrokerState.harden_config` / `runtime_posture_aware` threading; or (b) the off row carries a non-default posture, which is the regression guard for the B1.1 contract (no default-flip, pinned by the B1.3 `default_posture_label_is_still_isolated_process_exposure` unit test). |

## Design choice: where the decision lives

`effective_posture_for_audit` is the single point of policy. The
function takes the two inputs that matter (the harden profile and
the operator's opt-in) and returns the (label, reason) pair that
the audit row carries. Every audit row in B1.4 goes through this
function — no caller has to remember the 2x2 truth table.

This is deliberately placed in `isolated_exec.rs` (the B1.3
runtime-aware module) and not in `audit.rs` or `worker.rs`:
`isolated_exec.rs` is the only file that knows about both the
`HardenConfig` shape and the `PostureLabel` ↔ `DegradedReason`
contract. Putting the decision in `worker.rs` would force a
dep cycle (worker → isolated_exec → harden), and putting it in
`audit.rs` would force `audit.rs` to learn about `HardenConfig`,
which it deliberately does not (the audit chain is a pure
serializer).

## Feature-flag policy (deliberate)

`PostureLabel::default()` is still NOT updated. The default stays
`IsolatedProcessExposure` for B1.4, pinned by the B1.3 unit test
`default_posture_label_is_still_isolated_process_exposure`. The
opt-in is a flag, not a default-flip:

- A deployment that does not pass `--runtime-posture-aware` keeps
  the B1.1 honest label. Every audit row carries
  `ISOLATED_PROCESS_EXPOSURE` + `degraded_reason: None`.
- A deployment that passes `--runtime-posture-aware` gets the
  runtime decision. The audit row reflects the actual host
  posture: `STRONG_SECRETLESS` on a cgroup-fence host,
  `ISOLATED_PROCESS_EXPOSURE` + a `DegradedReason` on a host
  without one.

The DRAFT spec raised three open questions (flag name, opt-in vs
default-flip, `--harden` ↔ `--runtime-posture-aware` coupling).
The user said "si" on 2026-10-13 to proceed with the design as
drafted, with no overrides. The three questions shipped as
drafted: `--runtime-posture-aware`, opt-in not default-flip,
independent of `--harden`.

## Honest observations

- **A pre-existing clippy ratchet drift was uncovered when I ran
  the gate.** `python3 scripts/check-clippy-ratchet.py` reported
  `1 / 0` — one warning, baseline zero. The warning is in
  `worker.rs:1867` (`redundant_closure`) and was introduced by
  B1.2 commit `9461cd0`, present at the merge base `9f867b8` and
  therefore not introduced by B1.4. The ratchet baseline was set
  to 0 in `27a8f1d` ("v0.38.0 housekeeping"), which is *after*
  B1.2, so B1.2 broke the ratchet and the gate was never re-run
  through the B1 merges. My earlier "clippy clean" claim in the
  B1.4 memory note was wrong, or the ratchet gate was simply
  never invoked. B1.4 is **clippy-clean on its own** (0 new
  warnings) but inherits the pre-existing drift.

  **The user approved camino 2**: pay the B1.2 lint now (1 line)
  as a separate housekeeping commit in the B1.4 block, so the
  block closes with the ratchet at 0/0. The commit changes
  `|| reset_signal_state_for_worker()` to
  `reset_signal_state_for_worker` in
  `crates/broker/src/worker.rs:1867`. No other code paths
  touched; the function signature is identical; the call site
  compiles to the same instruction.

- **Pre-existing fmt drift is unchanged.** `cargo fmt --all
  -- --check` reports 11 diffs in 6 files
  (`audit.rs`, `connect_runtime.rs`, `worker.rs`,
  `cli/src/main.rs`, `integrations/src/lib.rs`). All 11 are
  pre-existing in `b1/worker-lifetime` (the user's "opción A"
  pendiente from the B1.1 receipt). B1.4 itself introduced 1
  fmt drift (`isolated_exec.rs:198`, the `(None, _) | (Some(_),
  false) =>` arm of `effective_posture_for_audit`); that was
  fixed in the `39d1b6b` commit. The pre-existing 11 are NOT
  paid in this block; the user explicitly approved leaving them
  for a separate housekeeping block.

- **`audit_worker` crossed clippy's `too_many_arguments` threshold
  again.** It went from 8 to 9 arguments (added `opt_in: bool`).
  The `#[allow(clippy::too_many_arguments)]` was widened from 8
  to 9 with a doc update. The function is private (not part of
  the public surface); the allow is scoped; and the honest answer
  to clippy's complaint is still to bundle the per-run fields
  into a struct — that refactor touches every call site and is
  bigger than B1.4's scope.

- **`worker::spawn` is `pub` and crossed a similar threshold.**
  It is now 5 arguments (added `harden: Option<&HardenConfig>`
  and `opt_in: bool`). I did NOT add a `#[allow(...)]` here
  because clippy's `too_many_arguments` is configured for 7 in
  the user's tree; the function is still under that limit. The
  function does pass clippy cleanly.

- **The pre-merge SDDK gate bit me.** I had to use
  `git sddk-align --ack --work-item <uuid> --summary ...`
  before `git commit`, and the `sddk-close` will run on
  post-commit. The same dance as B1.2 / B1.3 — well understood
  and documented in `docs/ci-policy.md`.

- **Test-path `spawn` calls were not collapsed into a helper.**
  20 `spawn(` calls in `uat_040_isolated_worker_runtime.rs` were
  updated to pass `None, false`. A `spawn_no_harden(r, name,
  opts, audit)` helper would have kept the test file cleaner,
  but the existing test file already inlines the 4-arg
  signature; adding a helper was a bigger change than the
  parameter count. Follow-up.

## What is NOT in this commit

- No `cargo publish`. No tag. No dist manifest change. The branch
  is off `b1/worker-lifetime` and lands on its own.
- No `PostureLabel::default()` flip. The default stays
  `IsolatedProcessExposure`. The opt-in is a CLI flag.
- No `uat_017` regression — the opt-in is a CLI flag, not an env
  var, so the scanner's "no `std::env::var*` in production"
  contract holds.
- No fmt drift cleanup. The 11 pre-existing diffs stay in
  `b1/worker-lifetime` for the separate "opción A" block.
- No public-API change. The CLI flag is the only new operator
  surface; the IPC DTO did not change (B1.3 added
  `degraded_reason`, B1.4 only exercises it).
- No B1.5 work. B1.5 (deferred: yank policy decision) is a
  separate worktree and a separate user decision.

## Awaiting user review

- [ ] User confirms `--runtime-posture-aware` is the right name
      (or asks for a rename)
- [ ] User confirms the opt-in policy is the right one
      (vs a future default-flip with a deprecation window)
- [ ] User reviews the `--harden` ↔ `--runtime-posture-aware`
      independence (currently: they are independent; a
      deployment can use one without the other)
- [ ] User decides whether to push `b1/worker-lifetime` to
      origin and create a GitHub Release (this receipt
      closes the B1.4 block locally; push is the user's call)
- [ ] User decides the B0 release yank policy
      (3 paths documented in the B1.1 receipt)
