# B1.3 — cgroup-probe + degraded_reason

**Status**: DRAFT (not yet committed; awaiting user confirmation)
**Branch**: `b1/cgroup-probe-and-degraded-reason` (created from `b1/worker-lifetime`, HEAD `48f29dd`)
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-3`

## What B1.3 does

The B1.1 receipt's "Known limitations" section names three things B1.3
adds. Concretely:

1. **A `degraded_reason: Option<String>` field on the audit record** for
   `WorkerSpawned`. Populated only when the broker had to fall back from
   `StrongSecretless` to `IsolatedProcessExposure` for *this* run, with
   one of a closed enum of reasons (`"cgroup_v2_unavailable"`,
   `"slice_creation_failed"`, `"non_linux"`). Absent in the
   `StrongSecretless` path so the audit row does not grow a column the
   strong case never uses.
2. **A `strong_secretless_enabled()` accessor in `isolated_exec.rs`** that
   reads the existing `HardenConfig` (cgroup v2 mounted AND slice created
   successfully) and answers the question once. B1.1's `Default for
   PostureLabel` becomes the single call site, so the flip is one line.
3. **Flip the default.** When `strong_secretless_enabled()` returns true,
   `PostureLabel::default()` returns `StrongSecretless` and the wire
   audit row carries `"STRONG_SECRETLESS"`. The B1.1
   `uat_040_posture_label_in_audit_record` test's assertion of
   `"ISOLATED_PROCESS_EXPOSURE"` becomes a feature-flag test that
   exercises both paths (strong on cgroup-host, isolated on no-cgroup or
   slice-creation-failed).

## Why this is the right shape

- **The cgroup probe already exists.** `harden::install` already returns
  `HardenConfig { cgroup_v2, slice_created, slice_path, ... }` from
  `main.rs:563`. B1.3 is plumbing, not kernel work.
- **The audit log field is metadata-only.** `WorkerSpawned` is already
  shape-level redacted (per the B1.1 doc-comment at `worker.rs:975-985`).
  Adding `degraded_reason: Option<String>` cannot leak a secret by
  construction; the field is a closed-enum string.
- **The `StrongSecretless` variant already exists** in the `PostureLabel`
  enum (B1.1 commit `171be5a` reserved it for B1.3). The default flip is
  the only enum-touching change.
- **No new module, no new crate, no new dependency.** Total diff is
  expected to be: `isolated_exec.rs` (degraded_reason type +
  `strong_secretless_enabled()`), `ipc-protocol/src/lib.rs`
  (`degraded_reason: Option<String>` field + stale-doc fix at line
  1162), `worker.rs` (carry the value from `PostureLabel::default()`
  into the audit row), one UAT-040 test split, and this receipt.

## What it does NOT do

- **It does not create the cgroup slice on a no-cgroup host.** The
  existing `detect_cgroup_v2` is read-only on missing v2. B1.3 is not
  the place to add slice creation for a host that lacks cgroup v2 — that
  is a V1-C1 / V1-C5 host-dep concern, out of scope for hardening.
- **It does not change the B1.1 process-group reaper.** The reaper is
  orthogonal to the cgroup fence; both protect in different ways.
- **It does not touch the B0 release.** No `cargo publish`, no
  `dist-manifest.json` change, no tag. The branch sits on
  `b1/worker-lifetime` and lands on its own.

## Test plan

- `uat_040_posture_label_in_audit_record` (existing): update to
  parameterise the test by HardenConfig and assert both paths (strong on
  cgroup-v2-mounted host, isolated otherwise). The existing
  `"ISOLATED_PROCESS_EXPOSURE"` assertion becomes a new helper
  `uat_040_strong_secretless_when_cgroup_fence_present` plus
  `uat_040_isolated_process_exposure_when_cgroup_fence_absent`.
- `uat_040_degraded_reason_records_why_we_demoted` (new): synthesise a
  worker run with a HardenConfig where cgroup v2 is missing, and assert
  `degraded_reason == Some("cgroup_v2_unavailable")`. Synthesised, not
  fake: a test-only constructor of HardenConfig exists at
  `harden.rs::HardenConfig::empty()`, and `install_with` runs against
  the real /proc/cgroup.
- Falsify against the closed enum: a hand-built `degraded_reason: "foo"`
  on a real audit row is rejected by a parse guard (or, more honestly,
  never appears because the type is a Rust enum and only the broker
  builds it).

## Risk and reversibility

- All changes are behind existing type-safe enums. A wrong flip defaults
  to the B1.1 behaviour, which is the regression-safe direction.
- The branch is off `b1/worker-lifetime`, not `main`. If the work does
  not land, the branch and worktree can be deleted with no impact on
  `main` or any release pipeline.
- The audit IPC field `degraded_reason: Option<String>` is
  backwards-compatible: existing consumers see `None` until B1.3 ships.

## Estimated diff size

- 1 enum in `isolated_exec.rs` (`DegradedReason`, ~30 lines)
- 1 accessor function (~10 lines)
- 1 default-flip (~3 lines)
- 1 audit DTO field addition in `ipc-protocol/src/lib.rs` (~3 lines)
- 1 doc-comment fix on the `posture` field (1 line)
- 1 audit-row populate in `worker.rs` (~5 lines)
- 2-3 new UAT-040 tests + 1 test split (~150 lines)
- 1 receipt (this document, ~200 lines including evidence)

Total: ~400 lines, mostly test code. The production change is roughly
50 lines.

## Awaiting confirmation

- [ ] User confirms "B1.3" is what was meant by "adelante apruebo"
- [ ] User confirms the audit field `degraded_reason: Option<String>` is
      the right shape (vs an enum at the IPC boundary, or
      a separate `PostureDegradation` event variant)
- [ ] User confirms default flip policy: B1.3 flips by default (strong
      when cgroup present, isolated when not) vs. opt-in via a feature
      flag (B1.3 introduces the plumbing but the default stays
      `IsolatedProcessExposure` for one more cycle)
