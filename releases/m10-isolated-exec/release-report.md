# M10 — Isolated exec compatibility — Release Receipt

> Release via local Git (per orchestrator directive: SDDK state machine
> is bypassed per the precedent in `p-28fce7028ac3c497/releases/v0.107.0`).

## Cycle

- **name**: m10-isolated-exec
- **type**: R&D gate (M10-prototype pass)
- **verdict**: PASS — M10-runtime follow-up may start
- **scope**: p-20a1ee316faf2ba3 / w-14da88592558b9434aff17d8
- **tag**: `m10-isolated-exec` (annotated, local)

## Requirements closed (M10-prototype)

- **M10-R1** (`WorkerTemplate` + `WorkerRegistry`) — registered-worker
  resolver.
- **M10-R2** (`EgressPolicy`) — allow-list / deny with `authorises()`.
- **M10-R3** (`SecretInjectionPlan`) — EnvVar / File / None.
- **M10-R4** (`LandlockProfile` + `SeccompProfile`) — per-template
  profile types.
- **M10-R5** (`Redactor`) — exact-byte replacement with
  longest-match-first.
- **M10-R6** (`POSTURE_LABEL`) — `ISOLATED_PROCESS_EXPOSURE`.

## Coverage

| Test | Purpose | Result |
|---|---|---|
| `isolated_exec::tests::*` (18 unit tests) | unit | pass |
| `uat_021_isolated_worker_egress` (5 integration tests) | integration | pass |
| `uat_022_transformed_stdout_leak` (7 integration tests) | integration | pass |

## Workspace test totals

| Crate | count |
|---|---|
| asv-broker unit | 67 → 85 (+18) |
| asv-broker integration (M10) | 12 (5+7) |
| asv-broker integration (M9) | 14 |
| asv-broker integration (M7+M8+rest) | 105 |
| asv-ebpfd | 7 |
| (other crates) | 125+ |
| **total** | **~348** (1 ignored, 2 pre-existing flakes) |

## Atomic commits

| SHA | Subject |
|---|---|
| (single) | feat(broker): M10 isolated exec compatibility prototype |

## Honest gaps (deferred to M10-runtime follow-up)

- The actual `std::process::Command` + namespace setup.
- The Landlock + Seccomp per-template installation (uses M8 verbs).
- The cgroup slice creation per worker.
- The audit log emission for each secret injection.
- The UI surface (M5 dashboard indicator for `ISOLATED_PROCESS_EXPOSURE`).

## Verdict

The M10-prototype cycle **passes**. UAT-021 (egress confinement) and
UAT-022 (redactor honest limitation) are covered. The runtime
follow-up cycle adds the actual process spawning + namespace flow.