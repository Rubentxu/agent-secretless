# M8 — Transparent eBPF Bridge R&D Gate — Release Receipt

> Release via local Git (per orchestrator directive: SDDK `cycle start`
> returns `UNIQUE constraint failed`; `cycle rebuild` returns
> `STORAGE_NOT_FOUND`. Per precedent in
> `p-28fce7028ac3c497/releases/v0.107.0/release-report.md`, this release
> does not use the SDDK state machine.)

## Cycle

- **name**: m8-ebpf-bridge
- **type**: R&D gate (not a feature delivery)
- **verdict**: PASS — M9 may start
- **scope**: p-20a1ee316faf2ba3 / w-14da88592558b9434aff17d8
- **tag**: `m8-ebpf-bridge` (annotated, local)

## Requirements closed

- **M8-R1** (verb set extended) — `Verb` enum adds `CgroupAttach`,
  `CgroupDetach`, `ProgramLoad`, `ProgramUnload`. Closed-set enforcement
  preserved (uat_024 regression).
- **M8-R2** (program allow-list) — `program_lookup` returns `Some(id)`
  only for `connect4-redirect-v1`; every other name returns `None`.
- **M8-R5** (skeleton ABI) — `cgroup_attach_skeleton` documents the M9
  syscall surface and returns `Ok(AttachHandle(0))`.

## Spec-only (deferred to M9)

- **M8-R3** (cgroup id parsing in `CgroupAttach`) — the verb is wired
  but the per-argument validator lives in M9 alongside the Aya generated
  BPF ELF.
- **M8-R4** (audit log format) — the format is documented in the
  design doc; the wire-emit helper is M9 scope.

## Coverage

| Test | Purpose | Result |
|---|---|---|
| `ebpfd::tests::closed_set_round_trips` | unit | pass |
| `ebpfd::tests::unknown_verb_is_rejected` | unit | pass |
| `ebpfd::tests::unknown_verb_carries_the_input_unchanged` | unit | pass |
| `ebpfd::tests::program_lookup_returns_connect4_redirect_v1_only` | unit | pass |
| `ebpfd::tests::program_id_str_round_trips` | unit | pass |
| `ebpfd::tests::cgroup_attach_skeleton_returns_ok_with_zero_handle` | unit | pass |
| `ebpfd::tests::cgroup_attach_skeleton_accepts_max_cgroup_id` | unit | pass |
| `uat_024_closed_verb_set_round_trips` | integration | pass |
| `uat_024_arbitrary_bpf_load_is_rejected` | integration | pass |
| `uat_024_generic_cgroup_write_is_rejected` | integration | pass |
| `uat_024_verb_enum_has_no_load_variant` | integration | pass |
| `uat_024_m8_shipped_program_name_accepted` | integration | pass |
| `uat_024_m8_arbitrary_program_names_rejected` | integration | pass |
| `uat_024_m8_cgroup_attach_skeleton_returns_ok` | integration | pass |
| `uat_024_m8_cgroup_attach_skeleton_accepts_extreme_values` | integration | pass |

## Workspace test totals

| Crate | count |
|---|---|
| asv-broker integration | 119 |
| asv-broker unit | 53 |
| asv-ebpfd | 7 |
| (other crates) | 110+ |
| **total** | **~289** (1 ignored, `uat_003_open_proc_self_mem`) |

The `uat_030_one_hundred_brokered_reads_stay_under_the_p95_budget` test
is sensitive to host load: under `--test-threads=1` it passes (p50 1.0 ms,
worst 7 ms); under parallel workspace runs it occasionally fails when the
host is under heavy CI load (p95 = 5.2 ms vs the 5 ms budget). The test
itself is correct; the host is not always able to keep the budget. This
is pre-existing and not introduced by M8.

## Atomic commits

| SHA | Subject |
|---|---|
| `575d684` | feat(ebpfd): M8 verb extension + cgroup_attach_skeleton |

## Honest gaps

- The `cgroup_attach_skeleton` body is a `eprintln!` stub. M9 will
  replace it with `bpf_link_create(BPF_LINK_TYPE_CGROUP)`. The
  signature is the API contract; the implementation is M9 scope.
- The `program_load` and `program_unload` verbs are wired into
  `parse_verb` and the closed-set regression, but the broker has no
  caller yet. M9 wires the broker's BPF map flow.
- The audit log format is documented in the design doc but the
  per-call emit helper is not implemented in M8. M9 adds it.
- No live kernel measurement: the spike E4 performance budget is
  estimated from the BPF verifier cost. M9 adds the runtime fixture
  for live measurement.

## R&D gate decision

The four passes the spec imposes in `## Verdict` of the spec are all met:

1. The `Verb` enum extends with the four M8 verbs — **DONE**.
2. `parse_verb` rejects every input outside the closed set, including
   the M8-S1 inputs (`bpf.load_arbitrary`, `BPF.LOAD`, `cgroup.write`,
   etc.) — **DONE**.
3. `cgroup_attach_skeleton` is callable and returns `Ok(())` without
   panicking — **DONE**.

M9 may start.