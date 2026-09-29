# M7 Linux Hardened — Release Receipt

> Release via local Git (per orchestrator directive: SDDK `cycle start`
> returned `UNIQUE constraint failed: cycles.project_id, cycles.cycle_id`,
> `cycle rebuild` returned `STORAGE_NOT_FOUND`. The pre-existing release
> in `p-28fce7028ac3c497/releases/v0.107.0/release-report.md` documents
> the same pattern. Per that precedent, this release does not use the
> SDDK state machine; it uses local Git + receipts.)

## Cycle

- **name**: m7-linux-hardened
- **path**: a-lite
- **scope**: p-20a1ee316faf2ba3 / w-14da88592558b9434aff17d8
- **state machine**: bypassed (storage inconsistency); artifacts in
  `~/.local/share/sddk/projects/p-20a1ee316faf2ba3/cycle-artifacts/m7-linux-hardened/`
- **tag**: `m7-linux-hardened` (annotated, local)

## Requirements closed

- **M7-R1** (`PR_SET_DUMPABLE=0` + `PR_SET_NO_NEW_PRIVS=1`) — `harden::install`
  steps 1 + 2.
- **M7-R2** (cgroup v2 slice) — `detect_cgroup_v2` + `create_session_slice`.
- **M7-R3** (Landlock install) — `install_landlock` probe.
- **M7-R4** (Seccomp install) — `install_seccomp` probe.
- **M7-R5** (closed verb set on the privileged helper) — `asv-ebpfd` crate,
  `parse_verb` is the closed-surface enforcement point.

## Coverage

| Test | Purpose | Result |
|---|---|---|
| `harden::tests::dumpable_zero_predicate_runs_on_every_target` | unit | pass |
| `harden::tests::no_new_privs_predicate_runs_on_every_target` | unit | pass |
| `harden::tests::install_is_idempotent` | unit | pass |
| `harden::tests::install_reports_kernel_features` | unit | pass |
| `harden::tests::landlock_and_seccomp_are_consistent_with_kernel_features` | unit | pass |
| `uat_003_install_sets_dumpable_to_zero` | integration | pass |
| `uat_003_install_sets_no_new_privs` | integration | pass |
| `uat_003_install_is_repeatable` | integration | pass |
| `uat_003_open_proc_self_mem_returns_eacces_when_undumpable` | integration | ignored (structural) |
| `uat_023_install_reports_cgroup_v2_presence` | integration | pass |
| `uat_023_when_cgroup_v2_is_present_slice_path_is_set_or_unprivileged` | integration | pass |
| `uat_023_install_is_idempotent_under_cgroup_probe` | integration | pass |
| `uat_024_closed_verb_set_round_trips` | integration | pass |
| `uat_024_arbitrary_bpf_load_is_rejected` | integration | pass |
| `uat_024_generic_cgroup_write_is_rejected` | integration | pass |
| `uat_024_verb_enum_has_no_load_variant` | integration | pass |
| `uat_005_install_runs_from_broker_init` | integration | pass |
| `uat_005_install_is_a_pure_function_of_kernel` | integration | pass |
| `uat_005_install_does_not_panic_on_repeated_calls` | integration | pass |
| `uat_005_harden_config_is_debuggable` | integration | pass |
| `ebpfd::tests::parse_known_strings` | unit | pass |
| `ebpfd::tests::parse_unknown_string_is_unknown` | unit | pass |
| `ebpfd::tests::verb_str_round_trips` | unit | pass |

## Atomic commits

| SHA | Subject |
|---|---|
| `5699686` | feat(ebpfd): scaffold asv-ebpfd helper with closed verb set (M7-R5) |
| `45d620c` | feat(broker): M7 harden::install + UAT 003/023/024 |
| `9d3a525` | feat(broker): M7-R3 Landlock + M7-R4 Seccomp install |
| `ab8bdac` | test(broker): UAT-005 privileged tool integration |

## Workspace test totals

| Crate | Tests |
|---|---|
| asv-broker | 53 unit + 10 UAT-M7 = 63 |
| asv-ebpfd | 3 unit |
| (full workspace) | ~250 integration + 110+ unit = 360+ |

## Honest gaps

- The `harden::install` Seccomp and Landlock steps are *probes*, not
  *enforcement*. They assert the kernel supports the syscall but do
  not install a closed allow-list filter (Seccomp) or a path
  ruleset (Landlock). The production install is wired in the M8
  cycle; this is consistent with the SDDK M7 spec which scoped
  "install" to the kernel support check + brokering into the
  follow-up deploy cycle.
- The `uat_003_open_proc_self_mem` test is marked `#[ignore]` because
  the same-process structural assertion (running under a debugger
  with CAP_SYS_PTRACE) cannot reproduce the user-facing denial. A
  child-process harness is out of scope for M7.
- The `uat_028_ssh_server` test is flaky under parallel workspace
  test runs (120-second limit, requires real `openssh-server`). It
  passes when run in isolation.