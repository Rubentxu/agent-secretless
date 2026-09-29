# M7 Linux Hardened — Merge Receipt

## Merge to main

- **HEAD at merge**: `ab8bdac`
- **Branch**: main
- **Strategy**: fast-forward (linear history; each M7 commit landed
  directly on `main` after the M6 release at `0a643fa`).
- **Conflicts**: none.

## Released commits

| SHA | Subject |
|---|---|
| `5699686` | feat(ebpfd): scaffold asv-ebpfd helper with closed verb set (M7-R5) |
| `45d620c` | feat(broker): M7 harden::install + UAT 003/023/024 |
| `9d3a525` | feat(broker): M7-R3 Landlock + M7-R4 Seccomp install |
| `ab8bdac` | test(broker): UAT-005 privileged tool integration |

## Changes since M6 (`0a643fa`)

```
5699686..ab8bdac
 crates/broker/Cargo.toml                          |   5 +
 crates/broker/src/harden.rs                       | 365 ++++++
 crates/broker/src/lib.rs                          |   1 +
 crates/broker/tests/uat_003_proc_inspection.rs    |  60 ++
 crates/broker/tests/uat_005_privileged_tools.rs    |  67 ++
 crates/broker/tests/uat_023_cgroup_escape.rs      |  55 ++
 crates/broker/tests/uat_024_helper_scope.rs       |  75 ++
 crates/ebpfd/Cargo.toml                           |  16 +
 crates/ebpfd/src/lib.rs                            |  99 ++
 docs/design/m7-design.md                          | new
 docs/exploration/m7-exploration.md                | new
 docs/specs/m7-linux-hardened/specification.md     | new
 releases/m7-linux-hardened/release-report.md      | new
 Cargo.lock                                        |   (auto)
```