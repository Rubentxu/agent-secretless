# M8 — Transparent eBPF Bridge R&D Gate — Merge Receipt

## Merge to main

- **HEAD at merge**: `575d684`
- **Branch**: main
- **Strategy**: fast-forward (linear history; commit landed on main).
- **Conflicts**: none.

## Released commits

| SHA | Subject |
|---|---|
| `575d684` | feat(ebpfd): M8 verb extension + cgroup_attach_skeleton |

## Changes since M7 (`82c4090`)

```
575d684..575d684
 crates/broker/tests/uat_024_helper_scope.rs | 51 +++++++++++++
 crates/ebpfd/src/lib.rs                      | 37 ++++++--
 crates/ebpfd/src/verbs.rs                    | 144 +++++++++++++++++++++++++++++
 docs/design/m8-design.md                     | new
 docs/exploration/m8-exploration.md           | new
 docs/specs/m8-ebpf-bridge/specification.md   | new
```