# M8 — Transparent eBPF Bridge R&D Gate — Archive Receipt

## Gate closed

- **name**: m8-ebpf-bridge
- **type**: R&D gate
- **verdict**: PASS — M9 may start
- **closed_at**: 2026-09-29T09:34:00Z (estimated; CI clock)
- **release_sha**: `575d684`
- **tag**: `m8-ebpf-bridge` (annotated; SHA `575d684`)

## Archived artifacts

| Artifact | Purpose |
| --- | --- |
| `docs/specs/m8-ebpf-bridge/specification.md` | ADDED requirements M8-R1..R5 |
| `docs/exploration/m8-exploration.md` | Spike E1..E4 + decision matrix |
| `docs/design/m8-design.md` | Verb enum extension + program allow-list + audit format + skeleton ABI |
| `releases/m8-ebpf-bridge/release-report.md` | Requirement coverage + gaps |
| `releases/m8-ebpf-bridge/merge-receipt.md` | Git history summary |

## Knowledge synced

- The closed verb set is now 8 verbs (4 M7 + 4 M8). Any future verb
  addition MUST extend `uat_024_helper_scope` and `ebpfd::tests`.
- `program_lookup` is the single allow-list for shipped BPF programs.
  Adding a new shipped program requires a new `ProgramId` variant AND
  a new entry in `program_lookup` AND a regression test in
  `ebpfd::tests::program_lookup_returns_*_only`.
- `cgroup_attach_skeleton` is the documented M9 ABI. M9 replaces the
  body with a real `bpf_link_create(BPF_LINK_TYPE_CGROUP)` call. The
  signature is the API contract; the implementation is M9 scope.

## Follow-ups (deferred to M9)

- Aya-generated `connect4-redirect-v1.c` BPF ELF object.
- BTF availability detector (kernel ≥ 5.15 with `/sys/kernel/btf/vmlinux`).
- Per-cgroup map management in the broker (which sessions redirect
  which destinations).
- Audit log emit helper that writes the documented line.
- `CgroupAttach` argument validator (parses `0x[0-9a-fA-F]+` to u64;
  rejects paths and other formats).

## R&D gate outcome

The M8 R&D gate **passes** and M9 (Transparent TLS bridge) may start.
The gate's deliverables (verb extension, allow-list, audit format,
skeleton) are sufficient evidence that the M9 architecture is
achievable with the current technology choice (Aya + userspace loader +
asv-ebpfd).