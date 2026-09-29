# M8 — Transparent eBPF Bridge R&D Gate — Specification

## Goal

M8 is a **research & design gate**, not a feature delivery. It authorises (or
rejects) starting M9 (Transparent TLS bridge) based on the feasibility of
cgroup-based socket redirect via Aya + asv-ebpfd.

## ADDED requirements

### M8-R1 — asv-ebpfd verb set extended for cgroup redirect

The privileged helper `asv-ebpfd` SHALL accept exactly these verbs:

| Verb | Verb string | Purpose |
|---|---|---|
| `SessionAttach` | `session.attach` | (existing, M7) attach BPF map entry for a session |
| `SessionDetach` | `session.detach` | (existing, M7) clean up map entries on session end |
| `CgroupRead` | `cgroup.read` | (existing, M7) observability |
| `SeccompDump` | `seccomp.dump` | (existing, M7) observability |
| `CgroupAttach` | `cgroup.attach` | (M8 E1) attach loaded program to a cgroup id |
| `CgroupDetach` | `cgroup.detach` | (M8 E1) detach program from a cgroup id |
| `ProgramLoad` | `program.load` | (M8 E1) load a shipped/signed BPF ELF by name |
| `ProgramUnload` | `program.unload` | (M8 E1) unload a previously loaded program |

#### Scenario: closed-set enforcement

> When the broker receives a request `asv-ebpfd <other-verb>`, the helper
> MUST reject it with `VerbError::Unknown(<other-verb>)`.

### M8-R2 — ProgramLoad is a closed allow-list, not arbitrary bytecode

`ProgramLoad` SHALL accept only a *name* (string) and reject every input not
in the table of shipped programs. The table is:

| Name | Type | Description |
|---|---|---|
| `connect4-redirect-v1` | CGROUP_SOCK_ADDR | rewrites IPv4 connect destinations |

Names not in the table return `VerbError::Unknown` with the input verbatim.

#### Scenario: shipped name accepted, arbitrary name rejected

> Given the helper knows `connect4-redirect-v1`, calling `ProgramLoad` with
> that name returns `Ok(ProgramId::Connect4RedirectV1)`. Calling with
> `bpf.load_arbitrary` returns `Err(VerbError::Unknown("bpf.load_arbitrary".into()))`.

### M8-R3 — CgroupAttach takes a cgroup id, not a path

`CgroupAttach` SHALL accept a numeric cgroup id (u64, hex-encoded) returned
from a prior `CgroupRead` call. Path-based inputs (`/sys/fs/cgroup/...`)
return `VerbError::InvalidArgument`.

#### Scenario: cgroup id accepted, path rejected

> `CgroupAttach` with the wire id `"0x1234"` (or decimal `"4660"`) parses to
> `Ok(0x1234)`. `CgroupAttach("/sys/fs/cgroup/...")`, `"../escape"`, `""`,
> `"12x"`, `"0x"` and values above `u64::MAX` return
> `Err(VerbError::InvalidArgument)`.
> (Concretely implemented and tested by `parse_cgroup_id` — cycle
> m8-rd-gate, ebpfd unit tests + `uat_024_m8_parse_cgroup_id_rejects_path_arguments`.)

### M8-R4 — Audit log emits one line per privileged verb

Every successful `ProgramLoad`, `CgroupAttach`, `CgroupDetach`,
`ProgramUnload` SHALL emit one audit line of the form:

```
asv-ebpfd: <verb> <arg> sequence=<N> session=<session-id>
```

Where `N` is a monotonically increasing sequence number from the helper
(`AuditCounter`, 1-based, one per helper process; implemented in cycle
m8-rd-gate — `session=<session-id>` remains `session=prototype` until M9
threads the real session id).

### M8-R5 — Prototype CgroupAttach syscall surface

The helper MUST include a function `cgroup_attach_skeleton` which the M9
implementation can replace. The function signature documents the intended
ABI; the body does nothing destructive and returns `Ok(())`. The structural
test asserts that `cgroup_attach_skeleton` is callable with a numeric cgroup
id and returns `Ok(())` without panicking.

## MODIFIED requirements

None. M8 is additive on top of M7.

## REMOVED requirements

None.

## Out of scope

- Aya-generated BPF ELF objects — M9.
- BPF map management for active sessions — M9.
- TLS bridge — M9.
- Performance benchmarks — M9.

## Verification

1. `cargo test -p asv-ebpfd` covers the closed verb set + prototype hooks.
2. `cargo test --test uat_024_helper_scope -p asv-broker` covers the
   integration with the broker.
3. The exploration doc and the design doc are present in
   `docs/exploration/m8-exploration.md` and `docs/design/m8-design.md`.

## Verdict

The M8 cycle is **passed** if all four M8-R1..M8-R5 scenarios pass their
regression tests and the docs are present. Then M9 starts. Otherwise the
project falls back to explicit-proxy-only (M4+M6) and M8 is closed with
verdict "fail-soft".