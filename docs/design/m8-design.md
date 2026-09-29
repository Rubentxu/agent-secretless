# M8 — Transparent eBPF Bridge R&D Gate — Design

## 1. Scope reminder

M8 is a **research & design gate**. It does **not** ship the Aya-generated
eBPF runtime. It extends the `asv-ebpfd` verb set, locks in the closed
allow-list, and documents the syscall ABI that M9 will call for real.

## 2. `asv-ebpfd` extension

### 2.1 `Verb` enum extended

The current M7 enum:

```rust
pub enum Verb {
    SessionAttach,
    SessionDetach,
    CgroupRead,
    SeccompDump,
}
```

Extends to:

```rust
pub enum Verb {
    // M7 surface — unchanged
    SessionAttach,
    SessionDetach,
    CgroupRead,
    SeccompDump,
    // M8 surface — new
    CgroupAttach,
    CgroupDetach,
    ProgramLoad,
    ProgramUnload,
}
```

Each variant has a `as_str()` that returns its verb string. `parse_verb`
matches exhaustively and rejects unknown inputs with `VerbError::Unknown`.

### 2.2 Verb string table

| Variant | Verb string |
|---|---|
| `SessionAttach` | `session.attach` |
| `SessionDetach` | `session.detach` |
| `CgroupRead` | `cgroup.read` |
| `SeccompDump` | `seccomp.dump` |
| `CgroupAttach` | `cgroup.attach` |
| `CgroupDetach` | `cgroup.detach` |
| `ProgramLoad` | `program.load` |
| `ProgramUnload` | `program.unload` |

### 2.3 Argument types

| Variant | Argument | Returns |
|---|---|---|
| `SessionAttach` | `SessionAttachArgs { session_id, cgroup_id, program_id }` | `Ok(())` |
| `SessionDetach` | `SessionDetachArgs { session_id }` | `Ok(())` |
| `CgroupRead` | `()` | `Ok(CgroupSnapshot)` |
| `SeccompDump` | `()` | `Ok(SeccompSnapshot)` |
| `CgroupAttach` | `CgroupAttachArgs { cgroup_id, program_id }` | `Ok(AttachHandle)` |
| `CgroupDetach` | `CgroupDetachArgs { attach_handle }` | `Ok(())` |
| `ProgramLoad` | `ProgramLoadArgs { name }` | `Ok(ProgramId)` |
| `ProgramUnload` | `ProgramUnloadArgs { program_id }` | `Ok(())` |

`CgroupAttachArgs.cgroup_id` is parsed from a `0x[0-9a-fA-F]+` string and
must be a valid u64. Any other input format returns `VerbError::InvalidArgument`.

### 2.4 Program allow-list

The helper keeps an inline table of shipped programs:

```rust
pub fn program_lookup(name: &str) -> Option<ProgramId> {
    match name {
        "connect4-redirect-v1" => Some(ProgramId::Connect4RedirectV1),
        _ => None,
    }
}
```

`ProgramLoad` calls this and returns `Err(VerbError::Unknown(name.into()))`
on `None`. The helper **never** accepts a path to a `.bpf.o` file or a raw
bytecode buffer. The body of the program is shipped with the broker binary
in M9.

## 3. Audit log format

```
asv-ebpfd: <verb> <arg> sequence=<N> session=<session-id>
```

`N` starts at 1 and increments per call. The `sequence` field is the
broker's primary tool for detecting lost audit lines (a gap in the sequence
number is itself an alert).

The M8 prototype writes to `stderr` (acceptable for the gate). M9 will route
the audit log to the broker's structured logging.

## 4. `cgroup_attach_skeleton` ABI

The M8 prototype includes a function with the *intended* M9 signature. It
does nothing destructive and returns `Ok(())`. The doc-comment is the
authoritative description of what M9 will replace this with.

```rust
/// Attach a loaded BPF program to a cgroup id.
///
/// M9 implementation:
///   - validate cgroup_id is in the broker-owned set,
///   - call bpf_link_create with type BPF_LINK_TYPE_CGROUP and
///     prog_id and cgroup_id,
///   - return a stable handle (the bpf_link fd) wrapped in AttachHandle,
///   - on success emit an audit line at sequence=N.
///
/// M8 prototype returns Ok(()) without performing any syscall. This is the
/// structural skeleton.
pub fn cgroup_attach_skeleton(
    cgroup_id: u64,
    program_id: ProgramId,
) -> Result<AttachHandle, HelperError> {
    let _ = (cgroup_id, program_id);
    Ok(AttachHandle(0))
}
```

The structural test asserts that this function is callable, returns `Ok`,
and does not panic.

## 5. Closed-set regression

The existing `uat_024_helper_scope` test in `asv-broker/tests/` is
extended with these additional inputs:

```
"bpf.load_arbitrary", "BPF.LOAD", "cgroup.write", "cgroup.move",
"cgroup.freeze", "program.load_arbitrary", "program.attach_arbitrary"
```

Each is asserted to return `VerbError::Unknown`. The test is the regression
guard for M8-R2 / M8-R3.

## 6. Why this design passes the R&D gate

- The `Verb` enum extension is a strict addition; the M7 surface is
  untouched and the existing `uat_024` test still passes.
- The allow-list mechanism for `ProgramLoad` is one `match` statement;
  there is no path that accepts a bytecode buffer or a file path.
- The audit log format is documented and the M9 implementer knows exactly
  what to emit.
- The prototype `cgroup_attach_skeleton` documents the M9 syscall surface
  in code, so the gap between M8 and M9 is reduced from "research" to
  "wire Aya + implement the body of the skeleton function".

## 7. Out-of-scope (deferred to M9)

- The Aya-generated `connect4-redirect-v1.c` BPF program.
- The runtime that detects BTF availability and decides to load the
  program or fall back to explicit proxy.
- The broker-side session cgroup map (which sessions are redirecting what
  destinations).
- The TLS bridge that terminates the redirected socket on the broker side.

## 8. Verdict

M8 design passes the R&D gate. The deliverables — verb extension,
allow-list, audit format, prototype hook — are sufficient to authorise
starting M9.