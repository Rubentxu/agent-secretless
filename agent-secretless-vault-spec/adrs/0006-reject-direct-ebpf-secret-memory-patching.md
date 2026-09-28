# ADR-0006 — Reject direct eBPF secret injection into user memory

- Status: Accepted
- Date: 2026-09-28

## Context

`bpf_probe_write_user` can modify user memory in some tracing contexts, suggesting a tempting design where a placeholder is replaced just before use.

## Decision

Do not use eBPF/uprobes to write real credentials into arbitrary agent/CLI user-space memory.

## Rationale

- Linux documentation warns `bpf_probe_write_user` is not a security mechanism due to TOCTOU risk.
- Secret would exist in the untrusted process.
- TLS normally encrypts before kernel send hooks.
- Runtime/TLS ABI diversity makes generic coverage fragile.
- Buffer mutation can corrupt/crash processes.

## Consequences

Credential substitution belongs in broker/proxy memory outside the agent process.
