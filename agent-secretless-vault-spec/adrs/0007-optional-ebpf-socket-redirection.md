# ADR-0007 — Use eBPF for optional session-aware socket redirection and egress control

- Status: Accepted with research gate
- Date: 2026-09-28

## Decision

Investigate `cgroup/connect4`, `connect6` and peer-address hooks to transparently route selected connections from an ASV session to a local proxy while retaining original-destination metadata.

Also use cgroup eBPF for egress allow/deny and session attribution.

## Conditions

Production feature ships only after roadmap M8 GO criteria pass.

## Consequences

Agent commands may remain unchanged even for tools ignoring `HTTPS_PROXY`, while secrets stay in userspace broker/proxy. Linux-specific complexity is isolated behind platform ports.
