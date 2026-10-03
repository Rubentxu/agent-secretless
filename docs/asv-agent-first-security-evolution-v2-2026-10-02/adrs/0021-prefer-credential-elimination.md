# ADR-0021 — Prefer credential elimination and ephemeral authority over static secret retrieval

- Status: Proposed
- Date: 2026-10-02

## Decision

The credential planner prefers, when available and policy-compatible:

```text
native federation
proof-of-possession
brokered signer
dynamic short-lived credential
semantic proxy/helper
surrogate
ephemeral projection
isolated exposure
raw exposure
```

A provider-specific strategy may override exact ranking only with an explicit rationale and posture.

## Consequences

- The vault remains important but is no longer the default answer to every integration.
- Integrations can transition from stored secrets to workload identity without changing agent UX.
- Strategy selection becomes auditable.
