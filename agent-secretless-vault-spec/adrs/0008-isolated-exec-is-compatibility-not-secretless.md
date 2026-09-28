# ADR-0008 — Isolated execution is a compatibility fallback

- Status: Accepted
- Date: 2026-09-28

## Decision

When a legacy tool must hold a real credential, run it in a broker-created isolated worker rather than in the agent process tree.

Classify this `ISOLATED_PROCESS_EXPOSURE`, not strong-secretless.

## Required controls

- separate identity/sandbox,
- minimal filesystem,
- narrow egress,
- short lifetime,
- no agent-controlled inherited descriptors,
- secret zeroization/cleanup.

## Rationale

A process that legitimately receives a bearer secret can encode/transform it, so output redaction cannot provide a strong non-disclosure guarantee. Network/filesystem confinement is the critical control.
