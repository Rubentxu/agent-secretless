# ADR-0022 — Sensitive authority is bound to an ActionIntent and immutable execution plan

- Status: Proposed
- Date: 2026-10-02

## Decision

Sensitive operations may be planned before execution. Authorization is bound to a digest over relevant intent/execution dimensions.

Changing a bound dimension invalidates the plan.

## Bound dimensions

As applicable:

- principal;
- agent/workload;
- operation;
- resource;
- destination;
- tool identity;
- arguments digest;
- config fingerprint;
- policy epoch;
- required posture;
- expiry.

## Consequences

- Reduces TOCTOU, PATH hijacking and intent drift.
- Enables approvals tied to exact effects.
- Enables PipelineK durable step identity to be incorporated later without coupling ASV domain to PipelineK.
