# ADR-0026 — Credential rotation uses stable logical bindings and staged candidates

- Status: Proposed
- Date: 2026-10-02

## Decision

Consumers reference a stable logical binding. Rotation creates a staged candidate, validates it, atomically switches the binding, then revokes the previous credential.

## Consequences

- Consumers do not change configuration on every rotation.
- Zero-disruption drain is possible.
- Rollback is explicit.
- PipelineK workflows can persist references/receipts without ever receiving secret bytes.
