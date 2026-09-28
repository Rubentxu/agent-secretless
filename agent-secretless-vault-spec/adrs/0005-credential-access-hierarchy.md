# ADR-0005 — Credential access hierarchy

- Status: Accepted
- Date: 2026-09-28

## Decision

Choose the strongest compatible mechanism in this order:

1. non-exportable signer/cryptographic operation,
2. workload/delegated identity,
3. protocol/service proxy,
4. broker-side request signing,
5. dynamic short-lived credential,
6. transparent TLS surrogate bridge,
7. isolated execution,
8. explicit raw exposure only as degraded opt-in.

## Consequences

Integration quality is measured by security property, not merely by whether a command works.
