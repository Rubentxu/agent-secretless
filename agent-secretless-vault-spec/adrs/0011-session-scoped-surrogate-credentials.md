# ADR-0011 — Session-scoped surrogate credentials

- Status: Accepted
- Date: 2026-09-28

## Decision

For CLIs that require the *presence* of a credential, inject a non-secret surrogate mapped inside broker state.

A surrogate is:

- session-scoped,
- audience-bound,
- time-limited,
- provider-invalid,
- optionally shaped to satisfy local client validation.

The real credential is substituted/signed only inside a trusted connector/proxy.

## Consequences

This preserves CLI compatibility while ensuring `env`, shell tracing and process memory reveal at most a useless local reference.
