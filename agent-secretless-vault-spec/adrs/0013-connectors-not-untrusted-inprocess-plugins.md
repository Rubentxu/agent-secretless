# ADR-0013 — No arbitrary in-process connector plugins in v1

- Status: Accepted
- Date: 2026-09-28

## Decision

V1 connectors are reviewed built-ins. Future third-party extension should prefer a versioned out-of-process connector protocol with narrowly delegated operations.

## Rationale

A dynamically loaded plugin inside `asv-brokerd` executes in the same address space as decrypted credentials and defeats the effort spent reducing trusted code.
