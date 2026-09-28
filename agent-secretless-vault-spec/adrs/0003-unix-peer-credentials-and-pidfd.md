# ADR-0003 — Authenticate local clients from OS peer evidence

- Status: Accepted
- Date: 2026-09-28

## Decision

Linux broker IPC uses Unix-domain sockets and obtains peer PID/UID/GID with `SO_PEERCRED`. Broker associates process evidence with a pidfd/session launch record to reduce PID-reuse ambiguity.

Self-declared agent names are metadata, not authentication.

## Consequences

The design follows workload-attestation principles similar to SPIRE and enables policy to bind access to actual local process/session context.
