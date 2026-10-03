# ADR-0019 — Agent surfaces navigate a versioned hypermedia protocol

- Status: Proposed
- Date: 2026-10-02

## Decision

ASV exposes `asv agent discover --json` as the canonical agent entry point and returns versioned typed relations (`rel`) plus safe invocation descriptors (`program` + `argv[]`).

Skills are external clients of this protocol; they are not compiled into ASV.

## Consequences

- Agent workflows become discoverable.
- Skills shrink and avoid duplicating state machines.
- CLI/MCP can share one capability catalogue.
- Removing a relation removes the advertised path; agents must not guess hidden verbs.
- Protocol compatibility must be versioned independently from product version.
