# ADR-0010 — Keep vault behind a port; evaluate Stronghold but do not lock in yet

- Status: Accepted
- Date: 2026-09-28

## Decision

Define a vault port and build/evaluate a local encrypted backend using established cryptographic libraries. Run an explicit evaluation of IOTA Stronghold/procedure semantics before selecting it as the long-term storage engine.

Do not use the Tauri Stronghold JavaScript plugin as the agent/broker secret API.

## Rationale

Stronghold has attractive non-read/procedure concepts, but current low-level documentation includes an unaudited-library warning. The product should preserve the ability to replace storage without changing agent integrations.
