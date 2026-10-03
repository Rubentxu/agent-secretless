# ADR-0023 — Workload identity and proof-of-possession are first-class authority inputs

- Status: Proposed
- Date: 2026-10-02

## Decision

ASV separates human principal, agent actor, workload identity, session identity and tool identity.

Where supported, access tokens should be sender-constrained or signer-backed so theft of bearer material is insufficient to act.

Adapters may provide SPIFFE-like, TPM-attested or platform-specific workload identity; local pidfd/kernel evidence remains valid.

## Consequences

- Better multi-agent attribution.
- Enables attenuated delegation.
- Enables short-lived session keys controlled by broker.
- Avoids collapsing workload identity into a self-declared agent name.
