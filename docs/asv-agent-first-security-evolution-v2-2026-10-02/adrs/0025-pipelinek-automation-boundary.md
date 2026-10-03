# ADR-0025 — PipelineK is an optional automation adapter; the ASV broker never depends on it

- Status: Proposed
- Date: 2026-10-02

## Decision

Complex lifecycle automation (rotation, migration, incident remediation) may use PipelineK through an `AutomationPort` in ASV's control plane.

`asv-brokerd` never launches or embeds PipelineK.

On the PipelineK side, ASV integration is an `OFFICIAL_PLUGIN` using public SDK mechanisms. Jenkins-friendly core DSL signatures and semantics remain untouched.

## Consequences

- ASV avoids building a workflow engine.
- Broker TCB remains small.
- PipelineK durability/replay can be reused.
- PipelineK can evolve generic SDK ports/capabilities when justified, but never ASV-specific implementation in core.
