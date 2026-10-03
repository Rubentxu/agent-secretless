# ASV roadmap resequencing

This patch preserves M0–M13 truth and removes duplication between the old DX pack and the newer post-v1 evolution.

## Before v1: M13-DX — agent-first release operability

**Ownership:** subdivision of existing M13, not a new milestone family.

It can be implemented while unrelated M11/M12 evidence is still being obtained, but it does **not** close M13 or v1 by itself.

### DX-A — Product boundary / package allowlist

- explicit production component manifest;
- public `asv`;
- private `asv-brokerd` outside PATH;
- optional console;
- `asv-vault-tool` forbidden from production artifacts;
- distribution content falsification test.

**Why here:** M13 already owns package hardening, SBOM and signed artifacts.

### DX-B — Setup + doctor

- idempotent `asv setup`;
- `asv doctor --json`;
- binary/broker/protocol/path consistency;
- clean HOME install UAT.

**Why here:** v1 cannot be considered operationally usable if humans/agents need broker internals.

### DX-C — Minimal agent hypermedia contract

- `asv.agent/v1`;
- `asv agent discover --json`;
- typed relations for doctor/setup/capabilities/supported operations;
- errors return recovery relations;
- no stateful `agent next` engine.

**Why here:** agent-first is a product property, not a connector family.

### DX-D — Official skill

- `Rubentxu/agent-skill/skills/agent-secretless`;
- router + progressive references;
- evals;
- no runtime/workflow logic duplicated in Markdown.

### DX-E — release artifact route

- signed direct archive/installer using the production manifest.

**Non-blocking post-v1 channels:** mise/deb/rpm/updater can progress as a distribution track without consuming a numbered security milestone.

---

## M14 — Credential Workflow Adapters

**Goal:** integrate real tool configuration without creating a second provider/connector framework.

First adapters:

1. npm;
2. Maven;
3. Gradle;
4. curl.

ASV owns:

```text
discover -> plan -> adopt -> project -> verify -> scrub
```

But strategy execution reuses existing ASV primitives:

- HTTP broker/surrogates from M4;
- signer/session paths from earlier milestones;
- compatibility isolated worker from M10 only when unavoidable;
- M11 provider mechanisms when available.

No adapter may implement its own vault, OAuth client framework or isolated executor.

### Exit

- safe discovery with no secret output;
- fingerprint/TOCTOU protection;
- strongest existing strategy selected;
- ephemeral projections truthfully classified;
- scrub only after positive and negative verification.

---

## M15 — Authority Planning & Plan-Bound Execution

**Goal:** bind authority to precise intent and select among existing mechanisms.

### Scope

- `ActionIntent`;
- principal / agent / workload attribution;
- tool identity;
- plan digest and expiry;
- destination/resource binding;
- approval bound to plan digest;
- strategy ranking over **existing** connector/provider capabilities;
- proof-of-possession use when a provider adapter already supports it.

### Explicit non-scope

- no second Cedar engine;
- no new OAuth/STS/mTLS provider framework;
- no duplicate signer/proxy implementation.

M11 remains owner of provider-specific mechanisms.

---

## M16 — Durable Automation Port (PipelineK integration)

**Goal:** delegate complex multi-step lifecycle execution to a workflow engine rather than growing one in ASV.

### ASV owns

- atomic credential operations;
- logical credential bindings;
- rotation/adoption domain plan;
- operation idempotency/reconciliation contracts;
- security approval;
- immediate compromise freeze/revoke;
- `AutomationPort` abstraction.

### PipelineK adapter owns

- durable sequencing;
- restart/replay;
- waiting/resume;
- cancellation;
- workflow receipts/correlation.

### Hard law

`asv-brokerd` never depends on PipelineK.

### Direct vs automated

- provider-native atomic rotation → ASV direct;
- multi-step rotation/migration/remediation → AutomationPort, official PipelineK adapter preferred;
- no hidden ASV fallback workflow engine that duplicates PipelineK.

### Dynamic plans

ASV may produce a versioned `RotationPlan`/`AdoptionPlan`; PipelineK executes it only through a **native/public workflow capability**. If PipelineK does not yet expose such a generic mechanism, use a bounded certified template for the first vertical and wait for PipelineK's own roadmap rather than building a private executor in the plugin.

---

## M17 — Attested Authority

**Prerequisites:** M7 hardening evidence + real M12 hardware work where required.

### Scope

- generic `AttestationPort`;
- freshness and evidence refs;
- Keylime/Trustee adapter spike;
- Cedar consumes attestation verdict;
- signed authorization receipts;
- secret-safe OTLP projection;
- optional SELinux/fapolicyd/OpenSCAP posture ingestion.

### Non-scope

- no duplicate TPM sealing;
- no duplicate Landlock/seccomp/cgroup framework;
- no ASV-managed enterprise remediation engine.

### Conditional later research

TDX/SNP confidential worker or remote broker only when a remote/shared deployment has a concrete threat-model need.

---

## M18 — v1.1 stabilization

- full new AAT/UAT matrix;
- migration/rollback;
- update anti-rollback design (TUF-compatible decision);
- provenance/SLSA where release infrastructure can prove it;
- stress rotation;
- audit/receipt correlation;
- external review preparation;
- skill eval regression;
- no new broad integration families.

## Dependency view

```text
Existing M0-M13
     |
     +-- M13-DX (agent-first release operability)
     |
     v
    v1.0
     |
     v
M14 tool workflow adapters
     |
     v
M15 authority planning
     |
     +-------------------+
     |                   |
     v                   v
M16 durable automation  M17 attested authority
     |                   |
     +---------+---------+
               v
          M18 v1.1 stabilization
```
