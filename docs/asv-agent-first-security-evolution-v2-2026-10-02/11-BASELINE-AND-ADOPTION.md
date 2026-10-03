# Baseline and adoption guide — reconciled

## Baseline

```text
Rubentxu/agent-secretless
main = 39ae8fbafbee6a3114baa6f431ed56f928ca6984
2026-10-02
```

Roadmap authority remains `agent-secretless-vault-spec/docs/15-ROADMAP.md`.

## Truth that must not be overwritten

- M9: partially open **at this baseline**. It was closed in `v0.28.0` on
  2026-10-03 — the exit-UAT row went NOT MET → MET and UAT coverage 28/40 →
  29/40 — so the line below records the baseline as reviewed, not the
  repository today. What that closure does *not* claim is unchanged and
  still binds: no production listener for the CONNECT relay, one request per
  tunnel, and a destination-derived nonce that resists transfer without
  being freshness.
- M11: a framework/prototype is not a real OAuth/provider integration.
- M12: software TPM is not real hardware evidence.
- M13: RC/v1.0 gate.

## Adoption into the live roadmap

Do not append the old M14 distribution milestone.

Instead:

1. Fold product manifest, setup/doctor, `asv.agent/v1`, official skill and signed archive into **M13-DX**.
2. Keep M13 closure dependent on all existing M13/v1 release gates.
3. Append after v1:
   - M14 Credential Workflow Adapters;
   - M15 Authority Planning;
   - M16 Durable Automation;
   - M17 Attested Authority;
   - M18 v1.1 Stabilization.
4. Do not open all post-v1 milestones simultaneously.
5. Preserve previous packs under `docs/history/` as inputs, not authorities.

## First implementation slice

```text
M13-DX:
production manifest
+ dev-tool quarantine
+ setup/doctor --json
+ asv agent discover --json
+ external skill
```

No PipelineK, TDX, Keylime, PoP or tool-adapter breadth in this slice.

## Second slice

After v1 sequencing allows M14:

```text
adapter contract
+ secure parser substrate
+ npm
+ fingerprint/TOCTOU
+ posture truthfulness
```

## Provider/federation rule

M15 must consume mechanisms from M11. If a plan requires a provider capability that M11 has not delivered, the correct state is `Unsupported`/blocked, not a new implementation hidden in M15.

## PipelineK rule

Do not use PipelineK for broker-critical operations or simple atomic credential use.

Use PipelineK only after ASV exposes idempotent/reconcilable atomic lifecycle operations and a versioned automation contract.

## DoD

A milestone closes only when:
- required AAT/UAT evidence exists;
- falsification tests exist for new security claims;
- security posture is truthful;
- no agent-facing secret retrieval path was added;
- optional adapters remain optional;
- implementation evidence, not documents, supports the status.
