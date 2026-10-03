# Capability ownership and no-overlap law

## Principle

A feature is duplicated when two components can independently answer the same semantic question.

The system must instead separate **decision authority** from **execution authority**.

| Concern | Semantic owner | Consumer | Must not own it |
|---|---|---|---|
| Secret storage/crypto | ASV | broker/connectors | PipelineK |
| Credential/provider selection | ASV | `pipelinek-asv` consumes `PreparedUse` | PipelineK |
| Federation/OAuth/STS/mTLS/signers | ASV M11 | authority planner | PipelineK |
| Cedar credential authorization | ASV | plugin gets verdict/ref | PipelineK |
| Human approval for authority | ASV | PipelineK may wait/resume | PipelineK policy |
| Security posture | ASV | PipelineK records/displays | PipelineK planner |
| `.npmrc`, Maven, Gradle, curl semantics | ASV M14 | generic projection consumer | PipelineK adapters |
| Shell execution | PipelineK `core.sh` | ASV scope surrounds body | ASV second shell engine |
| Durable Step identity/journal/replay | PipelineK | ASV may bind a plan to identity | ASV workflow journal |
| Workflow retries/recovery/cancel | PipelineK | ASV operations are idempotent/reconcilable | ASV mini engine |
| Rotation domain semantics | ASV | PipelineK executes phases | PipelineK provider logic |
| Immediate compromise freeze/revoke | ASV | automation may be triggered afterwards | PipelineK |
| Long remediation workflow | PipelineK or another AutomationPort adapter | ASV initiates | ASV broker |
| TPM vault sealing | ASV M12 | attestation consumes evidence | PipelineK |
| Landlock/seccomp/cgroup hardening | ASV M7 | posture/attestation consumes evidence | M17 duplicate framework |
| Keylime/Trustee verdict | ASV M17 via `AttestationPort` | Cedar/planner | PipelineK |
| Pipeline execution evidence | PipelineK | ASV stores correlation/ref | duplicate ASV pipeline journal |
| Security authorization receipt | ASV | PipelineK stores digest/ref | duplicate PipelineK security ledger |
| Credential/security HATEOAS | ASV CLI | skills | PipelineK |
| Step/pipeline introspection | PipelineK | skills may consult | ASV |

## Composition laws

```text
EffectiveAuthority = ASV authorization

EffectiveEgress =
    PipelineK runtime allowlist
    ∩ ASV credential audience

EffectiveExecution =
    PipelineK durable execution
    under ASV PreparedUse
```

A weaker decision from one product may never widen a stronger restriction from the other.

## Consequences

- Adding Cargo/pip/NuGet support in ASV must not require new PipelineK StepKeys.
- PipelineK must never parse `.npmrc` or `settings.xml` for ASV.
- ASV must never recreate retry/replay/journal/wait/resume for complex lifecycle workflows.
- `pipelinek-asv` must remain an adapter: no Cedar, no vault, no provider selection, no secret material.
- Skills must route to the owner; they must not reproduce state machines in Markdown.
