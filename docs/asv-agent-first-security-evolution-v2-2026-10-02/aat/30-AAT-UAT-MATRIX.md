# Agent Acceptance / UAT matrix — reconciled

## M13-DX — Distribution + agent discovery

| ID | Scenario | Expected |
|---|---|---|
| AAT-DX-001 | PATH after install | only public `asv`; broker outside PATH |
| AAT-DX-002 | production archive | no `asv-vault-tool`, harness/fuzz/fixture executables |
| AAT-DX-003 | new Cargo bin unclassified | release admission fails |
| AAT-DX-004 | fresh agent knows only `asv agent discover --json` | reaches setup/doctor/capabilities without prose scraping |
| AAT-DX-005 | unsupported agent protocol | fail-closed + upgrade/recovery relation |
| AAT-DX-006 | doctor output | no canary/token/private key/passphrase |
| AAT-DX-007 | skill stale operation | follows advertised relations; no hidden hardcoded workflow |

## M14 — Credential Workflow Adapters

| ID | Scenario | Expected |
|---|---|---|
| AAT-CW-010 | npm discover | registry/selector metadata only, never token |
| AAT-CW-011 | Maven XXE | no local/network entity resolution |
| AAT-CW-012 | Gradle projection cancellation | ephemeral projection cleaned |
| AAT-CW-013 | curl malicious config/include | rejected or explicitly degraded |
| AAT-CW-014 | config changes after plan | use invalidated |
| AAT-CW-015 | real token readable by target | posture is not `STRONG_SECRETLESS` |
| AAT-CW-016 | audience A credential used for B | denied |
| AAT-CW-017 | scrub before positive proof | refused |
| AAT-CW-018 | legacy/bypass path after migration | negative verification catches it |
| AAT-CW-019 | add new adapter | reuses M4/M10/M11 primitives; no duplicate provider/vault/executor |

## M15 — Authority Planning

| ID | Scenario | Expected |
|---|---|---|
| AAT-AP-020 | PATH hijack | tool identity drift invalidates plan |
| AAT-AP-021 | destination mutation | plan invalidated |
| AAT-AP-022 | config mutation | plan invalidated |
| AAT-AP-023 | expired plan | execution denied |
| AAT-AP-024 | approval digest A used for B | denied |
| AAT-AP-025 | human principal + agent actor | both recorded |
| AAT-AP-026 | delegated capability widened | denied |
| AAT-AP-027 | M11 stronger mechanism available | weaker static-secret strategy not selected without policy reason |
| AAT-AP-028 | PoP token copied without key | unusable where provider supports PoP |
| AAT-AP-029 | unknown semantic operation | fail-closed |
| AAT-AP-030 | M15 tries to implement second OAuth/STS framework | architecture gate fails |

## M16 — Durable Automation / PipelineK

| ID | Scenario | Expected |
|---|---|---|
| AAT-AU-030 | PipelineK absent | basic ASV broker/run operations still work |
| AAT-AU-031 | `asv-brokerd` dependency scan | no PipelineK dependency |
| AAT-AU-032 | multi-step rotation replay | candidate is not duplicated |
| AAT-AU-033 | crash during switch | reconcile observed binding before continue |
| AAT-AU-034 | crash around revoke | no false success |
| AAT-AU-035 | failed live validation | rollback/reconcile according to provider capability |
| AAT-AU-036 | rotation close | old credential unusable or explicit unverifiable human decision |
| AAT-AU-037 | workflow persistence | only refs/digests, never credential bytes/transient leases |
| AAT-AU-038 | dynamic plan unsupported by PipelineK | bounded template or wait for generic feature; no private engine |
| AAT-AU-039 | cross-ledger refs | ASV and PipelineK correlate same operation without duplicate security ledger |
| AAT-AU-040 | workflow files/state | no project-repo litter |

## M17 — Attested Authority

| ID | Scenario | Expected |
|---|---|---|
| AAT-AT-050 | unsupported host | `Unsupported`, never `Trusted` |
| AAT-AT-051 | stale evidence | denied when freshness required |
| AAT-AT-052 | measurement mismatch | untrusted |
| AAT-AT-053 | M12 TPM evidence consumed | hardware witness referenced without replacing M12 sealing |
| AAT-AT-054 | verifier unavailable | no silent fallback when policy requires attestation |
| AAT-AT-055 | protected executable changed | trust evidence invalid |
| AAT-AT-056 | posture ingestion | SELinux/fapolicyd/OpenSCAP evidence consumed without duplicate hardening engine |
| AAT-AT-057 | signed receipt tampered | verification fails |
| AAT-AT-058 | OTLP export | canary absent |
| AAT-AT-059 | confidential worker ships | documented TEE threat model proven |
| AAT-AT-060 | no TEE | no confidential posture label |

## M18 — v1.1 stabilization

| ID | Scenario | Expected |
|---|---|---|
| AAT-ST-070 | upgrade/rollback | schema/protocol migration reversible per policy |
| AAT-ST-071 | updater rollback/freeze attempt | rejected by chosen anti-rollback design |
| AAT-ST-072 | provenance verification | unknown/untrusted parameters fail closed where provenance is enforced |
| AAT-ST-073 | stress rotation/adoption | no orphan authority/material |
| AAT-ST-074 | skill regression | agent routes to advertised capabilities only |
| AAT-ST-075 | full matrix | all mandatory prior AAT/UAT evidence current and traceable |
