# Work Units — reconciled sequence

## M13-DX — agent-first release operability

### WU-DX-01 — Production component manifest
- enumerate Cargo binaries;
- classify public/private/dev/optional;
- release fails on unclassified executable.

### WU-DX-02 — Dev-tool quarantine
- `asv-vault-tool` feature-gated;
- production artifact denylist;
- archive falsification test.

### WU-DX-03 — Setup + doctor
- idempotent `asv setup`;
- `asv doctor --json`;
- binary/broker/protocol/path/install-provenance checks.

### WU-DX-04 — `asv.agent/v1`
- `asv agent discover --json`;
- typed rel vocabulary;
- error recovery links;
- protocol negotiation;
- explicitly no stateful `agent next` workflow engine.

### WU-DX-05 — Official external skill
- `Rubentxu/agent-skill/skills/agent-secretless`;
- progressive disclosure;
- evals;
- no duplicated runtime/policy/workflow logic.

### WU-DX-06 — Signed production archive
- manifest-driven content;
- checksums/signature/SBOM;
- clean-HOME install UAT.

---

## M14 — Credential Workflow Adapters

### WU-CW-01 — Adapter contract
Typed `discover -> plan -> adopt -> project -> verify -> scrub`.

### WU-CW-02 — Secure parser substrate
- ownership/mode/symlink checks;
- fingerprint/TOCTOU;
- XML DTD/XXE disabled;
- include policy;
- no secret output.

### WU-CW-03 — npm reference adapter

### WU-CW-04 — Maven reference adapter

### WU-CW-05 — Gradle reference adapter

### WU-CW-06 — curl reference adapter

### WU-CW-07 — Safe scrub + negative verification
Scrub only after ASV-backed positive test and explicit bypass/negative test.

**Reuse law:** M14 consumes M4 broker/surrogates, M10 isolated compatibility and M11 provider mechanisms. It does not recreate them.

---

## M15 — Authority Planning & Plan-Bound Execution

### WU-AP-01 — `ActionIntent`
Principal, actor, workload, operation, resource, destination.

### WU-AP-02 — Tool identity
Realpath/digest/owner/provenance evidence where policy requires it.

### WU-AP-03 — Plan digest + expiry
Bind operation/resource/tool/config/destination and reject drift.

### WU-AP-04 — Strategy selection
Rank already-available ASV mechanisms:
federation/dynamic > PoP > signer/proxy/surrogate > ephemeral projection > isolated exposure.

### WU-AP-05 — Principal/actor/workload audit

### WU-AP-06 — Plan-bound approval

### WU-AP-07 — M11 integration proof
Consume one real provider mechanism delivered by M11. No new OAuth/STS/mTLS framework in M15.

### WU-AP-08 — PoP proof
Only if a real M11/provider adapter supports sender-constrained credentials.

---

## M16 — Durable Automation Port

### WU-AU-01 — `AutomationPort`
ASV control plane/CLI only; broker stays independent.

### WU-AU-02 — Atomic lifecycle operation algebra
Refs only; idempotent/reconcilable:
plan, issue, validate, switch, drain, revoke, verify, receipt.

### WU-AU-03 — Logical binding + staged candidate
Stable consumer reference; candidate staged before cutover.

### WU-AU-04 — PipelineK adapter
Optional adapter from `AutomationPort`, never broker dependency.

### WU-AU-05 — Rotation template
First bounded certified workflow.

### WU-AU-06 — Adoption/migration template
Only after M14 adapters are stable.

### WU-AU-07 — Incident remediation template
Immediate deny/freeze remains ASV; long remediation is delegated.

### WU-AU-08 — Cross-ledger correlation
ASV receipt + PipelineK run/step refs/digests, no duplicated secret/security state.

---

## M17 — Attested Authority

### WU-AT-01 — Generic `AttestationPort`

### WU-AT-02 — Consume M12 real TPM evidence
No replacement TPM vault implementation.

### WU-AT-03 — Keylime/Trustee spike

### WU-AT-04 — Cedar attestation binding
fresh/trusted/stale/unsupported as policy input.

### WU-AT-05 — Signed authorization receipts

### WU-AT-06 — Secret-safe OTLP projection

### WU-AT-07 — Optional SELinux/fapolicyd/OpenSCAP posture ingestion
Consume host evidence; do not create a second hardening framework.

### WU-AT-08 — Confidential worker GO/NO-GO
TDX/SNP only for a concrete remote/shared threat model.

---

## M18 — v1.1 stabilization

### WU-ST-01 — Full AAT/UAT aggregation
### WU-ST-02 — Migration/rollback
### WU-ST-03 — Update anti-rollback/TUF-compatible decision
### WU-ST-04 — Provenance/SLSA where evidence is real
### WU-ST-05 — Rotation/adoption stress
### WU-ST-06 — Audit/receipt correlation
### WU-ST-07 — Skill eval regression
### WU-ST-08 — External security review preparation

No new broad integration families in M18.

## Verification discipline

Focused tests during implementation; full suite at integration/release.

Every WU requires:
- positive acceptance evidence;
- negative/falsification evidence;
- no secret leakage;
- truthful posture;
- atomic Conventional Commit(s);
- roadmap update only after observed evidence.
