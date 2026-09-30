# Security and Release Gates

## R0 — Build and provenance

- reproducible/traceable build process documented,
- dependency lockfiles committed,
- SBOM generated for release artifacts,
- release artifacts signed where supported,
- no debug/development feature that enables secret dumping in production build.

## R1 — Secret API invariant

Static/API review confirms no agent-accessible path equivalent to:

```text
get_secret
export_secret
show_token
read_vault_record
```

Human-only reveal path, if enabled, is separate and cannot be invoked through agent session/MCP permissions.

## R2 — Vault

- authenticated encryption tests,
- wrong-key/tamper failure,
- migration tests,
- backup/restore,
- locked startup,
- zeroization tests where observable,
- broker core dumps disabled.

## R3 — Identity/session

- peer credentials from OS,
- PID reuse mitigated with pidfd/launch record,
- capability bound to session,
- replay from sibling/outside session denied,
- revoke works.

## R4 — Policy

- deny by default,
- Cedar schema validates policies,
- high-risk defaults documented,
- approval replay blocked,
- malformed/missing context fails closed.

## R5 — Connector security

For each connector:

- audience binding,
- canonical parsing,
- redirect policy,
- negative authorization tests,
- no secret in agent process for integrations labelled `STRONG_SECRETLESS`,
- documented limitations.

## R6 — Agent leak harness

Full adversarial suite passes:

- env/proc,
- shell tracing,
- argv,
- filesystem search,
- ptrace/process VM in hardened profile,
- unauthorized network sink,
- malicious redirects,
- crash/log scanning.

## R7 — eBPF/privilege separation

If eBPF feature ships:

- privileged helper has no secret API/storage access,
- only shipped/signed BPF object set can load,
- cgroup escape UAT passes,
- map cleanup tests pass under stress,
- disable/unavailable path is safe and visible,
- direct user-memory secret patching is absent.

## R8 — Tauri

- no remote scripts/assets,
- strict CSP,
- minimal capabilities,
- XSS metadata test,
- frontend cannot request stored secret values,
- approval window permissions isolated,
- security-sensitive plugin permissions reviewed.

## R9 — Audit

- canary secrets absent from persisted logs,
- audit tamper-evidence chain validates,
- security posture recorded per operation,
- retention configurable.

## R10 — Compatibility truthfulness

Every supported integration has one of the defined posture labels. No documentation or UI implies `EXEC_ISOLATED`/raw env is equivalent to secretless proxy/signing.

## R11 — Full certification

Before final release:

- all required UAT green, where "required" is the UAT owned by each milestone
  exit in `15-ROADMAP.md` as enforced by `tools/check-gates.py`,
- fuzz regression corpus green,
- full supported-kernel matrix green,
- dependency vulnerabilities triaged,
- known security limitations published,
- no open severity-critical/high issue that violates core secretless invariants,
- `NFR-PERF-001` measured and within budget: p95 local authorization under
  5 ms, or 6 ms for the end-to-end brokered read in either build profile,
  evidenced by UAT-030 with the measured host recorded. A performance claim
  without a recorded host and percentile is not a pass.

## Gate status as of 2026-09-30

`15-ROADMAP.md` delegates M11 and M13 completion to this document rather
than to a fixed UAT set. That delegation is only meaningful if the current
state is stated, so it is stated here. Source: `docs/exploration/m11-m13-convergence.md`.

| Gate | Status | Evidence |
|---|---|---|
| R11 dependency audit | pass | `cargo audit`: 0 advisories, 335 deps |
| R11 full suite | pass | 486 passed / 0 failed / 1 ignored |
| R11 clippy `-D warnings` | pass | clean |
| R11 formatting | pass | `cargo fmt --all -- --check` clean |
| R11 `NFR-PERF-001` | pass | UAT-030, 6 ms budget, both profiles, host recorded |
| M12 hardware-backed vault | **NOT MET** | no TPM on this host (`/dev/tpm*` absent, `/sys/class/tpm` empty, no TPM CPU flag). UAT-034 exercises the structural shape against `SoftwareTpm`, a content-addressed placeholder. No hardware-backed guarantee is claimed. |
| M11 live OAuth2 provider | **NOT MET** | `StaticClientCredentialsIssuer` only; no AS interaction, no PKCE. The framework and its 6 tests are real. |
| M11-M13 semver | **NOT MET** | tagged `m11-*`/`m12-*`/`m13-*` with no cycle receipt and no version. `v0.11.0` stays on `9bd86dd` and must not be moved to cover them. |
| R10 compatibility truthfulness | partial | the `ISOLATED_PROCESS_EXPOSURE` posture label exists; the per-integration catalog required by M11 has no live provider to populate yet. |

Two of these cannot be closed by writing code on this machine: M12 needs a
host with a TPM, and M11 needs a real provider to point the framework at.
Recording them as open is the correct outcome, not a blocker to route around.
