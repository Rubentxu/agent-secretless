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

- all required UAT green,
- fuzz regression corpus green,
- full supported-kernel matrix green,
- dependency vulnerabilities triaged,
- known security limitations published,
- no open severity-critical/high issue that violates core secretless invariants.
