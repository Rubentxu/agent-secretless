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

## Gate status as of 2026-10-01

`15-ROADMAP.md` delegates M11 and M13 completion to this document rather
than to a fixed UAT set. That delegation is only meaningful if the current
state is stated, so it is stated here.

Every claim in the table below that the repository can decide is verified by
`scripts/check-gate-status.py`, which runs as the `gate-status` stage of
`pipeline.kts` and fails the build when a row stops matching reality. The
previous table, written 2026-09-30, had drifted in three rows within eleven
days; a status table with nothing checking it is a comment. Claims that depend
on the host or on an external service are marked below and are deliberately
not machine-asserted, because nothing in this repository can decide them.

A UAT id cited by a gate must also mean one thing. `tools/check-gates.py`
verifies that no two test files declare the same id and that no file declares
an id this document's UAT spec does not define, because a gate reading
"UAT-030 passed" cannot act on an id two suites claim. It also checks that a
header which attributes a quotation to the spec pack is quoting something
that is actually in it: five such quotations were fabricated, each one letting
a suite present a requirement the spec never stated as though it were
normative. That check is a hard defect, scored on the longest unbroken run of
words the quotation shares with the pack, because a plausible sentence about
vaults still draws most of its individual words from a pack that discusses
nothing else. A claim whose title shares no content word with the spec's title
for that id is reported as a warning, not a defect: only the spec author can
say which side of a misattribution is wrong, and the test is real either way.
`14-UAT-ADVERSARIAL.md` defines UAT-001 through UAT-034; ids above that range
are not reserved, and a repository file named for one carries a filename claim
its header does not back. `check-gates.py` reports those as warnings rather
than defects, so the gap stays visible without inventing a spec entry the spec
authors have not written.

| Gate | Status | Evidence |
|---|---|---|
| R11 dependency audit | pass with warning | `cargo audit`: 0 advisories, 337 deps, 1 yanked warning (`yoke-derive` 0.8.3, transitive via `url`→`idna`→`icu`). Recorded as a finding; clearing it means a transitive bump. |
| R11 full suite | pass | 608 tests enumerated, 607 passed / 0 failed / 1 ignored, at `v0.17.10`. The 11 added by ADR-0015's admission rule are hostile cases for the three control-plane conditions; `gate-status` refuses the run if this row and the repository disagree. |
| R11 clippy `-D warnings` | pass | clean across `--workspace --all-targets --locked` |
| R11 formatting | pass | `cargo fmt --all -- --check` clean |
| R11 `NFR-PERF-001` | pass | UAT-030, 6 ms budget, both profiles, host recorded |
| M12 hardware-backed vault | **NOT MET** — host-dependent, not machine-asserted | no TPM on this host (`/dev/tpm*` absent, `/sys/class/tpm` empty, no TPM CPU flag). UAT-034 exercises the structural shape against `SoftwareTpm`, a content-addressed placeholder. No hardware-backed guarantee is claimed. |
| M11 live OAuth2 provider | **NOT MET** — external dependency, not machine-asserted | `crates/broker/src/oauth2.rs` defines the trait and one prototype implementation, `ClientCredentialsIssuer`, whose `issue()` synthesises a token instead of performing an HTTPS POST to the token endpoint. No AS interaction, no PKCE anywhere in `crates/`. The module carries 10 `#[test]` functions and `oauth2_surrogate_lifecycle.rs` is M11's acceptance test; `15-ROADMAP.md` gates M11 with no fixed UAT set, so that suite is deliberately not numbered against a spec UAT. Nothing in the runtime calls the module yet. |
| M11-M13 semver | **NOT MET** | `m11-oauth2-framework`, `m12-tpm-vault` and `m13-rc-stabilization` are all ancestors of `v0.11.0` (`9bd86dd`): the milestone work shipped by riding inside that release, never by being deliberately versioned. No cycle receipt and no version of their own stands behind them, which is why the roadmap's assertion of milestone completion has nothing to point at. `gate-status` verifies the ancestry so this row cannot drift into claiming the opposite. |
| R10 compatibility truthfulness | partial | the `ISOLATED_PROCESS_EXPOSURE` posture label exists; the per-integration catalog required by M11 has no live provider to populate yet. |
| M9 exit-UAT trace | **NOT MET** — spec adjudication required | `15-ROADMAP.md` gates M9 on UAT-010, 011, 012 and 013. The spec titles those "HTTP surrogate bridge", "TLS pinning" and "transparent eBPF redirect", and no suite claims any of them: the three files named for those ids test the CONNECT allow-list, the redirect denier and the trust injection adapter, which are M9 *scope* items but not the UATs M9's exit is written against. UAT-013 has no suite at all. The work is implemented; the trace from exit gate to evidence is what is missing, and closing it means deciding whether the spec titles or the suite assignments are wrong — a spec change, not a code change. |

M12 and M11 cannot be closed by writing code on this machine: M12 needs a
host with a TPM, and M11 needs a real provider to point the framework at.
Recording them as open is the correct outcome, not a blocker to route around.
That is also why the guard does not assert them — a script that asserted them
would be asserting an author's intent rather than a fact.
