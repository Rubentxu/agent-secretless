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
| R11 dependency audit | pass with warning | `cargo audit`: 0 advisories, 338 deps, 1 yanked warning (`yoke-derive` 0.8.3, transitive via `url`→`idna`→`icu`). Recorded as a finding; clearing it means a transitive bump. |
| R11 full suite | pass | 706 tests enumerated, 706 passed / 0 ignored / 0 failed. The 1 added by the H1 second half is `an_admitted_peer_still_cannot_submit_an_approval_on_the_agent_socket` in `crates/broker/src/lib.rs`; see the H1 row for why the pre-existing self-approval test could not see the defect. The 6 added by the H2 fix are in `crates/broker/tests/h2_issuance_policy_gate.rs`; the seventh change is `h2_github_policy_bypass.rs` moving from an `#[ignore]`d failing test to a passing one, so the enumerated total rises by 6 and the ignored count falls from 1 to 0. The 5 added to make the matrix cross-implementation are the 4 in `crates/broker/tests/connect_serve.rs` and 1 in `crates/tls-acceptor/tests/openssl_client.rs`; together they measure the surface the bridge actually negotiates and publish it at `docs/tls-compatibility-matrix.md`: a client offering `h2` and `http/1.1` through ALPN gets **no** protocol selected, a TLS-1.3-only client negotiates 1.3, a TLS-1.2-only client still completes, a real `openssl s_client` negotiates `TLSv1.3 / TLS_AES_256_GCM_SHA384` while offering `h2,http/1.1`, and a negative control proves the same observation can see a selection when a server does offer one. Each cell was falsified against mutated code — M1 offered ALPN and the ALPN test went red naming `h2`; M2 and M3 pinned the server to a single TLS version and each version test went red; M4 inverted the version branch and the coherence assertion went red. The 5 added for UAT-010 (`crates/broker/tests/credential_ingest_boundary.rs` and `crates/broker/tests/uat_005_replay.rs`) cover the secret being in neither argv nor `/proc/<pid>/environ` of the live CLI while it holds it, the plant's own output, the **success** path rendering no secret in the response or the broker state, and the credentialed operation being audited with its chain verifying and its event serialized clean. The 4 added by the M9 CONNECT path (`crates/broker/tests/connect_serve.rs`) cover an unauthorised target opening no upstream socket, a leaf minted for another host being refused, a session leaf completing a handshake with bytes reaching the origin in both directions, and UAT-011 — a client pinning the upstream certificate refused at the handshake.  The 4 added by ADR-0018's credential-kind label cover a record written before the label existed still opening, a reader without the field still parsing a record that has it — the property that rejected widening the vault enum, because an unknown variant fails the whole body — a label beside its storage class reporting the label, and all nine domain kinds surviving a write and a reopen; the 2 before them rewrite ADR-0016's refusal into the round trip it was protecting. `gate-status` re-derives this count from the repository on every run, so the row cannot outlive the suite — it caught the 659→664 drift in that very change, and then twice more in the M5 series — 693→697 when the capability wire-name tests landed, and 697→698 when the M5 end-to-end test did. Both times the change that made the row stale was a change this same work added, which is the case a hand-maintained number never survives introduced by the four capability wire-name tests — which is the second time it has done its job, and the first time it caught a change made in the same commit series that added the tests. |
| R11 clippy `-D warnings` | pass | clean across `--workspace --all-targets --locked` |
| R11 formatting | pass | `cargo fmt --all -- --check` clean |
| R11 README test count | pass | both READMEs state 706 tests, re-derived by `cargo test --workspace --locked -- --list`. The count lived in the READMEs for several milestones with nothing checking it, and had drifted to 424 while the real number was 669 — a claim in a document that no gate contradicted. This row closes that class: a stale count in `README.md` or `README-es.md` now fails the build |
| R12 console front-end | pass | `apps/desktop/ui/` references no remote origin, and the CSP in `apps/desktop/tauri.conf.json` denies `unsafe-inline`, `unsafe-eval`, `object-src`, and remote origins, with the asset protocol disabled. UAT-019's first two clauses — a hostile label is rendered as data and no script executes — are enforced by a CSP that is *written*, not by a CDN that happens to be unreachable today. `check-gate-status` reads the files rather than launching a WebView, so the row is checkable in a pipeline with no display; what it does not cover is the last two clauses of UAT-019, which need the real WebView and are covered by `crates`-side tests in the M5 cycle |
| R11 `NFR-PERF-001` | pass | UAT-030, 6 ms budget, both profiles, host recorded |
| M5 operator console | **pass** — 2 of 3 exits machine-asserted, 1 host-dependent | all three exit criteria are implemented and none is claimed on faith. **E2E** add→grant→use→revoke runs against a real broker process, a real vault file and a real control-plane enrolment (`crates/broker/tests/m5_console_e2e.rs`); its revoke assertion is shaped as *not* `Upstream`, because that is what the broker answers when it accepted the token and reached for the provider, and the target repo is deliberately unresolvable so the two states cannot be confused. **UAT-019** and **UAT-020** are checked against a real WebKit engine by `apps/desktop/tests/uat019_probe.c`, which drives the *shipped* `ui/index.html` and `ui/app.js`; Tauri's `test` feature is rejected for this because its mocked runtime never loads a WebView and would prove nothing about script execution. The probe carries three guards — a control that must execute, a vacuity check that the front-end actually rendered, and an origin check — and each exists because the run without it lied. **Not machine-asserted in the pipeline:** the probe needs a display and webkit2gtk-devel, neither of which the CI container has, so it is run on the release host and its result is transcribed here. The rest of M5 *is* machine-asserted: R12 and the `asv-desktop` policy surface (8 tests, no GUI toolchain). |
| H2 GitHub policy bypass | **MET** — both layers closed, each falsified | `ReadIssue`, `CreateIssue` and `CreateRelease` never consulted the policy engine: `ReadIssue` did exactly three things — `authorize_github`, `validate_repo`, `surrogates.redeem` — and `authorize_github` checked two conditions (peer owns the session, a vault is open), while `PostgresQuery` called `authorize_postgres_statement` per statement. A `DatabaseCredential` surrogate was spent on `ReadIssue` and the broker dialled `api.github.com`. **Layer 1 (code never evaluates) is closed at issuance.** `MintSurrogate` now performs exactly one `policy.authorize` call for the family the credential belongs to, so an operator who tightens `POLICY_TEXT` now observes a real refusal where before the tightening was inert on this path. Minting is the enforcement point because a surrogate *is* a capability, and it is the only affordable one: `uat_030_perf` times 100 `ReadIssue` calls, so a per-operation evaluation would land inside the measured loop. **Layer 2 (class confusion) is closed at redemption.** `SurrogateRecord` carries the credential's `CredentialClass` and `redeem_for` asks which `OperationFamily` it is being spent on, so a database-class token cannot back a GitHub call — the `audience-bound` property ADR-0011 already promised and that no path checked. Both halves are **falsified**: making `CredentialClass::backs` return `true` unconditionally turns `h2_github_policy_bypass` red with the original symptom (`request to api.github.com failed`), and deleting the `authorize_surrogate_mint` call turns three tests in `h2_issuance_policy_gate` red, including one that observes a minted token under a `forbid`-everything policy. The first version of the bypass test asserted only `code != Upstream` inside an `if let Response::Error`, so it would also have passed on a *successful* GitHub read; it is rewritten to assert the exact code and the class reason. **What this row does not claim:** a session holding a `Generic`-class GitHub credential can still perform GitHub operations under the *default* policy, because the default policy permits the trio unconditionally on `resource is Api`. That is a default posture, not a code defect, and narrowing it is a policy change with a broad blast radius that belongs in its own cycle. **Correction to the previous revision of this row:** it stated the rejected direct fix "broke `NFR-PERF-001` (p95 6564us against the 6000us budget, measured with `git stash`, not assumed)". That number does not reproduce. The baseline is p50 1269-1403us / p95 1525-1846us over five runs on this host, so the budget had roughly 3.2x headroom, not the ~5% the earlier figure implied. The direct fix was still not the right shape — a per-operation Cedar evaluation on a path that `uat_030_perf` times 100 times buys nothing a mint-time decision does not buy better — but it was rejected for a reason that was **not** measured, and the earlier record is corrected here rather than quietly dropped. |
| H1 approval has no path to the policy engine | **NOT MET** — blocked on a control-plane transport, not on missing engine code | `SubmitApproval` (`crates/broker/src/lib.rs:761`) evaluates `admission::admit_control_plane(peer, &state.control_plane, &admission::ProcFs)` and then refuses either way: on a `Denial` it reports which of the three ADR-0015 conditions failed, and on `Ok(())` it reports *"admission granted, but approvals have no path to the policy engine yet"*. The `Ok(())` arm is the finding — the caller satisfied every admission condition and the broker still said no, so this is a missing implementation rather than a closed door. `AuditQuery` (`:890`) has the same shape. **The policy engine's approval machinery is already complete and tested**, which is why this is not a "wire it up" item: `issue_approval` (`crates/policy/src/lib.rs:521`) mints one, `authorize` validates a presented approval against session, action, resource and `request_digest` (`:613-655`), expiry and use budget are enforced, the use is decremented only on the allow path, and `denial_paths_do_not_decrement_approval_uses` (`:1094`) proves a denial does not burn a use. Two *other* control-plane verbs are wired and do work — the credential-ingest paths at `lib.rs:550` and `lib.rs:662` both run the same predicate and then proceed. **Why it is not a one-line fix:** all four verbs are reached over the *same* Unix socket as the agent IPC. Wiring `SubmitApproval` there would let an agent mint the very approval it is being asked to earn, which is the self-approval hole the code comment at `:762` exists to refuse. Closing H1 therefore requires a transport that is not the agent socket, which is a larger M4 deliverable than the P1 label suggests. Recorded here so the gate table stops reading as clean over an unnamed P1, which is how H2 stayed invisible for a release. **The refusal is fail-closed but was not pinned, and the pre-existing test could not have caught the hole.** `agent_cannot_submit_its_own_approval` uses `BrokerState::default()`, whose enrolment record is empty, so `admit_control_plane` always answers `Err(NotEnrolled)` and the handler never reaches its `Ok(())` arm — the arm where admission *succeeds* and the broker still refuses, which is the whole of H1's current safety. Falsified by changing that arm to mint (`Response::ApprovalIssued`): the old test **stayed green** while a new test, `an_admitted_peer_still_cannot_submit_an_approval_on_the_agent_socket`, went red reporting `ApprovalIssued { action: GitPush, .. }`. The new test enrols this binary honestly via `enrolment_of_this_binary()`, asserts `admit_control_plane` actually returns `Ok(())` first so it cannot pass for the unenrolled reason, and asserts on the *message* (`no path to the policy engine`) rather than the code, because both arms answer `Denied` |
| M12 hardware-backed vault | **NOT MET** — host-dependent, not machine-asserted | no TPM on this host (`/dev/tpm*` absent, `/sys/class/tpm` empty, no TPM CPU flag). UAT-034 exercises the structural shape against `SoftwareTpm`, a content-addressed placeholder. No hardware-backed guarantee is claimed. |
| M11 live OAuth2 provider | **NOT MET** — external dependency, not machine-asserted | `crates/broker/src/oauth2.rs` defines the trait and one prototype implementation, `ClientCredentialsIssuer`, whose `issue()` synthesises a token instead of performing an HTTPS POST to the token endpoint. No AS interaction, no PKCE anywhere in `crates/`. The module carries 10 `#[test]` functions and `oauth2_surrogate_lifecycle.rs` is M11's acceptance test; `15-ROADMAP.md` gates M11 with no fixed UAT set, so that suite is deliberately not numbered against a spec UAT. Nothing in the runtime calls the module yet. |
| M11-M13 semver | **NOT MET** | `m11-oauth2-framework`, `m12-tpm-vault` and `m13-rc-stabilization` are all ancestors of `v0.11.0` (`9bd86dd`): the milestone work shipped by riding inside that release, never by being deliberately versioned. No cycle receipt and no version of their own stands behind them, which is why the roadmap's assertion of milestone completion has nothing to point at. `gate-status` verifies the ancestry so this row cannot drift into claiming the opposite. |
| R10 compatibility truthfulness | partial | the `ISOLATED_PROCESS_EXPOSURE` posture label exists; the per-integration catalog required by M11 has no live provider to populate yet. |
| M9 exit-UAT trace | **NOT MET** — UAT-011 implemented; UAT-010 covered on the broker's semantic path but not on CONNECT; UAT-012, 013 still unsupported | `15-ROADMAP.md` gates M9 on UAT-010, 011, 012 and 013. As of v0.22.0: **UAT-011 (TLS pinning)** has a suite at `crates/broker/tests/connect_serve.rs::a_pinning_client_is_refused_and_the_bridge_does_not_patch_it` — a client pinning the upstream certificate is refused, and the bridge fails *at the handshake* rather than patching the client. The traffic path it needed now exists: `Bridge::serve_connect` authorises, terminates TLS with a per-session leaf and dials the upstream, where `handle_connect` previously authorised and returned. **UAT-010** names surrogate substitution reaching the provider with the secret visible to nothing the client can observe, and is covered at `crates/broker/tests/uat_005_replay.rs` (origin receives the real credential and never the surrogate; the success path renders no secret; the credentialed operation is audited and its chain verifies) and `crates/broker/tests/credential_ingest_boundary.rs` (the plant's own output, and `/proc/<pid>/cmdline` and `/proc/<pid>/environ` of the live CLI while it holds the secret). What that does **not** cover is the CONNECT path: `Bridge::handle_connect` authorises a destination host and holds no session, and a surrogate redeems only through its minting session, so an ordinary CLI has no surrogate to redeem. `FND-m9-connect-substitution` carries the options, including the one that would give up the `WrongSession` refusal. **UAT-012 and UAT-013** remain blocked by ADR-0007, which gates eBPF redirection on M8 GO. The second exit criterion, the **TLS compatibility matrix published from tests**, is met as of 2026-10-01 at `docs/tls-compatibility-matrix.md`: 17 rows, each citing its witness, with cipher suites, key-exchange groups, signature algorithms, resumption and renegotiation published as untested rather than omitted, and three recorded falsifications (M1 offered ALPN and the ALPN test went red naming `h2`; M2/M3 pinned the server to one TLS version and each version test went red). M9 stays open. |

M12 and M11 cannot be closed by writing code on this machine: M12 needs a
host with a TPM, and M11 needs a real provider to point the framework at.
Recording them as open is the correct outcome, not a blocker to route around.
That is also why the guard does not assert them — a script that asserted them
would be asserting an author's intent rather than a fact.
