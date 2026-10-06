# ROADMAP — Planning Authority

This file is the single planning authority for the initial product line and for
its continuation. Specifications and ADRs define intent/decisions; this roadmap
defines sequence and exit criteria.

**Verifiable status does not live here.** This file says what is planned and in
what order. Whether something is actually true today is asserted in
`16-SECURITY-RELEASE-GATES.md`, which is checked against the repository by
`scripts/check-gate-status.py` and `tools/check-gates.py`. A milestone in this
file is not a claim about the world; a row in that file is.

## Critical path — rebaselined

**This file remains the single planning authority.** The blocks below fix the
*order*; the `## M…` sections further down remain the authority for each
milestone's scope and exit UATs, and they are not replaced by this section.
Anything this section contradicts is a sequencing claim and loses.

The decision, and why, is [ADR-0020](../adrs/0020-adoption-before-hardware-tpm2-leaves-the-v1-critical-path.md):
**v1.0 is optimized for daily secretless work and ease of adoption, not for the
completion percentage of historical milestones.**

```text
R0  Truthfulness + distribution + skill
 │
R1  M10 production reachability          isolated exec, reachable from a product surface
 │
R2  M11 providers worth having           Git/GitHub, OAuth2, STS, Kubernetes
 │
R3  M14 credential workflow adapters     npm, Maven, Gradle, curl
 │
R4  M15 plan-bound authority             ActionIntent, plan digest, receipts
 │
R5  M13 certification of the useful product
 │
 └────────────── v1.0 ──────────────────► tag
                  │
                  ▼
R6  M16 durable automation + PipelineK   durable orchestration authority
 │
R7  ecosystem expansion                   adapters and providers by real use
 │
R8  M12 TPM2 hardware, for real          deferred validation, not a prototype
 │
R9  M17 attestation / trusted execution  depends on real M12 evidence
 │
 └────────────── R10 M18 stabilization of the next line
```

| Block | What it is | Exit |
|---|---|---|
| **R0** | Make the current product installable and consumable with verified provenance, and give an agent an official way in. | Signature verification reachable from a clean install; negative provenance tests that fail rather than warn; the official skill published outside this repository and checked as FAIL when absent; this roadmap updated. |
| **R1** | One productive path from a public operation to the existing isolated worker. | A test that starts at the product surface: `public operation → IPC → broker → isolated process`, and no second executor, shell runtime or sandbox. |
| **R2** | Providers as complete verticals, not as trait count. | Per provider: a real provider, a real operation, a real secretless property, and negative adversarial tests — or it does not count. |
| **R3** | The adapter pipeline: `discover → safe parse → plan → adopt → binding → project → execute → verify → scrub → receipt`. | npm, Maven, Gradle and curl each with at least one real vertical, and a new adapter addable without touching broker or domain. |
| **R4** | Authority bound to an operation, not to a session. | `discover → ActionIntent → plan → authorize → execute → receipt` demonstrated on npm and on a second, different family. |
| **R5** | Certification of the useful product. Feature breadth freezes here. | The release matrix run clean, a distribution E2E from a machine with no source tree, and the full gate run with `PASS`/`FAIL`/`SKIPPED`/`UNAVAILABLE_SUBSTRATE` kept distinct — a requirement that cannot run is not a pass. |
| **R6** | PipelineK as durable orchestration authority; ASV as identity, credential and policy authority. | Removing `pipelinek-asv` leaves PipelineK core functionally equivalent, and removing PipelineK leaves ASV able to perform every atomic operation by hand. |
| **R7** | Ecosystem growth by use, not by catalogue. | Every new integration states which of `STRONG_SECRETLESS`, `SHORT_LIVED_EXPOSURE`, `RAW_PROCESS_EXPOSURE` it lands in. |
| **R8** | Real hardware-backed vault. | On a physical host: `enroll → seal → reboot → unlock`, and `change measured state → unlock → DENIED`, plus software↔device-bound migration. |
| **R9** | Attestation as a verdict the domain consumes, never a vendor API. | Attested secret release working end to end on real TPM evidence. |
| **R10** | Stabilize adapters + plan-bound authority + durable automation + optional hardware trust together. | The compatibility, migration, failure and partial-cutover matrix green, with a TPM-less install remaining a supported configuration. |

### Where the blocks stand

Recorded from measured results, not from intent. A block is listed here only
when its exit condition has been observed to hold; a block that was *attempted*
is not listed, and a block with a residual says so in its own row.

| Block | State | Measured by |
|---|---|---|
| **R0** | **not closed**, and both red gates name their own cause | `tests/r0_gate.py` — **2 passed, 2 failed, 0 unavailable**. R0.1 (roadmap authority) and R0.2 (installer provenance: signature verification reachable from a clean install, 46 negative provenance checks, each one shown refusable) both hold. **R0.3 is red** because the official skill, published outside this repository, has not caught up to the four registry relations R2.F published: the cross-repo contract now stands at **109 checks, 4 failed**, and the four failures are exactly those four relations the skill cannot find documented. **R0.4 is red** because the working tree carries another campaign's uncommitted work. This row previously read *closed, 4 passed, 0 failed, 105 checks*; all three numbers were written before the measurement they describe. |
| **R1** | closed, and the caveat that qualified it is gone | `r1_isolated_reachability` 11/11 and `r1_isolated_e2e` 6/6, both from the product surface, and `uat_040_isolated_worker_runtime` 15/15. This row previously carried a caveat that 21 tests returned early when their substrate was missing and Cargo reported that as **passed**. The figure was right and the file count was wrong — it is three files, not five, and the split is 18 plus 3. All 18 now **refuse** with `UNAVAILABLE_SUBSTRATE` and are falsified by `tests/falsification/r1_substrate_falsify.py`: 18 red, 14 green, 0 unmeasured. The remaining 3 are the PostgreSQL rows, which already had the better shape (`ASV_UAT033_REQUIRE=1`) and are left alone. See *The rows that reported passing without running*. |
| **R2.A** | closed, with one half `host-dependent` | `r2a_github_vertical` 11/11 in-process against a real TLS origin, and `r2a_cli_reachability` 4/4 against the real binaries. The live call against the real `api.github.com` is **not** measured and is not claimed; see *Status of item 1* below. |
| **R2.B** | surface delivered; scope-as-policy-resource still open | `oauth2_vertical` 10/10 over a real vault, a real issuer and a real resource call, `r2b_oauth2_revocation` 5/5 with four falsifications, and now `r2b2_oauth2_vertical` 25/25 through the broker's own `handle` — `asv oauth2 whoami` reaches the port. `ALLOWED_AUDIENCES` was **not** widened: `Resource::OAuth2Client` is a separate type, so admitting a generic IdP cannot reopen D6 for GitHub and AWS, and the schema refuses the dangerous rule at load rather than at evaluation. The answer is verified against the deployment, not relayed, and the issuer's own escalation check turns out to speak before the broker's. Falsified 15 mutations in five passes: 14 red, 1 documented survivor, 0 unmeasured. Still open: a live third-party IdP, scope as a policy resource, and the config-file-vs-policy intersection. See *Status of item 4*. |
| **R2.C** | one operation reachable from the product surface; item 2 still not closed | `aws::sigv4` 16/16 against the AWS documentation's own vectors, `aws::sts` 34/34 and `aws::calendar` 9/9 against an oracle written from the specifications, `aws::port` 12/12 with no socket in it, `aws::identity` 12/12 against two documented AWS samples, `r2c2b_sts_vertical` 18/18 against a real TLS origin, and `r2c3_aws_vertical` 13/13 from the product surface — CLI verb, typed IPC, real vault, real policy, real origin, and the advertisement an agent reads to find the verb at all. **113 mutations** across seven harnesses, and the number is the sum of the harness files rather than an inherited figure: 25 `sigv4`, 25 `sts`, 13 `client`, 14 `calendar`, 13 `port`, 14 `identity`, 9 `r2c3`. Of those, **110 red, 1 refused by the compiler, 2 recorded survivors** (the post-read size bound, unexercised because the fake origin always declares a `content-length`; and the binding's `Debug`, which cannot leak because `AwsSecretPort`'s own `Debug` does not). All seven are in the repository at `tests/falsification/` and every one was re-run from there, so the figure is re-derivable rather than merely asserted. **One operation is not a catalogue** — `s3:GetObject`, the regional STS endpoints and the live call are open, so item 2 is not closed under M11's rule. See *Status of item 2*. |
| **R2.D** | **internal only** — no product surface at all | `crates/broker/src/k8s/` is eleven files wired into the broker as `pub mod k8s`, carrying **95 inline rows** and five falsification harnesses (`k8s_request`, `k8s_client`, `k8s_binding`, `k8s_metadata`, `k8s_port`), all of whose snippets still match the source. What is missing is everything an agent can touch: **0 typed IPC requests, 0 CLI verbs, 0 published relations, 0 socket-level verticals.** The module comment says *"the request core first"*, which is an honest acknowledgement of a partial increment and not a claim of closure. M11's rule is provider + operation + secretless property + adversarial rows; this has three and lacks the operation. |
| **R2.E** | **internal only** — no product surface at all | `crates/broker/src/mtls/` is seven files wired as `pub mod mtls` inside `tls_bridge.rs`, carrying **36 inline rows** and one falsification harness of some length (`mtls_falsify.py`). Same absence: **0 typed IPC requests, 0 CLI verbs, 0 published relations, 0 socket-level verticals.** The negative tests are real; what has never been demonstrated is an agent asking for a certificate and a broker issuing one. |
| **R2.F** | surface delivered end-to-end; the registry side is **not** closed | `r2f_registry_vertical` **21/21** against a real socket — declaration, reachability, pull and push across both manifests and blobs — plus four `asv registry` verbs and four published relations (`asv://rels/registry/{manifest,blob}/{read,push}`), so an agent can *find* the capability rather than be told it exists. Pull and push share one `RegistryGrant`; each arm still writes its own `Action` at the call site, because a policy that permits pushing a blob has not by itself permitted publishing an index that names it. Re-derived from `tests/falsification/registry_client_falsify.py`, all red: building the manifest path with the two checked halves the wrong way round reds `the_manifest_path_is_built_from_the_two_checked_halves`; returning a blob without comparing it to the digest asked for, and believing the registry's own `Docker-Content-Digest` header instead of hashing the body, both red the check-on-the-wire rows. The second is the interesting one — the header is the registry's *claim*, so trusting it is a closed loop in which a registry that sends the wrong bytes and asserts the digest that was asked for agrees with itself. The realm and address-literal mutations had gone stale the same way and were **re-pointed at the current source** rather than left broken: `crates/connector-http/src/registry.rs` grew a private `vet_reaching` seam, so `resolve_and_pin(&authority, TOKEN_PORT, policy)` became `resolve_and_pin(&vetted.authority, port, policy)` and the port check moved from a named local to the parameter. All five now apply and all five go red — **37 of 37 mutations in `registry_client_falsify.py` falsify, 0 survivors, 0 compiler-refused, 0 unmeasured, 0 harness errors, exit 0**, and the 37 is the harness's own total rather than a number summed here: 6 + 3 + 8 for R2.F.2, 8 + 4 for R2.F.4, 5 + 3 for R2.F.5. Five claims about realm vetting and address literals had been unmeasured for as long as that seam existed, and the reason nobody noticed is that the harness was failing loudly and nobody was reading its exit code. **Still open:** push is monolithic rather than a `POST`→`PUT` session, so a registry answering with a `Location` the client has not vetted is a follow-up; and `put_blob` verifies the digest *before* opening the socket but cannot verify that the registry kept the bytes, because the registry does not return them. See *Status of item 7*. |

**The R1 row is the one worth reading twice.** `uat_040`'s file-injection row was
asserting that the staged secret reached the redacted channel in cleartext — a
test encoding a defect as its expectation — and it was green for exactly as long
as that was true. R1 fixed the leak, so the row went red, and the full-workspace
run that R2.A's exit gate required is what surfaced it. A block can be declared
closed with a red test inside it, and the way that happened here was a row that
never ran being indistinguishable from a row that passed. Fixed in `9d3d556`;
the structural half is backlog.

#### The rows that reported passing without running

That half is no longer backlog, and it was worse than the row above suggested.

**Eighteen rows across three files** — `r1_isolated_reachability.rs`,
`r1_isolated_e2e.rs` and `uat_040_isolated_worker_runtime.rs` — probed for
unprivileged user namespaces and, finding none, printed a line to stderr and
`return`ed. Cargo reports a `return` as **passed**. So on a host without that
kernel feature, eighteen evidence rows produced eighteen green ticks having
examined nothing, and nothing in the suite-size guard could see it: the guard
re-derives what is *enumerated*, and all eighteen were enumerated and passing.

The fix is a `require_userns(row)` that panics with `UNAVAILABLE_SUBSTRATE`
naming the row. The three states the full gate already distinguishes —
`PASS`, `FAIL`, `SKIPPED`, `UNAVAILABLE_SUBSTRATE` — are not reachable from a
`return`, because Cargo has no "skipped" state for an early return; the only
attribute that produces one is `#[ignore]`, and that is a compile-time decision
about a host nobody knows at compile time. **So a skip here can only be a
failure**, and the message says which of the two it is rather than leaving a
reader to guess from a red X.

**The PostgreSQL suites already had the better answer and were left alone.**
`uat033_broker.rs` and `uat033_live.rs` skip by default and turn a missing
substrate into a failure under `ASV_UAT033_REQUIRE=1`. That is right for a
substrate a developer may legitimately lack, and it is a deliberate design
rather than an oversight — so the honest record is that this repository now has
two conventions for the same problem, and why. The userns rows cannot use the
second one without reintroducing the phantom pass, because the default *is* the
lie.

Falsified by `tests/falsification/r1_substrate_falsify.py`, which makes the
probe answer "unavailable" the way a locked-down host would and asserts **18
red, 14 green, 0 unmeasured**. The second half is the point: a campaign that
only checked the guarded rows go red would also be satisfied by a guard that
panicked unconditionally, which would turn eighteen evidence rows into eighteen
refusals. The mutation has to be the *availability*, not the guard.

Two harness defects are recorded because both produced output that looked fine.
The first version passed `--test <target>` as a single argv element, so cargo
matched no test for all thirty-two rows and the campaign reported `no-run` across
the board — the four-bucket accounting is what made that visible rather than a
result. And one row name was written from memory rather than read out of the
file, which produced one `no-run` in a run where the other thirty-one were
correct. Both are the same lesson as `9d3d556`, one level down: a harness that
cannot say "I measured nothing" will eventually say "green".

### What moved, and what stayed

- **TPM2 is not a v1.0 gate.** M12 is `prototype` with hardware validation
  deferred to **R8**. `TpmDevice`, `SoftwareTpm`, their contracts, their fast
  tests and their documentation are kept, so the capability costs nothing to
  carry. The M12 section below is unchanged and remains its specification.
- **M14 and M15 are advanced**, to R3 and R4: they are what a person or an
  agent adopts.
- **M16 is post-v1.0**, at R6. Durable orchestration belongs to PipelineK.
- **M17 depends on real M12**, at R9. Attestation is a claim about what
  executed, and `swtpm` is not evidence of what executed.
- **M18 stabilizes the next line**, at R10.
- v1.0's security baseline rests on what already exists and runs on any host:
  encrypted vault, no-exportability, broker boundary, policy, dedicated
  identity, seccomp, Landlock, cgroups, session isolation.

**M12 returns to the critical path when a requirement says so** — a customer
requirement, an enterprise compliance obligation, a vault that must be
physically bound to a device, attested secret release, a remote broker on an
untrusted host, Keylime/Trustee, or confidential computing. It does not return
because the work is half done, and no schedule brings it back on its own.

### On the `R` in `R0`–`R10`

This is a different series from the `R…` rows in
`16-SECURITY-RELEASE-GATES.md`, which are release gates. `R0`–`R10` here are
work blocks; `R0`, `R10`, `R11`, `R12` there are gates. **A work block is not a
gate and a gate is not a work block**, and neither is derived from the other.

## Status vocabulary

Every capability named in this roadmap carries exactly one of these four
states. They are not a maturity gradient — they answer four different
questions, and a capability is routinely in one of them while being absent
from another.

| State | Means | Closing condition |
|---|---|---|
| **verified** | An exit UAT is claimed by a test file in this repository and that test runs green. | The claim is machine-checked: `tools/check-gates.py` resolves the UAT id to a file, and the test passes. |
| **implemented** | The code exists and is exercised, but the property that matters is not yet proven adversarially. | Needs a test that can be shown to fail when the property is removed. |
| **host-dependent** | The capability is decided in code but its guarantee cannot be established on the machine that builds it — it needs a TPM, a live provider, or a physical host. | Only a different host can close it. No repository check asserts it, because nothing in a repository can decide it. |
| **prototype** | A shape, an interface and a reference implementation exist. Nothing depends on them at runtime. | Needs a real caller before it can be anything else. |

A **prototype** is not a smaller **implemented**. The M11 OAuth2 module has ten
unit tests and a reference issuer, and it is still a prototype, because no
production path calls it and a unit test on an uncalled function proves only
that the function agrees with itself.

A milestone closes only when its exit UAT is green — that is, only when its
capabilities reach **verified**. `host-dependent` and `prototype` are honest
places to stop; what is not acceptable is a milestone marked closed while its
capabilities are in either of them.

## Release strategy

Build vertical security proofs before broad connector count.

```text
R0 Foundations
   ↓
R1 Secretless SSH vertical
   ↓
R2 HTTP broker vertical
   ↓
R3 Tauri operator UX
   ↓
R4 Linux hardened sessions
   ↓
R5 TLS bridge (CONNECT path)      ← not eBPF; see M8 NO-GO
   ↓
R6 Connector expansion
   ↓
R7 Security stabilization RC
   ↓
v1.0 certified
```

R5 was specified as a transparent eBPF socket redirect. It shipped as the
explicit CONNECT/TLS bridge instead, because M8 decided NO-GO. The stage kept
its position in the sequence and lost its mechanism; the ordering was never the
thing in doubt.

A milestone closes only when its exit UAT is green.

---

## M0 — Threat model + executable architecture

**Goal:** create a compiling workspace whose boundaries match the security model.

### Scope

- Rust workspace skeleton.
- Domain ADTs.
- Broker process + versioned Unix IPC skeleton.
- CLI `status` and `run` skeleton.
- Dedicated service install prototype.
- Secret-safe error/log types.
- Test harness with canary-secret fixture.

### Required decisions

- ADR-0001 no secret retrieval API.
- ADR-0002 separate broker/Tauri.
- ADR-0003 Unix peer identity.
- ADR-0004 policy engine.

### Exit

- broker and CLI communicate using kernel peer credentials,
- untrusted DTOs cannot deserialize into secret-bearing domain type,
- canary never appears in debug/error serialization tests,
- UAT threat harness can launch arbitrary attack scripts even though no connector exists yet.

### Exit UAT

- UAT-031,
- UAT-032.

---

## M1 — Local vault + secure ingestion

**Goal:** securely store a credential and use it internally without creating an agent retrieval path.

### Scope

- versioned vault envelope,
- Argon2id unlock baseline,
- AEAD encrypted records,
- `secrecy`/`zeroize` handling,
- non-dumpable broker hardening,
- credential metadata CRUD,
- CLI no-echo ingestion,
- backup/restore prototype,
- feature probe for `memfd_secret`,
- Stronghold evaluation spike and recorded decision.

### Exit UAT

- UAT-018 audit leak,
- UAT-025 vault theft,
- UAT-026 backup/restore.
- UAT-036,

---

## M2 — Agent sessions + SSH signer (first complete vertical)

**Goal:** agent performs real Git/SSH work without private-key exposure.

### Scope

- `asv run`,
- environment quarantine,
- session lifecycle,
- custom SSH-agent compatible socket,
- SSH-key credential type,
- initial policy enforcement,
- session revoke,
- Git-over-SSH developer profile.

### Exit UAT

- UAT-001, 002, 004, 014, 016, 028.

### Gate notes

Placeholder replay outside the session is deliberately **not** an M2 gate: it
requires copying a surrogate outside ASV, and the surrogate registry only
arrives in M4. It is claimed by M4, the first milestone whose scope provides it.

### Product checkpoint

At this point ASV has demonstrated its defining property for private keys.

---

## M3 — Cedar policy + approval workflow

**Goal:** bound secret use to operation/resource/session.

### Scope

- Cedar schema/entities,
- deny-by-default,
- capability grants,
- TTL/use-count,
- approval objects,
- policy explain endpoint,
- protected-resource example.

### Exit UAT

- UAT-015,
- UAT-029,
- replay/expiry property tests.

---

## M4 — HTTP broker + surrogate credentials

**Goal:** bearer/API-key workflows without real secret in client process.

### Scope

- HTTP connector framework,
- exact authority normalizer,
- surrogate registry,
- explicit local proxy mode,
- one reference provider connector (GitHub-style bearer API),
- redirect and DNS controls,
- service-specific semantic operation example.

### Exit UAT

- UAT-005 through 010,
- UAT-017,
- UAT-027,
- UAT-030,
- fuzz corpus for URL/headers.

### Gate notes

Placeholder replay outside the session is claimed here rather than at M2: it
needs a surrogate to place outside ASV, and the surrogate registry is M4 scope.

Secret rotation lands here because rotation has to work against a stable
credential ID that both a live session and a Cedar policy already reference. M4
is the first milestone where a bearer/API-key secret is issued into a session;
earlier milestones have no second credential to rotate.

Performance smoke lands here because its 100 brokered read requests need the
HTTP broker path, and its overhead budget is only meaningful once that path
exists. The numeric threshold is `NFR-PERF-001` in `01-PRODUCT-SPEC.md`: p95
local authorization under 5 ms. Measuring it is M4 work.

---

## M5 — Tauri 2 dashboard

**Goal:** usable KeePass-like human control plane.

### Scope

- credentials/groups,
- add credential wizard,
- exportability status,
- policies,
- approvals,
- sessions,
- integrations/security posture,
- audit timeline,
- strict capabilities/CSP,
- no remote frontend assets.

### Exit UAT

- UAT-019,
- UAT-020,
- end-to-end add credential -> grant -> agent use -> revoke.

### Status: closed — 2 of 3 exits machine-asserted, 1 host-dependent

This milestone **shipped**, and both READMEs said otherwise for several
milestones. The console is `apps/desktop/ui/` and it is not a placeholder; the
claims that it was "not started" and that it was "remaining before 1.0" were
both false, and both are now removed.

- **E2E add → grant → use → revoke** is `verified` against a real broker
  process, a real vault file and a real control-plane enrolment
  (`crates/broker/tests/m5_console_e2e.rs`).
- **UAT-019 / UAT-020** are checked against a real WebKit engine by
  `apps/desktop/tests/uat019_probe.c`, which drives the *shipped* `ui/index.html`
  and `ui/app.js`. That is `host-dependent` in the sense that matters to a
  pipeline: the probe needs a display and `webkit2gtk-devel`, neither of which
  the CI container has, so it runs on the release host.
- The console **policy surface** (8 tests) and the CSP are machine-asserted
  with no GUI toolchain at all, as R12.

**Known gap, carried forward and not claimed closed:** the console has no
indicator that a TLS bridge is active. `apps/desktop/ui/` contains no
reference to interception, the bridge, TLS or surrogates. An operator cannot
see from the UI that an intercepting path exists, which is a real
observability gap even though it is not a security one.

---

## M6 — Non-HTTP protocol proxy

**Goal:** prove architecture beyond HTTP and SSH.

### Scope

- connector process/trait stabilization,
- PostgreSQL reference connector,
- local session endpoint,
- DB resource/action policy,
- optional dynamic DB credential provider adapter spike.

### Exit

- agent runs `psql` without password in env/file/process tree,
- unauthorized DB/role denied,
- connection teardown on revoke.

### Exit UAT

- UAT-033.
- UAT-039,
- UAT-050,

### Status: closed — two exits verified in any run, one only with a substrate

M6 had **no row at all** in `16-SECURITY-RELEASE-GATES.md`, so "M6 is closed"
was asserted by this roadmap and by a receipt and contradicted by nothing. The
row now exists. The three exits are not equivalent to each other, and the
distinction is the interesting part:

- **UAT-050** (`crates/broker/tests/uat_050_connector_dispatch.rs`) is
  `verified` on any machine: it proves the broker dispatches on the request
  type rather than a provider string.
- **UAT-039** (`crates/broker/tests/uat_039_pg.rs`) is `verified` on any
  machine: the five M6 scenarios run end to end against a fake origin, so the
  broker's decision logic is exercised without a database.
- **UAT-033** is the milestone's actual claim — *`psql` connects to a real
  server and the password appears in no file, no process and no environment* —
  and it is the one that needs a substrate. Two suites prove it,
  `crates/connector-pg/tests/uat033_live.rs` (the transport) and
  `crates/broker/tests/uat033_broker.rs` (the broker reaching a real server
  with the password borrowed from a vault), and both are `host-dependent` on a
  disposable PostgreSQL described by `ASV_UAT033_PG_*`.

**The caveat is stated because it is the kind that bites.** In the pipeline,
`scripts/uat033-pg-substrate.sh run` brings the substrate up and sets
`ASV_UAT033_REQUIRE=1`, so a substrate that fails to start is a hard failure —
that run is `verified`. In a bare `cargo test --workspace`, both suites **skip
with a message and pass**. A local run therefore reports the suite green with
UAT-033's real-transport assertions never executed, and a reader of that
summary is entitled to assume they ran. `uat033_live.rs` says this about
itself in its own header; it is repeated here because the roadmap is what
someone reads before trusting a green suite.

This also resolves a contradiction the READMEs carried simultaneously:
"live transport pending" and "UAT-033 runs against a real PostgreSQL in CI"
were both present, and the second was true only of the pipeline.

---

## M7 — Linux hardened sessions

**Goal:** resist process-inspection and exfiltration attacks from agent tree.

### Scope

- dedicated broker UID production packaging,
- cgroup v2 session ownership,
- `asv-ebpfd` privilege-separated helper skeleton,
- exec/connect telemetry,
- egress allow/deny maps,
- conservative seccomp profile,
- Landlock worker sandbox,
- private/protected `/proc` strategy,
- ptrace/process-VM/pidfd attack regression tests.

### Exit UAT

- UAT-003,
- UAT-023,
- UAT-024,
- UAT-048,

### Gate notes

The eBPF wrong-cgroup case is deliberately **not** an M7 gate: it requires
socket redirection, which is not part of M7. M7's scope stops at cgroup v2
ownership, Landlock and seccomp; the eBPF redirect path is an M8 research
decision that only becomes a feature at M9, and M9 claims it.

Isolated worker exfiltration is likewise **not** an M7 gate: it requires the
registered worker templates and separate-identity workers, which are M10's
scope. M10 claims it.

### Status: closed on its UAT, with one residual that matters more than it did

M7's exit UAT are claimed and green. The residual is the first item in its own
scope list — *"dedicated broker UID production packaging"* — and it is the only
scope item not delivered.

- **The broker still runs as the invoking user.** A separate uid was specified
  and is not shipped. `PR_SET_DUMPABLE=0` and Landlock are what stand in the
  way of a same-uid process reading broker memory, and both are *policy*
  enforcement that a same-uid process with `CAP_SYS_PTRACE` can defeat. The
  README has said this plainly for several milestones; it remains true.
- **The claim is therefore narrower than "the broker's memory is
  unreadable",** and is now the one the tests make: unreadable by a process
  that **lacks `CAP_SYS_PTRACE`**, which is the check the kernel performs.
  A dedicated uid would make it unconditional by making the attacker
  unprivileged by construction.

### What UAT-003's dropped clause now proves (V1-C1)

UAT-003's strongest clause used to be `#[ignore]`d:
`uat_003_open_proc_self_mem_returns_eacces_when_undumpable` was ignored as
*"structural: requires a child process to attempt the open; the in-process
check is dumpable_is_zero"*. That reason named the fix — a child process —
and the fix was never built, so the clause had never executed. It was the
only `#[ignore]`d test in the workspace, and **the workspace now contains
none**.

`crates/broker/tests/uat_003_proc_inspection.rs` runs the scenario against the
kernel: a forked child sets the target's dumpable flag, forks an attacker
under the **same uid**, and the attacker opens `/proc/<broker>/mem`. Three
conditions make the result attributable rather than merely green:

- the refusal must be `EACCES` or `EPERM` specifically, so a test cannot pass
  because the target had exited (`ENOENT`);
- the same attack against a *dumpable* sibling of the same uid must **succeed**,
  so a host where the open failed for an unrelated reason cannot pass it;
- the attacker must be shown to **lack `CAP_SYS_PTRACE`**, or on a privileged
  host the kernel permits the read regardless of hardening and the assertion
  measures the wrong thing. The guard is proven able to reject a privileged
  `CapEff` by a doctored value, because no ordinary run can produce one.

The first version of this test was **not falsifiable** and that was found by
trying: `PR_SET_DUMPABLE` is a *process* attribute and every `#[test]` in a
binary shares one process, so removing the hardening left the suite green —
the neighbouring test had set the flag back. A test whose outcome depends on
another test is not a test of the property. The scenario now runs entirely
inside a forked child that owns its own state.

### C1-R — the dedicated uid, from footnote to a checked fact

The first item in M7's own scope was *dedicated broker UID production
packaging*, and it stayed undelivered. The gate row said so in prose, which is
the weakest possible place for a security claim: nobody reads a footnote, and
nothing failed when it was ignored.

**What the code actually said, read rather than quoted.** The socket is `0600`
in a `0700` directory, the process is undumpable, Landlock and seccomp are
installed — and **all of it lives inside the invoking user's own boundary**. So
any other program that user runs is in the same uid, is outside the reach of
`PR_SET_DUMPABLE` as far as this broker's `/proc/<pid>/mem` is concerned, and
can open the socket, the vault and the audit log. UAT-003 proves the broker is
unreadable by a process *lacking* `CAP_SYS_PTRACE`; a dedicated uid is what
turns that into "unreadable by anything that is not root". The distance between
those two sentences was the whole residual.

**It is now enforced rather than described.** `crates/broker/src/identity.rs`
decides the posture in one function, and the launch contract feeds it two
numbers: `--identity-uid` declares the uid the installation expects, and
`--require-dedicated-identity` can demand the guarantee. The decision is a
comparison, not an inference. The tempting version of this module asks whether
the uid *looks like* a service account — below 1000, no login shell, absent
from the invoking user's session — and every one of those is a heuristic that
agrees with the truth on the machine that wrote it and disagrees everywhere
else with nothing failing. So the installation **declares** and the process
**measures**, and the answer is whether they are the same number.

**Two failures, with two different severities, which is the whole design.**

- A declaration that is **not honoured is always fatal**. An operator who
  declared `998` and got their own account believes they installed a service;
  the credential is in the wrong domain and nothing about the process says so.
  This is the "looks healthy while verifying nothing" shape, in a new place.
- The **absence** of a declaration is not a fault. A developer on their own
  machine has no dedicated uid, and a module that refused them would be refused
  by the next person to run the tests. That asymmetry is why the guarantee is a
  *flag* rather than a default: `--require-dedicated-identity` is what turns the
  development posture into a refusal, which is exactly what stops a packaged
  install from degrading into it quietly and reporting success.

A third case sits alongside: the socket **path** is derived from `getuid()`,
the real uid, while the socket's `0600` ownership is the **effective** uid.
Under a setuid bit those disagree and the derivation is wrong in a way nothing
else in the broker would notice, so both are read and a setuid broker is
refused under the same demand that refuses a missing declaration. It is not a
posture anyone asked for.

**Falsified 5 of 5** by `tests/identity_falsification.py`, and against the
**real binary** rather than the function — the decision being correct and
`main` not calling it are different failures, and this repository has found
that defect twice already on this very surface, in `ShutdownSignal::stop` and
`ShutdownSignal::revoke`.

**The campaign's fourth row found that the ordering witness was the weaker of
the two, and that is the finding.** Moving the check to just after
`VaultStore::open` still refuses, still exits non-zero and still names its
declared and actual uid: every message assertion passes. What it does not do is
refuse *first*, because `main` binds the socket at line 555 and opens the vault
at 627, so the broker has been listening the whole time — and a client dialling
that socket in the window gets a process that is about to die holding its
credential, while an operator reading the log sees a refusal that looks as
though it happened first. So `a_refused_broker_leaves_no_socket_and_no
_listener` asserts the filesystem rather than the prose.

The companion correction is a sentence in the test fixture. Its timeout said
*"neither started nor exited"*, which is what a reader takes away and is wrong:
what happens when the gate is absent is the more alarming thing, the broker
starts, opens the vault and **keeps serving**. It now says so by name, because
reporting an escape behind a word that reads like infrastructure is how an
escape survives a campaign.

**Packaging.** `packaging/asv-brokerd.dedicated.service` is the system unit that
declares an identity, with `StateDirectory` and `RuntimeDirectory` at 0700 so
systemd owns the vault and the socket without the installer `chown`ing anything.
`DynamicUser` is **declined, with the reason written down**: a dynamically
allocated uid is chosen at activation, so there is nothing an operator can put
in `--identity-uid` beforehand and the check would be unreachable in the one
configuration where it would be most convenient. A deployment that wants no
account can still get most of the property by dropping `--identity-uid` and
keeping `--require-dedicated-identity`, which proves nobody claimed a wrong
identity rather than that a right one was claimed.

**What this block does not close.** Creating the system account, and proving
the unit on a host that has one. This machine has no `sudo`, and nothing in the
repository can assert what `getent passwd` answers on a host that is not this
one. The posture is now enforceable; it is not yet exercised on a real service
account, and the gate row says that rather than rounding it up.

### C1-R, second increment — the posture on the wire, and a fifth state

The first increment made the identity **enforceable** and it stayed invisible,
which is the whole reason the M7 residual was a footnote: a refusal an
operator never learns about is not a control they can rely on. So the posture
is now a field, `BrokerInfo::identity` (protocol v6 to v7), and both `asv
doctor` and `agent discover` report it.

**`dedicated` is derived, never an argument.** A constructor that took the flag
would let a caller assemble a report saying *dedicated* about a broker that
declared a different uid — which is precisely the claim this field exists to
make falsifiable, so the derivation is the property and the signature enforces
it.

**The three states are three, and the third is why.** A shared, undeclared uid
is the documented posture of an unpackaged deployment, so it is not `Ok` (a
clean bill of health for the one protection the broker cannot give itself), not
`Warn` (see below) and not `Unknown` (it *is* observable, and the number
matters). A build that reports nothing is `Unknown`, because that is what it is
— version skew, which `broker.protocol` already names.

**A check needed a fifth state, and needing one is the finding.** The first
version reported a shared identity as `Warn`, which made every `asv doctor` on a
development machine read `Degraded`: a broker started from a shell shares that
shell's uid, so the degradation was permanent. **A status that is always
degraded is a status nobody reads**, which is the same shape of failure as a
check that always passes — and it contradicted the claim the M7 row above
spends a milestone narrowing, by degrading the diagnostic for the very state
that row calls correct. Six existing tests failed on it, and none of them was
wrong. `CheckState` therefore gained `Info`: observed, stated, and not a defect
in this installation. It still carries the remedy with both flags, because an
operator can act on that without being told their installation is broken.

The human renderer counts `Info` in its summary, because a state that is
neither a warning nor unknown would otherwise reach the operator only by
scrolling. While there: the width assertion tested `Unknown` rather than the
**longest** spelling, so `info` — four characters — would have passed a test
pinned to `unknown` without breaking anything, which is the shape of a guard
that has stopped guarding. It now walks `CheckState::ALL`, which was the
original intent.

**Falsified 4 of 4 — and W2 escaped on the first run, which is the row worth
keeping.** Dropping the field where the CLI reads the broker's response left the
entire workspace green. The reason is precise and it is the third time this
repository has found it: the doctor tests build `BrokerFacts` by hand and never
cross the wire, and `agent discover` did not render the identity at all, so the
value **travelled from the broker and died inside the product**. A complete and
correct mechanism with no production consumer, which no test of its own unit can
catch — `ShutdownSignal::stop`, `ShutdownSignal::revoke` and the untested
`RouteTransports` are the two earlier instances of it in this product, and
`RouteTransports` is the one a falsification campaign found.

Both halves of the fix were required, not one. `agent discover` now renders the
identity with its three states named — it is the surface an autonomous caller
reads rather than a human, so a state without a name would be worse than a
state that is absent. And the cold-discovery test asserts it **over a real
socket and on the envelope**, so it covers the serialisation as well as the
mapping; asserting on the struct would have covered the mapping alone and left
the same hole one layer down.

### The defect this found next to it

Writing that proof turned up a real defect in the hardened path, in the code
rather than in a document. `install_with` runs at `crates/broker/src/main.rs:221`
and the passphrase is read at `:315`; `landlock_restrict_self()` is
irreversible, and the declared path set granted the socket directory, the
vault's parent and the audit log's parent — **and nothing else the broker
opens**. So `asv-brokerd --harden --passphrase-file ~/.config/asv/passphrase`
sandboxed the broker out of its own passphrase and would have exited with
`cannot read passphrase file`. `~/.config` is not in `STATIC_READ_HIERARCHIES`,
which covers `/usr`, `/lib`, `/lib64`, `/etc`, `/proc/self`, `/sys/fs/cgroup`
and `/dev/null`.

The vault's directory *was* granted, so the vault would have opened. The
shipped deployment never hit it because `packaging/asv-brokerd.service` does not
pass `--harden` — and the unit's own comment had attributed the absent sandbox
directives to the write set being *unenumerated*, which had itself become
false. The mode that was broken was the one nobody enabled.

Fixed by extracting the declaration into
`harden::broker_install_paths`, which is testable, and adding the passphrase's
parent as **read-only** — the broker has no business writing beside a
passphrase. Five assertions in
`crates/broker/tests/uat_048_landlock_install_paths.rs` — nine assertions, not five — cover the mapping from
the operator's arguments to the set, including one that fails if a future
change widens the static hierarchies over the test's premise.

### What is still open

The dedicated uid, and therefore the unconditional form of the claim. It needs
a system account, and creating one requires privileges this host does not
grant, so it is **host-dependent** in the same sense as M11 and M12 — and no
guard asserts it, because nothing in a repository can decide whether an OS
account exists. The service ownership that would go with it (a system unit, a
dedicated `User=`, the right `StateDirectory`/`RuntimeDirectory` ownership) is
part of that same work, not a separate thing.

---

## M8 — Transparent eBPF bridge R&D gate

**Goal:** decide whether transparent socket redirection is production-worthy.

This is a **research milestone with a go/no-go gate**, not an assumed feature.

### E1 socket redirect

- cgroup connect4/connect6 redirect,
- original destination map,
- getpeername compatibility,
- loop exclusion,
- deterministic cleanup.

### E2 TLS trust matrix

Test major TLS/runtime families.

### E3 security proof

Surrogate works, real token absent from client, host/redirect attacks denied.

### E4 performance/reliability

Stress long-running agent sessions, high socket churn and map cleanup.

### Decision: **NO-GO** (recorded 2026-10-01)

M8 is decided, not deferred. The verdict has two independent legs and either
one alone is sufficient.

**Leg 1 — the research produced no program.** `cgroup_attach_skeleton`
(`crates/ebpfd/src/verbs.rs:239`) is documented as performing *"no syscall"* and
returns `Ok(AttachHandle(0))`. `crates/ebpfd` contains no BPF source, no ELF
object and no build step. `ProgramId::Connect4RedirectV1` is annotated as *"one
shipped ELF object in the broker's M9 deliverable"* — an object that does not
exist. A no-op that returns success cannot satisfy "reliable cleanup and
fail-closed behavior", so the go criteria were unreachable by construction
rather than by a shortfall in effort.

**Leg 2 — the build host cannot load a BPF object.** Measured directly rather
than read from `/proc/self/status`: `BPF_MAP_CREATE` returns `-1 errno=1
(EPERM)`. `CapBnd` does include `CAP_SYS_ADMIN`, so the kernel is not refusing
to grant the capability; the process was simply never given it, with
`unprivileged_bpf_disabled=2` and `/sys/fs/bpf` unreadable. Recorded in
`docs/receipts/m9-ebpf-capability-block.md`.

**The three negative criteria pass,** which is why this is a NO-GO and not a
rejection of the approach in principle: `bpf_probe_write_user` appears 0 times
in `crates/`, uprobe patching 0 times, and there is no system-wide CA.
`SSL_CERT_FILE` is a *per-session* env binding written by `tls_bridge.rs:398`
into that session's own environment, and `harden.rs:154` mounts `/etc`
read-only rather than installing into it. `crates/ebpfd` is a closed
eight-verb vocabulary that by construction accepts no arbitrary BPF bytecode.

### Consequence

The **No-go fallback is the shipped path.** "Keep explicit proxy + service
shims; eBPF remains egress/telemetry only" is not a contingency awaiting a
better experiment — it is what the repository already does, and `asv-ebpfd`
remains the egress/telemetry helper its own module doc describes. Because
ADR-0007 conditions the production feature on M8 GO, that feature is not
coming.

This is what M9 turned out to be. `eBPF transparent routing` left M9's scope
and the explicit CONNECT bridge stayed.

### Go criteria (not met, retained for the record)

- no direct `bpf_probe_write_user`,
- no generic uprobe patching,
- no permanent system CA,
- explicit list of supported client/runtime combinations,
- reliable cleanup and fail-closed behavior.

The first three are met. The fourth was published as `docs/tls-compatibility-matrix.md`
on the CONNECT path, which is not the same measurement. The fifth is not met,
and cannot be: there is no program to clean up.

This is a go/no-go research gate, not a shipped connector: its experiments
reuse the surrogate and hardened session delivered by earlier milestones, so it
re-runs their acceptance set rather than owning any of its own. It is
therefore DELEGATED to `16-SECURITY-RELEASE-GATES` and is not gated on UAT.

---

## M9 — TLS bridge on the CONNECT path

**Not conditional on M8 GO. This is M8's fallback, and it is what shipped.**

### Scope

Shipped:

- per-session ephemeral CA,
- local trust injection adapters,
- leaf issuance for exact hosts,
- strict CONNECT/redirect controls,
- credential substitution on the CONNECT path,
- a TLS compatibility matrix published from tests.

Dropped with the M8 NO-GO:

- ~~eBPF transparent routing~~ — the mechanism that gave this milestone the
  word "transparent" in its original title,
- HTTP/2 on the bridge, as a supported product feature. The bridge selects no
  ALPN protocol, so HTTP/1.1 only; see the matrix for why that is deliberate,
- a UI indicator that TLS interception is active. There is no interception
  indicator because M5 shipped without one, and that gap is real: an operator
  cannot see from the console that a bridge exists. It is carried forward, not
  claimed closed.

### Exit UAT

- UAT-010, 011, 012, 013,
- TLS compatibility matrix published from tests.

UAT-012 and UAT-013 are **superseded by the M8 NO-GO**, not blocked: they gate
the transparent redirect, which will not ship, so the question they posed has
an answer.

### The TLS compatibility matrix is published

The second exit criterion is met as of 2026-10-01. The artefact is
`docs/tls-compatibility-matrix.md`, and it is measured rather than asserted:
each row names the test that produces it, and the rows that no test covers —
cipher suites, key-exchange groups, signature algorithms, resumption,
renegotiation — are published **as untested** rather than omitted.

It is not `docs/12-COMPATIBILITY-MATRIX.md`. That document is a catalogue of
which tools work with which mechanism; this one is measured protocol behaviour
on the CONNECT path. Neither stands in for the other.

The measurement found one property that was load-bearing and unwatched: the
bridge selects no ALPN protocol, and it survives only because
`LeafMaterial::server_config` never sets `alpn_protocols`. Adding that field —
one line, and nothing about it reads as a security change — would make the
bridge negotiate `h2` over a tunnel it does not parse and cannot relay. The
matrix pins it with a test and records the falsification that proves the test
can fail.

**The matrix measured one leg, and C2.8 added a second.** The sentence in the
artefact claiming its rows describe "both TLS surfaces in the workspace" was
true when written and C2.8 made it false: making the broker-to-destination hop
TLS introduced a `rustls::ClientConfig` of its own, and the ALPN hazard the
matrix pinned for the server side has a **mirror** on the client side that
nothing watched. A broker that *offered* `h2` to the destination would get one
that believes it is speaking HTTP/2, and then relay `curl`'s HTTP/1.1 bytes
into it.

The client leg now has its own table (rows 19-26), its own witnesses in
`crates/broker/tests/connect_upstream_negotiation.rs`, and its own campaign in
`tests/upstream_negotiation_falsification.py` — **3 of 3 red on the assertion
each row names, with no residue**. Two limits are recorded in the same table
rather than left out: the client-auth row is falsified by a **control pair**
rather than a mutation, because the bridge holds no key material one could use,
and the cipher/provider row is **not pinnable at all** with `ring` as the only
enabled provider. A matrix that gave those two the same weight as the ALPN row
would be claiming a symmetry that does not exist.

This closed one exit criterion. It did not move UAT-010 on the CONNECT path,
and it does not touch UAT-012/013, which are superseded by the M8 NO-GO rather
than blocked: the feature they gate will not ship, so the question they posed
is answered rather than outstanding.

### The substitution increment: identity, answered

This section used to read that substitution on the CONNECT path was *not a
parser away* and was blocked on an identity question, and it pointed at
`FND-m9-connect-substitution` as carrying "the options and their costs". **That
finding was referenced by this file and by `tls_bridge.rs` and existed in no
document at all** — referencing it is not having it. Writing the options down
was part of the work.

ADR-0019 records four. The obvious one, taking the session from the kernel via
the socket peer, was **discarded by measurement**: `SO_PEERCRED` on a connected
`AF_INET` socket returns the unavailable sentinel (`pid=0 uid=-1 gid=-1`),
with an `AF_UNIX` control on the same machine returning the correct pid. Letting
the token be its own proof was discarded because it gives up `WrongSession`.
"CONNECT does not substitute" was kept, but as the **failure** rather than as
an alternative: a CONNECT that proves no session gets no tunnel, which is why
`EstablishedTunnel::session` is an `AgentSessionId` and not an `Option`.

What was chosen is a signed nonce. `asv run` opens a real session and binds its
public key to it over the kernel-authenticated socket; the CONNECT client
presents its key blob plus a signature over a nonce derived from the
destination; the bridge resolves that to the session whose **registered** key
verifies, and redeems the surrogate in it. `crates/broker/tests/uat_010_connect_substitution.rs`
proves it end to end with real keys and a real origin socket, falsified eight
ways.

UAT-012 and UAT-013 were superseded by the M8 NO-GO. UAT-011 was already
covered and the TLS compatibility matrix was published from tests. **M9 is
closed.** What is *not* claimed is on the M9 row of the release gates: no
production listener wires the relay into a running broker, one request is served
per tunnel, and the destination-derived nonce prevents a proof from being
transferred to another destination without being freshness.

---

## M10 — Isolated exec compatibility

**Goal:** support unavoidable legacy tools without lying about guarantees.

### Scope

- registered worker templates only,
- separate identity/namespaces,
- Landlock/seccomp,
- egress enforcement,
- secret env/file injection inside worker only,
- exact-secret stdout redaction as defense-in-depth,
- posture label `ISOLATED_PROCESS_EXPOSURE`.

### Exit UAT

- UAT-021 and UAT-022.
- UAT-040,

---

## M11 — High-value connector expansion

Order by value and achievable secretless property:

1. GitHub/Git HTTPS refinement.
2. AWS request re-signing + STS.
3. Kubernetes API reverse proxy.
4. OAuth2 provider framework.
5. mTLS/X.509 signer/connector.
6. Terraform provider compatibility catalog.
7. Docker/registry research.

Each connector must ship with its own adversarial tests and security classification.

### Exit

No fixed UAT set: each connector is gated by the acceptance tests it
introduces, and the set grows with the catalog. Completion is DELEGATED to
`16-SECURITY-RELEASE-GATES`, which requires the full matrix.

### Status of item 1 (GitHub): **implemented**, and reachable from a product surface

Item 1 was the last of the seven to have a production consumer, and like item 4
it was complete long before anything could reach it. The gap was not in the
connector or the broker: `Request::ReadIssue`, `CreateIssue` and `CreateRelease`
existed, were policy-gated, and had about thirty tests — and **every call-site
of all three in the tree was a test**. The relationship between "a GitHub
capability exists" and "an operator can ask for one" had never been stated, so
the three `AgentRel` GitHub links sat `withheld` while pointing at
`asv run -- gh issue view --`: an argv for a command this CLI does not have, on
a path that would not have let `gh` authenticate anyway, because `asv run`
substitutes at a CONNECT tunnel and never hands the child a token.

`asv github` is the surface. It opens a session, mints a **one-use** surrogate
from a vault *id*, spends it on a typed operation, and ends the session before
printing. There is no path in the CLI that can produce a GitHub token, and that
is not a gap to be filled in later — it is the reason the command exists. Three
decisions are decisions rather than conveniences: `--credential` is a vault id
and never a token; `--body` is a path or `-`, never a literal, because `argv` is
readable by any same-uid peer through `/proc/<pid>/cmdline`; and the surrogate is
minted per invocation with `max_uses: 1`, because a long-lived surrogate is a
bearer capability that outlives the reason it was minted.

`requires_human` stays `true` on all three relations **including the read**. The
read looks like the cheap case and is not — it lends a credential to a third
party over the network — and relaxing it to `false` would have been a one-word
change made by the same commit that published the link, with no policy decision
behind it. It is pinned, and relaxing it is a separate proposal.

**The evidence is deliberately split in two, and neither half claims the
other's.**

- `crates/broker/tests/r2a_github_vertical.rs` (11 rows) drives the real
  `BrokerState`, a real `VaultStore` and `VaultSecretPort`, the real policy and
  the real `GithubClient` against a local origin with real certificate
  verification. It establishes that the operation succeeds, that the origin
  really received the credential, that only the three promised fields come back,
  that the grant is spent by its one use, that a spent grant costs nothing on
  the wire, that a cross-origin redirect never reaches the second origin, that a
  hostile repository never dials at all, and that no token appears in any
  response, refusal or audit record.
- `crates/broker/tests/r2a_cli_reachability.rs` (4 rows) drives the real
  binaries and establishes that the verb parses, dials a real broker process and
  is answered by it.

**What is not measured, stated before anyone has to ask.** The second file is
hermetic by arrangement — every row is refused by the broker before any connector
runs, so it never resolves `api.github.com` — and it therefore **cannot**
establish that a read succeeds. The reason is a design property, not a gap in the
fixture: the GitHub audience is the compile-time constant `GITHUB_AUTHORITY`, and
the broker's dev-dependency on itself applies "to the lib as a dependency of the
test, and never to the binary". Putting a test-only audience override in a
production binary is the switch this design refuses to have. So **a live call
against the real `api.github.com` remains `host-dependent`**: it needs a real
token in a real vault on a machine with network, and no repository check asserts
it. M11's rule asks for a real provider; the provider half of that is honestly
outstanding, not quietly claimed.

Falsifications run rather than assumed: `token` → `bearer` in the authorization
header turns two rows red; removing `validate_repo`'s character check turns the
repository row red with `owner/repo ` reaching the provider; making `run_github`
able to skip the socket turns three of the four CLI rows red.

### Status of item 4 (OAuth2 provider framework): **implemented**, self-hosted

#### The port is live in the process and inert

This section is here because the row above used to describe OAuth2 as *partial*
and name one of the two gaps — the operator-configured scope — as if the other
were reachability. Reachability is the larger gap, and it is easy to miss
because the code looks connected.

It is not. Measured, not inferred:

- `crates/broker/src/main.rs` constructs `OAuth2SecretPort` from the operator's
  `--oauth2-clients` JSON file and installs it in `state.secrets` behind a
  `RoutingSecretPort`. That wiring exists and works.
- `crates/ipc-protocol` has **no** `Request` variant that asks for a token, and
  the dispatch in `crates/broker/src/lib.rs` has no arm that serves one.
- The CLI has no `oauth2` verb; the only occurrence of the string in
  `crates/cli/src/main.rs` is `CredentialKind::OAuth2` in a kind parser.

So an operator can start the daemon with a perfectly good OAuth2 client, the
broker will mint short-lived access tokens for it on demand from inside its own
`lend` call, and **nothing an agent says can cause that to happen.** The
`oauth2_vertical` is thorough — 11 rows over a real vault, a real issuer and a
real resource call — and it is a *library* vertical: it drives `lend` directly.
It proves the exchange and the property; it does not prove the path an agent
takes, because there isn't one.

**This is also the real answer to why the scope is operator-configured.** The
recorded reasoning is that a scope a request chose would be a scope the agent
picked, so the scope lives in configuration and policy should eventually own it.
That is right as far as it goes and it is not the whole cause: **no policy is
evaluated on this path at all, because there is no path.** A scope cannot be
policy-bound by a policy that is never consulted. Making the scope
policy-derived without first giving the port a product surface would be deriving
a scope for a request nobody can make.

#### What the next increment has to be, in order

1. **A surface, before a scope rule.** `Action::OAuth2Token`, a typed request
   and response, a dispatch arm, and a verb — so that something reaches the port
   at all. And the response carries no token: the token is spent inside a
   `SecretSink`, exactly as `lend` already requires, so the operation the agent
   names is an *operation*, not a credential.
2. **Then the scope, as a policy resource.** The audience alone is not enough to
   write `read`-but-not-`write` against, so the resource has to carry the scope
   as well as the audience — a new resource variant rather than a field added to
   `Resource::Api`, because GitHub and AWS are already evaluated against that
   one and widening it would change their meaning for every existing policy.
3. **The intersection, and which side wins.** The operator's file proposes a
   scope and the policy bounds it; the broker refuses when the proposal exceeds
   the grant. A weaker answer does not widen a stronger one, and the agent names
   neither. The refusal has to name which side was too wide, because
   "`Forbidden`" against a mismatch between a config file and a policy sends the
   operator looking in the wrong file.

Until step 1 exists, the honest description of item 4 is a complete provider
framework with no consumer — which is the failure mode the goal forbids under
the name *code without a consumer*, and which this row now says outright.

#### R2.B.2 — step 1, delivered: the surface, and the answer it produced

`asv oauth2 whoami` now reaches the port. `Request::OAuth2Identity` names a
session and a credential *reference* and nothing else; `Response::OAuth2Identity`
carries three non-secret strings; `Action::OAuth2Identity` is the verb;
`oauth2.identity` is the advertised capability; and `OAuth2Binding` in
`crates/broker/src/oauth2_binding.rs` is the deployment the broker authorizes
against. The client secret is spent inside the port on one token request and
never reaches a sink, so the operation the agent names is an operation.

**The four things a request cannot name are `token_url`, `resource_url`,
`audience` and `scope`,** and the absence of those fields is the claim rather
than an omission. All four come from `--oauth2-clients`, which the daemon reads
and validates at startup; a request that could name its own scope would be a
request that named its own authority.

Three findings came out of building it, and each one changed the design.

**One: the allowlist was not widened, and that is the load-bearing decision.**
`ALLOWED_AUDIENCES` remains exactly `["api.github.com", "sts.amazonaws.com"]`.
The obvious way to make a generic IdP reachable is to add its host, and doing so
would have compiled and passed every row while silently reopening D6 for GitHub
and AWS — they share the `Api` resource type, and `audience_is_approved` gates
every one of them, so any policy text could then have named `evil.example` and
been approved. Instead `Resource::OAuth2Client` is a **separate resource type**,
keyed by credential wire id, and it does not reach `audience_is_approved` at
all. The reachability guarantee is obtained structurally — the deployment
declares, the request proposes, and a policy can only allow or deny one of the
already-declared clients — instead of by enumeration, which is the weaker
mechanism here because a list long enough to be a product is a list nobody
maintains. Three type facts forced the new variant rather than making it a
preference: an RFC 8707 audience is a **URI** and `Resource::Api.audience` is an
`Authority`, which is a *host*; the audience is never request-supplied, so
`Authority`'s "an uncanonical audience cannot be constructed" buys nothing; and
the host the client secret is actually POSTed to is `token_url`, which
`ALLOWED_AUDIENCES` never gated at all — `load_clients` checked only
`starts_with("https://")`, a scheme check rather than an approval check, so
treating the audience as the approval question would have been a category error
about the wrong string.

The control turned out **stronger than a runtime denial**, which was not
anticipated. The Cedar schema declares `oauth2_identity` as applying to
`OAuth2Client` only, so an operator cannot *write* the dangerous rule at all:
`permit (…, action == Action::"oauth2_identity", resource is Api)` fails strict
validation when the policy is compiled, naming the offending rule, before any
request exists. The failure mode is unreachable by construction rather than by a
check that might be forgotten.

**Two: the answer is verified, not relayed — and the issuer speaks first.**
The deployment declares the scope and audience it expects, and a disagreement
with the resource's own answer is a refusal. The reason is that a resource
server reports whatever it was given, honestly, *including more than the
operator configured*; relaying that would leave `--oauth2-clients` describing an
authority that is no longer the one in play, which is the escalation M11 exists
to prevent arrived at through the provider rather than through a request.

The first version of the widening row **failed**, and how it failed is the
finding: `ClientCredentialsIssuer::issue` already refuses a widened grant —
`credential scope escalated: asked for "read:pods", granted "read:pods
write:pods"` — and it does so *before the broker holds a token*. That is the
stronger control, and it means the broker's own comparison in
`OAuth2Binding::identity` is unreachable through the production issuer. It was
kept rather than deleted, because a provider that widens the grant *after*
issuance is real and `OAuth2Issuer` is an extension point a deployment can
supply — and a control nobody can reach is not a control, neither is one nobody
can falsify. The two layers are now asserted separately, and each is reachable.

**Three: the documented AWS policy rule cannot work, and R2.B.2 refused to
repeat it.** `POLICY_TEXT` tells an operator to write
`resource.audience == "sts.eu-west-1.amazonaws.com"`, and that condition can
never be true: `cedar_decision` calls `Request::new(…, None)` and nothing in the
policy crate ever builds an `Entity`, so `Api::audience` is declared in
`SCHEMA_JSON` and never supplied. An operator following the documentation would
get a permanent, unexplained denial. The reachable-host guarantee is *not*
affected — `audience_is_approved` runs in Rust before Cedar, so only the
attribute is missing — and the working form is to match the entity **name**,
`Api::"api:<audience>"`. `OAuth2Client` therefore carries no attribute at all,
and the correction is recorded in the policy text next to the rule it corrects.
Fixing the attribute is its own change with its own evidence and is **not** part
of this one.

Measured: `r2b2_oauth2_vertical` 22 rows through the broker's own `handle`, with
a real `VaultStore`, a real routing port, a real Cedar policy, a real RFC 6749
server and a real RFC 8707 resource; `oauth2_port` loader rows 6 including three
new ones. Falsified by `tests/falsification/r2b2_falsify.py` in five passes:
**broker 5/5 red, binding 5/5 red, policy 2/2 red, selfreport 2/2 red, and one
documented survivor** — 15 mutations, 14 red, 1 survivor, 0 measured-nothing.

The survivor is the interesting one and it is not a defect.
`INDEPENDENCE_MUTATIONS` widens `ALLOWED_AUDIENCES` by one host and asserts the
OAuth2 happy path **still passes**, which is the measurement that the OAuth2
surface does not depend on the allowlist at all — the design's central claim,
stated as a number rather than as a paragraph. The first version of this campaign
filed that mutation under a heading implying it should go red, and it did not;
the cause was the campaign, not the code, because the harm of stretching the list
falls on GitHub and AWS and no OAuth2 row can go red however far it is stretched.
The two *dangerous* widenings were then re-aimed at the policy crate's own
`unapproved_audience_is_denied_even_though_it_canonicalizes`, and both go red —
so the harm is measured, and the independence is measured, and they are not the
same measurement.

The campaign found five defects in its own evidence and each was repaired rather
than absorbed:

- a missing ownership row (a survivor — nothing tested session ownership);
- a mutation whose snippet was not the code it claimed to change, so it mutated
  zero characters and reported a survivor;
- a row measuring UTF-8 strictness on a path where the token is always valid, and
  therefore incapable of failing;
- a row accepting *any* refusal, which left the non-2xx check unfalsifiable
  because a JSON parse failure is also a refusal;
- a `--exact` invocation that passed a bare test name, so both policy mutations
  reported `measured nothing` and the harness was reporting its own addressing
  bug as a result.

The last two are the reason a campaign is worth running even when the code is
right: in both cases the code was fine and the *evidence* was not, and a summary
that reported either as a pass would have been worse than no campaign.

Steps 2 and 3 remain open and are unchanged: the scope as a policy *resource*,
and the intersection where the operator's file proposes and the policy bounds.
What exists now is the prerequisite for both — and note that step 2's "a new
resource variant rather than a field added to `Resource::Api`" is now half-done
for a different reason, since the variant exists for the approval argument above
rather than for the scope, and it will carry the scope when step 2 arrives.

#### The attribute mechanism, which is what step 2 actually needs

R2.B.2 found that the rule `POLICY_TEXT` recommends for AWS could never match,
and it recorded the cause: `cedar_decision` passed `&Entities::empty()` to
`is_authorized`, so no resource entity existed and no attribute was ever
available to compare. That was fixed separately, and the reason it is its own
block rather than a line inside R2.B.2 is that **step 2 is impossible to build
correctly without it**: making the scope a policy resource means writing
conditions on attributes, and an attribute mechanism that does not supply
attributes is a mechanism that silently denies every rule written against it.
Building step 2 first would have produced a scope nobody could author a policy
for, and the rows would have passed while the feature did not work — the same
failure R2.B.2 was written to end.

The mechanism, in full:

- Cedar resolves a resource's attributes from the **`Entities` store**, not from
  the `Request` — a `Request` is three entity ids and a context. The original
  code passed an empty store, which is the whole defect.
- `resource_attributes` names the attribute per variant, and the store is built
  **with** the schema so Cedar rejects an attribute the schema does not declare.
  That matters in the direction that is easy to miss: no policy can reference an
  undeclared attribute, so an undeclared one reaching the evaluator would not
  look wrong while the mechanism quietly stopped working.
- `Request::new` now receives the schema too, so the request shape is validated
  on every evaluation rather than trusted.
- The engine's error is **carried into the denial's reason** rather than
  discarded as `"policy engine failure"`. This was not a nicety: the first
  attempt at the fix used `RestrictedExpression::from_str`, which parses a Cedar
  *expression* rather than reading a string, so `api.github.com` became a path
  reference to a non-existent entity and **every** `Api` authorization failed
  closed. With the error discarded that presented as three rows saying
  `assertion failed` and a decision indistinguishable from a policy denial. A
  fix that turns every authorization into a quiet deny is the most dangerous kind
  of broken, and the only reason it was found in minutes rather than shipped is
  that the reason was legible.

**The reachable host set is unchanged, and that is the claim rather than an
assertion of good intentions.** An unapproved audience is still refused in Rust
before Cedar is consulted; supplying the attribute only lets a rule *narrow*
within the set D6 already approved. Supplying an attribute is a fidelity change,
and the row that holds the distinction is
`audience_attributes_do_not_widen_the_reachable_set`.

The documented rule also **did not parse**, which is the third defect stacked in
one sentence and the reason a row loads the exact text the docs print. Cedar
4.7.1 rejects both `resource is Api && x` and `(resource is Api) && x`; the
grammar wants a `when` clause:

```
permit (principal, action == Action::"aws_sts_caller_identity",
        resource is Api) when { resource.audience == "sts.eu-west-1.amazonaws.com" };
```

So the original recommendation was a condition that could never match, inside a
rule that would not load, in documentation nothing in the tree exercised. All
three are gone and the rule is now a row.

Measured: `asv-policy` 22/22, four of them new and aimed at the two directions —
fidelity (`the_documented_audience_rule_now_matches_and_only_its_own_audience`,
`a_resource_entity_carries_exactly_what_its_schema_declares`,
`an_attribute_the_schema_does_not_declare_is_refused_by_the_store`,
`a_schema_that_does_not_declare_the_supplied_attribute_is_refused`) and
reachability (`audience_attributes_do_not_widen_the_reachable_set`).
Falsified by `tests/falsification/policy_attrs_falsify.py`: **7 mutations in two
passes, 7 red, 0 survivors, 0 measured nothing.**

One survivor became a row rather than a deletion, and the reason generalises. A
mutation dropping `Some(&self.schema)` left the direct-Cedar row green —
correctly, since a *correctly named* attribute is accepted either way, so no row
could tell. The row that makes it observable does not call Cedar at all: it
builds an engine whose `Api` type declares no shape, so the production path
supplies an attribute that schema does not declare. **A row that proves a
library behaves is not a row that proves this code is wired to use it.**

Also found, and fixed because it made the above undiagnosable:
`ExplainResult::reason` is a `ReasonCode` and reads `NoMatchingPolicy` for *both*
"the policy did not match" and "the engine refused", so the two are
indistinguishable from the outside. The free text lives on the decision. Worth
naming because a row asserting the wrong field reported a *correct* store
refusal as an acceptance.

Cedar 4.7.1's schema violation message is `entity does not conform to the
schema` and does not name the offending attribute. A row asserting it did was
wrong, in the same class as the defect this block fixes — claiming a diagnostic
the library does not produce — so it was corrected to the guarantee that holds:
a drift **denies** rather than comparing against nothing. Naming the attribute
would be better and is not written; it is a one-line wrapper on the way in.

Open, and not closed by any of the above: a live exchange against a real
third-party IdP needs a host that has one; `IDENTITY_TIMEOUT` bounds the call but
no row measures a hung resource, because a ten-second test is not a better test;
and the registration file's `resource_url` path component is dropped at load
(the broker dials `/resource` itself) without a row saying so out loud.

#### R2.B.2d — the scope is a policy resource, and what that is worth

The scope a registration carries is now an attribute a policy can be written
about. `SCHEMA_JSON` declares `OAuth2Client` with one attribute, `scope`, of type
`Set` of `String`; `resource_attributes` supplies it from the **deployment's**
`registered_scope`; and an operator can write:

```
permit (principal, action == Action::"oauth2_identity",
        resource is OAuth2Client)
when { resource.scope == ["read:pods"] };
```

**It is a `Set` and not the raw string, and that is the whole design rather than
a type preference.** A `String` has no `contains` in Cedar, so the only way to
test a text scope is substring matching — and substring matching on scopes fails
in the direction that matters: `pods:read` is a substring of `pods:readonly`, and
a policy refusing `pods:delete` would also refuse a scope that merely *mentions*
it. A set has neither failure, because membership is equality on whole tokens.
The one function that answers "what is this scope list" is
`asv_domain::scope_set`, which sorts and deduplicates, and it is called by the
issuer that refuses an escalation, by the policy that reads the set, and by the
broker that compares the answer. It used to be private to the issuer, which is
the second definition of the same concept and the reason it moved.

Measured: `asv-policy` **25/25** (three new rows), `r2b2_oauth2_vertical`
**25/25** (three new rows, and one that had to be rewritten — below).
Falsified by `tests/falsification/oauth2_scope_falsify.py`: **17 mutations in
five passes — 15 red, 1 refused by the compiler, 1 survivor, 0 measured
nothing.**

Three findings came out of building it, and each one corrected something I had
written earlier in this same document.

**One: the documented rule was wrong a third time, in the same way.** The block
above records that Cedar 4.7.1 rejects `resource is Api && x` and wants a `when`
block. The rule for the scope was then written in the rejected form, in the
documentation, by the same author, one commit later. It is worth writing down the
second time; it was not worth writing down the second time and making the same
mistake a third, and the row that loads the exact text the docs print is what
turned a would-not-load into a test failure in seconds.

**Two: a `contains` rule is a filter, not a guard, and the first version of the
row claimed the stronger thing.** A rule asking
`resource.scope.contains("pods:read")` is satisfied by `pods:read pods:delete` as
readily as by `pods:read`. The row that asserted it refused the wider
registration failed, and it was right to: **Cedar permits or refuses a
registration, it does not narrow one.** No policy language can hand a token, so
"read but not write" as a *narrowing* is not something this change could
deliver, and the honest form of the rule is set equality — one positive
statement of the exact grant, with no denylist for the operator to keep complete.
`POLICY_TEXT` now recommends the equality form and says why the denylist is the
trap most people reach for. A third row was removed rather than kept: it
duplicated `a_provider_granting_less_than_the_deployment_declares_is_refused`
and asserted the wrong error code for it.

**Three: the broker compared the scope as text while the policy compared it as a
set, and the two disagreed about the same grant.** A row that passed
`"read:pods  read:pods"` — two spaces — to measure whether a repeated token is one
grant was permitted by the policy and then refused by the broker as a widening,
because the fixture's IdP reports the scope it granted normalised to single
spaces and the broker's comparison was `reported.scope != registered_scope`.
That is not cosmetic: **RFC 6749 §3.3 defines `scope` as an unordered list, so an
IdP that reorders or re-spaces what it grants is behaving correctly**, and an
operator whose registration file had a double space would have had every OAuth2
identity call refused with a message telling them their configuration no longer
described the credential. The comparison now goes through the same
`scope_set`. Both directions still refuse — a grant the operator did not declare
is refused whether wider or narrower — so what changed is that *how the two lists
were typed* stopped mattering. The defect was older than this change; what this
change did was make the two layers answer the same question, which is what made
the disagreement visible.

The remaining two paragraphs are about the campaign rather than the build, and
they are the ones worth carrying to the next falsification harness in this repo.

**A guard defect found while running the gates, and deliberately not fixed here.**
`scripts/check-gate-status.py` reports `R11 full suite: states 1220 tests, 1596
are enumerated` and the matching `R11 README test count` row. Both numbers are in
`16-SECURITY-RELEASE-GATES.md`, and reading the row rather than obeying it is the
whole finding: it records a **dated measurement** — "both re-measured on this
cycle rather than carried forward, at 1220 enumerated" — and the guard
re-derives it against the *current* enumeration. So the row is not stale, the
guard is asking the wrong question, and the two available "fixes" are both wrong:
writing 1596 into the row would falsify a historical record by claiming a cycle
measured something it did not, and suppressing the check would leave a real
regression class unwatched. **The guard needs to distinguish a claim about the
present from a record of a past measurement**, and that is its own change, in a
document a second session is writing. Not touched here on purpose; the same file
also carries the `R11 dependency audit` and `R11 formatting` rows, both of which
are pre-existing drift over 38 unformatted files mostly belonging to that
session.

**The one survivor is a result, and deleting it would have hidden something.**
The mutation drops the deduplication from the scope normalisation, and the row
stays green: **Cedar's `Set` collapses duplicate members**, so `"read:pods
read:pods"` reaches the evaluator as `{read:pods}` and `== ["read:pods"]` holds
without the dedup ever running. So the dedup is *unobservable through the
policy* — no rule and no row can tell those two implementations apart, and a row
claiming to would be claiming a property Cedar's own type supplies. The dedup is
not decoration; it is load-bearing one layer down, where the **issuer** compares
the requested scope against the granted one before a token exists and a
duplicate really would read as a narrowing. The two layers are protected by
different mechanisms, and the survivor is the measurement of that. Kept, with the
explanation, because removing it would leave a mutation list that reads as
complete coverage of something it does not cover.

**A mutation outlived its row twice, and the pattern is the finding.** The
unsplit-set mutation survived a row whose cases all had the same outcome whether
the set was split or not — a row that cannot tell two implementations apart is a
row that measures nothing about either, however many cases it has. And a second
mutation was filed against a row that a rewrite of the block had silently
dropped, which the harness reported as `no-run` rather than as a falsification.
**A campaign's mutation list is coupled to its row list**, and a row block
rewritten for clarity quietly un-measures whatever pointed at it. Both were
re-filed against rows that do own the property, and the `no-run` bucket in the
harness is the reason the second was visible at all.

#### R2.B.2e, rescoped: narrowing a token is a port capability, not a policy one

The original step 2 was going to be the intersection — the operator's file
proposes a ceiling, a request proposes less, the policy bounds it, and the
provider mints the smaller grant. Having built the first half, the honest
conclusion is that **the second half is not a policy change and cannot be made
one**, for two reasons that are properties of the tree rather than of the design:

- `SecretPort` is a vault-and-provider boundary with **seventeen
  implementations** across the tree, and a scope is not a concept any of the
  other sixteen has. Putting a scope parameter on `lend` would mean every vault,
  AWS, Kubernetes and mTLS port carrying an OAuth2 field they cannot honour.
- The OAuth2 port's cache is **keyed by credential alone**, so a narrow request
  served after a wide one would be answered with the wide cached token. The key
  has to become `(credential, scope)`, and that is a change to the caching
  invariant rather than a line in a policy document.

So the scope-aware lend needs its own handle, and the day someone builds it must
change the cache key in the same commit. Until then the posture is exact and
worth stating: **the token's ceiling is the IdP's own grant, and what the policy
can do is refuse a registration whose registered scope is not the one it wants.**
That is a real control and it is the one an operator can use today; it is not
least privilege per request, and the difference is what R2.B.2e is now for.

#### A process incident, because it changed what a commit message can be trusted to mean

While R2.B.2 was being written, a second agent session working in the same
repository committed `bb710f5 feat(aws): the answer to "is this object there" that
holds no object` — and that commit **contains R2.B.2's edits to
`tests/falsification/README.md`**. The other session staged that file whole while
these edits were uncommitted in the working tree, so three paragraphs about the
OAuth2 campaign shipped under a message about `s3:HeadObject`.

The content is correct and nothing was lost, which is the only reason this is
recorded as an incident rather than as damage. The attribution is wrong, and
attribution is load-bearing here: this project claims that a commit message
states what a commit did, and a reader auditing `bb710f5` for what changed in the
falsification coverage would find three OAuth2 paragraphs with no mention in the
title or body.

The cause is the one this file already warns about — two writers, one index — and
the rule that prevents it is the one already written: **stage an explicit list of
files, never a path or a directory, and re-check `git status` immediately before
committing.** `git add tests/falsification/README.md` is a path; a file two
writers both touch is the case where a path is not enough.

What this does *not* justify is rewriting `bb710f5`. History is shared with a
session that is still writing, and an amend or a rebase to fix a message would
trade a documented misattribution for an undocumented one. The honest repair is
the one available: say so here, where the authority is read.

**The same class of incident, one direction over, and it is worth separating
because the tool behaved reasonably and the result is still wrong.** R2.B.2d's
commit `f85556f` staged an explicit list of eleven files and committed cleanly.
Its *alignment acknowledgement* was bound to work item `b259f5bd` — "R2.F.1
registry challenge, scope narrowing and realm vetting", in cycle
`p-20a1ee316faf2ba3/r2f-registry` — which is the other session's work, because
the only open cycle at the time was theirs. `git sddk-align` names the active
work item and does not read the staged diff, so following it exactly as
documented produced a receipt attributing an OAuth2 policy change to a Docker
registry work item. The correct work item was created afterwards
(`fec4f163`, cycle `p-20a1ee316faf2ba3/oauth2-scope-policy`) and the closeout
carries the real contribution, decisions, discoveries and unknowns.

Two things follow, and the second is the one that generalises. The staging rule
above is necessary and it was **not sufficient** — the commit content was right
and the ledger was still wrong, so an audit that trusts the receipt alone would
have read this change as registry work. And the cause is the mirror image of
`bb710f5`: there, a path absorbed another writer's file; here, an active-item
default absorbed this writer's work. **With two writers on one index, both a
loose path and a correct-but-unscoped default are ways to attribute work to
somebody else's item**, and the receipt has to be read against the diff, not
against itself.

It also has a second-order consequence worth stating, because the campaign ran
during the same window: the `policy` pass first reported three
`compiler-refused` results that were **not measurements at all**. The other
session's `aws/s3/object.rs` did not compile at that moment, so the whole
workspace failed to build and the harness correctly reported the
unreadable bucket — for a reason that had nothing to do with the mutations. Those
three results were discarded and the pass re-run on a tree that compiled, which
is the only reason the numbers above are trustworthy. **A campaign's result is
only about the tree it ran on**, and a concurrent writer invalidates it without
touching the file under mutation.

Item 4 was the only one of the seven that had been built when R2.A started, and
the difference between what it was and what it is took five increments, each of
which is worth naming because the first two changed nothing a reader could see.

It began as a prototype: a trait, a struct, and an `issue()` that hashed the
client id and the scope and called the result a bearer token. Ten unit tests
agreed with it about everything, including the parts that were wrong. Then, in
order:

- **The transport.** `asv_connector_http`'s scripted fake origin could not host
  a server, because a server's answer depends on what was asked. `TlsOrigin`
  answers from a handler, and the TLS machinery — accept, handshake, read a
  request, write a response — now exists once for both shapes instead of once
  per fixture. `PinnedClient` gained a finite timeout, because a client with no
  timeout is not fast, it is unbounded, and an origin that accepts and then says
  nothing is indistinguishable from one withholding an answer on purpose.
- **A party that can say no.** `AuthorizationServer` implements RFC 6749
  §2.3.1/§4.4/§5.1/§5.2, RFC 7009, RFC 7662 and RFC 8707 over a real TLS
  socket, with twenty tests establishing that it enforces them rather than
  replaying answers. Its default client's identifier contains a colon, which is
  load-bearing: form-encoded it survives the split on the first colon, sent raw
  it does not, so a client that skips the encoding cannot tell itself apart
  from a conforming one.
- **The issuer stopped inventing tokens.** `ClientCredentialsIssuer` performs a
  real HTTPS POST, and three of its rules exist because the alternative is a
  broker that looks healthy while holding more authority than it was asked for:
  the endpoint must be HTTPS, a granted scope that differs from the requested
  one aborts, and a token with no positive `expires_in` is refused. The
  placeholder was renamed `DeterministicTokenIssuer` and a source-scanning test
  fails if production code names it — a guard that has been seen to fail.
- **It gained a production consumer**, which is what `prototype` meant. The
  second increment still had a real issuer and *no caller anywhere in the
  runtime*, so the status did not move; this is the fourth time this product has
  produced a complete and correct mechanism with no production consumer, and the
  third time a campaign rather than a test is what found it.
  `OAuth2SecretPort` is a `SecretPort`, so a credential registered through
  `asv-brokerd --oauth2-clients PATH` is read from the real vault, spent on one
  token request, and what the operation's sink receives is a short-lived access
  token. The wiring is in `main.rs`. `RoutingSecretPort` falls through to the
  vault on `NotFound` **only**: any other failure is a refusal, because a
  provider outage answered from the vault hands the operation the stored
  `client_secret` and the operation then succeeds.
- **Five mutations, five reds.** `tests/oauth2_falsification.py` replaces the
  exchange with a direct read of the stored secret (8 of the 10 vertical tests
  go red), drops the token cache's deadline, makes the router fall back to the
  vault on any error, accepts a widened scope, and sends the Basic credential
  over the raw pair. No residue.

**What this is not, stated before anyone has to ask.** The provider is
self-hosted, not a third-party IdP, and the documents say `self-hosted` in the
status field rather than `real` in the prose. Establishing compatibility with an
operator's actual identity provider needs a host that has one, so **V1-C3 stays
host-dependent in its strong form** and the difference is a fact about the
work rather than an excuse. One further limit is named as a limit rather than
as a control: the requested scope is operator-configured rather than
policy-derived, so an operation can ask for a scope the policy never agreed to.
That one is **R4's work, not R2.B's** — a scope the operator wrote down is a
weaker property than a scope a plan was bound to, and closing it means binding
the request to the authority rather than to a file.

**R2.B.1 closed the revocation gap, and the limit it named was worse than the
wording suggested.** This section used to say that "while `forget()` makes a
revocation immediate when called, the credential-removal path does not call it
yet, so a revocation's real effect is bounded by the token's `expires_in`". That
undersold it: `DeleteCredential` answered `CredentialDeleted` while a cached
access token kept being lent to requests for the rest of its life, so the
operator was told a credential was gone and the broker kept spending it.

The call was not reachable as written, and that is the part worth keeping.
`BrokerState` holds `Arc<dyn SecretPort>`, the concrete type is erased behind a
`RoutingSecretPort`, and the trait had no method to call. `forget` is now
**required on `SecretPort`, with no default**: a default no-op would have been
one line and would have left the property resting on every future port author
remembering to override it. Required, a new `SecretPort` does not compile until
it has said what it does with derived secrets.

What it is not: this is not a provider-side revoke. It is "stop answering from
what I already hold", which bounds the window to nothing locally; a token the
IdP already issued stays valid there until it expires or is revoked there.

Measured by `crates/broker/tests/r2b_oauth2_revocation.rs` (5 rows) with four
falsifications run: `forget` as a no-op reds two rows; `DeleteCredential`
stopping to call it reds one and only the one about the delete path; `forget`
as a blanket `cache.clear()` reds the row about a sibling credential staying
served; and `forget` on the refusal path reds the row about a refused deletion
— because the vault write is what decides, and a refusal must cost nothing.

Only items 2 and 6 are unstarted. Item 7 is the one that reached a surface, and R2.F's row above is the record of it. Items 3 and 5 are the opposite case, and the word that matters for them is *not* "landed": Kubernetes and mTLS are wired into the broker — `pub mod k8s` in `lib.rs`, `pub mod mtls` in `tls_bridge.rs` — and adversarially tested more deeply than anything else in this tree, 95 and 36 inline rows behind six falsification harnesses. **Neither has a typed IPC request, a CLI verb, a published relation, or one socket-level vertical.** They are internal implementations carrying real negative tests, which is the situation R1 names when it says a very well tested infrastructure is still a prototype if no product surface can use it. Under M11's rule they hold the provider, the secretless property and the adversarial rows, and lack the operation — so neither closes. Item 2 is the case this paragraph used to file as unstarted and is half-built rather than absent — R2.C's row above records the signing, STS and calendar work, and that same row records why it does not close item 2. Item 6, Terraform, is genuinely unstarted: there is no Terraform identifier anywhere in `crates/`. Item 1 is the one semantic connector
exercised against a real socket, as *Status of item 1* above records, and item 2
has a foundation and nothing else, as *Status of item 2* below records.

### Status of item 2 (AWS re-signing + STS): **foundation only**

There was no AWS code in this repository when R2.C started — not a trait, not a
stub, not a test. So item 2 is construction rather than repair, and the failure
mode is different from item 1's: there was no existing path to inherit a
property from, so a subtly wrong signing primitive would be the whole problem.

**R2.C.1 was the signing core, R2.C.2.a the `AssumeRole` protocol in both
directions, R2.C.2.b the socket, the cache and the `SecretPort`, and R2.C.3 the
first request signed with a session and the first one an agent can ask for.**
What is still missing is named below rather than summarised as "more work":
`s3:GetObject`, a live call, and the regional STS endpoints. **Per M11's rule a
provider does not count as closed on an encoding plus a signing core, and it does
not count as closed on one operation either** — see *The first agent-reachable
operation* below for what R2.C.3 does and does not establish.

What is left, in order:

- **`s3:GetObject`**, named explicitly and excluded from R2.C.3 rather than
  implied. It is the obvious second operation and it is not free: S3 addressing,
  percent-encoding of the key inside the canonical path, and a body that is not a
  document. The reader's rule — *a document that is not understood is rejected,
  not guessed* — applies to a response body as much as to a policy file.
- **Regional STS endpoints.** `ALLOWED_AUDIENCES` covers `sts.amazonaws.com` and
  nothing else, so an operator who pinned a region cannot have it honoured yet.
  Fixing it properly means threading the region into `audience_is_approved`,
  which changes a contract rather than adding a string, so it is declared open
  in the code rather than quietly left.
- **A live call against AWS**, which is `host-dependent` for the same reason
  item 1's is: it needs a real account and real credentials on a machine with
  network, and no repository check asserts it. And if AWS accepts the exact
  percent-encoding the body emits is still open, so this is a measurement, not a
  formality.

#### The XML reader, and why there is no parser

`Cargo.lock` still has no XML parser in it and none was added. A general parser
brings a DTD, and a DTD is an XXE surface. The reader implements no entity
mechanism at all: the five predefined entities and numeric references are
decoded, and **every other entity is a refusal** — as is a bare `&`, and as is a
document declaring a DTD. There is no code path in the file that turns a name
into a fetch, so `&xxe;` has nothing to attack.

That leniency was removed on purpose, and the reason is the one the whole file
is built on: everywhere else — a duplicated element, an unclosed tag, a body
that is not UTF-8, an instant that is not the documented shape — a document the
reader does not understand is **refused rather than guessed at**. Preserving
`&xxe;` as five literal characters was the single place it guessed. It is also
not a real loss: a credential cannot contain `&name;`, so its presence is
evidence the document is not what it claims.

#### Three defects the evidence found, and one it did not

- **A panic on a two-byte character beside a tag.** The duplicate-element check
  indexed one byte past the opening tag, which lands inside a multibyte
  character. A reader pointed at a socket must not take the process down, and
  the row that measures it is
  `a_multibyte_character_beside_a_tag_is_read_whole_and_does_not_bring_the_reader_down`.
  The fix is `match_indices`, so every index sliced at is one the string library
  already proved to be a character boundary.
- **A leap second was accepted and silently clamped to 59**, while the
  function's own doc comment said leap seconds were "refused rather than
  approximated". The oracle disagreed with the code and the code was wrong: a
  timestamp read wrongly is a credential believed valid after it is not.
- **A credential field containing whitespace was accepted.** The AWS reference
  page prints the sample `SessionToken` across five indented lines. That folding
  cannot arrive on a socket — the token becomes an HTTP header value, and a
  header value cannot contain a newline — but a reader that trimmed or un-folded
  would mint a session wrong by exactly the whitespace it chose to remove, and
  report success. The reader now refuses, which says *this document is not a
  credential*.
- **The one that was not a defect in the code: the first run of the
  falsification harness reported all 24 mutations as falsified when it had run
  zero tests.** It passed a short test name to `cargo test --exact`, cargo
  matched nothing, printed `running 0 tests` and `test result: ok. 0 passed`,
  and the harness read that as green. It is the same class of failure as
  `uat_040`: a row that never ran is indistinguishable from a row that passed
  unless the harness is built so it cannot say so. The harness now refuses to
  report green unless the named row ran, and separately refuses to read a
  failure as anything but a failure.

**The arithmetic in the falsification summary was wrong too**, and in the
direction that flatters: it computed "falsified" as everything that was not a
survivor, which swept the compiler-refused mutations into the count while the
line beneath said they were not counted. The 25 mutations partition into **24
red, 1 refused by the compiler, 0 survivors, 0 unmeasured**, and the harness now
asserts that the four buckets sum to the number of mutations run.

**No new supply-chain surface.** `sha2` was already a direct broker dependency
and `hmac` was already resolved through the vault; `Cargo.lock` gains one line
and no package. `aws-sigv4` was not used: a new name in a signed SBOM to avoid
a four-step HMAC chain is the wrong trade. The XML reader added no dependency at
all, which is the point of it.

#### The oracle, and why the vectors mattered more than the tests

Every expected value comes from the AWS documentation and none was copied from
this implementation's output: they were computed first by a separate
implementation written from the specification, and the two compared. That caught
two bugs no test written afterwards would have found. The first put the date
stamp in the credential scope **twice**, and the signature was still correct —
the extra text
is not hashed — so nothing local noticed and every provider would have rejected
the request with a scope no reader could reconcile against the signature beside
it. The second was a parameter that could not do what its name promised: the
path is split on `/` before encoding, so a segment can never contain a slash,
and the real AWS rule is *double* encoding outside S3.

Three of the four first-run failures were the test being wrong rather than the
code, and a fifth falsification did not bite until its row was rebuilt with a
pair that actually distinguishes the two implementations. Both are recorded in
the module and in the test, because "the tests pass" is the least informative
sentence anyone can write about a signing primitive.

**No new supply-chain surface.** `sha2` was already a direct broker dependency
and `hmac` was already resolved through the vault; `Cargo.lock` gains one line
and no package. `aws-sigv4` was not used: a new name in a signed SBOM to avoid
a four-step HMAC chain is the wrong trade.

#### The cache, and the three values that will not become one

`AwsSecretPort` is where R2.C.2 earns its name, and its central decision is a
**refusal**. An AWS session is three values — access key id, secret access key,
session token — and the `SecretPort` trait this tree already has hands over one
`&[u8]`, whose only consumer builds a bearer `Authorization` header out of it.
So `lend` always returns `Unavailable` with a message saying why, and the
method a caller actually uses is `lend_session`, whose sink takes all three or
nothing. The refusal is structural rather than a missing feature: there is no
conversion from three values to one, so nobody can add one without writing it,
and `AwsSession` has neither `Clone` nor public getters on the two secret fields
for the same reason — so the cache cannot duplicate the values to hand them out
twice. `Arc<AwsSession>` is a handle, not a copy.

`forget` is required on `SecretPort` with no default since R2.B, so the
revocation property is enforced by the type rather than by this port's
good manners. Two rows hold it from both directions, because a `forget` that
does nothing and a `forget` that clears everything both pass a test that only
ever used one credential.

**The margin rule is where the silent case lives**, and it is the same trap R2.B
found on the OAuth2 port: a margin at or above the session lifetime does not
make the port refuse, it makes every call re-mint — nothing fails, and the only
symptom is STS sitting on the critical path of every request. The port **cannot**
refuse it, because the lifetime is whatever the role allows and the role is only
consulted at mint time, so a check in the constructor would be a check against
nothing. What it can do is make the arithmetic public in `serve_for`, whose
answer for a degenerate configuration is `Duration::ZERO` rather than a negative
number nobody notices. The boundary is **strict**: a session with exactly the
margin left is not usable, because a request signed now and sent a moment later
arrives with the margin already spent.

#### Five defects the port's own evidence found

Three were in the code and two were in the rows, and the distinction is the
point of recording them together.

- **`with_margin` documented a refusal it structurally could not perform.** It
  returned `Result<Self, StsClientError>` and claimed in its doc that it
  "refuses a value that would make the cache useless" — while accepting
  everything, because there is no lifetime to compare a margin against at
  construction. A constructor that validates is the specific thing whose absence
  let the OAuth2 port's silent case stay silent. It returns `Self` now and says
  why it cannot refuse.
- **`Debug` printed a count where the receipt needs the names.** The row
  asserting the printed form identifies the cached credential went red against
  the implementation, and the implementation was wrong: a count of one is not
  actionable for an operator. It prints the credential ids — vault names, not
  secrets — and still prints none of the three values behind them.
- **The margin boundary row was one second on the wrong side.** It asked for a
  session with 61 seconds left against a 60-second margin and asserted a
  re-mint; the port served it, correctly. "A bit inside the margin" is not a
  thing: the row now pins both sides of the strict boundary, because a row that
  cannot tell the two apart is not measuring the rule.
- **The concurrency row could not fail, and would have hung rather than
  failed.** It claimed to catch a lock held across the exchange, but its
  exchange returned immediately, so nothing was ever contended — and under the
  mutation it names, the row would have deadlocked rather than failed. It now
  *holds* the first exchange open, asks for a second credential while it is in
  flight, and waits with a deadline. Under the mutation it gets a red row; it no
  longer gets a hang. A test that hangs is worse than a test that fails, and the
  first version was the former.
- **A row's leak assertion was defended by a different file.** "Printing the
  port never prints a session" cannot fail on the secret values, because
  `AwsSession` redacts its own `Debug` — that is R2.C.2.a's row. As written the
  assertion read as if *this* file kept the values out. It now also asserts that
  the listing carries none of the session's own detail, which is a property of
  this file and is falsifiable here.

**Two rows were replaced because they were unfalsifiable, not because they
passed.** "A failing exchange is not cached" cannot be broken from this file at
all: the `?` precedes the insert, and no reachable mutation can put a session
into the cache on the error path without a constructor that does not exist. It
is now two rows that can be broken — *a failure leaves the cache alone* (caught
by an error path that calls `cache.clear()`, turning one unreachable STS into
every credential re-minting at once) and *a failure does not buy a stale
session* (caught by the tempting fallback that serves whatever is cached when
STS is down, which converts a clean local refusal into a signature AWS rejects
with a name pointing at the credential rather than at the margin).

**The 13 mutations partition into 13 red, 0 refused by the compiler, 0
survivors, 0 unmeasured.** A fourth harness defect is recorded because the first
run of it reported on the wrong file: the base harness reads its mutation list
out of its own module namespace, so assigning a same-named list locally did
nothing and the campaign falsified `sts.rs` while saying nothing whatsoever
about the port. `sts.rs` was verified restored, the wiring fixed, and the
campaign re-run — and the harness now names its target file in its own header so
that a mismatch is visible in the first line of the output.

#### The first agent-reachable operation

R2.C.3 is the increment that makes the provider *usable*, and the whole of it is
one idea: **the agent names an operation and a credential id, and never sees an
AWS secret.** Handing the agent a session token would be a weaker property
wearing the same label, so it was never on the table — and the strongest form of
that property turned out to be structural rather than a refusal.

`Response::AwsCallerIdentity { arn, user_id, account }` has **no field in which
a secret fits.** There is nowhere to put an access key, a session token or a
signature. That is a stronger claim than "the broker refuses to return one",
because a refusal is a branch somebody can delete, and an absent field is not a
branch. The same argument drove the request: the agent sends a `CredentialId`,
and the broker resolves it, mints, signs and answers with the provider's own
reply.

What that required, in order:

- `Action::AwsStsCallerIdentity` in the domain, with a deliberately breaking
  variant — `action_name` is exhaustive on purpose, so the compiler forces
  every reader to decide rather than letting a wildcard answer.
- `Request::AwsCallerIdentity` / `Response::AwsCallerIdentity` in the protocol,
  and `PROTOCOL_VERSION` **8 → 9**. A wire change is not free, and pretending
  otherwise is how two peers disagree about what they are holding.
- `AwsDeployment` / `AwsBinding` in the broker: the operator's declaration of
  *which credential, which audience, which region, which role*. The audience
  comes from the **deployment**, never from the request, so a policy permitting
  `sts.eu-west-1.amazonaws.com` permits it there and not on a host a request
  asked for.
- `asv aws whoami --credential <id>`, and `r2c3_aws_vertical` 13/13 from the
  product surface against a real TLS origin, a real vault and a real policy.

**The operation was built and not announced, and every row above was green.**
`compiled_capabilities()` is what `asv capabilities` and `asv discover` read, and
it did not name `aws.sts.caller_identity` — so a fully working AWS path was
invisible to the only surface an agent uses to find out what a product can do.
This is R1's lesson applied to discovery rather than to execution, and it is the
more embarrassing half of the gap: the operation worked, and no user could tell.

The module that owns the list also **cited a test that did not exist.**
`every_advertised_capability_is_handled` was named in a doc comment as the thing
keeping the list and the dispatch in step; grep found the citation and nothing
else. A guard asserted in prose is worth nothing, and the direction that was
actually missing — a handled operation that is not advertised — is the one no
existing test looked at in either direction.

Both directions now exist and are checked against a sample that covers every
`Request` variant: `every_advertised_capability_is_handled` (the direction the
doc claimed) and `every_handled_operation_is_advertised` (the direction that
found the defect). A third row, `the_sample_covers_every_request_variant`, exists
because deleting a line from that sample would silently remove a variant from the
coverage of both — and a coverage check you can quietly delete is not coverage.
The classification is an exhaustive `match`, so adding a variant does not compile
until someone has decided what capability it is.

**The stock policy does not permit `aws_sts_caller_identity`.** That is the
`connect_route` precedent: a new surface does not start allowed because a release
added it. It *is* in the schema, because strict validation would otherwise reject
at load time a rule the operator wrote on purpose. The order is: a provider is
declared in `ALLOWED_AUDIENCES` in Rust, then in the policy. Both halves, or the
operation cannot be reached.

**Two properties are worth stating because they are structural, not tested.**
Ending the session stops further AWS calls, because the deployment is only
reachable through a session-owned peer; and the encoded response carries no
credential, because the type has nowhere to put one. Both were rows, and both
have a mutation that turns them red.

#### The deadlock the evidence found, and what it says about the other path

The most serious defect in the block was found by `eu-stack` on a hung test, not
by reading: `authorize_aws` held the session-store guard across the policy
evaluation, and `evaluate` wants the **same** `std::sync::Mutex`. Every
successful `asv aws` call would have hung the real broker. It was found because
the vertical ran the success path in-process against a real store rather than
mocking one.

The fix is a method, `session_owned_by`, that takes the guard, answers, and drops
it. **`authorize_github` was rewritten to go through it too**, which is the
finding worth keeping: the same latent shape existed on the GitHub path and was
only visible once the second caller existed. Two callers is the minimum for a
lock-ordering defect to be a pattern rather than an anecdote.

The other four defects in this increment were smaller and are recorded because
the same thing is true of all of them — a green row that asserted the wrong
thing:

- **The deployment was indexed by label instead of by `CredentialId`,** so every
  call was refused with "no AWS deployment configured for …". A refusal that is
  always taken is a feature that never worked, and the row that caught it was the
  one asserting the success path.
- **`ALLOWED_AUDIENCES` had no AWS entry,** so every request was rejected before
  Cedar was ever consulted. The rejection was correct *for the reason given* and
  the reason was wrong.
- **`SessionStore::belongs_to` compares only `pid`,** so a second
  `WorkloadIdentity` in the same process *is* the same peer. The row asserting
  "another peer is refused" was therefore unfalsifiable as written; it now
  asserts a session *this peer does not own*, which is the property that exists
  and can be broken.
- Two of the row's own expectations were wrong: the action name the broker
  reports is `aws_sts_caller_identity` where the variant is
  `aws.sts.caller_identity`, and the `Host` the client compares is the
  **authority**, not the string it was handed.

**The 9 mutations partition into 8 red, 0 refused by the compiler, 0 unmeasured,
1 a recorded survivor.** The survivor is kept rather than deleted: printing the
port from the binding's `Debug` does not leak, because `AwsSecretPort` has a
hand-written `Debug` that prints the margin and the credential ids and nothing
else — the property `port_falsify.py` already falsifies with two mutations of its
own. The defence is two layers down, so the row is a regression net and not the
evidence, and saying so is the point.

Of the eight, the two that matter most are the ones that came last. *Build the
operation and never announce it* is the mutation that corresponds to the defect
this increment actually shipped with, and it is worth noting that every one of
the eleven rows that existed before it stayed green under it. A vertical that
proves an operation works is not evidence that anything can find it. *Announce it
under a name that reads like a retrieval* is the second: the capability is
spelled for what the caller gets back, not after the AWS API action it calls, so
`aws.sts.get_caller_identity` — the obvious name, and the one the API uses — is
refused by a substring rule as well as by a row.

One harness defect is recorded with it. The ownership mutation's snippet opened
on the two guards that `authorize_github` and `authorize_aws` share, so the
harness counted two matches and **measured nothing** — reported as a skip, which
is exactly what it was. Anchoring the snippet on the line only `authorize_aws`
has made it a measurement. A falsification harness that silently declines to
measure is worse than no harness, because its total still looks like a number.

**The seven harnesses are in this repository, at `tests/falsification/`,** and the
113 is re-derivable from a clean checkout by running them. Getting there was a
defect of its own: six of them lived at `~/agent-secretless-tmp` with `REPO`,
`CARGO_TARGET_DIR`, `PATH`, `HOME` and the backup directory all written out as
absolute paths for one machine. A campaign file that resolves to someone else's
home directory is in the repository in name only, and the figure it produces is
reproducible only by the person who wrote it. `REPO` now comes from `__file__`
and the environment is inherited rather than replaced, so the only thing a
second machine needs is a checkout and a cargo.

Seven runs from the new location reproduce the seven numbers in the table above
unchanged, which is the point of having done it: 25, 25, 13, 14, 13, 14 and 9.

**The seventh is the one this closes.** R2.C.1's `sigv4` campaign was run inline
and left no harness, so for the whole of this block the signing core — the part
every other figure rests on — was the single number a second person could not
re-derive, and the roadmap said so in three places rather than quietly rounding
it up. It now has one: **25 mutations, 25 red, 0 survivors, 0 unmeasured.** No
gap remains in R2.C's evidence, and the sentence that named the gap is gone
because it is no longer true.

The ordering inside that campaign is the part worth keeping. The *arithmetic* —
the four HMAC steps and the encoding rules — comes first, because those are what
the published vectors pin down. The *property* the module argues for comes
second, because the vectors cannot establish it: every vector is a request that
should succeed, so only a row that refuses a request can check it. A signer that
computes the right HMAC and drops the host requirement passes all six vectors and
replays across destinations, which is why the mutations that matter most there
are the ones that delete a refusal.

### Status of item 7 (Docker/registry): **implemented for OCI read and push**, and the catalogue is not closed

Item 7 was the last of the seven to be unreachable from any product surface. It has a
surface now: four `asv registry` verbs, four published relations, and
`r2f_registry_vertical` at 21 rows against a real socket rather than an in-process
call. The registry's answer is the registry's — the client never sees the credential —
and a response is bounded at 1 MiB, because a registry must not be able to choose how
much memory the broker uses.

Two corrections in this block were security findings rather than features, and they
are worth reading as a pair. `AddressPolicy` refused the IPv4 spellings of a
destination it refused and accepted several IPv6 ones: multicast, `ff00::/8`,
`fec0::/10`, 6to4 and both NAT64 prefixes all spelled a host the policy was already
refusing (`4586028`). And the four registry arms each carried their own copy of the
same six-step preamble, which is how a check like *the credential must be the one the
declaration named* comes to be maintained in four places; it is one `RegistryGrant` now
(`63869bc`), with each arm keeping its `Action` at the call site so a reviewer reads
the action rather than infers it from a parameter.

The registry side is not closed. Push is monolithic rather than a `POST`→`PUT` session,
so a registry that answers with a `Location` is a `realm`-shaped input that would need
the same vetting a realm gets, and it does not get it yet. And `put_blob` proves the
digest before opening the socket but cannot prove the registry stored the bytes, because
the registry does not return them: a registry that accepts an upload and discards it is
indistinguishable, from here, from one that kept it. Docker itself is unstarted; what
exists is the OCI distribution surface underneath it.

---

## M12 — TPM/hardware-backed vault

> **Deferred to R8; not a v1.0 gate.** This section is unchanged and remains
> M12's specification — the scope, the exit and the exit UAT below are exactly
> what R8 has to satisfy. What changed is its position in the order, and why:
> a guarantee that needs `/dev/tpmrm0` cannot gate a release built on hosts that
> do not have one, and `swtpm` is a TPM 2.0 implementation rather than silicon.
> The software half is further along than "not started" — a real client, pinned
> command encodings and a measured, durable seal path — and that measurement is
> the R8 starting point, not an argument for v1.0 waiting.
> See [ADR-0020](../adrs/0020-adoption-before-hardware-tpm2-leaves-the-v1-critical-path.md).

### Scope

- hardware-keystore port,
- TPM2 wrapping/sealing,
- recovery workflow,
- optional PCR/device-state policy,
- migration between passphrase and device-bound vault modes.

### Exit

- device-bound theft test,
- documented recovery before destructive enrollment,
- clean fallback on unsupported hardware.

### Exit UAT

- UAT-034.

---

## M13 — RC security stabilization

### Freeze

No new broad connector families.

### Work

- third-party security review preparation,
- fuzz duration increase,
- dependency/advisory audit,
- full UAT matrix,
- package hardening,
- upgrade/migration tests,
- crash/recovery,
- docs/manual,
- signed reproducible artifacts where practical,
- SBOM.

### RC exit

### Exit UAT

- UAT-035.

### RC exit

All release gates in `16-SECURITY-RELEASE-GATES.md` pass.

### Status: **partial** — and it is not close to the freeze being satisfiable

M13's work list is a certification checklist, and the honest reading is that
most of it is still open. `16-SECURITY-RELEASE-GATES.md` has a row for M13 now
(it had none, which is how both READMEs came to carry `M13 ✅`).

Done, and verified in the pipeline:

- dependency/advisory audit — 0 advisories over 338 deps, one yanked
  transitive recorded as a finding,
- crash/recovery — UAT-035, a journal replay that never advances past a torn
  write,
- docs, SBOM, ops manual.

Not done:

- **third-party security review** — not performed, and not performable from a
  developer's machine. It is preparation for a review, not the review.
- **signed reproducible artifacts** (R0) — no signing pipeline,
- **full UAT matrix green** — 29 of 40 ids claimed, and the 11 unclaimed are
  grouped by cause, with 2 superseded rather than outstanding,
- **upgrade/migration across releases** — the rekey and vault-format migration
  tests exist; a release-to-release upgrade and rollback test does not.

The freeze is therefore not yet a constraint anyone has had to respect,
because the certification work that would justify it has not been done. Saying
so is cheaper than a v1.0 tag that a release host immediately contradicts.

### Certification measured on this host

A count without the command that produced it is a number in a document. These
two are recorded with their commands, their commit, and the exit code of the
process that ran them.

**Release — the exact command the quick-start documents**
(`cargo test --workspace --release -- --test-threads=1 --skip uat_028 --skip
one_hundred_brokered_reads`), at `539269d`, on this host: **87 blocks, 1192
passed, 0 failed, 0 ignored, 2 filtered out**, `CARGO_EXIT=0`. 1194 enumerated
less the two the command skips is 1192, which is the number both READMEs state
and the number `scripts/check-doc-claims.py` re-derives on every run. The p95
budget is in the skipped set for that command and is asserted on its own
instead: measured in release at p95=1490us against a 6000us budget.

**Debug — plain `cargo test --workspace --locked`**, at `8032dfe`, on this host:
**87 blocks, 1193 passed, 0 failed, 1 ignored, 0 measured, 0 filtered out**,
`CARGO_EXIT=0`. The one ignored test is `uat_030_perf.rs`'s p95 budget, which
carries `#[cfg_attr(debug_assertions, ignore)]` because a latency budget
measured against debug ed25519 is a statement about `debug_assertions` rather
than about the product. 1193 + 1 is the same 1194 the release run reaches by a
different route, which is the useful part: the enumeration is one number and the
passed/ignored split is per profile. That is why neither README may say
"0 ignored" without naming the profile — the sentence is the claim, and the
claim is true in one build and false in the other.

### What this freeze is, and what it is not

It is a constraint on new work: no adapters, no planners, no new providers, and
the four open items above stay open rather than being closed by shipping around
them. It is not a v1.0 tag, and nothing in this section should be read as one.

Two of the four open items cannot be earned from this machine at all — the
third-party review needs a reviewer who is not the author, and signed
reproducible artifacts need a release host that holds a signing key. The other
two are work, not obstacles: the UAT matrix and a release-to-release upgrade and
rollback test are both things this machine could do, and neither has been
started. The distinction matters, because "not performable here" is an excuse
and "not started" is a debt.

### One number in this section is not yet a number

The UAT coverage figure above — "29 of 40 ids claimed" — is not a single
well-defined quantity, and a freeze should not cite it as if it were measured.
Three readings of the same 40 defined ids give three answers: the pipeline
guard reports 29 claimed by a test header plus 5 more implied by filename, and
a wider reading of the same header region finds 35. The difference is entirely
in how much of a test file counts as its header. Until one definition is
written down and the guard implements that one, the coverage claim is
`unmeasured`, and the 5 ids with no evidence under any reading are the honest
starting point for the remaining work.

---

## M14 — Credential workflow adapters (R3)

The pipeline the rebaseline puts at R3, ahead of the M11 residual:
`discover → safe parse → plan → adopt → binding → project → execute → verify →
scrub → receipt`. **R3.A.1 builds the first two steps and the surface they
report through.** `plan` is R3.A.2 and `adopt` is R3.A.3, and both are started: R3.A.2 is sectioned below and landed in `7e5fa34`, R3.A.3 in `56b3182`. What is genuinely not started is everything after `adopt` — `binding`, `project`, `execute`, `verify`, `scrub`, `receipt`.

The exit criterion for R3 is *"a new adapter addable without touching broker or
domain"*, which is a statement about the shape of the tree rather than about how
many adapters exist. So the first increment is the shape: a crate that depends
on the vocabulary and on nothing else.

### R3.A.1 — describe a tool's configuration without reading its secrets

`crates/integrations` is a new workspace crate. It depends on `asv-domain`,
`serde`, `serde_json`, `sha2`, `thiserror` and `libc`, and on **nothing that
lends**. That is the constraint that makes the rest of the design fall out
rather than be argued for: `discover` reads files its caller could already
read, so a round-trip through the broker would authorize nothing, and a step
that *could* reach a vault is a step that could be made to. `plan` and `adopt`
will need the broker; `discover` must not be able to use it.

Measured: **40 rows green** in `asv-integrations` (10 fingerprint, 17 npm, 11
audience, 2 crate), **5 rows green** in the product vertical
`crates/broker/tests/r3a_npm_discovery.rs`, **23 mutations, 23 red, 0 survivors,
0 compiler-refused, 0 unmeasured** across four passes (`leak`, `parse`,
`fingerprint`, `audience`).

**The report has nowhere to put a secret, so it cannot carry one.** This is a
property of types rather than of redaction: a selector is reported as *field +
registry + length*, and a setting this parser does not model is recorded as
`Opaque { len }` — present and undescribed, which is a different statement from
"there is nothing here". No digest of a value is published, deliberately: a
digest of an extracted value is an oracle, and `_auth` is base64 of
`user:password`, which is low entropy. The digest *of the file* is safe and is
what the fingerprint publishes. The two central rows assert over the
**serialised JSON** and the `Debug` rendering rather than over the struct,
because a claim about today's fields is not a claim about what a caller
receives — and what a caller receives reaches a terminal, a log and an agent's
context.

**`RegistryAudience` is its own type, and not `asv_domain::Authority`.** This
was the one architectural finding worth the detour. Reusing `Authority` for a
registry imported a restriction that belongs to a different question: `Authority`
rejects a port and a single-label host, both by design, because it answers *the
audience of an API* — a multi-level host. A registry answers *an endpoint*, and
`localhost:4873` is Verdaccio's default, i.e. the most common private npm
registry there is. Reusing the type would have made the adapter refuse the
registry it exists to find. So `RegistryAudience` accepts `host`, `host:port`,
`[ipv6]` and `[ipv6]:port`, and refuses a scheme, a path, userinfo, an
unbracketed IPv6 literal, port zero or out of range, and an empty label — each
because guessing which of two readings the operator meant is how a credential
reaches a service they did not name.

**The fingerprint is integrity, not confidentiality, and the line is drawn
between what another user can write and what they can read.** Refused: not a
regular file, a symlink whose target is outside a *named* root, a foreign
owner uid, and group- or world-writable. Reported rather than refused:
group- or world-readable — npm itself writes `.npmrc` at 0644, so refusing it
would make discovery fail on almost every real machine, which is a tool that
cannot see the file it exists to fix. The symlink allowance is compared
component-wise, because a string prefix hands out `/home/u/.config-backup` to an
allowance meant for `/home/u/.config`.

**The parser is fail-closed about its own ignorance.** `include:` refuses the
whole file, because `plan` cannot revalidate a file `discover` never read. A
line that is not `key = value` refuses the file, because reporting the lines
that did parse produces a report that reads complete about a file whose meaning
the parser does not have. `${VAR}` is **named, never resolved** — the
environment is the caller's, not the file's, and the name is what an operator
needs in order to know what to project. No registry is invented for a file that
declares none.

**The campaign found three rows that could not fail, and all three were
defects in the rows rather than in the code.** They are recorded because the
pattern generalises to every campaign in this file:

- A row that read the environment reference but left the variable **unset**
  could not distinguish a resolver from a non-resolver: an unset variable makes
  both return the literal's length. It now sets a canary of a different length
  and asserts the two lengths differ, which is what makes the row falsifiable
  at all. The property being measured is *never reads the environment*, and a
  read that returns `None` is invisible to a row that has nothing to resolve.
- Two mutations aimed at the branch that records an unmodelled setting were
  filed against a row whose fixture is an `//`-prefixed key — and that returns
  long before the branch, because an unrecognised *auth field* is
  `AuthField::Unrecognised` and never becomes a `SettingValue` at all. **Two
  rows that both end in the word "unrecognised", neither measuring the other's
  code.** Both mutations were re-filed against a row that owns the property,
  and the auth-field path — which had no mutation of its own — was given one.
- One mutation was `compiler-refused` rather than red. It removed the `include`
  guard by deleting two lines, which moved `key` and `value` and left `E0382`
  for every later use. A compile error says the mutation was **malformed**,
  and a malformed mutation measures nothing about the property it was written
  to attack; the base harness reports it as a stronger answer than green, and
  for a campaign that is not true. Rewritten as `if false`, which still
  type-checks, still borrows and does not run. The row went red.

**`discover` runs the real binary.** `asv integrations discover --json` emits
`asv.discovery/v1`, and emits it on the error path too, so a caller parsing the
output has one shape to handle. `--allow-symlink-root` is the only way to widen
the fingerprint's refusal, it is a named root rather than a flag, and an unknown
family exits non-zero with the list of families this build knows.

**Not closed, and not simulated.** The `ForeignOwner` refusal is real and
**cannot be falsified in this environment**: it needs a second uid to `chown` to,
and that needs privileges this session does not have. Declared rather than
mocked. A host with a foreign-owned `.npmrc` has never been observed here.

**Two houses to note before a later step depends on them.** The new crate *does*
read the process environment, in its tests, to prove it does not read it
otherwise; `D9`/`uat_017_env_scan` forbids `std::env` in **broker and
connector**, and this is a file-reading surface that depends on neither, so the
rule is untouched — but the distinction is worth writing down rather than
discovering later. And `discover` reaches no broker, which is correct for this
step and will have to change at `plan`.

### R3.A.2 — the strategies available, and the one that says nothing can be done

`asv integrations plan npm --json`. The design doc
(`docs/asv-agent-first-security-evolution-v2-2026-10-02/04-CREDENTIAL-WORKFLOW-ADAPTERS.md`
§2) defines this step as *"produce estrategias disponibles ordenadas por
postura"*, so a plan is **advice**, and advice has a failure mode code does not:
it can be *confidently wrong*.

Measured: **20 rows** in `asv-integrations` (60 in the crate), **7 rows** in the
product vertical `crates/broker/tests/r3a2_npm_plan.rs` — a real `VaultStore`, a
real `asv-brokerd`, a real socket, a real `asv` client and a real `.npmrc`
holding a real token — and **18 mutations across four passes**: 18 red, 0
survivors, 0 compiler-refused, 0 unmeasured.

**The dependency is inverted, and that is the whole design.** `plan` cannot
answer without knowing what credentials exist, and only the broker knows that,
so the naive shape is for the crate to ask — which would put the credential
plane one dependency away from the crate whose entire justification is holding
none. So `plan_npm(&NpmDiscovery, &[CredentialMetadata]) -> IntegrationPlan` is
a **pure function**, and the CLI supplies the inventory. The day the broker
reports a credential's audience and scope, the CLI's index changes and *this
file does not* — which is R3's exit criterion demonstrated rather than asserted.

**The three postures have independent preconditions, and each refusal is a
control rather than a gap.**

- `STRONG_SECRETLESS` — the broker substitutes the value, so the tool never
  holds it. Available for anything not database-shaped.
- `SHORT_LIVED_EXPOSURE` — only for `OAuth2`, because only OAuth2 has something
  to *mint*. A static bearer token written to a file and deleted afterwards is
  not a short-lived credential; it is a static credential that briefly existed,
  and offering the posture **renames the risk instead of reducing it**.
- `RAW_PROCESS_EXPOSURE` — refused when `Exportability::NonExportable`, which is
  the **default**, so this is the common path. The value cannot leave the vault,
  so writing it out is not something ASV can do, and offering it would send an
  operator to `adopt` for a step that fails.

**Two credentials come back `ambiguous`, and that is the interesting result.**
The broker reports a credential's `kind` and **not** the audience it is
registered for — `Request::ListCredentialMetadata` returns `{id, label, kind,
exportability}` and no wire surface reports more — so when a vault holds two
bearer tokens, nothing in `plan`'s inputs distinguishes the registry one from
the CI one. Choosing the first would be a coin flip presented as a decision, so
`plan` names both and `adopt` disambiguates. **This is a real gap in the input,
reported rather than papered over**, and closing it means a protocol change that
R2.F.3 owns, not a planner that guesses.

**§7 is honoured structurally.** `PlanEntry` names credential, audience and
operations together, because a binding recorded as `npm-token` is the thing the
step exists to stop, and §8's posture order *is* the declaration order of
`Posture` — one ranking, written once, so the order in the JSON cannot drift
from the order the code produces.

**§6 is a promise about bytes, and `revalidate` is what keeps it.** A plan that
survived a changed file is worse than no plan, because it looks like an answer.
Drift is refused as `CONFIG_CHANGED`; a comparison by digest alone would let a
file swapped for an *identical* copy pass, so the inode is compared too; and a
vanished file is `Unreadable`, not `Ok`.

**Two defects found, one of them in the verification itself.**

- The design doc that defines `CredentialBinding` **was cited earlier in this
  file as non-existent**. It exists, committed in `0ea4881`, and R3.A.1's
  `RegistryAudience` argument would have read differently against it. The error
  was a working note, never a committed claim; recorded because the same
  "I could not find it" reasoning is how a referenced authority gets invented
  around.
- **An orphaned module compiles and passes.** R3.A.2's first run reported
  **40 tests green** while `plan.rs` and `plan/tests.rs` were compiled by
  nobody: the other session's release work restored the *tracked* `lib.rs` to
  HEAD, `pub mod plan;` went with it, and the two *untracked* files it named
  nothing about were simply not part of the crate. No warning, no error, no
  failing row — the only signal was that the count did not move. A deliberate
  compile error appended to `plan/tests.rs` did not fail the build, which is
  what proved it. **The defence is the product surface**: `asv integrations plan`
  cannot exist if `plan` is unreachable, so the CLI wiring is the structural
  guarantee and the crate count is only a smoke signal.

**The campaign found that this stage's headline property is not falsifiable
here, and that is the finding.** The first `leak` mutation carried a credential
value into `PlanEntry` and the row stayed green — because **no mutation of this
crate can make the plan leak one**: its two inputs carry no secret, since the
parse result records a value's *length* and the inventory a label, a kind and an
exportability. The property is **structural, not behavioural**, so it is not
mutation-falsifiable at this layer, and a mutation that cannot be written is not
evidence either way. The claim is therefore split where it can be measured: the
input half by `npm_discover_falsify.py`'s `leak` bucket, which does turn red when
a value is added to the parse result, and the output half by a row run against a
real token in a real fixture. What replaced the bucket is the risk that *is*
reachable here, and it is a plan's real failure: **saying something it was not
told** — naming an audience its selector did not carry, or a length its file did
not have.

**Not started, and not simulated.** `adopt` — the step that actually moves a
credential — is untouched; this stage names what *could* be moved and refuses
what could not. `OperationFamily` has **no `Registry` variant**, so the shape
rule is asked directly against `CredentialClass` rather than through
`CredentialClass::backs`; that gap belongs to `asv-domain` and to R2.F.3, and is
recorded here rather than taken unilaterally in a crate another session is
editing.

### R3.A.3 — adopt: the first step that moves a credential

`asv integrations adopt npm --file … --audience … --field … --label … --from-plan …`.
The first stage where a secret exists in the process at all, and the first one
that changes the machine rather than describing it.

Measured: **15 rows** in `asv-integrations` for this stage (75 in the crate),
**7 rows** in the vertical `crates/broker/tests/r3a3_npm_adopt.rs` against a real
`VaultStore`, a real `asv-brokerd`, a real socket and a real `.npmrc` holding a
real token, and **11 mutations across four passes**: 11 red, 0 survivors, 0
compiler-refused, 0 unmeasured.

**The claim is two halves or neither: the credential is in the vault, and the
file is byte-identical afterwards.** A credential moved with the file already
scrubbed has skipped four steps of §10 and a human; a file untouched with
nothing in the vault has moved nothing. The row asserts both on the same run.

**Doc 04 §10 is why this step does not write the file, and the receipt says so.**
§10's order is import → verify vault → verify new integration → negative bypass
test → human approval → scrub → rescan → receipt. This command does the first
and reports the other five as `outstanding`, so an import can never be mistaken
for a completed migration. A scrub is the single most consequential thing this
stage *could* do, and it is the one thing a "while we are here" tidy-up would
do — which is why the campaign has a mutation that performs one, and why the row
asserts the bytes rather than trusting a code review.

**The crate's law is narrower than "never touches a value", and stating it
narrowly is what makes it true.** `discover` and `plan` never materialise a
value and cannot even reach a vault. `adopt` has to produce one, because moving
it *is* the job. So the law this module keeps is **"cannot reach a vault"** — no
client, no socket, no session — and the ordering that makes it safe is that
*which* credential to move is decided before the value exists, which is why
`NpmAdoption::extract` takes a selector rather than returning candidates.
`SecretString` is the return type, and it implements **no** `Display` at all, so
a format string that would print the value does not compile rather than needing
review.

**Six refusals, each a control rather than a gap.** Drift since the plan; a
`${VAR}` with no value in the file to move; an empty value; a misspelled field; a
field set twice for one registry, where npm's effective value is the last and
guessing would import something the tool would not use; and a selector whose
registry the file does not mention. A refusal is printed to a terminal, so the
error type carries no value either — there is a row for that, because an arm that
reaches for `value` to be helpful reads as better diagnostics and is the exact
shape of leak that survives review.

**§6 was unreachable from the product until it was made reachable.** The first
implementation fingerprinted the file in the CLI and handed that fingerprint
straight to `extract`, so the drift check compared the file against itself: it
could detect a concurrent edit during the command and nothing else, and "changed
since you planned" was impossible. `--from-plan` now takes the fingerprint from
the `plan` output this import answers, and the command **refuses without it**
rather than importing unchecked. The plan is what makes the import checkable.

**Three defects found, two of them in the verification itself.**

- **The selector's registry was never checked.** `extract` matched on the field
  name alone, so an operator asking to adopt the credential for
  `other.example.test` was served the value written for `registry.example.test`
  — the wrong credential imported, under a receipt naming the wrong audience,
  looking like a success. A field name is half a selector's identity and the
  half that is easy to check is the half that gets checked first.
- **`IntegrationPlan` could not be read back.** It derived `Deserialize` while
  carrying `schema: &'static str`, which compiles and cannot work: a `&'static
  str` deserialises only from data that already lives forever. **A derive is
  only instantiated when something asks for it**, so the defect looked clean in
  review and broke the moment `adopt` needed to read a plan off disk. All three
  schema fields are now `String`, and a round-trip row pins it.
- Two campaign mutations were aimed wrong and reported as survivors when they
  were **failed experiments**: one used `FileFingerprint::matches` on the
  assumption it was a digest comparison (it compares inode too, so it still
  caught the replacement), and one put the *key* into a refusal message while the
  row was about the *value*. A mutation that does not remove the thing its row
  is about has not falsified anything, and reporting it as a survivor would have
  been the honest-looking mistake.

**Not started, and not simulated.** The projection — leaving behind something
that points npm at the broker instead of at a token — is R3.A.4, and `adopt`
does not do it. **A second import of the same selector is not refused**, because
the vault does not report what audience a credential is registered for, so
"already adopted" is not a question this step can currently answer; the same gap
that makes `plan` report two bearer tokens as ambiguous. Recorded rather than
guessed at.

### R3.B.1 — Maven, and the first measurement of R3's exit criterion

`asv integrations discover --family maven`. The second family, and the one that
had to *earn* the criterion rather than assert it.

**The exit criterion is "a new adapter addable without touching broker or
domain", which is a statement about the shape of the tree and not a statement
about how many adapters exist.** With one family it was untested, and untested
criteria are aspirations. What adding Maven actually touched:

```text
crates/integrations/**      the family itself
crates/cli/src/main.rs      one match arm, one prose printer
── nothing else ──
crates/broker/src/  crates/domain/src/  crates/ipc-protocol/src/  crates/connector-http/src/
```

**It cost one shared type to get there, and that is the finding.** `Candidate::origin`
was typed `npm::Origin`, so a second family's precedence could not be expressed
without either borrowing npm's three levels or changing it. Lifted to the crate
root with a fourth level — `Tool`, where the tool and the operating system
disagree about the name for the same directory, which is Maven's
`$MAVEN_HOME/conf` and is not a "global". The lift immediately broke the CLI's
npm printer on a non-exhaustive `match`, which is the closed enum doing its job.

Measured: **30 rows** in `asv-integrations` for Maven (105 in the crate),
**6 rows** in the vertical `crates/broker/tests/r3b1_maven_discovery.rs` against
the real `asv` binary and a real `settings.xml`, and **21 mutations across four
buckets**: 21 red, 0 survivors, 0 compiler-refused, 0 unmeasured.

**§5's four XML requirements, and three of the four are the parser's.** DTD
disabled and external entities disabled are structural (`roxmltree` refuses a
DOCTYPE with `DtdDetected` before reading it, and an undeclared entity reference
is an error rather than a fetch); network resolution is structural (no
dependencies, `#![forbid(unsafe_code)]`, no `std::net`); **size and depth limits
are ours, and the depth one was a documented lie until a row proved it.**

The module first documented `nodes_limit` as "the ceiling on nesting". It is not.
`roxmltree` appends an element's node when it reaches that element's **closing**
tag (`parse.rs:781`, in the `Close` arm), so a document nested `N` deep recurses
`N` deep before a single node exists to count — the ceiling is consulted on the
way back out, by which time the stack is spent. Measured: a document nested 2049
deep **aborted the process**, and `nodes_limit` was never read. So there is now a
`MAX_DEPTH` of 64, enforced by a quote-aware pre-scan on the text before the
parser is handed anything, and three separate ceilings with three rows each —
because a ceiling that refuses everything is not a ceiling.

**`<server><configuration>` is where Artifactory and Nexus keep an API key**, and
an adapter written to the obvious shape models only `<username>`/`<password>`: it
reports one credential and silently omits the second. An element the adapter does
not model is therefore *named and measured* (`undescribed: [{element, len}]`),
never read — present-and-not-described is a different claim from absent. The same
reasoning strips `user:password@` from a mirror URL, which is a credential more
often than anyone expects and which no one greps for.

**Two report decisions that a first reading would have got wrong.** A
`${env.ACME_TOKEN}` password is reported with `password_len: null` and the
variable's name — the 19 characters in the file are text standing in for a
credential, not the credential, and a report that offers both numbers is offering
one plausible-looking wrong answer. And a `<proxy>` with no `<active>` is
inactive, because the opposite default tells an operator a credential path is
live that Maven will not take.

**The policy this family has and npm does not: refuse the file, keep the report.**
A world-writable or foreign-owned `settings.xml` becomes a finding and the run
still succeeds. Absence is not a finding — most machines have no `settings.xml`
— and the prose does not say "none was found" when a refusal is pending, because
that is a claim about a file that exists.

**A row of R3.A.1 broke, correctly.** `an_unknown_family_is_refused_with_the_list
_of_what_this_build_knows` used `maven` as its example of an unknown family. It
was right until Maven existed. Replaced with a sentinel that cannot become a real
family, so the row points at the refusal path rather than at the current contents
of the enum — a row wired to a *future* family has a shelf life, and its
expiry looks like a defect somewhere else.

**Not started, and not simulated.** `plan` and `adopt` for Maven do not exist:
this family is `discover` and safe parse, which is what R3.B specifies. Mirrors,
`<profiles>` and the repository `<id>` chain are read but not yet bound. The §6
TOCTOU revalidation is not reachable because there is no plan to revalidate.
`env_reference` names a variable and never resolves it — the environment is the
caller's, not the file's. The `registry_audience`/`asv-domain` audience gap that
blocks a Maven binding is unchanged and still belongs to R2.F.3.

### The broker's accept loop, and the two rows that were missing for it

`crates/broker/src/lib.rs` and `main.rs` changed shape, and until now no row
in this file described that change or measured it.

**`BrokerState` stopped being `&mut`.** `serve` and `handle` took
`&mut BrokerState` because the accept loop called them once per connection
from a single thread. So nothing in the type system had ever asked whether two
connections could be in flight at once — the property was enforced by having
exactly one thread, which is a property of `main.rs` rather than of the state,
and not one a reader can check. The credential inventory now carries its own
`Arc<Mutex<Vec<CredentialMetadata>>>`, `connectors` is
`Box<dyn ConnectorFactory + Send + Sync>`, and a `const _: ()` block asserts
`Send + Sync` at compile time, so the first field to lose the property is a
build error rather than a data race.

**The loop became a thread per connection, bounded by a cap.** Each accepted
socket is served on its own thread with its own 5s read/write deadline, and
`MAX_IN_FLIGHT_CONNECTIONS = 64` refuses rather than queues. The counter is
incremented before the spawn and decremented inside the thread, so a burst
arriving faster than it is served cannot race past the cap. Unbounded threads
would be the same denial of service the sequential loop had, moved somewhere
less visible: a peer opening thousands of sockets costs thousands of stacks.

**Measured now, measured before in neither.** Two rows in
`crates/broker/tests/concurrent_connections_do_not_queue.rs`, against the real
`asv-brokerd` binary and a real socket:

| Row | Measured | Bound |
|---|---|---|
| `an_honest_client_is_answered_while_a_silent_peer_is_still_open` | **604µs** | 2s |
| `a_burst_past_the_in_flight_cap_is_refused_rather_than_queued` | **149µs**, after 64 in flight | 5s socket deadline |

Both numbers are printed by the rows rather than only asserted, because a bound
nothing approaches is indistinguishable from a bound that is simply far away.
The first row is falsifiable rather than decorative because a serialised loop
cannot answer before the silent peer's 5s deadline expires — so 604µs is not
"fast", it is a statement about concurrency. The second separates *refused*
from *waited its turn*: 149µs is three orders of magnitude inside the deadline,
so nothing was served and then abandoned.

**The row that claimed this coverage did not have it.**
`idle_connection_does_not_block_the_broker.rs` bounds its honest client at 20s
against a 5s socket deadline, so it passes against a broker that waits the
silent peer out *and* against one that answers immediately. Its module doc also
still described the loop as calling `serve` "before it accepts again", which
stopped being true with this change. The row is still worth running — it is
what a mutation removing `set_read_timeout` will exhaust, through the real
binary — but its doc now says plainly that it is not the sharpest statement of
the property, and names the file that is.

**Not closed, and not simulated.** The cap refuses *everyone* past 64,
including an honest agent: a flood is indistinguishable from a busy install at
the accept loop, so a peer that opens 65 sockets can lock out the 65th honest
agent for up to 5s. That is the deliberate trade named in `main.rs` — a visible
refusal beats an invisible stall — and it is a policy question this cycle does
not settle. Separately, the TCP tunnel listener carries its own `InFlight`
gauge with its own accounting, and no row here covers that path either. And
`main.rs` still has no falsification harness at all: the two rows above are
integration rows against a spawned binary, which is a weaker kind of evidence
than the campaign the connector and registry crates carry.

---

## v1.0 — Certified product line

> **Sequenced by the rebaseline above; scope below unchanged.** `V1-C0`–`V1-C5`
> below is the historical path and is kept as the record of what was planned.
> The path actually followed to v1.0 is `R0`–`R5` in *Critical path — rebaselined*
> ([ADR-0020](../adrs/0020-adoption-before-hardware-tpm2-leaves-the-v1-critical-path.md)):
> TPM2 is **not** among the v1.0 blocks and sits at R8, and M14/M15 enter at R3/R4
> ahead of the M11 residual this list puts third. `V1-C4` is superseded in
> sequence only — M12's scope, exit criteria and exit UATs below are untouched,
> and M12 remains open.

Minimum supported story:

- KeePass-like local dashboard,
- local encrypted vault,
- non-exportable credentials,
- session launcher,
- SSH/Git SSH secretless,
- HTTP/service broker,
- PostgreSQL proxy,
- policy/approvals,
- audit,
- Linux hardened mode,
- ~~transparent eBPF bridge only if M8/M9 passed~~ — **withdrawn**: M8 is
  NO-GO, so the v1.0 story is the explicit CONNECT bridge of M9,
- compatibility worker clearly labelled,
- CLI + optional MCP control surface.

### Exit

Release aggregation, not an independent gate: it is the union of the milestones
above. Completion is DELEGATED to `16-SECURITY-RELEASE-GATES`.

### The path from v0.28.0 to v1.0

M8 is decided and M9 is closed, so the remaining work to v1.0 is not a matter of
finishing the transparent bridge. It is the sequence below. The ordering is
deliberate: C0 first, because writing more code on top of an authority that
misdescribes the product compounds the error.

```text
CURRENT: v0.29.0
│
├─ V1-C0  Rebaseline / truthfulness        ← this document, this cycle
├─ V1-C1  M7 residual: agent uid != broker uid
├─ V1-C2  M9 productionization residuals
├─ V1-C3  M11 against a real OAuth2 provider
├─ V1-C4  M12 against real TPM hardware   ← superseded: R8, not a v1.0 block
│
├─ V1-C5  M13 final certification
│
└────────────── v1.0
```

- **V1-C1** closes the M7 residual recorded above. **Done, in two parts with
  different owners.** The *proof* is delivered: UAT-003's dropped clause now
  runs against the kernel with the same-uid attacker, a `EACCES`/`EPERM`
  requirement, a control that must succeed against a dumpable sibling, and a
  demonstrated guard that the attacker lacks `CAP_SYS_PTRACE`. Writing it also
  found and fixed a real defect beside it — `--harden` was sandboxing the
  broker out of its own passphrase file. The *identity* is **host-dependent**:
  `asv-brokerd` under a separate OS uid, with the service ownership that goes
  with it, needs a system account, and creating one needs privileges this
  build host does not grant. No new sandbox framework: seccomp, Landlock and
  cgroups are already M7's, and the gap was a declared read path, not a
  missing control.
- **V1-C2** productionizes what M9 verified but did not ship as a network
  surface: a production listener wiring `relay_substituted` into a running
  `asv-brokerd`, real CONNECT lifecycle, more than one request per tunnel where
  the protocol allows, a formal decision on freshness and replay, shutdown and
  revoke mid-tunnel, stress and cancellation, and observability that carries no
  sensitive material. The three limits recorded on M9's gate row are its scope.
  **Delivered in full, measured.** The listener, the wiring into a running
  `asv-brokerd`, real CONNECT lifecycle, multi-request tunnels, a formal
  freshness decision, shutdown and revoke mid-tunnel, stress and cancellation,
  and observability that carries no sensitive material. The six criteria are
  stated with their witnesses in *V1-C2 — the six criteria* below, and each one
  names the test that carries it rather than the feature that was intended. Two
  things are **not** claimed there and neither is small: the destination leg is
  verified against a locally minted CA rather than a public one, and the default
  for `--connect-roots` is only half falsifiable. See *V1-C2 — what is built and
  what is not* below for the history.
- **V1-C3** turns M11 from a prototype into a vertical. The `ClientCredentialsIssuer`
  becomes a *reference implementation* rather than the evidence of closure, and
  the closure is an HTTPS POST to a real token endpoint producing a short-lived
  credential that reaches an operation and is then revoked, expired and audited.
  M15's strategy selection is only meaningful over provider-backed strategies,
  so this is a prerequisite and not a parallel.
  **Half of it is delivered and the half that is not is the one that needs a
  host.** The vertical exists and is measured: a client secret in a real vault
  is traded for a short-lived token, the secret stops at the broker, expiry and
  revocation are refusals, the audience is bound, a provider that stops
  answering stops the operation, and the exchange is on the provider's record.
  The provider is **self-hosted** — a real authorization server implementing
  RFC 6749, RFC 7009, RFC 7662 and RFC 8707, not a third-party IdP — and
  nothing about the broker's behaviour depends on that choice except its
  compatibility with someone else's. So M11 is `implemented` and V1-C3 is
  **still host-dependent**, now for one stated reason rather than for all of
  them.
- **V1-C4** does the same for M12 with a real TPM: a hardware adapter,
  enrollment, recovery before any destructive step, PCR and device-state change,
  a theft test, software ↔ device-bound migration, and `Unsupported` rather than
  simulated success on hardware that cannot do it. `SoftwareTpm` stays for fast
  tests and is never the evidence. This also unblocks M17.
- **V1-C5** is the freeze. No adapters, no planners, no new providers — only the
  M13 checklist above, done properly, against a release host.

**V1-C3 and V1-C4 are host-dependent.** Neither can be closed on a machine with
no OAuth2 provider to point at and no TPM. That is a property of the work, not
a blocker to route around, and it is why the two are late in the sequence
rather than early: everything executable on an ordinary machine is executed
first.

### V1-C2 — what is built and what is not

The first V1-C2 delivery adds `crates/broker/src/connect_listener.rs` and the
cancellation surface it needs on `Bridge`. It is worth being exact about the
split, because M9's gate row listed three limits and only one of them moved.

**Delivered and `verified` — the lifecycle of a CONNECT listener.**

- `ConnectListener` binds, accepts, and gives every connection its own task, so
  one hostile client cannot stop the broker serving the next.
- `read_connect_head` had **no deadline at all** before this. A client that
  opened a socket and said nothing held a thread indefinitely, and no test could
  catch it because no test ran a listener. It now has one, and it is bounded.
- `ShutdownSignal` carries shutdown and per-session revocation as one mechanism,
  because they are one poll, and the difference is only who asked.
- A tunnel that is **already established** is torn down by a revocation or a
  shutdown. `serve_connect` disarms the read timeout before handing the socket
  to rustls, so without re-arming it a tunnel is a tunnel no signal can reach —
  which is the shape a revoked agent actually produces.
- Every connection produces a `ConnectionOutcome`, including the ones discarded
  before a destination was parseable. A listener that cannot say what it dropped
  is not auditable; the first version returned nothing for those, which is how a
  dropped connection became invisible rather than recorded.

**Two claims the first delivery had to withdraw after falsifying itself.**

1. The `head_deadline` arm of `Bridge::is_pollable` and `arm_read_timeout` was
   **dead code**: `with_head_deadline` was called from exactly one place, and
   always together with `with_cancel`, so `cancel.is_some()` was already true
   and the deadline never decided anything. Dropping the arm left every test
   green. The clause is now exercised by a bridge that has a deadline and
   *nothing else* to interrupt its read.
2. The reciprocal revocation test was **blind to a global kill**, which is the
   mutation that mattered most. It revoked session B and then sent session A's
   request — so the request was already in the socket buffer,
   `read_byte_cancellable` returned on its first successful read, and the branch
   that consults `cancel_reason` was never reached. A relay that consults
   nothing, and one that is told "cancelled" for somebody else's session, are
   indistinguishable from outside a tunnel that never has to wait. The
   revocation now lands while the tunnel is parked on the poll, and the test
   asserts it is *still running* afterwards.

**One claim that could not be made deterministically, and is not claimed.**
`ShutdownSignal::wait_stopped` calls `notified.enable()` before checking the
stopped flag, which closes the window in which a `stop()` lands between the
check and the `await`. Closing that window requires a yield between two
statements *inside a single poll*, which cannot be provoked from a test, so
there is no deterministic test for it. The `enable()` is correct and stays; the
window is recorded as a residual rather than dressed up as covered.

**Not delivered — M9's third limit stands unchanged.**

- ~~Nothing in `asv-brokerd` starts this listener.~~ **Delivered** in the second
  V1-C2 delivery: `--connect-listen ADDR`, read from `argv` because D9 forbids
  `std::env::var*` in broker production sources, and refused without `--vault`
  because a tunnel with no credential behind it can only ever be a refusal.
  The allow-list ships **empty**, so the listener refuses every destination
  until an operator widens it. That is the correct posture for a surface that
  did not exist a milestone ago, and widening it is M14's work where the
  destinations are known.
- One request per tunnel. Not yet decided, and the decision is a design question
  about what a surrogate is worth, not a bug.
- The destination-derived nonce is **not** freshness. A formal decision is
  still owed.
- ~~Observability reaches `ListenerReport` and stops there. It is not yet wired
  to the audit chain.~~ **Delivered** in the third V1-C2 delivery:
  `SharedSubstitutionAudit` and `ChainReport` append into the broker's own
  durable chain, so a CONNECT outcome and the request that produced it land in
  one log and verify against one chain. See below for what the chain is allowed
  to carry, which is not the same as what the operator's log line carries.
- The `main.rs` line that hands the listener its `SessionStore` is **not
  covered by a test**, because an integration test does not build the binary.
  What the suite pins is the construction the line performs, and a falsification
  run showed that pinning it is what catches the mistake: see below.

**A third finding, and the one this delivery nearly shipped.** The first wiring
gave the listener a fresh `SessionStore::new()`. It compiled, bound the port,
accepted, resolved no proof, and refused — and every one of those behaviours is
what a *correct* listener does when a stranger connects. A test asserting "the
listener answers" passes on it. That is M11's shape exactly: a prototype with
tests, calling nothing real, and the difference is invisible from outside.

The fix was to share the broker's own state. `BrokerState::sessions` and
`BrokerState::surrogates` are now `Arc<Mutex<…>>`, because two stores would mean
a session opened over the socket is unknown to the CONNECT path and a surrogate
minted by `MintSurrogate` is un-redeemable there. That is a correctness
requirement, not a convenience, and it is the decision `connect_listener`
deliberately declined to make.

**A control can be two halves that each look redundant.** Proof resolution
compares the presented key blob against the one the session registered, and
verifies the signature against the *registered* key. A falsification run found
that removing the comparison alone leaves the suite **green** — the signature is
still checked against each session's own key — and that verifying against the
*presented* key alone also leaves it green, because the comparison still pins
them equal. Neither half is load-bearing on its own, and a mutation run that
only ever breaks one of them reports a suite with no hole in it. Breaking both
together is the fatal one: a stranger's own key and signature inheriting
whichever session is first in the table, which is the option ADR-0019
discarded. The harness now expresses multi-site mutations for exactly this
reason, and the surviving test fails with `Some(AgentSessionId(…))` where it
should have `None`.

**One more false claim, this time in a comment.** `issue_leaf`'s own doc said it
rejects bare IP literals. A probe printing what each host form actually does
says otherwise: `127.0.0.1` is accepted, and a trailing dot is accepted too. It
is not a hole — the allow-list is consulted before issuance is ever reached —
but a security comment that overstates what is rejected is the same defect as a
document that overstates what is verified, and it is now corrected in place with
the measurement next to it.

**A third delivery: the CONNECT path and the broker's requests end up in one
chain.** `BrokerState::audit` is now `Arc<Mutex<AuditLog>>` — the third shared
lock, and for the same reason as the other two: a listener and a request handler
that reach *different* logs produce a chain that verifies, because each half
verifies alone, and a record that is in neither. `SharedSubstitutionAudit`
records every substitution the tunnel performs, and `ChainReport` records the
outcome, including the connections that were refused before a destination was
parseable.

**The chain carries a class, never the error's text.** This is not a style
preference and it was forced by measurement. `parse_connect_target` builds
`BridgeError::Protocol(format!("{authority} has no port"))`, and `authority` is
bytes the client sent. Chaining that verbatim would put attacker-controlled
bytes into the durable log, so `refusal_class(&BridgeError)` maps an error to a
fixed vocabulary by **match**, and the full text stays in the operator's log
line, where it belongs.

**A class derived from a human-readable message changes when somebody improves
the message.** `ConnectionResult::Cancelled` used to carry a `String`, and the
test looked for `"head deadline elapsed"` while the code produced `"read
deadline elapsed"` — the test passed for months on a different string than the
one it named, and every such cancellation was recorded as `other` without ever
saying so. It is now `Cancelled(CancelReason)`, a value the type system carries
from the code that decided it, and renaming the operator-facing message can no
longer change what is audited.

**Sharing the audit behind a mutex deadlocked the audit read.** `AuditQuery`
answered a struct literal whose three fields each called `audit_chain!`. A
struct literal keeps its temporaries until the end of the expression, so the
second `lock()` blocked a thread forever on a mutex it already held —
`std::sync::Mutex` is not reentrant, and the fields had been written when
`audit` was a plain field where the second read was free. The admitted-reader
test hung the suite; the fix takes one guard and reads all three from it, which
also makes `records`, `chain_head` and `dropped` one consistent snapshot rather
than three reads that could straddle an append.

Finding that required a scanner, which required falsifying the scanner first.
The first two versions of it reported **zero** on the very expression that
deadlocked: one treated a block's `}` as a statement boundary and then excused
the finding whenever *any* acquisition in the region was bound to a name, and
the second split on commas — which is precisely where struct-literal fields
live, so it separated the simultaneous case into innocent pieces. Only the
third, which cuts on `;` and on a closing `}` and at `=>` (match arms are
alternatives, and their temporaries are never both created), fires on the real
defect and stays quiet on two sibling arms that each take a guard. A guard that
has never been seen to fail is not evidence of anything, including a guard
whose subject is a bug that has already happened once.

**Still not delivered.** One request per tunnel — not yet decided, and the
decision is about what a surrogate is worth. The destination-derived nonce is
still not freshness, and the formal decision is still owed. The `main.rs` line
that hands the listener its `SessionStore` is still uncovered, because an
integration test does not build the binary; the suite pins the construction, not
the line.

### V1-C2 — freshness and replay: the decision, and the claim it withdraws

`proof_nonce` is `SHA256(len(key) ‖ key ‖ host ‖ port)`. It binds a proof to a
destination, which is worth having, and it is **not** freshness. That much was
already recorded. What was not recorded is that the justification written next
to it was **false**, and writing the decision down meant measuring it first.

**The withdrawn claim.** `proof_nonce` said a replay "is not a grant, because
the surrogate it would be spent with is single-use and was already spent the
first time". That is true of the first surrogate and of no other.
`SurrogateRegistry::mint` appends a record with no cap per session or per
credential, and the nonce binds to `(key, destination)` alone, so it cannot
tell two live surrogates apart. `one_proof_reaches_every_live_surrogate_of_a_
session` measures the consequence: a second, still-unspent surrogate of the
same session redeems under the same captured proof and returns the identical
`CredentialId`. One observed proof is a bearer for **every** surrogate that
session holds for that destination, for the life of the session.

The exposure is bounded, and the bounds are the reason this is a decision
rather than an incident. The attacker must still present a surrogate, and the
surrogate travels *inside* the TLS session the broker terminates, not in the
plaintext CONNECT head where the proof is. The destination is authorised
before the proof is examined at all. And no test, listener or attacker needs a
credential to observe the difference. So the honest position is that freshness
is **absent**, not that it is **bounded by the surrogate** — and a security
comment that gets this backwards is the same defect as a document that
overstates what is verified.

**A second wall, found while looking.** Nothing in the shipped product emits
`x-asv-session-proof`. The header name occurs in the broker and in two
documents; `proof_nonce` is called only from tests and from the broker's own
verification. So the live `--connect-listen` surface refuses every client for a
second, independent reason beyond the empty allow-list: not only is nothing
authorised, **no client can prove anything at all**. This is the same shape as
the `SessionStore::new()` finding in the second delivery — a surface whose
tests all pass because every test drives the producing side itself.

**The decision: a per-session counter, in the nonce, with a windowed replay
cache on the broker.** The three options and why the other two lose:

1. **Keep the nonce as it is and document the exposure.** Cheapest, and it
   leaves a live bearer whose lifetime is the session rather than the tunnel.
2. **A server-issued nonce.** Strongest against replay, and the reason it was
   already rejected in ADR-0019 stands: it costs a round trip *before* the
   CONNECT, on a path whose entire purpose is to serve clients that have no
   round trip to spend. It would make the security property true by making the
   feature unusable.
3. **A per-session monotonic counter folded into the nonce, with the broker
   refusing a counter it has already seen.** This is the one that is chosen.
   The client holds the counter in the session it already has open, so there
   is no new round trip and no clock agreement. The broker keeps a *windowed*
   set of spent counters per session rather than only the highest: two
   concurrent CONNECTs from one session would otherwise race, and a
   strict-highest scheme turns a concurrency accident into a spurious refusal.

The honest cost of the choice: a counter is state, and it is state that must be
bounded, released on session end, and reasoned about concurrently. It is not a
five-line change to a hash function, and it is deliberately **not** landed in
the same commit that recorded the finding.

**Why now is the right moment, and it is a narrow one.** No client exists, so
there is nothing to migrate and no deployed proof to invalidate. Once a client
ships, changing what the nonce commits to becomes a breaking change to a
protocol that is already v4. The window for making this correct is open
precisely because the surface is not yet reachable, and it closes the moment
the first real client can complete a CONNECT.

#### V1-C2 — the counter, implemented (fifth delivery)

`proof_nonce` now folds the counter in, the counter travels in the clear on
the wire as the middle of three dot-separated parts, and the broker spends it.
What it buys is **single use, not recency** — a proof is good once, and "good
once" is a different claim from "recent", and the documentation says so rather
than borrowing the word *freshness* for it.

**A proof with no counter is refused, not defaulted.** The lenient reading —
parse what is there, default the rest to zero — looks generous and is a
downgrade: every proof minted before counters existed would share counter 0,
the first arrival would spend it, and the rest would be refused for what reads
like a replay attack rather than a version mismatch. The test for this is
`a_proof_without_a_counter_is_refused_rather_than_defaulted`, and it pins a
wire-format decision that is otherwise invisible.

**Verify, then spend, in one method.** The counter is spent by the same call
that verifies the signature, because splitting it into `resolve` plus `spend`
would let a caller invert the order. The ordering is the half that is easy to
get backwards: a proof that does not verify must never reach the window, or
anyone who cannot sign could walk a session's counters forward until the
honest client's real counter looked stale — a denial delivered by a party that
never proved anything, and one the honest client cannot distinguish from an
attack. The test double honours the counter for the same reason: a double that
ignored it would let every replay test pass for the wrong reason, with the
refusal coming from the double rather than from the design.

**The window lives inside the session record, and there is one lock.**
`SessionRecord` holds `public_key` and `ReplayWindow` together, under the
`Arc<Mutex<SessionStore>>` the port already had. An intermediate version gave
the window its own `Mutex` because the trait method could only take `&self`,
and added a lock-ordering law to go with it. That was the wrong diagnosis: the
`MutexGuard` was already mutable, so the **trait** was the thing with the bad
shape, and the fix was to change the trait rather than to add a second lock.
Two things follow that a second lock would have cost. There is no
`store -> window` ordering to state and therefore no new class of deadlock to
reason about, and `EndSession` removes the record, so the window is freed with
it — no second map to keep in step, and a test that says so
(`ending_a_session_releases_its_replay_window`) rather than a memory number
nobody checks.

**The window is a bitmap, not a set.** `highest: Option<u64>` and `seen:
u128`: sixteen bytes of bitmap, fixed, no allocation on the hot path, and
"is this counter already spent" is a shift and a mask. A growing set of spent
counters would be a memory-growth lever handed to anyone who can complete a
proof, since the counters are attacker-supplied numbers. The capacity and the
policy are the same number — 128 — so there is no knob to tune.

**The first version of the window accepted stale counters, and was corrected
before it shipped.** It reasoned that an honest client cannot fall further
behind than the window, so a counter below the window must be an attack — and
then *accepted* it. That reasoning is about the honest client, and the caller
is precisely the thing that is not assumed honest: an attacker replaying an
old captured proof presents exactly such a counter. It now fails closed, and
`a_counter_older_than_the_window_is_refused_rather_than_accepted` is the test
that says so.

**The textbook rule is wrong here.** "Refuse anything at or below the highest
counter seen" is the version most designs reach for, and it turns two CONNECTs
a client issued concurrently into one tunnel and one spurious denial — a
liveness bug wearing a security costume, and one the honest client cannot
distinguish from an attack either. The window accepts an out-of-order counter
inside its range and refuses a replay of one already spent, which is the pair
of behaviours that match what a real client does.

**The caller no longer supplies a nonce.** `SessionProofs::resolve(key, nonce,
signature)` split one invariant across two components: the bridge built the
nonce, the resolver trusted it. A test written against that boundary failed to
fail, because the resolver verifies the bytes it is handed and has no idea
what they were *for*. The contract is now `authenticate(proof, target)`: the
nonce is derived inside, from `(key, destination, counter)`, so "verified
against the wrong destination" is unrepresentable rather than merely
discouraged. `ProofRejection` distinguishes `NoSuchSession`, `Replayed` and
`TooOld`, because a client that has fallen behind needs to tell that from an
attack, and both from a bug.

**The nonce says what it may mean.** `PROOF_DOMAIN` —
`asv/connect/session-proof/v2` — is hashed in before anything else. The same
session key signs other things, and ten bytes make it explicit that this
signature can only ever mean "CONNECT session proof v2". Bumping the constant
is a breaking change, which is the point.

**A test I wrote asserted something false, and the run said so.** The first
version of the counter test passed the old nonce to the resolver with counter
0 and expected a refusal, on the theory that the resolver would notice the
signature had not committed to that counter. It does not. The assertion was
wrong about the design rather than catching a hole in it, and it now lives
where the nonce is constructed — `a_proof_signed_for_one_counter_does_not_verify_for_another`.

**A sentinel for "empty" cost the whole property.** The window started as
`highest = u64::MAX`, which saves eight bytes. The age of a session's *first*
counter then came out as `u64::MAX - counter` — far older than the window — so
every session's first proof was refused as stale. Five tests caught it at once.
`Option<u64>` is twenty-four bytes and works.

**The fixtures had to learn the rule, and that is the evidence.** A mechanical
update gave every proof in `uat_010_connect_substitution.rs` counter 1, and
eleven tests went red. Nothing was broken: the fixture was minting a new proof
per tunnel from a session that had already spent that counter, and the broker
was right to refuse. The fixture now holds one counter per signer in that
party's own sequence, which is what a real client does.

**One test would have passed for the wrong reason.** `an_ended_session_stops_resolving`
re-presented the same counter after ending the session, so it would have been
refused as a replay whether or not the session still existed. It now uses a
fresh counter, and says why.

**Still owed, and not claimed by this delivery.** No client produces a proof,
so there is no end-to-end evidence of the counter working across a real
socket — only across the store. The window is bounded, so a proof older than
the bitmap reaches is refused rather than replayed, and that bound is a
deliberate memory trade rather than a claim of unbounded replay protection.
And the double-lock class found in the third delivery still has no shipped
guard.

#### Who owns the counter — recorded before it is built

A counter per session is only meaningful if exactly one thing increments it.
The obvious shape breaks:

```text
asv run <agent>
   ├── curl A
   ├── curl B
   └── npm
```

Three children, one session, each starting at 1. The window would refuse the
second and the third as replays of a counter the first already spent, and the
refusal is indistinguishable from an attack — the client cannot tell, and
neither can an operator reading the log.

So the counter cannot belong to the session, and it cannot belong to each
child. It belongs to **one emitter per session**, and the shape that fits the
product is a session-local shim rather than a change to every client:

```text
ordinary CLI (curl, npm, Maven, Gradle)
     │  knows nothing about ASV
     ▼
session-local ASV proxy
     ├── owns the atomic counter
     ├── asks SSH_AUTH_SOCK to sign the nonce
     └── adds x-asv-session-proof
     ▼
asv-brokerd CONNECT listener
```

This is the shell-first requirement applied to the replay fix. The
alternative — teaching each client to manufacture an ASV header — is M14's
work, and it would put the protocol inside every toolchain, which is the
opposite of what M14 is for. It is recorded because the counter is worthless
without it, and a counter that refuses a client's second legitimate tunnel is
worse than no counter at all: it is a denial of service wearing a security
costume, which is the same shape as the "strict highest counter seen" rule the
window deliberately avoids.

**Status: built, but not yet in a session.** `ProofIssuer` is the "one emitter
per session" this section argues for and it holds the only counter the session
spends; `SessionShim` is the proxy that takes an ordinary client's CONNECT and
mints the proof for the destination it named. See *C2.5-b* and *C2.5-c*. What
is missing is the last inch: `asv run` does not start the shim or point its
child at it, so nothing in the product invokes any of this yet.

#### C2.5-S1 — measured: only one client can carry the proof

Before building the emitter, the question that decides its shape was measured
rather than argued: does `x-asv-session-proof` reach a CONNECT at all on the
clients an agent actually runs? `HTTPS_PROXY` is not an answer by itself — a
client can add headers to the *origin* request, which is the wrong place,
because the broker never sees those.

`tests/connect_injection_spike.py`, each client against a one-shot local
listener that reads the CONNECT head and closes. Nothing touches the network.

| client | `x-asv-session-proof` on CONNECT |
|---|---|
| `curl --proxy-header` | **yes** |
| `curl` without the flag (control) | no |
| `git` via `http.proxy` | no |
| `npm` via `HTTPS_PROXY` | no |
| `java` via `-Dhttps.proxyHost`/`Port` | no |

**The measurement is falsified by its own control**, which is the only reason
to believe the "yes": the same client without the flag sends no such header.
Every other row sent a CONNECT and simply had nothing of ours on it.

**Two of the spike's own defects are worth more than the table.** The detector
compared an uppercase canary against a lowercased head, so it reported "no"
for a header that was sitting in the captured bytes — the positive case was
invisible and the conclusion was the *opposite* of the truth, with output that
looked entirely normal. And the first Java probe ran a class that did not
exist, so the JVM exited before opening a socket: its row was absence of
evidence wearing the clothes of evidence, which is a row that would have
decided an architecture on nothing. A row that cannot fail is not a
measurement.

**The decision this forces: a session-local shim, not a portable header.**
Option A — clients talking to the broker directly — is available on exactly one
stack. Teaching `git`, `npm` and the JVM to manufacture an ASV header is
precisely what must not happen: it puts the protocol inside every toolchain,
which is the thing M14 exists to avoid, and it would mean three separate
implementations of counter ownership. The shim is not the fallback; it is the
only shape that works, and it is the same component that gives a session its
single counter. One `asv run` produces one emitter, and `curl`, `git`, `npm`,
`mvn`, `gradle` and the agent keep knowing nothing about `SessionProof`.

**Two independent walls still stand.** The allow-list ships empty, so nothing
is authorised; and no shipped client emits the header, so nothing can prove
anything. A counter closes neither.

#### C2.5-S2 — measured: a blind relay can inject the proof and still be blind

S1 decided *who carries* the proof. It left one premise unmeasured, and the
whole shim rests on it: that a shim can inject the header into the pre-`200`
conversation and then stop being a protocol participant. If the blind relay
breaks reuse, the shim has to terminate TLS and re-originate, which drags the
broker's entire trust boundary down into the session directory — a different
design with different risk, and one that would have been built on an assumption.

`tests/connect_relay_spike.py` measures it over real TLS, with a real CONNECT
listener that refuses anything without the proof, a real TLS-terminating
broker, and ordinary `curl`.

| row | question | result |
|---|---|---|
| A | direct to the broker, no proof | `403`, zero origin requests |
| B | shim, 1 request | 1 request reaches the origin |
| C | shim, 3 requests, one host | **3 requests over 1 TLS session** |
| D | shim, 2 different hosts | 2 client conns, 2 upstream, 2 CONNECTs |
| E | shim with injection disabled | `403` |

**Row C is the answer, and row D is the relief.** TLS keep-alive survives being
relayed by something that cannot read it, so the shim needs no framing, no
session table and no TLS of its own: it writes one header and becomes
`recv`/`sendall`. Row D says `curl` did not try to multiplex a second CONNECT
onto the first socket, so the cheap shape is not being paid for with a
connection-reuse regression on the client side either.

**Row D is a measurement of one client.** `curl` not multiplexing says nothing
about `git`, `npm` or the JVM, and the shim is written for the latter two in
particular. Treat the loop-after-tunnel as unmeasured until it is measured on
the clients that will use it.

**The spike was falsified before its result was believed** —
`tests/connect_relay_falsification.py`, 4 mutations, 4 killed, control green:

| mutation | row that must go red | signature it produced |
|---|---|---|
| shim does not inject | B, C | `403` on every request |
| shim never relays | B, C | broken pipe, zero origin requests |
| proof gate disarmed | A, E | `through!` instead of `403` |
| **origin closes early** | **C** | **3 requests over 3 TLS sessions** |

The last one is the one that gives row C its meaning. It touches nothing in the
shim and breaks reuse one layer below; row C went red with the exact reuse
signature while A, B, D and E stayed green. Without it, C would only have shown
that three bytes eventually arrived, which is a much weaker claim wearing the
same label.

**Three defects in the harness, all of which pointed at the shim.**

1. `socket.timeout` is an `OSError`, so every `accept()` loop's `except OSError:
   return` killed the servers one second in. A bank of tests that stops running
   still prints a table.
2. The broker spoke plain HTTP to a TLS origin and dropped response bodies, so
   the tunnel "failed" twice before the harness was right. Both failures were
   reported as failures of the *relay* — the exact shape of a false
   architecture conclusion. The broker now terminates TLS and relays onward,
   which is both correct and what the product does.
3. The first harness parser matched `^(ok|XX) (A\..*)$`, whose greedy `.*` made
   every key a whole table row. It reported **"FALSIFICATION FAILED" for four
   mutants that had all been killed correctly**, with the right signatures, in
   the output directly above the verdict. A second version split on two-or-more
   spaces, which does not separate `ok` from the row name either. Both failed
   by *asserting*, which is the safe direction and still useless.

The pattern is the one this project keeps meeting: the detector is where the
truth gets lost, and a red harness that is red for the wrong reason is worse
than a green one, because it will be read as a finding about the system.

#### The falsification run of this delivery, and what it caught about the harness

The first run reported **4 of 7**. All three that stayed green were defects in
the *tests or the harness*, not holes in the code, and each is worth naming
because the failure mode is the same one this project keeps meeting:

- **A test that never reached the branch it named.** The stale-counter test
  accepted 1, then 500, then replayed 1 — but accepting 500 had already
  *remembered* 1, so the "already spent" arm caught it and the stale arm was
  never entered. Disabling the stale arm left the suite green. It now pushes
  more counters than the window holds, and asserts that its own fixture is
  valid before asserting the property.
- **A mutation that was not the mutation it claimed.** "Spend before verify"
  inserted the signature check *between* the two phases, which is still
  verify-then-spend. It is now a genuine two-site swap.
- **A mutation that was not observable at all.** Defaulting a missing counter
  to 0 was tested only against a two-part header, which is refused on arity
  before the counter is ever read. The case that reaches it is a counter that
  is *present and not a number*, and that is now a test of its own.

**And then the harness itself was wrong, in a way it had already been wrong
before.** With two edits on one file, the driver re-read the *pristine* text
for each site, so the second write threw the first mutation away and a
multi-site mutation silently degraded into its last edit. The
`connect_wiring_falsification.py` harness written in the second delivery keeps
two maps — `pristine` for the restore and `working` for the application —
precisely because of that, and this new harness collapsed them back into one.
A lesson recorded once is not a lesson recorded; it is a thing that happened
to one harness until it happens to a second one.

The harness was then rebuilt against the redesigned code, with eight
mutations over nine sites. Two of them exist because the window is a bitmap
and a counter on the wire, and neither is reachable by a mutation of the
older design: **not checking the duplicate bit** — the bitmap's only job, and
without which the window remembers nothing — and **accepting the two-segment
legacy header** as counter 0, which is the compatibility reading that looks
kind and would give every pre-counter proof the same counter.

#### C2.5-a — the format gets a second side, so it moves to where both sides can see it

S1 decided who carries the proof, S2 decided how thin the shim can be. Both
answers left the same prerequisite untouched: **there was no producer.** Every
`x-asv-session-proof` on the wire to date was built by a test, by hand, out of
the same constants the broker then parsed. A test that builds a value the way
the code under test builds it is a test that agrees with a broken format.

So the format now has two sides, and that changes where it lives.
`proof_nonce`, `SessionProof`, `PROOF_DOMAIN`, `SESSION_PROOF_HEADER` and the
base64 codec move out of `asv-broker`'s `tls_bridge` into `asv-ssh-agent`,
next to `verify_proof` and `public_key_blob` — the crate that already owns what
a signature over a session key *means*. The broker keeps a three-line adapter,
because a destination there is an `AuthorityEndpoint` and the call sites that
authorise one should not have to destructure it to sign for it. **The adapter
is vocabulary, not a second derivation**: there is one hash in the tree and it
lives where both parties can call it.

**The digest layout is pinned, and the vectors came from the old code.** Three
digests were taken from the broker's implementation *before* the move, by
printing what it actually produced. A vector written after the move would only
prove the new code agrees with itself, which is the property most likely to be
wrong: a nonce derivation that changes silently does not fail at the broker, it
fails as "no proof ever verifies", which is the same error a dozen unrelated
mistakes produce.

**The producer side is new, and it is the side that was missing.** A base64
*encoder* did not exist in the tree at all — the decoder had been carrying the
format alone, which is a format that can be parsed but never minted. It is
unpadded, because that is what the wire already carries and a second spelling
of the same proof is a second thing to canonicalise later.

**Falsification: 13 mutations, 13 killed, control green**
(`tests/proof_format_falsification.py`). Six of them are caught by the pinned
vector and by nothing else, which is worth stating plainly: the round-trip
test signs and verifies with the same function, so it agrees with *any* layout
and cannot see a digest change. Only the vector can.

**Two defects the run found, and the second one is a real hole.**

1. The harness's first expectations were wrong in that same direction — six
   mutations were expected to redden the round trip as well as the vector, and
   they did not, because my own module doc had already said they would not.
   Expectation and reasoning disagreed, and the code won.
2. `a_two_segment_proof_is_not_a_proof` was **passing for the wrong reason**. It
   fed the legacy shape `key.signature`, which the decoder refuses because
   `signature` is not a number — the counter parse fails first, and arity is
   never reached. A decoder that had started supplying a default for a missing
   signature would have passed that test. The test now also feeds `key.counter`,
   the shape such a decoder actually admits, and the harness mutates exactly
   that. This is the falsification earning its keep: the mutation could not
   reach the test as written, and "the mutation could not reach it" and "the
   property is covered" are different sentences.

**And it is the third time that exact trap, in the same project.** The C2.4
section immediately above this one records it under a different name: *"A
mutation that was not observable at all. Defaulting a missing counter to 0 was
tested only against a two-part header, which is refused on arity before the
counter is ever read."* Same structure, same crate, two deliveries apart: a
mutation aimed at a parser rule, landing on an input that a *different* parser
rule already refused, so the property looked covered and was not. The written
record of the first one did not prevent the second. What would have is a rule —
*every mutation names the input that reaches the branch it targets* — checked by
reading the mutations rather than by reading the prose. That is a candidate for
a permanent guard, and it is not written.

**A decoder claim nothing checked.** The base64 decoder's doc has always said
it refuses characters outside the alphabet, and until this delivery no test
did. The test that now covers it asserts its own preconditions after its first
version silently passed on a `replace` whose target character was not in the
string — the absence-of-evidence trap, in a test written specifically to catch
a decoder that would have skipped those characters.

**Known laxity, deliberately not fixed here.** The decoder accepts `=` and
stops, so a padded and an unpadded spelling of the same proof would both parse.
Closing that is a behaviour change to a security path, and mixing it into a
move makes the move unverifiable: the vector cannot tell "the move was
faithful" from "the move was also a change". It is a separate delivery.

#### C2.5-b — the counter has exactly one owner, and that owner can now sign

This section answers the question left open by *Who owns the counter* above.
That one said the shape before it was built; this one is the build.

**`ProofIssuer`: one per session, holding the only counter that session
spends.** `issue(host, port)` takes the next counter from a `SeqCst` atomic
and returns a signed `SessionProof`. A second issuer is constructible, and that
is why `next_counter` is exposed: the duplication is *observable* rather than
silent, so a shim that somehow held two would be caught instead of quietly
splitting the counter space. A counter per child is not merely discouraged, it
is not expressible as the intended design — the thing that increments it is a
named object with one atomic inside it.

**The crate had a server and no client.** `AgentSession` signs, and nothing in
the tree could ask it to. `AgentClient` speaks the bounded 11/13 subset over
the `SSH_AUTH_SOCK` path and nothing else: it does not read `~/.ssh`, and a
missing socket is an error rather than an occasion to find another identity.

Three decisions in the client are about refusing rather than about working:

- **It names the key it wants signed**, instead of asking "sign this" and
  taking whatever comes back. A socket pointed somewhere else then produces a
  signature the broker refuses, rather than one it might accept.
- **It takes the key blob from the agent**, not from the caller, because the
  agent is the authority on which key it signs with. `discover` refuses an
  agent offering more than one identity rather than picking the first, which
  would be choosing a key on no evidence.
- **`Refused` is a distinct error from `Io`.** A session that declined to sign
  and a socket that is not there are different facts, and only one of them is
  worth retrying.

**A failed signing still spends its counter, and that is deliberate.** A counter
handed back after a failure is one an attacker can walk backwards by making the
agent slow. The window is 128 wide, so a few lost counters cost nothing; a
*reusable* counter costs the property it exists to provide.

**Falsification: 14 mutations, 14 killed, control green**
(`tests/proof_issuer_falsification.py`). Every client test goes through a real
`AgentSession` socket, because the thing under test is that two halves of one
crate agree across a length-prefixed frame. Six of the mutations need an agent
that misbehaves — a wrong algorithm name, two identities, a length field that
lies — which a real session cannot produce and only an adversarial one can.

**Four things the run found, three of them in the tests or the harness.**

1. **The identity reader was a misreading of the protocol, and the real socket
   caught it on the first run.** Every SSH-agent identity is a blob *and* a
   comment; the reader took the blob and then asserted the frame was exhausted,
   which it never is. An in-process fake would have agreed with the mistake,
   because the fake would have been written from the same misreading. The
   adversarial fixture exists to *attack* the client, which is the opposite of
   standing in for the server.
2. **A test aimed at the wrong layer.** `two_identities_are_refused…` called
   `identities()` and expected a refusal. But `identities()` is a faithful
   reader — refusing a well-formed response would be the bug — and the
   "exactly one identity" rule is policy that lives in `discover`. The test now
   asserts both: the reader reports two, and `discover` refuses.
3. **A size check that exists in two places is pinned by naming which copy is
   under test.** The oversized-payload test pointed at a live agent, so deleting
   the check in `sign` changed nothing observable: the frame writer refused the
   same value independently. Against an absent socket the layers separate — a
   refusal before connecting is `Malformed`, a deleted check becomes `Io`.
4. **A test made only of negative assertions proves nothing on its own.** Every
   assertion in `a_proof_is_refused_for_a_destination_it_was_not_minted_for` was
   "this signature does not verify there", and a signature over the wrong nonce
   does not verify *anywhere*, so all of them held for a completely broken
   issuer. It now asserts the positive half first.

And one expectation of mine was wrong twice: a mutation meant to hand the
counter back on failure was first written as `store(counter + 1)` followed by
`fetch_add(1)`, which is *exactly what the original does*. A mutation that
changes nothing is indistinguishable from one that changes something and is not
caught, so reading the mutation is part of falsifying it.

#### C2.5-c — the shim exists, and it is as dumb as the measurement said it could be

`crates/cli/src/session_shim.rs`. It binds loopback, takes a CONNECT from a
client that has never heard of Agent Secretless, asks the session's one issuer
for a proof bound to the destination that CONNECT named, injects the header,
and hands the request to the broker. After the `200` it is `recv`/`sendall`.

**The destination had to become a shared type before any of this worked.**
The proof's nonce is a hash over a *canonical* host and port, and the shim has
to derive the same one the broker will. The broker had a private
`parse_connect_target`; the shim would have needed a second one, and two
parsers do not fail loudly — they produce proofs that verify nowhere, which
reads as a broken signer rather than as a disagreement. So the parse moved to
`asv_domain::ConnectTarget`, beside `Authority::canonicalize`, which is already
the declared single source of truth for "the same host" in this codebase. The
broker now delegates to it and keeps `AuthorityEndpoint` as its own
authorisation vocabulary; the shim and the broker share the *reading* and
nothing else.

**The shim is not a policy engine and is written so it cannot become one
casually.** It authorises nothing, resolves nothing, substitutes nothing, and
does not know the allowlist. When the broker drops a refused CONNECT — which
is what the real one does, writing no HTTP error at all — the shim answers
`502 Bad Gateway` and nothing more: a bare status line with no header, no
reason, no hint. A client that learned *why* its proof could not be minted
would be learning something about the session's signing state that it has no
business knowing, and the refusal's real reason belongs in the audit chain,
for the operator, not in a string this process invented.

**It replaces a client-supplied proof rather than adding to it.** The broker
reads the *first* `x-asv-session-proof` it finds, so a shim that merely
appended would hand a client the race. A forged proof would be refused anyway
— it cannot be signed by the session's key — but the design must not make
which header wins a race.

**Both heads are read one byte at a time.** A `BufReader` is the obvious
choice and it is wrong in both directions: it may buffer past `\r\n\r\n` and
swallow the first bytes of the client's TLS ClientHello, and on the other side
it would eat the start of the broker's first record.

**Falsification: 9 mutations, 9 killed, control green**
(`tests/session_shim_falsification.py`) — plus one **removed**, and the removal
is the finding. The first run killed 4 of 10, and every survivor was a hole in
a test rather than a strength in the shim:

- **The destination test only ever named one host.** With every request naming
  `api.example.com:443`, "minted for the requested destination" and "minted
  for a hardcoded one" are the same observation, and a mutation that hardcoded
  the destination changed nothing. The test now opens two tunnels to different
  hosts and checks each proof against its own destination *and* against the
  other's.
- **The refusal test used the very status a mutation rewrote to**, so
  "restated by the shim" and "forwarded verbatim" were indistinguishable. The
  fixture now answers `407`, a status the shim would never invent.
- **The `502` was only checked for its status line**, which left the shim free
  to attach an explanation. The assertion is now on the whole reply, byte for
  byte.
- **The head bound had no test at all**, so removing it was invisible. There is
  now one that sends a head past the bound and asserts nothing reaches the
  broker.

**And the branch I deleted rather than tested.** The shim originally looped,
serving a second CONNECT on the same client socket. The test for it opened a
*second connection*, so it proved nothing about the loop. When the test was
rewritten to actually use one socket, it failed — and the reason is the
finding: after the `200` the shim is a pipe, so bytes the client sends next are
tunnel payload, which is the correct reading of them, and the client has no
way to learn the tunnel ended. **No client can reach that loop.** Reaching it
in a test needed a `sleep`, and a branch that needs a sleep to reach is a
branch no client can reach. So the loop is gone, the test is replaced by the
property that is actually true and observable — post-`200` bytes travel as
payload and are not intercepted — and the mutation against it is removed with
its reason rather than left failing forever. The C2.5-S2 measurement agrees:
`curl` did not multiplex, and there is no portable way for it to learn that it
could.

## C2.6 — CONNECT policy and configuration

### Status: applied

`ConnectRoute` exists, each route is authorized by Cedar at load, and the bridge
holds no rule. The allow-list is no longer `Vec::new()` and the handler is no
longer carrying `OperationFamily::GitHub` as a constant.

**Two decisions, both taken by the owner rather than inferred.**

*Where the allow-list comes from.* A declarative route file, authorized by Cedar
when it loads. The alternative considered and rejected was deriving the list from
the policy engine alone: it needs the schema extended for port and family, and
`ALLOWED_AUDIENCES` would still have been a `const` of compilation — the same
`if github.com` moved to another crate. The second alternative, a config file
with no cross-check, was rejected because it makes the file a second policy
engine able to permit anything, which is the reuse law's own prohibition.

*How the family is bound.* Each route declares its own family and credential.
Resolving it from the session's existing surrogate was considered and rejected:
it couples policy to inventory and has no answer for a session that has not
minted a surrogate yet.

**One trap, found and closed rather than walked into.** The obvious
implementation of "authorized by Cedar at load" is a `permit` for
`connect_route`. That makes the cross-check *vacuous* — every route passes, so
the file cannot fail and the check is not a control. It is the same defect M6-R5
exists to prevent for the database verbs. So the built-in policy text has **no**
`permit` for `connect_route`, and a stock broker refuses every declared route.
Widening CONNECT is now two visible edits — a route file and a rule — rather
than one, and both show up in a diff.

**What the loader refuses, and why each refusal is a control.**

| refused | the attack it closes |
|---|---|
| surrounding whitespace | a loader that trims first reinstates the textual allowlist bypass `canonicalize` exists to prevent |
| a single-label host | `localhost` as a routing shortcut |
| an IP literal | the direct-address trick: no name to pin, and a route that outlives whatever the operator thought the number meant |
| port 0 | not a service |
| an empty credential alias | a route with nothing to substitute |
| two routes for one endpoint | a coin flip decided by file order |
| an unknown field | a typo'd field silently defaulting |
| a route the policy does not permit | the config widening what the policy allows |

**`Authority` deserializes without canonicalizing.** It is
`#[serde(transparent)]` over a `String`, so a route file is exactly the path by
which an uncanonical spelling reaches the table. The loader canonicalizes on the
way in for that reason, and `deny_unknown_fields` is on because a typo'd
`operation_family` would otherwise deserialize into a route with no family.

**The `git_hub` spelling.** `OperationFamily` derives
`rename_all = "snake_case"`, so serde splits `GitHub` at the internal capital and
the wire form is `git_hub`. `github` is a *different* variant and is refused.
Measured, not assumed: the first version of the unknown-field test was passing
for the wrong reason and this is how it surfaced.

**What a route does not pin.** A route pins an identity — a canonical name and a
port — not an address. Resolution happens later against whatever resolver the
host has, so a hostile answer can still point a permitted name at an attacker's
address. The table's contribution is bounded and now written down: the proof
nonce, the authorization and the audit record all name the *authority*, never
the resolved address, so a rebind cannot change what was authorized. Pinning the
address is a separate control that does not exist yet.

**Evidence.** 17 tests in `crates/broker/src/connect_routes.rs`, one per property
the objective names. 10/10 mutations turn the suite red: IP-literal refusal
removed, Cedar cross-check removed, unknown fields ignored, port dropped from the
match, host trimmed before canonicalizing, lookalike accepted, duplicate endpoint
silently kept, port 0 accepted, a denied route no longer failing the file, and
`withdraw` turned into a no-op. One of those ten initially **escaped** — the
unknown-field test omitted a required field, so serde reported the missing field
and the test kept passing with `deny_unknown_fields` deleted. Fixed by supplying
every required field and adding a control that must load, so the only thing wrong
with the document is the extra field.

**Still owed, and not claimed by this delivery.** No route is reachable in a
shipped build, because no shipped policy permits one. That is deliberate and
fail-closed, and it means C2.7 needs an operator configuration to demonstrate
anything: a route file *and* a policy file. The end-to-end vertical, the
adversarial campaign and the concurrency work are C2.7 and C2.8, not this block.

## C2.7 — CONNECT as a product capability, not an internal surface

### Status: closed — A, B, C and the end-to-end vertical all landed

**C2.7 is closed.** The vertical below drives a real credentialed request from
`asv run` through a real broker to a real origin with an ordinary `curl`, and
every assertion in it was falsified before this line was written. What remains
for this path is C2.8: the adversarial campaign and the concurrency work, which
are properties of the running system rather than of a single request.

The three prerequisites below were prerequisites, not the vertical.

### C2.7-A — the shim had a lifecycle no owner could end

`SessionShim::serve_forever(self) -> !` took itself, returned nothing, and could
not be stopped. Nothing in the product invoked it, so nothing noticed — and a
thread holding a bound loopback port and a live `ProofIssuer` after the command
it belonged to had exited is a session that keeps spending proofs for a session
that no longer exists. A proof minted then resolves to nothing, which reads as a
broken signer rather than as a dead session.

`spawn` returns a `ShimHandle`; `stop` sets the flag, unparks, and joins. The
accept loop is non-blocking and parks between attempts, so a session that makes
one request an hour costs nothing.

**`IDLE_PARK` is three seconds, and that is load-bearing.** `stop` unparks, so a
real shutdown returns in microseconds; the interval only governs the broken path.
It is long because the lifecycle test sets a bound *below* it — a stop that
returned in 200ms and a stop that waited the park out are indistinguishable when
the park is short, and the test meant to tell them apart could not. The first
version used 50ms against a 5s bound, and deleting the `unpark` passed it.

**The idle test measures rather than asserts.** Its first version slept and then
checked the shim still answered, which passes on a busy-wait exactly as it
passes on a parked loop: a spinning accept loop is *correct*, it just burns a
core, and correctness was all the old assertion could see. It now reads the
kernel's CPU accounting for the accept thread from `/proc/self/task/<tid>/stat`
across a park interval, with the tick rate asked of `sysconf(_SC_CLK_TCK)`
rather than assumed to be 100.

### C2.7-B — the broker publishes where it listens, and it was publishing the wrong thing

`connect_listen` is a new `SelfReport` field and a new `BrokerInfo` field, so
`asv run` can start a session's shim without being *told* where to point it. Two
sources of truth for one address can disagree, and the disagreement is silent:
the shim would forward every CONNECT to a port where no broker is listening and
the session would simply never tunnel. This is `SelfReport`'s own argument, from
`selfreport.rs` — the answer to a question about the running broker should not
exist for the length of a log line.

`PROTOCOL_VERSION` is 5.

**The broker was publishing `127.0.0.1:0`.** Port 0 means "choose one", and the
value that gets logged is still the string that was passed in. Every session
would have been handed a port nobody listens on.

### C2.7-C — `asv run` starts the shim, and ends it

One shim per session, started by `asv run` and not by the child: the shim owns
the session's *only* counter, and three children each minting their own would
present 1, 1, 1 with the second refused as a replay of the first.

Four proxy variables are set — the ones that produce a CONNECT. `HTTP_PROXY` is
deliberately not: it makes a client send a plain proxy request, the shim refuses
anything that is not a CONNECT, and the result would be a mysterious failure for
a request the broker was never going to see.

`NO_PROXY` and `no_proxy` are **removed**, not merged. An inherited `NO_PROXY`
naming a destination makes the child connect to it directly — no CONNECT, no
proof, no substitution. One inherited variable defeats the whole path.

The teardown covers the spawn-failure path, not just the normal exit: a child
that never ran is exactly when a `?` would have returned with a bound port and a
live issuer still attached.

### The finding that mattered most: `--connect-listen` had never started

`crates/broker/tests/connect_address_publication.rs` starts the real
`asv-brokerd` binary and asks it where it is listening. It failed on the first
run, and the reason was not the thing it was written for:

```text
thread 'main' panicked at crates/broker/src/main.rs:610:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

`tokio::net::TcpListener::from_std` registers the descriptor with the runtime's
reactor, and holding a `Runtime` in scope is not the same as being inside it —
`runtime_guard` was kept for its lifetime and never entered. `git log -S` over
that file finds no `enter()`, so this predates every recent cycle.

**The CONNECT listener has never once started in a real broker process.** Every
CONNECT test builds its listener in-process, where the test already runs inside
a runtime, which is why the suite reported a surface that could not come up. This
is the failure class `tests/connect_wiring_falsification.py` exists to catch,
arriving by a route it did not look for.

It is worth being precise about what this says about the earlier evidence. The
C2.6 route table, the C2.5 shim, the proof format and the counter are all real
and all tested — but "tested" meant "tested in process", and the one hop between
a test process and a running broker was broken. The end-to-end vertical is not
an additional test to write. It is the first test that would have seen this.

### C2.7-D — the vertical, and the two claims it did not measure

`crates/broker/tests/connect_vertical_e2e.rs` is the first test in this path that
runs nothing in-process. A real `asv-brokerd` with a real vault, a real route
file and a real policy file; a real `asv run` that opens a real session and
starts a real shim; a real `curl` that has never heard of Agent Secretless and is
told nothing but a proxy URL; a real origin on a real socket. The credential is
planted the way an operator plants one — `asv add-credential` over stdin — and
the id that verb mints is what the route file names, because the ids are the
product's and a test cannot invent one.

It found the defect above, and then it found two of its own.

**The audit assertion was a no-op.** It shelled out to
`asv-brokerd --audit-verify`. There is no such flag — the broker has
`--audit-file` — and it was never started with one, so there was no file to
verify. The assertion then sat behind `if command.success()`, which meant it
would also have passed against a broker writing no audit at all. The one property
this file exists to certify was a conditional that could not fail. It is now read
off the file the broker actually wrote, parsed into records rather than grepped as
text, checked for the substitution that happened and the refusal that did not, and
given a tamper control: `verify_file` answers `Ok` to an empty file, so a green
verification means nothing until the same call is shown going red on an altered
record.

**The replay assertion was not a replay.** It opened a second session and checked
its output for the secret, under a comment claiming it showed a surrogate could
not be reused. The second session minted its own token; the two sessions never
held the same value, and the question was never put. The token is now carried
from one session into another, with the positive half in the same run so that
"not yours" is distinguishable from "nothing works at all".

And it is worth recording *why* the first attempt at that was wrong even after
being rewritten, because the reason is the interesting part. The first version
took the token from a session that had already finished — and `SessionEnded`
calls `revoke_session`, which *deletes* a session's surrogates from the registry.
So the foreign token was refused for being unknown, and the session comparison in
`redeem_for` was never reached. The assertion was green and wrong. It stayed
green when the mutation campaign deleted the session comparison outright, which
is how the difference was found: an assertion satisfied by a refusal of the wrong
cause is indistinguishable from a working one until the control is taken away. The
measurement now holds both sessions open at the same time, which is the only state
in which the binding is reachable.

**A hung client, and a shim that could not be torn down.** When the broker refuses
a substitution — the wrong session, the wrong class, a spent budget — it has
already read the head and it drops the connection. The shim relays both directions
in their own threads behind a shared flag, and a thread blocked in `read` cannot
see that flag: it only checks before it blocks. So the pump reading the broker
ended and the pump reading the client stayed blocked, waiting for a client that
was waiting for a reply. A real `curl` hung for **241 seconds**. The fix is a
250 ms poll interval in each pump: not a deadline — it never closes a tunnel, and
an idle tunnel of any length still survives — but the ability to notice that the
other end went away. "No deadline inside the tunnel" was a correct decision that
had been over-applied to the teardown; an unbounded tunnel and a tunnel that cannot
end are not the same thing, and only the first was being asked for.

**What the vertical does not claim.** `curl --insecure`: the session CA is minted
per broker run and the test has no channel to pin it, so the client's trust
decision is waived and nothing here is evidence that certificate trust is solved
for an operator. It also does not show that a *proof* is single-use end to end —
the shim mints one per connection, so an ordinary client is never in a position
to replay one; that property is measured in the broker's verifier and in the
issuer's counter, and claiming it here would be claiming a hop this test does not
cross. And the bridge dials the destination *before* it can read the head that
carries the surrogate, so a refused tunnel still leaves an empty connection open
at the origin. That is written down rather than hidden, and it is why the
assertions count the requests that carried bytes, and above all the ones that
carried the real credential, rather than counting connections.

`tests/connect_vertical_falsification.py` deletes the control behind each of those
assertions — the session comparison, the chain verifier's ability to see a break,
the recorded outcome, the recorded destination, the surrogate handed to the child
— and requires the *named* assertion to go red. Five of five, and a run that
fails for any other reason counts as an escape rather than as a pass.

## C2.8 — CONNECT in production, and the first thing that is not

### Status: open. Eight measurements in; the fifth built the multi-request loop and found four defects in it, the sixth falsified the loop and found two more, the seventh carried a real `npm install` through it and found the boundary of the design, and the eighth built the TLS leg from the broker to the destination and found a hole in the tests where a defect was assumed. Every defect so far sat under a green test

V1-C2's scope, written when the block was opened and not narrowed since: *a
production listener wiring `relay_substituted` into a running `asv-brokerd`,
real CONNECT lifecycle, **more than one request per tunnel where the protocol
allows**, a formal decision on freshness and replay, **shutdown and revoke
mid-tunnel**, **stress and cancellation**, and observability that carries no
sensitive material.* The listener, the lifecycle and the freshness decision are
delivered by C2.6 and C2.7. The rest is this block.

The first thing measured in it is the bolded one, and it is worth stating
plainly because it is the kind of limit a demo never shows.

**A CONNECT tunnel serves exactly one request, and HTTP/1.1 clients reuse their
connections.** Against the real broker, with an origin that keeps the connection
open and an ordinary `curl` told nothing but a proxy URL:

```text
CONN=1 CODE=200      the first request, on one connection
CONN=0 CODE=000      the second, curl reusing that same connection
```

`CONN=0` is the half that carries the meaning. `curl` did not open a second
connection; it reused the tunnel and got nothing back. So the second request is
not being refused by the destination — **the destination never sees it**.

The cause is in `relay_substituted`. It reads one head, writes the rewritten one,
and then `relay_back` copies the response direction until EOF or a byte limit.
The request direction is never pumped again, so a second request sits in a socket
buffer that nobody reads. This is the shape of ordinary traffic rather than an
edge case, and the failure is opaque: a client sees a dead transfer with no
explanation, not a refusal.

**What still holds, and why that distinction matters.** The destination never
received a second request, so it never received a second copy of the credential,
and nothing forwarded a surrogate it could not spend. The gap is availability and
opacity, not disclosure. Recording that precisely is not a way of making it
smaller — "the second request fails" and "the second request leaks something"
call for different work, and only one of them is a security defect.

`a_tunnel_serves_one_request_and_the_protocol_allows_more` in
`crates/broker/tests/connect_vertical_e2e.rs` is the measurement held in the
suite. It is a characterization and says so: it asserts the limit, and it goes
red if the tunnel ever serves two — the signal that both the limit and its
comment have become stale.

**One session sustained 8 of the 64 tunnels it was asked for — and both causes
were bugs in this repository, not in the client.**

```text
parallel=16  ok=8   failed=8
parallel=32  ok=8   failed=24
parallel=64  ok=8   failed=56
```

Eight, every time, whatever the client asked for. The broker's own account of
the 64 split the 56 refusals into two causes, and **neither was a documented
budget**:

```text
17  no session proof resolved for this tunnel
39  the presented surrogate was refused   -> SurrogateError::Exhausted
```

**The window marked the wrong bit when it advanced.** Bit `i` means
`highest - 1 - i`, so the *previous* highest — which has just been spent — lands
on bit `shift - 1`, not on bit 0. The two coincide only when the shift is exactly
one, which is the single case the existing test happened to cover: *8 then 7*.
Every arrival with a gap of two or more marked `highest - 1` as spent, a counter
nobody had presented, and refused the next honest client to use it. Sixty-four
concurrent CONNECTs lost seventeen legitimate proofs this way, and they were
freshly minted, correctly signed, from a session that had done nothing wrong.
The comment above the window says outright that refusing a legitimate out-of-order
counter is "a liveness bug wearing a security costume"; it was wearing one.

**The surrogate's budget was 8, not the 32 the broker asked for.** `mint` clamps
into the protocol's `MAX_SURROGATE_USES`, and a clamp that lowers what you asked
for raises nothing, logs nothing, and returns a value the wire reports honestly —
so the CLI, the audit and the tests all believed it. The ceiling was written when
a surrogate was minted by an operator for one operation, where eight is
generous; `CreateSession` mints one per route and hands it to a child that may
issue a stream of requests, and eight is not a backstop but a product limit no
ordinary client survives. The ceiling now follows the broker's already-declared
intent, and a test fails if the two ever drift apart again.

**Measured after both, against the same 64:** 32 complete and 32 are refused for
the budget that is *documented* — a budget doing its job. The property the test
now asserts is the one that must not regress: the anti-replay window refuses
**nothing** honest under load, and every refusal carries a reason an operator can
read.

**How the defect was found, which is the part worth keeping.** The vertical's
fixture started the broker with its `stdout` sent to `/dev/null`, because that is
where `tracing_subscriber::fmt()` writes. Every refusal reason the broker
produces was being discarded, and a test that silences the observer gets exactly
the same result as a test with no observer at all. Capturing it turned a
counter — "8" — into two named causes, and then into two line numbers.

**Revoke mid-tunnel: three defects, each of them already covered by a green
test.** A CONNECT tunnel used to serve one request and then sit there, which is
the ordinary state of a live tunnel, so the honest way to ask whether it
outlives its session is to let it get there. The fixture answers from the far
end: the origin holds the connection it was given and reports whether it is
still holding it, **with no read deadline behind the answer**, so "still open"
cannot be a timer wearing a tunnel's clothes. The test controls for that,
because it first has to see the tunnel open while the session is still live —
one sample is not an observation, and a tunnel that collapses the instant it is
used satisfies "zero connections after teardown" perfectly while proving
nothing.

It found three things, in this order.

**One, and the worst: the surrogate registry's lock was held for the whole
length of every tunnel.** `SubstitutionPort` borrowed the registry, so the
caller's `MutexGuard` had to outlive the port and the port had to outlive the
relay. With one established and idle tunnel open, the broker could not
`EndSession` for *any* peer, an `asv run` whose child exited never returned, and
the main thread sat in `futex_do_wait` while the durable chain recorded no
`end_session` at all. The same lock is what `CreateSession` mints through and
what revocation deletes through, so one client holding a tunnel open froze the
session lifecycle for the whole broker. It was found by looking at `/proc`,
because the failure mode is a hang and a hang is not a red test.

The two comments above the call site said the opposite of what the code did —
"taken for the length of one registry operation — never for the length of a
tunnel" — and `SharedSubstitutionAudit` cites "the same rule the surrogate
registry follows", a rule its neighbour was not following. The port now takes a
`&dyn SurrogateLending` and locks it itself, for one `redeem_for` per request.
That is not tidiness: it makes "held for one operation" the only thing the type
can express, because there is no borrow left to accidentally extend.

**Two: `ShutdownSignal::revoke` had no caller outside tests.** The broker built
a signal in `main.rs`, handed it to the listener, and had no way to name it
again from the socket handler. Ending a session killed its *surrogates*, so no
new tunnel could be authorised, while every tunnel already established went on
relaying the real credential to its destination for a session that no longer
existed. The mechanism was proven the whole time: C1.1,
`revoking_an_established_session_tears_down_its_tunnel`, cancels a live tunnel
and passes against a broker that never revokes anything, because it revokes the
signal itself. A test that does the subject's job cannot tell a working product
from a working mechanic. The signal is now in `BrokerState`, `main.rs` hands out
that one, and `EndSession` revokes inside the ownership guard — a revoke placed
earlier would let any peer on the socket destroy any session it can name without
owning it, and that ordering is itself a test.

**Three: `relay_back` never consulted the cancellation source.** It was a plain
copy until EOF, so a revoke could only ever reach a tunnel still reading its
*first* request head — and the ordinary state of a live tunnel is past that
head. Wiring the revoke alone changed nothing observable: measured end to end
with the fix in and `relay_back` untouched, the destination still held its
connection 20 s after the session ended.

**What the vertical can and cannot establish, stated because it is the kind of
thing a test file quietly overclaims.** It asks the destination, not the client,
so it measures the tunnel rather than the client's socket. It cannot say *who*
closed it: `asv run` stops its shim before it ends its session, and a dead shim
drops its sockets, so a tunnel dying at teardown is equally consistent with the
shim dying and with the broker cancelling. So the end-to-end claim is checked
here and the broker's own claim is checked where it can be isolated, in
`connect_session_revocation_wiring.rs`. A green test in one with the other
missing is a guarantee nobody actually has, and the wiring file says outright
that it cannot see `main.rs` at all — a second signal there would pass all four
of its tests, and covering that is the vertical's job.

All five assertions are falsified by a named one going red: a lock held across
the relay, the revoke deleted, the revoke moved ahead of the ownership check, a
revocation that is not scoped to a session, a broker born stopped, a response
relay that ignores cancellation, and two fixture mutations — **8 of 8**
(`tests/connect_lifecycle_falsification.py`). Two of those eight exist to reach
controls the others cannot: a fixture that closes instantly is caught at the
first gate, so without one that closes *slowly* the settle window would be an
assertion no mutation can reach, which is the decoration this repository keeps
finding. A campaign that scored a killed run as "the test did not fail" would
also have scored the worst defect in the slice as the mildest, so a hang counts
as a detection.

**The observability sweep, and the surface nobody had checked.** The vertical
already proved the child's `argv`, its environment, its output and the durable
chain carry no credential. The operator's log is the surface an operator
actually reads while something is going wrong, and it had never been looked at
by a single assertion.

Checked in two halves, because they are two different questions. One asks
whether anything the broker *holds* reaches a surface: it does not, and that is
now a test with a control, so a sweep that only reports the defect it found
cannot be re-run against a future change to the surface it did not find. The
other asks whether something the *client* chooses can be made to appear there,
and it could:

```text
WARN CONNECT refused destination=<no destination read> session=None
     reason=malformed CONNECT request: CONNECT authority "gho_ASVclientWrote…" carries no port
```

A bare socket wrote that. No proof, no surrogate, not even a well-formed
CONNECT — because `parse_connect_target` runs before the session proof is
authenticated, and `ConnectTargetError::NoPort` carries the request line's
authority verbatim. The durable chain recorded the same connection as
`detail: "malformed_request"`: a class, no client bytes. The two surfaces were
also **two different functions**, and the kind-based one existed, was correct,
and had no production caller while the chain searched the rendered message for
a prefix — the failure `cancellation_class` already documents in its own
comment. They answered differently for most variants.

`ConnectionResult::Refused` is now a class and an optional detail, derived from
the error's *kind* where the error is in hand, so the two surfaces read one
field and cannot drift. `refusal_detail` drops the text for exactly the
variants that quote the client and keeps it for everything that is a fact about
this broker: a canonicalised host, an I/O error, a handshake failure, a
constant message. The rule is about **provenance**, not about length or about
looking sensitive — which is why a refusal with no detail is still recorded,
and that has its own test, because a reporter that treated "no detail" as "no
record" would leave the chain with a gap and a chain with gaps fails
verification for everybody after it.

Making the match exhaustive caught the last thing: `_ => "other"` had been
swallowing `BridgeError::Upstream`, so a `Connect` that could not reach its
destination was recorded under a class an operator could not act on. A new
variant is a compile error now instead of a silent fallthrough. Falsified
**5 of 5** (`tests/connect_observability_falsification.py`), two of them
mutating the *clean* surface rather than the leaky one — a careless `tracing`
of the forwarded request, and a careful-looking trace of the redemption — so
the assertion that the log is clean is falsifiable in both directions.

**And the two limits that make multi-request tunnels impossible are both too
small, measured rather than argued.** The surrogate budget and the response cap
were set when a tunnel served one request, and both are accidental limiters
today. Measured on a real workload — `npm install --loglevel=http express` on a
throwaway package, a 65-package tree:

| | measured | limit at the time | ratio |
|---|---|---|---|
| HTTPS requests | **93** | 32 surrogate uses per session | 0.34 |
| content installed | **2.1 MiB** | 1 MiB `max_response` per tunnel | 0.48 |

So the budget is a third of a *trivial* install, and the response cap is under
half of it. A real project build is one to two orders of magnitude past both.
The consequence is not that a tunnel is too generous; it is that the limits
would break the workload at request 33 and at the first large tarball, while
looking like a policy. They were the reason the concurrency measurement found
8-of-64 and read it as the budget "doing its job" — it was doing its job, and
the job was the wrong one.

**The re-derivation owed here has now been done, and the number that was wrong
was a different one from the one that looked wrong.** The protocol's
`MAX_SURROGATE_USES` was raised from 32 to 8192 against that table, and the
product was still refused at request 33. The reason is the same shape as the
`mint` clamp one level up: the session does not mint through `MintSurrogate`,
it goes through `CreateSession`, and that path mints what
`SESSION_SURROGATE_MAX_USES` says. The constant was **also 32**, and nothing had
put those two numbers in front of each other.

So the fourth clamp was not a clamp — it was a constant that was never wrong on
its own terms. `MAX_SURROGATE_USES = 8192` is the protocol's ceiling, which
bounds what a session may *ask for* over the socket; it never bounded what a
session was *given*, and no test compared the two. Worse, the invariant that
should have caught it, `a_tunnel_is_bounded_below_its_sessions_own_ceiling`,
passed — because it compared the tunnel's `max_requests` of 4096 against the
protocol's 8192, a grant `asv run` never receives. A limit checked against a
ceiling nobody is held to is not a check.

The measured consequence, before the fix, spent rather than argued:

```text
request 32 of a workload measured at 93 requests was refused (Exhausted);
the session's surrogate paid for 32 of them.
```

**A client sees its own token refused and has no way to tell a budget from a
replay.** That is the sentence that mattered. Every other signal in the system
says a credential was tampered with, and the honest reading here is that
nothing was tampered with — the grant simply ran out. It would have been read as
an attack, and the correct response to an attack is not to raise a limit.

What it is now: `SESSION_SURROGATE_MAX_USES` **is** `MAX_SURROGATE_USES`. That
is not "unbounded" dressed up — 8192 is already what a session may obtain
through `MintSurrogate` over the socket, so this removes a discrepancy between
two paths to the same grant rather than opening a third. What bounds a session is
unchanged and is what always was: its TTL, its revocability, and `EndSession`,
which drops every token it holds. The tunnel keeps its own `max_requests` below
that grant, so a connection still cannot spend a whole session, and the check
that says so now compares against the grant.

Two tests hold the numbers, and they are deliberately **not** comparisons of
constants, because a comparison of constants is what passed for the wrong reason
last time:

* `a_session_surrogate_pays_for_a_workload_that_was_actually_run` **spends** the
  grant 930 times — the measured 93 with the same tenfold headroom the per-tunnel
  limits are held to — and fails with the request index and the number paid.
* `a_tunnel_is_bounded_below_the_budget_its_own_session_was_handed` compares the
  tunnel's cap against `SESSION_SURROGATE_MAX_USES`, which is the number the
  session was actually handed.

Falsified **8 of 8** (`tests/relay_limits_falsification.py`). The row worth
naming is the second-to-last: mutating the protocol ceiling down to 32 lowers
*both* numbers together, and `session_mint_survives_the_protocol_ceiling` — the
test that exists precisely to catch a silent clamp — is perfectly happy, because
no clamp happened. Two tests catch it, and neither is the clamp test. The last
row sets the session budget back to 32 directly, which is the same product
defect reached by a different road, and is caught by the same test.

This is the answer to the question this block has carried since C2.7-D: no, 32
uses per session do not come close to a real `npm`, `Maven` or `Gradle` run. The
loop is still the next increment — but a loop over a budget that dies at request
33 would have been a loop that a real client could not finish, which is the same
lesson as the third clamp wearing different clothes.

**And the increment is bigger than "add a loop", which is worth writing down
before anyone starts it.** The obvious design is a loop: read the next
`\r\n\r\n`, substitute, write, repeat. It is wrong, and the reason is that
`\r\n\r\n` only frames a head when a head is what comes next — which is true
of the *first* head on a connection and false of every head after a request
body. After a `POST`, the bytes between the head and the next request are the
body, and a body can contain `\r\n\r\n` itself, so "scan for the terminator"
would substitute a credential into the middle of someone's form post.

So a correct multi-request relay needs an HTTP framing layer this codebase
deliberately does not have: `Content-Length` and `Transfer-Encoding: chunked` on
the response side, the same on the request side, and — the part that is a
judgement rather than an implementation — what the tunnel does with a response
it cannot frame. The posture this repository takes everywhere else is the
answer: **refuse, do not guess.** A tunnel that cannot frame a response ends
there rather than forwarding a credential into a stream whose boundaries it
does not know, and the client reconnects, which is what an HTTP client does
anyway. That is defensible, and it is also a real layer of new code in the
most security-sensitive part of the broker, which is why it is owed as an
increment and not slipped in at the end of a block that has already found four
defects in this path.

The two-dimensional relay also has a cost that has to be chosen rather than
inherited: both directions need the same `rustls::ServerConnection`, so it
cannot be split across two threads, and it cannot block on one direction while
the other has data. A poll interval small enough not to add latency to a
keep-alive round trip makes revocation *faster* than today's 250 ms and costs
CPU proportional to the number of idle tunnels open. Both numbers are
decisions, and neither should be a default nobody wrote down.

**And the multi-request relay is measured working, end to end, with the real
binaries.** Not a unit test and not a harness: a real `asv-brokerd` with a real
vault, route and policy file, a real `asv run` opening a real session, a real shim,
a real `curl` told nothing but a proxy URL, and a real origin on a real socket.
Before, on one tunnel:

```text
CONN=1 CODE=200      the first request, on one connection
CONN=0 CODE=000      the second request, curl reusing that same connection
```

`CONN=0` was the load-bearing half — curl did not open a second connection, it
reused the tunnel and got nothing back, so the second request never reached the
destination. After:

```text
CONN=1 CODE=200
CONN=0 CODE=200
```

and the destination receives the **real credential on both requests**, which is
the half that is a security property rather than an availability one. One
credential for the first and a stale surrogate for the second would be a tunnel
that looks like it works and quietly fails at the provider. The characterisation
became a claim, and its own message said what to do when it went green: rewrite
both the assertion and the comment.

**The loop is sequential, and that is the design decision worth writing down.**
One request in flight at a time: head, frame, substitute, forward, relay the
body, then read the response. Every real HTTP/1.1 client waits for response *n*
before sending request *n+1*, so the shape costs nothing — and it removes the
duplex deadlock outright instead of papering over it with a second thread and a
poll interval, which is what the previous note here worried about. Both directions
are cancellable at every read, and a revocation reaches a tunnel that is *inside*
the loop rather than only one waiting for its first head.

**Three things a sequential pump refuses rather than half-serves**, each one a
case where the ordinary order would hang rather than fail — both peers waiting,
nothing timing out, and a log with nothing in it: a request carrying
`Expect: 100-continue`, which withholds its body until the origin answers; a
request carrying `Upgrade`; and a `101` from the origin. All three are detected in
`http_frame`, refused before a byte reaches the origin, and reported as
`relay_limit` with the reason attached. The client reconnects, which is what an
HTTP client does anyway.

**A chunked body is relayed byte for byte, framing included.** That is what makes
it safe to have in the credential path: the client parses the *origin's* framing
and the relay expresses no opinion about the body beyond where it ends. Where a
size line is a plain hexadecimal number the relay agrees; where a second parser
could read it differently — `+1a`, `0x1a`, a list, a sign — it is refused.

**And four defects the measurement found in the new code itself**, which is the
usual shape of this block and the reason it is worth the increments:

1. `relay_chunked` **read the CRLF that terminates each chunk and dropped it.**
   26 bytes counted against 22 written, the missing four being the two CRLFs after
   the chunk data. A client parsing that would have found the next chunk's size
   line where its data was supposed to end — a relay that corrupted the framing of
   a message carrying a credential, from a function whose whole contract was not
   to. It was found by a test asserting the counted bytes equal the written ones,
   which is a number nobody can check if the two are the same number.
2. A client hanging up at a message boundary — how **every** keep-alive
   connection ends — was reported as `Io("unexpected end of stream")`, and rustls
   reports the same event as `UnexpectedEof`. With one request per tunnel this never
   surfaced; with a loop it lands on **every ordinary teardown**, so every finished
   tunnel logged an I/O error and an operator reading a log full of them learns to
   ignore the class a real fault arrives under. The transport's EOF is now `None`,
   and the framing layer above it decides whether that was a close or a
   truncation.
3. `FrameError::TooLarge` carried one message for two different bounds, so **a
   body over the per-message limit was reported as "the request head exceeds the
   limit"** — sending an operator to look at head sizes. The two bounds are now a
   `Subject`, and a test puts them side by side because a test that asserted each
   in isolation could not tell they had been confused.
4. A body over the limit was classified `malformed_request`, telling an operator
   the peer sent something broken when the peer sent something correct and the
   answer is a number in this repository. `BridgeError::Limit` exists so a budget
   can be reported as a budget, and `frame_failure` applies that rule at the point
   where the mistake was about to be made.

One of them was not in the new code at all. The test fixture for the scripted
origin waited for its buffer to *end* in `\r\n\r\n` instead of to *contain* it,
and deadlocked when a head and its body arrived in one read — **the same "scan for
the terminator" mistake `http_frame` was written to prevent, reproduced in twenty
lines of test fixture.** It is the better argument for the framing layer that this
increment produced, and the fixture now says why it searches.

**Then the loop was falsified, and the campaign found two more defects and two
rows that were lying about what they tested.** `tests/relay_loop_falsification.py`,
**18 rows, 18 red for the named reason**, no residue in the tree. Its shape is the
one this repository has settled on: each row breaks one thing the loop is supposed
to get right and requires a *named* assertion to go red, and a row where the suite
stays green is a property nothing is watching. A run that produced no `test result:`
line at all is reported `KILLED`, never `ESCAPED` — inventing that verdict is the
one thing a falsification campaign must not do, and the first version of this
runner did exactly that to a suite that was merely slow.

**The lifetime budget was spent after the bytes, not before them.** `max_response`
was enforced by adding the body's length to `returned` *after* the copy finished.
So a `Content-Length` — which is whatever the origin says — was forwarded in full
before the tunnel noticed it had been over budget for some time. An origin
declaring eight gigabytes got all eight gigabytes onto the wire to the client, and
the budget that exists to stop exactly that was a number checked afterwards. The
two sibling arms, chunked and close-delimited, had always bounded the copy itself;
this one did not. The cap is now in front of the copy, and the response head is
charged to it before the head is sent.

**A close-delimited response that ran past the cap was cut at the cap and reported
complete.** With no `Content-Length` and no `Transfer-Encoding` the body ends when
the origin closes, so nothing in the message says how long it is — and a body that
*exactly fills* the remaining budget is indistinguishable from one that is longer.
The relay looked zero bytes past the cap, got nothing, and returned `Ok`. What the
client held was a head promising 512 bytes, 181 of them, and a clean end: the one
outcome this module refuses to produce anywhere else. It looks one byte past the
cap now, and a byte there is a refusal. **The control is a test of its own**, because
"refuse whenever the cap is reached" passes every test in the suite and every real
streaming response.

**And the campaign found a third thing, which is about how the code was written
rather than what it did.** `let remaining = limits.max_response - returned` was a
plain subtraction whose safety depended entirely on the head check three lines
above. Delete the check — which is what row R16 does — and a tunnel that had gone
over budget panicked on `usize` underflow in a worker thread; in a release build
that is a wrap to `usize::MAX` and a budget of nothing. It is saturating now. A
budget whose correctness depends on the line above it holding is one edit away from
not being a budget, and the whole point of that block is that the cap does not come
after the bytes.

**Two of the eighteen rows were the same mutation under two names, and both were
passing for the wrong reason.** L3 is "the CRLF that ends each chunk is read and
dropped" and its replacement re-added the write it meant to delete, so it actually
neutered the *check* — L4's defect, under L4's name. L4's own replacement was a
bare `if false {`, which leaves the block unclosed and does not compile, so the
runner skipped it and nobody noticed that the only row for it had never run. L3 now
deletes the write and keeps the check; L4 empties the check and keeps the write.

**And a row pointed at a test that could not fail for the reason it named.** L6
claimed to isolate the per-chunk budget check, and the arithmetic says it never
could: `body_end = total + size + 2` is compared *after* a size line, and every
chunk sets `total = body_end` on the way out, so a body the per-chunk check refuses
is refused again by the running total at the next line, always. No input reaches
the running total on its own except one whose offending line is the **terminal**
chunk's, because `size == 0` breaks out before `body_end` is computed at all. The
row now names that input, and the assertion that fires is the byte count on the
client side of the copy: the refused terminal size line was never written. The
version of that test which claimed the opposite made an arithmetic claim about its
own fixture that was simply false, and a test whose arithmetic has not been checked
is a test that survives the defect it was written to catch.

**And the workload this block kept deferring: a real `npm install` through the
real relay, with the real client.** Not a harness and not three scripted `GET`s
— `npm` on this machine, which has never heard of Agent Secretless, handed a
registry URL and an `HTTPS_PROXY` and nothing else, against a real `asv-brokerd`
with a real vault, route and policy, through a real session shim. The origin is
a process the driver starts and it is the **witness**: it decides whether the
bytes it was handed are the real credential or the surrogate, which is the only
vantage point from which that question has an answer
(`tests/connect_workload_e2e.py`).

```text
npm install          exit 0, node_modules/asv-workload present, 8.4 s
origin requests      242
tunnels              4
requests per tunnel  60.5
bytes                2 264 191  (40 572 packument + 2 223 619 tarball)
real credential      242 of 242
surrogate            0
```

**Both limits this block raised are load-bearing rather than theoretical, and
this is the number that says so.** 242 requests is 2.6× the 93 that the session
budget died at, and 2.26 MiB is past the 2.1 MiB that the response cap used to
refuse. A relay that could carry three scripted requests and could not carry this
would look identical in every test the block had written. The four-tunnel,
sixty-per-tunnel shape is also the thing no scripted fixture can produce: `npm`
opens a bounded number of connections and reuses each of them for dozens of
messages, which is exactly the reuse the one-request relay could not survive.

**And the measurement found the boundary of what this path can reach, which is
not a limit but an architectural gap.** The broker dials its upstream with a
plain `TcpStream::connect`
(`crates/broker/src/tls_bridge.rs`, `serve_connect`): the leg from the broker to
the destination is **cleartext**. A real `registry.npmjs.org` speaks TLS only, so
pointing this at the real registry fails at the first byte for a reason that has
nothing to do with the loop. The registry here is therefore a local one serving
a synthetic dependency tree, and the claim is scoped to that: a real client, a
real workload, real connection reuse, a chunked response on a real client's path,
and the credential property measured at the destination. What it does **not**
establish is that a real HTTPS destination is reachable, because today it is not.
That is owed, and it is owed as TLS on the upstream leg rather than as a bug.

Two smaller things the driver had to learn, both of which is the shape of this
block. A CONNECT route must name a **host**, not a literal address — the product
refuses `127.0.0.1` with *"a route must name a host it can pin"*, which is a
correct refusal and not something a fixture should route around. And `npm`
ignores `NODE_TLS_REJECT_UNAUTHORIZED=0` in favour of its own `strict-ssl`, so
the child needs `--strict-ssl=false`, which is npm's `curl -k` and the same
relaxation the Rust vertical makes and for the same reason.

**A cross-check that was not a second count, after it disagreed with one.** The
broker logs a request total per tunnel, but only for a tunnel that *finishes*;
one still open when the session ends is revoked instead, and produces no line.
One run reported 199 against the origin's 242 and another reported 242. The gap
is the revocation path working, and reading it as a lost log line would have
turned a correct behaviour into a phantom discrepancy. It is reported as an upper
bound now, and the origin remains the witness: it counts what it was handed, and
nothing the broker says about itself can move that number.

**The eighth measurement closed the leg, and the way it was closed is the part
worth reading.** The increment this section owed is built: the transport is a
required field of `ConnectRoute`, the bridge dials TLS and verifies against
operator anchors, and a bridge with no transport declared reaches nothing. What
the campaign then found is not a defect in the product but a **hole where one
was assumed to be.**

`tests/upstream_tls_falsification.py` has 8 rows. On its first run, seven went
red and one came back **ESCAPE**: *a route that declares `tls` is dialled in the
clear* — the declaration silently ignored and the real credential put on the wire
in the open, which is the entire leak this block exists to close. The mutation
was sound. The problem was that **nothing in the workspace had ever constructed
the policy production uses.** All five original properties were measured through
a test-local `Always` that answers whatever it is handed, while the real
implementation is `RouteTransports`. So the leak itself was untested, and every
other row in the campaign had a witness.

```text
R2 a route that declares tls is dialled in the clear   ESCAPE   -> hole, not defect
```

**A campaign row that escapes is a statement about the tests, not about the
mutation.** Reading it the other way round is how a suite ends up green and
wrong, and the cost here was the highest in this block. The hole is closed by two
tests, and the second is the subtle one: `a_destination_no_route_declares_is_not
_dialled` builds the two gates **disagreeing on purpose** — the table names one
host, the bridge's policy authorizes another — because with them in agreement the
policy refuses first and the test would have measured *that* refusal, which is a
real property and not this one. **8/8 red by their named assertion, no residue.**

Three more defects, all of them in the measurement rather than the product, and
all the same failure as the L3/L4 pair the relay campaign found: a row that
cannot run is not a pass. R1's mutation did not compile — twice, as a doubled
`.map` and then as a `Result` unwrapped as an `Option` — so that row had never
measured anything. The runner selected rows by reading `sys.argv[1:]` while
`argparse` had no positionals declared, so **no single row could be re-run at
all**. And reproducing R1 by hand had left the mutation applied to the tree, so
`RouteTransports` was answering `Cleartext` for any destination with no route —
the fail-open default the change exists to prevent — with the suite green around
it.

**What the property is, stated so it can be checked.** The refusal has to happen
at the handshake, before the credential is written, and that is asserted on
**whether `serve_connect` returned a tunnel** rather than on the origin's buffer:
a destination whose handshake failed cannot report bytes it never got to read, so
the buffer cannot distinguish "refused first" from "refused after handing over
the secret". Row T2 deletes the eager handshake and the suite stays green on the
buffer alone — which is why the test was split, and why the split is the
assertion rather than a convenience.

**Still owed in this block.** **Half the default for `--connect-roots` is now
measured and half is not.** `a_broker_given_no_destination_anchors_reaches_no
_tls_destination` starts the **real binary with the flag absent** and watches a
route declaring `tls` reach nothing — zero handshakes at a real TLS origin, no
request, no credential — with a control that runs the same fixture against the
same CA, flag present, and asserts a 200 and the real credential. Falsified:
discarding the anchors the broker loaded turns the *control* red, which is the
half that had to move first. The half still owed is the **public-roots
fallback**: proving the absence of anchors never quietly becomes a trust-everyone
set needs an origin holding a **publicly-issued** certificate, and every origin
in this repository trusts a CA the test minted itself, which a public bundle
would refuse exactly as an empty store does. That is why the campaign called the
gap unclosable here rather than closing it with a test that cannot see it.
**No public HTTPS destination has been reached through this**, for the same
reason plus the open bundled-roots decision: a fixed public root set would verify
`registry.npmjs.org` with this product's credentials and refuse every destination
an operator runs on a private CA. `webpki-roots` is in `Cargo.lock` only
transitively, so choosing it is a new dependency and the campaign could not
falsify that choice. And **every fixture in this repository still dials a
loopback origin in `cleartext`**, so the end-to-end verticals exercise the
`cleartext` declaration and not the `tls` one — the TLS leg is measured against
a locally minted CA, which is honest and is not the same as a registry. Also
still owed: **stress and cancellation under load** beyond the anti-replay
property already measured — and **that is now measured too**.
`a_revocation_under_load_ends_one_sessions_tunnels_and_nobody_elses` stands up
twelve real tunnels in flight against a destination that promises 64 response
bytes and sends 2, so every relay is mid-copy, and revokes one session. Its
eight tunnels all end inside 20s, all reporting `Cancelled(SessionRevoked)`
rather than an I/O error or a budget; the other session's four are untouched.
**The scoping is the half that is new.** With one tunnel there is nothing to
spare, so every earlier revocation test would have passed against a `revoke`
that cancelled everything. Falsified both ways: dropping the session from the
relay's cancel check leaves `0 of 8` ending, and making `is_revoked` answer true
for any non-empty revoked set ends the *untouched* session's tunnels too.

It is measured in process for a structural reason, not a preference: `asv run`
stops its shim *before* it ends a session, so end to end a tunnel closing is
equally consistent with the shim dying and with the broker cancelling. The
first run of this test reported `1 of 8` and the reason is worth keeping — the
fixture minted a session per rig, so seven of the eight belonged to sessions
nobody had revoked. **A correct product refusing to cancel tunnels it had no
authority over, read as a cancellation that did not scale.**

**And the broker had no ordered shutdown at all** was
the last thing owed here, and it was a defect rather than a gap:
`ShutdownSignal::stop` — the mechanism that ends a tunnel deliberately, the one
the accept loop watches and the bridge polls every 50 ms — had **no caller
outside tests**. An operator's `SIGTERM` therefore did what the kernel does to
every process: it killed the broker, and the tunnels died with it as a side
effect of their descriptors closing, recorded in the chain as nothing at all.
**The same defect `revoke` turned out to have one increment earlier, found
again in the method beside it**, which is the argument for asking what a
mechanism's callers are rather than whether the mechanism works.

`a_terminated_broker_ends_its_tunnels_by_shutdown_and_says_so` now signals a
real broker with a real relay still pumping and asserts both halves: the process
leaves with its own exit code rather than a signal's, and the chain carries
`"outcome":"cancelled"` with `"detail":"shutdown"`. Falsified one half at a time
— removing the handler fails the exit-code assertion, and leaving `stop()`
uncalled while the process still exits cleanly fails the chain one. Measuring it
needed a fixture shape the file did not have: every existing origin lets the
relay *finish*, so a signal sent afterwards lands on an idle broker. The new
`OriginMode::Stall` promises 64 response bytes and sends 2, which is the only
way to leave the relay itself mid-copy — **a test that cannot put the product in
the state it is about is a test about the fixture.**

The drain waits on a real in-flight gauge, `InFlight`, which counts a tunnel as
over only *after* its outcome reaches the chain. The first version waited on a
flag `stop` sets before it returns, so the window collapsed to nothing and the
process left before the outcome was written — the chain assertion caught exactly
that, with a chain that ended mid-conversation.

### V1-C2 — the six criteria, and what each one rests on

The criterion is a property of the product, not a feature that was intended, so
every line below names the test that carries it. A criterion whose witness is a
document is not a criterion; a criterion whose witness is a log line is not
either, and two of these were log lines until this block replaced them.

| criterion | VERIFIED by |
|---|---|
| **freshness** | `a_proof_replayed_with_the_same_counter_is_refused`, `a_counter_arriving_out_of_order_after_a_gap_is_accepted`, `a_counter_replayed_after_a_gap_is_still_refused`, `a_counter_older_than_the_window_is_refused_rather_than_accepted`, `ending_a_session_releases_its_replay_window` in `crates/broker/src/lib.rs`; `uat_005_replay` 6/6; and `the_anti_replay_window_refuses_no_honest_proof_under_load` in the vertical, where 64 concurrent CONNECTs from one session had **zero** honest proofs refused |
| **identity** | `an_unauthorised_destination_is_refused_before_the_proof_is_looked_at` and `an_unauthorised_target_opens_no_upstream_socket` in `crates/broker/tests/uat_010_connect_substitution.rs` and `connect_serve.rs` — a CONNECT with no session opens no socket, which is the fail-closed case as a type rather than as a comment |
| **policy** | `a_route_the_policy_does_not_permit_is_refused_at_load` in the vertical, and `a_route_must_say_how_its_destination_is_reached` beside `an_unknown_field_is_refused_rather_than_ignored` in `crates/broker/src/connect_routes.rs` (18/18). Every route is authorized against Cedar **at load**, one refusal fails the whole load, and the fields an operator must state — `minimum_posture` and `upstream` — have no defaults, so neither can be chosen by omission |
| **revocation** | `a_revocation_under_load_ends_one_sessions_tunnels_and_nobody_elses` — twelve real tunnels in flight, one session revoked, that session's eight ending as `Cancelled(SessionRevoked)` and the other session's four untouched; `connect_session_revocation_wiring` 4/4; and `a_tunnel_does_not_outlive_the_session_that_authorised_it`. **The scoping is the part no earlier test could see**, and both of its mutations were run: dropping the session from the cancel check leaves 0 of 8 ending, and an unscoped `is_revoked` ends the *untouched* session's tunnels |
| **audit** | `connect_audit_chain` 9/9, plus `a_client_with_no_credential_cannot_write_its_own_text_into_the_operator_log` and `the_brokers_own_log_carries_neither_the_credential_nor_a_surrogate` in the vertical. A CONNECT outcome and the requests around it verify against one durable chain, the chain carries a **class** rather than the error's text, and the text a client controls reaches neither surface |
| **secretlessness** | `asv_run_curl_reaches_the_origin_with_the_real_credential_and_nobody_else` in the vertical, `no_replay_path_exposes_the_real_credential`, and `a_tracing_script_cannot_dump_a_real_credential` (1/1). The real credential reaches the destination and nothing else; the origin is the witness, and the argument to that, the audit record and the operator's log, is what makes it a property rather than a reading of the broker's own account of itself |

The vertical behind most of them is the one that makes the rest mean anything:
a real `asv-brokerd`, a real vault, a real route file and policy, a real
`asv run` opening a real session and starting a real shim, an ordinary `curl`
told nothing but a proxy URL, and a real destination on a real socket — with the
credential planted through `asv add-credential`, because a route names a
canonical id only the product mints.

**Three things this block does not claim, and two of them are not small.**

1. **The destination leg is verified against a locally minted CA.** No public
   HTTPS destination has been reached through this path, because that needs a
   decision about bundled roots that is a threat-model question and not an
   implementation one. A fixed public root set would verify
   `registry.npmjs.org` with this product's credentials and refuse every
   destination an operator runs on a private CA.
2. **Half the `--connect-roots` default is unfalsifiable here.** A broker with
   no anchors reaching no TLS destination is measured with the real binary and
   the flag absent, control included. Proving that the absence never falls back
   to a public root set needs an origin holding a **publicly-issued**
   certificate, and every origin in this repository trusts a CA the test minted —
   which a public bundle would refuse exactly as an empty store does.
3. **The drain is a bound, not a latency claim.** A signalled broker waits at
   most 5 s for its tunnels and logs when the window expires. No run has
   triggered that, and the figure is a safety valve rather than a measurement.

With those written down, V1-C2 is `verified`. The next block is **C1-R** — a
dedicated OS identity for the broker, which is M7's residual and which removes
a class of attack this product currently only mitigates.



Adopted from `docs/asv-agent-first-security-evolution-v2-2026-10-02/`. **This
section is the integration point, and it is the only one.** The pack remains
where it was written, as research, with its own baseline and its own
`00-README.md`; it does not become a second planning authority, and nothing
above this line is superseded by it. What is adopted here is its *sequence* and
its *invariants*; its work-unit identifiers are referenced from here so that a
reader has one place to look.

```text
              v1.0
                 │
                 ▼
M14  Credential Workflow Adapters (npm, Maven, Gradle, curl)
                 │
                 ▼
M15  Authority Planning & Plan-Bound Execution
                 │
          ┌──────┴──────┐
          ▼             ▼
       M16             M17
 Durable automation  Attested Authority
          │             │
          └──────┬──────┘
                 ▼
M18  v1.1 stabilization
```

The rule that governs all five: **reuse, do not rebuild.** M14 must not create a
second vault, an OAuth framework, an HTTP proxy or an isolated executor — those
are M4, M10 and M11, and M15 plans *over* the capabilities that exist rather
than re-deriving them. M16 puts PipelineK outside the broker's TCB entirely:
ASV keeps ownership of rotate, adopt, switch, revoke, freeze, logical bindings
and reconciliation, while PipelineK owns sequencing, wait/resume, retry and
durable workflow state. The boundary is a law, not a preference —
`asv-brokerd -X-> PipelineK`.

M17 depends on M7 hardening, M12 real TPM evidence and M15's plan object, in
that order. TDX/SEV-SNP stays conditional research and is not a requirement to
close M17.

## Prioritization rule after v1

Do not optimize for number of credential providers. Prefer integrations that improve one of:

1. percentage of daily agent shell work that is strong-secretless,
2. reduction of agent configuration,
3. reduction of privilege scope,
4. quality of attribution/audit,
5. portability without weakening invariants.
