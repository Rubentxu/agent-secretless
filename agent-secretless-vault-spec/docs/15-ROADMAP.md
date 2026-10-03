# ROADMAP — Planning Authority

This file is the single planning authority for the initial product line and for
its continuation. Specifications and ADRs define intent/decisions; this roadmap
defines sequence and exit criteria.

**Verifiable status does not live here.** This file says what is planned and in
what order. Whether something is actually true today is asserted in
`16-SECURITY-RELEASE-GATES.md`, which is checked against the repository by
`scripts/check-gate-status.py` and `tools/check-gates.py`. A milestone in this
file is not a claim about the world; a row in that file is.

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
`crates/broker/tests/uat_048_landlock_install_paths.rs` cover the mapping from
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

---

## M12 — TPM/hardware-backed vault

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

---

## v1.0 — Certified product line

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
CURRENT: v0.28.0
│
├─ V1-C0  Rebaseline / truthfulness        ← this document, this cycle
├─ V1-C1  M7 residual: agent uid != broker uid
├─ V1-C2  M9 productionization residuals
├─ V1-C3  M11 against a real OAuth2 provider
├─ V1-C4  M12 against real TPM hardware
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
  **First delivery, measured** (`crates/broker/src/connect_listener.rs`, the
  V1-C2 receipt): the listener and the lifecycle it owns are `implemented` and
  their tests are `verified`; the wiring into `asv-brokerd` is **not** done, so
  M9's third limit stands unchanged. See *V1-C2 — what is built and what is
  not* below for the split, the two falsified claims this delivery corrected,
  and the one claim that could not be made deterministically.
- **V1-C3** turns M11 from a prototype into a vertical. The `ClientCredentialsIssuer`
  becomes a *reference implementation* rather than the evidence of closure, and
  the closure is an HTTPS POST to a real token endpoint producing a short-lived
  credential that reaches an operation and is then revoked, expired and audited.
  M15's strategy selection is only meaningful over provider-backed strategies,
  so this is a prerequisite and not a parallel.
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
- Observability reaches `ListenerReport` and stops there. It is not yet wired to
  the audit chain.
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

## After v1.0 — M14 through M18

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
