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

### Status: open. The first measurement is in, and it is not a security finding

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

**Still owed in this block.** Shutdown and revoke *mid-tunnel* — the shim's own
teardown is measured and the session's revocation is measured, but a tunnel
revoked while bytes are flowing is not. Stress and cancellation. And the
observability sweep, which is the part most likely to be wrong in a way nobody
is looking for.



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
