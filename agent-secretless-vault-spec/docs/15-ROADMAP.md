# ROADMAP — Planning Authority

This file is the single planning authority for the initial product line. Specifications and ADRs define intent/decisions; this roadmap defines sequence and exit criteria.

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
R5 Transparent bridge/eBPF
   ↓
R6 Connector expansion
   ↓
R7 Security stabilization RC
   ↓
v1.0 certified
```

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
- UAT-024.

### Gate notes

The eBPF wrong-cgroup case is deliberately **not** an M7 gate: it requires
socket redirection, which is not part of M7. M7's scope stops at cgroup v2
ownership, Landlock and seccomp; the eBPF redirect path is an M8 research
decision that only becomes a feature at M9, and M9 claims it.

Isolated worker exfiltration is likewise **not** an M7 gate: it requires the
registered worker templates and separate-identity workers, which are M10's
scope. M10 claims it.

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

### Go criteria

- no direct `bpf_probe_write_user`,
- no generic uprobe patching,
- no permanent system CA,
- explicit list of supported client/runtime combinations,
- reliable cleanup and fail-closed behavior.

This is a go/no-go research gate, not a shipped connector: its experiments
reuse the surrogate and hardened session delivered by earlier milestones, so it
re-runs their acceptance set rather than owning any of its own. It is
therefore DELEGATED to `16-SECURITY-RELEASE-GATES` and is not gated on UAT.

### No-go fallback

Keep explicit proxy + service shims; eBPF remains egress/telemetry only.

---

## M9 — Transparent TLS bridge

**Conditional on M8 GO.**

### Scope

- per-session ephemeral CA,
- local trust injection adapters,
- leaf issuance for exact hosts,
- eBPF transparent routing,
- HTTP/1.1 + HTTP/2 compatibility where proxy stack supports it,
- strict CONNECT/redirect controls,
- UI indicator that TLS interception is active.

### Exit UAT

- UAT-010, 011, 012, 013,
- TLS compatibility matrix published from tests.

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

All release gates in `16-SECURITY-RELEASE-GATES.md` pass.

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
- transparent eBPF bridge only if M8/M9 passed,
- compatibility worker clearly labelled,
- CLI + optional MCP control surface.

### Exit

Release aggregation, not an independent gate: it is the union of the milestones
above. Completion is DELEGATED to `16-SECURITY-RELEASE-GATES`.

## Prioritization rule after v1

Do not optimize for number of credential providers. Prefer integrations that improve one of:

1. percentage of daily agent shell work that is strong-secretless,
2. reduction of agent configuration,
3. reduction of privilege scope,
4. quality of attribution/audit,
5. portability without weakening invariants.
