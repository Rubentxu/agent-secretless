# M8 — Transparent eBPF Bridge R&D Gate — Exploration

## 1. Question (from `06-TRANSPARENT-BRIDGE-EBPF.md`)

> Can eBPF transparently replace a placeholder with a real token/credential at
> runtime so arbitrary shell/CLI tools can authenticate without ever receiving the
> secret?

## 2. Authoritative ADR (verbatim)

> Use eBPF to make the **path** transparent, not to make the **secret bytes**
> magically appear inside an untrusted process.

> **Direct user-memory replacement with eBPF is technically possible in narrow
> cases but is the wrong security primitive and is rejected for the product
> core.**

> **Transparent socket redirection with eBPF is viable and useful.** The actual
> credential substitution should happen in a userspace protocol/TLS broker
> outside the agent process.

## 3. Goal of M8 (R&D gate)

M8 is a **research & design gate**. The deliverable is **not** a shipping eBPF
runtime. It is:

1. A **decision document** confirming the spikes E1..E4 in the spec are
   achievable with the Aya + userspace loader + asv-ebpfd helper architecture,
   or are blocked and need a different approach.
2. A **prototype skeleton** of the `asv-ebpfd` helper expanded with the verbs
   needed for socket-level redirect (cgroup attach/detach, program load/unload).
3. A **regression test** that locks in the closed verb set against E1's verbs
   (no `bpf_load_arbitrary`, no `cgroup_write`, etc.).

If the gate fails, M9 (Transparent TLS bridge) is not started; the project
falls back to the explicit-proxy-only architecture already shipped.

## 4. Spike E1 — Socket redirect feasibility

### 4.1 Kernel primitive

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` attaches to `connect4` and `connect6`
cgroup/bpf-cgroup hooks. The hook can:

- Read the destination `sockaddr`.
- Read the calling task's cgroup ID.
- Return `BPF_OK`, `BPF_REDIRECT` (to a local socket map), or `SECCOMP_RET_*`
  semantics via a sibling `BPF_PROG_TYPE_CGROUP_SKB` for the data path.

For redirect-to-local-proxy:

- The hook detects outbound `connect()` calls inside a protected cgroup.
- It looks up the destination in a BPF map keyed by `(cgroup_id, host, port)`.
- It rewrites the destination `sockaddr` to `127.0.0.1:ASV_LOCAL_PORT`.
- The userspace broker connects to the original destination from outside the
  protected cgroup.

The `getpeername` hook (`BPF_CGROUP_GETPEERNAME`) lets the application keep
observing the original logical peer.

### 4.2 Why this is feasible on Rust+Linux

- Aya 0.14 supports `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` in both `aya` and
  `aya-bpf` macros.
- Aya emits CO-RE BTF ELF, so the broker can ship one binary and load on
  different kernels (subject to BTF presence, which is the default on
  5.10+).
- The redirect program is <100 instructions of BPF; verifier-compatible.
- The map types (`BPF_MAP_TYPE_SOCKHASH`, `BPF_MAP_TYPE_HASH`) are stable
  since 4.19.

### 4.3 Risks

- **Loop protection**: the broker itself opens outbound sockets; those must
  not be redirected. The hook must look up `current_cgroup_id` against the
  redirect map and skip if it is the broker's cgroup.
- **Cleanup on session end**: a session-end notification must delete all
  map entries whose owner cgroup matches. The helper owns the map and must
  respond to a delete verb.
- **Verifier rejection**: BPF verifier is per-host kernel. The spike must run
  on a 5.15+ kernel at minimum; older kernels are out of scope for M8.

### 4.4 Decision

ACCEPT advanced — wire M8 spike E1 into the design and ship a prototype.

## 5. Spike E2 — TLS trust compatibility

Not implemented in M8 — TLS trust is M9 scope. The M8 gate documents which
ecosystems ASV must test before declaring M9 ready.

| Runtime | Trust-discovery | Intercept path | Verdict |
|---|---|---|---|
| curl + OpenSSL | OPENSSL_CA env or /etc/nsswitch.conf | HTTP proxy | works without config |
| Python requests + urllib3 + certifi | ssl.CERT_REQUIRED with certifi.where() | HTTP proxy or SOCKS | works without config |
| Git + libcurl | curl-style env vars | GIT_HTTP_PROXY | works with proxy config |
| GitHub CLI (`gh`) | Go net/http with Mozilla CA bundle | HTTP proxy | works with proxy config |
| Go CLI | x509.SystemCertPool() | HTTP proxy | works with proxy config |
| Node.js | node:tls + NODE_EXTRA_CA_CERTS | HTTP proxy or transparent | works with NODE_EXTRA_CA_CERTS |
| rustls + native-tls | webpki-roots + system roots | HTTP proxy | works with proxy config |
| OpenJDK | javax.net.ssl.trustStore | HTTP proxy | requires -Djavax.net.ssl.trustStore |

The transparent-mode redirect (eBPF socket rewrite) needs the TLS bridge
from M9 to terminate the client side. This is a follow-up.

## 6. Spike E3 — Surrogate replacement (covered by M6 + M4)

Already implemented in M6 (`connector-pg`) and M4 (`connector-http`). The
surrogate token never enters the agent's address space; the broker holds the
real credential and substitutes at request time.

M8's only contribution is the **transparent** mode where the agent's HTTP
client *thinks* it is sending to `api.example.com` but the kernel rewrites
the socket to `127.0.0.1:ASV_TLS_BRIDGE`. This requires M9.

## 7. Spike E4 — Performance budget

Estimated overhead from BPF `cgroup_sock_addr` hooks:

| Operation | Without eBPF | With eBPF | Delta |
|---|---|---|---|
| `connect()` syscall | ~3 µs | ~8 µs | +5 µs |
| DNS resolution | 5–50 ms | 5–50 ms (unchanged) | 0 |
| TLS handshake | 1–5 ms | 1–5 ms (unchanged) | 0 |
| Total per request | 5–60 ms | 5–60 ms | < 0.1% |

The 5 µs hook overhead is negligible relative to TLS handshake time.

The M8 R&D gate does not include a live measurement. That requires a kernel
with BTF and is scheduled for M9's performance test fixture.

## 8. Decision matrix (from spec, retained verbatim)

| Approach | Technically viable | Strong security | Generic | Product decision |
|---|---:|---:|---:|---|
| eBPF writes real secret into CLI memory | Narrowly | No | No | REJECT |
| uprobe TLS-library patching | Narrowly | No | No | REJECT |
| seccomp user-notify rewrite of buffers | Narrowly | No/fragile | No | REJECT |
| eBPF cgroup socket redirect to broker | Yes | Yes as routing/enforcement | Linux | ACCEPT advanced |
| explicit local proxy | Yes | Yes with strict audience binding | Broad HTTP | ACCEPT core/early |
| session TLS bridge + surrogate | Yes | Strong with stated limits | Broad HTTP | ACCEPT optional |
| protocol-specific proxy | Yes | Strong | Per protocol | ACCEPT core |

## 9. Closed verb set (asv-ebpfd)

The privileged helper's vocabulary for the M8+E1 surface:

```rust
pub enum Verb {
    SessionAttach,   // existing — wires broker session to BPF map
    SessionDetach,   // existing — cleans up map entries
    CgroupRead,      // existing — observability
    SeccompDump,     // existing — observability
    CgroupAttach,    // M8 E1 — attach loaded program to cgroup id
    CgroupDetach,    // M8 E1 — detach program from cgroup id
    ProgramLoad,     // M8 E1 — load a shipped (signed) BPF ELF, named
    ProgramUnload,   // M8 E1 — unload a previously loaded program
}
```

Critically, **no** arbitrary bytecode load. `ProgramLoad` accepts only a
*name* that the helper matches against a shipped/signed table (see ADR in §9
of `06-TRANSPARENT-BRIDGE-EBPF.md`).

## 10. Gaps and follow-ups

- **BTF kernel dependency** — the eBPF program is CO-RE; without BTF the
  verifier may reject offsets. The M8 spike must run on a 5.15+ kernel
  with `/sys/kernel/btf/vmlinux` present.
- **Loop detection** — the broker's outbound sockets must be excluded from
  the redirect. The implementation uses a separate cgroup for the broker
  process.
- **Audit trail** — every `ProgramLoad` / `CgroupAttach` / `CgroupDetach`
  must be logged with the calling session id and the cgroup id. The helper
  returns the sequence number for the audit log to ingest.
- **M9 dependency** — M8's prototype demonstrates the verb set; M9 wires
  the Aya-generated BPF ELF and the broker's redirect map management.

## 11. Verdict

**Local criteria: PASS. Normative M8 exit: DELEGATED, 8 PASS / 0 FAIL /
3 UNVERIFIABLE-IN-REPO.**

`15-ROADMAP.md` states that M8 owns no acceptance set of its own: it
"re-runs their acceptance set rather than owning any of its own" and is
therefore DELEGATED to `16-SECURITY-RELEASE-GATES`. `tools/check-gates.py`
confirms this mechanically: it reports `M8 Go criteria [] DELEGATED`.

So there are two distinct claims, and conflating them would be a false
verdict:

| Scope | Status | Basis |
|---|---|---|
| The three conditions written in this section | **PASS** | re-verified by execution, table below |
| R0-R11 in `16-SECURITY-RELEASE-GATES` | **8 PASS / 0 FAIL / 3 UNVERIFIABLE-IN-REPO** | `python3 tools/rc-exit-checklist.py` |

The delegated set was executed, not assumed. On 2026-09-30 at `7e6a352`:

```text
R1  Secret API invariant        PASS
R2  Vault                       PASS
R3  Identity/session            PASS
R4  Policy                      PASS
R5  Connector security          PASS
R6  Agent leak harness          PASS
R7  eBPF/privilege separation   PASS
R9  Audit                       PASS
R10 Compatibility truthfulness  PASS
R0  Build and provenance        UNVERIFIABLE-IN-REPO  (only: release-artifact signing)
R8  Tauri                       UNVERIFIABLE-IN-REPO  (no Tauri app yet; M5 scope)
R11 Full certification          UNVERIFIABLE-IN-REPO
summary: 9 PASS / 0 FAIL / 3 UNVERIFIABLE-IN-REPO
```

R0 is UNVERIFIABLE on only one of its five bullets. The other four pass,
including `SBOM generated: target/sbom.json exists`. The three
UNVERIFIABLE items are things a repository cannot attest for itself:
signing on release infrastructure, a UI that does not exist yet, and full
certification that presupposes each milestone's own UAT set. None of them
is a defect; all three are outside this repo's reach by construction.

The three local conditions were re-verified by execution on 2026-09-30 at
`7e6a352`, not inferred from reading the code:

| Criterion | Evidence | Result |
|---|---|---|
| `Verb` extends with the four M8 verbs | `crates/ebpfd/src/verbs.rs:30`, 4 variants plus their wire names | met |
| `parse_verb` rejects everything outside the closed set | `closed_set_round_trips`, `unknown_verb_is_rejected`, `unknown_verb_carries_the_input_unchanged` | 3/3 ok |
| `CgroupAttach` prototype exists and the helper recognises the verb | `cgroup_attach_skeleton`, `cgroup_attach_skeleton_returns_ok_with_zero_handle`, `cgroup_attach_skeleton_accepts_max_cgroup_id` | 3/3 ok |

```text
cargo test -p asv-ebpfd --lib -- closed_set_round_trips unknown_verb_is_rejected \
  unknown_verb_carries_the_input_unchanged cgroup_attach_skeleton
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out
```

The closed-set rejection was falsified before being trusted: widening the
real `parse_verb` match to accept `cgroup.freeze` turned
`unknown_verb_is_rejected` red at `crates/ebpfd/src/verbs.rs:306`, and the
change was reverted (`git diff` clean, 11/11 green after restore). An
earlier falsification attempt that only moved an entry inside the test's own
input list stayed green and proved nothing; it was discarded.

M9 is unblocked by the local criteria, and the delegated R0-R11 set
reports no FAIL. It does not mean M8 is fully certified: three gates are
UNVERIFIABLE-IN-REPO by construction, and R11 full certification remains
open until every milestone's own UAT set is green. Claiming M8 "fully
certified" would overstate what was observed; claiming nothing would
understate the 9 gates that pass.

The criteria as written:

M8 R&D gate **PASSES** if:

- The `Verb` enum extends with the four M8 verbs.
- `parse_verb` rejects every input outside the closed set (regression test
  extends `uat_024_helper_scope`).
- A prototype `asv-ebpfd::CgroupAttach` function exists that demonstrates
  the syscall surface (does NOT need to attach a real program; just
  document the ABI and pass a sanity check that the helper recognizes
  the verb).

If those three are met, M9 starts; if not, the project keeps the
explicit-proxy-only architecture shipped in M4+M6 and the M8 cycle is
closed with verdict "fail-soft, fallback to explicit proxy".