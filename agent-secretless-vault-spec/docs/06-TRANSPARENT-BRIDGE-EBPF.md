# Transparent Credential Bridge and eBPF Research

> **Outcome, recorded 2026-10-01: the transparent socket redirect did not ship.**
>
> This document is the research that produced the decision; it is kept as the
> record of *how* the decision was reached and is not a description of the
> product. The formal NO-GO lives in `15-ROADMAP.md` (M8) and its verifiable
> form in `16-SECURITY-RELEASE-GATES.md`; the two legs of evidence are that
> `cgroup_attach_skeleton` performs no syscall and no BPF object was ever
> written, and that this build host cannot load one
> (`docs/receipts/m9-ebpf-capability-block.md`).
>
> What shipped instead is this document's **explicit-proxy** path, not its
> transparent one: the CONNECT bridge in `crates/broker/src/tls_bridge.rs`,
> with credential substitution on the CONNECT path. Sections 1, 3 and 4 below
> are unaffected — the rejection of `bpf_probe_write_user` and the
> egress/telemetry role are both still the design. What changed is §4.1 and §5's
> transparent branch, which describe a mechanism that will not exist, and the
> `ACCEPT advanced` cell in §12.

## 1. Question

Can eBPF transparently replace a placeholder with a real token/credential at runtime so arbitrary shell/CLI tools can authenticate without ever receiving the secret?

## 2. Short answer

**Direct user-memory replacement with eBPF is technically possible in narrow cases but is the wrong security primitive and is rejected for the product core.**

**Transparent socket redirection with eBPF is viable and useful.** The actual credential substitution should happen in a userspace protocol/TLS broker outside the agent process.

## 3. Why direct `bpf_probe_write_user` is rejected

Linux exposes `bpf_probe_write_user`, which can modify user-space memory from certain tracing contexts. Its documentation explicitly warns that it should **not** be used to implement security because of TOCTOU races and describes it as suitable for experiments/debugging/manipulation of semi-cooperative processes.

Even ignoring that warning, a generic placeholder patcher fails in practice:

1. The secret would end up inside the target process address space.
2. The exact buffer to patch differs by language/runtime/library.
3. A CLI may copy/encode/hash/sign the token before a convenient hook.
4. For HTTPS, the kernel normally sees encrypted TLS records, not HTTP headers.
5. OpenSSL, rustls, Go TLS, Java JSSE, Node/BoringSSL and custom stacks expose different user-space call sites.
6. `write`, `writev`, `send`, `sendmsg`, io_uring and library-internal buffering complicate coverage.
7. Any uprobe strategy is ABI/version sensitive.
8. Mutation races can crash or corrupt processes.

**ADR decision:** eBPF MUST NOT inject real credential bytes into arbitrary agent user memory.

## 4. Where eBPF *is* a strong fit

### 4.1 cgroup socket redirection

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` hooks at `connect4/connect6` can inspect, deny or rewrite a destination. Linux also offers `getpeername` hooks so applications can continue observing the original logical peer after socket-level rewriting.

This enables:

```text
Agent CLI thinks: api.example.com:443
            |
            | connect()
            v
cgroup eBPF rewrites selected flow
            |
            v
127.0.0.1:ASV_PROXY
            |
            v
ASV broker connects to original target
```

A BPF map can retain original destination/socket metadata. This is conceptually similar to socket-level service translation patterns already used by systems such as Cilium.

### 4.2 egress enforcement

For a protected worker or session, cgroup hooks can deny connections not in the policy map.

This is particularly valuable for `EXEC_ISOLATED`: if a worker must hold a raw credential, it should only be able to reach the exact intended service.

### 4.3 session/process evidence

Tracepoints/LSM/cgroup association can provide:

- exec events,
- process ancestry evidence,
- outbound connect events,
- session attribution,
- policy-denial telemetry.

Payload inspection is deliberately avoided.

### 4.4 optional BPF LSM

BPF LSM can add runtime MAC/audit hooks on supported systems. It is a later hardening layer, not required for v1, because it increases privilege/kernel compatibility requirements.

## 5. Proposed Transparent Credential Bridge (TCB)

### Mode TCB-HTTP

The agent receives a surrogate token:

```bash
GITHUB_TOKEN=__ASV_SURROGATE_a91...__
```

The CLI constructs an ordinary request containing the surrogate.

For tools honoring proxy settings:

```text
CLI -> explicit ASV TLS proxy -> upstream
```

For tools ignoring proxy settings, Linux transparent mode can use eBPF socket rewriting:

```text
CLI -> connect(api.example.com:443)
       eBPF redirects socket
     -> ASV TLS bridge
     -> api.example.com:443
```

The TLS bridge:

1. verifies the original destination is policy-approved,
2. terminates client-side TLS using a session-scoped CA,
3. parses the application request,
4. recognizes a surrogate credential/reference,
5. asks broker for an authorized credential operation,
6. substitutes/signs **inside broker/proxy memory**,
7. creates a fresh validated TLS connection upstream,
8. rejects unsafe redirects/authority changes.

## 6. Session-scoped CA design

Never install an ASV CA as a permanent system root by default.

For a transparent session:

1. broker generates ephemeral root/intermediate material,
2. root trust is injected only into the launched process tree where possible,
3. CA private key stays broker-side,
4. leaf certificates are issued only for explicitly permitted hostnames,
5. wildcard issuance is prohibited by default,
6. CA is destroyed on session end.

Typical compatibility environment may include application-specific trust variables/configuration such as generic OpenSSL/curl/Python/Node/Java trust paths. This is necessarily ecosystem-dependent and must be tested per runtime.

### Limitation

Applications using certificate pinning, embedded roots, custom TLS stacks or unsupported trust discovery will not work in this mode. ASV must not bypass pinning by patching the process.

## 7. TLS bridge threat controls

### Host normalization

Authorize using parsed canonical authority, not string-prefix matching.

Check:

- DNS name,
- SNI,
- HTTP `Host`/`:authority`,
- destination IP/port,
- connector audience.

### Redirects

Default: deny cross-origin redirect while a credential binding is active.

Same-origin redirects are re-authorized after URL normalization.

### DNS rebinding

Resolve/bind upstream destinations within broker policy. Do not accept an agent-controlled arbitrary resolved IP merely because hostname text matches.

### CONNECT

Generic HTTP CONNECT from the agent must not become an escape tunnel. Only configured targets may be connected.

## 8. Non-TLS / protocol cases

For PostgreSQL and similar protocols, use protocol-aware proxying rather than byte-level placeholder replacement.

For plaintext HTTP (rare), the proxy may substitute without TLS interception, but the external upstream should normally still be TLS-protected.

## 9. eBPF privilege architecture

Do not run `asv-brokerd` with broad BPF/network-admin privileges.

Use:

```text
asv-ebpfd (tiny privileged helper)
    - owns approved BPF objects/maps/cgroups
    - accepts a narrow local protocol
    - contains no vault access

asv-brokerd (_asv user)
    - requests map/session changes
    - owns secrets
```

The helper only loads shipped/signed program variants. It must not accept arbitrary BPF bytecode from clients.

## 10. Aya

Use Aya for Rust eBPF development because it supports Rust user-space/eBPF workflows and CO-RE without a runtime dependency on BCC/libbpf.

Recommended crates/modules:

```text
crates/ebpf-common      shared repr(C) map/event types
crates/ebpf-programs    no_std Aya eBPF code
crates/ebpf-controller  privileged userspace loader/controller
```

## 11. R&D spike required before committing transparent mode

### Spike E1 — socket redirect

Prove on supported Linux kernels:

- redirect a target `connect4/connect6` from a protected cgroup to local proxy,
- retain original destination in BPF socket storage/map,
- preserve sensible `getpeername`,
- exclude proxy's own upstream sockets to avoid loops,
- clean maps reliably after socket/session end.

### Spike E2 — TLS trust compatibility

Validate:

- curl/OpenSSL,
- Python requests,
- Node,
- Git/libcurl,
- GitHub CLI,
- Go CLI,
- Rust rustls/native-tls examples,
- Java CLI.

Record which require explicit config and which cannot be intercepted.

### Spike E3 — surrogate replacement

Demonstrate:

- CLI sees only surrogate,
- broker inserts real token,
- `/proc`, `env`, `gdb` against CLI never show real token,
- malicious redirect cannot carry credential elsewhere,
- surrogate copied outside session is useless.

### Spike E4 — performance

Measure p50/p95 latency and throughput overhead for explicit proxy vs eBPF redirect.

## 12. Decision matrix

| Approach | Technically viable | Strong security | Generic | Product decision |
|---|---:|---:|---:|---|
| eBPF writes real secret into CLI memory | Narrowly | No | No | REJECT |
| uprobe TLS-library patching | Narrowly | No | No | REJECT |
| seccomp user-notify rewrite of buffers | Narrowly | No/fragile | No | REJECT |
| eBPF cgroup socket redirect to broker | Yes | Yes as routing/enforcement | Linux | **NOT SHIPPED — superseded by the M8 NO-GO.** Viable in principle; the research produced no program and the build host cannot load one. The transparent *UX* it promised is delivered instead by the explicit CONNECT bridge |
| explicit local proxy | Yes | Yes with strict audience binding | Broad HTTP | ACCEPT core/early — **this is the path that shipped** |
| session TLS bridge + surrogate | Yes | Strong with stated limits | Broad HTTP | ACCEPT optional — **shipped, as the CONNECT path** |
| protocol-specific proxy | Yes | Strong | Per protocol | ACCEPT core |

Two rows changed after 2026-09-28 and are annotated rather than rewritten: the
redirect, which was `ACCEPT advanced` and is not shipping, and the two rows
below it, which were correctly marked and turned out to be what the product is
actually built on. A decision matrix that is edited to agree with the outcome
stops being evidence, so the original verdict is left in place next to what
happened to it.

## 13. Bottom line

Use eBPF to make the **path** transparent, not to make the **secret bytes**
magically appear inside an untrusted process.

That keeps the central invariant intact and still delivers the UX benefit: the
agent runs familiar commands while the kernel transparently steers eligible
traffic into a credential broker.

**The invariant half held; the mechanism half did not.** The first sentence is
the design and it survived the research intact — no secret bytes in an untrusted
process, which is the property everything else serves. The second sentence was
the promise eBPF was supposed to keep, and it is delivered by something else: an
ordinary `HTTPS_PROXY` and a CONNECT bridge, with the client configuring its
proxy explicitly. A CLI that ignores proxy settings is not covered by anything
in this repository, and that limitation is stated rather than engineered around,
because the alternative — a mechanism that does not exist — cannot be stated
honestly at all.
