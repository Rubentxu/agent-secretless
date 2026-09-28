# Research Notes and Sources

Research snapshot: **2026-09-28**.

This file records the community/kernel patterns that informed the architecture. Re-check current versions/security status before implementation or release.

## Secretless proxy patterns

### CyberArk Secretless Broker

- Connector model transforms unauthenticated HTTP/TCP requests/connections into authenticated ones.
- HTTP connectors can add Authorization/API-key headers outside the client application.
- Project/source: https://github.com/cyberark/secretless-broker
- Connector documentation: https://github.com/cyberark/secretless-broker/blob/main/pkg/secretless/plugin/connector/README.md

### Aembit AI/MCP identity gateway

- Current documentation describes a gateway that proxies MCP access while downstream credentials remain in the gateway, with user+agent attribution and fail-closed policy.
- https://docs.aembit-eng.com/get-started/use-cases/mcp-server-access/
- https://docs.aembit-eng.com/get-started/use-cases/ai-agents

### Vault dynamic credentials

- Dynamic database credentials, leases and revocation demonstrate replacing static shared secrets with per-use/per-workload credentials.
- https://developer.hashicorp.com/vault/docs/secrets/databases

## Workload identity

### SPIFFE/SPIRE

- Workload API on Unix uses a Unix-domain socket.
- SPIRE identifies caller PID through the kernel and runs workload attestors to derive selectors/identity.
- https://spiffe.io/docs/latest/spire-about/spire-concepts/

### Unix peer credentials

- Linux `SO_PEERCRED` returns peer PID/UID/GID for connected Unix sockets.
- https://man7.org/linux/man-pages/man7/unix.7.html

### pidfd

- `pidfd_open` provides a stable file-descriptor reference to a process; `pidfd_getfd` is guarded by ptrace-style access checks.
- https://man7.org/linux/man-pages/man2/pidfd_open.2.html
- https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html

## SSH-agent pattern

OpenSSH documents that forwarded `ssh-agent` use does not send private keys or passphrases across the SSH connection; callers request identity operations through the agent.

- https://man.openbsd.org/ssh-agent.1

## Linux secret/process hardening

### `memfd_secret`

Provides anonymous RAM-backed secret memory with stronger protections than ordinary mappings.

- https://man7.org/linux/man-pages/man2/memfd_secret.2.html

### Landlock

Stackable Linux Security Module allowing unprivileged processes to restrict themselves; current documentation includes filesystem and network access classes.

- https://docs.kernel.org/userspace-api/landlock.html

### seccomp

- syscall filtering: https://man7.org/linux/man-pages/man2/seccomp.2.html
- user notification: https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html

Important: seccomp user-notification documentation explicitly warns against using the CONTINUE mechanism as a security-policy decision due to race conditions. ASV therefore does not base credential substitution/security on syscall-user-notify mutation.

### `/proc` hidepid

Linux procfs supports `hidepid` modes to reduce cross-process information visibility.

- https://docs.kernel.org/filesystems/proc.html

## eBPF

### `bpf_probe_write_user`

Documentation explicitly says it should not be used to implement security because of TOCTOU issues and risk; it is oriented to debugging/experimental manipulation.

- https://docs.ebpf.io/linux/helper-function/bpf_probe_write_user/

This is the main reason direct secret injection into CLI memory is rejected.

### cgroup socket address programs

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` can act on `connect4/connect6` and rewrite socket destination arguments; `getpeername` hooks can support reverse logical-address presentation.

- https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/

The official/example documentation demonstrates storing original service addresses in socket storage and rewriting connect/peer information, validating the feasibility of ASV's transparent redirection spike.

### BPF LSM

Allows privileged runtime instrumentation of Linux Security Module hooks for MAC/audit policies.

- https://docs.kernel.org/bpf/prog_lsm.html

### Cilium patterns

Cilium demonstrates production use of eBPF socket-level service translation and transparent proxy injection, useful as architectural evidence that socket redirection to a userspace L7 proxy is viable.

- https://docs.cilium.io/en/stable/network/ebpf/intro/
- https://docs.cilium.io/en/latest/security/network/proxy/

### Aya

Rust eBPF framework with Cargo workflow and CO-RE support without runtime BCC/libbpf dependency.

- https://aya-rs.dev/book/

## Tauri 2

Tauri distinguishes Rust core and WebView trust boundaries and uses capability configuration to constrain frontend access. Its CSP documentation recommends avoiding remote content and using restrictive CSP.

- https://v2.tauri.app/security/
- https://v2.tauri.app/security/capabilities/
- https://v2.tauri.app/security/csp/

### Stronghold

Tauri offers a Stronghold plugin and IOTA Stronghold provides procedure-oriented protected secret storage concepts.

- https://v2.tauri.app/plugin/stronghold/
- https://github.com/iotaledger/stronghold.rs

Caution: current `stronghold_engine` docs state the library has not had a formal third-party security audit. ASV should evaluate it rather than blindly making it the vault root of trust.

## Policy

### Cedar

Cedar models authorization as Principal + Action + Resource + Context and has explicit guidance for agents acting on behalf of users.

- https://docs.cedarpolicy.com/auth/authorization.html
- https://docs.cedarpolicy.com/bestpractices/bp-using-the-context.html

## Rust secret handling

### `secrecy`

Provides secret wrapper types, explicit exposure traits and zeroization-on-drop behavior.

- https://docs.rs/secrecy/

### `zeroize`

Provides compiler-resistant memory clearing primitives.

- https://docs.rs/zeroize/

### TPM

`tss-esapi` is a Rust wrapper over TPM2 TSS ESAPI.

- https://docs.rs/tss-esapi/

## OWASP

OWASP Secrets Management Cheat Sheet notes that environment variables are generally accessible to processes and can appear in logs/dumps, and recommends avoiding them when other methods are available.

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Research conclusion on placeholder injection

The useful synthesis is:

```text
DO NOT:
  eBPF writes secret bytes into arbitrary process memory

DO:
  surrogate in agent process
       +
  eBPF/session-aware socket redirection (optional)
       +
  userspace protocol/TLS proxy
       +
  broker-side credential injection/signing
       +
  destination/action policy
```

This preserves the secretless boundary while still letting ordinary shell/CLI tools behave as if a credential were configured.
