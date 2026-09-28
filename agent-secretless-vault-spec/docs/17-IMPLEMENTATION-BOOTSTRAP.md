# Implementation Bootstrap

This is the recommended first coding sequence.

## 1. Repository skeleton

```text
Cargo.toml
rust-toolchain.toml
README.md
SECURITY.md
ROADMAP.md -> docs/15-ROADMAP.md or keep a root copy as authority

crates/
  domain/
  ipc-protocol/
  identity/
  session/
  policy-api/
  broker/
  vault-api/
  vault-local/
  crypto/
  connector-api/
  connector-ssh-agent/
  audit/
  cli/

apps/
  brokerd/
  desktop-tauri/      # add only after the first CLI vertical is stable

tests/
  adversarial/
  fixtures/
```

## 2. First types to implement

Avoid framework code first. Start with pure domain invariants:

```rust
CredentialId
CredentialKind
Exportability
AgentSessionId
WorkloadIdentity
Action
Resource
Audience
CapabilityGrant
IntegrationPosture
Decision
```

Secret-bearing type:

```rust
struct SecretBytes(SecretBox<Vec<u8>>);
```

Do not derive `Debug`, `Clone`, `Serialize` on it.

## 3. First end-to-end test before UI

### Test objective

A private SSH key is stored in vault; `asv run -- ssh ...` succeeds; attack child cannot obtain key bytes.

This gives a real vertical across:

```text
vault -> broker -> identity -> policy -> SSH agent -> shell agent session
```

and proves the core architecture before HTTP/Tauri/eBPF complexity.

## 4. Initial IPC methods

Only:

```text
Ping
CreateSession
EndSession
ListCredentialMetadata
BeginCredentialIngest
DeleteCredential
Authorize
```

SSH signing uses the SSH-agent protocol on a dedicated session socket, not a generic “give me key bytes” RPC.

## 5. Broker service prototype

During development the broker can run manually, but early integration must test a distinct OS UID because same-user isolation can mask architectural weaknesses.

Installation research:

```text
systemd system service: asv-brokerd
runtime socket directory: /run/asv/users/<uid>/...
vault storage: /var/lib/asv/users/<uid>/... or carefully permissioned user-specific location
```

Exact paths are implementation decisions; maintain separate ownership.

## 6. Tauri timing

Do not let desktop UI delay the security proof.

Sequence:

1. CLI vault ingestion.
2. SSH vertical.
3. policy/session tests.
4. then Tauri dashboard over stable broker IPC.

## 7. eBPF timing

Do not start by writing BPF programs.

First write `SessionEnforcer` abstraction and a no-op/portable implementation.

Later add:

```text
LinuxCgroupEnforcer
LinuxEbpfEnforcer
```

Run M8 as a research branch/spike with explicit go/no-go evidence.

## 8. Suggested dependencies to evaluate

Core:

```text
tokio
serde (metadata DTOs only)
thiserror
tracing
uuid
rustix or nix
```

Secrets/crypto:

```text
secrecy
zeroize
argon2
chacha20poly1305 or aes-gcm
rand/getrandom
```

Policy:

```text
cedar-policy
```

Storage:

```text
rusqlite/sqlx (metadata + encrypted blobs)
```

Linux/eBPF:

```text
aya
aya-ebpf
```

TPM later:

```text
tss-esapi
```

Treat all versions as a dependency-resolution task at implementation time; pin after compatibility/security review rather than copying versions from this document.

## 9. Coding rules for secret paths

- `#![forbid(unsafe_code)]` where possible.
- Unsafe code isolated in small platform/crypto-memory modules and reviewed separately.
- No `unwrap()` in broker request paths where malformed untrusted input can reach it.
- Bounded allocations for IPC/protocol inputs.
- Error variants carry IDs/context, never secret values.
- Secret access functions deliberately noisy in code review (`expose_secret()` style).
- Connector tests include malicious destination and logging paths.

## 10. Initial backlog

### B0 domain

- [ ] ADTs and invariants
- [ ] posture classification
- [ ] secret-safe error model

### B1 IPC identity

- [ ] Unix server
- [ ] `SO_PEERCRED`
- [ ] pidfd association
- [ ] protocol version
- [ ] fuzz decoder

### B2 vault

- [ ] KDF/envelope
- [ ] encrypted record
- [ ] lock/unlock
- [ ] secret-safe memory wrapper
- [ ] canary log tests

### B3 sessions

- [ ] `asv run`
- [ ] environment quarantine
- [ ] lifecycle/revoke

### B4 SSH

- [ ] agent protocol subset
- [ ] key listing public material
- [ ] sign request
- [ ] policy gate
- [ ] real OpenSSH integration test

### B5 adversarial harness

- [ ] env/proc scripts
- [ ] shell tracing
- [ ] filesystem scan
- [ ] ptrace attempt
- [ ] sentinel scanning

Only after B0–B5 is stable, start HTTP/Tauri work.
