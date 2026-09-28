# Vision and Architectural Principles

## Vision

Make credentials boring for agents.

An agent should be able to execute normal shell workflows without learning passwords, bearer tokens or private keys, while a human can manage credentials and access policies through a familiar local desktop dashboard.

The desired interaction is:

```text
Human stores credential once
        ↓
Human grants capability/policy
        ↓
Agent launches in an ASV session
        ↓
Agent uses normal CLI tools
        ↓
Broker authenticates outside agent process
        ↓
External service
```

The agent should care about **what it is allowed to do**, not **what credential string makes it possible**.

## Principles

### P1 — Capability, not credential

The unit exposed to an agent is an operation/capability such as:

```text
git.push repo=org/repo branch=feature/*
ssh.connect host=build-01
http.request audience=api.example.com
postgres.connect database=analytics role=readonly
release.create repo=org/repo
```

not:

```text
GITHUB_TOKEN=...
AWS_SECRET_ACCESS_KEY=...
password=...
```

### P2 — No raw-secret retrieval API

Agent surfaces MUST NOT expose raw retrieval.

Human-facing export is a separately governed exceptional path, disabled for `NonExportable` credentials.

### P3 — Prefer cryptographic use over secret delivery

Priority order:

1. Non-exportable cryptographic operation (`ssh-agent`, signing, mTLS).
2. Workload identity / delegated identity.
3. Authenticated protocol proxy.
4. Service-specific request signer/re-writer.
5. Dynamic/short-lived credential.
6. Isolated compatibility execution.
7. Raw credential delivery — outside the normal product promise.

### P4 — Shell-first, MCP-second

MCP is control-plane ergonomics. Shell/CLI is the primary data plane.

MCP should be useful for requests like “ask for release permission”, not required for every `git fetch`.

### P5 — Compatibility without pretending it is security

If a tool absolutely requires a real credential in its own process, ASV must label that integration `COMPATIBILITY`, not `SECRETLESS`.

Security posture must be visible to the user.

### P6 — Fail closed for protected operations

If policy evaluation, identity attestation, broker availability or connector validation fails, protected operations fail rather than falling back to raw credentials.

### P7 — Bind access to context

A capability should be bound to as much context as is stable and useful:

- user identity,
- agent session,
- cgroup,
- PID ancestry,
- executable identity,
- workspace,
- repository/resource,
- operation,
- destination/audience,
- TTL,
- maximum uses,
- human approval state.

### P8 — Separate trust domains

The Tauri WebView, the agent, the broker, eBPF controller and credential workers have different trust levels and must not share a single privilege domain.

### P9 — Minimise privileged code

The eBPF/cgroup helper may need elevated privileges. It must be a tiny, narrow service with a strict command protocol, not the main broker.

### P10 — eBPF enforces and redirects; it does not own secrets

eBPF may:

- identify/observe process/session activity,
- constrain or deny network destinations,
- transparently redirect selected sockets to the local broker,
- support reverse mapping for rewritten sockets,
- produce security telemetry.

It must not be the vault and should not patch secret strings into arbitrary user memory.

### P11 — Explicit degradation

On systems without eBPF, TPM, Landlock or `memfd_secret`, ASV continues with a clearly reported lower security profile rather than silently emulating guarantees it cannot provide.

### P12 — Architecture remains evolvable

Connector, provider and platform mechanisms are ports. The domain should not depend on Tauri, Aya, SQLite, MCP, TPM or a specific vault implementation.
