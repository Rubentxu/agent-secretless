# Agent Secretless Vault (ASV) — Architecture & Implementation Pack

> Working name. Rename the product before public release if desired.

**Snapshot:** 2026-09-28  
**Primary target:** Linux developer workstations running coding/AI agents that operate mostly through `sh`, scripts and CLI tools.  
**Implementation:** Rust + Tauri 2, with optional Linux hardening using cgroup v2, Landlock, seccomp and eBPF/Aya.

## One-sentence product definition

ASV is a local credential control plane that lets an AI agent **use an identity or credential without being given the credential material**, with a KeePass-like dashboard for humans and a shell-first data plane for agents.

## Non-negotiable invariant

The normal agent-facing API MUST NOT contain a `getSecret`, `showSecret`, `exportSecret` or equivalent operation.

The primary primitives are:

- `SIGN` — use a private key without exporting it.
- `PROXY` — authenticate a protocol request outside the agent process.
- `CONNECT` — provide a brokered authenticated connection.
- `REQUEST` — perform a constrained service operation on behalf of a session.
- `EXCHANGE_IDENTITY` — mint/obtain short-lived provider credentials when supported.
- `EXEC_ISOLATED` — compatibility fallback when a third-party CLI can only consume a raw credential.

## Why shell-first

Coding agents predominantly call existing tools rather than application APIs directly. The UX goal is therefore:

```bash
asv run jcode
# or
asv run codex
# or any arbitrary agent/command
asv run -- my-agent --flags
```

After that, as much as possible, the agent keeps using normal commands:

```bash
git fetch
git push
ssh host
gh issue list
curl ...
psql ...
aws ...
kubectl ...
terraform ...
```

ASV inserts compatibility at protocol, socket, proxy, endpoint or narrowly scoped shim boundaries rather than teaching the LLM a new tool for every operation.

## Package map

### Specifications

1. [`docs/00-VISION-AND-PRINCIPLES.md`](docs/00-VISION-AND-PRINCIPLES.md)
2. [`docs/01-PRODUCT-SPEC.md`](docs/01-PRODUCT-SPEC.md)
3. [`docs/02-THREAT-MODEL.md`](docs/02-THREAT-MODEL.md)
4. [`docs/03-ARCHITECTURE.md`](docs/03-ARCHITECTURE.md)
5. [`docs/04-SHELL-FIRST-INTEGRATION.md`](docs/04-SHELL-FIRST-INTEGRATION.md)
6. [`docs/05-CREDENTIAL-ACCESS-MODES.md`](docs/05-CREDENTIAL-ACCESS-MODES.md)
7. [`docs/06-TRANSPARENT-BRIDGE-EBPF.md`](docs/06-TRANSPARENT-BRIDGE-EBPF.md)
8. [`docs/07-VAULT-CRYPTO-MEMORY.md`](docs/07-VAULT-CRYPTO-MEMORY.md)
9. [`docs/08-IDENTITY-POLICY-CAPABILITIES.md`](docs/08-IDENTITY-POLICY-CAPABILITIES.md)
10. [`docs/09-TAURI-DASHBOARD.md`](docs/09-TAURI-DASHBOARD.md)
11. [`docs/10-CLI-MCP-API.md`](docs/10-CLI-MCP-API.md)
12. [`docs/11-AUDIT-OBSERVABILITY.md`](docs/11-AUDIT-OBSERVABILITY.md)
13. [`docs/12-COMPATIBILITY-MATRIX.md`](docs/12-COMPATIBILITY-MATRIX.md)
14. [`docs/13-TEST-STRATEGY.md`](docs/13-TEST-STRATEGY.md)
15. [`docs/14-UAT-ADVERSARIAL.md`](docs/14-UAT-ADVERSARIAL.md)
16. [`docs/15-ROADMAP.md`](docs/15-ROADMAP.md) — planning authority
17. [`docs/16-SECURITY-RELEASE-GATES.md`](docs/16-SECURITY-RELEASE-GATES.md)
18. [`docs/17-IMPLEMENTATION-BOOTSTRAP.md`](docs/17-IMPLEMENTATION-BOOTSTRAP.md)
19. [`docs/18-RESEARCH-SOURCES.md`](docs/18-RESEARCH-SOURCES.md)
20. [`docs/19-ALTERNATIVES-AND-REJECTIONS.md`](docs/19-ALTERNATIVES-AND-REJECTIONS.md)

### ADRs

See [`adrs/`](adrs/). They lock the key architectural choices while keeping implementation details evolvable.

## Recommended first vertical slice

Do **not** begin with transparent eBPF credential rewriting. Begin by proving the security invariant with mechanisms that are naturally secretless:

1. Rust broker daemon under a distinct OS identity.
2. Unix-domain IPC + peer credential attestation.
3. Local encrypted vault.
4. Agent session launcher + environment sanitisation.
5. SSH-agent compatible signer.
6. HTTP service proxy with one GitHub-like connector.
7. Cedar authorization.
8. Tauri 2 dashboard for credential/policy/session management.
9. Adversarial tests proving the agent process tree cannot retrieve the secret.

Then add the eBPF transparent bridge as a separate hardening/compatibility milestone.

## Definition of “secretless” used by this project

A mechanism is **strong-secretless** only when the protected secret does not appear in:

- the agent process memory,
- descendants controlled by the agent,
- the agent environment,
- process arguments,
- files visible to the agent,
- stdout/stderr/logs visible to the agent,
- IPC responses sent to the agent.

A process may still be able to *exercise a granted capability*. Therefore policy constraints, destination binding, TTL, operation binding and auditing are part of the security model. “The token cannot be printed” is not enough if the agent can use it to send arbitrary authenticated requests.
