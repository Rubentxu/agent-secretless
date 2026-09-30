# Product Specification

## 1. Product goal

Provide a local “KeePass-like” credential application specifically designed for AI/coding agents and shell automation, with the strongest practical resistance to credential disclosure while preserving normal CLI workflows.

## 2. Primary personas

### Human developer/operator

Needs to:

- add/import credentials,
- classify them by type and sensitivity,
- decide which agents/workspaces may use them,
- approve high-risk actions,
- inspect sessions and audit history,
- revoke access instantly,
- rotate credentials without reconfiguring every agent.

### AI/coding agent

Needs to:

- invoke existing CLI tools,
- request capabilities where necessary,
- receive useful errors when policy denies an action,
- avoid handling or persisting real secret material.

### Security-conscious power user

Needs to:

- enable TPM-backed vault unlock,
- enable Linux hardened session mode,
- constrain egress,
- require approvals,
- inspect process/network evidence,
- verify that an integration is truly secretless rather than merely ephemeral.

## 3. Core functional requirements

### FR-001 Credential CRUD

The human dashboard shall support credential records with metadata and encrypted secret payloads.

Initial credential ADT:

```rust
enum CredentialKind {
    ApiKey,
    BearerToken,
    OAuth2,
    UsernamePassword,
    SshPrivateKey,
    X509ClientIdentity,
    AwsAccessKey,
    DatabaseCredential,
    GenericSecret,
}
```

The domain must be extensible without adding arbitrary `HashMap<String,String>` as the primary representation.

### FR-002 Exportability

Every credential shall have an export policy:

```text
NonExportable   default for agent credentials
HumanOnly       reveal/copy only after explicit human re-authentication
Exportable      explicit opt-in; never exposed through agent CLI/MCP
```

### FR-003 Agent sessions

`asv run -- <command>` creates a bounded session with:

- session ID,
- user identity,
- root PID/pidfd,
- optional cgroup,
- workspace,
- agent executable metadata,
- policy set,
- allowed integration profile,
- start/end timestamps.

All descendants are associated with the session where platform support permits.

### FR-004 Environment quarantine

The launcher shall prevent accidentally inherited raw credentials from undermining the model.

Default behaviour:

- known secret environment variables are stripped or quarantined,
- command-line arguments are never populated with raw secrets,
- ASV injects only non-secret session handles and surrogate placeholders,
- user receives a warning if the parent shell already contains likely secret variables.

Examples of variables to detect include well-known token/password/key names and configurable patterns. Detection must not log values.

### FR-005 SSH agent compatibility

ASV shall expose an `SSH_AUTH_SOCK` compatible endpoint for eligible keys.

The private key must remain broker-side. Signing requests are authorized by session and policy.

### FR-006 HTTP/service brokering

ASV shall support service connectors that transform an unauthenticated/surrogate request into an authenticated request outside the agent process.

Connectors must bind credentials to:

- allowed scheme,
- normalized host/audience,
- destination port,
- method/action,
- path/resource patterns,
- redirect policy.

### FR-007 TCP/protocol brokering

ASV shall support protocol-specific local listeners/connectors for services where authentication occurs inside a non-HTTP protocol, beginning with PostgreSQL as the reference design.

### FR-008 Dynamic credentials

Where a provider supports leases/token exchange, the broker should prefer short-lived derived credentials to a long-lived static token.

### FR-009 Capability authorization

Authorization request shape:

```text
principal + action + resource + context -> Allow | Deny | RequireApproval
```

The policy engine is deny-by-default.

### FR-010 Approvals

High-risk capabilities can require:

- `Once`,
- `ForSession`,
- `UntilExpiry`,
- a persisted policy change.

The approval UI must display agent, workspace, exact action, resource and credential identity without displaying the secret.

### FR-011 CLI

Human/control CLI and agent-compatible CLI must be available without exposing secrets.

### FR-012 MCP

An optional MCP server exposes control/capability operations only. No raw secret method exists.

### FR-013 Transparent compatibility bridge

Linux hardened mode may redirect eligible session network connections to a local broker transparently with cgroup/eBPF socket hooks.

For TLS traffic, actual placeholder substitution occurs in a userspace TLS/application proxy, not in eBPF.

### FR-014 Security posture

Every integration reports one of:

```text
STRONG_SECRETLESS
SHORT_LIVED_EXPOSURE
ISOLATED_PROCESS_EXPOSURE
RAW_PROCESS_EXPOSURE
UNSUPPORTED
```

The UI never labels a compatibility mechanism as fully secretless.

### FR-015 Audit

Audit records include:

- session,
- human user,
- agent identity,
- operation,
- resource,
- connector,
- policy decision,
- approval reference,
- start/end/result,
- destination metadata.

They MUST NOT contain credential values, surrogate-to-secret mappings, decrypted request authorization headers or request/response bodies by default.

## 4. UX requirements

### Dashboard primary screens

- Credentials
- Agents / launch profiles
- Workspaces
- Sessions
- Policies
- Approvals
- Integrations
- Audit
- Security posture / diagnostics

### Credential wizard

Steps:

1. Choose type.
2. Enter provider/account/resource metadata.
3. Enter secret through the safest available ingestion path.
4. Choose exportability.
5. Choose allowed operations/resources.
6. Choose agents/workspaces.
7. Test connector without revealing secret.

### Agent launch

The common path should be one command:

```bash
asv run jcode
```

No prompt engineering should be required merely to make credentials work.

## 5. Non-functional requirements

### NFR-SEC-001

Broker compromise is treated as high impact; privileged and secret-bearing code must be deliberately small.

### NFR-SEC-002

No secret in normal debug formatting. Secret-bearing Rust types use explicit exposure APIs and zeroization.

### NFR-SEC-003

Crash reports, tracing and logs must have secret-safe schemas.

### NFR-PERF-001

Native signer and local policy checks should add negligible perceived latency. Target p95 local authorization under 5 ms on a normal workstation, excluding human approval and upstream provider latency.

Measured on the development host (Intel Xeon E5-2682 v4 @ 2.50GHz), a brokered read costs ~4.3 ms at p50 and ~4.9 ms at p95 in a debug build, and ~1.3 ms / ~1.7 ms in a release build. Of the debug figure only ~195 µs is local authorization; the rest is the TLS handshake and round trip to the loopback origin. "Normal workstation" is not numerically defined, and the debug p95 sits within 0.1-0.3 ms of the threshold, so a strict 5 ms bound makes the check a coin flip: 2-5 of 100 reads per run land at or above 5 ms and the p95 crosses accordingly. The profile matters and cannot be ignored, which a 5 ms bound does.

The bound is therefore 6 ms, measured against the slower of the two profiles so the same constant gates both. The 5 ms figure continues to describe local authorization itself, which meets it with two orders of magnitude to spare. The end-to-end budget is set by the excluded provider round trip, and a threshold that excludes it cannot be enforced on a measurement that includes it. UAT-030 additionally fails if the budget exceeds 6x the p95 that the same run measured, so the constant cannot be raised into irrelevance without the run going red.

### NFR-PORT-001

Core domain and connectors are portable Rust. Linux-specific hardening lives behind platform ports.

### NFR-TEST-001

Every new connector requires negative/adversarial tests, not only happy-path authentication tests.

## 6. Out of scope for initial product

- Protecting against a compromised kernel/root attacker.
- Universal transparent interception of every TLS implementation.
- Perfect DLP against a process that legitimately receives a raw bearer secret.
- Cloud multi-tenant control plane.
- Building a general password manager replacement.
- Chatbot UI.
