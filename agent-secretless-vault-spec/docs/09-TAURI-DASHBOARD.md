# Tauri 2 Dashboard Specification

## 1. Role

Tauri is the human control plane, not the credential data plane for agents.

The Rust broker remains a separate service/process.

## 2. Security boundary

Tauri explicitly distinguishes privileged Rust core/plugin code from WebView code. ASV must treat the WebView as semi-trusted and expose a tiny IPC command surface.

Rules:

- bundle all frontend assets locally,
- no CDN scripts,
- no arbitrary remote navigation,
- strict CSP,
- minimal Tauri capabilities per window,
- no generic shell plugin permissions,
- no secret-bearing logs,
- no vault file direct access from JS,
- no JavaScript API returning stored secret values.

## 3. Windows

### Main dashboard

Read/control metadata, sessions and policies.

### Approval window

Separate capability set. It can approve/deny requests but cannot read credentials.

### Credential ingestion

Baseline can use main window password field; hardened mode launches native secure-input helper.

Avoid giving every window a merged superset of capabilities.

## 4. Main navigation

```text
Credentials
Agents
Workspaces
Sessions
Policies
Approvals
Integrations
Audit
Security
Settings
```

## 5. Credentials screen

KeePass-like split view:

```text
┌ Vault / groups ┬ Credential list ┬ Details ┐
│ Development    │ GitHub work     │ Type    │
│ Personal       │ AWS sandbox     │ Scope   │
│ Production     │ SSH deploy      │ Policy  │
│ Archived       │ ...             │ Usage   │
└────────────────┴─────────────────┴─────────┘
```

Details emphasize:

- credential type,
- account/provider,
- exportability,
- allowed connectors,
- last use,
- linked policies,
- rotation state,
- security level.

Do not make “show password” the primary interaction. For `NonExportable` it does not exist.

## 6. Integrations screen

Detected tool matrix:

```text
ssh        STRONG_SECRETLESS   SSH agent
Git SSH    STRONG_SECRETLESS   SSH agent
curl       STRONG_SECRETLESS*  HTTP/TLS bridge for configured APIs
gh         STRONG_SECRETLESS*  GitHub connector / bridge
aws        connector dependent request re-signing
psql       STRONG_SECRETLESS   PostgreSQL proxy
terraform  MIXED               provider dependent
kubectl    STRONG/MIXED        API proxy or short-lived exec token
```

`*` displays limitations such as session CA interception.

## 7. Session screen

Show:

- agent executable/profile,
- workspace,
- duration,
- security profile,
- granted capabilities,
- active listeners,
- process tree (when available),
- network destinations summary,
- recent policy decisions.

Actions:

- revoke session,
- lock credential use,
- inspect audit,
- change temporary grant.

## 8. Approval UX

Approval card must answer:

- Who? human + agent identity
- Where? workspace
- What? exact operation
- On what? exact resource
- Using which credential/account?
- For how long/how many uses?
- Why did policy require approval?

Buttons:

```text
Deny | Allow once | Allow for session | Edit policy…
```

Dangerous persistent changes require a second explicit step.

## 9. Security screen

Runtime posture checklist:

```text
Vault locked/unlocked
Broker separate UID
Core dumps disabled
memfd_secret available
TPM available/bound
eBPF enforcement active
cgroup v2 active
Landlock ABI
seccomp profile
Session CA active/inactive
Raw exposure integrations count
```

No green “secure” badge if degraded modes are active; show precise properties.

## 10. Frontend technology

Suggested:

- Tauri 2
- React + TypeScript
- TanStack Router/Query if useful
- small component set
- no remote analytics in security-sensitive builds

Frontend state contains metadata only. Secret field state should have the shortest possible lifetime.
