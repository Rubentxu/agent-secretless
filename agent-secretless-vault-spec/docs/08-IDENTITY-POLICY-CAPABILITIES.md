# Identity, Policy and Capabilities

## 1. Workload identity model

Borrow the useful idea from SPIFFE/SPIRE: identity is derived from evidence about the process calling the local workload endpoint rather than trusting a self-declared `agent=jcode` string.

### Evidence

On Linux:

1. accept Unix socket connection,
2. obtain `SO_PEERCRED` PID/UID/GID,
3. immediately open/associate pidfd to reduce PID-reuse risk,
4. gather process executable/cgroup/session launch evidence,
5. match against an ASV launch/session record,
6. construct `WorkloadIdentity`.

```rust
struct WorkloadIdentity {
    uid: u32,
    executable: PathBuf,
    executable_digest: Option<Digest>,
    session_id: AgentSessionId,
    cgroup_id: Option<CgroupId>,
    workspace: WorkspaceId,
    agent_profile: Option<AgentProfileId>,
}
```

Do not rely on binary hash alone because agent binaries update frequently.

## 2. Blended human + agent identity

Authorization should know both:

```text
human user
+
agent/workload session
```

This supports policies such as:

```text
User Alice using an approved coding-agent session in workspace X
may read GitHub repo X
```

without granting every process owned by the user the same credential capability.

## 3. Cedar

Use Cedar as the initial policy engine because its PARC model maps naturally:

```text
Principal
Action
Resource
Context
```

Recommended primary principal: `AgentSession` or `Agent`, with human identity represented as a related entity or request context depending on the policy question.

## 4. Entities

Suggested Cedar namespace concepts:

```text
User
Agent
AgentSession
Workspace
Credential
Repository
Host
Database
Service
Capability
```

Actions:

```text
CredentialUse::Sign
SSH::Connect
Git::Fetch
Git::Push
HTTP::Request
GitHub::IssueCreate
GitHub::ReleaseCreate
Database::Connect
AWS::Request
Kubernetes::Request
```

## 5. Policy examples

Conceptual example:

```cedar
permit (
  principal is AgentSession,
  action == GitHub::Action::"IssueCreate",
  resource is Repository
)
when {
  principal.workspace == resource.workspace &&
  principal.securityLevel >= 2
};
```

Release creation with approval can be modelled as a broker precondition/context rather than giving Cedar mutable workflow responsibilities:

```text
Cedar allows action only when context.approvalValid == true
```

The approval verifier is responsible for producing that trusted context.

## 6. Capability grants

A grant is not the credential. It is authorization state.

```rust
struct CapabilityGrant {
    id: CapabilityId,
    session: AgentSessionId,
    action: Action,
    resource: Resource,
    audience: Option<Audience>,
    issued_at: Instant,
    expires_at: Instant,
    remaining_uses: Option<u32>,
    approval_id: Option<ApprovalId>,
}
```

A copied capability ID is insufficient. Broker also verifies actual peer/session identity.

## 7. Default policy

Deny by default.

Initial UX presets:

### Read-only developer

- Git fetch/read
- API GET/read scopes
- DB read role
- no pushes/releases/destructive operations

### Developer

- read
- push non-protected branches
- issue/comment writes
- protected branch/release requires approval

### Release operator

- release capabilities allowed only from selected workspace and with approval/attestation gates

## 8. Audience binding

Every bearer-like credential must declare an audience/connector scope.

Examples:

```text
GitHub PAT -> api.github.com + github.com allowed connector set
Slack token -> slack.com API only
Custom API key -> exact configured authority
```

A generic “use this token on any URL” policy is prohibited by default.

## 9. Resource semantics

Service connectors should progressively expose semantic resources/actions rather than only HTTP method/path.

Start generic where necessary, then refine high-value connectors.

## 10. Approvals

Approval object binds:

- session,
- exact action,
- exact resource,
- optional request digest,
- expiry,
- use count.

An approval must not silently broaden into “all future operations” unless the human explicitly chooses to create a persistent policy.

## 11. Revocation

Revoking session:

- invalidates grants,
- closes local listener sockets,
- removes eBPF/cgroup policy entries,
- terminates session workers,
- revokes dynamic provider leases when supported.
