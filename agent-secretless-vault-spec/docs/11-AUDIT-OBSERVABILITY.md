# Audit and Observability

## 1. Goal

Provide enough evidence to answer:

- which human/agent used a credential capability,
- from which workspace/session,
- for what operation/resource,
- which policy allowed/denied it,
- which network destination was involved,
- whether human approval occurred,
- whether the integration was strong-secretless or degraded.

Without turning the audit system into a secret exfiltration channel.

## 2. Event schema

```rust
struct AuditEvent {
    event_id: Uuid,
    timestamp: Timestamp,
    session_id: Option<SessionId>,
    user_id: UserId,
    workload_id: Option<WorkloadId>,
    event_kind: EventKind,
    action: Option<Action>,
    resource: Option<ResourceRef>,
    credential_id: Option<CredentialId>,
    connector: Option<ConnectorId>,
    decision: Option<Decision>,
    approval_id: Option<ApprovalId>,
    destination: Option<RedactedDestination>,
    security_posture: Option<IntegrationPosture>,
    outcome: Outcome,
}
```

## 3. Never log

- raw credentials,
- decrypted vault payload,
- Authorization/Cookie/API-key headers,
- surrogate-to-secret maps,
- TLS session private keys,
- request bodies by default,
- raw environment dumps,
- process memory snippets.

## 4. Structured redaction

Do not rely primarily on regex redaction after formatting.

Design event types so secret-bearing values are absent before serialization.

Defense-in-depth can scan logs for known exact secret fingerprints in test environments, but production audit must not need the secret to redact it.

## 5. Process/network observability

Linux hardened mode may emit:

```text
ProcessExec(session, pid, parent, executable)
NetworkConnect(session, pid, destination, decision)
NetworkRedirect(session, original_destination, proxy_listener)
PolicyDeny(...)
```

Do not capture packet payloads through eBPF for ordinary auditing.

## 6. Tamper evidence

Phase 1:

- append-only logical audit table,
- monotonic sequence,
- hash chain across events.

Later:

- periodic signed audit checkpoints,
- optional external export.

## 7. Retention

Configurable. Defaults should avoid indefinite accumulation of sensitive operational metadata.

## 8. UI

Audit views:

- timeline,
- by credential,
- by agent/session,
- denied requests,
- approval trail,
- degraded-mode uses.

A high-value view is “credentials exercised by this session”, not “credential values”.
