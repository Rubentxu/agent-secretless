# ADR-0001 — No agent-facing secret retrieval API

- Status: Accepted
- Date: 2026-09-28

## Context

Traditional vaults expose `get secret`. That makes it impossible to guarantee that a prompt-injected or malicious agent cannot print/persist/exfiltrate the value.

## Decision

Normal agent surfaces will expose operations/capabilities, not raw secret retrieval.

Allowed primitive families:

```text
SIGN
PROXY
CONNECT
REQUEST
EXCHANGE_IDENTITY
EXEC_ISOLATED
```

MCP and session CLI MUST NOT add aliases that recreate `getSecret` indirectly.

Human-only reveal is a separate exceptional capability governed by credential exportability and is not available to agent sessions.

## Consequences

- Strong architectural invariant.
- More protocol/service connectors are required.
- Some legacy tools can only be supported in a weaker compatibility mode.
