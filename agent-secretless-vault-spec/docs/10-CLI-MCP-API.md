# CLI, Local API and MCP Specification

## 1. CLI philosophy

The CLI controls sessions and capabilities; it does not become a second password-retrieval interface.

Binary: `asv`.

## 2. Human/control commands

```bash
asv status
asv doctor
asv lock
asv unlock

asv credential list
asv credential add <type>
asv credential inspect <id>
asv credential rotate <id>
asv credential delete <id>

asv policy list
asv policy explain --session ... --action ... --resource ...

asv session list
asv session inspect <id>
asv session revoke <id>

asv audit tail
asv audit query ...
```

`credential inspect` returns metadata only unless a dedicated human-only reveal path is invoked and exportability allows it.

## 3. Agent launch

```bash
asv run -- jcode
asv run --profile hardened -- codex
asv run --workspace "$PWD" -- my-agent
```

### Exit semantics

`asv run` should proxy child exit code/signals faithfully.

## 4. Explicit capability operations

For cases where transparent integration is unsuitable:

```bash
asv request github.issue.create repo=org/repo title-file=/tmp/title
asv connect postgres --credential analytics-ro -- psql
asv sign ssh --key deploy --host build.example
```

No command prints the credential.

## 5. Local broker protocol

Separate method families:

### Metadata/control

```text
Status
ListCredentialsMetadata
CreateCredentialMetadata
StartSecureIngest
DeleteCredential
CreateSession
EndSession
ListCapabilities
RequestCapability
Approve
Deny
QueryAudit
```

### Data-plane handles

Prefer Unix listener FDs/endpoints or protocol-specific sockets rather than returning bearer data.

### Forbidden generic methods

```text
GetSecret
ExportSecretForAgent
GetDecryptedPayload
RunArbitraryCommandWithSecret
```

The last item is important: isolated execution must require a registered integration/credential mapping, not arbitrary shell text supplied to a privileged broker.

## 6. Secure ingestion protocol

Possible flow:

```text
UI -> broker: StartSecureIngest(metadata)
broker -> UI: one-use ingest endpoint/nonce
native helper -> endpoint: encrypted/authenticated secret bytes
broker: stores, closes endpoint
UI: receives success metadata only
```

Use OS peer credentials in addition to nonce binding.

## 7. MCP role

MCP is optional and intentionally small.

Suggested tools:

```text
asv.session.status
asv.capabilities.list
asv.capabilities.request
asv.operation.invoke
asv.approval.status
asv.integration.status
```

MCP resources may expose non-secret documentation/policy information.

## 8. MCP prohibited surface

Never expose:

```text
secret.get
secret.list_values
secret.export
credential.reveal
vault.decrypt
```

## 9. MCP operation design

A semantic MCP call can be useful for a high-risk action:

```json
{
  "action": "github.release.create",
  "resource": "repo:org/project",
  "parameters": {
    "tag": "v1.2.0"
  }
}
```

Broker authorizes and connector performs action. The agent receives result metadata, not a token.

## 10. Shell data plane should remain independent

If MCP is disconnected, previously authorized shell/proxy operations may continue according to session policy. The agent should not need an MCP round trip for every network packet or SSH signature.

## 11. Error design

Errors should be useful but non-leaky:

```text
ASV_DENIED: github.release.create requires human approval for repo org/project
ASV_DESTINATION_DENIED: credential github-work is not valid for host evil.example
ASV_INTEGRATION_UNSUPPORTED: tool uses certificate pinning; transparent TLS mode unavailable
ASV_SESSION_EXPIRED
```

Do not echo auth headers, credential values, full sensitive request bodies or upstream responses known to contain credentials.
