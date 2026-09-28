# CLI / Protocol Compatibility Matrix

This matrix is a roadmap target, not a claim that all integrations are already implemented.

| Tool/use case | Preferred mechanism | Secret in agent process? | Priority | Notes |
|---|---|---:|---:|---|
| `ssh` | SSH agent protocol | No | P0 | Best reference integration |
| Git over SSH | SSH agent protocol | No | P0 | Preferred Git transport |
| Git HTTPS | service/TLS proxy | No | P1 | Avoid credential helper for strong mode |
| `curl` API token | explicit or transparent TLS bridge | No real token | P1 | Surrogate replacement |
| `gh` | GitHub service connector/TLS bridge | No real token | P1 | Surrogate satisfies auth presence |
| PostgreSQL/`psql` | protocol-aware local proxy | No | P1 | Reference non-HTTP connector |
| generic HTTP API | scoped proxy connector | No | P1 | Exact audience binding |
| AWS CLI/API | proxy re-signing | No real key | P2 | Replace/recompute SigV4 broker-side |
| Kubernetes API/`kubectl` | local API reverse proxy | No | P2 | Strong mode; exec-token mode is weaker |
| Terraform providers | provider dependent | Mixed | P2/P3 | HTTP bridge helps many; adapter catalog required |
| Docker registry | registry/protocol adapter | Mixed | P3 | credential helper alone exposes credential to Docker process |
| OAuth browser flows | broker obtains refresh token | No refresh token | P2 | access-token exposure depends integration |
| X.509/mTLS | brokered TLS/signing proxy | No private key | P2 | hardware key support later |
| `cosign`/signing | signer/PKCS#11-like adapter | No private key | P2 | operation-specific |
| arbitrary legacy CLI | isolated exec | Worker yes | P1 fallback | Constrain egress/filesystem |

## Git credential helper warning

Git credential helpers return a credential to Git. They are valuable for UX but do not meet the strong-secretless property because the target process receives the value.

Strong ASV Git guidance:

1. prefer SSH remotes + ASV SSH agent,
2. for HTTPS use broker/proxy integration,
3. credential helper is explicitly labelled degraded compatibility.

## Terraform

Terraform itself and providers use many credential patterns. Treat “Terraform support” as a catalog, not one feature.

Integration classes:

- providers using ordinary HTTP bearer/API-key auth -> TLS bridge/service connector,
- providers supporting OAuth/device/workload identity -> brokered identity where possible,
- cloud request-signing providers -> request signer proxy,
- provider reading token and using custom/pinned transport -> isolated worker or unsupported strong mode.

`asv doctor terraform` should inspect provider lock/config metadata where feasible and report posture without reading secret values.

## Kubernetes

Strong mode:

```text
kubectl -> local ASV API endpoint -> real Kubernetes API
```

Kubeconfig presented to agent contains local endpoint/session identity only. Broker performs upstream auth.

Compatibility mode using an `exec` credential plugin returns a token to `kubectl`; classify short-lived exposure even if TTL is tiny.

## AWS

Do not give the agent `AWS_SECRET_ACCESS_KEY` in strong mode.

Potential strategy:

- agent has syntactically valid surrogate values,
- service proxy terminates request,
- discards surrogate-derived SigV4,
- re-signs canonical request with real/temporary credential,
- forwards only to authorized AWS service/region/resource patterns.

Prefer STS short-lived credentials inside broker where possible.
