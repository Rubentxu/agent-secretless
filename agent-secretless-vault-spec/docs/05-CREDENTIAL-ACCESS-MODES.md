# Credential Access Modes

## 1. Security ladder

| Mode | Secret enters agent tree? | Transparency | Recommended use |
|---|---:|---:|---|
| Non-exportable signer | No | High | SSH/private keys, signing |
| Protocol/service proxy | No | High | HTTP APIs, DBs, MCP, K8s API |
| Dynamic identity/lease | Sometimes short-lived token | Medium/High | OAuth, cloud, DB roles |
| TLS placeholder bridge | No real secret in agent | Very high | HTTP CLI compatibility |
| Isolated exec | Yes, isolated worker only | Medium | Legacy CLI fallback |
| Raw env/file | Yes | High | Explicit degraded mode only |

## 2. SIGN

Reference pattern: `ssh-agent`.

The agent sees public identity information and can request signing, but the private key does not leave broker-controlled storage.

Policy can constrain:

- session,
- host/resource,
- key,
- purpose,
- confirmation,
- TTL/rate.

## 3. PROXY / REQUEST

Reference pattern: Secretless Broker / identity gateway.

```text
client <-> ASV proxy <-> authenticated upstream
```

HTTP connector can:

- insert/replace `Authorization`,
- insert API-key headers,
- perform OAuth exchange,
- calculate request signatures,
- enforce host/method/path,
- deny unsafe redirects.

The client does not receive the real header.

## 4. CONNECT

Protocol-specific connector authenticates upstream and exposes a local session endpoint.

Examples:

- PostgreSQL
- Redis
- selected TLS client-certificate protocols

Each protocol needs a real connector; a byte-forwarding TCP proxy cannot magically hide a password if the authentication exchange originates in the client.

## 5. EXCHANGE_IDENTITY

Prefer provider-native temporary identity when available.

Examples:

- OAuth access token minted from protected refresh token,
- dynamic database credential,
- short-lived certificate,
- cloud STS session.

If the derived token must enter the client process, classify as `SHORT_LIVED_EXPOSURE`, not strong-secretless.

## 6. TRANSPARENT TLS PLACEHOLDER BRIDGE

Agent process contains only surrogate placeholders. A local TLS/application proxy sees plaintext after terminating TLS, recognizes the surrogate and applies the real credential upstream.

Advantages:

- works with many ordinary HTTP CLIs,
- agent may require no command changes,
- raw credential remains outside client process.

Costs:

- requires a session-specific trust root or another controlled endpoint mechanism,
- proxy can see plaintext application traffic,
- certificate-pinning/custom TLS stacks may reject it,
- must be narrowly scoped by destination.

This is optional advanced compatibility, not the first security primitive.

## 7. EXEC_ISOLATED

Only when the application itself must possess a raw secret.

```text
Agent
  | operation request
  v
Broker
  | starts isolated worker under different identity
  v
Tool + real credential
```

Worker controls:

- different UID or isolated user namespace where appropriate,
- private `/proc`,
- no ptrace from agent,
- narrow filesystem view,
- network destination allowlist,
- no inherited agent-controlled FDs,
- short lifetime,
- stdout/stderr filtering for exact known secrets,
- automatic destruction.

Important limitation: a malicious tool that receives the secret can transform and exfiltrate it. Therefore this mode is not strong-secretless; network confinement is the real protection.

## 8. Raw credential mode

Not enabled by default.

If a user explicitly chooses to expose a token to an agent process, UI must show:

```text
Security level: RAW_PROCESS_EXPOSURE
The target process can read, transform and exfiltrate this credential.
```

No marketing language should call this safe simply because the variable is temporary.
