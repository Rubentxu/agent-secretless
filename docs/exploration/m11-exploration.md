# M11 — High-value connector expansion — Exploration

## 1. Goal

Per `agent-secretless-vault-spec/docs/15-ROADMAP.md`:

> ## M11 — High-value connector expansion
>
> Order by value and achievable secretless property:
>
> 1. GitHub/Git HTTPS refinement.
> 2. AWS request re-signing + STS.
> 3. Kubernetes API reverse proxy.
> 4. OAuth2 provider framework.
> 5. mTLS/X.509 signer/connector.
> 6. Terraform provider compatibility catalog.
> 7. Docker/registry research.

M11 is a **port expansion** milestone, not a single feature. Each item
above is a substantial piece of work. M11 ships in passes per
connector.

## 2. Status of each item

| # | Item | Status | M11-cycle |
|---|---|---|---|
| 1 | GitHub/Git HTTPS refinement | shipped in M4 (R9 github.rs) | — |
| 2 | AWS request re-signing + STS | not started | later pass |
| 3 | Kubernetes API reverse proxy | not started | later pass |
| 4 | OAuth2 provider framework | not started | M11-prototype (this cycle) |
| 5 | mTLS/X.509 signer/connector | not started | later pass |
| 6 | Terraform provider compatibility catalog | research | later pass |
| 7 | Docker/registry research | research | later pass |

This cycle delivers M11-prototype for the OAuth2 provider framework
(item #4). The remaining items are scheduled as later passes.

## 3. OAuth2 provider framework — Spike O1

OAuth2 (RFC 6749) gives an agent the ability to obtain a short-lived
access token from an identity provider, without ever receiving the
long-lived refresh token. The broker can hold the refresh token, mint
a fresh access token on demand, and present it to the agent as a
surrogate credential.

The framework needs at least:

| Type | Purpose |
|---|---|
| `OAuth2Config` | provider URL, client id, client secret, scope, audience |
| `OAuth2Issuer` | RFC 6749 §4.4 client_credentials; RFC 6749 §6 refresh_token |
| `OAuth2Token` | access_token, token_type, expires_in, refresh_token |
| `OAuth2Surrogate` | the broker-managed credential that the agent sees |

### 3.1 Surrogate shape

```rust
pub struct OAuth2Token {
    pub access_token: Vec<u8>,         // zeroized on drop
    pub token_type: String,            // "Bearer"
    pub expires_in: Duration,          // 3600 typically
    pub refresh_token: Option<Vec<u8>>, // zeroized; NEVER returned to the agent
    pub scope: String,                 // optional
}
```

`OAuth2Token` is created by the broker; only the `access_token` (and
NOT the `refresh_token`) is exposed as a surrogate to the agent.

### 3.2 Surrogate-issuer trait

```rust
pub trait OAuth2Issuer {
    fn issue(&self, audience: &str, scope: &str) -> Result<OAuth2Token, OAuth2Error>;
    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error>;
}
```

A `ClientCredentialsIssuer` (server-to-server, RFC 6749 §4.4) uses the
client secret; a `RefreshTokenIssuer` (RFC 6749 §6) uses the refresh
token. Both return a fresh `OAuth2Token` with a new access_token and
optionally a new refresh_token.

### 3.3 The framework is closed-set

The framework MUST NOT accept arbitrary OAuth2 flows from the agent.
The agent requests `OAuth2Issuer::issue(audience, scope)` or
`OAuth2Issuer::refresh(token)`. The framework chooses the provider
based on the audience.

### 3.4 Why this matters

The framework is the structural answer to "agent with broker-held
credentials and short-lived access". Without it the agent must hold
the long-lived credential; with it the agent only holds the access
token and the broker refreshes in the background.

## 4. Verdict

M11-prototype **passes** if:

- `OAuth2Token`, `OAuth2Config`, `OAuth2Issuer` trait, and at least
  one concrete issuer (`ClientCredentialsIssuer`) exist.
- `ClientCredentialsIssuer::issue` constructs a deterministic
  placeholder token (the real flow needs HTTPS, deferred to runtime).
- `OAuth2Token::expose_access_token` returns the access bytes;
  `refresh_token` is not exposed by the public API.
- `uat_030_oauth2_surrogate_lifecycle` passes.

## 5. Honest gaps (deferred to M11-runtime follow-up per item)

The remaining M11 items (AWS, K8s, mTLS, Terraform, Docker) are
research / connector implementations that need their own cycles. The
OAuth2 framework is the only one addressed in M11-prototype.

The OAuth2 runtime (HTTPS POST to the provider, response parsing) is
deferred to the OAuth2 runtime follow-up.