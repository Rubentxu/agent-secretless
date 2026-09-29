# M11 — High-value connector expansion — Specification (OAuth2 prototype)

## Goal

M11 ships per connector. This cycle covers item #4 of the M11 roadmap:
the **OAuth2 provider framework**. The framework is a closed-set
issuer + a token API with no-expose-token semantics.

The remaining M11 items (GitHub/Git refinement, AWS, K8s, mTLS,
Terraform, Docker) are scheduled as later passes.

## ADDED requirements

### M11-R1 — OAuth2Token shape

The framework MUST define `OAuth2Token` with these fields:

| Field | Type | Notes |
|---|---|---|
| `access_token` | `Vec<u8>` | zeroized on drop |
| `token_type` | `String` | `"Bearer"` |
| `expires_in` | `Duration` | from the provider response |
| `refresh_token` | `Option<Vec<u8>>` | zeroized on drop; **NEVER** returned by `expose_access_token` |
| `scope` | `Option<String>` | optional |

`expose_access_token(&self) -> &[u8]` returns the access bytes; the
refresh bytes are not reachable through the public surface.

#### Scenario: refresh token is not exposed by the public API

> Given a `OAuth2Token` whose `refresh_token` is `Some(b"refresh-...")`,
> `expose_access_token()` returns only the access bytes. The struct
> has no public method that returns the refresh bytes.

### M11-R2 — OAuth2Config

The framework MUST define `OAuth2Config` with these fields:

| Field | Type | Notes |
|---|---|---|
| `token_url` | `String` | RFC 6749 §3.2 token endpoint |
| `client_id` | `String` | public client identifier |
| `client_secret` | `Vec<u8>` | zeroized on drop; never returned by `client_secret()` accessor after the issuer is built |
| `audience` | `String` | provider audience (informational) |

The runtime follow-up replaces the `ClientCredentialsIssuer::issue`
body with a real HTTPS POST.

#### Scenario: client_secret is not exposed after issuer construction

> Given an `OAuth2Config` with `client_secret = b"shh"`, calling
> `ClientCredentialsIssuer::new(cfg)` followed by `cfg.client_secret()`
> MUST not return the bytes after the issuer is built. (The prototype
> does not implement this restriction; the runtime follow-up adds it.)

### M11-R3 — OAuth2Issuer trait

The framework MUST define an `OAuth2Issuer` trait with two methods:

```rust
pub trait OAuth2Issuer {
    fn issue(&self, scope: &str) -> Result<OAuth2Token, OAuth2Error>;
    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error>;
}
```

#### Scenario: ClientCredentialsIssuer implements the trait

> Given a `ClientCredentialsIssuer` constructed from a config,
> `issuer.issue("read:pods")` returns an `OAuth2Token`. The token's
> `access_token` is non-empty; `token_type == "Bearer"`; `expires_in`
> is positive.

### M11-R4 — Closed-set verification

The framework MUST NOT expose a verb that lets an arbitrary flow be
selected. The agent calls `issue(scope)` or `refresh(refresh_token)`
and the framework chooses the provider based on the audience.

#### Scenario: agent cannot select the flow

> The framework's public API has exactly two entry methods: `issue`
> and `refresh`. There is no `do_authorization_code_flow`,
> `do_implicit_flow`, or similar.

### M11-R5 — Token zeroization

`OAuth2Token::access_token` and `OAuth2Token::refresh_token` MUST be
zeroized on drop. The framework uses `Zeroizing<Vec<u8>>` or
equivalent.

## MODIFIED requirements

None.

## REMOVED requirements

None.

## Out of scope

- The actual HTTPS POST to the provider (runtime follow-up).
- AWS SigV4 request re-signing.
- Kubernetes API reverse proxy.
- mTLS / X.509 signer.
- Terraform provider catalog.
- Docker / registry research.

## Verification

1. `cargo test -p asv-broker --lib oauth2` covers the items above.
2. `uat_030_oauth2_surrogate_lifecycle` passes.

## Verdict

The M11-OAuth2-prototype cycle **passes** if all five items above are
present and tested. The remaining M11 items are scheduled.