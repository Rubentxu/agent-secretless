# M9 — Transparent TLS bridge — Specification (M9-prototype pass)

## Goal

M9 ships in two passes:

1. **M9-prototype** (this cycle) — data types + dispatcher + threat
   controls. Includes per-session CA shape, CONNECT allow-list, redirect
   denier, and a single trust-injection adapter (OpenSSL/curl). The TLS
   bridge runtime and the full adapter list are deferred.
2. **M9-runtime follow-up** (next cycle) — the rustls + hyper + Aya
   runtime, the full adapter list, HTTP/2 ALPN, and the UI surface
   wired into M5's dashboard.

This spec covers only the prototype pass.

## ADDED requirements

### M9-R1 — Per-session CA shape

The broker MUST provide a `SessionCa` struct constructed at session start:

| Field | Type | Description |
|---|---|---|
| `session_id` | `SessionId` | session this CA belongs to |
| `root_der` | `Vec<u8>` | DER-encoded root certificate |
| `intermediate_der` | `Vec<u8>` | DER-encoded intermediate certificate |
| `issued_at` | `Instant` | when the CA was generated |
| `ttl` | `Duration` | how long the CA is valid (default 8h) |

The CA's private key MUST NOT be exposed outside the broker process. The
prototype constructor uses a deterministic-but-seeded RNG so the unit
test is reproducible; the runtime follow-up replaces it with
`rcgen::CertificateParams::new` + `OsRng`.

#### Scenario: constructor yields a CA with the requested TTL and a non-empty root DER

> `SessionCa::new(session, 8h)` returns a CA with `issued_at` within the
> last 100 ms, `ttl == 8h`, `root_der.len() > 0`,
> `intermediate_der.len() > 0`.

### M9-R2 — CONNECT allow-list

The bridge MUST authorise `CONNECT` requests against the session's
connector audience set. The set is built from `ConnectorFactory::connectors()`
at session start. Generic HTTP CONNECT MUST NOT become an escape tunnel.

```rust
pub struct ConnectPolicy { pub allowed: Vec<Authority> }
pub fn authorize_connect(
    policy: &ConnectPolicy, target: &Authority,
) -> Result<(), ConnectError>;
```

`authorize_connect` returns `Ok` iff the target's host AND port are in the
allowed list. Mismatches return `Err(ConnectError::TunnelNotAllowed)`.

#### Scenario: api.example.com allowed, attacker.example.net denied

> Given `ConnectPolicy { allowed: [Authority("api.example.com", 443)] }`,
> `authorize_connect(&api.example.com)` returns `Ok(())`. Calling
> `authorize_connect(&attacker.example.net)` returns
> `Err(ConnectError::TunnelNotAllowed)`.

### M9-R3 — Cross-origin redirect denial

When the upstream returns a 30x response while a credential binding is
active, the bridge MUST re-authorise the redirect target. The check is:

- canonicalize both the original and proposed authorities,
- compare hosts (case-folded),
- compare ports.

Same-origin redirects pass; cross-origin redirects return
`Err(RedirectError::CrossOrigin { original, proposed })`.

#### Scenario: same-origin redirect is re-authorised

> Given `original = api.example.com:443` and a 30x redirect to
> `api.example.com:8443`, `authorize_redirect` returns
> `Err(RedirectError::CrossOrigin)` (different port).

#### Scenario: cross-origin redirect is denied

> Given `original = api.example.com:443` and a 30x redirect to
> `attacker.example.net:443`, `authorize_redirect` returns
> `Err(RedirectError::CrossOrigin)`.

### M9-R4 — Trust-injection trait + OpenSSL/curl adapter

The bridge MUST expose a `TrustInjector` trait and at least one concrete
adapter (`OpenSslEnvInjector`) that emits a CA trust path the OpenSSL /
libcurl stack can use. The adapter emits a `SSL_CERT_FILE` value pointing
at a session-scoped file path the broker writes at session start.

```rust
pub trait TrustInjector {
    fn name(&self) -> &'static str;
    fn inject(&self, ca: &SessionCa, session_dir: &Path) -> Result<TrustBinding, InjectError>;
}
```

`TrustBinding { name, env_var, env_value }` is what the runtime follows
when spawning the agent's process tree.

#### Scenario: OpenSslEnvInjector writes a file and returns the path

> Given a `SessionCa` with non-empty `root_der` and a writable
> `session_dir`, `OpenSslEnvInjector::inject(&ca, &dir)` writes the
> root DER to `dir/ssl-cert.pem` and returns
> `TrustBinding { name: "openssl", env_var: "SSL_CERT_FILE",
> env_value: dir/ssl-cert.pem }`.

### M9-R5 — Bridge dispatcher (skeleton)

The bridge MUST expose a `Bridge` struct with a single entry point:

```rust
pub struct Bridge { policy: ConnectPolicy }
pub fn handle_connect(&self, target: &Authority) -> Result<(), BridgeError>;
```

`handle_connect` delegates to `authorize_connect` and returns the same
error type. The runtime follow-up replaces the body with the
`rustls::Server` + `hyper` acceptor.

## MODIFIED requirements

None. M9 is additive on top of M8.

## REMOVED requirements

None.

## Out of scope (deferred to M9-runtime follow-up)

- The `rustls` server + `hyper` HTTP/1.1 + HTTP/2 runtime.
- The full trust-injection adapter list (Python, Node, Java, Go, Git).
- The Aya-generated BPF ELF that does the socket redirect.
- The UI surface (M5 dashboard indicator).

## Verification

1. `cargo test -p asv-broker --lib tls` covers the four items.
2. The exploration and design docs are present.
3. The integration test `uat_010_connect_allow_list` (M9-R2 scenario),
   `uat_011_redirect_denier` (M9-R3 scenarios), and
   `uat_012_trust_injection` (M9-R4 scenario) pass.

## Verdict

The M9-prototype cycle **passes** if all four items above are present
and tested. M9-runtime follow-up is scheduled as the next cycle.