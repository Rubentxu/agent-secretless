# M9 — Transparent TLS bridge — Exploration

## 1. Goal

Per `agent-secretless-vault-spec/docs/15-ROADMAP.md`:

> ## M9 — Transparent TLS bridge
>
> **Conditional on M8 GO.**
>
> ### Scope
>
> - per-session ephemeral CA,
> - local trust injection adapters,
> - leaf issuance for exact hosts,
> - eBPF transparent routing,
> - HTTP/1.1 + HTTP/2 compatibility where proxy stack supports it,
> - strict CONNECT/redirect controls,
> - UI indicator that TLS interception is active.
>
> ### Exit UAT
>
> - UAT-010, 011, 012, 013,
> - TLS compatibility matrix published from tests.

M8 verdict is PASS, so M9 is unblocked.

## 2. Authoritative spec source

`agent-secretless-vault-spec/docs/06-TRANSPARENT-BRIDGE-EBPF.md` defines:

- Section 5 — TCB-HTTP / TLS bridge flow (8 steps)
- Section 6 — Session-scoped CA design (6 properties)
- Section 7 — TLS bridge threat controls (host normalization,
  redirects, DNS rebinding, CONNECT)

These are the source of truth. The M9 prototype below implements the
data types and the dispatcher; the runtime TLS termination and the
eBPF transparent routing are scoped to M9's **runtime follow-up**.

## 3. Codebase inventory

### 3.1 Existing surface

- `asv_broker::authority::Authority` (M6) — `canonicalize` parses hostnames
  from `Authority::canonicalize`, rejects single-label hosts, host:port.
- `asv_broker::surrogate::SurrogateToken` / `SurrogateRegistry` (M4) — the
  surrogate lifecycle. Already powers the HTTP broker.
- `asv_broker::connector_factory::ConnectorFactory` (M4, M6) — the
  `Connector` trait and the live + local implementations.
- `asv_ebpfd` (M7, M8) — the privileged helper. M9 does NOT add new
  verbs; the helper surface is unchanged.

### 3.2 Missing surface for M9

- A per-session CA (key + x509 issuer). The spec wants rcgen or rustls.
- A CONNECT allow-list (policy).
- A redirect denier that cross-checks the original authority.
- A leaf certificate issuer keyed on host (only the explicit allow-list).
- A trust-injection adapter list (OpenSSL env, Java keystore, etc.).
- A TLS bridge runtime (rustls Server + Client + Tokio + surrogate
  substitution). Out of scope for the M9-prototype pass.

## 4. Spike T1 — Per-session CA shape

The CA is an issuer (root + intermediate) created when a session starts.
The CA's private key NEVER leaves the broker process. The leaf certs are
generated on demand when the agent connects to an allowed host.

```rust
pub struct SessionCa {
    pub session_id: SessionId,
    pub root: rcgen::Certificate,
    pub intermediate: rcgen::Certificate,
    pub issued_at: Instant,
    pub ttl: Duration,
}
```

In M9-prototype this is a data type with a constructor that:
- generates a random root key,
- generates an intermediate signed by the root,
- emits the root DER for trust injection,
- does NOT yet terminate TLS — that runtime lives in the M9-runtime
  follow-up.

## 5. Spike T2 — CONNECT allow-list

The agent's HTTP client sends `CONNECT api.example.com:443 HTTP/1.1`.
The bridge MUST NOT become a generic tunnel. The allow-list is:

```rust
pub struct ConnectPolicy {
    pub allowed: Vec<Authority>,
}
```

`authority_for_connect(target: &Authority) -> Result<(), ConnectError>`:
- if `target` is in the allowed list → Ok.
- else → Err(ConnectError::TunnelNotAllowed(target.clone())).

The allow-list is the same as the connector audience list. The session's
authority set is built from `ConnectorFactory::connectors()` at session
start.

## 6. Spike T3 — Redirect denier

A 30x response from the upstream MUST be re-authorized. Cross-origin
redirects (different DNS, SNI, or host header) MUST be denied while a
credential binding is active.

```rust
pub fn authorize_redirect(
    original: &Authority, proposed: &Authority,
) -> Result<(), RedirectError>
```

- if `original.host == proposed.host` (case-folded) and `port == path` →
  Ok.
- else → Err(RedirectError::CrossOrigin { .. }).

Same-origin redirects are passed to HTTP authorization.

## 7. Spike T4 — Host normalization

The upstream authority is parsed for:
- DNS name
- SNI (for TLS)
- HTTP `Host` / `:authority`
- destination IP/port

`canonicalize(&Authority) -> Result<Authority, HostError>` already does
this in M6. M9 wires it into the bridge's authorization step.

## 8. Spike T5 — Trust injection

The trust-injection adapter list is a `Vec<Box<dyn TrustInjector>>`.
Each injector knows how to set the right environment variable or config
file for a given application.

For M9-prototype, we define a trait and a single OpenSSL/curl injector
that writes to `SSL_CERT_FILE` for the session's process tree.

```rust
pub trait TrustInjector {
    fn name(&self) -> &'static str;
    fn inject(&self, session: &SessionCa) -> Result<(), InjectError>;
}

pub struct OpenSslEnvInjector;
impl TrustInjector for OpenSslEnvInjector { ... }
```

The full adapter list is the M9-runtime follow-up.

## 9. Spike T6 — UI indicator

A small surface: `asv-tls-bridge` prints to stderr on each interception:
`asv-tls: intercepting <host>:<port> for session <id>`. The M9 runtime
follow-up wires this into the broker's structured logging.

## 10. Spike T7 — HTTP/1.1 + HTTP/2

The TLS bridge uses `hyper` for HTTP/1.1 and HTTP/2. Both work with the
surrogate substitution because the surrogate is a literal string the
client sends in an HTTP header (or `:authority` for HTTP/2). The M9
prototype does not need a runtime here; it documents the constraint
that the bridge MUST NOT buffer the body — surrogate substitution is
header-only.

## 11. Spike T8 — Performance

Per M8 E4, the per-request overhead is dominated by TLS handshake
(~1–5 ms). The TLS bridge adds two TLS handshakes (client-side + upstream)
per session, plus the surrogate lookup (~50 µs in M4's measurement).
The expected additional latency is < 1 ms on top of TLS.

The M9 prototype does not include a live measurement. The M9 runtime
follow-up adds the fixture.

## 12. Decision matrix

| Component | M9-prototype scope | M9-runtime follow-up |
|---|---|---|
| `SessionCa` data type | yes | n/a |
| `ConnectPolicy` + tests | yes | n/a |
| `authorize_redirect` + tests | yes | n/a |
| `TrustInjector` trait + OpenSSL/curl | yes | full adapter list |
| TLS bridge runtime (rustls/hyper) | no | yes |
| eBPF transparent routing | no | yes (Aya + M8 verbs) |
| UI surface | no (stderr) | yes (M5 dashboard) |
| HTTP/2 ALPN | no | yes |

## 13. Honest gaps

- The TLS bridge runtime is NOT shipped in the M9-prototype. It is a
  structural skeleton (data types + dispatcher) plus tests. The full
  runtime requires `rcgen` + `rustls` + `hyper` and a connection
  acceptor. That is the M9-runtime follow-up.
- The trust-injection adapter list is limited to OpenSSL/curl. The full
  list (Python requests, Node, Java, Go, Git) is the M9-runtime
  follow-up.
- The eBPF transparent mode requires the BPF shipped in M9-runtime
  follow-up; the broker-side wiring exists in M8's design.

## 14. Verdict

M9-prototype **passes** if:

- `SessionCa` is a real struct with a real constructor.
- `ConnectPolicy::authorize` rejects unauthorized CONNECT targets.
- `authorize_redirect` rejects cross-origin redirects.
- `TrustInjector` trait + `OpenSslEnvInjector` exists and is testable.
- All four items above have unit + integration tests.
- The M9 spec is present in `docs/specs/m9-tls-bridge/specification.md`
  and the design doc describes the M9-runtime follow-up.

M9-runtime follow-up is a separate cycle that starts after M9-prototype
is closed. It adds the rustls + hyper + Aya runtime and the full
adapter list.