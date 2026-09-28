# ADR-0012 — TLS interception, when needed, uses session-scoped trust only

- Status: Accepted for optional transparent bridge
- Date: 2026-09-28

## Decision

ASV will not install a permanent system-wide interception CA by default.

Transparent TLS mode generates ephemeral session trust material; CA private key remains broker-side and leaf issuance is restricted to explicitly approved hostnames.

Clients with unsupported pinning/custom trust stores fail cleanly rather than being patched to disable verification.
