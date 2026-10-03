# ADR-0020 — Tool configuration is handled through semantic credential workflow adapters

- Status: Proposed
- Date: 2026-10-02

## Decision

Introduce semantic adapters for credential-bearing tool configuration (`.npmrc`, Maven `settings.xml`, Gradle properties, curl config/netrc, later Docker/Cargo/pip/NuGet/Terraform).

Adapters implement:

```text
discover -> plan -> adopt -> project -> cleanup
```

They parse known semantics but do not execute arbitrary configuration.

## Consequences

- ASV can migrate real developer environments without exposing credential values.
- Config fingerprint becomes part of TOCTOU protection.
- Ephemeral config does not automatically imply strong-secretless.
- Parser hardening and ownership checks become security gates.
