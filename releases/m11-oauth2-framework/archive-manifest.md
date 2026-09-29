# M11 — Archive Manifest

## Cycle

M11-prototype (item #4: OAuth2 provider framework).

## Artifacts

| Path | Role |
|---|---|
| `releases/m11-oauth2-framework/release-report.md` | Cycle release report |
| `releases/m11-oauth2-framework/merge-receipt.md` | Git push receipt |
| `releases/m11-oauth2-framework/archive-manifest.md` | This file |
| `docs/exploration/m11-exploration.md` | Exploration notes |
| `docs/specs/m11-connectors/specification.md` | Delta spec |
| `crates/broker/src/oauth2.rs` | OAuth2 module (data + trait + issuer) |
| `crates/broker/tests/uat_030_oauth2_surrogate_lifecycle.rs` | Integration tests |

## Tag

`m11-oauth2-framework` at `93ed1ae`.

## Spec coverage

M11-R1..M11-R5 (all).

## Tests

- Unit tests in `crates/broker/src/oauth2.rs`: 10
- UAT-030 integration tests: 6

Total new tests: **16** (all pass).

## Carry-forward to M12

- Runtime HTTPS POST to the OAuth2 provider (deferred).
- AWS, K8s, mTLS, Terraform, Docker connectors (deferred).
- Client-secret zeroization in `OAuth2Config` (deferred).

## Status

PASS.