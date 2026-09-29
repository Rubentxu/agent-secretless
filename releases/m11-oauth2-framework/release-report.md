# M11 — OAuth2 provider framework — Release Report

## Cycle

M11-prototype (item #4 of the M11 roadmap).

## Verdict

PASS.

## What shipped

| Artifact | Path |
|---|---|
| M11 exploration | `docs/exploration/m11-exploration.md` |
| M11 specification | `docs/specs/m11-connectors/specification.md` |
| OAuth2 module | `crates/broker/src/oauth2.rs` |
| UAT-030 integration tests | `crates/broker/tests/uat_030_oauth2_surrogate_lifecycle.rs` |

## Spec coverage

| Requirement | Where | Test |
|---|---|---|
| M11-R1 OAuth2Token shape | `oauth2::OAuth2Token` | `token_exposes_access_bytes`, `token_carries_refresh_bytes_internally` |
| M11-R2 OAuth2Config | `oauth2::OAuth2Config` | `oauth2_config_constructs_from_parts` |
| M11-R3 OAuth2Issuer trait | `oauth2::OAuth2Issuer`, `ClientCredentialsIssuer` | `client_credentials_issuer_issue_returns_bearer_token`, `client_credentials_issuer_refresh_returns_new_token` |
| M11-R4 closed-set | trait has 2 entry methods (`issue`, `refresh`) | `uat_030_refresh_bytes_are_not_reachable_via_public_api` |
| M11-R5 token zeroization | `Zeroizing<Vec<u8>>` wrapper + explicit `Drop` | structural |

## Tests

| Suite | Count | Result |
|---|---|---|
| `cargo test --lib -p asv-broker oauth2` | 10 | all pass |
| `cargo test --test uat_030_oauth2_surrogate_lifecycle` | 6 | all pass |

## Workspace totals (post-M11)

| Suite | Result |
|---|---|
| `cargo build --workspace --all-targets` | OK |
| `cargo test --workspace --all-targets` (surgical oauth2) | 16 new, all pass |

## Honest gaps (deferred)

- The actual HTTPS POST to the provider (`runtime_not_implemented`
  path is structural; the placeholder is content-addressed, not
  derived from a real IdP).
- AWS SigV4 request re-signing.
- Kubernetes API reverse proxy.
- mTLS / X.509 signer.
- Terraform provider catalog.
- Docker / registry research.
- Client-secret zeroization in `OAuth2Config` (the runtime follow-up
  moves `client_secret` into the issuer at construction time and
  zeroes it on the config).

## Next milestone

M12 — TPM hardware-backed vault.