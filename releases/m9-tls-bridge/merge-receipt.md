# M9 — Transparent TLS bridge — Merge Receipt

## Merge to main

- **HEAD at merge**: see commit log
- **Branch**: main
- **Strategy**: fast-forward (linear history).
- **Conflicts**: none.

## Released commits

| SHA | Subject |
|---|---|
| (single) | feat(broker): M9 transparent TLS bridge prototype |

## Changes since M8

```
crates/broker/src/lib.rs                      |   1 +
crates/broker/src/tls_bridge.rs              | 511 ++++++++++++++++
crates/broker/tests/uat_010_connect_allow_list.rs | new
crates/broker/tests/uat_011_redirect_denier.rs | new
crates/broker/tests/uat_012_trust_injection.rs | new
docs/exploration/m9-exploration.md            | new
docs/specs/m9-tls-bridge/specification.md     | new
```