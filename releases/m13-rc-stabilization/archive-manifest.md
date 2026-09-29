# M13 — Archive Manifest

## Cycle

M13 — RC security stabilization.

## Artifacts

| Path | Role |
|---|---|
| `releases/m13-rc-stabilization/release-report.md` | Cycle release report |
| `releases/m13-rc-stabilization/merge-receipt.md` | Git push receipt |
| `releases/m13-rc-stabilization/archive-manifest.md` | This file |
| `docs/exploration/m13-exploration.md` | Exploration notes |
| `docs/manual/OPERATIONS.md` | Operator manual |
| `crates/broker/src/recovery.rs` | Crash/recovery module |
| `crates/broker/tests/uat_035_crash_recovery.rs` | Integration tests |
| `target/sbom.json` | SBOM via `cargo metadata` (1.5 MB) |

## Tag

`m13-rc-stabilization` at `4956255`.

## Stabilization evidence

| Check | Result |
|---|---|
| `cargo audit` | 0 advisories on 331 deps |
| `cargo test --workspace --release -- --test-threads=1 --skip uat_028` | ~393 passed, 0 failed, 1 ignored |
| `cargo test --lib -p asv-broker recovery` | 14 passed |
| `cargo test --test uat_035_crash_recovery` | 6 passed |

## Tests added in M13

- Unit tests in `crates/broker/src/recovery.rs`: 14
- UAT-035 integration tests: 6
- **Total new: 20**

## Carry-forward to v1.0 prep

- Third-party security review
- Fuzz targets / fuzz duration increase
- Signed reproducible artifacts
- Upgrade / migration tests

## Status

PASS.

## Roadmap end-state

M13 closes the prototype roadmap. All 8 milestones (M6..M13) shipped
consecutively with tags pushed to the remote.