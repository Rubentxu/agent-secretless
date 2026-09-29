# M12 — Archive Manifest

## Cycle

M12-prototype (TPM / hardware-backed vault).

## Artifacts

| Path | Role |
|---|---|
| `releases/m12-tpm-vault/release-report.md` | Cycle release report |
| `releases/m12-tpm-vault/merge-receipt.md` | Git push receipt |
| `releases/m12-tpm-vault/archive-manifest.md` | This file |
| `docs/exploration/m12-exploration.md` | Exploration notes |
| `docs/specs/m12-tpm/specification.md` | Delta spec |
| `crates/vault/src/tpm.rs` | TPM module |
| `crates/vault/tests/uat_034_tpm_device_bound_theft.rs` | Integration tests |

## Tag

`m12-tpm-vault` at `91d19d6`.

## Spec coverage

M12-R1..M12-R6 (all).

## Tests

- Unit tests in `crates/vault/src/tpm.rs`: 19
- UAT-034 integration tests: 8

Total new tests: **27** (all pass).

## Carry-forward to M13

- Real TCG TPM2 client (`/dev/tpmrm0`).
- Argon2id + AEAD verification of the recovery blob at runtime.
- Migration passphrase-bound -> device-bound.
- Auto-detection of available TPM.

## Status

PASS.