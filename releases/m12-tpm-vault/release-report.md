# M12 — TPM / hardware-backed vault — Release Report

## Cycle

M12-prototype.

## Verdict

PASS.

## What shipped

| Artifact | Path |
|---|---|
| M12 exploration | `docs/exploration/m12-exploration.md` |
| M12 specification | `docs/specs/m12-tpm/specification.md` |
| TPM module | `crates/vault/src/tpm.rs` |
| UAT-034 integration tests | `crates/vault/tests/uat_034_tpm_device_bound_theft.rs` |

## Spec coverage

| Requirement | Where | Test |
|---|---|---|
| M12-R1 TpmDevice trait | `tpm::TpmDevice` | all unit + uat tests |
| M12-R2 TpmSealed shape | `tpm::TpmSealed` | `tpm_sealed_serializes_and_deserializes_round_trip`, `uat_034_sealed_blob_survives_serde_round_trip` |
| M12-R3 PcrPolicy semantics | `tpm::PcrPolicy::matches` | `pcr_policy_matches_when_observed_digests_match`, `pcr_policy_rejects_drifted_digests`, `pcr_policy_rejects_missing_slot`, `uat_034_drifted_pcr_state_refuses_to_unseal`, `uat_034_pcr_policy_rejects_missing_observed_digest` |
| M12-R4 RecoveryBlob | `tpm::RecoveryBlob` | `recovery_blob_serializes_and_deserializes_round_trip`, `uat_034_recovery_blob_unlocks_when_tpm_unavailable` |
| M12-R5 Fallback policy | `tpm::DeviceBoundUnlocker` | `device_bound_unlocker_reports_pcr_mismatch_via_try_unseal`, `device_bound_unlocker_recover_*` |
| M12-R6 Hardware flag | `tpm::TpmDevice::is_hardware` | `software_tpm_is_not_hardware`, `uat_034_software_tpm_is_not_hardware` |

## Tests

| Suite | Count | Result |
|---|---|---|
| `cargo test --lib -p asv-vault tpm` | 19 | all pass |
| `cargo test --test uat_034_tpm_device_bound_theft` | 8 | all pass |

## Honest gaps (deferred to M12-runtime)

- Real TCG TPM2 client (`/dev/tpmrm0`).
- Argon2id + AEAD verification of the recovery blob at runtime.
- Migration passphrase-bound -> device-bound (re-seal workflow).
- Auto-detection of available TPM.

## Next milestone

M13 — RC security stabilization.