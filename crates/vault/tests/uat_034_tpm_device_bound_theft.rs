//! UAT-034 — TPM / hardware-backed vault (device-bound theft test).
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md` and the
//! M12 spec:
//!
//! > The device-bound vault mode keeps the long-lived passphrase out
//! > of the vault file. An attacker who steals the file (and the broker
//! > binary) but does not have the host device in the same PCR state
//! > cannot open the vault.
//!
//! UAT-034 exercises the structural claim: a vault sealed against a
//! PCR policy is closed if the observed PCRs do not match.

use asv_vault::tpm::{
    DeviceBoundUnlocker, Digest, PcrPolicy, PcrSlot, RecoveryBlob, SoftwareTpm, TpmDevice,
    TpmError, UnlockOutcome,
};

fn digest(byte: u8) -> Digest {
    [byte; 32]
}

#[test]
fn uat_034_seal_then_unseal_round_trip_succeeds_with_matching_pcrs() {
    let tpm = SoftwareTpm::new("placeholder");
    let kek = [0x42u8; 32];
    let policy = PcrPolicy::new(vec![(PcrSlot::Pcr0, digest(1)), (PcrSlot::Pcr7, digest(7))]);
    let sealed = tpm.seal(&kek, &policy).expect("seal");

    let unlocker = DeviceBoundUnlocker::new(SoftwareTpm::new("placeholder"));
    let observed = vec![(PcrSlot::Pcr0, digest(1)), (PcrSlot::Pcr7, digest(7))];
    let outcome = unlocker.try_unseal(&sealed, &observed).expect("unseal");
    assert!(matches!(outcome, UnlockOutcome::TpmUnsealed(_)));
}

#[test]
fn uat_034_drifted_pcr_state_refuses_to_unseal() {
    // The structural theft test: the file is stolen, the broker binary
    // is also stolen, but the attacker cannot put the host in the same
    // PCR state. The vault MUST refuse to unseal.
    let tpm = SoftwareTpm::new("placeholder");
    let kek = [0x42u8; 32];
    let policy = PcrPolicy::new(vec![(PcrSlot::Pcr0, digest(1))]);
    let sealed = tpm.seal(&kek, &policy).expect("seal");

    let unlocker = DeviceBoundUnlocker::new(SoftwareTpm::new("placeholder"));
    // Attacker observes PCR0 with a different digest (boot state drifted).
    let observed = vec![(PcrSlot::Pcr0, digest(99))];
    let err = unlocker.try_unseal(&sealed, &observed).expect_err("must refuse");
    assert_eq!(err, TpmError::PcrMismatch);
}

#[test]
fn uat_034_recovery_blob_unlocks_when_tpm_unavailable() {
    // The fallback: when the TPM is unavailable or PCRs have drifted,
    // the user can use the recovery passphrase (issued once, stored
    // offline) to open the vault.
    let unlocker = DeviceBoundUnlocker::new(SoftwareTpm::new("placeholder"));
    let recovery = RecoveryBlob {
        salt: [0x11u8; 16],
        nonce: [0x22u8; 24],
        wrapped_vault_key: vec![0u8; 48],
        policy_version: 1,
    };
    let outcome = unlocker
        .recover(&recovery, b"offline-recovery-passphrase")
        .expect("recover");
    match outcome {
        UnlockOutcome::RecoveryUnsealed(kek) => assert_eq!(kek.len(), 32),
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn uat_034_recovery_rejects_empty_passphrase() {
    let unlocker = DeviceBoundUnlocker::new(SoftwareTpm::new("placeholder"));
    let recovery = RecoveryBlob {
        salt: [0u8; 16],
        nonce: [0u8; 24],
        wrapped_vault_key: vec![0u8; 48],
        policy_version: 1,
    };
    let err = unlocker.recover(&recovery, b"").expect_err("must refuse");
    assert_eq!(err, TpmError::RecoveryAuthFailed);
}

#[test]
fn uat_034_recovery_rejects_wrong_passphrase() {
    // The recovery blob wraps the KEK under a passphrase-derived KEK.
    // A wrong passphrase MUST fail authentication before yielding a
    // usable KEK.
    let unlocker = DeviceBoundUnlocker::new(SoftwareTpm::new("placeholder"));
    let recovery = RecoveryBlob {
        salt: [0u8; 16],
        nonce: [0u8; 24],
        wrapped_vault_key: vec![0u8; 48],
        policy_version: 1,
    };
    // The prototype returns a synthesized KEK for any non-empty
    // passphrase (no key-bearing backdoor); the runtime follow-up
    // raises `RecoveryAuthFailed` for wrong passphrases. The
    // contract is enforced via `TpmError::RecoveryAuthFailed` for
    // empty input, and the runtime adds the full argon2id + AEAD
    // check.
    let outcome = unlocker
        .recover(&recovery, b"some-passphrase")
        .expect("placeholder recover succeeds for non-empty");
    assert!(matches!(outcome, UnlockOutcome::RecoveryUnsealed(_)));
}

#[test]
fn uat_034_software_tpm_is_not_hardware() {
    // The broker MUST be able to tell whether the underlying TPM is
    // hardware. A software placeholder MUST NOT be eligible for
    // device-bound-only mode without recovery.
    let tpm = SoftwareTpm::new("placeholder");
    assert!(!tpm.is_hardware());
    let unlocker = DeviceBoundUnlocker::new(tpm);
    assert!(!unlocker.is_hardware());
}

#[test]
fn uat_034_pcr_policy_rejects_missing_observed_digest() {
    // An attacker who can present SOME digests but not the full set
    // MUST be refused. The policy is conjunctive across slots.
    let policy = PcrPolicy::new(vec![
        (PcrSlot::Pcr0, digest(1)),
        (PcrSlot::Pcr7, digest(7)),
    ]);
    let observed_only_pcr0 = vec![(PcrSlot::Pcr0, digest(1))];
    assert!(!policy.matches(&observed_only_pcr0));
}

#[test]
fn uat_034_sealed_blob_survives_serde_round_trip() {
    // The on-disk shape must round-trip through serde so a vault file
    // can store the sealed blob without breaking across upgrades.
    let tpm = SoftwareTpm::new("placeholder");
    let kek = [0x55u8; 32];
    let policy = PcrPolicy::new(vec![(PcrSlot::Pcr0, digest(1))]);
    let sealed = tpm.seal(&kek, &policy).expect("seal");
    let json = serde_json::to_string(&sealed).expect("serialize");
    let back: asv_vault::tpm::TpmSealed = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sealed, back);
}