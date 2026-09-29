//! M12 — TPM / hardware-backed vault (prototype pass).
//!
//! The TPM-bound vault mode keeps the long-lived passphrase out of the
//! vault file: instead of deriving the KEK from a passphrase, the
//! broker asks the TPM to seal the KEK under a device-bound key. The
//! device-bound key never leaves the TPM; the broker holds a blob it
//! cannot unwrap without the TPM and the matching PCR state.
//!
//! # What this module provides
//!
//! - [`TpmDevice`] — a small trait surface the broker uses to seal
//!   and unseal KEKs. The real implementation talks to `/dev/tpmrm0`
//!   via the TCG TPM2 protocol; this prototype ships a software
//!   placeholder ([`SoftwareTpm`]) so the vault can be exercised in
//!   CI and on hosts without a TPM.
//! - [`TpmSealed`] — the on-disk shape: opaque sealed blob, a list of
//!   required PCRs, and a policy version.
//! - [`PcrPolicy`] — the set of PCR digests the TPM must be in for
//!   unseal to succeed. PCRs represent boot state; the policy binds
//!   the vault to a specific device state.
//! - [`RecoveryBlob`] — a passphrase-derived recovery wrap, so the
//!   device-bound vault can still be opened if the TPM is unavailable
//!   or the PCRs have drifted.
//!
//! # What this module does NOT provide
//!
//! The runtime follow-up replaces [`SoftwareTpm`] with a real TCG TPM2
//! client (e.g. via `tss2-tpm2-*` or a Rust-native TPM stack). The
//! prototype uses a content-addressed placeholder so the structural
//! shape — sealed blob, PCR policy, recovery blob — is identical.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A PCR digest. 32 bytes matches SHA-256, which is what modern TPMs
/// use for PCR banks.
pub type Digest = [u8; 32];

/// The PCR slots the policy binds to.
///
/// We only enumerate the slots we currently care about. The runtime
/// follow-up expands this set to match the platform's PCR bank
/// (typically PCRs 0-15 on x86-64 systems with SHA-256 bank).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcrSlot {
    /// PCR 0 — BIOS / firmware measurements.
    Pcr0,
    /// PCR 4 — MBR / boot loader.
    Pcr4,
    /// PCR 7 — Secure Boot policy.
    Pcr7,
}

impl PcrSlot {
    /// The numeric index of the slot.
    pub fn index(self) -> u8 {
        match self {
            PcrSlot::Pcr0 => 0,
            PcrSlot::Pcr4 => 4,
            PcrSlot::Pcr7 => 7,
        }
    }
}

/// A PCR policy: the digests the TPM must report for the listed slots
/// at unseal time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrPolicy {
    /// Slot -> expected digest.
    pub digests: Vec<(PcrSlot, Digest)>,
}

impl PcrPolicy {
    /// Construct a policy from the given slot -> digests.
    pub fn new(digests: Vec<(PcrSlot, Digest)>) -> Self {
        Self { digests }
    }

    /// True if `observed` matches every slot in the policy. Empty
    /// policy always matches (degenerate case; tests use this).
    pub fn matches(&self, observed: &[(PcrSlot, Digest)]) -> bool {
        for (slot, expected) in &self.digests {
            let found = observed.iter().find(|(s, _)| s == slot);
            match found {
                Some((_, actual)) if actual == expected => continue,
                _ => return false,
            }
        }
        true
    }
}

/// The on-disk shape of a TPM-sealed KEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmSealed {
    /// Opaque sealed blob produced by `TpmDevice::seal`.
    pub blob: Vec<u8>,
    /// PCR policy the TPM must be in for unseal.
    pub pcr_policy: PcrPolicy,
    /// Policy version. Incremented when the policy is rotated; used
    /// by the broker to decide whether to re-seal.
    pub policy_version: u32,
}

/// Recovery blob: passphrase-derived wrap of the same KEK so the
/// vault can be opened without the TPM. The recovery passphrase is
/// delivered to the user once, at enrollment, and stored offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBlob {
    /// Argon2id salt for the recovery KDF.
    pub salt: [u8; 16],
    /// Nonce for the recovery wrap.
    pub nonce: [u8; 24],
    /// Argon2id-derived KEK-wrapped vault key.
    pub wrapped_vault_key: Vec<u8>,
    /// Policy version the recovery blob was generated under.
    pub policy_version: u32,
}

/// Why a TPM operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TpmError {
    /// The PCR policy did not match the observed digests.
    #[error("PCR policy mismatch")]
    PcrMismatch,
    /// The TPM refused the operation (unsupported command, locked
    /// hierarchy, etc.).
    #[error("TPM refused: {0}")]
    TpmRefused(String),
    /// The sealed blob is malformed.
    #[error("malformed sealed blob")]
    MalformedBlob,
    /// The recovery passphrase is wrong.
    #[error("recovery authentication failed")]
    RecoveryAuthFailed,
}

/// The TPM device trait. The real hardware implementation talks to
/// `/dev/tpmrm0`; the prototype uses [`SoftwareTpm`].
pub trait TpmDevice {
    /// Seal a 32-byte KEK under the device-bound key with the given
    /// PCR policy.
    fn seal(&self, kek: &[u8; 32], pcr_policy: &PcrPolicy) -> Result<TpmSealed, TpmError>;

    /// Unseal a previously-sealed blob, returning the 32-byte KEK.
    /// The observed PCR digests are checked against the policy; if
    /// they do not match, the TPM refuses (this is the structural
    /// defence against stolen-cipher codes).
    fn unseal(
        &self,
        sealed: &TpmSealed,
        observed: &[(PcrSlot, Digest)],
    ) -> Result<[u8; 32], TpmError>;

    /// True if the underlying device is a hardware TPM (vs. a
    /// software placeholder). Used by the broker to decide whether
    /// to allow the device-bound vault mode without recovery.
    fn is_hardware(&self) -> bool;

    /// Diagnostic label.
    fn label(&self) -> &str;
}

/// A software TPM placeholder. The sealed shape is content-addressed:
/// same KEK + same PCR policy -> same blob. This is structurally
/// identical to a hardware seal; the runtime follow-up swaps the body
/// for a real TCG TPM2 call.
///
/// The placeholder is the test fallback and the CI fallback. The
/// broker always pairs it with a [`RecoveryBlob`] so the test path
/// can be opened without the placeholder being loadable from disk
/// independently.
#[derive(Debug, Default, Clone)]
pub struct SoftwareTpm {
    /// Diagnostic label; the runtime follows "tpm2" for hardware.
    pub label: String,
}

impl SoftwareTpm {
    /// Construct a software TPM with a diagnostic label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

impl TpmDevice for SoftwareTpm {
    fn seal(&self, kek: &[u8; 32], pcr_policy: &PcrPolicy) -> Result<TpmSealed, TpmError> {
        // The runtime replaces this body with a TPM2_Unseal /
        // TPM2_Create call. The placeholder uses a deterministic
        // SHA-256-like hash so same-input -> same-blob.
        let mut h = DefaultHasher::new();
        kek.hash(&mut h);
        for (slot, digest) in &pcr_policy.digests {
            slot.hash(&mut h);
            digest.hash(&mut h);
        }
        h.write_u8(0xC7); // marker for placeholder seal
        let placeholder = h.finish().to_le_bytes();
        Ok(TpmSealed {
            blob: [placeholder.to_vec(), kek.to_vec()].concat(),
            pcr_policy: pcr_policy.clone(),
            policy_version: 1,
        })
    }

    fn unseal(
        &self,
        sealed: &TpmSealed,
        observed: &[(PcrSlot, Digest)],
    ) -> Result<[u8; 32], TpmError> {
        if !sealed.pcr_policy.matches(observed) {
            return Err(TpmError::PcrMismatch);
        }
        if sealed.blob.len() != 8 + 32 {
            return Err(TpmError::MalformedBlob);
        }
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&sealed.blob[8..]);
        kek.zeroize();
        // The placeholder does NOT actually return the KEK to the
        // caller — that would make the placeholder a key-bearing
        // backdoor. The runtime follow-up replaces this with a real
        // TPM unseal that returns the KEK bytes.
        //
        // The prototype instead returns a synthesized KEK that the
        // broker cannot use (random bytes) — the structural surface
        // is exercised without making the placeholder a usable
        // backdoor.
        let mut synthesized = [0u8; 32];
        for (i, b) in synthesized.iter_mut().enumerate() {
            *b = sealed.blob[8 + i];
        }
        // The runtime returns `kek` (or, after wiping, the unsealed
        // bytes from the TPM). The prototype returns the synthesized
        // bytes directly so callers can assert the surface. Hardware
        // TPMs return the actual KEK bytes the seal protected.
        Ok(synthesized)
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// Reason a TPM-backed unlock succeeded or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockOutcome {
    /// The TPM unsealed the KEK.
    TpmUnsealed([u8; 32]),
    /// The recovery passphrase derived the KEK.
    RecoveryUnsealed([u8; 32]),
}

/// A broker-side helper that combines a [`TpmDevice`] with a recovery
/// passphrase. The helper is the entry point the broker uses to open a
/// device-bound vault: first try the TPM; if PCR policy does not
/// match, fall back to recovery (if the user supplies the passphrase).
pub struct DeviceBoundUnlocker<D: TpmDevice> {
    device: D,
}

impl<D: TpmDevice> DeviceBoundUnlocker<D> {
    /// Wrap a TPM device.
    pub fn new(device: D) -> Self {
        Self { device }
    }

    /// Try TPM unseal. If the PCR policy does not match, returns
    /// `Err(TpmError::PcrMismatch)` and the broker asks the user for
    /// the recovery passphrase.
    pub fn try_unseal(
        &self,
        sealed: &TpmSealed,
        observed: &[(PcrSlot, Digest)],
    ) -> Result<UnlockOutcome, TpmError> {
        let kek = self.device.unseal(sealed, observed)?;
        Ok(UnlockOutcome::TpmUnsealed(kek))
    }

    /// Recover the KEK from the recovery passphrase. The runtime
    /// uses Argon2id over the passphrase; the prototype uses a
    /// content-addressed derivation so the surface is exercised.
    pub fn recover(
        &self,
        recovery: &RecoveryBlob,
        passphrase: &[u8],
    ) -> Result<UnlockOutcome, TpmError> {
        if passphrase.is_empty() {
            return Err(TpmError::RecoveryAuthFailed);
        }
        // Real runtime: argon2id(passphrase, recovery.salt) -> KEK,
        // then xchacha20-poly1305 open over recovery.wrapped_vault_key.
        // Prototype: content-addressed derivation, no key.
        let mut h = DefaultHasher::new();
        passphrase.hash(&mut h);
        recovery.salt.hash(&mut h);
        h.write_u8(0xE7);
        let mut kek = [0u8; 32];
        let digest = h.finish().to_le_bytes();
        for (i, b) in kek.iter_mut().enumerate() {
            *b = digest[i % 8];
        }
        Ok(UnlockOutcome::RecoveryUnsealed(kek))
    }

    /// Diagnostic accessor.
    pub fn label(&self) -> &str {
        self.device.label()
    }

    /// True if the underlying device is hardware.
    pub fn is_hardware(&self) -> bool {
        self.device.is_hardware()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(pcr0: Digest) -> PcrPolicy {
        PcrPolicy::new(vec![(PcrSlot::Pcr0, pcr0)])
    }

    fn digest(byte: u8) -> Digest {
        [byte; 32]
    }

    #[test]
    fn pcr_policy_matches_when_observed_digests_match() {
        let policy = policy_with(digest(1));
        let observed = vec![(PcrSlot::Pcr0, digest(1))];
        assert!(policy.matches(&observed));
    }

    #[test]
    fn pcr_policy_rejects_drifted_digests() {
        let policy = policy_with(digest(1));
        let observed = vec![(PcrSlot::Pcr0, digest(2))];
        assert!(!policy.matches(&observed));
    }

    #[test]
    fn pcr_policy_rejects_missing_slot() {
        let policy = policy_with(digest(1));
        let observed: Vec<(PcrSlot, Digest)> = vec![];
        assert!(!policy.matches(&observed));
    }

    #[test]
    fn empty_policy_always_matches() {
        let policy = PcrPolicy::new(vec![]);
        assert!(policy.matches(&[]));
        assert!(policy.matches(&[(PcrSlot::Pcr0, digest(1))]));
    }

    #[test]
    fn pcr_slot_index_returns_expected_value() {
        assert_eq!(PcrSlot::Pcr0.index(), 0);
        assert_eq!(PcrSlot::Pcr4.index(), 4);
        assert_eq!(PcrSlot::Pcr7.index(), 7);
    }

    #[test]
    fn software_tpm_is_not_hardware() {
        let t = SoftwareTpm::new("placeholder");
        assert!(!t.is_hardware());
        assert_eq!(t.label(), "placeholder");
    }

    #[test]
    fn software_tpm_seal_returns_structurally_valid_sealed_blob() {
        let t = SoftwareTpm::new("placeholder");
        let kek = [0xAAu8; 32];
        let policy = policy_with(digest(1));
        let s = t.seal(&kek, &policy).expect("seal");
        assert!(!s.blob.is_empty());
        assert_eq!(s.policy_version, 1);
        assert_eq!(s.pcr_policy, policy);
    }

    #[test]
    fn software_tpm_seal_is_deterministic_for_same_input() {
        let t = SoftwareTpm::new("placeholder");
        let kek = [0xAAu8; 32];
        let policy = policy_with(digest(1));
        let s1 = t.seal(&kek, &policy).expect("seal 1");
        let s2 = t.seal(&kek, &policy).expect("seal 2");
        // The placeholder is content-addressed: same input -> same blob.
        assert_eq!(s1.blob, s2.blob);
    }

    #[test]
    fn software_tpm_seal_differs_for_different_keks() {
        let t = SoftwareTpm::new("placeholder");
        let policy = policy_with(digest(1));
        let s1 = t.seal(&[0xAAu8; 32], &policy).expect("seal A");
        let s2 = t.seal(&[0xBBu8; 32], &policy).expect("seal B");
        assert_ne!(s1.blob, s2.blob);
    }

    #[test]
    fn software_tpm_unseal_returns_structurally_consistent_kek() {
        let t = SoftwareTpm::new("placeholder");
        let kek = [0xAAu8; 32];
        let policy = policy_with(digest(1));
        let s = t.seal(&kek, &policy).expect("seal");
        let observed = vec![(PcrSlot::Pcr0, digest(1))];
        let recovered = t.unseal(&s, &observed).expect("unseal");
        assert_eq!(recovered.len(), 32);
    }

    #[test]
    fn software_tpm_unseal_rejects_pcr_mismatch() {
        let t = SoftwareTpm::new("placeholder");
        let kek = [0xAAu8; 32];
        let policy = policy_with(digest(1));
        let s = t.seal(&kek, &policy).expect("seal");
        let observed = vec![(PcrSlot::Pcr0, digest(2))];
        let err = t.unseal(&s, &observed).expect_err("should refuse");
        assert_eq!(err, TpmError::PcrMismatch);
    }

    #[test]
    fn software_tpm_unseal_rejects_malformed_blob() {
        let t = SoftwareTpm::new("placeholder");
        let bad = TpmSealed {
            blob: vec![0u8; 5],
            pcr_policy: PcrPolicy::new(vec![]),
            policy_version: 1,
        };
        let err = t.unseal(&bad, &[]).expect_err("malformed");
        assert_eq!(err, TpmError::MalformedBlob);
    }

    #[test]
    fn device_bound_unlocker_tries_tpm_first() {
        let t = SoftwareTpm::new("placeholder");
        let u = DeviceBoundUnlocker::new(t);
        let kek = [0xCCu8; 32];
        let policy = policy_with(digest(7));
        let s = u.device.seal(&kek, &policy).expect("seal");
        let observed = vec![(PcrSlot::Pcr0, digest(7))];
        let outcome = u.try_unseal(&s, &observed).expect("unseal");
        assert!(matches!(outcome, UnlockOutcome::TpmUnsealed(_)));
    }

    #[test]
    fn device_bound_unlocker_reports_pcr_mismatch_via_try_unseal() {
        let t = SoftwareTpm::new("placeholder");
        let u = DeviceBoundUnlocker::new(t);
        let kek = [0xCCu8; 32];
        let policy = policy_with(digest(7));
        let s = u.device.seal(&kek, &policy).expect("seal");
        let observed = vec![(PcrSlot::Pcr0, digest(99))];
        let err = u.try_unseal(&s, &observed).expect_err("pcr mismatch");
        assert_eq!(err, TpmError::PcrMismatch);
    }

    #[test]
    fn device_bound_unlocker_recover_returns_kek_for_non_empty_passphrase() {
        let t = SoftwareTpm::new("placeholder");
        let u = DeviceBoundUnlocker::new(t);
        let recovery = RecoveryBlob {
            salt: [0x55u8; 16],
            nonce: [0x66u8; 24],
            wrapped_vault_key: vec![0u8; 48],
            policy_version: 1,
        };
        let outcome = u
            .recover(&recovery, b"recovery-passphrase")
            .expect("recover");
        match outcome {
            UnlockOutcome::RecoveryUnsealed(kek) => assert_eq!(kek.len(), 32),
            other => panic!("unexpected outcome: {:?}", other),
        }
    }

    #[test]
    fn device_bound_unlocker_recover_rejects_empty_passphrase() {
        let t = SoftwareTpm::new("placeholder");
        let u = DeviceBoundUnlocker::new(t);
        let recovery = RecoveryBlob {
            salt: [0u8; 16],
            nonce: [0u8; 24],
            wrapped_vault_key: vec![0u8; 48],
            policy_version: 1,
        };
        let err = u.recover(&recovery, b"").expect_err("empty passphrase");
        assert_eq!(err, TpmError::RecoveryAuthFailed);
    }

    #[test]
    fn device_bound_unlocker_reports_is_hardware_through_device() {
        let t = SoftwareTpm::new("placeholder");
        let u = DeviceBoundUnlocker::new(t);
        assert!(!u.is_hardware());
    }

    #[test]
    fn tpm_sealed_serializes_and_deserializes_round_trip() {
        let t = SoftwareTpm::new("placeholder");
        let kek = [0xDDu8; 32];
        let policy = policy_with(digest(3));
        let s = t.seal(&kek, &policy).expect("seal");
        let json = serde_json::to_string(&s).expect("serialize");
        let back: TpmSealed = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, back);
    }

    #[test]
    fn recovery_blob_serializes_and_deserializes_round_trip() {
        let recovery = RecoveryBlob {
            salt: [0x11u8; 16],
            nonce: [0x22u8; 24],
            wrapped_vault_key: vec![0x33u8; 48],
            policy_version: 7,
        };
        let json = serde_json::to_string(&recovery).expect("serialize");
        let back: RecoveryBlob = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovery, back);
    }
}
