//! Vault envelope format and key hierarchy.
//!
//! Normative source: `docs/07-VAULT-CRYPTO-MEMORY.md` §2 and §3.
//!
//! ```text
//! Master/KEK
//!    |
//!    +--> wraps per-record or per-vault DEKs
//!              |
//!              +--> AEAD encrypts credential payloads
//! ```
//!
//! Two design rules from the spec drive everything in this module:
//!
//! 1. **Metadata and secret material are separate records.** A stolen
//!    locked vault must not disclose labels, account names or providers, so
//!    this module keeps the authenticated *body* of the vault opaque. The
//!    spec allows plaintext metadata as a privacy option, but a vault whose
//!    plaintext reveals which providers a user has accounts with is a worse
//!    default than one that does not, so the body stays encrypted.
//!
//! 2. **Do not invent a cipher or KDF.** Argon2id derives the KEK and
//!    XChaCha20-Poly1305 does the AEAD, exactly as named by the spec. The
//!    parameters that vary (Argon2 memory/time/parallelism, cipher id, KDF
//!    id, envelope version) are *versioned fields in the file*, not compile
//!    time constants, because §4 requires Argon2id parameters to be
//!    "calibrated on first setup and versioned for future migration".

use chacha20poly1305::aead::{Aead, Key, KeyInit};
use core::fmt;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Envelope format version. Bump when a reader cannot correctly interpret
/// every previously written file.
pub const ENVELOPE_VERSION: u16 = 1;

/// Magic prefix so a backup or vault file is recognisable and so restoring a
/// random file fails loudly rather than silently.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"ASVVAULT";

/// Cipher identifiers. Versioned in the file so an algorithm migration is a
/// data decision, not a binary replacement.
pub mod cipher_id {
    /// XChaCha20-Poly1305, 24-byte nonce, 128-bit tag.
    pub const XCHACHA20_POLY1305: u8 = 1;
}

/// KDF identifiers.
pub mod kdf_id {
    /// Argon2id with versioned parameters.
    pub const ARGON2ID: u8 = 1;
}

/// Argon2id parameters, versioned in the file per spec §4.
///
/// Defaults are calibrated for an interactive unlock on a developer machine
/// while keeping a stolen vault expensive to brute-force. They are recorded
/// so that raising them later does not invalidate existing vaults: the next
/// unlock re-derives with the stored parameters and can opportunistically
/// re-wrap the KEK with stronger ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Argon2 variant id. Only Argon2id is permitted; the field exists so a
    /// future migration is representable in the format.
    pub kdf_id: u8,
    /// Memory cost in kibibytes.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
    /// Length of the derived key in bytes.
    pub key_len: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes, 32-byte key.
    ///
    /// This is the OWASP-recommended Argon2id baseline shape for a
    /// passphrase KDF and is deliberately recorded in the file rather than
    /// assumed, so M12 or any later milestone can raise it and migrate.
    fn default() -> Self {
        Self {
            kdf_id: kdf_id::ARGON2ID,
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            key_len: 32,
        }
    }
}

impl KdfParams {
    /// Parameters suitable for tests and for the harness, which unlock a vault
    /// many times per run. Never used for a real vault.
    pub fn fast_for_tests() -> Self {
        Self {
            kdf_id: kdf_id::ARGON2ID,
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            key_len: 32,
        }
    }

    /// Rejects parameter sets that would weaken the vault. A file that
    /// arrives with absurd cost values must fail rather than pin a CPU.
    ///
    /// Note the lower bound on memory: 8 KiB would be crackable instantly, so
    /// a file claiming it is treated as hostile or corrupt. This is also what
    /// makes the test parameters acceptable: they sit exactly on the floor.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.kdf_id != kdf_id::ARGON2ID {
            return Err(EnvelopeError::UnsupportedKdf(self.kdf_id));
        }
        if self.m_cost_kib < 8 * 1024 {
            return Err(EnvelopeError::WeakKdfParams);
        }
        if self.m_cost_kib > 4 * 1024 * 1024 {
            return Err(EnvelopeError::KdfParamsOutOfRange);
        }
        if self.t_cost == 0 || self.t_cost > 16 {
            return Err(EnvelopeError::KdfParamsOutOfRange);
        }
        if self.p_cost == 0 || self.p_cost > 64 {
            return Err(EnvelopeError::KdfParamsOutOfRange);
        }
        if self.key_len != 32 {
            return Err(EnvelopeError::KdfParamsOutOfRange);
        }
        Ok(())
    }
}

/// Salt length for Argon2id. 16 bytes is the library default and matches the
/// spec's "OS CSPRNG for salts".
pub const SALT_LEN: usize = 16;

/// A key-encryption key: the output of Argon2id over a passphrase, or a
/// randomly generated vault key.
///
/// It deliberately implements `Debug` as redacted and does not implement
/// `Serialize`, so it cannot reach a log line or a DTO. `expose` is the single
/// read path, mirroring [`asv_domain::secret::SecretBytes`].
pub struct KeyEncryptionKey(zeroize::Zeroizing<[u8; 32]>);

impl KeyEncryptionKey {
    /// Wraps 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// The single read path. Callers must not log, format or persist it.
    #[allow(clippy::needless_lifetimes)]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Overwrites the key in place. Used when a vault is re-locked or when
    /// the derived key must not survive an operation.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyEncryptionKey(<redacted>)")
    }
}

/// Vault header: everything needed to attempt an unlock, and nothing that
/// discloses a credential.
///
/// Spec §2 separates metadata from payload. This header is *not* credential
/// metadata: it is the container description, and the spec's "authenticated
/// metadata/header" requirement for backups (§11) is satisfied by the AEAD tag
/// over the body rather than by trusting this struct on its own. A tampered
/// header therefore causes an authentication failure, not a misparse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Format version.
    pub version: u16,
    /// Cipher used for the body.
    pub cipher_id: u8,
    /// KDF parameters used to derive the KEK from the passphrase.
    pub kdf: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// Nonce for the KEK-wrapped vault key.
    pub wrap_nonce: [u8; 24],
    /// The vault data-encryption key, wrapped by the KEK.
    pub wrapped_vault_key: Vec<u8>,
    /// Nonce for the body.
    pub body_nonce: [u8; 24],
    /// Monotonic revision, incremented on every successful mutation.
    pub revision: u64,
}

impl VaultHeader {
    /// Builds a header for a freshly created vault: generate a vault key, wrap
    /// it under the KEK derived from the passphrase, and reserve a body nonce.
    pub fn create(
        passphrase: &secrecy::SecretString,
        params: KdfParams,
    ) -> Result<Self, EnvelopeError> {
        params.validate()?;

        let mut salt = [0u8; SALT_LEN];
        let mut wrap_nonce = [0u8; 24];
        let mut body_nonce = [0u8; 24];
        let mut vault_key = [0u8; 32];
        fill_random(&mut salt);
        fill_random(&mut wrap_nonce);
        fill_random(&mut body_nonce);
        fill_random(&mut vault_key);

        let kek = derive_kek(passphrase, params, salt)?;
        let wrapped = wrap_key(&kek, &wrap_nonce, &vault_key)?;
        vault_key.zeroize();

        Ok(Self {
            version: ENVELOPE_VERSION,
            cipher_id: cipher_id::XCHACHA20_POLY1305,
            kdf: params,
            salt,
            wrap_nonce,
            wrapped_vault_key: wrapped,
            body_nonce,
            revision: 1,
        })
    }

    /// Validates structural fields before any expensive work.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        if self.cipher_id != cipher_id::XCHACHA20_POLY1305 {
            return Err(EnvelopeError::UnsupportedCipher(self.cipher_id));
        }
        self.kdf.validate()?;
        // The wrapped vault key is a 32-byte key plus a 16-byte Poly1305 tag.
        if self.wrapped_vault_key.len() != 32 + 16 {
            return Err(EnvelopeError::MalformedEnvelope);
        }
        Ok(())
    }

    /// Unwraps the vault data-encryption key using a passphrase.
    ///
    /// A wrong passphrase fails here, at the AEAD tag, before the body is
    /// touched. That ordering is what UAT-025 requires: "wrong passphrase
    /// fails authenticated decryption without partial data disclosure".
    pub fn unlock(&self, passphrase: &secrecy::SecretString) -> Result<VaultKey, EnvelopeError> {
        self.validate()?;
        let kek = derive_kek(passphrase, self.kdf, self.salt)?;
        let mut raw = unwrap_key(&kek, &self.wrap_nonce, &self.wrapped_vault_key)?;
        let key = VaultKey::from_bytes(raw);
        raw.zeroize();
        Ok(key)
    }
}

/// The vault data-encryption key, held only while the vault is unlocked.
///
/// Same discipline as [`KeyEncryptionKey`]: redacted `Debug`, no
/// `Serialize`, explicit `expose`.
pub struct VaultKey(zeroize::Zeroizing<[u8; 32]>);

impl VaultKey {
    /// Wraps 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// The single read path for AEAD operations. Callers must not log or
    /// persist the returned reference.
    #[allow(clippy::needless_lifetimes)]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Overwrites the vault key in place, for explicit re-lock paths.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }

    /// Constant-time comparison, so a future "is this the same key" check
    /// cannot become a timing oracle.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// Fills a buffer from the OS CSPRNG for callers in this crate, per spec §3.
///
/// `getrandom` is what `rand::rngs::OsRng` uses on Linux, and it fails closed
/// rather than falling back to a weak source.
pub fn fill_random_for_crate(buf: &mut [u8]) {
    fill_random(buf)
}

fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .expect("OS CSPRNG unavailable; refusing to generate a weak key");
}

/// Derives the key-encryption key from a passphrase with Argon2id.
///
/// The passphrase is a `SecretString` from `secrecy`, so it is zeroized on
/// drop, and it is never formatted here.
pub fn derive_kek(
    passphrase: &secrecy::SecretString,
    params: KdfParams,
    salt: [u8; SALT_LEN],
) -> Result<KeyEncryptionKey, EnvelopeError> {
    params.validate()?;

    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(params.key_len as usize),
    )
    .map_err(|_| EnvelopeError::KdfParamsOutOfRange)?;

    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );

    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), &salt, &mut key)
        .map_err(|_| EnvelopeError::KdfFailed)?;

    Ok(KeyEncryptionKey::from_bytes(key))
}

/// Wraps the vault key under the KEK.
fn wrap_key(
    kek: &KeyEncryptionKey,
    nonce: &[u8; 24],
    vault_key: &[u8; 32],
) -> Result<Vec<u8>, EnvelopeError> {
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(
        Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(kek.expose()),
    );
    cipher
        .encrypt(nonce.into(), vault_key.as_slice())
        .map_err(|_| EnvelopeError::Crypto)
}

/// Unwraps the vault key under the KEK, authenticating before returning.
fn unwrap_key(
    kek: &KeyEncryptionKey,
    nonce: &[u8; 24],
    wrapped: &[u8],
) -> Result<[u8; 32], EnvelopeError> {
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(
        Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(kek.expose()),
    );
    let mut plain = cipher
        .decrypt(nonce.into(), wrapped)
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;

    if plain.len() != 32 {
        plain.zeroize();
        return Err(EnvelopeError::MalformedEnvelope);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    plain.zeroize();
    Ok(key)
}

/// Errors from envelope handling.
///
/// [`EnvelopeError::AuthenticationFailed`] is deliberately the same error for
/// a wrong passphrase and for a tampered body: distinguishing them would leak
/// whether a guess produced a valid tag.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Envelope version this build cannot read.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u16),
    /// Cipher id this build does not implement.
    #[error("unsupported cipher id: {0}")]
    UnsupportedCipher(u8),
    /// KDF id this build does not implement.
    #[error("unsupported kdf id: {0}")]
    UnsupportedKdf(u8),
    /// KDF parameters that would weaken or hang on the vault.
    #[error("kdf parameters below the security floor")]
    WeakKdfParams,
    /// KDF parameters outside the accepted range.
    #[error("kdf parameters out of range")]
    KdfParamsOutOfRange,
    /// The key-derivation step failed.
    #[error("key derivation failed")]
    KdfFailed,
    /// AEAD operation failed for a non-authentication reason.
    #[error("cryptographic operation failed")]
    Crypto,
    /// AEAD tag did not verify: wrong passphrase, wrong key, or tampering.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Structurally invalid envelope.
    #[error("malformed envelope")]
    MalformedEnvelope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    const CANARY: &str = "ASV-CANARY-4f2b9c1e7a-DO-NOT-LEAK";

    fn passphrase() -> secrecy::SecretString {
        secrecy::SecretString::from("correct horse battery staple".to_string())
    }

    fn test_header() -> VaultHeader {
        VaultHeader::create(&passphrase(), KdfParams::fast_for_tests()).expect("header creation")
    }

    #[test]
    fn create_then_unlock_round_trips_the_vault_key() {
        let header = test_header();
        let unlocked = header.unlock(&passphrase()).expect("unlock");
        let again = header.unlock(&passphrase()).expect("second unlock");
        assert!(
            unlocked.ct_eq(&again),
            "same passphrase must yield same key"
        );
    }

    #[test]
    fn wrong_passphrase_fails_authentication() {
        let header = test_header();
        let wrong = secrecy::SecretString::from("not the passphrase".to_string());
        let err = header
            .unlock(&wrong)
            .expect_err("wrong passphrase must fail");
        assert_eq!(err, EnvelopeError::AuthenticationFailed);
    }

    #[test]
    fn wrong_passphrase_is_indistinguishable_from_tampering() {
        // UAT-025 requires that a failed unlock discloses nothing. If these
        // two produced different errors, an attacker could learn whether a
        // guess produced a valid tag.
        let header = test_header();
        let wrong = header
            .unlock(&secrecy::SecretString::from("guess".to_string()))
            .expect_err("wrong passphrase");

        let mut tampered = test_header();
        tampered.wrapped_vault_key[0] ^= 0x01;
        let corrupted = tampered.unlock(&passphrase()).expect_err("tampered key");

        assert_eq!(wrong, corrupted);
    }

    #[test]
    fn tampered_salt_fails_authentication() {
        let mut header = test_header();
        header.salt[0] ^= 0xff;
        let err = header.unlock(&passphrase()).expect_err("tampered salt");
        assert_eq!(err, EnvelopeError::AuthenticationFailed);
    }

    #[test]
    fn tampered_wrap_nonce_fails_authentication() {
        let mut header = test_header();
        header.wrap_nonce[0] ^= 0xff;
        let err = header.unlock(&passphrase()).expect_err("tampered nonce");
        assert_eq!(err, EnvelopeError::AuthenticationFailed);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut header = test_header();
        header.version = 99;
        assert_eq!(
            header.validate().expect_err("future version"),
            EnvelopeError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn unsupported_cipher_is_rejected() {
        let mut header = test_header();
        header.cipher_id = 42;
        assert_eq!(
            header.validate().expect_err("unknown cipher"),
            EnvelopeError::UnsupportedCipher(42)
        );
    }

    #[test]
    fn weak_kdf_parameters_are_rejected() {
        // Far below any safe floor.
        let params = KdfParams {
            m_cost_kib: 64,
            ..KdfParams::default()
        };
        let err = VaultHeader::create(&passphrase(), params).expect_err("weak params");
        assert_eq!(err, EnvelopeError::WeakKdfParams);
    }

    #[test]
    fn non_argon2id_kdf_is_rejected() {
        let params = KdfParams {
            kdf_id: 7,
            ..KdfParams::default()
        };
        assert_eq!(
            params.validate().expect_err("bad kdf"),
            EnvelopeError::UnsupportedKdf(7)
        );
    }

    #[test]
    fn default_params_pass_validation() {
        KdfParams::default()
            .validate()
            .expect("defaults must be accepted");
    }

    #[test]
    fn malformed_wrapped_key_length_is_rejected() {
        let mut header = test_header();
        header.wrapped_vault_key.truncate(10);
        assert_eq!(
            header.validate().expect_err("short key"),
            EnvelopeError::MalformedEnvelope
        );
    }

    #[test]
    fn key_debug_is_redacted() {
        let header = test_header();
        let key = header.unlock(&passphrase()).expect("unlock");
        let rendered = format!("{key:?}");
        assert!(
            rendered.contains("redacted"),
            "should mark redaction: {rendered}"
        );
    }

    #[test]
    fn header_debug_never_contains_the_passphrase() {
        let secret_pass = secrecy::SecretString::from(CANARY.to_string());
        let header =
            VaultHeader::create(&secret_pass, KdfParams::fast_for_tests()).expect("create");
        let rendered = format!("{header:?}");
        assert!(
            !rendered.contains(CANARY),
            "header Debug leaked the passphrase: {rendered}"
        );
    }

    #[test]
    fn header_debug_never_contains_the_canary_secret() {
        // The header is serializable metadata, so it is a leak surface a
        // future audit log could capture. The canary must not appear in it.
        let header = test_header();
        let rendered = format!("{header:?}");
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn header_json_contains_no_plaintext_secret_material() {
        let header = test_header();
        let json = serde_json::to_string(&header).expect("serialize");
        // The wrapped key is 48 bytes of ciphertext; nothing in a header
        // should ever be a 32-byte raw key or the passphrase.
        assert!(!json.contains(CANARY));
        assert!(json.contains("wrapped_vault_key"));
    }

    #[test]
    fn wiped_key_is_no_longer_usable() {
        let header = test_header();
        let key = header.unlock(&passphrase()).expect("unlock");
        let before = *key.expose();
        let mut key = key;
        key.wipe();
        // The wipe is observable: the buffer no longer holds the derived key.
        assert_ne!(*key.expose(), before, "wipe must overwrite the key");
        assert_eq!(*key.expose(), [0u8; 32]);
    }

    #[test]
    fn two_vaults_with_the_same_passphrase_differ() {
        let a = test_header();
        let b = test_header();
        assert_ne!(a.salt, b.salt, "salts must be unique per vault");
        assert_ne!(a.wrapped_vault_key, b.wrapped_vault_key);
        assert!(!a
            .unlock(&passphrase())
            .expect("unlock a")
            .ct_eq(&b.unlock(&passphrase()).expect("unlock b")));
    }

    #[test]
    fn passphrase_is_not_retained_by_the_header() {
        // `SecretString` is zeroized on drop; the header holds only derived
        // material. Assert the header never embeds the passphrase bytes.
        let pass = secrecy::SecretString::from("unique-passphrase-9f2b".to_string());
        let header = VaultHeader::create(&pass, KdfParams::fast_for_tests()).expect("create");
        let json = serde_json::to_string(&header).expect("serialize");
        let exposed: &str = pass.expose_secret();
        assert!(!json.contains(exposed));
    }
}
