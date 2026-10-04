//! Local encrypted vault for Agent Secretless Vault.
//!
//! Milestone: **M1 — Local vault + secure ingestion** (`docs/15-ROADMAP.md`).
//! Normative sources:
//!
//! - `docs/07-VAULT-CRYPTO-MEMORY.md` — key hierarchy, memory handling,
//!   ingestion, backup.
//! - `docs/14-UAT-ADVERSARIAL.md` — UAT-018 audit leak, UAT-025 vault theft,
//!   UAT-026 backup/restore.
//! - `docs/02-THREAT-MODEL.md` — what the vault does *not* defend against.
//!
//! # The property this crate exists to provide
//!
//! ASV's premise is that an agent can use a credential without ever being
//! able to read it. That makes this crate unusual in two ways, and both are
//! load-bearing:
//!
//! 1. **No retrieval API.** There is no `get_secret(id) -> &[u8]`. The only
//!    read path is [`store::VaultStore::with_secret`], which lends the
//!    plaintext to a closure and zeroizes it before returning. A getter would
//!    become a retrieval path the instant any connector wrapped it, which is
//!    precisely the failure mode ADR-0001 exists to prevent.
//!
//! 2. **No plaintext secret types.** [`store::CredentialMetadata`] is
//!    loggable; the secret is [`asv_domain::secret::SecretBytes`], which has no
//!    `Debug` derive, no `Clone` and no `Serialize`. Those absences are the
//!    mechanism, not an oversight.
//!
//! # Cryptography
//!
//! Argon2id derives the key-encryption key and XChaCha20-Poly1305 encrypts,
//! exactly as `docs/07-VAULT-CRYPTO-MEMORY.md` §3 names them. The spec says
//! "Do not invent a cipher or KDF", so nothing here does. KDF parameters live
//! in the file rather than in code, so they can be raised and migrated
//! without invalidating existing vaults.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod envelope;
pub mod ingest;
pub mod memfd;
pub mod store;
pub mod tpm;
/// A real TPM 2.0 client: the wire protocol, not a placeholder for it.
pub mod tpm2;

pub use envelope::{EnvelopeError, KdfParams, VaultHeader, VaultKey, ENVELOPE_VERSION};
pub use store::{
    CredentialKind, CredentialMetadata, CredentialRecord, Exportability, VaultBody, VaultError,
    VaultFile, VaultStore,
};

/// Version of this crate, for diagnostics and receipts.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
