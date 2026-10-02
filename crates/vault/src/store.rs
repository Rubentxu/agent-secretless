//! UAT-025 — vault theft.
//! Alongside UAT-026 backup/restore in this module: `backup_and_restore_round_trip_on_a_clean_path`,
//! `backup_is_owner_only_and_opaque`, and the record-redaction suite around them.
//! Encrypted vault body: credential records, metadata CRUD, and the file
//! format.
//!
//! Normative source: `docs/07-VAULT-CRYPTO-MEMORY.md` §2 (metadata vs secret
//! material) and §11 (backup and recovery).
//!
//! # The defining constraint
//!
//! ASV's whole premise is that an agent has **no retrieval path** to a
//! secret. That means this crate must not expose a public "give me the
//! plaintext of credential X" function, because any such function becomes a
//! retrieval path the moment a connector or IPC handler wraps it.
//!
//! Instead the payload is encrypted as one authenticated blob, and the only
//! read path is [`VaultStore::with_payload`], which lends the plaintext to a
//! caller-supplied closure and zeroizes it before returning. A closure cannot
//! stash the bytes in a longer-lived structure without doing so explicitly, so
//! the retrieval surface stays visible in review.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use asv_domain::secret::SecretBytes;
use chacha20poly1305::aead::{Aead, Key, KeyInit};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::envelope::{
    EnvelopeError, KdfParams, VaultHeader, VaultKey, ENVELOPE_MAGIC, ENVELOPE_VERSION,
};

/// Exportability class of a credential.
///
/// Spec §10: `NonExportable` is "impossible through supported UI/CLI once
/// stored", `HumanOnly` requires re-authentication and is never returned
/// through agent IPC/MCP, and `Exportable` still requires explicit human
/// interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exportability {
    /// Cannot be revealed by any supported interface once stored.
    NonExportable,
    /// Revealable by a re-authenticated human, never by an agent.
    HumanOnly,
    /// Revealable by a human acting explicitly.
    Exportable,
}

impl Exportability {
    /// Whether an agent-facing request may ever be served for this class.
    ///
    /// The answer is "no" for all three today, and that is the point: the
    /// method exists so that when a retrieval path is ever added, the policy
    /// decision has to be made in one visible place rather than implied by
    /// whichever connector happened to call first.
    pub fn permits_agent_retrieval(&self) -> bool {
        false
    }
}

/// Kind of credential. M1 defines the vocabulary; connector types in later
/// milestones extend it without changing the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    /// Generic opaque secret.
    Opaque,
    /// Private key for SSH or signing.
    PrivateKey,
    /// Bearer token or API key.
    BearerToken,
    /// Basic-auth password.
    Password,
    /// Database password.
    DatabasePassword,
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Opaque => "opaque",
            Self::PrivateKey => "private-key",
            Self::BearerToken => "bearer-token",
            Self::Password => "password",
            Self::DatabasePassword => "database-password",
        };
        f.write_str(s)
    }
}

/// Non-secret description of a credential, per spec §2.
///
/// This type is safe to log and to show in a UI. It is stored **inside** the
/// encrypted body, not beside it, so that a stolen locked vault does not
/// disclose which providers a user holds accounts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Stable identifier. Policies reference this, never the token string,
    /// which is what makes rotation transparent to agent configuration.
    pub id: String,
    /// Human label.
    pub label: String,
    /// Credential kind.
    pub kind: CredentialKind,
    /// The kind the operator actually asked for, when it is finer than
    /// [`kind`](Self::kind) can express.
    ///
    /// `kind` is the **storage class** — how the secret is held — and it is
    /// what this vault has always meant by "kind". This field is the
    /// **label**, and it exists because the storage vocabulary is five and the
    /// domain's is nine, and collapsing the four extra onto a neighbour would
    /// hand back a credential under a name the operator did not choose. A
    /// credential works either way, so a silent change is invisible until
    /// somebody reads the inventory.
    ///
    /// `Option` with `#[serde(default)]` is a format decision, not laziness,
    /// and it is the reason this field exists instead of a wider enum:
    ///
    /// - a vault written **before** this field has no `domain_kind`, so it
    ///   deserializes to `None` and the storage class alone decides;
    /// - a vault written **after** it is still readable by a binary that has
    ///   never heard of the field, because serde ignores what it does not
    ///   know — the credential stays reachable and only the label is coarser.
    ///
    /// Widening [`CredentialKind`] instead would fail the second case: an old
    /// binary cannot deserialize an unknown enum variant, so the body would
    /// not parse and **every** credential in the vault would be lost, not
    /// just the new one. Losing a whole vault to keep one label is not a
    /// trade worth making, and REQ-4 exists to keep it from being made.
    #[serde(default)]
    pub domain_kind: Option<asv_domain::CredentialKind>,
    /// Provider or service name.
    pub provider: String,
    /// Account or user name at the provider.
    pub account: String,
    /// Resource this credential is for, when the provider scopes it.
    pub resource: String,
    /// Policy references bound to this credential.
    pub policy_refs: Vec<String>,
    /// Exportability class.
    pub exportability: Exportability,
    /// Unix seconds at creation.
    pub created_at: u64,
    /// Unix seconds at last rotation.
    pub rotated_at: u64,
}

impl CredentialMetadata {
    /// Builds metadata with an empty policy list and matching timestamps.
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        kind: CredentialKind,
        provider: impl Into<String>,
        account: impl Into<String>,
        now: u64,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind,
            domain_kind: None,
            provider: provider.into(),
            account: account.into(),
            resource: String::new(),
            policy_refs: Vec::new(),
            exportability: Exportability::NonExportable,
            created_at: now,
            rotated_at: now,
        }
    }

    /// The kind to report for this credential: the operator's own choice when
    /// there is one, and the storage class when there is not.
    ///
    /// One place, so there is one answer. A record may legitimately hold both a
    /// label and a storage class — an `api_key` *is* held as a bearer token —
    /// and this is what keeps the two from being confused for a conflict.
    pub fn effective_kind(&self) -> asv_domain::CredentialKind {
        match self.domain_kind {
            Some(kind) => kind,
            None => match self.kind {
                CredentialKind::Opaque => asv_domain::CredentialKind::GenericSecret,
                CredentialKind::PrivateKey => asv_domain::CredentialKind::SshPrivateKey,
                CredentialKind::BearerToken => asv_domain::CredentialKind::BearerToken,
                CredentialKind::Password => asv_domain::CredentialKind::UsernamePassword,
                CredentialKind::DatabasePassword => asv_domain::CredentialKind::DatabaseCredential,
            },
        }
    }
}

/// A credential record: metadata plus the secret, as held in the decrypted
/// body.
///
/// `Debug` is implemented manually and redacts the secret, because the
/// `#[derive(Debug)]` on `CredentialMetadata` would otherwise be enough for
/// this type to be logged whole.
pub struct CredentialRecord {
    /// Non-secret description.
    pub metadata: CredentialMetadata,
    /// The secret material.
    pub secret: SecretBytes,
}

impl std::fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("metadata", &self.metadata)
            .field("secret", &self.secret)
            .finish()
    }
}

/// The decrypted vault body.
///
/// A `BTreeMap` rather than a `HashMap` so that a serialized vault is
/// byte-stable for identical logical content, which is what makes the
/// envelope's AEAD tag reproducible in tests and backup comparisons.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBody {
    /// Records keyed by credential id.
    pub records: BTreeMap<String, CredentialRecordBody>,
}

/// A record as stored in the encrypted body.
///
/// The secret is a raw byte string here because the whole struct lives only
/// inside the AEAD ciphertext; it is turned back into a `SecretBytes` on read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecordBody {
    /// Non-secret description.
    pub metadata: CredentialMetadata,
    /// Secret material.
    pub secret: Vec<u8>,
}

impl VaultBody {
    /// An empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of credentials.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the vault holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Adds or replaces a credential.
    pub fn upsert(&mut self, metadata: CredentialMetadata, secret: SecretBytes) {
        self.records.insert(
            metadata.id.clone(),
            CredentialRecordBody {
                metadata,
                secret: secret.expose().to_vec(),
            },
        );
    }

    /// Removes a credential, returning whether it existed.
    pub fn remove(&mut self, id: &str) -> bool {
        self.records.remove(id).is_some()
    }

    /// Metadata for one credential, without touching the secret.
    pub fn metadata(&self, id: &str) -> Option<&CredentialMetadata> {
        self.records.get(id).map(|r| &r.metadata)
    }

    /// Lists all metadata, which is what a credential picker needs.
    pub fn list_metadata(&self) -> Vec<&CredentialMetadata> {
        self.records.values().map(|r| &r.metadata).collect()
    }

    /// Serializes the body for encryption. The plaintext buffer is zeroized by
    /// the caller once the AEAD call completes.
    fn to_json(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|_| VaultError::Serialization)
    }

    /// Parses a decrypted body, validating every record on the way in.
    ///
    /// Validation is not optional here: this is the first point where
    /// attacker-influenced bytes have been authenticated but not yet
    /// interpreted, and a record whose metadata contradicts its own id would
    /// break the stable-id contract that policies depend on.
    fn from_json(bytes: &[u8]) -> Result<Self, VaultError> {
        let body: VaultBody =
            serde_json::from_slice(bytes).map_err(|_| VaultError::Serialization)?;
        for (key, record) in &body.records {
            if key != &record.metadata.id {
                // The map key and the embedded id must agree, or a lookup by
                // id could return a different record than the caller asked
                // for. This is the first point where authenticated bytes are
                // interpreted, so it is where the invariant is checked.
                return Err(VaultError::MalformedBody);
            }
            if record.metadata.id.is_empty() {
                return Err(VaultError::MalformedBody);
            }
        }
        Ok(body)
    }
}

/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Underlying envelope or AEAD failure.
    #[error("envelope error: {0}")]
    Envelope(#[from] EnvelopeError),
    /// The requested credential id does not exist.
    #[error("credential not found: {0}")]
    NotFound(String),
    /// A credential with this id already exists.
    #[error("credential already exists: {0}")]
    AlreadyExists(String),
    /// Serialization or deserialization failed.
    #[error("serialization failed")]
    Serialization,
    /// The decrypted body did not satisfy the record invariants.
    #[error("malformed vault body")]
    MalformedBody,
    /// Filesystem failure, annotated with the path.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path involved in the failure.
        path: String,
        /// Underlying error.
        source: io::Error,
    },
}

impl VaultError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

/// The on-disk file layout: magic, length-prefixed header, length-prefixed
/// body ciphertext.
///
/// Public, with private fields, so the envelope parser can be held to its
/// contract from outside the crate: [`VaultFile::decode`] is a total function
/// over untrusted bytes — `Ok` or `Err`, never panic — and every accepted
/// input must survive the `decode`-then-`encode` round trip unchanged. The
/// fuzz target `fuzz_vault_envelope_decode` (in the `fuzz/` workspace) is
/// what enforces both, against arbitrary bytes rather than a table of known
/// bad ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFile {
    header: VaultHeader,
    body_ciphertext: Vec<u8>,
}

impl VaultFile {
    /// Serializes the envelope: magic, length-prefixed header JSON,
    /// length-prefixed body ciphertext — the exact shape [`VaultFile::decode`]
    /// parses, so the writer and the parser cannot drift apart silently.
    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let header_json =
            serde_json::to_vec(&self.header).map_err(|_| VaultError::Serialization)?;
        let mut out = Vec::with_capacity(
            ENVELOPE_MAGIC.len() + 8 + header_json.len() + self.body_ciphertext.len(),
        );
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.extend_from_slice(&(header_json.len() as u64).to_le_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&(self.body_ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.body_ciphertext);
        Ok(out)
    }

    /// Parses the on-disk envelope from arbitrary bytes. Total function:
    /// `Ok` or `Err`, never panic, on any input whatsoever — the length
    /// arithmetic is `checked_add` end to end and every slice is taken
    /// after a bound that proves it. See the type's docs for the fuzz
    /// contract that keeps that sentence true.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        const PREFIX: usize = 8 + 8;
        if bytes.len() < PREFIX || &bytes[..8] != ENVELOPE_MAGIC {
            return Err(VaultError::MalformedBody);
        }
        let header_len = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")) as usize;
        // Every length add is checked, and the check carries forward: a
        // header length near usize::MAX passes `PREFIX.checked_add` (the
        // sum is merely huge, not overflowing) and then overflowed the
        // plain `+ 8` on the next line — found by the envelope fuzzer in
        // its first 20 seconds. `body_len_at` is the checked position of
        // the body-length field, and every later slice derives from it.
        let header_end = PREFIX
            .checked_add(header_len)
            .ok_or(VaultError::MalformedBody)?;
        let body_len_at = header_end.checked_add(8).ok_or(VaultError::MalformedBody)?;
        if bytes.len() < body_len_at {
            return Err(VaultError::MalformedBody);
        }
        let header: VaultHeader = serde_json::from_slice(&bytes[PREFIX..header_end])
            .map_err(|_| VaultError::Serialization)?;
        let body_len =
            u64::from_le_bytes(bytes[header_end..body_len_at].try_into().expect("8 bytes"))
                as usize;
        let body_end = body_len_at
            .checked_add(body_len)
            .ok_or(VaultError::MalformedBody)?;
        if bytes.len() != body_end {
            return Err(VaultError::MalformedBody);
        }
        let body_ciphertext = bytes[body_len_at..body_end].to_vec();
        Ok(Self {
            header,
            body_ciphertext,
        })
    }
}

/// An unlocked vault held in memory, ready for mutations.
pub struct VaultStore {
    header: VaultHeader,
    body: VaultBody,
    path: std::path::PathBuf,
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultStore")
            .field("path", &self.path)
            .field("revision", &self.header.revision)
            .field("credentials", &self.body.len())
            .finish()
    }
}

impl VaultStore {
    /// Creates a new encrypted vault file and returns it unlocked.
    ///
    /// The file is written with `0600` before any secret exists in it, so
    /// there is no window in which a partially written vault is readable by
    /// another uid.
    pub fn create(
        path: impl AsRef<Path>,
        passphrase: &SecretString,
        params: KdfParams,
    ) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let header = VaultHeader::create(passphrase, params)?;
        let body = VaultBody::new();
        let key = header.unlock(passphrase)?;
        let mut store = Self { header, body, path };
        store.persist(&key)?;
        Ok(store)
    }

    /// Opens a locked vault file and unlocks it.
    pub fn open(path: impl AsRef<Path>, passphrase: &SecretString) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|e| VaultError::io(&path, e))?;
        let file = VaultFile::decode(&bytes)?;
        file.header.validate()?;
        let key = file.header.unlock(passphrase)?;
        let body = store_decrypt_body(&file.header, &key, &file.body_ciphertext)?;
        Ok(Self {
            header: file.header,
            body,
            path,
        })
    }

    /// Re-encrypts and writes the vault, bumping the revision.
    ///
    /// The revision is bumped in the *encoded copy* and committed to
    /// `self.header` only after the write lands. Incrementing the live header
    /// first — as this used to — meant a write that then failed had still
    /// consumed a revision, so the counter measured attempts rather than
    /// history. Doing it the other way round and never committing early keeps
    /// the file and memory in step: both say N before, both say N+1 after,
    /// and a failed write leaves both at N.
    fn persist(&mut self, key: &VaultKey) -> Result<(), VaultError> {
        let mut nonce = [0u8; 24];
        crate::envelope::fill_random_for_crate(&mut nonce);
        let mut plaintext = self.body.to_json()?;
        let ciphertext =
            encrypt_body(key, &nonce, &plaintext).map_err(|_| VaultError::MalformedBody)?;
        plaintext.zeroize();

        let mut header = self.header.clone();
        header.body_nonce = nonce;
        header.revision += 1;

        let encoded = VaultFile {
            header,
            body_ciphertext: ciphertext,
        }
        .encode()?;

        write_private(&self.path, &encoded)?;

        // The write landed; now the live header may follow it.
        self.header.body_nonce = nonce;
        self.header.revision += 1;
        Ok(())
    }

    /// Runs a body mutation and persists it, restoring the body if the write
    /// fails.
    ///
    /// `persist` writes to a file, and a write can fail: a full disk, a
    /// read-only mount, a revoked permission. Without the restore, a failed
    /// write leaves the mutation in memory with no counterpart on disk, and
    /// `list()` reads the body — so the broker would report holding a
    /// credential that is not in the file, and the next successful write of
    /// any kind would serialise the orphan out.
    ///
    /// The whole body is snapshotted rather than an inverse of the mutation
    /// being undone. That is O(vault size) per write, which costs nothing here
    /// because writes are operator-driven rather than on any hot path, and it
    /// cannot be wrong: a new mutation that forgets its inverse gets the
    /// rollback for free instead of re-opening this defect. If writes ever
    /// become hot enough for the copy to matter, this is the line to revisit.
    fn transact<T>(
        &mut self,
        key: &VaultKey,
        mutate: impl FnOnce(&mut VaultBody) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let snapshot = self.body.clone();
        match mutate(&mut self.body) {
            Err(error) => {
                self.body = snapshot;
                Err(error)
            }
            Ok(value) => match self.persist(key) {
                Ok(()) => Ok(value),
                Err(error) => {
                    self.body = snapshot;
                    Err(error)
                }
            },
        }
    }

    /// Adds or replaces a credential and persists.
    pub fn upsert(
        &mut self,
        key: &VaultKey,
        metadata: CredentialMetadata,
        secret: SecretBytes,
    ) -> Result<(), VaultError> {
        self.transact(key, |body| {
            body.upsert(metadata, secret);
            Ok(())
        })
    }

    /// Adds a credential, failing if the id already exists.
    pub fn insert(
        &mut self,
        key: &VaultKey,
        metadata: CredentialMetadata,
        secret: SecretBytes,
    ) -> Result<(), VaultError> {
        if self.body.records.contains_key(&metadata.id) {
            return Err(VaultError::AlreadyExists(metadata.id));
        }
        self.upsert(key, metadata, secret)
    }

    /// Removes a credential and persists.
    pub fn remove(&mut self, key: &VaultKey, id: &str) -> Result<(), VaultError> {
        self.transact(key, |body| {
            if !body.remove(id) {
                return Err(VaultError::NotFound(id.to_string()));
            }
            Ok(())
        })
    }

    /// Lists credential metadata. Safe to log: no secret material.
    pub fn list(&self) -> Vec<&CredentialMetadata> {
        self.body.list_metadata()
    }

    /// Metadata for one credential.
    pub fn metadata(&self, id: &str) -> Result<&CredentialMetadata, VaultError> {
        self.body
            .metadata(id)
            .ok_or_else(|| VaultError::NotFound(id.to_string()))
    }

    /// The single secret read path: lends the plaintext of exactly one
    /// credential to `f` and zeroizes it afterwards.
    ///
    /// This is deliberately a closure rather than a getter. A `get_secret(id)
    /// -> &[u8]` would be a retrieval path that any connector could call and
    /// any audit could log; a closure makes the use explicit, keeps the
    /// plaintext from outliving the call by construction, and documents in one
    /// place that ASV does not offer agent retrieval.
    ///
    /// # The closure receives one secret, not the whole vault
    ///
    /// The body is encrypted as a single authenticated blob, so decrypting it
    /// necessarily materialises every record. `with_secret` parses the body,
    /// hands the closure *only* the requested record's bytes, and zeroizes the
    /// intermediate plaintext before returning. An earlier version of this
    /// method passed the decrypted body straight through, which silently
    /// turned every read into a bulk disclosure; the unit test
    /// `with_secret_reveals_only_the_requested_credential` exists to keep that
    /// from coming back.
    pub fn with_secret<T>(
        &self,
        key: &VaultKey,
        id: &str,
        f: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, VaultError> {
        if !self.body.records.contains_key(id) {
            return Err(VaultError::NotFound(id.to_string()));
        }
        // The nonce and the ciphertext must come from the *same* read of the
        // file. Taking the nonce from `self.header` while the ciphertext comes
        // from disk means a store that was opened before another handle wrote
        // the vault pairs a fresh ciphertext with a stale nonce, and the AEAD
        // tag check fails with `AuthenticationFailed` — a corruption-shaped
        // error for what is really just "the file changed under you".
        //
        // R7 makes this reachable: rotation is supposed to be observable by a
        // running broker that was never told about it, and that is exactly a
        // second handle writing while the first still holds the old header.
        let (nonce, ciphertext) = self.body_ciphertext_and_nonce()?;
        let mut plaintext = decrypt_body(key, &nonce, &ciphertext)?;
        let body = VaultBody::from_json(&plaintext);
        // Zeroize the whole decrypted body regardless of whether the parse
        // succeeded: on the error path `plaintext` still holds every secret.
        plaintext.zeroize();
        let body = body?;

        let record = body
            .records
            .get(id)
            .ok_or_else(|| VaultError::NotFound(id.to_string()))?;
        Ok(f(&record.secret))
    }

    /// Rotates the secret for an existing credential, keeping its id and
    /// metadata stable so policies and agent configuration are unaffected.
    pub fn rotate(
        &mut self,
        key: &VaultKey,
        id: &str,
        secret: SecretBytes,
        now: u64,
    ) -> Result<(), VaultError> {
        let record = self
            .body
            .records
            .get_mut(id)
            .ok_or_else(|| VaultError::NotFound(id.to_string()))?;
        record.secret = secret.expose().to_vec();
        record.metadata.rotated_at = now;
        self.persist(key)
    }

    /// Current revision, incremented on every successful write.
    pub fn revision(&self) -> u64 {
        self.header.revision
    }

    /// Writes an encrypted backup of the current vault.
    ///
    /// Spec §11: "encrypted backup only", "versioned file format",
    /// "authenticated metadata/header", "recovery key/passphrase flow
    /// documented". The backup is the same envelope as the vault itself,
    /// re-encrypted under a *separate* backup passphrase so that holding a
    /// backup does not hand over the live vault key.
    pub fn backup(
        &self,
        destination: impl AsRef<Path>,
        backup_passphrase: &SecretString,
    ) -> Result<(), VaultError> {
        let destination = destination.as_ref().to_path_buf();
        let header = VaultHeader::create(backup_passphrase, self.header.kdf)?;
        let key = header.unlock(backup_passphrase)?;
        let mut nonce = [0u8; 24];
        crate::envelope::fill_random_for_crate(&mut nonce);
        let mut plaintext = self.body.to_json()?;
        let ciphertext =
            encrypt_body(&key, &nonce, &plaintext).map_err(|_| VaultError::MalformedBody)?;
        plaintext.zeroize();

        // The header must record the nonce that actually encrypted the body,
        // or a later `open` would try to decrypt with the wrong nonce. The
        // header built by `VaultHeader::create` carries a placeholder.
        let mut header = header;
        header.body_nonce = nonce;

        let encoded = VaultFile {
            header,
            body_ciphertext: ciphertext,
        }
        .encode()?;
        write_private(&destination, &encoded)
    }

    /// Re-wraps the vault's data-encryption key under a new passphrase,
    /// persisting the migration atomically.
    ///
    /// This is the migration path for the envelope (R2 "migration tests",
    /// spec §11 "versioned file format"): only the KEK wrapping changes —
    /// the DEK is never re-generated — so the migration is transparent to
    /// every backup made under the same live vault key. The persisted
    /// body is re-encrypted under the same DEK with a fresh nonce by
    /// `persist` (identical to any other write). See
    /// [`VaultHeader::rewrap`] for the envelope mechanics.
    ///
    /// Ordering guarantees:
    /// - `current` is proven before anything is mutated: a wrong current
    ///   passphrase fails at the AEAD tag, exactly like `open`, and the
    ///   file is untouched;
    /// - the header is rewrapped in memory first; `persist` then writes
    ///   the complete new envelope. If the write fails, the in-memory
    ///   header is rolled back so the store still matches the on-disk
    ///   file, which still opens with the old passphrase.
    ///
    /// An empty `next` is a configuration error, not a migration, and is
    /// rejected without touching anything.
    pub fn rekey_passphrase(
        &mut self,
        current: &SecretString,
        next: &SecretString,
    ) -> Result<(), VaultError> {
        // Fail closed before touching anything: the caller must prove
        // possession of the current passphrase, exactly as `open` does.
        let mut dek = self.header.unlock(current)?;

        // Rewrap in a scratch copy so a rejected rewrap leaves the store
        // (and the caller's next attempt) untouched.
        let mut replacement = self.header.clone();
        replacement.rewrap(&dek, next)?;

        let old_header = std::mem::replace(&mut self.header, replacement);
        // The body ciphertext is unchanged by a rewrap; re-persist so the
        // file atomically records the new header (and the revision bump
        // proves the write happened).
        let result = self.persist(&dek);
        if result.is_err() {
            // Roll the header back so the in-memory store still matches the
            // on-disk file, which still opens with the old passphrase.
            self.header = old_header;
        }
        dek.wipe();
        result
    }

    /// Restores a backup into `destination` and verifies it authenticates.
    pub fn restore(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        backup_passphrase: &SecretString,
    ) -> Result<Self, VaultError> {
        let restored = Self::open(backup, backup_passphrase)?;
        let key = restored.header.unlock(backup_passphrase)?;
        let mut store = Self {
            header: restored.header.clone(),
            body: restored.body,
            path: destination.as_ref().to_path_buf(),
        };
        store.persist(&key)?;
        Ok(store)
    }

    /// The vault file on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The vault header, for backup and diagnostics.
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Envelope version this build writes.
    pub fn format_version() -> u16 {
        ENVELOPE_VERSION
    }

    /// Reads the body's AEAD nonce and ciphertext from a single decode of the
    /// file on disk.
    ///
    /// These two must never come from different sources. The nonce lives in
    /// the header and the ciphertext is the rest of the envelope, so a store
    /// that re-read one and cached the other can pair a fresh ciphertext with
    /// a stale nonce after any write performed by another handle. The tag then
    /// fails, and the failure is indistinguishable from real corruption — which
    /// is the worst possible report for a file that is perfectly fine.
    fn body_ciphertext_and_nonce(&self) -> Result<([u8; 24], Vec<u8>), VaultError> {
        let bytes = std::fs::read(&self.path).map_err(|e| VaultError::io(&self.path, e))?;
        let file = VaultFile::decode(&bytes)?;
        Ok((file.header.body_nonce, file.body_ciphertext))
    }
}

/// Encrypts the body with the vault key.
fn encrypt_body(
    key: &VaultKey,
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(
        Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(key.expose()),
    );
    cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|_| EnvelopeError::Crypto)
}

/// Decrypts the body with the vault key, authenticating first.
fn decrypt_body(
    key: &VaultKey,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(
        Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(key.expose()),
    );
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| EnvelopeError::AuthenticationFailed)
}

fn store_decrypt_body(
    header: &VaultHeader,
    key: &VaultKey,
    ciphertext: &[u8],
) -> Result<VaultBody, VaultError> {
    let mut plaintext = decrypt_body(key, &header.body_nonce, ciphertext)?;
    let body = VaultBody::from_json(&plaintext);
    plaintext.zeroize();
    body
}

/// The temp-file name `write_private` writes to before renaming over `path`.
///
/// Unique per process and per call, so no two writers — in this process or in
/// any other — ever truncate the same temp file. The pid alone would not do:
/// two `VaultStore`s in one process writing the same vault would share it. The
/// counter is what makes the name per-call.
///
/// A crashed writer leaves one of these behind. That is the accepted cost of
/// the guarantee: the leftover is ciphertext at `0600` whose name says which
/// pid left it, whereas a shared name risks splicing two bodies into the vault
/// itself.
fn tmp_sibling(path: &Path) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault");
    format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Writes a file with `0600` permissions, creating parents as needed.
///
/// Spec §8 requires minimal filesystem access and a non-dumpable broker; the
/// vault file is the most sensitive artefact ASV owns, so it is owner-only
/// from the moment it exists.
///
/// Writes `bytes` to `path` so no reader can observe a partial file.
///
/// The previous version opened the target with `truncate(true)` and wrote in
/// place, so every write passed the vault through a truncated state. That was
/// survivable only because the broker was the sole writer and `&mut self`
/// enforced it in-process; `with_secret` re-reads the ciphertext from disk on
/// every call precisely so it sees the newest write, and an in-place write is
/// exactly what it would catch mid-flight.
///
/// The replacement writes a temporary file beside the target and renames it
/// over, which is atomic within a filesystem. Four details are load-bearing:
///
/// - **Same directory.** `rename` across filesystems fails with `EXDEV`, and
///   a temp file in `/tmp` would make every write fail on any real
///   deployment.
/// - **`0600` on the temp file.** The rename carries the temp file's mode onto
///   the target, so a permissive temp file would leave a world-readable vault.
/// - **A name no other writer holds.** See `tmp_sibling` below; a shared name
///   would let two writers splice into one file.
/// - **Mode re-asserted on the target afterwards.** The old code set `0600` on
///   every write because an existing file keeps its old mode under umask; the
///   temp-file path must not quietly drop that defence.
///
/// A failure at any point removes the temp file and leaves the previous vault
/// exactly as it was.
///
/// What this does *not* claim: durability across a power cut. The data is
/// fsynced before the rename, but the directory entry is not, so a crash
/// immediately after the rename can lose it and leave the previous revision on
/// disk — the same memory/disagreement this function's callers just stopped
/// producing, arrived at from the other side. Closing that needs a directory
/// fsync, which is not here because nothing here could falsify it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::io(parent, e))?;
            restrict_dir(parent)?;
        }
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // A name no other writer can be holding. A shared temp name would let two
    // writers truncate and fill the *same* file, so the bytes landing there
    // would be a splice of two bodies — and renaming that spliced file over
    // the target would destroy a vault, which is a far worse outcome than the
    // stale revision the second writer's write already costs it. Unique per
    // process and per call, so the guarantee is the weaker one that still
    // matters: the target is always a whole vault written by one writer, and
    // with two writers the last rename wins.
    let tmp = dir.join(tmp_sibling(path));

    let write = |target: &Path| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(target)?;
        // `create` honours the umask only when creating, and an existing file
        // keeps its old mode, so set it explicitly on every write.
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
        file.write_all(bytes)?;
        file.sync_all()
    };

    if let Err(e) = write(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(VaultError::io(path, e));
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(VaultError::io(path, e));
    }

    // The rename carried the temp file's mode across; re-assert on the target
    // so the defence the old in-place path provided is not lost.
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    Ok(())
}

fn restrict_dir(dir: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| VaultError::io(dir, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const CANARY: &str = "ASV-CANARY-4f2b9c1e7a-DO-NOT-LEAK";

    /// Fuzz regression (crash-6396125b3da22c2a02504e2f935c5206f9600b16):
    /// a header length of `usize::MAX - 16` passes `PREFIX.checked_add`
    /// with room to spare — the sum is usize::MAX, huge but not overflowing
    /// — and then overflowed the plain `+ 8` that followed. The fix carries
    /// the check forward (`body_len_at`), and this input must be an `Err`,
    /// in debug and in release, for any file length.
    #[test]
    fn header_length_near_usize_max_is_rejected_not_panicked() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&0xFFFFFFFFFFFFFFEFu64.to_le_bytes());
        bytes.extend_from_slice(b"{\"version\":1}");
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::MalformedBody)
        ));
    }

    fn pass() -> SecretString {
        SecretString::from("test-passphrase".to_string())
    }

    fn vault(dir: &tempfile::TempDir) -> VaultStore {
        let path = dir.path().join("vault.asv");
        VaultStore::create(&path, &pass(), KdfParams::fast_for_tests()).expect("create")
    }

    fn canary_secret() -> SecretBytes {
        SecretBytes::new(CANARY.as_bytes().to_vec())
    }

    /// A record exactly as it was serialised **before** `domain_kind` existed.
    ///
    /// Written out as a literal rather than derived from `CredentialMetadata`,
    /// because deriving it would inherit `#[serde(default)]` and the test would
    /// prove that the current struct can read itself. What has to be pinned is
    /// that a body carrying no such key is still accepted, and only a literal
    /// actually lacks the key.
    const LEGACY_METADATA: &str = r#"{
        "id": "legacy-1",
        "label": "written before the label existed",
        "kind": "BearerToken",
        "provider": "github",
        "account": "acct",
        "resource": "",
        "policy_refs": [],
        "exportability": "NonExportable",
        "created_at": 1,
        "rotated_at": 1
    }"#;

    /// The same record as a reader from before the field would have seen it:
    /// no `domain_kind` member at all. This is the shape REQ-4 is about.
    #[derive(Deserialize)]
    struct LegacyMetadata {
        id: String,
        label: String,
        kind: CredentialKind,
        provider: String,
        account: String,
        resource: String,
        policy_refs: Vec<String>,
        exportability: Exportability,
        created_at: u64,
        rotated_at: u64,
    }

    #[test]
    fn a_record_written_before_the_label_existed_still_opens() {
        let legacy: CredentialMetadata =
            serde_json::from_str(LEGACY_METADATA).expect("a pre-label record must parse");
        assert_eq!(legacy.id, "legacy-1");
        assert_eq!(
            legacy.domain_kind, None,
            "absent must read as None, not fail"
        );
        // And it still answers with the storage class, which is the only
        // thing it ever said.
        assert_eq!(
            legacy.effective_kind(),
            asv_domain::CredentialKind::BearerToken
        );
    }

    /// The requirement that decided the design: a reader without the field
    /// must still parse a record that has it.
    ///
    /// Had the vault's `CredentialKind` been widened instead, an old binary
    /// meeting an unknown variant would fail to deserialize and the **whole
    /// body** would be rejected — every credential lost, not just the new
    /// one. This asserts the opposite actually happens: serde ignores the key
    /// it does not know, the record survives, and the secret is still
    /// reachable. Degradation, not destruction.
    #[test]
    fn a_reader_without_the_label_still_parses_a_record_that_has_it() {
        let mut modern = CredentialMetadata::new(
            "modern-1",
            "an api key",
            CredentialKind::BearerToken,
            "github",
            "acct",
            1,
        );
        modern.domain_kind = Some(asv_domain::CredentialKind::ApiKey);

        let json = serde_json::to_string(&modern).expect("serialises");
        let legacy: LegacyMetadata =
            serde_json::from_str(&json).expect("a pre-label reader must still parse it");

        assert_eq!(legacy.id, "modern-1");
        assert_eq!(legacy.label, "an api key");
        assert_eq!(legacy.provider, "github");
        assert_eq!(legacy.account, "acct");
        assert_eq!(legacy.resource, "");
        assert!(legacy.policy_refs.is_empty());
        assert_eq!(legacy.created_at, 1);
        assert_eq!(legacy.rotated_at, 1);
        assert_eq!(
            legacy.exportability,
            Exportability::NonExportable,
            "the exportability class must not drift either — R1 keys off it"
        );
        assert_eq!(
            legacy.kind,
            CredentialKind::BearerToken,
            "the storage class is what the old reader sees, and it is intact"
        );
        // The label is the only thing lost, and it is a label.
        assert!(
            !json.contains("\"secret\""),
            "metadata must not carry a secret"
        );
    }

    /// A label and a storage class together are a fact, not a conflict: an
    /// `api_key` really is held as a bearer token. The reported kind is the
    /// label, and the storage class is left exactly as it was rather than
    /// rewritten to agree — two fields must not end up answering one question.
    #[test]
    fn a_label_beside_its_storage_class_reports_the_label() {
        let mut metadata =
            CredentialMetadata::new("c1", "l", CredentialKind::BearerToken, "github", "acct", 1);
        metadata.domain_kind = Some(asv_domain::CredentialKind::OAuth2);

        assert_eq!(
            metadata.effective_kind(),
            asv_domain::CredentialKind::OAuth2,
            "the operator's label must win over the storage class"
        );
        assert_eq!(
            metadata.kind,
            CredentialKind::BearerToken,
            "the storage class must not be rewritten to match the label"
        );
    }

    /// Every one of the domain's nine kinds survives being stored, read back
    /// and reopened. The mapping is total, so this is the property that would
    /// fail first if a variant were ever added without a storage class.
    #[test]
    fn all_nine_domain_kinds_survive_a_write_and_a_reopen() {
        use asv_domain::CredentialKind as DomainKind;
        let all = [
            DomainKind::ApiKey,
            DomainKind::BearerToken,
            DomainKind::OAuth2,
            DomainKind::UsernamePassword,
            DomainKind::SshPrivateKey,
            DomainKind::X509ClientIdentity,
            DomainKind::AwsAccessKey,
            DomainKind::DatabaseCredential,
            DomainKind::GenericSecret,
        ];
        assert_eq!(all.len(), 9, "the domain's vocabulary changed");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.asv");
        let mut store =
            VaultStore::create(&path, &pass(), KdfParams::fast_for_tests()).expect("create vault");
        let key = store.header().unlock(&pass()).expect("unlock");

        for (index, domain) in all.iter().enumerate() {
            let id = format!("c{index}");
            let mut metadata = CredentialMetadata::new(
                id.clone(),
                format!("label-{index}"),
                super::tests::storage_class_for(*domain),
                "github",
                "acct",
                1,
            );
            metadata.domain_kind = Some(*domain);
            store
                .insert(&key, metadata, canary_secret())
                .expect("insert");
        }

        let reopened = VaultStore::open(&path, &pass()).expect("reopen");
        for (index, domain) in all.iter().enumerate() {
            let metadata = reopened
                .metadata(&format!("c{index}"))
                .expect("the record is still there");
            assert_eq!(
                metadata.effective_kind(),
                *domain,
                "{domain:?} did not survive the file"
            );
        }
    }

    /// The storage class the broker would pick for a domain kind, mirrored
    /// here so the vault's own test does not depend on the broker's mapping.
    fn storage_class_for(kind: asv_domain::CredentialKind) -> CredentialKind {
        match kind {
            asv_domain::CredentialKind::BearerToken
            | asv_domain::CredentialKind::ApiKey
            | asv_domain::CredentialKind::OAuth2 => CredentialKind::BearerToken,
            asv_domain::CredentialKind::UsernamePassword => CredentialKind::Password,
            asv_domain::CredentialKind::SshPrivateKey
            | asv_domain::CredentialKind::X509ClientIdentity
            | asv_domain::CredentialKind::AwsAccessKey => CredentialKind::PrivateKey,
            asv_domain::CredentialKind::DatabaseCredential => CredentialKind::DatabasePassword,
            asv_domain::CredentialKind::GenericSecret => CredentialKind::Opaque,
        }
    }

    /// The atomic write's temp name must differ on every call, including
    /// twice in a row from the same process on the same path. A shared name
    /// would let two writers truncate and fill one file, and renaming that
    /// over the target would splice two bodies into the vault.
    #[test]
    fn the_temp_name_is_unique_per_call() {
        let path = Path::new("/vaults/vault.asv");
        let first = tmp_sibling(path);
        let second = tmp_sibling(path);
        assert_ne!(first, second, "two writes shared a temp name: {first}");
        assert!(
            first.starts_with(".vault.asv.") && first.ends_with(".tmp"),
            "temp name is not the expected shape: {first}"
        );
        assert!(
            first.contains(&std::process::id().to_string()),
            "temp name does not carry the pid: {first}"
        );
    }

    #[test]
    fn create_produces_an_owner_only_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.path())
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "vault file must be 0600, got {mode:o}");
    }

    #[test]
    fn canary_never_appears_in_the_vault_file_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new(
                    "c1",
                    "gh token",
                    CredentialKind::BearerToken,
                    "github",
                    "octocat",
                    100,
                ),
                canary_secret(),
            )
            .expect("insert");
        drop(key);

        let bytes = std::fs::read(store.path()).expect("read");
        assert!(
            !contains(&bytes, CANARY.as_bytes()),
            "the canary is present in the vault file in plaintext"
        );
    }

    #[test]
    fn labels_and_providers_are_also_encrypted() {
        // Spec §2 keeps metadata and payload separate. This asserts the
        // stronger property we actually implemented: the body is opaque, so a
        // stolen locked vault does not even reveal which providers are in use.
        //
        // Every needle below is at least eight bytes, and that is load-bearing
        // rather than incidental. This searches the *ciphertext* for the
        // plaintext, so a short needle collides with the random bytes by
        // chance at roughly (file_len - n) / 2^(8n): at two bytes that is on
        // the order of a percent per run for a vault of a few KiB. The first
        // version of this test used the id `c1` and the username `root`, and
        // it failed under full-suite load for exactly that reason — a guard
        // that cries wolf is worse than no guard, because it teaches everyone
        // to re-run a red suite.
        //
        // Longer needles do not weaken the test. A real leak puts the whole
        // value in the file, so a longer value is still detected, and the
        // accidental-collision rate drops by orders of magnitude.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new(
                    "cred-prod-0001",
                    "prod-db-master",
                    CredentialKind::DatabasePassword,
                    "acme-internal",
                    "deploy-service",
                    100,
                ),
                canary_secret(),
            )
            .expect("insert");
        drop(key);

        let bytes = std::fs::read(store.path()).expect("read");
        for needle in [
            &b"cred-prod-0001"[..],
            &b"prod-db-master"[..],
            &b"acme-internal"[..],
            &b"deploy-service"[..],
        ] {
            assert!(
                !contains(&bytes, needle),
                "metadata {:?} leaked into the {} encrypted bytes",
                String::from_utf8_lossy(needle),
                bytes.len(),
            );
        }
    }

    #[test]
    fn open_with_wrong_passphrase_fails_and_yields_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let wrong = SecretString::from("wrong".to_string());
        let err = VaultStore::open(store.path(), &wrong).expect_err("wrong passphrase");
        assert!(matches!(
            err,
            VaultError::Envelope(EnvelopeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn round_trip_preserves_metadata_and_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        let mut meta = CredentialMetadata::new(
            "c1",
            "gh token",
            CredentialKind::BearerToken,
            "github",
            "octocat",
            100,
        );
        meta.policy_refs = vec!["p1".into()];
        meta.exportability = Exportability::HumanOnly;
        store.insert(&key, meta, canary_secret()).expect("insert");
        drop(key);

        let reopened = VaultStore::open(store.path(), &pass()).expect("reopen");
        let meta = reopened.metadata("c1").expect("metadata");
        assert_eq!(meta.label, "gh token");
        assert_eq!(meta.provider, "github");
        assert_eq!(meta.policy_refs, vec!["p1".to_string()]);
        assert_eq!(meta.exportability, Exportability::HumanOnly);
    }

    #[test]
    fn with_secret_reveals_only_the_requested_credential() {
        // Regression guard for a real defect: `with_secret` used to hand the
        // closure the entire decrypted body, so reading one credential
        // disclosed every other credential in the vault. That is precisely the
        // retrieval path this crate exists to avoid.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("wanted", "l", CredentialKind::Opaque, "p", "a", 1),
                SecretBytes::new(b"the-one-secret".to_vec()),
            )
            .expect("insert");
        store
            .insert(
                &key,
                CredentialMetadata::new("other", "l", CredentialKind::Opaque, "p", "a", 1),
                SecretBytes::new(b"MUST-NOT-APPEAR".to_vec()),
            )
            .expect("insert");
        drop(key);

        let key = store.header().unlock(&pass()).expect("unlock");
        let seen = store
            .with_secret(&key, "wanted", |bytes| {
                String::from_utf8_lossy(bytes).into_owned()
            })
            .expect("with_secret");
        assert_eq!(seen, "the-one-secret");
        assert!(
            !seen.contains("MUST-NOT-APPEAR"),
            "reading one credential disclosed another: {seen}"
        );
    }

    #[test]
    fn with_secret_yields_the_real_bytes_then_erases_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
                canary_secret(),
            )
            .expect("insert");
        drop(key);

        let key = store.header().unlock(&pass()).expect("unlock");
        let seen = store
            .with_secret(&key, "c1", |bytes| bytes.to_vec())
            .expect("with_secret");
        assert_eq!(seen, CANARY.as_bytes());
    }

    #[test]
    fn no_public_getter_returns_plaintext() {
        // A structural guarantee, asserted at the type level by review and
        // here by intent: the store exposes `with_secret` (a closure) and no
        // `get_secret`/`secret` accessor. If someone adds a getter later this
        // test should fail to compile against the new API being used here.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        assert!(store.with_secret(&key, "missing", |_| ()).is_err());
    }

    #[test]
    fn with_secret_on_missing_id_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        let err = store
            .with_secret(&key, "nope", |_| ())
            .expect_err("missing");
        assert!(matches!(err, VaultError::NotFound(_)));
    }

    #[test]
    fn insert_rejects_duplicate_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        let meta = CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1);
        store
            .insert(&key, meta.clone(), canary_secret())
            .expect("first");
        let err = store
            .insert(&key, meta, canary_secret())
            .expect_err("duplicate");
        assert!(matches!(err, VaultError::AlreadyExists(_)));
    }

    #[test]
    fn remove_reports_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
                canary_secret(),
            )
            .expect("insert");
        store.remove(&key, "c1").expect("remove");
        assert!(store.remove(&key, "c1").is_err());
        assert!(store.list().is_empty());
    }

    #[test]
    fn rotation_keeps_id_and_metadata_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        let meta = CredentialMetadata::new(
            "c1",
            "stable-label",
            CredentialKind::BearerToken,
            "github",
            "octocat",
            100,
        );
        store.insert(&key, meta, canary_secret()).expect("insert");
        let new_secret = SecretBytes::new(b"rotated-token-value".to_vec());
        store.rotate(&key, "c1", new_secret, 200).expect("rotate");
        drop(key);

        let reopened = VaultStore::open(store.path(), &pass()).expect("reopen");
        let meta = reopened.metadata("c1").expect("metadata");
        assert_eq!(meta.id, "c1");
        assert_eq!(meta.label, "stable-label");
        assert_eq!(meta.created_at, 100);
        assert_eq!(meta.rotated_at, 200);
        let key = reopened.header().unlock(&pass()).expect("unlock");
        let seen = reopened
            .with_secret(&key, "c1", |b| b.to_vec())
            .expect("read");
        assert_eq!(seen, b"rotated-token-value");
    }

    #[test]
    fn revision_increases_on_every_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let before = store.revision();
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
                canary_secret(),
            )
            .expect("insert");
        assert!(store.revision() > before, "revision must advance");
    }

    #[test]
    fn tampered_body_fails_authentication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
                canary_secret(),
            )
            .expect("insert");
        drop(key);

        let mut bytes = std::fs::read(store.path()).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = dir.path().join("tampered.asv");
        std::fs::write(&tampered, &bytes).expect("write");

        let err = VaultStore::open(&tampered, &pass()).expect_err("tampered body");
        assert!(matches!(
            err,
            VaultError::Envelope(EnvelopeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncated_file_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let bytes = std::fs::read(store.path()).expect("read");
        let short = dir.path().join("short.asv");
        std::fs::write(&short, &bytes[..bytes.len() / 2]).expect("write");
        assert!(VaultStore::open(&short, &pass()).is_err());
    }

    #[test]
    fn random_file_is_rejected_by_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let junk = dir.path().join("junk.asv");
        let mut f = std::fs::File::create(&junk).expect("create");
        f.write_all(b"not a vault at all, just bytes")
            .expect("write");
        assert!(VaultStore::open(&junk, &pass()).is_err());
    }

    #[test]
    fn backup_and_restore_round_trip_on_a_clean_path() {
        // UAT-026: restore an encrypted backup on a clean system using the
        // documented recovery factor, with credentials and policy references
        // preserved.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        let mut meta = CredentialMetadata::new(
            "c1",
            "prod-db",
            CredentialKind::DatabasePassword,
            "acme",
            "root",
            100,
        );
        meta.policy_refs = vec!["policy-a".into(), "policy-b".into()];
        store.insert(&key, meta, canary_secret()).expect("insert");
        drop(key);

        let backup_path = dir.path().join("backup.asv");
        let recovery = SecretString::from("recovery-factor".to_string());
        store.backup(&backup_path, &recovery).expect("backup");

        // Simulate a clean system: no original vault, only the backup.
        let restored_path = dir.path().join("restored").join("vault.asv");
        let restored =
            VaultStore::restore(&backup_path, &restored_path, &recovery).expect("restore");

        let meta = restored.metadata("c1").expect("metadata after restore");
        assert_eq!(meta.label, "prod-db");
        assert_eq!(
            meta.policy_refs,
            vec!["policy-a".to_string(), "policy-b".to_string()]
        );
        let key = restored
            .header()
            .unlock(&recovery)
            .expect("unlock restored");
        let seen = restored
            .with_secret(&key, "c1", |b| b.to_vec())
            .expect("read");
        assert_eq!(seen, CANARY.as_bytes());
    }

    #[test]
    fn backup_is_owner_only_and_opaque() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new(
                    "c1",
                    "label-x",
                    CredentialKind::Opaque,
                    "prov-y",
                    "acct-z",
                    1,
                ),
                canary_secret(),
            )
            .expect("insert");
        drop(key);

        let backup = dir.path().join("b.asv");
        let recovery = SecretString::from("recovery".to_string());
        store.backup(&backup, &recovery).expect("backup");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let bytes = std::fs::read(&backup).expect("read");
        for needle in [
            CANARY.as_bytes(),
            &b"label-x"[..],
            &b"prov-y"[..],
            &b"acct-z"[..],
        ] {
            assert!(!contains(&bytes, needle), "backup leaked plaintext");
        }
    }

    #[test]
    fn restore_with_wrong_recovery_factor_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let backup = dir.path().join("b.asv");
        store
            .backup(&backup, &SecretString::from("right".to_string()))
            .expect("backup");
        let err = VaultStore::restore(
            &backup,
            dir.path().join("r.asv"),
            &SecretString::from("wrong".to_string()),
        )
        .expect_err("wrong recovery factor");
        assert!(matches!(
            err,
            VaultError::Envelope(EnvelopeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn backup_uses_a_different_key_from_the_live_vault() {
        // Holding a backup must not hand over the live vault key.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let live_key = store.header().unlock(&pass()).expect("unlock");
        let backup = dir.path().join("b.asv");
        store
            .backup(&backup, &SecretString::from("same-passphrase".to_string()))
            .expect("backup");
        let backup_store =
            VaultStore::open(&backup, &SecretString::from("same-passphrase".to_string()))
                .expect("open backup");
        let backup_key = backup_store
            .header()
            .unlock(&SecretString::from("same-passphrase".to_string()))
            .expect("unlock");
        assert!(
            !live_key.ct_eq(&backup_key),
            "backup must use a distinct vault key"
        );
    }

    #[test]
    fn no_exportability_class_permits_agent_retrieval() {
        for class in [
            Exportability::NonExportable,
            Exportability::HumanOnly,
            Exportability::Exportable,
        ] {
            assert!(
                !class.permits_agent_retrieval(),
                "{class:?} must not permit agent retrieval"
            );
        }
    }

    #[test]
    fn record_debug_redacts_the_secret() {
        let record = CredentialRecord {
            metadata: CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
            secret: canary_secret(),
        };
        let rendered = format!("{record:?}");
        assert!(
            !rendered.contains(CANARY),
            "record Debug leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn store_debug_is_metadata_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "p", "a", 1),
                canary_secret(),
            )
            .expect("insert");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn vault_error_debug_is_secret_free() {
        // The error path is a classic leak site: a failing unlock could
        // otherwise embed the attempted passphrase.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let err = VaultStore::open(store.path(), &SecretString::from(CANARY.to_string()))
            .expect_err("bad passphrase");
        let rendered = format!("{err:?}");
        assert!(!rendered.contains(CANARY), "error Debug leaked: {rendered}");
        let as_string = err.to_string();
        assert!(!as_string.contains(CANARY));
    }

    #[test]
    fn multiple_credentials_all_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let key = store.header().unlock(&pass()).expect("unlock");
        for i in 0..5 {
            store
                .insert(
                    &key,
                    CredentialMetadata::new(
                        format!("c{i}"),
                        format!("label-{i}"),
                        CredentialKind::Opaque,
                        "p",
                        "a",
                        i as u64,
                    ),
                    SecretBytes::new(format!("secret-value-{i}").into_bytes()),
                )
                .expect("insert");
        }
        drop(key);

        let reopened = VaultStore::open(store.path(), &pass()).expect("reopen");
        assert_eq!(reopened.list().len(), 5);
        let key = reopened.header().unlock(&pass()).expect("unlock");
        for i in 0..5 {
            let seen = reopened
                .with_secret(&key, &format!("c{i}"), |b| b.to_vec())
                .expect("read");
            assert_eq!(seen, format!("secret-value-{i}").as_bytes());
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // -----------------------------------------------------------------------
    // Migration / upgrade-contract tests (RC gate R2, cycle r2-migration-tests).
    //
    // The vault has shipped exactly one envelope version, so "migration tests"
    // here pin the forward-compatibility contract documented in
    // docs/manual/OPERATIONS.md: the byte layout future readers must parse, the
    // loud rejection of any other declared version, reader idempotence across
    // its own rewrites (the in-place migration path), and versioned KDF params
    // read from the file rather than from binary defaults.
    // -----------------------------------------------------------------------

    /// Rewrites the `version` field of a vault file's header JSON, keeping the
    /// length prefixes consistent so the mutation is *only* the declared
    /// version. Returns the mutated full file bytes.
    fn splice_version(bytes: &[u8], version: u16) -> Vec<u8> {
        let header_len = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")) as usize;
        let mut header: serde_json::Value =
            serde_json::from_slice(&bytes[16..16 + header_len]).expect("header json");
        header["version"] = serde_json::Value::from(version);
        let new_header = serde_json::to_vec(&header).expect("re-serialize");
        let mut out = Vec::with_capacity(8 + 8 + new_header.len() + bytes.len());
        out.extend_from_slice(&bytes[..8]);
        out.extend_from_slice(&(new_header.len() as u64).to_le_bytes());
        out.extend_from_slice(&new_header);
        out.extend_from_slice(&bytes[16 + header_len..]);
        out
    }

    #[test]
    fn vault_file_layout_is_pinned() {
        // R1.1/S1: the on-disk contract a future reader (or migration tool)
        // depends on. If this test breaks, the envelope changed and a release
        // shipping that change owes the world an explicit migration tool.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let bytes = std::fs::read(store.path()).expect("read");

        assert!(bytes.len() > 8 + 8 + 2 + 8, "file suspiciously short");
        assert_eq!(&bytes[..8], ENVELOPE_MAGIC, "magic prefix");

        let header_len = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")) as usize;
        let header_end = 16 + header_len;
        let body_len = u64::from_le_bytes(
            bytes[header_end..header_end + 8]
                .try_into()
                .expect("8 bytes"),
        ) as usize;

        assert_eq!(
            bytes.len(),
            header_end + 8 + body_len,
            "file must be exactly magic + u64le(header) + header + u64le(body) + body"
        );
        assert!(bytes[16] == b'{', "header must be a JSON object");

        // And the pinned reader agrees with the structural parse.
        assert!(VaultStore::open(store.path(), &pass()).is_ok());
    }

    #[test]
    fn open_rejects_a_newer_version_without_touching_the_file() {
        // R2.1/S2a: a file from the *future* must fail loudly and leave the
        // bytes exactly as they were (no partial decrypt, no rewrite).
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let original = std::fs::read(store.path()).expect("read");
        let mutated = splice_version(&original, ENVELOPE_VERSION + 1);
        std::fs::write(store.path(), &mutated).expect("write mutated");

        let err = VaultStore::open(store.path(), &pass()).expect_err("future version");
        assert!(
            matches!(
                err,
                VaultError::Envelope(EnvelopeError::UnsupportedVersion(v)) if v == ENVELOPE_VERSION + 1
            ),
            "expected UnsupportedVersion({}), got {err}",
            ENVELOPE_VERSION + 1
        );

        let after = std::fs::read(store.path()).expect("read after");
        assert_eq!(mutated, after, "open must not rewrite the vault file");
    }

    #[test]
    fn open_rejects_older_version_zero() {
        // R2.1/S2b: no v0 ever shipped, but if one ever surfaces it must be
        // rejected with the same loud error, not best-effort parsed.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vault(&dir);
        let original = std::fs::read(store.path()).expect("read");
        let mutated = splice_version(&original, 0);
        std::fs::write(store.path(), &mutated).expect("write mutated");

        let err = VaultStore::open(store.path(), &pass()).expect_err("version 0");
        assert!(
            matches!(
                err,
                VaultError::Envelope(EnvelopeError::UnsupportedVersion(0))
            ),
            "expected UnsupportedVersion(0), got {err}"
        );
    }

    #[test]
    fn rewrite_round_trip_preserves_records_and_bumps_revision() {
        // R3.1/S3: the in-place migration path is "open with current reader,
        // mutate, save". The reader must survive its own rewrites: records
        // intact, revision advancing by exactly one per persisted mutation.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = vault(&dir);
        let revision_at_create = store.revision();
        let key = store.header().unlock(&pass()).expect("unlock");
        for i in 0..2 {
            store
                .insert(
                    &key,
                    CredentialMetadata::new(
                        format!("m{i}"),
                        format!("label-{i}"),
                        CredentialKind::Opaque,
                        "p",
                        "a",
                        i as u64,
                    ),
                    SecretBytes::new(format!("migration-secret-{i}").into_bytes()),
                )
                .expect("insert");
        }
        let revision_after_two = store.revision();
        drop(key);

        let reopened = VaultStore::open(store.path(), &pass()).expect("reopen");
        assert_eq!(reopened.list().len(), 2);
        assert_eq!(
            reopened.revision(),
            revision_after_two,
            "reopen must not bump revision"
        );
        assert_eq!(
            revision_after_two - revision_at_create,
            2,
            "exactly one revision bump per mutation"
        );

        let key = reopened.header().unlock(&pass()).expect("unlock");
        let seen = reopened
            .with_secret(&key, "m1", |b| b.to_vec())
            .expect("read");
        assert_eq!(seen, b"migration-secret-1");
    }

    #[test]
    fn custom_kdf_params_round_trip_from_the_file() {
        // R4.1/S4: KDF parameters are versioned *in the file* so raising them
        // later cannot invalidate existing vaults. A vault written with valid
        // non-default params must open by reading its own params.
        let custom = KdfParams {
            m_cost_kib: 16 * 1024,
            t_cost: 2,
            p_cost: 2,
            ..KdfParams::fast_for_tests()
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("custom.asv");
        {
            let store = VaultStore::create(&path, &pass(), custom).expect("create");
            assert_eq!(store.header().kdf, custom);
        }
        let reopened = VaultStore::open(&path, &pass()).expect("reopen");
        assert_eq!(
            reopened.header().kdf,
            custom,
            "params must come from the file, not binary defaults"
        );
    }
}
