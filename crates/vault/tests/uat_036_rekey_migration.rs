//! UAT-036 — passphrase rekey over the versioned envelope.
//! R2 migration tests: passphrase rekey over the versioned envelope.
//!
//! `16-SECURITY-RELEASE-GATES.md` R2 (Vault) requires "migration tests":
//! the envelope format is versioned (spec §11), and migrating a vault
//! from an old passphrase to a new one is the operator-facing migration
//! this release gate is about. These tests pin the contract:
//!
//! - old passphrase stops working, new one works, credentials survive;
//! - a pre-rekey backup made under the OLD live vault key still
//!   restores with its own passphrase (a rekey is a wrap change, not a
//!   body re-encryption);
//! - the on-disk file keeps authenticating its body with the header's
//!   body_nonce across the migration;
//! - wrong `current` fails closed at the AEAD tag, before any write;
//! - an empty `next` is a config error, not a migration;
//! - a rekey leaves no canary in the file bytes, and equal-passphrase
//!   rekeys still produce different bytes (fresh salt + wrap nonce).

use asv_domain::secret::SecretBytes;
use asv_vault::store::{CredentialKind, CredentialMetadata};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

const CANARY: &str = "ASV-CANARY-7d31e90a2c-R2-MIGRATION";

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn fast() -> KdfParams {
    KdfParams::fast_for_tests()
}

fn seeded(path: impl AsRef<std::path::Path>) -> VaultStore {
    let mut store = VaultStore::create(path, &pass("old-passphrase"), fast()).expect("create");
    let key = store
        .header()
        .unlock(&pass("old-passphrase"))
        .expect("unlock");
    store
        .insert(
            &key,
            CredentialMetadata::new(
                "gh-token",
                "GitHub personal token",
                CredentialKind::BearerToken,
                "github",
                "octocat",
                1_700_000_000,
            ),
            SecretBytes::new(CANARY.as_bytes().to_vec()),
        )
        .expect("insert");
    store
}

#[test]
fn rekey_old_pass_stops_working_and_new_pass_opens_with_credentials_intact() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("new-passphrase-9"))
        .expect("rekey");

    // Old passphrase fails closed, indistinguishably from tampering.
    assert!(
        VaultStore::open(&path, &pass("old-passphrase")).is_err(),
        "old passphrase still opens the vault after rekey"
    );

    // New passphrase opens, and every credential survived the migration.
    let reopened = VaultStore::open(&path, &pass("new-passphrase-9")).expect("reopen new");
    let key = reopened
        .header()
        .unlock(&pass("new-passphrase-9"))
        .expect("unlock");
    assert_eq!(reopened.list().len(), 1, "credentials lost in rekey");
    assert_eq!(
        reopened
            .with_secret(&key, "gh-token", |b| b.to_vec())
            .expect("read"),
        CANARY.as_bytes(),
        "secret bytes changed across rekey"
    );
}

#[test]
fn rekey_persists_to_disk_and_a_second_handle_sees_the_migration() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("new-passphrase-9"))
        .expect("rekey");

    // A fresh handle (the operator's next boot) opens only with the new
    // passphrase: the rekey hit the disk, not just the in-memory header.
    assert!(VaultStore::open(&path, &pass("old-passphrase")).is_err());
    VaultStore::open(&path, &pass("new-passphrase-9")).expect("disk records the new wrap");
}

#[test]
fn pre_rekey_backup_still_restores_after_a_rekey() {
    // A rekey re-wraps the DEK; it does not re-encrypt the body and does
    // not touch backups made earlier. An operator who rotated the
    // passphrase after taking a backup must not find that backup broken.
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);

    let backup_pass = pass("offline-recovery-factor");
    let backup_path = dir.path().join("backup.asv");
    store.backup(&backup_path, &backup_pass).expect("backup");

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("new-passphrase-9"))
        .expect("rekey after backup");

    // The backup predates the migration and uses its own passphrase.
    let clean = dir.path().join("restored").join("vault.asv");
    let restored = VaultStore::restore(&backup_path, &clean, &backup_pass).expect("restore");
    let key = restored.header().unlock(&backup_pass).expect("unlock");
    assert_eq!(
        restored
            .with_secret(&key, "gh-token", |b| b.to_vec())
            .expect("read"),
        CANARY.as_bytes(),
        "pre-rekey backup lost credential bytes"
    );
}

#[test]
fn rekey_with_wrong_current_fails_closed_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);
    let before = std::fs::read(&path).expect("read before");
    let revision_before = store.header().revision;

    let err = store
        .rekey_passphrase(&pass("WRONG-passphrase"), &pass("new-passphrase-9"))
        .expect_err("rekey with wrong current must fail");
    assert!(
        matches!(err, asv_vault::VaultError::Envelope(_)),
        "wrong current must fail at the envelope/AEAD layer, got {err:?}"
    );

    // No bytes changed on disk, and the in-memory store keeps working
    // with the real passphrase.
    let after = std::fs::read(&path).expect("read after");
    assert_eq!(before, after, "failed rekey must not touch the file");
    assert_eq!(store.header().revision, revision_before);
    VaultStore::open(&path, &pass("old-passphrase")).expect("old pass still valid");
}

#[test]
fn rekey_to_an_empty_passphrase_is_a_config_error_not_a_migration() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);
    let before = std::fs::read(&path).expect("read before");

    let err = store
        .rekey_passphrase(&pass("old-passphrase"), &pass(""))
        .expect_err("empty next must fail");
    assert!(
        matches!(err, asv_vault::VaultError::Envelope(_)),
        "empty next must fail at the envelope layer, got {err:?}"
    );
    assert_eq!(std::fs::read(&path).expect("read after"), before);
    VaultStore::open(&path, &pass("old-passphrase")).expect("store unaffected");
}

#[test]
fn rekey_to_the_same_passphrase_refreshes_kdf_material_and_keeps_working() {
    // Equal-passphrase rekey is a legitimate KDF-parameter refresh: the
    // salt and wrap nonce are redrawn, so bytes differ, but semantics
    // are unchanged.
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);
    let before = std::fs::read(&path).expect("read before");
    let revision_before = store.header().revision;

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("old-passphrase"))
        .expect("same-passphrase rekey");

    let after = std::fs::read(&path).expect("read after");
    assert_ne!(
        before, after,
        "equal-passphrase rekey must still redraw salt/wrap nonce"
    );
    assert!(store.header().revision > revision_before);
    VaultStore::open(&path, &pass("old-passphrase")).expect("same pass still opens");
    assert!(VaultStore::open(&path, &pass("WRONG")).is_err());
}

#[test]
fn rekeyed_file_has_no_canary_and_owner_only_permissions() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("new-passphrase-9"))
        .expect("rekey");

    let bytes = std::fs::read(&path).expect("read");
    assert!(
        !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
        "canary leaked into the rekeyed vault file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "rekey must preserve the owner-only file mode"
        );
    }
}

#[test]
fn two_rekeys_in_sequence_both_work() {
    // Rotation is not a one-shot: A -> B -> C must behave like A -> B.
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("pass-b"))
        .expect("first rekey");
    store
        .rekey_passphrase(&pass("pass-b"), &pass("pass-c"))
        .expect("second rekey");

    assert!(VaultStore::open(&path, &pass("old-passphrase")).is_err());
    assert!(VaultStore::open(&path, &pass("pass-b")).is_err());
    let reopened = VaultStore::open(&path, &pass("pass-c")).expect("reopen");
    assert_eq!(reopened.list().len(), 1);
}

#[test]
fn revision_increases_across_rekey_and_file_stays_self_consistent() {
    // After a rekey the persisted file must be self-consistent: the new
    // header's body_nonce pairs with the freshly persisted body
    // ciphertext, so a fresh handle opens and reads every credential.
    // The revision bump proves the write happened, and the header that
    // changed is the wrap (salt/wrapped key), not the DEK identity.
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("vault.asv");
    let mut store = seeded(&path);
    let revision_before = store.header().revision;
    let kdf_before = store.header().kdf;

    store
        .rekey_passphrase(&pass("old-passphrase"), &pass("new-passphrase-9"))
        .expect("rekey");

    assert!(
        store.header().revision > revision_before,
        "rekey must bump the revision like any persisted write"
    );
    assert_eq!(
        store.header().kdf,
        kdf_before,
        "rekey must not silently change KDF parameters"
    );
    // Self-consistency: fresh handle + new passphrase reads the secret.
    let reopened = VaultStore::open(&path, &pass("new-passphrase-9")).expect("reopen");
    let key = reopened
        .header()
        .unlock(&pass("new-passphrase-9"))
        .expect("unlock");
    assert_eq!(
        reopened
            .with_secret(&key, "gh-token", |b| b.to_vec())
            .expect("read"),
        CANARY.as_bytes()
    );
}
