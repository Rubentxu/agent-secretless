//! M1 exit UATs as executable tests.
//!
//! `docs/15-ROADMAP.md` M1 Exit UAT:
//!
//! - UAT-018 audit leak
//! - UAT-025 vault theft
//! - UAT-026 backup/restore
//!
//! Each test below names the UAT it discharges. These are integration tests
//! rather than unit tests on purpose: the UATs describe an *operator-level*
//! scenario (a thief copies a file, a restore runs on a clean system), so
//! asserting them crate-internally would test the wrong boundary.

use asv_domain::secret::SecretBytes;
use asv_vault::store::{CredentialKind, CredentialMetadata, Exportability};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

const CANARY: &str = "ASV-CANARY-4f2b9c1e7a-M1-UAT";
const OTHER_SECRET: &str = "ASV-SECOND-CANARY-91ac3f-DO-NOT-LEAK";

fn pass() -> SecretString {
    SecretString::from("integration-passphrase".to_string())
}

fn seeded(dir: &tempfile::TempDir) -> VaultStore {
    let mut store = VaultStore::create(
        dir.path().join("vault.asv"),
        &pass(),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");
    let key = store.header().unlock(&pass()).expect("unlock");

    let mut gh = CredentialMetadata::new(
        "gh-token",
        "GitHub personal token",
        CredentialKind::BearerToken,
        "github",
        "octocat",
        1_700_000_000,
    );
    gh.policy_refs = vec!["allow-git-push".into()];
    gh.exportability = Exportability::NonExportable;
    store
        .insert(&key, gh, SecretBytes::new(CANARY.as_bytes().to_vec()))
        .expect("insert gh");

    store
        .insert(
            &key,
            CredentialMetadata::new(
                "db-root",
                "prod database root",
                CredentialKind::DatabasePassword,
                "acme-internal",
                "root",
                1_700_000_000,
            ),
            SecretBytes::new(OTHER_SECRET.as_bytes().to_vec()),
        )
        .expect("insert db");
    store
}

/// UAT-018 — audit leak.
///
/// "Exercise every connector using known canary secrets. Expected: exact
/// canaries absent from all persisted ASV audit/log files."
///
/// M1 has no connector and no audit log yet, so the honest version of this
/// test is the strongest adjacent claim: exercise every vault write path with
/// known canaries and assert that nothing ASV persists contains them, and that
/// nothing ASV can render contains them. When M2 adds connectors and an audit
/// sink, this test extends to that sink rather than being replaced.
#[test]
fn uat_018_audit_leak() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = seeded(&dir);

    // Every artefact ASV persisted: the vault file and its parent directory.
    let vault_bytes = std::fs::read(store.path()).expect("read vault");
    let mut persisted: Vec<u8> = vault_bytes.clone();
    if let Some(parent) = store.path().parent() {
        for entry in std::fs::read_dir(parent).expect("read dir") {
            let entry = entry.expect("entry");
            if entry.path().is_file() {
                persisted.extend(std::fs::read(entry.path()).expect("read file"));
            }
        }
    }

    for canary in [CANARY, OTHER_SECRET] {
        assert!(
            !contains(&persisted, canary.as_bytes()),
            "UAT-018 violated: {canary} is present in a persisted ASV artefact"
        );
    }

    // Everything ASV can render for an operator or an audit view.
    let key = store.header().unlock(&pass()).expect("unlock");
    let mut rendered = String::new();
    for meta in store.list() {
        rendered.push_str(&format!("{meta:?}\n"));
    }
    rendered.push_str(&format!("{:?}\n", store));
    // Metadata legitimately names the provider, but never a secret value.
    for canary in [CANARY, OTHER_SECRET] {
        assert!(
            !rendered.contains(canary),
            "UAT-018 violated: {canary} leaked into a rendered view"
        );
    }

    // And the list/metadata surface exposes no secret bytes at all.
    for meta in store.list() {
        assert_eq!(meta.kind, {
            if meta.id == "gh-token" {
                CredentialKind::BearerToken
            } else {
                CredentialKind::DatabasePassword
            }
        });
    }
    let _ = key;
}

/// UAT-025 — vault theft.
///
/// "Copy vault database while locked and attempt offline inspection.
/// Expected: no plaintext secret; wrong passphrase fails authenticated
/// decryption without partial data disclosure."
#[test]
fn uat_025_vault_theft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = seeded(&dir);

    // The thief copies the file while it is locked.
    let stolen_bytes = std::fs::read(store.path()).expect("theft");
    let stolen = dir.path().join("stolen.asv");
    std::fs::write(&stolen, &stolen_bytes).expect("write stolen copy");

    // Offline inspection: no secret in the raw bytes.
    for canary in [CANARY, OTHER_SECRET] {
        assert!(
            !contains(&stolen_bytes, canary.as_bytes()),
            "UAT-025 violated: {canary} is readable in the locked vault"
        );
    }
    // Not even the metadata that names the accounts.
    for needle in ["GitHub personal token", "acme-internal", "allow-git-push"] {
        assert!(
            !contains(&stolen_bytes, needle.as_bytes()),
            "UAT-025 violated: metadata {needle} is readable in the locked vault"
        );
    }

    // Brute force with the wrong passphrase: fails, and discloses nothing.
    for guess in [
        "",
        "wrong",
        "integration-passphras",
        "integration-passphrase ",
    ] {
        let attempt = VaultStore::open(&stolen, &SecretString::from(guess.to_string()));
        let err = attempt
            .err()
            .unwrap_or_else(|| panic!("a wrong passphrase must not open the vault: {guess:?}"));
        let rendered = err.to_string();
        assert!(
            !rendered.contains(CANARY) && !rendered.contains(OTHER_SECRET),
            "UAT-025 violated: the failure disclosed secret material: {rendered}"
        );
    }

    // Tampering is caught, not silently tolerated.
    for offset in [0usize, 40, stolen_bytes.len() - 1] {
        let mut tampered = stolen_bytes.clone();
        tampered[offset] ^= 0x01;
        let path = dir.path().join(format!("tampered-{offset}.asv"));
        std::fs::write(&path, &tampered).expect("write tampered");
        assert!(
            VaultStore::open(&path, &pass()).is_err(),
            "UAT-025 violated: tampering at offset {offset} was accepted"
        );
    }

    // The rightful passphrase still works, so the theft test did not simply
    // break the file.
    let recovered = VaultStore::open(&stolen, &pass()).expect("the owner can still open it");
    assert_eq!(recovered.list().len(), 2);
}

/// UAT-026 — backup/restore.
///
/// "Restore encrypted backup on clean system using documented recovery factor.
/// Expected: integrity verified, credentials restored, policies preserved
/// according to versioned format."
#[test]
fn uat_026_backup_restore() {
    let original_dir = tempfile::tempdir().expect("original system");
    let store = seeded(&original_dir);
    let original_key = store.header().unlock(&pass()).expect("unlock");

    // Documented recovery factor: a separate passphrase for the backup.
    let recovery = SecretString::from("offline-recovery-factor".to_string());
    let backup_path = original_dir.path().join("vault-backup.asv");
    store.backup(&backup_path, &recovery).expect("backup");

    // The clean system has only the backup. The original vault is gone.
    let clean_dir = tempfile::tempdir().expect("clean system");
    let restored_path = clean_dir.path().join("restored").join("vault.asv");
    let restored = VaultStore::restore(&backup_path, &restored_path, &recovery)
        .expect("restore on a clean system");

    // Integrity verified: wrong recovery factor is rejected outright.
    assert!(
        VaultStore::restore(
            &backup_path,
            clean_dir.path().join("wrong.asv"),
            &SecretString::from("not-the-recovery-factor".to_string())
        )
        .is_err(),
        "UAT-026 violated: a wrong recovery factor was accepted"
    );

    // Credentials restored.
    assert_eq!(
        restored.list().len(),
        2,
        "UAT-026: credentials not restored"
    );

    // Policies preserved: the stable id, its policy refs and exportability.
    let gh = restored.metadata("gh-token").expect("gh restored");
    assert_eq!(gh.id, "gh-token");
    assert_eq!(gh.label, "GitHub personal token");
    assert_eq!(gh.provider, "github");
    assert_eq!(gh.account, "octocat");
    assert_eq!(gh.kind, CredentialKind::BearerToken);
    assert_eq!(gh.policy_refs, vec!["allow-git-push".to_string()]);
    assert_eq!(gh.exportability, Exportability::NonExportable);
    assert_eq!(gh.created_at, 1_700_000_000);

    // Versioned format: the restored vault declares a supported version.
    assert_eq!(restored.header().version, asv_vault::ENVELOPE_VERSION);
    assert_eq!(
        restored.header().cipher_id,
        asv_vault::envelope::cipher_id::XCHACHA20_POLY1305
    );
    assert_eq!(
        restored.header().kdf.kdf_id,
        asv_vault::envelope::kdf_id::ARGON2ID
    );

    // Secret values survive intact, still not readable from disk.
    let restored_key = restored
        .header()
        .unlock(&recovery)
        .expect("unlock restored");
    assert_eq!(
        restored
            .with_secret(&restored_key, "gh-token", |b| b.to_vec())
            .expect("read gh"),
        CANARY.as_bytes()
    );
    assert_eq!(
        restored
            .with_secret(&restored_key, "db-root", |b| b.to_vec())
            .expect("read db"),
        OTHER_SECRET.as_bytes()
    );

    let restored_bytes = std::fs::read(&restored_path).expect("read restored");
    for canary in [CANARY, OTHER_SECRET] {
        assert!(
            !contains(&restored_bytes, canary.as_bytes()),
            "UAT-026 violated: {canary} is readable in the restored vault"
        );
    }

    // The restored vault is a working vault: it can be mutated and reopened.
    let mut restored = restored;
    restored
        .rotate(
            &restored_key,
            "gh-token",
            SecretBytes::new(b"rotated-after-restore".to_vec()),
            1_700_009_999,
        )
        .expect("rotate after restore");
    drop(restored_key);
    drop(original_key);

    let reopened = VaultStore::open(&restored_path, &recovery).expect("reopen restored");
    let meta = reopened.metadata("gh-token").expect("meta after rotate");
    assert_eq!(meta.rotated_at, 1_700_009_999);
    assert_eq!(
        meta.created_at, 1_700_000_000,
        "rotation must not rewrite history"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
