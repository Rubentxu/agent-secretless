//! The vault's write path is transactional and atomic.
//!
//! Every test here was written against a defect that was reproduced before
//! the fix. The first one is the probe from exploration, unchanged in what it
//! asserts: a write that fails must not leave the in-memory body holding a
//! record the file does not.
//!
//! Note one behaviour change the fix produced, because it is the kind of thing
//! that looks like a regression and is not: with the in-place write, a
//! read-only *vault file* made `upsert` fail. With the atomic write it
//! succeeds, because `rename` needs only directory permission. The failure
//! these tests drive is an unwritable *directory*, which is the condition that
//! still stops a write.

use asv_vault::{CredentialKind, CredentialMetadata, KdfParams, VaultStore};
use std::os::unix::fs::PermissionsExt;

fn meta(id: &str) -> CredentialMetadata {
    CredentialMetadata::new(
        id,
        "label",
        CredentialKind::BearerToken,
        "github",
        "acct",
        1,
    )
}

fn secret() -> asv_domain::SecretBytes {
    asv_domain::SecretBytes::new(b"s3cret".to_vec())
}

struct Vault {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    pass: secrecy::SecretString,
}

impl Vault {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.asv");
        let pass = secrecy::SecretString::from("pw".to_string());
        VaultStore::create(&path, &pass, KdfParams::fast_for_tests()).expect("create vault");
        Vault { dir, path, pass }
    }

    fn open(&self) -> VaultStore {
        VaultStore::open(&self.path, &self.pass).expect("open vault")
    }

    /// Makes any write fail: the directory cannot be written to, so neither
    /// the temp file nor a rename can land.
    fn seal_writes(&self) {
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod dir ro");
    }

    fn unseal_writes(&self) {
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod dir rw");
    }

    fn leftovers(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "vault.asv")
            .collect()
    }
}

/// The defect this cycle exists for: a failed write left the record in the
/// in-memory body, `list()` read the body, and the broker believed it held a
/// credential the file did not.
#[test]
fn a_failed_upsert_leaves_memory_and_the_file_in_agreement() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");

    v.seal_writes();
    let result = store.upsert(&key, meta("probe-id"), secret());
    v.unseal_writes();

    assert!(result.is_err(), "the write was supposed to fail");

    let in_memory = store.list().iter().any(|m| m.id == "probe-id");
    let on_disk = v.open().list().iter().any(|m| m.id == "probe-id");
    assert_eq!(in_memory, on_disk, "memory and the file disagree");
    assert!(!in_memory, "memory kept a record the write never landed");
}

/// The same defect in the other direction: a failed `remove` left the body
/// without the record while the file still had it.
#[test]
fn a_failed_remove_restores_the_record() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    store.upsert(&key, meta("doomed"), secret()).expect("seed");

    v.seal_writes();
    let result = store.remove(&key, "doomed");
    v.unseal_writes();

    assert!(result.is_err(), "the write was supposed to fail");

    let in_memory = store.list().iter().any(|m| m.id == "doomed");
    let on_disk = v.open().list().iter().any(|m| m.id == "doomed");
    assert!(in_memory, "a failed remove dropped the record from memory");
    assert!(on_disk);
}

/// `revision` used to be incremented before the write, so a failed write
/// consumed one and the counter measured attempts rather than history.
#[test]
fn a_failed_write_does_not_consume_a_revision() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    let before = store.header().revision;

    v.seal_writes();
    let _ = store.upsert(&key, meta("probe-id"), secret());
    v.unseal_writes();

    assert_eq!(
        store.header().revision,
        before,
        "a failed write moved the revision"
    );
}

/// A failed write must leave the previous vault exactly as it was: still
/// readable, still holding what it held.
#[test]
fn a_failed_write_leaves_the_previous_vault_intact() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    store
        .upsert(&key, meta("survivor"), secret())
        .expect("seed");

    v.seal_writes();
    let _ = store.upsert(&key, meta("doomed"), secret());
    v.unseal_writes();

    let reopened = v.open();
    assert!(reopened.list().iter().any(|m| m.id == "survivor"));
    assert!(!reopened.list().iter().any(|m| m.id == "doomed"));
}

/// A failed write must not leave a file of ciphertext beside the vault.
#[test]
fn a_failed_write_leaves_no_temporary_file() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");

    v.seal_writes();
    let _ = store.upsert(&key, meta("probe-id"), secret());
    v.unseal_writes();

    assert!(
        v.leftovers().is_empty(),
        "debris left behind: {:?}",
        v.leftovers()
    );
}

/// A successful write must not leave debris either.
#[test]
fn a_successful_write_leaves_no_temporary_file() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    store.upsert(&key, meta("kept"), secret()).expect("upsert");
    assert!(
        v.leftovers().is_empty(),
        "debris left behind: {:?}",
        v.leftovers()
    );
}

/// The rename carries the temp file's mode onto the target, so the `0600`
/// defence the old in-place path re-asserted on every write has to survive it.
#[test]
fn the_vault_stays_0600_after_a_write() {
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    store.upsert(&key, meta("kept"), secret()).expect("upsert");

    let mode = std::fs::metadata(&v.path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "vault mode is {mode:o} after a write");
}

/// Atomicity, decided without a race: hold the file open across a write.
///
/// An in-place `truncate(true)` write mutates the same inode, so this handle
/// would see the new content. A `rename` swaps a different inode into place,
/// so the handle keeps reading the vault as it was. The old code would fail
/// this; the new one passes it, deterministically.
#[test]
fn an_open_handle_still_reads_the_previous_vault_across_a_write() {
    use std::io::{Read, Seek, SeekFrom};
    let v = Vault::new();
    let mut store = v.open();
    let key = store.header().unlock(&v.pass).expect("unlock");
    store.upsert(&key, meta("before"), secret()).expect("seed");

    let mut held = std::fs::File::open(&v.path).expect("open handle");
    let before_len = held.metadata().expect("stat").len();

    store.upsert(&key, meta("after"), secret()).expect("upsert");

    held.seek(SeekFrom::Start(0)).expect("rewind");
    let mut buf = vec![0u8; before_len as usize];
    held.read_exact(&mut buf)
        .expect("read through the held handle");
    assert_eq!(
        buf.len(),
        before_len as usize,
        "the held handle saw a different file"
    );
    assert!(
        !buf.is_empty() && buf.iter().any(|b| *b != 0),
        "the held handle read a truncated file: the target was rewritten in place"
    );
}
