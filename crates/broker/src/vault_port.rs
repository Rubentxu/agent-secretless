//! The bridge from a surrogate to the bytes it stands for (M4, design v2 D2).
//!
//! This module is the *only* place where a `CredentialId` and a secret meet.
//! Everything above it works in surrogates; everything below it is the vault.
//! Keeping the join in one file is what makes the claim checkable: grep for
//! `with_secret` and there is one answer, and it is here.
//!
//! # Why the adapter is not the connector's job
//!
//! [`asv_connector_http::SecretPort`] is declared in the connector crate and
//! implemented here, in the broker. The direction is the security property, not
//! a layering preference:
//!
//! - The broker is the secret-bearing process. It is the one allowed to open
//!   the vault (ADR-0002).
//! - The connector must not depend on `asv-vault`. A connector that could
//!   open the vault itself would be a second place secret material can be
//!   reached for, and D2's one-way dependency would be documentation rather
//!   than structure.
//!
//! So the connector states the port and the broker implements it. The trait
//! exists to be implemented on this side of the boundary.

use std::sync::{Arc, Mutex};

use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_vault::{CredentialMetadata, VaultError, VaultKey, VaultStore};

/// A [`SecretPort`] backed by an encrypted vault.
///
/// Holds the key by `Arc` rather than by value so the port can be shared as
/// `Arc<dyn SecretPort>` without the broker cloning key material, and so the
/// key's own `Zeroize` still governs its lifetime.
///
/// The store is shared with [`VaultWritePort`] behind a `Mutex`, and both hold
/// the *same* instance. A second `VaultStore` on the same path would have been
/// the tidier-looking design and does not work: `with_secret` gates on
/// `self.body.records`, the **in-memory** body, so a credential written through
/// another handle is in the file and absent from this one, and the lender would
/// answer `NotFound` for a credential that is right there.
///
/// A `Mutex` rather than an `RwLock` is deliberate and measured, not lazy: the
/// broker's accept loop (`main.rs`) serves one connection to completion before
/// accepting the next, so there is no read concurrency to share and a
/// read/write lock would be a second lock type to reason about for no gain.
pub struct VaultSecretPort {
    store: Arc<Mutex<VaultStore>>,
    key: Arc<VaultKey>,
}

impl VaultSecretPort {
    /// Builds a port that unlocks credentials from `store` using `key`.
    pub fn new(store: Arc<Mutex<VaultStore>>, key: Arc<VaultKey>) -> Self {
        Self { store, key }
    }
}

impl SecretPort for VaultSecretPort {
    /// Unlocks `credential` and lends it to `sink`, then lets it go.
    ///
    /// The two obligations this method has are both structural:
    ///
    /// 1. The secret reaches `sink` only through a borrow valid for the
    ///    duration of the call. Nothing is returned, nothing is stored, and
    ///    `with_secret` zeroizes the decrypted body on the way out.
    /// 2. `sink` is the only thing that sees the bytes, so "the secret is
    ///    attached to exactly one request and that request is the one we
    ///    authenticated" is a property of the type, not of a code review.
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        let store = self.store.lock().map_err(|_| {
            // A poisoned lock means a previous holder panicked mid-operation.
            // That is not a recoverable state for a vault: reporting it as an
            // ordinary "unavailable" would hide that something already went
            // wrong, so it is named.
            SecretError::Unavailable("the vault lock was poisoned by an earlier failure".into())
        })?;
        store
            .with_secret(&self.key, credential, |secret| sink.accept(secret))
            .map_err(|error| translate(error, credential))?
    }

    /// Nothing to drop, and that is a fact about this port rather than an
    /// omission.
    ///
    /// `lend` here opens the record, hands the bytes to `sink` and closes it
    /// again; the store is the source of truth and this port holds no derived
    /// copy of anything. So by the time `DeleteCredential` calls this, the
    /// record it is deleting is already gone from the only place it was ever
    /// held, and a later `lend` answers `NotFound` on its own.
    ///
    /// Written out explicitly, with the reason, because the trait requires it:
    /// a required method is only a structural guarantee if an implementation
    /// with nothing to do says so on purpose. An empty body here means "this
    /// port keeps nothing", not "nobody thought about it".
    fn forget(&self, _credential: &str) {}
}

/// The only path by which a credential enters the vault from a running broker.
///
/// It lives in this module for the reason the module exists: this is where a
/// `CredentialId` and a secret meet, and after ADR-0016 that is true of a
/// credential going *in* as well as one coming out. A separate module for the
/// writer would have quietly become the second place secret material arrives.
///
/// Admission is **not** re-checked here. This port is the mechanism; ADR-0015's
/// predicate is the broker's decision, and a second check would be a second
/// place to get it subtly wrong.
pub struct VaultWritePort {
    store: Arc<Mutex<VaultStore>>,
    key: Arc<VaultKey>,
}

impl VaultWritePort {
    /// Builds a writer over the same store instance `lender` uses.
    pub fn new(store: Arc<Mutex<VaultStore>>, key: Arc<VaultKey>) -> Self {
        Self { store, key }
    }

    /// Plants `metadata` and `secret` in the vault file.
    ///
    /// `insert` rather than `upsert`, and that is a security choice as much as
    /// a semantic one: it fails closed if the id already exists, so a write can
    /// never quietly replace the secret behind a credential an agent is already
    /// holding a live surrogate for. Replacing a secret is a rotation, and
    /// rotation is a different operation with a different audit story.
    pub fn create(
        &self,
        metadata: CredentialMetadata,
        secret: asv_domain::SecretBytes,
    ) -> Result<String, VaultError> {
        let id = metadata.id.clone();
        let mut store = self.store.lock().map_err(|_| VaultError::MalformedBody)?;
        store.insert(&self.key, metadata, secret)?;
        Ok(id)
    }

    /// Removes a credential from the vault file.
    pub fn remove(&self, id: &str) -> Result<(), VaultError> {
        let mut store = self.store.lock().map_err(|_| VaultError::MalformedBody)?;
        store.remove(&self.key, id)
    }
}

/// Maps a vault failure onto the connector's vocabulary.
///
/// The two cases are kept apart on purpose. "This credential does not exist"
/// and "the vault could not be opened" send an operator to different places,
/// and the broker answers the agent differently for each.
fn translate(error: VaultError, credential: &str) -> SecretError {
    match error {
        VaultError::NotFound(_) => SecretError::NotFound(credential.to_string()),
        // The credential's own name is carried so a log line on the broker
        // side can name it, but the connector re-words this before it can reach
        // an agent. Nothing outside this process is told which credential was
        // asked for.
        other => SecretError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use asv_domain::secret::SecretBytes;
    use asv_vault::{CredentialKind, CredentialMetadata, KdfParams};
    use secrecy::SecretString;

    /// A value that must never appear in an error, a log, or anything a caller
    /// of the broker could read back.
    const CANARY: &str = "ASV-CANARY-port-3b7f-DO-NOT-LEAK";

    fn pass() -> SecretString {
        SecretString::from("test-passphrase".to_string())
    }

    /// An unlocked port over a real encrypted vault holding `CANARY` as `c1`
    /// and a second credential as `c2`.
    ///
    /// The key is handed straight to the port, so the helper returns only the
    /// port. The canary is not a random string per run: a fixed value is what
    /// makes "this exact token never appears in a response" a checkable
    /// assertion rather than a hope about entropy.
    fn port_with(dir: &tempfile::TempDir) -> Arc<dyn SecretPort> {
        let path = dir.path().join("vault.asv");
        let mut store =
            VaultStore::create(&path, &pass(), KdfParams::fast_for_tests()).expect("create");
        let key = store.header().unlock(&pass()).expect("unlock");
        store
            .insert(
                &key,
                CredentialMetadata::new("c1", "l", CredentialKind::Opaque, "github", "a", 1),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert c1");
        store
            .insert(
                &key,
                CredentialMetadata::new("c2", "l", CredentialKind::Opaque, "github", "a", 1),
                SecretBytes::new(b"a-second-secret".to_vec()),
            )
            .expect("insert c2");
        Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        ))
    }

    /// A sink that keeps whatever it is handed, standing in for the header
    /// builder. The real sink scrubs on drop; this one has to keep the bytes
    /// long enough to assert on them.
    #[derive(Default)]
    struct CapturingSink {
        seen: Vec<u8>,
        accepts: u32,
    }

    impl SecretSink for CapturingSink {
        fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
            self.seen = secret.to_vec();
            self.accepts += 1;
            Ok(())
        }
    }

    /// A sink that refuses, standing in for a request the broker could not
    /// assemble. The failure has to reach the caller rather than being
    /// swallowed by the vault's `with_secret`.
    struct RefusingSink;

    impl SecretSink for RefusingSink {
        fn accept(&mut self, _secret: &[u8]) -> Result<(), SecretError> {
            Err(SecretError::Unavailable(
                "the request was already assembled".into(),
            ))
        }
    }

    /// The vault really hands over the stored bytes, and the port hands them
    /// over exactly once.
    #[test]
    fn lending_yields_the_real_bytes_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = port_with(&dir);
        let mut sink = CapturingSink::default();

        port.lend("c1", &mut sink).expect("lend");

        assert_eq!(sink.seen, CANARY.as_bytes(), "the port invented a value");
        assert_eq!(sink.accepts, 1, "the secret was handed over more than once");
    }

    /// Reading one credential must not disclose the others. `with_secret`
    /// already guarantees this; the port is the path that makes it reachable,
    /// so the guarantee is asserted here too.
    #[test]
    fn lending_one_credential_does_not_disclose_another() {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = port_with(&dir);
        let mut sink = CapturingSink::default();

        port.lend("c1", &mut sink).expect("lend");

        let seen = String::from_utf8_lossy(&sink.seen);
        assert!(
            !seen.contains("a-second-secret"),
            "lending c1 disclosed c2: {seen}"
        );
    }

    /// A missing credential is `NotFound`, not `Unavailable`. The broker maps
    /// the two to different IPC answers, so collapsing them here would make
    /// that mapping unreachable.
    #[test]
    fn a_missing_credential_reports_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = port_with(&dir);
        let mut sink = CapturingSink::default();

        let error = port.lend("no-such", &mut sink).expect_err("must not lend");

        assert!(matches!(error, SecretError::NotFound(_)), "got {error:?}");
        assert_eq!(sink.accepts, 0, "the sink ran without a secret");
    }

    /// A failure inside the sink must surface. `with_secret` returns the
    /// closure's result, so a port that discarded it would report a successful
    /// request that never got built.
    #[test]
    fn a_failing_sink_is_reported_to_the_caller() {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = port_with(&dir);

        let error = port
            .lend("c1", &mut RefusingSink)
            .expect_err("a refused request must not read as a successful lend");

        assert!(
            matches!(error, SecretError::Unavailable(_)),
            "got {error:?}"
        );
    }

    /// The credential's own name may appear in a broker-side log, but the
    /// secret must not appear in the error a port hands upwards.
    #[test]
    fn a_lending_failure_does_not_carry_the_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = port_with(&dir);

        let error = port
            .lend("c1", &mut RefusingSink)
            .expect_err("the sink refuses");

        assert!(
            !error.to_string().contains(CANARY),
            "the secret leaked into {error:?}"
        );
    }
}
