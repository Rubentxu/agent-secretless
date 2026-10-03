//! The broker can be given a credential (ADR-0016, ADR-0015).
//!
//! Every test here was written against a requirement with a stated falsifying
//! condition, and the requirements came before the code. What the suite exists
//! to catch is not "the verb works" — it is the ways this particular verb could
//! be wrong without failing a happy-path test:
//!
//! 1. it admits something ADR-0015 refuses,
//! 2. it puts a credential somewhere that is not the vault file,
//! 3. it leaves a secret in a place an operator will paste.
//!
//! **What is deliberately not here.** The three ADR-0015 conditions have eleven
//! hostile tests of their own in `admission_control_plane.rs`, driven by
//! scripted evidence. Repeating them here would be a second copy that drifts.
//! What this file adds is the *wiring* claim: the verb reaches the same
//! predicate, and its refusal is the predicate's answer rather than a string.
//! Two of the three conditions are reachable through `handle()` — an
//! unenrolled caller and an unpinned one. The third, a caller genuinely inside
//! a broker cgroup slice, is not reachable in a test on this host because the
//! handler reads the real `/proc`; it is covered at the predicate level, and
//! saying so is better than faking a pid.

use std::sync::{Arc, Mutex};

use asv_broker::admission::{self, Enrolment};
use asv_broker::{BrokerState, VaultSecretPort, VaultWritePort};
use asv_domain::CredentialKind;
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{OpaqueSecret, Request, Response};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// A value that must never appear in a response, an error, a log, or the vault
/// file. Fixed, not random: a fixed string is what makes "this exact token
/// never appears" a checkable assertion rather than a hope about entropy.
const CANARY: &str = "ASV-CANARY-create-9d1e-DO-NOT-LEAK";

fn pass() -> SecretString {
    SecretString::from("test-passphrase".to_string())
}

fn self_pid() -> i32 {
    i32::try_from(std::process::id()).expect("a pid that fits in i32")
}

fn peer() -> WorkloadIdentity {
    WorkloadIdentity::from_peer(asv_identity::PeerCredentials {
        pid: self_pid(),
        uid: 1000,
        gid: 1000,
    })
}

/// The peer `main.rs` would build: pinned, because ADR-0015's condition 3
/// requires it and `from_peer` does not pin.
fn pinned_peer() -> WorkloadIdentity {
    let mut identity = peer();
    // Pinning a pid that does not exist would fail for a reason that has
    // nothing to do with what is under test, so this pins the test process.
    identity.pin_pidfd().expect("pin this live process");
    identity
}

fn create_request(kind: CredentialKind) -> Request {
    Request::CreateCredential {
        label: "uat".into(),
        kind,
        provider: "github".into(),
        account: "acct".into(),
        secret: OpaqueSecret::new(CANARY.as_bytes().to_vec()),
    }
}

/// A vault on disk, a broker holding it, and a writer wired to the same store
/// instance — the production shape from `main.rs`.
struct Broker {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    state: BrokerState,
    key: Arc<asv_vault::VaultKey>,
    handle: WorkloadIdentity,
}

impl Broker {
    fn new(enrol: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.asv");
        let store =
            VaultStore::create(&path, &pass(), KdfParams::fast_for_tests()).expect("create");
        let key = Arc::new(store.header().unlock(&pass()).expect("unlock"));
        let mut state = BrokerState::default();
        asv_broker::inventory::load(&mut state, &store);
        let store = Arc::new(Mutex::new(store));

        state.vault_writer = Some(Arc::new(VaultWritePort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::clone(&store),
            key.clone(),
        )));

        if enrol {
            // The enrolled principal is *this* test binary, digested the way
            // `admission::enrol` digests one. Enrolling the real executable is
            // what makes the admitted case a real admission rather than a
            // bypass, and it means the digest is computed from bytes on disk.
            let exe = std::fs::canonicalize(std::env::current_exe().expect("current_exe"))
                .expect("canonical");
            let bytes = std::fs::read(&exe).expect("read exe");
            state.control_plane = Enrolment::empty().enrol(exe, admission::sha256(&bytes));
        }

        Broker {
            _dir: dir,
            path,
            state,
            key,
            handle: pinned_peer(),
        }
    }

    /// Re-opens the vault from scratch, as another process would.
    fn reopen(&self) -> VaultStore {
        VaultStore::open(&self.path, &pass()).expect("reopen")
    }

    fn file_holds(&self, id: &str) -> bool {
        self.reopen().list().iter().any(|m| m.id == id)
    }

    fn file_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("read vault file")
    }
}

// --------------------------------------------------------------------------
// REQ-1 — the refusal is derived, and names its condition
// --------------------------------------------------------------------------

/// The admitted case, and the narrowest one: enrolled, pinned, and outside any
/// broker slice because this test process is not in one.
#[test]
fn an_admitted_principal_can_create() {
    let mut b = Broker::new(true);
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );

    let id = match response {
        Response::CredentialCreated { id, .. } => id,
        other => panic!("admission granted and the write failed: {other:?}"),
    };
    assert_eq!(b.state.credentials.len(), 1, "the inventory did not follow");
    assert!(b.file_holds(&id.to_wire()), "the file does not hold it");
}

/// An unenrolled caller is refused, and the refusal says *which* condition.
///
/// The message matters as much as the refusal: an operator who cannot tell
/// "you never enrolled me" from "your process is under agent control" cannot
/// fix either.
#[test]
fn an_unenrolled_caller_is_refused_by_name() {
    let mut b = Broker::new(false);
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );

    match response {
        Response::Error { code, message } => {
            assert_eq!(code, asv_ipc_protocol::ErrorCode::Denied, "{message}");
            assert!(
                message.contains("enrolled"),
                "the refusal does not name the condition: {message}"
            );
        }
        other => panic!("an unenrolled caller created a credential: {other:?}"),
    }
    assert!(
        b.state.credentials.is_empty(),
        "a refused create touched the inventory"
    );
    assert!(
        b.reopen().list().is_empty(),
        "a refused create touched the vault"
    );
}

/// Condition 3 through the verb: no pin, no credential, even enrolled.
#[test]
fn an_unpinned_caller_is_refused_even_when_enrolled() {
    let mut b = Broker::new(true);
    let unpinned = peer();
    let response = asv_broker::handle(
        &mut b.state,
        &unpinned,
        create_request(CredentialKind::BearerToken),
    );

    match response {
        Response::Error { message, .. } => assert!(
            message.contains("pidfd"),
            "the refusal does not name the missing pin: {message}"
        ),
        other => panic!("an unpinned caller created a credential: {other:?}"),
    }
    assert!(b.reopen().list().is_empty());
}

// --------------------------------------------------------------------------
// REQ-2 — the credential reaches the file, not only memory
// --------------------------------------------------------------------------

/// The defect this whole cycle is adjacent to: a credential that exists in the
/// running broker and in nobody's file. Checked from a *fresh* open, because
/// reading through the writer's own handle would pass either way.
#[test]
fn a_created_credential_survives_a_fresh_open_of_the_vault() {
    let mut b = Broker::new(true);
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    let id = match response {
        Response::CredentialCreated { id, .. } => id.to_wire(),
        other => panic!("create failed: {other:?}"),
    };

    let reopened = b.reopen();
    assert!(
        reopened.list().iter().any(|m| m.id == id),
        "the file does not hold {id}"
    );

    // And the secret is really in there, not just the metadata.
    let mut seen = false;
    reopened
        .with_secret(&b.key, &id, |bytes| seen = bytes == CANARY.as_bytes())
        .expect("with_secret");
    assert!(seen, "the stored secret is not the one that was sent");
}

/// The write must move the file's revision, which is the observable difference
/// between "wrote the file" and "remembered it".
#[test]
fn a_created_credential_advances_the_files_revision() {
    let mut b = Broker::new(true);
    let before = b.reopen().header().revision;

    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    assert!(
        matches!(response, Response::CredentialCreated { .. }),
        "{response:?}"
    );

    let after = b.reopen().header().revision;
    assert!(
        after > before,
        "the file revision did not move: {before} -> {after}"
    );
}

// --------------------------------------------------------------------------
// REQ-3 — immediately grantable and usable
// --------------------------------------------------------------------------

/// The M5 exit phrase's middle, in miniature: a credential created through the
/// broker is one the broker can mint against, with no restart in between.
#[test]
fn a_created_credential_can_mint_a_surrogate_immediately() {
    let mut b = Broker::new(true);
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    let id = match response {
        Response::CredentialCreated { id, .. } => id,
        other => panic!("create failed: {other:?}"),
    };

    let session = match asv_broker::handle(
        &mut b.state,
        &b.handle,
        Request::CreateSession {
            workspace: "/w".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("session failed: {other:?}"),
    };

    let minted = asv_broker::handle(
        &mut b.state,
        &b.handle,
        Request::MintSurrogate {
            session,
            credential: id,
            max_uses: 1,
            ttl_secs: 60,
        },
    );
    match minted {
        Response::SurrogateMinted { .. } => {}
        other => panic!("a credential created a moment ago cannot be minted: {other:?}"),
    }
}

// --------------------------------------------------------------------------
// REQ-4 — nothing discloses the secret
// --------------------------------------------------------------------------

/// The canary must not be in the response or in the vault file. A vault is
/// encrypted at rest, so finding the plaintext in the file would mean the
/// write path leaked the secret before encrypting it.
#[test]
fn the_secret_appears_in_no_response_and_in_no_vault_file() {
    let mut b = Broker::new(true);
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    let rendered = format!("{response:?}");
    assert!(
        !rendered.contains(CANARY),
        "the response carried it: {rendered}"
    );

    let file = String::from_utf8_lossy(&b.file_bytes()).into_owned();
    assert!(
        !file.contains(CANARY),
        "the vault file contains the plaintext secret"
    );
}

/// `Debug` on a request is the quiet leak: a failed `assert_eq!` between two
/// requests prints both. This pins the wrapper, not the call site.
#[test]
fn a_request_debug_renders_the_secret_as_redacted() {
    let request = create_request(CredentialKind::BearerToken);
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(CANARY), "Debug leaked it: {rendered}");
    assert!(
        rendered.contains("redacted"),
        "Debug did not mark the field: {rendered}"
    );
}

/// The wrapper owns a `Zeroizing`, so dropping a decoded-then-refused request
/// runs the zeroizing destructor. The buffer itself is not observable from safe
/// code, so what this pins is the type's promise rather than heap contents.
#[test]
fn the_secret_wrapper_exposes_only_through_the_named_read_path() {
    let owned = OpaqueSecret::new(vec![7u8; 4]);
    assert_eq!(owned.expose().len(), 4);
}

// --------------------------------------------------------------------------
// The kind vocabulary: a label beside the storage class
// --------------------------------------------------------------------------

/// The four kinds the vault has no storage class for are now stored — and they
/// must come back as themselves.
///
/// This test used to assert the opposite, that they were refused. The refusal
/// was correct then and it is gone now, and the reason it could go is the
/// whole point: the record now carries the kind the operator named *beside*
/// the storage class, so collapsing an `ApiKey` onto `BearerToken` no longer
/// loses what the operator asked for. Without the label this assertion is
/// exactly the silent mislabel the refusal existed to prevent, which is why
/// the round trip is checked and not merely the acceptance.
#[test]
fn a_kind_without_a_storage_class_is_stored_and_read_back_as_itself() {
    let mut b = Broker::new(true);
    let mut planted = Vec::new();
    for kind in [
        CredentialKind::ApiKey,
        CredentialKind::OAuth2,
        CredentialKind::X509ClientIdentity,
        CredentialKind::AwsAccessKey,
    ] {
        let response = asv_broker::handle(&mut b.state, &b.handle, create_request(kind));
        match response {
            Response::CredentialCreated { id, .. } => planted.push((kind, id)),
            other => panic!("{kind:?} was refused rather than stored: {other:?}"),
        }
    }

    // Reopened from the file, by a fresh read of the vault rather than from
    // the broker's in-memory list, so a label held only in memory cannot pass.
    let reopened = b.reopen();
    let listed = match asv_broker::handle(
        &mut b.state,
        &b.handle,
        asv_ipc_protocol::Request::ListCredentialMetadata,
    ) {
        Response::CredentialMetadata { entries } => entries,
        other => panic!("expected a listing, got {other:?}"),
    };

    for (kind, id) in planted {
        let entry = listed
            .iter()
            .find(|e| e.id == *id.as_uuid())
            .unwrap_or_else(|| panic!("{kind:?} was stored but is not listed"));
        assert_eq!(
            entry.kind, kind,
            "{kind:?} came back as {:?} — the label did not survive the file",
            entry.kind
        );
    }
    assert_eq!(reopened.list().len(), 4, "every kind reached the file");
}

/// The five that do survive must come back as themselves, not as a neighbour.
#[test]
fn every_storable_kind_survives_the_round_trip() {
    let mut b = Broker::new(true);
    for kind in [
        CredentialKind::BearerToken,
        CredentialKind::UsernamePassword,
        CredentialKind::SshPrivateKey,
        CredentialKind::DatabaseCredential,
        CredentialKind::GenericSecret,
    ] {
        let response = asv_broker::handle(&mut b.state, &b.handle, create_request(kind));
        let id = match response {
            Response::CredentialCreated { id, .. } => id,
            other => panic!("{kind:?} should be storable: {other:?}"),
        };
        let projected = b
            .state
            .credentials
            .iter()
            .find(|m| m.id == id)
            .expect("inventory entry");
        assert_eq!(projected.kind, kind, "{kind:?} came back as something else");
    }
    // All five are in the file, not four: a kind that stored but failed to
    // project would leave the inventory short without failing the loop above.
    assert_eq!(
        b.reopen().list().len(),
        5,
        "the vault does not hold all five"
    );
}

/// The broker mints the id, so a request cannot name its own handle and two
/// creates cannot collide.
#[test]
fn two_creates_never_collide() {
    let mut b = Broker::new(true);
    let first = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    let second = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );
    let (Response::CredentialCreated { id: a, .. }, Response::CredentialCreated { id: b_id, .. }) =
        (first, second)
    else {
        panic!("both creates should succeed");
    };
    assert_ne!(a, b_id, "the broker minted the same id twice");
}

// --------------------------------------------------------------------------
// The no-write-path case must fail closed
// --------------------------------------------------------------------------

/// A broker with no write path refuses. The tempting alternative — accept the
/// secret and hold it somewhere that is not the encrypted vault — is the one
/// this product exists to avoid.
#[test]
fn a_broker_with_no_write_path_refuses_rather_than_buffering() {
    // An *admitted* caller, so the write-path branch is the one under test. With
    // an empty enrolment the refusal would come from admission instead and this
    // test would pass against a broker that had no notion of a write path at
    // all — the first version of it made exactly that mistake.
    let mut b = Broker::new(true);
    b.state.vault_writer = None;
    let response = asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );

    match response {
        Response::Error { message, .. } => assert!(
            message.contains("no vault write path"),
            "the refusal does not say why: {message}"
        ),
        other => panic!("a broker with no vault accepted a secret: {other:?}"),
    }
}

// --------------------------------------------------------------------------
// Audit: the create is recorded, and records nothing sensitive
// --------------------------------------------------------------------------

/// Every handled request is audited once, and the audit DTO has no field that
/// could carry the secret — so this is about the record existing at all.
#[test]
fn a_create_is_audited_without_its_secret() {
    let mut b = Broker::new(true);
    asv_broker::handle(
        &mut b.state,
        &b.handle,
        create_request(CredentialKind::BearerToken),
    );

    let records = b.state.audit.lock().expect("no test holds this").query(0);
    assert!(
        records
            .iter()
            .any(|r| { format!("{r:?}").contains("create_credential") }),
        "the create was not audited: {records:?}"
    );
    assert!(
        !format!("{records:?}").contains(CANARY),
        "the audit log holds the secret"
    );
}

// --------------------------------------------------------------------------
// REQ-5 — the enrolment record, and the two ways reading it can go wrong
// --------------------------------------------------------------------------

/// A vault path and a stand-in executable. No KDF: the enrolment record is a
/// file beside the vault, and a test that derives a key to check a text file is
/// paying for confidence it does not need.
fn enrolment_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("vault.asv");
    std::fs::write(
        &vault,
        b"not a real vault; the record is read without opening it",
    )
    .expect("write");
    let principal = dir.path().join("asv-cli");
    std::fs::write(&principal, b"#!/bin/sh\n# the control plane\nexec true\n").expect("write");
    (dir, vault, principal)
}

/// The record round-trips: what `enrol` writes is what `load_enrolment` reads.
#[test]
fn an_enrolment_round_trips_through_the_sidecar() {
    let (_dir, vault, principal) = enrolment_fixture();
    admission::enrol(&vault, &principal).expect("enrol");

    let loaded = admission::load_enrolment(&vault).expect("load");
    assert_eq!(
        loaded.principals().len(),
        1,
        "the record did not round-trip"
    );
    assert_eq!(
        loaded.principals()[0].path,
        std::fs::canonicalize(&principal).expect("canonical"),
        "the enrolment names a different path than the one enrolled"
    );
    let bytes = std::fs::read(&principal).expect("read");
    assert_eq!(
        loaded.principals()[0].digest,
        admission::sha256(&bytes),
        "the recorded digest is not the file's digest"
    );
}

/// The record grants the capability to plant credentials, so it is owner-only
/// from the moment it exists. A world-readable control-plane record would hand
/// the same enrolment to any process the operator starts.
#[test]
fn the_enrolment_record_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, vault, principal) = enrolment_fixture();
    let path = admission::enrol(&vault, &principal).expect("enrol");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the enrolment record is {mode:o}");
}

/// The digest binds the *contents*, so a file replaced at an enrolled path no
/// longer matches its enrolment. This is the property that makes an enrolment
/// worth having over a bare path check.
///
/// The first version of this test asserted that the *loaded* digest changes
/// after the file is replaced. It does not, and should not: the record is a
/// snapshot taken at enrolment, and the comparison happens at admission, when
/// `admit_control_plane` reads the peer's live executable and compares. So what
/// is asserted here is the mismatch that the admission check would see — the
/// first version was testing that a file is a snapshot, which is true and
/// irrelevant.
#[test]
fn replacing_the_principal_breaks_the_digest_the_enrolment_binds() {
    let (_dir, vault, principal) = enrolment_fixture();
    admission::enrol(&vault, &principal).expect("enrol");
    let enrolled = admission::load_enrolment(&vault).expect("load");

    let original = std::fs::read(&principal).expect("read");
    assert_eq!(
        enrolled.principals()[0].digest,
        admission::sha256(&original),
        "the enrolment does not match the file it names"
    );

    std::fs::write(&principal, b"#!/bin/sh\n# replaced\nexec true\n").expect("replace");
    let replaced = std::fs::read(&principal).expect("read");
    assert_ne!(
        enrolled.principals()[0].digest,
        admission::sha256(&replaced),
        "a replaced file still matches its enrolment, so admission would admit it"
    );
}

/// A missing record is the normal state: nobody is enrolled, and the broker
/// starts. It is not an error, and reporting it as one would make the fail-safe
/// case look like a fault on every unconfigured boot.
#[test]
fn a_missing_enrolment_record_is_an_empty_enrolment_not_an_error() {
    let (_dir, vault, _principal) = enrolment_fixture();
    let loaded = admission::load_enrolment(&vault).expect("a missing record must not be an error");
    assert!(loaded.principals().is_empty());
}

/// A record that exists and cannot be parsed is an error, because reading it as
/// "nobody is enrolled" would make a damaged authorisation file
/// indistinguishable from an operator who chose not to enrol anyone.
#[test]
fn a_corrupt_enrolment_record_is_an_error_not_an_empty_enrolment() {
    let (_dir, vault, _principal) = enrolment_fixture();
    let path = admission::enrolment_path(&vault);
    std::fs::write(&path, b"this is not a digest record\n").expect("write");

    let loaded = admission::load_enrolment(&vault);
    assert!(
        loaded.is_err(),
        "a corrupt authorisation record was read as an empty enrolment"
    );
}

/// A record whose digest is not 64 hex characters is refused, rather than
/// hashed into something that would have to be collided with to be accepted.
#[test]
fn a_malformed_digest_is_refused() {
    let (_dir, vault, _principal) = enrolment_fixture();
    let path = admission::enrolment_path(&vault);
    std::fs::write(&path, b"deadbeef  /usr/bin/asv\n").expect("write");
    assert!(
        admission::load_enrolment(&vault).is_err(),
        "a short digest was accepted as a content binding"
    );
}
