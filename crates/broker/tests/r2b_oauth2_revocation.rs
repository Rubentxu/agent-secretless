//! R2.B — a credential deletion is a revocation, not a message.
//!
//! # The gap
//!
//! `Request::DeleteCredential` removed the vault record and revoked the
//! session's surrogates, and answered `CredentialDeleted`. It never reached
//! into the secret port — so an OAuth2 access token that `OAuth2SecretPort` had
//! already exchanged and cached kept being served for the remainder of its
//! `expires_in`. The operator was told the credential was gone, and the broker
//! kept lending its token.
//!
//! It was not reachable as written, and that is the part worth recording.
//! `BrokerState` holds `Arc<dyn SecretPort>`, the concrete type is erased
//! behind a `RoutingSecretPort`, and the trait had no method to call. Adding a
//! `forget` with a default no-op would have been one line and would have left
//! the property resting on every future port author remembering to override it.
//! It is required instead, with no default: a new `SecretPort` does not compile
//! until it has said what it does with derived secrets.
//!
//! # What is real here
//!
//! A real `BrokerState`, a real `VaultStore` and `VaultWritePort`, the real
//! admission predicate from ADR-0015, the real `RoutingSecretPort` over the
//! real `OAuth2SecretPort`, and a real issuer behind the factory. The only
//! fixture is the issuer, which is deterministic so the rows can count grants
//! instead of comparing token bytes.
//!
//! The counter, not the token, is the observable throughout. A deterministic
//! issuer is content-addressed, so a second grant produces identical bytes and
//! a test watching the bytes would pass whether the cache was used or not —
//! the same shape of hole as a test that watches a struct instead of the wire.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asv_broker::admission::{self, Enrolment};
use asv_broker::oauth2::{DeterministicTokenIssuer, OAuth2Config, OAuth2Error, OAuth2Issuer};
use asv_broker::oauth2_port::{
    OAuth2Client, OAuth2IssuerFactory, OAuth2SecretPort, RoutingSecretPort,
};
use asv_broker::{BrokerState, VaultSecretPort, VaultWritePort};
use asv_domain::SecretBytes;
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{Request, Response};
use asv_vault::{KdfParams, VaultKey, VaultStore};
use secrecy::SecretString;

/// The first credential. Deleted by the first two rows.
const CRED_A: &str = "a1b2c3d4-0000-4000-8000-00000000000a";
/// The second credential. Exists so a blanket "clear everything" cannot pass.
const CRED_B: &str = "a1b2c3d4-0000-4000-8000-00000000000b";

/// A third credential, used only by the refusal row. It is registered, it
/// caches a token, and it is then removed from the vault *directly*, so a later
/// `DeleteCredential` for it takes the refusal path with a live cache entry.
///
/// Without that last part the row proves nothing: forgetting a name nobody
/// holds is harmless, so a broker that forgot on the refusal path would pass a
/// test that only used an unrelated id. The first version of this row did
/// exactly that, and the mutation it was written to catch did not turn it red.
const CRED_C: &str = "a1b2c3d4-0000-4000-8000-00000000000c";

/// Distinct `client_id`s, because the per-client grant counter is keyed on the
/// id: `OAuth2Config` does not carry the credential name.
const CLIENT_ID_A: &str = "asv-broker-a";
const CLIENT_ID_B: &str = "asv-broker-b";
const CLIENT_ID_C: &str = "asv-broker-c";

/// Grants actually requested from the provider, across every client.
///
/// Per-client rather than global, because "did the provider get asked again"
/// is only meaningful if it is asked about *the credential under test*. One
/// counter for the whole suite would let a re-exchange of the other client
/// mask a cache that was never dropped.
#[derive(Default)]
struct Grants {
    total: AtomicUsize,
    a: AtomicUsize,
    b: AtomicUsize,
    c: AtomicUsize,
}

impl Grants {
    fn for_client_id(&self, client_id: &str) -> &AtomicUsize {
        match client_id {
            CLIENT_ID_A => &self.a,
            CLIENT_ID_B => &self.b,
            CLIENT_ID_C => &self.c,
            other => panic!("the fixture has no counter for {other}"),
        }
    }
}

struct Factory(Arc<Grants>);

impl OAuth2IssuerFactory for Factory {
    fn issuer(&self, config: OAuth2Config) -> Result<Box<dyn OAuth2Issuer>, OAuth2Error> {
        self.0.total.fetch_add(1, Ordering::SeqCst);
        // `OAuth2Config` carries no credential name — it is the provider-side
        // shape, and the credential is the port's own key. So the per-client
        // counter is keyed on `client_id`, and the fixture gives each client a
        // distinct one. Sharing an id would have made "was the provider asked
        // about *this* client again" unanswerable, which is the whole question
        // the rows below ask.
        self.0
            .for_client_id(&config.client_id)
            .fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(DeterministicTokenIssuer::new(config)))
    }
}

/// A sink that records only that it was called, and with how many bytes.
///
/// The bytes are never kept. A row that failed would print them, and this is a
/// file about a token that must not end up in anyone's terminal.
#[derive(Debug)]
struct Called {
    calls: usize,
    len: usize,
}

impl asv_connector_http::SecretSink for Called {
    fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
        self.calls += 1;
        self.len += secret.len();
        Ok(())
    }
}

struct Broker {
    state: BrokerState,
    grants: Arc<Grants>,
    peer: WorkloadIdentity,
    _dir: tempfile::TempDir,
}

impl Broker {
    /// Removes a record from the vault without going through the verb.
    ///
    /// Only the refusal row uses this, and only to construct the one state it
    /// needs: a credential that the port will still answer for, that still has
    /// a cached token, and that the vault no longer holds. There is no other
    /// way to reach the `NotFound` refusal path with something to lose.
    fn remove_behind_the_broker(&self, id: &str) {
        self.state
            .vault_writer
            .as_ref()
            .expect("the fixture wired a writer")
            .remove(id)
            .expect("the record is there to remove");
    }
}

impl Broker {
    /// A broker with two registered OAuth2 clients, both present in the vault.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase = SecretString::from("r2b-passphrase".to_string());

        let mut store = VaultStore::create(
            dir.path().join("v.asv"),
            &passphrase,
            KdfParams::fast_for_tests(),
        )
        .expect("create vault");
        let key: Arc<VaultKey> = Arc::new(
            store
                .header()
                .unlock(&passphrase)
                .expect("unlock with the passphrase just used"),
        );

        for (id, label) in [(CRED_A, "r2b-a"), (CRED_B, "r2b-b"), (CRED_C, "r2b-c")] {
            store
                .insert(
                    &key,
                    asv_vault::CredentialMetadata::new(
                        id,
                        label,
                        asv_vault::CredentialKind::Opaque,
                        "oauth2",
                        "Rubentxu",
                        1,
                    ),
                    SecretBytes::new(b"client-secret-bytes".to_vec()),
                )
                .expect("insert");
        }

        let store = Arc::new(Mutex::new(store));
        let vault: Arc<dyn asv_connector_http::SecretPort> =
            Arc::new(VaultSecretPort::new(Arc::clone(&store), Arc::clone(&key)));

        let grants = Arc::new(Grants::default());
        let oauth2 = Arc::new(
            OAuth2SecretPort::with_parts(
                Arc::clone(&vault),
                vec![
                    client(CRED_A, CLIENT_ID_A),
                    client(CRED_B, CLIENT_ID_B),
                    client(CRED_C, CLIENT_ID_C),
                ],
                Arc::new(Factory(Arc::clone(&grants))),
            )
            // Well under the issuer's `expires_in` of 3600s, so the cache
            // actually holds something.
            //
            // The first version of this fixture used 3600s — thinking a
            // generous margin was the safe direction — and every row failed with
            // the grant count at 2 instead of 1. `serve_for` is
            // `expires_in.checked_sub(margin)`, so a margin at or above
            // `expires_in` returns `Duration::ZERO` and the port **silently stops
            // caching**. Nothing logs it and nothing refuses it; the symptom is
            // only that a token is re-exchanged more often than expected, which
            // reads as a provider problem and is not one. Worth a comment here
            // because the knob's safe direction is not the obvious one.
            .with_margin(Duration::from_secs(60)),
        );

        let mut state = BrokerState::default();
        state.vault_writer = Some(Arc::new(VaultWritePort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));
        // The routing port behind a trait object: the shape `DeleteCredential`
        // can only reach through the method this change added.
        state.secrets = Some(Arc::new(RoutingSecretPort::new(
            Arc::clone(&oauth2) as Arc<dyn asv_connector_http::SecretPort>,
            Arc::clone(&vault),
        )));

        // The real admission predicate, satisfied the same way
        // `credential_create_path` satisfies it: by enrolling the binary that is
        // actually running. Faking the third condition instead would make this
        // file a test of a bypass.
        let exe = std::fs::canonicalize(std::env::current_exe().expect("current_exe"))
            .expect("canonical");
        let bytes = std::fs::read(&exe).expect("read exe");
        state.control_plane = Enrolment::empty().enrol(exe, admission::sha256(&bytes));

        let mut peer = WorkloadIdentity::from_peer(asv_identity::PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pin this test's own process");

        Self {
            state,
            grants,
            peer,
            _dir: dir,
        }
    }

    /// Lends `credential` through the state, the way a connector would.
    fn lend(&self, credential: &str) -> Result<Called, asv_connector_http::SecretError> {
        let mut sink = Called { calls: 0, len: 0 };
        self.state
            .secrets
            .as_ref()
            .expect("the fixture wired a port")
            .lend(credential, &mut sink)?;
        Ok(sink)
    }

    /// Grants the provider has actually issued for one credential.
    fn grants_for(&self, credential: &str) -> usize {
        let client_id = match credential {
            CRED_A => CLIENT_ID_A,
            CRED_B => CLIENT_ID_B,
            CRED_C => CLIENT_ID_C,
            other => panic!("the fixture has no counter for {other}"),
        };
        self.grants.for_client_id(client_id).load(Ordering::SeqCst)
    }

    fn delete(&mut self, id: &str) -> Response {
        asv_broker::handle(
            &mut self.state,
            &self.peer,
            Request::DeleteCredential {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
                id: asv_domain::CredentialId::from_wire(id).expect("canonical wire form"),
            },
        )
    }
}

fn client(credential: &str, client_id: &str) -> OAuth2Client {
    OAuth2Client {
        credential: credential.to_string(),
        client_id: client_id.to_string(),
        token_url: "https://idp.example.com/token".to_string(),
        audience: "https://api.example.com".to_string(),
        scope: "read".to_string(),
    }
}

// ---------------------------------------------------------------------------

/// `forget` through the trait really empties the cache.
///
/// The mechanism, isolated from the deletion, because the deletion has a
/// confound: once the vault record is gone, `exchange` fails inside
/// `config_for` — *before* the issuer factory is ever reached — so the grant
/// counter cannot move either way and cannot tell the two behaviours apart. The
/// first version of this row asserted that counter and failed for exactly that
/// reason, which is worth recording because the wrong observable here looks
/// like a broken product rather than a broken assertion.
///
/// So this row asks the question with no confound in it: the credential is
/// still in the vault, so a re-exchange *would* succeed if the cache were
/// empty, and the grant count is the witness.
///
/// **Mutation:** make `OAuth2SecretPort::forget` not remove from the cache, and
/// this goes red at "the provider was asked again" — the count stays at 1.
#[test]
fn forget_through_the_trait_empties_the_cache() {
    let broker = Broker::new();

    broker.lend(CRED_A).expect("the first lend exchanges");
    broker
        .lend(CRED_A)
        .expect("the second lend is served from the cache");
    assert_eq!(
        broker.grants_for(CRED_A),
        1,
        "the cache did not answer the second lend, so this row cannot tell an          emptied cache from an issuer that re-exchanges every time"
    );

    let held = broker.state.secrets.as_ref().expect("a port is wired");
    held.forget(CRED_A);

    broker
        .lend(CRED_A)
        .expect("the vault still has the client, so this succeeds");
    assert_eq!(
        broker.grants_for(CRED_A),
        2,
        "the provider was not asked again, so the token was served out of a cache          that was supposed to have been dropped"
    );
}

/// Deleting a credential stops the cached token being served, and the answer
/// says which way it went.
///
/// This is the row that answers "what mutation makes it red", and the
/// discriminator is the **sink**, not the grant count. `OAuth2SecretPort::lend`
/// checks the cache *before* it reads the vault, so:
///
/// - cache survived → `cached()` returns `Some` → `Ok`, the sink is handed the
///   stale token, and the deletion was a message;
/// - cache dropped → the vault read fails → `Err`, and the sink is never called.
///
/// Both outcomes are an error from the operator's point of view, and only one
/// of them is a revocation. The row asserts the sink was not called, which is
/// what separates them.
///
/// **Mutation:** make `DeleteCredential` stop calling `secrets.forget`, and this
/// goes red — `lend` returns `Ok` with the token the deleted credential had.
///
/// **Mutation:** make `forget` a no-op, and it goes red the same way.
#[test]
fn deleting_a_credential_stops_its_cached_token_being_served() {
    let mut broker = Broker::new();

    broker.lend(CRED_A).expect("the first lend exchanges");
    let cached = broker
        .lend(CRED_A)
        .expect("the second lend is served from cache");
    assert_eq!(cached.calls, 1, "precondition: the cache really answered");
    assert_eq!(
        broker.grants_for(CRED_A),
        1,
        "precondition: one grant so far"
    );

    let deleted = broker.delete(CRED_A);
    assert!(
        matches!(deleted, Response::CredentialDeleted { .. }),
        "the deletion must succeed on a credential the vault holds, got {deleted:?}"
    );

    // The vault record is gone, so *some* failure is expected. The question is
    // which one, and only the sink answers it.
    let after = broker.lend(CRED_A);
    match after {
        Ok(sink) => panic!(
            "the deleted credential's cached token was served: the sink was called \
             {} time(s) with {} bytes, so `CredentialDeleted` was a message and not \
             a revocation",
            sink.calls, sink.len
        ),
        Err(error) => {
            // `NotFound` rather than `Unavailable`: the record is gone, and a
            // provider that could not be reached would be a different condition
            // sending an operator to a different place.
            assert!(
                matches!(error, asv_connector_http::SecretError::NotFound(_)),
                "a deleted credential must fail as absent, got {error:?}"
            );
        }
    }
}

/// A refused deletion must not forget anything — and the thing it must not
/// forget is a live token.
///
/// The cheap wrong fix. "Clear the token cache when someone calls
/// `DeleteCredential`" reads as harmless and is not. The vault write is the
/// thing that decides; `forget` may only follow a write that happened. A
/// broker that forgets on the refusal path lets anyone who can reach the verb
/// drop the cache for a credential that is still perfectly valid, and the next
/// operation silently re-exchanges it.
///
/// **The first version of this row could not catch that**, and the mutation it
/// was written for did not turn it red. It used an id that had no cache entry
/// at all, so forgetting it was harmless and the wrong implementation passed.
/// The row now constructs the state that makes the ordering observable: `C`
/// is registered, its token is cached, and its vault record is then removed
/// *directly through the writer* — so `DeleteCredential` for `C` takes the
/// refusal path while `C` still has a live entry to lose.
///
/// **Mutation:** call `secrets.forget` on the `NotFound` refusal path, and this
/// goes red.
#[test]
fn a_refused_deletion_does_not_forget_a_live_token() {
    let mut broker = Broker::new();

    // C caches a token, and the grant count proves the cache is answering.
    broker.lend(CRED_C).expect("c exchanges");
    broker.lend(CRED_C).expect("c is served from the cache");
    assert_eq!(
        broker.grants_for(CRED_C),
        1,
        "precondition: the cache answered"
    );

    // The record goes away without the verb seeing it, so the verb's own write
    // is what fails.
    broker.remove_behind_the_broker(CRED_C);

    let refused = broker.delete(CRED_C);
    assert!(
        matches!(
            refused,
            Response::Error {
                code: asv_ipc_protocol::ErrorCode::InvalidRequest,
                ..
            }
        ),
        "a deletion for a record the vault does not hold must be refused, got {refused:?}"
    );

    // C's token is still cached and must still be served from it.
    let after = broker
        .lend(CRED_C)
        .expect("a refused deletion must not have touched C's cache");
    assert_eq!(
        after.calls, 1,
        "the sink must have received the cached token"
    );
    assert_eq!(
        broker.grants_for(CRED_C),
        1,
        "a refused deletion reached the token cache; anyone who can reach the \
         verb could then re-exchange every credential in the vault"
    );
}

/// Deleting one credential leaves another's cached token alone.
///
/// The other cheap wrong fix, and the one a "just clear the map" patch makes.
/// `forget` is keyed by name. If it flushed, then deleting one credential would
/// silently invalidate every other live one — a denial of service delivered
/// through a privacy operation, and one an operator has no way to diagnose from
/// the answer they got.
///
/// **Mutation:** make `forget` call `cache.clear()` instead of
/// `cache.remove(credential)`, and this goes red.
#[test]
fn deleting_one_credential_leaves_another_credential_served() {
    let mut broker = Broker::new();

    broker.lend(CRED_A).expect("a exchanges");
    broker.lend(CRED_B).expect("b exchanges");
    broker.lend(CRED_A).expect("a from cache");
    broker.lend(CRED_B).expect("b from cache");
    assert_eq!(
        (broker.grants_for(CRED_A), broker.grants_for(CRED_B)),
        (1, 1)
    );

    let deleted = broker.delete(CRED_A);
    assert!(
        matches!(deleted, Response::CredentialDeleted { .. }),
        "precondition: the deletion must succeed, got {deleted:?}"
    );

    // B is untouched, and still served from its own cache.
    broker.lend(CRED_B).expect("b is still served");
    assert_eq!(
        broker.grants_for(CRED_B),
        1,
        "deleting A invalidated B's cached token; a privacy operation is not a \
         denial of service against every other live credential"
    );
    // A is gone, so its counter is not a meaningful observable here: the vault
    // read fails inside `config_for` before the issuer is reached. Row 1 is
    // where the count is the right witness.
}

/// The trait makes the property structural, and that is checkable.
///
/// `forget` has no default. The rows above prove the wiring works; this one
/// proves the *next* port cannot skip it, and the way to prove that is to say
/// what would not compile. A comment cannot fail, so this asserts the shape
/// that does: the three production ports each answer for themselves, and the
/// broker reaches them through `Arc<dyn SecretPort>` rather than a concrete
/// type — which is the only reason the call is reachable at all.
///
/// **Mutation:** give `SecretPort::forget` a default body, and this test still
/// compiles, which is exactly the point: the guarantee moves from the compiler
/// to a convention, and nothing in the suite can see that happen. That is why
/// the guarantee is the absence of a default and this row is only its
/// documentation.
#[test]
fn every_port_answers_for_itself_and_the_broker_only_holds_the_trait() {
    let broker = Broker::new();

    // The state holds a trait object, not the concrete port. If this ever
    // becomes `Option<OAuth2SecretPort>`, the erasure is gone and `DeleteCredential`
    // can only reach the OAuth2 port by a second, type-specific field.
    let held = broker.state.secrets.as_ref().expect("a port is wired");
    let _: &dyn asv_connector_http::SecretPort = held.as_ref();

    // `forget` is callable through the trait, and each port has made a
    // decision. Calling it on a name nobody holds must be harmless, because
    // `DeleteCredential` cannot know which wrapped port holds what.
    held.forget("a-name-no-port-has");
    broker
        .lend(CRED_A)
        .expect("a forget for an unknown name changed nothing");
    assert_eq!(
        broker.grants_for(CRED_A),
        1,
        "forgetting an unheld name dropped a live cache entry"
    );
}
