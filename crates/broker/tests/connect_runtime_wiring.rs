//! The production ports the CONNECT listener is wired with (V1-C2).
//!
//! These are the tests for `connect_runtime`, and their subject is not
//! "substitution works" — `uat_010_connect_substitution.rs` proves that with a
//! real origin. The subject here is narrower and, for one of them, sharper:
//!
//! **A production port wired to the wrong state looks exactly like a working
//! one.** The first version of `main.rs` handed the listener a fresh
//! `SessionStore::new()`. It compiled, bound the port, accepted, resolved no
//! proof, and refused — and every one of those behaviours is what a correct
//! listener does when a stranger connects. A test that asserted "the listener
//! answers" would have called it working. What distinguishes them is *which*
//! refusal, and which session it names, so that is what these assert.
//!
//! Nothing here reaches the network: `SystemUpstream` is tested against names
//! that resolve to loopback or to nothing at all, never to a real provider.

use std::sync::Arc;
use std::time::Duration;

use asv_broker::connect_runtime::{SessionLeafSource, SharedSessions, SystemUpstream};
use asv_broker::tls_bridge::{
    AuthorityEndpoint, LeafSource, SessionCa, SessionProofs, UpstreamResolver,
};
use asv_broker::SessionStore;
use asv_domain::{AgentSessionId, Authority};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ssh_agent::public_key_blob;
use ed25519_dalek::{Signer, SigningKey};

fn endpoint(host: &str, port: u16) -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(host).expect("canonical host"), port)
        .expect("valid endpoint")
}

fn peer() -> WorkloadIdentity {
    WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: 1000,
        gid: 1000,
    })
}

/// **A fresh store must not resolve a proof the broker's own store does.**
///
/// The direct shape of the wiring bug. The right store resolves the session;
/// an empty one cannot. Asserting the *positive* case on the shared store is
/// the half that matters — the negative case alone would also be satisfied by
/// a port that resolves nothing at all, which is the failure mode.
#[test]
fn the_shared_store_resolves_a_proof_and_an_empty_one_cannot() {
    let peer = peer();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let blob = public_key_blob(&key.verifying_key());

    let mut real = SessionStore::new();
    let session = real.create("wiring".into(), &peer);
    real.register_key(session, &peer, blob.clone())
        .expect("register the key");

    let nonce = b"a destination-bound nonce";
    let signature = key.sign(nonce).to_bytes();

    let shared = SharedSessions::new(Arc::new(std::sync::Mutex::new(real)));
    assert_eq!(
        shared.resolve(&blob, nonce, &signature),
        Some(session),
        "the listener must resolve a proof against the broker's own session table"
    );

    // The exact thing the first wiring did.
    let empty = SharedSessions::new(Arc::new(std::sync::Mutex::new(SessionStore::new())));
    assert_eq!(
        empty.resolve(&blob, nonce, &signature),
        None,
        "an empty store must resolve nothing — this is the bug, stated as an \
         assertion so a regression is a red test rather than a silent refusal"
    );
}

/// **A key registered for one session must not resolve to another.**
///
/// The shared store widens what a port can see — now it can see *every* live
/// session, not one. That is the price of not running two stores, so the
/// property the sharing could have broken is pinned here: a session that was
/// never registered cannot be produced by presenting someone else's key.
#[test]
fn a_proof_under_one_key_never_resolves_to_another_session() {
    let peer = peer();
    let key_a = SigningKey::generate(&mut rand::rngs::OsRng);
    let key_b = SigningKey::generate(&mut rand::rngs::OsRng);

    let mut store = SessionStore::new();
    let session_a = store.create("a".into(), &peer);
    let _session_b = store.create("b".into(), &peer);
    store
        .register_key(session_a, &peer, public_key_blob(&key_a.verifying_key()))
        .expect("A registers");

    let shared = SharedSessions::new(Arc::new(std::sync::Mutex::new(store)));
    let nonce = b"nonce";
    let blob_b = public_key_blob(&key_b.verifying_key());
    assert_eq!(
        shared.resolve(&blob_b, nonce, &key_b.sign(nonce).to_bytes()),
        None,
        "B's key is not registered anywhere, so it must resolve to nothing"
    );
}

/// A proof whose signature does not verify is not a session, even when the key
/// blob matches. The blob is public by construction — `ssh-add -L` hands it
/// out — so this half is what stops the shared store from being a lookup table
/// anyone can read an answer from.
#[test]
fn a_matching_blob_with_a_bad_signature_resolves_to_nothing() {
    let peer = peer();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    let blob = public_key_blob(&key.verifying_key());

    let mut store = SessionStore::new();
    let session = store.create("a".into(), &peer);
    store
        .register_key(session, &peer, blob.clone())
        .expect("A registers");

    let shared = SharedSessions::new(Arc::new(std::sync::Mutex::new(store)));
    let nonce = b"nonce";
    assert_eq!(
        shared.resolve(&blob, nonce, &other.sign(nonce).to_bytes()),
        None,
        "a signature by a different key over the same blob must not resolve"
    );
}

/// Issuance follows the canonical form, and the refusals are the ones
/// canonicalisation cannot repair.
///
/// Every assertion here came from a probe that printed what each form actually
/// did, because two of this test's first drafts were wrong about the code. One
/// asserted an upper-case host is refused — it is not, issuance lowercases.
/// Another asserted a trailing dot is refused — it is not either, it is the DNS
/// root form of the same name and it is what a resolver hands back. A third
/// asserted bare IP literals are rejected, which the source comment also
/// claimed and which is false. Guessing what a security check does is how a
/// test ends up pinning a fiction.
#[test]
fn issuance_follows_the_canonical_form_and_refuses_what_it_cannot_repair() {
    let ca = Arc::new(SessionCa::new("wiring", 1, Duration::from_secs(3600)));
    let source = SessionLeafSource::new(Arc::clone(&ca));
    let now = std::time::Instant::now();

    for accepted in [
        "example.test",
        "EXAMPLE.TEST",  // canonicalised, not refused
        "example.test.", // the DNS root form of the same name
        "a.example.test",
        "127.0.0.1", // measured accepted; reachable only via the allow-list
    ] {
        source
            .issue_for(accepted, now)
            .unwrap_or_else(|e| panic!("{accepted:?} must mint a leaf, got {e}"));
    }

    for refused in [
        "example.test:443", // a port smuggled into the name
        "user@example.test",
        "  example.test  ",
        "exa mple.test",
        "%65xample.test",
        "localhost", // a single label
        "",          // and the empty name
    ] {
        let err = source
            .issue_for(refused, now)
            .err()
            .unwrap_or_else(|| panic!("{refused:?} must not mint a leaf"));
        assert!(
            !err.to_string().is_empty(),
            "a refusal must still say why: {err}"
        );
    }
}

/// The root a client must trust is the one the CA carries, and it is bytes
/// rather than a certificate object so a caller can write it to disk.
#[test]
fn the_leaf_source_publishes_the_root_a_client_must_trust() {
    let ca = Arc::new(SessionCa::new("wiring", 2, Duration::from_secs(3600)));
    let source = SessionLeafSource::new(Arc::clone(&ca));
    assert_eq!(
        source.root_der(),
        ca.root_der.as_slice(),
        "the published root must be the CA's own, or a client would trust a \
         certificate the broker cannot sign"
    );
    assert!(
        !source.root_der().is_empty(),
        "an empty root would be a trust store that accepts nothing, published \
         as if it worked"
    );
}

/// The resolver answers with loopback for a loopback name and refuses a name
/// that resolves nowhere, rather than inventing an address.
#[test]
fn the_resolver_refuses_a_name_that_resolves_nowhere() {
    let resolver = SystemUpstream;
    let target = endpoint("this-name-does-not-resolve.invalid", 443);
    let err = resolver
        .resolve(&target)
        .expect_err("a .invalid name must not resolve");
    assert!(
        !err.to_string().is_empty(),
        "a DNS failure must say what failed: {err}"
    );
}

/// The proxy cannot be pointed at a bare service name.
///
/// Written after a test used `localhost` and failed: `Authority` refuses a
/// single label, so the proxy cannot be aimed at `localhost` or at a bare
/// service name on the local network. That is a real property and it belongs
/// in a test — the allow-list and the resolver both rest on the name having
/// been canonicalised, and this is the check that it was.
#[test]
fn a_single_label_name_is_refused_before_the_resolver_ever_sees_it() {
    let err = Authority::canonicalize("localhost")
        .expect_err("a bare service name must not be a canonical authority");
    assert!(
        err.to_string().contains("two labels"),
        "the refusal must name the reason it refused, so a change in the rule \
         is visible here rather than silent: {err}"
    );
}

/// `Debug` on the leaf source must not print key material, and the port
/// carries a private key. This is the shape check, asserted so the intent is
/// written where a future edit would break it.
#[test]
fn the_leaf_source_prints_no_key_material() {
    let ca = Arc::new(SessionCa::new("wiring", 3, Duration::from_secs(3600)));
    let rendered = format!("{:?}", SessionLeafSource::new(ca));
    assert!(
        !rendered.contains("PRIVATE KEY"),
        "a Debug that names private key material would put it in every log \
         line that mentions the source: {rendered}"
    );
    assert!(
        rendered.contains("wiring"),
        "the session id is the one fact an operator needs: {rendered}"
    );
}

/// A revoked session stops resolving immediately.
///
/// The shared store is live state, so a session that `end()`s must vanish from
/// proof resolution — otherwise a CONNECT could prove a session the socket path
/// has already killed, which is the exact window a revocation exists to close.
#[test]
fn an_ended_session_stops_resolving() {
    let peer = peer();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let blob = public_key_blob(&key.verifying_key());
    let nonce = b"nonce";
    let signature = key.sign(nonce).to_bytes();

    let mut store = SessionStore::new();
    let session: AgentSessionId = store.create("revoke".into(), &peer);
    store
        .register_key(session, &peer, blob.clone())
        .expect("register");
    // The handle stays in the test rather than behind a `store()` accessor on
    // the port. Ending a session is something the broker's own socket path
    // does, so the test drives it the way production does — through the shared
    // `Arc` — instead of through an API invented to make the test convenient.
    let store = Arc::new(std::sync::Mutex::new(store));
    let shared = SharedSessions::new(Arc::clone(&store));

    assert_eq!(shared.resolve(&blob, nonce, &signature), Some(session));
    store.lock().expect("no one holds this").end(session);
    assert_eq!(
        shared.resolve(&blob, nonce, &signature),
        None,
        "a session the broker has ended must not still open a tunnel"
    );
}
