//! UAT-017 — broker crash.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`):
//!
//! > Kill broker during protected operation.
//! > Expected: operation fails closed; no fallback to raw environment
//! > credentials.
//!
//! The second clause is the one that matters and the one that is easy to
//! satisfy by accident. "Fails closed" has a cheap reading — return an
//! error — that any implementation passes while still reaching for
//! `GITHUB_TOKEN` the moment the broker is gone. So these tests assert the
//! negative: the credential is not obtainable from the crashed-broker path,
//! and no response is produced that looks like success.
//!
//! # What "the broker is dead" means here
//!
//! `handle` is a pure function over `&mut BrokerState`, so this suite
//! exercises the two ways a broker can actually stop answering a client,
//! both of which the transport layer funnels into an error:
//!
//! 1. **The process is gone.** A `UnixStream::connect` to a socket with no
//!    listener returns `ECONNREFUSED`, and a connect to a socket whose
//!    listener vanished mid-read returns `UnexpectedEof` or `ECONNRESET`.
//!    Neither is a `Response`; the client cannot mistake either for a
//!    result.
//! 2. **The state is gone.** The broker is alive but the `BrokerState` is
//!    unreachable or default. A default state has `secrets: None`, and this
//!    is the dangerous case: a broker that is *running* but has no vault
//!    could plausibly be coded to degrade. It must refuse instead.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use asv_broker::{handle, BrokerState};
use asv_domain::SecretBytes;
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_vault::{KdfParams, VaultStore};

/// A credential the environment is known to contain, and which must never
/// appear in anything this suite produces.
const CANARY: &str = "ghp_CANARY_MUST_NEVER_LEAK_broker_crash";

fn temp_socket(tag: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("asv-uat017-{}-{tag}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("broker.sock")
}

/// Mints a surrogate the way a real agent does: over the public IPC surface,
/// through a pinned session and a real credential.
///
/// Going through `Request` rather than poking `SurrogateRegistry` is
/// deliberate. A test that calls the registry directly would pass even if
/// the broker's own mint path had been removed, and the properties under
/// test here are properties of the broker, not of a struct field.
fn state_with_live_session() -> (
    BrokerState,
    WorkloadIdentity,
    String,
    asv_domain::AgentSessionId,
) {
    state_with_session_id()
}

/// As above, but also hands back the session id, which the restart tests
/// need in order to assert that a fresh broker does not re-pin it.
fn state_with_session_id() -> (
    BrokerState,
    WorkloadIdentity,
    String,
    asv_domain::AgentSessionId,
) {
    let mut state = BrokerState::default();
    // The inventory is projected from a real vault record rather than seeded
    // through a test-only helper, so the credential a minted surrogate is
    // bound to came from the same path production uses. The vault is then
    // dropped and `state.secrets` is deliberately left `None`: that is the
    // condition this suite exists to pin, and a broker that could mint and
    // then read would have everything it needs to degrade.
    const CRED: &str = "3c4d5e6f-7081-4293-a4b5-c6d7e8f9012a";
    let credential = asv_domain::CredentialId::from_wire(CRED).expect("canonical wire form");
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = secrecy::SecretString::from("uat017-pass".to_string());
        let mut store =
            VaultStore::create(dir.path().join("v.asv"), &pass, KdfParams::fast_for_tests())
                .expect("create vault");
        let key = store.header().unlock(&pass).expect("unlock");
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    CRED,
                    "github-work",
                    asv_vault::CredentialKind::Opaque,
                    "github",
                    "o",
                    1,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert");
        asv_broker::inventory::load(&mut state, &store);
    }
    assert_eq!(
        state.credentials.lock().expect("not poisoned").len(),
        1,
        "the fixture vault holds exactly one canonical credential"
    );

    let peer = pinned_peer();
    let session = state
        .sessions
        .lock()
        .expect("no test holds this")
        .create("uat017".into(), &peer);

    let minted = handle(
        &mut state,
        &peer,
        Request::MintSurrogate {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            credential,
            ttl_secs: 300,
            max_uses: 5,
        },
    );

    let token = match minted {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("the fixture must be able to mint; got {other:?}"),
    };
    (state, peer, token, session)
}

// ---------------------------------------------------------------------------
// 1. The client cannot invent a response when the broker is not there.
// ---------------------------------------------------------------------------

/// The exact sequence a client performs: connect, write, read. With no
/// listener the connect fails, and the test asserts the *kind* of failure,
/// because "returns some error" is too weak to be a security property —
/// a client that mapped a dead broker to `Response::Ok` with empty
/// contents would pass a looser assertion.
#[test]
fn connecting_to_a_dead_broker_is_a_transport_error_not_a_response() {
    let path = temp_socket("absent");

    let result = std::os::unix::net::UnixStream::connect(&path);

    assert!(
        result.is_err(),
        "connecting to {path:?} must fail when no broker is listening; a successful \
         connect would mean something is squatting on the broker socket"
    );
    let error = result.unwrap_err();
    assert!(
        matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::ConnectionRefused
        ),
        "expected a not-found or refused error, got {:?}",
        error.kind()
    );
}

/// A broker that dies *after* accepting is the harder case: the connect
/// succeeds, the write succeeds, and then the read returns nothing. The
/// client's own guard is what turns that into a failure, and this test
/// pins the guard's contract: zero bytes is an error, never an empty
/// success.
#[test]
fn a_broker_that_dies_mid_request_yields_no_response() {
    let path = temp_socket("mid-flight");

    // A listener that accepts one connection and then drops it without
    // replying. This is exactly what a killed broker looks like to a
    // client that had already connected.
    let listener = UnixListener::bind(&path).expect("bind");
    let accepted = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read whatever the client sent, then vanish.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            drop(stream);
        }
    });

    let mut stream = std::os::unix::net::UnixStream::connect(&path).expect("connect");
    let request = Request::Ping { protocol: 1 };
    let payload = serde_json::to_vec(&request).expect("serialize");
    stream.write_all(&payload).expect("write");
    stream.flush().expect("flush");

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream
        .read(&mut buf)
        .expect("read returns a result, not a panic");

    accepted.join().expect("listener thread");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        n, 0,
        "a broker that died without answering must produce zero bytes; {n} bytes means \
         the client would have to decide what a partial reply means"
    );
    // And the zero bytes must not parse as a successful response, which is
    // the whole point: there is nothing for the caller to mistake for a
    // result.
    let decoded: Result<Response, _> = serde_json::from_slice(&buf[..n]);
    assert!(
        decoded.is_err(),
        "an empty body must not decode as a Response, got {decoded:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. A live broker with no vault refuses rather than degrading.
// ---------------------------------------------------------------------------

/// The fail-closed property with the broker alive and reachable, which is
/// strictly harder than the crash case.
///
/// A `BrokerState::default()` has no secret port. The obvious "helpful"
/// implementation of a semantic GitHub operation at this point is to reach
/// for the ambient token, because the operation is well-formed and the
/// only thing missing is a credential. The test pins that it does not.
#[test]
fn a_live_broker_without_a_vault_refuses_instead_of_degrading() {
    let (mut state, peer, token, session) = state_with_live_session();
    assert!(
        state.secrets.is_none(),
        "the default state must have no vault, or this test proves nothing"
    );

    // Every semantic operation, not just one: a fallback implemented in
    // `CreateIssue` but not in `ReadIssue` is still a fallback.
    for request in [
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token.clone(),
            repo: "owner/repo".into(),
            number: 1,
        },
        Request::CreateIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token.clone(),
            repo: "owner/repo".into(),
            title: "t".into(),
            body: "b".into(),
        },
        Request::CreateRelease {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token.clone(),
            repo: "owner/repo".into(),
            tag: "v1".into(),
            name: "n".into(),
            body: "b".into(),
        },
    ] {
        let response = handle(&mut state, &peer, request.clone());
        assert!(
            matches!(
                response,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "{request:?} must be Denied with no vault open, got {response:?}. Anything \
             other than Denied means the broker found a way to proceed without the \
             credential it refused to have."
        );
    }
}

/// The refusal message must say *why*, because "Denied" alone is what a
/// user sees when they mistyped a repository, and the two situations need
/// opposite responses. This also pins that the message does not leak the
/// canary or any path to it.
#[test]
fn the_refusal_explains_the_missing_vault_without_leaking() {
    let (mut state, peer, token, session) = state_with_live_session();

    let response = handle(
        &mut state,
        &peer,
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token,
            repo: "owner/repo".into(),
            number: 1,
        },
    );

    let message = match &response {
        Response::Error { message, .. } => message.clone(),
        other => panic!("expected an error, got {other:?}"),
    };

    assert!(
        message.contains("vault") || message.contains("credential store"),
        "the refusal must name the missing vault, got {message:?}"
    );
    assert!(
        !message.contains(CANARY),
        "the refusal leaked the canary: {message:?}"
    );
}

/// The canary is in the environment for the whole test binary, and the
/// broker's own `Debug` is what ends up in a crash report. Neither the
/// rendered state nor the rendered response may contain it.
#[test]
fn a_dead_broker_leaves_nothing_printable_behind() {
    // Put the canary in the environment the way a real deployment would.
    // Safety: single-threaded setup before the assertions, and the scan
    // test in this crate proves production code never reads it.
    std::env::set_var("GITHUB_TOKEN", CANARY);

    let (mut state, peer, token, session) = state_with_live_session();

    let response = handle(
        &mut state,
        &peer,
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token,
            repo: "owner/repo".into(),
            number: 1,
        },
    );

    let rendered_state = format!("{state:?}");
    let rendered_response = format!("{response:?}");

    assert!(
        !rendered_state.contains(CANARY),
        "BrokerState::Debug leaked the canary: {rendered_state}"
    );
    assert!(
        !rendered_response.contains(CANARY),
        "the response leaked the canary: {rendered_response}"
    );

    // The canary in the environment is the fallback path a degraded broker
    // would take. Asserting only on the absence of a leak would pass for a
    // broker that quietly grabbed the token and then failed downstream, so
    // the refusal itself is asserted: a degraded broker is one that got
    // *past* this check.
    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "with GITHUB_TOKEN in the environment and no vault open, the broker must still \
         refuse; got {response:?}. A non-Denied answer here is the broker reaching for \
         the ambient credential."
    );

    std::env::remove_var("GITHUB_TOKEN");
}

/// Losing the state must not resurrect the session or the surrogate. A
/// broker that restarts has no memory of what it issued, and a surrogate
/// that survives a restart would be a credential outliving its authority.
#[test]
fn state_loss_does_not_resurrect_a_session_or_surrogate() {
    let (first, peer, token, session) = state_with_session_id();

    // The broker dies. What comes back is a fresh process with a fresh
    // default state. The credentials are copied over on purpose: a restarted
    // broker could plausibly reload its metadata from disk while having no
    // authority to redeem anything, and that is the closest thing to a real
    // restart this suite can build.
    let mut restarted = BrokerState {
        credentials: std::sync::Arc::new(std::sync::Mutex::new(
            first.credentials.lock().expect("not poisoned").clone(),
        )),
        ..BrokerState::default()
    };

    let response = handle(
        &mut restarted,
        &peer,
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token,
            repo: "owner/repo".into(),
            number: 1,
        },
    );

    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "a token minted by a previous broker process must not work against a new one, \
         got {response:?}"
    );
    assert!(
        !restarted
            .sessions
            .lock()
            .expect("no test holds this")
            .is_pinned(session),
        "the session must not reappear in a fresh state"
    );
    // The denial above is ambiguous on its own: an unknown session and a
    // missing vault both produce `Denied`. This is the check that makes the
    // test mean what its name says — the *session* is what the restarted
    // broker is missing, and the broker's own copy of that store is empty.
    assert_eq!(
        restarted.sessions.lock().expect("no test holds this").len(),
        0,
        "the restarted broker must start with no sessions at all; a non-zero count would \
         mean state was carried across the crash and the previous denial was proving \
         something else"
    );
}

/// The retry is the interesting word in "broker death/retry". A client
/// that retries against a restarted broker must be denied, not served —
/// the retry is precisely the moment a naive implementation falls back.
#[test]
fn retrying_after_the_broker_restarts_is_still_denied() {
    let (mut original, peer, token, session) = state_with_live_session();

    // Control: the refusal must be attributable to the missing vault, not to
    // a malformed request. If this one ever stops being `Denied`, every
    // assertion below it is vacuous.
    let control = handle(
        &mut original,
        &peer,
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token.clone(),
            repo: "owner/repo".into(),
            number: 1,
        },
    );
    assert!(
        matches!(
            control,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "the live broker must deny on the missing vault, got {control:?}"
    );

    // Broker restarts. Same token, same session id, same request.
    let mut restarted = BrokerState::default();
    let second = handle(
        &mut restarted,
        &peer,
        Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: token,
            repo: "owner/repo".into(),
            number: 1,
        },
    );

    assert!(
        matches!(
            second,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "the retry must be denied as well, got {second:?}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A peer whose process is genuinely pidfd-pinned, because D4 makes the pin
/// a precondition for minting and a test that used a weaker identity would
/// be testing a different broker.
fn pinned_peer() -> WorkloadIdentity {
    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("pidfd_open on self");
    assert!(peer.is_pidfd_pinned(), "the fixture must be pinned");
    peer
}
