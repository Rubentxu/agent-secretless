//! B1: a request that disagrees about the protocol is refused before the
//! broker evaluates a single capability.
//!
//! # What was measured before this file existed
//!
//! `asv_ipc_protocol::check_version` existed, was correct, and had **no
//! production caller**. The only comparable logic lived inside the
//! `Ping | AgentInfo` arm of `handle_inner`, so the check was real for those two
//! verbs and absent for the other twenty-five. Every verb that carries a
//! session, a surrogate or a credential — `CreateSession`, `RunIsolated`,
//! `PullManifest`, `PostgresQuery` and the rest — reached policy evaluation,
//! vault access and process spawn without either side of the connection ever
//! comparing a number.
//!
//! That is not a handshake gap. It is a gate with no doorway: the broker could
//! execute a capability on behalf of a client that would have disagreed with
//! its reading of the protocol, and neither side would have found out.
//!
//! # What this row has to distinguish
//!
//! "There is a version check" and "the version check runs first" are different
//! claims, and only the second one is the DoD criterion. A check that ran after
//! session admission, after policy evaluation and after the worker registry was
//! consulted would satisfy the first and fail the second while still refusing
//! the request — just with the wrong reason, having already done the work the
//! gate exists to prevent.
//!
//! So each row below sends a request that is wrong in the version **and** wrong
//! in every other way it could be wrong, and requires the answer to name the
//! version. The control at the bottom sends the same requests at the right
//! version and requires that they stop being version errors — without it, a
//! broker that refused everything for a different reason would pass.

use asv_broker::{handle, BrokerState};
use asv_domain::{AgentSessionId, CredentialId, CredentialKind};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{decode_request, ErrorCode, Request, Response, PROTOCOL_VERSION};

/// A version no client of this build would speak.
const FOREIGN: u16 = 3;

/// A session id that was never issued. Paired with a wrong version so the row
/// can tell "refused before it looked" from "refused when it looked".
const NO_SUCH_SESSION: &str = "00000000-0000-4000-8000-000000000000";

fn peer() -> WorkloadIdentity {
    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("pin this test's own process");
    peer
}

/// The verbs that carry authority, in the shapes they carry it in.
///
/// Not a sample: between them they cover a bare verb, a session-scoped verb, a
/// surrogate-bearing verb, a worker spawn and a statement execution. A gate
/// that only some of them passed would still be a hole, and a list is the only
/// thing that makes "some" visible.
fn requests(protocol: u16) -> Vec<(Request, &'static str)> {
    let session = AgentSessionId::new();
    vec![
        (
            Request::CreateSession {
                protocol,
                workspace: "/repo".into(),
            },
            "create_session",
        ),
        (
            Request::ListCredentialMetadata { protocol },
            "list_credential_metadata",
        ),
        (
            Request::RunIsolated {
                protocol,
                session,
                worker: "no-such-worker".into(),
                args: Vec::new(),
                credential: None,
                timeout_ms: None,
            },
            "run_isolated",
        ),
        (
            Request::PullManifest {
                protocol,
                session,
                surrogate: "not-a-surrogate".into(),
                registry: "nowhere.invalid".into(),
                repository: "library/nothing".into(),
                reference: "latest".into(),
            },
            "pull_manifest",
        ),
        (
            Request::PostgresQuery {
                protocol,
                session,
                sql: "SELECT 1".into(),
            },
            "postgres_query",
        ),
        (
            Request::CreateCredential {
                protocol,
                label: "x".into(),
                kind: CredentialKind::GenericSecret,
                provider: "p".into(),
                account: "a".into(),
                secret: asv_ipc_protocol::OpaqueSecret::new(b"v".to_vec()),
            },
            "create_credential",
        ),
    ]
}

/// **Every verb refuses a foreign protocol, and says so in those words.**
///
/// `VersionMismatch` specifically. Any other code means the broker got as far
/// as admitting the session, evaluating policy or consulting the worker
/// registry before it compared numbers — which is the failure this criterion
/// is about.
#[test]
fn a_foreign_protocol_is_refused_by_every_verb_that_carries_authority() {
    let state = BrokerState::default();
    let peer = peer();

    for (request, name) in requests(FOREIGN) {
        let response = handle(&state, &peer, request);
        assert!(
            matches!(
                response,
                Response::Error {
                    code: ErrorCode::VersionMismatch,
                    ..
                }
            ),
            "{name} did not refuse a foreign protocol as a version mismatch. It \
             answered {response:?}, which means the broker evaluated the request \
             before it compared versions."
        );
    }
}

/// **The version is compared before the request is looked at.**
///
/// The strongest of the rows, and the one a "there is a version check" gate
/// fails. `RunIsolated` here is wrong four ways at once: the version is
/// foreign, the session was never issued, the worker is not in the registry,
/// and no vault is open. A broker that checked the version at any point after
/// session ownership would answer `Denied` — correctly, for the wrong reason,
/// having already done the admission work the gate exists to prevent.
///
/// So the assertion is on the *reason*, and the control below is what keeps it
/// honest: the same request at the right version stops being a version error.
#[test]
fn the_version_is_compared_before_the_request_is_looked_at() {
    let state = BrokerState::default();
    let peer = peer();

    let refused = handle(&state, &peer, run_isolated(FOREIGN));
    assert!(
        matches!(
            refused,
            Response::Error {
                code: ErrorCode::VersionMismatch,
                ..
            }
        ),
        "a foreign protocol was answered {refused:?} rather than refused. The \
         request names a session that was never issued and a worker that is not \
         registered, so any answer other than VersionMismatch is the broker \
         having admitted or looked up the request before comparing versions."
    );

    // The control. Without it, "everything is VersionMismatch" would pass for a
    // broker that simply refuses every request it cannot parse.
    let answered = handle(&state, &peer, run_isolated(PROTOCOL_VERSION));
    assert!(
        !matches!(
            answered,
            Response::Error {
                code: ErrorCode::VersionMismatch,
                ..
            }
        ),
        "the very same request at this build's own protocol is also a version \
         mismatch ({answered:?}), so the row above proves nothing about ordering."
    );
}

fn run_isolated(protocol: u16) -> Request {
    Request::RunIsolated {
        protocol,
        session: AgentSessionId::new(),
        worker: "no-such-worker".into(),
        args: Vec::new(),
        credential: None,
        timeout_ms: None,
    }
}

/// **A request that does not name its version does not decode.**
///
/// The other half of the same gate, and the reason `PROTOCOL_VERSION` is 11
/// and not 10. `protocol` is a required field, not a defaulted one: a client
/// built against the previous version sends a document without it and fails at
/// the decoder, rather than being answered under a reading of the protocol it
/// never agreed to.
///
/// A `#[serde(default)]` here would have made this row green in the cheapest
/// possible way and turned the whole gate back into a suggestion, which is
/// why the absence of a default is the property rather than an accident.
#[test]
fn a_request_that_does_not_name_its_version_does_not_decode() {
    let missing = br#"{"method":"create_session","workspace":"/repo"}"#;
    let error = decode_request(missing).expect_err("a versionless request must not decode");
    assert!(
        !matches!(
            error,
            asv_ipc_protocol::ProtocolError::VersionMismatch { .. }
        ),
        "a request with no version at all must fail as malformed, not as a \
         version mismatch: there is no number to disagree about. Got {error:?}."
    );

    // The same document with this build's version does decode, so the row above
    // is about the missing field and not about the verb being unknown.
    let named = br#"{"method":"create_session","protocol":11,"workspace":"/repo"}"#;
    assert!(
        decode_request(named).is_ok(),
        "a create_session carrying protocol 11 must decode; if it does not, the \
         row above was passing because the verb is unparseable rather than \
         because the version is required."
    );
    assert_eq!(
        PROTOCOL_VERSION, 11,
        "the two hand-written documents above name 11, so this build must speak \
         11 or the row is asserting against a different protocol than the one \
         it just verified."
    );
}

/// **A credential id is not a protocol number.**
///
/// Present because the gate reads a field, and a field is exactly what a
/// well-meaning refactor would move. This row fails if `protocol` is ever
/// confused for the credential reference that `RunIsolated` also carries.
#[test]
fn the_version_and_the_credential_reference_are_different_numbers() {
    let session = AgentSessionId::new();
    let credential = CredentialId::from_wire(NO_SUCH_SESSION).expect("a canonical wire form");
    let foreign_credential = Request::RunIsolated {
        protocol: FOREIGN,
        session,
        worker: "no-such-worker".into(),
        args: Vec::new(),
        credential: Some(credential.to_wire()),
        timeout_ms: None,
    };
    let response = handle(&BrokerState::default(), &peer(), foreign_credential);
    assert!(
        matches!(
            response,
            Response::Error {
                code: ErrorCode::VersionMismatch,
                ..
            }
        ),
        "naming a credential must not satisfy the version gate: {response:?}"
    );
}

/// **A refused request leaves nothing behind.**
///
/// The row above answers the wrong question, and this is how it was found: it
/// asserts on the *response*, and a gate placed after the dispatcher produces
/// the same response while doing every side effect first. Moving the check one
/// line down leaves all three rows above green — the answer is still
/// `VersionMismatch` — while a client the broker just refused has already had
/// its session created, its surrogates minted, or its key bound.
///
/// So this row asserts on the store rather than on the answer. `RegisterSessionKey`
/// is the verb to use because its effect is readable through an existing public
/// accessor, and because binding a key is a grant of real weight: the session's
/// key is how a later CONNECT proof is resolved to a session, so a key bound by
/// a client the broker refused is a key nobody asked the broker to bind.
#[test]
fn a_refused_request_binds_nothing() {
    let state = BrokerState::default();
    let peer = peer();

    // A real session, opened at this build's own version.
    let session = match handle(
        &state,
        &peer,
        Request::CreateSession {
            protocol: PROTOCOL_VERSION,
            workspace: "/repo".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("the fixture must be able to open a session: {other:?}"),
    };

    let key = b"a-public-key-from-a-client-we-are-about-to-refuse";
    let refused = handle(
        &state,
        &peer,
        Request::RegisterSessionKey {
            protocol: FOREIGN,
            session,
            public_key_blob: key.to_vec(),
        },
    );
    assert!(
        matches!(
            refused,
            Response::Error {
                code: ErrorCode::VersionMismatch,
                ..
            }
        ),
        "expected a version mismatch, got {refused:?}"
    );

    assert!(
        state
            .sessions
            .lock()
            .expect("not poisoned")
            .public_key_of(session)
            .is_none(),
        "the broker refused the request and bound the key anyway. The response \
         says the version did not match, and the store says the grant exists."
    );
}
