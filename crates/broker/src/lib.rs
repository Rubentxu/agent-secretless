//! Broker request handling.
//!
//! Kept separate from `main.rs` so the authorization-relevant logic is testable
//! without spawning a process. The M0 broker is intentionally thin: it
//! establishes identity, enforces the protocol boundary, and holds session
//! state. Vault access and connectors are M1 and M4.

use asv_domain::{AgentSessionId, CredentialId, CredentialMetadata};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{ErrorCode, Request, Response, PROTOCOL_VERSION};
use std::collections::HashMap;

/// In-memory session table. M1 replaces this with persistent, encrypted state;
/// M0 only needs it to prove the lifecycle boundary.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: HashMap<AgentSessionId, SessionRecord>,
}

#[derive(Debug)]
struct SessionRecord {
    workspace: String,
    peer_pid: i32,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a session bound to the calling peer's PID.
    pub fn create(&mut self, workspace: String, peer: &WorkloadIdentity) -> AgentSessionId {
        let id = AgentSessionId::new();
        self.sessions.insert(
            id,
            SessionRecord {
                workspace,
                peer_pid: peer.credentials.pid,
            },
        );
        id
    }

    /// Returns the workspace a session was opened against.
    pub fn workspace_of(&self, id: AgentSessionId) -> Option<&str> {
        self.sessions.get(&id).map(|r| r.workspace.as_str())
    }

    /// Returns the PID that opened a session.
    ///
    /// M1 uses this to bind a session to the launching process, and M7 uses it
    /// to correlate a session with cgroup evidence. Reading it here keeps the
    /// field honest instead of a placeholder waiting for a future milestone.
    pub fn peer_pid_of(&self, id: AgentSessionId) -> Option<i32> {
        self.sessions.get(&id).map(|r| r.peer_pid)
    }

    /// Ends a session. Returns whether it existed, so a caller can distinguish
    /// "revoked" from "never existed" instead of silently succeeding.
    pub fn end(&mut self, id: AgentSessionId) -> bool {
        self.sessions.remove(&id).is_some()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Broker-side state. M0 has no vault, so credential metadata is an in-memory
/// list seeded by tests; M1 makes it encrypted and persistent.
#[derive(Debug, Default)]
pub struct BrokerState {
    pub sessions: SessionStore,
    pub credentials: Vec<CredentialMetadata>,
}

/// Handles one authenticated request.
///
/// `peer` is kernel-attested by the caller before we get here. There is no code
/// path that reaches this function without a `WorkloadIdentity`, which is what
/// makes ADR-0003 structural instead of aspirational.
pub fn handle(state: &mut BrokerState, peer: &WorkloadIdentity, request: Request) -> Response {
    // A connection whose process could not be pinned is still usable, but the
    // weaker evidence is recorded rather than hidden.
    let evidence_note = if peer.is_pidfd_pinned() {
        "pidfd-pinned"
    } else {
        "peercred-only"
    };
    tracing::debug!(%evidence_note, pid = peer.credentials.pid, "authenticated request");

    match request {
        Request::Ping { protocol } => {
            if protocol != PROTOCOL_VERSION {
                return Response::Error {
                    code: ErrorCode::VersionMismatch,
                    message: format!(
                        "client speaks protocol {protocol}, broker speaks {PROTOCOL_VERSION}"
                    ),
                };
            }
            Response::Pong {
                protocol: PROTOCOL_VERSION,
            }
        }

        Request::CreateSession { workspace } => {
            let id = state.sessions.create(workspace, peer);
            Response::SessionCreated { session: id }
        }

        Request::EndSession { session } => {
            if state.sessions.end(session) {
                Response::SessionEnded { session }
            } else {
                // Fail closed: an unknown session is an error, not a no-op.
                // UAT-014 requires revoke to be observable.
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("no such session: {session}"),
                }
            }
        }

        Request::ListCredentialMetadata => Response::CredentialMetadata {
            entries: state.credentials.iter().map(Into::into).collect(),
        },

        Request::DeleteCredential { id } => {
            let before = state.credentials.len();
            state.credentials.retain(|c| c.id != id);
            if state.credentials.len() == before {
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("no such credential: {}", id),
                }
            } else {
                Response::CredentialDeleted { id }
            }
        }
    }
}

/// Seeds a credential for tests and for the M0 CLI smoke path.
pub fn insert_credential(state: &mut BrokerState, metadata: CredentialMetadata) -> CredentialId {
    let id = metadata.id;
    state.credentials.push(metadata);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_domain::CredentialKind;
    use asv_identity::PeerCredentials;

    fn peer() -> WorkloadIdentity {
        WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        })
    }

    #[test]
    fn ping_reports_the_broker_protocol_version() {
        let mut state = BrokerState::default();
        let resp = handle(
            &mut state,
            &peer(),
            Request::Ping {
                protocol: PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            resp,
            Response::Pong {
                protocol: PROTOCOL_VERSION
            }
        );
    }

    /// A stale client must be rejected, not served in a degraded mode.
    #[test]
    fn version_mismatch_is_an_error_response() {
        let mut state = BrokerState::default();
        let resp = handle(&mut state, &peer(), Request::Ping { protocol: 0 });
        match resp {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::VersionMismatch),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn session_lifecycle_is_observable() {
        let mut state = BrokerState::default();
        let session = match handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        assert_eq!(state.sessions.len(), 1);

        assert_eq!(
            handle(&mut state, &peer(), Request::EndSession { session }),
            Response::SessionEnded { session }
        );
        assert!(state.sessions.is_empty());

        // Second revoke must report honestly instead of pretending.
        match handle(&mut state, &peer(), Request::EndSession { session }) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("double revoke must fail, got {other:?}"),
        }
    }

    /// Metadata listing is the only credential surface, and it must be empty by
    /// default rather than seeded with anything resembling a value.
    #[test]
    fn listing_credentials_returns_metadata_only() {
        let mut state = BrokerState::default();
        let id = insert_credential(
            &mut state,
            CredentialMetadata::new("github-work", CredentialKind::BearerToken),
        );

        let resp = handle(&mut state, &peer(), Request::ListCredentialMetadata);
        let entries = match resp {
            Response::CredentialMetadata { entries } => entries,
            other => panic!("expected metadata, got {other:?}"),
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, *id.as_uuid());
        assert_eq!(entries[0].label, "github-work");

        let json = serde_json::to_string(&entries).expect("serializes");
        assert!(!json.to_lowercase().contains("secret"));
    }

    #[test]
    fn deleting_an_unknown_credential_fails_closed() {
        let mut state = BrokerState::default();
        let ghost = CredentialId::new();
        match handle(&mut state, &peer(), Request::DeleteCredential { id: ghost }) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    /// A canary in any request field must not reach the response bytes.
    #[test]
    fn canary_never_crosses_the_response_boundary() {
        const CANARY: &str = "ASV-CANARY-5b2f8a31-DO-NOT-LEAK";
        let mut state = BrokerState::default();
        let resp = handle(
            &mut state,
            &peer(),
            Request::CreateSession {
                workspace: CANARY.into(),
            },
        );
        let bytes = asv_ipc_protocol::encode_response(&resp).expect("encodes");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "canary leaked into response: {text}"
        );
    }
}
