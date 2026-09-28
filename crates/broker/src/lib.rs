//! Broker request handling.
//!
//! Kept separate from `main.rs` so the authorization-relevant logic is testable
//! without spawning a process. The M0 broker is intentionally thin: it
//! establishes identity, enforces the protocol boundary, and holds session
//! state. Vault access and connectors are M1 and M4.

use asv_domain::{AgentSessionId, CredentialId, CredentialMetadata};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{ErrorCode, Request, Response, PROTOCOL_VERSION};
use asv_policy::{AuthorizationRequest, PolicyEngine};
use std::collections::HashMap;

pub mod surrogate;

pub use surrogate::{now_secs, SurrogateError, SurrogateRegistry};

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
    /// Whether the peer's process could be pinned with a pidfd (M4 D4).
    ///
    /// Directed requirement, not a global deny: `main.rs` deliberately makes
    /// an unpinned peer a log-and-continue case, so refusing here would revert
    /// a documented M0 decision. What D4 requires is narrower, and this field
    /// is what makes it enforceable: a surrogate is a credential-shaped token,
    /// so minting one for a process we can only weakly attribute is the case
    /// that actually deserves a refusal.
    pinned: bool,
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
                pinned: peer.is_pidfd_pinned(),
            },
        );
        id
    }

    /// Whether the session's peer was pidfd-pinned when it was opened (M4 D4).
    ///
    /// Recorded at creation rather than queried later: pinning is evidence
    /// about the connection that opened the session, and a later query would
    /// describe a different moment. A session opened unpinned stays unpinned,
    /// which is the conservative direction.
    pub fn is_pinned(&self, id: AgentSessionId) -> bool {
        self.sessions.get(&id).is_some_and(|record| record.pinned)
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

    pub fn belongs_to(&self, id: AgentSessionId, peer: &WorkloadIdentity) -> bool {
        self.sessions
            .get(&id)
            .map(|record| record.peer_pid == peer.credentials.pid)
            .unwrap_or(false)
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
    pub policy: PolicyEngine,
    /// M4: the tokens an agent holds instead of credentials (D3).
    pub surrogates: SurrogateRegistry,
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
                state.policy.revoke_session(session);
                // The session's surrogates die with it. Leaving them live would
                // make the session lifetime advisory: an agent could keep
                // spending a token after the session that authorized it is gone.
                state.surrogates.revoke_session(session);
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

        Request::Authorize {
            mut request,
            capability,
            approval,
        } => {
            if !state.sessions.belongs_to(request.session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            bind_peer_identity(&mut request, peer);
            Response::Authorization {
                explanation: state.policy.authorize(&request, capability, approval),
            }
        }

        Request::ExplainAuthorization { mut request } => {
            if !state.sessions.belongs_to(request.session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            bind_peer_identity(&mut request, peer);
            Response::Authorization {
                explanation: state.policy.explain(&request),
            }
        }

        Request::SubmitApproval { .. } => {
            // An agent connection may never approve its own request. UAT-015
            // requires the broker to block *until a human approves*, and
            // ADR-0004 keeps approval lifecycle an application concern whose
            // validity arrives as trusted context. Exposing this method on the
            // agent IPC made the gate self-satisfying: the agent minted the
            // very approval it was being asked to earn.
            //
            // The human control plane is a separate channel (M4) and does not
            // reach this variant. Until it exists, the honest state is a
            // closed door rather than a pretend approval.
            Response::Error {
                code: ErrorCode::Denied,
                message: "approval must be issued by the human control plane, not by the requesting agent session".into(),
            }
        }

        Request::MintSurrogate {
            session,
            credential,
            max_uses,
            ttl_secs,
        } => {
            if !state.sessions.belongs_to(session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            // D4, directed requirement: the rest of the broker treats an
            // unpinned peer as a weaker-but-usable connection, but minting a
            // credential-shaped token for a process we can only weakly
            // attribute is the case worth refusing.
            if !state.sessions.is_pinned(session) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "surrogate minting requires a pidfd-pinned session".into(),
                };
            }
            if !state.credentials.iter().any(|c| c.id == credential) {
                // An unknown credential would mint a token that always fails
                // later. Refusing here reports the real problem instead.
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("no such credential: {credential}"),
                };
            }

            match state
                .surrogates
                .mint(session, credential, ttl_secs, max_uses, now_secs())
            {
                Ok((surrogate, expires_at, granted)) => {
                    // The token is never logged. Only its budget and its
                    // lifetime, which are the facts an operator needs.
                    tracing::info!(
                        %session,
                        expires_at,
                        max_uses = granted,
                        "surrogate minted"
                    );
                    Response::SurrogateMinted {
                        surrogate,
                        expires_at,
                        max_uses: granted,
                    }
                }
                Err(error) => Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: error.to_string(),
                },
            }
        }

        Request::RevokeSurrogate { session, surrogate } => {
            if !state.sessions.belongs_to(session, peer) {
                return Response::Error {
                    code: ErrorCode::Denied,
                    message: "session is not owned by the authenticated peer".into(),
                };
            }
            if state.surrogates.revoke(&surrogate, session) {
                Response::SurrogateRevoked { surrogate }
            } else {
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: "no such surrogate for this session".into(),
                }
            }
        }

        // The three semantic operations belong to CU-2.2: they need the
        // connector and the secret port. Answering them here with a canned
        // success would be worse than not answering at all.
        Request::ReadIssue { .. } | Request::CreateIssue { .. } | Request::CreateRelease { .. } => {
            Response::Error {
                code: ErrorCode::UnknownMethod,
                message: "semantic GitHub operations are not wired to a connector yet".into(),
            }
        }
    }
}

/// Rebinds the client-declared identity context to kernel-attested facts.
///
/// `PolicyContext.peer_uid` arrives inside the request body, so it is
/// attacker-controlled: nothing stopped a caller from claiming `uid: 0` while
/// running as an unprivileged user, and policy decisions that referenced the
/// uid would have been made against a lie. The broker knows the real uid from
/// `SO_PEERCRED`, so the declared value is overwritten rather than trusted.
fn bind_peer_identity(request: &mut AuthorizationRequest, peer: &WorkloadIdentity) {
    request.context.peer_uid = peer.credentials.uid;
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
    use asv_policy::{AuthorizationRequest, PolicyContext};

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

    #[test]
    fn protected_push_requires_exact_single_use_approval() {
        let mut state = BrokerState::default();
        let peer = peer();
        let session = match handle(
            &mut state,
            &peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: Some("main".into()),
                request_digest: Some("release-digest".into()),
                peer_uid: peer.credentials.uid,
            },
        };

        // The agent path cannot mint an approval, so the gate holds closed.
        let unapproved = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: None,
            },
        );
        assert!(
            matches!(&unapproved, Response::Authorization { explanation } if !explanation.decision.is_allowed()),
            "a protected push without approval was not gated: {unapproved:?}"
        );

        // The human control plane issues the approval out of band; M3 grants it
        // directly against the policy engine rather than over the agent IPC.
        let approval = state.policy.issue_approval(&request, 60, 1);

        let first = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request: request.clone(),
                capability: None,
                approval: Some(approval.id),
            },
        );
        assert!(
            matches!(first, Response::Authorization { explanation } if explanation.decision.is_allowed())
        );

        let replay = handle(
            &mut state,
            &peer,
            Request::Authorize {
                request,
                capability: None,
                approval: Some(approval.id),
            },
        );
        assert!(
            matches!(replay, Response::Authorization { explanation } if !explanation.decision.is_allowed())
        );
    }

    /// H1: an agent must not be able to mint its own approval. UAT-015 requires
    /// "broker blocks until approval" from a human, and the ADR-0004 consequence
    /// note says approval validity is *supplied* as trusted context, not that the
    /// agent supplies it. If this test fails, an agent can approve itself.
    #[test]
    fn agent_cannot_submit_its_own_approval() {
        let mut state = BrokerState::default();
        let agent_peer = peer();
        let session = match handle(
            &mut state,
            &agent_peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: Some("main".into()),
                request_digest: Some("release-digest".into()),
                peer_uid: agent_peer.credentials.uid,
            },
        };
        match handle(
            &mut state,
            &agent_peer,
            Request::SubmitApproval {
                request: request.clone(),
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => {
                panic!("agent minted its own approval, defeating the approval gate: {other:?}")
            }
        }
    }

    /// H2: `PolicyContext.peer_uid` arrives inside the request body, so it is
    /// attacker-controlled. The broker must overwrite it with the
    /// kernel-attested uid before policy sees it, otherwise any uid-aware rule
    /// would be decided against a lie the caller invented.
    #[test]
    fn policy_context_peer_uid_is_overwritten_by_kernel_evidence() {
        let mut state = BrokerState::default();
        let agent_peer = peer();
        let session = match handle(
            &mut state,
            &agent_peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session } => session,
            other => panic!("expected session creation, got {other:?}"),
        };
        let real_uid = agent_peer.credentials.uid;
        let mut request = AuthorizationRequest {
            session,
            action: asv_domain::Action::GitPush,
            resource: asv_domain::Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: None,
                request_digest: None,
                peer_uid: 0,
            },
        };
        assert_eq!(request.context.peer_uid, 0, "client declared a forged uid");

        bind_peer_identity(&mut request, &agent_peer);

        assert_eq!(
            request.context.peer_uid, real_uid,
            "forged peer_uid survived into the policy context"
        );
        assert_ne!(request.context.peer_uid, 0);
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

/// The M4 session-bound surrogate tests. These drive the real `handle` entry
/// point rather than the registry directly, because the questions that matter
/// here are about the broker's decisions, not about the registry's internals.
#[cfg(test)]
mod surrogate_tests {
    use super::*;
    use asv_domain::CredentialKind;
    use asv_identity::PeerCredentials;
    use asv_ipc_protocol::MAX_SURROGATE_USES;

    /// A peer whose process is pinned, which is the precondition D4 puts on
    /// minting. The pin is real: `pin_pidfd` on this very process.
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

    /// The weaker state: kernel-attested credentials, no pidfd. M0 treats this
    /// as usable, and D4 keeps that decision.
    fn unpinned_peer() -> WorkloadIdentity {
        let peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        assert!(!peer.is_pidfd_pinned(), "the fixture must be unpinned");
        peer
    }

    fn state_with_credential() -> (BrokerState, CredentialId) {
        let mut state = BrokerState::default();
        let metadata = CredentialMetadata::new("github-work", CredentialKind::BearerToken);
        let id = insert_credential(&mut state, metadata);
        (state, id)
    }

    fn mint(state: &mut BrokerState, peer: &WorkloadIdentity) -> (AgentSessionId, String) {
        let session = state.sessions.create("/repo".to_string(), peer);
        let credential = state.credentials[0].id;
        match handle(
            state,
            peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => (session, surrogate),
            other => panic!("expected a minted surrogate, got {other:?}"),
        }
    }

    /// D4's directed requirement: an unpinned session is still usable for
    /// everything M0 allowed, but it cannot mint a credential-shaped token.
    /// Without this test, "directed" is indistinguishable from "global deny".
    #[test]
    fn an_unpinned_session_can_still_create_and_end_sessions() {
        let mut state = BrokerState::default();
        let peer = unpinned_peer();
        let session = match handle(
            &mut state,
            &peer,
            Request::CreateSession {
                workspace: "/repo".into(),
            },
        ) {
            Response::SessionCreated { session } => session,
            other => panic!("expected creation, got {other:?}"),
        };
        assert!(
            !state.sessions.is_pinned(session),
            "the fixture session is unpinned"
        );
        assert_eq!(
            handle(&mut state, &peer, Request::EndSession { session }),
            Response::SessionEnded { session },
            "M0 behaviour must be preserved for an unpinned peer"
        );
    }

    /// And the narrow refusal that D4 actually asks for.
    #[test]
    fn an_unpinned_peer_cannot_mint_a_surrogate() {
        let (mut state, credential) = state_with_credential();
        let peer = unpinned_peer();
        let session = state.sessions.create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("an unpinned peer must be refused, got {other:?}"),
        }
        assert!(
            state.surrogates.is_empty(),
            "a refused mint must leave no token behind"
        );
    }

    /// A pinned peer mints successfully, and the response carries a token that
    /// is recognisably a surrogate rather than anything credential-shaped.
    #[test]
    fn a_pinned_peer_mints_a_bounded_surrogate() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);
        assert!(token.starts_with("asv1_"), "{token}");
        assert_eq!(state.surrogates.len(), 1);

        // The session ends, the token dies with it. This is the property that
        // makes the session a real boundary rather than bookkeeping.
        assert_eq!(
            handle(&mut state, &peer, Request::EndSession { session }),
            Response::SessionEnded { session }
        );
        assert_eq!(
            state.surrogates.len(),
            0,
            "ending a session must revoke its surrogates"
        );
    }

    /// A session owned by another peer must not mint, even with a valid
    /// credential id. The session check runs before the credential lookup, so
    /// the answer is a denial and never "no such credential", which would
    /// confirm the id exists.
    #[test]
    fn a_session_cannot_be_used_by_a_stranger() {
        let (mut state, credential) = state_with_credential();
        let owner = pinned_peer();
        let session = state.sessions.create("/repo".to_string(), &owner);

        // A different PID, so `belongs_to` is false.
        let stranger = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32 + 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        match handle(
            &mut state,
            &stranger,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("a stranger must be refused, got {other:?}"),
        }
        assert!(state.surrogates.is_empty());
    }

    /// Minting against a credential the broker does not hold would produce a
    /// token that always fails later, which reads as a broker bug rather than
    /// a client error.
    #[test]
    fn an_unknown_credential_is_refused_at_mint_time() {
        let mut state = BrokerState::default();
        let peer = pinned_peer();
        let session = state.sessions.create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential: CredentialId::new(),
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("an unknown credential must be refused, got {other:?}"),
        }
        assert!(state.surrogates.is_empty());
    }

    /// A client asking for an absurd budget is clamped, and the clamped value
    /// is what comes back. The agent can then budget its own calls against the
    /// real number instead of the one it asked for.
    #[test]
    fn a_client_cannot_widen_its_own_surrogate_budget() {
        let (mut state, credential) = state_with_credential();
        let peer = pinned_peer();
        let session = state.sessions.create("/repo".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: u32::MAX,
                ttl_secs: u64::MAX,
            },
        ) {
            Response::SurrogateMinted {
                max_uses,
                expires_at,
                surrogate,
            } => {
                assert_eq!(max_uses, MAX_SURROGATE_USES);
                assert!(surrogate.starts_with("asv1_"));
                assert!(expires_at > 0);
            }
            other => panic!("expected a clamped mint, got {other:?}"),
        }
    }

    /// Revoke is session-scoped, and revoking something you do not own reports
    /// honestly instead of pretending it worked.
    #[test]
    fn revoke_is_scoped_to_the_owning_session() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);

        // A stranger's revoke, under their own session, must not touch it.
        let other_session = state.sessions.create("/other".to_string(), &peer);
        match handle(
            &mut state,
            &peer,
            Request::RevokeSurrogate {
                session: other_session,
                surrogate: token.clone(),
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("a cross-session revoke must fail, got {other:?}"),
        }
        assert_eq!(state.surrogates.len(), 1, "the token is untouched");

        // The owner can.
        assert_eq!(
            handle(
                &mut state,
                &peer,
                Request::RevokeSurrogate {
                    session,
                    surrogate: token.clone(),
                }
            ),
            Response::SurrogateRevoked { surrogate: token }
        );
        assert!(state.surrogates.is_empty());
    }

    /// The three semantic operations are not wired yet. They must say so
    /// rather than answering with a plausible-looking success, because a fake
    /// success here is indistinguishable from a working brokered call.
    #[test]
    fn semantic_operations_fail_closed_until_a_connector_exists() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, token) = mint(&mut state, &peer);

        for request in [
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                number: 1,
            },
            Request::CreateIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                title: "t".into(),
                body: "b".into(),
            },
            Request::CreateRelease {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                tag: "v1".into(),
                name: "n".into(),
                body: "b".into(),
            },
        ] {
            match handle(&mut state, &peer, request) {
                Response::Error { code, .. } => assert_eq!(
                    code,
                    ErrorCode::UnknownMethod,
                    "an unwired operation must say so"
                ),
                other => panic!("an unwired operation must not answer {other:?}"),
            }
        }
        // And crucially, an unattempted call must not have spent the budget.
        assert_eq!(state.surrogates.len(), 1, "the token is still live");
    }

    /// A minted token is the only credential-shaped string the broker emits,
    /// and the response must not also leak the underlying credential id.
    #[test]
    fn minting_leaks_no_credential_material() {
        const CANARY: &str = "ASV-CANARY-9f2c-DO-NOT-LEAK";
        let mut state = BrokerState::default();
        let metadata = CredentialMetadata::new(CANARY, CredentialKind::BearerToken);
        let credential = insert_credential(&mut state, metadata);
        let peer = pinned_peer();
        let session = state.sessions.create("/repo".to_string(), &peer);

        let response = handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        );
        let bytes = asv_ipc_protocol::encode_response(&response).expect("encodes");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "the credential label leaked into the mint response: {text}"
        );
        assert!(
            !text.contains(&credential.as_uuid().to_string()),
            "the credential id leaked into the mint response: {text}"
        );
    }

    /// Teardown leaves nothing live. UAT-030 asserts this, so the invariant is
    /// pinned where the state actually lives.
    #[test]
    fn teardown_leaves_no_surrogate_behind() {
        let (mut state, _) = state_with_credential();
        let peer = pinned_peer();
        let (session, _) = mint(&mut state, &peer);
        assert_eq!(state.surrogates.len(), 1, "one token is live");
        handle(&mut state, &peer, Request::EndSession { session });
        assert!(state.surrogates.is_empty(), "and none after teardown");
        assert!(state.sessions.is_empty(), "and no session either");
    }
}
