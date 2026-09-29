//! Broker request handling.
//!
//! Kept separate from `main.rs` so the authorization-relevant logic is testable
//! without spawning a process. The M0 broker is intentionally thin: it
//! establishes identity, enforces the protocol boundary, and holds session
//! state. Vault access and connectors are M1 and M4.

use asv_connector_http::{validate_repo, AddressPolicy, GithubClient, GithubError, SecretPort};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialId, CredentialMetadata};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{ErrorCode, Request, Response, PROTOCOL_VERSION};
use asv_policy::{AuthorizationRequest, PolicyEngine};
use std::collections::HashMap;
use std::sync::Arc;

pub mod harden;
pub mod isolated_exec;
pub mod oauth2;
pub mod recovery;
pub mod surrogate;
pub mod tls_bridge;
pub mod vault_port;

pub use surrogate::{now_secs, SurrogateError, SurrogateRegistry};
pub use vault_port::VaultSecretPort;

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

    /// Count of live sessions whose peer was pidfd-pinned at creation.
    ///
    /// This is the UAT-030 zero-live-pin counter. R3 ("PID reuse mitigated
    /// with pidfd/launch record") requires that a broker holding a pin for a
    /// peer cannot outlive the session the pin is bound to: every pin must
    /// be released when the session ends. `pin_count` is the observable
    /// surface that makes that property testable from outside the crate.
    pub fn pin_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|record| record.pinned)
            .count()
    }
}

/// Builds the GitHub client for one operation.
///
/// Exists as a trait for the same reason [`vault_port::VaultSecretPort`] lives
/// on this side of the boundary: the broker is the only crate that may hold
/// both a secret port and a connector, and it is also the only crate that can
/// be pointed at a fake origin in a test. Injecting the factory means the
/// production path and the test path run the *same* authorisation, redeeming
/// and response-shaping code, and the only thing a test substitutes is where
/// the bytes go.
pub trait ConnectorFactory {
    /// Builds a client for `audience` that lends from `secrets`.
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError>;

    /// Builds a PostgreSQL client for the requested audience, database,
    /// and role. The factory does not authorise the (database, role)
    /// pair; the connector does, before any I/O (M6-R3).
    ///
    /// The default implementation refuses every audience, because the
    /// production `LiveConnectorFactory` does not have a real PostgreSQL
    /// transport wired; tests override it with a factory that routes
    /// to a `fake_pg` origin.
    fn postgres(
        &self,
        _audience: Authority,
        _database: String,
        _role: String,
        _secrets: Arc<dyn SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Err(PgError::UnsupportedInThisBuild)
    }
}

/// The production factory: real DNS, real TLS, public addresses only.
#[derive(Debug, Clone, Default)]
pub struct LiveConnectorFactory;

impl ConnectorFactory for LiveConnectorFactory {
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError> {
        // 443 is GitHub's HTTPS port, stated here rather than inherited from a
        // config value the caller does not control.
        Ok(GithubClient::new(
            audience,
            443,
            AddressPolicy::default(),
            secrets,
        ))
    }

    fn postgres(
        &self,
        _audience: Authority,
        _database: String,
        _role: String,
        _secrets: Arc<dyn SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Err(PgError::UnsupportedInThisBuild)
    }
}

/// Broker-side state. M0 has no vault, so credential metadata is an in-memory
/// list seeded by tests; M1 makes it encrypted and persistent.
pub struct BrokerState {
    pub sessions: SessionStore,
    pub credentials: Vec<CredentialMetadata>,
    pub policy: PolicyEngine,
    /// M4: the tokens an agent holds instead of credentials (D3).
    pub surrogates: SurrogateRegistry,
    /// M4 CU-2.2: the secret-bearing side of the broker. `None` means no vault
    /// is open, and every semantic operation then refuses. That is the
    /// fail-closed reading: a broker that cannot reach a credential must not
    /// fall back to a direct or anonymous call.
    pub secrets: Option<Arc<dyn SecretPort>>,
    /// M4 CU-2.2: how to reach GitHub. Injected so a test can point the very
    /// same authorisation path at a local origin.
    pub connectors: Box<dyn ConnectorFactory>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            sessions: SessionStore::default(),
            credentials: Vec::new(),
            policy: PolicyEngine::default(),
            surrogates: SurrogateRegistry::default(),
            // Fail-closed by construction: the only way a semantic operation
            // can run is for something to have opened a vault and said so.
            // There is no `Default` that fabricates a port.
            secrets: None,
            connectors: Box::new(LiveConnectorFactory),
        }
    }
}

impl std::fmt::Debug for BrokerState {
    /// Hand-written because the two `dyn` fields are not `Debug`, and deriving
    /// would either fail or force `Debug` onto the traits for no gain.
    ///
    /// What it prints is deliberately thin: whether a vault is open is useful
    /// in a crash report, and what that vault contains is not something a
    /// `Debug` should be in a position to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerState")
            .field("sessions", &self.sessions)
            .field("credentials", &self.credentials.len())
            .field("surrogates", &self.surrogates)
            .field("vault_open", &self.secrets.is_some())
            .finish_non_exhaustive()
    }
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

        // The three semantic operations are the only paths from a surrogate to
        // a real credential, so they share one preamble: same ownership check,
        // same vault requirement, same argument validation, and the surrogate
        // spent in the same place. Splitting them into three near-copies is how
        // one of them ends up skipping the ownership check.
        Request::ReadIssue {
            session,
            surrogate,
            repo,
            number,
        } => {
            if let Err(denial) = state.authorize_github(session, peer) {
                return *denial;
            }
            // Validated before the token is spent. `redeem` consumes a use, and
            // an agent that sends `owner/repo/../../admin` would otherwise be
            // charged for a request that was refused on its own argument.
            if let Err(error) = validate_repo(&repo) {
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: error.to_string(),
                };
            }
            match state.surrogates.redeem(&surrogate, session, now_secs()) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.read_issue(&credential.to_wire(), &repo, number) {
                        Ok(issue) => Response::IssueRead {
                            title: issue.title,
                            body: issue.body,
                            state: issue.state,
                        },
                        // The provider's own body is never forwarded. M4-R1
                        // promises the three fields and nothing else, and an
                        // upstream body can carry anything the provider chose
                        // to put in it.
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }

        Request::CreateIssue {
            session,
            surrogate,
            repo,
            title,
            body,
        } => {
            if let Err(denial) = state.authorize_github(session, peer) {
                return *denial;
            }
            if let Err(error) = validate_repo(&repo) {
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: error.to_string(),
                };
            }
            match state.surrogates.redeem(&surrogate, session, now_secs()) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.create_issue(&credential.to_wire(), &repo, &title, &body) {
                        Ok(issue) => Response::IssueCreated {
                            number: issue.number,
                            url: issue.url,
                        },
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }

        Request::CreateRelease {
            session,
            surrogate,
            repo,
            tag,
            name,
            body,
        } => {
            if let Err(denial) = state.authorize_github(session, peer) {
                return *denial;
            }
            if let Err(error) = validate_repo(&repo) {
                return Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: error.to_string(),
                };
            }
            match state.surrogates.redeem(&surrogate, session, now_secs()) {
                Ok(credential) => {
                    let client = match state.github_client() {
                        Ok(client) => client,
                        Err(response) => return *response,
                    };
                    match client.create_release(&credential.to_wire(), &repo, &tag, &name, &body) {
                        Ok(release) => Response::ReleaseCreated {
                            tag: release.tag,
                            url: release.url,
                        },
                        Err(error) => github_failure(error),
                    }
                }
                Err(error) => surrogate_failure(error),
            }
        }
    }
}

/// The audience every semantic GitHub operation goes to.
///
/// One constant, not a request field. An agent that could name the host would
/// be able to point a credential at any endpoint that presents a valid
/// certificate for it, which is the generic HTTP escape hatch M4-R9 rules out.
const GITHUB_AUTHORITY: &str = "api.github.com";

impl BrokerState {
    /// The checks every brokered GitHub operation shares, before anything is
    /// spent or sent.
    ///
    /// Ownership first, then the vault. A session not owned by this peer must
    /// not even learn whether a vault is open, and a broker with no vault must
    /// refuse rather than reach GitHub unauthenticated.
    fn authorize_github(
        &self,
        session: AgentSessionId,
        peer: &WorkloadIdentity,
    ) -> Result<(), Box<Response>> {
        if !self.sessions.belongs_to(session, peer) {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into(),
            }));
        }
        if self.secrets.is_none() {
            return Err(Box::new(Response::Error {
                code: ErrorCode::Denied,
                // Explicit about *why* there is no degraded path. The
                // alternative reading of a missing vault is "call GitHub
                // anonymously", and for a private repository that quietly
                // becomes "act as if the credential were not needed".
                message: "no credential store is open, so no brokered operation can run".into(),
            }));
        }
        Ok(())
    }

    /// Builds the client for one operation, refusing if the broker has no vault.
    fn github_client(&self) -> Result<GithubClient, Box<Response>> {
        // `Response` is boxed in the error position because it carries two
        // `String`s inline; a `Result<GithubClient, Response>` would make every
        // `?` in the operation bodies copy a struct that has no business being
        // that large on a path that usually succeeds.
        let secrets = self.secrets.as_ref().ok_or_else(|| {
            Box::new(Response::Error {
                code: ErrorCode::Denied,
                message: "no credential store is open, so no brokered operation can run".into(),
            })
        })?;
        let authority = Authority::canonicalize(GITHUB_AUTHORITY).map_err(|error| {
            Box::new(Response::Error {
                code: ErrorCode::Upstream,
                message: format!("the GitHub authority is not usable: {error}"),
            })
        })?;
        self.connectors
            .github(authority, Arc::clone(secrets))
            .map_err(|error| Box::new(github_failure(error)))
    }
}

/// Why a surrogate was refused, as an IPC answer.
///
/// `Expired` and `Exhausted` are separate codes: one says "mint a new token",
/// the other says "you spent it, mint a new token", and an operator reading a
/// log needs to tell them apart.
fn surrogate_failure(error: SurrogateError) -> Response {
    use SurrogateError::*;
    let code = match error {
        Unknown | WrongSession => ErrorCode::Denied,
        Expired => ErrorCode::SurrogateExpired,
        Exhausted => ErrorCode::SurrogateExhausted,
    };
    Response::Error {
        code,
        // `SurrogateError`'s messages name the token's *properties*, never the
        // token and never the credential behind it.
        message: error.to_string(),
    }
}

/// Why a GitHub operation failed, as an IPC answer.
///
/// A credential the vault does not know is a provider-independent failure, so
/// it does not become `Upstream` either: the agent is not the problem, the
/// broker's own store is. It is reported as `InvalidRequest` rather than
/// `Denied` because `Denied` reads as "you are not allowed", and the agent
/// demonstrably was: it presented a token this broker minted. The message
/// carries the real cause, and it carries no credential name.
///
/// `Repo` is the one case that is the agent's own fault, and it is the only
/// one answered as such.
fn github_failure(error: GithubError) -> Response {
    let (code, message) = match error {
        GithubError::Repo(error) => (ErrorCode::InvalidRequest, error.to_string()),
        GithubError::Secret(asv_connector_http::SecretError::NotFound(_)) => (
            ErrorCode::InvalidRequest,
            "the credential this surrogate stands for is no longer in the vault".to_string(),
        ),
        GithubError::Secret(_) => (
            ErrorCode::InvalidRequest,
            "the credential could not be unlocked".to_string(),
        ),
        // Every transport failure keeps its own reason. The provider's body is
        // not part of it: an error an agent can read is also a place upstream
        // content would land.
        GithubError::Transport(error) => (ErrorCode::Upstream, error.to_string()),
        GithubError::Upstream { audience, detail } => (
            ErrorCode::Upstream,
            format!("{audience} answered without {detail}"),
        ),
    };
    Response::Error { code, message }
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

    /// A broker with no vault open refuses all three semantic operations, and
    /// refuses them as a *denial* rather than as "no such method".
    ///
    /// CU-2.2 wired these operations, so `UnknownMethod` is no longer the
    /// honest answer and keeping it would have meant preserving a weaker
    /// guarantee than the code now makes. The guarantee that survives, and is
    /// stronger, is the one that matters: no vault means no brokered call, ever,
    /// and no fallback to an anonymous or direct request. The response is
    /// `Denied` precisely so a caller can tell "this broker cannot do that" from
    /// "you asked for something that does not exist".
    #[test]
    fn semantic_operations_are_denied_while_no_vault_is_open() {
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
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Denied, "got {message:?}");
                    // The refusal has to say *why*, or an operator reads
                    // "denied" as a policy decision and goes looking for a
                    // policy that does not exist.
                    assert!(
                        message.contains("credential store"),
                        "the denial must name the missing vault, got {message:?}"
                    );
                }
                other => panic!("a vaultless broker must not answer {other:?}"),
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

/// End-to-end tests for the brokered GitHub path (M4 CU-2.2).
///
/// These are the tests that matter most for this work item, because they are
/// the only ones that cross every boundary at once: an IPC request in, a
/// surrogate redeemed, a credential unlocked from a real encrypted vault, an
/// authenticated request out over real TLS, and a response shaped back. Each
/// layer has its own unit tests, and every one of them would still pass if the
/// layers were wired to each other wrongly.
#[cfg(test)]
mod e2e {
    use super::*;

    use asv_connector_http::fake_origin::{self, Reply};
    use asv_connector_http::{AddressPolicy, Certificate, GithubClient, ResolvedAudience};
    use asv_domain::secret::SecretBytes;
    use asv_identity::PeerCredentials;
    use asv_vault::{KdfParams, VaultKey, VaultStore};
    use secrecy::SecretString;

    use std::net::{IpAddr, Ipv4Addr};

    /// The secret the vault holds. Every assertion below is about this exact
    /// string appearing where it should and nowhere else.
    const CANARY: &str = "ASV-CANARY-e2e-5c1a-DO-NOT-LEAK";

    /// A factory that points the connector at a local TLS origin.
    ///
    /// Built per origin because the certificate and the port differ, and
    /// because sharing one across tests would let them observe each other's
    /// requests.
    struct LocalFactory {
        resolved: ResolvedAudience,
        root: Certificate,
    }

    impl ConnectorFactory for LocalFactory {
        fn github(
            &self,
            _audience: Authority,
            secrets: Arc<dyn SecretPort>,
        ) -> Result<GithubClient, GithubError> {
            // Loopback is allowed here and only here. The production factory
            // never sets it, which is the whole reason this substitution is
            // visible in the source rather than hidden in a config value.
            Ok(GithubClient::pinned_to(
                self.resolved.clone(),
                AddressPolicy {
                    allow_loopback: true,
                },
                secrets,
            )
            .trusting(vec![self.root.clone()]))
        }

        // M6-T7: test factory does not route to a fake_pg; production
        // shape is enough for the existing HTTP tests. Any test that
        // exercises the broker-side PostgreSQL flow installs a
        // factory whose postgres routes to fake_pg explicitly.
        fn postgres(
            &self,
            audience: Authority,
            database: String,
            role: String,
            _secrets: Arc<dyn SecretPort>,
        ) -> Result<PostgresClient, PgError> {
            Ok(PostgresClient::new(audience, database, role))
        }
    }

    fn pass() -> SecretString {
        SecretString::from("test-passphrase".to_string())
    }

    /// A broker with a real vault open, a credential registered under `id`, a
    /// pinned peer, and a minted surrogate pointing at the local origin.
    ///
    /// Returns the state, the peer, the session, the token, the origin *and*
    /// the vault's directory. The directory has to outlive the call: the
    /// broker holds no file handle, it re-opens the vault by path on every
    /// lend, so a `TempDir` dropped here would turn every operation into an
    /// "io error: no such file". The tests therefore keep it alive and drop it
    /// last, which is the same lifetime a real deployment has.
    #[allow(clippy::type_complexity)]
    fn brokered(
        reply: Reply,
    ) -> (
        BrokerState,
        WorkloadIdentity,
        AgentSessionId,
        String,
        fake_origin::FakeOrigin,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = VaultStore::create(
            dir.path().join("v.asv"),
            &pass(),
            KdfParams::fast_for_tests(),
        )
        .expect("create");
        let key: VaultKey = store.header().unlock(&pass()).expect("unlock");

        // The vault's record id has to be the same string the broker will ask
        // for. The broker registers the id it mints a surrogate over, and the
        // vault is keyed by that id's wire form.
        // `CredentialMetadata::new` here is the *domain* one, which mints a
        // fresh UUID. The vault is then keyed by that id's wire form, so the
        // string the broker redeems a surrogate to is the string the vault can
        // unlock. Qualifying both types matters: the domain and the vault each
        // have their own `CredentialKind` and `CredentialMetadata`, and an
        // unqualified import silently picks the wrong pair.
        let mut state = BrokerState::default();
        let credential = insert_credential(
            &mut state,
            asv_domain::CredentialMetadata::new(
                "github-e2e",
                asv_domain::CredentialKind::BearerToken,
            ),
        );
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    credential.to_wire(),
                    "e2e",
                    asv_vault::CredentialKind::Opaque,
                    "github",
                    "a",
                    1,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert");

        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::new(store),
            Arc::new(key),
        )));

        let origin = fake_origin::start(reply);
        state.connectors = Box::new(LocalFactory {
            resolved: ResolvedAudience {
                authority: Authority::canonicalize(&origin.certified_for).expect("authority"),
                port: origin.port,
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
            root: origin.certificate(),
        });

        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pidfd_open on self");
        let session = state.sessions.create("/repo".to_string(), &peer);
        let token = match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("expected a token, got {other:?}"),
        };
        (state, peer, session, token, origin, dir)
    }

    fn issue_json() -> String {
        serde_json::json!({
            "number": 7,
            "title": "a title",
            "body": "a body",
            "state": "open",
            "html_url": "https://github.com/o/r/issues/7",
            // A field the broker must not forward. If it ever appears in a
            // response, the "three fields and nothing else" promise is broken.
            "secret_sauce": "MUST-NOT-BE-FORWARDED"
        })
        .to_string()
    }

    /// The whole path works: a surrogate becomes an authenticated request that
    /// the provider answers, and the agent gets the three promised fields.
    #[test]
    fn a_read_issue_sends_the_credential_and_returns_only_the_promised_fields() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert_eq!(
            response,
            Response::IssueRead {
                title: "a title".into(),
                body: "a body".into(),
                state: "open".into(),
            },
            "the read must return exactly the three promised fields"
        );

        let sent = origin.last().expect("the provider was contacted");
        assert_eq!(sent.method(), "GET");
        assert_eq!(sent.path(), "/repos/o/r/issues/7");
        // The credential really travelled, and only to the provider.
        assert_eq!(
            sent.header("authorization"),
            Some(format!("token {CANARY}").as_str()),
            "the request was not authenticated with the vaulted credential"
        );
        // And the response never carried the secret back to the agent.
        assert!(
            !format!("{response:?}").contains(CANARY),
            "the response leaked the credential: {response:?}"
        );
        assert!(
            !format!("{response:?}").contains("MUST-NOT-BE-FORWARDED"),
            "the response forwarded an unpromised field: {response:?}"
        );
    }

    /// Creating an issue spends exactly one use, and the second attempt with
    /// the same token fails as exhausted.
    #[test]
    fn a_create_issue_spends_one_use_and_a_second_attempt_is_exhausted() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        let request = |surrogate: String| Request::CreateIssue {
            session,
            surrogate,
            repo: "o/r".into(),
            title: "t".into(),
            body: "b".into(),
        };

        let first = handle(&mut state, &peer, request(token.clone()));
        assert_eq!(
            first,
            Response::IssueCreated {
                number: 7,
                url: "https://github.com/o/r/issues/7".into()
            }
        );

        let second = handle(&mut state, &peer, request(token.clone()));
        // max_uses was 2, so the second call is the last one that can work.
        assert!(
            !matches!(second, Response::Error { .. }),
            "the second use was refused: {second:?}"
        );

        let third = handle(&mut state, &peer, request(token));
        assert_eq!(
            third,
            Response::Error {
                code: ErrorCode::SurrogateExhausted,
                message: third_message(&third)
            },
            "the budget was not enforced"
        );
        assert_eq!(
            origin.connections(),
            2,
            "the refused call reached the provider"
        );
    }

    /// A surrogate minted for one session is refused from another, and the
    /// refusal costs nothing.
    ///
    /// The second session belongs to the *same* peer on purpose: this is the
    /// test for `redeem`'s `WrongSession` check, which is the one an attacker
    /// hits by running two sessions of their own and moving a token between
    /// them. The different-peer case is a separate guarantee (that the session
    /// is not owned by the caller) and has its own test above.
    #[test]
    fn a_surrogate_from_another_session_of_the_same_peer_is_refused() {
        let (mut state, peer, _session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        let other = state.sessions.create("/other".to_string(), &peer);

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session: other,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        // Refused for belonging to another session, and the message says so
        // rather than claiming the token is unknown: the broker does know it,
        // and a message that hid that would cost an agent a debugging session.
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "surrogate was minted for a different session".into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a foreign session reached the provider"
        );
    }

    /// A session belonging to another process is refused before anything else.
    #[test]
    fn a_session_belonging_to_another_process_is_refused() {
        let (mut state, peer, _session, token, origin, _dir) = brokered(Reply::Json(issue_json()));
        // A different pid, which is what `belongs_to` actually compares. A
        // same-pid-different-uid fixture would not exercise the check: the
        // broker records the pid at session creation and compares pids, so
        // two identities for one process are one peer as far as it is
        // concerned. Pinning is not required for a refusal, which is the
        // point: an unpinned stranger is still a stranger.
        let mut stranger = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32 + 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        stranger.pin_pidfd().ok();
        let foreign = state.sessions.create("/theirs".to_string(), &stranger);

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session: foreign,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        // Note the direction: `handle` is given `peer`, and the session belongs
        // to `stranger`. The check is on who owns the session, not on who is
        // calling.
        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a foreign peer reached the provider"
        );
    }

    /// The broker's own validation runs before the token is redeemed, which is
    /// the only thing the connector's cannot do.
    ///
    /// A `max_uses` of one makes the difference observable: with the broker's
    /// check removed, the connector still refuses the malformed repository and
    /// the caller still sees `InvalidRequest`, but by then `redeem` has already
    /// spent the only use, so the legitimate call below is refused as
    /// `SurrogateExhausted`. Two layers returning the same code for the same
    /// input is exactly the arrangement that hides a missing check, so the
    /// budget is what this test actually asserts.
    #[test]
    fn a_malformed_repo_does_not_spend_the_only_use() {
        // The token from the fixture is re-minted below with a single use, so
        // the fixture's two-use one is not bound here.
        let (mut state, peer, session, _token, origin, _dir) = brokered(Reply::Json(issue_json()));
        // Re-mint with a single use. `brokered` grants two so other tests can
        // make two calls; here one is the whole point.
        state.surrogates = SurrogateRegistry::default();
        let credential = state.credentials[0].id;
        let token = match handle(
            &mut state,
            &peer,
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 1,
                ttl_secs: 60,
            },
        ) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("expected a token, got {other:?}"),
        };

        let refused = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r/../../admin".into(),
                number: 7,
            },
        );
        assert_eq!(
            refused,
            Response::Error {
                code: ErrorCode::InvalidRequest,
                message: "repository must be `owner/repo` with non-empty ASCII path components"
                    .into()
            }
        );
        assert_eq!(
            origin.connections(),
            0,
            "a malformed repo reached the provider"
        );

        // The one use is still there. If the broker validated after redeeming,
        // this would be `SurrogateExhausted`.
        let ok = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );
        assert!(
            matches!(ok, Response::IssueRead { .. }),
            "the refused call spent the budget: {ok:?}"
        );
    }

    /// A token that does not exist never reaches the provider, and the error
    /// says nothing about what does exist.
    #[test]
    fn an_unknown_token_never_reaches_the_provider() {
        let (mut state, peer, session, _token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: "asv1_not-a-real-token".into(),
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert_eq!(
            response,
            Response::Error {
                code: ErrorCode::Denied,
                message: "no surrogate matches the presented token".into()
            }
        );
        assert_eq!(origin.connections(), 0);
    }

    /// Ending the session revokes every surrogate it minted, so a token that
    /// was valid a moment ago is now refused.
    #[test]
    fn ending_a_session_revokes_its_surrogates() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let before = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token.clone(),
                repo: "o/r".into(),
                number: 7,
            },
        );
        assert!(
            matches!(before, Response::IssueRead { .. }),
            "got {before:?}"
        );

        handle(&mut state, &peer, Request::EndSession { session });

        let after = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );
        // The session itself is gone, so the refusal is about ownership, not
        // about the token. Both refusals are `Denied` and neither reaches the
        // provider; which of the two fired is not the point of the test, and
        // asserting on the exact wording here would only pin an implementation
        // detail of the session store.
        assert_eq!(
            after,
            Response::Error {
                code: ErrorCode::Denied,
                message: "session is not owned by the authenticated peer".into()
            }
        );
        assert_eq!(
            origin.connections(),
            1,
            "the post-revocation call reached the provider"
        );
    }

    /// The provider's error is relayed as an upstream failure, and the
    /// provider's own body is not.
    #[test]
    fn an_upstream_failure_is_reported_as_upstream_and_carries_no_body() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Status {
            status: 404,
            body: "{\"message\":\"MUST-NOT-BE-FORWARDED\"}".into(),
        });

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        match response {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::Upstream);
                assert!(
                    message.contains("404"),
                    "the status must be reported: {message}"
                );
                assert!(
                    !message.contains("MUST-NOT-BE-FORWARDED"),
                    "the provider's body was relayed: {message}"
                );
            }
            other => panic!("a 404 must be an error, got {other:?}"),
        }
        assert_eq!(origin.connections(), 1);
    }

    /// A creation sends a JSON body built from the agent's text, and the
    /// broker forwards only the two identity fields back.
    #[test]
    fn a_create_release_sends_the_tag_and_returns_only_tag_and_url() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(
            serde_json::json!({
                "tag_name": "v1.2.3",
                "html_url": "https://github.com/o/r/releases/v1.2.3",
                "upload_url": "MUST-NOT-BE-FORWARDED"
            })
            .to_string(),
        ));

        let response = handle(
            &mut state,
            &peer,
            Request::CreateRelease {
                session,
                surrogate: token,
                repo: "o/r".into(),
                tag: "v1.2.3".into(),
                name: "Release".into(),
                body: "notes".into(),
            },
        );

        assert_eq!(
            response,
            Response::ReleaseCreated {
                tag: "v1.2.3".into(),
                url: "https://github.com/o/r/releases/v1.2.3".into(),
            }
        );

        let sent = origin.last().expect("the provider was contacted");
        assert_eq!(sent.method(), "POST");
        assert_eq!(sent.path(), "/repos/o/r/releases");
        let body = sent.body.as_str();
        assert!(body.contains("\"tag_name\":\"v1.2.3\""), "body was {body}");
        assert_eq!(
            sent.header("authorization"),
            Some(format!("token {CANARY}").as_str())
        );
        assert!(
            !format!("{response:?}").contains("MUST-NOT-BE-FORWARDED"),
            "an unpromised field was forwarded: {response:?}"
        );
    }

    /// A token cannot be used to reach anything but GitHub. The broker builds
    /// the client for a fixed authority, so there is no request field that
    /// could redirect the credential elsewhere.
    #[test]
    fn the_request_cannot_choose_the_audience() {
        let (mut state, peer, session, token, origin, _dir) = brokered(Reply::Json(issue_json()));

        let response = handle(
            &mut state,
            &peer,
            Request::ReadIssue {
                session,
                surrogate: token,
                repo: "o/r".into(),
                number: 7,
            },
        );

        assert!(
            matches!(response, Response::IssueRead { .. }),
            "got {response:?}"
        );
        let sent = origin.last().expect("the provider was contacted");
        // The only host that saw the credential is the one the broker chose.
        assert_eq!(origin.connections(), 1);
        assert_eq!(sent.path(), "/repos/o/r/issues/7");
    }

    /// The message of an error response, for use in an expected value.
    fn third_message(response: &Response) -> String {
        match response {
            Response::Error { message, .. } => message.clone(),
            other => panic!("expected an error, got {other:?}"),
        }
    }
}
