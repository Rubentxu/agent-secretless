//! Deny-by-default authorization state for M3.
//!
//! Cedar is kept behind this adapter. The public types contain authorization
//! metadata only and cannot carry credential material.

use asv_domain::{Action, AgentSessionId, ApprovalId, CapabilityId, Decision, Resource};
use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_TEXT: &str = r#"
permit (principal, action == Action::"git_fetch", resource);
permit (principal, action == Action::"ssh_connect", resource);
permit (principal, action == Action::"git_push", resource)
when { context.protected_ref == false || context.approved == true };
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorizationInstant(pub u64);

pub trait Clock: Send + Sync {
    fn now(&self) -> AuthorizationInstant;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> AuthorizationInstant {
        AuthorizationInstant(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ManualClock {
    now: Arc<Mutex<AuthorizationInstant>>,
}

impl ManualClock {
    pub fn new(now: AuthorizationInstant) -> Self {
        Self {
            now: Arc::new(Mutex::new(now)),
        }
    }

    pub fn set(&self, now: AuthorizationInstant) {
        *self.now.lock().expect("manual clock lock poisoned") = now;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> AuthorizationInstant {
        *self.now.lock().expect("manual clock lock poisoned")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub workspace: String,
    pub protected_ref: Option<String>,
    pub request_digest: Option<String>,
    pub peer_uid: u32,
}

impl PolicyContext {
    fn is_protected_main(&self) -> bool {
        self.protected_ref.as_deref() == Some("main")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub session: AgentSessionId,
    pub action: Action,
    pub resource: Resource,
    pub context: PolicyContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: CapabilityId,
    pub session: AgentSessionId,
    pub action: Action,
    pub resource: Resource,
    pub issued_at: AuthorizationInstant,
    pub expires_at: AuthorizationInstant,
    pub remaining_uses: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: ApprovalId,
    pub session: AgentSessionId,
    pub action: Action,
    pub resource: Resource,
    pub request_digest: Option<String>,
    pub expires_at: AuthorizationInstant,
    pub remaining_uses: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    AllowedByPolicy,
    NoMatchingPolicy,
    ApprovalRequired,
    ApprovalMismatch,
    ApprovalExpired,
    ApprovalConsumed,
    CapabilityMismatch,
    CapabilityExpired,
    CapabilityExhausted,
    SessionRevoked,
    EngineFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainResult {
    pub decision: Decision,
    pub reason: ReasonCode,
    pub rule: String,
    pub session: AgentSessionId,
    pub action: Action,
    pub resource: Resource,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy engine failed closed: {0}")]
    Engine(String),
}

#[derive(Debug, Default)]
struct Store {
    grants: HashMap<CapabilityId, CapabilityGrant>,
    approvals: HashMap<ApprovalId, Approval>,
    revoked: std::collections::HashSet<AgentSessionId>,
}

pub struct PolicyEngine {
    authorizer: Authorizer,
    policies: PolicySet,
    store: Mutex<Store>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine").finish_non_exhaustive()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock)).expect("built-in Cedar policy must parse")
    }
}

impl PolicyEngine {
    pub fn new(clock: Arc<dyn Clock>) -> Result<Self, PolicyError> {
        let policies = PolicySet::from_str(POLICY_TEXT)
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            store: Mutex::new(Store::default()),
            clock,
        })
    }

    pub fn issue_grant(
        &self,
        request: &AuthorizationRequest,
        ttl_secs: u64,
        remaining_uses: Option<u32>,
    ) -> CapabilityGrant {
        let issued_at = self.clock.now();
        let grant = CapabilityGrant {
            id: CapabilityId::new(),
            session: request.session,
            action: request.action.clone(),
            resource: request.resource.clone(),
            issued_at,
            expires_at: AuthorizationInstant(issued_at.0.saturating_add(ttl_secs)),
            remaining_uses,
        };
        self.store
            .lock()
            .expect("policy store lock poisoned")
            .grants
            .insert(grant.id, grant.clone());
        grant
    }

    pub fn issue_approval(
        &self,
        request: &AuthorizationRequest,
        ttl_secs: u64,
        remaining_uses: u32,
    ) -> Approval {
        let approval = Approval {
            id: ApprovalId::new(),
            session: request.session,
            action: request.action.clone(),
            resource: request.resource.clone(),
            request_digest: request.context.request_digest.clone(),
            expires_at: AuthorizationInstant(self.clock.now().0.saturating_add(ttl_secs)),
            remaining_uses,
        };
        self.store
            .lock()
            .expect("policy store lock poisoned")
            .approvals
            .insert(approval.id, approval.clone());
        approval
    }

    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        capability: Option<CapabilityId>,
        approval: Option<ApprovalId>,
    ) -> ExplainResult {
        let now = self.clock.now();
        let mut store = self.store.lock().expect("policy store lock poisoned");
        if store.revoked.contains(&request.session) {
            return self.result(
                request,
                Decision::Deny {
                    reason: "session revoked".into(),
                },
                ReasonCode::SessionRevoked,
            );
        }
        if let Some(id) = capability {
            let Some(grant) = store.grants.get_mut(&id) else {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "capability mismatch".into(),
                    },
                    ReasonCode::CapabilityMismatch,
                );
            };
            if grant.session != request.session
                || grant.action != request.action
                || grant.resource != request.resource
            {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "capability mismatch".into(),
                    },
                    ReasonCode::CapabilityMismatch,
                );
            }
            if now >= grant.expires_at {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "capability expired".into(),
                    },
                    ReasonCode::CapabilityExpired,
                );
            }
            if matches!(grant.remaining_uses, Some(0)) {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "capability exhausted".into(),
                    },
                    ReasonCode::CapabilityExhausted,
                );
            }
        }
        let mut approval_validated = false;
        if request.action == Action::GitPush && request.context.is_protected_main() {
            let Some(approval_id) = approval else {
                return self.result(
                    request,
                    Decision::RequireApproval {
                        approval: ApprovalId::new(),
                    },
                    ReasonCode::ApprovalRequired,
                );
            };
            let Some(existing) = store.approvals.get_mut(&approval_id) else {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "approval mismatch".into(),
                    },
                    ReasonCode::ApprovalMismatch,
                );
            };
            if existing.session != request.session
                || existing.action != request.action
                || existing.resource != request.resource
                || existing.request_digest != request.context.request_digest
            {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "approval mismatch".into(),
                    },
                    ReasonCode::ApprovalMismatch,
                );
            }
            if now >= existing.expires_at {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "approval expired".into(),
                    },
                    ReasonCode::ApprovalExpired,
                );
            }
            if existing.remaining_uses == 0 {
                return self.result(
                    request,
                    Decision::Deny {
                        reason: "approval consumed".into(),
                    },
                    ReasonCode::ApprovalConsumed,
                );
            }
            existing.remaining_uses -= 1;
            approval_validated = true;
        }
        let decision = match self.cedar_decision(request, approval_validated) {
            Ok(true) => Decision::Allow,
            Ok(false) => Decision::Deny {
                reason: "no matching policy".into(),
            },
            Err(_) => Decision::Deny {
                reason: "policy engine failure".into(),
            },
        };
        if matches!(decision, Decision::Allow) {
            if let Some(id) = capability {
                if let Some(grant) = store.grants.get_mut(&id) {
                    if let Some(uses) = &mut grant.remaining_uses {
                        *uses = uses.saturating_sub(1);
                    }
                }
            }
        }
        let reason = if decision.is_allowed() {
            ReasonCode::AllowedByPolicy
        } else {
            ReasonCode::NoMatchingPolicy
        };
        self.result(request, decision, reason)
    }

    pub fn explain(&self, request: &AuthorizationRequest) -> ExplainResult {
        if request.action == Action::GitPush && request.context.is_protected_main() {
            return self.result(
                request,
                Decision::RequireApproval {
                    approval: ApprovalId::new(),
                },
                ReasonCode::ApprovalRequired,
            );
        }
        match self.cedar_decision(request, false) {
            Ok(true) => self.result(request, Decision::Allow, ReasonCode::AllowedByPolicy),
            Ok(false) => self.result(
                request,
                Decision::Deny {
                    reason: "no matching policy".into(),
                },
                ReasonCode::NoMatchingPolicy,
            ),
            Err(_) => self.result(
                request,
                Decision::Deny {
                    reason: "policy engine failure".into(),
                },
                ReasonCode::EngineFailure,
            ),
        }
    }

    pub fn revoke_session(&self, session: AgentSessionId) {
        let mut store = self.store.lock().expect("policy store lock poisoned");
        store.revoked.insert(session);
        store.grants.retain(|_, grant| grant.session != session);
        store
            .approvals
            .retain(|_, approval| approval.session != session);
    }

    fn result(
        &self,
        request: &AuthorizationRequest,
        decision: Decision,
        reason: ReasonCode,
    ) -> ExplainResult {
        ExplainResult {
            decision,
            reason,
            rule: "m3-default-policy".into(),
            session: request.session,
            action: request.action.clone(),
            resource: request.resource.clone(),
        }
    }

    fn cedar_decision(
        &self,
        request: &AuthorizationRequest,
        approval_validated: bool,
    ) -> Result<bool, PolicyError> {
        let principal = EntityUid::from_str(&format!("AgentSession::\"{}\"", request.session))
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let action = EntityUid::from_str(&format!("Action::\"{}\"", action_name(&request.action)))
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let resource = EntityUid::from_str(&format!(
            "Repository::\"{}\"",
            resource_name(&request.resource)
        ))
        .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let protected = if request.context.is_protected_main() {
            "true"
        } else {
            "false"
        };
        let context = Context::from_pairs([
            (
                "protected_ref".into(),
                RestrictedExpression::from_str(protected)
                    .map_err(|error| PolicyError::Engine(error.to_string()))?,
            ),
            (
                "approved".into(),
                RestrictedExpression::from_str(if approval_validated { "true" } else { "false" })
                    .map_err(|error| PolicyError::Engine(error.to_string()))?,
            ),
        ])
        .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let request = Request::new(principal, action, resource, context, None)
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        Ok(self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty())
            .decision()
            == cedar_policy::Decision::Allow)
    }
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::GitFetch => "git_fetch",
        Action::GitPush => "git_push",
        Action::SshConnect => "ssh_connect",
        _ => "unsupported",
    }
}

fn resource_name(resource: &Resource) -> String {
    match resource {
        Resource::Repository { owner, name } => format!("{owner}/{name}"),
        Resource::Database { name, role } => format!("db:{name}/{role}"),
        Resource::Host { hostname } => format!("host:{hostname}"),
        Resource::Api { audience } => format!("api:{audience}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: Action, protected_ref: Option<&str>) -> AuthorizationRequest {
        AuthorizationRequest {
            session: AgentSessionId::new(),
            action,
            resource: Resource::Repository {
                owner: "acme".into(),
                name: "app".into(),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: protected_ref.map(str::to_owned),
                request_digest: Some("digest".into()),
                peer_uid: 1000,
            },
        }
    }

    #[test]
    fn cedar_policy_allows_fetch_and_denies_unknown_action() {
        let engine = PolicyEngine::default();
        assert!(engine
            .authorize(&request(Action::GitFetch, None), None, None)
            .decision
            .is_allowed());
        assert!(!engine
            .authorize(&request(Action::GitHubIssueCreate, None), None, None)
            .decision
            .is_allowed());
    }

    #[test]
    fn protected_main_requires_exact_single_use_approval() {
        let clock = Arc::new(ManualClock::new(AuthorizationInstant(10)));
        let engine = PolicyEngine::new(clock).unwrap();
        let req = request(Action::GitPush, Some("main"));
        let approval = engine.issue_approval(&req, 10, 1);
        assert!(!engine.authorize(&req, None, None).decision.is_allowed());
        assert!(engine
            .authorize(&req, None, Some(approval.id))
            .decision
            .is_allowed());
        assert!(!engine
            .authorize(&req, None, Some(approval.id))
            .decision
            .is_allowed());
    }

    #[test]
    fn expiry_and_revoke_fail_closed() {
        let clock = Arc::new(ManualClock::new(AuthorizationInstant(10)));
        let engine = PolicyEngine::new(clock.clone()).unwrap();
        let req = request(Action::GitFetch, None);
        let grant = engine.issue_grant(&req, 5, Some(1));
        assert!(engine
            .authorize(&req, Some(grant.id), None)
            .decision
            .is_allowed());
        clock.set(AuthorizationInstant(20));
        assert!(!engine
            .authorize(&req, Some(grant.id), None)
            .decision
            .is_allowed());
        engine.revoke_session(req.session);
        assert_eq!(engine.explain(&req).reason, ReasonCode::AllowedByPolicy);
        assert!(!engine.authorize(&req, None, None).decision.is_allowed());
    }

    #[test]
    fn explain_does_not_consume_approval() {
        let engine = PolicyEngine::default();
        let req = request(Action::GitPush, Some("main"));
        let approval = engine.issue_approval(&req, 10, 1);
        let _ = engine.explain(&req);
        assert!(engine
            .authorize(&req, None, Some(approval.id))
            .decision
            .is_allowed());
    }
}
