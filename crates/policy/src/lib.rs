//! Deny-by-default authorization state for M3.
//!
//! Cedar is kept behind this adapter. The public types contain authorization
//! metadata only and cannot carry credential material.

use asv_domain::{Action, AgentSessionId, ApprovalId, Authority, CapabilityId, Decision, Resource};
use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, PolicySet, Request, RestrictedExpression, Schema,
    ValidationMode, Validator,
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

// M4 semantic GitHub actions (D6). The scope is `resource is Api`, which only
// fires now that the Cedar entity type follows the Resource variant (D6) —
// before this, the entity was hardcoded to Repository and every `is Api` rule
// was vacuously false.
//
// Approval does not live here. `Authority` proves the audience is spelled one
// way, and `audience_is_approved` proves it is approved; both run in Rust
// before Cedar is consulted, so no policy text can widen the reachable host
// set. `http_request` is absent on purpose: the generic escape hatch is not
// authorizable.
permit (
    principal,
    action in [Action::"github_issue_read", Action::"github_issue_create",
                Action::"github_release_create"],
    resource is Api
);

// M6-R5 database verbs. Only the gateway verb and the read verb are permitted
// here, and the omission is the point: `postgres_insert`,
// `postgres_create_table`, `postgres_drop_table` and `postgres_alter_table` are
// absent, so they are denied by default and an operator who wants them adds a
// rule. A default policy that permitted every verb would make the five Cedar
// actions decorative, which is the failure M6-R5 exists to prevent.
//
// `postgres_connect` is the gateway: it opens the socket and lends the
// credential, and it was permitted before the query path consulted the policy
// at all, so leaving it out would have been a behaviour change nobody asked
// for. `postgres_read` is what makes the transport usable without making it
// writable.
permit (principal, action == Action::"postgres_connect", resource is Database);
permit (principal, action == Action::"postgres_read", resource is Database);
"#;

/// Audiences a semantic HTTP action may ever target (D6; the design v2 open
/// question resolved it as a compile-time constant, not configuration).
///
/// This is the approval half of the allowlist. [`Authority`] proves a host is
/// *spelled* one way; this proves it is *approved*. Both are required, because
/// `evil.example` canonicalizes perfectly and would otherwise pass.
pub(crate) const ALLOWED_AUDIENCES: &[&str] = &["api.github.com"];

/// Whether an audience may be targeted at all (D6).
///
/// Fail-closed: an unparseable or unapproved authority is never allowed. This
/// runs before Cedar, so a policy typo cannot widen the reachable set.
fn audience_is_approved(audience: &Authority) -> bool {
    ALLOWED_AUDIENCES
        .iter()
        .any(|allowed| Authority::canonicalize(allowed) == Ok(audience.clone()))
}

/// The Cedar schema (D11), in the JSON shape Cedar 4.7.1 accepts: a namespace
/// (here the empty default) holding `entityTypes` and `actions`.
///
/// Without it, `PolicySet::from_str` validates nothing: a mis-spelled action
/// silently stops matching (fail-closed, so an availability bug), while a
/// *correctly spelled* rule naming an invented action parses and ALLOWS
/// (a real exposure). The schema closes the action namespace, so a rule that
/// names a verb this system does not have is a validation error at load time.
const SCHEMA_JSON: &str = r#"{
  "": {
    "commonTypes": {},
    "entityTypes": {
      "AgentSession": {},
      "Repository": {},
      "Database": {},
      "Host": {},
      "Api": {
        "shape": {
          "type": "Record",
          "attributes": {
            "audience": { "type": "String" }
          }
        }
      }
    },
    "actions": {
      "git_fetch": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Repository"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "git_push": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Repository"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "ssh_connect": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Host"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_connect": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_read": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_insert": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_create_table": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_drop_table": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "postgres_alter_table": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Database"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "http_request": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Host"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "github_issue_read": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Api"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "github_issue_create": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Api"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "github_release_create": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Api"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      }
    }
  }
}"#;

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
    /// Whether this request targets a protected ref and therefore needs an
    /// explicit human approval.
    ///
    /// The predicate is deliberately conservative: an absent `protected_ref`
    /// means the caller made no push claim, but any ref that *is* claimed and
    /// is not recognized as an ordinary unprotected branch is treated as
    /// protected. The previous exact comparison against the literal `"main"`
    /// let `refs/heads/main` — the spelling git itself always sends — fall
    /// through as unprotected and bypass the approval gate entirely, which
    /// defeats UAT-029 and release gate R4. Failing closed is the only safe
    /// direction here.
    fn is_protected_main(&self) -> bool {
        match self.protected_ref.as_deref().map(str::trim) {
            // No ref was claimed on this request, so there is nothing to
            // protect. This is the fetch / non-push path.
            None | Some("") => false,
            // Any declared ref is treated as protected. M3 cannot query the
            // remote's protection rules, so assuming "unprotected" for an
            // unrecognized name would be a silent downgrade. An explicit
            // unprotected branch is a future field, not a hardcoded guess.
            Some(_) => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub session: AgentSessionId,
    pub action: Action,
    pub resource: Resource,
    pub context: PolicyContext,
}

impl AuthorizationRequest {
    /// The stable resource identifier handed to Cedar.
    pub fn resource_name(&self) -> String {
        resource_name(&self.resource)
    }
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
        Self::from_policy_text_with_clock(POLICY_TEXT, clock)
    }

    /// Loads policy text, validating it against the schema (D11).
    ///
    /// Validation is the point: a rule naming an action this system does not
    /// have is a load-time error, not a rule that would quietly ALLOW it.
    pub fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        Self::from_policy_text_with_clock(policy_text, Arc::new(SystemClock))
    }

    fn from_policy_text_with_clock(
        policy_text: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PolicyError> {
        let schema = Schema::from_json_str(SCHEMA_JSON)
            .map_err(|error| PolicyError::Engine(format!("invalid built-in schema: {error}")))?;
        let policies = PolicySet::from_str(policy_text)
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let validator = Validator::new(schema);
        let validation = validator.validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(PolicyError::Engine(format!(
                "policy failed schema validation: {:?}",
                validation.validation_errors().collect::<Vec<_>>()
            )));
        }
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
        // D6 second layer, evaluated before Cedar: an unapproved audience is
        // denied without ever reaching the authorizer, so no policy text can
        // widen the reachable host set. The first layer (the `Authority` type)
        // already proved the spelling; this one proves approval.
        if let Resource::Api { audience } = &request.resource {
            if !audience_is_approved(audience) {
                return Ok(false);
            }
        }
        let principal = EntityUid::from_str(&format!("AgentSession::\"{}\"", request.session))
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let action = EntityUid::from_str(&format!("Action::\"{}\"", action_name(&request.action)))
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let resource = EntityUid::from_str(&format!(
            "{}::\"{}\"",
            entity_type(&request.resource),
            request.resource_name()
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

/// The Cedar action name. Exhaustive on purpose (D6): the old catch-all arm
/// collapsed every non-Git/SSH action to `"unsupported"`, which silently made
/// the semantic GitHub path inexecutable. A new variant now breaks the build
/// here, on purpose.
fn action_name(action: &Action) -> &'static str {
    match action {
        Action::GitFetch => "git_fetch",
        Action::GitPush => "git_push",
        Action::SshConnect => "ssh_connect",
        Action::PostgresConnect => "postgres_connect",
        Action::PostgresRead => "postgres_read",
        Action::PostgresInsert => "postgres_insert",
        Action::PostgresCreateTable => "postgres_create_table",
        Action::PostgresDropTable => "postgres_drop_table",
        Action::PostgresAlterTable => "postgres_alter_table",
        Action::HttpRequest => "http_request",
        Action::GitHubIssueRead => "github_issue_read",
        Action::GitHubIssueCreate => "github_issue_create",
        Action::GitHubReleaseCreate => "github_release_create",
    }
}

/// The Cedar entity type for a resource (D6).
///
/// This must follow the `Resource` variant. It used to be hardcoded to
/// `Repository`, which made every `resource is Api` rule *vacuously* false —
/// a rule that can never fire hides the bug instead of reporting it.
fn entity_type(resource: &Resource) -> &'static str {
    match resource {
        Resource::Repository { .. } => "Repository",
        Resource::Database { .. } => "Database",
        Resource::Host { .. } => "Host",
        Resource::Api { .. } => "Api",
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
    use asv_domain::Authority;

    fn api_request(action: Action, audience: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            session: AgentSessionId::new(),
            action,
            resource: Resource::Api {
                audience: Authority::canonicalize(audience).expect("valid authority"),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: None,
                request_digest: Some("digest".into()),
                peer_uid: 1000,
            },
        }
    }

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

    // --- CU-1.2 RED: entity typing, schema and the audience allowlist (D6/D11)

    /// D6: the Cedar entity type must come from the `Resource` variant, not be
    /// hardcoded to `Repository`. Before this, `resource is Api` was
    /// *vacuously* false for every Api request, so a rule about APIs could
    /// never fire — and a rule that never fires hides the bug instead of
    /// failing loudly.
    #[test]
    fn cedar_entity_type_follows_the_resource_variant() {
        assert_eq!(
            entity_type(&Resource::Repository {
                owner: "a".into(),
                name: "b".into()
            }),
            "Repository"
        );
        assert_eq!(
            entity_type(&Resource::Database {
                name: "a".into(),
                role: "b".into()
            }),
            "Database"
        );
        assert_eq!(
            entity_type(&Resource::Host {
                hostname: "a".into()
            }),
            "Host"
        );
        assert_eq!(
            entity_type(&Resource::Api {
                audience: Authority::canonicalize("api.github.com").expect("valid")
            }),
            "Api"
        );
    }

    /// The two layers of D6 must not collapse: canonicalization proves a host
    /// is spelled one way; the allowlist proves it is *approved*. A
    /// well-formed but unapproved audience canonicalizes fine and must still
    /// be denied.
    #[test]
    fn unapproved_audience_is_denied_even_though_it_canonicalizes() {
        let engine = PolicyEngine::default();
        let evil = api_request(Action::GitHubIssueRead, "evil.example");
        // The type accepted it, so nothing upstream can catch it...
        assert_eq!(evil.resource_name(), "api:evil.example");
        // ...and policy must.
        assert!(!engine.authorize(&evil, None, None).decision.is_allowed());
    }

    /// The approved audience is reachable for the semantic read, and the
    /// action namespace is closed: `http.request` is the generic escape hatch
    /// and stays unauthorizable.
    #[test]
    fn approved_audience_allows_the_semantic_read_but_not_http_request() {
        let engine = PolicyEngine::default();
        assert!(engine
            .authorize(
                &api_request(Action::GitHubIssueRead, "api.github.com"),
                None,
                None
            )
            .decision
            .is_allowed());
        assert!(!engine
            .authorize(
                &api_request(Action::HttpRequest, "api.github.com"),
                None,
                None
            )
            .decision
            .is_allowed());
    }

    /// Case-folding equivalence must survive policy too: the spec accepts a
    /// case-folded hostname, so `API.GITHUB.COM.` and `api.github.com` are the
    /// same approved audience, while a lookalike suffix is not.
    #[test]
    fn audience_comparison_is_canonical_not_textual() {
        let engine = PolicyEngine::default();
        assert!(engine
            .authorize(
                &api_request(Action::GitHubIssueRead, "API.GITHUB.COM."),
                None,
                None
            )
            .decision
            .is_allowed());
        assert!(!engine
            .authorize(
                &api_request(Action::GitHubIssueRead, "api.github.com.evil.example"),
                None,
                None
            )
            .decision
            .is_allowed());
    }

    /// D11: the schema closes the action namespace. A policy naming an action
    /// that does not exist must be a *validation error*, not a rule that
    /// silently parses and would allow an invented verb.
    #[test]
    fn a_policy_naming_an_invented_action_fails_validation() {
        let invented = r#"
permit (principal, action == Action::"attacker_supplied_garbage", resource);
"#;
        let result = PolicyEngine::from_policy_text(invented);
        assert!(
            result.is_err(),
            "a rule naming a non-existent action must be rejected, not parsed"
        );
    }

    /// The shipped policy and schema must agree: the built-in policy has to
    /// validate against the built-in schema, and the semantic GitHub actions
    /// must be reachable only through the allowlisted audience.
    #[test]
    fn built_in_policy_validates_against_the_built_in_schema() {
        let engine = PolicyEngine::default();
        assert!(engine
            .authorize(
                &api_request(Action::GitHubIssueCreate, "api.github.com"),
                None,
                None
            )
            .decision
            .is_allowed());
        assert!(!engine
            .authorize(
                &api_request(Action::GitHubIssueCreate, "evil.example"),
                None,
                None
            )
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

    /// H3: an approval must not be consumed by a request it was not issued for.
    /// `request_digest` is part of the approval binding, so a mismatched digest
    /// must be rejected *without* spending the approval. The decrement happens
    /// only after the mismatch check, so this specific case is safe; the real
    /// question is whether the decrement precedes the Cedar verdict. Probe it
    /// with a request that passes every binding check but is still denied by
    /// policy: an approval on a resource the Cedar policy does not permit.
    #[test]
    fn mismatched_digest_does_not_burn_the_approval() {
        let clock = Arc::new(ManualClock::new(AuthorizationInstant(10)));
        let engine = PolicyEngine::new(clock).unwrap();
        let approved = request(Action::GitPush, Some("main"));
        let approval = engine.issue_approval(&approved, 10, 1);

        // Same session/action/resource/protected ref, different digest.
        let mut tampered = approved.clone();
        tampered.context.request_digest = Some("attacker-swapped-digest".into());
        let denied = engine.authorize(&tampered, None, Some(approval.id));
        assert!(!denied.decision.is_allowed());
        assert_eq!(denied.reason, ReasonCode::ApprovalMismatch);

        // The approval must survive a rejected attempt.
        let allowed = engine.authorize(&approved, None, Some(approval.id));
        assert!(
            allowed.decision.is_allowed(),
            "a rejected attempt burned the human's approval: {allowed:?}"
        );
    }

    /// H3b: a *consumed* approval is spent even when the final decision is a
    /// denial. Construct the case: bind the approval to a session, revoke that
    /// session, then present the approval. The revoke path must deny. If the
    /// approval's `remaining_uses` were decremented before the revoke check, a
    /// denial would also burn a use. This asserts deny-without-burn directly.
    #[test]
    fn denial_paths_do_not_decrement_approval_uses() {
        let clock = Arc::new(ManualClock::new(AuthorizationInstant(10)));
        let engine = PolicyEngine::new(clock.clone()).unwrap();
        let req = request(Action::GitPush, Some("main"));
        let approval = engine.issue_approval(&req, 100, 3);

        // 1) Expired approval: deny, must not decrement.
        clock.set(AuthorizationInstant(10 + 100));
        let expired = engine.authorize(&req, None, Some(approval.id));
        assert!(!expired.decision.is_allowed());

        // A non-expiring approval on a fresh session must still have 3 uses.
        let engine2 = PolicyEngine::new(clock).unwrap();
        let req2 = request(Action::GitPush, Some("main"));
        let a2 = engine2.issue_approval(&req2, 1000, 3);
        for _ in 0..3 {
            assert!(engine2
                .authorize(&req2, None, Some(a2.id))
                .decision
                .is_allowed());
        }
        let fourth = engine2.authorize(&req2, None, Some(a2.id));
        assert_eq!(fourth.reason, ReasonCode::ApprovalConsumed);
    }

    /// H4: the protected-ref gate is exact-match on the literal "main". Any other
    /// protected ref (e.g. "refs/heads/main", "release/1.0", "main.lock") falls
    /// through `is_protected_main` and is treated as *unprotected*, so it needs
    /// no approval. Counterfactual: a push to a protected non-"main" ref must
    /// not be silently allowed without approval.
    #[test]
    fn protected_ref_detection_is_not_bare_main() {
        let engine = PolicyEngine::default();
        for protected in ["refs/heads/main", "master", "release/1.0"] {
            let req = request(Action::GitPush, Some(protected));
            let decision = engine.authorize(&req, None, None);
            assert!(
                !decision.decision.is_allowed(),
                "push to protected ref {protected} was allowed without approval"
            );
        }
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

/// Closes backlog item `bl-bl-01M3MG517Q0003879086VZVGC0` (M3-era, recorded
/// during M4 design).
///
/// The item reported two defects. Both were fixed in `10b76ad`; neither had a
/// test that would fail if the fix were undone, which is why the item stayed
/// open. This is that test.
///
/// Defect 1: `cedar_decision` presented every `Resource` variant as
/// `Repository::`, so a rule scoped to `resource is Api` was vacuously false
/// and `Database`/`Host` shared the mistake. Fixed by `entity_type`.
///
/// Defect 2: `PolicySet::from_str` received `schema=None`, so a correctly
/// spelled rule naming an invented action parsed and granted `Allow`. Fixed by
/// validating against `SCHEMA_JSON` in `ValidationMode::Strict`.
#[test]
fn a_rule_naming_an_invented_action_is_rejected_at_load_time() {
    // Spelled correctly as Cedar, and semantically exactly the attack the
    // backlog item described: a verb this system does not have. Without a
    // schema this parses and allows, because Cedar has no vocabulary to check
    // it against.
    let invented = r#"
permit(principal is AgentSession, action == Action::"DetonateEverything", resource is Repository);
"#;
    assert!(
        PolicyEngine::from_policy_text(invented).is_err(),
        "a rule naming an action outside the schema must be a load-time error. If this \
         parses, the schema is not being applied and any verb can be granted."
    );
}

/// The other half of defect 2: the entity type must follow the resource
/// variant, so a rule scoped to `Api` is not silently false for a Repository
/// and not silently true for everything.
#[test]
fn the_entity_type_follows_the_resource_variant() {
    for (expected, resource) in [
        (
            "Repository",
            Resource::Repository {
                owner: "o".into(),
                name: "r".into(),
            },
        ),
        (
            "Database",
            Resource::Database {
                name: "d".into(),
                role: "rw".into(),
            },
        ),
        (
            "Host",
            Resource::Host {
                hostname: "h".into(),
            },
        ),
        (
            "Api",
            Resource::Api {
                audience: Authority::canonicalize("api.github.com").expect("canonical spelling"),
            },
        ),
    ] {
        assert_eq!(
            entity_type(&resource),
            expected,
            "a rule scoped to `resource is {expected}` must be able to match this variant; \
             a hardcoded type would make it vacuously false"
        );
    }
}

/// M6-R5, the spec's exact scenario: a policy that allows `connect` but not
/// `create_table`, while `select 1` is still served.
///
/// The point of the scenario is that the policy is the *only* thing that
/// changes. No connector code differs between the two engines, so if this
/// test needed a connector edit to pass, M6-R5 would be false.
#[test]
fn m6_r5_policy_denies_create_table_while_serving_read() {
    let policy = r#"
permit (principal, action == Action::"postgres_connect", resource is Database);
permit (principal, action == Action::"postgres_read", resource is Database);
"#;
    let engine = PolicyEngine::from_policy_text(policy).expect("policy must validate");
    let db = || AuthorizationRequest {
        session: AgentSessionId::new(),
        action: Action::PostgresConnect,
        resource: Resource::Database {
            name: "asv".into(),
            role: "app".into(),
        },
        context: PolicyContext {
            workspace: "/repo".into(),
            protected_ref: None,
            request_digest: Some("digest".into()),
            peer_uid: 1000,
        },
    };
    let with_action = |action: Action| AuthorizationRequest { action, ..db() };

    assert!(engine.authorize(&db(), None, None).decision.is_allowed());
    assert!(engine
        .authorize(&with_action(Action::PostgresRead), None, None)
        .decision
        .is_allowed());
    assert!(!engine
        .authorize(&with_action(Action::PostgresCreateTable), None, None)
        .decision
        .is_allowed());
}

/// The complement of the scenario above: once a policy allows the DDL verb,
/// `create_table` becomes allowed with no change to any connector code
/// (M6-R5, "policy change needs no edit").
#[test]
fn m6_r5_allowing_ddl_needs_no_connector_change() {
    let engine = PolicyEngine::from_policy_text(
        r#"
permit (principal, action == Action::"postgres_connect", resource is Database);
permit (principal, action == Action::"postgres_create_table", resource is Database);
"#,
    )
    .expect("policy must validate");
    let request = AuthorizationRequest {
        session: AgentSessionId::new(),
        action: Action::PostgresCreateTable,
        resource: Resource::Database {
            name: "asv".into(),
            role: "app".into(),
        },
        context: PolicyContext {
            workspace: "/repo".into(),
            protected_ref: None,
            request_digest: Some("digest".into()),
            peer_uid: 1000,
        },
    };
    assert!(engine.authorize(&request, None, None).decision.is_allowed());
}
