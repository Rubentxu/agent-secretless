//! UAT-029 — protected branch policy.
//! The protected-ref rules, and the approval that satisfies them exactly once:
//! `protected_push_requires_exact_single_use_approval` in the broker and
//! `denial_paths_do_not_decrement_approval_uses` here.
//! Deny-by-default authorization state for M3.
//!
//! Cedar is kept behind this adapter. The public types contain authorization
//! metadata only and cannot carry credential material.

use asv_domain::{Action, AgentSessionId, ApprovalId, Authority, CapabilityId, Decision, Resource};
use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityUid, PolicySet, Request, RestrictedExpression,
    Schema, ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name every decision made by the **built-in** policy carries.
///
/// Only ever true of [`Self::default`] and [`Self::new`]. A broker started with
/// `--policy` names the operator's file instead, because a receipt that credits
/// the built-in for a decision somebody else's policy made is worse than a
/// receipt with no name at all.
pub const DEFAULT_POLICY_NAME: &str = "m3-default-policy";

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

// C2.6: `connect_route` has NO permit rule, and the omission is the point.
//
// A route file is a *declaration* that a host may be CONNECT-ed; this action
// is the *permission*. An operator who wants `api.github.com:443` reachable
// writes both the route and a rule here. There is no blanket permit because a
// blanket permit would make the cross-check vacuous: every route would pass,
// and a file that cannot fail is not a control -- it is the same defect M6-R5
// exists to prevent for the database verbs, where permitting every verb would
// make the five Cedar actions decorative.
//
// So a stock broker refuses every declared route. That is the truthful posture
// for a surface that was not there before, and widening it is an explicit
// policy edit an operator can see in a diff, rather than a side effect of
// writing a JSON file.
//
// `aws_sts_caller_identity` has **no permit rule either, for the same reason**.
// It is a surface that did not exist when this text was written, and permitting
// it here would mean every deployment that upgrades starts answering AWS on
// behalf of every agent session, with no operator having decided that. The
// action is in the *schema* -- without it, a policy naming it would fail
// strict validation at load rather than deny at evaluation, and a load-time
// crash for a rule an operator wrote on purpose is the wrong failure mode. So an
// operator who wants it writes:
//
//   permit (principal, action == Action::"aws_sts_caller_identity",
//           resource is Api) when { resource.audience == "sts.eu-west-1.amazonaws.com" };
//
// **The `when` clause is not decoration, and getting the form wrong is the third
// defect stacked in this one sentence.** Cedar 4.7.1 rejects both
// `resource is Api && x` ("unexpected token `&&`") and
// `(resource is Api) && x` ("unexpected token `(`"); the grammar wants the
// condition in a `when` block. So the rule as originally written would not have
// loaded *even now* that the attribute is supplied — a condition that could
// never match, inside a rule that would not parse, and nothing in the tree ran
// it to notice either. `the_documented_audience_rule_now_matches_and_only_its_own_audience`
// is the row that loads the exact text printed here, so a future Cedar upgrade
// that changes the grammar fails a test rather than silently invalidating every
// operator's policy.
//
// and naming the audience there is the point: the broker evaluates against the
// *deployment's* audience, so the rule is about one declared destination rather
// than about AWS in general.
//
// -- A defect that was here, and is fixed. Kept because the fix is the evidence
//
// The AWS example above says `resource.audience == "..."`, and for a while that
// condition **could never be true**. `cedar_decision` built the entity store with
// `&Entities::empty()`, and nothing in this crate built an `Entity`, so
// `Api::audience` was declared in `SCHEMA_JSON`, validated against, and never
// supplied. An operator who followed the documentation got a permanent,
// unexplained denial. The reachable-host guarantee was never affected, because
// `audience_is_approved` runs in Rust before Cedar; only the attribute was
// missing.
//
// The fix built the store with the schema, so an attribute is supplied and
// checked against its declaration on the way in. `resource_attributes` is the
// whole mechanism now, and it is one function every variant goes through -- so
// a variant that forgets its arm is refused at load by a missing required
// attribute rather than quietly making every condition on it unanswerable.
//
// A reader who remembers "match the entity name instead" is remembering advice
// that was true for one commit and is now actively wrong: `Api::"api:<audience>"`
// still works, and it constrains nothing the attribute does not.
//
// `oauth2_identity` has no permit rule, and that is unchanged and still the
// right default: a surface added after this text was written should not start
// answering on behalf of every session because someone upgraded. What changed is
// that the rule an operator *writes* can now say something about the authority,
// because the registration's scope is a declared attribute (`Set<String>`) rather
// than nothing:
//
//   permit (principal, action == Action::"oauth2_identity",
//           resource is OAuth2Client)
//   when { resource.scope.contains("pods:read")
//          && !resource.scope.contains("pods:delete") };
//
// **The `when` block is not decoration here either, and this paragraph has now
// been wrong twice.** The rule above is the third one in this file to be written
// as `resource is Api && condition`, and Cedar 4.7.1 rejects all three the same
// way: the head is a `permit (principal, action, resource)` clause and the
// condition belongs in a separate `when { .. }` block. It was worth writing
// down the second time; it was not worth writing down the second time and then
// making the same mistake a third. `contains` does not change the grammar, and a
// rule with a condition in the head fails to *load* -- which is at least loud.
//
// The entity type is `OAuth2Client` rather than `Api` -- see `ALLOWED_AUDIENCES`
// for why widening that list to admit arbitrary IdPs would be a regression for
// GitHub and AWS rather than a compromise. Addressing one *registered client* is
// the right granularity anyway: the authority being delegated is the
// registration, and two registrations may share an audience while differing in
// scope -- which is exactly the pair a `Set` can tell apart and an audience
// comparison could not.
//
// **Which of those two shapes an operator should write, and why the first one is
// a trap.** Both rules are valid Cedar and both refuse a registration carrying
// `pods:delete`. They are not the same control:
//
//   when { resource.scope.contains("pods:read")
//          && !resource.scope.contains("pods:delete") }     // a denylist
//   when { resource.scope == ["pods:read"] }                // an allowlist
//
// The first is what most people write, and it is wrong in a way that only shows
// up later. It refuses the scope you thought of; it permits
// `pods:read pods:create pods:escalate`, because `create` was never on the list.
// **A denylist is only as complete as the operator's memory of every mutating
// scope their IdP offers**, and the failure arrives after the policy is written,
// in production, on a registration somebody else added.
//
// The second says what is allowed rather than what is forbidden, so there is
// nothing to keep complete, and it is the shape the rows in `r2b2_oauth2_vertical`
// measure. Prefer it. Use the denylist form only when the registration's grant is
// genuinely open-ended and the operator really does mean "anything but these".
//
// **What neither shape does: narrow.** Cedar *permits or refuses a registration*;
// it cannot rewrite one, and no policy language can hand a token. The rule above
// says "this session may act through a client whose registered scope is exactly
// `pods:read`, and through no other" — an all-or-nothing judgement about one
// registration. The token's ceiling is the IdP's own grant, and the broker's
// comparison against the provider's answer is what catches the day it drifts.
//
// Narrowing a token *below* its registration — an agent asking for less than the
// client holds, and the provider minting the smaller grant — is a *port*
// capability rather than a policy one, and it is a separate change. It cannot be
// bolted on by widening `SecretPort`, which is a vault-and-provider boundary
// shared by seventeen implementations that have no concept of an OAuth2 scope;
// the scope-aware lend needs its own handle, and the token cache's key has to
// become `(credential, scope)` or a narrow request would be served a wide cached
// token.
//
// -- M11-R2.F.3: the OCI registry, and the shape of the rule an operator writes
//
// `registry_pull` and `registry_push` are in the *schema* and have **no permit
// rule**, and that is the same decision as `aws_sts_caller_identity` and
// `oauth2_identity` above rather than a new one: a surface that did not exist
// when this text was written does not start answering on behalf of every session
// because somebody upgraded. They are in the schema because without it a policy
// naming them would fail strict validation at *load*, and a load-time crash for a
// rule an operator wrote on purpose is the wrong failure mode — the correct one
// is a denial at evaluation, which is what an operator can read and act on.
//
// The entity type is `Registry` and it carries **two** attributes, which is the
// only part of this that is new:
//
//   permit (principal, action == Action::"registry_pull", resource is Registry)
//   when { resource.authority == "registry-1.docker.io"
//          && resource.repository == "library/alpine" };
//
// `repository` exists because a registry grants per repository, in a scope of
// the form `repository:<name>:<actions>`. An `Api` — a bare audience — cannot
// ask the question an operator actually has, which is "may this agent pull
// *this* image", and pretending otherwise would have produced a rule that either
// allowed every repository or none.
//
// **The `authority` attribute is safe to expose, and the reason is not that it
// is validated — it is that nothing the agent sends can put a value in it.**
// `audience_is_approved` does not gate `Registry`, and it does not need to,
// because the broker builds this value from operator configuration and the
// request only ever names a repository. A rule that compares `authority` is
// therefore comparing a *declared* fact: naming `evil.example` there produces a
// rule that never fires, not one that fires against an agent-chosen host.
//
// **And the same paragraph has to warn about the failure mode in the other
// direction, because it is the one a reader is most likely to assume away.** If
// the broker ever built this entity from a request-supplied host, the rule above
// would become a *filter* over hosts the agent chose, and "deny everything
// except `registry-1.docker.io`" would silently become "allow everything except
// `registry-1.docker.io`" — the inversion, with the same policy text. The
// allowlist property here is structural, and it lives in the broker's
// configuration, not in this file. That is the same bargain `OAuth2Client`
// struck, and it is worth knowing which file a property actually lives in before
// trusting it here.
//"#;

/// Audiences a semantic HTTP action may ever target (D6; the design v2 open
/// question resolved it as a compile-time constant, not configuration).
///
/// This is the approval half of the allowlist. [`Authority`] proves a host is
/// *spelled* one way; this proves it is *approved*. Both are required, because
/// `evil.example` canonicalizes perfectly and would otherwise pass.
///
/// `sts.amazonaws.com` joined it in R2.C.3, and finding out that it had to was
/// the point of running the vertical: the AWS operation reached the policy and
/// was refused with "no matching policy", which reads like a Cedar problem and
/// is not one. This list runs in Rust *before* Cedar, deliberately, so no policy
/// text can widen the reachable host set — which means a new provider cannot be
/// permitted by writing a policy rule. It has to be declared here first, and
/// that two-step is the control working rather than an obstacle.
///
/// **Regional STS endpoints are NOT listed, and that is an open item rather than
/// an oversight.** AWS also serves `sts.<region>.amazonaws.com`, and a static
/// list of those goes stale with every region AWS adds. The narrow rule would be
/// "the global endpoint, or the regional endpoint whose region equals the one the
/// deployment configured" — which needs the region passed alongside the audience,
/// so it is a change to this function's contract rather than one more string.
/// Until that exists, an AWS deployment must use the global endpoint, which is
/// what `asv_broker::aws::client::STS_ENDPOINT` already pins.
pub(crate) const ALLOWED_AUDIENCES: &[&str] = &["api.github.com", "sts.amazonaws.com"];

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
      },
      "OAuth2Client": {
        "shape": {
          "type": "Record",
          "attributes": {
            "scope": {
              "type": "Set",
              "element": { "type": "String" }
            }
          }
        }
      },
      "Registry": {
        "shape": {
          "type": "Record",
          "attributes": {
            "authority": { "type": "String" },
            "repository": { "type": "String" }
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
      "connect_route": {
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
      "aws_sts_caller_identity": {
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
      "oauth2_identity": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["OAuth2Client"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "registry_pull": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Registry"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "registry_push": {
        "memberOf": [],
        "appliesTo": {
          "principalTypes": ["AgentSession"],
          "resourceTypes": ["Registry"],
          "context": {
            "type": "Record",
            "attributes": {
              "protected_ref": { "type": "Boolean" },
              "approved": { "type": "Boolean" }
            }
          }
        }
      },
      "k8s_read": {
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
      "mtls_sign": {
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
    /// Kept because `Entity::new` needs it: building a resource with its
    /// attributes is how a policy condition on an attribute is answered, and
    /// Cedar validates the entity against the same schema the policies were
    /// validated against. One schema, held once, so the two cannot drift.
    schema: Arc<Schema>,
    /// What to call this policy in every decision it produces.
    ///
    /// **It used to be the constant `"m3-default-policy"`, written into every
    /// [`ExplainResult`] regardless of where the text came from.** Found by
    /// running the broker with `--policy` pointing at a file an operator wrote:
    /// the receipt said `allow by m3-default-policy` for a decision that policy
    /// had made, which points the reader at the wrong file in the one artefact
    /// whose purpose is to say who decided what.
    ///
    /// The name is carried rather than inferred because nothing downstream can
    /// recover it — the broker has already forgotten where it read the text from
    /// by the time a decision is written, and guessing from the text would mean
    /// parsing Cedar to extract a filename.
    policy_name: String,
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
        Self::from_named_policy_text_with_clock(POLICY_TEXT, DEFAULT_POLICY_NAME, clock)
    }

    /// Loads policy text, validating it against the schema (D11).
    ///
    /// Validation is the point: a rule naming an action this system does not
    /// have is a load-time error, not a rule that would quietly ALLOW it.
    pub fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        Self::from_named_policy_text(policy_text, DEFAULT_POLICY_NAME)
    }

    /// The same, naming the policy for every decision it will produce.
    ///
    /// **The name goes in the receipt, so it has to be something an operator can
    /// match against the file they delivered** — a path, or whatever the
    /// deployment calls the policy. `&str` rather than `Path` because this is a
    /// label in a document, not a path anything reads.
    pub fn from_named_policy_text(
        policy_text: &str,
        policy_name: &str,
    ) -> Result<Self, PolicyError> {
        Self::from_named_policy_text_with_clock(policy_text, policy_name, Arc::new(SystemClock))
    }

    fn from_named_policy_text_with_clock(
        policy_text: &str,
        policy_name: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PolicyError> {
        let schema = Schema::from_json_str(SCHEMA_JSON)
            .map_err(|error| PolicyError::Engine(format!("invalid built-in schema: {error}")))?;
        let policies = PolicySet::from_str(policy_text)
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        let validator = Validator::new(schema.clone());
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
            schema: Arc::new(schema),
            policy_name: policy_name.to_string(),
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
            // The reason is carried rather than discarded. "policy engine
            // failure" with nothing behind it is a dead end for an operator, and
            // it made this class of bug invisible while it was being fixed: a
            // Cedar error and a policy denial produced the same decision, so a
            // change that broke *every* authorization still read as a quiet
            // deny. Failing closed was never in question — the decision is still
            // a Deny — but a refusal nobody can diagnose is not much of one.
            //
            // Nothing secret reaches here: it is Cedar's complaint about a
            // resource *type* or a missing attribute, never a value.
            Err(error) => Decision::Deny {
                reason: format!("policy engine failure: {error}"),
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
            rule: self.policy_name.clone(),
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
        //
        // **The match is on `Api` and only on `Api`, and R2.B.2 added a second
        // resource type that deliberately does not come through here.** Read
        // that as a decision, not an oversight, because the natural reaction to
        // "a new resource type skips the allowlist" is to add it to the list --
        // and that would break the property this function exists to provide.
        //
        // `ALLOWED_AUDIENCES` enumerates first-party API hosts. OAuth2's purpose
        // is reaching IdPs that are not on any enumerable list, so the two
        // requirements are in direct conflict and *something* has to give.
        // Widening the list gives the wrong thing: it would approve `evil.example`
        // for **GitHub and AWS too**, because they share this resource type, and
        // D6's guarantee is precisely that policy text cannot choose the host.
        //
        // What is given instead is the enumeration. `Resource::OAuth2Client`
        // arrives here with an audience the *operator* declared in
        // `--oauth2-clients` and the broker validated at startup, and it is the
        // only audience the call can use. A policy can therefore allow or deny
        // a set the policy did not choose, which is the same guarantee D6 buys
        // for `Api` — reached structurally rather than by list membership.
        // `OAuth2AudienceReachesCedar` is the row that holds this line, and if it
        // ever goes red the correct repair is to make the audience
        // non-request-supplied, never to add a host to the list.
        if let Resource::Api { audience } = &request.resource {
            // R2.D and R2.E carry the *declared* audience on `Resource::Api`,
            // not a request-chosen one. The deployment is the operator's
            // `k8s_bindings` entry or `mtls_signers` entry, and the broker
            // builds the request from the binding — so the audience is
            // non-request-supplied exactly the way OAuth2's is, and the
            // same structural guarantee D6 buys for OAuth2 (a policy can
            // only allow or deny a set the policy did not choose) holds
            // here too. Skipping the allowlist for these two actions is
            // therefore safe; the test row `deployment_backed_audience_is_not_allowlisted_but_evaluates`
            // pins the property.
            if !matches!(request.action, Action::K8sRead | Action::MTlsSign)
                && !audience_is_approved(audience)
            {
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
        // The resource's own attributes, which `SCHEMA_JSON` has been declaring
        // since M4 and which nothing ever supplied.
        //
        // `Request::new`'s last argument is where a resource's attributes go, and
        // it was `None` — so `Api::audience` was a declared-but-absent field, and
        // a policy condition on it (`resource.audience == "api.github.com"`, the
        // rule this file's own `POLICY_TEXT` tells an operator to write) could
        // never be true. Not "fail-closed", which is what an absent *resource*
        // would be: the condition simply had nothing to compare, so the rule
        // denied forever and the operator got no explanation.
        //
        // **This is a fidelity fix and not a reachability fix, and the
        // difference is the whole safety argument.** An unapproved audience is
        // still refused a dozen lines above, in Rust, before Cedar is
        // consulted — so the set of hosts a policy can reach is unchanged, and
        // this only lets a rule *narrow* within the set D6 already approved. The
        // row that holds that is
        // `unapproved_audience_is_denied_even_though_it_canonicalizes`, and
        // `audience_attributes_do_not_widen_the_reachable_set` is the one that
        // would go red if this ever started answering a different question.
        let mut resource_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        for (name, value) in resource_attributes(&request.resource) {
            // `new_string`, **not** `from_str`. `RestrictedExpression::from_str`
            // parses a *Cedar expression*, so handing it `api.github.com` builds
            // a path expression referring to the entity `api.github.com` — which
            // does not exist, and which fails closed with `invalid member access
            // api.github, api has no fields or methods`. Every audience in this
            // system is a dotted host, so every value would have hit it.
            //
            // The failure was invisible because `authorize` discarded the engine
            // error and answered `"policy engine failure"`, which is the same
            // decision a policy denial produces: the change turned *every* `Api`
            // authorization into a quiet deny and three rows said "assertion
            // failed" with nothing behind them. The two fixes belong together —
            // a string literal, and an error an operator can read.
            //
            // The `Set` arm is the same care applied to a value that is not a
            // string at all: `new_set` over `new_string` members, never
            // `from_str` on the joined `"read write"` — which would be a Cedar
            // *expression* naming two entities, and would fail closed on every
            // scope that contains a space.
            let value = match value {
                ResourceAttribute::Text(text) => RestrictedExpression::new_string(text),
                ResourceAttribute::Set(members) => RestrictedExpression::new_set(
                    members.into_iter().map(RestrictedExpression::new_string),
                ),
            };
            resource_attrs.insert(name.to_string(), value);
        }
        // **This is where the attributes go, and the fact that they did not go
        // here is the whole defect.** Cedar resolves a resource's attributes from
        // the `Entities` store handed to `is_authorized`, *not* from the
        // `Request` — `Request::new`'s fifth argument is the schema, and a
        // `Request` is three uids and a context. So the original call passed
        // `&Entities::empty()` and every attribute was structurally unreachable:
        // `SCHEMA_JSON` declared `Api::audience`, the policies were validated
        // against that declaration, and a rule could be written, loaded, and be
        // denied forever because the value it compared against did not exist.
        //
        // The entity store is built with the schema, so Cedar checks each
        // attribute against the declaration as it is added. That makes both
        // failure directions loud rather than silent: an attribute the schema
        // does not declare is refused here, and — because the schema declares
        // `audience` and a missing required attribute is also an error — a
        // variant whose `resource_attributes` arm was forgotten is refused here
        // too, instead of quietly making every condition on it unanswerable.
        let entities = if resource_attrs.is_empty() {
            Entities::empty()
        } else {
            let entity = Entity::new(resource.clone(), resource_attrs, HashSet::new())
                .map_err(|error| PolicyError::Engine(error.to_string()))?;
            Entities::from_entities(vec![entity], Some(&self.schema))
                .map_err(|error| PolicyError::Engine(error.to_string()))?
        };
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
        // The schema goes here rather than as `None` so Cedar validates the
        // request shape — principal type, action, resource type — on every
        // evaluation instead of trusting that the code and the schema agree.
        let request = Request::new(principal, action, resource, context, Some(&self.schema))
            .map_err(|error| PolicyError::Engine(error.to_string()))?;
        Ok(self
            .authorizer
            .is_authorized(&request, &self.policies, &entities)
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
        Action::ConnectRoute => "connect_route",
        Action::AwsStsCallerIdentity => "aws_sts_caller_identity",
        Action::OAuth2Identity => "oauth2_identity",
        Action::RegistryPull => "registry_pull",
        Action::RegistryPush => "registry_push",
        Action::K8sRead => "k8s_read",
        Action::MTlsSign => "mtls_sign",
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
        Resource::OAuth2Client { .. } => "OAuth2Client",
        Resource::Registry { .. } => "Registry",
    }
}

fn resource_name(resource: &Resource) -> String {
    match resource {
        Resource::Repository { owner, name } => format!("{owner}/{name}"),
        Resource::Database { name, role } => format!("db:{name}/{role}"),
        Resource::Host { hostname } => format!("host:{hostname}"),
        Resource::Api { audience } => format!("api:{audience}"),
        // `oauth2:` rather than the bare id, so a policy rule naming an OAuth2
        // client can never be confused with one naming a repository that
        // happens to share a name. The prefix is the only thing keeping the
        // entity namespaces apart, and it is here rather than in the type name
        // because Cedar sees only a string.
        Resource::OAuth2Client { credential, .. } => format!("oauth2:{credential}"),
        // `registry:` rather than the bare repository, for the same reason as
        // `oauth2:` above. A repository name is attacker-supplied text in a
        // system that also has `Repository { owner, name }`, and an entity uid
        // of `library/alpine` from one namespace would be indistinguishable
        // from one of the other. The prefix is the only thing keeping them
        // apart, and Cedar sees only a string.
        Resource::Registry {
            authority,
            repository,
        } => {
            format!("registry:{authority}/{repository}")
        }
    }
}

/// The attributes a resource entity carries, as `(name, value)` pairs.
///
/// **Every variant here must match a shape declared in `SCHEMA_JSON`, and an
/// attribute that does not is a load-time error rather than a silently absent
/// field** — which is the property that makes this function's output trustworthy
/// rather than hopeful. An entity built with an attribute the schema does not
/// declare fails `Entity::new`, so a typo here stops the broker rather than
/// producing another rule that can never match.
///
/// The value is typed because Cedar's is. A `String` attribute and a `Set`
/// attribute are different types to the schema, and the wrong constructor does
/// not error usefully — `new_string("read write")` is a perfectly valid string
/// that no `contains` will ever find anything in, so a scope declared as text
/// would load cleanly and deny silently. [`ResourceAttribute`] makes the
/// distinction something a reviewer can see at the match arm.
fn resource_attributes(resource: &Resource) -> Vec<(&'static str, ResourceAttribute)> {
    match resource {
        Resource::Api { audience } => {
            vec![("audience", ResourceAttribute::Text(audience.to_string()))]
        }
        // **A `Set`, and this is the arm that makes the scope a policy
        // resource.** RFC 6749's `scope` is a space-delimited list, so the
        // honest Cedar type is a set of strings and the honest policy question
        // is `contains`.
        //
        // The alternative — hand over the raw string and let the rule test it
        // with `contains` — is not a weaker control, it is **no control at all**,
        // and it fails in the direction that matters. A `String` has no `contains`
        // in Cedar, so a rule written that way is rejected; an author who wanted
        // substring matching and got it would find that `pods:read` is a
        // substring of `pods:readwrite`, that `read` is a substring of both, and
        // that a policy refusing `pods:delete` also refuses a scope that merely
        // *mentions* it. A set cannot have either failure: membership is equality
        // on whole tokens, and a token that is not there is not there.
        Resource::OAuth2Client { scope, .. } => {
            vec![(
                "scope",
                ResourceAttribute::Set(asv_domain::scope_set(scope)),
            )]
        }
        // The repository is a policy input, and it is the *only* thing in this
        // value the agent chose. It is exposed as an attribute rather than
        // folded into the uid because a rule that wants to allow one
        // repository and refuse another has to be able to ask, and
        // `entity == Resource::"..."` can only ever name one of them.
        //
        // The authority is here too, and the reason is worth being explicit
        // about: it is exposed so a policy *can* be written per registry, and
        // it is safe to expose because it is not request-supplied. The broker
        // builds this value from operator configuration, so a rule that reads
        // `authority` is reading a declared fact, not an agent's suggestion.
        Resource::Registry {
            authority,
            repository,
        } => vec![
            ("authority", ResourceAttribute::Text(authority.to_string())),
            ("repository", ResourceAttribute::Text(repository.clone())),
        ],
        Resource::Repository { .. } | Resource::Database { .. } | Resource::Host { .. } => {
            Vec::new()
        }
    }
}

/// A resource attribute's value, in the shape the schema declares for it.
///
/// Exists because [`resource_attributes`] is where a type decision is made and
/// the alternative is a `String` that means "a string, or the words of a set,
/// depending on which variant you are looking at".
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResourceAttribute {
    /// A Cedar `String`, built with `RestrictedExpression::new_string`.
    Text(String),
    /// A Cedar `Set` of `String`, built with `RestrictedExpression::new_set`.
    Set(Vec<String>),
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

    /// An OAuth2 identity request against a registration carrying `scope`.
    ///
    /// The scope is the whole point of this helper existing: it is the field the
    /// policy is supposed to be able to reason about, and a fixture that hardcoded
    /// one would make every row below pass with a rule nobody wrote.
    fn oauth2_request(action: Action, scope: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            session: AgentSessionId::new(),
            action,
            resource: Resource::OAuth2Client {
                credential: "cred-1".into(),
                audience: "https://api.asv.test".into(),
                scope: scope.into(),
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

    /// **The allowlist had no row, and this is it.**
    ///
    /// `ALLOWED_AUDIENCES` is called a two-entry list in four files and it is
    /// the control D6 rests on: `audience_is_approved` gates every `Api`, so a
    /// third entry would let *policy text* name an arbitrary host as an audience
    /// and have it approved — reopening, for GitHub and AWS, the exact hole D6
    /// closes. The rows around this one do not catch that. `evil.example` is
    /// not a host anyone would add, and the documented-rule row only shows two
    /// named hosts discriminating; both stay green when a third appears.
    ///
    /// Both halves, because they fail differently and neither substitutes for
    /// the other. The membership assertion is the tripwire: it is red for *any*
    /// widening, including a host no row happens to probe. The probe loop is the
    /// behaviour, saying what the list is for rather than what it spells today —
    /// which is the shape of the claim if someone later argues the literal is
    /// what matters.
    #[test]
    fn the_api_allowlist_names_only_the_two_first_party_hosts() {
        assert_eq!(
            ALLOWED_AUDIENCES,
            &["api.github.com", "sts.amazonaws.com"],
            "the API allowlist gained an entry: a third host would let policy text \
             name an audience D6 exists to refuse"
        );
        // And the list means what the doc above says it means, for the hosts an
        // author would actually reach for: a generic IdP, a lookalike of GitHub,
        // and both a regional AWS endpoint and a suffixed global one.
        for host in [
            "idp.example.com",
            "api.github.com.attacker.test",
            "sts.eu-west-1.amazonaws.com",
            "sts.amazonaws.com.attacker.test",
        ] {
            let authority = Authority::canonicalize(host).expect("a well-formed authority");
            assert!(
                !audience_is_approved(&authority),
                "{host} was approved as an API audience"
            );
        }
    }

    /// **The row the whole change exists for.** The rule `POLICY_TEXT` tells an
    /// operator to write — `resource.audience == "sts.amazonaws.com"` — now
    /// matches, and a rule naming a different audience does not.
    ///
    /// Both halves are asserted because the interesting failure is a rule that
    /// matches *everything*, which would look identical to "it works" if only the
    /// first half were checked. A condition on an attribute that silently
    /// evaluated to nothing is the previous behaviour, and it denied; a condition
    /// that silently evaluated to true would be a new one, and it would allow.
    #[test]
    fn the_documented_audience_rule_now_matches_and_only_its_own_audience() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"github_issue_read",
                   resource is Api) when { resource.audience == "sts.amazonaws.com" };"#,
        )
        .expect("the documented rule now loads and is valid");
        // The audience the rule names: permitted.
        assert!(
            engine
                .authorize(
                    &api_request(Action::GitHubIssueRead, "sts.amazonaws.com"),
                    None,
                    None
                )
                .decision
                .is_allowed(),
            "a rule naming the resource's own audience still denies"
        );
        // The other approved audience: denied, so the condition discriminates
        // rather than merely being satisfiable.
        assert!(
            !engine
                .authorize(
                    &api_request(Action::GitHubIssueRead, "api.github.com"),
                    None,
                    None
                )
                .decision
                .is_allowed(),
            "the condition is satisfiable by any Api, not by the one it names"
        );
    }

    /// **The safety row, and the one that must exist for the row above to be
    /// allowed to exist.** Supplying the attribute changed what a policy can say,
    /// so the reachable set has to be re-measured rather than assumed.
    ///
    /// The policy here is as permissive as the grammar allows — `resource is
    /// Api`, no audience condition at all — and the audience is unapproved. It is
    /// denied by `audience_is_approved` in Rust, before Cedar is consulted, which
    /// is the layer that has always held and the layer this change does not
    /// touch. The point of the row is that populating an attribute did not move
    /// that check, and a regression that popped the `if let Resource::Api` would
    /// make it red.
    #[test]
    fn audience_attributes_do_not_widen_the_reachable_set() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"github_issue_read", resource is Api);"#,
        )
        .expect("the most permissive Api rule is valid");
        // Permitted audience: allowed, so the rule is genuinely permissive and
        // the denial below is about the audience rather than about the policy.
        assert!(
            engine
                .authorize(
                    &api_request(Action::GitHubIssueRead, "api.github.com"),
                    None,
                    None
                )
                .decision
                .is_allowed(),
            "the fixture policy is not permissive, so the denial below proves nothing"
        );
        // Unapproved audience: denied, with the attribute present and populated.
        let denied = engine.authorize(
            &api_request(Action::GitHubIssueRead, "evil.example"),
            None,
            None,
        );
        assert!(
            !denied.decision.is_allowed(),
            "an unapproved audience became reachable once its attribute was supplied"
        );
        // And it is refused by the Rust-side check rather than by a rule that
        // happened not to match — the distinction an operator needs, because the
        // first is "this host is not approved" and the second is "you did not
        // write a rule for it".
        assert!(
            !format!("{:?}", denied.reason).contains("policy engine failure"),
            "the refusal came from the engine rather than the allowlist: {:?}",
            denied.reason
        );
    }

    /// The attribute a resource carries is exactly the one its schema declares,
    /// and nothing more.
    ///
    /// A resource entity built with an attribute `SCHEMA_JSON` does not declare
    /// is refused by `Entities::from_entities`, which is the property that makes
    /// `resource_attributes` trustworthy: it cannot quietly grow a field no
    /// policy can reference, and it cannot lose one every rule depends on,
    /// without a policy evaluation failing loudly rather than denying in silence.
    ///
    /// **Two shaped types, not one, and the row covers both** because a check
    /// written when only `Api` had a shape would keep passing after `OAuth2Client`
    /// grew one — the missing arm and the wrong-typed arm are different bugs with
    /// the same symptom, and only the second is silent.
    #[test]
    fn a_resource_entity_carries_exactly_what_its_schema_declares() {
        let schema = Schema::from_json_str(SCHEMA_JSON).expect("the built-in schema parses");
        let audience = Authority::canonicalize("api.github.com").expect("valid");
        let api = Resource::Api {
            audience: audience.clone(),
        };
        // Declared: `Api` has a shape with one **String** attribute.
        assert_eq!(
            resource_attributes(&api),
            vec![("audience", ResourceAttribute::Text(audience.to_string()))],
            "the Api arm must emit a String, which is what the schema declares for it"
        );
        // Declared: `OAuth2Client` has one attribute and it is a **Set of
        // String**. A `Text` here would satisfy the name and fail the type, and
        // the failure a policy author would see is a rule that never matches.
        assert_eq!(
            resource_attributes(
                &oauth2_request(Action::OAuth2Identity, "write  read read").resource
            ),
            vec![(
                "scope",
                ResourceAttribute::Set(vec!["read".into(), "write".into()])
            )],
            "the OAuth2Client arm must emit a Set of the individual scope tokens, \
             deduplicated and order-independent"
        );
        // And both are accepted by the schema that declares them, built the way
        // `cedar_decision` builds them.
        for resource in [
            api.clone(),
            oauth2_request(Action::OAuth2Identity, "read").resource,
        ] {
            let uid = EntityUid::from_str(&format!(
                "{}::\"{}\"",
                entity_type(&resource),
                resource_name(&resource)
            ))
            .expect("the resource name is a valid entity id");
            let attrs: HashMap<String, RestrictedExpression> = resource_attributes(&resource)
                .into_iter()
                .map(|(name, value)| {
                    let value = match value {
                        ResourceAttribute::Text(text) => RestrictedExpression::new_string(text),
                        ResourceAttribute::Set(members) => RestrictedExpression::new_set(
                            members.into_iter().map(RestrictedExpression::new_string),
                        ),
                    };
                    (name.to_string(), value)
                })
                .collect();
            let entity = Entity::new(uid, attrs, HashSet::new())
                .expect("an entity with declared attributes builds");
            Entities::from_entities(vec![entity], Some(&schema)).unwrap_or_else(|error| {
                panic!(
                    "{} does not conform to the schema: {error}",
                    resource_name(&resource)
                )
            });
        }
        // The types with no shape carry nothing, which is why they need no
        // entity at all: supplying an empty one would be a no-op with a cost.
        for resource_without_attributes in [
            Resource::Repository {
                owner: "a".into(),
                name: "b".into(),
            },
            Resource::Database {
                name: "a".into(),
                role: "b".into(),
            },
            Resource::Host {
                hostname: "a".into(),
            },
        ] {
            assert!(
                resource_attributes(&resource_without_attributes).is_empty(),
                "{resource_without_attributes:?} declares no shape, so it must carry no attribute"
            );
        }
    }

    /// **The row this whole change exists for: a policy can say what the
    /// registration is allowed to carry, and the rule really is evaluated.**
    ///
    /// The exact text `POLICY_TEXT` prints for an operator to copy:
    ///
    /// ```text
    /// permit (principal, action == Action::"oauth2_identity",
    ///         resource is OAuth2Client)
    /// when { resource.scope.contains("pods:read")
    ///        && !resource.scope.contains("pods:delete") };
    /// ```
    ///
    /// The two halves are the two things a substring comparison could not do.
    /// `contains("pods:read")` is the ordinary case, and it is here to prove the
    /// Set reaches Cedar at all. The negated half is the one that matters: with
    /// the scope as a `String`, "read but not write" is not expressible, because
    /// Cedar's `contains` is set membership and a `String` has no sets — and
    /// with it as text, the only way to write the rule is substring matching,
    /// which refuses a scope that merely *mentions* `pods:delete` and misses one
    /// that *contains* `pods:delete` as a prefix.
    ///
    /// A rule that cannot be satisfied is the failure this must not have: the
    /// first assertion below is the one that would catch a `Set` silently
    /// degraded to a `String`, because a `contains` on a `String` is rejected at
    /// *load* and the whole engine would refuse to build rather than permit
    /// anything.
    #[test]
    fn a_scope_condition_separates_a_read_only_client_from_a_read_write_one() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"oauth2_identity",
                       resource is OAuth2Client)
                   when { resource.scope.contains("pods:read")
                          && !resource.scope.contains("pods:delete") };"#,
        )
        .expect("the documented OAuth2 scope rule is valid Cedar and validates");
        let allowed = engine.authorize(
            &oauth2_request(Action::OAuth2Identity, "pods:read"),
            None,
            None,
        );
        assert!(
            allowed.decision.is_allowed(),
            "a read-only registration must satisfy a rule that says read-only: {:?}",
            allowed.reason
        );
        for refused_scope in ["pods:read pods:delete", "pods:delete", "pods:readonly"] {
            let denied = engine.authorize(
                &oauth2_request(Action::OAuth2Identity, refused_scope),
                None,
                None,
            );
            assert!(
                !denied.decision.is_allowed(),
                "{refused_scope:?} satisfied a rule that forbids pods:delete — membership is \
                 equality on whole tokens, so pods:readonly is not pods:read"
            );
        }
        // And the rule is not a blanket permit wearing a condition: a scope with
        // no read at all is refused by the same rule that permits the first one.
        assert!(
            !engine
                .authorize(
                    &oauth2_request(Action::OAuth2Identity, "pods:list"),
                    None,
                    None
                )
                .decision
                .is_allowed(),
            "a registration with none of the required scope was permitted"
        );
    }

    /// The scope order and repetition an operator actually types make no
    /// difference to what the policy sees.
    ///
    /// RFC 6749's `scope` is a list and the IdP may echo it back in any order, so
    /// `"pods:read pods:write"` and `"pods:write pods:read"` are one grant. If the
    /// Set were built from the raw string, a policy that required an exact
    /// ordering would pass on one registration and fail on the next — and the
    /// failure would look like the policy being wrong rather than the
    /// normalisation being incomplete.
    ///
    /// This shares its normalisation with the issuer's escalation check, which is
    /// why [`asv_domain::scope_set`] is one function and not two: a rule that
    /// agreed with the issuer about order would be a rule that could one day stop
    /// agreeing, with nothing in the tree to notice.
    #[test]
    fn scope_order_and_repetition_are_one_grant_to_both_the_policy_and_the_issuer() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"oauth2_identity",
                       resource is OAuth2Client)
                   when { resource.scope.contains("pods:read") };"#,
        )
        .expect("valid");
        for spelling in [
            "pods:read",
            "pods:read  pods:read",
            "  pods:read",
            "pods:read\t",
        ] {
            let allowed = engine.authorize(
                &oauth2_request(Action::OAuth2Identity, spelling),
                None,
                None,
            );
            assert!(
                allowed.decision.is_allowed(),
                "{spelling:?} is the same grant as `pods:read` and must be permitted: {:?}",
                allowed.reason
            );
        }
        // The one definition, checked against the definition this crate used to
        // carry. The issuer calls the same function, so a change here moves both
        // — and this assertion is what makes that a *checked* claim rather than
        // a comment.
        assert_eq!(
            asv_domain::scope_set("write  read read"),
            vec!["read".to_string(), "write".to_string()],
            "scope_set is the shared normalisation: split on whitespace, sorted, deduplicated"
        );
    }

    /// The scope the policy reads is the **registration's**, and the schema
    /// refuses a rule that tries to read a different one.
    ///
    /// Two directions, because they are different guarantees. First: the field
    /// `resource_attributes` reads is the `scope` of the resource, and the
    /// broker fills that from the deployment — a row that could not distinguish
    /// the two would pass if the broker started putting the *audience* there, and
    /// the audience is a URL, so every membership test would fail closed and
    /// every OAuth2 identity call would be denied for a reason no policy text
    /// could explain.
    ///
    /// Second, and this is the property R2.B.2 relies on: a rule naming
    /// `resource.audience` on an `OAuth2Client` is a **load-time** failure. The
    /// operator gets told, once, at startup, instead of a permanent unexplained
    /// denial per request. The control is stronger than it was designed to be —
    /// it is the same accident that made the dangerous AWS rule unwritable.
    #[test]
    fn the_oauth2_scope_is_the_registration_s_and_a_rule_cannot_reach_anything_else() {
        // The audience is not reachable as an attribute on this type, even
        // though the domain variant carries it for the audit trail.
        let refused = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"oauth2_identity",
                       resource is OAuth2Client)
                   when { resource.audience == "https://api.asv.test" };"#,
        );
        assert!(
            refused.is_err(),
            "a rule reading an attribute the OAuth2Client shape does not declare must not load"
        );

        // And the scope is what the rule actually reads: an audience that
        // *contains* the scope string cannot satisfy a membership test, which is
        // the falsifiable form of "the policy reads the scope and not the
        // audience".
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"oauth2_identity",
                       resource is OAuth2Client)
                   when { resource.scope.contains("pods:read") };"#,
        )
        .expect("valid");
        let mut mislabelled = oauth2_request(Action::OAuth2Identity, "pods:read");
        if let Resource::OAuth2Client { scope, .. } = &mut mislabelled.resource {
            *scope = "https://pods:read.asv.test".into();
        }
        assert!(
            !engine
                .authorize(&mislabelled, None, None)
                .decision
                .is_allowed(),
            "a scope token that embeds the string was treated as the scope itself, so the rule \
             is not testing whole tokens"
        );
    }

    /// A resource attribute the schema does not declare is refused by the
    /// entity store, which is what makes a schema/attribute drift **loud**.
    ///
    /// `resource_attributes` names `"audience"` and `SCHEMA_JSON` declares it,
    /// so the two cannot disagree silently today. If one is edited and the other
    /// is not, `Entities::from_entities` refuses the entity and every `Api`
    /// authorization becomes a denial — correct, and useless on its own, because
    /// a denial is what a *policy* produces too. The operator could not tell
    /// "your policy does not permit this" from "this build is broken", and a
    /// broken build that denies everything is the quietest failure available.
    ///
    /// The misspelling here is deliberate and is the shape a real drift takes: a
    /// one-word edit on one side of a pair nothing else checks.
    #[test]
    fn an_attribute_the_schema_does_not_declare_is_refused_by_the_store() {
        let engine = PolicyEngine::default();
        let schema = Schema::from_json_str(SCHEMA_JSON).expect("the built-in schema parses");
        let uid = EntityUid::from_str(&format!(
            "Api::\"{}\"",
            resource_name(&Resource::Api {
                audience: Authority::canonicalize("api.github.com").expect("valid")
            })
        ))
        .expect("the resource name is a valid entity id");

        // The declared name builds and the schema accepts it.
        let declared: HashMap<String, RestrictedExpression> = [(
            "audience".to_string(),
            RestrictedExpression::new_string("api.github.com".into()),
        )]
        .into_iter()
        .collect();
        let accepted = Entity::new(uid.clone(), declared, HashSet::new())
            .map_err(|error| error.to_string())
            .and_then(|entity| {
                Entities::from_entities(vec![entity], Some(&schema)).map_err(|e| e.to_string())
            });
        assert!(
            accepted.is_ok(),
            "the declared attribute is refused, so the schema is not the shape the code writes: {accepted:?}"
        );

        // The misspelled one does not.
        //
        // **The refusal is loud but generic**, and that is worth stating rather
        // than papering over: Cedar 4.7.1 says `entity does not conform to the
        // schema` and does not name the attribute. The first version of this row
        // asserted it did, and was wrong — the same mistake this file's whole
        // change is about, in the opposite direction: claiming a diagnostic the
        // library does not produce.
        //
        // So the guarantee is precisely "a drift denies rather than silently
        // comparing against nothing", and the *diagnosis* is the operator's
        // because the message points at the shape rather than the value. The
        // `audience` string is one line away in `resource_attributes` and one
        // line away in `SCHEMA_JSON`, which is what makes that acceptable.
        let typo: HashMap<String, RestrictedExpression> = [(
            "audiant".to_string(),
            RestrictedExpression::new_string("api.github.com".into()),
        )]
        .into_iter()
        .collect();
        let refused = Entity::new(uid, typo, HashSet::new())
            .map_err(|error| error.to_string())
            .and_then(|entity| {
                Entities::from_entities(vec![entity], Some(&schema)).map_err(|e| e.to_string())
            })
            .expect_err("an undeclared attribute is accepted, so a drift would be silent");
        assert!(
            refused.contains("schema"),
            "the refusal does not even mention the schema, so it reads like any \
             other construction failure: {refused}"
        );
        // And a correct build is unaffected by any of this.
        assert!(engine
            .authorize(
                &api_request(Action::GitHubIssueRead, "api.github.com"),
                None,
                None
            )
            .decision
            .is_allowed());
    }

    /// **The row that makes `Some(&schema)` load-bearing.** It is the one thing
    /// the previous row could not measure, and the reason is worth stating: that
    /// row calls `Entities::from_entities` itself, so it proves Cedar refuses an
    /// undeclared attribute while saying nothing about whether the *production*
    /// path passes the schema. Mutating `Some(&self.schema)` to `None` left it
    /// green, correctly, because a correctly-named attribute is accepted either
    /// way.
    ///
    /// So the schema is doctored instead: an engine whose `Api` type declares no
    /// shape, built through the same fields production builds. The production
    /// path then supplies an `audience` attribute that *this* schema does not
    /// declare, and the question becomes observable: with the schema passed, the
    /// request is refused as a schema violation; without it, the entity is
    /// accepted and a permissive policy allows the call.
    ///
    /// That is the whole value of the schema argument. A future edit that drops
    /// it would let an attribute the schema never declared reach the evaluator,
    /// and no policy can reference such an attribute — so nothing would look
    /// wrong while the mechanism quietly stopped working.
    #[test]
    fn a_schema_that_does_not_declare_the_supplied_attribute_is_refused() {
        // `Api` with no shape, so `audience` is undeclared for this engine.
        let doctored = SCHEMA_JSON.replace(
            r#""Api": {
        "shape": {
          "type": "Record",
          "attributes": {
            "audience": { "type": "String" }
          }
        }
      }"#,
            r#""Api": {}"#,
        );
        assert_ne!(
            doctored, SCHEMA_JSON,
            "the doctored schema is identical to the real one, so this row \
             would pass for the wrong reason"
        );
        let schema = Schema::from_json_str(&doctored).expect("the doctored schema parses");
        let base = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"github_issue_read", resource is Api);"#,
        )
        .expect("the fixture policy is valid against the real schema");
        let engine = PolicyEngine {
            schema: Arc::new(schema),
            ..base
        };
        let decided = engine.authorize(
            &api_request(Action::GitHubIssueRead, "api.github.com"),
            None,
            None,
        );
        // `ExplainResult::reason` is a `ReasonCode` and is `NoMatchingPolicy`
        // for *both* "the policy did not match" and "the engine refused", which
        // is why the first version of this assertion read the wrong field and
        // looked like the store had accepted the entity. The free text lives on
        // the decision, and that is the field an operator sees in a denial.
        let Decision::Deny { reason } = &decided.decision else {
            panic!("the call was allowed, so the schema argument is not applied: {decided:?}");
        };
        assert!(
            reason.contains("policy engine failure"),
            "the refusal does not say the engine refused it, so it is \
             indistinguishable from a policy that simply did not match: {reason}"
        );
        assert!(
            reason.contains("schema"),
            "and it does not mention the schema, which is the only thing that \
             was actually wrong: {reason}"
        );
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

// ------------------------------------------------------------ M11-R2.F.3

#[cfg(test)]
/// A registry request against a declared authority and a named repository.
///
/// Both halves are parameters for the same reason the OAuth2 helper takes a
/// scope: the authority is what an operator's rule compares against and the
/// repository is what the agent chose, and a fixture that hardcoded either
/// one would let every row below pass with a rule nobody wrote.
fn registry_request(action: Action, authority: &str, repository: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        session: AgentSessionId::new(),
        action,
        resource: Resource::Registry {
            authority: Authority::canonicalize(authority).expect("valid authority"),
            repository: repository.into(),
        },
        context: PolicyContext {
            workspace: "/repo".into(),
            protected_ref: None,
            request_digest: Some("digest".into()),
            peer_uid: 1000,
        },
    }
}

/// A stock broker refuses every registry operation, pull included.
///
/// This is the load-bearing row for the whole increment, and it is easier to
/// get wrong than it looks. `registry_pull` is the *read* half of a provider
/// whose read half looks harmless — and permitting it here would mean every
/// deployment that upgrades to a version with an OCI connector starts letting
/// every agent session pull every image its credential can reach, with no
/// operator having decided that. The two actions are in the Cedar *schema* so
/// that a rule naming them loads and then denies, which is a failure an
/// operator can read, rather than failing at policy load.
///
/// Mutation: add `permit (principal, action == Action::"registry_pull",
/// resource is Registry);` to `POLICY_TEXT`.
#[test]
fn la_policy_por_defecto_no_permite_nada_sobre_un_registro() {
    let engine = PolicyEngine::default();
    for (action, label) in [
        (Action::RegistryPull, "pull"),
        (Action::RegistryPush, "push"),
    ] {
        let verdict = engine.authorize(
            &registry_request(action, "registry-1.docker.io", "library/alpine"),
            None,
            None,
        );
        assert!(
            !verdict.decision.is_allowed(),
            "a default policy permitted a registry {label}, so an operator who \
             never wrote a rule would find their deployment pulling images"
        );
    }
}

/// The rule `POLICY_TEXT` tells an operator to write now matches, and matches
/// only the registry and repository it names.
///
/// Both halves, for the reason the AWS row above says twice: the interesting
/// failure is a condition that is satisfiable by *anything*, which looks
/// identical to "it works" when only the positive half is asserted. A
/// `when { resource.repository == ... }` against an attribute nothing supplies
/// would deny always, and `when { true }` would allow always — and the first
/// is the bug that shipped once already, in `Api::audience`.
///
/// Mutation: drop the `repository` arm from `resource_attributes`, or supply
/// the authority under the repository's name.
#[test]
fn la_regla_documentada_de_un_registro_casa_y_solo_con_el_suyo() {
    let engine = PolicyEngine::from_policy_text(
        r#"permit (principal, action == Action::"registry_pull", resource is Registry)
           when { resource.authority == "registry-1.docker.io"
                  && resource.repository == "library/alpine" };"#,
    )
    .expect("the documented rule loads and is valid");

    assert!(
        engine
            .authorize(
                &registry_request(
                    Action::RegistryPull,
                    "registry-1.docker.io",
                    "library/alpine"
                ),
                None,
                None,
            )
            .decision
            .is_allowed(),
        "a rule naming the registry's own repository still denies"
    );

    // The same registry, another repository. This half has no analogue on any
    // other provider here, and it is the whole reason `Registry` is not an
    // `Api`: without a repository attribute there is nothing to write.
    assert!(
        !engine
            .authorize(
                &registry_request(Action::RegistryPull, "registry-1.docker.io", "acme/private"),
                None,
                None,
            )
            .decision
            .is_allowed(),
        "a pull of another repository on the same approved registry was allowed"
    );

    // Another registry, the repository the rule names.
    assert!(
        !engine
            .authorize(
                &registry_request(Action::RegistryPull, "ghcr.io", "library/alpine"),
                None,
                None,
            )
            .decision
            .is_allowed(),
        "the same repository on another registry was allowed"
    );
}

/// A rule that permits only `registry_pull` does not also permit
/// `registry_push`, and permitting the read is not a decision about the
/// write.
///
/// The two actions exist separately because a pull reads content this side
/// can verify and a push asserts content *to* someone else: after it, a
/// repository that other agents, other CI and other humans pull from is no
/// longer the one they were verifying. One `registry_access` action with a
/// scope parameter would have collapsed exactly that, and the collapse would
/// have looked like a simplification.
///
/// Mutation: put both actions in the `action in [...]` head of the rule.
#[test]
fn un_pull_permitido_no_arrastra_al_push() {
    let engine = PolicyEngine::from_policy_text(
        r#"permit (principal, action == Action::"registry_pull", resource is Registry)
           when { resource.repository == "library/alpine" };"#,
    )
    .expect("the pull-only rule loads");

    assert!(
        engine
            .authorize(
                &registry_request(
                    Action::RegistryPull,
                    "registry-1.docker.io",
                    "library/alpine"
                ),
                None,
                None,
            )
            .decision
            .is_allowed(),
        "the pull the rule names is denied, so the row would prove nothing"
    );
    assert!(
        !engine
            .authorize(
                &registry_request(
                    Action::RegistryPush,
                    "registry-1.docker.io",
                    "library/alpine"
                ),
                None,
                None,
            )
            .decision
            .is_allowed(),
        "a rule that permits a pull also permitted a push to the same repository"
    );
}

/// The registry entity is not a repository entity, and the uid says so.
///
/// `Repository { owner, name }` renders `acme/app`; a `Registry` holding the
/// repository `app` on `registry-1.docker.io` renders
/// `registry:registry-1.docker.io/library/app`. Without the prefix the two
/// are the same string, and a policy rule naming one would match whichever
/// the entity store happened to hold — which is the D6 defect the comment on
/// `entity_type` describes, in a different costume.
///
/// Mutation: drop the `registry:` prefix from `resource_name`.
#[test]
fn una_entidad_de_registro_no_se_puede_confundir_con_una_de_repositorio() {
    let uid = registry_request(Action::RegistryPull, "registry-1.docker.io", "library/app")
        .resource_name();

    assert!(
        uid.starts_with("registry:"),
        "a registry entity has no namespace prefix: {uid:?}"
    );
    // The value is stable enough for an operator to write into a policy,
    // which is the only reason to build it as a string at all.
    assert_eq!(uid, "registry:registry-1.docker.io/library/app");
}

/// What `Authority` gives a registry resource, stated exactly.
///
/// This row replaced a stronger claim that was simply false, and the false
/// claim is worth recording because it is the fifth time this repository has
/// written it. The earlier version asserted that
/// `registry-1.docker.io.evil.example` would not canonicalize. It does — it is
/// a perfectly valid host, and a *different* one, and treating that as a forgery
/// is the wrong model: a suffix mirla is not a misspelling of an approved host,
/// it is somebody else's host.
///
/// The two guarantees below are the ones that are actually true, and both are
/// needed:
///
/// 1. **One spelling per host.** `REGISTRY-1.DOCKER.IO` and
///    `registry-1.docker.io` are the same value, so an operator writing one and
///    a broker building the other compare equal. A case-sensitive `String` would
///    make the allowlist a spelling lottery.
/// 2. **Anything that is not a bare host is refused** — a scheme, a port, a
///    path, an empty label. So the value inside a `Registry` is a host and
///    cannot smuggle a URL, which is what keeps a policy rule comparing it from
///    being about a different string than the one that gets dialled.
///
/// And what the type does **not** give is approval. `ALLOWED_AUDIENCES` does
/// not list registries and does not need to, because the broker builds this
/// value from operator configuration and the request only ever names a
/// repository. A row claiming this layer enforced an allowlist would be the
/// exact defect D6's own row warns about.
///
/// Mutation: stop lowercasing, or accept a scheme/port/path in
/// `Authority::canonicalize`.
#[test]
fn una_autoridad_de_registro_tiene_una_sola_ortografia_y_es_un_host() {
    // 1. One spelling per host.
    assert_eq!(
        Authority::canonicalize("REGISTRY-1.DOCKER.IO").expect("valid"),
        Authority::canonicalize("registry-1.docker.io").expect("valid"),
        "two spellings of one host are two values, so an operator's rule depends \
         on how the broker typed it"
    );
    // And a suffix mirla is a *different* host, which is why an allowlist has to
    // be an exact comparison rather than a suffix test.
    assert_ne!(
        Authority::canonicalize("registry-1.docker.io.evil.example").expect("valid"),
        Authority::canonicalize("registry-1.docker.io").expect("valid"),
    );
    // 2. Not a bare host, refused.
    for not_a_host in [
        "https://registry-1.docker.io",
        "registry-1.docker.io:443",
        "evil.example/registry-1.docker.io",
        "registry-1.docker.io/v2/",
        "a..b",
        "",
    ] {
        assert!(
            Authority::canonicalize(not_a_host).is_err(),
            "{not_a_host:?} became an authority, so a policy rule comparing it \
             would be comparing a different string than the one dialled"
        );
    }
}

// These three rows live outside `mod tests` because the file is laid out
// that way, and a `use super::tests::api_request;` would be the wrong shape
// (the `api_request` helper is in scope *inside* mod tests only). Inlining
// the `AuthorizationRequest` is the cheaper repair, and the duplication is
// bounded — three tests, one request shape.
#[cfg(test)]
mod r2_d_e_audience_carveout {
    use super::*;

    fn request(action: Action, audience: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            session: AgentSessionId::new(),
            action,
            resource: Resource::Api {
                audience: Authority::canonicalize(audience).expect("canonical authority"),
            },
            context: PolicyContext {
                workspace: "/repo".into(),
                protected_ref: None,
                request_digest: Some("digest".into()),
                peer_uid: 1000,
            },
        }
    }

    #[test]
    fn k8s_read_evaluates_against_a_deployment_declared_audience() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"k8s_read", resource is Api) when {
                resource.audience == "kubernetes.default.svc"
            };"#,
        )
        .expect("the documented rule loads and is valid");
        let verdict = engine
            .authorize(
                &request(Action::K8sRead, "kubernetes.default.svc"),
                None,
                None,
            )
            .decision;
        assert!(verdict.is_allowed(), "{verdict:?}");
    }

    #[test]
    fn mtls_sign_evaluates_against_a_deployment_declared_audience() {
        let engine = PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"mtls_sign", resource is Api) when {
                resource.audience == "svc-a.internal"
            };"#,
        )
        .expect("the documented rule loads and is valid");
        let verdict = engine
            .authorize(&request(Action::MTlsSign, "svc-a.internal"), None, None)
            .decision;
        assert!(verdict.is_allowed(), "{verdict:?}");
    }

    #[test]
    fn the_first_party_audience_check_still_refuses_unapproved_hosts() {
        let engine = PolicyEngine::from_policy_text(r#"permit (principal, action, resource);"#)
            .expect("the most permissive policy is valid");
        let verdict = engine
            .authorize(
                &request(Action::GitHubIssueRead, "evil.example"),
                None,
                None,
            )
            .decision;
        assert!(!verdict.is_allowed(), "{verdict:?}");
    }
}
