//! C2.6 — the CONNECT route table.
//!
//! The CONNECT listener used to be constructed with `Vec::new()` and a handler
//! carrying `OperationFamily::GitHub` as a constant. That is a proxy that
//! refuses every tunnel, and a proxy that would have substituted a GitHub
//! credential for *any* host the moment someone widened the first list. Both
//! halves were the same defect: the bridge held the policy.
//!
//! This module moves the decision out of the bridge. An operator writes routes
//! declaratively, each route names its own operation family and credential, and
//! every route is authorized against the existing Cedar [`PolicyEngine`] at load
//! time. The bridge then holds no rules at all — it resolves a route that is
//! already authorised, and refuses anything it cannot resolve.
//!
//! **The file is a declaration; Cedar is the permission.** A route that names a
//! host the policy does not permit is refused when the file loads, so editing
//! the config cannot widen what the policy allows. That is the whole reason the
//! cross-check happens here rather than being left to the CONNECT path, where a
//! missing check reads exactly like a policy that permits everything.
//!
//! **The default policy permits no route at all.** See the note in
//! `asv_policy`'s `POLICY_TEXT`. A stock broker refuses every declared route,
//! which is the truthful posture for a surface that did not exist before.
//!
//! ## What a route does and does not pin
//!
//! A route pins an *identity*: a canonical DNS name and a port. It does not pin
//! an address, and it cannot. Resolution happens later, at connect time, against
//! whatever resolver the host has — so a hostile DNS answer can still point a
//! permitted name at an attacker's address. The route table's contribution to
//! that problem is bounded and worth stating plainly: the proof nonce, the
//! authorization and the audit record all name the *authority*, never the
//! resolved address, so a rebind cannot change what was authorized. Pinning the
//! address too is a separate control that does not exist yet, and this module
//! does not pretend otherwise.
//!
//! An IP literal is refused outright. `Authority::canonicalize` accepts
//! `127.0.0.1` — it is a syntactically valid, four-label name — and a direct
//! address in a route file is precisely the shape of the direct-address trick
//! the allow-list exists to refuse: no DNS to pin, and a route that outlives
//! whatever the operator thought the number meant.

use asv_domain::{
    Action, AgentSessionId, Authority, AuthorityError, IntegrationPosture, OperationFamily,
    Resource,
};
use asv_policy::{PolicyContext, PolicyEngine, ReasonCode};
use serde::{Deserialize, Serialize};

use crate::tls_bridge::{AuthorityEndpoint, ConnectPolicy};

/// One declared route, exactly as an operator wrote it.
///
/// This is the deserialization shape and it is deliberately *not* the shape the
/// broker authorizes: [`Self::authority`] is a [`String`] because
/// `Authority` is `#[serde(transparent)]` and would deserialize any spelling
/// without canonicalizing it. A route file is untrusted input, so the string is
/// canonicalized on the way in and a lookalike host is rejected rather than
/// silently normalized into a match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRoute {
    /// The DNS name, e.g. `api.github.com`. Canonicalized at load.
    pub authority: String,
    /// The TCP port. Port 0 is refused.
    pub port: u16,
    /// Which family of brokered operation this route serves.
    ///
    /// Spelled `git_hub` or `database` in the file. That is not a typo:
    /// `OperationFamily` derives `rename_all = "snake_case"`, and serde splits
    /// `GitHub` at the internal capital, so `github` is a *different* variant
    /// and is refused. The file therefore cannot be written from a guess at the
    /// Rust spelling, which is the intended direction to be wrong in.
    pub operation_family: OperationFamily,
    /// The credential alias whose value is substituted into the tunnel.
    pub credential: String,
    /// The weakest posture that may be used for this route.
    ///
    /// Required, not defaulted. `IntegrationPosture` has no `Default` and that
    /// is correct: a missing posture would have to be *some* variant, and
    /// every candidate is wrong in a different direction. Defaulting to
    /// `Unsupported` reads as "ASV declined", defaulting to
    /// `StrongSecretless` invents a guarantee nobody made. Making the operator
    /// state it is the only option that cannot be silently wrong.
    pub minimum_posture: IntegrationPosture,
}

/// A route that has passed canonicalization and the policy cross-check.
///
/// The fields are what the bridge reads, and there is no raw spelling left in
/// here to re-parse. That is the point: a second parser in the CONNECT path
/// would not fail loudly, it would produce routes that match nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoute {
    endpoint: AuthorityEndpoint,
    operation_family: OperationFamily,
    credential: String,
    minimum_posture: IntegrationPosture,
}

impl ResolvedRoute {
    /// The canonical `(authority, port)` this route authorizes.
    pub fn endpoint(&self) -> &AuthorityEndpoint {
        &self.endpoint
    }

    /// The family the substitution runs under. Per route, not per handler.
    pub fn operation_family(&self) -> OperationFamily {
        self.operation_family
    }

    /// The credential alias substituted into the tunnel.
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// The weakest posture permitted for this route.
    pub fn minimum_posture(&self) -> IntegrationPosture {
        self.minimum_posture
    }
}

/// The loaded, authorized route table.
///
/// An empty set is not a degraded table, it is a closed proxy: it authorizes
/// nothing, and [`ConnectPolicy::is_empty`] reports it so a caller can say so
/// out loud rather than serving a listener that refuses for a reason nobody has
/// written down.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectRouteSet {
    routes: Vec<ResolvedRoute>,
}

impl ConnectRouteSet {
    /// Parse and validate a route file, then authorize every route against the
    /// policy engine.
    ///
    /// The order is deliberate. Structural validation happens first so a
    /// malformed file is reported as a malformed file, rather than as a policy
    /// denial for a route that could never have parsed. Policy is consulted
    /// second, and a single refusal fails the whole load: a table that silently
    /// dropped the routes Cedar denied would let an operator read "the broker
    /// started" as "my configuration is in force", which is the one reading
    /// that must never be true by accident.
    pub fn load(routes_json: &str, policy: &PolicyEngine) -> Result<Self, ConnectRouteError> {
        let declared: Vec<ConnectRoute> = serde_json::from_str(routes_json)
            .map_err(|e| ConnectRouteError::Malformed(e.to_string()))?;
        Self::from_routes(declared, policy)
    }

    /// The same, from already-deserialized routes.
    pub fn from_routes(
        declared: Vec<ConnectRoute>,
        policy: &PolicyEngine,
    ) -> Result<Self, ConnectRouteError> {
        let mut resolved: Vec<ResolvedRoute> = Vec::with_capacity(declared.len());

        for route in declared {
            let authority = Authority::canonicalize(&route.authority).map_err(|source| {
                ConnectRouteError::NotAHost {
                    spelled: route.authority.clone(),
                    source,
                }
            })?;

            // A direct address is a syntactically valid authority and a policy
            // hole: there is no name to pin and no DNS answer to distrust, so
            // the route would authorize exactly the literal the operator
            // typed. Refused rather than warned about.
            if looks_like_ip_literal(&authority) {
                return Err(ConnectRouteError::IpLiteral {
                    spelled: route.authority.clone(),
                });
            }

            let endpoint = AuthorityEndpoint::new(authority, route.port).map_err(|_| {
                ConnectRouteError::ZeroPort {
                    spelled: route.authority.clone(),
                }
            })?;

            if route.credential.trim().is_empty() {
                return Err(ConnectRouteError::EmptyCredential {
                    endpoint: endpoint.to_string(),
                });
            }

            if resolved.iter().any(|r| r.endpoint == endpoint) {
                // Two routes for one endpoint is a coin flip, not a merge: they
                // can disagree about the credential, and which one won would
                // depend on file order.
                return Err(ConnectRouteError::Duplicate {
                    endpoint: endpoint.to_string(),
                });
            }

            authorize_route(policy, &endpoint)?;

            resolved.push(ResolvedRoute {
                endpoint,
                operation_family: route.operation_family,
                credential: route.credential,
                minimum_posture: route.minimum_posture,
            });
        }

        Ok(Self { routes: resolved })
    }

    /// The routes, in declaration order.
    pub fn routes(&self) -> &[ResolvedRoute] {
        &self.routes
    }

    /// The route that authorizes exactly this endpoint, if any.
    ///
    /// Exact match on the canonical `(authority, port)` pair. A host that
    /// merely resembles an allowed one resolves to nothing, which is the
    /// property the whole table exists to have.
    pub fn route_for(&self, target: &AuthorityEndpoint) -> Option<&ResolvedRoute> {
        self.routes.iter().find(|r| r.endpoint == *target)
    }

    /// Whether this table authorizes the target.
    pub fn authorizes(&self, target: &AuthorityEndpoint) -> bool {
        self.route_for(target).is_some()
    }

    /// Whether the table is empty, i.e. the proxy is closed.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Number of authorized routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Withdraw a route.
    ///
    /// Returns whether it was there. This is the reload path, and it is honest
    /// about scope: a withdrawn route refuses *new* tunnels immediately while
    /// every session record and every established tunnel is untouched. Sessions
    /// outlive configuration on purpose — an operator pulling a route must not
    /// silently revoke the credentials of an agent mid-command, which is a
    /// different operation with a different name (`revoke`) and its own audit
    /// record.
    pub fn withdraw(&mut self, target: &AuthorityEndpoint) -> bool {
        let before = self.routes.len();
        self.routes.retain(|r| r.endpoint != *target);
        self.routes.len() != before
    }

    /// The bridge's allow-list, derived from this table.
    pub fn to_connect_policy(&self) -> ConnectPolicy {
        ConnectPolicy {
            allowed: self.routes.iter().map(|r| r.endpoint.clone()).collect(),
        }
    }
}

/// Ask the policy engine whether this route may exist at all.
///
/// The session id is freshly minted per load and is not an agent session. It
/// carries no grants and no revocations, so the decision Cedar returns is a
/// function of the policy text alone — which is the property being relied on
/// here. Naming it explicitly matters: a future change that hands this check a
/// real session, or reuses one across loads, would make a load-time decision
/// depend on session state, and a route that was authorized at boot could stop
/// being authorized without the file changing.
fn authorize_route(
    policy: &PolicyEngine,
    endpoint: &AuthorityEndpoint,
) -> Result<(), ConnectRouteError> {
    let request = asv_policy::AuthorizationRequest {
        session: AgentSessionId::new(),
        action: Action::ConnectRoute,
        resource: Resource::Host {
            hostname: endpoint.host().to_owned(),
        },
        context: PolicyContext {
            workspace: String::new(),
            protected_ref: None,
            request_digest: None,
            // The declaring process runs as the broker's own user. It is
            // recorded so an audit of a denial can name who asked, not so the
            // decision can vary by uid.
            peer_uid: 0,
        },
    };

    let verdict = policy.authorize(&request, None, None);
    match verdict.reason {
        ReasonCode::AllowedByPolicy => Ok(()),
        other => Err(ConnectRouteError::NotPermitted {
            endpoint: endpoint.to_string(),
            reason: other,
        }),
    }
}

/// Whether a canonical authority is really a dotted-quad or a numeric address.
///
/// `Authority::canonicalize` accepts `127.0.0.1` and `0x7f.1` alike: both are
/// valid label syntax, and neither is a name. The check is the last label being
/// entirely numeric, which is what every numeric TLD form has in common.
fn looks_like_ip_literal(authority: &Authority) -> bool {
    authority
        .as_ref()
        .rsplit('.')
        .next()
        .is_some_and(|last| !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
}

/// Why a route table could not be loaded.
///
/// Every variant names the offending route and none of them name a secret: the
/// input is an operator's config file, and the values here are hosts, ports and
/// credential *aliases*, never credential material.
#[derive(Debug, thiserror::Error)]
pub enum ConnectRouteError {
    #[error("the route file is not valid JSON: {0}")]
    Malformed(String),

    #[error("{spelled:?} is not a usable host: {source}")]
    NotAHost {
        spelled: String,
        #[source]
        source: AuthorityError,
    },

    #[error("{spelled:?} is a direct address, not a name; a route must name a host it can pin")]
    IpLiteral { spelled: String },

    #[error("port 0 is not a service port ({spelled})")]
    ZeroPort { spelled: String },

    #[error("{endpoint} declares an empty credential alias")]
    EmptyCredential { endpoint: String },

    #[error("{endpoint} is declared more than once; which credential it uses would depend on file order")]
    Duplicate { endpoint: String },

    #[error("the policy does not permit a route to {endpoint}: {reason:?}")]
    NotPermitted {
        endpoint: String,
        reason: ReasonCode,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy that permits the `connect_route` action for any host.
    ///
    /// The stock policy permits none, which is the fail-closed reading, so
    /// every test that is *not* about the refusal supplies this. That split is
    /// the point: the permissive text is explicit and local, never a default.
    fn permitting() -> PolicyEngine {
        PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"connect_route", resource is Host);"#,
        )
        .expect("test policy must validate")
    }

    /// A policy that permits the route action for one host only.
    ///
    /// The host is pinned by entity equality rather than by an attribute
    /// comparison. `Host` declares no attributes in the schema, so
    /// `resource.hostname` is an `UnsafeAttributeAccess` that fails validation
    /// — and exact entity equality is the stronger form anyway: it admits one
    /// specific canonical name rather than a value a future attribute could
    /// make matchable in part.
    fn permitting_only(host: &str) -> PolicyEngine {
        PolicyEngine::from_policy_text(&format!(
            r#"permit (principal, action == Action::"connect_route", resource == Host::"host:{host}");"#
        ))
        .expect("test policy must validate")
    }

    fn route(authority: &str, port: u16) -> ConnectRoute {
        ConnectRoute {
            authority: authority.to_owned(),
            port,
            operation_family: OperationFamily::GitHub,
            credential: "github".to_owned(),
            minimum_posture: IntegrationPosture::StrongSecretless,
        }
    }

    fn endpoint(authority: &str, port: u16) -> AuthorityEndpoint {
        AuthorityEndpoint::new(
            Authority::canonicalize(authority).expect("valid host"),
            port,
        )
        .expect("valid port")
    }

    // -- the properties the objective names, one test each -------------------

    #[test]
    fn an_allowed_host_on_the_wrong_port_is_denied() {
        let set = ConnectRouteSet::from_routes(vec![route("api.github.com", 443)], &permitting())
            .expect("route must load");

        assert!(set.authorizes(&endpoint("api.github.com", 443)));
        // Same host, different port. The port is part of the identity: a route
        // for 443 is not consent for 8443, and a host-only allowlist would
        // hand every port on that host to the tunnel.
        assert!(!set.authorizes(&endpoint("api.github.com", 8443)));
        assert!(set
            .to_connect_policy()
            .authorize(&endpoint("api.github.com", 8443))
            .is_err());
    }

    #[test]
    fn a_lookalike_host_is_denied() {
        let set = ConnectRouteSet::from_routes(vec![route("api.github.com", 443)], &permitting())
            .expect("route must load");

        for lookalike in [
            "api.github.com.evil.test",
            "evil-api.github.com",
            "apiXgithub.com",
            "api.github.co",
            "github.com",
        ] {
            assert!(
                !set.authorizes(&endpoint(lookalike, 443)),
                "{lookalike} must not be authorized by a route for api.github.com"
            );
        }
    }

    #[test]
    fn canonicalization_folds_case_and_trailing_dot_to_the_same_route() {
        let set = ConnectRouteSet::from_routes(vec![route("API.GitHub.COM.", 443)], &permitting())
            .expect("route must load");

        // Canonicalized once, on the way in, so every spelling a client may
        // legitimately send resolves to the one route.
        for spelling in ["api.github.com", "API.GITHUB.COM", "api.github.com."] {
            assert!(
                set.authorizes(&endpoint(spelling, 443)),
                "{spelling} should reach the same canonical route"
            );
        }
        assert_eq!(set.len(), 1, "three spellings must not become three routes");
    }

    #[test]
    fn a_direct_address_is_refused_rather_than_routed() {
        // `Authority::canonicalize` accepts all of these — they are valid label
        // syntax — which is exactly why the route loader has to refuse them.
        for literal in ["127.0.0.1", "10.0.0.5", "169.254.169.254", "0x7f.1"] {
            let err = ConnectRouteSet::from_routes(vec![route(literal, 443)], &permitting())
                .expect_err("a direct address must not become a route");
            assert!(
                matches!(err, ConnectRouteError::IpLiteral { .. }),
                "{literal} produced {err:?}"
            );
        }
    }

    #[test]
    fn a_rebind_cannot_change_the_authorized_identity() {
        let set = ConnectRouteSet::from_routes(vec![route("api.github.com", 443)], &permitting())
            .expect("route must load");

        // What a hostile resolver can do is change the *address* behind a name.
        // What it cannot do is change which identity the route authorized: the
        // table matches on the canonical name, and a target spelled any other
        // way — including the address the rebind produced — resolves to
        // nothing. This is the boundary, and the test is here so that widening
        // the table later has to confront it.
        assert!(set.authorizes(&endpoint("api.github.com", 443)));
        assert!(!set.authorizes(&endpoint("93.184.216.34", 443)));
        assert!(!set.authorizes(&endpoint("api.github.com.attacker.test", 443)));
    }

    #[test]
    fn a_resolved_route_cannot_be_edited_after_the_plan() {
        let set = ConnectRouteSet::from_routes(vec![route("api.github.com", 443)], &permitting())
            .expect("route must load");

        // The resolved route is reached by shared reference and exposes no
        // mutating accessor, so the bridge cannot retarget a route after it was
        // authorized. The only way to change one is to build another table.
        let resolved = set
            .route_for(&endpoint("api.github.com", 443))
            .expect("route present");
        assert_eq!(resolved.operation_family(), OperationFamily::GitHub);
        assert_eq!(resolved.credential(), "github");
        assert_eq!(resolved.endpoint().port(), 443);

        // A clone is a copy: mutating the caller's copy does not reach the set.
        let mut copy = set.clone();
        copy.withdraw(&endpoint("api.github.com", 443));
        assert!(
            set.authorizes(&endpoint("api.github.com", 443)),
            "withdrawing from a copy must not reach the original table"
        );
    }

    #[test]
    fn a_withdrawn_route_stops_new_tunnels_and_leaves_sessions_alone() {
        let mut set =
            ConnectRouteSet::from_routes(vec![route("api.github.com", 443)], &permitting())
                .expect("route must load");

        assert!(set.withdraw(&endpoint("api.github.com", 443)));
        assert!(!set.authorizes(&endpoint("api.github.com", 443)));
        assert!(set.is_empty(), "a withdrawn table is a closed proxy");

        // Withdrawing twice is not an error and not a silent success: the
        // caller learns the route was already gone.
        assert!(!set.withdraw(&endpoint("api.github.com", 443)));
    }

    #[test]
    fn an_empty_table_stays_closed() {
        let set = ConnectRouteSet::from_routes(Vec::new(), &permitting()).expect("empty loads");

        assert!(set.is_empty());
        assert!(set.to_connect_policy().is_empty());
        assert!(
            set.to_connect_policy()
                .authorize(&endpoint("api.github.com", 443))
                .is_err(),
            "an empty route table must refuse every destination"
        );
    }

    // -- the load-time permission, which is the C2.6 decision ---------------

    #[test]
    fn the_stock_policy_permits_no_route() {
        // No `permit` for `connect_route` exists in the built-in text, so a
        // route file alone authorizes nothing. This is the fail-closed reading
        // and it is asserted rather than assumed, because the alternative — a
        // blanket permit — would make every other test in this file vacuous.
        let err = ConnectRouteSet::from_routes(
            vec![route("api.github.com", 443)],
            &PolicyEngine::default(),
        )
        .expect_err("the default policy must refuse every route");

        match err {
            ConnectRouteError::NotPermitted { reason, .. } => {
                assert_eq!(reason, ReasonCode::NoMatchingPolicy);
            }
            other => panic!("expected a policy refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_route_the_policy_does_not_name_is_refused_at_load() {
        let policy = permitting_only("api.github.com");

        let err = ConnectRouteSet::from_routes(vec![route("registry.npmjs.org", 443)], &policy)
            .expect_err("a host outside the policy text must not load");

        match err {
            ConnectRouteError::NotPermitted { endpoint, reason } => {
                assert_eq!(endpoint, "registry.npmjs.org:443");
                assert_eq!(reason, ReasonCode::NoMatchingPolicy);
            }
            other => panic!("expected a policy refusal, got {other:?}"),
        }
    }

    #[test]
    fn one_refused_route_fails_the_whole_file() {
        // A table that silently dropped the denied route would let an operator
        // read "the broker started" as "my configuration is in force".
        let err = ConnectRouteSet::from_routes(
            vec![
                route("api.github.com", 443),
                route("registry.npmjs.org", 443),
            ],
            &permitting_only("api.github.com"),
        )
        .expect_err("a partially authorized file must not load");

        assert!(matches!(err, ConnectRouteError::NotPermitted { .. }));
    }

    // -- the per-route family and credential, which is the second decision --

    #[test]
    fn each_route_declares_its_own_family_and_credential() {
        let mut npm = route("registry.npmjs.org", 443);
        npm.operation_family = OperationFamily::Database;
        npm.credential = "npm_token".to_owned();

        let set =
            ConnectRouteSet::from_routes(vec![route("api.github.com", 443), npm], &permitting())
                .expect("routes must load");

        let github = set
            .route_for(&endpoint("api.github.com", 443))
            .expect("github route present");
        let registry = set
            .route_for(&endpoint("registry.npmjs.org", 443))
            .expect("npm route present");

        assert_eq!(github.operation_family(), OperationFamily::GitHub);
        assert_eq!(github.credential(), "github");
        assert_eq!(registry.operation_family(), OperationFamily::Database);
        assert_eq!(registry.credential(), "npm_token");
    }

    // -- structural validation ---------------------------------------------

    #[test]
    fn a_malformed_file_is_reported_as_malformed_not_as_a_denial() {
        let err = ConnectRouteSet::load("{ not json", &permitting())
            .expect_err("malformed input must not load");
        assert!(matches!(err, ConnectRouteError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // A typo'd `operation_family` would deserialize to a route with no
        // family, and the substitution would then run under whatever the
        // bridge defaulted to. Refusing the file makes the typo visible.
        //
        // Every required field is present, so the *only* thing wrong with this
        // document is the trailing `allowed_any_host`. The first version of
        // this test omitted `minimum_posture` and therefore passed for the
        // wrong reason — serde reported the missing field, not the unknown
        // one, and the test would have kept passing with
        // `deny_unknown_fields` deleted. A test that cannot fail is not a
        // measurement, so the mutation is what proves this one bites.
        let json = r#"[
            {"authority":"api.github.com","port":443,
             "operation_family":"git_hub","credential":"github",
             "minimum_posture":"STRONG_SECRETLESS",
             "allowed_any_host":true}
        ]"#;

        // The control: the same document without the unknown field loads.
        let control = r#"[
            {"authority":"api.github.com","port":443,
             "operation_family":"git_hub","credential":"github",
             "minimum_posture":"STRONG_SECRETLESS"}
        ]"#;
        ConnectRouteSet::load(control, &permitting())
            .expect("the control must load, or this test proves nothing");

        let err = ConnectRouteSet::load(json, &permitting())
            .expect_err("an unknown field must not be ignored");
        assert!(matches!(err, ConnectRouteError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn an_unusable_host_spelling_is_refused() {
        // The whitespace cases are the ones a loader is most tempted to
        // `trim()` away, and `Authority::canonicalize` refuses them for a
        // stated reason: a surrounding space would let `"api.github.com "`
        // slip past a textual comparison. A route loader that trims first
        // would reintroduce exactly that, so it is pinned here.
        for bad in [
            "not a host",
            "host/path",
            "user@host",
            "",
            "localhost",
            " api.github.com",
            "api.github.com ",
            "\tapi.github.com",
        ] {
            let err = ConnectRouteSet::from_routes(vec![route(bad, 443)], &permitting())
                .expect_err("{bad} must not become a route");
            assert!(
                matches!(err, ConnectRouteError::NotAHost { .. }),
                "{bad} produced {err:?}"
            );
        }
    }

    #[test]
    fn port_zero_and_an_empty_credential_are_refused() {
        let err = ConnectRouteSet::from_routes(vec![route("api.github.com", 0)], &permitting())
            .expect_err("port 0 must not become a route");
        assert!(matches!(err, ConnectRouteError::ZeroPort { .. }), "{err:?}");

        let mut blank = route("api.github.com", 443);
        blank.credential = "   ".to_owned();
        let err = ConnectRouteSet::from_routes(vec![blank], &permitting())
            .expect_err("a blank credential must not become a route");
        assert!(
            matches!(err, ConnectRouteError::EmptyCredential { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn two_routes_for_one_endpoint_are_refused() {
        let mut other = route("API.GITHUB.COM.", 443);
        other.credential = "other".to_owned();

        let err =
            ConnectRouteSet::from_routes(vec![route("api.github.com", 443), other], &permitting())
                .expect_err("the same endpoint twice must not load");
        assert!(
            matches!(err, ConnectRouteError::Duplicate { .. }),
            "{err:?}"
        );
    }
}
