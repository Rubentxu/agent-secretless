//! An RFC 6749 authorization server, for the broker's own OAuth2 tests.
//!
//! # Why this is a server and not a canned responder
//!
//! The OAuth2 framework could not leave `prototype` by testing itself. Its own
//! unit tests agree with it about everything, including the parts that are
//! wrong. To be anything else it has to face something that can say no for
//! reasons of its own: a wrong secret, an expired token, a revoked grant, a
//! scope the client was not entitled to, an audience it was not issued for.
//!
//! So this is a real server on a real TLS socket, and it enforces the
//! specifications rather than replaying fixtures:
//!
//! - **RFC 6749 §2.3.1** — `client_secret_basic`: the client identifier and
//!   secret are form-encoded, joined with `:`, and base64'd. The decode here is
//!   the exact inverse, and a credential that arrives raw is rejected. That
//!   asymmetry is the whole test: a client that skips the encoding does not get
//!   a token, it gets `invalid_client`.
//! - **RFC 6749 §4.4** — the `client_credentials` and `refresh_token` grants.
//! - **RFC 6749 §5.1 / §5.2** — the success and error response shapes, including
//!   `Cache-Control: no-store` and a form-encoded error body.
//! - **RFC 6749 §5.1** — *"the scope of the issued token is different from the
//!   scope requested"*. The server is allowed to widen it; the client is not.
//!   [`AuthorizationServer::override_scope`] makes it widen on purpose.
//! - **RFC 7009** — revocation, which answers 200 even for a token it never
//!   issued, and which invalidates the access tokens of the same grant.
//! - **RFC 7662** — introspection, which reports liveness without leaking the
//!   token.
//! - **RFC 8707** — resource indicators, so a token is bound to one audience and
//!   presenting it elsewhere is refused.
//!
//! # What this is not
//!
//! It is not a third-party identity provider, and no claim here depends on one
//! being reachable. What it establishes is the property the broker is
//! responsible for — that it authenticates, honours the scope it was granted,
//! refuses what it was not, and treats expiry and revocation as refusals —
//! against a party that is independent of it in the only sense that matters:
//! it does not share the broker's code and does not consult the broker's
//! opinion before saying no.
//!
//! # Reachability
//!
//! Gated on the `test-support` feature, which is off by default. A production
//! broker cannot link this, and the gate is the reason the feature exists
//! rather than a `#[cfg(test)]` that integration tests could not see.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asv_connector_http::{Observed, OriginHandler, OriginResponse, TlsOrigin};
use base64::Engine as _;
use subtle::ConstantTimeEq;

/// The base64 alphabet of RFC 4648 §4, which is what §2.3.1's `Basic` scheme
/// is defined over. Spelled out here rather than pulled from a request header
/// so the encoding is a property of this file.
const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// The name this server's certificate is issued for. Nothing resolves it; a
/// client has to be built with the address mapping, which is what
/// `PinnedClient` does and what makes reaching this server mean something.
pub const AS_HOST: &str = "idp.asv.test";

/// The audience the protected resource speaks for. A token issued for anything
/// else is not accepted here, which is what makes "wrong destination" a
/// property rather than an opinion.
pub const RESOURCE_AUDIENCE: &str = "https://api.asv.test";

/// How long a real one of these has lived. Short enough that a test can watch
/// a token expire without a `sleep` that makes the suite slow, long enough
/// that ordinary assertions are not racing the clock.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// The client this server will authenticate.
#[derive(Debug, Clone)]
pub struct AsClient {
    pub client_id: String,
    pub client_secret: String,
    /// Every scope this client is entitled to, space separated. The server
    /// will never grant something outside this set.
    pub scope: String,
    /// Every audience this client may ask a token for, space separated.
    pub audience: String,
}

impl AsClient {
    /// A client whose identifier and secret both break naive Basic credentials.
    ///
    /// The `:` in the identifier is the load-bearing part. Form-encoded it
    /// travels as `asv%3A…`, which survives the server's split-on-first-colon.
    /// Sent raw it does not: the server splits at the wrong `:` and the halves
    /// no longer match, so the credential fails to authenticate. A test with an
    /// uncomplicated identifier cannot tell a conforming client from a
    /// non-conforming one, and would pass on both.
    pub fn awkward() -> Self {
        Self {
            client_id: "asv:broker/ci".to_string(),
            client_secret: "p ss+w&rd:".to_string(),
            scope: "read:pods write:pods".to_string(),
            audience: format!("{RESOURCE_AUDIENCE} https://admin.asv.test"),
        }
    }

    /// A client with unremarkable credentials, for tests that are about
    /// something other than encoding.
    pub fn plain() -> Self {
        Self {
            client_id: "asv-broker".to_string(),
            client_secret: "correct-horse".to_string(),
            scope: "read:pods".to_string(),
            audience: RESOURCE_AUDIENCE.to_string(),
        }
    }

    fn scopes(&self) -> Vec<&str> {
        self.scope.split_whitespace().collect()
    }

    fn audiences(&self) -> Vec<&str> {
        self.audience.split_whitespace().collect()
    }
}

/// One entry in the server's own log.
///
/// Carries no token and no secret, only a fingerprint, because an audit trail
/// that has to be protected as carefully as the credential it recorded is not
/// one anybody will keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Seconds since the epoch, which is what an operator reads.
    pub at_unix: u64,
    /// Which endpoint was asked.
    pub endpoint: &'static str,
    /// The authenticated client, or `None` when authentication failed.
    pub client_id: Option<String>,
    /// The grant type, for the token endpoint.
    pub grant_type: Option<String>,
    /// The scope that was granted, or that was asked for and refused.
    pub scope: Option<String>,
    /// The audience the token was bound to, when one was asked for.
    pub audience: Option<String>,
    /// What happened, in the server's own words.
    pub outcome: &'static str,
    /// The first eight hex digits of the token's SHA-256, so entries about the
    /// same token can be correlated without the token being recoverable.
    pub token_fingerprint: Option<String>,
}

/// One grant: everything issued under one authorization.
#[derive(Debug, Clone)]
struct Grant {
    client_id: String,
    scope: String,
    audience: Option<String>,
    expires_at: Instant,
    /// Set when the whole grant is revoked. A revoked refresh token takes its
    /// access tokens with it, which is what RFC 7009 asks for.
    revoked: bool,
    /// Access tokens individually revoked under a live grant.
    revoked_access: HashSet<String>,
    /// The current refresh token, rotated on every use.
    refresh: Option<String>,
}

impl Grant {
    /// Whether `token` is a live access token of this grant right now.
    fn access_is_live(&self, token: &str, now: Instant) -> bool {
        !self.revoked && !self.revoked_access.contains(token) && now < self.expires_at
    }

    /// Whether the grant itself is still live, which an access token's answer
    /// also depends on.
    fn is_live(&self, now: Instant) -> bool {
        !self.revoked && now < self.expires_at
    }
}

/// Everything mutable, behind one lock.
///
/// One lock rather than one per map because the operations that matter read
/// across all of them — a revocation touches a grant, an index and the log —
/// and a fixture that can deadlock under a test is worse than one that is
/// slightly coarser than it needs to be.
#[derive(Default)]
struct Store {
    grants: HashMap<String, Grant>,
    access_index: HashMap<String, String>,
    refresh_index: HashMap<String, String>,
    audit: Vec<AuditEntry>,
}

struct AsState {
    client: AsClient,
    ttl: Duration,
    /// Force the granted scope, whatever was asked for. RFC 6749 §5.1 lets a
    /// server widen the scope and requires the client to notice; this is how a
    /// test makes the server take that option.
    override_scope: Mutex<Option<String>>,
    /// Refuse every token request, the way an unreachable provider does. The
    /// point is that a client must treat it as a refusal, not as a licence to
    /// continue with whatever it had.
    offline: AtomicBool,
    store: Mutex<Store>,
}

/// What a request asked for, gathered once and handed to every log line it
/// produces.
///
/// A struct rather than four more parameters: every call site was spelling the
/// same four `Some(...)` values, which is both why the function had grown to
/// eight arguments and why a call site that forgot one was invisible. Fields
/// start empty because authentication happens before the body is parsed, and
/// the log has to be writable for a request that never got that far.
#[derive(Debug, Default, Clone)]
struct RequestFacts {
    client_id: Option<String>,
    grant_type: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
}

impl AsState {
    fn record(
        &self,
        endpoint: &'static str,
        outcome: &'static str,
        facts: &RequestFacts,
        token: Option<&str>,
    ) {
        let mut store = self.store.lock().expect("poisoned");
        store.audit.push(AuditEntry {
            at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            endpoint,
            client_id: facts.client_id.clone(),
            grant_type: facts.grant_type.clone(),
            scope: facts.scope.clone(),
            audience: facts.audience.clone(),
            outcome,
            token_fingerprint: token.map(fingerprint),
        });
    }

    /// Looks a token up in either namespace, returning the grant id.
    fn grant_of(store: &Store, token: &str) -> Option<String> {
        store
            .access_index
            .get(token)
            .or_else(|| store.refresh_index.get(token))
            .cloned()
    }

    /// Issues an access token and, for a fresh grant, a refresh token.
    fn issue(
        &self,
        client_id: &str,
        scope: &str,
        audience: Option<&str>,
        with_refresh: bool,
    ) -> (String, Option<String>) {
        let access = random_token();
        let refresh = with_refresh.then(random_token);
        let mut store = self.store.lock().expect("poisoned");
        let grant_id = random_token();
        store.grants.insert(
            grant_id.clone(),
            Grant {
                client_id: client_id.to_string(),
                scope: scope.to_string(),
                audience: audience.map(str::to_string),
                expires_at: Instant::now() + self.ttl,
                revoked: false,
                revoked_access: HashSet::new(),
                refresh: refresh.clone(),
            },
        );
        store.access_index.insert(access.clone(), grant_id.clone());
        if let Some(refresh) = &refresh {
            store.refresh_index.insert(refresh.clone(), grant_id);
        }
        (access, refresh)
    }

    /// Issues an access token inside an existing grant, rotating the refresh
    /// token and retiring the previous one.
    ///
    /// The grant is taken out of the map, mutated, and put back, rather than
    /// borrowed in place. Holding a `&mut Grant` while touching the two indexes
    /// is the same map, and splitting a borrow across them is a way to write a
    /// fixture that only compiles because the indices happen to be disjoint
    /// fields today.
    fn reissue(
        &self,
        grant_id: &str,
        old_refresh: &str,
    ) -> Option<(String, String, String, Option<String>)> {
        let mut store = self.store.lock().expect("poisoned");
        let mut grant = store.grants.remove(grant_id)?;
        let live = grant.is_live(Instant::now()) && grant.refresh.as_deref() == Some(old_refresh);
        if !live {
            // Put it back untouched. A refresh that failed for any other reason
            // must not have silently consumed the grant.
            store.grants.insert(grant_id.to_string(), grant);
            return None;
        }
        let access = random_token();
        let new_refresh = random_token();
        store
            .access_index
            .insert(access.clone(), grant_id.to_string());
        store.refresh_index.remove(old_refresh);
        store
            .refresh_index
            .insert(new_refresh.clone(), grant_id.to_string());
        grant.refresh = Some(new_refresh.clone());
        let scope = grant.scope.clone();
        let audience = grant.audience.clone();
        store.grants.insert(grant_id.to_string(), grant);
        Some((access, new_refresh, scope, audience))
    }
}

/// A running authorization server. Dropping it stops the listener.
pub struct AuthorizationServer {
    origin: TlsOrigin,
    state: Arc<AsState>,
}

impl AuthorizationServer {
    /// Starts a server for `client` over a real TLS socket.
    pub fn start(client: AsClient) -> Self {
        Self::with_ttl(client, DEFAULT_TTL)
    }

    /// Starts a server whose tokens live for `ttl`.
    ///
    /// Expiry is measured against the clock, not simulated: a token issued here
    /// really does stop being live after `ttl`, and a test that sleeps past it
    /// is observing a time-based refusal rather than being told about one.
    pub fn with_ttl(client: AsClient, ttl: Duration) -> Self {
        let state = Arc::new(AsState {
            client,
            ttl,
            override_scope: Mutex::new(None),
            offline: AtomicBool::new(false),
            store: Mutex::new(Store::default()),
        });
        let handler_state = Arc::clone(&state);
        let handler: OriginHandler =
            Arc::new(move |observed: &Observed| route(&handler_state, observed));
        AuthorizationServer {
            origin: TlsOrigin::start(AS_HOST, handler),
            state,
        }
    }

    /// Makes the next and every later token request fail as an unavailable
    /// provider does.
    pub fn set_offline(&self, offline: bool) {
        self.state.offline.store(offline, Ordering::SeqCst);
    }

    /// Forces the granted scope to `scope`, whatever the client asks for.
    pub fn override_scope(&self, scope: &str) {
        *self.state.override_scope.lock().expect("poisoned") = Some(scope.to_string());
    }

    /// The URL of an endpoint on this server.
    pub fn url(&self, path: &str) -> String {
        self.origin.url(path)
    }

    /// The address a client has to be pinned to in order to reach this server.
    pub fn port(&self) -> u16 {
        self.origin.port
    }

    /// The name this server's certificate is issued for.
    pub fn host(&self) -> &str {
        &self.origin.certified_for
    }

    /// The certificate a test client has to trust to reach this server.
    pub fn certificate(&self) -> asv_connector_http::Certificate {
        self.origin.certificate()
    }

    /// Everything the server logged, oldest first.
    pub fn audit(&self) -> Vec<AuditEntry> {
        self.state.store.lock().expect("poisoned").audit.clone()
    }

    /// The log entries for one outcome, for a test that does not care about
    /// order.
    pub fn audit_with_outcome(&self, outcome: &str) -> Vec<AuditEntry> {
        self.audit()
            .into_iter()
            .filter(|entry| entry.outcome == outcome)
            .collect()
    }
}

/// Routes a request to the endpoint that owns it.
fn route(state: &AsState, observed: &Observed) -> OriginResponse {
    match observed.path() {
        "/token" => token(state, observed),
        "/revoke" => revoke(state, observed),
        "/introspect" => introspect(state, observed),
        "/resource" => resource(state, observed),
        _ => OriginResponse::json(404, r#"{"error":"not_found"}"#),
    }
}

/// The RFC 6749 §4.4 token endpoint.
fn token(state: &AsState, observed: &Observed) -> OriginResponse {
    // Gathered in one place and updated as the request is understood, so every
    // refusal below can say what was asked without each arm repeating itself.
    let mut facts = RequestFacts::default();
    if observed.method() != "POST" {
        state.record("/token", "method_not_allowed", &facts, None);
        return OriginResponse::json(405, r#"{"error":"invalid_request"}"#);
    }
    // An unreachable provider is not a provider that says yes. The answer has
    // to be a refusal the client can tell apart from success, or "provider down"
    // becomes "the broker kept working", which is the failure this fixture
    // exists to make impossible.
    if state.offline.load(Ordering::SeqCst) {
        state.record("/token", "provider_unavailable", &facts, None);
        return OriginResponse::form(
            503,
            "error=temporarily_unavailable&error_description=the+provider+is+unavailable",
        );
    }
    let client_id = match authenticate(state, observed) {
        Ok(client_id) => client_id,
        Err(refusal) => return refusal,
    };
    facts.client_id = Some(client_id.clone());
    let form = parse_form(&observed.body);
    facts.grant_type = form.get("grant_type").cloned();
    facts.scope = form.get("scope").cloned();
    facts.audience = form.get("audience").cloned();
    let grant_type = facts.grant_type.clone().unwrap_or_default();
    let requested_scope = facts.scope.clone().unwrap_or_default();
    let audience = facts.audience.clone().unwrap_or_default();

    if let Some(refused) = check_audience(state, &audience) {
        state.record("/token", "invalid_target", &facts, None);
        return refused;
    }

    // A token requested with no resource indicator is bound to this server's own
    // resource, not left unbound. "Unbound" would have to be read by every
    // resource as "valid anywhere", which is the one reading that turns a
    // missing parameter into a grant; binding it here is both the safe default
    // and what makes the parameter optional without making it meaningless.
    let bound_audience = if audience.is_empty() {
        RESOURCE_AUDIENCE.to_string()
    } else {
        audience.clone()
    };
    match grant_type.as_str() {
        "client_credentials" => {
            let granted = match granted_scope(state, &requested_scope) {
                Ok(granted) => granted,
                Err(refused) => {
                    state.record("/token", "invalid_scope", &facts, None);
                    return refused;
                }
            };
            let (access, refresh) =
                state.issue(&client_id, &granted, Some(bound_audience.as_str()), true);
            // What the log records is the scope that was *granted*, not the one
            // that was asked for. A widening is the case where those differ, and
            // it is precisely the one an operator reading this later needs to
            // see.
            facts.scope = Some(granted.clone());
            facts.audience = Some(bound_audience.clone());
            state.record("/token", "issued", &facts, Some(&access));
            let mut body = String::new();
            let _ = write!(
                body,
                r#"{{"access_token":"{access}","token_type":"Bearer","expires_in":{},"scope":"{granted}","aud":"{bound_audience}""#,
                state.ttl.as_secs()
            );
            if let Some(refresh) = &refresh {
                let _ = write!(body, r#","refresh_token":"{refresh}""#);
            }
            body.push('}');
            // §5.1: a token response must not be cached. Stated here rather
            // than assumed so a client that ignores the header still has to
            // cope, and so a test can assert the header is really there.
            OriginResponse::json(200, body).with_header("cache-control", "no-store")
        }
        "refresh_token" => {
            let Some(refresh) = form.get("refresh_token") else {
                return error(400, "invalid_request", "refresh_token+is+required");
            };
            let store = state.store.lock().expect("poisoned");
            let Some(grant_id) = AsState::grant_of(&store, refresh) else {
                drop(store);
                state.record("/token", "invalid_grant", &facts, Some(refresh));
                return error(400, "invalid_grant", "the+refresh+token+is+not+valid");
            };
            drop(store);
            match state.reissue(&grant_id, refresh) {
                Some((access, new_refresh, scope, granted_audience)) => {
                    let bound = granted_audience.clone().unwrap_or_default();
                    facts.scope = Some(scope.clone());
                    facts.audience = Some(bound.clone());
                    state.record("/token", "reissued", &facts, Some(&access));
                    let mut body = String::new();
                    let _ = write!(
                        body,
                        r#"{{"access_token":"{access}","token_type":"Bearer","expires_in":{},"scope":"{scope}""#,
                        state.ttl.as_secs()
                    );
                    if !bound.is_empty() {
                        let _ = write!(body, r#","aud":"{bound}""#);
                    }
                    let _ = write!(body, r#","refresh_token":"{new_refresh}""#);
                    body.push('}');
                    OriginResponse::json(200, body).with_header("cache-control", "no-store")
                }
                None => {
                    state.record("/token", "invalid_grant", &facts, Some(refresh));
                    error(400, "invalid_grant", "the+refresh+token+is+no+longer+valid")
                }
            }
        }
        other => {
            facts.grant_type = Some(other.to_string());
            state.record("/token", "unsupported_grant_type", &facts, None);
            error(
                400,
                "unsupported_grant_type",
                "this+grant+type+is+not+supported",
            )
        }
    }
}

/// The RFC 7009 revocation endpoint.
fn revoke(state: &AsState, observed: &Observed) -> OriginResponse {
    let client_id = match authenticate(state, observed) {
        Ok(client_id) => client_id,
        Err(refusal) => return refusal,
    };
    let facts = RequestFacts {
        client_id: Some(client_id),
        ..RequestFacts::default()
    };
    let form = parse_form(&observed.body);
    let Some(token) = form.get("token") else {
        return error(400, "invalid_request", "token+is+required");
    };
    let mut store = state.store.lock().expect("poisoned");
    let found = AsState::grant_of(&store, token);
    match found {
        Some(grant_id) => {
            // §2.1: revoking a refresh token invalidates the access tokens
            // issued from the same authorization grant. A server that revokes
            // only the token named would leave the access token working, which
            // is the whole reason the rule exists.
            //
            // The grant is taken out and put back rather than borrowed in
            // place: the answer depends on both the grant and the access index,
            // and they are fields of the same map.
            let is_access = store.access_index.contains_key(token);
            let siblings: Vec<String> = store
                .access_index
                .iter()
                .filter(|(_, id)| *id == &grant_id)
                .map(|(access, _)| access.clone())
                .collect();
            if let Some(mut grant) = store.grants.remove(&grant_id) {
                if let Some(refresh) = grant.refresh.take() {
                    store.refresh_index.remove(&refresh);
                }
                if is_access {
                    grant.revoked_access.insert(token.to_string());
                } else {
                    grant.revoked = true;
                    grant.revoked_access.extend(siblings);
                }
                store.grants.insert(grant_id, grant);
            }
            store.refresh_index.remove(token);
        }
        None => {
            // §2.2: 200 even for a token the server never issued. Saying "I do
            // not know that token" turns the endpoint into an oracle.
            drop(store);
            state.record("/revoke", "unknown_token", &facts, Some(token));
            return OriginResponse::json(200, "{}");
        }
    }
    drop(store);
    state.record("/revoke", "revoked", &facts, Some(token));
    OriginResponse::json(200, "{}")
}

/// The RFC 7662 introspection endpoint.
fn introspect(state: &AsState, observed: &Observed) -> OriginResponse {
    let client_id = match authenticate(state, observed) {
        Ok(client_id) => client_id,
        Err(refusal) => return refusal,
    };
    let form = parse_form(&observed.body);
    let Some(token) = form.get("token") else {
        return error(400, "invalid_request", "token+is+required");
    };
    let store = state.store.lock().expect("poisoned");
    let now = Instant::now();
    let answer = match AsState::grant_of(&store, token)
        .and_then(|id| store.grants.get(&id))
        .filter(|grant| grant.client_id == client_id)
    {
        Some(grant) if grant.access_is_live(token, now) => {
            let remaining = grant.expires_at.saturating_duration_since(now);
            let mut body = format!(
                r#"{{"active":true,"client_id":"{}","scope":"{}","exp":{}"#,
                grant.client_id,
                grant.scope,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default()
                    + remaining.as_secs()
            );
            if let Some(audience) = &grant.audience {
                let _ = write!(body, r#","aud":"{audience}""#);
            }
            body.push('}');
            body
        }
        _ => r#"{"active":false}"#.to_string(),
    };
    let active = answer.contains(r#""active":true"#);
    drop(store);
    let facts = RequestFacts {
        client_id: Some(client_id),
        ..RequestFacts::default()
    };
    state.record(
        "/introspect",
        if active {
            "introspected_active"
        } else {
            "introspected_inactive"
        },
        &facts,
        Some(token),
    );
    OriginResponse::json(200, answer)
}

/// The protected resource. A token is accepted only if it is live *and* was
/// issued for this audience.
fn resource(state: &AsState, observed: &Observed) -> OriginResponse {
    let Some(presented) = bearer_token(observed) else {
        return bearer_error("invalid_request", "a+bearer+token+is+required");
    };
    let store = state.store.lock().expect("poisoned");
    let now = Instant::now();
    let verdict = AsState::grant_of(&store, &presented).and_then(|id| {
        store
            .grants
            .get(&id)
            .filter(|grant| grant.access_is_live(&presented, now))
            .map(|grant| (grant.scope.clone(), grant.audience.clone()))
    });
    let Some((scope, audience)) = verdict else {
        drop(store);
        state.record(
            "/resource",
            "inactive_token",
            &RequestFacts::default(),
            Some(&presented),
        );
        return bearer_error("invalid_token", "the+token+is+not+active");
    };
    // A live token aimed at a different resource is still the wrong token here.
    // RFC 8707 binds a token to its audience, and a server that ignores the
    // binding has not implemented the binding.
    if audience.as_deref() != Some(RESOURCE_AUDIENCE) {
        drop(store);
        state.record(
            "/resource",
            "wrong_audience",
            &RequestFacts {
                scope: Some(scope),
                audience,
                ..RequestFacts::default()
            },
            Some(&presented),
        );
        return bearer_error(
            "invalid_token",
            "the+token+was+not+issued+for+this+resource",
        );
    }
    drop(store);
    state.record(
        "/resource",
        "served",
        &RequestFacts {
            scope: Some(scope.clone()),
            audience: Some(RESOURCE_AUDIENCE.to_string()),
            ..RequestFacts::default()
        },
        Some(&presented),
    );
    OriginResponse::json(
        200,
        format!(r#"{{"resource":"pods","scope":"{scope}","audience":"{RESOURCE_AUDIENCE}"}}"#),
    )
}

/// Authenticates a confidential client, or returns the refusal to send.
///
/// The decode is the exact inverse of RFC 6749 §2.3.1: base64, split at the
/// first `:`, then form-decode each half. Splitting *before* decoding is the
/// point — a decoded colon would let a client identifier smuggle a separator
/// and shift the halves.
fn authenticate(state: &AsState, observed: &Observed) -> Result<String, OriginResponse> {
    let invalid = || {
        OriginResponse::form(
            401,
            "error=invalid_client&error_description=client+authentication+failed",
        )
        // §5.2: when the client tried to authenticate with the Authorization
        // header, the server must say so with a 401 and name the schemes it
        // supports. A 400 here would tell a conforming client its scheme is
        // wrong when it is not.
        .with_header("www-authenticate", "Basic realm=\"asv-test-idp\"")
    };
    let Some(header) = observed.header("authorization") else {
        state.record("/auth", "no_credentials", &RequestFacts::default(), None);
        return Err(invalid());
    };
    let Some(encoded) = header
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map(|(_, rest)| rest.trim())
    else {
        state.record("/auth", "not_basic", &RequestFacts::default(), None);
        return Err(invalid());
    };
    // Both failures collapse to one refusal. Distinguishing "not base64" from
    // "not UTF-8" in the answer would tell an attacker which half of a guess
    // was closer, and the client has no use for the difference.
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let Some(decoded) = decoded else {
        state.record("/auth", "bad_base64", &RequestFacts::default(), None);
        return Err(invalid());
    };
    let Some((raw_id, raw_secret)) = decoded.split_once(':') else {
        state.record("/auth", "no_separator", &RequestFacts::default(), None);
        return Err(invalid());
    };
    let (client_id, secret) = (form_decode(raw_id), form_decode(raw_secret));
    let expected = &state.client;
    // Both comparisons, always. A short-circuiting `&&` would let the timing
    // say whether the identifier was right before looking at the secret, and a
    // fixture is the wrong place to teach that shape.
    let id_ok = constant_eq(client_id.as_bytes(), expected.client_id.as_bytes());
    let secret_ok = constant_eq(secret.as_bytes(), expected.client_secret.as_bytes());
    if !(id_ok & secret_ok) {
        state.record("/auth", "bad_credentials", &RequestFacts::default(), None);
        return Err(invalid());
    }
    state.record(
        "/auth",
        "authenticated",
        &RequestFacts {
            client_id: Some(expected.client_id.clone()),
            ..RequestFacts::default()
        },
        None,
    );
    Ok(expected.client_id.clone())
}

/// The scope this client gets, or the refusal to send.
///
/// Three outcomes, and the middle one is the interesting one: RFC 6749 lets the
/// server grant *less* than was asked, so a narrowing is a normal answer and
/// not an error. Only asking for something outside the entitlement is
/// `invalid_scope`.
fn granted_scope(state: &AsState, requested: &str) -> Result<String, OriginResponse> {
    if let Some(forced) = state.override_scope.lock().expect("poisoned").clone() {
        return Ok(forced);
    }
    let entitled = state.client.scopes();
    if requested.is_empty() {
        return Ok(state.client.scope.clone());
    }
    let mut granted = Vec::new();
    for asked in requested.split_whitespace() {
        if !entitled.contains(&asked) {
            return Err(error(
                400,
                "invalid_scope",
                "the+requested+scope+exceeds+what+this+client+may+be+granted",
            ));
        }
        granted.push(asked);
    }
    Ok(granted.join(" "))
}

/// RFC 8707: an audience the client was not entitled to is `invalid_target`.
fn check_audience(state: &AsState, audience: &str) -> Option<OriginResponse> {
    if audience.is_empty() {
        return None;
    }
    if state.client.audiences().contains(&audience) {
        return None;
    }
    Some(error(
        400,
        "invalid_target",
        "the+requested+audience+is+not+available+to+this+client",
    ))
}

/// An RFC 6749 §5.2 error: a 400 with a form body, and no store directive.
fn error(status: u16, code: &str, description: &str) -> OriginResponse {
    OriginResponse::form(
        status,
        format!("error={code}&error_description={description}"),
    )
}

/// A `WWW-Authenticate: Bearer` refusal, per RFC 6750 §3.
fn bearer_error(code: &str, description: &str) -> OriginResponse {
    OriginResponse::json(
        401,
        format!(r#"{{"error":"{code}","error_description":"{description}"}}"#),
    )
    .with_header(
        "www-authenticate",
        &format!("Bearer error=\"{code}\", error_description=\"{description}\""),
    )
}

/// The token in an `Authorization: Bearer …` header.
fn bearer_token(observed: &Observed) -> Option<String> {
    observed
        .header("authorization")?
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_string())
}

/// Parses an `application/x-www-form-urlencoded` body.
///
/// Repeated keys take the last value, which is what every other implementation
/// of this encoding does; a server that took the first would disagree with the
/// client about a body containing a duplicate, and the disagreement would show
/// up as a fixture bug rather than as a protocol bug.
fn parse_form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// `application/x-www-form-urlencoded` decoding for a single component.
///
/// Not `parse_form`: that one splits a body, and here the input is one already
/// isolated half of a Basic credential.
fn form_decode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for (key, value) in url::form_urlencoded::parse(format!("k={raw}").as_bytes()) {
        if key == "k" {
            out = value.into_owned();
        }
    }
    out
}

/// The first eight hex digits of a token's SHA-256.
fn fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A 256-bit token, hex encoded.
///
/// 32 bytes of OS entropy per token. A fixture whose tokens were derived from
/// the client secret would make "the token is not the secret" true by accident
/// rather than by construction, and that is the one thing the tests downstream
/// most need to be real.
fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Length-independent equality, so a wrong secret of a different length is not
/// distinguishable by how long the comparison took.
fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        // Still burn a comparison, so the length check is not the only thing
        // that varies with the input.
        let _ = right.ct_eq(right);
        return false;
    }
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A direct client for the server, bypassing the broker's issuer entirely.
    ///
    /// These tests are about whether the *server* is a real authorization
    /// server. If they went through the broker they would pass on a client and
    /// a server that were wrong in the same way, which is the failure mode a
    /// fixture is supposed to rule out.
    fn client_for(server: &AuthorizationServer) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(server.certificate())
            .resolve(
                server.host(),
                format!("127.0.0.1:{}", server.port())
                    .parse()
                    .expect("addr"),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client")
    }

    /// The credential a conforming client sends, built the way §2.3.1 says.
    fn basic(client: &AsClient) -> String {
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                encode(&client.client_id),
                encode(&client.client_secret)
            ))
        )
    }

    fn form_request(
        server: &AuthorizationServer,
        path: &str,
        body: String,
    ) -> reqwest::blocking::RequestBuilder {
        client_for(server)
            .post(server.url(path))
            .header("authorization", basic(&server.state.client))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
    }

    /// The encoding is pinned against literals, not against the crate.
    ///
    /// If both the client and the server used one implementation and it drifted,
    /// every other test here would keep passing. These are the escapes written
    /// out by hand from RFC 6749 §2.3.1's reference to the Appendix B algorithm.
    #[test]
    fn the_form_encoding_is_the_one_the_rfc_names() {
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        assert_eq!(encode("asv:broker/ci"), "asv%3Abroker%2Fci");
        assert_eq!(encode("p ss+w&rd:"), "p+ss%2Bw%26rd%3A");
        assert_eq!(encode("plain"), "plain");
        // And the inverse, which is what the server does with each half.
        assert_eq!(form_decode("asv%3Abroker%2Fci"), "asv:broker/ci");
        assert_eq!(form_decode("p+ss%2Bw%26rd%3A"), "p ss+w&rd:");
        assert_eq!(form_decode("plain"), "plain");
    }

    /// The credentials that matter are the ones that break a naive client.
    #[test]
    fn the_default_client_breaks_a_naive_basic_credential() {
        let client = AsClient::awkward();
        let naive = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", client.client_id, client.client_secret))
        );
        // Raw, the split lands inside the identifier.
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(naive.split_once(' ').expect("scheme").1)
                .expect("base64"),
        )
        .expect("utf8");
        let (id, secret) = decoded.split_once(':').expect("separator");
        assert_ne!(
            id, client.client_id,
            "a raw identifier must not survive the split"
        );
        assert_ne!(secret, client.client_secret);

        // Conforming, it does.
        let conforming = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(basic(&client).split_once(' ').expect("scheme").1)
                .expect("base64"),
        )
        .expect("utf8");
        let (id, secret) = conforming.split_once(':').expect("separator");
        assert_eq!(form_decode(id), client.client_id);
        assert_eq!(form_decode(secret), client.client_secret);
    }

    /// A wrong secret is refused with the status and headers §5.2 requires.
    #[test]
    fn a_wrong_secret_is_invalid_client_with_a_401() {
        let server = AuthorizationServer::start(AsClient::awkward());
        let bad = AsClient {
            client_secret: "p ss+w&rdX".to_string(),
            ..AsClient::awkward()
        };
        let response = client_for(&server)
            .post(server.url("/token"))
            .header("authorization", basic(&bad))
            .body("grant_type=client_credentials")
            .send()
            .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 401);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Basic realm=\"asv-test-idp\"")
        );
        let body = response.text().expect("body");
        assert!(body.contains("error=invalid_client"), "{body}");
        assert!(server.audit_with_outcome("bad_credentials").len() == 1);
    }

    /// A missing secret is refused, and a non-Basic scheme is refused.
    #[test]
    fn no_credentials_and_a_foreign_scheme_are_both_refused() {
        let server = AuthorizationServer::start(AsClient::plain());
        for header in [None, Some("Bearer abc123")] {
            let mut request = client_for(&server)
                .post(server.url("/token"))
                .body("grant_type=client_credentials");
            if let Some(header) = header {
                request = request.header("authorization", header);
            }
            let response = request.send().expect("TLS completes");
            assert_eq!(response.status().as_u16(), 401, "{header:?}");
            assert!(response
                .text()
                .expect("body")
                .contains("error=invalid_client"));
        }
        assert_eq!(server.audit_with_outcome("no_credentials").len(), 1);
        assert_eq!(server.audit_with_outcome("not_basic").len(), 1);
    }

    /// A conforming request gets a real, opaque, expiring token.
    #[test]
    fn a_conforming_request_gets_an_opaque_expiring_token() {
        let server = AuthorizationServer::start(AsClient::plain());
        let response = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&scope=read%3Apods".to_string(),
        )
        .send()
        .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "§5.1: a token response must not be cached"
        );
        let body: serde_json::Value = response.json().expect("json");
        let access = body["access_token"].as_str().expect("access_token");
        assert_eq!(access.len(), 64, "256 bits, hex encoded");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 300);
        assert_eq!(body["scope"], "read:pods");
        assert!(body["refresh_token"].as_str().is_some());
        // Opaque means unrelated to the secret: the same client asking twice
        // gets different tokens, and neither contains the secret.
        let again: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("second request")
        .json()
        .expect("json");
        assert_ne!(again["access_token"].as_str().expect("token"), access);
        assert!(!access.contains("correct-horse"));
    }

    /// Asking for more than the client is entitled to is `invalid_scope`;
    /// asking for less is granted, because RFC 6749 says it may be.
    #[test]
    fn scope_entitlement_is_enforced_and_narrowing_is_allowed() {
        let server = AuthorizationServer::start(AsClient::plain());

        let refused = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&scope=write%3Apods".to_string(),
        )
        .send()
        .expect("TLS completes");
        assert_eq!(refused.status().as_u16(), 400);
        assert!(refused
            .text()
            .expect("body")
            .contains("error=invalid_scope"));

        let narrowed = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&scope=".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json::<serde_json::Value>()
        .expect("json");
        assert_eq!(
            narrowed["scope"], "read:pods",
            "an empty request gets the entitlement"
        );
    }

    /// §5.1 lets the server widen. The fixture takes the option on purpose, so
    /// a client that does not notice can be caught.
    #[test]
    fn the_server_can_widen_the_scope_on_purpose() {
        let server = AuthorizationServer::start(AsClient::plain());
        server.override_scope("read:pods write:pods admin:everything");
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&scope=read%3Apods".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        assert_eq!(body["scope"], "read:pods write:pods admin:everything");
    }

    /// RFC 8707: a token is bound to its audience, and one issued elsewhere is
    /// refused by this resource.
    #[test]
    fn a_token_is_bound_to_the_audience_it_was_issued_for() {
        let server = AuthorizationServer::start(AsClient::awkward());
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&audience=https%3A%2F%2Fadmin.asv.test".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let elsewhere = body["access_token"].as_str().expect("token");
        assert_eq!(body["aud"], "https://admin.asv.test");

        let refused = client_for(&server)
            .get(server.url("/resource"))
            .header("authorization", format!("Bearer {elsewhere}"))
            .send()
            .expect("TLS completes");
        assert_eq!(refused.status().as_u16(), 401);
        assert!(server.audit_with_outcome("wrong_audience").len() == 1);
    }

    /// An audience the client was not entitled to is `invalid_target`.
    #[test]
    fn an_unentitled_audience_is_invalid_target() {
        let server = AuthorizationServer::start(AsClient::plain());
        let response = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&audience=https%3A%2F%2Felsewhere.test".to_string(),
        )
        .send()
        .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 400);
        assert!(response
            .text()
            .expect("body")
            .contains("error=invalid_target"));
    }

    /// A live token with the right audience is served, and the server says
    /// which scope it carried.
    #[test]
    fn a_live_token_for_this_audience_is_served() {
        let server = AuthorizationServer::start(AsClient::plain());
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&audience=".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        // No audience asked for: the fixture binds the token to its own
        // resource, so the happy path is reachable without the parameter.
        let served = client_for(&server)
            .get(server.url("/resource"))
            .header(
                "authorization",
                format!("Bearer {}", body["access_token"].as_str().expect("token")),
            )
            .send()
            .expect("TLS completes");
        assert_eq!(served.status().as_u16(), 200);
        assert_eq!(
            served.json::<serde_json::Value>().expect("json")["scope"],
            "read:pods"
        );
    }

    /// Expiry is real time, not a flag.
    #[test]
    fn a_token_stops_being_live_when_its_time_is_up() {
        let server = AuthorizationServer::with_ttl(AsClient::plain(), Duration::from_millis(150));
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let token = body["access_token"].as_str().expect("token").to_string();
        assert_eq!(
            body["expires_in"], 0,
            "a sub-second TTL reports zero whole seconds"
        );

        let during = client_for(&server)
            .get(server.url("/resource"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .expect("TLS completes");
        assert_eq!(during.status().as_u16(), 200);

        std::thread::sleep(Duration::from_millis(250));
        let after = client_for(&server)
            .get(server.url("/resource"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .expect("TLS completes");
        assert_eq!(
            after.status().as_u16(),
            401,
            "an expired token is a refusal"
        );
        assert!(server.audit_with_outcome("inactive_token").len() == 1);
    }

    /// RFC 7009 revocation, including the part that matters: revoking the
    /// refresh token takes the access tokens of the same grant with it.
    #[test]
    fn revoking_the_refresh_token_kills_the_access_token_too() {
        let server = AuthorizationServer::start(AsClient::plain());
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let access = body["access_token"].as_str().expect("token").to_string();
        let refresh = body["refresh_token"].as_str().expect("refresh").to_string();

        let revoked = form_request(&server, "/revoke", format!("token={refresh}"))
            .send()
            .expect("TLS completes");
        assert_eq!(revoked.status().as_u16(), 200);

        let served = client_for(&server)
            .get(server.url("/resource"))
            .header("authorization", format!("Bearer {access}"))
            .send()
            .expect("TLS completes");
        assert_eq!(
            served.status().as_u16(),
            401,
            "an access token from a revoked grant must not keep working"
        );
    }

    /// §2.2: 200 for a token the server never issued, so the endpoint is not an
    /// oracle.
    #[test]
    fn revoking_an_unknown_token_still_answers_200() {
        let server = AuthorizationServer::start(AsClient::plain());
        let response = form_request(&server, "/revoke", "token=never-existed".to_string())
            .send()
            .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(server.audit_with_outcome("unknown_token").len(), 1);
    }

    /// RFC 7662: liveness without leaking the token, and only for the client
    /// that owns the grant.
    #[test]
    fn introspection_reports_liveness_without_leaking_the_token() {
        let server = AuthorizationServer::start(AsClient::plain());
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let access = body["access_token"].as_str().expect("token").to_string();

        let answer: serde_json::Value =
            form_request(&server, "/introspect", format!("token={access}"))
                .send()
                .expect("TLS completes")
                .json()
                .expect("json");
        assert_eq!(answer["active"], true);
        assert_eq!(answer["client_id"], "asv-broker");
        assert_eq!(answer["scope"], "read:pods");
        let rendered = format!("{answer:?}");
        assert!(
            !rendered.contains(&access),
            "introspection must not echo the token"
        );

        let unknown: serde_json::Value =
            form_request(&server, "/introspect", "token=not-a-real-token".to_string())
                .send()
                .expect("TLS completes")
                .json()
                .expect("json");
        assert_eq!(unknown["active"], false);
    }

    /// Refresh issues a new access token and rotates the refresh token, so the
    /// old one is spent.
    #[test]
    fn refresh_issues_a_new_access_token_and_spends_the_old_refresh_token() {
        let server = AuthorizationServer::start(AsClient::plain());
        let first: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let first_access = first["access_token"].as_str().expect("token").to_string();
        let first_refresh = first["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_string();

        let second: serde_json::Value = form_request(
            &server,
            "/token",
            format!("grant_type=refresh_token&refresh_token={first_refresh}"),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let second_access = second["access_token"].as_str().expect("token").to_string();
        let second_refresh = second["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_string();
        assert_ne!(second_access, first_access);
        assert_ne!(second_refresh, first_refresh);

        let replayed = form_request(
            &server,
            "/token",
            format!("grant_type=refresh_token&refresh_token={first_refresh}"),
        )
        .send()
        .expect("TLS completes");
        assert_eq!(replayed.status().as_u16(), 400);
        assert!(replayed
            .text()
            .expect("body")
            .contains("error=invalid_grant"));
    }

    /// An unsupported grant type is refused by name.
    #[test]
    fn an_unsupported_grant_type_is_refused_by_name() {
        let server = AuthorizationServer::start(AsClient::plain());
        let response = form_request(&server, "/token", "grant_type=password".to_string())
            .send()
            .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 400);
        assert!(response
            .text()
            .expect("body")
            .contains("error=unsupported_grant_type"));
    }

    /// A provider that is down answers as one, and the answer is a refusal
    /// rather than an empty success.
    #[test]
    fn a_provider_that_is_down_answers_503_and_issues_nothing() {
        let server = AuthorizationServer::start(AsClient::plain());
        server.set_offline(true);
        let response = form_request(
            &server,
            "/token",
            "grant_type=client_credentials".to_string(),
        )
        .send()
        .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 503);
        assert!(response
            .text()
            .expect("body")
            .contains("error=temporarily_unavailable"));
        assert!(server.audit_with_outcome("provider_unavailable").len() == 1);
    }

    /// The log records what happened and nothing that would leak if it leaked.
    #[test]
    fn the_audit_log_records_the_request_and_never_the_credential() {
        let server = AuthorizationServer::start(AsClient::awkward());
        let body: serde_json::Value = form_request(
            &server,
            "/token",
            "grant_type=client_credentials&scope=read%3Apods".to_string(),
        )
        .send()
        .expect("TLS completes")
        .json()
        .expect("json");
        let access = body["access_token"].as_str().expect("token").to_string();
        client_for(&server)
            .get(server.url("/resource"))
            .header("authorization", format!("Bearer {access}"))
            .send()
            .expect("TLS completes");

        let audit = server.audit();
        let issued = audit
            .iter()
            .find(|entry| entry.outcome == "issued")
            .expect("the issuance is logged");
        assert_eq!(issued.client_id.as_deref(), Some("asv:broker/ci"));
        assert_eq!(issued.scope.as_deref(), Some("read:pods"));
        assert!(issued.at_unix > 0, "an audit entry has to say when");
        assert_eq!(issued.token_fingerprint.as_ref().map(String::len), Some(8));

        let rendered = format!("{audit:?}");
        assert!(
            !rendered.contains(&access),
            "the log must not carry the token"
        );
        assert!(
            !rendered.contains("p ss+w&rd:"),
            "the log must not carry the secret"
        );
        assert!(server
            .audit_with_outcome("served")
            .iter()
            .any(|entry| entry.token_fingerprint == issued.token_fingerprint));
    }

    /// `test-support` must stay off by default, and that has to be a fact
    /// rather than a habit.
    ///
    /// The compiler already enforces the stronger half — this module names
    /// `TlsOrigin`, which `asv-connector-http` only exports under
    /// `test-support`, so a wrongly-gated build would not compile at all. What
    /// the compiler cannot say is whether someone later writes
    /// `default = ["test-support"]`, at which point every binary in the
    /// workspace would ship a server that hands out tokens. That is a one-line
    /// edit, so it gets a test.
    #[test]
    fn the_fixture_feature_is_not_in_the_default_set() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("the broker's own manifest");
        let features = text
            .split("[features]")
            .nth(1)
            .expect("the manifest declares a [features] table")
            .split("\n[")
            .next()
            .expect("the features table is bounded by the next section");
        for line in features.lines() {
            let line = line.trim();
            if let Some(default) = line.strip_prefix("default") {
                assert!(
                    !default.contains("test-support"),
                    "`default` must not enable the authorization server: {line}"
                );
            }
        }
    }

    /// Every endpoint authenticates. An unauthenticated introspection or
    /// revocation would let anyone ask whether a token is live.
    #[test]
    fn revocation_and_introspection_require_authentication() {
        let server = AuthorizationServer::start(AsClient::plain());
        for path in ["/revoke", "/introspect"] {
            let response = client_for(&server)
                .post(server.url(path))
                .body("token=x")
                .send()
                .expect("TLS completes");
            assert_eq!(response.status().as_u16(), 401, "{path}");
        }
    }
}
