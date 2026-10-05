//! One registered OAuth2 client, and the call that asks a protected resource
//! which identity it acts as — R2.B.2.
//!
//! # Why this module exists at all
//!
//! `oauth2_port.rs` trades a stored client secret for a short-lived access
//! token, and `oauth2.rs` speaks the protocol to a real provider. Both were
//! complete while **nothing in the product could reach either of them**: the
//! daemon mounted the port and no request could name it, so the whole of M11's
//! second provider was a library vertical. That diagnosis is recorded in the
//! roadmap; this file is the other half of the answer.
//!
//! # The shape of the claim
//!
//! ```text
//! agent ──OAuth2Identity{credential}──▶ broker
//!                                        │  1. resolve the reference against
//!                                        │     the registrations it was given
//!                                        │  2. policy: oauth2.identity on that
//!                                        │     one client
//!                                        │  3. borrow a token from the port
//!                                        │     (the secret stops here)
//!                                        │  4. GET the deployment's resource
//!                                        │     with that token
//!                                        │  5. **compare** the answer
//!                                        ▼
//!                          {resource, scope, audience}
//! ```
//!
//! Step 5 is the part that is not obvious, and the reason the response type
//! gets to carry `scope` at all.
//!
//! # Step 5, and what it is defending
//!
//! A resource server reports the scope the IdP actually granted. It will do so
//! honestly, including when the grant is **wider** than the operator declared —
//! because the IdP's own configuration drifted, or the client is registered for
//! more than this deployment thinks, or the provider changed what it issues.
//!
//! Relaying that verbatim would be a subtle and serious failure. The operator
//! reads `--oauth2-clients`, believes the scope is `pods:read`, and has written
//! a policy on that understanding. The agent asks what identity it has, is told
//! `pods:read pods:delete pods:exec`, and the operator's configuration no longer
//! describes the authority that is actually in play. That is the escalation M11
//! exists to prevent — reached through the *provider* rather than through a
//! request, which is why guarding the request's fields is not sufficient.
//!
//! So the deployment declares the scope and the audience it expects, and a
//! disagreement is a refusal. The answer the agent receives is therefore a
//! *verified* claim about the deployment, not a transcript of the provider — and
//! [`VerifiedIdentity`] is a type rather than a `struct` precisely so that a
//! caller cannot obtain one without going through the comparison.
//!
//! # Why the resource URL is here and not in the request
//!
//! Because it is where the token goes, and a token presented to an
//! attacker-chosen host is a token handed over. It is operator configuration,
//! validated at load, and [`OAuth2Deployment::resource`] has no argument a
//! request could supply. The same reasoning [`crate::aws_binding`] gives for the
//! AWS audience, arriving at the same conclusion from the opposite direction:
//! there the destination was a signed host, here it is a bearer header.

use std::sync::Arc;

use asv_connector_http::transport::{AddressPolicy, PinnedClient, TransportError};
use asv_connector_http::{resolve_and_pin, SecretPort};
use asv_domain::{Authority, CredentialId, SecretBytes};

/// How long one identity query may take before the broker answers.
///
/// Not a tuning knob. `PinnedClient::build_timed` exists precisely because "a
/// client with no timeout is not fast, it is *unbounded*", and this operation
/// has to answer a question a policy gate is waiting on: a resource server that
/// accepts the connection and then says nothing would otherwise hold the calling
/// thread until something else killed it, which an agent cannot distinguish from
/// a provider that is merely slow. A bounded answer is refusable; an unbounded
/// one is not.
pub const IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What one registered client is, as the operator declared it.
///
/// **Every field is non-secret.** `client_id` is public by definition (RFC 6749
/// §2.3.1), and the endpoints and the scope are things an operator types into a
/// configuration file. The client secret is the only secret involved and it is
/// not here: it stays in the vault under [`Self::credential`] and is spent
/// inside the port on one token request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2Deployment {
    /// The vault credential holding the client secret, as the vault's own
    /// `CredentialId` — **not a human label**.
    ///
    /// Keyed by `CredentialId` for the reason `AwsDeployment::credential`
    /// documents: the first version of that field was a label like
    /// `aws-prod`, and the request arrived carrying the wire id the CLI tells
    /// the user to copy, so every call was refused against a name no caller
    /// could ever send. The two spellings have to be the same spelling.
    pub credential: CredentialId,
    /// The authorization server's token endpoint. HTTPS, checked at load.
    ///
    /// **This is the host the client secret is POSTed to**, which makes it the
    /// most security-relevant string in the file, and it is *not* gated by
    /// `ALLOWED_AUDIENCES` — that list is about API audiences, and it would be
    /// the wrong control here even if it applied. See
    /// [`crate::oauth2_port::load_clients`] for what is checked.
    pub token_endpoint: Authority,
    /// The protected resource this client is brokered against: where the
    /// derived token is presented, and which host `resolve_and_pin` vets.
    pub resource: Authority,
    /// The port the resource is reached on. Explicit rather than implied so a
    /// deployment cannot be talked into a different port by a default.
    pub resource_port: u16,
    /// The RFC 8707 resource indicator the token is requested for.
    ///
    /// **Not** an [`Authority`] and deliberately so: RFC 8707 indicators are
    /// URIs (`https://api.asv.test`), with a scheme and often a path, and
    /// `Authority` is a type whose entire value is that it means exactly one
    /// thing — a canonical host. The audience is operator text that is compared
    /// against what the resource reports, and a comparison does not need a type
    /// that forbids construction.
    pub audience: String,
    /// The scope the operator expects the provider to grant.
    ///
    /// This is the field that makes step 5 above possible. Without it the broker
    /// could only relay, and "the provider granted more than we configured"
    /// would be undetectable.
    pub expected_scope: String,
}

impl OAuth2Deployment {
    /// Whether this deployment is the one a request's credential names.
    pub fn serves(&self, credential: &CredentialId) -> bool {
        &self.credential == credential
    }
}

/// A deployment, its pinned client, and the port that derives tokens for it.
pub struct OAuth2Binding {
    pub deployment: OAuth2Deployment,
    /// `client_id` lives on the binding rather than on the deployment because it
    /// is a *public* identifier that pairs with the secret in the vault, and
    /// the deployment is the thing a policy reasons about. Keeping the public
    /// half out of the policy-facing struct means `Debug` on a deployment can
    /// never print something an operator would rather not have in a log line.
    pub client_id: String,
    client: Arc<PinnedClient>,
    /// The vetted address list, kept because `PinnedClient::url` takes it.
    ///
    /// Stored rather than re-resolved per call on purpose: this struct exists to
    /// make the second DNS answer impossible, and a `resolve_and_pin` inside
    /// `identity` would be exactly that second lookup.
    resolved: asv_connector_http::ResolvedAudience,
    port: Arc<dyn SecretPort>,
    /// The address policy this binding was built under.
    ///
    /// Kept rather than dropped so the decision is *reportable*: `Debug` prints
    /// it, so a `allow_loopback: true` in a log line is visible rather than
    /// inferred from the absence of a fault. A field nobody reads is not a
    /// record of anything, and a loopback-permitting binding in a production
    /// log should be the kind of thing someone can grep for.
    policy: AddressPolicy,
}

impl std::fmt::Debug for OAuth2Binding {
    /// The deployment, the client id, and whether loopback was permitted. The
    /// port holds cached access tokens, so a derived `Debug` on a type that
    /// reaches them is a leak one `{:?}` away — the same reason `AwsBinding`
    /// writes its own.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Binding")
            .field("deployment", &self.deployment)
            .field("client_id", &self.client_id)
            .field("allow_loopback", &self.policy.allow_loopback)
            .finish_non_exhaustive()
    }
}

impl OAuth2Binding {
    /// Wires a deployment to a pinned HTTP client and a port over the vault.
    ///
    /// `port` is the *routing* port the daemon already built, so a credential
    /// that is not registered here is never reached through this binding — the
    /// lookup in [`crate::BrokerState`] is what decides that, and this port is
    /// only ever asked for a name a deployment declared.
    ///
    /// Fails here rather than at first use: the resource host is vetted at
    /// startup, so a deployment naming something unroutable stops the broker
    /// with a message about the *configuration*, not with a transport error
    /// attributed to a credential at the first agent call.
    pub fn new(
        deployment: OAuth2Deployment,
        client_id: String,
        port: Arc<dyn SecretPort>,
    ) -> Result<Self, TransportError> {
        let policy = AddressPolicy::default();
        let resolved = resolve_and_pin(
            &deployment.resource,
            deployment.resource_port,
            policy,
        )?;
        let client = Arc::new(PinnedClient::build_timed(
            &resolved,
            policy,
            &[],
            Some(IDENTITY_TIMEOUT),
        )?);
        Ok(Self {
            deployment,
            client_id,
            client,
            resolved,
            port,
            policy,
        })
    }

    /// As [`Self::new`], with a **pre-vetted** address list, an explicit address
    /// policy and extra TLS roots.
    ///
    /// Two reasons this takes `resolved` instead of resolving for itself, and the
    /// second is the one that matters:
    ///
    /// 1. A test resource is a named loopback fixture — `idp.asv.test` — which
    ///    does not resolve, so a constructor that resolved here could never reach
    ///    it. `AwsBinding` takes a pre-built client for the same reason.
    /// 2. **The address policy is applied to the supplied list anyway.**
    ///    `PinnedClient::build_with_roots` re-filters every address against
    ///    `policy` even though `resolve_and_pin` already did, and the reason the
    ///    connector gives is the right one: `ResolvedAudience` is a public struct
    ///    a caller can build by hand, so a builder that trusted its input would
    ///    turn a type-level promise into a convention. Passing `127.0.0.1` here
    ///    therefore only works when `policy.allow_loopback` is set, and this
    ///    function — never [`Self::new`] — is the only place that can set it.
    pub fn with_test_transport(
        deployment: OAuth2Deployment,
        client_id: String,
        port: Arc<dyn SecretPort>,
        resolved: asv_connector_http::ResolvedAudience,
        policy: AddressPolicy,
        roots: &[reqwest::Certificate],
    ) -> Result<Self, TransportError> {
        let client = Arc::new(PinnedClient::build_with_roots(
            &resolved,
            policy,
            roots,
        )?);
        Ok(Self {
            deployment,
            client_id,
            client,
            resolved,
            port,
            policy,
        })
    }

    /// Borrows a derived access token for this deployment.
    ///
    /// The only way a token exists outside the port, and it exists for exactly
    /// the length of one call. It is zeroized on the way out by `SecretBytes`'s
    /// own `Drop`; nothing stores it and nothing logs it.
    fn borrow_token(&self, credential_wire: &str) -> Result<SecretBytes, String> {
        let mut captured: Option<SecretBytes> = None;
        struct Capture<'a>(&'a mut Option<SecretBytes>);
        impl asv_connector_http::SecretSink for Capture<'_> {
            fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
                *self.0 = Some(SecretBytes::new(secret.to_vec()));
                Ok(())
            }
        }
        self.port
            .lend(credential_wire, &mut Capture(&mut captured))
            .map_err(|error| error.to_string())?;
        captured.ok_or_else(|| "the OAuth2 port returned no token".to_string())
    }

    /// Asks the resource which identity this deployment acts as, and refuses an
    /// answer that does not match what the deployment declared.
    ///
    /// This is the whole operation, and the comparison at the end is not an
    /// afterthought — see the module docs.
    pub fn identity(&self, credential_wire: &str) -> Result<VerifiedIdentity, IdentityError> {
        let token = self
            .borrow_token(credential_wire)
            .map_err(IdentityError::Port)?;
        let url = self
            .client
            .url(&self.resolved, "/resource")
            .map_err(IdentityError::Transport)?;

        // A bearer token is ASCII by definition (RFC 6750's `b64token`), so a
        // non-UTF-8 one is not a token this can present. `from_utf8_lossy`
        // would "handle" it by substituting U+FFFD and sending a header the
        // resource did not mint, which turns a refusal into a confusing 401.
        let token = std::str::from_utf8(token.expose())
            .map_err(|_| IdentityError::Port(
                "the OAuth2 port returned a token that is not valid UTF-8".into(),
            ))?
            .to_string();

        let response = self
            .client
            .client()
            .get(url)
            // The header is built from the borrowed token and dropped with the
            // request. `bearer_auth` takes a `String`, so this is one copy of
            // the token in the broker's heap for the life of the call — the
            // same trade `oauth2.rs` already makes for the token request, and
            // bounded by `IDENTITY_TIMEOUT` rather than by the caller's
            // patience.
            .bearer_auth(token)
            .header("accept", "application/json")
            .send()
            .map_err(IdentityError::Wire)?;
        let status = response.status();
        if !status.is_success() {
            // The resource's own error body is deliberately not relayed: it is
            // written by a third party and is not obliged to be free of
            // anything. The status is the whole of the report.
            return Err(IdentityError::Refused {
                status: status.as_u16(),
            });
        }
        let body = response.text().map_err(IdentityError::Wire)?;
        let reported: ReportedIdentity = serde_json::from_str(&body)
            .map_err(|error| IdentityError::Malformed(error.to_string()))?;

        // The comparison. `expected_scope` and `audience` come from the
        // deployment, never from the request and never from the response, so
        // there is no path by which either side of this test can be chosen by
        // the caller.
        if reported.scope != self.deployment.expected_scope {
            return Err(IdentityError::ScopeWider {
                expected: self.deployment.expected_scope.clone(),
                granted: reported.scope,
            });
        }
        if reported.audience != self.deployment.audience {
            return Err(IdentityError::AudienceMismatch {
                expected: self.deployment.audience.clone(),
                reported: reported.audience,
            });
        }
        Ok(VerifiedIdentity {
            resource: reported.resource,
            scope: reported.scope,
            audience: reported.audience,
        })
    }
}

/// What the resource said, before the broker believed any of it.
///
/// Private to the module's trust boundary: [`VerifiedIdentity`] is the only
/// type that leaves [`OAuth2Binding::identity`], and it can only be built after
/// the comparison. Naming the unverified shape separately is what stops a later
/// edit from returning a `ReportedIdentity` from a path that skipped the check.
#[derive(Debug, serde::Deserialize)]
struct ReportedIdentity {
    resource: String,
    scope: String,
    audience: String,
}

/// A resource's answer that has been checked against the deployment.
///
/// Constructible only inside this module, and only by [`OAuth2Binding::identity`]
/// after both comparisons have passed. That is the whole reason this is a
/// distinct type from the response DTO: the DTO is what crosses the socket, and
/// nothing in the broker can build one out of an unverified provider answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub resource: String,
    pub scope: String,
    pub audience: String,
}

/// Why an identity could not be established.
///
/// Split by *whose* fault it is, because the three cases send an operator to
/// three different places and a single opaque error would make all three look
/// like a network fault. The distinctions are load-bearing for the operator and
/// they are all refusals — there is no variant that means "carry on".
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The port could not produce a token: the client secret was unreadable,
    /// the IdP refused it, or the token endpoint was unreachable.
    #[error("the OAuth2 port could not issue a token: {0}")]
    Port(String),
    /// The resource host could not be vetted or reached.
    #[error("the OAuth2 resource could not be reached: {0}")]
    Transport(#[source] TransportError),
    /// The request itself failed after the host was vetted.
    ///
    /// Split from [`Self::Transport`] because they send an operator to different
    /// places and lumping them together makes an unroutable deployment look like
    /// a flaky network. `Transport` is a *configuration* fault found at startup
    /// or on the first call; this is a connection, TLS or timeout fault.
    #[error("the OAuth2 resource request failed: {0}")]
    Wire(#[source] reqwest::Error),
    /// The resource answered with a non-2xx status.
    #[error("the OAuth2 resource refused the token (HTTP {status})")]
    Refused { status: u16 },
    /// The resource's body was not the shape this expects.
    #[error("the OAuth2 resource returned an unreadable body: {0}")]
    Malformed(String),
    /// **The provider granted a different scope than the deployment declares.**
    ///
    /// The one that matters, and the reason this operation is not a relay. An
    /// operator reading this learns that their configuration no longer describes
    /// the authority in play — which is a fact about their IdP registration, not
    /// about the broker, and one they cannot fix by editing policy.
    #[error(
        "the OAuth2 provider granted scope {granted:?} but the deployment declares {expected:?}; \
         refusing rather than reporting authority the operator did not configure"
    )]
    ScopeWider { expected: String, granted: String },
    /// The token was bound to a different audience than the deployment declares.
    #[error(
        "the token was issued for audience {reported:?} but the deployment declares {expected:?}"
    )]
    AudienceMismatch { expected: String, reported: String },
}
