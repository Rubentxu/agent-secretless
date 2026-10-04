//! M11 — OAuth2 provider framework.
//!
//! The framework is the structural answer to "agent with broker-held
//! credentials and short-lived access". Without it the agent must hold
//! the long-lived credential; with it the agent only holds the access
//! token and the broker refreshes in the background.
//!
//! [`ClientCredentialsIssuer`] performs a real HTTPS POST to the provider's
//! token endpoint, authenticating as a confidential client per RFC 6749
//! §2.3.1. Three of its rules exist because the alternative is a broker that
//! looks healthy while holding more authority than it was asked for:
//!
//! 1. **The endpoint must be HTTPS.** The request carries the client secret in
//!    an `Authorization` header, so a `http://` token URL puts the long-lived
//!    credential on the wire in the clear. There is no configuration that
//!    turns this off.
//! 2. **A granted scope different from the requested one aborts.** RFC 6749
//!    §5.1 permits a server to grant less, and requires the client to notice
//!    when it does. A *widening* is a privilege escalation and is refused as
//!    [`OAuth2Error::ScopeEscalated`]; a *narrowing* is refused as
//!    [`OAuth2Error::ScopeNarrowed`], because a caller that asked for
//!    `read write` and silently received `read` has been given an answer it
//!    did not ask about.
//! 3. **A token with no positive `expires_in` is refused.** A framework whose
//!    entire premise is short-lived access cannot accept a credential that
//!    claims to last forever, and RFC 6749 only makes `expires_in`
//!    *recommended*.
//!
//! [`DeterministicTokenIssuer`] is the old placeholder, renamed for what it
//! is. It mints tokens locally and talks to nobody, which is legitimate in a
//! test and indefensible anywhere else; a source-scanning test in this module
//! fails if production code names it.
//!
//! Authoritative source: `agent-secretless-vault-spec/docs/15-ROADMAP.md`
//! section M11 item #4, and `V1-C3`.

use std::time::Duration;

// `Authority` is `asv_domain`'s, not the connector's: it is the canonical form
// of a host name, and re-exporting it from the transport crate would give two
// names for one type and let a caller mix them up.
use asv_connector_http::{resolve_and_pin, AddressPolicy, PinnedClient};
// Only the test-only constructor names this, and only when it exists.
#[cfg(any(test, feature = "test-support"))]
use asv_connector_http::ResolvedAudience;
use asv_domain::Authority;
use base64::Engine as _;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The base64 alphabet of RFC 4648 §4, which §2.3.1's `Basic` scheme is
/// defined over.
const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// How long a token request may take before the provider is treated as down.
///
/// Bounded because the caller is a process holding a long-lived credential
/// whose only egress is this call. A provider that accepts the connection and
/// then says nothing is not slow, it is indistinguishable from one that is
/// withholding an answer on purpose, and an unbounded wait resolves that
/// ambiguity in the provider's favour.
pub const DEFAULT_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// An OAuth2 token (RFC 6749 §5.1).
///
/// `access_token` and `refresh_token` are wrapped in `Zeroizing` so
/// the bytes are wiped from memory when the `OAuth2Token` is dropped.
#[derive(Debug)]
pub struct OAuth2Token {
    /// The access token the agent receives.
    access_token: Zeroizing<Vec<u8>>,
    /// Token type, typically `"Bearer"`.
    pub token_type: String,
    /// Lifetime of the access token as the provider reported it.
    pub expires_in: Duration,
    /// Refresh token, if any. Never reachable through the public
    /// surface (only `expose_access_token` exists).
    refresh_token: Option<Zeroizing<Vec<u8>>>,
    /// Granted scope, if any.
    pub scope: Option<String>,
}

impl OAuth2Token {
    /// Build a new token.
    pub fn new(
        access_token: Vec<u8>,
        token_type: impl Into<String>,
        expires_in: Duration,
        refresh_token: Option<Vec<u8>>,
        scope: Option<String>,
    ) -> Self {
        Self {
            access_token: Zeroizing::new(access_token),
            token_type: token_type.into(),
            expires_in,
            refresh_token: refresh_token.map(Zeroizing::new),
            scope,
        }
    }

    /// Borrow the access bytes. The refresh bytes are not reachable
    /// through this method or any other public method.
    pub fn expose_access_token(&self) -> &[u8] {
        &self.access_token
    }

    /// True if a refresh token is held.
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Length of the access token, in bytes.
    pub fn access_token_len(&self) -> usize {
        self.access_token.len()
    }

    /// Hands the refresh token to a caller that has to keep it, and takes it
    /// out of this token.
    ///
    /// Deliberately the only way out, and consuming rather than borrowing: a
    /// refresh token is a long-lived credential, so the surface that can
    /// release one should be impossible to call twice and impossible to call
    /// by accident. The alternative — a `&[u8]` accessor — is a method anyone
    /// can add a call to, and one that leaves the bytes in a place this type
    /// can no longer wipe.
    pub fn take_refresh_token(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.refresh_token.take()
    }
}

impl Drop for OAuth2Token {
    fn drop(&mut self) {
        // The Zeroizing wrapper already handles drop; this Drop impl
        // exists to document the invariant that the bytes are zeroed.
        self.access_token.zeroize();
        if let Some(rt) = self.refresh_token.as_mut() {
            rt.zeroize();
        }
    }
}

/// Static configuration of an OAuth2 client.
#[derive(Clone)]
pub struct OAuth2Config {
    /// RFC 6749 §3.2 token endpoint. Must be `https`: see the module docs.
    pub token_url: String,
    /// Public client identifier. Form-encoded before it goes into a Basic
    /// credential, per §2.3.1.
    pub client_id: String,
    /// Client secret. Never leaves the broker except in an `Authorization`
    /// header to the token endpoint.
    pub client_secret: Vec<u8>,
    /// Provider audience (RFC 8707 resource indicator). Sent when non-empty.
    pub audience: String,
}

/// Redacts the secret.
///
/// Hand-written rather than derived, and that is the point: a derived `Debug`
/// on a struct holding a long-lived credential prints it into whatever log
/// statement, panic message or test failure reaches for `{config:?}`. The
/// length is kept because "no secret configured" and "a 32-byte secret" are
/// different situations and an operator needs to tell them apart.
impl std::fmt::Debug for OAuth2Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuth2Config")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("client_secret_len", &self.client_secret.len())
            .field("audience", &self.audience)
            .finish()
    }
}

impl OAuth2Config {
    /// Construct a config from parts.
    pub fn new(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Vec<u8>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret,
            audience: audience.into(),
        }
    }
}

/// Why an OAuth2 operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuth2Error {
    /// The provider answered, and the answer was no.
    ///
    /// `code` is RFC 6749 §5.2's `error` field when the body carried one, so an
    /// operator sees `invalid_client` rather than "400".
    #[error("provider rejected the request ({status} {code}): {description}")]
    ProviderRejected {
        status: u16,
        code: String,
        description: String,
    },
    /// The provider could not be reached, or the answer did not arrive in
    /// time. Never a success: an issuer that cannot reach its provider has no
    /// token to give, and reporting otherwise is how a broker ends up
    /// authorising an operation it never authorised.
    #[error("token endpoint unreachable: {0}")]
    ProviderUnreachable(String),
    /// A structural problem with the response (absent `access_token`, no
    /// `expires_in`, a token type this broker will not present).
    #[error("malformed token response: {0}")]
    MalformedToken(String),
    /// The provider granted more than was asked for.
    ///
    /// Its own variant because it is a different incident from every other
    /// refusal here: nothing failed, the provider said yes, and the yes was
    /// wider than the question.
    #[error("scope escalated: asked for {requested:?}, granted {granted:?}")]
    ScopeEscalated { requested: String, granted: String },
    /// The provider granted less than was asked for.
    #[error("scope narrowed: asked for {requested:?}, granted {granted:?}")]
    ScopeNarrowed { requested: String, granted: String },
    /// The token endpoint is not HTTPS, so the client secret would travel in
    /// the clear.
    #[error("token endpoint is not https: {0}")]
    InsecureEndpoint(String),
}

/// The OAuth2 issuer trait. Implementations MUST return a fresh token
/// without exposing the long-lived credential to the agent.
pub trait OAuth2Issuer {
    /// Issue a fresh access token using the configured client
    /// credentials (RFC 6749 §4.4).
    fn issue(&self, scope: &str) -> Result<OAuth2Token, OAuth2Error>;

    /// Refresh an existing access token using a refresh token (RFC
    /// 6749 §6).
    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error>;

    /// The token URL this issuer talks to. Used by the runtime
    /// follow-up for diagnostics.
    fn token_url(&self) -> &str;

    /// The audience this issuer serves. The agent requests the right
    /// issuer by passing the audience to the framework.
    fn audience(&self) -> &str;
}

/// How the issuer reaches a token endpoint.
///
/// Separate from the config because the two have different lifetimes and
/// different trust: the config is what an operator writes, and this is what a
/// test needs to substitute. A constructor that took both would let a test
/// point at loopback without saying so.
#[derive(Clone)]
struct Transport {
    client: PinnedClient,
    url: url::Url,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL is the useful part; the client is not, and asking one to
        // print itself would be asking `reqwest` what it feels like printing.
        formatter
            .debug_struct("Transport")
            .field("url", &self.url.as_str())
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Builds a transport for a production endpoint: resolve once, check the
    /// address against the public-address policy, pin it, and trust exactly
    /// what the platform trusts.
    fn production(token_url: &str) -> Result<Self, OAuth2Error> {
        let (url, authority, port) = parse_endpoint(token_url)?;
        let policy = AddressPolicy::default();
        let resolved = resolve_and_pin(&authority, port, policy).map_err(unreachable)?;
        let client = PinnedClient::build_timed(&resolved, policy, &[], Some(DEFAULT_TOKEN_TIMEOUT))
            .map_err(unreachable)?;
        Ok(Self { client, url })
    }

    /// Builds a transport against an already-vetted audience.
    ///
    /// The address policy is applied again inside `build_timed`, so handing in
    /// a hand-built `ResolvedAudience` is not a way around the private-address
    /// refusal: the check runs on the addresses either way. What this *is* for
    /// is a provider that is not in DNS — a locally issued certificate and a
    /// name nothing resolves.
    ///
    /// Gated with the constructor below, and for the same reason: it takes a
    /// `reqwest::Certificate`, which `asv-connector-http` does not even export
    /// without its `test-support` feature. The gate here is not tidiness, it is
    /// the only thing stopping a production build from acquiring the ability to
    /// trust a certificate it was handed.
    #[cfg(any(test, feature = "test-support"))]
    fn pinned(
        token_url: &str,
        resolved: &ResolvedAudience,
        policy: AddressPolicy,
        extra_roots: &[asv_connector_http::Certificate],
    ) -> Result<Self, OAuth2Error> {
        let (mut url, _, _) = parse_endpoint(token_url)?;
        // The URL is rebuilt from the vetted audience rather than trusted from
        // the caller. The client dials the port in the URL while the policy
        // checked the port in the audience, so two disagreeing values would
        // have had one checked and the other dialled. Deriving one from the
        // other is the only arrangement where "vetted" and "connected to" are
        // the same statement.
        url.set_host(Some(resolved.authority.as_str()))
            .map_err(|_| OAuth2Error::MalformedToken("token url host".to_string()))?;
        url.set_port(Some(resolved.port))
            .map_err(|_| OAuth2Error::MalformedToken("token url port".to_string()))?;
        let client =
            PinnedClient::build_timed(resolved, policy, extra_roots, Some(DEFAULT_TOKEN_TIMEOUT))
                .map_err(unreachable)?;
        Ok(Self { client, url })
    }

    /// One `application/x-www-form-urlencoded` POST to the token endpoint.
    ///
    /// The credential is assembled inside the call and zeroized on the way out
    /// rather than being held by the caller, so there is no window in which a
    /// second holder of the secret exists.
    fn post(&self, form: &str, config: &OAuth2Config) -> Result<Value, OAuth2Error> {
        let authorization = basic_credential(config)?;
        let response = self
            .client
            .client()
            .post(self.url.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::AUTHORIZATION, authorization.as_str())
            .body(form.to_string())
            .send()
            .map_err(|error| OAuth2Error::ProviderUnreachable(error.to_string()))?;

        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|error| OAuth2Error::ProviderUnreachable(error.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(provider_rejected(status, &body));
        }
        serde_json::from_str(&body).map_err(|error| {
            OAuth2Error::MalformedToken(format!("the token response is not JSON: {error}"))
        })
    }
}

/// A transport error phrased as "the provider could not be reached", which is
/// what a resolution or client-construction failure actually means to a caller
/// deciding whether to retry.
fn unreachable(error: impl std::fmt::Display) -> OAuth2Error {
    OAuth2Error::ProviderUnreachable(error.to_string())
}

/// Splits a token URL into the parts the transport needs, refusing anything
/// that is not HTTPS.
fn parse_endpoint(token_url: &str) -> Result<(url::Url, Authority, u16), OAuth2Error> {
    let url = url::Url::parse(token_url)
        .map_err(|error| OAuth2Error::MalformedToken(format!("token url: {error}")))?;
    if url.scheme() != "https" {
        return Err(OAuth2Error::InsecureEndpoint(token_url.to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| OAuth2Error::MalformedToken("the token url has no host".to_string()))?;
    let authority = Authority::canonicalize(host)
        .map_err(|error| OAuth2Error::MalformedToken(format!("token url host: {error}")))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| OAuth2Error::MalformedToken("the token url has no port".to_string()))?;
    Ok((url, authority, port))
}

/// The RFC 6749 §5.2 error body, when the provider sent one.
fn provider_rejected(status: u16, body: &str) -> OAuth2Error {
    let field = |name: &str| {
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
    };
    let code = field("error").unwrap_or_else(|| "no_error_code".to_string());
    let description = field("error_description")
        .or_else(|| {
            // A provider that answered with something that is not a §5.2 form
            // is still telling the operator something. Kept, and truncated,
            // rather than discarded: an empty description on a 502 tells
            // nobody what the gateway said.
            let trimmed = body.trim();
            (!trimmed.is_empty()).then(|| trimmed.chars().take(200).collect())
        })
        .unwrap_or_else(|| "no description".to_string());
    OAuth2Error::ProviderRejected {
        status,
        code,
        description,
    }
}

/// Builds the `Authorization` header value for RFC 6749 §2.3.1.
///
/// The identifier and the secret are form-encoded *before* being joined with
/// `:` and base64'd, which is the whole content of the rule and the part that is
/// easy to skip. Written byte by byte into one buffer, so no intermediate holds
/// a copy of the secret that nothing is responsible for wiping.
fn basic_credential(config: &OAuth2Config) -> Result<Zeroizing<String>, OAuth2Error> {
    if config.client_id.is_empty() {
        return Err(OAuth2Error::MalformedToken("empty client_id".into()));
    }
    let mut joined = Zeroizing::new(String::with_capacity(
        config.client_id.len() + config.client_secret.len() + 1,
    ));
    push_form_encoded(&mut joined, config.client_id.as_bytes());
    joined.push(':');
    push_form_encoded(&mut joined, &config.client_secret);
    let header = Zeroizing::new(format!("Basic {}", BASE64.encode(joined.as_bytes())));
    Ok(header)
}

/// Appends `raw` to `out` in `application/x-www-form-urlencoded` form.
fn push_form_encoded(out: &mut Zeroizing<String>, raw: &[u8]) {
    for escape in url::form_urlencoded::byte_serialize(raw) {
        // `write!` on a `String` is infallible, but going through the formatter
        // for a value that is a literal byte is needless; `push_str` cannot
        // fail and cannot partially write.
        out.push_str(escape);
    }
}

/// A scope string as a set.
///
/// RFC 6749's `scope` is a space-delimited *list*, so `read write` and
/// `write read` are the same grant. Comparing the strings would call a
/// reordering an escalation, and a client that normalised differently from its
/// provider would refuse every token.
fn scope_set(scope: &str) -> Vec<String> {
    let mut parts: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
    parts.sort();
    parts.dedup();
    parts
}

/// Refuses a granted scope that is not the requested one.
///
/// Two refusals, not one, because the two mean different things to whoever has
/// to respond: a widening is a provider handing out more than it was asked, and
/// a narrowing is an operation quietly not being able to do what it claimed.
fn check_scope(requested: &str, granted: &str) -> Result<(), OAuth2Error> {
    let asked = scope_set(requested);
    let gave = scope_set(granted);
    if asked == gave {
        return Ok(());
    }
    let widened = gave.iter().any(|scope| !asked.contains(scope));
    if widened {
        Err(OAuth2Error::ScopeEscalated {
            requested: requested.to_string(),
            granted: granted.to_string(),
        })
    } else {
        Err(OAuth2Error::ScopeNarrowed {
            requested: requested.to_string(),
            granted: granted.to_string(),
        })
    }
}

/// Reads an RFC 6749 §5.1 success body into a token.
///
/// `expected_scope` is what the caller asked for, or `None` when there was no
/// question to compare the answer against — a refresh, where the grant is
/// whatever the original authorization established.
fn parse_token(body: &Value, expected_scope: Option<&str>) -> Result<OAuth2Token, OAuth2Error> {
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| OAuth2Error::MalformedToken("no access_token in the response".into()))?;

    // A token type this broker does not know how to present is refused rather
    // than downgraded. The only thing it does with a token is send it as
    // `Bearer`, and sending a `DPoP` or `mac` token that way is a silent
    // downgrade of a proof the provider asked for.
    let token_type = body
        .get("token_type")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| OAuth2Error::MalformedToken("no token_type in the response".into()))?;
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(OAuth2Error::MalformedToken(format!(
            "the provider issued a {token_type:?} token and this broker only presents bearer"
        )));
    }

    // A short-lived framework cannot accept a credential with no lifetime. §5.1
    // makes `expires_in` recommended, so this is the case where a conforming
    // provider may legitimately omit it — and the omission must not become a
    // token that outlives the process.
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            OAuth2Error::MalformedToken(
                "no positive expires_in: a token with no lifetime is not short-lived access".into(),
            )
        })?;

    let scope = body
        .get("scope")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let (Some(requested), Some(granted)) = (expected_scope, scope.as_deref()) {
        check_scope(requested, granted)?;
    }

    let refresh = body
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(|token| token.as_bytes().to_vec());

    Ok(OAuth2Token::new(
        access.as_bytes().to_vec(),
        token_type.to_string(),
        Duration::from_secs(expires_in),
        refresh,
        scope,
    ))
}

/// A client-credentials issuer (RFC 6749 §4.4) that performs a real HTTPS POST
/// to the token endpoint.
#[derive(Clone)]
pub struct ClientCredentialsIssuer {
    config: OAuth2Config,
    transport: Transport,
}

impl std::fmt::Debug for ClientCredentialsIssuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientCredentialsIssuer")
            .field("config", &self.config)
            .field("transport", &self.transport)
            .finish()
    }
}

impl ClientCredentialsIssuer {
    /// Construct an issuer for a production endpoint.
    ///
    /// Resolves the name once and pins the answer, so a second lookup inside
    /// the HTTP stack cannot answer with a different address than the one that
    /// was vetted. Refuses a non-HTTPS endpoint rather than warning about it.
    pub fn new(config: OAuth2Config) -> Result<Self, OAuth2Error> {
        let transport = Transport::production(&config.token_url)?;
        Ok(Self { config, transport })
    }

    /// Construct an issuer against an already-vetted audience.
    ///
    /// For a provider that is not in DNS. The address policy is applied again
    /// when the client is built, so this cannot be used to reach a private
    /// address that the policy refuses.
    ///
    /// Test-only, and unavailable in a production build for a structural reason
    /// rather than a policy one: the certificate type it needs is not exported
    /// by `asv-connector-http` unless that crate's own `test-support` feature is
    /// on. There is no configuration of this binary that makes it exist.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_resolved(
        config: OAuth2Config,
        resolved: &ResolvedAudience,
        policy: AddressPolicy,
        extra_roots: &[asv_connector_http::Certificate],
    ) -> Result<Self, OAuth2Error> {
        let transport = Transport::pinned(&config.token_url, resolved, policy, extra_roots)?;
        Ok(Self { config, transport })
    }

    /// Builds the `grant_type=…` form body.
    fn request_form(&self, fields: &[(&str, &str)]) -> Zeroizing<String> {
        let mut form = Zeroizing::new(String::new());
        for (name, value) in fields {
            if !form.is_empty() {
                form.push('&');
            }
            form.push_str(name);
            form.push('=');
            push_form_encoded(&mut form, value.as_bytes());
        }
        form
    }
}

impl OAuth2Issuer for ClientCredentialsIssuer {
    fn issue(&self, scope: &str) -> Result<OAuth2Token, OAuth2Error> {
        if self.config.client_id.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty client_id".into()));
        }
        let form = self.request_form(&[
            ("grant_type", "client_credentials"),
            ("scope", scope),
            ("audience", self.config.audience.as_str()),
        ]);
        let body = self.transport.post(form.as_str(), &self.config)?;
        // A response that omits `scope` granted exactly what was asked, which
        // is what §5.1 says an omission means. Passing the requested scope
        // anyway would then compare it against nothing and learn nothing.
        let expected = (!scope.is_empty()).then_some(scope);
        parse_token(&body, expected)
    }

    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error> {
        if refresh_token.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty refresh_token".into()));
        }
        // The refresh token is itself a long-lived credential, so it is encoded
        // straight into a wiped buffer rather than through a `String` the
        // caller could still be holding.
        let encoded =
            Zeroizing::new(url::form_urlencoded::byte_serialize(refresh_token).collect::<String>());
        let form = self.request_form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", encoded.as_str()),
        ]);
        let body = self.transport.post(form.as_str(), &self.config)?;
        // No scope to check against: the grant is the one the original
        // authorization established, and the broker does not hold it here. The
        // granted scope is still returned on the token so a caller that does
        // know it can check.
        parse_token(&body, None)
    }

    fn token_url(&self) -> &str {
        &self.config.token_url
    }

    fn audience(&self) -> &str {
        &self.config.audience
    }
}

/// A deterministic issuer that mints tokens locally and contacts nobody.
///
/// **Test-only. Never wire this to production.** It exists because a test
/// needs an `OAuth2Issuer` without a provider, and it is dangerous for exactly
/// the reason that is easy to miss: it is not a broken issuer, it is a
/// *working* one. It returns a well-formed `Bearer` token with a positive
/// lifetime and no error path, so every consumer above it behaves correctly
/// against a credential that grants nothing anywhere.
///
/// `deterministic_issuance_never_reaches_production` in this module fails if
/// any source file outside the tests names it.
#[derive(Debug, Clone)]
pub struct DeterministicTokenIssuer {
    config: OAuth2Config,
}

impl DeterministicTokenIssuer {
    /// Construct a deterministic issuer from a config.
    pub fn new(config: OAuth2Config) -> Self {
        Self { config }
    }
}

impl OAuth2Issuer for DeterministicTokenIssuer {
    fn issue(&self, scope: &str) -> Result<OAuth2Token, OAuth2Error> {
        if self.config.client_id.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty client_id".into()));
        }
        let access_token = synth_access_token(&self.config.client_id, scope);
        let scope_owned = if scope.is_empty() {
            None
        } else {
            Some(scope.to_string())
        };
        Ok(OAuth2Token::new(
            access_token,
            "Bearer",
            Duration::from_secs(3600),
            Some(synth_refresh_token(&self.config.client_id)),
            scope_owned,
        ))
    }

    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error> {
        if refresh_token.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty refresh_token".into()));
        }
        Ok(OAuth2Token::new(
            synth_access_token_from_refresh(refresh_token),
            "Bearer",
            Duration::from_secs(3600),
            Some(refresh_token.to_vec()),
            None,
        ))
    }

    fn token_url(&self) -> &str {
        &self.config.token_url
    }

    fn audience(&self) -> &str {
        &self.config.audience
    }
}

fn synth_access_token(client_id: &str, scope: &str) -> Vec<u8> {
    // Deterministic and content-addressed, which is what makes it useless as a
    // credential and useful as a fixture: two calls agree, so a test can name
    // the value it expects.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client_id.hash(&mut h);
    scope.hash(&mut h);
    h.write_u64(0xA11CE); // version marker for the deterministic issuer
    h.finish().to_le_bytes().to_vec()
}

fn synth_refresh_token(client_id: &str) -> Vec<u8> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client_id.hash(&mut h);
    h.write_u64(0xBE12E5);
    h.finish().to_le_bytes().to_vec()
}

fn synth_access_token_from_refresh(refresh_token: &[u8]) -> Vec<u8> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    refresh_token.hash(&mut h);
    h.write_u64(0xACC355);
    h.finish().to_le_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuth2Config {
        OAuth2Config::new(
            "https://idp.example.com/oauth2/token",
            "client-1",
            b"shh".to_vec(),
            "https://api.example.com",
        )
    }

    /// The error half of a result.
    ///
    /// `OAuth2Token` deliberately has no `PartialEq`: a derived one would
    /// compare two access tokens, and an equality that reads credential bytes
    /// is an equality nobody wants in a log line or an assertion failure
    /// message.
    fn err(result: Result<OAuth2Token, OAuth2Error>) -> OAuth2Error {
        match result {
            Ok(token) => panic!("expected a refusal, got a {} token", token.token_type),
            Err(error) => error,
        }
    }

    /// A JSON body shaped like an RFC 6749 §5.1 success.
    fn token_body() -> Value {
        serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "read",
            "refresh_token": "rt-1",
        })
    }

    /// The endpoint has to be HTTPS, because the request carries the secret in
    /// a header. A `http://` token URL is the one misconfiguration that turns
    /// the whole framework into a plain-text credential distributor.
    #[test]
    fn a_plaintext_token_endpoint_is_refused() {
        let config = OAuth2Config::new(
            "http://idp.example.com/oauth2/token",
            "client-1",
            b"shh".to_vec(),
            "https://api.example.com",
        );
        assert!(matches!(
            ClientCredentialsIssuer::new(config),
            Err(OAuth2Error::InsecureEndpoint(_))
        ));
    }

    /// The credential is base64 over the *form-encoded* pair, and the escapes
    /// are spelled out here so the assertion does not rest on the encoder.
    #[test]
    fn the_basic_credential_is_the_form_encoded_pair() {
        let awkward = OAuth2Config::new(
            "https://idp.example.com/token",
            "asv:broker/ci".to_string(),
            b"p ss+w&rd:".to_vec(),
            "",
        );
        let header = basic_credential(&awkward).expect("credential");
        let encoded = header.strip_prefix("Basic ").expect("the Basic scheme");
        let decoded = BASE64.decode(encoded).expect("base64");
        assert_eq!(
            String::from_utf8(decoded).expect("utf8"),
            "asv%3Abroker%2Fci:p+ss%2Bw%26rd%3A",
            "the halves must be encoded before they are joined"
        );
    }

    /// The secret must not survive as a plain copy anywhere the header does
    /// not reach. `Zeroizing` is the only reason this is a fact rather than an
    /// intention, and the test is the reason it stays one.
    #[test]
    fn an_empty_client_id_is_refused_before_any_encoding() {
        let empty = OAuth2Config::new("https://idp.example.com/token", "", b"shh".to_vec(), "");
        assert!(matches!(
            basic_credential(&empty),
            Err(OAuth2Error::MalformedToken(_))
        ));
    }

    /// A well-formed response becomes a token.
    #[test]
    fn a_well_formed_response_becomes_a_token() {
        let token = parse_token(&token_body(), Some("read")).expect("parse");
        assert_eq!(token.expose_access_token(), b"at-1");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, Duration::from_secs(300));
        assert!(token.has_refresh_token());
        assert_eq!(token.scope.as_deref(), Some("read"));
    }

    /// The absence of `expires_in` is a refusal, not a default. RFC 6749 only
    /// makes it recommended, and honouring the recommendation is the entire
    /// difference between short-lived access and a permanent credential.
    #[test]
    fn a_token_with_no_lifetime_is_refused() {
        for body in [
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
            serde_json::json!({"access_token": "at", "token_type": "Bearer", "expires_in": 0}),
            serde_json::json!({"access_token": "at", "token_type": "Bearer", "expires_in": -1}),
        ] {
            assert!(
                matches!(
                    parse_token(&body, None),
                    Err(OAuth2Error::MalformedToken(_))
                ),
                "{body} must not become a token"
            );
        }
    }

    /// A token type this broker cannot present is refused, not downgraded.
    #[test]
    fn an_unpresentable_token_type_is_refused() {
        let body = serde_json::json!({
            "access_token": "at", "token_type": "DPoP", "expires_in": 300,
        });
        assert!(matches!(
            parse_token(&body, None),
            Err(OAuth2Error::MalformedToken(_))
        ));
    }

    /// A missing `access_token` is not an empty token.
    #[test]
    fn a_response_with_no_access_token_is_refused() {
        for body in [
            serde_json::json!({"token_type": "Bearer", "expires_in": 300}),
            serde_json::json!({"access_token": "", "token_type": "Bearer", "expires_in": 300}),
        ] {
            assert!(matches!(
                parse_token(&body, None),
                Err(OAuth2Error::MalformedToken(_))
            ));
        }
    }

    /// The property the whole increment exists for: a provider that grants
    /// *more* than it was asked is refused, and named as an escalation rather
    /// than as a generic failure.
    #[test]
    fn a_widened_scope_is_refused_as_an_escalation() {
        let body = serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 300,
            "scope": "read write admin",
        });
        assert_eq!(
            err(parse_token(&body, Some("read"))),
            OAuth2Error::ScopeEscalated {
                requested: "read".to_string(),
                granted: "read write admin".to_string(),
            }
        );
    }

    /// A narrowing is also refused, because a caller that asked for `read
    /// write` and silently got `read` has been told something it did not ask
    /// about.
    #[test]
    fn a_narrowed_scope_is_refused_as_a_narrowing() {
        let body = serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 300,
            "scope": "read",
        });
        assert_eq!(
            err(parse_token(&body, Some("read write"))),
            OAuth2Error::ScopeNarrowed {
                requested: "read write".to_string(),
                granted: "read".to_string(),
            }
        );
    }

    /// `scope` is a set, not a string. A provider that lists the same scopes in
    /// another order granted exactly what was asked for, and a comparison on
    /// the raw string would call it an escalation.
    #[test]
    fn a_reordered_scope_is_the_same_grant() {
        assert!(check_scope("read write", "write read").is_ok());
        assert!(check_scope("read read", "read").is_ok());
    }

    /// A response with no `scope` granted exactly what was asked, so there is
    /// nothing to compare and nothing to refuse.
    #[test]
    fn an_absent_scope_grants_exactly_what_was_requested() {
        let body = serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 300,
        });
        let token = parse_token(&body, Some("read")).expect("an omission is not a difference");
        assert!(token.scope.is_none());
    }

    /// An RFC 6749 §5.2 error body becomes a named error, so an operator reads
    /// `invalid_client` rather than `400`.
    #[test]
    fn a_provider_error_body_is_named() {
        let error = provider_rejected(
            401,
            "error=invalid_client&error_description=client+authentication+failed",
        );
        assert_eq!(
            error,
            OAuth2Error::ProviderRejected {
                status: 401,
                code: "invalid_client".to_string(),
                description: "client authentication failed".to_string(),
            }
        );
    }

    /// A provider that answers with something that is not a §5.2 form still
    /// said something, and an empty description would throw it away.
    #[test]
    fn a_non_conforming_error_body_is_kept_rather_than_discarded() {
        let error = provider_rejected(502, "<html>bad gateway</html>");
        match error {
            OAuth2Error::ProviderRejected {
                status,
                code,
                description,
            } => {
                assert_eq!(status, 502);
                assert_eq!(code, "no_error_code");
                assert!(description.contains("bad gateway"), "{description}");
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// The refresh token leaves the token exactly once, and the surface that
    /// releases it is consuming.
    #[test]
    fn a_refresh_token_can_be_taken_exactly_once() {
        let mut token = parse_token(&token_body(), Some("read")).expect("parse");
        assert!(token.take_refresh_token().is_some());
        assert!(token.take_refresh_token().is_none());
        assert!(!token.has_refresh_token());
    }

    /// The deterministic issuer still behaves like an issuer, which is exactly
    /// why it is dangerous outside a test.
    #[test]
    fn the_deterministic_issuer_answers_without_a_provider() {
        let issuer = DeterministicTokenIssuer::new(config());
        let token = issuer.issue("read:pods").expect("issue");
        assert_eq!(token.token_type, "Bearer");
        assert!(token.expires_in > Duration::from_secs(0));
        assert!(!token.expose_access_token().is_empty());
        assert!(token.has_refresh_token());
        assert_eq!(token.scope.as_deref(), Some("read:pods"));

        let again = issuer.issue("read:pods").expect("issue again");
        assert_eq!(
            token.expose_access_token(),
            again.expose_access_token(),
            "the deterministic issuer is content-addressed"
        );
    }

    /// The deterministic issuer refuses the two inputs that have no honest
    /// answer, so a test that exercises those paths is exercising the real
    /// issuer's shape rather than a special case.
    #[test]
    fn the_deterministic_issuer_refuses_empty_identifiers_and_refreshes() {
        let empty = OAuth2Config::new("https://idp.example.com/token", "", b"shh".to_vec(), "");
        assert!(matches!(
            DeterministicTokenIssuer::new(empty).issue("read"),
            Err(OAuth2Error::MalformedToken(_))
        ));
        let issuer = DeterministicTokenIssuer::new(config());
        assert!(matches!(
            issuer.refresh(b""),
            Err(OAuth2Error::MalformedToken(_))
        ));
    }

    #[test]
    fn an_issuer_exposes_its_token_url_and_audience() {
        let issuer = DeterministicTokenIssuer::new(config());
        assert_eq!(issuer.token_url(), "https://idp.example.com/oauth2/token");
        assert_eq!(issuer.audience(), "https://api.example.com");
    }

    /// The guard that keeps the deterministic issuer a fixture.
    ///
    /// Documentation is not a control, and this is the control: the name may
    /// appear in this module and in test code, and nowhere else. A test that
    /// only asserted the issuer worked would pass on a broker issuing
    /// well-formed tokens that grant nothing anywhere, which is the failure
    /// mode this whole work item exists to remove.
    #[test]
    fn deterministic_issuance_never_reaches_production() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let offenders: Vec<String> = walk(root)
            .into_iter()
            .filter(|path| {
                let text = path.to_string_lossy();
                if text.contains("/tests/") || text.ends_with("oauth2.rs") {
                    return false;
                }
                std::fs::read_to_string(path)
                    .map(|body| body.contains("DeterministicTokenIssuer"))
                    .unwrap_or(false)
            })
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        assert!(
            offenders.is_empty(),
            "the deterministic issuer is a test double and may not be named by: {offenders:?}"
        );
    }

    /// Every `.rs` under the crate, skipping `target`.
    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                found.extend(walk(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
        found
    }
}
