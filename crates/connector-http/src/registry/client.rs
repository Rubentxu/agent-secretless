//! The registry request loop: a `401`, a token, and the retry.
//!
//! [`super::registry`] decides *which* token to ask for. This module spends it,
//! and the only reason it is worth a file of its own is the shape of what it
//! holds while it does: the long-lived credential exists inside one
//! [`crate::github::SecretPort::lend`] call and nowhere else, and the token that call produces
//! exists until the retry that uses it and not one instruction longer.
//!
//! # Why the credential and the token are not the same kind of thing
//!
//! The vault holds the registry password. That password never becomes an HTTP
//! header here: it is lent, it is used to redeem a token at the `realm`, and it
//! is gone by the time the retry is assembled. The token is what the retry
//! carries, and it is spent inside one connection. An agent talking to this
//! client holds neither, which is the posture the research settled and the
//! reason this belongs in M11 rather than in a catalogue.
//!
//! # What a caller cannot do with this type
//!
//! There is no method that takes a URL, a path or a header from the caller. A
//! registry operation is named -- [`crate::registry::client::RegistryClient::get_manifest`],
//! [`crate::registry::client::RegistryClient::put_manifest`] -- and the path is built from a
//! [`RepositoryName`] and an [`crate::registry::client::ImageReference`], both of which refuse anything
//! that could step outside the repository they name. The scope comes from the
//! operation, so there is no input here that could widen a pull into a write.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::Value;
use zeroize::Zeroizing;

use asv_domain::Authority;

use super::{
    granted_scope_from_token_response, narrow, scope_to_request, BearerChallenge, ChallengeError,
    Realm, RealmError, RegistryOperation, RegistryScope, RepositoryName, ScopeError,
};
use crate::github::{SecretError, SecretPort, SecretSink};
use crate::transport::{AddressPolicy, PinnedClient, ResolvedAudience, TransportError};

/// The longest a manifest reference may be, per the distribution
/// specification's tag grammar.
const MAX_REFERENCE_LENGTH: usize = 128;

/// The port a token endpoint is reached on. Written here as well as in the
/// supermodule because this is the one that builds the token request, and a
/// client that reached the realm on a different port than the realm rule allows
/// would be the same defect wearing a different constant.
const TOKEN_PORT: u16 = 443;

/// A manifest reference: a tag or a digest, and nothing that could leave the
/// repository.
///
/// A reference is interpolated into a URL path, so a reference containing
/// `/..` would address a different resource on the same registry -- and
/// `/v2/../v2/other/manifests/x` is a pull from `other`. The grammar is short
/// and it is the whole of the property; there is no allowlist of tags because
/// tags are user-chosen and an allowlist of tags would be a list of everyone's
/// tags.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ImageReference {
    /// A mutable name, e.g. `latest`.
    Tag(String),
    /// A content address, e.g. `sha256:<64 hex>`.
    Digest(String),
}

impl ImageReference {
    /// Reads a reference, refusing anything outside the distribution spec.
    ///
    /// A tag is `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`. The length bound is not
    /// cosmetic either: it is what keeps a reference from being a very long
    /// string the token endpoint has to read.
    pub fn parse(raw: &str) -> Result<Self, ReferenceError> {
        if raw.is_empty() {
            return Err(ReferenceError::Empty);
        }
        if raw.len() > MAX_REFERENCE_LENGTH {
            return Err(ReferenceError::TooLong {
                len: raw.len(),
                max: MAX_REFERENCE_LENGTH,
            });
        }
        if let Some(digest) = raw.strip_prefix("sha256:") {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(ReferenceError::MalformedDigest);
            }
            return Ok(Self::Digest(raw.to_string()));
        }
        if raw.contains(':') {
            // Whatever follows a colon is a digest, and the only one this
            // speaks is `sha256`. Saying `MalformedTag` for `sha512:...` would
            // name the wrong half of the grammar to whoever has to fix it.
            return Err(ReferenceError::MalformedDigest);
        }
        let first = raw.as_bytes()[0];
        if !(first.is_ascii_alphanumeric() || first == b'_') {
            return Err(ReferenceError::MalformedTag);
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ReferenceError::MalformedTag);
        }
        Ok(Self::Tag(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Tag(t) | Self::Digest(t) => t,
        }
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a manifest reference was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceError {
    #[error("the manifest reference is empty")]
    Empty,
    #[error("the manifest reference is {len} bytes, over the {max} a reference may be")]
    TooLong { len: usize, max: usize },
    #[error("the manifest reference is not a well-formed tag")]
    MalformedTag,
    #[error("the manifest reference is not a well-formed sha256 digest")]
    MalformedDigest,
}

/// Everything that can go wrong in one registry operation.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error(transparent)]
    Challenge(#[from] ChallengeError),
    #[error(transparent)]
    Realm(#[from] RealmError),
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Reference(#[from] ReferenceError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// The registry answered `401` without saying how to authenticate. A client
    /// that guessed would be inventing a credential source.
    #[error("the registry refused the request without a challenge")]
    NoChallenge,
    #[error("the token endpoint answered {status} instead of a token")]
    TokenEndpointRefused { status: u16 },
    #[error("the token endpoint's answer holds no token")]
    NoTokenInResponse,
    #[error("the registry answered {status} rather than the {expected} the operation expected")]
    UnexpectedStatus { status: u16, expected: u16 },
}

/// What a successful read produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRead {
    /// The media type the registry declared, e.g.
    /// `application/vnd.oci.image.manifest.v1+json`.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// A client that talks to one registry family, using one stored credential.
///
/// The credential is named at construction and never read again: every use
/// goes through the port, and the port is what can revoke.
pub struct RegistryClient {
    port: Arc<dyn SecretPort>,
    credential: String,
    policy: AddressPolicy,
    /// The port the token endpoint is reached on.
    ///
    /// 443 in production, and there is no way to change it that compiles
    /// outside `test-support`: the test origin listens on an ephemeral port,
    /// and a rule that could not be pointed at a fixture could not be falsified
    /// by one.
    realm_port: u16,
    /// The addresses the token endpoint is reached at.
    ///
    /// Empty in production, where the realm is resolved and checked. A test
    /// sets it because a name resolving to both `127.0.0.1` and `::1` makes a
    /// v4-only fixture unreachable, and the alternative -- a fixture that
    /// resolves its own name -- would be a fixture no vetting could refuse.
    #[cfg(any(test, feature = "test-support"))]
    realm_addresses: Vec<std::net::IpAddr>,
    /// Extra certificates to trust, empty in production.
    ///
    /// The field exists so a test can point the client at a real socket with a
    /// real handshake; `PinnedClient::build_with_roots` with nothing in it is
    /// `build`, so an empty list grants nothing.
    extra_roots: Vec<reqwest::Certificate>,
}

impl RegistryClient {
    /// Builds a client for the credential named `credential`.
    ///
    /// The name is stored rather than the secret, so this struct has nothing
    /// to zeroize and no `Debug` worth writing.
    pub fn new(
        port: Arc<dyn SecretPort>,
        credential: impl Into<String>,
        policy: AddressPolicy,
    ) -> Self {
        Self {
            port,
            credential: credential.into(),
            policy,
            realm_port: TOKEN_PORT,
            #[cfg(any(test, feature = "test-support"))]
            realm_addresses: Vec::new(),
            extra_roots: Vec::new(),
        }
    }

    /// Reaches the token endpoint at `addresses` rather than at whatever the
    /// realm's name resolves to.
    ///
    /// The same address policy still vets them; only the lookup is skipped.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reaching_realm_at(mut self, addresses: Vec<std::net::IpAddr>) -> Self {
        self.realm_addresses = addresses;
        self
    }

    /// Reaches the token endpoint on `port` rather than on 443.
    ///
    /// Feature-gated for the same reason [`RegistryClient::trusting`] is: this
    /// is a rule, and a rule with a production-reachable override is not one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reaching_realm_on(mut self, port: u16) -> Self {
        self.realm_port = port;
        self
    }

    /// A client that also trusts `extra_roots`.
    ///
    /// Feature-gated for the reason every other test-support surface in this
    /// crate is: a client that could be pointed at a certificate this side
    /// chose rather than one the registry presented is a client whose TLS is
    /// worth being suspicious of in production.
    #[cfg(any(test, feature = "test-support"))]
    pub fn trusting(
        port: Arc<dyn SecretPort>,
        credential: impl Into<String>,
        policy: AddressPolicy,
        extra_roots: Vec<reqwest::Certificate>,
    ) -> Self {
        Self {
            port,
            credential: credential.into(),
            policy,
            realm_port: TOKEN_PORT,
            #[cfg(any(test, feature = "test-support"))]
            realm_addresses: Vec::new(),
            extra_roots,
        }
    }

    /// Reads a manifest. This is the whole of a pull.
    ///
    /// `registry` is the audience the caller already vetted and pinned, not a
    /// name to resolve here. Resolving it a second time inside this client
    /// would be a second chance for the resolver to answer differently from
    /// the address that was authorised, which is the reason
    /// [`crate::transport::PinnedClient`] is `Clone` and rebuilt per operation
    /// rather than rebuilt here.
    pub fn get_manifest(
        &self,
        registry: &ResolvedAudience,
        repository: &RepositoryName,
        reference: &ImageReference,
    ) -> Result<ManifestRead, RegistryError> {
        let path = manifest_path(repository, reference);
        let outcome = self.attempt(
            registry,
            reqwest::Method::GET,
            &path,
            RegistryOperation::Pull,
            repository,
            None,
        )?;
        Ok(ManifestRead {
            content_type: outcome
                .headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            body: outcome.body,
        })
    }

    /// Writes a manifest. This is the whole of a push's first half.
    pub fn put_manifest(
        &self,
        registry: &ResolvedAudience,
        repository: &RepositoryName,
        reference: &ImageReference,
        body: &[u8],
    ) -> Result<(), RegistryError> {
        self.attempt(
            registry,
            reqwest::Method::PUT,
            &manifest_path(repository, reference),
            RegistryOperation::Push,
            repository,
            Some(body),
        )?;
        Ok(())
    }

    /// One operation, with the `401` loop around it.
    ///
    /// The unauthenticated attempt comes first, and that ordering is worth a
    /// sentence: a registry serving an anonymous pull answers `200` and this
    /// never reaches the token exchange at all. Sending a credential at a
    /// registry that did not ask for one would be the opposite of this
    /// module's argument.
    fn attempt(
        &self,
        registry: &ResolvedAudience,
        method: reqwest::Method,
        path: &str,
        operation: RegistryOperation,
        repository: &RepositoryName,
        body: Option<&[u8]>,
    ) -> Result<Outcome, RegistryError> {
        let client = self.pinned_client(registry)?;
        let anonymous = build_request(&client, registry, method.clone(), path, body, None)?;

        let response = send(&client, anonymous, registry)?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return finish(response, operation);
        }

        let challenge_header = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .ok_or(RegistryError::NoChallenge)?
            .to_string();
        let challenge = BearerChallenge::parse(&challenge_header)?;

        let token = self.redeem(&challenge, operation, repository)?;
        let authenticated =
            build_request(&client, registry, method, path, body, Some(token.as_str()))?;
        finish(send(&client, authenticated, registry)?, operation)
    }

    /// A client for the registry, re-checked against the policy.
    ///
    /// `PinnedClient::build` re-filters the addresses even though the caller
    /// already vetted them. That redundancy is the crate's own argument about
    /// hand-built audiences, and it applies here too.
    fn pinned_client(&self, registry: &ResolvedAudience) -> Result<PinnedClient, TransportError> {
        PinnedClient::build_with_roots(registry, self.policy, &self.extra_roots)
    }

    /// Redeems the challenge for a token, and narrows the grant on the way out.
    ///
    /// The credential is lent exactly once, and the sink that receives it is
    /// the only thing in this function that can see it: the sink builds the
    /// token request, executes it, and hands back the response body. By the
    /// time `lend` returns, the password is unreferenced and the response is
    /// the only thing left.
    fn redeem(
        &self,
        challenge: &BearerChallenge,
        operation: RegistryOperation,
        repository: &RepositoryName,
    ) -> Result<Zeroizing<String>, RegistryError> {
        #[cfg(not(any(test, feature = "test-support")))]
        let realm = Realm::vet_reaching(challenge.realm(), self.policy, self.realm_port)?;
        #[cfg(any(test, feature = "test-support"))]
        let realm = if self.realm_addresses.is_empty() {
            Realm::vet_reaching(challenge.realm(), self.policy, self.realm_port)?
        } else {
            Realm::vet_reaching_at(
                challenge.realm(),
                self.policy,
                self.realm_port,
                &self.realm_addresses,
            )?
        };
        let asked = scope_to_request(operation, repository);

        // `Realm::vet` pins the authority against port 443, which is the only
        // port a realm may name. The pinned client is built from that same
        // `ResolvedAudience`, so the addresses the realm was checked against
        // are the addresses the token request goes to.
        let client =
            PinnedClient::build_with_roots(realm.resolved(), self.policy, &self.extra_roots)?;
        let url = token_url(&client, &realm, challenge.service(), &asked)?;
        let builder = client
            .client()
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");

        let mut sink = TokenAttempt::new(builder);
        self.port.lend(&self.credential, &mut sink)?;
        let outcome = sink.send(&client, realm.authority())?;

        if !outcome.status.is_success() {
            return Err(RegistryError::TokenEndpointRefused {
                status: outcome.status.as_u16(),
            });
        }

        // The grant is read before the token is, and narrowing happens before
        // anything can spend it. A token for `repository:x:pull,push` is
        // already in memory at this point, but nothing has been built with it,
        // and the only way to get to it from here is through a scope that
        // covers the operation.
        let granted = granted_scope_from_token_response(&outcome.body)?;
        narrow(&asked, &granted)?;

        let value: Value =
            serde_json::from_str(&outcome.body).map_err(|_| RegistryError::NoTokenInResponse)?;
        let token = value
            .get("token")
            .or_else(|| value.get("access_token"))
            .and_then(Value::as_str)
            .ok_or(RegistryError::NoTokenInResponse)?;

        Ok(Zeroizing::new(token.to_string()))
    }
}

/// The result of one completed request.
struct Outcome {
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

/// `/v2/<repository>/manifests/<reference>`, from parts that cannot step
/// outside themselves.
fn manifest_path(repository: &RepositoryName, reference: &ImageReference) -> String {
    format!(
        "/v2/{}/manifests/{}",
        repository.as_str(),
        reference.as_str()
    )
}

/// The token endpoint's URL, with the service and the scope this side asked
/// for.
///
/// The scope in the query is [`scope_to_request`]'s, never
/// [`BearerChallenge::requested_scope`]'s. This is the second place the same
/// decision is made, and it is made in code rather than by reading the
/// challenge because the query string is what the token endpoint sees.
fn token_url(
    client: &PinnedClient,
    realm: &Realm,
    service: Option<&str>,
    asked: &RegistryScope,
) -> Result<url::Url, TransportError> {
    let mut url = client.url(realm.resolved(), realm.path())?;
    {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in token_query(service, asked) {
            pairs.append_pair(&name, &value);
        }
    }
    Ok(url)
}

/// The token request's query, as the pairs it will be written from.
///
/// Split out from [`token_url`] so the decision can be read without a URL and
/// without a socket, because the decision is the whole of this module's
/// argument and it is worth a row that does not need one.
fn token_query(service: Option<&str>, asked: &RegistryScope) -> Vec<(String, String)> {
    let mut query = Vec::new();
    if let Some(service) = service {
        query.push(("service".to_string(), service.to_string()));
    }
    query.push(("scope".to_string(), asked.as_str()));
    query
}

/// Builds one request, with the bearer attached only when there is one.
///
/// The URL is composed rather than taken from a `ResolvedAudience` because
/// there is no audience to compose it from: the client is already pinned to the
/// addresses `resolve_and_pin` vetted, and the host in the URL only decides
/// which of them the TLS handshake and the `Host` header name. Both halves come
/// from an `Authority` this side canonicalized and a path this side built out
/// of checked parts.
fn build_request(
    client: &PinnedClient,
    registry: &ResolvedAudience,
    method: reqwest::Method,
    path: &str,
    body: Option<&[u8]>,
    token: Option<&str>,
) -> Result<reqwest::blocking::Request, TransportError> {
    let url = client.url(registry, path)?;
    let mut builder = client.client().request(method, url);
    if let Some(token) = token {
        builder = builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(body) = body {
        builder = builder.body(body.to_vec());
    }
    builder
        .build()
        .map_err(|e| TransportError::InvalidUrl(e.to_string()))
}

/// Sends one request and reads the whole answer.
///
/// The status is kept rather than collapsed: the `401` is a step in the
/// protocol here, not an error, and a client that turned it into one could
/// never read a challenge.
fn send(
    client: &PinnedClient,
    request: reqwest::blocking::Request,
    audience: &ResolvedAudience,
) -> Result<reqwest::blocking::Response, TransportError> {
    client.client().execute(request).map_err(|_| {
        // Deliberately not the reqwest error: its `Display` can echo the URL
        // and its `Debug` can include the request, and a request carries the
        // header this module exists to keep unnamed.
        TransportError::RequestFailed {
            audience: audience.authority.to_string(),
            reason: "the registry request could not be completed".to_string(),
        }
    })
}

/// Turns a completed request into either bytes or the error that names what was
/// expected.
fn finish(
    mut response: reqwest::blocking::Response,
    operation: RegistryOperation,
) -> Result<Outcome, RegistryError> {
    let expected = match operation {
        RegistryOperation::Pull => 200,
        RegistryOperation::Push => 201,
    };
    if response.status().as_u16() != expected {
        return Err(RegistryError::UnexpectedStatus {
            status: response.status().as_u16(),
            expected,
        });
    }
    let headers = response.headers().clone();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut response, &mut body).map_err(|e| {
        TransportError::RequestFailed {
            audience: "the registry".to_string(),
            reason: e.to_string(),
        }
    })?;
    Ok(Outcome { headers, body })
}

/// The token request, and what it produced.
///
/// The credential is used exactly once, to build one header, and the request
/// built from it is dropped when this scope ends. What survives is the body,
/// which is held in a [`Zeroizing`] because it contains a token.
struct TokenAttempt {
    pending: Option<reqwest::blocking::RequestBuilder>,
    request: Option<reqwest::blocking::Request>,
}

/// What the token endpoint said, read in one pass.
///
/// The status is carried alongside the body rather than left on a
/// `reqwest::Response` because the body has to be read to be checked and a
/// response whose body is already consumed is a response nobody can look at
/// again. Rebuilding one from parts is not possible, and making a second
/// request to find out how the first went is not an option this module has.
struct TokenOutcome {
    status: reqwest::StatusCode,
    body: Zeroizing<String>,
}

impl TokenAttempt {
    fn new(pending: reqwest::blocking::RequestBuilder) -> Self {
        Self {
            pending: Some(pending),
            request: None,
        }
    }

    fn send(
        &mut self,
        client: &PinnedClient,
        audience: &Authority,
    ) -> Result<TokenOutcome, TransportError> {
        let request = self
            .request
            .take()
            .ok_or_else(|| TransportError::RequestFailed {
                audience: audience.to_string(),
                reason: "the token request was never given a credential".to_string(),
            })?;
        let mut response =
            client
                .client()
                .execute(request)
                .map_err(|_| TransportError::RequestFailed {
                    audience: audience.to_string(),
                    reason: "the token request could not be completed".to_string(),
                })?;
        let status = response.status();
        let mut body = String::new();
        std::io::Read::read_to_string(&mut response, &mut body).map_err(|e| {
            TransportError::RequestFailed {
                audience: audience.to_string(),
                reason: e.to_string(),
            }
        })?;
        Ok(TokenOutcome {
            status,
            body: Zeroizing::new(body),
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod wire_tests;

impl SecretSink for TokenAttempt {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        let header = basic_header(secret)?;
        let builder = self.pending.take().ok_or_else(|| {
            SecretError::Unavailable("the token request was already assembled".to_string())
        })?;
        self.request = Some(
            builder
                .header(reqwest::header::AUTHORIZATION, &*header)
                .build()
                .map_err(|_| {
                    SecretError::Unavailable(
                        "the authorization header could not be assembled".into(),
                    )
                })?,
        );
        Ok(())
    }
}

/// `Basic base64(<credential>)`, scrubbed when the scope ends.
///
/// The registry password is what the vault holds, and the spec has it go over
/// the wire base64-encoded inside a `Basic` header. The encoding is not
/// protection; the `Zeroizing` is what removes the copy from freed memory.
fn basic_header(secret: &[u8]) -> Result<Zeroizing<String>, SecretError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    Ok(Zeroizing::new(format!("Basic {encoded}")))
}
