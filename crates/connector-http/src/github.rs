//! Semantic GitHub operations (M4-R9, design v2 D2, D8).
//!
//! The surface here is deliberately not `http.request`. A generic HTTP escape
//! hatch would let an agent aim a brokered credential at any path on any
//! approved host, which is most of the way back to holding the credential
//! itself. Instead there are three named operations, each with a request shape
//! the broker builds, and each returning only the fields the broker is willing
//! to forward (M4-R1: a surrogate is not a credential, and neither is the
//! answer).
//!
//! # The credential never gets a name
//!
//! [`SecretPort::lend`] lends the secret to a closure and takes it
//! back afterwards. That is the whole security argument of this module, and it
//! is structural rather than conventional:
//!
//! - No method here returns secret material, so there is nothing to store, log
//!   or forward.
//! - The header is attached inside the closure, per attempt, so a hop the
//!   origin check rejects never sees a header at all (D7, M4-R5).
//! - Nothing here formats a request or response body into a log. The provider's
//!   body can contain anything upstream chose to put there, and an audit log is
//!   a place secrets end up by accident, so there is no such code path.

use std::io::Read;
use std::sync::Arc;

use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use asv_domain::Authority;

use crate::transport::{
    resolve_and_pin, AddressPolicy, PinnedClient, Redirect, ResolvedAudience, TransportError,
};

/// The port through which the broker lends a credential to one request.
///
/// Implemented by the secret-bearing process, backed by the vault's
/// `with_secret`. Declaring it here rather than taking a `&VaultStore` is what
/// keeps `asv-vault` out of this crate's dependency graph: a connector that
/// could open the vault itself would be a second place where secret material
/// can be reached for, and D2's one-way dependency would be a lie.
/// `Send + Sync` because the broker now hands this port to the CONNECT
/// listener, which runs one tunnel per `spawn_blocking` thread.
///
/// The bounds are not decoration: without them `Arc<dyn SecretPort>` is neither
/// `Send` nor `Sync`, and the only ways to satisfy a `ConnectionHandler` would
/// be to wrap every implementation in a lock at the edge or to run tunnels on
/// one thread. Every implementation in the tree already holds `Arc`s and
/// `Mutex`es, so the bound describes what the port has always been in
/// practice; it is written down now that something requires it.
pub trait SecretPort: Send + Sync {
    /// Lends the credential named by `credential` to `sink`, and takes it back.
    ///
    /// The `sink` shape is what makes this a trait object. A method returning
    /// an arbitrary `T` is generic, and a generic method makes a trait
    /// non-object-safe, so `Arc<dyn SecretPort>` would not compile and the
    /// whole dependency-injection shape would collapse into generics threaded
    /// through the broker. A `&mut dyn SecretSink` keeps the port dyn-safe
    /// without giving up the guarantee: `accept` receives borrowed bytes valid
    /// only for the call, so there is still nothing a caller can store.
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError>;

    /// Drops anything this port is holding that was *derived* from
    /// `credential`, so that a deletion stops being served immediately.
    ///
    /// # Why it is required, with no default
    ///
    /// A port that holds a derived secret — an exchanged token, a minted
    /// short-lived credential — is serving authority after the operator was
    /// told the credential is gone. `DeleteCredential` removes the vault record
    /// and revokes the session's surrogates, but a cache inside the port is
    /// invisible to both. So the broker has to be able to reach it, and the
    /// only handle it holds is `Arc<dyn SecretPort>`: the concrete type is
    /// erased behind a `RoutingSecretPort`, which is exactly why this call was
    /// unreachable when the gap was found.
    ///
    /// A `forget` with a default no-op would have been one line instead of this
    /// paragraph, and it would have left the property resting on every future
    /// port author remembering to override it. Requiring it moves the guarantee
    /// into the type system: **a new `SecretPort` does not compile until it has
    /// said what it does with derived secrets.** An implementation with nothing
    /// derived implements it as an explicit no-op with a reason, which is
    /// different from an implementation that never considered it.
    ///
    /// # What it is not
    ///
    /// This is not a network revocation, and a port must not pretend to be
    /// one. It is "stop answering from what I already hold", which bounds the
    /// window to nothing locally. A token the *provider* has already issued
    /// stays valid at the provider until it expires or is revoked there, and
    /// only the port's own cache is this port's to drop. A connector that needs
    /// a real provider-side revoke belongs behind a different operation.
    ///
    /// # Scope
    ///
    /// Deliberately the credential, and nothing else. Ending a *session* must
    /// not call this: the derived secret belongs to the credential, which
    /// outlives every session, and a session ending would otherwise silently
    /// re-exchange a token for a client that is still perfectly valid.
    fn forget(&self, credential: &str);
}

/// One use of a borrowed credential.
///
/// The sink is how a request gets built without the secret ever having a name
/// in the caller's scope: the port calls `accept`, the sink attaches a header
/// from the borrowed bytes, and by the time `lend` returns the bytes are gone.
pub trait SecretSink {
    /// Uses `secret` to do one thing. Returning an error aborts the attempt.
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError>;
}

/// Why a credential could not be lent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// `VaultError` is not in this crate's vocabulary: the port reports that a
    /// credential could not be unlocked and the connector decides what that
    /// means for the operation.
    #[error("no such credential: {0}")]
    NotFound(String),

    #[error("credential {0} could not be unlocked")]
    Unavailable(String),
}

/// The issues and releases this module speaks in.
///
/// Every field is built by the broker from a validated `repo` string, never
/// taken from the agent's request and concatenated in. `Display` is
/// deliberately absent: a path is assembled once, here, from parts that have
/// already been through [`validate_repo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoRef<'a> {
    owner: &'a str,
    repo: &'a str,
}

/// Why a `owner/repo` string was refused.
///
/// The message never echoes the input. A rejected repository string is
/// attacker-supplied and this ends up in an error the caller can see; putting
/// the hostile input back into the message turns an error report into a
/// reflected-content channel.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepoError {
    #[error("repository must be `owner/repo` with non-empty ASCII path components")]
    Malformed,

    #[error("repository component is longer than {0} characters")]
    ComponentTooLong(usize),
}

/// GitHub's own limits are the standard here: a repository name is at most 100
/// characters and may contain alphanumerics, `.`, `-` and `_`. The owner is
/// held to the same conservative rule rather than allowing anything GitHub
/// tolerates, because the goal is not to accept every repository GitHub has,
/// it is to make sure no character in this string can escape its path segment.
const MAX_COMPONENT: usize = 100;

/// Parses `owner/repo`, refusing anything that could change the request shape.
pub fn validate_repo(repo: &str) -> Result<RepoRef<'_>, RepoError> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    // Exactly one separator. `a/b/c` and `a` are both refused rather than
    // normalised, because a normalising parser is a parser whose behaviour
    // depends on how many times it has been called.
    if parts.next().is_some() || owner.is_empty() || name.is_empty() {
        return Err(RepoError::Malformed);
    }
    for component in [owner, name] {
        if component.len() > MAX_COMPONENT {
            return Err(RepoError::ComponentTooLong(MAX_COMPONENT));
        }
        if !component
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(RepoError::Malformed);
        }
    }
    // A component that is only dots would still parse, and `.` or `..` is a
    // path segment that means something to any layer that later re-reads this.
    if [owner, name].iter().any(|c| c.bytes().all(|b| b == b'.')) {
        return Err(RepoError::Malformed);
    }
    Ok(RepoRef { owner, repo: name })
}

impl RepoRef<'_> {
    /// The request path for a repository's issue `number`.
    ///
    /// `number` is a `u64` rendered with `Display`, so it cannot inject a
    /// separator; there is no string form of it that reaches this function.
    pub fn issue_path(&self, number: u64) -> String {
        format!("/repos/{}/{}/issues/{number}", self.owner, self.repo)
    }

    /// The request path for a repository's issues collection.
    pub fn issues_path(&self) -> String {
        format!("/repos/{}/{}/issues", self.owner, self.repo)
    }

    /// The request path for a repository's releases collection.
    pub fn releases_path(&self) -> String {
        format!("/repos/{}/{}/releases", self.owner, self.repo)
    }

    /// The `owner/repo` form, for error messages that need to name the target.
    pub fn label(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

/// Why a response body could not be turned into a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadFailure {
    TooLarge,
    Unreadable,
    NotJson,
}

/// Why a semantic operation could not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GithubError {
    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    Secret(#[from] SecretError),

    #[error("repository reference is not usable")]
    Repo(#[from] RepoError),

    /// The provider answered, but not with the shape this operation needs.
    ///
    /// This is distinct from a non-2xx, which is a [`TransportError`] because
    /// the request itself failed. A 200 that omits `state` succeeded as an HTTP
    /// exchange and failed as an operation, and collapsing the two would make
    /// "GitHub is down" and "GitHub sent something unexpected" indistinguishable
    /// to the caller.
    #[error("{audience} answered without {detail}")]
    Upstream { audience: String, detail: String },
}

/// The largest provider body this broker will hold.
///
/// A GitHub issue body is kilobytes. A megabyte is three orders of magnitude
/// past anything legitimate, and refusing beats truncating: a truncated field
/// is a field that looks like real data to the agent reading it.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// The three fields M4-R9 promises for a read, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSummary {
    pub title: String,
    pub body: String,
    pub state: String,
}

/// The identity of a created issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedIssue {
    pub number: u64,
    pub url: String,
}

/// The identity of a created release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedRelease {
    pub tag: String,
    pub url: String,
}

/// Talks to GitHub on behalf of one session.
///
/// One instance per operation, matching D1: the client is built from a
/// freshly-vetted address list, so it cannot outlive the pinning decision that
/// justified it.
pub struct GithubClient {
    audience: Authority,
    port: u16,
    policy: AddressPolicy,
    roots: Vec<reqwest::Certificate>,
    secrets: Arc<dyn SecretPort>,
    /// A pre-resolved audience, set only by [`GithubClient::pinned_to`]. When
    /// present it replaces the per-operation DNS lookup, and it is still vetted
    /// by `policy` inside `PinnedClient::build_with_roots`.
    resolved: Option<ResolvedAudience>,
}

impl GithubClient {
    /// Builds a client for `audience`, lending credentials from `secrets`.
    pub fn new(
        audience: Authority,
        port: u16,
        policy: AddressPolicy,
        secrets: Arc<dyn SecretPort>,
    ) -> Self {
        Self {
            audience,
            port,
            policy,
            roots: Vec::new(),
            secrets,
            resolved: None,
        }
    }

    /// Builds a client for an audience whose address is already known.
    ///
    /// Production goes through [`GithubClient::new`], which resolves DNS per
    /// operation. This entry point exists for a test that points the client at a
    /// local origin: resolving `api.github.com` for real would reach the actual
    /// GitHub, which is not what a unit test means to do and not something a CI
    /// box should attempt.
    ///
    /// The vetting is not skipped. The address list still goes through
    /// [`PinnedClient::build_with_roots`] with `policy`, so a hand-built
    /// `ResolvedAudience` cannot smuggle a non-public address past the filter.
    pub fn pinned_to(
        resolved: ResolvedAudience,
        policy: AddressPolicy,
        secrets: Arc<dyn SecretPort>,
    ) -> Self {
        Self {
            audience: resolved.authority.clone(),
            port: resolved.port,
            policy,
            roots: Vec::new(),
            secrets,
            resolved: Some(resolved),
        }
    }

    /// Trusts extra certificate roots.
    ///
    /// Exists so a test can point a client at a real local origin and still
    /// exercise genuine certificate verification. Production never calls this,
    /// which is what keeps "we verify the certificate" a real claim rather than
    /// a shape that tests happen to fill.
    pub fn trusting(mut self, roots: Vec<reqwest::Certificate>) -> Self {
        self.roots = roots;
        self
    }

    /// Resolves, vets and pins the audience, right now.
    ///
    /// Per operation, not at construction: a client built earlier carries a
    /// DNS answer that is now stale, and M4-R4 constrains the address *at
    /// connect time*, which is a different statement from "it was public when
    /// the process started".
    fn pinned(&self) -> Result<(PinnedClient, ResolvedAudience), GithubError> {
        let resolved = match &self.resolved {
            Some(pre) => pre.clone(),
            None => resolve_and_pin(&self.audience, self.port, self.policy)?,
        };
        let client = PinnedClient::build_with_roots(&resolved, self.policy, &self.roots)?;
        Ok((client, resolved))
    }

    /// The absolute URL for `path` on the pinned audience.
    fn endpoint(&self, client: &PinnedClient, resolved: &ResolvedAudience, path: &str) -> Url {
        // `url` only fails on a malformed format string, and the format here is
        // built from a validated authority and a caller-built path.
        client
            .url(resolved, path)
            .expect("a validated authority and a built path always form a URL")
    }

    /// Issues one authenticated request, following at most
    /// [`PinnedClient::follow_same_origin`]'s same-origin hops.
    ///
    /// The credential is re-read from the port on every hop. That is not
    /// redundancy, it is the requirement: a hop the broker does not
    /// re-authenticate is a hop whose authentication it never checked, and D8
    /// wants the read per operation anyway.
    ///
    /// The attempt closure reports [`GithubError`] rather than
    /// [`TransportError`] so a lending failure keeps its own variant. A hop
    /// that cannot obtain a credential has not failed to reach the provider,
    /// and saying so as a transport error would be a small lie that costs the
    /// broker the ability to answer `NotFound` differently from `Unavailable`.
    fn send(
        &self,
        credential: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, GithubError> {
        let (client, resolved) = self.pinned()?;
        let origin = self.endpoint(&client, &resolved, "/");
        let url = self.endpoint(&client, &resolved, path);

        PinnedClient::follow_same_origin(url, &origin, |target| {
            // The builder carries no credential. It is built here, handed to
            // the port, and the port is what attaches the `Authorization`
            // header from bytes it lends for this one attempt.
            let mut builder = client
                .client()
                .request(method.clone(), target.clone())
                .header(reqwest::header::ACCEPT, "application/vnd.github+json");
            if let Some(payload) = &body {
                builder = builder.json(payload);
            }
            let mut sink = AuthenticatedAttempt {
                pending: Some(builder),
                request: None,
            };
            self.secrets.lend(credential, &mut sink).map_err(|source| {
                // The port's own reason is carried as a variant, not
                // flattened into a transport string. The broker picks the
                // IPC error code from this: "no such credential" and
                // "could not unlock" are different operator problems, and a
                // caller forced to parse `reason` to tell them apart is
                // one refactor away from losing the distinction.
                //
                // The credential's own name is dropped here, not just left
                // out of a message: `SecretError`'s `Display` embeds it.
                GithubError::Secret(match source {
                    SecretError::NotFound(_) => SecretError::NotFound(
                        "the credential this surrogate stands for is not in the vault".to_string(),
                    ),
                    _ => SecretError::Unavailable("the vault could not open it".to_string()),
                })
            })?;

            let response = sink.send(client.client(), self.audience.as_str())?;

            let status = response.status();
            if status.is_redirection() {
                // A redirection with no usable `Location` is a dead end, and it
                // says so. Falling through to the non-2xx path would report it as
                // "the request could not be completed", which is a different
                // failure and would send an operator looking in the wrong place.
                let next = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        GithubError::Transport(TransportError::RequestFailed {
                            audience: self.audience.to_string(),
                            reason: format!(
                                "the provider answered {} without a usable Location header",
                                status.as_u16()
                            ),
                        })
                    })?
                    .to_string();
                return target.join(&next).map(Redirect::Hop).map_err(|error| {
                    GithubError::Transport(TransportError::InvalidUrl(error.to_string()))
                });
            }

            let code = status.as_u16();
            // The body is read inside the redirect loop, so a read failure is
            // re-expressed as a `TransportError`: the wire completed and the
            // body is what was wrong with it. `TooLarge` has a variant of its
            // own precisely so the caller never has to recover it from a
            // string.
            let payload = self.read_body(response).map_err(|failure| match failure {
                ReadFailure::TooLarge => TransportError::ResponseTooLarge {
                    audience: self.audience.to_string(),
                },
                ReadFailure::Unreadable => TransportError::RequestFailed {
                    audience: self.audience.to_string(),
                    reason: "the response body could not be read".to_string(),
                },
                ReadFailure::NotJson => TransportError::RequestFailed {
                    audience: self.audience.to_string(),
                    reason: "the provider did not answer with JSON".to_string(),
                },
            })?;
            if !(200..300).contains(&code) {
                return Err(GithubError::Transport(TransportError::RequestFailed {
                    audience: self.audience.to_string(),
                    reason: format!("upstream answered {code}"),
                }));
            }
            Ok(Redirect::Done(payload))
        })
    }

    /// Reads a response body under a hard size cap.
    ///
    /// The cap is checked against `Content-Length` when the server offers it
    /// and again while reading, because a chunked response can lie about it or
    /// omit it entirely.
    ///
    /// The three failures are separate types rather than strings so the caller
    /// can map each one to its own error without parsing a message.
    fn read_body(&self, response: reqwest::blocking::Response) -> Result<Value, ReadFailure> {
        if response
            .content_length()
            .is_some_and(|declared| declared > MAX_RESPONSE_BYTES)
        {
            return Err(ReadFailure::TooLarge);
        }
        let mut buffer = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| ReadFailure::Unreadable)?;
        if buffer.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(ReadFailure::TooLarge);
        }
        // An empty body is legitimate for a 204, and is not an error.
        if buffer.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&buffer).map_err(|_| ReadFailure::NotJson)
    }

    /// Reads one issue, returning only the three promised fields.
    pub fn read_issue(
        &self,
        credential: &str,
        repo: &str,
        number: u64,
    ) -> Result<IssueSummary, GithubError> {
        let target = validate_repo(repo)?;
        let value = self.send(
            credential,
            reqwest::Method::GET,
            &target.issue_path(number),
            None,
        )?;
        let missing = |what: &str| GithubError::Upstream {
            audience: self.audience.to_string(),
            detail: what.to_string(),
        };
        let title = value
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("title"))?;
        let state = value
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("state"))?;
        Ok(IssueSummary {
            title: title.to_string(),
            // GitHub sends `"body": null` for an issue with no description.
            // Forwarding an empty string is a choice: the agent asked for a
            // body and there is none, and `""` says that without pretending the
            // field was absent.
            body: value
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            state: state.to_string(),
        })
    }

    /// Creates one issue.
    pub fn create_issue(
        &self,
        credential: &str,
        repo: &str,
        title: &str,
        body: &str,
    ) -> Result<CreatedIssue, GithubError> {
        let target = validate_repo(repo)?;
        // `json!` escapes the agent's text as a JSON string value, so a title
        // containing a quote or a newline is data, not structure.
        let payload = serde_json::json!({ "title": title, "body": body });
        let value = self.send(
            credential,
            reqwest::Method::POST,
            &target.issues_path(),
            Some(payload),
        )?;
        let number =
            value
                .get("number")
                .and_then(Value::as_u64)
                .ok_or_else(|| GithubError::Upstream {
                    audience: self.audience.to_string(),
                    detail: "number".to_string(),
                })?;
        Ok(CreatedIssue {
            number,
            url: value
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    /// Creates one release.
    pub fn create_release(
        &self,
        credential: &str,
        repo: &str,
        tag: &str,
        name: &str,
        body: &str,
    ) -> Result<CreatedRelease, GithubError> {
        let target = validate_repo(repo)?;
        let payload = serde_json::json!({ "tag_name": tag, "name": name, "body": body });
        let value = self.send(
            credential,
            reqwest::Method::POST,
            &target.releases_path(),
            Some(payload),
        )?;
        Ok(CreatedRelease {
            // The tag is echoed back from the request rather than read from the
            // response: GitHub does not always echo it, and an agent that
            // created `v1` needs to be told `v1`, not `null`.
            tag: tag.to_string(),
            url: value
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// One authenticated request, assembled from a borrowed credential.
///
/// This is the type that makes the credential unnamed. The port hands it the
/// secret for exactly as long as it takes to attach one header, and by the
/// time `lend` returns the borrowed bytes are back with the vault and the
/// request is complete.
struct AuthenticatedAttempt {
    /// The un-authenticated half, held only until the port lends a secret.
    /// `accept` takes it, attaches the header, and stores the finished request
    /// in `request` instead, so a builder that could be re-sent unauthenticated
    /// never survives the lending.
    pending: Option<reqwest::blocking::RequestBuilder>,
    /// The finished request. `None` until `accept` runs.
    request: Option<reqwest::blocking::Request>,
}

impl AuthenticatedAttempt {
    /// Sends the assembled request.
    ///
    /// Consumes it because `Request` is what `execute` takes, and a sink that
    /// has already been lent a secret is finished either way.
    fn send(
        self,
        client: &reqwest::blocking::Client,
        audience: &str,
    ) -> Result<reqwest::blocking::Response, TransportError> {
        let request = self.request.ok_or_else(|| {
            // A `Sink` with no request attached is a programming error, and
            // panicking here would turn it into a denial of service for the
            // broker process: any caller that can construct a Sink without
            // lending a credential first would take the whole broker down
            // instead of getting an error it could report. The invariant is
            // still checked, it is just checked by returning instead of by
            // aborting.
            TransportError::RequestFailed {
                audience: audience.to_string(),
                reason: "the sink was never given a credential".to_string(),
            }
        })?;
        // The reqwest error is deliberately dropped. Its `Display` can echo the
        // request URL and its `Debug` can include the request itself, and a
        // request carries the header this module exists to keep unnamed.
        client
            .execute(request)
            .map_err(|_| TransportError::RequestFailed {
                audience: audience.to_string(),
                reason: "the authenticated request could not be completed".to_string(),
            })
    }
}

impl SecretSink for AuthenticatedAttempt {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        let header = authorization_header(secret)?;
        // `header` takes the builder by value and returns a new one, which is
        // why the builder is a field rather than something built here: the
        // un-authenticated request is assembled by the caller, and this only
        // ever adds the one header that makes it authenticated.
        let builder = self
            .pending
            .take()
            .ok_or_else(|| SecretError::Unavailable("the request was already assembled".into()))?;
        self.request = Some(
            builder
                .header(reqwest::header::AUTHORIZATION, &*header)
                .build()
                .map_err(|_| {
                    SecretError::Unavailable(
                        "the authorization header could not be assembled".to_string(),
                    )
                })?,
        );
        Ok(())
    }
}

/// The `Authorization` header value, built from borrowed secret bytes and
/// scrubbed when this scope ends.
///
/// A token left in freed heap memory is a token that can turn up in a core
/// dump, a `/proc/pid/mem` read, or an unrelated bug that dumps a buffer it
/// should not have. The wrapper costs one allocation and removes that class of
/// accident.
fn authorization_header(secret: &[u8]) -> Result<Zeroizing<String>, SecretError> {
    let token = std::str::from_utf8(secret).map_err(|_| {
        SecretError::Unavailable("the stored credential is not valid UTF-8".to_string())
    })?;
    Ok(Zeroizing::new(format!("token {token}")))
}

#[cfg(test)]
mod tests;
