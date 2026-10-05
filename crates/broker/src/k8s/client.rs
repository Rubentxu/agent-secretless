//! R2.D.3.1 — the transport that actually opens the socket.
//!
//! [`request`](super::request) builds a path and [`port`](super::port) lends a
//! token. Neither of them sends anything. This is the join, and it is where the
//! property either holds or does not, because this is the first and only place
//! the token becomes bytes on a wire.
//!
//! # The difference from AWS, which is the whole reason this file is careful
//!
//! [`SigV4Signer`](crate::aws::sigv4::SigV4Signer) turns the AWS long-lived key
//! into a *signature*, and a signature is not the secret. Keeping the signed
//! request around is harmless, so the sink AWS lends into can hand its signer
//! back to a caller that then builds the request and holds it for as long as
//! it likes.
//!
//! A Kubernetes bearer token has no such transform. `Authorization: Bearer
//! <token>` **is** the credential: anything that can read the header can act as
//! the ServiceAccount, and the header is the only thing standing between a
//! leaked buffer and a pod that gets to create pods. So the header here is
//! built inside the sink's `accept`, handed out exactly once, and wiped on
//! drop — and the type that holds it is a sink, not a request builder, so
//! there is no API on which to ask for it twice.
//!
//! # What is *not* claimed here
//!
//! **`Zeroizing` covers ASV's copies, and only ASV's copies.** When the header
//! is handed to `reqwest`, the HTTP stack copies the bytes into its own request
//! buffer, and that buffer is freed rather than wiped when the request is
//! dropped. Making that copy wipeable would mean owning the HTTP stack. The
//! honest statement is therefore: *the token has one lifetime inside ASV — the
//! send — and one lifetime outside it, in a buffer this crate does not
//! control.* A product that needs the second one gone needs a transport that
//! can promise it, and that is a separate decision rather than a line of
//! comment.
//!
//! The same honesty applies to the reply. [`K8sReply`] carries a body, capped
//! but present, and *whether a body may contain a secret is not this file's
//! decision*. It is the operation's: a `Secret` read has to drop `data` before
//! answering, and that is R2.D.3.2's property to hold, not this one's.
//!
//! # Redirects
//!
//! A bearer token must never reach a second origin. This client follows
//! same-origin hops only, through
//! [`PinnedClient::follow_same_origin`](asv_connector_http::transport::PinnedClient::follow_same_origin),
//! and re-lends the token from the port on **every** hop rather than reusing
//! the previous one. That is stricter than it looks: it means a redirect cannot
//! even be served from a copy the client still holds, because by the time the
//! next attempt runs the previous sink is already dropped and zeroized.

use std::time::Duration;

use asv_connector_http::transport::{
    AddressPolicy, PinnedClient, Redirect, ResolvedAudience, TransportError,
};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use zeroize::Zeroizing;

use super::request::{ApiError, ApiRequest};
use super::port::MAX_TOKEN_BYTES;

/// The largest reply body this client will read into memory.
///
/// Not a politeness limit. An API server that answers a `get` with a body
/// larger than this has either been substituted for or is malfunctioning, and
/// both are cases where buffering the whole thing is the wrong move.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// What one attempt concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sReply {
    /// The status the origin answered with.
    pub status: u16,
    /// The body, read up to [`MAX_REPLY_BYTES`].
    pub body: Vec<u8>,
}

impl K8sReply {
    /// Whether the origin reported success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Why a Kubernetes request could not be completed.
///
/// Grouped by *which decision stopped it*, because that is the thing a flat
/// message destroys: a refused path is a caller's bug, a refused transport is
/// a threat or a misconfiguration, a refused credential is a mount that moved,
/// and a refused body is an origin that is not the one that was pinned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum K8sClientError {
    /// The request could not be built. Always the caller's input.
    #[error("the Kubernetes request is not well-formed: {0}")]
    Request(#[from] ApiError),

    /// The transport refused: a private peer, a cross-origin redirect, a TLS
    /// failure, a body too large. These are the rows that keep a bearer token
    /// from reaching where it was not lent for.
    #[error("the Kubernetes transport refused: {0}")]
    Transport(#[from] TransportError),

    /// The token could not be borrowed, or the header could not be built from
    /// it.
    #[error("the Kubernetes credential could not be lent: {0}")]
    Secret(#[from] SecretError),

    /// The client was asked to do something impossible before any socket: a
    /// timeout that is not positive, or a reply cap that is zero.
    #[error("the Kubernetes client is misconfigured: {0}")]
    Misconfigured(String),
}

/// Holds the assembled `Authorization` header, and gives it away once.
///
/// The whole reason this is a sink rather than a helper that returns a
/// `HeaderValue` is the `take`: the header is *consumed* by the send, so
/// "send the request, then log the request" is not a sequence this type can
/// express, and neither is "send it to a second address".
struct BearerSink {
    header: Option<Zeroizing<Vec<u8>>>,
    /// The scheme name is fixed; the port has already refused a token large
    /// enough to matter and a token with a control character in it, which is
    /// what would let the prefix and the token be read as two headers.
    scheme: &'static [u8],
}

impl SecretSink for BearerSink {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        // A `Zeroizing<Vec<u8>>` rather than a `String`: the port already
        // refuses control characters, so the token is well-formed, but nothing
        // here needs it to be UTF-8 and refusing a valid token over an encoding
        // question would be a refusal for the wrong reason.
        let mut header = Vec::with_capacity(self.scheme.len() + 1 + secret.len());
        header.extend_from_slice(self.scheme);
        header.push(b' ');
        header.extend_from_slice(secret);
        // Overwrite rather than assign: a sink whose `accept` is somehow called
        // twice must not leave the first header alive in the old allocation.
        if let Some(previous) = self.header.take() {
            drop(previous);
        }
        self.header = Some(Zeroizing::new(header));
        Ok(())
    }
}

impl BearerSink {
    fn new() -> Self {
        Self {
            header: None,
            scheme: b"Bearer",
        }
    }

    /// Hands the header over, exactly once.
    fn take(&mut self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        self.header
            .take()
            .ok_or_else(|| SecretError::Unavailable("the port lent nothing to sign".into()))
    }
}

/// Sends Kubernetes requests to one pinned API server.
///
/// Holds the client and the audience, and nothing secret. Constructing it
/// performs the only DNS lookup the request will ever use, because the client
/// pins the answer and the HTTP stack never re-resolves the name.
pub struct K8sClient {
    transport: PinnedClient,
    audience: ResolvedAudience,
    origin: url::Url,
}

impl K8sClient {
    /// Builds a client for an already-resolved audience.
    ///
    /// `timeout` bounds each attempt. `None` is accepted and means unbounded,
    /// which is honest rather than convenient: a caller that has no deadline of
    /// its own gets a client with none, and the transport documents why that is
    /// the worst failure available for a broker.
    pub fn new(
        audience: ResolvedAudience,
        policy: AddressPolicy,
        timeout: Option<Duration>,
    ) -> Result<Self, K8sClientError> {
        Self::assemble(audience, policy, timeout, &[])
    }

    /// Builds a client that additionally trusts `extra_roots`.
    ///
    /// This exists for the same reason and with the same rule as
    /// [`PinnedClient::build_with_roots`]: a test needs to point a pinned
    /// client at a real local origin and still exercise genuine certificate
    /// verification, and the alternative — `danger_accept_invalid_certs` —
    /// would prove that the code path runs, not that the certificate was
    /// checked. Production calls [`K8sClient::new`], which passes no extra
    /// roots and therefore trusts exactly what the platform trusts.
    pub fn new_with_roots(
        audience: ResolvedAudience,
        policy: AddressPolicy,
        timeout: Option<Duration>,
        extra_roots: &[reqwest::Certificate],
    ) -> Result<Self, K8sClientError> {
        Self::assemble(audience, policy, timeout, extra_roots)
    }

    fn assemble(
        audience: ResolvedAudience,
        policy: AddressPolicy,
        timeout: Option<Duration>,
        extra_roots: &[reqwest::Certificate],
    ) -> Result<Self, K8sClientError> {
        let transport = PinnedClient::build_timed(&audience, policy, extra_roots, timeout)?;
        let origin = transport.url(&audience, "/")?;
        Ok(Self {
            transport,
            audience,
            origin,
        })
    }

    /// The audience this client will only ever talk to.
    pub fn authority(&self) -> &str {
        self.audience.authority.as_str()
    }

    /// Sends one request, borrowing the token for the send and nothing longer.
    ///
    /// The token is re-lent from the port on every redirect hop, so a redirect
    /// cannot be served from a copy this client is still holding.
    pub fn send(
        &self,
        port: &dyn SecretPort,
        credential: &str,
        request: &ApiRequest<'_>,
    ) -> Result<K8sReply, K8sClientError> {
        let path = request.path()?;
        let url = self.transport.url(&self.audience, &path)?;
        let method = method_for(request.verb);
        let origin = self.origin.clone();

        // The closure is the only place the token exists outside the port, and
        // it exists there for exactly one attempt. Returning `Hop` ends this
        // scope, which drops the sink and wipes the header before the next
        // attempt re-lends.
        let reply = PinnedClient::follow_same_origin(
            url,
            &origin,
            |target| -> Result<Redirect<K8sReply>, K8sClientError> {
            let mut sink = BearerSink::new();
            port.lend(credential, &mut sink)?;
            let header = sink.take()?;

            // A token the port accepted that the HTTP stack will not take is a
            // credential problem, not a transport one, and saying so keeps the
            // operator looking at the mount rather than at the network.
            let value = reqwest::header::HeaderValue::from_bytes(&header).map_err(|_| {
                SecretError::Unavailable(
                    "a token this port accepted is not a header value the HTTP stack will send".into(),
                )
            })?;
            // `builder` is dropped with this scope too, so the copy the HTTP
            // stack made of the header does not outlive the attempt either.
            let response = self
                .transport
                .client()
                .request(method.clone(), target.clone())
                .header(reqwest::header::AUTHORIZATION, value)
                .send()
                .map_err(|error| TransportError::RequestFailed {
                    audience: self.audience.authority.to_string(),
                    reason: error.to_string(),
                })?;

            let status = response.status().as_u16();
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| target.join(value).ok());

            if let Some(next) = next {
                if status >= 300 && status < 400 {
                    return Ok(Redirect::Hop(next));
                }
            }

            let mut body = Vec::new();
            read_capped(response, self.audience.authority.to_string(), &mut body)?;
                Ok(Redirect::Done(K8sReply { status, body }))
            },
        )?;
        Ok(reply)
    }
}

/// The HTTP method an operation sends.
///
/// This repeats [`Verb::method`](super::request::Verb::method) on purpose, and
/// the repetition is pinned by a row in this module rather than left to drift:
/// `Verb::method` is a `&'static str` and re-parsing it would put an
/// `unwrap`/`expect` on the one path where a panic means a token is dropped
/// mid-flight. A total match over the four variants cannot fail, and a test
/// asserts the two mappings agree so the duplication stays a checked one.
fn method_for(verb: super::request::Verb) -> reqwest::Method {
    match verb {
        super::request::Verb::Get | super::request::Verb::List => reqwest::Method::GET,
        super::request::Verb::Create => reqwest::Method::POST,
        super::request::Verb::Delete => reqwest::Method::DELETE,
    }
}

/// Reads a body, refusing rather than truncating when it is too large.
///
/// Truncating would be worse than refusing: a caller parsing a truncated JSON
/// document gets a parse error about the document, not about the origin having
/// sent something too big to be the API server.
fn read_capped(
    mut response: reqwest::blocking::Response,
    audience: String,
    into: &mut Vec<u8>,
) -> Result<(), K8sClientError> {
    use std::io::Read;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = response.read(&mut chunk).map_err(|error| {
            TransportError::RequestFailed {
                audience: audience.clone(),
                reason: error.to_string(),
            }
        })?;
        if read == 0 {
            return Ok(());
        }
        if into.len() + read > MAX_REPLY_BYTES {
            return Err(TransportError::ResponseTooLarge { audience }.into());
        }
        into.extend_from_slice(&chunk[..read]);
    }
}

/// The bound the port enforces, re-exported so an operation can name it in a
/// refusal instead of inventing its own number.
pub const TOKEN_LIMIT: usize = MAX_TOKEN_BYTES;

#[cfg(test)]
mod tests;
