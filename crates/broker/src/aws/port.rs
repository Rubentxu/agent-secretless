//! The cache in front of `sts:AssumeRole` — R2.C.2.b, the port.
//!
//! # What this caches, and what it refuses to be
//!
//! An AWS session is **three** values that only mean anything together: the
//! access key id, the secret access key and the session token. Sign one request
//! with two of them and the provider answers `InvalidClientTokenId` or
//! `SignatureDoesNotMatch`, and neither names the mistake.
//!
//! The `SecretPort` trait this tree already has hands over **one** `&[u8]`, and
//! its only consumer in this repository builds an HTTP `Authorization` header
//! out of it. So [`AwsSecretPort::lend`] **refuses**, and the refusal says why:
//! an AWS session served through the single-value sink would end up in a header
//! shaped for a bearer token, and the two are not interchangeable. The port still
//! implements `SecretPort` — which is what makes `forget` mandatory on it and
//! puts it behind the same deletion path as every other derived secret — and the
//! one method a caller actually uses is [`AwsSecretPort::lend_session`], whose
//! sink takes all three or nothing.
//!
//! That is a deliberate refusal rather than an inconvenience, and it is
//! structural: there is no conversion from three values to the one the shared
//! sink wants, so nobody can add one without writing it.
//!
//! # The margin rule, and the bug it hides
//!
//! A session is served from the cache only if it outlives the caller's margin.
//! When a session is minted, its lifetime is capped by what the role allows, so
//! **a margin at or above the lifetime means nothing is ever served from the
//! cache** and every call re-mints. R2.B found that on the OAuth2 port, where it
//! had been silent; the same trap is here.
//!
//! The port cannot *refuse* it, because the lifetime is the role's and the role
//! is only consulted at mint time. What it can do is refuse to hide it, and
//! that is [`AwsSecretPort::serve_for`]: the arithmetic that decides how long a
//! session is served for is one named function whose answer for a degenerate
//! configuration is `Duration::ZERO` rather than a negative number nobody
//! notices. The configuration is visible; the symptom is not left to a caller
//! to discover as latency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use asv_connector_http::{SecretError, SecretPort, SecretSink};

use super::client::{StsClient, StsClientError};
use super::sts::{AwsSecretSink, AwsSession};

/// One use of a session's three signing values is
/// [`AwsSecretSink`], which R2.C.2.a already defines
/// for exactly this: it is what `AwsSession::with_signing_values` takes, so
/// declaring a second shape here would have been a second way for three values
/// to leave a session.

/// A client this port asks for a session.
///
/// A trait rather than `StsClient` so the cache rows can count the mints without
/// a socket, and so a second provider shape can be added without touching the
/// cache. The production implementation is `StsClient`, adapted by
/// [`ClientExchange`].
pub trait SessionExchange: Send + Sync {
    fn exchange(&self, credential: &str, now: SystemTime) -> Result<AwsSession, StsClientError>;
}

/// Adapts a [`StsClient`] plus a `SecretPort` into a [`SessionExchange`].
///
/// This is where the long-lived key is borrowed, and it is the *only* place: the
/// cache above never sees it, and neither does anything downstream of a minted
/// session.
pub struct ClientExchange {
    client: Arc<StsClient>,
    long_lived: Arc<dyn SecretPort>,
}

impl ClientExchange {
    pub fn new(client: Arc<StsClient>, long_lived: Arc<dyn SecretPort>) -> Self {
        Self { client, long_lived }
    }
}

impl SessionExchange for ClientExchange {
    fn exchange(&self, credential: &str, now: SystemTime) -> Result<AwsSession, StsClientError> {
        self.client
            .assume_role(self.long_lived.as_ref(), credential, now)
    }
}

/// Caches short-lived AWS sessions and serves them until they stop being worth
/// spending.
pub struct AwsSecretPort {
    exchange: Arc<dyn SessionExchange>,
    cache: Mutex<HashMap<String, Arc<AwsSession>>>,
    margin: Duration,
}

impl std::fmt::Debug for AwsSecretPort {
    /// Names what is cached without naming what it is.
    ///
    /// The credential ids are vault names, and an operator reading a receipt
    /// needs them — a count of one is not actionable. The sessions behind them
    /// are three values each, so this prints the ids and not the values; a
    /// derived `Debug` here would put a secret access key in a log line, and
    /// `Debug` gets called by assertion failures, so that is a leak one `{:?}`
    /// away from happening.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSecretPort")
            .field("margin", &self.margin)
            .field("cached", &self.cached())
            .finish()
    }
}

impl AwsSecretPort {
    /// The margin below which a cached session is refused.
    ///
    /// Sixty seconds: a session that expires while a request is being signed
    /// fails at the provider with a name that does not point here, so the cache
    /// gives up the session before that rather than after.
    pub const DEFAULT_MARGIN: Duration = Duration::from_secs(60);

    pub fn new(exchange: Arc<dyn SessionExchange>) -> Self {
        Self {
            exchange,
            cache: Mutex::new(HashMap::new()),
            margin: Self::DEFAULT_MARGIN,
        }
    }

    /// Sets the margin.
    ///
    /// **It cannot refuse a margin that would make the cache useless, and this
    /// says why instead of pretending otherwise.** How long a session lives is
    /// whatever the role allows, and the role is only consulted when a session
    /// is minted — so at construction time there is no lifetime to compare a
    /// margin against, and a check here would be a check against nothing.
    /// Pretending otherwise is how the OAuth2 port's silent case happened: a
    /// constructor that validated, an arithmetically degenerate configuration,
    /// and a latency profile nobody noticed until an operator asked why STS was
    /// slow.
    ///
    /// What the port can do instead is make the arithmetic public in
    /// [`Self::serve_for`], so the caller configuring this can see the
    /// degenerate case before it happens and the caller at runtime can read it
    /// off the same function. `a_margin_that_swallows_the_session_makes_every_
    /// lend_mint_again` pins what it looks like when it does happen.
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin;
        self
    }

    /// How long a session of lifetime `lifetime` is actually served for.
    ///
    /// **`Duration::ZERO` when the margin swallows the whole lifetime.** That is
    /// the silent case R2.B found on the OAuth2 port: a margin at or above the
    /// lifetime does not make the port refuse, it makes every call re-mint, and
    /// nothing fails — it just gets slower and depends on STS for every request.
    /// Returning zero makes the caller able to notice, and
    /// `a_margin_above_the_lifetime_serves_nothing_and_says_so` pins it.
    pub fn serve_for(lifetime: Duration, margin: Duration) -> Duration {
        lifetime.checked_sub(margin).unwrap_or(Duration::ZERO)
    }

    /// The credentials this port holds something for.
    pub fn cached(&self) -> Vec<String> {
        self.cache
            .lock()
            .map(|cache| {
                let mut ids: Vec<String> = cache.keys().cloned().collect();
                ids.sort();
                ids
            })
            .unwrap_or_default()
    }

    /// Lends the three signing values of the session for `credential`, minting
    /// one first if the cache cannot serve.
    ///
    /// The mint happens under no lock: the cache lock is only held to read and
    /// write the map, so a slow exchange does not block every other credential.
    /// That is a deliberate trade — two concurrent mints for the same credential
    /// are possible, and both are valid sessions, so the cost is one extra
    /// request rather than a lock held across a network call.
    pub fn lend_session(
        &self,
        credential: &str,
        now: SystemTime,
        sink: &mut dyn AwsSecretSink,
    ) -> Result<(), StsClientError> {
        if let Some(cached) = self.usable(credential, now) {
            return Self::hand_over(&cached, sink);
        }
        let minted = Arc::new(self.exchange.exchange(credential, now)?);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(credential.to_string(), minted.clone());
        }
        // The caller is lent from the very session that was cached, not a copy:
        // `AwsSession` has no `Clone` and no public getter for the two secret
        // fields precisely so that a cache cannot hand the same values out twice
        // by duplicating them. The `Arc` is a handle, not a copy.
        Self::hand_over(&minted, sink)
    }

    /// Moves a session's three values into `sink` and takes them back.
    fn hand_over(
        session: &AwsSession,
        sink: &mut dyn AwsSecretSink,
    ) -> Result<(), StsClientError> {
        session
            .with_signing_values(sink)
            .map_err(StsClientError::Request)
    }

    /// The cached session for `credential`, if it is still worth spending.
    fn usable(&self, credential: &str, now: SystemTime) -> Option<Arc<AwsSession>> {
        let cache = self.cache.lock().ok()?;
        let cached = cache.get(credential)?;
        if cached.usable_at(now, self.margin) {
            return Some(cached.clone());
        }
        None
    }
}

impl SecretPort for AwsSecretPort {
    /// **Refuses, always.** See the module docs: the single-value sink's only
    /// consumer builds a bearer header, and an AWS session has no business in
    /// one. This is a structural refusal rather than a missing feature — there
    /// is no conversion to offer.
    fn lend(&self, _credential: &str, _sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        Err(SecretError::Unavailable(
            "an AWS session is three values and is served through lend_session; \
             the single-value sink builds a bearer header and must not be handed \
             a session token"
                .into(),
        ))
    }

    /// Drops the cached session, so the next lend re-mints.
    ///
    /// Required on `SecretPort` with no default since R2.B, which is what makes
    /// this property structural rather than a convention: a `SecretPort` that
    /// derives something *must* say what it does with it. `DeleteCredential`
    /// removes the vault record and revokes the session's surrogates, and a
    /// cache invisible to both is a credential still being served after the
    /// operator was told it is gone.
    fn forget(&self, credential: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(credential);
        }
    }
}

#[cfg(test)]
mod tests;
