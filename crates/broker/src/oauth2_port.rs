//! The production consumer of M11: a [`SecretPort`] that lends a short-lived
//! access token instead of the long-lived client secret.
//!
//! # Why this is the increment and not another test
//!
//! `oauth2.rs` can be complete and still leave the milestone a *prototype*,
//! because a framework nothing calls has proved only that it agrees with
//! itself. The gate says so in one line — "Nothing in the runtime calls the
//! module yet" — and that line was true of an earlier delivery of this work
//! even after the issuer had been made real. It is no longer true, and the
//! reason is this file.
//!
//! # The shape of the claim
//!
//! The broker is the secret-bearing process. A vault credential labelled
//! `oauth2` is a *client secret*, and a client secret handed to an agent is the
//! failure M11 exists to prevent. This port sits between the vault and the
//! connector, and it is shaped so the swap is not a matter of care:
//!
//! ```text
//! vault  ──lend(secret)──▶  OAuth2SecretPort  ──POST /token──▶ provider
//!                                                              │
//!                                            access token ◀────┘
//!                                                   │
//!                                          sink.accept(token)
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asv_connector_http::{SecretError, SecretPort, SecretSink};
use zeroize::Zeroizing;

use crate::oauth2::{
    ClientCredentialsIssuer, OAuth2Config, OAuth2Error, OAuth2Issuer, OAuth2Token,
};

/// How long before a token's own lifetime runs out the port stops serving it.
///
/// Not a safety margin against a slow provider — it is a safety margin against
/// the *consumer*. A token handed out one millisecond before it expires is a
/// token that reaches an operation after it has expired, and the resource server
/// is then the only thing standing between that and a rejection that looks like
/// a network fault. Re-issuing early is one extra token request; handing out one
/// that is about to die is an operation that fails for a reason nobody can see.
pub const DEFAULT_REISSUE_MARGIN: Duration = Duration::from_secs(30);

/// The non-secret half of one OAuth2 client registration.
///
/// Deliberately separate from the secret. Everything here is safe to log, to
/// print in `asv doctor`, and to put in a configuration file; the client secret
/// stays in the vault and is read only to build one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2Client {
    /// The vault credential holding the client secret. Not this client.
    pub credential: String,
    /// The public client identifier (RFC 6749 §2.3.1).
    pub client_id: String,
    /// The provider's token endpoint. Must be HTTPS; the issuer refuses the rest.
    pub token_url: String,
    /// The resource this client may ask a token for (RFC 8707).
    pub audience: String,
    /// The scope to request.
    ///
    /// Configured per client rather than derived from the destination, and that
    /// is a real limitation rather than a simplification: a scope that a request
    /// chose would be a scope the agent picked, and the whole point of the
    /// escalation refusal in [`crate::oauth2`] is that the broker does not take
    /// the agent's word for what it needs. Policy should own this; until it
    /// does, it is operator-written, which is the weaker of the two but still
    /// not agent-written.
    pub scope: String,
}

/// Builds an issuer for one token request.
///
/// A trait for the reason [`crate::ConnectorFactory`] is one, and the reason is
/// the same: the production path and the test path must run the same exchange,
/// and the only thing a test should substitute is where the bytes go. A test
/// that built its own `OAuth2SecretPort` around a different issuer would prove
/// the port's plumbing and not the port.
pub trait OAuth2IssuerFactory: Send + Sync {
    /// Builds an issuer for `config`, or refuses.
    fn issuer(&self, config: OAuth2Config) -> Result<Box<dyn OAuth2Issuer>, OAuth2Error>;
}

/// The production factory: a real HTTPS issuer against a real provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProviderIssuerFactory;

impl OAuth2IssuerFactory for ProviderIssuerFactory {
    fn issuer(&self, config: OAuth2Config) -> Result<Box<dyn OAuth2Issuer>, OAuth2Error> {
        Ok(Box::new(ClientCredentialsIssuer::new(config)?))
    }
}

/// One issued credential and the moment it stops being served.
struct CachedToken {
    bytes: Zeroizing<Vec<u8>>,
    /// After this instant the token must not be served again.
    serve_until: Instant,
}

/// A [`SecretPort`] that trades a stored client secret for a short-lived token.
///
/// The secret is read from the vault, spent on one token request, and never
/// handed to a sink. What reaches the sink is an access token the provider
/// issued, which expires on the provider's clock and not on the broker's
/// opinion of one.
pub struct OAuth2SecretPort {
    vault: Arc<dyn SecretPort>,
    /// Credential id to registration. Keyed by the *vault* credential, because
    /// that is the name an operation asks for.
    clients: HashMap<String, OAuth2Client>,
    factory: Arc<dyn OAuth2IssuerFactory>,
    cache: Mutex<HashMap<String, CachedToken>>,
    margin: Duration,
}

impl OAuth2SecretPort {
    /// Wraps `vault` so that the credentials named in `clients` are served as
    /// access tokens.
    pub fn new(vault: Arc<dyn SecretPort>, clients: Vec<OAuth2Client>) -> Self {
        Self::with_parts(vault, clients, Arc::new(ProviderIssuerFactory))
    }

    /// As [`Self::new`], with the issuer factory and the re-issue margin
    /// supplied.
    pub fn with_parts(
        vault: Arc<dyn SecretPort>,
        clients: Vec<OAuth2Client>,
        factory: Arc<dyn OAuth2IssuerFactory>,
    ) -> Self {
        Self {
            vault,
            clients: clients
                .into_iter()
                .map(|client| (client.credential.clone(), client))
                .collect(),
            factory,
            cache: Mutex::new(HashMap::new()),
            margin: DEFAULT_REISSUE_MARGIN,
        }
    }

    /// Sets how early a token is retired.
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin;
        self
    }

    /// The credential ids this port will answer for.
    pub fn credentials(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.clients.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// A cached token that is still inside its lifetime, or `None`.
    ///
    /// The check is `now < serve_until` and nothing else. A cache that is
    /// consulted without a deadline is a permanent credential wearing a
    /// short-lived one's name, and that is the single most valuable thing this
    /// file could get wrong.
    ///
    /// A poisoned lock is a refusal rather than a cache miss. Reporting a miss
    /// would silently re-issue, which is the safe direction but hides that
    /// something panicked inside the process holding a credential.
    fn cached(&self, credential: &str, now: Instant) -> Result<Option<Vec<u8>>, SecretError> {
        let mut cache = self.cache.lock().map_err(|_| {
            SecretError::Unavailable("the OAuth2 token cache lock was poisoned".into())
        })?;
        let Some(entry) = cache.get(credential) else {
            return Ok(None);
        };
        if now >= entry.serve_until {
            // Dropped rather than kept: a stale entry that is never consulted
            // is a credential the broker is still holding for no reason.
            cache.remove(credential);
            return Ok(None);
        }
        Ok(Some(entry.bytes.to_vec()))
    }

    /// How long a token with this lifetime may be served.
    ///
    /// Zero means "do not cache this one", which is the answer whenever the
    /// margin eats the whole lifetime. Caching it anyway would serve a token
    /// that is already inside its own safety margin.
    fn serve_for(&self, expires_in: Duration) -> Duration {
        match expires_in.checked_sub(self.margin) {
            Some(usable) if !usable.is_zero() => usable,
            _ => Duration::ZERO,
        }
    }

    /// Reads the client secret out of the vault and assembles the config.
    ///
    /// The secret is copied once, into a wiped buffer, because `OAuth2Config`
    /// owns its bytes and has to outlive the vault's borrow for the length of
    /// one request. That copy lives inside the broker, exists for one token
    /// request, and is zeroized on the way out. It is the only place the secret
    /// exists outside the vault's own decrypt scope.
    fn config_for(&self, client: &OAuth2Client) -> Result<OAuth2Config, SecretError> {
        let mut captured: Option<Zeroizing<Vec<u8>>> = None;
        self.vault
            .lend(&client.credential, &mut Capture { out: &mut captured })?;
        let secret = captured.ok_or_else(|| {
            SecretError::Unavailable(format!(
                "the vault returned no bytes for {}",
                client.credential
            ))
        })?;
        Ok(OAuth2Config::new(
            client.token_url.clone(),
            client.client_id.clone(),
            secret.to_vec(),
            client.audience.clone(),
        ))
    }

    /// Asks the provider for a fresh token.
    fn exchange(&self, client: &OAuth2Client) -> Result<OAuth2Token, SecretError> {
        let config = self.config_for(client)?;
        let issuer = self.factory.issuer(config).map_err(unavailable)?;
        issuer.issue(&client.scope).map_err(unavailable)
    }

    /// Forgets every cached token.
    ///
    /// Called when a session ends or a credential is removed. Without it a
    /// revoked client keeps being served for the rest of the token's lifetime,
    /// which is bounded but not zero.
    pub fn forget(&self, credential: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(credential);
        }
    }
}

impl SecretPort for OAuth2SecretPort {
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        let Some(client) = self.clients.get(credential) else {
            // Not "unavailable" and not a provider error: this port simply is
            // not registered for that name, and conflating the two would send an
            // operator to look at the vault when the answer is in the
            // configuration.
            return Err(SecretError::NotFound(credential.to_string()));
        };
        let now = Instant::now();
        if let Some(bytes) = self.cached(credential, now)? {
            return sink.accept(&bytes);
        }
        let token = self.exchange(client)?;
        let serve_for = self.serve_for(token.expires_in);
        if !serve_for.is_zero() {
            let mut cache = self.cache.lock().map_err(|_| {
                SecretError::Unavailable("the OAuth2 token cache lock was poisoned".into())
            })?;
            cache.insert(
                credential.to_string(),
                CachedToken {
                    bytes: Zeroizing::new(token.expose_access_token().to_vec()),
                    serve_until: Instant::now() + serve_for,
                },
            );
        }
        // The sink is given the token and never the secret. A failure here is
        // the operation's own, and it propagates rather than being retried: a
        // retried borrow would be a second use of a credential the connector
        // may already have spent.
        sink.accept(token.expose_access_token())
    }
}

/// A sink that keeps a copy, for reading a secret out of the vault.
///
/// The shape is forced by [`SecretPort`]: the only way to get bytes out of a
/// port is to be the thing it lends to. That is a feature of the design and not
/// an inconvenience here.
struct Capture<'a> {
    out: &'a mut Option<Zeroizing<Vec<u8>>>,
}

impl SecretSink for Capture<'_> {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        *self.out = Some(Zeroizing::new(secret.to_vec()));
        Ok(())
    }
}

/// A provider failure is `Unavailable`, and it is named that way rather than
/// flattened into a transport error: "the provider said no" and "the provider
/// could not be reached" send an operator to different places, and the caller
/// can only retry one of them.
fn unavailable(error: OAuth2Error) -> SecretError {
    SecretError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::DeterministicTokenIssuer;
    use asv_connector_http::SecretError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FixedSecret(&'static [u8]);

    impl SecretPort for FixedSecret {
        fn lend(&self, _credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
            sink.accept(self.0)
        }
    }

    fn client() -> OAuth2Client {
        OAuth2Client {
            credential: "cred-1".to_string(),
            client_id: "asv-broker".to_string(),
            token_url: "https://idp.example.com/token".to_string(),
            audience: "https://api.example.com".to_string(),
            scope: "read".to_string(),
        }
    }

    /// Counts how many times a token was actually asked for.
    ///
    /// The counter, not the token bytes, is the observable. The deterministic
    /// issuer is content-addressed, so a second grant produces the same bytes
    /// and a test that watched the bytes would pass whether the cache was used
    /// or not — which is the same shape of hole as a test that watches a struct
    /// instead of the wire.
    #[derive(Default)]
    struct Grants(AtomicUsize);

    struct Factory(Arc<Grants>);

    impl OAuth2IssuerFactory for Factory {
        fn issuer(&self, config: OAuth2Config) -> Result<Box<dyn OAuth2Issuer>, OAuth2Error> {
            self.0 .0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(DeterministicTokenIssuer::new(config)))
        }
    }

    fn port(secret: &'static [u8], margin: Duration) -> (OAuth2SecretPort, Arc<Grants>) {
        let grants = Arc::new(Grants::default());
        let port = OAuth2SecretPort::with_parts(
            Arc::new(FixedSecret(secret)),
            vec![client()],
            Arc::new(Factory(Arc::clone(&grants))),
        )
        .with_margin(margin);
        (port, grants)
    }

    #[derive(Default)]
    struct Seen {
        bytes: Vec<u8>,
        calls: usize,
    }

    impl SecretSink for Seen {
        fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
            self.bytes = secret.to_vec();
            self.calls += 1;
            Ok(())
        }
    }

    /// The two facts this file exists to make true, checked together because
    /// either alone is satisfiable by a broken port.
    #[test]
    fn the_sink_receives_a_token_and_never_the_secret() {
        let (port, _grants) = port(b"the-client-secret", Duration::ZERO);
        let mut seen = Seen::default();
        port.lend("cred-1", &mut seen).expect("lend");
        assert_ne!(seen.bytes, b"the-client-secret");
        assert!(!seen.bytes.is_empty());
    }

    /// An unregistered name is `NotFound`. Collapsing it into `Unavailable`
    /// would point an operator at the vault when the answer is in the
    /// configuration.
    #[test]
    fn an_unregistered_credential_is_not_found() {
        let (port, _grants) = port(b"the-client-secret", Duration::ZERO);
        let mut seen = Seen::default();
        assert!(matches!(
            port.lend("cred-unknown", &mut seen),
            Err(SecretError::NotFound(_))
        ));
        assert_eq!(seen.calls, 0, "the sink must not be reached at all");
    }

    /// A token inside its lifetime is served again without asking the provider,
    /// which is the reason for a cache at all.
    #[test]
    fn a_token_inside_its_lifetime_is_served_again() {
        let (port, grants) = port(b"the-client-secret", Duration::ZERO);
        let mut first = Seen::default();
        let mut second = Seen::default();
        port.lend("cred-1", &mut first).expect("first");
        port.lend("cred-1", &mut second).expect("second");
        assert_eq!(first.bytes, second.bytes, "one grant, two operations");
        assert_eq!(
            grants.0.load(Ordering::SeqCst),
            1,
            "the second operation must not have asked the provider again"
        );
    }

    /// A margin wider than the token's own lifetime means the token is never
    /// served from the cache, because every token arrives already inside the
    /// margin it was supposed to be retired before.
    #[test]
    fn a_margin_wider_than_the_lifetime_never_serves_a_cached_token() {
        let (wide, _grants) = port(b"the-client-secret", Duration::from_secs(86_400));
        assert_eq!(wide.serve_for(Duration::from_secs(300)), Duration::ZERO);
        // And with no margin, a normal lifetime is servable.
        let (plain, _grants) = port(b"the-client-secret", Duration::ZERO);
        assert_eq!(
            plain.serve_for(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    /// `forget` drops the entry, which is what makes a revocation effective
    /// before the token's own lifetime runs out.
    #[test]
    fn forgetting_a_credential_drops_its_cached_token() {
        let (port, grants) = port(b"the-client-secret", Duration::ZERO);
        let mut first = Seen::default();
        port.lend("cred-1", &mut first).expect("first");
        assert_eq!(grants.0.load(Ordering::SeqCst), 1);
        port.forget("cred-1");
        let mut second = Seen::default();
        port.lend("cred-1", &mut second).expect("second");
        assert_eq!(
            grants.0.load(Ordering::SeqCst),
            2,
            "after forgetting, a new grant is asked for"
        );
    }

    #[test]
    fn the_port_lists_the_credentials_it_will_answer_for() {
        let (port, _grants) = port(b"the-client-secret", Duration::ZERO);
        assert_eq!(port.credentials(), vec!["cred-1".to_string()]);
    }
}
