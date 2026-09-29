//! M11 — OAuth2 provider framework (prototype pass).
//!
//! The framework is the structural answer to "agent with broker-held
//! credentials and short-lived access". Without it the agent must hold
//! the long-lived credential; with it the agent only holds the access
//! token and the broker refreshes in the background.
//!
//! The prototype defines the data types and the trait surface; the
//! runtime follow-up replaces `ClientCredentialsIssuer::issue` with a
//! real HTTPS POST to the provider's token endpoint.
//!
//! Authoritative source: `agent-secretless-vault-spec/docs/15-ROADMAP.md`
//! section M11 item #4.

use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

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

/// Static configuration of an OAuth2 client. The runtime follow-up
/// replaces the `client_secret` accessor with a `Zeroizing<Vec<u8>>`
/// that is moved into the issuer at construction time and dropped
/// from the config afterwards.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// RFC 6749 §3.2 token endpoint.
    pub token_url: String,
    /// Public client identifier.
    pub client_id: String,
    /// Client secret. The runtime replaces `Vec<u8>` with a
    /// `Zeroizing<Vec<u8>>` and consumes the value on `issue`.
    pub client_secret: Vec<u8>,
    /// Provider audience (informational).
    pub audience: String,
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
    /// The provider rejected the request.
    #[error("provider rejected request: {0}")]
    ProviderRejected(String),
    /// A structural problem with the token (e.g. empty access_token).
    #[error("malformed token: {0}")]
    MalformedToken(String),
    /// The runtime is the prototype; the real HTTPS POST is the
    /// runtime follow-up.
    #[error("runtime not implemented (M11-prototype placeholder)")]
    RuntimeNotImplemented,
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

/// A client-credentials issuer (RFC 6749 §4.4). The prototype builds
/// a deterministic placeholder token; the runtime follow-up replaces
/// the body with a real HTTPS POST.
#[derive(Debug, Clone)]
pub struct ClientCredentialsIssuer {
    config: OAuth2Config,
}

impl ClientCredentialsIssuer {
    /// Construct a new issuer from a config.
    pub fn new(config: OAuth2Config) -> Self {
        Self { config }
    }
}

impl OAuth2Issuer for ClientCredentialsIssuer {
    fn issue(&self, scope: &str) -> Result<OAuth2Token, OAuth2Error> {
        // The runtime follow-up replaces this body with an HTTPS POST
        // to `self.config.token_url`. The prototype returns a
        // deterministic placeholder so the broker-side unit test can
        // assert the surface without an external provider.
        if self.config.client_id.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty client_id".into()));
        }
        let access_token = synth_access_token(&self.config.client_id, scope);
        let expires_in = Duration::from_secs(3600);
        let scope_owned = if scope.is_empty() {
            None
        } else {
            Some(scope.to_string())
        };
        Ok(OAuth2Token::new(
            access_token,
            "Bearer",
            expires_in,
            Some(synth_refresh_token(&self.config.client_id)),
            scope_owned,
        ))
    }

    fn refresh(&self, refresh_token: &[u8]) -> Result<OAuth2Token, OAuth2Error> {
        if refresh_token.is_empty() {
            return Err(OAuth2Error::MalformedToken("empty refresh_token".into()));
        }
        let access_token = synth_access_token_from_refresh(refresh_token);
        Ok(OAuth2Token::new(
            access_token,
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
    // Deterministic, content-addressed placeholder. The runtime
    // replaces this with the provider's response.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client_id.hash(&mut h);
    scope.hash(&mut h);
    h.write_u64(0xA11CE); // version marker for the placeholder
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

    #[test]
    fn token_exposes_access_bytes() {
        let t = OAuth2Token::new(
            b"access".to_vec(),
            "Bearer",
            Duration::from_secs(60),
            None,
            None,
        );
        assert_eq!(t.expose_access_token(), b"access");
        assert_eq!(t.access_token_len(), 6);
        assert_eq!(t.token_type, "Bearer");
        assert_eq!(t.expires_in, Duration::from_secs(60));
        assert!(!t.has_refresh_token());
    }

    #[test]
    fn token_carries_refresh_bytes_internally() {
        let t = OAuth2Token::new(
            b"access".to_vec(),
            "Bearer",
            Duration::from_secs(60),
            Some(b"refresh".to_vec()),
            Some("read".to_string()),
        );
        assert!(t.has_refresh_token());
        // The public surface does NOT expose refresh_token. The only
        // way to read the access bytes is `expose_access_token`.
        assert_eq!(t.expose_access_token(), b"access");
    }

    #[test]
    fn oauth2_config_constructs_from_parts() {
        let c = config();
        assert_eq!(c.token_url, "https://idp.example.com/oauth2/token");
        assert_eq!(c.client_id, "client-1");
        assert_eq!(c.client_secret, b"shh");
        assert_eq!(c.audience, "https://api.example.com");
    }

    #[test]
    fn client_credentials_issuer_issue_returns_bearer_token() {
        let i = ClientCredentialsIssuer::new(config());
        let t = i.issue("read:pods").expect("issue");
        assert_eq!(t.token_type, "Bearer");
        assert!(t.expires_in > Duration::from_secs(0));
        assert!(!t.expose_access_token().is_empty());
        assert!(t.has_refresh_token());
        assert_eq!(t.scope.as_deref(), Some("read:pods"));
    }

    #[test]
    fn client_credentials_issuer_issue_is_deterministic_for_same_input() {
        let i = ClientCredentialsIssuer::new(config());
        let t1 = i.issue("read").expect("issue 1");
        let t2 = i.issue("read").expect("issue 2");
        // The prototype's placeholder is content-addressed; the
        // runtime follow-up will return whatever the provider says.
        assert_eq!(t1.expose_access_token(), t2.expose_access_token());
    }

    #[test]
    fn client_credentials_issuer_issue_rejects_empty_client_id() {
        let cfg = OAuth2Config::new(
            "https://idp.example.com/oauth2/token",
            "",
            b"shh".to_vec(),
            "https://api.example.com",
        );
        let i = ClientCredentialsIssuer::new(cfg);
        assert!(matches!(
            i.issue("read"),
            Err(OAuth2Error::MalformedToken(_))
        ));
    }

    #[test]
    fn client_credentials_issuer_refresh_returns_new_token() {
        let i = ClientCredentialsIssuer::new(config());
        let original_refresh = b"refresh-token";
        let t = i.refresh(original_refresh).expect("refresh");
        assert!(!t.expose_access_token().is_empty());
        assert!(t.has_refresh_token());
        // The access bytes are content-addressed from the refresh bytes.
        // Calling refresh twice with the same input returns the same access.
        let t2 = i.refresh(original_refresh).expect("refresh 2");
        assert_eq!(t.expose_access_token(), t2.expose_access_token());
    }

    #[test]
    fn client_credentials_issuer_refresh_rejects_empty_input() {
        let i = ClientCredentialsIssuer::new(config());
        assert!(matches!(
            i.refresh(b""),
            Err(OAuth2Error::MalformedToken(_))
        ));
    }

    #[test]
    fn issuer_exposes_token_url_and_audience() {
        let i = ClientCredentialsIssuer::new(config());
        assert_eq!(i.token_url(), "https://idp.example.com/oauth2/token");
        assert_eq!(i.audience(), "https://api.example.com");
    }

    #[test]
    fn issue_returns_runtime_not_implemented_for_prototype_clarity() {
        // The prototype does NOT raise `RuntimeNotImplemented` because
        // it builds a placeholder token. The runtime follow-up will
        // raise it for any unhandled case.
        let i = ClientCredentialsIssuer::new(config());
        let _ = i.issue("read").expect("prototype issue should succeed");
    }
}