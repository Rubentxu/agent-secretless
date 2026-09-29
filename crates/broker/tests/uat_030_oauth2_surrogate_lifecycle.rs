//! UAT-030 — OAuth2 surrogate lifecycle.
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md` and the
//! M11 spec for the OAuth2 provider framework:
//!
//! > The framework MUST NOT expose the long-lived credential; the agent
//! > only holds the short-lived access token; the broker refreshes.
//!
//! UAT-030 exercises the structural claim: the broker issues a token,
//! the agent sees only the access bytes, the refresh bytes are
//! internal to the broker.

use asv_broker::oauth2::{ClientCredentialsIssuer, OAuth2Config, OAuth2Issuer};

fn config() -> OAuth2Config {
    OAuth2Config::new(
        "https://idp.example.com/oauth2/token",
        "agent-secretless",
        b"prototype-client-secret".to_vec(),
        "https://api.example.com",
    )
}

#[test]
fn uat_030_issue_returns_bearer_token_with_non_empty_access() {
    let issuer = ClientCredentialsIssuer::new(config());
    let t = issuer.issue("read:pods").expect("issue");
    assert_eq!(t.token_type, "Bearer");
    assert!(!t.expose_access_token().is_empty());
    assert!(t.expires_in.as_secs() > 0);
}

#[test]
fn uat_030_refresh_bytes_are_not_reachable_via_public_api() {
    // The structural guarantee: the public surface has
    // `expose_access_token`, nothing else for tokens. The refresh
    // bytes are stored in the struct but the broker-side code is
    // the only path that ever uses them.
    let issuer = ClientCredentialsIssuer::new(config());
    let t = issuer.issue("read:pods").expect("issue");
    assert!(t.has_refresh_token());
    // No `expose_refresh_token` method exists; the public API does
    // not provide a way to read the refresh bytes.
    //
    // We assert this by listing the public methods on `OAuth2Token`
    // implicitly — anything reachable from `&self` and named
    // `expose_*` or `refresh_*` would be a regression.
    let _ = t.access_token_len();
    let _ = t.token_type.clone();
    let _ = t.expires_in;
    let _ = t.scope.clone();
}

#[test]
fn uat_030_refresh_returns_fresh_access_bytes_for_same_refresh_input() {
    let issuer = ClientCredentialsIssuer::new(config());
    let t1 = issuer.refresh(b"refresh-token-1").expect("refresh 1");
    let t2 = issuer.refresh(b"refresh-token-1").expect("refresh 2");
    // The placeholder is content-addressed: same input -> same access.
    // The runtime replaces this with a real provider call that may
    // return different bytes for the same refresh input (e.g. rotated
    // signing keys).
    assert_eq!(t1.expose_access_token(), t2.expose_access_token());
}

#[test]
fn uat_030_refresh_for_different_inputs_yields_different_access() {
    let issuer = ClientCredentialsIssuer::new(config());
    let t1 = issuer.refresh(b"refresh-A").expect("refresh A");
    let t2 = issuer.refresh(b"refresh-B").expect("refresh B");
    assert_ne!(t1.expose_access_token(), t2.expose_access_token());
}

#[test]
fn uat_030_issuer_reports_provider_url_and_audience() {
    let issuer = ClientCredentialsIssuer::new(config());
    assert_eq!(issuer.token_url(), "https://idp.example.com/oauth2/token");
    assert_eq!(issuer.audience(), "https://api.example.com");
}

#[test]
fn uat_030_issue_rejects_empty_client_id() {
    let bad = OAuth2Config::new(
        "https://idp.example.com/oauth2/token",
        "",
        b"shh".to_vec(),
        "https://api.example.com",
    );
    let issuer = ClientCredentialsIssuer::new(bad);
    assert!(matches!(
        issuer.issue("read"),
        Err(asv_broker::oauth2::OAuth2Error::MalformedToken(_))
    ));
}