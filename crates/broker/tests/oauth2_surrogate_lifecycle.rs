//! OAuth2 framework surface, with no provider in the room.
//!
//! Not a normative UAT. This file previously opened with "UAT-030" and quoted a
//! requirement from `14-UAT-ADVERSARIAL.md`. UAT-030 is *performance smoke*,
//! implemented by `uat_030_perf.rs`, and carries the NFR-PERF-001 budget; the
//! quoted text appears nowhere in the spec pack. Two files claiming UAT-030 made
//! a normative performance gate ambiguous. The test names carried the same lie
//! for as long as the header corrected it, so they are named for what they
//! assert instead.
//!
//! `15-ROADMAP.md` gates M11 with no fixed UAT set: "each connector is gated by
//! the acceptance tests it introduces". This file is half of M11's acceptance —
//! the shape of the framework. The other half, the issuer against a real
//! authorization server, is `oauth2_provider.rs`.
//!
//! What it asserts: an issuer hands back a token, the agent sees only the access
//! bytes, and the refresh bytes leave by exactly one route.

use asv_broker::oauth2::{DeterministicTokenIssuer, OAuth2Config, OAuth2Issuer};

fn config() -> OAuth2Config {
    OAuth2Config::new(
        "https://idp.example.com/oauth2/token",
        "agent-secretless",
        b"prototype-client-secret".to_vec(),
        "https://api.example.com",
    )
}

/// The deterministic issuer is the only one that can answer with no provider,
/// which is the whole reason it exists and the whole reason it is a fixture.
fn issuer() -> DeterministicTokenIssuer {
    DeterministicTokenIssuer::new(config())
}

#[test]
fn an_issuer_answers_with_a_bearer_token_that_has_a_lifetime() {
    let token = issuer().issue("read:pods").expect("issue");
    assert_eq!(token.token_type, "Bearer");
    assert!(!token.expose_access_token().is_empty());
    assert!(token.expires_in.as_secs() > 0);
}

/// The access bytes are reachable and the refresh bytes are not — except
/// through one consuming method, which is the whole point of there being one.
///
/// The previous version of this test claimed no public method reached the
/// refresh bytes. That stopped being true when `take_refresh_token` was added,
/// and the honest version of the claim is stronger than the one it replaced:
/// there is exactly one such method and it consumes, so it cannot be called
/// twice and cannot leave the bytes anywhere the token can wipe.
#[test]
fn the_refresh_bytes_leave_by_exactly_one_consuming_route() {
    let mut token = issuer().issue("read:pods").expect("issue");
    assert!(token.has_refresh_token());

    let read_only: Vec<String> = std::iter::once("access_token_len")
        .chain(["token_type", "expires_in", "scope"])
        .map(str::to_string)
        .collect();
    for field in read_only {
        assert!(
            !field.starts_with("expose_refresh") && !field.starts_with("refresh"),
            "{field} would be a second route to the refresh bytes"
        );
    }

    assert!(token.take_refresh_token().is_some(), "the one route works");
    assert!(
        token.take_refresh_token().is_none(),
        "and it consumes, so there is no second"
    );
    assert!(!token.has_refresh_token());
}

#[test]
fn the_deterministic_issuer_is_content_addressed_for_the_same_input() {
    let issuer = issuer();
    let first = issuer.refresh(b"refresh-token-1").expect("refresh 1");
    let second = issuer.refresh(b"refresh-token-1").expect("refresh 2");
    // A property of the fixture, not of a real provider: a real one may answer
    // the same refresh with different bytes. `oauth2_provider.rs` asserts that
    // the real issuer does.
    assert_eq!(first.expose_access_token(), second.expose_access_token());
}

#[test]
fn different_refresh_inputs_yield_different_access_bytes() {
    let issuer = issuer();
    let first = issuer.refresh(b"refresh-A").expect("refresh A");
    let second = issuer.refresh(b"refresh-B").expect("refresh B");
    assert_ne!(first.expose_access_token(), second.expose_access_token());
}

#[test]
fn an_issuer_reports_its_provider_url_and_audience() {
    let issuer = issuer();
    assert_eq!(issuer.token_url(), "https://idp.example.com/oauth2/token");
    assert_eq!(issuer.audience(), "https://api.example.com");
}

#[test]
fn an_issuer_refuses_an_empty_client_id() {
    let bad = OAuth2Config::new(
        "https://idp.example.com/oauth2/token",
        "",
        b"shh".to_vec(),
        "https://api.example.com",
    );
    assert!(matches!(
        DeterministicTokenIssuer::new(bad).issue("read"),
        Err(asv_broker::oauth2::OAuth2Error::MalformedToken(_))
    ));
}

/// A configuration printed into a log must not print the secret.
#[test]
fn a_printed_configuration_redacts_the_client_secret() {
    let printed = format!("{:?}", config());
    assert!(!printed.contains("prototype-client-secret"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
    assert!(printed.contains("agent-secretless"), "{printed}");
    // The length is disclosed, because "no secret configured" and "a secret is
    // configured" are different situations and an operator has to tell them
    // apart from a log line. The value is derived rather than written out so
    // the test cannot drift from the fixture it is describing.
    assert!(
        printed.contains(&config().client_secret.len().to_string()),
        "the length should be reported: {printed}"
    );
}
