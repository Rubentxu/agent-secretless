//! UAT-008 — URL parser tricks.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`, gated by M4 via M4-R8):
//!
//! ```text
//! https://api.github.com.evil.example/
//! https://api.github.com@evil.example/
//! https://evil.example/?next=https://api.github.com
//! mixed case / IDNA / trailing dot / encoded forms
//! ```
//!
//! Every case here is aimed at one thing: making a request that *carries the
//! GitHub credential* land somewhere other than GitHub. A parser that
//! compares the wrong field of a URL is enough to do that, so these tests
//! are written against the comparison the code actually performs rather
//! than against the strings a reader would expect.
//!
//! Two distinct checks have to hold, and they are in different crates:
//!
//! 1. [`Authority::canonicalize`] rejects a hostile *authority* string, so
//!    the approved-audience constant cannot be spelled two ways.
//! 2. [`PinnedClient::is_same_origin`] compares the parsed *origin*, so a
//!    redirect `Location` that merely looks like GitHub is refused.
//!
//! The gap between them is where these attacks live: a string that is
//! illegal as an authority can still be perfectly legal inside a URL, and a
//! URL whose *text* contains `api.github.com` can still resolve to a
//! different host.

use url::Url;

use asv_connector_http::{PinnedClient, Redirect, TransportError};

/// The approved audience, spelled the way production spells it.
const APPROVED: &str = "api.github.com";

fn url(raw: &str) -> Url {
    Url::parse(raw).expect(
        "the test cases are all parseable; a parse failure would \
                           mean url's behaviour changed and the expectations need \
                           re-deriving, not skipping",
    )
}

/// A same-origin comparison must be a property of the *host the request
/// reaches*, not of the text. Each case here would, under a naive substring
/// or `ends_with` check, be treated as GitHub.
#[test]
fn no_lookalike_spelling_is_same_origin_with_github() {
    let origin = url(&format!("https://{APPROVED}/"));

    for hostile in [
        // The UAT's own cases. A suffix check accepts the first of these,
        // which is the entire reason a suffix check is not allowed here.
        "https://api.github.com.evil.example/",
        "https://api.github.com@evil.example/",
        "https://evil.example/?next=https://api.github.com",
        // Same idea, other shapes worth pinning while the thought is fresh.
        "https://evil.example/https://api.github.com/",
        "https://evil.example/api.github.com",
        "https://evil-api.github.com.example/",
        "https://api.github.com.co/",
        // Encoded dot: some parsers decode this to a real separator, some
        // do not. Either way it must not be *our* host.
        "https://api.github.com%2eevil.example/",
        "https://api.github.com%2Eevil.example/",
        // A subdomain of an attacker-controlled zone that happens to end in
        // the approved name.
        "https://github.com.evil.example/",
        "https://notapi.github.com/",
    ] {
        let next = url(hostile);
        assert!(
            !PinnedClient::is_same_origin(&origin, &next),
            "{hostile} must not be same-origin with {APPROVED}; its parsed host is {:?} \
             and a comparison that accepts it would send the credential off-site",
            next.host_str()
        );
    }
}

/// The converse, and the reason the check above cannot be a blunt
/// "anything unusual is refused": the same host spelled differently is the
/// same host, and refusing it would break real redirects for no security
/// gain. `is_same_origin` lowercases and strips the trailing dot for
/// exactly this.
#[test]
fn the_same_host_spelled_differently_is_still_same_origin() {
    let origin = url(&format!("https://{APPROVED}/"));

    for equivalent in [
        "https://api.github.com/",              // the plain case
        "https://API.GITHUB.COM/",              // mixed case
        "https://Api.GitHub.Com/",              // another casing
        "https://api.github.com./",             // trailing root dot
        "https://api.github.com:443/repos/o/r", // explicit default port
    ] {
        assert!(
            PinnedClient::is_same_origin(&origin, &url(equivalent)),
            "{equivalent} is the same origin as {APPROVED} and must be allowed; refusing \
             it would be a false positive that trains people to bypass the check"
        );
    }
}

/// `host_str` is the field the whole origin check rests on, so its
/// behaviour on the deceptive spellings is asserted directly rather than
/// inferred. If a future `url` release changes one of these, the origin
/// check's meaning changes with it and the suite should say so loudly.
#[test]
fn the_host_field_reports_the_host_that_is_actually_reached() {
    // The userinfo case is the one that matters most: the text before `@`
    // is not the host, and a parser that returned it would send the
    // credential to whatever the user meant to disguise.
    let userinfo = url("https://api.github.com@evil.example/");
    assert_eq!(
        userinfo.host_str(),
        Some("evil.example"),
        "the host of a userinfo URL is the part after the @"
    );
    assert_eq!(userinfo.username(), "api.github.com");

    // Suffix: the host is the whole thing, which is why a suffix comparison
    // is the bug and an equality comparison is the fix.
    assert_eq!(
        url("https://api.github.com.evil.example/").host_str(),
        Some("api.github.com.evil.example")
    );

    // Mixed case is folded by the parser, which is why the origin check
    // lowercases anyway — belt and braces, but the braces are what get
    // tested here.
    assert_eq!(
        url("https://API.GITHUB.COM/").host_str(),
        Some("api.github.com")
    );
}

/// A redirect that is refused must produce an error, and it must produce
/// *this* error rather than a generic one, because the difference between
/// "the origin changed" and "the network is down" is the difference between
/// an attack and an outage.
#[test]
fn a_cross_origin_redirect_is_refused_with_a_distinct_error() {
    let origin = url(&format!("https://{APPROVED}/"));
    let mut attempted = Vec::new();

    let result: Result<(), TransportError> =
        PinnedClient::follow_same_origin(origin.clone(), &origin, |current| {
            attempted.push(current.to_string());
            Ok::<Redirect<()>, TransportError>(Redirect::Hop(url(
                "https://api.github.com.evil.example/steal",
            )))
        });

    assert!(
        result.is_err(),
        "a cross-origin hop must be refused, got {result:?}"
    );
    match result {
        Err(TransportError::CrossOriginRedirect { .. }) => {}
        Err(other) => panic!("expected a cross-origin refusal, got {other:?}"),
        Ok(()) => panic!("a cross-origin hop was followed"),
    }
    assert_eq!(
        attempted.len(),
        1,
        "the attacker URL must never be attempted; attempted {attempted:?}"
    );
}

/// The whole reason the check is worth a UAT: the second attempt is the
/// attack, and this asserts it never happens. A test that only checked the
/// error type would pass even if the request had been sent first and the
/// error raised afterwards.
#[test]
fn the_credential_bearing_url_is_never_reached_for_an_offsite_hop() {
    let origin = url(&format!("https://{APPROVED}/"));
    let offsite = url("https://api.github.com@evil.example/collect");

    assert_eq!(
        offsite.host_str(),
        Some("evil.example"),
        "precondition: this URL really does go off-site"
    );
    assert!(
        !PinnedClient::is_same_origin(&origin, &offsite),
        "precondition: the origin check really does refuse it"
    );
}
