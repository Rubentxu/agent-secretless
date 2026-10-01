//! M9 redirect denier.
//!
//! Not a normative UAT: `14-UAT-ADVERSARIAL.md` titles UAT-011 "TLS
//! pinning", which is a different subject — a client that pins the
//! upstream certificate and cannot accept the session CA. The filename
//! retains `uat_011` from when this file was filed under that id; the
//! requirement these tests actually pin is the M9-R3 one below.
//!
//! M9-R3 specifies that `authorize_redirect` accepts only same-origin
//! redirects while a credential binding is active.

use asv_broker::tls_bridge::{authorize_redirect, AuthorityEndpoint, RedirectError};
use asv_domain::Authority;

fn origin() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("api.example.com").expect("host"),
        443,
    )
    .expect("endpoint")
}

fn attacker() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("attacker.example.net").expect("host"),
        443,
    )
    .expect("endpoint")
}

fn same_host_diff_port() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("api.example.com").expect("host"),
        8443,
    )
    .expect("endpoint")
}

#[test]
fn uat_011_same_origin_redirect_is_authorized() {
    let o = origin();
    let proposed = AuthorityEndpoint::new(
        Authority::canonicalize("api.example.com").expect("host"),
        443,
    )
    .expect("endpoint");
    assert!(
        authorize_redirect(&o, &proposed).is_ok(),
        "same host, same port must pass"
    );
}

#[test]
fn uat_011_cross_origin_redirect_is_denied() {
    let o = origin();
    let p = attacker();
    let err = authorize_redirect(&o, &p).expect_err("must deny cross-origin");
    match err {
        RedirectError::CrossOrigin { from, to } => {
            assert_eq!(from, "api.example.com:443");
            assert_eq!(to, "attacker.example.net:443");
        }
    }
}

#[test]
fn uat_011_cross_port_redirect_is_denied() {
    // The M9 spec uses canonical host comparison. Same-host, different
    // port is *not* same-origin for the credential-binding semantics
    // because the upstream service may be a different trust zone.
    let o = origin();
    let p = same_host_diff_port();
    let err = authorize_redirect(&o, &p).expect_err("cross-port must deny");
    assert!(matches!(err, RedirectError::CrossOrigin { .. }));
}

#[test]
fn uat_011_authorization_is_symmetric_for_unrelated_origins() {
    // The check is symmetric in the sense that neither direction of
    // an unrelated pair is accepted. This guards against a confused
    // implementation that only checks one direction.
    let a = origin();
    let b = attacker();
    assert!(authorize_redirect(&a, &b).is_err());
    assert!(authorize_redirect(&b, &a).is_err());
}

#[test]
fn uat_011_authorisation_carries_endpoint_strings_in_error() {
    // The error MUST include both endpoints so the audit log can record
    // the exact cross-origin attempt without losing information.
    let err = authorize_redirect(&origin(), &attacker()).expect_err("err");
    let s = format!("{err}");
    assert!(s.contains("api.example.com:443"));
    assert!(s.contains("attacker.example.net:443"));
}
