//! M9 CONNECT allow-list. **This file claims no UAT, and the filename does not
//! mean that it does.**
//!
//! The name is historical: this file was once filed under UAT-010, and the
//! subject moved underneath it. UAT-010 is now "surrogate substitution reaches
//! the provider and the client never sees the secret", which is proved
//! elsewhere and not here — substitution needs a session and a surrogate, and
//! this suite has neither.
//!
//! An earlier revision of this header claimed UAT-010 and then disclaimed it
//! two lines later, citing a title the spec no longer used. The checker could
//! not catch it, because the claim line reproduced the spec title verbatim and
//! so matched. A claim line that is withdrawn four lines later is not a claim;
//! it is a false claim with a footnote.
//!
//! What these tests actually pin is M9-R2: `ConnectPolicy::authorize` accepts
//! only the endpoints in the session's connector audience, exercised through
//! the broker-side `tls_bridge::Bridge::handle_connect` from the surface a real
//! broker would call.
//! from the surface a real broker would call.

use asv_broker::tls_bridge::{AuthorityEndpoint, Bridge, ConnectError, ConnectPolicy};
use asv_domain::Authority;

fn api_endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("api.example.com").expect("host"),
        443,
    )
    .expect("endpoint")
}

fn attacker_endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("attacker.example.net").expect("host"),
        443,
    )
    .expect("endpoint")
}

fn same_host_wrong_port() -> AuthorityEndpoint {
    AuthorityEndpoint::new(
        Authority::canonicalize("api.example.com").expect("host"),
        8443,
    )
    .expect("endpoint")
}

#[test]
fn uat_010_allowed_connect_succeeds() {
    let policy = ConnectPolicy {
        allowed: vec![api_endpoint()],
    };
    let bridge = Bridge::new(policy);
    let target = api_endpoint();
    assert!(
        bridge.handle_connect(&target).is_ok(),
        "api.example.com:443 must be allowed when in the allow-list"
    );
}

#[test]
fn uat_010_disallowed_host_is_rejected() {
    let policy = ConnectPolicy {
        allowed: vec![api_endpoint()],
    };
    let bridge = Bridge::new(policy);
    let target = attacker_endpoint();
    let err = bridge.handle_connect(&target).expect_err("must reject");
    match err {
        asv_broker::tls_bridge::BridgeError::Connect(ConnectError::TunnelNotAllowed(s)) => {
            assert_eq!(s, "attacker.example.net:443");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn uat_010_same_host_wrong_port_is_rejected() {
    // The allow-list is per-endpoint. Even if the host matches, the
    // wrong port is denied. This prevents a port-mismatch from leaking
    // into an unexpected upstream service.
    let policy = ConnectPolicy {
        allowed: vec![api_endpoint()],
    };
    let bridge = Bridge::new(policy);
    let target = same_host_wrong_port();
    assert!(
        bridge.handle_connect(&target).is_err(),
        "api.example.com:8443 must not be allowed when only :443 is in the allow-list"
    );
}

#[test]
fn uat_010_empty_policy_blocks_all_traffic() {
    // A session with no allowed endpoints has a closed bridge. The
    // broker must never send CONNECT through such a policy.
    let bridge = Bridge::new(ConnectPolicy::default());
    assert!(bridge.handle_connect(&api_endpoint()).is_err());
    assert_eq!(bridge.allowed_count(), 0);
}

#[test]
fn uat_010_policy_with_multiple_allowed_endpoints() {
    let policy = ConnectPolicy {
        allowed: vec![
            api_endpoint(),
            AuthorityEndpoint::new(
                Authority::canonicalize("api.example.com").expect("host"),
                8443,
            )
            .expect("endpoint"),
        ],
    };
    let bridge = Bridge::new(policy);
    assert!(bridge.handle_connect(&api_endpoint()).is_ok());
    assert!(bridge
        .handle_connect(
            &AuthorityEndpoint::new(
                Authority::canonicalize("api.example.com").expect("host"),
                8443
            )
            .expect("endpoint")
        )
        .is_ok());
    assert_eq!(bridge.allowed_count(), 2);
}
