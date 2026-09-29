//! UAT-010 — CONNECT allow-list.
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md`:
//!
//! > Compromised unprivileged client requests arbitrary CONNECT tunnel.
//! > Expected: denied unless target is in the policy's allow-list.
//!
//! M9-R2 specifies that `ConnectPolicy::authorize` accepts only the
//! endpoints in the session's connector audience. This integration
//! test exercises the broker-side `tls_bridge::Bridge::handle_connect`
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
