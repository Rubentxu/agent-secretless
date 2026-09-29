//! UAT-012 — Trust injection adapter.
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md`:
//!
//! > Compromised unprivileged client tries to skip the CA-trust setup
//! > so the agent process never trusts the broker CA. Expected: agent
//! > cannot authenticate via the TLS bridge.
//!
//! M9-R4 specifies that a `TrustInjector` adapter writes the session CA
//! to a session-scoped path and returns a binding the broker uses to
//! spawn the agent's process tree with the right env vars.

use asv_broker::tls_bridge::{
    AuthorityEndpoint, Bridge, ConnectPolicy, InjectError, OpenSslEnvInjector, SessionCa,
    TrustInjector, DEFAULT_SESSION_CA_TTL,
};
use asv_domain::Authority;

fn api_endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize("api.example.com").expect("host"), 443)
        .expect("endpoint")
}

#[test]
fn uat_012_openssl_injector_writes_file_with_correct_env_var() {
    let tmp = std::env::temp_dir().join(format!("asv-uat012-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let ca = SessionCa::new("sess-012", 13, DEFAULT_SESSION_CA_TTL);
    let binding = OpenSslEnvInjector.inject(&ca, &tmp).expect("inject OK");
    assert_eq!(binding.name, "openssl");
    assert_eq!(binding.env_var, "SSL_CERT_FILE");
    assert!(binding.env_value.exists());
    let written = std::fs::read(&binding.env_value).expect("read");
    assert_eq!(written, ca.root_der);
    let _ = std::fs::remove_file(&binding.env_value);
    let _ = std::fs::remove_dir(&tmp);
}

#[test]
fn uat_012_injector_rejects_empty_ca() {
    // An empty CA must never produce a binding — the agent process
    // would trust nothing and the TLS handshake would fail anyway.
    let mut ca = SessionCa::new("sess-012-empty", 0, DEFAULT_SESSION_CA_TTL);
    ca.root_der.clear();
    let tmp = std::env::temp_dir().join("asv-uat012-empty");
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let err = OpenSslEnvInjector.inject(&ca, &tmp).expect_err("must reject");
    match err {
        InjectError::EmptyCa(s) => assert_eq!(s, "sess-012-empty"),
        other => panic!("unexpected error: {other:?}"),
    }
    let _ = std::fs::remove_dir(&tmp);
}

#[test]
fn uat_012_bridge_integration_with_session_ca() {
    // The bridge + CA + injector + policy are the four pieces the M9
    // runtime follow-up will compose at session start. This test
    // composes them end-to-end as a structural sanity check.
    let policy = ConnectPolicy {
        allowed: vec![api_endpoint()],
    };
    let bridge = Bridge::new(policy);
    assert!(bridge.handle_connect(&api_endpoint()).is_ok());

    let tmp = std::env::temp_dir().join(format!("asv-uat012-bridge-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let ca = SessionCa::new("sess-bridge", 99, DEFAULT_SESSION_CA_TTL);
    let binding = OpenSslEnvInjector.inject(&ca, &tmp).expect("inject OK");
    assert_eq!(binding.env_var, "SSL_CERT_FILE");
    assert!(binding.env_value.exists());

    let _ = std::fs::remove_file(&binding.env_value);
    let _ = std::fs::remove_dir(&tmp);
}

#[test]
fn uat_012_injector_is_idempotent_under_repeat_calls() {
    // The session may call `inject` more than once if the broker
    // re-spawns part of the agent's process tree. The file is
    // rewritten each time, which is structurally acceptable.
    let tmp = std::env::temp_dir().join(format!("asv-uat012-idem-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let ca = SessionCa::new("sess-idem", 5, DEFAULT_SESSION_CA_TTL);
    let b1 = OpenSslEnvInjector.inject(&ca, &tmp).expect("first");
    let b2 = OpenSslEnvInjector.inject(&ca, &tmp).expect("second");
    assert_eq!(b1.env_var, b2.env_var);
    assert_eq!(b1.env_value, b2.env_value);
    let written = std::fs::read(&b1.env_value).expect("read");
    assert_eq!(written, ca.root_der);

    let _ = std::fs::remove_file(&b1.env_value);
    let _ = std::fs::remove_dir(&tmp);
}