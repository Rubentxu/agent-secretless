//! Rows for the deployment declaration.
//!
//! The interesting refusals here are the ones about the in-cluster exception,
//! because a Kubernetes API server is nearly always a private address and the
//! transport refuses those by default. Every rule below is about keeping that
//! exception from becoming the general hole it could easily be.

use std::path::PathBuf;

use asv_domain::{Authority, CredentialId};

use super::{
    DEFAULT_KUBELET_PORT, DeploymentError, InCluster, K8sBinding, K8sDeployment, PROJECTED_TOKEN_PATH,
};

fn credential() -> CredentialId {
    CredentialId::from_wire("5f1c2a80-9d3e-4a77-b6c1-0e2f3a4b5c6d").expect("a wire credential id")
}

fn deployment(audience: &str) -> K8sDeployment {
    K8sDeployment {
        credential: credential(),
        audience: Authority::canonicalize(audience).expect("canonical audience"),
        port: DEFAULT_KUBELET_PORT,
        token_path: PathBuf::from(PROJECTED_TOKEN_PATH),
        in_cluster: None,
    }
}

/// # The in-cluster exception
///
/// This is the whole reason the module exists.

#[test]
fn a_private_audience_is_refused_when_the_operator_did_not_declare_it() {
    let err = deployment("kubernetes.default.svc")
        .check(true)
        .expect_err("a private audience is refused by default");

    assert_eq!(
        err,
        DeploymentError::PrivateAudienceUndeclared {
            audience: Authority::canonicalize("kubernetes.default.svc").expect("canonical")
        },
        "{err:?}"
    );
}

#[test]
fn the_refusal_says_what_to_do_rather_than_only_what_failed() {
    // An operator who reads "connection refused" adds a network rule. An
    // operator who reads this adds one field to a config file. The difference
    // is the size of the hole.
    let err = deployment("kubernetes.default.svc")
        .check(true)
        .expect_err("undeclared");
    let rendered = format!("{err}");

    assert!(rendered.contains("declare"), "the refusal must say how: {rendered}");
    assert!(rendered.contains("private"), "and must say why: {rendered}");
}

#[test]
fn a_declared_cluster_name_is_accepted_for_a_private_audience() {
    deployment("kubernetes.default.svc")
        .in_cluster()
        .check(true)
        .expect("a declared in-cluster deployment is the normal case");
}

#[test]
fn a_cluster_local_name_is_accepted_too() {
    deployment("kubernetes.default.svc.cluster.local")
        .in_cluster()
        .check(true)
        .expect("the fully qualified form is the same name");
}

/// # The exception may not become a hole

#[test]
fn an_ip_literal_may_not_declare_itself_in_cluster() {
    // This is the rule that keeps the exception narrow. Without it, "allow the
    // private address" is one flag away from "allow any address the broker can
    // reach", and a name-based check is what says no.
    let err = deployment("10.0.0.5")
        .in_cluster()
        .check(true)
        .expect_err("an IP literal is not a cluster DNS name");

    assert!(matches!(err, DeploymentError::NotAClusterName { .. }), "{err:?}");
}

#[test]
fn a_name_that_only_looks_like_a_cluster_name_is_refused() {
    // `evil.svc.attacker.example` ends with something an operator might
    // recognise, and the suffix check has to be anchored to the *whole* name
    // rather than to a fragment of it.
    let err = deployment("kubernetes.default.svc.attacker.example")
        .in_cluster()
        .check(true)
        .expect_err("the suffix has to be the end of the name");

    assert!(matches!(err, DeploymentError::NotAClusterName { .. }), "{err:?}");
}

#[test]
fn a_bare_suffix_is_refused_before_the_in_cluster_check_ever_sees_it() {
    // `.svc` is a suffix, not a name, and the first version of this row assumed
    // `InCluster::matches` was what turned it away. It is not: `Authority`
    // refuses to construct one at all. The row is kept, and rewritten, because
    // knowing *which layer* closes a case is the difference between a check you
    // can reason about and one you are relying on by luck — and a future
    // loosening of `Authority` would leave this module's suffix check as the
    // only thing standing there, which is a fact worth having written down.
    assert!(
        Authority::canonicalize(".svc").is_err(),
        "a bare suffix must not be constructible as an audience"
    );
}

#[test]
fn a_public_audience_may_not_carry_the_exception() {
    // Harmless in itself, and refused because a configuration carrying an
    // exception that does nothing is a configuration nobody has read — and the
    // next person to add a public audience to that file inherits a habit.
    let err = deployment("api.example.com")
        .in_cluster()
        .check(false)
        .expect_err("the exception means nothing for a public audience");

    assert!(matches!(
        err,
        DeploymentError::ExceptionOnAPublicAudience { .. }
    ), "{err:?}");
}

#[test]
fn a_public_audience_without_the_exception_is_accepted() {
    // The other side, so the refusal above is not just "everything is refused".
    deployment("api.example.com")
        .check(false)
        .expect("a public audience needs no exception");
}

/// # The rest of the load-time checks
///
/// All of these refuse at load rather than at the first call, which is the
/// whole reason `check` is separate from `K8sBinding::new`.

#[test]
fn a_relative_token_path_is_refused_at_load() {
    let mut d = deployment("kubernetes.default.svc").in_cluster();
    d.token_path = PathBuf::from("var/run/secrets/token");
    let err = d.check(true).expect_err("a relative path depends on the cwd");

    assert!(
        matches!(err, DeploymentError::RelativeTokenPath { .. }),
        "{err:?}"
    );
}

#[test]
fn a_port_of_zero_is_refused() {
    let mut d = deployment("kubernetes.default.svc").in_cluster();
    d.port = 0;
    let err = d.check(true).expect_err("port 0 never connects");

    assert_eq!(err, DeploymentError::ZeroPort);
}

#[test]
fn the_port_refusal_comes_before_the_audience_refusal() {
    // Order is a decision, not an accident: a deployment that is wrong in two
    // ways should be told about the one that would have stopped it at load
    // anyway. Both are refused, and the first one named is the cheaper fix.
    let mut d = deployment("10.0.0.5");
    d.port = 0;
    let err = d.check(true).expect_err("two things are wrong");

    assert_eq!(err, DeploymentError::ZeroPort, "{err:?}");
}

#[test]
fn a_deployment_whose_token_file_does_not_exist_still_loads() {
    // The constructor reads nothing, so a kubelet that has not projected the
    // token yet — or a broker that restarts before the pod does — is not a
    // startup failure. The path is checked for shape, not for existence.
    let mut d = deployment("kubernetes.default.svc").in_cluster();
    d.token_path = PathBuf::from("/nonexistent/asv/k8s/token");

    d.check(true).expect("a missing file is a lend-time problem, not a load-time one");
}

/// # The exception has to be visible where it is in force

#[test]
fn a_binding_says_that_it_is_using_the_in_cluster_exception() {
    // The declaration is carried on the thing that holds it, so an operator
    // reading a `Debug` of the live binding can see that the address policy is
    // not what it is everywhere else.
    let deployment = deployment("kubernetes.default.svc").in_cluster();
    let rendered = format!("{deployment:?}");

    assert!(
        rendered.contains("InCluster"),
        "the exception must be visible in the declaration: {rendered}"
    );
}

#[test]
fn a_deployment_without_the_exception_does_not_claim_one() {
    let rendered = format!("{:?}", deployment("api.example.com"));

    assert!(
        !rendered.contains("InCluster"),
        "nothing may claim an exception that is not in force: {rendered}"
    );
}

/// # The positive rows

#[test]
fn the_projected_token_path_is_the_one_kubernetes_actually_uses() {
    // The first version of this row read the path out of the deployment built
    // by the fixture above — and the fixture held the literal, not the product.
    // So the row was pinning its own test and would have stayed green through
    // any change to the shipped path. It now compares the product constant
    // against the documented string, which is the only version of this that can
    // fail.
    assert_eq!(
        PROJECTED_TOKEN_PATH,
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "the projected-token path moved; every real deployment would fail"
    );
}

#[test]
fn a_deployment_that_is_correct_would_not_pass_a_check_that_refused_everything() {
    // The counterpart to the refusals above, and the reason they mean anything.
    assert!(InCluster::matches(
        &Authority::canonicalize("kubernetes.default.svc").expect("canonical")
    ));
    assert!(!InCluster::matches(
        &Authority::canonicalize("10.0.0.5").expect("canonical")
    ));
}

/// # The binding
///
/// These need a `K8sBinding`, which the first version of this module could not
/// build in a row: `K8sBinding::new` constructed the client, and constructing a
/// client performs the DNS pin. Taking the client instead — the split
/// `AwsBinding::new` already uses — makes the wiring testable without a
/// network, and these are the rows that say so.

fn binding(deployment: K8sDeployment) -> K8sBinding {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use asv_connector_http::transport::{AddressPolicy, ResolvedAudience};

    use super::super::client::K8sClient;

    let resolved = ResolvedAudience {
        authority: deployment.audience.clone(),
        port: deployment.port,
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let client = K8sClient::new_with_roots(
        resolved,
        AddressPolicy { allow_loopback: true },
        Some(std::time::Duration::from_secs(5)),
        &[],
    )
    .expect("the fixture audience is acceptable to a pinned client");
    K8sBinding::new(deployment, Arc::new(client)).expect("the deployment wires")
}

#[test]
fn a_binding_serves_the_credential_it_declares() {
    let binding = binding(deployment("kubernetes.default.svc").in_cluster());

    assert!(
        binding.serves(&credential()),
        "a request naming the declared credential must reach this binding"
    );
}

#[test]
fn a_binding_serves_nothing_else() {
    // The other half, and the reason `serves` exists at all: an agent must not
    // be able to reach a cluster it was not configured for by guessing an id.
    let binding = binding(deployment("kubernetes.default.svc").in_cluster());
    let other = CredentialId::from_wire("11111111-2222-3333-4444-555555555555")
        .expect("a wire credential id");

    assert!(!binding.serves(&other), "an unconfigured credential reached a binding");
}

#[test]
fn the_bindings_debug_carries_the_declaration_and_nothing_else() {
    // `finish_non_exhaustive` rather than a derived `Debug`: the port is added
    // to this struct over time, and a derived one would start printing it the
    // day that happened, without anyone deciding to.
    //
    // The first version of this row asserted the rendering did not contain the
    // text "port", which failed on the deployment's own `port: 6443` — a field
    // that is supposed to be printed. What it means is the *port object*, and
    // the check is on the type name a derived `Debug` would have used.
    let binding = binding(deployment("kubernetes.default.svc").in_cluster());
    let rendered = format!("{binding:?}");

    assert!(rendered.contains("kubernetes.default.svc"), "{rendered}");
    assert!(rendered.contains("InCluster"), "{rendered}");
    assert!(
        !rendered.contains("K8sSecretPort"),
        "the lending port must not be printed: {rendered}"
    );
    assert!(
        rendered.trim_end().ends_with(".. }"),
        "the rendering must be explicitly non-exhaustive: {rendered}"
    );
}
