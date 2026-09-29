//! UAT-021 — Isolated worker egress.
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md`:
//!
//! > Worker tool intentionally tries to send secret to unauthorized sink.
//! > Expected: network confinement blocks sink. This demonstrates why
//! > output redaction alone is insufficient.
//!
//! M10-R2 specifies that `EgressPolicy` authorises only the explicit
//! allow-list. UAT-021 is the structural claim that the policy fires
//! before the worker can open the sink socket.

use asv_broker::isolated_exec::{EgressPolicy, WorkerTemplate, WorkerRegistry};
use asv_broker::tls_bridge::AuthorityEndpoint;
use asv_domain::Authority;

fn auth(s: &str) -> Authority {
    Authority::canonicalize(s).expect("host")
}

fn api_endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(auth("api.example.com"), 443).expect("endpoint")
}

fn attacker_endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("endpoint")
}

#[test]
fn uat_021_deny_policy_blocks_all_sinks() {
    let p = EgressPolicy::Deny;
    assert!(!p.authorises(&api_endpoint()));
    assert!(!p.authorises(&attacker_endpoint()));
}

#[test]
fn uat_021_allow_list_permits_only_listed_sinks() {
    let p = EgressPolicy::Allow(vec![api_endpoint()]);
    assert!(p.authorises(&api_endpoint()));
    assert!(!p.authorises(&attacker_endpoint()));
}

#[test]
fn uat_021_allow_list_must_be_exact_host_and_port() {
    // The allow-list is per (host, port). Same host, different port is
    // denied. This is the structural guarantee that a port-mismatch
    // cannot leak to an unexpected upstream.
    let p = EgressPolicy::Allow(vec![api_endpoint()]);
    let wrong_port =
        AuthorityEndpoint::new(auth("api.example.com"), 8443).expect("endpoint");
    assert!(!p.authorises(&wrong_port));
}

#[test]
fn uat_021_registered_worker_carries_egress_policy() {
    // The worker template is the unit of registration. A registered
    // worker's egress policy is what the runtime uses to authorise
    // sink sockets.
    let t = WorkerTemplate {
        name: "kubectl-worker".into(),
        binary: "/usr/bin/kubectl".into(),
        arguments: vec!["get".into(), "pods".into()],
        secret_injection: asv_broker::isolated_exec::SecretInjectionPlan::EnvVar {
            name: "KUBE_TOKEN".into(),
        },
        egress_policy: EgressPolicy::Allow(vec![api_endpoint()]),
        landlock_profile: Default::default(),
        seccomp_profile: asv_broker::isolated_exec::SeccompProfile::ClosedAllowList,
    };
    let r = WorkerRegistry::new(vec![t]);
    let resolved = r.get("kubectl-worker").expect("registered");
    assert!(resolved.egress_policy.authorises(&api_endpoint()));
    assert!(!resolved.egress_policy.authorises(&attacker_endpoint()));
}

#[test]
fn uat_021_unregistered_worker_is_refused() {
    // The structural guarantee: a worker that is not in the registry
    // cannot run. This is the "registered worker templates only" rule
    // from the M10 spec.
    let r = WorkerRegistry::new(vec![WorkerTemplate {
        name: "kubectl-worker".into(),
        binary: "/usr/bin/kubectl".into(),
        arguments: vec![],
        secret_injection: asv_broker::isolated_exec::SecretInjectionPlan::None,
        egress_policy: EgressPolicy::Deny,
        landlock_profile: Default::default(),
        seccomp_profile: asv_broker::isolated_exec::SeccompProfile::ClosedAllowList,
    }]);
    assert!(r.get("kubectl-worker-evil").is_none());
    assert!(r.get("bash").is_none());
    assert!(r.get("env").is_none());
}