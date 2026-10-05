//! R2.C.3 — `asv aws whoami` through the broker, against a real TLS origin.
//!
//! # What this file is for
//!
//! `r2c2b_sts_vertical.rs` measures the *operation*: a session signed call over
//! a socket, with the token inside the signature. It never goes through the
//! product surface, so it cannot answer the question M11's rule asks — can an
//! agent name this? This file is the other half. Every request here is an
//! `asv_ipc_protocol::Request` handed to the broker's own `handle`, with a real
//! `VaultStore`, a real `AwsSecretPort`, a real Cedar policy and a real TLS
//! origin.
//!
//! # What it does not claim
//!
//! **The origin records; it does not verify the signature.** Same limit as
//! `r2c2b_sts_vertical.rs`, for the same reason: a second SigV4 verifier cannot
//! live in `asv-connector-http` without a dependency cycle, and two verifiers
//! are two things to keep correct. Signature *validity* is R2.C.1's rows
//! against AWS's published vectors. And the AWS reference states that
//! `GetCallerIdentity` answers even when access is denied, so this operation
//! could not demonstrate an accepted signature even in principle.
//!
//! **The live call against AWS is not measured here and is not claimed.** The
//! audience in this file is loopback and the region is the fixture's.
//!
//! # Why the refusals are the interesting rows
//!
//! A row asserting "the CLI reached the broker" is weak if the broker would say
//! the same thing to anything. So each refusal names the *specific* one it
//! expects, and each is one the broker could only produce after looking at what
//! the request actually said: a credential no deployment names, a policy that
//! does not permit the action, or a session the peer does not own. Every one of
//! them is asserted to have happened **before any socket**, which is the
//! property that makes an authorization worth having.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_broker::aws_binding::{AwsBinding, AwsDeployment};
use asv_broker::aws::client::{AwsCredentialConfig, StsClient};
use asv_broker::handle;
use asv_broker::{BrokerState, VaultSecretPort};
use asv_connector_http::fake_origin::{Observed, OriginResponse, TlsOrigin};
use asv_connector_http::transport::{AddressPolicy, PinnedClient, ResolvedAudience};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_policy::PolicyEngine;
use asv_vault::{KdfParams, VaultKey, VaultStore};

const CRED: &str = "5f1c2a80-9d3e-4a77-b6c1-0e2f3a4b5c6d";
const LONG_LIVED_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const SESSION_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCSESSIONKEY";
const SESSION_TOKEN: &str = "FQoGZXIvYXdzEBYaCSESSIONTOKENXX";
const ROLE: &str = "arn:aws:iam::123456789012:role/demo";

/// The origin answers the two calls differently, the way a real STS does.
fn origin() -> TlsOrigin {
    TlsOrigin::start("sts.amazonaws.com", Arc::new(|observed: &Observed| {
        if observed.body.contains("Action=GetCallerIdentity") {
            OriginResponse::new(200, identity_response())
        } else {
            OriginResponse::new(200, assume_role_response())
        }
    }))
}

fn identity_response() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/demo/asv-session</Arn>
    <UserId>ARO123EXAMPLE123:asv-session</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"#
        .to_string()
}

fn assume_role_response() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult><Credentials>
    <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
    <SecretAccessKey>{SESSION_SECRET_KEY}</SecretAccessKey>
    <SessionToken>{SESSION_TOKEN}</SessionToken>
    <Expiration>2999-01-01T00:00:00Z</Expiration>
  </Credentials></AssumeRoleResult>
</AssumeRoleResponse>"#
    )
}

/// A broker with a real vault, a real policy, a real origin and a real session.
struct Vertical {
    state: BrokerState,
    peer: WorkloadIdentity,
    origin: TlsOrigin,
    session: AgentSessionId,
    _dir: tempfile::TempDir,
}

impl Vertical {
    fn new(policy: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase = secrecy::SecretString::from("r2c3-passphrase".to_string());

        let mut store =
            VaultStore::create(dir.path().join("v.asv"), &passphrase, KdfParams::fast_for_tests())
                .expect("create vault");
        let key: VaultKey = store
            .header()
            .unlock(&passphrase)
            .expect("unlock with the passphrase just used");
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    CRED,
                    "aws-prod",
                    asv_vault::CredentialKind::Opaque,
                    "aws",
                    "Rubentxu",
                    1,
                ),
                SecretBytes::new(LONG_LIVED_KEY.as_bytes().to_vec()),
            )
            .expect("insert the credential");

        let mut state = BrokerState::default();
        // Through the same inventory pass the broker runs at startup, so this
        // fixture cannot pass by seeding a field production never writes.
        let loaded = asv_broker::inventory::load(&mut state, &store);
        assert_eq!(
            (loaded.loaded, loaded.skipped, loaded.collisions),
            (1, 0, 0),
            "the fixture vault holds exactly one credential"
        );
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        )));
        state.policy = PolicyEngine::from_policy_text(policy).expect("the policy text is valid");

        let origin = origin();
        let audience = Authority::canonicalize(&origin.certified_for).expect("canonical audience");
        let resolved = ResolvedAudience {
            authority: audience.clone(),
            port: origin.port,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        // Loopback is allowed only because the audience is loopback; the
        // production call does not allow it, and `PinnedClient` re-checks the
        // addresses it was handed either way.
        let transport = PinnedClient::build_with_roots(
            &resolved,
            AddressPolicy { allow_loopback: true },
            &[origin.certificate()],
        )
        .expect("the fixture origin is usable over the pinned audience");
        let client = Arc::new(StsClient::new(
            transport,
            resolved,
            AwsCredentialConfig {
                access_key_id: ACCESS_KEY_ID.to_string(),
                region: "us-east-1".to_string(),
                role_arn: ROLE.to_string(),
                role_session_name: "asv-session".to_string(),
                duration_seconds: 3600,
                external_id: None,
            },
        ));
        state.aws.push(AwsBinding::new(
            AwsDeployment {
                credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
                    audience,
                region: "us-east-1".to_string(),
                role_arn: ROLE.to_string(),
                role_session_name: "asv-session".to_string(),
                duration_seconds: 3600,
            },
            client,
            // The binding's own long-lived key comes from the same vault, so
            // the value the test can name and the value the broker borrows are
            // the same one.
            match state.secrets.clone() {
                Some(port) => port,
                None => panic!("the fixture just set a secret port"),
            },
        ));

        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pin this test's own process");
        let session = state
            .sessions
            .lock()
            .expect("no test holds this")
            .create("/repo".into(), &peer);

        Self {
            state,
            peer,
            origin,
            session,
            _dir: dir,
        }
    }

    /// The policy an operator writes to allow this, and only this.
    fn permitting() -> Self {
        Self::new(
            r#"permit (principal, action == Action::"aws_sts_caller_identity", resource is Api);"#,
        )
    }

    fn whoami(&mut self, credential: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::AwsCallerIdentity {
                session: self.session,
                credential: credential.to_string(),
            },
        )
    }
}

fn refusal(response: &Response) -> (ErrorCode, &str) {
    match response {
        Response::Error { code, message } => (*code, message.as_str()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The reachability claim M11's rule asks for: an agent names the operation,
/// and the answer is the provider's.
///
/// The request is an `asv_ipc_protocol::Request` handed to the broker's own
/// `handle` — the same entry point the socket path uses — so nothing here is a
/// shortcut around the dispatch.
#[test]
fn an_agent_names_the_operation_and_gets_the_providers_own_answer() {
    let mut vertical = Vertical::permitting();
    match vertical.whoami(CRED) {
        Response::AwsCallerIdentity { arn, user_id, account } => {
            assert_eq!(arn, "arn:aws:sts::123456789012:assumed-role/demo/asv-session");
            assert_eq!(user_id, "ARO123EXAMPLE123:asv-session");
            assert_eq!(account, "123456789012");
        }
        other => panic!("a permitted call was refused: {other:?}"),
    }
    // And it really did go to AWS-shaped traffic, twice: the mint and the call.
    let observed = vertical.origin.observed();
    assert_eq!(observed.len(), 2, "a mint and a call, in that order");
}

/// The property the whole block exists for, on the wire an agent receives.
///
/// `Response::AwsCallerIdentity` has three string fields, so this is close to
/// structural — but "the type cannot hold one" and "the bytes an agent parses
/// contain none" are different claims, and only the second is what a caller
/// experiences. Both are asserted, and the second is the one that would catch a
/// future field added to the response.
#[test]
fn the_encoded_response_carries_no_credential() {
    let mut vertical = Vertical::permitting();
    let response = vertical.whoami(CRED);
    let encoded = serde_json::to_string(&response).expect("the response encodes");
    for secret in [LONG_LIVED_KEY, SESSION_SECRET_KEY, SESSION_TOKEN] {
        assert!(!encoded.contains(secret), "a credential reached the caller: {encoded}");
    }
    // And the row is not passing on an empty string.
    assert!(encoded.contains("assumed-role/demo/asv-session"), "{encoded}");
}

/// The audit has to answer "who spent this credential" without being a second
/// copy of the credential.
#[test]
fn the_audit_record_of_the_call_carries_no_credential() {
    let mut vertical = Vertical::permitting();
    vertical.whoami(CRED);

    let log = vertical.state.audit.lock().expect("no test holds this");
    // `query(0)` is the only read the log offers, and it is the same one the
    // operator console uses.
    let records = format!("{:?}", log.query(0));
    assert!(
        records.contains("aws") || records.contains("AwsCallerIdentity"),
        "the call left no audit trace: {records}"
    );
    for secret in [LONG_LIVED_KEY, SESSION_SECRET_KEY, SESSION_TOKEN] {
        assert!(!records.contains(secret), "a credential reached the audit: {records}");
    }
}

/// A credential no deployment names is refused, and it is refused *before* any
/// socket — the request is the untrusted side of this socket, so a credential
/// nobody configured must not get as far as a network call.
#[test]
fn a_credential_no_deployment_names_is_refused_before_any_socket() {
    let mut vertical = Vertical::permitting();
    // A *well-formed* id that was never enrolled. A malformed one would be
    // refused earlier as `InvalidRequest`, and the row would then be measuring
    // the parse rather than the deployment lookup -- and "not granted" and "you
    // called me wrong" are different answers a caller needs to tell apart.
    let asked = vertical.whoami("00000000-0000-4000-8000-0000deadbeef");
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(
        message.contains("00000000-0000-4000-8000-0000deadbeef"),
        "the refusal does not name what was asked for: {message}"
    );
    // The message says what *is* configured, because an agent that cannot find
    // its credential needs to tell "not granted" from "misspelled".
    assert!(
        message.contains(CRED),
        "the refusal does not list the configured deployments: {message}"
    );
    assert!(vertical.origin.observed().is_empty(), "a refused request reached AWS");
}

/// A stock policy permits nothing here, and the omission is the point.
///
/// The built-in policy text has no `permit` for this action, so an operator who
/// upgrades starts refusing every AWS call rather than answering them. Widening
/// it is an explicit policy edit somebody can see in a diff.
#[test]
fn a_stock_policy_refuses_the_operation_before_any_socket() {
    let mut vertical = Vertical::new("");
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    // The message carries the `Display` spelling (`aws.sts.caller_identity`),
    // not the Cedar one (`aws_sts_caller_identity`). Both spellings are the same
    // verb, and this row is about the *decision*, so it pins the form that
    // actually reaches an operator.
    assert!(message.contains("aws.sts.caller_identity"), "{message}");
    assert!(vertical.origin.observed().is_empty(), "a denied request reached AWS");
}

/// A session this peer does not own is refused, before any socket.
///
/// **The fixture cannot express "another peer", and knowing why is the point.**
/// `SessionStore::belongs_to` compares the peer's **pid**, not its whole
/// identity, so a second `WorkloadIdentity` built in this process *is* the same
/// peer as far as the store is concerned. The first draft of this row built one
/// with a different gid, which the store cannot see — so the row would have
/// measured the deployment lookup instead of ownership while claiming to measure
/// ownership.
///
/// What is measurable in-process is "a session this peer does not own", and that
/// is what it now asserts. Genuinely another peer needs a second process, which
/// is what the CLI-reachability file is for.
#[test]
fn a_session_this_peer_does_not_own_is_refused_before_any_socket() {
    let mut vertical = Vertical::permitting();
    let response = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::AwsCallerIdentity {
            // A real, well-formed id that was never created, so the refusal is
            // ownership rather than a parse error.
            session: AgentSessionId::new(),
            credential: CRED.to_string(),
        },
    );
    let (code, message) = refusal(&response);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("not owned"), "{message}");
    assert!(vertical.origin.observed().is_empty(), "an unowned session reached AWS");
}

/// A broker with no deployment configured refuses everything, and says so.
///
/// The empty reading is the fail-closed one: a deployment that has not said
/// which role it may assume is not a deployment that gets to assume whatever a
/// request asks for.
#[test]
fn a_broker_with_no_deployment_configured_refuses_every_aws_request() {
    let mut vertical = Vertical::permitting();
    vertical.state.aws.clear();
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("configured"), "{message}");
    assert!(vertical.origin.observed().is_empty(), "an unconfigured broker reached AWS");
}

/// Ending the session stops the next call, so an AWS operation cannot outlive
/// the authority that authorized it.
#[test]
fn ending_the_session_stops_further_aws_calls() {
    let mut vertical = Vertical::permitting();
    assert!(matches!(
        vertical.whoami(CRED),
        Response::AwsCallerIdentity { .. }
    ));
    handle(
        &mut vertical.state,
        &vertical.peer,
        Request::EndSession {
            session: vertical.session,
        },
    );
    let after = vertical.whoami(CRED);
    let (code, message) = refusal(&after);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("not owned") || message.contains("revoked"), "{message}");
}

/// The operator's audience, not the request's.
///
/// There is no audience in the request type at all, so this row is really about
/// the deployment: the signed request goes to the host the *deployment* names.
/// If the two could diverge, a signature would be computed for one place and
/// sent to another, and the signature would be the only thing in the request
/// that disagreed with where it went.
#[test]
fn the_request_goes_to_the_deployments_audience() {
    let mut vertical = Vertical::permitting();
    vertical.whoami(CRED);
    let observed = vertical.origin.observed();
    assert!(!observed.is_empty(), "the call never reached the origin");
    for request in observed {
        let host = request
            .header("host")
            .expect("a signed request carries a Host");
        // The `Host` carries the port too, and it must: the fixture origin is on
        // a loopback port and a Host that disagreed with the request line is a
        // header SigV4 signs. So the property is that the *authority* is the one
        // the deployment named, not that the header is a bare string equal to it.
        let authority = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        assert_eq!(
            authority,
            vertical.origin.certified_for,
            "the request went somewhere the deployment did not name: {host}"
        );
    }
}

/// A broker with no vault open refuses, and says why.
///
/// The check is not decorative: without it the deployment's binding would try to
/// borrow a long-lived key from a port that does not exist, and "no vault" would
/// arrive at the operator as a transport failure naming AWS.
#[test]
fn a_broker_with_no_vault_open_refuses_before_any_socket() {
    let mut vertical = Vertical::permitting();
    vertical.state.secrets = None;
    let asked = vertical.whoami(CRED);
    let (code, message) = refusal(&asked);
    assert_eq!(code, ErrorCode::Denied);
    assert!(message.contains("credential store"), "{message}");
    assert!(vertical.origin.observed().is_empty(), "an unvaulted broker reached AWS");
}

/// A binding printed whole names the deployment and none of the sessions.
///
/// `AwsBinding` reaches an `AwsSecretPort`, which holds sessions, so a derived
/// `Debug` is a session in an operator's log with a `{:?}` away. The deployment
/// half is asserted too, because a `Debug` that hides everything is not a fix —
/// it is the same defect pointing the other way.
#[test]
fn a_binding_printed_never_prints_a_session() {
    let mut vertical = Vertical::permitting();
    vertical.whoami(CRED);
    let printed = format!("{:?}", vertical.state.aws[0]);
    for secret in [LONG_LIVED_KEY, SESSION_SECRET_KEY, SESSION_TOKEN] {
        assert!(!printed.contains(secret), "a credential reached the binding's Debug");
    }
    assert!(printed.contains(ROLE), "the printed binding lost the role: {printed}");
    assert!(printed.contains(CRED), "the printed binding lost the credential: {printed}");
}

/// An agent that asks the broker what it can do is told about this one.
///
/// The defect this row exists for: the whole vertical — action, typed request,
/// broker operation, CLI verb — was built and *not advertised*, so
/// `asv capabilities` reported a product with no AWS path. Every other row here
/// would have stayed green. The operation worked and was invisible, which is
/// not a smaller version of missing; it is the same gap with a working thing
/// behind it.
///
/// Asked through `AgentInfo` rather than by reading the field, because that is
/// the request `asv capabilities` and `asv discover` actually make.
#[test]
fn an_agent_asking_what_the_broker_can_do_is_told_about_aws() {
    let mut vertical = Vertical::permitting();
    let response = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::AgentInfo {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
    );
    let capabilities = match response {
        Response::BrokerInfo { capabilities, .. } => capabilities,
        other => panic!("expected a self-description, got {other:?}"),
    };
    assert!(
        capabilities.iter().any(|c| c == "aws.sts.caller_identity"),
        "the broker serves aws.sts.caller_identity and does not advertise it, so an \
         agent reading its capabilities is told the product cannot do it: {capabilities:?}"
    );
}

/// The advertised list never claims a capability that returns a secret.
///
/// Not specific to AWS: this is the property that makes the list safe to print,
/// and it is asserted here because the increment above added a name to it.
#[test]
fn the_advertised_aws_capability_does_not_name_a_retrieval() {
    let mut vertical = Vertical::permitting();
    let response = handle(
        &mut vertical.state,
        &vertical.peer,
        Request::AgentInfo {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
    );
    let capabilities = match response {
        Response::BrokerInfo { capabilities, .. } => capabilities,
        other => panic!("expected a self-description, got {other:?}"),
    };
    for capability in capabilities.iter().filter(|c| c.starts_with("aws.")) {
        let lowered = capability.to_lowercase();
        for forbidden in ["get", "reveal", "export", "plaintext", "credential_value"] {
            assert!(
                !lowered.contains(forbidden),
                "`{capability}` reads as a retrieval capability; no advertised name may \
                 return a secret (ADR-0001)"
            );
        }
    }
}
