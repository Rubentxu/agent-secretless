//! B1.11's ephemeral boundary check: `asv oauth2 whoami` against a hostile
//! identity provider, end to end through the real CLI binary.
//!
//! The block's AAT (roadmap, `docs/plans/b1-delivery-roadmap.md` B1.11 T4):
//! the error the operator reads from the CLI must not contain the client
//! secret a hostile IdP reflected in its RFC 6749 §5.2 error body. The
//! sanitization itself is pinned by permanent rows in `asv-broker`
//! (`oauth2.rs`, `oauth2_provider.rs`); what only this file can see is the
//! whole journey — real IPC socket, real `asv` process, both the prose and
//! `--json` renderings the operator actually reads.
//!
//! The broker is served in-process because the production `asv-brokerd`
//! hard-codes the production issuer factory, whose address policy refuses
//! loopback by design; the fixture IdP is a named loopback TLS origin. The
//! accept loop below is a one-connection-at-a-time mirror of the daemon's
//! `serve` (peer credentials first, one bounded read, `handle`, one write),
//! so the requests the CLI sends are served by the broker's own dispatch.
//!
//! Ephemeral by the block's working pattern: deleted at block close, before
//! the `b1.11` tag, with the permanent rows carrying the property forward.

use std::io::{Read, Write};
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asv_broker::oauth2::{ClientCredentialsIssuer, OAuth2Config, OAuth2Error};
use asv_broker::oauth2_binding::{OAuth2Binding, OAuth2Deployment};
use asv_broker::oauth2_port::{
    OAuth2Client, OAuth2IssuerFactory, OAuth2SecretPort, RoutingSecretPort,
};
use asv_broker::oauth2_test_support::{AsClient, AuthorizationServer, RESOURCE_AUDIENCE};
use asv_broker::{handle, BrokerState, VaultSecretPort};
use asv_connector_http::transport::AddressPolicy;
use asv_connector_http::{ResolvedAudience, SecretPort};
use asv_domain::{Authority, CredentialId, SecretBytes};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{decode_request, encode_response, ErrorCode, Response};
use asv_policy::PolicyEngine;
use asv_vault::{CredentialKind, CredentialMetadata, KdfParams, VaultKey, VaultStore};

/// The credential as `asv credentials` prints it: the only spelling a request
/// can carry, and the one the registration and the policy below both name.
const CRED: &str = "7c3e1a90-2b44-4d61-9f08-5e6a7b8c9d01";
const SCOPE: &str = "read:pods";

/// An issuer factory pointing the real `ClientCredentialsIssuer` at the
/// fixture's loopback TLS origin, exactly as the broker's own vertical tests
/// do: the loopback opt-in is the factory's to make, never production's.
struct FixtureIssuer {
    certificate: asv_connector_http::Certificate,
    host: String,
    port: u16,
}

impl OAuth2IssuerFactory for FixtureIssuer {
    fn issuer(
        &self,
        config: OAuth2Config,
    ) -> Result<Box<dyn asv_broker::oauth2::OAuth2Issuer>, OAuth2Error> {
        let issuer = ClientCredentialsIssuer::with_resolved(
            config,
            &ResolvedAudience {
                authority: Authority::canonicalize(&self.host)
                    .expect("the fixture host is canonical"),
                port: self.port,
                addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            },
            AddressPolicy {
                allow_loopback: true,
            },
            std::slice::from_ref(&self.certificate),
        )
        .expect("an issuer against the fixture");
        Ok(Box::new(issuer))
    }
}

/// A broker whose IdP is hostile: it rejects the (wrong) secret the vault
/// holds *and* reflects the real one in every error body. The vault secret is
/// wrong on purpose — the exchange must fail so the error path is the one the
/// CLI renders, and the reflected text is the real secret so a leak here is a
/// live credential and not a canary that never was.
fn hostile_broker(
    dir: &std::path::Path,
    server: &AuthorizationServer,
    client: &AsClient,
) -> BrokerState {
    let passphrase = secrecy::SecretString::from("eph-b1-11-passphrase".to_string());
    let mut store = VaultStore::create(dir.join("v.asv"), &passphrase, KdfParams::fast_for_tests())
        .expect("create vault");
    let key: VaultKey = store
        .header()
        .unlock(&passphrase)
        .expect("unlock with the passphrase just used");
    store
        .insert(
            &key,
            CredentialMetadata::new(
                CRED,
                "hostile idp client",
                CredentialKind::BearerToken,
                "oauth2",
                "eph",
                1,
            ),
            SecretBytes::new(b"not-the-real-secret".to_vec()),
        )
        .expect("insert the credential");

    let mut state = BrokerState::default();
    let loaded = asv_broker::inventory::load(&state, &store);
    assert_eq!(
        (loaded.loaded, loaded.skipped, loaded.collisions),
        (1, 0, 0),
        "the fixture vault holds exactly one credential"
    );

    let vault: Arc<dyn SecretPort> = Arc::new(VaultSecretPort::new(
        Arc::new(Mutex::new(store)),
        Arc::new(key),
    ));
    let oauth2: Arc<dyn SecretPort> = Arc::new(OAuth2SecretPort::with_parts(
        Arc::clone(&vault),
        vec![OAuth2Client {
            credential: CRED.to_string(),
            client_id: client.client_id.clone(),
            token_url: server.url("/token"),
            audience: RESOURCE_AUDIENCE.to_string(),
            scope: SCOPE.to_string(),
        }],
        Arc::new(FixtureIssuer {
            certificate: server.certificate(),
            host: server.host().to_string(),
            port: server.port(),
        }),
    ));
    let routing: Arc<dyn SecretPort> = Arc::new(RoutingSecretPort::new(oauth2, vault));
    state.secrets = Some(Arc::clone(&routing));

    let host = Authority::canonicalize(server.host()).expect("the fixture host is canonical");
    state.oauth2.push(
        OAuth2Binding::with_test_transport(
            OAuth2Deployment {
                credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
                token_endpoint: host.clone(),
                resource: host,
                resource_port: server.port(),
                audience: RESOURCE_AUDIENCE.to_string(),
                registered_scope: SCOPE.to_string(),
            },
            client.client_id.clone(),
            routing,
            ResolvedAudience {
                authority: Authority::canonicalize(server.host()).expect("canonical"),
                port: server.port(),
                addresses: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            },
            AddressPolicy {
                allow_loopback: true,
            },
            std::slice::from_ref(&server.certificate()),
        )
        .expect("the fixture resource is usable over a pinned loopback client"),
    );

    state.policy = PolicyEngine::from_policy_text(&format!(
        r#"permit (principal, action == Action::"oauth2_identity",
               resource == OAuth2Client::"oauth2:{CRED}");"#
    ))
    .expect("the policy text is valid");

    state
}

/// One connection, served the way the daemon serves it: identity from the
/// kernel before any request byte, one bounded read, the broker's own
/// `handle`, one write. The ephemeral cannot import the daemon's `serve`
/// (it lives in the binary), so it mirrors it, and the mirror stays honest
/// by being this small.
fn serve_one(state: &BrokerState, stream: UnixStream) -> std::io::Result<()> {
    let creds = asv_identity::peer_credentials(&stream.as_fd())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
    let mut identity = WorkloadIdentity::from_peer(creds);
    let _ = identity.pin_pidfd();

    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    let mut buf = vec![0u8; asv_ipc_protocol::MAX_MESSAGE_BYTES + 1];
    let n = reader.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let response = match decode_request(&buf[..n]) {
        Ok(request) => handle(state, &identity, request),
        Err(e) => Response::Error {
            code: ErrorCode::UnknownMethod,
            message: e.to_string(),
        },
    };
    let bytes = encode_response(&response).map_err(|e| std::io::Error::other(e.to_string()))?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Serves connections until `stop` is set, with the accept loop in
/// non-blocking mode so the test can end it without killing the thread.
fn serve_socket(listener: UnixListener, state: Arc<BrokerState>, stop: Arc<AtomicBool>) {
    listener
        .set_nonblocking(true)
        .expect("the ephemeral server can go non-blocking");
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("the accepted stream goes back to blocking");
                let _ = serve_one(&state, stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return,
        }
    }
}

/// Runs `asv oauth2 whoami` against `socket` and returns (exit code, stdout,
/// stderr). `extra` carries `--json` for the envelope rendering.
fn whoami(socket: &std::path::Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_asv"))
        .env("ASV_SOCKET", socket)
        .args(["oauth2", "whoami", "--credential", CRED])
        .args(extra)
        .output()
        .expect("the asv binary runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The AAT: both renderings the operator can read — prose and `--json` —
/// refuse the hostile provider's exchange without ever showing the secret it
/// reflected.
#[test]
fn the_cli_whoami_error_does_not_contain_the_reflected_secret() {
    let client = AsClient::awkward();
    let server = AuthorizationServer::start(client.clone());
    server.reflect_in_errors(&client.client_secret);

    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("broker.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind the ephemeral socket");

    let state = Arc::new(hostile_broker(dir.path(), &server, &client));
    let stop = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let state = Arc::clone(&state);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || serve_socket(listener, state, stop))
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    // The CLI retries nothing, but the socket must exist before the first
    // connect, and it does: bind happened above. Serve, then stop.
    for extra in [&[] as &[&str], &["--json"]] {
        let (code, stdout, stderr) = whoami(&socket_path, extra);
        assert!(
            Instant::now() < deadline,
            "the ephemeral server or the CLI stalled"
        );
        assert_eq!(
            code,
            Some(1),
            "whoami against a hostile IdP must fail, not succeed silently"
        );
        for (name, stream) in [("stdout", &stdout), ("stderr", &stderr)] {
            assert!(
                !stream.contains(&client.client_secret),
                "the reflected client secret reached the CLI's {name}:\n{stream}"
            );
        }
    }

    stop.store(true, Ordering::SeqCst);
    server_thread
        .join()
        .expect("the ephemeral server thread ends");

    // The exchange really reached the hostile provider, so the absence above
    // is the boundary's doing and not a broker that never asked.
    assert_eq!(
        server.audit_with_outcome("bad_credentials").len(),
        2,
        "one hostile rejection per rendering, both against the real token endpoint"
    );
}
