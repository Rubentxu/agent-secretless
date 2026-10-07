//! B1: a slow provider must not delay another session.
//!
//! # Why this row is not the same as the worker one
//!
//! `b1_worker_does_not_serialize_the_broker.rs` proved that a slow *worker*
//! does not freeze the broker, and it did so by finding a lock that was held
//! across the child's whole life. The question this file asks is whether the
//! other slow thing in the protocol behaves the same way, because it gets there
//! by a completely different route.
//!
//! A provider request is not one long call into a child. It is a chain: admit
//! the session, check the pin, redeem a surrogate, evaluate policy, resolve a
//! *declared* registry, build a client, and only then talk to the network. Every
//! one of those steps could hold a lock, and the network call is the one that
//! takes seconds. So the shape to measure is specific: does anything stay held
//! between "the broker starts dialling" and "the broker has its answer".
//!
//! # Why the provider here is a real one
//!
//! The origin below is a real TLS server with a real certificate and a real
//! token exchange in front of it. It is not a mock client and it is not a stub
//! factory: `ConnectorFactory` returns concrete client types, so the only way
//! to make a provider slow is to make the thing it talks to slow. The handler
//! accepts the connection and then sleeps, which is what an unresponsive
//! registry looks like from inside the broker.
//!
//! The token exchange is deliberately *not* slowed. A handler that slept on
//! every request would also delay the realm, and the row would end up measuring
//! two stalls at once.
//!
//! # The witness
//!
//! Asserting that a second session was created would pass on a broker whose
//! first request had already finished. So the row also requires the provider
//! call to still be running at the instant the second session appeared — the
//! same two-part shape as the worker row, for the same reason.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use asv_broker::{handle, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::fake_origin::{Observed, OriginResponse, TlsOrigin};
use asv_connector_http::registry::client::{RegistryClient, RegistryError};
use asv_connector_http::{AddressPolicy, Certificate, GithubClient, ResolvedAudience};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{Request, Response};
use asv_policy::PolicyEngine;
use asv_vault::{KdfParams, VaultKey, VaultStore};

/// A registry-shaped password, so a leak would be recognisable as one.
const CANARY: &str = "hunter2-the-real-registry-password";

/// A canonical vault id, spelled the way `asv credentials` prints it.
const CRED: &str = "3f7c1d92-4a6b-4c1e-9d3f-2b8e5a7c0d14";

/// Two labels, because `Authority::canonicalize` refuses a bare one and the
/// origins certify for it.
const NAME: &str = "localhost.localdomain";

const REPOSITORY: &str = "library/alpine";

const MANIFEST: &[u8] = br#"{"schemaVersion":2,"layers":[{"digest":"sha256:aa"}]}"#;

/// How long the origin accepts a request and then says nothing.
///
/// Comfortably longer than the row's patience, so a provider that is genuinely
/// mid-call cannot be confused with one that returned quickly. It is also
/// shorter than the client-side timeouts, so the row finishes as a measurement
/// rather than as a test that waits out a transport deadline.
const STALL: Duration = Duration::from_secs(8);

/// How long a second agent may wait while the provider is still talking.
///
/// A serialising broker cannot answer until the stall ends, so the two designs
/// are separated by 4x.
const CONCURRENT_ANSWER: Duration = Duration::from_secs(2);

/// The mint permit every policy below is composed with.
fn composed(extra: &str) -> String {
    format!(
        "permit (principal, action == Action::\"github_issue_read\", resource is Api);\n{extra}"
    )
}

/// Permits a pull from any declared registry, and nothing else.
const PULL_ANY: &str = r#"
permit (principal, action == Action::"registry_pull", resource is Registry);
"#;

struct Stalling {
    resolved: ResolvedAudience,
    roots: Vec<Certificate>,
    realm_port: u16,
}

impl ConnectorFactory for Stalling {
    fn github(
        &self,
        _audience: Authority,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<GithubClient, asv_connector_http::GithubError> {
        // No test roots: this row never asks GitHub for anything, and a
        // client built to trust the fixture's CAs would be a second thing the
        // row could accidentally depend on.
        Ok(GithubClient::pinned_to(
            self.resolved.clone(),
            AddressPolicy {
                allow_loopback: true,
            },
            secrets,
        ))
    }

    fn registry(
        &self,
        _audience: Authority,
        credential: CredentialId,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<RegistryClient, RegistryError> {
        Ok(RegistryClient::trusting(
            secrets,
            credential.to_wire(),
            AddressPolicy {
                allow_loopback: true,
            },
            self.roots.clone(),
        )
        .reaching_realm_on(self.realm_port)
        .reaching_realm_at(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]))
    }

    fn postgres(
        &self,
        audience: Authority,
        database: String,
        role: String,
        _secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Ok(PostgresClient::new(audience, database, role))
    }

    /// The default resolves the authority over DNS and refuses loopback, which
    /// is the right production reading and would refuse this fixture before it
    /// ever dialled. Overridden to hand back the declared authority — and to
    /// assert it is the declared one, so the row cannot pass against a factory
    /// that quietly pointed somewhere else.
    fn resolve_registry(&self, audience: &Authority) -> Result<ResolvedAudience, RegistryError> {
        assert_eq!(
            audience.as_str(),
            NAME,
            "the broker resolved an authority the declaration does not name: {audience}"
        );
        Ok(self.resolved.clone())
    }
}

struct Vertical {
    state: BrokerState,
    _realm: TlsOrigin,
    _registry: TlsOrigin,
    session: AgentSessionId,
    surrogate: String,
    _dir: tempfile::TempDir,
}

/// Builds the whole chain, with a registry that accepts and then stalls.
fn stalling_vertical() -> Vertical {
    let dir = tempfile::tempdir().expect("tempdir");
    let passphrase = secrecy::SecretString::from("b1-stall-passphrase".to_string());

    let mut store = VaultStore::create(
        dir.path().join("v.asv"),
        &passphrase,
        KdfParams::fast_for_tests(),
    )
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
                "b1-registry",
                asv_vault::CredentialKind::Opaque,
                "registry",
                "Rubentxu",
                1,
            ),
            SecretBytes::new(CANARY.as_bytes().to_vec()),
        )
        .expect("insert the credential");

    let mut state = BrokerState::default();
    let loaded = asv_broker::inventory::load(&state, &store);
    assert_eq!(
        (loaded.loaded, loaded.skipped, loaded.collisions),
        (1, 0, 0),
        "the fixture vault holds exactly one credential; any other count means \
         the inventory projection changed under this suite"
    );
    state.secrets = Some(Arc::new(VaultSecretPort::new(
        Arc::new(std::sync::Mutex::new(store)),
        Arc::new(key),
    )));

    let declaration_path = dir.path().join("registries.json");
    std::fs::write(
        &declaration_path,
        format!(r#"[{{"registry":"{NAME}","credential":"{CRED}"}}]"#),
    )
    .expect("write the declaration file");
    state.registries =
        asv_broker::registry_declaration::load(&declaration_path).expect("valid declarations");

    state.policy =
        PolicyEngine::from_policy_text(&composed(PULL_ANY)).expect("the fixture policy is valid");

    let realm = TlsOrigin::start(
        NAME,
        Arc::new(|_: &Observed| {
            OriginResponse::json(
                200,
                r#"{"token":"issued-token-value","expires_in":300,"scope":"repository:library/alpine:pull"}"#,
            )
        }),
    );

    // Captured before the closure, because the closure takes ownership of the
    // origin and the port is still needed here for the factory.
    let realm_url = realm.url("/token");
    // The only difference from a working registry: once it has been
    // authenticated, it does not answer. The challenge is still refused
    // promptly so the token exchange itself stays off the clock.
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let challenge = format!(
                r#"Bearer realm="{}",service="registry.docker.io",scope="repository:{REPOSITORY}:pull""#,
                realm_url
            );
            let authenticated = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if !authenticated {
                return OriginResponse::new(401, "").with_header("www-authenticate", &challenge);
            }
            std::thread::sleep(STALL);
            OriginResponse::new(200, String::from_utf8_lossy(MANIFEST).to_string())
                .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
        }),
    );

    state.connectors = Box::new(Stalling {
        resolved: ResolvedAudience {
            authority: Authority::canonicalize(NAME).expect("a two-label name"),
            port: registry.port,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        },
        roots: vec![registry.certificate(), realm.certificate()],
        realm_port: realm.port,
    });

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

    let surrogate = match handle(
        &state,
        &peer,
        Request::MintSurrogate {
            session,
            credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
            max_uses: 4,
            ttl_secs: 300,
        },
    ) {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("the fixture must be able to mint: {other:?}"),
    };

    Vertical {
        state,
        _realm: realm,
        _registry: registry,
        session,
        surrogate,
        _dir: dir,
    }
}

/// **A provider that has not answered yet does not delay another session.**
///
/// The exit criterion "slow provider no bloquea otra sesión", measured end to
/// end: a real session, a real surrogate, a real policy decision, a real
/// declared registry, a real TLS handshake and a real token exchange — and then
/// a server that stops answering.
#[test]
fn a_slow_provider_does_not_delay_another_session() {
    let v = stalling_vertical();
    // Taken before the state is shared, and by value rather than by reference,
    // so the origins and the temp dir stay alive for the whole row: dropping
    // either the origin or the vault under a live request would turn a
    // concurrency measurement into a measurement of a torn-down fixture.
    let _keeps_origins_alive = (&v._realm, &v._registry, &v._dir);
    let session = v.session;
    let surrogate = v.surrogate.clone();
    let state = Arc::new(v.state);

    // The agent that will be talking to the unresponsive registry. Pinned,
    // because the session was opened by a pinned peer and every provider verb
    // checks the pin before it dials — an unpinned identity is refused before
    // the network, which is correct behaviour and would make this row measure
    // a refusal rather than a stall.
    let mut puller = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    puller.pin_pidfd().expect("pin this test's own process");
    let (tx, rx) = std::sync::mpsc::channel();
    let request = Request::PullManifest {
        session,
        surrogate,
        registry: NAME.to_string(),
        repository: REPOSITORY.to_string(),
        reference: "latest".to_string(),
    };
    let puller_state = Arc::clone(&state);
    let puller_thread = std::thread::spawn(move || {
        tx.send(handle(&puller_state, &puller, request)).ok();
    });

    // Setup, not measurement: let the chain reach the origin before the clock
    // below starts.
    std::thread::sleep(Duration::from_millis(400));

    let newcomer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });

    let started = Instant::now();
    let response = handle(
        &state,
        &newcomer,
        Request::CreateSession {
            workspace: "/another/repo".to_string(),
        },
    );
    let elapsed = started.elapsed();

    assert!(
        matches!(response, Response::SessionCreated { .. }),
        "a second agent could not open a session while a provider was mid-call: \
         {response:?}"
    );
    assert!(
        elapsed < CONCURRENT_ANSWER,
        "the second agent waited {elapsed:?} for a session. The registry it is \
         not talking to accepted the connection and stopped answering {STALL:?} \
         ago, so this is a broker serialising on a provider rather than one that \
         serves two agents at once."
    );
    if let Ok(answer) = rx.try_recv() {
        panic!(
            "the provider had already answered before the second session was \
             created, so this row proved only that a broker with nothing to wait \
             for is responsive. It answered in well under the {STALL:?} its \
             origin was supposed to take, which means it never reached the \
             stall. Its answer was: {answer:?}"
        );
    }

    puller_thread
        .join()
        .expect("the pull thread must not panic");
}
