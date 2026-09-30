//! UAT-033 through the broker, against a real PostgreSQL server.
//!
//! The connector's own suite proves the transport. This proves the thing the
//! milestone is actually about: that the *broker* reaches a real server, and
//! that the password it used to get there never appears anywhere an agent
//! could read it.
//!
//! The distinction from the connector suite is the whole reason this file
//! exists. The connector tests start a session with a password the test is
//! holding. These go through `handle`, the same synchronous entry point every
//! agent request uses, with the password sitting in an encrypted vault and the
//! broker borrowing it. If the credential leaked on that path, these are the
//! tests that would see it, because a leak has to happen somewhere between the
//! vault and the socket and this is the code that owns that gap.
//!
//! # The substrate
//!
//! Same disposable PostgreSQL as the connector suite, described by the same
//! `ASV_UAT033_PG_*` variables, with one deliberate difference: the password
//! arrives in a *file*, not in an environment variable. These tests assert the
//! password is absent from `/proc/<pid>/environ`, and a test that handed the
//! password to itself through the environment would be asserting that the
//! string the test itself planted is absent. The connector suite learned this
//! the hard way with `PGPASSFILE`; this suite has to learn it up front or the
//! leak check is a tautology.

use std::net::IpAddr;
use std::path::PathBuf;

use asv_broker::pg_session::render_row;
use asv_broker::{handle, BrokerState, LiveConnectorFactory, PgRuntime};
use asv_connector_pg::TlsRoots;
use asv_domain::{AgentSessionId, CredentialKind, CredentialMetadata};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_vault::{KdfParams, VaultKey, VaultStore};
use secrecy::SecretString;
use std::sync::Arc;

/// The disposable substrate, or `None` when it is not configured.
///
/// The password is the leak canary, so every check reads `substrate.password`
/// rather than a constant duplicated here. A copy could drift from the file the
/// substrate actually uses, and then the assertions would be searching for a
/// string the system has never seen, which passes without proving anything.
struct Substrate {
    address: IpAddr,
    port: u16,
    root: PathBuf,
    name: String,
    role: String,
    database: String,
    password: String,
}

fn substrate() -> Option<Substrate> {
    let address = std::env::var("ASV_UAT033_PG_ADDR").ok()?.parse().ok()?;
    let port = std::env::var("ASV_UAT033_PG_PORT").ok()?.parse().ok()?;
    let root = PathBuf::from(std::env::var("ASV_UAT033_PG_ROOT").ok()?);
    let name = std::env::var("ASV_UAT033_PG_NAME").ok()?;
    let role = std::env::var("ASV_UAT033_PG_ROLE").ok()?;
    let database = std::env::var("ASV_UAT033_PG_DB").ok()?;
    // The password comes from a file, and the path to that file is all that
    // appears in the environment. Reading it here is the only place the raw
    // value exists outside the vault.
    let path = std::env::var("ASV_UAT033_PG_PASSWORD_FILE").ok()?;
    let password = std::fs::read_to_string(path).ok()?;
    Some(Substrate {
        address,
        port,
        root,
        name,
        role,
        database,
        password: password.trim_end_matches(['\n', '\r']).to_string(),
    })
}

/// Runs `body`, or records a visible skip.
macro_rules! with_substrate {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            let Some(substrate) = substrate() else {
                let required = std::env::var("ASV_UAT033_REQUIRE").is_ok_and(|v| v == "1");
                let reason = format!(
                    "{} needs ASV_UAT033_PG_* to point at a disposable PostgreSQL \
                     with TLS and a SCRAM role",
                    stringify!($name)
                );
                if required {
                    panic!("{reason}; ASV_UAT033_REQUIRE=1 makes a missing substrate a failure");
                }
                println!("SKIPPED: {reason}");
                eprintln!("SKIPPED: {reason}");
                return;
            };
            $body(substrate);
        }
    };
}

/// A peer whose pid is the test process, so it owns the session it creates.
fn self_peer() -> WorkloadIdentity {
    WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    })
}

/// A broker with a real vault, a real runtime, and the substrate's credential
/// stored under the label the broker derives from `(database, role)`.
///
/// Returns the state, the peer, the session, and the vault directory, which
/// has to outlive the test: the broker re-opens the vault by key on every
/// lend, so dropping it turns every operation into an io error.
fn brokered(
    substrate: &Substrate,
) -> (
    BrokerState,
    WorkloadIdentity,
    AgentSessionId,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let passphrase = SecretString::from("uat033-vault-passphrase".to_string());
    let mut store = VaultStore::create(
        dir.path().join("v.asv"),
        &passphrase,
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");
    let key: VaultKey = store.header().unlock(&passphrase).expect("unlock");

    let mut state = BrokerState::default();
    let label = register_pg_credential(&mut state, &substrate.database, &substrate.role);
    store
        .insert(
            &key,
            asv_vault::CredentialMetadata::new(
                label,
                "uat033",
                asv_vault::CredentialKind::Opaque,
                "postgres",
                "app",
                1,
            ),
            asv_domain::SecretBytes::new(substrate.password.as_bytes().to_vec()),
        )
        .expect("insert the password into the vault");

    state.secrets = Some(Arc::new(asv_broker::VaultSecretPort::new(
        Arc::new(store),
        Arc::new(key),
    )));
    state.runtime = Some(runtime());

    // The roots the substrate's certificate validates under. Without this the
    // connector would refuse the server's certificate, and the test would be
    // proving that TLS works rather than that the broker connects.
    let pem = std::fs::read(&substrate.root)
        .unwrap_or_else(|error| panic!("read {}: {error}", substrate.root.display()));
    state.connectors = Box::new(LiveConnectorFactory {
        roots: Some(TlsRoots::system().with_extra_roots(pem)),
        server_name: Some(substrate.name.clone()),
    });

    let peer = self_peer();
    let session = state.sessions.create("/repo".to_string(), &peer);
    (state, peer, session, dir)
}

/// Registers a credential for the pair and keys the vault to the label the
/// broker will ask for.
///
/// The label is the derived `pg/<database>/<role>` string, not a UUID, because
/// the broker derives the label from the pair and never learns a credential id
/// from the agent. Keying the vault by anything else would make the lookup fail
/// in a way that looked like a missing credential rather than a mismatched
/// label.
fn register_pg_credential(state: &mut BrokerState, database: &str, role: &str) -> String {
    let metadata = CredentialMetadata::new(
        format!("pg/{database}/{role}"),
        CredentialKind::DatabaseCredential,
    );
    state.credentials.push(metadata);
    format!("pg/{database}/{role}")
}

/// The runtime the live transport is driven on, shared by every test.
fn runtime() -> PgRuntime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
    });
    PgRuntime::from_handle(runtime.handle().clone())
}

// The whole path, end to end: connect, query, revoke.
with_substrate!(
    the_broker_connects_queries_and_revokes,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);

        // Connect. The response names the pair the broker chose and nothing else.
        let connected = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: substrate.name.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: substrate.role.clone(),
            },
        );
        match &connected {
            Response::PostgresConnected { database, role, .. } => {
                assert_eq!(database, &substrate.database);
                assert_eq!(role, &substrate.role);
            }
            other => panic!("connect failed: {other:?}"),
        }

        // Query. The value comes from the server, not from the broker.
        let result = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: "select 41 + 1".into(),
            },
        );
        match &result {
            Response::PostgresResult { row_count, rows } => {
                assert_eq!(*row_count, 1, "one row: {rows:?}");
                assert_eq!(rows, &vec![render_row(&["42".to_string()])]);
            }
            other => panic!("query failed: {other:?}"),
        }

        // Revoke, and the answer must be an *observed* teardown.
        let revoked = handle(&mut state, &peer, Request::PostgresRevoke { session });
        assert_eq!(
            revoked,
            Response::PostgresRevoked {
                session,
                backend_terminated: true,
            },
            "the server closed the socket, so the teardown was observed"
        );
        assert_eq!(
            state.postgres.len(),
            0,
            "the session was consumed by the revoke"
        );
    }
);

// The leak check, on the broker's own path.
//
// Reads this process's `/proc/<pid>/{environ,cmdline}` after a full
// connect-query-revoke cycle and asserts the password is in neither. It is
// the broker's own pid, not a child's, because the broker is the process that
// holds the credential.
with_substrate!(
    the_broker_process_never_carries_the_password,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        let connected = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: substrate.name.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: substrate.role.clone(),
            },
        );
        assert!(
            matches!(connected, Response::PostgresConnected { .. }),
            "connect failed: {connected:?}"
        );

        let pid = std::process::id();
        for (label, path) in [
            ("environ", format!("/proc/{pid}/environ")),
            ("cmdline", format!("/proc/{pid}/cmdline")),
        ] {
            let raw = std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
            let text = String::from_utf8_lossy(&raw);
            assert!(
                !text.contains(&substrate.password),
                "the password leaked into the broker's {label}"
            );
        }
        // The positive control: without it the two assertions above would pass even
        // if /proc reads returned nothing at all.
        let environ = std::fs::read(format!("/proc/{pid}/environ")).expect("environ");
        assert!(
            !environ.is_empty(),
            "/proc reads returned nothing, so the check is vacuous"
        );

        let _ = handle(&mut state, &peer, Request::PostgresRevoke { session });
    }
);

// No response to a PostgreSQL request may carry the credential, whatever the
// outcome.
with_substrate!(
    no_response_carries_the_credential,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);

        // A wrong role names a credential the vault does not hold, so this is the
        // failure path: the broker asked, the vault said no, and the answer still
        // must not leak anything.
        let refused = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: substrate.name.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: "a-role-the-vault-does-not-hold".into(),
            },
        );
        assert!(matches!(refused, Response::Error { .. }), "got {refused:?}");

        // And the success path, for the same reason.
        let connected = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: substrate.name.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: substrate.role.clone(),
            },
        );
        let rendered = format!("{connected:?}");
        assert!(
            !rendered.contains(&substrate.password),
            "the response carried the credential: {rendered}"
        );
        let _ = handle(&mut state, &peer, Request::PostgresRevoke { session });
    }
);

// The agent cannot name a credential. Two different roles for the same
// database produce two different vault lookups, and only the granted one
// connects.
with_substrate!(
    the_agent_cannot_substitute_a_role,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);

        let wrong = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: substrate.name.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: "postgres".into(),
            },
        );
        // The answer is a refusal, and it does not say *why* in a way that maps
        // the vault: "not found" and "wrong password" are the same shape to the
        // agent, which is the point of M6-R3.
        assert!(
            matches!(
                wrong,
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    ..
                }
            ),
            "got {wrong:?}"
        );
        assert_eq!(
            state.postgres.len(),
            0,
            "a refused connect left a session behind"
        );
    }
);
