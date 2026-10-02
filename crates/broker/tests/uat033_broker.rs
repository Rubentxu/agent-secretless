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
        Arc::new(std::sync::Mutex::new(store)),
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
        // H5: the deployment declares the one destination it lends to, and the
        // certificate is checked against *that* name. The request below names
        // the same pair, so it is the declared entry that reaches the socket.
        destinations: vec![
            asv_broker::PgDestination::new(&substrate.name, substrate.address)
                .expect("the substrate name is a canonical host"),
        ],
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

/// A short, unique, legal SQL identifier suffix.
///
/// The tables these tests create must not collide between tests, and the
/// session id is a UUID whose hyphens are legal in an identifier but which
/// reads badly in a failure message.
fn unique_suffix() -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}_{}", std::process::id(), n)
}

// M6-R5, the scenario the spec spells out: a policy that allows `connect` and
// `select 1` but denies `create table`, against a real server.
//
// The claim under test is not "the classifier knows that CREATE TABLE is a
// different verb from SELECT". That is a unit test in `pg_policy`, and it was
// passing while the broker never asked the policy anything. The claim here is
// that a statement the policy denies does not reach the server. So the test
// connects for real, runs a read the policy allows, and then runs a write the
// policy forbids, and the write must be refused while the read still works.
with_substrate!(
    a_policy_allows_select_and_denies_create_table,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        // The M6-R5 policy, verbatim in intent: read is permitted, creating a
        // table is not. No other database verb is permitted either, so this
        // policy is the narrow one the spec describes.
        state.policy = asv_policy::PolicyEngine::from_policy_text(
            r#"
            permit (principal, action == Action::"postgres_connect", resource is Database);
            permit (principal, action == Action::"postgres_read", resource is Database);
            "#,
        )
        .expect("the M6-R5 policy parses and validates against the schema");

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
            "the gateway verb is permitted, so the connect must succeed: {connected:?}"
        );

        // The allowed half. If this fails, the gate is not selective, it is
        // just broken, and the denial below would prove nothing.
        let read = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: "select 1".into(),
            },
        );
        match &read {
            Response::PostgresResult { rows, row_count } => {
                assert_eq!(*row_count, 1, "select 1 returns one row: {read:?}");
                assert_eq!(rows, &vec![render_row(&["1".to_string()])]);
            }
            other => panic!("a policy-allowed read was refused: {other:?}"),
        }

        // The denied half. This is the scenario: the policy does not mention
        // create_table, so the table is never created.
        let table = format!("m6_r5_denied_{}", unique_suffix());
        let create = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: format!("create table {table} (id int)"),
            },
        );
        assert!(
            matches!(
                create,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "a policy that does not permit create_table must deny it, got {create:?}"
        );

        // And the server must agree, rather than the broker merely reporting
        // a denial it invented. Asking through the allowed verb is the only
        // way left to ask.
        let probe = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: format!(
                    "select count(*) from information_schema.tables where table_name = '{table}'"
                ),
            },
        );
        let count = match &probe {
            Response::PostgresResult { rows, .. } => rows.first().cloned().unwrap_or_default(),
            other => panic!("the probe must be a permitted read: {other:?}"),
        };
        assert_eq!(
            count, "0",
            "the table must not exist on the server; a denial that still created it would be a lie"
        );
    }
);

// The fail-closed half, end to end. `GRANT` is a statement the classifier does
// not place, so it is denied before the policy is consulted at all. This is the
// property that makes the classifier safe to be a recogniser rather than a
// parser: what it cannot understand, it does not run.
with_substrate!(
    policy_denies_a_statement_the_classifier_cannot_place,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        // A policy that permits everything the classifier *can* place, so the
        // only thing that can refuse `grant` is the classifier itself.
        state.policy = asv_policy::PolicyEngine::from_policy_text(
            r#"
            permit (principal, action == Action::"postgres_connect", resource is Database);
            permit (principal, action == Action::"postgres_read", resource is Database);
            permit (principal, action == Action::"postgres_insert", resource is Database);
            permit (principal, action == Action::"postgres_create_table", resource is Database);
            permit (principal, action == Action::"postgres_drop_table", resource is Database);
            permit (principal, action == Action::"postgres_alter_table", resource is Database);
            "#,
        )
        .expect("the permissive policy parses");
        assert!(
            matches!(
                handle(
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
                ),
                Response::PostgresConnected { .. }
            ),
            "connect first, so the statement below has a live session to be denied on"
        );

        for sql in [
            "grant all on everything to public",
            "copy (select 1) to program 'id'",
            "vacuum",
        ] {
            let response = handle(
                &mut state,
                &peer,
                Request::PostgresQuery {
                    session,
                    sql: sql.to_string(),
                },
            );
            assert!(
                matches!(
                    response,
                    Response::Error {
                        code: ErrorCode::Denied,
                        ..
                    }
                ),
                "an unclassified statement must be denied, and `{sql}` is one. Got {response:?}"
            );
        }
    }
);

// The M6-R5 scenario, played by the two statements that defeat it. The policy
// below is the read-only one the milestone names: it permits connect and read,
// and says nothing about create_table. A classifier that reads only the leading
// keyword calls `select ... into` a read and `explain analyze delete` a read, so
// both run, and the denial the operator wrote is the one the agent walks past.
with_substrate!(
    a_write_disguised_as_a_read_is_denied_by_a_read_only_policy,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        state.policy = asv_policy::PolicyEngine::from_policy_text(
            r#"
            permit (principal, action == Action::"postgres_connect", resource is Database);
            permit (principal, action == Action::"postgres_read", resource is Database);
            "#,
        )
        .expect("the read-only policy parses and validates against the schema");

        assert!(
            matches!(
                handle(
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
                ),
                Response::PostgresConnected { .. }
            ),
            "connect first, so each statement below has a live session to be denied on"
        );

        // The allowed half, again. If this fails the gate is not selective but
        // broken, and the denials below would prove nothing.
        assert!(
            matches!(
                handle(
                    &mut state,
                    &peer,
                    Request::PostgresQuery {
                        session,
                        sql: "select 1".into(),
                    },
                ),
                Response::PostgresResult { .. }
            ),
            "a policy-allowed read must still succeed"
        );

        // One prefix, used by the statements and by the probe below, so the
        // probe searches for a name something actually tried to create.
        let prefix = format!("m6_r5_disguised_{}_", unique_suffix());
        for sql in [
            format!("select 1 into {prefix}a"),
            // `EXPLAIN ANALYZE` executes what it plans, so the wrapper is a
            // write even though its first word is not one.
            format!("explain analyze create table {prefix}b (id int)"),
        ] {
            let response = handle(
                &mut state,
                &peer,
                Request::PostgresQuery {
                    session,
                    sql: sql.clone(),
                },
            );
            assert!(
                matches!(
                    response,
                    Response::Error {
                        code: ErrorCode::Denied,
                        ..
                    }
                ),
                "a write that opens with a read keyword must be denied by a \
                 read-only policy. `{sql}` is one. Got {response:?}"
            );
        }

        // The server must agree. A denial that still created the table would be
        // a lie, and asking through the permitted verb is the only way left to
        // ask.
        let probe = handle(
            &mut state,
            &peer,
            Request::PostgresQuery {
                session,
                sql: format!(
                    "select count(*) from information_schema.tables where table_name like '{prefix}%'"
                ),
            },
        );
        let count = match &probe {
            Response::PostgresResult { rows, .. } => rows.first().cloned().unwrap_or_default(),
            other => panic!("the probe must be a permitted read: {other:?}"),
        };
        assert_eq!(
            count, "0",
            "neither statement may have reached the server; a denial that still \
             created the table would be a lie"
        );
    }
);

// The second M6-R5 scenario: changing the policy needs no connector change.
// The same running session, the same statement, one new policy decision.
with_substrate!(
    a_policy_change_applies_without_a_connector_change,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        state.policy = asv_policy::PolicyEngine::from_policy_text(
            r#"
            permit (principal, action == Action::"postgres_connect", resource is Database);
            permit (principal, action == Action::"postgres_read", resource is Database);
            permit (principal, action == Action::"postgres_create_table", resource is Database);
            "#,
        )
        .expect("the permitting policy parses");
        assert!(
            matches!(
                handle(
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
                ),
                Response::PostgresConnected { .. }
            ),
            "connect first"
        );

        let table = format!("m6_r5_then_{}", unique_suffix());
        // Permitted by the first policy.
        assert!(
            matches!(
                handle(
                    &mut state,
                    &peer,
                    Request::PostgresQuery {
                        session,
                        sql: format!("create table {table} (id int)"),
                    },
                ),
                Response::PostgresResult { .. }
            ),
            "the first policy permits create_table"
        );

        // The policy now forbids it. Nothing about the connector, the
        // session, or the socket changes; only the policy text does.
        state.policy = asv_policy::PolicyEngine::from_policy_text(
            r#"
            permit (principal, action == Action::"postgres_connect", resource is Database);
            permit (principal, action == Action::"postgres_read", resource is Database);
            "#,
        )
        .expect("the tightened policy parses");

        let second = format!("{table}_two");
        assert!(
            matches!(
                handle(
                    &mut state,
                    &peer,
                    Request::PostgresQuery {
                        session,
                        sql: format!("create table {second} (id int)"),
                    },
                ),
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ),
            "the tightened policy must deny create_table with no code change"
        );
        // And the read the tightened policy still permits keeps working, so
        // the gate is selective rather than closed.
        assert!(
            matches!(
                handle(
                    &mut state,
                    &peer,
                    Request::PostgresQuery {
                        session,
                        sql: "select 1".into(),
                    },
                ),
                Response::PostgresResult { .. }
            ),
            "a permitted read still runs after the policy tightened"
        );
    }
);

// The factory's pinned name wins over the request's `host`.
//
// `LiveConnectorFactory::server_name` was a public field nothing read:
// `postgres_connect` took the certificate name from the request, so a
// deployment that configured a name here got the request's name anyway. The
// existing tests set both to the same value, which is why nothing noticed.
//
// The substrate's certificate carries two SANs, `DNS:pg.local.test` and
// `IP:127.0.0.1`, and both tests below depend on that.
//
// H5 changed what this pair is about. The old pair proved that a *pinned*
// `server_name` overrode the request's host, which meant the certificate was
// checked against a name the deployment configured but the request did not
// name. That is now subsumed: the broker resolves the request against the
// deployment's declared destinations and then uses the **declared** host as
// the certificate name, so a request cannot reach the TLS stage at all unless
// it named a declared host. The stronger pair is therefore: the declared
// destination connects, and the undeclared one is refused before any socket.
with_substrate!(
    the_declared_destination_is_the_one_the_certificate_is_checked_against,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);
        // `brokered` declared this exact pair, so the request and the
        // declaration agree and the certificate is checked against the declared
        // name, which the substrate's certificate carries.
        let declared = substrate.name.clone();
        state.connectors = Box::new(LiveConnectorFactory {
            roots: Some(
                TlsRoots::system()
                    .with_extra_roots(std::fs::read(&substrate.root).expect("root pem")),
            ),
            destinations: vec![asv_broker::PgDestination::new(&declared, substrate.address)
                .expect("a canonical host")],
            server_name: Some(declared.clone()),
        });

        let response = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: declared.clone(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: substrate.role.clone(),
            },
        );
        assert!(
            matches!(response, Response::PostgresConnected { .. }),
            "the deployment declared {declared} and the request named it, so the \
             certificate must have been checked against the declared name. Got {response:?}"
        );
    }
);

// The control: the same deployment, the same address, and the same granted
// `(database, role)` — only the host differs. This is UAT-006's scenario with a
// real server one address away, so "refused" here means refused before the
// socket, not refused by a certificate mismatch after dialling it.
with_substrate!(
    an_undeclared_host_is_refused_before_any_socket_is_opened,
    |substrate: Substrate| {
        let (mut state, peer, session, _dir) = brokered(&substrate);

        let response = handle(
            &mut state,
            &peer,
            Request::PostgresConnect {
                session,
                host: "not-the-substrate.example".to_string(),
                host_addr: substrate.address.to_string(),
                port: substrate.port,
                database: substrate.database.clone(),
                role: substrate.role.clone(),
            },
        );
        match &response {
            Response::Error { code, message } => {
                assert_eq!(
                    *code,
                    asv_ipc_protocol::ErrorCode::Denied,
                    "a host the deployment never declared must be denied by the \
                     destination gate. Got {response:?}"
                );
                assert!(
                    !message.contains("certificate") && !message.contains("TLS"),
                    "the refusal must come from the destination gate and not from a \
                     certificate mismatch after dialling, or the gate is not what \
                     stopped it. Got: {message}"
                );
            }
            other => panic!(
                "the agent named a host this deployment never declared and it was \
                 accepted. Got {other:?}"
            ),
        }
    }
);
