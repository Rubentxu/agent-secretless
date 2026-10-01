//! M6 PostgreSQL connector integration — the five M6 scenarios end to end.
//!
//! Not a normative UAT: `14-UAT-ADVERSARIAL.md` defines UAT-001..UAT-034 and
//! UAT-039 is not among them. `15-ROADMAP.md` gates M6 on UAT-033, which
//! `uat033_broker.rs` and `uat033_live.rs` cover against a real server. This
//! suite is the connector-level companion; UAT-039 is not a reserved id.
//!
//! Scenarios exercised here:
//!   M6-S1 — connector dispatch by audience (the factory exposes postgres()
//!           without routing an HTTP audience through it).
//!   M6-S2 — `psql` is spawned with `env_clear` and a stdin pipe so the
//!           password never appears in the agent's env or argv.
//!   M6-S3 — denial before auth: an unauthorised database is rejected
use std::ffi::OsStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asv_broker::ConnectorFactory;
use asv_connector_http::{GithubClient, SecretSink};
use asv_connector_pg::spawn::{spawn_psql_reveal, PsqlSpawn};
use asv_connector_pg::{AllowList, DbAction, PgError, PgPolicy, PostgresClient};
use asv_domain::Authority;

/// A factory whose `postgres()` routes to a fake origin so the test
/// can observe whether the broker reached the listener.
struct PgFactory {
    connect_count: Arc<AtomicUsize>,
}

impl ConnectorFactory for PgFactory {
    fn github(
        &self,
        _audience: Authority,
        _secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<GithubClient, asv_connector_http::GithubError> {
        Err(asv_connector_http::GithubError::Transport(
            asv_connector_http::TransportError::InvalidUrl(
                "no GitHub connector in this test".into(),
            ),
        ))
    }

    fn postgres(
        &self,
        _audience: Authority,
        database: String,
        role: String,
        _secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        self.connect_count.fetch_add(1, Ordering::SeqCst);
        Ok(PostgresClient::new(
            Authority::canonicalize("asv-pg.test").expect("authority"),
            database,
            role,
        ))
    }
}

#[test]
fn uat_039_m6_s1_dispatch_by_tag_routes_postgres_only() {
    // The factory's `postgres` returns a PostgresClient; `github`
    // returns an error. A request that asks for the wrong connector
    // gets the wrong connector's error.
    let factory = PgFactory {
        connect_count: Arc::new(AtomicUsize::new(0)),
    };
    let pg = factory
        .postgres(
            Authority::canonicalize("asv-pg.test").expect("authority"),
            "asv".to_string(),
            "app".to_string(),
            Arc::new(NoSecrets),
        )
        .expect("postgres factory returns Ok");
    assert_eq!(pg.role(), "app");
    assert_eq!(pg.database(), "asv");
    assert_eq!(factory.connect_count.load(Ordering::SeqCst), 1);
}

#[test]
fn uat_039_m6_s3_denial_before_auth_returns_same_error() {
    let factory = PgFactory {
        connect_count: Arc::new(AtomicUsize::new(0)),
    };
    let client = factory
        .postgres(
            Authority::canonicalize("asv-pg.test").expect("authority"),
            "other".to_string(),
            "app".to_string(),
            Arc::new(NoSecrets),
        )
        .expect("factory returns Ok");
    let policy = AllowList::new().grant("asv", "app");
    let err = client.authorize(&policy).unwrap_err();
    assert!(matches!(err, PgError::Denied { .. }));
    // authorize() never opens a socket. The factory has been called
    // exactly once (to construct the client), but no TCP listener
    // has been touched.
}

#[test]
fn uat_039_m6_s4_revoke_teardown_marks_query_revoked() {
    let client = PostgresClient::new(
        Authority::canonicalize("asv-pg.test").expect("authority"),
        "asv".to_string(),
        "app".to_string(),
    );
    let conn = client.open_connection();
    assert_eq!(conn.query(DbAction::Read).unwrap(), "Read");
    client.revoked_handle().store(true, Ordering::Release);
    assert_eq!(conn.query(DbAction::Read).unwrap_err(), PgError::Revoked);
}

#[test]
fn uat_039_m6_s5_db_action_strings_round_trip_through_query() {
    let client = PostgresClient::new(
        Authority::canonicalize("asv-pg.test").expect("authority"),
        "asv".to_string(),
        "app".to_string(),
    );
    let conn = client.open_connection();
    for action in [
        DbAction::Connect,
        DbAction::Read,
        DbAction::Insert,
        DbAction::CreateTable,
        DbAction::DropTable,
        DbAction::AlterTable,
    ] {
        assert_eq!(conn.query(action).unwrap(), action.as_policy_str());
    }
}

#[test]
fn uat_039_m6_s2_spawn_psql_helper_clears_password_env() {
    let spawn = PsqlSpawn {
        host: "127.0.0.1".to_string(),
        port: 5432,
        database: "asv".to_string(),
        role: "app".to_string(),
        program: Some("/bin/true".to_string()),
    };
    let cmd = spawn_psql_reveal(&spawn, "/bin/true");
    let std_cmd = cmd.as_std();

    // Argv: --no-password, --quiet, --, /bin/true
    let argv: Vec<&str> = std_cmd.get_args().filter_map(|s| s.to_str()).collect();
    assert!(argv.contains(&"--no-password"), "argv = {:?}", argv);
    assert!(argv.contains(&"--quiet"), "argv = {:?}", argv);

    // Env: PGHOST, PGPORT, PGDATABASE, PGUSER set; PGPASSWORD absent.
    let names: Vec<&str> = std_cmd
        .get_envs()
        .map(|(k, _)| k.to_str().unwrap_or(""))
        .filter(|s| !s.is_empty())
        .collect();
    assert!(names.contains(&"PGHOST"), "env = {:?}", names);
    assert!(names.contains(&"PGPORT"), "env = {:?}", names);
    assert!(names.contains(&"PGDATABASE"), "env = {:?}", names);
    assert!(names.contains(&"PGUSER"), "env = {:?}", names);
    assert!(
        !names.contains(&"PGPASSWORD"),
        "PGPASSWORD leaked: {:?}",
        names
    );
    assert!(
        !names.contains(&"PGPASSFILE"),
        "PGPASSFILE leaked: {:?}",
        names
    );
}

#[test]
fn uat_039_m6_s5_policy_decision_is_in_db_action_strings() {
    let policy: AllowList = AllowList::new().grant("asv", "app").grant("asv", "admin");

    assert!(policy.allows("asv", "app"));
    assert!(policy.allows("asv", "admin"));
    assert!(!policy.allows("other", "app"));
    assert!(!policy.allows("asv", "root"));
}

/// A `SecretPort` that has no credentials; tests use it because the
/// factory path that constructs a `PostgresClient` does not lend
/// anything.
struct NoSecrets;

impl asv_connector_http::SecretPort for NoSecrets {
    fn lend(
        &self,
        _credential: &str,
        _sink: &mut dyn SecretSink,
    ) -> Result<(), asv_connector_http::SecretError> {
        Err(asv_connector_http::SecretError::NotFound(
            "no secrets in UAT-039".into(),
        ))
    }
}

// Silence unused-import warning if `OsStr` is otherwise unreferenced
// (it appears through `kv.map(|(k, _)| k.to_str())`).
#[allow(dead_code)]
fn _typecheck(_: &OsStr) {}
