//! The live transport against a real PostgreSQL server (UAT-033).
//!
//! Every test here drives the actual connector against a real `postgres`
//! process with real TLS and a real SCRAM verifier. Nothing is stubbed: the
//! assertion "no password in `/proc/<pid>/environ`" is only meaningful if
//! there is a real `psql` process to read, and "the server dropped the
//! connection" is only meaningful if a server was there to drop it.
//!
//! # The substrate
//!
//! The server is not started by this suite. It is a disposable instance the
//! operator prepares, and the four environment variables below describe it.
//! When they are absent the suite skips with a message rather than failing,
//! because "no substrate" is not "the transport is broken" and a red suite
//! that means nothing trains people to ignore red.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `ASV_UAT033_PG_ADDR`   | `127.0.0.1` |
//! | `ASV_UAT033_PG_PORT`   | `55440` |
//! | `ASV_UAT033_PG_ROOT`   | PEM root the server's chain validates under |
//! | `ASV_UAT033_PG_NAME`   | the name in the certificate's SAN, usually `127.0.0.1` |
//! | `ASV_UAT033_PG_ROLE`   | a non-superuser role, `app` |
//! | `ASV_UAT033_PG_DB`     | a database `app` may connect to, `asvdb` |
//! | `ASV_UAT033_PG_PASSWORD` | that role's password |
//!
//! The password is read from the environment on the *test* side, which is
//! the one place UAT-033 does not look: the assertion is that the broker's
//! own process never hands it to the agent, and the test harness is not the
//! agent.

use std::net::IpAddr;
use std::path::PathBuf;

use asv_connector_pg::live::{self, TlsRoots};
use asv_connector_pg::Teardown;

/// The canary. If this string appears anywhere the agent can read, the UAT
/// fails. It is deliberately distinctive so a grep cannot hit it by accident.
///
/// The value is also the substrate password, so the test has something real to
/// hunt for: a canary nobody ever actually uses proves nothing.
const CANARY: &str = "uat033-canary-4f2a9c";

/// Where the substrate is, or why there isn't one.
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
    let address = std::env::var("ASV_UAT033_PG_ADDR").ok()?;
    let port = std::env::var("ASV_UAT033_PG_PORT").ok()?.parse().ok()?;
    let root = PathBuf::from(std::env::var("ASV_UAT033_PG_ROOT").ok()?);
    let name = std::env::var("ASV_UAT033_PG_NAME").ok()?;
    let role = std::env::var("ASV_UAT033_PG_ROLE").ok()?;
    let database = std::env::var("ASV_UAT033_PG_DB").ok()?;
    let password = std::env::var("ASV_UAT033_PG_PASSWORD").ok()?;
    Some(Substrate {
        address: address.parse().ok()?,
        port,
        root,
        name,
        role,
        database,
        password,
    })
}

impl Clone for Substrate {
    /// A cheap copy so the macro can hand each test an owned value.
    ///
    /// The password is cloned rather than shared by reference because the
    /// test bodies are `async move` blocks: capturing `&Substrate` would make
    /// the future borrow the stack slot the test function owns, which the
    /// borrow checker is right to reject. The substrate lives for the whole
    /// test either way.
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            port: self.port,
            root: self.root.clone(),
            name: self.name.clone(),
            role: self.role.clone(),
            database: self.database.clone(),
            password: self.password.clone(),
        }
    }
}

/// Runs `body` against the substrate, or records the skip and returns.
///
/// The skip is a *printed* skip, not a silent pass, and that distinction is
/// the whole point. A test that returns early on absent configuration is
/// reported by `cargo test` as `ok`, so a suite where the substrate is missing
/// looks identical to a suite where every assertion held. Anyone reading the
/// summary is entitled to assume the assertions ran. Rust has no
/// `#[ignore]`-at-runtime construct, so the honest options are to fail or to
/// make the skip loud; this makes it loud on both streams and exits non-zero
/// only when the caller asked for the substrate, which `ASV_UAT033_REQUIRE=1`
/// does. A release gate sets that, so a missing substrate is a hard failure in
/// the one context where a missing substrate *is* a failure, and a quiet note
/// everywhere else.
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
                    panic!(
                        "{reason}; ASV_UAT033_REQUIRE=1 was set, so a missing substrate \
                         is a failure rather than a skip"
                    );
                }
                // Printed on both streams: `cargo test --nocapture` keeps stdout
                // and a CI log usually keeps stderr, so neither can drop it.
                println!("SKIPPED: {reason}");
                eprintln!("SKIPPED: {reason}");
                return;
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            // The substrate is moved into the async block. An `async move`
            // that borrowed it would tie the future's lifetime to the stack
            // slot below, which the compiler correctly refuses.
            runtime.block_on(async move { $body(substrate).await });
        }
    };
}

fn roots(substrate: &Substrate) -> TlsRoots {
    let pem = std::fs::read(&substrate.root)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", substrate.root.display()));
    TlsRoots::system().with_extra_roots(pem)
}

async fn open(substrate: &Substrate) -> asv_connector_pg::LivePgSession {
    let roots = roots(substrate);
    live::connect(
        substrate.address,
        substrate.port,
        &substrate.name,
        &roots,
        &substrate.database,
        &substrate.role,
        &substrate.password,
    )
    .await
    .unwrap_or_else(|error| panic!("connect to the substrate failed: {error}"))
}

with_substrate!(connects_and_answers_a_statement, |substrate: Substrate| async move {
    let mut session = open(&substrate).await;

    // The handshake reporting a real server version is what separates
    // "connected to PostgreSQL" from "connected to something that speaks the
    // framing". A connector that ignored ParameterStatus could not tell.
    let version = session
        .parameter("server_version")
        .expect("the server must report server_version");
    assert!(
        version.starts_with(|c: char| c.is_ascii_digit()),
        "server_version {version:?} does not look like a PostgreSQL version"
    );

    let result = session.query("select 1 as one").await.expect("select 1");
    assert_eq!(result.row_count(), 1, "select 1 returns exactly one row");
    assert_eq!(result.rows[0], vec!["1".to_string()]);
    assert!(
        result.tag.starts_with("SELECT"),
        "expected a SELECT tag, got {:?}",
        result.tag
    );

    // A real backend pid is M6-R4's handle on the server side.
    let pid = session
        .backend_pid()
        .filter(|pid| *pid > 0)
        .expect("the server must send BackendKeyData");
    assert!(pid > 0);
});

with_substrate!(a_null_column_is_not_the_string_null, |substrate: Substrate| async move {
    let mut session = open(&substrate).await;
    // SQL NULL and the four-character string 'NULL' are different values.
    // Rendering both as "NULL" would make a caller unable to tell an absent
    // value from a present one, which matters for any policy that filters
    // on a column.
    let result = session
        .query("select null::text as a, 'NULL'::text as b")
        .await
        .expect("select with a null");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], "", "a NULL renders as empty, not as a literal");
    assert_eq!(result.rows[0][1], "NULL", "the string 'NULL' is preserved verbatim");
});

with_substrate!(a_wrong_password_is_refused, |substrate: Substrate| async move {
    let roots = roots(&substrate);
    let error = live::connect(
        substrate.address,
        substrate.port,
        &substrate.name,
        &roots,
        &substrate.database,
        &substrate.role,
        "definitely-not-the-password",
    )
    .await
    .expect_err("a wrong password must not authenticate");

    // The refusal must not leak the password, nor echo the server's message
    // verbatim if that message would contain credential material. This
    // checks the first; the second is a property of the server, not of us.
    let rendered = error.to_string();
    assert!(
        !rendered.contains("definitely-not-the-password"),
        "the error leaked the password: {rendered}"
    );
    assert!(
        !rendered.contains(CANARY),
        "the error leaked another password: {rendered}"
    );
});

with_substrate!(
    an_untrusted_root_cannot_connect,
    |substrate: Substrate| async move {
        // Same server, same credentials, but the platform store only. The
        // server's root was issued by this test run, so no public CA vouches
        // for it and the handshake must fail. This is the test that would
        // catch a `dangerous()` verifier or a verify callback that returned
        // Ok unconditionally.
        let error = live::connect(
            substrate.address,
            substrate.port,
            &substrate.name,
            &TlsRoots::system(),
            &substrate.database,
            &substrate.role,
            &substrate.password,
        )
        .await
        .expect_err("an untrusted chain must not be accepted");

        let rendered = error.to_string().to_lowercase();
        assert!(
            rendered.contains("certificate")
                || rendered.contains("unknown issuer")
                || rendered.contains("invalid"),
            "expected a certificate verification failure, got: {rendered}"
        );
        assert!(
            !rendered.contains(&substrate.password),
            "a TLS failure must not echo the password"
        );
    }
);

with_substrate!(
    a_wrong_server_name_cannot_connect,
    |substrate: Substrate| async move {
        // The right root, the wrong name. Certificate verification has two
        // halves and this is the half that catches a server holding a
        // certificate for someone else.
        let roots = roots(&substrate);
        let error = live::connect(
            substrate.address,
            substrate.port,
            "not-the-server-name.invalid",
            &roots,
            &substrate.database,
            &substrate.role,
            &substrate.password,
        )
        .await
        .expect_err("a name mismatch must not be accepted");

        let rendered = error.to_string().to_lowercase();
        assert!(
            rendered.contains("certificate") || rendered.contains("name"),
            "expected a name verification failure, got: {rendered}"
        );
    }
);

with_substrate!(
    revoke_is_observed_by_the_server,
    |substrate: Substrate| async move {
        let mut session = open(&substrate).await;
        let pid = session.backend_pid().expect("backend pid");

        // Before the revoke, the statement works. Without this the teardown
        // test would pass against a session that never had access to begin
        // with.
        session
            .query("select 1")
            .await
            .expect("the session works before the revoke");

        let teardown = session.revoke().await;
        assert_eq!(
            teardown,
            Teardown::ServerClosed,
            "M6-R4 needs the server to have closed the connection, not the \
             broker to have stopped reading"
        );

        // The local half: a statement after the revoke must fail without
        // reaching the socket. A connector that reported teardown but still
        // served statements would satisfy the assertion above and be wrong.
        let error = session
            .query("select 1")
            .await
            .expect_err("a statement after revoke must fail");
        assert!(
            matches!(error, asv_connector_pg::WireError::Revoked),
            "expected Revoked, got {error:?}"
        );
        assert!(session.is_revoked());

        // The server-side half, asked of the server rather than of us. This
        // is the check no local latch can fake: the pid is gone from
        // pg_stat_activity because the backend exited.
        let alive = backend_still_listed(&substrate, pid).await;
        assert!(
            !alive,
            "backend {pid} is still listed by the server after Terminate, so \
             the connection was not torn down server-side"
        );
    }
);

with_substrate!(
    revoke_twice_is_not_a_lie,
    |substrate: Substrate| async move {
        let mut session = open(&substrate).await;
        assert_eq!(session.revoke().await, Teardown::ServerClosed);
        // The second revoke has nothing to terminate. It must say so rather
        // than repeat a success the second call did not observe.
        let second = session.revoke().await;
        assert!(
            matches!(second, Teardown::AlreadyGone | Teardown::NotObserved),
            "a second revoke claimed {second:?} without observing a teardown"
        );
    }
);

/// Resolves a program name to an absolute path using the current `PATH`.
///
/// Returns `None` when nothing matches, so the caller reports a missing
/// client rather than letting the spawn fail later with a message about the
/// child's own executable.
fn which(program: &std::path::Path) -> Option<std::path::PathBuf> {
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// Reads `/proc/<pid>/environ` as a NUL-separated list.
///
/// Returns `None` when the process is gone, which is a normal race and not a
/// test failure. A real leak is found in `/proc/<pid>/environ` while the
/// process is *alive*, so the test reads it before waiting on the child.
fn environ_of(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    Some(
        raw.split(|byte| *byte == 0)
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect(),
    )
}

/// Reads `/proc/<pid>/cmdline` as a NUL-separated list of arguments.
fn cmdline_of(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|byte| *byte == 0)
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect(),
    )
}

// UAT-033: a real `psql` must connect without the password appearing in its
// own process, in either place a process can be read from.
//
// The comment is a line comment rather than a doc comment because it precedes
// a macro invocation, and a `///` there is not attached to anything, which the
// compiler says so out loud. The reasoning it carries is about the assertions
// below, so it is worth keeping either way.
with_substrate!(psql_authenticates_without_the_password_in_proc, |substrate: Substrate| async move {
    // The password reaches the client through `PGPASSFILE`, a file it reads
    // and does not put in its arguments or environment. That is the *shape*
    // of the claim being tested: a secret handed to a child must arrive
    // through a channel the child reads, not through one a reader of `/proc`
    // can see. Nothing here is mocked. `psql` is the real client, the
    // substrate is a real server, and the assertions read the kernel's view of
    // a real process.
    let passfile = std::env::temp_dir().join(format!("asv-uat033-{}.pgpass", std::process::id()));
    // `chmod 0600`: libpq refuses a world-readable password file, so this is
    // what makes the client accept it at all, not a hygiene step.
    std::fs::write(
        &passfile,
        format!("{}:{}:{}:{}:{}\n", substrate.address, substrate.port, substrate.database, substrate.role, CANARY),
    )
    .expect("write the passfile");
    restrict_to_owner(&passfile);

    let host = substrate.name.clone();
    let port = substrate.port.to_string();
    let database = substrate.database.clone();
    let role = substrate.role.clone();
    let passfile = passfile.clone();

    // Resolve `psql` to an absolute path *before* clearing the environment.
    // With an empty `PATH` the exec succeeds on argv[0] alone, and then psql
    // fails with `could not find own program executable`, because it re-execs
    // itself to find its share directory. This is a real failure the live run
    // surfaced, and it is why the clear-then-spawn order below is not reversed.
    let psql = std::env::var("ASV_UAT033_PSQL")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("psql"));
    let psql = which(&psql).unwrap_or_else(|| {
        panic!(
            "psql was not found on PATH; install the client or set \
             ASV_UAT033_PSQL to its absolute path"
        )
    });

    let child = std::process::Command::new(&psql)
        .env_clear()
        .env("PGPASSFILE", &passfile)
        // The password is *not* set in the child's environment. This is the
        // assertion's subject, not a comment: if a future change added
        // `PGPASSWORD`, the environ read below would find the canary.
        .arg("--host").arg(&host)
        .arg("--port").arg(&port)
        .arg("--username").arg(&role)
        .arg("--dbname").arg(&database)
        .arg("--no-password")
        .arg("--tuples-only")
        .arg("--command").arg("select 41 + 1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("psql must be installed to run this UAT");

    let pid = child.id();
    // Read `/proc` while the child is alive. After it exits the files are
    // gone, and a leak would become unobservable exactly when the test
    // finishes looking for it.
    let environ = environ_of(pid);
    let cmdline = cmdline_of(pid);

    let output = child.wait_with_output().expect("wait for psql");
    let _ = std::fs::remove_file(&passfile);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "psql did not connect: {stderr}\nstdout: {stdout}"
    );
    assert_eq!(stdout.trim(), "42", "the real client must run the real statement");

    // The leak check. Both reads are required: a secret in the arguments is
    // the common mistake, and a secret in the environment is the one that a
    // wrapper is tempted to introduce later.
    for (label, entries) in [("environ", environ), ("cmdline", cmdline)] {
        let entries = entries.unwrap_or_else(|| {
            panic!("{label} for pid {pid} was unreadable, so this run proves nothing")
        });
        for entry in &entries {
            assert!(
                !entry.contains(CANARY),
                "the password leaked into /proc/{pid}/{label}: {entry}"
            );
        }
    }
    // The positive control, without which the assertions above are vacuous:
    // if `/proc` were not actually readable, they would pass no matter what.
    assert!(
        !environ_of(std::process::id()).expect("our own environ is readable").is_empty(),
        "/proc reads returned nothing, so the leak check cannot fail"
    );
});

/// Restricts a file to its owner, the mode libpq insists on.
#[cfg(unix)]
fn restrict_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("stat the passfile").permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).expect("chmod the passfile");
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &std::path::Path) {
    // The substrate is disposable and this suite is only ever run on a Unix
    // host with a real PostgreSQL; the other branch exists so the crate
    // compiles elsewhere rather than because it is expected to work.
}

/// Asks the server whether `pid` is still a live backend.
///
/// Connects as the same role and reads `pg_stat_activity`. A superuser-only
/// view would make this impossible from the test's own credentials, which is
/// why it filters on `pid` in `pg_stat_activity`, which every role can see
/// for its own sessions.
async fn backend_still_listed(substrate: &Substrate, pid: i32) -> bool {
    // A second connection is needed because the session under test has been
    // terminated. The query is parameterless by necessity: the simple query
    // protocol has no bind step, and interpolating `pid` into SQL from a
    // value the test itself produced is safe here only because it is an i32
    // this test just read off the wire.
    let roots = roots(substrate);
    let mut observer = match live::connect(
        substrate.address,
        substrate.port,
        &substrate.name,
        &roots,
        &substrate.database,
        &substrate.role,
        &substrate.password,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => panic!("the observer session could not connect: {error}"),
    };
    let sql = format!("select count(*) from pg_stat_activity where pid = {pid}");
    match observer.query(&sql).await {
        Ok(result) => result
            .rows
            .first()
            .and_then(|row| row.first())
            .map(|count| count.trim() != "0")
            .unwrap_or(false),
        Err(error) => panic!("pg_stat_activity could not be read: {error}"),
    }
}
