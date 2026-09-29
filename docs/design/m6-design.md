# M6 Design — PostgreSQL reference connector

## Goal

Add a PostgreSQL reference connector that satisfies M6-R1..R5 and proves
the secret-broker pattern generalises to a stateful, connection-oriented
protocol without ever putting the password somewhere the agent can read.

## Crate topology

New crate: `crates/connector-pg/`, sibling of `connector-http`.

```
crates/
  connector-http/    # M4 (existing)
  connector-pg/      # M6 (new)
    Cargo.toml
    src/
      lib.rs
      pg.rs           # PostgresClient — semantic operations
      spawn.rs        # spawn_psql helper, password-on-stdin
      transport.rs    # PinnedPgClient over rustls-postgres (or tcp-only stub)
      fake_pg.rs      # in-process TCP server, gate: tests only
      pg/tests.rs     # inside-aist tests for the proxy
  broker/src/lib.rs   # ConnectorFactory gains fn postgres
```

The crate re-uses `asv-domain::Authority` (already in M4). It depends on
`connector-http`'s `transport::AddressPolicy` if exporting it adds no API
surface; otherwise copy the policy into the new crate to avoid a circular
dependency.

## ConnectorFactory extension

```rust
pub trait ConnectorFactory {
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError>;

    /// Builds a PostgreSQL client for the given audience.
    ///
    /// `database` and `role` are *requested* by the session, not authorised
    /// here. The factory exists to construct the client; the actual
    /// authorisation happens against the policy engine (M6-R5) inside the
    /// connector before any I/O.
    fn postgres(
        &self,
        audience: Authority,
        database: String,
        role: String,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<PostgresClient, PgError>;
}
```

A second method (not a generic dispatch) is the right shape because the
error types are different. The broker keeps its `Box<dyn ConnectorFactory>`
shape — adding a method is a non-breaking change for every existing test
because none of them construct an HTTP-only factory that would now lack
`postgres`. The tests that already do not touch PostgreSQL would never
call `postgres`, and Rust's coherence rules make adding a default method
the smallest possible surface.

The production factory `LiveConnectorFactory` provides `postgres` returning
`PgError::UnsupportedInThisBuild` until the real PG client is wired; the
default in tests points at the fake origin.

## PostgresClient shape

Mirroring `GithubClient`, but with state:

```rust
pub struct PostgresClient {
    audience: Authority,
    database: Database,    // restricted to a set the policy authorises
    role: Role,
    pinned: PinnedPgClient,
    secrets: Arc<dyn SecretPort>,
}

impl PostgresClient {
    /// Opens the connection. Returns a `PgConnection` that owns the
    /// socket and the borrowed credential.
    pub async fn connect(&self) -> Result<PgConnection, PgError>;

    /// Tears the connection down. Called on revoke (M6-R4).
    pub async fn revoke(&self, conn: &mut PgConnection) -> Result<(), PgError>;
}
```

`PgConnection` holds:

- the pinned TCP socket (no agent-side state),
- the current borrowed credential (Zeroizing<u8>, dropped on revoke),
- a `revoked: Arc<AtomicBool>` the broker can flip without holding the
  connection's lock (so the next statement observes it).

## spawn_psql helper

`spawn::spawn_psql` builds a `tokio::process::Command` for `psql`, with:

- `env_clear()` so no parent env leaks through;
- `env("PGHOST", ...)`, `env("PGPORT", ...)`, `env("PGDATABASE", ...)`,
  `env("PGUSER", ...)` set to *non-secret* values the broker has
  approved;
- `env("PGPASSWORD", ...)` **never** set — instead the password is
  piped on stdin, in a small handshake `pg` accepts over its connection
  protocol after `psql` has already opened the TCP socket without
  authenticating;
- stdin opened via `Stdio::piped()` so the broker writes the password
  once and closes;
- stdout/stderr captured by the broker, not by the agent (this is what
  keeps the password out of any file the agent writes).

The `Stdio::null()` for stderr avoids leaking error messages that
sometimes include connection strings.

## fake_pg (test support)

A `tokio::net::TcpListener` accepting one connection at a time on a
random loopback port. Implements:

- the PostgreSQL `StartupMessage` parsing: extracts `user`, `database`,
  returns `ErrorResponse` if either is not in the allowed set;
- the `PasswordMessage` parsing: accepts any 32+ byte string and keeps
  it in memory to verify the broker's spawn helper pipes the password
  via stdin (not via env or cmdline);
- the `Query`/`SimpleQuery` cycle for `select 1` and `create table x`;
- a `terminate` hook the broker's `revoke` calls to close the socket.

The fake origin is wired into `go_router` analogue (the M4 term):
`LiveConnectorFactory::postgres` in test builds points at the fake,
in production builds returns `PgError::UnsupportedInThisBuild`.

## Authorisation before authentication (M6-R3)

`PostgresClient::connect` does:

1. Resolve + pin the audience (same shape as M4's `resolve_and_pin`).
2. Check the policy: is `database` and `role` allowed for this
   principal? If not, return `PgError::Denied` *before* opening a TCP
   socket. The `Denied` variant has no `PgError::DbExists` analogue —
   the response is the same regardless of whether the database
   exists. This is the M6-R3 enforcement point.
3. Open the TCP socket, then perform the PostgreSQL startup, then
   pipe the password.

The `PgError::Denied` carries only `("database", "role")` and never
the resolved addresses; this is what avoids the existence-oracle leak.

## Revocation (M6-R4)

`BrokerState::surrogates` already exposes a `revoke(session_id)`. M6
adds an `OnRevoke` callback registration: when a session's surrogate
is revoked, every `PgConnection` that session owns gets its
`revoked: Arc<AtomicBool>` flipped. The next `Query` returns
`PgError::Revoked` and the TCP socket is closed by dropping the
`PgConnection`.

## Resource/action policy (M6-R5)

The connector surfaces:

```rust
pub enum DbAction {
    Connect,
    CreateTable,
    Select,
    Insert,
    DropTable,
    AlterTable,
}
```

The Cedar policy in `crates/broker/src/policy/olicies.cedar` (existing)
gains a rule:

```
permit(principal, action == DbAction::"Connect", resource)
when { ... };

forbid(principal, action == DbAction::"CreateTable", resource)
when { ... };
```

The test for M6-S5 compiles a policy with only `Connect` allowed,
issues `create table x`, expects `PgError::Denied`, then issues
`select 1` and expects success.

## Test plan

`crates/connector-pg/src/pg/tests.rs` (inside-aist tests, the M4
convention):

- `pg_s1_dispatch_by_tag` — M6-S1, unit: `ConnectorFactory::postgres`
  routes only PostgreSQL-tagged audiences.
- `pg_s2_password_absence` — M6-S2, integration: spawn a fake `psql`
  stub that dumps its environment and argv, run the broker's
  `spawn_psql`, grep all four surfaces for the password.
- `pg_s3_denial_before_auth` — M6-S3, unit: pass an unauthorised
  database, assert no TCP connect was attempted (counter on
  `fake_pg`'s listener is zero).
- `pg_s4_revoke_teardown` — M6-S4, integration: open a session,
  revoke, send another query, observe `PgError::Revoked`.
- `pg_s5_policy_action` — M6-S5, unit: install a restrictive
  Cedar policy, exercise `create table` then `select 1`.

Each test uses `fake_pg` so no live PostgreSQL is needed.

## What is deliberately out of scope

- A real `postgres-protocol` library integration (uses `tokio-postgres`
  only inside `transport.rs`, behind the trait so the fake works).
- Connection pooling (one TCP socket per session is correct here).
- The optional spike for the dynamic DB credential provider.

## Estimated size

- `crates/connector-pg/src/lib.rs`           ~50 LOC
- `crates/connector-pg/src/pg.rs`           ~250 LOC
- `crates/connector-pg/src/spawn.rs`        ~120 LOC
- `crates/connector-pg/src/transport.rs`    ~200 LOC
- `crates/connector-pg/src/fake_pg.rs`      ~250 LOC
- `crates/connector-pg/src/pg/tests.rs`     ~400 LOC
- edits to `crates/broker/src/lib.rs`       ~30 LOC
- edits to `Cargo.toml` (workspace)         ~3 LOC

Total ~1300 LOC, comparable to M4's connector-http (2500 LOC) but
without the redirect / pagination machinery.