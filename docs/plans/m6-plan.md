# M6 Implementation Plan

Source: M6 specification (`docs/specs/m6-postgres/specification.md`),
M6 design (`docs/design/m6-design.md`).

## Carry-over

Existing draft work item `6e29af7b-0f9b-4dde-883b-d3e7ee8033b7`
("M6 spec and PostgreSQL connector scaffold"). It is satisfied by the
specification + exploration + design already produced; this plan
decomposes the remaining work into executable tasks.

## Task decomposition

### T1 — `feat(workspace): scaffold crates/connector-pg`

Create the new crate under `crates/connector-pg/`, register it in the
workspace `Cargo.toml`, mirror the `connector-http` skeleton (Cargo.toml,
src/lib.rs, no impl yet). Confirm `cargo check -p asv-connector-pg`
compiles empty.

Exit criteria:
- `cargo check -p asv-connector-pg` exits 0.
- `Cargo.toml` workspace lists `crates/connector-pg`.

### T2 — `feat(transport): PgError and AddressPolicy in connector-pg`

Copy/port the `AddressPolicy` shape from `connector-http/transport.rs`
into `connector-pg/transport.rs`, add a `PgError` enum (`Denied`,
`UnsupportedInThisBuild`, `Revoked`, `StartupFailed`, `I/O`).

Exit criteria:
- `cargo check -p asv-connector-pg` exits 0.
- Unit test for `AddressPolicy::permits` covering loopback, RFC1918,
  documentation, IPv4-mapped IPv6.

### T3 — `feat(spawn): spawn_psql helper`

Implement `spawn::spawn_psql` with `env_clear()`, `Stdio::piped()`,
`PGPASSWORD` deliberately absent from the environment. Write the helper
test on a no-op command (echo false) to verify env-clear works.

Exit criteria:
- `cargo test -p asv-connector-pg spawn` passes.
- The test prints the resulting env on stdout (so it can be eyeballed).

### T4 — `feat(pg): PostgresClient with policy check before connect`

`PostgresClient::connect` validates `(database, role)` against a policy
before any TCP. `PgError::Denied` is returned without opening a socket.

Exit criteria:
- Unit test: an unauthorised database returns `PgError::Denied`, and a
  counter inside `fake_pg` (which is not yet wired to the real
  listener) is the proxy for "no socket was opened".

### T5 — `test(pg): fake_pg in-process server`

Wire a `tokio::net::TcpListener` in tests; implement `StartupMessage`
parsing enough to accept the broker's connect and reply with a
synthetic `AuthenticationOk`. The hook counts incoming connections.

Exit criteria:
- `fake_pg::listener()` returns a `TestPg` whose `connection_count()`
  increments on each connect.
- A direct unit test sends one startup, sees the counter == 1.

### T6 — `feat(pg): revoke teardown via Arc<AtomicBool>`

`PgConnection` carries a `revoked: Arc<AtomicBool>`. The broker's
surrogate revoke sets it. The next query observes it and returns
`PgError::Revoked`.

Exit criteria:
- Unit test: open a connection, flip `revoked`, send a query, observe
  `PgError::Revoked`.

### T7 — `feat(broker): ConnectorFactory::postgres`

Extend `ConnectorFactory` in `crates/broker/src/lib.rs` with a `fn
postgres(...)` returning `PostgresClient`. `LiveConnectorFactory::postgres`
returns `PgError::UnsupportedInThisBuild`; `TestConnectorFactory`
(implemented in `crates/broker/tests/support.rs`) routes to `fake_pg`.

Exit criteria:
- `cargo check -p asv-broker` exits 0.
- A pre-existing broker test that uses `LiveConnectorFactory` is
  unchanged.

### T9 — `test(uat-039): M6-S1..S5 in one integration test`

Single integration test that wires fake_pg → spawn_psql → PostgresClient
and exercises M6-S1..S5 in order.

Exit criteria:
- `cargo test -p asv-connector-pg uat_039` passes.
- Test name and scenario ids visible in the failure message.

### T10 — `chore(dev-deps): update workspace lockfile and CI config`

Add `asv-connector-pg` to any CI matrix (`tools/ci/*`, `.github/workflows/*`).

Exit criteria:
- A dry-run of the workspace-level test command lists
  `asv-connector-pg`.

## Sequencing

T1, T2, T3, T5 can land first (independent). T4 depends on T2. T6
depends on T5. T7 depends on T4 + T6. T9 depends on T7. T10 last.

A natural commit ordering:

1. `chore(workspace): scaffold crates/connector-pg`     (T1)
2. `feat(transport): PgError and AddressPolicy`         (T2)
3. `feat(spawn): spawn_psql helper`                     (T3)
4. `test(pg): fake_pg in-process server`                (T5)
5. `feat(pg): PostgresClient with policy check`         (T4)
6. `feat(pg): revoke teardown via AtomicBool`           (T6)
7. `feat(broker): ConnectorFactory::postgres`           (T7)
8. `test(uat-039): M6-S1..S5 integration`               (T9)
9. `chore(dev-deps): update workspace lockfile and CI`  (T10)

## Risk and rollback

- T7 changes the broker's public trait. The change is *non-breaking*
  for any existing implementor because the existing trait had a single
  method and every implementor adds the new method. A botched change
  is reverted by reverting that single commit.
- T5 spawns an OS thread pool via tokio. If `tokio` runtime is not
  present in dev-deps for the new crate, T5 fails first. The Cargo.toml
  for connector-http is the template.

## What is intentionally not in this plan

- A real PostgreSQL round-trip (deferred; no architectural coverage).
- Cedar policy grammar extension (the existing `db_resource` /
  `db_action` from M3's policy work is reused as-is).
- Connection pooling.
- The optional spike for the dynamic DB credential provider.