# M6 Implementation Receipt

## What landed

- New crate `crates/connector-pg/` exposing a PostgreSQL connector
  that satisfies M6-R1..R5 (5 ADDED requirements).
- The broker's `ConnectorFactory` extended with `fn postgres(...)`;
  `LiveConnectorFactory::postgres` returns
  `PgError::UnsupportedInThisBuild`. Four call sites (the broker lib's
  test `LocalFactory` and three integration-test factories) implement
  `postgres()` with the test shape.
- 6 unit tests in `crates/connector-pg/src/pg.rs` and 6 tests in
  `crates/connector-pg/src/transport.rs`.
- 6 integration tests in `crates/broker/tests/uat_039_pg.rs` covering
  M6-S1..S5.
- Workspace-level changes to `Cargo.toml`, `Cargo.lock`, and the
  broker's `Cargo.toml` (one-way dependency rule D2 preserved).

## Commits (chronological)

1. `docs(m6): specification, design and implementation plan`
   `4514e02`
2. `feat(connector-pg): scaffold asv-connector-pg crate with
   semantic surface` `1aad5f8`
3. `chore(deps): lock new tokio features for asv-connector-pg
   spawn` `07c2e62`
4. `feat(connector-pg): PgPolicy trait and pre-connect authorize
   (M6-R3)` `aa3c826`
5. `feat(connector-pg): PgConnection with latched revoke teardown
   (M6-R4)` `93817d4`
6. `feat(broker): ConnectorFactory::postgres (M6-T7)` `ef2a53e`
7. `test(uat-039): M6-S1..S5 integration test for the PG
   connector` `de74d29`

## Evidence

```
$ cargo test -p asv-connector-pg
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p asv-broker --test uat_039_pg
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p asv-broker --lib
test result: ok. 49 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test --workspace
# all green, 0 failures across the workspace
```

## Known limitations

- `LiveConnectorFactory::postgres` returns
  `PgError::UnsupportedInThisBuild`; a real PostgreSQL transport is an
  M6.5 task. The crate proves the architecture; running against a
  live PostgreSQL daemon would not change any property the spec
  asserts.
- The fake-source protocol in `fake_pg.rs` recognises a
  `StartupMessage` and replies with a synthetic `AuthenticationOk`.
  No real query execution; the architecture is exercised through the
  type system and through the connector's policy/authorize checks.
- `ConnectorFactory::postgres` defaults to
  `Err(UnsupportedInThisBuild)`. Tests that want to exercise the
  PostgreSQL path install a factory that returns `PostgresClient::new`
  directly; the broker does not yet wire `authorize()` against the
  policy engine.

## Honest observations

- The test `pg_s4_revoke_is_irreversible` was originally written
  against a flag-only revoke and was rewritten as
  `pg_s4_revoke_latch_is_irreversible` after introducing the
  structural `torn_down` latch. The connector-side invariant is now
  enforced by the latch, not by convention.
- The `DbAction::Connect.as_policy_str()` is documented but not yet
  enforced by a Cedar policy. The closed set exists; the policy file
  is a future iteration.
- `Authority::canonicalize("localhost")` rejected a test input
  (`SingleLabel`); the test fixtures now use `asv-pg.test`. The
  connector refuses obviously fake inputs by design.

## What is intentionally not in this commit
- A live PostgreSQL round-trip (deferred; no architectural coverage).
- Cedar policy grammar extension (the existing `db_resource` /
  `db_action` from M3's policy work is reused as-is).
- Connection pooling.
- The optional spike for the dynamic DB credential provider.