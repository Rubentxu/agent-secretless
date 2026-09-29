// Inside-aist tests for the semantic PG surface.
//
// Each test exercises one scenario from docs/specs/m6-postgres/specification.md.
// The five scenarios are gathered in a single integration test in the broker
// crate (T9); this file hosts the unit-level checks.
//
// The tests in this file are not collected by `cargo test` until the
// module is declared `mod tests` from `pg.rs`. That declaration is part
// of T5 (the real `pg/tests.rs` lives in `crates/connector-pg/src/pg/tests.rs`,
// matched by the `[include]`-style structure `asv-connector-http` uses
// for its github tests).