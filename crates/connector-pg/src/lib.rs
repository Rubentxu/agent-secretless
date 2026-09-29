//! PostgreSQL transport for brokered, semantic DB calls (M6 design v2).
//!
//! The crate has no session or policy state. It holds only:
//!
//!  - the address policy and pinning rules the broker relies on,
//!  - the semantic `connect`/`authorize` surface a session can drive,
//!  - the `spawn_psql` helper that hands the password to `psql` without
//!    ever putting it on the agent's command line, environment, or any
//!    file the agent could read.
//!
//! The connector is `PostgresClient`, deliberately not a generic
//! "postgresql" escape hatch. The broker decides database and role, not the
//! agent (M6-R3: denial happens before authentication completes).
//!
//! R6 / D9: this crate must never read the environment. A future
//! regression test (mirror of the asv-connector-http rule) will enforce
//! it; for now every code path that would set `PGPASSWORD` or
//! `PGPASSFILE` is forbidden by inspection.

#![cfg_attr(any(test, feature = "test-support"), allow(dead_code, unused_imports))]

/// A local in-process TCP server that speaks the PostgreSQL startup
/// protocol enough to drive the real connector against a real socket
/// without touching the network. Gated on `cfg(test)` or the
/// `test-support` feature, mirroring `asv-connector-http::fake_origin`.
#[cfg(any(test, feature = "test-support"))]
pub mod fake_pg;

/// The semantic PostgreSQL surface: a `PostgresClient` whose methods
/// are the broker's verbs (`connect`, `query`, `revoke`).
pub mod pg;

/// The pinned transport: address resolution, address policy, and the
/// `PinnedPgClient` shape that records the resolved addresses the
/// connector will reach.
pub mod transport;

/// The `spawn_psql` helper. Lives in its own module so the surface is
/// easy to audit: the rule is `env_clear + Stdio::piped + PGPASSWORD
/// absent from env`, and there is exactly one place where the rule is
/// stated and one place where it is implemented.
pub mod spawn;

pub use pg::{AllowList, DbAction, DenyAll, PgConnection, PgError, PgPolicy, PostgresClient};
pub use spawn::{spawn_psql_reveal, PsqlSpawn};
pub use transport::{
    resolve_and_pin, AddressPolicy, PgAudience, PinnedPgClient, PinnedPgError, ResolvedPgAudience,
};

#[cfg(any(test, feature = "test-support"))]
pub use fake_pg::FakePg;
