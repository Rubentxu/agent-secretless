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

/// A local in-process TCP server that speaks the PostgreSQL startup
/// protocol enough to drive the real connector against a real socket
/// without touching the network. Test-only.
#[cfg(test)]
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

/// SCRAM-SHA-256, the authentication a modern PostgreSQL server requires.
///
/// Separate from the wire protocol because it is the one part of the
/// transport with a published test vector: RFC 7677 gives a full exchange
/// with expected output, so the implementation can be pinned to something
/// outside this repository instead of to itself.
pub mod scram;

/// The PostgreSQL v3 wire protocol: framing, the startup handshake, and the
/// two query paths. Separate from `live` so the codec can be driven against
/// a scripted peer without a TLS stack in the way.
pub mod wire;

/// The live connection: TCP, TLS, SCRAM, and the teardown observation
/// M6-R4 requires.
pub mod live;

/// How the broker reaches a PostgreSQL server.
///
/// Separated from `LiveConnectorFactory` in the broker so this crate states
/// what a connection needs and the broker decides what it is willing to supply.
/// The password is a borrowed slice rather than a field: this struct is `Debug`
/// and `Clone`, and a password that could be printed is a password that will be.
#[derive(Debug, Clone)]
pub struct LiveConnectorConfig {
    /// The address the broker pinned and the policy already allowed.
    pub address: std::net::IpAddr,
    /// The port, pinned alongside the address.
    pub port: u16,
    /// The name the server certificate must match. Never derived from the
    /// address: a certificate carries names, and a client that checks an IP
    /// string is not verifying anything.
    pub server_name: String,
    /// Roots to trust in addition to the platform store.
    pub roots: TlsRoots,
    /// The database the broker authorised for this session.
    pub database: String,
    /// The role the broker authorised for this session.
    pub role: String,
}

impl LiveConnectorConfig {
    /// Builds a config for a `host:port` the caller has already authorised.
    pub fn new(
        address: std::net::IpAddr,
        port: u16,
        server_name: impl Into<String>,
        roots: TlsRoots,
        database: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            address,
            port,
            server_name: server_name.into(),
            roots,
            database: database.into(),
            role: role.into(),
        }
    }
}

pub use live::{connect, LivePgSession, Teardown, TlsRoots};
pub use wire::{QueryResult, WireError};

pub use LiveConnectorConfig as ConnectorConfig;

pub use pg::{AllowList, DbAction, DenyAll, PgConnection, PgError, PgPolicy, PostgresClient};
pub use scram::{normalise_password, NormalisedPassword, Scram, ScramError};
pub use spawn::{spawn_psql_reveal, PsqlSpawn};
pub use transport::{
    resolve_and_pin, AddressPolicy, PgAudience, PinnedPgClient, PinnedPgError, ResolvedPgAudience,
};

#[cfg(test)]
pub use fake_pg::FakePg;
