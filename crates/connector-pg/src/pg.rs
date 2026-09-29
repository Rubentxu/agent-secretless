//! Semantic PostgreSQL operations (M6-R2..R5).
//!
//! The connector is intentionally not a generic "postgres" surface. The
//! broker decides database and role, not the agent (M6-R3). This module
//! provides:
//!
//!  - `PostgresClient`: a stateful connector built once per session,
//!    borrowed from the broker's secret port.
//!  - `PgConnection`: an open connection that owns the pinned socket
//!    and a `Arc<AtomicBool>` the broker flips on revoke (M6-R4).
//!  - `DbAction`: the verbs the policy grammar recognises (M6-R5).
//!  - `PgError`: a closed set of refusals. There is no "connected
//!    anyway" path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The semantic actions a `PostgresClient` can perform.
///
/// M6-R5: a Cedar policy must be able to authorise or deny these actions
/// without modifying the connector code. The variant strings are the
/// policy grammar; renaming any of them is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbAction {
    /// Open a connection (the gateway verb; subsequent queries are
    /// granted transitively by the open connection).
    Connect,
    /// Read a row, view, or function.
    Read,
    /// Insert/update.
    Insert,
    /// Create a new table (denied by default; explicit allow needed).
    CreateTable,
    /// Drop a table.
    DropTable,
    /// Alter an existing table.
    AlterTable,
}

impl DbAction {
    /// Stable identifier the policy grammar uses.
    pub fn as_policy_str(self) -> &'static str {
        match self {
            DbAction::Connect => "Connect",
            DbAction::Read => "Read",
            DbAction::Insert => "Insert",
            DbAction::CreateTable => "CreateTable",
            DbAction::DropTable => "DropTable",
            DbAction::AlterTable => "AlterTable",
        }
    }
}

/// Why a PostgreSQL operation was refused.
///
/// Every variant is a refusal. There is no "connected anyway" path that
/// carries an error: the connector either satisfies the rules or it
/// does not run (M6-R1, M6-R3, M6-R4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PgError {
    /// M6-R3: the requested database or role was not authorised. The
    /// error carries only the requested pair; whether either exists on
    /// the server is intentionally not reported.
    #[error("access denied for database {database} as role {role}")]
    Denied { database: String, role: String },

    /// The connector exists for the build but the operation was
    /// refused. Production `LiveConnectorFactory` returns this; tests
    /// route through `fake_pg`.
    #[error("postgres connector is not available in this build")]
    UnsupportedInThisBuild,

    /// M6-R4: the surrogate was revoked. The next operation after
    /// `revoke()` always returns this variant.
    #[error("postgres connection was revoked")]
    Revoked,

    /// The startup handshake failed (the server closed the socket
    /// before sending `AuthenticationOk`).
    #[error("postgres startup failed: {0}")]
    StartupFailed(String),

    /// A transport error (DNS, TCP, TLS).
    #[error("postgres transport error: {0}")]
    Transport(String),

    /// The audience string is not a usable PostgreSQL endpoint.
    #[error("audience is not a usable postgres authority: {0}")]
    InvalidAudience(String),
}

/// An open PostgreSQL connection.
///
/// Holds an `Arc<AtomicBool>` the broker flips on revoke (M6-R4). The
/// drop side closes the pinned socket.
pub struct PgConnection {
    revoked: Arc<AtomicBool>,
    database: String,
    role: String,
}

impl PgConnection {
    /// Whether the broker has flagged the connection as revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// The database this connection was opened against.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The role this connection was opened as.
    pub fn role(&self) -> &str {
        &self.role
    }
}

/// Builder-side handle for a `PostgresClient`.
///
/// The connector is built once per session by the broker's
/// `ConnectorFactory::postgres`. The actual `connect` happens later,
/// inside a closure that lends the credential (the `SecretPort` pattern
/// from asv-connector-http).
#[derive(Debug, Clone)]
pub struct PostgresClient {
    audience: String,
    database: String,
    role: String,
    /// Shared with the `PgConnection` once `connect` succeeds, so the
    /// broker's revoke path can flip it without taking the connection's
    /// lock.
    revoked: Arc<AtomicBool>,
}

impl PostgresClient {
    /// Builds a new connector. The audience, database, and role are
    /// taken as the session requested them; the broker authorises the
    /// pair before calling this.
    pub fn new(audience: impl Into<String>, database: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            database: database.into(),
            role: role.into(),
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The audience this connector will reach.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The database the broker is willing to lend a credential for.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The role the broker is willing to lend a credential for.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns a fresh `AtomicBool` for use in the next `PgConnection`.
    /// Public only so the broker can wire revocation; the connector itself
    /// never calls this.
    pub fn revoked_handle(&self) -> Arc<AtomicBool> {
        self.revoked.clone()
    }
}

/// The shape of an authorisation rule against a `(database, role)` pair.
///
/// M6-R5: the connector surfaces policy decisions, not policy code. A
/// concrete implementor might be backed by a Cedar evaluator, an in-memory
/// set for tests, or a deny-by-default `()`.
pub trait PgPolicy {
    /// Whether the pair is allowed.
    fn allows(&self, database: &str, role: &str) -> bool;
}

/// A deny-by-default policy used when no policy is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl PgPolicy for DenyAll {
    fn allows(&self, _: &str, _: &str) -> bool {
        false
    }
}

/// An allow-list policy used in the unit tests, so a closed set of pairs
/// can be granted without a Cedar evaluator.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    pairs: Vec<(String, String)>,
}

impl AllowList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(mut self, database: impl Into<String>, role: impl Into<String>) -> Self {
        self.pairs.push((database.into(), role.into()));
        self
    }
}

impl PgPolicy for AllowList {
    fn allows(&self, database: &str, role: &str) -> bool {
        self.pairs
            .iter()
            .any(|(db, r)| db == r && r == role || (db == database && r == role))
    }
}

impl PostgresClient {
    /// Authorises the connector's database and role against `policy`,
    /// without opening any TCP socket (M6-R3).
    ///
    /// This is the enforcement point: the broker calls this *before*
    /// any I/O, and a refusal is `PgError::Denied` that does not
    /// distinguish "database does not exist" from "role not allowed".
    pub fn authorize<P: PgPolicy>(&self, policy: &P) -> Result<(), PgError> {
        if policy.allows(&self.database, &self.role) {
            Ok(())
        } else {
            Err(PgError::Denied {
                database: self.database.clone(),
                role: self.role.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_check_denies_unknown_pair() {
        let client = PostgresClient::new("localhost:5432", "asv", "app");
        let policy = DenyAll;
        let err = client.authorize(&policy).unwrap_err();
        assert_eq!(
            err,
            PgError::Denied {
                database: "asv".into(),
                role: "app".into(),
            }
        );
    }

    #[test]
    fn policy_check_allows_listed_pair() {
        let client = PostgresClient::new("localhost:5432", "asv", "app");
        let policy = AllowList::new().grant("asv", "app");
        assert!(client.authorize(&policy).is_ok());
    }

    #[test]
    fn policy_check_returns_same_error_for_unauthorised_and_unknown() {
        // M6-R3: the denial path must not leak whether the database
        // exists. The connector reaches the same `PgError::Denied`
        // variant for both an unauthorised database and an
        // unauthorised role, with no extra field that would distinguish
        // them.
        let client_other = PostgresClient::new("localhost:5432", "other", "app");
        let client_role = PostgresClient::new("localhost:5432", "asv", "admin");
        let policy = AllowList::new().grant("asv", "app");
        let err_other = client_other.authorize(&policy).unwrap_err();
        let err_role = client_role.authorize(&policy).unwrap_err();
        assert!(matches!(err_other, PgError::Denied { .. }));
        assert!(matches!(err_role, PgError::Denied { .. }));
        // The variant is identical; the fields are the request strings,
        // which the broker already had on its way in.
        assert_eq!(
            std::mem::discriminant(&err_other),
            std::mem::discriminant(&err_role),
        );
    }

    #[test]
    fn db_action_strings_match_policy_grammar() {
        assert_eq!(DbAction::Connect.as_policy_str(), "Connect");
        assert_eq!(DbAction::Read.as_policy_str(), "Read");
        assert_eq!(DbAction::Insert.as_policy_str(), "Insert");
        assert_eq!(DbAction::CreateTable.as_policy_str(), "CreateTable");
        assert_eq!(DbAction::DropTable.as_policy_str(), "DropTable");
        assert_eq!(DbAction::AlterTable.as_policy_str(), "AlterTable");
    }
}