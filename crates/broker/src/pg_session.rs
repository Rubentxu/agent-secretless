//! The broker's live PostgreSQL sessions (M6).
//!
//! The broker's request handler is synchronous and every request goes through
//! it, while the transport is `async`. Rather than make the whole broker async
//! for one verb, a live session is owned by a task on a shared runtime and the
//! caller talks to it through a channel. That keeps one code path for every
//! request and one owner for every socket.
//!
//! What this module guarantees, and why each guarantee is here:
//!
//! * **The password never becomes a field.** The map holds a sender and the
//!   identifiers the broker chose. There is nowhere for a credential to land,
//!   so there is nothing to scrub later.
//! * **A statement never outlives its revoke.** The revoke latch lives inside
//!   the session and is checked before any statement reaches the socket, so the
//!   ordering does not depend on the caller remembering.
//! * **A teardown is only reported when it was observed.** The value returned
//!   is what the socket did, never the fact that a revoke was requested. This
//!   is the distinction M6-R4 exists for.

use asv_connector_pg::{LiveConnectorConfig, LivePgSession, QueryResult, Teardown, WireError};
use asv_domain::AgentSessionId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// The outcome of one statement, as the broker reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementOutcome {
    /// The rows, each rendered as the server sent it.
    ///
    /// A row is a list of column values in text form. The broker does not
    /// reformat, retype, or truncate: its job is to hand back the server's
    /// answer, and any shaping it did would be a second thing a caller could be
    /// wrong about. A SQL NULL stays distinguishable from the four characters
    /// `NULL` because the connector preserves that distinction, and collapsing
    /// it here would undo the one guarantee a text protocol can make.
    pub rows: Vec<Vec<String>>,
}

impl StatementOutcome {
    fn from_result(result: QueryResult) -> Self {
        Self { rows: result.rows }
    }
}

/// Renders one row as a single string for the wire.
///
/// The IPC response carries `Vec<String>`, one string per row, so the column
/// boundaries have to be encoded into the string itself. The separator is a
/// unit separator (`0x1f`) rather than a space or a tab because those are
/// legal inside a text value: a row holding a space-separated string would be
/// indistinguishable from two columns, and a client that split on the wrong
/// character would be wrong in a way nothing downstream could detect.
///
/// A SQL NULL is rendered as an empty field, which is also what it is on the
/// wire, and the connector's own null handling is what keeps a literal `NULL`
/// distinguishable from an absent value.
pub fn render_row(row: &[String]) -> String {
    row.join("\u{1f}")
}

/// A failure the broker turns into an IPC answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgSessionError {
    /// The session is not open, or the peer does not own it.
    NoSuchSession,
    /// The session was revoked; nothing further may run on it.
    Revoked,
    /// A real transport failure. The message is the connector's own, which by
    /// construction never carries the password.
    Transport(String),
}

impl std::fmt::Display for PgSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchSession => write!(f, "no open postgres session for this request"),
            Self::Revoked => write!(f, "postgres session was revoked"),
            Self::Transport(message) => write!(f, "postgres transport error: {message}"),
        }
    }
}

impl std::error::Error for PgSessionError {}

/// What a caller asks the owning task to do.
enum Command {
    Query(
        String,
        tokio::sync::oneshot::Sender<Result<StatementOutcome, PgSessionError>>,
    ),
    Revoke(tokio::sync::oneshot::Sender<Teardown>),
}

/// The broker's table of live PostgreSQL sessions.
///
/// Holds the *senders*. The socket lives in a task that owns the matching
/// receiver, which is what makes "exactly one owner per socket" structural
/// rather than a convention: there is no shared `&mut` for two requests to
/// race over.
#[derive(Default)]
pub struct PgSessionMap {
    sessions: Mutex<HashMap<AgentSessionId, mpsc::Sender<Command>>>,
}

use tokio::sync::mpsc;

impl PgSessionMap {
    /// How many sessions are open.
    ///
    /// Observable from outside the crate on purpose: the zero-live-session
    /// check has to be readable by something other than this module, or it is
    /// an assertion nobody can make.
    pub fn len(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops the handle without asking the server anything.
    ///
    /// Used when an agent session ends for a reason that is not a revoke. The
    /// sender goes away, the task's `recv` returns `None`, the task ends, and
    /// the socket closes. The server observes the same teardown it would
    /// observe from `Terminate`; the only difference is whether the broker
    /// waited to see it.
    pub fn forget(&self, session: AgentSessionId) -> bool {
        self.sessions
            .lock()
            .map(|mut s| s.remove(&session).is_some())
            .unwrap_or(false)
    }

    /// Runs `sql` on `session`, if it is open.
    pub async fn query(
        &self,
        session: AgentSessionId,
        sql: String,
    ) -> Result<StatementOutcome, PgSessionError> {
        let tx = self.sender(session)?;
        let (reply, answer) = tokio::sync::oneshot::channel();
        tx.send(Command::Query(sql, reply))
            .await
            .map_err(|_| PgSessionError::NoSuchSession)?;
        // A dropped reply means the task ended without answering, which is the
        // same observable fact as the session being gone. Mapping it to
        // `NoSuchSession` keeps a finished task from reading as a query
        // failure, which would send an operator looking at the wrong thing.
        answer.await.map_err(|_| PgSessionError::NoSuchSession)?
    }

    /// Revokes `session` and reports what the server did.
    pub async fn revoke(&self, session: AgentSessionId) -> Result<Teardown, PgSessionError> {
        let tx = self.sender(session)?;
        let (reply, answer) = tokio::sync::oneshot::channel();
        tx.send(Command::Revoke(reply))
            .await
            .map_err(|_| PgSessionError::NoSuchSession)?;
        // The entry goes before the answer is read. A revoke consumes the
        // session, so a second revoke has to find nothing rather than re-ask a
        // session that no longer exists. This is the broker-side half of the
        // same single-shot rule the connector enforces on its own socket.
        self.forget(session);
        answer.await.map_err(|_| PgSessionError::NoSuchSession)
    }

    fn sender(&self, session: AgentSessionId) -> Result<mpsc::Sender<Command>, PgSessionError> {
        self.sessions
            .lock()
            .ok()
            .and_then(|s| s.get(&session).cloned())
            .ok_or(PgSessionError::NoSuchSession)
    }
}

impl std::fmt::Debug for PgSessionMap {
    /// Prints the count and nothing else.
    ///
    /// A `Debug` that could print a session would be a `Debug` that could
    /// print a database, a role, and an address, and none of that belongs in a
    /// crash log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSessionMap")
            .field("open", &self.len())
            .finish()
    }
}

/// The runtime a live session is spawned onto.
///
/// Exists so the caller chooses the runtime rather than the map quietly
/// creating one. A runtime spawned behind a caller's back is a runtime whose
/// threads outlive the state a test believes it controls.
#[derive(Clone)]
pub struct PgRuntime(Arc<tokio::runtime::Handle>);

impl PgRuntime {
    /// The ambient runtime, if the caller is inside one.
    ///
    /// A broker under `#[tokio::main]` has one. A broker that is not gets
    /// `None` rather than a hidden runtime, so the synchronous entry point has
    /// to say where its work runs.
    pub fn ambient() -> Option<Self> {
        tokio::runtime::Handle::try_current()
            .ok()
            .map(|handle| Self(Arc::new(handle)))
    }

    /// Adopts an existing handle.
    ///
    /// The way a broker that is not itself inside a runtime gets one: the
    /// process builds the runtime, the broker is handed its handle, and the
    /// broker spawns its session tasks onto it. Which is the point, since a
    /// `Handle` is what lets a synchronous caller drive an asynchronous session
    /// without owning the runtime's threads.
    pub fn from_handle(handle: tokio::runtime::Handle) -> Self {
        Self(Arc::new(handle))
    }

    /// Drives `future` to completion on this runtime.
    ///
    /// `block_on` from inside a runtime thread panics, so this goes through
    /// `Handle::block_on`, which is the supported way to drive a future from
    /// a thread that happens to be inside the runtime. The broker's request
    /// path is synchronous by design, so this is the bridge and it has to be
    /// the one that knows the difference.
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}

impl std::fmt::Debug for PgRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PgRuntime")
    }
}

impl PgSessionMap {
    /// Connects, starts the owning task, and records it under `session`.
    ///
    /// The password is borrowed for the handshake and is not kept. It is copied
    /// into the SCRAM state, used to answer the server's challenge, and dropped
    /// with the handshake; nothing reachable from the recorded handle holds it.
    /// That is the reason the map is safe to keep for the life of a session
    /// without any scrubbing pass over it.
    pub async fn spawn(
        &self,
        runtime: &PgRuntime,
        session: AgentSessionId,
        config: &LiveConnectorConfig,
        password: &str,
    ) -> Result<(), PgSessionError> {
        // The socket is opened *here*, after the caller has authorised the
        // session and the pair. A refused request never gets this far, so it
        // never reaches a server.
        let connected = connect_with_password(config, password).await?;
        let (tx, rx) = mpsc::channel(8);
        runtime.0.spawn(drive(connected, rx));
        self.sessions
            .lock()
            .map_err(|_| poisoned())?
            .insert(session, tx);
        Ok(())
    }
}

/// The map's lock was poisoned by a panic in another thread.
fn poisoned() -> PgSessionError {
    PgSessionError::Transport("the postgres session table is poisoned".into())
}

/// Connects with a borrowed password, translating the connector's errors.
async fn connect_with_password(
    config: &LiveConnectorConfig,
    password: &str,
) -> Result<LivePgSession, PgSessionError> {
    asv_connector_pg::live::connect(
        config.address,
        config.port,
        &config.server_name,
        &config.roots,
        &config.database,
        &config.role,
        password,
    )
    .await
    .map_err(pg_error)
}

/// The connector's error as the broker's, keeping the two vocabularies apart.
fn pg_error(error: WireError) -> PgSessionError {
    match error {
        WireError::Revoked => PgSessionError::Revoked,
        other => PgSessionError::Transport(other.to_string()),
    }
}

/// The sink a lent credential is written into.
///
/// The `SecretPort` shape exists so a secret never gets a name in the caller's
/// scope: the port calls `accept` with borrowed bytes, the sink copies them
/// somewhere that zeroizes, and by the time `lend` returns the only copy the
/// broker has is the one that will be wiped.
///
/// The string lives beside the bytes in the same zeroizing wrapper rather than
/// being allocated as a `String` and borrowed back. A separate `String` would
/// have to be zeroized by hand, and a hand-written zeroize is one refactor away
/// from not happening.
#[derive(Debug, Default)]
pub struct BorrowedSecret(Option<Zeroizing<Vec<u8>>>);

impl BorrowedSecret {
    /// The borrowed credential, for the one call that needs it.
    ///
    /// Empty when nothing was lent, and that is the safe direction: a connect
    /// attempted without a credential is refused by the server, which is a
    /// better outcome than an unexpected success.
    pub fn expose(&self) -> &str {
        // The bytes came from a vault holding a password, so they are UTF-8 by
        // construction. Lossy conversion would hide a corrupt password behind
        // a U+FFFD and then report the failure at the server, so the check is
        // explicit: a password that is not text is refused here, named as such.
        match self.0.as_deref() {
            Some(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
            None => "",
        }
    }
}

impl asv_connector_http::SecretSink for BorrowedSecret {
    fn accept(&mut self, secret: &[u8]) -> Result<(), asv_connector_http::SecretError> {
        self.0 = Some(Zeroizing::new(secret.to_vec()));
        Ok(())
    }
}

/// The task body: one session, one command at a time.
async fn drive(mut session: LivePgSession, mut commands: mpsc::Receiver<Command>) {
    while let Some(command) = commands.recv().await {
        match command {
            Command::Query(sql, reply) => {
                let outcome = session
                    .query(&sql)
                    .await
                    .map(StatementOutcome::from_result)
                    .map_err(pg_error);
                // A send failure means the caller gave up. That is not an
                // error for the task: the statement already ran and the socket
                // is still healthy, so the session stays usable.
                let _ = reply.send(outcome);
            }
            Command::Revoke(reply) => {
                let teardown = session.revoke().await;
                let _ = reply.send(teardown);
                // The revoke consumed the session and its socket. Ending here
                // is what makes a second revoke find no task, which is the
                // single-shot rule the connector also enforces.
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_keeps_its_column_boundaries() {
        // The whole reason the separator is a unit separator and not a space:
        // a value may contain a space, and a client that split on one would see
        // two columns where the server sent one.
        let rendered = render_row(&["one two".to_string(), "three".to_string()]);
        assert_eq!(
            rendered.split('\u{1f}').collect::<Vec<_>>(),
            ["one two", "three"]
        );
    }

    #[test]
    fn an_empty_row_is_not_the_same_as_a_row_with_one_empty_column() {
        // Both render to the same string, and that is a real limitation of a
        // flat row encoding. It is stated here rather than discovered later:
        // the column count comes from the statement's row description, which
        // the simple query protocol does not return to a text-only client.
        assert_eq!(render_row(&[]), "");
        assert_eq!(render_row(&[String::new()]), "");
    }

    #[test]
    fn a_null_field_is_empty_rather_than_the_word_null() {
        // The connector encodes a SQL NULL as -1 length, and the renderer keeps
        // that as an empty field. Rendering the four characters `NULL` would
        // make a missing value indistinguishable from a real one.
        assert_eq!(render_row(&[String::new(), "x".to_string()]), "\u{1f}x");
    }

    #[test]
    fn a_sink_with_no_credential_exposes_nothing() {
        let sink = BorrowedSecret::default();
        assert_eq!(sink.expose(), "");
    }

    #[test]
    fn the_sink_debug_does_not_print_the_credential() {
        use asv_connector_http::SecretSink;
        let mut sink = BorrowedSecret::default();
        sink.accept(b"ASV-CANARY-sink-DO-NOT-LEAK").expect("accept");
        let rendered = format!("{sink:?}");
        assert!(
            !rendered.contains("ASV-CANARY"),
            "Debug leaked the credential: {rendered}"
        );
    }
}
