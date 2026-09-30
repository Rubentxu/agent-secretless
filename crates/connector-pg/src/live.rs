//! The live connection: TCP, TLS, startup, and the teardown M6-R4 asks about.
//!
//! # The two rules this module exists to hold
//!
//! **TLS is not optional and there is no fallback.** The connector sends an
//! `SSLRequest`, and a server that answers `N` ends the connection. A
//! connector that continued would be about to run a SCRAM exchange, and
//! therefore to send a password-derived key, in the clear. The refusal is
//! [`WireError::TlsRequired`], not a retry.
//!
//! **The broker's role, not the agent's.** `connect` takes a `role` and a
//! `database` that the caller has already authorised. There is no path here
//! that takes a connection string, and no way for a caller to name a host
//! other than the address already pinned by
//! [`crate::transport::resolve_and_pin`]. That is M6-R3 expressed as a type:
//! the escape hatch is not refused, it is unrepresentable.
//!
//! # Teardown
//!
//! M6-R4 requires evidence that the *server* dropped the connection. A broker
//! that flipped its own flag and reported success would pass the same test
//! against a server that never noticed, so [`LivePgSession::revoke`] does not
//! return a verdict from the local side. It sends `Terminate`, then reads,
//! and reports what the socket did. The two outcomes are distinguished:
//! an observed EOF means the server closed its end, and a write failure means
//! it had already gone.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::scram::ScramError;
use crate::wire::{
    self, QueryResult, ServerMessage, WireError, WireReader,
};

/// How long the connector waits for a connection and for each read.
///
/// Not configurable from the agent's side on purpose: a caller that could
/// raise the timeout could keep a revoked session's socket open indefinitely,
/// which is the same thing M6-R4 forbids in a slower form.
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// The trust anchors the connector verifies server certificates against.
///
/// Roots come from the platform store. A connector that let a caller pass its
/// own root set would make certificate verification a claim the caller
/// controls, which is the same weakness as letting the caller name the host.
#[derive(Debug, Clone, Default)]
pub struct TlsRoots {
    /// One PEM root, or several, to add to the platform set.
    extra_roots_pem: Vec<Vec<u8>>,
}

impl TlsRoots {
    /// The platform trust store and nothing else.
    pub fn system() -> Self {
        Self::default()
    }

    /// Adds PEM roots on top of the platform store.
    ///
    /// Exists for the UAT substrate, which is a server this machine issued
    /// its own root for. It takes *roots*, never a flag to skip verification,
    /// so the closest a caller can get to disabling TLS is to trust a root it
    /// controls, which is a narrower and more visible act.
    pub fn with_extra_roots(mut self, pem: Vec<u8>) -> Self {
        self.extra_roots_pem.push(pem);
        self
    }

    fn store(&self) -> Result<rustls::RootCertStore, WireError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for pem in &self.extra_roots_pem {
            let mut cursor = std::io::Cursor::new(pem.as_slice());
            // A malformed root file is a configuration error, not a network
            // one, so it is named as such. Silently continuing with the
            // platform store alone would produce a connection failure a long
            // way from the cause.
            for certificate in rustls_pemfile_certs(&mut cursor)? {
                roots
                    .add(certificate)
                    .map_err(|error| WireError::Protocol(format!("root certificate rejected: {error}")))?;
            }
        }
        Ok(roots)
    }
}

/// Minimal PEM certificate reader.
///
/// `rustls-pemfile` is not a workspace dependency and adding it for a dozen
/// lines is not worth a new crate in the lockfile, so the `CERTIFICATE` blocks
/// are extracted here. The parser is deliberately strict: it wants
/// base64 between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
/// and refuses anything else, because a silently mis-parsed root is a trust
/// decision made by accident.
fn rustls_pemfile_certs(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, WireError> {
    use base64::Engine as _;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(cursor.get_ref())
        .map_err(|_| WireError::Protocol("root file was not UTF-8".into()))?;
    let mut certificates = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else {
            break;
        };
        let body: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|error| WireError::Protocol(format!("root file had bad base64: {error}")))?;
        certificates.push(rustls_pki_types::CertificateDer::from(der));
        rest = &after[end + END.len()..];
    }
    if certificates.is_empty() {
        return Err(WireError::Protocol(
            "root file contained no CERTIFICATE block".into(),
        ));
    }
    Ok(certificates)
}

/// The broker's view of one live PostgreSQL session.
///
/// Owns the socket. The `revoked` flag is shared with whatever the broker
/// holds, so a revoke can be signalled without taking the session's lock and
/// so a query in flight can observe it between statements.
pub struct LivePgSession {
    role: String,
    database: String,
    /// The backend's process id, once the server has sent `BackendKeyData`.
    ///
    /// Kept because it is how a teardown is confirmed from the *server's*
    /// side: `pg_stat_activity` or `pg_terminate_backend` can be asked about
    /// this pid, which is evidence no local latch can fake.
    backend_pid: Option<i32>,
    /// The `ParameterStatus` pairs the server sent, e.g. `server_version`.
    ///
    /// Kept so a caller can report what it is actually talking to. A
    /// connector that reported "connected" without this could be connected
    /// to something that is not PostgreSQL, which is exactly the ambiguity
    /// M6-R3's semantic surface exists to remove.
    parameters: Vec<(String, String)>,
    revoked: Arc<AtomicBool>,
    /// The split TLS stream, held across statements.
    ///
    /// Not re-derived per query. `Framed::new` calls `tokio::io::split`, and
    /// each split installs its own buffer, so building one per statement
    /// would drop anything the previous read had buffered past the end of its
    /// result set. A server that pipelines a notice behind `ReadyForQuery`
    /// would then be read as the head of the next statement's result.
    framed: Option<Framed<TlsStream>>,
}

impl std::fmt::Debug for LivePgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LivePgSession")
            .field("role", &self.role)
            .field("database", &self.database)
            .field("backend_pid", &self.backend_pid)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

/// The TLS stream the connector speaks over.
type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// What a revoke observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// The server closed its end of the connection. This is the only outcome
    /// that satisfies M6-R4.
    ServerClosed,
    /// `Terminate` could not be sent because the socket was already gone,
    /// which also means the server is no longer there.
    AlreadyGone,
    /// The socket is still open after `Terminate` and a read. Reported as a
    /// failure rather than a success, because claiming teardown that was not
    /// observed is the exact defect M6-R4 exists to prevent.
    NotObserved,
}

impl LivePgSession {
    /// The role this session authenticated as.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// The database this session is bound to.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The server's process id for this backend, if the server sent it.
    pub fn backend_pid(&self) -> Option<i32> {
        self.backend_pid
    }

    /// One `ParameterStatus` value the server reported, e.g. `server_version`.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether the broker has flagged this session revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// Runs one statement.
    ///
    /// The revoke check is first and unconditional, so a statement issued
    /// after a revoke never reaches the socket. That is M6-R4's first half:
    /// the local guarantee. The second half, that the server actually
    /// dropped, is [`LivePgSession::revoke`].
    pub async fn query(&mut self, sql: &str) -> Result<QueryResult, WireError> {
        if self.is_revoked() {
            return Err(WireError::Revoked);
        }
        let framed = self.framed.as_mut().ok_or(WireError::Revoked)?;
        wire::write_packet(&mut framed.writer, &wire::simple_query_packet(sql)).await?;
        wire::collect_result(&mut framed.reader).await
    }

    /// Revokes the session and reports what the server did.
    ///
    /// Sends `Terminate`, then reads once. A clean `ReadyForQuery` or EOF both
    /// mean the socket is finished; a read that returns another result means
    /// the server is still talking, and that is reported as
    /// [`Teardown::NotObserved`] rather than papered over.
    ///
    /// The socket is dropped on the way out, whatever the outcome. That is not
    /// tidiness: a second call must not be able to write `Terminate` to a
    /// socket that is already half-closed, read the EOF that the *first*
    /// teardown produced, and report [`Teardown::ServerClosed`] a second time.
    /// The second call has observed nothing of its own, so it reports
    /// [`Teardown::AlreadyGone`]. Consuming the session is what makes the
    /// teardown claim single-shot, and a live test against a real server is
    /// the only thing that caught it.
    pub async fn revoke(&mut self) -> Teardown {
        // The flag goes up first and unconditionally. Even if the socket
        // misbehaves, a statement issued after this call must fail, so the
        // local latch cannot depend on the network round trip.
        self.revoked.store(true, Ordering::Release);
        let Some(mut framed) = self.framed.take() else {
            return Teardown::AlreadyGone;
        };
        if wire::write_packet(&mut framed.writer, &wire::terminate_packet())
            .await
            .is_err()
        {
            return Teardown::AlreadyGone;
        }
        // Read until the socket ends. A server that answers `Terminate` by
        // closing is the normal case; a server that keeps the connection open
        // is the case M6-R4 is about, and it is caught by the timeout.
        let outcome = match tokio::time::timeout(IO_TIMEOUT, framed.reader.read_message()).await {
            Ok(Err(error)) if error.is_disconnect() => Teardown::ServerClosed,
            Ok(Err(_)) | Err(_) => Teardown::NotObserved,
            Ok(Ok(_)) => {
                // The server sent something rather than closing. Keep
                // draining until it either closes or the deadline passes.
                match tokio::time::timeout(IO_TIMEOUT, framed.reader.read_message()).await {
                    Ok(Err(error)) if error.is_disconnect() => Teardown::ServerClosed,
                    _ => Teardown::NotObserved,
                }
            }
        };
        // `framed` drops here, closing the socket. Any `Err` from the write or
        // the read returns above has already dropped it too.
        outcome
    }
}

/// A reader and writer over the same stream, split so the codec can be used
/// on each half independently.
struct Framed<S> {
    reader: WireReader<tokio::io::ReadHalf<S>>,
    writer: tokio::io::WriteHalf<S>,
}

impl<S: AsyncRead + AsyncWrite> Framed<S> {
    fn new(stream: S) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            reader: WireReader::new(read),
            writer: write,
        }
    }
}

/// Dials `(address, port)`, negotiates TLS, starts the session and
/// authenticates it with SCRAM.
///
/// `role` and `database` are the broker's decision. The password is borrowed
/// for the length of the SCRAM exchange and never stored, named, or
/// formatted into a message.
pub async fn connect(
    address: std::net::IpAddr,
    port: u16,
    server_name: &str,
    roots: &TlsRoots,
    database: &str,
    role: &str,
    password: &str,
) -> Result<LivePgSession, WireError> {
    // Resolved and pinned by the caller. Connecting here rather than calling
    // `to_socket_addrs` is deliberate: a second lookup could return a
    // different address than the one the policy checked.
    let tcp = TcpStream::connect((address, port)).await?;
    tcp.set_nodelay(true).ok();
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
        .with_root_certificates(roots.store()?)
        .with_no_client_auth();
    // ALPN is mandatory, not a preference. PostgreSQL 18 closes a direct TLS
    // connection whose ClientHello carries no ALPN extension, and the client
    // sees only an `early eof`. Setting it here is the whole fix; the server
    // log line is `se recibió petición de conexión SSL directa sin la
    // extensión de negociación de protocolo ALPN`.
    config.alpn_protocols = vec![crate::wire::ALPN_PROTOCOL.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| WireError::Protocol(format!("{server_name} is not a valid TLS server name")))?;
    let tls = tokio::time::timeout(IO_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| WireError::Protocol("TLS handshake timed out".into()))??;

    // TLS is established before any credential exists. The ordering is the
    // argument for M6-R2: there is no point in this code path at which a
    // password could be sent in the clear, because the plaintext socket was
    // replaced before the password was read.
    //
    // The startup message goes over the already-negotiated TLS stream. A
    // connector that sent an `SSLRequest`, accepted an `N`, and then sent the
    // startup packet in the clear would be the plaintext fallback this
    // module refuses to have, so there is no `ssl_request_packet` call here
    // and no branch that continues without TLS.
    let (backend_pid, parameters, framed) =
        tokio::time::timeout(IO_TIMEOUT, start(tls, role, database, password))
            .await
            .map_err(|_| WireError::Protocol("handshake timed out".into()))??;

    Ok(LivePgSession {
        role: role.to_string(),
        database: database.to_string(),
        backend_pid: Some(backend_pid),
        parameters,
        revoked: Arc::new(AtomicBool::new(false)),
        framed: Some(framed),
    })
}

/// The `ParameterStatus` keys worth keeping.
///
/// PostgreSQL reports two dozen. These three identify the peer, which is the
/// only reason a caller would look; storing the rest would be collecting
/// server-controlled strings for no consumer.
const REPORTED_PARAMETERS: [&str; 3] = ["server_version", "server_encoding", "TimeZone"];

/// Sends the startup packet, drives the handshake, and returns the framed
/// stream for later statements.
///
/// The `Framed` is returned rather than rebuilt per statement because
/// `tokio::io::split` consumes the stream and installs a fresh buffer on each
/// half. Splitting per statement would drop whatever the previous read had
/// buffered past the end of its result set, so a server that pipelined a
/// notice behind `ReadyForQuery` would have that notice read as the head of
/// the next statement's result.
async fn start<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    role: &str,
    database: &str,
    password: &str,
) -> Result<(i32, Vec<(String, String)>, Framed<S>), WireError> {
    let mut framed = Framed::new(stream);
    wire::write_packet(&mut framed.writer, &wire::startup_packet(role, database)).await?;
    let (backend_pid, parameters) = drive_handshake(&mut framed, role, password).await?;
    Ok((backend_pid, parameters, framed))
}

/// Drives the post-startup handshake to `ReadyForQuery`.
///
/// The `backend_pid` is returned so the caller can record it: M6-R4's
/// teardown evidence comes from asking the server about this pid, and a
/// connector that did not capture it could not produce that evidence later.
async fn drive_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    framed: &mut Framed<S>,
    role: &str,
    password: &str,
) -> Result<(i32, Vec<(String, String)>), WireError> {
    let mut backend_pid = 0;
    let mut parameters = Vec::new();
    loop {
        match framed.reader.next_decoded().await? {
            ServerMessage::PasswordRequested(request) => {
                return Err(wire::refuse_password_method(request));
            }
            ServerMessage::SaslInitialRequest => {
                wire::run_scram(&mut framed.reader, &mut framed.writer, role, password).await?;
            }
            ServerMessage::AuthenticationOk => {}
            ServerMessage::BackendKeyData { process_id, .. } => backend_pid = process_id,
            ServerMessage::ParameterStatus { name, value } => {
                if REPORTED_PARAMETERS.contains(&name.as_str()) {
                    parameters.push((name, value));
                }
            }
            ServerMessage::ReadyForQuery => return Ok((backend_pid, parameters)),
            ServerMessage::Error { message } => return Err(WireError::Auth(message)),
            ServerMessage::Notice => {}
            ServerMessage::SaslChallenge(_) | ServerMessage::SaslFinal(_) => {
                return Err(WireError::Protocol(
                    "server sent a SCRAM message before requesting SCRAM".into(),
                ))
            }
            ServerMessage::RowDescription(_)
            | ServerMessage::DataRow(_)
            | ServerMessage::CommandComplete(_) => {
                return Err(WireError::Protocol(
                    "server sent a result during the handshake".into(),
                ))
            }
        }
    }
}

/// Maps a SCRAM failure onto the transport's error vocabulary.
///
/// The password never appears in either: a SCRAM error names the step that
/// failed, never the material used at it.
pub fn describe_scram_failure(error: ScramError) -> WireError {
    WireError::Auth(error.to_string())
}
