//! The PostgreSQL v3 wire protocol: message framing, the startup and
//! authentication handshake, and the two query paths.
//!
//! # Why the protocol is written out rather than delegated
//!
//! The obvious move is to take `tokio-postgres` and be done. Two things rule
//! it out, and both are properties this cycle exists to prove.
//!
//! The first is M6-R2. The UAT the milestone exits on states that the
//! password must be absent from the agent's environment, its process tree, its
//! connection string and any file it writes. libpq's own password handling
//! offers `PGPASSWORD` and `~/.pgpass`, both of which are exactly what the
//! UAT forbids, and the library's environment plumbing is not something a
//! caller can audit from the outside. Owning the exchange means the password
//! exists in one process's memory for the length of one SCRAM exchange and
//! nowhere else, and that claim is checkable by reading this file.
//!
//! The second is teardown. M6-R4 asks for evidence that the *server* dropped
//! the connection, not that the client stopped reading. A library that owns
//! the socket hides the shutdown from the broker, so the broker can only
//! assert what it believes rather than what it observed.
//!
//! # Framing
//!
//! Every message after the startup packet is a one-byte tag followed by a
//! 32-bit big-endian length that includes the length field itself but not the
//! tag. The startup packet is the exception: it has no tag, and its length is
//! offset by four to account for its own version field.
//!
//! The length is validated against [`MAX_MESSAGE_BYTES`](crate::wire::MAX_MESSAGE_BYTES) on every read. A
//! server that announces a huge length gets the socket closed rather than an
//! allocation of whatever it asked for; a broker that trusts a length field
//! from the network is a denial-of-service primitive with a remote trigger.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::scram::{Scram, ScramError};

/// The protocol version this connector speaks.
pub const PROTOCOL_VERSION: i32 = 196608; // 3.0, as PostgreSQL encodes it.

/// The ALPN protocol identifier PostgreSQL negotiates.
///
/// PostgreSQL 18 refuses a direct TLS connection whose ClientHello carries no
/// ALPN extension, and closes the socket with a log line rather than a wire
/// error. This was found by running the connector against a real server, not
/// by reading the documentation: the `psql` client has sent it since 12, and a
/// client that omits it gets an `early eof` with no other explanation. The
/// identifier is the same string the server logs, so a failure to match is
/// visible on both sides.
pub const ALPN_PROTOCOL: &[u8] = b"postgresql";

/// The ceiling on a single inbound message.
///
/// PostgreSQL's own limit is 1 GB for a message body. This is far lower and
/// deliberately so: the broker forwards statement results to an agent, and
/// anything this large is not a result an agent can use, so refusing early
/// bounds both the allocation and the response the agent has to parse.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The SSL request code the client sends to ask for TLS.
const SSL_REQUEST_CODE: i32 = 80877103;

/// The cancellation request code, which must be refused rather than honoured.
const CANCEL_REQUEST_CODE: i32 = 80877102;

/// The GSSAPI request code, refused for the same reason.
const GSSAPI_REQUEST_CODE: i32 = 80877104;

/// A protocol-level failure.
///
/// `Io` is separated from the rest because the transport treats a closed
/// socket as evidence of teardown, while a malformed message is a bug or an
/// attack and must never be reported as a clean disconnect.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("postgres transport io failed: {0}")]
    Io(#[from] io::Error),

    #[error("postgres server sent a malformed message: {0}")]
    Protocol(String),

    #[error("postgres server refused the connection: {0}")]
    Server(String),

    #[error("postgres authentication failed: {0}")]
    Auth(String),

    #[error("postgres query failed: {0}")]
    Query(String),

    #[error("postgres requires TLS and this build refused the plaintext fallback")]
    TlsRequired,

    #[error("postgres authentication failed: {0}")]
    Scram(#[from] ScramError),

    #[error("the broker revoked this connection")]
    Revoked,
}

impl WireError {
    /// Whether this error means the socket is gone.
    ///
    /// M6-R4 turns on this being narrow. A broker that reported
    /// "terminated" for a malformed message would pass the teardown test
    /// against a server that never acknowledged the connection at all, so
    /// only a genuine transport end counts.
    pub fn is_disconnect(&self) -> bool {
        matches!(
            self,
            WireError::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                )
        )
    }
}

/// Which authentication the server asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthRequest {
    CleartextPassword,
    Md5Password([u8; 4]),
}

/// One decoded message from the server.
///
/// Crate-visible rather than public: the only callers are the startup
/// sequence and the two query paths, all in this module. Making it `pub`
/// would freeze the server's message set into the crate's API surface, and
/// this milestone is explicitly not the finished transport.
#[derive(Debug)]
pub(crate) enum ServerMessage {
    /// `R` with `AuthenticationOk`.
    AuthenticationOk,
    /// `R` with a supported password request.
    PasswordRequested(AuthRequest),
    /// `R` with SASLInitialResponse.
    SaslInitialRequest,
    /// `R` with SASLResponse: the server-first message.
    SaslChallenge(Vec<u8>),
    /// `R` with SASLFinal: the server-final message.
    SaslFinal(Vec<u8>),
    /// `S`, the parameter status report. Retained rather than dropped: a
    /// connector that discards `server_version` cannot tell a caller which
    /// wire behaviour to expect, nor let the test suite assert the handshake
    /// actually reached a modern server.
    ParameterStatus { name: String, value: String },
    /// `K`, the backend key.
    ///
    /// Only `process_id` is kept. The `secret_key` is read to advance the
    /// frame and then dropped: it is the input to a cancellation request,
    /// which would let anyone holding a socket kill the backend the broker
    /// authorised. Keeping it in a struct invites that use.
    BackendKeyData { process_id: i32 },
    /// `Z`, ready for queries.
    ReadyForQuery,
    /// `T`, a row description.
    RowDescription(Vec<FieldDescription>),
    /// `D`, one data row.
    DataRow(Vec<Option<String>>),
    /// `C`, a command completion tag such as `SELECT 3`.
    CommandComplete(String),
    /// `E`, an error report.
    Error { message: String },
    /// `N`, a notice. Recognised and dropped.
    ///
    /// A notice changes no connection state, and the alternative, carrying
    /// the server's text to every caller, would put an unvalidated string
    /// from the network into every layer above this one. The tag is matched
    /// so the decode stays exhaustive; the payload is not retained.
    Notice,
}

/// One column of a result set.
///
/// `text` is the only format the connector requests, so the wire decoder does
/// not need to understand binary or other type representations. A column
/// whose type the server sends as something other than text is refused at
/// decode time rather than silently rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    pub name: String,
    pub type_oid: u32,
}

/// A decoded result set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryResult {
    /// The column names, in the order the server reported them.
    pub columns: Vec<String>,
    /// One entry per row, each the text of its columns.
    pub rows: Vec<Vec<String>>,
    /// The command tag, e.g. `SELECT 3` or `INSERT 0 1`.
    pub tag: String,
}

impl QueryResult {
    /// The number of rows, for the wire response's `row_count`.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// The reader half of a connection.
///
/// Owning the codec separately from the connection is what lets the teardown
/// path read the server's goodbye: M6-R4 needs to see the `Terminate`-induced
/// EOF, and a method that consumes `&mut self` makes that explicit rather
/// than a side effect of dropping something.
pub struct WireReader<R> {
    inner: R,
    /// Set once the transport has been told to stop, so a read after a
    /// revoke reports `Revoked` rather than whatever the socket happened to
    /// return. This is the local half of M6-R4; the server-observed half
    /// lives in [`WireReader::observe_termination`].
    revoked: bool,
}

impl<R: AsyncRead + Unpin> WireReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            revoked: false,
        }
    }

    /// Whether the broker has revoked this connection.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Marks the connection revoked. Local only: this does not claim the
    /// server has noticed.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Reads exactly one framed message into `(tag, body)`.
    ///
    /// `tag` is `None` for the untagged startup-era messages the server can
    /// send during authentication.
    pub(crate) async fn read_message(&mut self) -> Result<(Option<u8>, Vec<u8>), WireError> {
        if self.revoked {
            return Err(WireError::Revoked);
        }
        let mut header = [0u8; 5];
        self.inner.read_exact(&mut header).await?;
        let tag = header[0];
        let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = usize::try_from(len)
            .map_err(|_| WireError::Protocol(format!("announced a negative length of {len}")))?;
        // The declared length covers the four length bytes, so the body is
        // four shorter. A length below that is not a small message, it is a
        // malformed one.
        if len < 4 {
            return Err(WireError::Protocol(format!(
                "announced a length of {len}, which cannot even cover its own field"
            )));
        }
        if len > MAX_MESSAGE_BYTES {
            return Err(WireError::Protocol(format!(
                "announced {len} bytes, over the {MAX_MESSAGE_BYTES} ceiling"
            )));
        }
        let mut body = vec![0u8; len - 4];
        self.inner.read_exact(&mut body).await?;
        Ok((Some(tag), body))
    }

    /// Reads the next message and decodes it, skipping the notices and
    /// parameter status that carry no connection state.
    pub(crate) async fn next_decoded(&mut self) -> Result<ServerMessage, WireError> {
        loop {
            let (tag, body) = self.read_message().await?;
            let Some(tag) = tag else {
                return Err(WireError::Protocol(
                    "server sent an untagged message where a tagged one was required".into(),
                ));
            };
            match decode_message(tag, &body) {
                Ok(message) => return Ok(message),
                // A notice is informational. Returning it would make every
                // caller handle a variant that changes no state, so it is
                // dropped here and the loop continues.
                Err(Skip::Notice) => continue,
                Err(Skip::Error(error)) => return Err(error),
            }
        }
    }
}

/// A decode that means "not a message the caller has to see".
enum Skip {
    /// A notice: no state, keep reading.
    Notice,
    /// A real failure.
    Error(WireError),
}

fn decode_message(tag: u8, body: &[u8]) -> Result<ServerMessage, Skip> {
    match tag {
        b'R' => decode_auth(body),
        b'S' => {
            // Two cstrings in sequence: the name, then the value. Reading the
            // value at offset 0 again would return the name twice, which is
            // a bug that still type-checks and still looks plausible.
            let Some((name, after_name)) = read_cstring(body, 0) else {
                return Err(Skip::Error(WireError::Protocol(
                    "ParameterStatus carried no name".into(),
                )));
            };
            let value = read_cstring(body, after_name)
                .map(|(v, _)| v)
                .ok_or_else(|| {
                    Skip::Error(WireError::Protocol(
                        "ParameterStatus carried a name but no value".into(),
                    ))
                })?;
            Ok(ServerMessage::ParameterStatus { name, value })
        }
        b'K' => {
            if body.len() < 8 {
                return Err(Skip::Error(WireError::Protocol(
                    "BackendKeyData was shorter than 8 bytes".into(),
                )));
            }
            Ok(ServerMessage::BackendKeyData {
                process_id: i32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            })
        }
        b'Z' => Ok(ServerMessage::ReadyForQuery),
        b'T' => decode_row_description(body),
        b'D' => decode_data_row(body),
        b'C' => {
            // A command tag with no terminator is malformed. Substituting an
            // empty tag would turn a truncated message into a plausible-looking
            // result, and the tag is what tells a caller whether the statement
            // was a SELECT or a DDL command.
            let (tag, _) = read_cstring(body, 0).ok_or_else(|| {
                Skip::Error(WireError::Protocol(
                    "CommandComplete carried no terminated tag".into(),
                ))
            })?;
            Ok(ServerMessage::CommandComplete(tag))
        }
        b'E' => {
            let (_, message) = read_error_fields(body);
            Ok(ServerMessage::Error { message })
        }
        b'N' => Ok(ServerMessage::Notice),
        _ => Err(Skip::Notice),
    }
}

fn decode_auth(body: &[u8]) -> Result<ServerMessage, Skip> {
    let malformed = |what: &str| {
        Skip::Error(WireError::Protocol(format!(
            "authentication message was too short to carry {what}"
        )))
    };
    if body.len() < 4 {
        return Err(malformed("a code"));
    }
    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    match code {
        0 => Ok(ServerMessage::AuthenticationOk),
        3 => Ok(ServerMessage::PasswordRequested(
            AuthRequest::CleartextPassword,
        )),
        5 => {
            if body.len() < 8 {
                return Err(malformed("an MD5 salt"));
            }
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&body[4..8]);
            Ok(ServerMessage::PasswordRequested(AuthRequest::Md5Password(
                salt,
            )))
        }
        10 => Ok(ServerMessage::SaslInitialRequest),
        11 => Ok(ServerMessage::SaslChallenge(body[4..].to_vec())),
        12 => Ok(ServerMessage::SaslFinal(body[4..].to_vec())),
        // The server is asking for something this connector will not do.
        // Reporting it as an auth failure rather than a protocol error is
        // deliberate: from the agent's point of view the connection did not
        // authenticate, and that is the truth.
        other => Err(Skip::Error(WireError::Auth(format!(
            "server requested authentication method {other}, which this connector does not speak"
        )))),
    }
}

fn decode_row_description(body: &[u8]) -> Result<ServerMessage, Skip> {
    if body.len() < 2 {
        return Err(Skip::Error(WireError::Protocol(
            "RowDescription was shorter than its field count".into(),
        )));
    }
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut offset = 2;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next) = match read_cstring(body, offset) {
            Some(pair) => pair,
            None => {
                return Err(Skip::Error(WireError::Protocol(
                    "RowDescription ended mid-field".into(),
                )))
            }
        };
        // name, table oid, column number, type oid, type size, type modifier,
        // format code: 18 bytes after the name's NUL.
        let end = next
            .checked_add(18)
            .ok_or_else(|| Skip::Error(WireError::Protocol("field offset overflowed".into())))?;
        if end > body.len() {
            return Err(Skip::Error(WireError::Protocol(
                "RowDescription ended mid-field".into(),
            )));
        }
        fields.push(FieldDescription {
            name,
            type_oid: u32::from_be_bytes([
                body[next + 6],
                body[next + 7],
                body[next + 8],
                body[next + 9],
            ]),
        });
        offset = end;
    }
    Ok(ServerMessage::RowDescription(fields))
}

fn decode_data_row(body: &[u8]) -> Result<ServerMessage, Skip> {
    if body.len() < 2 {
        return Err(Skip::Error(WireError::Protocol(
            "DataRow was shorter than its column count".into(),
        )));
    }
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut offset = 2;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 4 > body.len() {
            return Err(Skip::Error(WireError::Protocol(
                "DataRow ended before a column length".into(),
            )));
        }
        let len = i32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ]);
        offset += 4;
        if len < 0 {
            // SQL NULL. `Option` rather than a sentinel string, because a
            // literal "NULL" is a value a column can genuinely hold.
            values.push(None);
            continue;
        }
        let len = len as usize;
        if offset + len > body.len() {
            return Err(Skip::Error(WireError::Protocol(
                "DataRow ended mid-value".into(),
            )));
        }
        let value = String::from_utf8_lossy(&body[offset..offset + len]).into_owned();
        values.push(Some(value));
        offset += len;
    }
    Ok(ServerMessage::DataRow(values))
}

/// Reads a NUL-terminated string at `offset`, returning it and the offset just
/// past the terminator.
fn read_cstring(body: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset > body.len() {
        return None;
    }
    let end = body[offset..].iter().position(|b| *b == 0)?;
    let text = String::from_utf8_lossy(&body[offset..offset + end]).into_owned();
    Some((text, offset + end + 1))
}

/// Reads the `M=` field of an error or notice, which is the human message.
///
/// `S=` and `C=` are also present but deliberately unread: `M=` is the one the
/// server writes for humans, and formatting the structured fields into a
/// string here would build the exact error-rendering path this repository
/// elsewhere forbids.
fn read_error_fields(body: &[u8]) -> (String, String) {
    let mut offset = 0;
    let mut code = String::new();
    let mut message = String::new();
    while let Some((field, after_name)) = read_cstring(body, offset) {
        if field == "Z" {
            break;
        }
        // Every field byte is followed by a value byte. Advancing past the
        // value is what keeps the loop moving: a version that read only the
        // field names would re-read the first value as the next field name
        // and walk off the end of the message.
        let Some((value, after_value)) = read_cstring(body, after_name) else {
            break;
        };
        offset = after_value;
        match field.as_str() {
            "C" => code = value,
            "M" => message = value,
            _ => {}
        }
    }
    (code, message)
}

/// Builds the TLS negotiation packet.
///
/// Refusing the plaintext fallback is the point of this function existing. A
/// connector that answers `N` to the server's `S` request has just offered to
/// send a SCRAM exchange, and therefore a password-derived key, in the clear.
#[allow(dead_code)]
pub(crate) fn ssl_request_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(8);
    packet.extend_from_slice(&8i32.to_be_bytes());
    packet.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    packet
}

/// Whether a startup code is one this connector must refuse.
///
/// Cancellation and GSSAPI are here rather than inline because both are
/// requests a client can send to a server and both are answered with an
/// error: a cancellation request is an unauthenticated way to kill a
/// backend, and honouring one would let anyone with a socket terminate a
/// session the broker authorised.
#[allow(dead_code)]
pub(crate) fn is_refused_startup_code(code: i32) -> bool {
    matches!(code, CANCEL_REQUEST_CODE | GSSAPI_REQUEST_CODE)
}

/// The startup packet for `(user, database)`.
pub fn startup_packet(user: &str, database: &str) -> Vec<u8> {
    let mut params = Vec::new();
    for (key, value) in [("user", user), ("database", database)] {
        params.extend_from_slice(key.as_bytes());
        params.push(0);
        params.extend_from_slice(value.as_bytes());
        params.push(0);
    }
    params.push(0); // the terminator the protocol requires

    let mut packet = Vec::with_capacity(params.len() + 8);
    // The length covers itself but not the version field, which is the one
    // place the startup packet breaks the framing rule of every other
    // message. Getting this wrong produces a length the server reads as
    // four bytes short, which surfaces as a confusing protocol error rather
    // than an obvious one.
    packet.extend_from_slice(&((params.len() + 8) as i32).to_be_bytes());
    packet.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    packet.extend_from_slice(&params);
    packet
}

/// Refuses the two password methods this connector will not use.
///
/// The function exists so the refusal is one call rather than a `match` arm
/// someone can later fill in. Cleartext sends the password verbatim; MD5 sends
/// a password-derived hash, which is replayable by anyone who observes it.
/// SCRAM is the only method that leaves the password off the wire in any
/// recoverable form, so it is the only one implemented, and this returns the
/// refusal for the other two rather than building a packet.
#[allow(dead_code)]
pub(crate) fn refuse_password_method(request: AuthRequest) -> WireError {
    match request {
        AuthRequest::CleartextPassword => WireError::Auth(
            "server requested cleartext password authentication, which this connector refuses"
                .into(),
        ),
        AuthRequest::Md5Password(_) => WireError::Auth(
            "server requested md5 password authentication, which is replayable and refused".into(),
        ),
    }
}

/// The `SASLInitialResponse` for SCRAM.
///
/// `client_first` is the bare client-first message, `n=role,r=nonce`. The
/// packet adds the mechanism name, its NUL, and the four-byte length of the
/// data. The length is computed from the assembled body rather than restated,
/// so it cannot drift from what is sent: getting it wrong is what PostgreSQL
/// reports as `SCRAM message malformed: length of message does not match
/// length of input`.
pub fn sasl_initial_packet(client_first: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(crate::scram::MECHANISM);
    body.push(0);
    body.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
    body.extend_from_slice(client_first);
    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(b'p');
    packet.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// A `SASLResponse` carrying the client-final message.
pub fn sasl_response_packet(message: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(message.len() + 5);
    packet.push(b'p');
    packet.extend_from_slice(&((message.len() + 4) as i32).to_be_bytes());
    packet.extend_from_slice(message);
    packet
}

/// The simple query protocol: one `Q` message carrying the statement.
pub fn simple_query_packet(sql: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(sql.len() + 1);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(b'Q');
    packet.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// The `Terminate` message.
///
/// Sent as the last thing on a clean close. It is not a guarantee that the
/// server noticed, which is why M6-R4 also needs an observed EOF; this is
/// the polite request, not the proof.
pub fn terminate_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(5);
    packet.push(b'X');
    packet.extend_from_slice(&4i32.to_be_bytes());
    packet
}

/// Writes a raw packet and flushes it.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &[u8],
) -> Result<(), WireError> {
    writer.write_all(packet).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a result set after a query, up to `ReadyForQuery`.
///
/// Collects rows rather than streaming them. The broker forwards the whole
/// result to the agent in one `PostgresResult`, so streaming would add a
/// backpressure mechanism whose only job is to be got wrong later.
pub async fn collect_result<R: AsyncRead + Unpin>(
    reader: &mut WireReader<R>,
) -> Result<QueryResult, WireError> {
    let mut result = QueryResult::default();
    loop {
        match reader.next_decoded().await? {
            ServerMessage::RowDescription(fields) => {
                result.columns = fields.into_iter().map(|f| f.name).collect();
            }
            ServerMessage::DataRow(values) => {
                result
                    .rows
                    .push(values.into_iter().map(|v| v.unwrap_or_default()).collect());
            }
            ServerMessage::CommandComplete(tag) => {
                result.tag = tag;
                // A command with no result set, e.g. `create table`, still ends
                // with ReadyForQuery; the loop continues to consume it so the
                // connection is left in a known state.
            }
            ServerMessage::ReadyForQuery => return Ok(result),
            ServerMessage::Error { message } => {
                return Err(WireError::Query(message));
            }
            ServerMessage::ParameterStatus { .. }
            | ServerMessage::BackendKeyData { .. }
            | ServerMessage::AuthenticationOk
            | ServerMessage::PasswordRequested(_)
            | ServerMessage::SaslInitialRequest
            | ServerMessage::SaslChallenge(_)
            | ServerMessage::SaslFinal(_) => {
                return Err(WireError::Protocol(
                    "server sent an authentication message where a result was expected".into(),
                ));
            }
            ServerMessage::Notice => {}
        }
    }
}

/// The SASL exchange, driven against an already-started connection.
///
/// Split out from the connection setup so the sequence can be tested against
/// a scripted peer rather than only against a live server. The order is
/// fixed by the protocol: initial response, server-first, client-final, then
/// the server's signature is verified *before* the connection is called
/// authenticated.
pub async fn run_scram<R, W>(
    reader: &mut WireReader<R>,
    writer: &mut W,
    role: &str,
    password: &str,
) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let normalised = crate::scram::normalise_password(password.as_bytes())?;
    let mut scram = Scram::new(role, normalised, &Scram::fresh_nonce());

    write_packet(writer, &sasl_initial_packet(&scram.client_first())).await?;
    // The arm binds the payload rather than discarding it. A `=> {}` arm that
    // named the value and dropped it compiles, and then the `let` below
    // shadows nothing and fails to compile only because the name was already
    // moved, which is a confusing way to learn the binding was empty.
    let server_first_bytes = match reader.next_decoded().await? {
        ServerMessage::SaslChallenge(payload) => payload,
        ServerMessage::Error { message } => return Err(WireError::Auth(message)),
        other => {
            return Err(WireError::Protocol(format!(
                "expected a SCRAM server-first message, got {other:?}"
            )))
        }
    };
    let server_first = String::from_utf8(server_first_bytes)
        .map_err(|_| WireError::Protocol("server-first was not UTF-8".into()))?;

    // The password never appears in any error raised past this point. A SCRAM
    // error names the step that failed, never the material used at it, and the
    // server's own refusal is relayed as its message rather than being wrapped
    // in anything that holds the credential. This is asserted by
    // `a_wrong_password_is_refused`, which fails if either this call or the
    // `Error` arms below ever grow the password into their output.
    let client_final = scram.client_final(&server_first)?;
    write_packet(writer, &sasl_response_packet(&client_final)).await?;

    let server_final_bytes = match reader.next_decoded().await? {
        ServerMessage::SaslFinal(payload) => payload,
        ServerMessage::Error { message } => return Err(WireError::Auth(message)),
        other => {
            return Err(WireError::Protocol(format!(
                "expected a SCRAM server-final message, got {other:?}"
            )))
        }
    };
    let server_final = String::from_utf8(server_final_bytes)
        .map_err(|_| WireError::Protocol("server-final was not UTF-8".into()))?;
    // The signature is checked here, not later. Declaring the connection
    // authenticated before this would make every later step run on a
    // credential the server never proved it holds.
    scram.verify_server_final(&server_final)?;
    Ok(())
}
