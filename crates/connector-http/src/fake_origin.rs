//! A real TLS origin used by the transport tests, and by whatever needs a
//! local HTTPS server that answers per request rather than per script.
//!
//! The point of this server is to make transport claims falsifiable. A mock
//! that returns a canned response proves nothing about SNI, certificate
//! verification, or which headers a redirect hop actually received, so this
//! speaks enough HTTP/1.1 to answer a real request from reqwest.
//!
//! Everything is loopback and self-signed, and the client under test is built
//! with a root that trusts exactly this certificate. That opt-in is deliberate:
//! it is the only way to test the TLS path without weakening production, where
//! `danger_accept_invalid_certs` stays false and the system trust store applies.
//!
//! There are two shapes, and they differ only in who decides the answer:
//!
//! - [`FakeOrigin`] replays a fixed script. It is what the transport tests want,
//!   because the claim there is "given this reply, does the client do the right
//!   thing", and a script states the premise exactly.
//! - [`TlsOrigin`] consults a handler per request. It is what a *server* needs
//!   to be: the answer depends on what was asked, so the fixture has to hold
//!   the state the answer is derived from.
//!
//! The TLS machinery — accept, handshake, read a request, write a response — is
//! shared and lives in [`TlsOrigin`]. Only the last step differs. The split is
//! worth the indirection precisely because that machinery is the part that is
//! hard to get right and easy to get subtly wrong: a body read that stops at a
//! record boundary, a status line with no code, a missing read deadline.

// Compiled only for the crate's own test build. The file is already gated at
// the module declaration, so the inner `#![cfg(test)]` would be redundant and
// would actually break the sibling `wire_tests` module, which is itself inside
// `cfg(test)` and therefore cannot see a doubly-gated item.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// What the server observed on one connection.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    /// The `Host` header, verbatim. This is the TLS/SNI-adjacent value a
    /// pinned client must preserve even though it connects to a bare IP.
    pub host_header: Option<String>,
    /// Every header the client sent, lowercased names, in arrival order.
    pub headers: Vec<(String, String)>,
    /// The request line, e.g. `GET /repos/a/b/issues/1 HTTP/1.1`.
    pub request_line: String,
    /// The request body, read to the length the client declared.
    pub body: String,
}

impl Observed {
    /// The value of a header, case-insensitively. Absent reads as `None`, not
    /// as an empty string: a missing credential and a blank one differ.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| key == &name)
            .map(|(_, value)| value.as_str())
    }

    /// The request method, from the request line.
    pub fn method(&self) -> &str {
        self.request_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
    }

    /// The request target, without the query string.
    pub fn path(&self) -> &str {
        let target = self
            .request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default();
        target.split('?').next().unwrap_or(target)
    }
}

/// One answer off the wire: a status, whatever headers it needs, and a body.
///
/// Deliberately not a string. A fixture that had to build the whole response
/// line itself would have each caller re-deriving `content-length`, and the
/// re-derived one would be wrong in exactly the case nobody is testing.
#[derive(Debug, Clone)]
pub struct OriginResponse {
    /// The status code. The reason phrase is filled in by the transport.
    pub status: u16,
    /// Headers to send, in order. A name repeated here is sent twice, which is
    /// what a caller asking for that wants.
    pub headers: Vec<(String, String)>,
    /// The body. Its length is what `content-length` says, always.
    pub body: String,
}

impl OriginResponse {
    /// A response with no content type declared.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// A response with a body a JSON parser may be pointed at.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, body).with_header("content-type", "application/json")
    }

    /// A response carrying a form body.
    ///
    /// The type is named rather than assumed because RFC 6749 §5.2 requires the
    /// token endpoint's error answer to be this one, and an error parsed as JSON
    /// because the server said `text/plain` is a bug that only shows up in
    /// production.
    pub fn form(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, body)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_header("cache-control", "no-store")
    }

    /// Adds a header. Repeated calls with the same name append rather than
    /// replace, so a caller can layer a default over a specific case.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// Decides what answers one request.
///
/// A closure rather than a trait so a fixture can capture its own state by
/// moving an `Arc` in, and so no implementor has to name a second type for a
/// job this small. `Send + Sync` because the accept loop answers connections on
/// threads it spawns.
pub type OriginHandler = Arc<dyn Fn(&Observed) -> OriginResponse + Send + Sync>;

/// The certificate type a test client needs to trust a [`TlsOrigin`].
///
/// An alias rather than a re-export of the whole `reqwest` crate: a crate over
/// this one needs the one type to name a factory field, and letting it reach
/// `reqwest` directly would make the connector's client library a dependency of
/// every consumer just to fill in a struct.
pub type Certificate = reqwest::Certificate;

/// A running TLS origin whose answers come from a handler. Dropping it stops
/// the accept loop.
pub struct TlsOrigin {
    pub port: u16,
    /// The certificate authority the test client must trust, in PEM form.
    pub ca_pem: String,
    /// The host name the certificate is issued for. Requests are addressed to
    /// this name so the client must present the right SNI.
    pub certified_for: String,
    observed: Arc<Mutex<Vec<Observed>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl TlsOrigin {
    /// Starts an origin certified for `certified_for`, answering through
    /// `handler`.
    ///
    /// The name is the certificate's subject, so a client that drops the
    /// hostname while connecting to the pinned address fails verification
    /// against this server exactly as it would against a real one. Choosing
    /// `api.github.com` here by accident would make a fixture lie about which
    /// audience it stands in for, hence the explicit parameter.
    pub fn start(certified_for: &str, handler: OriginHandler) -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![certified_for.to_string()]).expect("self-signed cert");

        let cert_der = cert.der().clone();
        let key_der = key_pair.serialize_der();
        let ca_pem = cert.pem();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        {
            let observed = Arc::clone(&observed);
            let connections = Arc::clone(&connections);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = stream else { return };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let observed = Arc::clone(&observed);
                    // Cloned per iteration rather than moved, so `cert_der` and
                    // `key_der` stay available to the next connection. A `move`
                    // closure would take them out of the loop's scope entirely.
                    let handler = Arc::clone(&handler);
                    let cert_der = cert_der.clone();
                    let key_der = key_der.clone();
                    std::thread::spawn(move || {
                        // Nagle would add latency to a request this short without
                        // buying anything, since each connection serves one request.
                        let _ = stream.set_nodelay(true);
                        let _ = serve(stream, cert_der, key_der, handler, observed);
                    });
                }
            });
        }

        TlsOrigin {
            port,
            ca_pem,
            certified_for: certified_for.to_string(),
            observed,
            connections,
            stop,
        }
    }

    /// Connections accepted so far. A pinning regression that opens a second
    /// connection is visible here.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Everything observed, oldest first.
    pub fn observed(&self) -> Vec<Observed> {
        self.observed.lock().expect("poisoned").clone()
    }

    /// The last request seen, or `None` if nothing arrived.
    pub fn last(&self) -> Option<Observed> {
        self.observed().pop()
    }

    /// The PEM certificate a test client must trust to talk to this origin.
    pub fn certificate(&self) -> reqwest::Certificate {
        reqwest::Certificate::from_pem(self.ca_pem.as_bytes()).expect("the origin's own PEM")
    }

    /// The HTTPS URL of `path` on the certified name.
    ///
    /// The name here is not resolvable — nothing in DNS points `certified_for`
    /// at loopback. A client has to be built with the mapping, which is what
    /// [`crate::transport::PinnedClient`] does, and that is the point: the
    /// fixture is only reachable by a client that got its address vetted.
    pub fn url(&self, path: &str) -> String {
        format!("https://{}:{}{}", self.certified_for, self.port, path)
    }
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop with one throwaway connection.
        let _ = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
    }
}

/// A [`TlsOrigin`] that replays a fixed script.
///
/// Derefs to the origin underneath, so every accessor and public field reads
/// the same whether a caller has the scripted shape or the general one.
pub struct FakeOrigin {
    inner: TlsOrigin,
}

impl std::ops::Deref for FakeOrigin {
    type Target = TlsOrigin;

    fn deref(&self) -> &TlsOrigin {
        &self.inner
    }
}

/// How the fake server should answer.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A plain 200 with this body.
    Body(String),
    /// A 302 whose `Location` is this value. A relative value is resolved
    /// against the request URL, exactly as a real origin would.
    Redirect(String),
    /// A 200 with a JSON content type. GitHub always sets one, and a client
    /// that only ever saw `text/plain` would never be tested against the real
    /// response shape.
    Json(String),
    /// An arbitrary status with a body.
    Status { status: u16, body: String },
    /// A redirection with no `Location` header at all. A real origin can do
    /// this, and a client that guesses a target from the status is broken.
    StatusWithoutLocation { status: u16 },
    /// A **non**-redirection status that carries a `Location` anyway.
    ///
    /// A real origin can do this, and it is the shape that separates a client
    /// that follows the header from one that follows the status. A test that
    /// only ever sends 302s cannot tell those apart.
    StatusWithLocation {
        status: u16,
        body: String,
        location: String,
    },
    /// One reply per request, in order. The last one repeats, so a test that
    /// makes more requests than it planned still terminates rather than
    /// hanging on an empty queue.
    Sequence(Vec<Reply>),

    /// A status with headers this caller chose, and no scripting.
    ///
    /// This exists because a `401` is not a status: a registry's `401` carries
    /// the `WWW-Authenticate` header that names the token endpoint, and a
    /// fixture that can only produce a status cannot produce the thing a
    /// registry client actually has to read. `Status` was enough while the only
    /// consumer parsed JSON bodies.
    WithHeaders {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
}

impl Reply {
    /// The response for this reply.
    fn to_response(&self) -> OriginResponse {
        match self {
            Reply::Body(body) => OriginResponse::new(200, body.clone()),
            Reply::Redirect(location) => {
                OriginResponse::new(302, String::new()).with_header("location", location)
            }
            Reply::Json(body) => OriginResponse::json(200, body.clone()),
            Reply::Status { status, body } => OriginResponse::new(*status, body.clone()),
            Reply::WithHeaders {
                status,
                headers,
                body,
            } => {
                let mut response = OriginResponse::new(*status, body.clone());
                for (name, value) in headers {
                    response = response.with_header(name, value);
                }
                response
            }
            Reply::StatusWithoutLocation { status } => OriginResponse::new(*status, String::new()),
            Reply::StatusWithLocation {
                status,
                body,
                location,
            } => OriginResponse::new(*status, body.clone()).with_header("location", location),
            // A sequence is resolved to one reply before it gets here, so a
            // nested sequence would mean a scripting mistake rather than a shape
            // the wire can express.
            Reply::Sequence(replies) => match replies.first() {
                Some(first) => first.to_response(),
                None => OriginResponse::new(500, String::new()),
            },
        }
    }
}

/// Starts a TLS origin answering every request with `reply`.
///
/// The scripted shape keeps the name `api.github.com` because every existing
/// caller of it is a GitHub transport test, and changing the SNI out from under
/// them would turn a shared helper into something every call site has to audit.
pub fn start(reply: Reply) -> FakeOrigin {
    FakeOrigin::sequence(reply)
}

impl FakeOrigin {
    /// Starts the scripted origin. Named separately from [`start`] so the
    /// scripted and handler-driven shapes sit side by side at the call site
    /// rather than one being spelled `start` and the other spelled out.
    pub fn sequence(reply: Reply) -> Self {
        let counter = Arc::new(AtomicUsize::new(0));
        let handler: OriginHandler = Arc::new(move |_observed| {
            let served = counter.fetch_add(1, Ordering::SeqCst);
            let chosen = match &reply {
                Reply::Sequence(replies) => replies
                    .get(served)
                    .or_else(|| replies.last())
                    .cloned()
                    .unwrap_or(Reply::Status {
                        status: 500,
                        body: String::new(),
                    }),
                single => single.clone(),
            };
            chosen.to_response()
        });
        FakeOrigin {
            inner: TlsOrigin::start("api.github.com", handler),
        }
    }
}

/// Serves exactly one request on an already-accepted TLS connection.
fn serve(
    stream: std::net::TcpStream,
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    handler: OriginHandler,
    observed: Arc<Mutex<Vec<Observed>>>,
) -> Result<(), String> {
    // A timeout is not optional here. This server answers one request and then
    // has nothing to say, so a read that waits for bytes which will never
    // arrive would hold the connection thread forever and hang the suite. A
    // test that trips the deadline gets a truncated body and a visible failure.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| format!("read timeout: {error}"))?;
    //
    // A server has no use for SNI verification: the name lives in the
    // certificate, and it is the *client* that has to check it. The fake
    // certificate is issued for the origin's `certified_for`, which is what
    // makes the client's own verification a real check rather than a rubber
    // stamp.
    let config = rustls_config(cert_der, key_der)?;
    // `ServerConnection::new` wants an `Arc<ServerConfig>` and no name: the
    // server side of rustls does not do SNI verification, so the name only
    // lives in the certificate.
    let connection = rustls::ServerConnection::new(Arc::new(config))
        .map_err(|error| format!("tls connection: {error}"))?;
    // `StreamOwned::new` takes the connection first, then the socket.
    let mut tls = rustls::StreamOwned::new(connection, stream);

    // The read borrow of `tls` ends before the response is written; holding
    // both at once would not compile, which is the borrow checker doing its job.
    let record = {
        let mut reader = BufReader::new(&mut tls);

        let mut request_line = String::new();
        if reader
            .read_line(&mut request_line)
            .map_err(|e| e.to_string())?
            == 0
        {
            return Err("client closed before sending a request line".to_string());
        }
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        // The body is read *before* the response is written, and it has to be
        // read to the exact declared length. A single `read` would stop at
        // whatever one TLS record happened to deliver, which makes the observed
        // body depend on packet boundaries rather than on what was sent.
        let body = read_body(&mut reader, &headers);

        Observed {
            host_header: headers
                .iter()
                .find(|(name, _)| name == "host")
                .map(|(_, value)| value.clone()),
            headers,
            request_line: request_line.trim_end().to_string(),
            body,
        }
    };

    // The record is filed before the handler is consulted, so a fixture that
    // fails while deciding still leaves evidence that the request arrived. A
    // test asserting on what the provider was asked has to keep working when the
    // provider is misbehaving, which is when the test most wants to read it.
    // The clone is the price of that ordering: the handler needs a borrow of the
    // record while the same lock is held by the push.
    observed.lock().expect("poisoned").push(record.clone());
    let response = handler(&record);
    tls.write_all(&render(&response))
        .map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// Reads exactly `content-length` bytes, and nothing more.
///
/// Bounded on purpose: a client that declared a huge length must not be able
/// to make the harness allocate without limit while a test waits on a read that
/// will never come. A short read is returned as what arrived, which makes a
/// mismatch visible in the test rather than a hang.
fn read_body<R: Read>(reader: &mut BufReader<R>, headers: &[(String, String)]) -> String {
    let declared = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(4 * 1024 * 1024);
    if declared == 0 {
        return String::new();
    }
    let mut buffer = vec![0u8; declared];
    // `read` in a loop rather than `read_exact`: a client that declares more
    // than it sends would make `read_exact` block until the read timeout, and
    // the harness has none. Stopping at the first short read is the only
    // option that cannot hang.
    let mut filled = 0usize;
    while filled < declared {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buffer.truncate(filled);
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Builds a server config trusting exactly the certificate it was given.
fn rustls_config(
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, String> {
    let certs = vec![cert_der];
    let key = PrivateKeyDer::try_from(key_der).map_err(|error| format!("private key: {error}"))?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("server config: {error}"))
}

/// Renders the wire response.
///
/// `content-length` is derived here and nowhere else, so it cannot drift from
/// the body, and the caller's headers are written after the status line.
fn render(response: &OriginResponse) -> Vec<u8> {
    let extra = response
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    format!(
        "HTTP/1.1 {}\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{}",
        status_line(response.status),
        response.body.len(),
        response.body
    )
    .into_bytes()
}

/// The status line for a status this harness can produce.
///
/// Both halves are required. A real server sends `"{code} {reason}"`, and
/// reqwest parses the code out of it; a line carrying only the reason phrase
/// makes every request fail with a transport error that says nothing about the
/// status, which is a miserable thing to debug.
fn status_line(status: u16) -> String {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    };
    format!("{status} {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handler that echoes the path back, so a test can prove the handler is
    /// what decided the answer rather than a script.
    fn echo_handler() -> OriginHandler {
        Arc::new(|observed: &Observed| {
            OriginResponse::json(200, format!(r#"{{"path":"{}"}}"#, observed.path()))
        })
    }

    fn client_for(origin: &TlsOrigin) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            // Redirects are off so a test that asks about a `302` sees the `302`
            // instead of the client chasing it around this same origin until the
            // hop budget runs out. Which is what the first draft of this helper
            // did, and the failure it produced said nothing about the server.
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .resolve(
                origin.certified_for.as_str(),
                format!("127.0.0.1:{}", origin.port)
                    .parse()
                    .expect("loopback addr"),
            )
            .build()
            .expect("client")
    }

    /// The general shape exists at all, and the answer is the handler's.
    #[test]
    fn a_handler_origin_answers_from_the_handler() {
        let origin = TlsOrigin::start("idp.test", echo_handler());
        let client = client_for(&origin);
        let response = client
            .get(origin.url("/token"))
            .send()
            .expect("TLS completes against the handler origin");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().expect("body"), r#"{"path":"/token"}"#);
    }

    /// The name is the point. A client that pinned an address but dropped the
    /// hostname would fail verification against this, and it is the same
    /// failure it would get from a real provider.
    #[test]
    fn the_origin_is_certified_for_the_name_it_was_given() {
        let origin = TlsOrigin::start("idp.test", echo_handler());
        assert_eq!(origin.certified_for, "idp.test");
        assert!(origin.ca_pem.contains("BEGIN CERTIFICATE"));

        // A client that does not know the name at all cannot build the URL, so
        // the check is that the URL names the certificate's subject.
        assert!(origin.url("/token").starts_with("https://idp.test:"));
    }

    /// The scripted shape must keep answering exactly as it did, or every
    /// transport test that depends on it has silently changed premise.
    #[test]
    fn the_scripted_shape_still_answers_its_script() {
        let origin = start(Reply::Sequence(vec![
            Reply::Json(r#"{"first":true}"#.to_string()),
            Reply::Status {
                status: 404,
                body: "gone".to_string(),
            },
        ]));
        let client = client_for(&origin);

        let first = client.get(origin.url("/a")).send().expect("first");
        assert_eq!(first.status().as_u16(), 200);
        assert_eq!(first.text().expect("body"), r#"{"first":true}"#);

        let second = client.get(origin.url("/b")).send().expect("second");
        assert_eq!(second.status().as_u16(), 404);
        assert_eq!(second.text().expect("body"), "gone");
    }

    /// The scripted origin keeps the name it always had. A fixture that started
    /// answering under a different SNI would make every existing call site
    /// depend on this file staying as it is.
    #[test]
    fn the_scripted_shape_keeps_the_github_name() {
        let origin = start(Reply::Body("{}".to_string()));
        assert_eq!(origin.certified_for, "api.github.com");
    }

    /// A `302` still carries a `Location`, and a status with none still does
    /// not invent one.
    #[test]
    fn redirects_keep_their_location_and_bare_statuses_keep_none() {
        let with = start(Reply::Redirect("/elsewhere".to_string()));
        let response = client_for(&with)
            .get(with.url("/a"))
            .send()
            .expect("redirect");
        assert_eq!(response.status().as_u16(), 302);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/elsewhere")
        );

        let without = start(Reply::StatusWithoutLocation { status: 302 });
        let response = client_for(&without)
            .get(without.url("/a"))
            .send()
            .expect("bare redirect");
        assert_eq!(response.status().as_u16(), 302);
        assert!(response.headers().get(reqwest::header::LOCATION).is_none());
    }

    /// A form answer has to declare itself as a form. RFC 6749 §5.2 makes the
    /// error body a form, and a parser that trusted the wrong content type
    /// would report a parse failure instead of the provider's own error code.
    #[test]
    fn a_form_response_declares_the_form_type() {
        let origin = TlsOrigin::start(
            "idp.test",
            Arc::new(|_| OriginResponse::form(400, "error=invalid_client&error_description=no")),
        );
        let response = client_for(&origin)
            .post(origin.url("/token"))
            .send()
            .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 400);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-www-form-urlencoded")
        );
    }

    /// A request body has to arrive whole. A body read that stopped at a record
    /// boundary would truncate long form posts and the fixture would answer a
    /// half-parsed request, which is the worst possible place to be wrong.
    #[test]
    fn a_long_request_body_arrives_whole() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let origin = TlsOrigin::start(
            "idp.test",
            Arc::new(move |observed: &Observed| {
                sink.lock().expect("poisoned").push(observed.body.clone());
                OriginResponse::json(200, "{}")
            }),
        );
        let payload = "a".repeat(64 * 1024);
        let response = client_for(&origin)
            .post(origin.url("/token"))
            .body(payload.clone())
            .send()
            .expect("TLS completes");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            seen.lock().expect("poisoned").first().map(String::as_str),
            Some(payload.as_str()),
            "a 64 KiB body must arrive in one piece"
        );
    }

    /// Every request is recorded, including the one the handler then answered
    /// badly. A fixture that lost evidence precisely when it misbehaved would be
    /// evidence-shaped and not evidence.
    #[test]
    fn a_request_is_recorded_even_when_the_handler_fails() {
        let origin = TlsOrigin::start(
            "idp.test",
            Arc::new(|_| -> OriginResponse { panic!("the handler has no answer for this") }),
        );
        // The panicking handler takes the connection thread down with it. The
        // record is filed before the response is written precisely so the
        // request that caused it survives; the client then sees a closed
        // connection, which is the honest answer to a server that died.
        let _ = client_for(&origin).get(origin.url("/boom")).send();
        assert_eq!(
            origin.observed().len(),
            1,
            "the request that panicked is kept"
        );
    }
}
