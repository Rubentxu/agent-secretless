//! A real TLS origin used by the transport tests.
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
    /// One reply per request, in order. The last one repeats, so a test that
    /// makes more requests than it planned still terminates rather than
    /// hanging on an empty queue.
    Sequence(Vec<Reply>),
}

impl Reply {
    /// The reply for the `index`-th request of a sequence.
    fn at(&self, index: usize) -> Reply {
        match self {
            Reply::Sequence(replies) => replies
                .get(index)
                .unwrap_or_else(|| replies.last().expect("a non-empty sequence"))
                .clone(),
            single => single.clone(),
        }
    }
}

/// The certificate type a test client needs to trust a [`FakeOrigin`].
///
/// An alias rather than a re-export of the whole `reqwest` crate: a crate over
/// this one needs the one type to name a factory field, and letting it reach
/// `reqwest` directly would make the connector's client library a dependency of
/// every consumer just to fill in a struct.
pub type Certificate = reqwest::Certificate;

/// A running fake origin. Dropping it stops the accept loop.
pub struct FakeOrigin {
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

impl FakeOrigin {
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
}

impl Drop for FakeOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop with one throwaway connection.
        let _ = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
    }
}

/// Starts a TLS origin answering every request with `reply`.
pub fn start(reply: Reply) -> FakeOrigin {
    let certified_for = "api.github.com";
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
            for (served, stream) in listener.incoming().enumerate() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { return };
                connections.fetch_add(1, Ordering::SeqCst);
                let observed = Arc::clone(&observed);
                // Each request picks its own reply from the script. Cloning per
                // iteration rather than moving keeps `cert_der`/`key_der`
                // available to the next one, which a `move` closure would take
                // out of the loop's scope entirely.
                let reply = reply.at(served);
                let cert_der = cert_der.clone();
                let key_der = key_der.clone();
                std::thread::spawn(move || {
                    // Nagle would add latency to a request this short without
                    // buying anything, since each connection serves one request.
                    let _ = stream.set_nodelay(true);
                    let _ = serve(stream, cert_der, key_der, reply, observed);
                });
            }
        });
    }

    FakeOrigin {
        port,
        ca_pem,
        certified_for: certified_for.to_string(),
        observed,
        connections,
        stop,
    }
}

/// Serves exactly one request on an already-accepted TLS connection.
fn serve(
    stream: std::net::TcpStream,
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    reply: Reply,
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
    // certificate is issued for `api.github.com`, which is what makes the
    // client's own verification a real check rather than a rubber stamp.
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

    observed.lock().expect("poisoned").push(record);
    tls.write_all(&render(&reply)).map_err(|e| e.to_string())?;
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

/// Renders the wire response. Kept pure so a test can assert on it without a
/// socket, and so the content-length and the body can never drift apart.
fn render(reply: &Reply) -> Vec<u8> {
    let (status, extra, body) = match reply {
        Reply::Body(body) => ("200 OK".to_string(), String::new(), body.as_str()),
        Reply::Redirect(location) => (
            "302 Found".to_string(),
            format!("location: {location}\r\n"),
            "",
        ),
        Reply::Json(body) => (
            "200 OK".to_string(),
            "content-type: application/json\r\n".to_string(),
            body.as_str(),
        ),
        Reply::Status { status, body } => (status_line(*status), String::new(), body.as_str()),
        Reply::StatusWithoutLocation { status } => (status_line(*status), String::new(), ""),
        // `serve` resolves a sequence to a single reply before it gets here, so
        // a nested sequence would mean a scripting mistake rather than a shape
        // the wire can express. An empty answer fails loudly instead.
        Reply::Sequence(replies) => match replies.first() {
            Some(first) => return render(first),
            None => ("500 Internal Server Error".to_string(), String::new(), ""),
        },
    };
    format!(
        "HTTP/1.1 {status}\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
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
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    };
    format!("{status} {reason}")
}
