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

use std::io::{BufRead, BufReader, Write};
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
}

/// How the fake server should answer.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A plain 200 with this body.
    Body(String),
    /// A 302 whose `Location` is this value. A relative value is resolved
    /// against the request URL, exactly as a real origin would.
    Redirect(String),
}

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
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { return };
                connections.fetch_add(1, Ordering::SeqCst);
                let observed = Arc::clone(&observed);
                let reply = reply.clone();
                // Cloned per connection, not moved: the `move` closure would
                // otherwise take them out of the loop's scope and the second
                // iteration would have nothing left to clone.
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
    // A server has no use for SNI verification: the name lives in the
    // certificate, and it is the *client* that has to check it. The fake
    // certificate is issued for `api.github.com`, which is what makes the
    // client's own verification a real check rather than a rubber stamp.
    let config = rustls_config(cert_der, key_der)?;
    // `ServerConnection::new` wants an `Arc<ServerConfig>` and no name: the
    // server side of rustls does not do SNI verification, so the name only
    // lives in the certificate. Getting this backwards produces two errors at
    // once, which is at least unambiguous.
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

        Observed {
            host_header: headers
                .iter()
                .find(|(name, _)| name == "host")
                .map(|(_, value)| value.clone()),
            headers,
            request_line: request_line.trim_end().to_string(),
        }
    };

    observed.lock().expect("poisoned").push(record);
    tls.write_all(&render(&reply)).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    Ok(())
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
        Reply::Body(body) => ("200 OK", String::new(), body.as_str()),
        Reply::Redirect(location) => ("302 Found", format!("location: {location}\r\n"), ""),
    };
    format!(
        "HTTP/1.1 {status}\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
