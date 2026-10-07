//! C2.7-D — the vertical. This is the test that says CONNECT is in the product.
//!
//! Everything here is a real process. A real `asv-brokerd` binary, started with
//! a real vault, a real route file and a real policy file. A real `asv run`,
//! which opens a real session and starts a real shim. A real `curl`, which has
//! never heard of Agent Secretless and is told nothing except a proxy URL. A
//! real origin process on a real socket.
//!
//! ## Why this file and not fifteen unit tests
//!
//! The previous blocks each proved a piece, and every one of those proofs was
//! honest. What none of them could see is the *hop between processes*. A test
//! that constructs a listener in-process is running inside a runtime, so it
//! never notices that the binary did not enter one — and for the whole history
//! of this path, `asv-brokerd --connect-listen` panicked at startup and the
//! suite reported a surface that could not come up. That defect is in
//! `crates/broker/tests/connect_address_publication.rs` now, and it was found
//! by a test written for a different question.
//!
//! The properties are asserted together rather than one at a time, because the
//! interesting failures are combinations. A proxy that substitutes the real
//! credential but leaks it into the child's environment is secretless in the
//! way that matters least and leaky in the way that matters most, and a
//! per-property test suite would report both halves as passing.
//!
//! ## What each claim is checked against
//!
//! | claim | checked by |
//! |---|---|
//! | the origin received the REAL credential | the origin's own captured bytes |
//! | the agent never received it | the child's captured environment |
//! | curl never received it | the child's stdout and stderr |
//! | argv carries no secret | the child's reconstructed `argv` |
//! | env carries no secret | the child's captured environment, line by line |
//! | stdout/stderr carry no secret | the captured output |
//! | the shim is session-local and not bypassable | the `HTTPS_PROXY` the child was handed, and the absence of the `NO_PROXY` it was started with |
//! | the child was given *something* to present | the `ASV_SURROGATE_*` variable, and that its value is a surrogate and not the secret |
//! | a surrogate is bound to its session | session A's token presented inside a **live** session B, refused, with the origin as the independent witness |
//! | a fresh session still works | the same session B using its own token, `200` |
//! | a closed session's token is dead | the separate revoked-session test, plus the broker's own revocation path |
//! | a wrong destination fails | a CONNECT to a host with no route |
//! | a revoked session fails | a CONNECT after the session ends |
//! | the audit chain verifies | the durable log, through the broker's own verifier, plus a tampered copy that must be refused |
//! | the substitution and the refusal are both recorded | the parsed audit records, not a substring over the file |
//!
//! Three of these rows were written as claims the first version of the file did
//! not check, and the third is the one worth reading twice. The replay row
//! opened a second session and never carried a token across it. The audit row
//! called a flag that does not exist and wrapped the result in a conditional.
//! The session-binding row was then rewritten and *still* measured something
//! else: it took the token from a session that had already ended, and
//! `SessionEnded` deletes a session's surrogates, so the token was refused for
//! being unknown and the session comparison was never reached. It stayed green
//! when the falsification campaign deleted that comparison outright. Only with
//! both sessions open at once is the binding reachable at all.
//!
//! Every row above is checked by deleting its control and requiring the named
//! assertion to go red: `tests/connect_vertical_falsification.py`, 5 of 5.
//!
//! ## The one thing this test cannot claim
//!
//! `curl --insecure`. The session CA is minted per broker run and the test has
//! no channel to pin it, so the client's trust decision is waived here. That is
//! sound for what is being tested — the CONNECT path and the secret's
//! containment — and it is *not* evidence that certificate trust is solved for
//! an operator. That is a different claim and it is not made here.
//!
//! Nor does this file demonstrate that a *proof* is single-use end to end. The
//! shim mints one proof per connection, so an ordinary client is never in a
//! position to replay one; that property is measured where it can be, in the
//! broker's verifier and in the issuer's counter (`crates/ssh-agent/src/
//! client.rs`). Claiming it here would be claiming a hop this test does not
//! cross.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asv_broker::tls_bridge::{issue_leaf, SessionCa};
use asv_tls_acceptor::LeafMaterial;
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The real credential. Its presence in the origin's bytes is the whole point;
/// its absence everywhere else is the whole point.
///
/// Deliberately shaped like a token so a substring search cannot be satisfied by
/// a word that happens to appear in a stack trace.
const REAL: &str = "gho_ASVcanaryE2E4d7f1a9b3c5e8f0a2b4d6c8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f";

/// A two-label name that resolves to loopback.
///
/// The route loader refuses a bare `localhost` (one label is not routable) and
/// refuses an IP literal (no name to pin), so a loopback fixture needs a name
/// that is genuinely a name. This one is on every `/etc/hosts` and is two
/// labels, so it passes canonicalization and resolves locally — which is what
/// lets the *real* broker resolve it, rather than a resolver the test injected.
const FIXTURE_HOST: &str = "localhost.localdomain";

/// The credential's label, which is what the environment variable is named
/// after. The broker reports it back from the vault's own metadata, so the
/// variable name is the operator's spelling rather than something invented here.
const CREDENTIAL_LABEL: &str = "e2e-token";

// ---------------------------------------------------------------------------
// Binaries
// ---------------------------------------------------------------------------

/// Locates a workspace binary through the one locator, which also refuses one
/// older than the sources of the package that produces it.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}
struct Broker(Child);

impl Broker {
    /// The pid, for a signal the test sends by hand.
    ///
    /// `Child::kill` is SIGKILL, which no handler can catch — so a test that
    /// used it would be measuring the kernel's teardown no matter what the
    /// broker installed, which is the opposite of what it is here to check.
    fn pid(&self) -> i32 {
        self.0.id() as i32
    }

    /// The exit status, if the broker has left. `None` while it has not.
    ///
    /// `try_wait` rather than `wait`, so the caller can bound the wait and
    /// report a broker that never left as a failure instead of hanging.
    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().expect("poll the broker")
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An `asv run` held open by the test until it is released.
///
/// The type exists for its `Drop`. The cross-session measurement needs the
/// first session to still be *alive* when the second one presents its token,
/// which means there is a window in the test where an assertion can fire with
/// a session open — and an `asv run` left running holds a shim, an agent
/// socket and a session the broker still has to reap. A failing test that also
/// leaks a process is a slower failing test, and the next test pays for it.
struct Session {
    child: Option<Child>,
    release: PathBuf,
}

impl Session {
    /// Let the child finish, and take its output.
    fn finish(mut self) -> std::process::Output {
        let _ = std::fs::write(&self.release, b"go");
        let child = self.child.take().expect("the session was already finished");
        child
            .wait_with_output()
            .expect("collect the session's output")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Release first, so a child that is polling the file gets to exit on
        // its own terms; kill it either way, because a test that failed is not
        // a reason to leave a process behind.
        let _ = std::fs::write(&self.release, b"go");
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Wait for a path to appear, bounded.
///
/// Every wait in this file is bounded. A test that hangs is worse than a test
/// that fails: the first one costs a person their afternoon, the second one
/// costs them a minute.
fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// A plain-TCP origin: the broker terminates TLS, so what arrives here is
/// readable bytes. That is deliberate — a fixture the test cannot read could
/// not assert that the real credential arrived.
struct Origin {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    /// Connections this origin is still holding open.
    ///
    /// The point of the fixture is the question "is that tunnel *still
    /// there*", and a request counter cannot answer it: a tunnel that is
    /// established and idle looks exactly like one that never existed.
    open: Arc<Mutex<usize>>,
    /// Completed TLS handshakes.
    ///
    /// **Always zero on a plain origin**, because a plain origin has no
    /// handshake to complete. It is a field rather than a separate struct so
    /// the fixture does not care which origin it got, and reading it on a plain
    /// origin would say "no handshake" about a connection that never wanted
    /// one — so only the TLS assertions below consult it.
    handshook: Arc<Mutex<usize>>,
}

/// What an origin does once a request arrives.
///
/// An enum rather than a growing set of booleans on `spawn`, because the three
/// shapes below are genuinely different fixtures and a caller naming one reads
/// better than a caller decoding three booleans into one.
#[derive(Debug, Clone, Copy)]
enum OriginMode {
    /// Answer `per_connection` requests, then close unless `holding`.
    Serve {
        per_connection: usize,
        holding: bool,
    },
    /// Answer one request with a head that promises **more than it sends**, then
    /// hold the connection open forever.
    ///
    /// **This is the only shape in which the relay — rather than the origin —
    /// is the thing holding the tunnel open.** Every other fixture ends with
    /// the relay already finished: the origin may still be holding its socket,
    /// but the broker has returned from `relay_substituted` and the tunnel is
    /// over as far as the product is concerned. A cancellation can only be
    /// observed on a relay that is still pumping, so this one exists to put it
    /// there: the client is left mid-response, blocked for bytes that never
    /// come, and the broker is blocked copying a direction that never ends.
    Stall,
}

impl Origin {
    /// An origin that answers `per_connection` requests on one connection
    /// before closing it.
    ///
    /// One is the shape the vertical uses: a CONNECT tunnel the client opens
    /// per request is what `curl` produces by default. More than one is the
    /// shape the *protocol* allows, and it is a different question — see
    /// `a_tunnel_serves_one_request_and_the_protocol_allows_more`.
    fn start_serving(per_connection: usize) -> Self {
        Self::spawn(
            OriginMode::Serve {
                per_connection,
                holding: false,
            },
            Some,
        )
    }

    /// An origin that answers one request and then *keeps the connection open*.
    ///
    /// This is what an established, idle tunnel looks like from the
    /// destination's side, and it is the only shape in which "did the tunnel
    /// end?" is a question about time rather than about a count.
    ///
    /// Two details make the answer trustworthy. The response omits
    /// `Connection: close`, so the client is not told to go; and the read that
    /// follows has **no deadline at all**, so the only thing that can end this
    /// connection is the other end going away. A holding origin with a read
    /// timeout would answer "is it still open?" with a yes for a while and a
    /// no for a reason that has nothing to do with the tunnel — which is how a
    /// lifecycle test ends up asserting a timer.
    fn start_holding() -> Self {
        Self::spawn(
            OriginMode::Serve {
                per_connection: 1,
                holding: true,
            },
            Some,
        )
    }

    /// An origin that speaks TLS with a certificate the operator minted.
    ///
    /// **The origin is TLS because the question is about trust.** A plain one
    /// would refuse a broker with no anchors and would also refuse one *with*
    /// the wrong anchors, and a test that cannot tell those apart is measuring
    /// "the handshake failed" rather than "the anchors were not there".
    ///
    /// `None` from the wrapper means the handshake did not complete, and the
    /// connection carries nothing — which is exactly the state the refusing
    /// broker leaves this origin in, and the reason the counter is separate
    /// from `open`: a connection that was dialled and refused is not a tunnel.
    fn start_tls_serving(ca: &SessionCa) -> Self {
        let leaf = issue_leaf(ca, FIXTURE_HOST, Instant::now()).expect("issue the origin's leaf");
        // **The chain, not just the leaf.** A session CA is root,
        // intermediate, leaf, and a store holding only the root can only build
        // a path if the peer presents the intermediate. Passing the end-entity
        // alone fails with `UnknownIssuer`, which reads as "your anchors are
        // wrong" and is not.
        let material = LeafMaterial::new(
            ca.root_der.clone(),
            vec![leaf.leaf_der.clone(), ca.intermediate_der.clone()],
            leaf.leaf_key.serialize_der(),
        )
        .expect("leaf material");
        let config = Arc::new(material.server_config().expect("server config"));

        Self::spawn(
            OriginMode::Serve {
                per_connection: 1,
                holding: false,
            },
            move |stream| {
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).ok()?;
                let mut tls = rustls::StreamOwned::new(connection, stream);
                if tls.conn.complete_io(&mut tls.sock).is_err() {
                    return None;
                }
                Some(tls)
            },
        )
    }

    /// An origin that leaves its client mid-response and never finishes.
    ///
    /// See [`OriginMode::Stall`]: the point is not the stall, it is that the
    /// relay is still pumping when a signal arrives.
    fn start_stalling() -> Self {
        Self::spawn(OriginMode::Stall, Some)
    }

    /// Completed TLS handshakes. Meaningful only on a TLS origin.
    fn completed_handshakes(&self) -> usize {
        *self.handshook.lock().expect("handshake counter")
    }

    fn spawn<S, W>(mode: OriginMode, wrap: W) -> Self
    where
        S: OriginStream + Send + 'static,
        W: Fn(TcpStream) -> Option<S> + Send + Sync + 'static,
    {
        // `[::]` is dual-stack on Linux, so one port answers on both `::1` and
        // `127.0.0.1`. The broker takes the first address the resolver returns,
        // and which one that is has changed between hosts; a single-family bind
        // would make this test a bet on the resolver's mood.
        let listener = TcpListener::bind("[::]:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let port = addr.port();
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);
        let open: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&open);
        let handshook: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let shakes = Arc::clone(&handshook);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                // The request-phase deadline, applied before any wrapper hides
                // the socket. A connection that is dialled and never speaks
                // must not pin a thread for the life of the run, and a broker
                // that dialled and then refused is exactly that connection.
                OriginStream::set_origin_timeout(&stream, Some(Duration::from_secs(20)));
                let Some(mut wrapped) = wrap(stream) else {
                    continue;
                };
                *shakes.lock().expect("handshake counter") += 1;
                let sink = Arc::clone(&sink);
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    *counter.lock().expect("open counter") += 1;
                    match mode {
                        OriginMode::Serve {
                            per_connection,
                            holding,
                        } => serve_connection(&mut wrapped, &sink, per_connection, holding),
                        OriginMode::Stall => stall_connection(&mut wrapped, &sink),
                    }
                    // The decrement is on the way out of every path, and there
                    // is no `return` in `serve_connection` to skip it. A counter
                    // that can be skipped is one the lifecycle test reads as
                    // "the tunnel closed" when the connection thread simply
                    // left early.
                    *counter.lock().expect("open counter") -= 1;
                });
            }
        });

        Self {
            port,
            requests,
            open,
            handshook,
        }
    }

    /// Everything the origin was sent, joined, for substring assertions.
    fn saw(&self) -> String {
        self.requests.lock().expect("origin sink").join("\n")
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("origin sink").len()
    }

    /// How many connections are still open.
    fn open_connections(&self) -> usize {
        *self.open.lock().expect("open counter")
    }

    /// Waits for the open count to *become* `n`, bounded.
    ///
    /// Polling rather than reading once, for the reason `wait_for_requests`
    /// gives: the fixture runs on its own threads, and a single read is a race
    /// that fails the test for being early instead of for being wrong.
    fn wait_for_open(&self, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.open_connections() == n {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Connections that carried a request at all.
    ///
    /// Not the same as `request_count`, and the difference is a property of the
    /// bridge rather than of this fixture: `serve_connect` dials the
    /// destination *before* it can read the client's head, because the head is
    /// what carries the surrogate and the head cannot arrive until the
    /// client-side TLS handshake is done. So a tunnel whose substitution is
    /// refused still leaves a connection open at the origin — one that carries
    /// nothing and is closed again.
    ///
    /// It is written down here rather than papered over, because the tempting
    /// assertion — "the origin served exactly one more request" — is counting
    /// the wrong thing, and would have gone green on a broker that opened a
    /// connection per tunnel and served every one of them.
    fn requests_with_bytes(&self) -> usize {
        self.requests
            .lock()
            .expect("origin sink")
            .iter()
            .filter(|r| !r.is_empty())
            .count()
    }

    /// How many of the captured requests carried the real credential.
    ///
    /// The witness that does not depend on how the bridge orders its dial: the
    /// secret is either in what the destination received or it is not.
    fn real_credential_requests(&self) -> usize {
        self.requests
            .lock()
            .expect("origin sink")
            .iter()
            .filter(|r| r.contains(REAL))
            .count()
    }

    /// Waits for at least `n` requests, bounded.
    ///
    /// The origin runs on its own threads, so reading straight after the client
    /// exits is a race and an early read would fail the test for being early
    /// rather than for being wrong.
    fn wait_for_requests(&self, n: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.request_count() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

/// Serves one connection by promising more response than it sends, then holds
/// it open forever.
///
/// The promise is the whole mechanism. A head with `Content-Length: 64` and two
/// bytes behind it leaves the client waiting for 62 that never arrive, and
/// leaves the broker copying a response direction that never ends — which is
/// the only state in which a cancellation has something to cancel. A fixture
/// that sent a well-formed short response instead would let the relay finish,
/// and a signal sent afterwards would be measuring an idle broker.
///
/// The connection is never closed by this thread. It ends when the other end
/// does, which for a cancellation is the point at which the test is asserting
/// something.
fn stall_connection<S: OriginStream>(stream: &mut S, sink: &Arc<Mutex<Vec<String>>>) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 2048];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
    if raw.is_empty() {
        return;
    }
    sink.lock()
        .expect("origin sink")
        .push(String::from_utf8_lossy(&raw).into_owned());
    if stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nok")
        .is_err()
    {
        return;
    }
    let _ = stream.flush();
    // No deadline, same as the holding origin: from here the connection ends
    // when the tunnel ends, and a read timeout would end the measurement with a
    // timer instead of with the thing under measurement.
    stream.set_origin_timeout(None);
    let mut buf = [0u8; 256];
    while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
}

/// Serves one connection, and returns when that connection is over.
///
/// A free function rather than a method because it takes the mutable stream,
/// and a `&mut self` here would borrow the fixture for the whole life of a
/// connection that is supposed to outlive every line the test writes next.
///
/// `served_any` decides whether the hold is entered. A connection that never
/// carried a request is the bridge's dial-before-the-head behaviour, not a
/// tunnel; holding it open forever would pin a thread and inflate the open
/// count with something no session authorised.
/// What a connection has to be able to do, so one server body serves both a
/// plain socket and a TLS one.
///
/// `Read + Write` is the whole of the HTTP an origin here speaks. The timeout
/// is a method rather than something the body sets for itself because
/// `StreamOwned` does not forward it: the deadline lives on the socket
/// underneath it, and getting that wrong turns a bounded fixture into one that
/// pins a thread for the life of the run.
trait OriginStream: Read + Write {
    fn set_origin_timeout(&self, timeout: Option<Duration>);
}

impl OriginStream for TcpStream {
    fn set_origin_timeout(&self, timeout: Option<Duration>) {
        let _ = self.set_read_timeout(timeout);
    }
}

impl OriginStream for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_origin_timeout(&self, timeout: Option<Duration>) {
        OriginStream::set_origin_timeout(&self.sock, timeout);
    }
}

fn serve_connection<S: OriginStream>(
    stream: &mut S,
    sink: &Arc<Mutex<Vec<String>>>,
    per_connection: usize,
    holding: bool,
) {
    // This deadline covers the request phase only, so a client that connects
    // and says nothing cannot pin a thread for the life of the suite. It is
    // applied by the accepting loop, before a TLS wrapper hides the socket.
    let mut served_any = false;
    for served in 0..per_connection {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 2048];
        // Read until the headers are complete, then answer. A `break` here ends
        // the connection rather than the loop, so a client that hangs up
        // mid-sequence is not answered with a fabricated request.
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
        if raw.is_empty() {
            break;
        }
        served_any = true;
        sink.lock()
            .expect("origin sink")
            .push(String::from_utf8_lossy(&raw).into_owned());
        // `close` on the last request is what tells `curl` it may stop reusing
        // the connection. A holding origin never sends it: the point is that
        // the connection outlives the response, and a client told to close
        // would close it and take the tunnel with it.
        let last = served + 1 == per_connection;
        let response: &[u8] = if last && !holding {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        };
        if stream.write_all(response).is_err() {
            break;
        }
        let _ = stream.flush();
    }
    if holding && served_any {
        // No deadline. From here the connection ends when the tunnel ends and
        // for no other reason, which is what lets `open_connections` answer
        // "is the tunnel still there" instead of "has the timeout fired".
        stream.set_origin_timeout(None);
        let mut buf = [0u8; 256];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

/// Minimal DER-to-PEM, and the base64 under it.
///
/// Copied rather than shared from `crates/tls-acceptor/tests/openssl_client.rs`,
/// which does the same thing for the same reason: `rustls`'s `PemObject` is
/// decode-only, so writing a certificate out costs either a dependency or
/// twenty lines, and one call does not justify a dependency in the test surface.
/// Written out here because a test helper shared across crates is a coupling
/// that buys nothing and costs a public API.
fn pem_encode(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        body.push(ALPHABET[(n >> 18) as usize & 63] as char);
        body.push(ALPHABET[(n >> 12) as usize & 63] as char);
        body.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        body.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    origin: Origin,
    credential_id: String,
    credential_label: String,
    /// The durable audit log the broker appends every substitution to.
    ///
    /// The broker is handed the path rather than asked to *be* asked: a chain
    /// that only exists inside the running process is not a chain an operator
    /// can verify, and an assertion that reaches for it over a flag that does
    /// not exist verifies nothing at all.
    audit: PathBuf,
    /// Named with a leading underscore because nothing else in this file
    /// *starts* the broker; they only stop it, through `Drop`. The shutdown
    /// measurement has to signal and then observe it leaving, so the handle is
    /// reachable and the field says so.
    _broker: Broker,
}

impl Fixture {
    /// The running broker's pid.
    fn broker_pid(&self) -> i32 {
        self._broker.pid()
    }

    /// The broker's exit status, or `None` while it is still running.
    fn try_wait_broker(&mut self) -> Option<std::process::ExitStatus> {
        self._broker.try_wait()
    }
}

impl Fixture {
    /// Plant the credential, then start the broker that will tunnel to it.
    ///
    /// Two broker runs, and the first one is not ceremony. A route names a
    /// credential by its canonical id, and the *product* mints those ids — the
    /// vault's own seeded canary carries a non-canonical id and the broker
    /// deliberately skips it, which is the right behaviour and means the test
    /// cannot invent an id and write a route against it.
    ///
    /// So the credential is added the way an operator adds one, over the
    /// product's own verb with the secret on stdin, and the id that verb minted
    /// is what the route file names. The second run then exists because the
    /// broker reads its inventory at startup: a credential added afterwards
    /// would not be in `state.credentials` when the session tries to mint for
    /// it, and the mint would be skipped for a reason no log would explain.
    fn new(tag: &str) -> Self {
        Self::with_origin(tag, Origin::start_serving(1))
    }

    /// A fixture whose origin answers several requests per connection.
    ///
    /// The port has to be the one the route file names, so the origin is
    /// started this way from the beginning rather than swapped afterwards: a
    /// fixture that reconnected the origin would leave the route naming a port
    /// nothing is listening on, and the tunnel would fail for a reason that has
    /// nothing to do with the question being asked.
    fn new_serving(tag: &str, per_connection: usize) -> Self {
        Self::with_origin(tag, Origin::start_serving(per_connection))
    }

    /// A fixture whose origin holds its connection open after answering.
    ///
    /// Started from the beginning for the same reason, and the origin is
    /// therefore a different *kind* of origin rather than a later phase of the
    /// same one.
    fn new_holding(tag: &str) -> Self {
        Self::with_origin(tag, Origin::start_holding())
    }

    /// A fixture whose route declares `upstream: "tls"` and whose origin
    /// presents a certificate minted from `ca`.
    ///
    /// With `anchored`, the broker is pointed at `ca`'s root through
    /// `--connect-roots` and the tunnel is expected to work. Without it, the
    /// flag is absent and the tunnel is expected to be refused. Both halves use
    /// the same CA on purpose: the difference between the two runs is the flag
    /// and nothing else, so "no anchors" is the only variable.
    fn new_tls(tag: &str, ca: &SessionCa, anchored: bool) -> Self {
        let origin = Origin::start_tls_serving(ca);
        let anchors = anchored.then_some(ca.root_der.as_slice());
        Self::build(tag, origin, "tls", anchors)
    }

    fn with_origin(tag: &str, origin: Origin) -> Self {
        Self::build(tag, origin, "cleartext", None)
    }

    /// A fixture whose origin never finishes answering.
    ///
    /// The only fixture whose tunnel is still being *relayed* when the test
    /// signals it, which is what makes a cancellation observable at all.
    fn new_stalling(tag: &str) -> Self {
        Self::with_origin(tag, Origin::start_stalling())
    }

    /// A fixture whose route declares `upstream` and whose broker is handed
    /// `connect_roots` — or, with `None`, is given **no** `--connect-roots` at
    /// all, which is the product's default and the thing under test.
    ///
    /// The anchors arrive as DER and are written here rather than by the
    /// caller, because `build` clears the working directory before it starts.
    /// A caller that wrote the file itself would watch it disappear, and the
    /// broker would refuse for want of a path — a failure shaped exactly like
    /// the one this test is looking for, which is how the first version of it
    /// reported a green control as a red assertion.
    ///
    /// `None` is not "an empty anchor file": it is the flag absent, so this
    /// reaches the branch in `main.rs` that an operator reaches by forgetting
    /// an argument. A fixture that wrote an empty PEM would exercise a
    /// different line and would go on passing if that line regressed.
    fn build(tag: &str, origin: Origin, upstream: &str, connect_roots: Option<&[u8]>) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");

        let anchor_file = connect_roots.map(|der| {
            let path = dir.join("roots.pem");
            std::fs::write(&path, pem_encode(der)).expect("write the anchor file");
            path
        });

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("e2e-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
        let secret = SecretString::new(value.clone().into());

        VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");

        // Enrolment writes to the vault, and the broker reads its admission
        // record at startup. Enrolling a broker that is already running is the
        // same ordering mistake as planting a credential into it: the record
        // exists on disk and the running process has never seen it, so the
        // refusal names the principal rather than the ordering.
        let enrolled = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("enrol the CLI as a principal");
        assert!(
            enrolled.status.success(),
            "enrolment failed: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );

        // --- phase one: add the credential and learn its id ---------------
        let plant = Broker(
            Command::new(cargo_bin("asv-brokerd"))
                .arg(&sock)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&passphrase)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the planting broker"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            sock.exists(),
            "the planting broker never created its socket"
        );

        let mut add = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&sock)
            .arg("add-credential")
            .arg("--label")
            .arg(CREDENTIAL_LABEL)
            .arg("--kind")
            .arg("bearer_token")
            .arg("--provider")
            .arg("github")
            .arg("--account")
            .arg("e2e")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run add-credential");
        {
            use std::io::Write as _;
            let mut stdin = add.stdin.take().expect("add-credential stdin");
            stdin.write_all(REAL.as_bytes()).expect("write the secret");
            stdin.write_all(b"\n").expect("terminate the secret");
            // Closed here, not earlier: `add-credential` reads to EOF.
            drop(stdin);
        }
        let added = add.wait_with_output().expect("add-credential finishes");
        assert!(
            added.status.success(),
            "add-credential failed: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        let plant_out = String::from_utf8_lossy(&added.stdout).into_owned();
        drop(plant);

        // "credential 00000000-...-.... created (e2e-token)"
        let credential_id = plant_out
            .split_whitespace()
            .nth(1)
            .filter(|word| word.contains('-'))
            .unwrap_or_else(|| panic!("could not read the minted id from: {plant_out}"))
            .to_owned();
        assert!(
            asv_domain::CredentialId::from_wire(&credential_id).is_ok(),
            "the broker minted an id this route file could not name: {credential_id}"
        );

        let _ = std::fs::remove_file(&sock);

        // --- phase two: the broker that will actually tunnel ---------------
        let routes = dir.join("routes.json");
        std::fs::write(
            &routes,
            format!(
                r#"[{{
  "authority": "{FIXTURE_HOST}",
  "port": {},
  "operation_family": "git_hub",
  "credential": "{credential_id}",
  "minimum_posture": "STRONG_SECRETLESS",
  "upstream": "{upstream}"
}}]"#,
                origin.port,
                upstream = upstream
            ),
        )
        .expect("write the route file");

        // The policy: the stock text plus the one rule C2.6 deliberately left
        // out. `from_policy_text` replaces the whole policy, so the GitHub
        // permit the mint consults has to be restated — a fixture policy that
        // omitted it would fail the mint for a reason unrelated to the route.
        let policy = dir.join("policy.cedar");
        std::fs::write(
            &policy,
            format!(
                r#"permit (principal, action == Action::"github_issue_read", resource is Api);
permit (principal, action == Action::"connect_route", resource == Host::"host:{FIXTURE_HOST}");
"#
            ),
        )
        .expect("write the policy file");

        let audit = dir.join("audit.jsonl");
        let mut broker_command = Command::new(cargo_bin("asv-brokerd"));
        broker_command
            .arg(&sock)
            .arg("--vault")
            .arg(&vault)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .arg("--connect-listen")
            .arg("127.0.0.1:0")
            .arg("--connect-routes")
            .arg(&routes)
            .arg("--policy")
            .arg(&policy)
            .arg("--audit-file")
            .arg(&audit);
        // **Only when there is something to hand it.** Omitting the argument
        // altogether is the state under test, and building the command with an
        // empty value would not be the same state at all.
        if let Some(roots) = anchor_file.as_ref() {
            broker_command.arg("--connect-roots").arg(roots);
        }
        let broker = Broker(
            broker_command
                // The broker's tracing goes to *stdout*, not stderr, so a
                // fixture that silences stdout is silently hiding the only
                // account of why a tunnel was refused.
                .stdout(
                    std::fs::File::create(dir.join("broker.log")).expect("create the broker log"),
                )
                .stderr(
                    std::fs::File::create(dir.join("broker.err"))
                        .expect("create the broker error log"),
                )
                .spawn()
                .expect("spawn the tunneling broker"),
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the broker never created its socket");

        Self {
            dir,
            sock,
            origin,
            credential_id,
            credential_label: CREDENTIAL_LABEL.to_owned(),
            audit,
            _broker: broker,
        }
    }

    /// The environment variable `asv run` exports a session's surrogate under.
    ///
    /// Derived from the label the vault itself reported, so the test reads the
    /// product's own spelling rather than agreeing with it by construction.
    fn surrogate_env_name(&self) -> String {
        format!(
            "ASV_SURROGATE_{}",
            self.credential_label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                })
                .collect::<String>()
        )
    }

    /// One ordinary `curl` through the whole path, run to completion.
    ///
    /// Returns what `curl` reported. **`000` is a real answer here**, not an
    /// absent one: it is what `curl -w '%{http_code}'` prints when the transfer
    /// never produced a response, which is what a refused tunnel looks like from
    /// the client. A helper that swallowed that would turn the property under
    /// test into a shape nothing could fail.
    fn one_shot_status(&self) -> String {
        let variable = self.surrogate_env_name();
        let out = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .arg("run")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                "curl -sS -k --max-time 25 -o /dev/null -w '%{{http_code}}' \
                   -H \"Authorization: Bearer ${variable}\" \
                   https://{FIXTURE_HOST}:{port}/resource",
                port = self.origin.port,
                variable = variable
            ))
            // Inherited bypasses, planted so their removal is observable.
            .env("NO_PROXY", "should-be-removed")
            .env("no_proxy", "should-be-removed")
            .output()
            .expect("run the session");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// The child script. A shell, because `curl` cannot read an environment
    /// variable on its own and the point is that an *ordinary* client is
    /// pointed at a proxy, not that it learned ASV's vocabulary.
    fn held_open_script(
        &self,
        status: &std::path::Path,
        token: &std::path::Path,
        release: &std::path::Path,
    ) -> String {
        let variable = self.surrogate_env_name();
        format!(
            "code=$(curl -sS -k --max-time 20 -o /dev/null -w '%{{http_code}}' \
               -H \"Authorization: Bearer ${variable}\" \
               https://{FIXTURE_HOST}:{port}/resource); \
             printf '%s' \"$code\" > {status}; \
             env | grep -iE 'asv|proxy' | sort; \
             printf '%s' \"${variable}\" > {token}; \
             while [ ! -f {release} ]; do sleep 0.2; done",
            port = self.origin.port,
            status = status.display(),
            token = token.display(),
            release = release.display()
        )
    }
}

// ---------------------------------------------------------------------------
// The vertical
// ---------------------------------------------------------------------------

#[test]
fn asv_run_curl_reaches_the_origin_with_the_real_credential_and_nobody_else() {
    let f = Fixture::new("vertical");
    let env_name = f.surrogate_env_name();
    let status_path = f.dir.join("session-a.status");
    let token_path = f.dir.join("session-a.token");
    let release_path = f.dir.join("release-a");

    // --- session A, held open ---------------------------------------------
    //
    // A has to still be *alive* when session B presents its token, and that is
    // the whole reason it is spawned rather than run to completion.
    //
    // `SessionEnded` calls `revoke_session`, which *deletes* a session's
    // surrogates from the registry. So a token taken from a session that has
    // already exited is refused for being unknown — a real property, and the
    // one the first version of this block measured while claiming to measure
    // another. The mutation campaign is what found the difference: deleting the
    // session comparison in `SurrogateRegistry::redeem_for` left the test
    // completely green, because the comparison was never reached. An assertion
    // satisfied by a refusal of the wrong cause is decoration, and it is
    // indistinguishable from a working one until you take the control away.
    let script_a = f.held_open_script(&status_path, &token_path, &release_path);
    let session_a = Session {
        child: Some(
            Command::new(cargo_bin("asv"))
                .arg("--socket")
                .arg(&f.sock)
                .arg("run")
                .arg("sh")
                .arg("-c")
                .arg(&script_a)
                // Inherited bypasses, planted so their removal is observable.
                .env("NO_PROXY", "should-be-removed")
                .env("no_proxy", "should-be-removed")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the first session"),
        ),
        release: release_path.clone(),
    };

    // The token is published after A's request has completed, so this is also
    // the wait for the happy path. Bounded, because a test that hangs is worse
    // than a test that fails.
    assert!(
        wait_for_file(&token_path, Duration::from_secs(90)),
        "session A never published a surrogate"
    );

    // 1. The origin received the REAL credential. This is the whole feature.
    let status_a = std::fs::read_to_string(&status_path).expect("read session A's status");
    assert_eq!(
        status_a.trim(),
        "200",
        "the tunnel did not complete; curl reported something other than 200"
    );
    assert!(
        f.origin.wait_for_requests(1),
        "the origin never received a request"
    );
    let seen = f.origin.saw();
    assert!(
        seen.contains(REAL),
        "the origin did not receive the real credential; it saw:\n{seen}"
    );

    // 2. The surrogate is a *session* capability, and the only way to measure
    // that is to carry one token into another live session.
    let token_a = std::fs::read_to_string(&token_path).expect("read session A's surrogate");
    let token_a = token_a.trim();
    assert!(
        token_a.starts_with("asv1_"),
        "the exported value is not a surrogate token: {token_a}"
    );
    assert!(token_a != REAL, "the surrogate *is* the real credential");

    // Session A is still open here. That is the whole point, and it is why this
    // block cannot be a `Command::output()`: that waits for the child.
    let bytes_before = f.origin.requests_with_bytes();
    let real_before = f.origin.real_credential_requests();
    let carried = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "curl -sS -k --max-time 20 -o /dev/null -w 'FOREIGN_%{{http_code}}' \
               -H 'Authorization: Bearer {token_a}' \
               https://{FIXTURE_HOST}:{port}/resource; echo; \
             curl -sS -k --max-time 20 -o /dev/null -w 'OWN_%{{http_code}}' \
               -H \"Authorization: Bearer ${env_name}\" \
               https://{FIXTURE_HOST}:{port}/resource; echo",
            port = f.origin.port
        ))
        .output()
        .expect("present another live session's surrogate");
    let carried_out = String::from_utf8_lossy(&carried.stdout);
    let carried_err = String::from_utf8_lossy(&carried.stderr);

    assert!(
        !carried_out.contains("FOREIGN_200"),
        "a live session's surrogate was redeemed by a different one: {carried_out}"
    );
    // The positive half, in the same run. Without it the refusal above is
    // ambiguous: a broker that refused every surrogate would also pass it, and
    // "not yours" has to be distinguishable from "nothing works at all".
    assert!(
        carried_out.contains("OWN_200"),
        "a fresh session could not use its own surrogate:\n{carried_out}\n{carried_err}"
    );

    // The origin is the independent witness, and it is asked two questions
    // because they are not the same question. The origin pushes each capture
    // *before* it answers, so both counts are settled by the time the client
    // has its status line.
    assert_eq!(
        f.origin.requests_with_bytes(),
        bytes_before + 1,
        "the origin received a request the sessions did not authorise"
    );
    // The one that matters: the foreign surrogate must not have put the real
    // credential in front of the destination. The bridge does open a connection
    // for a refused tunnel — it has to dial before it can read the head that
    // carries the surrogate — so a connection count would have grown by two.
    // Counting the secret is what measures the property.
    assert_eq!(
        f.origin.real_credential_requests(),
        real_before + 1,
        "the real credential reached the origin more times than it was authorised"
    );
    assert!(
        !carried_out.contains(REAL) && !carried_err.contains(REAL),
        "a refused surrogate leaked the credential:\n{carried_out}\n{carried_err}"
    );

    // 3-7. Now A can finish, and its output carries the rest of the claims:
    // the wiring the child was handed, and the four surfaces the secret must
    // not appear on.
    let a = session_a.finish();
    let stdout = String::from_utf8_lossy(&a.stdout);
    let stderr = String::from_utf8_lossy(&a.stderr);
    assert!(
        a.status.success(),
        "the session command failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // `Output` does not carry the argv, so it is reconstructed from what this
    // test asked for. The real `argv` of the process that ran is the script
    // text, and the secret is read from the broker, never passed in.
    let argv_used = format!("asv --socket {} run sh -c {script_a}", f.sock.display());
    for (what, haystack) in [
        ("the child's output", &format!("{stdout}\n{stderr}")),
        ("the child's argv", &argv_used),
    ] {
        assert!(
            !haystack.contains(REAL),
            "the real credential appeared in {what}:\n{haystack}"
        );
    }

    // The session ran with a real session id, a real agent socket and a proxy
    // pointed at this session's shim. If any of those were missing the tunnel
    // above could not have happened, so this is a positive check on the wiring
    // rather than a restatement of the 200.
    assert!(
        stdout.contains("ASV_SESSION_ID="),
        "the child was not told its session:\n{stdout}"
    );
    assert!(
        stdout.contains("SSH_AUTH_SOCK="),
        "the child had no agent socket:\n{stdout}"
    );
    assert!(
        stdout.contains("HTTPS_PROXY=http://127.0.0.1:"),
        "the child was not pointed at a session-local shim:\n{stdout}"
    );
    for inherited in ["NO_PROXY", "no_proxy"] {
        assert!(
            !stdout
                .lines()
                .any(|l| l.starts_with(&format!("{inherited}="))),
            "the inherited {inherited} survived into the child. It is a bypass, not a \
             preference: a destination named there is connected to directly, with no \
             CONNECT, no proof and no substitution.\n{stdout}"
        );
    }
    assert!(
        stdout.contains(&format!("{env_name}=")),
        "the child was given no surrogate to present, so nothing could be \
         substituted:\n{stdout}"
    );

    // 9. A wrong destination fails. Nothing routes it, so the tunnel is refused
    // and the origin count does not move.
    let wrong = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("curl")
        .arg("-sS")
        .arg("-k")
        .arg("--max-time")
        .arg("20")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(format!("https://{FIXTURE_HOST}:1/nowhere"))
        .output()
        .expect("connect to a port with no route");
    let wrong_out = String::from_utf8_lossy(&wrong.stdout);
    assert!(
        !wrong_out.contains("200"),
        "a destination with no route was tunnelled anyway: {wrong_out}"
    );
    assert!(
        !wrong_out.contains(REAL),
        "the refused destination leaked the credential:\n{wrong_out}\n{}",
        String::from_utf8_lossy(&wrong.stderr)
    );

    // 11. The audit chain verifies — read off the file the broker actually
    // wrote, with a tamper control, because a verifier that answers Ok to
    // everything verifies nothing.
    //
    // The first version shelled out to `asv-brokerd --audit-verify`. There is
    // no such flag, the broker was never started with an audit file, and the
    // whole assertion sat behind `if ... .success()`, so the one property this
    // file exists to certify was a no-op that would have passed against a
    // broker writing no audit at all. The flag name was never checked against
    // `main.rs`, which is the whole lesson of this block written down.
    let chain = std::fs::read_to_string(&f.audit).unwrap_or_else(|err| {
        panic!(
            "the broker wrote no audit log at {}: {err}",
            f.audit.display()
        )
    });
    // The records are parsed, not grepped.
    //
    // The first version of this block asserted that the chain text contained
    // `"destination":"localhost.localdomain:` — and it went green against a
    // mutation that rewrites the destination of every substitution record. It
    // was being satisfied by a *different* record: the listener writes one for
    // the connection as well as one for the credential, and the connection
    // record names the destination in its own spelling. A substring assertion
    // over a log cannot tell which line it was reading, so it cannot be made
    // red by changing the line it was supposed to be about.
    let records: Vec<asv_ipc_protocol::AuditRecordDto> = chain
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every audit line parses"))
        .collect();
    let substitutions: Vec<&asv_ipc_protocol::AuditRecordDto> = records
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { .. }
            )
        })
        .collect();
    let authorised = format!("{FIXTURE_HOST}:{}", f.origin.port);
    let done: Vec<_> = substitutions
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { outcome, .. }
                    if outcome == "substituted"
            )
        })
        .collect();
    assert_eq!(
        done.len(),
        2,
        "expected both authorised substitutions to be recorded, found {}\n{chain}",
        done.len()
    );
    for record in &done {
        let asv_ipc_protocol::AuditEventDto::CredentialSubstituted { destination, .. } =
            &record.event
        else {
            unreachable!("filtered to substitutions above")
        };
        assert_eq!(
            destination, &authorised,
            "a recorded substitution names a destination nobody authorised"
        );
    }
    // The refusal is recorded too, with the family left unresolved — the port
    // declined before it established one, and inventing it would put an
    // unestablished fact in the chain.
    let refused: Vec<_> = substitutions
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { outcome, .. }
                    if outcome == "refused"
            )
        })
        .collect();
    assert_eq!(
        refused.len(),
        1,
        "the refused cross-session attempt was not recorded as refused\n{chain}"
    );
    // The chain is the artefact that gets exported, hashed and shipped, so it
    // has to be the surface that most obviously cannot hold the secret.
    assert!(
        !chain.contains(REAL),
        "the real credential reached the durable audit log:\n{chain}"
    );
    asv_broker::audit::verify_file(&f.audit).expect("the audit chain does not verify");

    // The control. `verify_file` returns Ok for an empty file and for a
    // single-record chain, so a green verification above means nothing on its
    // own. The same call has to be shown going red on an altered record before
    // it is allowed to be evidence of anything.
    let tampered = f.dir.join("tampered-audit.jsonl");
    let altered = chain.replacen("\"substituted\"", "\"refused\"", 1);
    assert_ne!(
        altered, chain,
        "the tamper control changed nothing, so it would have passed for the \
         wrong reason"
    );
    std::fs::write(&tampered, altered).expect("write the altered chain");
    assert!(
        asv_broker::audit::verify_file(&tampered).is_err(),
        "the chain verifier accepted an altered record, so it cannot see a break"
    );

    let _ = f.credential_id;
}

/// One tunnel carries every request the client makes, and the destination
/// receives the real credential on each of them.
///
/// **This was a characterization and is now a claim, because the loop landed.**
/// Before, against this same real broker with a real origin that holds the
/// connection open, the measurement was:
///
/// ```text
/// CONN=1 CODE=200      the first request, on one connection
/// CONN=0 CODE=000      the second request, curl reusing that same connection
/// ```
///
/// `CONN=0` was the load-bearing half: curl did not open a second connection, it
/// reused the tunnel and got nothing back, so the second request never reached
/// the destination. The cause was in `relay_substituted` — it read one head,
/// wrote the rewritten one, and then copied the response direction until EOF, so
/// the request direction was never pumped again. That is now
///
/// ```text
/// CONN=1 CODE=200
/// CONN=0 CODE=200
/// ```
///
/// and this test asserts it, because a characterization that only fails is not
/// evidence of anything. Its own message said what to do when it went green:
/// rewrite both the assertion and the comment. This is both.
///
/// What changed the behaviour is not the loop on its own — it is a loop that
/// frames every message it relays. `Content-Length: 0` occurrences in the relay
/// was the measurement that named the missing piece: a request head, a body, and
/// a second request head on one connection cannot be told apart by scanning for
/// `\r\n\r\n`, because a body may contain the terminator itself, and a relay
/// that scans for it substitutes a credential into the middle of somebody's form
/// post. So each head is parsed for its framing, each body is relayed by the
/// framing the head declared, and the next head is read only where the previous
/// message ended.
#[test]
fn one_tunnel_carries_every_request_and_the_destination_sees_the_credential_on_each() {
    let f = Fixture::new_serving("pipelined", 2);

    // One `-H`, two URLs: curl applies it to both and reuses the connection,
    // which is the whole shape of the question. Two `-H` flags would send the
    // header twice on every request, and the destination would see two.
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null \
           -w 'CONN=%{{num_connects}} CODE=%{{http_code}}\n' \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/first \
           https://{FIXTURE_HOST}:{port}/second",
        port = f.origin.port
    );
    let child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("two requests on one tunnel");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);

    // The connection was reused. Without this the rest of the test would be
    // measuring a client that quietly opened a second tunnel, which is the easy
    // way for this property to be satisfied without the loop existing.
    assert!(
        stdout.contains("CONN=0"),
        "curl opened a second connection instead of reusing the tunnel, so this \
         measurement is about something else: {stdout}\n{stderr}"
    );

    // And both requests were served on it. The number is asserted rather than
    // described: a loop that carried the first request and dropped the second
    // would satisfy every other assertion in this test.
    let served = stdout.matches("CODE=200").count();
    assert_eq!(
        served, 2,
        "one tunnel served {served} of the two requests curl made on it: \
         {stdout}\n{stderr}"
    );

    // **The re-substitution, which is the part that is a security property and
    // not an availability one.** The destination has to receive the *real*
    // credential once per request: one credential for the first request and a
    // stale, already-spent surrogate for the second would be a tunnel that looks
    // like it works and quietly fails at the provider.
    let seen = f.origin.saw();
    f.origin.wait_for_requests(2);
    assert_eq!(
        f.origin.real_credential_requests(),
        2,
        "the destination did not receive the credential on both requests, so at \
         least one was forwarded with something else in the header: \n{seen}"
    );

    // **And the operator can tell a two-request tunnel from a one-request one.**
    //
    // The relay's own log line is the only place the request count exists outside
    // the outcome struct, and nothing asserted it — the falsification campaign
    // deleted `requests = outcome.requests` from the log and every test in the
    // suite stayed green, because a number nobody reads is a number nobody
    // maintains. This is a real operator surface: a tunnel that carried two
    // requests and a tunnel that carried one look identical in every other field.
    let log_path = f.dir.join("broker.log");
    assert!(
        log_gains(&log_path, "CONNECT tunnel relayed", Duration::from_secs(30)),
        "the broker never logged a relayed tunnel, so there is no line to read"
    );
    let log = strip_ansi(&std::fs::read_to_string(&log_path).expect("read the broker log"));
    assert!(
        log.contains("requests=2"),
        "the operator's line does not say the tunnel carried two requests, which is \
         the one fact that distinguishes this from the one-request tunnel it \
         replaced:\n{log}"
    );
    assert!(
        !seen.contains(&f.surrogate_env_name()),
        "a variable name in the destination's bytes would mean a token arrived: \n{seen}"
    );
    assert!(
        !stdout.contains(REAL) && !stderr.contains(REAL),
        "the real credential appeared outside the destination: \n{stdout}\n{stderr}"
    );
}

/// Sixty-four CONNECTs at once from one session, and the anti-replay window
/// must not refuse a single one of them.
///
/// This began as a characterisation of a defect and is now a claim, because the
/// defect is fixed. Before, 8 of 64 completed and the broker's log split the 56
/// refusals into 17 legitimate proofs refused as `Replayed` and 39 exhausted
/// surrogates. The 17 were the important half: proofs the session had just
/// minted, correctly signed, refused by the machinery that exists to stop
/// replays, in the one direction an honest client cannot distinguish from an
/// attack.
///
/// Two defects were behind it, both in this repository and neither in a test:
///
/// - The window marked the wrong bit when it advanced. Bit `i` means
///   `highest - 1 - i`, so the previous highest lands on `shift - 1`, not on
///   bit 0 — and those coincide only when the shift is exactly one, which is
///   the single case the existing test happened to cover.
/// - The surrogate's use budget was 8, not the 32 the broker asked for:
///   `mint` clamps into the protocol ceiling, and a clamp that lowers what you
///   asked for raises nothing and logs nothing. The wire reported the clamped
///   value, so every reader believed it.
///
/// Measured after both: **64 of 64 complete and nothing is refused.** The
/// surrogate budget was still 32 at that point, so the 32 that could not
/// complete were refused for the budget that was *documented* — a budget doing
/// its job, and the wrong job: `npm install express` needs 93. The budget is
/// now the protocol's ceiling, and a test that demanded a refusal at 64 would be
/// demanding the defect back.
///
/// The property asserted here is the one that must not regress: the anti-replay
/// window refuses nothing, every request is accounted for by a reason the
/// operator can read, and no session spends more than it was granted.
#[test]
fn the_anti_replay_window_refuses_no_honest_proof_under_load() {
    const PARALLEL: usize = 64;

    let f = Fixture::new_serving("concurrent", 1);
    let variable = f.surrogate_env_name();
    let out = f.dir.join("codes");
    let script = format!(
        "i=0; \
         while [ $i -lt {n} ]; do \
           ( curl -sS -k --max-time 60 -o /dev/null \
               -w '%{{http_code}}\n' \
               -H \"Authorization: Bearer ${{{variable}}}\" \
               \"https://{FIXTURE_HOST}:{port}/r$i\" >> {out} ) & \
           i=$((i+1)); \
         done; \
         wait",
        n = PARALLEL,
        port = f.origin.port,
        out = out.display()
    );
    let child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("parallel tunnels from one session");
    let codes = std::fs::read_to_string(&out).unwrap_or_default();
    let ok = codes.lines().filter(|l| l.trim() == "200").count();
    assert!(
        ok > 0,
        "no tunnel completed, so this measured nothing:\n{codes}"
    );

    // The broker's own account, which is why the fixture captures its stdout:
    // `tracing_subscriber::fmt()` writes there, and a fixture that silences
    // stdout hides the only record of why a tunnel was refused. An observer
    // switched off is indistinguishable from one that does not exist.
    let log = std::fs::read_to_string(f.dir.join("broker.log")).unwrap_or_default();
    let proof_refusals = log.matches("no session proof resolved").count();
    let surrogate_refusals = log.matches("the presented surrogate was refused").count();

    // The property. Sixty-four freshly minted proofs, and not one of them
    // refused for being a replay.
    assert_eq!(
        proof_refusals, 0,
        "{proof_refusals} legitimate proofs were refused as replays; a client paying \
         for a concurrent burst cannot tell that from an attack"
    );
    // And every request has a reason an operator can act on.
    assert_eq!(
        proof_refusals + surrogate_refusals,
        PARALLEL - ok,
        "the broker refused {} tunnels but accounted for {} of them; a refusal with \
         no reason in the log is one nobody can act on",
        PARALLEL - ok,
        proof_refusals + surrogate_refusals
    );
    // Whatever is left is the budget, doing what a budget is for.
    //
    // **This assertion used to pin the number 32 and cannot any more.** Sixty-four
    // CONNECTs exceeded a budget of 32, so "something was refused" doubled as
    // evidence that the budget is enforced. The session's budget is now the
    // protocol's own ceiling — 64 is nowhere near it, every tunnel completes, and
    // a test that demanded a refusal would be demanding the defect back.
    //
    // What replaces it is the same property stated without a magic number: no
    // session may spend more than it was granted. Enforcement at the point of
    // spending is witnessed where it can actually be witnessed, by
    // `a_session_surrogate_pays_for_a_workload_that_was_actually_run` and by the
    // registry's own exhaustion cases — a budget can be checked by spending it to
    // zero in a unit test, and cannot be checked by a workload too small to reach
    // it.
    assert!(
        ok <= asv_broker::session_surrogate_budget() as usize,
        "{ok} of {PARALLEL} tunnels completed and the session was granted {} operations, \
         so more were spent than were granted",
        asv_broker::session_surrogate_budget()
    );

    // What a concurrency fix must not break: the destination saw the credential
    // once per completed tunnel, and never a surrogate.
    assert_eq!(
        f.origin.real_credential_requests(),
        ok,
        "the destination saw the credential a different number of times than \
         tunnels completed"
    );
    let seen = f.origin.saw();
    assert!(
        !seen.contains("asv1_"),
        "a surrogate reached the destination:\n{seen}"
    );
    let _ = child;
}

// ---------------------------------------------------------------------------
// The negative half
// ---------------------------------------------------------------------------

/// A tunnel does not outlive the session that authorised it.
///
/// Two things are being measured, and the difference between them is the whole
/// reason this test is worth writing down.
///
/// **What the destination sees.** The origin holds the connection it was given
/// and reports whether it is still holding it, with no read deadline behind
/// the answer — so "still open" cannot be a timer wearing a tunnel's clothes.
/// When the session ends and the count goes to zero, the tunnel is gone from
/// the far end of the chain, which is the shape an operator would recognise.
///
/// **What it cannot settle.** It cannot say *who* closed it. `asv run` stops
/// its shim and ends its session in that order, and a dead shim drops its
/// sockets, so a tunnel closing here is equally consistent with the shim dying
/// and with the broker cancelling. The vertical has no way to hold the shim
/// open while the session ends, because ending the session *is* the shim
/// stopping.
///
/// So the end-to-end claim is checked here and the broker's own claim is
/// checked where it can be isolated, in
/// `connect_session_revocation_wiring.rs`. A green test above and a green test
/// there are two different guarantees; a green one with the other missing is
/// a guarantee nobody actually has.
///
/// Two URLs on one connection, deliberately. The first is answered and the
/// second is not — the limit measured in
/// `a_tunnel_serves_one_request_and_the_protocol_allows_more` — and that is
/// precisely what keeps `curl` inside the tunnel. A single-URL curl exits on
/// its response, and a tunnel whose client has already exited is not a tunnel
/// that outlived anything: the control below would pass against a fixture that
/// never held a connection at all.
///
/// `--max-time` is the second request giving up, and it is why this test takes
/// twenty seconds rather than three: the release file is only read after `curl`
/// returns, so curl's own deadline is what ends the command and lets `asv run`
/// begin its teardown. It has to clear the settle window below with room to
/// spare, because a `curl` that hit its deadline first would close the tunnel
/// for a reason that has nothing to do with the session — the one confound this
/// test cannot survive. Twenty against a control that fires at under one is
/// that room.
#[test]
fn a_tunnel_does_not_outlive_the_session_that_authorised_it() {
    let f = Fixture::new_holding("midtunnel");
    let variable = f.surrogate_env_name();
    let release_path = f.dir.join("mid.release");
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/first \
           https://{FIXTURE_HOST}:{port}/second; \
         while [ ! -f {release} ]; do sleep 0.2; done",
        port = f.origin.port,
        release = release_path.display()
    );

    let session = Session {
        child: Some(
            Command::new(cargo_bin("asv"))
                .arg("--socket")
                .arg(&f.sock)
                .arg("run")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the session under measurement"),
        ),
        release: release_path.clone(),
    };

    // The destination is asked, not the client. A client inside its own tunnel
    // cannot tell a live tunnel from a socket it is holding open by itself.
    assert!(
        f.origin.wait_for_open(1, Duration::from_secs(90)),
        "the tunnel was never established: the destination holds {} connections, \
         so the assertion after the session ends would be measuring nothing",
        f.origin.open_connections()
    );
    assert!(
        f.origin.wait_for_requests(1),
        "the destination never received a request"
    );

    // The control, and the reason the tunnel has to survive the request that
    // built it. One sample is not an observation: a tunnel that collapses the
    // instant it is used satisfies "zero connections after the session ends"
    // perfectly while proving nothing. A second look, after a settle window
    // and with the session still live, is what gives the later zero its
    // meaning.
    std::thread::sleep(Duration::from_millis(750));
    assert_eq!(
        f.origin.open_connections(),
        1,
        "the tunnel did not survive the request that established it; the \
         destination gave the connection back while the session was still live, \
         so nothing here is measuring a tunnel outliving anything"
    );
    assert_eq!(
        f.origin.real_credential_requests(),
        1,
        "the credential did not reach the destination exactly once under a live \
         session; whatever closes later is not a tunnel that was working"
    );

    // The session ends. `Session::finish` releases the child, waits for it, and
    // so returns only after `asv run` has stopped its shim and sent
    // `EndSession` — the teardown is over before the first observation.
    let out = session.finish();
    assert!(
        out.status.success(),
        "the session failed while tearing down\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        f.origin.wait_for_open(0, Duration::from_secs(20)),
        "a tunnel outlived the session that authorised it: the destination still \
         holds {} connections 20s after the session ended, carrying a credential \
         nobody authorised any more",
        f.origin.open_connections()
    );
}

#[test]
fn a_session_that_ends_takes_its_proof_authority_with_it() {
    let f = Fixture::new("revoked");
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null -w 'HTTP_%{{http_code}}' \
           -H \"Authorization: Bearer ${variable}\" \
           https://{FIXTURE_HOST}:{port}/resource; \\\
             env | grep -iE 'asv|proxy' | sort",
        port = f.origin.port
    );

    let first = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("first session");
    assert!(
        first.status.success(),
        "the first session failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The precondition. Everything below asserts what happens *after* the
    // session ends, and a first request that never worked would make the
    // shim-stopping assertion pass without anything having been proven.
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("HTTP_200"),
        "the first session never reached the origin: {}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(f.origin.wait_for_requests(1));

    // After the command returns, `asv run` has ended the session and stopped the
    // shim. A later attempt must not be able to use anything that session held.
    // What the shim's port does now is the observable part: a proxy that is still
    // listening would accept a CONNECT and mint a proof for a session that no
    // longer exists, which resolves to nothing and reads as a broken signer.
    let proxy = String::from_utf8_lossy(&first.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("HTTPS_PROXY=").map(|s| s.to_owned()))
        .expect("the child was told a proxy");
    let addr: SocketAddr = proxy
        .trim_start_matches("http://")
        .parse()
        .expect("proxy addr");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut still_listening = true;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                still_listening = false;
                break;
            }
        }
    }
    assert!(
        !still_listening,
        "the shim at {addr} is still listening after its session ended"
    );
}

#[test]
fn a_route_the_policy_does_not_permit_is_refused_at_load() {
    // The fail-closed half of C2.6, through the real binary: a route file whose
    // host the policy does not name stops the broker from starting at all. A
    // broker that started with the route silently dropped would let an operator
    // read "it is running" as "my configuration is in force".
    let dir = std::env::temp_dir().join(format!("asv-e2e-refused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the working dir");

    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let value = "e2e-refused-passphrase".to_owned();
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    VaultStore::create(
        &vault,
        &SecretString::new(value.clone().into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");
    // No credential is planted here on purpose. This route is refused at *load*,
    // before any mint is attempted, so a credential would prove nothing — and
    // planting one needs a `VaultKey` this test has no honest way to get.
    //
    // The id below is well-formed so the refusal this test measures is the
    // policy's, not a malformed credential reported through the same exit.
    let id = "00000000-0000-4000-8000-0000000000e2".to_owned();

    let routes = dir.join("routes.json");
    std::fs::write(
        &routes,
        format!(
            r#"[{{
  "authority": "{FIXTURE_HOST}",
  "port": 443,
  "operation_family": "git_hub",
  "credential": "{id}",
  "minimum_posture": "STRONG_SECRETLESS",
  "upstream": "cleartext"
}}]"#
        ),
    )
    .expect("write routes");

    // A policy that permits the GitHub mint but says nothing about this host.
    let policy = dir.join("policy.cedar");
    std::fs::write(
        &policy,
        "permit (principal, action == Action::\"github_issue_read\", resource is Api);\n",
    )
    .expect("write policy");

    let refused = Command::new(cargo_bin("asv-brokerd"))
        .arg(dir.join("broker.sock"))
        .arg("--vault")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--connect-listen")
        .arg("127.0.0.1:0")
        .arg("--connect-routes")
        .arg(&routes)
        .arg("--policy")
        .arg(&policy)
        .output()
        .expect("run the broker");

    assert!(
        !refused.status.success(),
        "a broker started with a route the policy does not permit"
    );
    let text = String::from_utf8_lossy(&refused.stderr);
    assert!(
        text.contains("connect-routes") || text.contains("policy does not permit"),
        "the refusal did not say why:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// The observability sweep
// ---------------------------------------------------------------------------

/// The address the broker said it was listening on, read out of its own log.
///
/// Taken from the log rather than from a flag or a fixture argument for the
/// same reason the concurrency test reads its refusals from there: the fixture
/// launches the real binary and the log is the only channel it has. The
/// circularity is benign — the address is a startup fact, and the thing under
/// test is what arrives *after* it.
fn connect_address_from_log(path: &std::path::Path) -> SocketAddr {
    let log = std::fs::read_to_string(path).expect("read the broker log");
    // `tracing_subscriber::fmt()` colourises, and the escape sequences land
    // either side of the field. Stripped rather than worked around: a fixture
    // that only parses the log when the terminal is a terminal is a fixture
    // that reports "no address" on half the machines it runs on.
    let plain = strip_ansi(&log);
    plain
        .lines()
        .filter_map(|line| line.split("bound=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .find_map(|addr| addr.parse().ok())
        .expect("the broker logged where it is listening")
}

/// Remove CSI escape sequences.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // `ESC [ … final-byte`, and the final byte is in `@`..=`~`.
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// Waits for `needle` to appear in the broker's log, bounded.
fn log_gains(log: &std::path::Path, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(log)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The broker's own log carries neither the credential nor a surrogate.
///
/// The vertical already proved the child's `argv`, its environment, its output
/// and the durable chain are clean. The operator's log is the surface that was
/// never checked, and it is the one an operator actually reads while something
/// is going wrong — so "it is not in the chain" says very little about it.
///
/// The control is the line that has to be there. A grep over an empty file
/// finds nothing and reports a pass, and an observer that is switched off is
/// indistinguishable from an observer that does not exist.
#[test]
fn the_brokers_own_log_carries_neither_the_credential_nor_a_surrogate() {
    let f = Fixture::new("observability");
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null -w '%{{http_code}}' \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/resource; echo",
        port = f.origin.port
    );
    let ran = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("a session that reaches the origin");
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("200"),
        "the session never reached the origin, so nothing was substituted and the \
         log sweep would be measuring an idle broker:\n{}\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(f.origin.wait_for_requests(1));

    let log_path = f.dir.join("broker.log");
    assert!(
        log_gains(&log_path, "CONNECT tunnel relayed", Duration::from_secs(30)),
        "the broker never logged relaying a tunnel; the log is not what this test \
         thinks it is"
    );
    let log = std::fs::read_to_string(&log_path).expect("read the broker log");

    assert!(
        !log.contains(REAL),
        "the real credential reached the operator's log:\n{log}"
    );
    // `asv1_` is the surrogate prefix, declared in `surrogate.rs` so a token is
    // never mistaken for a credential during triage. A log carrying one would
    // be a log carrying a spendable bearer token.
    assert!(
        !log.contains("asv1_"),
        "a surrogate reached the operator's log, so anything holding that file \
         holds a spendable token:\n{log}"
    );
}

/// A client with no credential cannot write its own words into the operator's
/// log.
///
/// **This is a claim, and it is red.** It is written as a claim rather than as
/// a characterisation because the thing it names is not a judgement call: a
/// client that never proves anything can put arbitrary bytes into a file the
/// operator reads, and the mechanism is short —
///
/// `parse_connect_target` runs **before** the session proof is authenticated
/// (the order in `serve_connect` is head, then target, then authorisation, then
/// proof), and `ConnectTargetError::NoPort` carries the request line's authority
/// verbatim. So `CONNECT <anything-without-a-colon>` writes `<anything>` into
/// the log, unvalidated and uncredited, up to the message bound.
///
/// The durable chain is already protected against exactly this, by
/// `refusal_class`; the operator's line was left carrying the raw text on the
/// judgement that it is "the surface that already exists to hold diagnostic
/// detail". The chain's own comment calls that text *attacker-controlled*, and
/// the reachability here is unauthenticated, which is a stronger statement than
/// the one that judgement was made under.
///
/// The client here is a bare socket. It carries no proof, no surrogate and no
/// credential, and it is not even a well-formed CONNECT — which is the point:
/// the bytes land before any of that is looked at.
#[test]
fn a_client_with_no_credential_cannot_write_its_own_text_into_the_operator_log() {
    let f = Fixture::new("injection");
    let log_path = f.dir.join("broker.log");
    // Waited for, not read once: the broker creates its control socket before
    // it binds the CONNECT listener, so the fixture's own readiness check can
    // be satisfied a moment before the line this test needs is written. A
    // fixture that read the log at that instant would report "no address" for
    // a broker that is about to say where it is.
    assert!(
        log_gains(&log_path, "CONNECT listener bound", Duration::from_secs(30)),
        "the broker never logged its CONNECT listener"
    );
    let addr = connect_address_from_log(&log_path);

    // Shaped like a credential so a substring search cannot be satisfied by a
    // word that happens to appear in a stack trace, and with no colon, so the
    // target parse fails with the request line's own text attached.
    let planted = "gho_ASVclientWroteThisE7b1c3d5f7a9b1d3f5a7c9e1b3d5f7a9b1d3f5a7c9e1";
    let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .expect("reach the CONNECT listener with no credential at all");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client
        .write_all(format!("CONNECT {planted} HTTP/1.1\r\nHost: {FIXTURE_HOST}\r\n\r\n").as_bytes())
        .expect("write a malformed CONNECT");
    let _ = client.flush();

    assert!(
        !log_gains(&log_path, planted, Duration::from_secs(15)),
        "a client that proved nothing, presented no surrogate and sent a malformed \
         request wrote its own text into the operator's log; the broker logs what \
         it cannot attribute to state it validated"
    );
}

/// **The default for `--connect-roots` is not "trust the internet".**
///
/// Until this test existed, that default was asserted by a line the broker
/// logs at startup and by nothing else. A log line is not a gate: it says what
/// the process believes, and the property is about what it *does*. The
/// campaign that guarded this increment said so in its own docstring and left
/// the gap open rather than dressing it up; this is the cheap half of closing
/// it, and the cheap half is the half that can be written.
///
/// **What it does and does not establish.** It shows that a broker started
/// without the flag reaches no TLS destination, while the same broker, the same
/// route and the same origin certificate are reached when the flag names that
/// certificate's CA. The difference between the two runs is the flag and
/// nothing else.
///
/// What it *cannot* show is that the absence of anchors never falls back to a
/// public root set, because that would need an origin holding a
/// **publicly-issued** certificate: every origin here trusts a CA this test
/// minted, and a bundled public bundle would refuse all of them exactly as an
/// empty store does. The mutation is also not expressible today, since
/// `webpki-roots` is not a dependency of this workspace. That half stays owed
/// and is written down in `15-ROADMAP.md`; claiming this test closes it would
/// be the same move the campaign refused to make.
#[test]
fn a_broker_given_no_destination_anchors_reaches_no_tls_destination() {
    let ca = SessionCa::new("vertical-roots", 37, Duration::from_secs(3600));

    // The control, first and in its own scope. A refusal with nothing to
    // refuse is not a measurement, and running it first means the asserting
    // broker is already gone when the second one starts — two brokers sharing
    // a machine is not a failure mode worth designing in.
    {
        let anchored = Fixture::new_tls("anchored", &ca, true);
        assert_eq!(
            anchored.one_shot_status(),
            "200",
            "a broker pointed at the origin's own CA did not reach it, so the refusal \
             measured below would prove nothing about the absence of anchors"
        );
        assert!(
            anchored.origin.saw().contains(REAL),
            "the anchored run reached the origin without the real credential, so this \
             fixture is not exercising the substitution it is meant to control for"
        );
        assert_eq!(
            anchored.origin.completed_handshakes(),
            1,
            "the anchored broker did not complete exactly one TLS handshake with the origin"
        );
    }

    // The default: the flag is absent, not present-and-empty.
    let unanchored = Fixture::new_tls("unanchored", &ca, false);
    assert_ne!(
        unanchored.one_shot_status(),
        "200",
        "a broker with no destination anchors served a TLS route anyway, so its empty \
         anchor store fell back to trusting something"
    );
    assert_eq!(
        unanchored.origin.completed_handshakes(),
        0,
        "the origin completed a TLS handshake although this broker was given no anchors, \
         so what was refused was the request rather than the connection"
    );
    assert!(
        !unanchored.origin.saw().contains(REAL),
        "a destination whose certificate could not be verified received the credential: {}",
        unanchored.origin.saw()
    );
}

/// **An operator's SIGTERM ends tunnels the way this product ends them.**
///
/// `ShutdownSignal::stop` is how a tunnel is meant to be torn down deliberately:
/// the accept loop stops accepting, and every tunnel in flight is cancelled
/// through the bridge's poll, recorded in the durable chain as
/// `cancelled`/`shutdown`. It had **no caller outside tests** — the sibling
/// defect `revoke` turned out to have one increment earlier, found again in the
/// method next to it. An operator's signal therefore did what the kernel does
/// to every process: it killed the broker, and the tunnels died as a side
/// effect of their file descriptors closing.
///
/// The difference is not tidiness and it is observable. A kernel teardown
/// leaves **no recorded reason** — an operator reading the chain sees a
/// connection that simply stopped. This test asserts the reason is there.
///
/// What it cannot show is a *drain*: the process leaves at the end of a bounded
/// window whether or not every tunnel finished inside it, and the log says when
/// the window elapsed. A true drain would need an in-flight gauge the product
/// does not have, and inventing one to make a test pass would be the larger
/// change.
#[test]
fn a_terminated_broker_ends_its_tunnels_by_shutdown_and_says_so() {
    let mut f = Fixture::new_stalling("ordered-shutdown");
    let variable = f.surrogate_env_name();
    let release_path = f.dir.join("held.release");
    // A single URL against an origin that promises 64 bytes and sends 2: curl
    // is left waiting for a body that never completes, and the broker is left
    // copying a response direction that never ends. That is the only state in
    // which "an ordered shutdown ended this tunnel" is a statement about a
    // relay rather than about a fixture.
    let script = format!(
        "curl -sS -k --max-time 60 -o /dev/null \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/resource; \
         while [ ! -f {release} ]; do sleep 0.2; done",
        port = f.origin.port,
        release = release_path.display()
    );

    // `Session` rather than a bare `Child`: its `Drop` releases the script and
    // reaps the process, and a test that signals a broker and then leaves a
    // client behind is a slower test for whoever runs it next.
    let session = Session {
        child: Some(
            Command::new(cargo_bin("asv"))
                .arg("--socket")
                .arg(&f.sock)
                .arg("run")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .env("NO_PROXY", "should-be-removed")
                .env("no_proxy", "should-be-removed")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the session under shutdown"),
        ),
        release: release_path.clone(),
    };

    // The destination is asked, not the client: a client inside its own tunnel
    // cannot tell a live tunnel from a socket it is holding open by itself.
    assert!(
        f.origin.wait_for_open(1, Duration::from_secs(90)),
        "the tunnel was never established, so a signal now would land on a broker \
         with nothing to end; the destination holds {} connections",
        f.origin.open_connections()
    );
    assert!(
        f.origin.wait_for_requests(1),
        "the destination never received a request, so the credential never crossed \
         this leg and there is nothing here for a shutdown to have protected"
    );

    // The signal, and the wait for the process to leave on its own.
    let pid = f.broker_pid();
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match f.try_wait_broker() {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "a broker asked to stop left with {:?} rather than a clean exit; \
                     a process killed by SIGTERM reports 128+15 and no code, and this \
                     one is supposed to choose its own ending",
                    status.code()
                );
                break;
            }
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            None => panic!("the broker did not leave within 30s of SIGTERM"),
        }
    }

    // The witness: the chain says *why* the tunnel ended, and it says the
    // reason the operator caused. Both halves are required, and the spellings
    // are the ones `ChainReport::record` writes — an outcome of `cancelled`
    // with a `detail` of `shutdown`. Asserting on the pair rather than on
    // either word alone is what keeps a test that passes for the wrong reason
    // from looking like one that passes.
    let chain = std::fs::read_to_string(&f.audit).expect("read the durable audit chain");
    assert!(
        chain.contains(r#""outcome":"cancelled""#) && chain.contains(r#""detail":"shutdown""#),
        "no tunnel in the chain was recorded as cancelled by shutdown, so this \
         broker's tunnels ended the way they always did — with the kernel closing \
         the sockets and the chain saying nothing about it:\n{chain}"
    );
    assert!(
        !chain.contains(REAL),
        "the real credential reached the audit chain:\n{chain}"
    );

    drop(session);
}

/// The real `npm`, through the whole path.
///
/// `curl` already proves the relay substitutes a bearer the client sends. This
/// proves the claim the product actually makes: that **npm**, the tool an
/// operator names, is secretless through the same path — no `curl` vocabulary,
/// no `-H` flag invented for the test.
///
/// Three things have to line up and none of them is obvious:
///
/// 1. npm sends its token **scoped** and refuses an unscoped one
///    (`ERR_INVALID_AUTH`), so the file is written inside the session rather
///    than beside it — the surrogate only exists in that environment;
/// 2. `asv run` publishes the relay through `HTTPS_PROXY`, and npm honours it
///    without being told anything about ASV;
/// 3. npm must accept the tunnel's TLS at all — which it does: with the
///    `NODE_EXTRA_CA_CERTS` anchor removed this test failed at
///    `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, having already reached the relay.
///
/// ## `--strict-ssl=false`, and what it costs
///
/// It is off, on purpose, and the reason is a property of the **fixture**: the
/// CA that `SessionCa` mints is not one node accepts, which is why the `curl`
/// vertical beside this one has always used `-k` and never verified anything
/// either. TLS verification of the destination is B5's subject and is not what
/// this test is about.
///
/// What the flag cannot weaken is the property under test. npm still presents
/// only its surrogate, the broker still has to redeem it, and the destination
/// still has to receive the real credential — none of which is a TLS decision.
/// Saying so is the point; a test that quietly turned verification off and left
/// the reader to assume otherwise would be the worse artefact.
///
/// The file is written with `printf` rather than `npm config set`, because the
/// shape under test is the one `project npm` emits, byte for byte.
///
/// ## What is asserted, and what is not
///
/// Asserted: the origin received at least one request, and **every** request it
/// received carried the real credential — which is the negative claim in a form
/// that does not need the test to know the surrogate's value.
///
/// Not asserted: npm's exit status. The fixture origin answers whatever it
/// answers, and whether that satisfies `npm view` is a property of the fixture's
/// body rather than of the secretless property under test.
#[test]
fn npm_whose_surrogate_the_broker_swaps_reaches_the_origin_as_the_real_credential() {
    let npm = require_npm();
    let ca = SessionCa::new("npm-vertical-roots", 37, Duration::from_secs(3600));
    let f = Fixture::new_tls("npm-vertical", &ca, true);
    let variable = f.surrogate_env_name();
    // `build` wrote this file and handed it to `--connect-roots`; the same bytes
    // have to reach node, or npm would be verifying against a different trust
    // decision than the broker is.
    let anchors = f.dir.join("roots.pem");
    assert!(
        anchors.exists(),
        "the fixture wrote no anchor file, so npm and the broker would not be \
         checking the same CA: {}",
        anchors.display()
    );

    let npmrc = f.dir.join("session.npmrc");
    // `${{{variable}}}` rather than `${variable}`: the shell expands that one,
    // because the surrogate only exists inside the session's environment. Rust
    // format! sees `${{` as a literal `${`, substitutes the variable name, and
    // closes with a literal `}`.
    let script = format!(
        "set -e; \
         printf 'registry=https://{HOST}:{PORT}\n//{HOST}:{PORT}/:_authToken=%s\n' \
             \"${{{variable}}}\" > {NPMRC}; \
         {NPM_BIN} view probe \
             --registry https://{HOST}:{PORT} \
             --userconfig {NPMRC} \
             --cache {CACHE} \
             --fetch-timeout 30000 \
             --strict-ssl=false",
        variable = variable,
        PORT = f.origin.port,
        HOST = FIXTURE_HOST,
        NPMRC = npmrc.display(),
        CACHE = f.dir.join("npmcache").display(),
        NPM_BIN = npm.display(),
    );

    let out = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .env("NODE_EXTRA_CA_CERTS", &anchors)
        .output()
        .expect("run the npm session");

    assert!(
        f.origin.wait_for_requests(1),
        "npm never got a request to the origin. npm said:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let seen = f.origin.saw();
    assert!(
        seen.contains(REAL),
        "the destination did not receive the real credential, so nothing was substituted:\n{seen}"
    );
    assert_eq!(
        f.origin.request_count(),
        f.origin.real_credential_requests(),
        "a request reached the destination without the real credential in it, which is a \
         tunnel that forwarded a surrogate upstream:\n{seen}"
    );

    // The audit chain, for the reason the curl vertical reads it: the
    // substitution is a fact an operator can verify after the fact, and a chain
    // that names the family but never the credential must not be mistaken for
    // one that did.
    let chain = std::fs::read_to_string(&f.audit).expect("read the durable audit chain");
    assert!(
        !chain.contains(REAL),
        "the real credential reached the audit chain:\n{chain}"
    );
}

/// The npm binary, or a failure that says what is missing.
///
/// **A refusal, not a skip.** npm is a required tool for this repository: the
/// vertical claims npm is secretless, and a suite that quietly passed without
/// npm would make that claim while never running it — the exact shape this
/// project keeps refusing. `UNAVAILABLE_SUBSTRATE` is a state a *requirement*
/// may end in; it is not what a gate does.
fn require_npm() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("npm");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "npm is not on PATH. It is a required tool for this repository: the npm vertical \
         cannot run without it, and this test fails rather than passing without it."
    );
}
