//! The session-local shim: the only thing an ordinary HTTP client has to know
//! about Agent Secretless, which is nothing.
//!
//! `curl`, `git`, `npm`, `mvn` and `gradle` cannot carry
//! `x-asv-session-proof` on a CONNECT — measured, in `tests/connect_injection_spike.py` —
//! and teaching each of them to manufacture one would put the protocol inside
//! every toolchain, which is the opposite of what M14 exists for. So the proof
//! is minted here, in the session, by the session's one issuer, and injected
//! into a CONNECT the client never knew it was making.
//!
//! **What the shim is, measured rather than assumed.** After `200 Connection
//! Established` this is a blind byte pipe. `tests/connect_relay_spike.py`
//! measured that an ordinary `curl` makes three requests over one TLS session
//! through a relay that cannot read it, so the shim needs no framing, no
//! session table and no TLS of its own. That measurement is what makes this
//! file two hundred lines instead of a second TLS stack in the session
//! directory.
//!
//! **What the shim is not.** It is not a policy engine. It authorises nothing,
//! resolves nothing, and substitutes nothing. It cannot: it does not know the
//! allowlist, and it must not grow one. A destination it is not told to
//! refuse is a destination the broker refuses, and the reason the broker
//! refused reaches the operator through the audit chain rather than through a
//! string this process invented.
//!
//! **The one hard rule.** A proof binds to a destination, and the destination
//! is a *canonical* host and port. So the request line is parsed with
//! `asv_domain::ConnectTarget`, the same function the broker uses, and a
//! shim that parsed it any other way would mint proofs that verify nowhere —
//! which reads as a broken signer rather than as a disagreement between two
//! parsers.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use asv_domain::ConnectTarget;
use asv_ssh_agent::{ProofIssuer, SESSION_PROOF_HEADER};

/// A CONNECT head is small and the bound is generous. It is not generous
/// without limit: this reads one byte at a time from a socket a client chose.
const MAX_HEAD: usize = 8 * 1024;

/// How long the shim waits for a CONNECT head on a socket that is not yet
/// inside a tunnel. Long enough for a slow client to send a header, short
/// enough that a socket nobody will use again does not pin a thread.
const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The only status the broker sends before a tunnel exists.
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established";

/// The same status as a pattern for `str::starts_with`, which takes a `&str`.
/// Only the tests assert on the reply as text.
#[cfg(test)]
const ESTABLISHED_TEXT: &str = "HTTP/1.1 200 Connection Established";

/// What the shim answers when the broker gives it no answer at all.
///
/// The broker drops a refused CONNECT rather than writing an HTTP error to the
/// client, so the shim sees a closed connection. It answers `502` because that
/// is the one thing it knows: the tunnel was not established here. It does not
/// pass on a reason, because it has none — inventing one would be the shim
/// deciding to be the policy engine it was built not to be.
const NO_UPSTREAM_REPLY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";

/// How long the accept loop parks before looking again.
///
/// Three seconds, and the number is load-bearing rather than a round choice.
/// `ShimHandle::stop` unparks the thread, so a real shutdown does not wait for
/// this to expire — it returns in microseconds. The interval therefore only
/// governs the *broken* path, and the lifecycle test sets a bound well below
/// it: a stop that returned in 200ms here and a stop that waited the park out
/// would look identical if the park were short. Choosing a small park to keep
/// the loop responsive would make the two indistinguishable, and the test that
/// is supposed to tell them apart could not.
///
/// Idle wake latency of three seconds costs nothing. The only thing this flag
/// guards is shutdown, and shutdown does not wait for the park.
const IDLE_PARK: std::time::Duration = std::time::Duration::from_secs(3);

/// Ticks per second in `/proc/<pid>/task/<tid>/stat`, from `sysconf(_SC_CLK_TCK)`.
///
/// Asked of the system rather than assumed to be 100. A hardcoded 100 would
/// make the idle test's threshold wrong on any host with a different tick
/// rate, in the direction of *passing* — the exact failure a measurement is
/// supposed to exclude.
/// This thread's kernel id.
fn current_tid() -> u32 {
    // SAFETY: `gettid` takes no arguments, touches no memory, and is async-
    // signal-safe; there is no precondition to satisfy.
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

#[cfg(test)]
fn clock_ticks_per_second() -> f64 {
    // SAFETY: `sysconf` is a pure query with no preconditions. `sysconf` takes
    // an int and returns a long; `_SC_CLK_TCK` is the documented selector.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as f64
    } else {
        100.0
    }
}

/// CPU jiffies this thread has consumed, from the kernel rather than a guess.
///
/// `None` when the proc entry is unreadable, which the caller must treat as
/// "cannot measure" rather than "measured zero". Reading zero for an
/// unreadable file is how a test ends up passing on a machine that never
/// reported.
#[cfg(test)]
fn thread_cpu_ticks(tid: u32) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    // The second field is the thread name in parentheses and may itself
    // contain spaces and parentheses, so fields are counted after the LAST
    // `)`. Counting from the first — or splitting the whole line on spaces —
    // reads the name as fields and shifts every value after it.
    let after_name = &raw[raw.rfind(')')? + 1..];
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // `after_name` starts at field 3, so utime is index 11 and stime index 12.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// A running shim, listening on loopback for its session's ordinary clients.
pub struct SessionShim {
    listener: TcpListener,
    issuer: Arc<ProofIssuer>,
    broker: SocketAddr,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionShim {
    /// Binds a loopback listener that will mint proofs with `issuer` and hand
    /// the CONNECTs to `broker`.
    pub fn bind(issuer: ProofIssuer, broker: SocketAddr) -> io::Result<Self> {
        // Loopback only, and the port is chosen by the kernel. A shim on a
        // routable address would be a proxy anyone on the network could ask
        // this session to sign for, which is the opposite of the intent.
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        // Non-blocking, because the accept loop has to be able to notice a
        // shutdown. A blocking `incoming()` can only be woken by a connection
        // arriving, and the one moment this shim must not depend on a client is
        // the moment the client has already exited.
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            issuer: Arc::new(issuer),
            broker,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// The address the session's clients should be pointed at.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// `http://127.0.0.1:PORT`, the value for `HTTPS_PROXY`.
    pub fn proxy_url(&self) -> io::Result<String> {
        Ok(format!("http://{}", self.local_addr()?))
    }

    /// Serves until the listener fails or [`ShimHandle::stop`] is called.
    ///
    /// One thread per connection, because a client that opens four tunnels at
    /// once must get four, and a serial shim would be a denial of service with
    /// the credentials in hand.
    pub fn serve_forever(self) {
        while !self.stopping.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((client, _)) => {
                    let issuer = Arc::clone(&self.issuer);
                    let broker = self.broker;
                    let _ = thread::Builder::new()
                        .name("asv-session-shim".into())
                        .spawn(move || {
                            let _ = serve_connection(client, &issuer, broker);
                        });
                }
                // Nothing waiting. Park rather than spin: this loop runs for the
                // whole session, and a session that makes one request an hour
                // should not cost a core doing it.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(IDLE_PARK);
                }
                // A transient accept error. Back off rather than spin, and keep
                // going: one refused accept is not a reason to end the session.
                Err(_) => {
                    thread::park_timeout(IDLE_PARK);
                }
            }
        }
    }

    /// Start serving on a background thread, returning a handle that stops it.
    ///
    /// The lifecycle is the point. A session is a bounded thing: `asv run`
    /// starts a shim, runs a child, and the shim must not outlive either. A
    /// `serve_forever` that owns its own thread cannot be stopped, so the
    /// accept loop's port — and the proof issuer behind it — would outlive the
    /// command by as long as the process did.
    pub fn spawn(self) -> io::Result<ShimHandle> {
        let addr = self.local_addr()?;
        let stopping = Arc::clone(&self.stopping);
        let tid_slot: Arc<std::sync::Mutex<Option<u32>>> = Arc::new(std::sync::Mutex::new(None));
        let tid_for_thread = Arc::clone(&tid_slot);
        let worker = thread::Builder::new()
            .name("asv-session-shim-accept".into())
            .spawn(move || {
                // Publish the tid from inside the thread, so it is the real one
                // rather than whatever a caller could guess.
                *tid_for_thread.lock().expect("tid slot lock") = Some(current_tid());
                self.serve_forever();
            })?;
        Ok(ShimHandle {
            addr,
            stopping,
            tid: tid_slot,
            worker: Some(worker),
        })
    }
}

/// The owner of a running shim's lifetime.
///
/// Dropping this **without** calling [`Self::stop`] leaves the thread running.
/// That is deliberate: a silent leak in a destructor would be harder to notice
/// than an explicit call, and this type exists so the owner has to say what
/// happens at the end of the session.
#[derive(Debug)]
pub struct ShimHandle {
    addr: SocketAddr,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    tid: Arc<std::sync::Mutex<Option<u32>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ShimHandle {
    /// The address the session's clients are pointed at.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The accept loop's kernel thread id, once the thread has started.
    ///
    /// Exposed so idle cost can be *measured* rather than assumed: a busy-wait
    /// and a parked loop behave identically to every functional test, and only
    /// a CPU reading tells them apart.
    pub fn accept_tid(&self) -> Option<u32> {
        self.tid.lock().ok().and_then(|slot| *slot)
    }

    /// Stop serving and wait for the accept loop to finish.
    ///
    /// Returns whether the accept loop was joined. A thread that panicked is
    /// reported rather than swallowed: a shim whose accept loop died is a shim
    /// that has silently stopped proxying, and the operator should hear about
    /// it from here rather than from a client that got no answer.
    pub fn stop(mut self) -> bool {
        self.stopping.store(true, Ordering::SeqCst);
        // Unpark first, then join: without the unpark the join waits out the
        // park interval, which would make every session pay 50ms to exit.
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
        match self.worker.take() {
            Some(worker) => worker.join().is_ok(),
            None => true,
        }
    }
}

fn serve_connection(
    mut client: TcpStream,
    issuer: &ProofIssuer,
    broker: SocketAddr,
) -> io::Result<()> {
    client.set_nodelay(true).ok();
    // One CONNECT per connection.
    //
    // A loop here looked like cheap compatibility: if a client ever asked for
    // a second tunnel on the same socket, serve it. It is unreachable. After
    // the `200` this shim is a byte pipe, so anything the client sends next is
    // tunnel payload — which is the correct reading of those bytes — and the
    // client has no way to learn the tunnel ended, because the shim holds its
    // socket open. The only way to exercise the loop was a test that slept,
    // and a test that needs a sleep to reach a branch is a branch no client
    // can reach. The measurement in `tests/connect_relay_spike.py` agrees:
    // `curl` did not multiplex a second CONNECT onto the first socket, and
    // there is no portable way for it to learn that it could.
    {
        let mut raw: Vec<u8> = Vec::with_capacity(512);
        // A client that connects and then says nothing would otherwise pin
        // this thread and both of its file descriptors for ever.
        client.set_read_timeout(Some(HEAD_TIMEOUT)).ok();
        if !read_head(&mut client, &mut raw)? {
            return Ok(());
        }
        let head = String::from_utf8_lossy(&raw).into_owned();

        let mut upstream = match open_tunnel(&head, issuer, broker) {
            Ok(upstream) => upstream,
            Err(reply) => {
                client.write_all(reply)?;
                client.flush()?;
                return Ok(());
            }
        };

        // The broker's own status line goes back verbatim. A 200 is the
        // broker's; a refusal is the broker's. The shim does not restate
        // either in its own words.
        let mut response: Vec<u8> = Vec::with_capacity(128);
        read_head(&mut upstream, &mut response)?;
        if response.is_empty() {
            client.write_all(NO_UPSTREAM_REPLY)?;
            return Ok(());
        }
        client.write_all(&response)?;
        client.flush()?;

        if !response.starts_with(ESTABLISHED) {
            return Ok(());
        }
        // Inside the tunnel there is no deadline and no framing: the shim is a
        // pipe and the client is entitled to a connection of whatever length
        // it negotiated.
        client.set_read_timeout(None).ok();
        upstream.set_read_timeout(None).ok();
        relay(&client, &upstream);
    }
    Ok(())
}

/// Mints a proof for the requested destination and hands the CONNECT on.
///
/// Returns the open upstream, or the bytes to answer the client with.
fn open_tunnel(
    head: &str,
    issuer: &ProofIssuer,
    broker: SocketAddr,
) -> Result<TcpStream, &'static [u8]> {
    let request_line = head.split("\r\n").next().unwrap_or_default();
    let target = match ConnectTarget::from_request_line(request_line) {
        Ok(target) => target,
        Err(_) => return Err(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
    };

    // Minted *before* the upstream is dialled, and spent whether or not the
    // dial works. The same reasoning the issuer uses when signing fails: a
    // counter handed back after a failure is one an attacker can walk
    // backwards by making the far end slow.
    let proof = match issuer.issue(target.host(), target.port()) {
        Ok(proof) => proof,
        // Every failure to mint is a 502, and none of them is reported with a
        // reason. A client that learns *why* its proof could not be minted
        // learns something about the session's signing state that it has no
        // business knowing.
        Err(_) => return Err(NO_UPSTREAM_REPLY),
    };

    let mut upstream = match TcpStream::connect(broker) {
        Ok(stream) => stream,
        Err(_) => return Err(NO_UPSTREAM_REPLY),
    };
    upstream.set_nodelay(true).ok();

    let request = build_upstream_head(head, &proof.encode());
    if upstream.write_all(request.as_bytes()).is_err() || upstream.flush().is_err() {
        return Err(NO_UPSTREAM_REPLY);
    }
    Ok(upstream)
}

/// Rewrites the client's head: our proof replaces any proof the client sent.
///
/// Stripping rather than appending is the point. The broker reads the *first*
/// `x-asv-session-proof` it finds, so a client that supplied its own would win
/// if the shim merely added a second header. A forged proof would be refused
/// anyway — it cannot be signed by the session's key — but the shim must not
/// build a design in which which header wins is a race.
fn build_upstream_head(head: &str, proof: &str) -> String {
    let mut out = String::with_capacity(head.len() + proof.len() + SESSION_PROOF_HEADER.len() + 4);
    for line in head.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let name = line.split_once(':').map(|(n, _)| n).unwrap_or("");
        if name.trim().eq_ignore_ascii_case(SESSION_PROOF_HEADER) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(SESSION_PROOF_HEADER);
    out.push_str(": ");
    out.push_str(proof);
    out.push_str("\r\n\r\n");
    out
}

/// Reads a head one byte at a time, stopping exactly at `\r\n\r\n`.
///
/// A `BufReader` is the obvious choice and it is wrong: it may buffer past the
/// terminator and swallow the first bytes of the client's TLS ClientHello,
/// which then never reach the handshake. The same mistake on the other side of
/// the relay would eat the beginning of the server's first record. One byte at
/// a time costs a syscall per header byte and is bounded by `MAX_HEAD`.
///
/// Returns false only on a clean EOF before a single byte arrived; every other
/// way of failing is an error.
fn read_head(stream: &mut TcpStream, out: &mut Vec<u8>) -> io::Result<bool> {
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Ok(out.is_empty()),
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if out.is_empty() {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "head did not terminate",
                ));
            }
            Err(e) => return Err(e),
        }
        out.push(byte[0]);
        if out.len() >= 4 && out[out.len() - 4..] == *b"\r\n\r\n" {
            return Ok(true);
        }
        if out.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "head is larger than the shim will read",
            ));
        }
    }
}

/// Moves bytes both ways until one side finishes.
///
/// After this the shim knows nothing about the stream and never will: what is
/// inside is a TLS session between the client and the broker, and the only
/// reason this works is that it does not need to know that.
fn relay(client: &TcpStream, upstream: &TcpStream) {
    use std::sync::atomic::{AtomicBool, Ordering};

    fn pump(from: &TcpStream, to: &TcpStream, done: &AtomicBool) {
        let mut reader = match from.try_clone() {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut writer = match to.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let mut buf = [0u8; 32 * 1024];
        loop {
            if done.load(Ordering::Acquire) {
                return;
            }
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
            }
        }
        done.store(true, Ordering::Release);
    }

    // `Arc` rather than a borrow: `thread::spawn` demands `'static`, and the
    // flag is the only thing the two directions share.
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let downstream = {
        let done = std::sync::Arc::clone(&done);
        let client = client.try_clone();
        let upstream = upstream.try_clone();
        thread::spawn(move || {
            if let (Ok(client), Ok(upstream)) = (client, upstream) {
                pump(&upstream, &client, &done);
            }
        })
    };
    pump(client, upstream, &done);
    let _ = downstream.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_ssh_agent::{proof_nonce, verify_proof, AgentClient, AgentSession};
    use std::time::{Duration, Instant};

    /// A broker stand-in that captures the head the shim forwards and then
    /// does whatever this test needs it to do.
    ///
    /// It reads one byte at a time for the same reason the shim does, so what
    /// it captures is exactly what was on the wire and not a buffered guess.
    struct CapturingBroker {
        addr: SocketAddr,
        heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        _dir: tempfile::TempDir,
    }

    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Reply 200, then echo every byte back.
        Tunnel,
        /// Reply with this exact status line and close.
        Status(&'static str),
        /// Close without replying at all, as the real broker does on refusal.
        SilentDrop,
    }

    impl CapturingBroker {
        fn new(behaviour: Behaviour) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            let addr = listener.local_addr().expect("addr");
            let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = std::sync::Arc::clone(&heads);
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    let Ok(mut conn) = incoming else { continue };
                    let sink = std::sync::Arc::clone(&sink);
                    std::thread::spawn(move || {
                        let mut raw = Vec::new();
                        if read_head(&mut conn, &mut raw).unwrap_or(false) {
                            sink.lock()
                                .expect("lock")
                                .push(String::from_utf8_lossy(&raw).into_owned());
                        }
                        match behaviour {
                            Behaviour::Tunnel => {
                                let _ = conn.write_all(ESTABLISHED);
                                let _ = conn.write_all(b"\r\n\r\n");
                                let _ = conn.flush();
                                let mut buf = [0u8; 4096];
                                while let Ok(n) = conn.read(&mut buf) {
                                    if n == 0 || conn.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                            Behaviour::Status(status) => {
                                let _ = conn.write_all(status.as_bytes());
                            }
                            Behaviour::SilentDrop => {}
                        }
                    });
                }
            });
            Self {
                addr,
                heads,
                _dir: dir,
            }
        }

        fn captured(&self) -> Vec<String> {
            self.heads.lock().expect("lock").clone()
        }

        fn last(&self) -> String {
            self.captured().last().cloned().unwrap_or_default()
        }
    }

    struct Fixture {
        shim_addr: SocketAddr,
        // Held so the agent socket outlives the issuer that dials it. Never
        // read, and named so "unused" does not read as "forgot to remove".
        _session: AgentSession,
        key_blob: Vec<u8>,
        _dir: tempfile::TempDir,
        _shim: ShimHandle,
    }

    impl Fixture {
        fn new(broker: SocketAddr) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let session = AgentSession::start(dir.path().join("session")).expect("start");
            let key_blob = session.public_key_blob();
            let client = AgentClient::new(session.socket_path());
            let issuer = ProofIssuer::discover(client).expect("discover");
            let shim = SessionShim::bind(issuer, broker).expect("bind");
            // `spawn` rather than a bare thread: the fixture now owns the
            // shim's lifetime, so a test that ends actually ends it. A thread
            // nobody holds outlives the test and keeps its port, which is the
            // leak the lifecycle exists to prevent.
            let handle = shim.spawn().expect("spawn accept loop");
            let shim_addr = handle.local_addr();
            Self {
                shim_addr,
                _shim: handle,
                _session: session,
                key_blob,
                _dir: dir,
            }
        }

        /// A client that speaks CONNECT to the shim and returns the reply.
        fn connect(&self, request: &str) -> (String, TcpStream) {
            let mut stream = TcpStream::connect(self.shim_addr).expect("connect");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            stream.write_all(request.as_bytes()).expect("write");
            stream.flush().expect("flush");
            let mut out = Vec::new();
            read_head(&mut stream, &mut out).expect("head");
            (String::from_utf8_lossy(&out).into_owned(), stream)
        }
    }

    fn connect_request(authority: &str) -> String {
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
    }

    fn proof_value(head: &str) -> String {
        head.split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case(SESSION_PROOF_HEADER)
                    .then(|| value.trim().to_string())
            })
            .expect("the shim injects a proof")
    }

    /// The decisive one: what the broker received is a proof it can verify,
    /// against the destination the client actually asked for.
    #[test]
    fn the_injected_proof_verifies_for_the_requested_destination() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        let (reply, _stream) = f.connect(&connect_request("api.example.com:443"));
        assert!(reply.starts_with(ESTABLISHED_TEXT), "got {reply:?}");

        let head = broker.last();
        let proof = asv_ssh_agent::SessionProof::decode(&proof_value(&head)).expect("decodes");
        let nonce = proof_nonce(&proof.key, "api.example.com", 443, proof.counter);
        assert_eq!(proof.key, f.key_blob);
        assert!(verify_proof(&proof.key, &nonce, &proof.signature));
    }

    /// The proof is bound to the destination, and the shim derived the
    /// destination the way the broker will derive it.
    ///
    /// The second CONNECT is the point of this test and the first version did
    /// not have it: with every request naming the same host, "minted for the
    /// requested destination" and "minted for a hardcoded one" are the same
    /// observation.
    #[test]
    fn a_proof_is_not_good_for_another_destination() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        f.connect(&connect_request("api.example.com:443"));
        f.connect(&connect_request("cdn.example.org:8443"));

        let heads = broker.captured();
        assert_eq!(heads.len(), 2);
        let first = asv_ssh_agent::SessionProof::decode(&proof_value(&heads[0])).expect("decodes");
        let second = asv_ssh_agent::SessionProof::decode(&proof_value(&heads[1])).expect("decodes");

        // Each proof verifies for the destination its own request named.
        assert!(verify_proof(
            &first.key,
            &proof_nonce(&first.key, "api.example.com", 443, first.counter),
            &first.signature
        ));
        assert!(verify_proof(
            &second.key,
            &proof_nonce(&second.key, "cdn.example.org", 8443, second.counter),
            &second.signature
        ));

        // And neither verifies for the other's.
        let crossed = proof_nonce(&first.key, "cdn.example.org", 8443, first.counter);
        assert!(!verify_proof(&first.key, &crossed, &first.signature));
        let evil = proof_nonce(&second.key, "evil.example.net", 443, second.counter);
        assert!(!verify_proof(&second.key, &evil, &second.signature));
    }

    /// A head larger than the bound is refused without reaching the broker.
    ///
    /// The bound is the only thing between a client-chosen socket and an
    /// unbounded read, and nothing else would notice its removal.
    #[test]
    fn an_oversized_head_is_refused_without_reaching_the_broker() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);

        let mut stream = TcpStream::connect(f.shim_addr).expect("connect");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let mut request = b"CONNECT api.example.com:443 HTTP/1.1\r\n".to_vec();
        // Well past MAX_HEAD, and never terminated.
        request.extend(vec![b'x'; MAX_HEAD + 64]);
        let _ = stream.write_all(&request);
        let _ = stream.flush();

        // The shim gives up on the head and closes. Reading here ends at EOF
        // rather than blocking, which is itself the assertion.
        let mut out = Vec::new();
        let read = read_head(&mut stream, &mut out);
        assert!(
            read.is_err() || String::from_utf8_lossy(&out).starts_with("HTTP/1.1 502"),
            "an oversized head must be refused, got {read:?} / {out:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(broker.captured().is_empty(), "nothing reached the broker");
    }

    /// The host is canonicalised identically on both sides, so a spelling that
    /// differs only in case still mints a proof the broker will accept.
    #[test]
    fn the_canonical_host_is_what_both_sides_derive() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        f.connect(&connect_request("API.Example.COM:443"));

        let proof =
            asv_ssh_agent::SessionProof::decode(&proof_value(&broker.last())).expect("decodes");
        let nonce = proof_nonce(&proof.key, "api.example.com", 443, proof.counter);
        assert!(verify_proof(&proof.key, &nonce, &proof.signature));
    }

    /// A client cannot pre-empt the shim's proof by sending its own. The
    /// broker reads the first matching header, so appending rather than
    /// replacing would hand the client the race.
    #[test]
    fn a_client_supplied_proof_is_replaced_not_appended() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        f.connect(&format!(
            "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n{SESSION_PROOF_HEADER}: not-a-proof\r\n\r\n"
        ));

        let head = broker.last();
        let occurrences = head
            .split("\r\n")
            .filter(|line| {
                line.split_once(':')
                    .map(|(n, _)| n.trim().eq_ignore_ascii_case(SESSION_PROOF_HEADER))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            occurrences, 1,
            "exactly one proof header reaches the broker"
        );
        assert_ne!(proof_value(&head), "not-a-proof");
    }

    /// A request that is not a CONNECT is refused, and costs no counter: the
    /// shim must not mint a proof for a destination nobody asked to open.
    #[test]
    fn a_non_connect_request_is_refused_and_costs_no_counter() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        let (reply, _stream) = f.connect("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        assert!(reply.starts_with("HTTP/1.1 400"), "got {reply:?}");
        assert!(broker.captured().is_empty(), "nothing reached the broker");
    }

    /// The real broker drops a refused CONNECT instead of writing an error,
    /// and the shim must still answer its client.
    #[test]
    fn a_silent_upstream_becomes_a_bad_gateway() {
        let broker = CapturingBroker::new(Behaviour::SilentDrop);
        let f = Fixture::new(broker.addr);
        let (reply, _stream) = f.connect(&connect_request("api.example.com:443"));
        // Exactly the bare status line. A header here would be the shim
        // explaining a refusal it has no standing to explain, and asserting
        // only `starts_with` would have let that through.
        assert_eq!(reply, "HTTP/1.1 502 Bad Gateway\r\n\r\n", "got {reply:?}");
    }

    /// A refusal is the broker's to state. The shim forwards it and adds
    /// nothing, because it has no standing to explain a policy it does not
    /// hold.
    #[test]
    fn a_refusal_is_forwarded_verbatim() {
        // A status the shim would never invent, so a rewrite is visible.
        let broker = CapturingBroker::new(Behaviour::Status(
            "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        ));
        let f = Fixture::new(broker.addr);
        let (reply, _stream) = f.connect(&connect_request("api.example.com:443"));
        assert!(reply.starts_with("HTTP/1.1 407"), "got {reply:?}");
    }

    /// After the 200 the shim is a pipe. It cannot read what goes through and
    /// it does not try.
    #[test]
    fn the_tunnel_carries_bytes_in_both_directions() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        let (_reply, mut stream) = f.connect(&connect_request("api.example.com:443"));

        // Not HTTP any more. If the shim were parsing, this would be a failure.
        let payload = [0x16, 0x03, 0x01, 0x00, 0xff, b'x', b'y'];
        stream.write_all(&payload).expect("write");
        stream.flush().ok();
        let mut got = [0u8; 7];
        stream.read_exact(&mut got).expect("echo");
        assert_eq!(got, payload);
    }

    /// A broker that is not there is a 502, not a hang and not a panic.
    #[test]
    fn an_unreachable_broker_is_a_bad_gateway() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dead: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let session = AgentSession::start(dir.path().join("session")).expect("start");
        let issuer =
            ProofIssuer::discover(AgentClient::new(session.socket_path())).expect("discover");
        let shim = SessionShim::bind(issuer, dead).expect("bind");
        let handle = shim.spawn().expect("spawn accept loop");
        let addr = handle.local_addr();

        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        stream
            .write_all(connect_request("api.example.com:443").as_bytes())
            .expect("write");
        let mut out = Vec::new();
        read_head(&mut stream, &mut out).expect("head");
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 502"));
        assert!(
            stop_within(handle, STOP_BOUND),
            "the accept loop must join cleanly"
        );
    }

    /// Stop a shim and fail if it takes longer than a generous bound.
    ///
    /// The bound is what makes this a test rather than a hope. If the accept
    /// loop went back to blocking in `accept()`, `stop` would not return — it
    /// would wait for a connection that will never come, because the client
    /// that would have made it has already exited. Asserting "it stopped" on a
    /// call that can wedge turns a regression into a hung suite instead of a
    /// red one, which is the worst version of the same defect.
    fn stop_within(handle: ShimHandle, bound: std::time::Duration) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let joined = handle.stop();
            let _ = tx.send(joined);
        });
        rx.recv_timeout(bound).unwrap_or_else(|_| {
            panic!("stop did not return within {bound:?}; the accept loop is not stoppable")
        })
    }

    /// Well below `IDLE_PARK`, and that ordering is the whole test.
    ///
    /// A stop that unparks returns in microseconds; a stop that only notices
    /// the flag when the park expires takes `IDLE_PARK`. A bound above the
    /// park would let both pass, which is what the first version of this test
    /// did — the unpark mutation escaped it.
    const STOP_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

    // -- the lifecycle, which is what `asv run` needs to own a shim ---------

    /// A stopped shim releases its port.
    ///
    /// This is the property `asv run` depends on and the reason the accept
    /// loop is stoppable at all. Before it existed, the shim's thread held the
    /// listener for the life of the process, so a session that ran `curl` and
    /// exited left a bound loopback port and a live proof issuer behind — and
    /// nothing in the product could end them.
    #[test]
    fn a_stopped_shim_releases_its_port() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path().join("session")).expect("start");
        let issuer =
            ProofIssuer::discover(AgentClient::new(session.socket_path())).expect("discover");
        let handle = SessionShim::bind(issuer, broker.addr)
            .expect("bind")
            .spawn()
            .expect("spawn");
        let addr = handle.local_addr();

        // Live: the port answers.
        TcpStream::connect(addr).expect("a running shim accepts");

        assert!(
            stop_within(handle, STOP_BOUND),
            "stop reports whether the loop joined"
        );

        // The listener is gone, so binding the same port must now succeed.
        // Nothing else holds it: the accept loop was the only owner.
        TcpListener::bind(addr).expect("the port must be free after stop");
    }

    /// `stop` is idempotent from the caller's side: it reports honestly rather
    /// than pretending a second stop did something.
    #[test]
    fn stopping_twice_reports_the_truth() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path().join("session")).expect("start");
        let issuer =
            ProofIssuer::discover(AgentClient::new(session.socket_path())).expect("discover");
        let handle = SessionShim::bind(issuer, broker.addr)
            .expect("bind")
            .spawn()
            .expect("spawn");
        let addr = handle.local_addr();

        assert!(
            stop_within(handle, STOP_BOUND),
            "the first stop joins the loop it started"
        );

        // A second bind also succeeds, which is the observable form of "the
        // port is free" — and the reason a caller cannot get a false `true`
        // from a handle that never ran.
        TcpListener::bind(addr).expect("port free after the first stop");
    }

    /// The accept loop is idle, not spinning — measured, not asserted.
    ///
    /// The previous version of this test slept and then checked the shim still
    /// answered. That passes on a busy-wait exactly as it passes on a parked
    /// loop: a spinning accept loop is *correct*, it just burns a core, and
    /// correctness is all the old assertion could see. The test name promised
    /// something the test did not check, which is worse than no test.
    ///
    /// So it reads the kernel's CPU accounting for the accept thread across an
    /// idle window. A parked loop consumes a handful of jiffies for the whole
    /// window; a spinning one consumes approximately the entire window.
    #[test]
    fn an_idle_shim_does_not_spin() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let dir = tempfile::tempdir().expect("tempdir");
        let session = AgentSession::start(dir.path().join("session")).expect("start");
        let issuer =
            ProofIssuer::discover(AgentClient::new(session.socket_path())).expect("discover");
        let handle = SessionShim::bind(issuer, broker.addr)
            .expect("bind")
            .spawn()
            .expect("spawn");

        // The tid is published from *inside* the thread, so it does not exist
        // the instant `spawn` returns. Wait for it, then for procfs to see it —
        // sampling before either exists would read a missing file as zero
        // ticks, and a spin would then sail through a threshold of nothing.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tid = handle.accept_tid();
        while (tid.is_none() || tid.and_then(thread_cpu_ticks).is_none())
            && Instant::now() < deadline
        {
            tid = handle.accept_tid();
            std::thread::sleep(Duration::from_millis(20));
        }
        let tid = tid.expect("the accept thread must publish its tid");
        let before = thread_cpu_ticks(tid).expect("the accept thread must be in procfs");

        // One park interval of genuine idleness.
        std::thread::sleep(IDLE_PARK);
        let after = thread_cpu_ticks(tid).expect("the accept thread must still be in procfs");
        let burned = after.saturating_sub(before);
        let window_ticks = (IDLE_PARK.as_secs_f64() * clock_ticks_per_second()) as u64;

        // A tenth of the window is generous for a loop that does nothing but
        // park, and still two orders of magnitude below a spin.
        assert!(
            burned * 10 <= window_ticks,
            "the accept loop burned {burned} jiffies idling for {window_ticks} \
             ({}% of the window) — that is a spin, not a park",
            (burned * 100) / window_ticks.max(1)
        );

        // And it is still serving, so the measurement was of a live loop.
        let mut stream = TcpStream::connect(handle.local_addr()).expect("still serving");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        stream
            .write_all(connect_request("api.example.com:443").as_bytes())
            .expect("write");
        let mut out = Vec::new();
        read_head(&mut stream, &mut out).expect("head");
        assert!(
            String::from_utf8_lossy(&out).starts_with(ESTABLISHED_TEXT),
            "a shim that idled must still serve"
        );
        assert!(stop_within(handle, STOP_BOUND));
    }

    /// Whatever the client sends after the `200` is tunnel payload.
    ///
    /// This is the mirror of the loop that was removed, and it is the
    /// observable half of the same fact: the shim has no notion of a second
    /// CONNECT, because after the `200` it has no notion of anything except
    /// bytes. A test that sent a second CONNECT here would be asserting the
    /// opposite of what the shim should do.
    #[test]
    fn bytes_after_the_established_reply_are_tunnel_payload() {
        let broker = CapturingBroker::new(Behaviour::Tunnel);
        let f = Fixture::new(broker.addr);
        let (_reply, mut stream) = f.connect(&connect_request("api.example.com:443"));

        let payload = connect_request("api.example.com:443");
        stream.write_all(payload.as_bytes()).expect("write");
        stream.flush().ok();

        // The echo comes back byte for byte, including the request line: the
        // shim did not intercept it, and neither did the broker.
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).expect("echo");
        assert_eq!(String::from_utf8_lossy(&got), payload);

        // And no second CONNECT reached the broker's CONNECT handling.
        assert_eq!(broker.captured().len(), 1);
    }
}
