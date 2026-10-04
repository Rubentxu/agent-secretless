//! UAT-010 — surrogate substitution reaches the provider and the client never
//! sees the secret, on the CONNECT path.
//!
//! UAT-010 was already satisfied on the broker's semantic path
//! (`uat_005_replay.rs`: the origin receives the real credential, the success
//! path leaks nothing, the operation is audited and its chain verifies). What
//! it did **not** cover was the CONNECT proxy path, and the reason was not a
//! missing parser: an ordinary CLI behind `HTTPS_PROXY` presents a CONNECT and
//! carries no session, and a surrogate is only redeemable through the session
//! that minted it. So the gap was identity, and ADR-0019 closed it with a
//! signed nonce instead of a claimed id.
//!
//! Everything below is real. The client is a full `rustls::ClientConfig` with
//! server-name verification on — not `dangerous()`, not a bypass. The session
//! keys are real ed25519 keys and the proofs are real signatures, checked by
//! the real `asv_ssh_agent::verify_proof`. The surrogate is minted by the real
//! `SurrogateRegistry`, redeemed through the real `SubstitutionPort`, and the
//! real credential reaches the real origin over a real socket. A test that
//! mocked the port would prove the bridge can splice two byte arrays.
//!
//! **The suite cannot pass vacuously.** `a_valid_proof_resolves_its_session`
//! asserts the origin *received* the canary credential; if substitution never
//! happened the assertion fails rather than passing on an absence of errors.
//! Every test that expects a failure additionally asserts the origin was sent
//! **zero** bytes, so "refused" cannot be satisfied by a relay that quietly
//! forwarded the request with the surrogate still in the header.
//!
//! **One criterion was corrected against its own spec text.** `spec.md` A3
//! reads "a reused nonce does not resolve: the same proof in a second tunnel
//! is refused". That cannot hold, and `design.md` F1 says why in advance: the
//! nonce is derived from the *destination*, not from a per-tunnel nonce the
//! server issues, so a proof replayed against the same destination verifies
//! again. A server-issued nonce would need a round trip before the CONNECT,
//! which an ordinary HTTP client cannot pay. What the design does buy is that
//! a proof does not transfer to a different destination, and that is what
//! `a_proof_does_not_transfer_to_another_destination` pins. Replay against the
//! same destination is not a grant, because the surrogate it would be spent
//! with is single-use and was already spent the first time.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asv_broker::audit::{AuditLog, SubstitutionRecorder};
use asv_broker::connect_runtime::SharedSessions;
use asv_broker::tls_bridge::{
    issue_leaf, proof_nonce, AuthorityEndpoint, Bridge, BridgeError, CleartextUpstream,
    ConnectPolicy, EstablishedTunnel, LeafError, LeafSource, RelayLimits, SessionCa, SessionProofs,
    SubstitutionError, SubstitutionOutcome, SubstitutionRecord, UpstreamResolver, VerifiedLeaf,
    SESSION_PROOF_HEADER,
};
use asv_broker::{SessionStore, SubstitutionPort, SurrogateRegistry};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_domain::{AgentSessionId, Authority, CredentialClass, CredentialId, OperationFamily};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ssh_agent::public_key_blob;
use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use sha2::{Digest, Sha256};

const HOST: &str = "api.github.test";
/// A second authorised endpoint on the same host, so the destination-binding
/// test can vary the nonce without varying anything else.
const OTHER_PORT: u16 = 8443;
/// The secret. If this string reaches the client side of the tunnel, or the
/// audit chain, the suite is red.
const REAL: &str = "ASV-REAL-CANARY-4d7e2a91-must-reach-the-provider";
const CRED: &str = "9c2f4a10-6b3e-4d51-8f27-1a5e0b93cc40";

// ---------------------------------------------------------------------------
// Base64 (standard alphabet, unpadded) — the encoding `SESSION_PROOF_HEADER`
// is written in.
// ---------------------------------------------------------------------------

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let b = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let quad = [n >> 18 & 63, n >> 12 & 63, n >> 6 & 63, n & 63];
        let take = match group.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for (i, v) in quad.iter().enumerate() {
            if i < take {
                out.push(ALPHABET[*v as usize] as char);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Test doubles for the two traits the bridge reaches outward through. Neither
// is a stand-in for a security decision: the leaves are a real SessionCa, the
// upstream resolver answers one address, and the SecretPort is where the
// credential bytes enter.
// ---------------------------------------------------------------------------

struct SessionLeaves {
    ca: Arc<SessionCa>,
}

impl LeafSource for SessionLeaves {
    fn issue_for(&self, host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError> {
        let certificate = issue_leaf(&self.ca, host, now)?;
        VerifiedLeaf::from_certificate(&self.ca, certificate)
            .map_err(|_| LeafError::InvalidHost("leaf material could not be assembled".to_string()))
    }
}

struct FixedUpstream {
    addr: SocketAddr,
}

impl UpstreamResolver for FixedUpstream {
    fn resolve(&self, _target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        Ok(self.addr)
    }
}

/// The credential store's only job: hand out the canary for the one
/// credential id the test minted a surrogate over.
struct CanaryStore;

impl SecretPort for CanaryStore {
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        if credential != CRED {
            return Err(SecretError::NotFound(credential.to_string()));
        }
        sink.accept(REAL.as_bytes())
    }
}

/// Counts `authenticate` calls, so the ordering test can prove the proof was never
/// looked at rather than inferring it from an error.
struct CountingProofs {
    inner: Arc<Mutex<SessionStore>>,
    calls: Arc<Mutex<usize>>,
}

impl SessionProofs for CountingProofs {
    fn authenticate(
        &self,
        proof: &asv_broker::tls_bridge::SessionProof,
        target: &AuthorityEndpoint,
    ) -> Result<AgentSessionId, asv_broker::ProofRejection> {
        *self.calls.lock().expect("count") += 1;
        // The real store, under the same lock production uses, so this double
        // counts calls without re-implementing what it counts.
        let mut store = self
            .inner
            .lock()
            .map_err(|_| asv_broker::ProofRejection::NoSuchSession)?;
        SessionStore::authenticate(&mut store, proof, target)
    }
}

/// The origin. Reads the request head, records every byte, answers, and closes.
///
/// Closing matters: `relay_back` copies until the upstream says EOF, so an
/// origin that held the connection open would turn every relay test into a
/// timeout rather than a result.
struct Origin {
    addr: SocketAddr,
    accepted: Arc<Mutex<usize>>,
    received: Arc<Mutex<Vec<u8>>>,
}

const ORIGIN_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

impl Origin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let accepted = Arc::new(Mutex::new(0usize));
        let received = Arc::new(Mutex::new(Vec::new()));
        let (a, r) = (Arc::clone(&accepted), Arc::clone(&received));
        thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            *a.lock().expect("count") += 1;
            let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
            let mut buffer = [0u8; 1024];
            let mut head = Vec::new();
            // Read until the head terminator, so the recorded bytes are the
            // whole request rather than whatever one `read` happened to get.
            while !head.ends_with(b"\r\n\r\n") {
                match socket.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        r.lock().expect("body").extend_from_slice(&buffer[..n]);
                        head.extend_from_slice(&buffer[..n]);
                    }
                }
            }
            let _ = socket.write_all(ORIGIN_RESPONSE.as_bytes());
            let _ = socket.flush();
        });
        Self {
            addr,
            accepted,
            received,
        }
    }

    fn accepted(&self) -> usize {
        *self.accepted.lock().expect("count")
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("body").clone()
    }

    /// Bounded wait, so a relay that never forwards fails the test instead of
    /// hanging the suite.
    fn wait_for_received(&self, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        loop {
            let body = self.received();
            if !body.is_empty() || Instant::now() >= deadline {
                return body;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// For the fail-closed arms: give a relay that *would* have forwarded the
    /// time to do it, then prove it did not.
    fn assert_nothing_received(&self) {
        let deadline = Instant::now() + Duration::from_millis(400);
        while Instant::now() < deadline {
            assert!(
                self.received().is_empty(),
                "the origin received a request that should never have been forwarded: {:?}",
                String::from_utf8_lossy(&self.received())
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

/// Which session's key signs a proof.
#[derive(Clone, Copy)]
enum Who {
    A,
    B,
    /// A key that is registered to nothing.
    Stranger,
}

/// The deployment's allow-list: two endpoints on one host, so the
/// destination-binding test can vary the nonce without varying anything else.
///
/// A function rather than a field because every helper needs it and `Bridge`
/// cannot be cloned into a thread: keeping it on the `Rig` produced a field
/// nothing read and three copies of the same policy.
fn policy() -> Bridge {
    cleartext_bridge(ConnectPolicy {
        allowed: vec![endpoint(HOST, 443), endpoint(HOST, OTHER_PORT)],
    })
}

/// A bridge that reaches every destination in the clear.
///
/// **Stated, not defaulted.** A `Bridge` with no transport policy reaches
/// nothing at all, so every fixture here has to say how it dials — and what it
/// says is a real property, not a formality: these origins are loopback plain
/// HTTP, so the credential crosses this leg in the clear, and the test that
/// says so is the one that should have to say so.
fn cleartext_bridge(policy: ConnectPolicy) -> Bridge {
    Bridge::new(policy).with_upstream(
        Arc::new(CleartextUpstream),
        Arc::new(rustls::RootCertStore::empty()),
    )
}

/// An origin that answers a **script** of raw responses, one per request, and
/// keeps the connection open between them.
///
/// The existing [`Origin`] is a single-shot that closes after one response,
/// which is right for proving substitution and wrong for a loop: a relay that
/// ended after one request and a relay that carried five would both look
/// identical against an origin that only ever answers one.
///
/// `script` is raw bytes rather than a description of a response, because the
/// cases this needs to stage are the ones no high-level description can express:
/// a chunked body, a `1xx` before the real answer, a response with no
/// `Content-Length` that ends when the origin closes, and a `101` that hands the
/// connection to another protocol. An origin that could only write well-formed
/// keep-alive responses could not stage any of them.
struct ScriptedOrigin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    served: Arc<Mutex<usize>>,
}

impl ScriptedOrigin {
    /// `script` entries are written in order, one per request read. The last
    /// entry is followed by a close, which is how a keep-alive origin says it
    /// has nothing more.
    fn start(script: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let served = Arc::new(Mutex::new(0usize));
        let (r, s) = (Arc::clone(&received), Arc::clone(&served));
        thread::spawn(move || {
            while let Ok((mut socket, _)) = listener.accept() {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
                let mut index = 0usize;
                loop {
                    if index >= script.len() {
                        // Nothing left to answer. The relay must treat this as
                        // an ordinary end, not as a truncation mid-message.
                        break;
                    }
                    if read_one_request(&mut socket, &r).is_none() {
                        break;
                    }
                    if socket.write_all(&script[index]).is_err() {
                        break;
                    }
                    let _ = socket.flush();
                    *s.lock().expect("served") += 1;
                    index += 1;
                }
            }
        });
        Self {
            addr,
            received,
            served,
        }
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("body").clone()
    }

    fn served(&self) -> usize {
        *self.served.lock().expect("served")
    }
}

/// Reads exactly one request — head **and** the body its head declares — and
/// records every byte of it.
///
/// **The body is why this is not one `read`, and the terminator search is why it
/// is not `ends_with`.** Two versions of this fixture were wrong in two different
/// ways, and both are worth writing down because the second one is the very
/// defect this increment exists to fix:
///
/// - Reading once per request and answering leaves a `POST` whose head and body
///   arrive in two segments with half a request in the socket, so the origin
///   answers early and the leftover is read as the *next* request. That is a
///   race, and a test that fails under load is reporting a race as a product
///   defect.
/// - Waiting for the accumulated buffer to *end* in `\r\n\r\n` is the
///   "scan for the terminator" mistake. A head and its body arriving in one read
///   leave the buffer ending in the body, so the origin waited for bytes that
///   would never come — and it deadlocked, because the relay was waiting for the
///   response the origin had not been asked for yet. It reproduced exactly the
///   bug `http_frame` was written to prevent, in twenty lines of test fixture,
///   which is a better argument for the framing layer than any comment.
///
/// So: search for the terminator, treat the bytes up to it as the head, and
/// count anything past it as the start of the body.
///
/// `Content-Length` only. A chunked *request* is not staged by any test here, and
/// an origin that silently mishandled one would be a fixture inventing failures
/// nobody is looking for; this says so by refusing one rather than by guessing.
fn read_one_request(socket: &mut TcpStream, record: &Arc<Mutex<Vec<u8>>>) -> Option<()> {
    let mut buf = [0u8; 4096];
    let mut raw: Vec<u8> = Vec::new();
    let terminator = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = socket.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        record.lock().expect("body").extend_from_slice(&buf[..n]);
        raw.extend_from_slice(&buf[..n]);
    };

    let head = String::from_utf8_lossy(&raw[..terminator]).to_string();
    if head.to_ascii_lowercase().contains("transfer-encoding:") {
        panic!("this origin stages responses, not chunked requests: {head}");
    }
    let declared: usize = head
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .next()
        .unwrap_or(0);

    let mut body = raw.len() - terminator;
    while body < declared {
        let want = (declared - body).min(buf.len());
        let n = socket.read(&mut buf[..want]).ok()?;
        if n == 0 {
            return None;
        }
        record.lock().expect("body").extend_from_slice(&buf[..n]);
        body += n;
    }
    Some(())
}

struct Rig {
    store: Arc<Mutex<SessionStore>>,
    registry: Arc<Mutex<SurrogateRegistry>>,
    ca: Arc<SessionCa>,
    root_der: Vec<u8>,
    origin: Origin,
    /// Present only for the loop tests, which need an origin that answers a
    /// script instead of closing after one response. `upstream_addr` is the
    /// only thing that reads it, so nothing else has to know which kind of
    /// origin a rig was built with.
    scripted: Option<ScriptedOrigin>,
    session_a: AgentSessionId,
    session_b: AgentSessionId,
    key_a: SigningKey,
    key_b: SigningKey,
    stranger: SigningKey,
    /// The surrogate minted for session A over the canary credential.
    surrogate_a: String,
    /// The surrogate minted for session B.
    surrogate_b: String,
    /// One counter per signer, in that party's own sequence. A real client
    /// holds a counter per session and increments it for every CONNECT; tests
    /// that open more than one tunnel for the same session would otherwise
    /// reuse a counter, and the second would be refused as a replay — which
    /// would be the property working, not the fixture being wrong.
    next_a: std::sync::atomic::AtomicU64,
    next_b: std::sync::atomic::AtomicU64,
    next_stranger: std::sync::atomic::AtomicU64,
}

impl Rig {
    fn new() -> Self {
        let peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: 1000,
            gid: 1000,
        });

        let key_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let stranger = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut store = SessionStore::new();
        let session_a = store.create("uat-010-a".into(), &peer);
        let session_b = store.create("uat-010-b".into(), &peer);
        store
            .register_key(session_a, &peer, public_key_blob(&key_a.verifying_key()))
            .expect("session A registers its key");
        store
            .register_key(session_b, &peer, public_key_blob(&key_b.verifying_key()))
            .expect("session B registers its key");

        // The stranger's key is deliberately *not* registered: that is what
        // makes it a stranger rather than a third session.
        let _ = stranger;

        let mut registry = SurrogateRegistry::new();
        let credential = CredentialId::from_wire(CRED).expect("canonical wire form");
        let now = asv_broker::surrogate::now_secs();
        let (surrogate_a, _, _) = registry
            .mint(
                session_a,
                credential,
                CredentialClass::Generic,
                3600,
                1,
                now,
            )
            .expect("mint for session A");
        let (surrogate_b, _, _) = registry
            .mint(
                session_b,
                credential,
                CredentialClass::Generic,
                3600,
                1,
                now,
            )
            .expect("mint for session B");

        let ca = Arc::new(SessionCa::new("uat-010", 7, Duration::from_secs(3600)));
        let root_der = ca.root_der.clone();

        Self {
            store: Arc::new(Mutex::new(store)),
            registry: Arc::new(Mutex::new(registry)),
            ca,
            root_der,
            origin: Origin::start(),
            scripted: None,
            session_a,
            session_b,
            key_a,
            key_b,
            stranger: SigningKey::generate(&mut rand::rngs::OsRng),
            surrogate_a,
            surrogate_b,
            next_a: std::sync::atomic::AtomicU64::new(1),
            next_b: std::sync::atomic::AtomicU64::new(1),
            next_stranger: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// The address the bridge resolves every authorised target to.
    fn upstream_addr(&self) -> SocketAddr {
        match &self.scripted {
            Some(scripted) => scripted.addr,
            None => self.origin.addr,
        }
    }

    /// A rig whose origin answers a **script** and keeps the connection open.
    ///
    /// `uses` is the surrogate's budget, and it is a parameter rather than a
    /// constant for the same reason it exists at all: a single-use surrogate
    /// cannot carry a second request, so a loop test built on the default rig
    /// would be measuring the budget rather than the loop. Naming the number at
    /// every call site means a test that wants a budget it did not ask for has
    /// to say so.
    fn with_script(script: Vec<Vec<u8>>, uses: u32) -> Self {
        let mut rig = Rig::new();
        rig.surrogate_a = rig.remint(uses);
        rig.scripted = Some(ScriptedOrigin::start(script));
        rig
    }

    /// Re-mints session A's surrogate with a budget the test chose.
    fn remint(&self, uses: u32) -> String {
        let mut registry = self.registry.lock().expect("registry");
        let credential = CredentialId::from_wire(CRED).expect("canonical wire form");
        let (token, _, _) = registry
            .mint(
                self.session_a,
                credential,
                CredentialClass::Generic,
                3600,
                uses,
                asv_broker::surrogate::now_secs(),
            )
            .expect("mint for session A");
        token
    }

    /// A substitution port over session A's registry and the canary store.
    ///
    /// Every loop test needs one, and building it inline would put eight lines
    /// of setup in front of each assertion. The family is `GitHub` because the
    /// credential's route is a GitHub one and a port that resolved a different
    /// family would refuse the redemption for a reason no test is about.
    fn port(&self) -> SubstitutionPort {
        SubstitutionPort::new(
            Arc::clone(&self.registry)
                as Arc<dyn asv_broker::surrogate::SurrogateLending + Send + Sync>,
            Arc::new(CanaryStore) as Arc<dyn SecretPort + Send + Sync>,
            OperationFamily::GitHub,
            "github",
        )
    }

    fn scripted(&self) -> &ScriptedOrigin {
        self.scripted
            .as_ref()
            .expect("this rig was built with a script, so it has a scripted origin")
    }

    /// The next counter for whoever is signing, in that party's own sequence.
    fn next_counter(&self, who: Who) -> u64 {
        use std::sync::atomic::Ordering::SeqCst;
        match who {
            Who::A => self.next_a.fetch_add(1, SeqCst),
            Who::B => self.next_b.fetch_add(1, SeqCst),
            Who::Stranger => self.next_stranger.fetch_add(1, SeqCst),
        }
    }

    fn key(&self, who: Who) -> &SigningKey {
        match who {
            Who::A => &self.key_a,
            Who::B => &self.key_b,
            Who::Stranger => &self.stranger,
        }
    }

    /// A real session proof: the key blob and a real signature over the
    /// destination-bound nonce, base64'd into the header value.
    fn proof(&self, who: Who, host: &str, port: u16) -> String {
        let key = self.key(who);
        let blob = public_key_blob(&key.verifying_key());
        let target = endpoint(host, port);
        let counter = self.next_counter(who);
        let nonce = proof_nonce(&blob, &target, counter);
        let signature = key.sign(&nonce).to_bytes();
        format!("{}.{counter}.{}", b64(&blob), b64(&signature))
    }

    /// Opens a CONNECT and returns the client's TLS side plus the tunnel.
    ///
    /// `port` is the *target* port, which is not the origin's address: the
    /// resolver maps every authorised target to the same origin, so the test
    /// can vary the destination without varying the socket.
    fn tunnel(
        &self,
        proof: Option<String>,
        port: u16,
    ) -> Result<(ClientSide, EstablishedTunnel), BridgeError> {
        let proofs: Arc<dyn SessionProofs + Send + Sync> =
            Arc::new(SharedSessions::new(Arc::clone(&self.store)));
        self.tunnel_with(proof, port, proofs)
    }

    fn tunnel_with(
        &self,
        proof: Option<String>,
        port: u16,
        proofs: Arc<dyn SessionProofs + Send + Sync>,
    ) -> Result<(ClientSide, EstablishedTunnel), BridgeError> {
        self.tunnel_on(policy(), proof, port, proofs)
    }

    /// A tunnel whose bridge can be interrupted from outside.
    ///
    /// Separate from `tunnel` because the cancellation cases need a signal the
    /// test keeps a handle on, and every other case needs a bridge that is
    /// never cancelled. Folding the signal into the shared helper would mean
    /// every test naming one.
    fn tunnel_cancellable(
        &self,
        proof: Option<String>,
        port: u16,
        cancel: Arc<dyn asv_broker::tls_bridge::Cancel>,
    ) -> Result<(ClientSide, EstablishedTunnel), BridgeError> {
        let proofs: Arc<dyn SessionProofs + Send + Sync> =
            Arc::new(SharedSessions::new(Arc::clone(&self.store)));
        self.tunnel_on(policy().with_cancel(cancel), proof, port, proofs)
    }

    fn tunnel_on(
        &self,
        bridge: Bridge,
        proof: Option<String>,
        port: u16,
        proofs: Arc<dyn SessionProofs + Send + Sync>,
    ) -> Result<(ClientSide, EstablishedTunnel), BridgeError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
        let mut client =
            TcpStream::connect(listener.local_addr().expect("bridge addr")).expect("connect");
        let (server_side, _) = listener.accept().expect("bridge accepts");

        let mut head = format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}\r\n");
        if let Some(proof) = proof {
            head.push_str(&format!("{SESSION_PROOF_HEADER}: {proof}\r\n"));
        }
        head.push_str("\r\n");
        client.write_all(head.as_bytes()).expect("write CONNECT");
        client.flush().expect("flush");

        let leaves = SessionLeaves {
            ca: Arc::clone(&self.ca),
        };
        let upstream = FixedUpstream {
            addr: self.upstream_addr(),
        };

        let handle = thread::spawn(move || {
            bridge.serve_connect(
                server_side,
                &leaves,
                &upstream,
                Some(proofs.as_ref()),
                Instant::now(),
            )
        });

        let ack = read_head(&mut client);
        assert!(
            ack.starts_with("HTTP/1.1 200"),
            "an authorised target is established before the handshake, got {ack:?}"
        );
        let tls = handshake(self.root_der.clone(), client).expect("the session leaf must verify");
        let tunnel = handle.join().expect("bridge thread")?;
        Ok((ClientSide(tls), tunnel))
    }

    /// The refusal arms. `serve_connect` fails before writing the ack, so
    /// there is no head to read — the tunnel helper would panic on EOF and
    /// report a socket error instead of the refusal under test.
    fn tunnel_refused(&self, proof: Option<String>, port: u16) -> BridgeError {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
        let mut client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (server_side, _) = listener.accept().expect("accepts");

        let mut head = format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}\r\n");
        if let Some(proof) = proof {
            head.push_str(&format!("{SESSION_PROOF_HEADER}: {proof}\r\n"));
        }
        head.push_str("\r\n");
        client.write_all(head.as_bytes()).expect("write CONNECT");
        client.flush().expect("flush");

        let bridge = policy();
        let leaves = SessionLeaves {
            ca: Arc::clone(&self.ca),
        };
        let upstream = FixedUpstream {
            addr: self.upstream_addr(),
        };
        let proofs: Arc<dyn SessionProofs + Send + Sync> =
            Arc::new(SharedSessions::new(Arc::clone(&self.store)));

        bridge
            .serve_connect(
                server_side,
                &leaves,
                &upstream,
                Some(proofs.as_ref()),
                Instant::now(),
            )
            .map(|_| ())
            .expect_err("this CONNECT should not have been served")
    }
}

fn endpoint(host: &str, port: u16) -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(host).expect("host"), port).expect("endpoint")
}

struct ClientSide(rustls::StreamOwned<ClientConnection, TcpStream>);

/// Only so `expect_err` can name the side it did not get. A socket is not
/// worth printing, and the interesting value on the error path is the
/// `BridgeError`.
impl std::fmt::Debug for ClientSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSide").finish()
    }
}

impl ClientSide {
    fn send(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).expect("client writes");
        self.0.flush().expect("flush");
    }

    /// One response head, as text, read a byte at a time to the terminator.
    ///
    /// A byte at a time for the same reason the relay does it: anything that
    /// reads past the terminator swallows the first bytes of the body, or of the
    /// next response, and a test that cannot tell those apart cannot test a
    /// relay that has to.
    fn read_head_str(&mut self) -> String {
        let _ = self.0.sock.set_read_timeout(Some(Duration::from_secs(10)));
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            self.0
                .read_exact(&mut byte)
                .expect("client reads one response head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii head")
    }

    fn recv(&mut self, n: usize) -> Vec<u8> {
        let _ = self.0.sock.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buffer = vec![0u8; n];
        self.0.read_exact(&mut buffer).expect("client reads");
        buffer
    }

    /// Whatever arrived, up to `n`, within `timeout` — without insisting on all
    /// of it.
    ///
    /// `recv` panics when the count falls short, which is right for a body that
    /// *should* be there and useless for one that should not: a relay that
    /// refuses a body mid-flight leaves the client holding a head promising N
    /// bytes and a body of M, and `M` is the whole observation. This cannot
    /// report "nothing" and "most of it" the same way, which is the distinction
    /// the two budgets on a response turn on.
    fn recv_within(&mut self, n: usize, timeout: Duration) -> Vec<u8> {
        let _ = self.0.sock.set_read_timeout(Some(timeout));
        let mut buffer = vec![0u8; n];
        let mut got = 0usize;
        while got < n {
            match self.0.read(&mut buffer[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(_) => break,
            }
        }
        buffer.truncate(got);
        buffer
    }
}

/// Reads a response head one byte at a time, stopping at the terminator.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read head");
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("ascii head")
}

fn handshake(
    root_der: Vec<u8>,
    stream: TcpStream,
) -> Result<rustls::StreamOwned<ClientConnection, TcpStream>, rustls::Error> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("the session root is a valid trust anchor");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(HOST.to_string()).expect("server name");
    let connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|_| rustls::Error::General("client rejected the server name".into()))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| rustls::Error::General(format!("client handshake failed: {e}")))?;
    Ok(tls)
}

fn request_with(token: &str) -> String {
    format!(
        "GET /repos/o/r/issues HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\n\r\n"
    )
}

/// A substitution audit port that keeps what it was told, for the arms that
/// inspect the record. The chain-backed half of A8 uses the real recorder.
#[derive(Default)]
struct Collected(Vec<SubstitutionRecord>);

impl asv_broker::tls_bridge::SubstitutionAudit for Collected {
    fn record(&mut self, record: SubstitutionRecord) -> Result<(), BridgeError> {
        self.0.push(record);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// A1 — a valid proof resolves its session
// ---------------------------------------------------------------------------

/// **A1 + A6.** The whole claim in one test: a valid proof resolves to the
/// session that made it, and the real credential reaches the origin.
///
/// These are the same act seen from both ends, and separating them would let
/// one of them pass vacuously — a bridge that resolved correctly but never
/// substituted, or one that substituted under an id it invented.
#[test]
fn a_valid_proof_resolves_its_session_and_the_origin_receives_the_credential() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);

    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    assert_eq!(
        tunnel.session, rig.session_a,
        "the proof resolved to something other than the session whose key signed it"
    );

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = rig.port();
    let outcome: SubstitutionOutcome = tunnel
        .relay_substituted(&mut port, &mut audit, RelayLimits::default())
        .expect("a redeemable surrogate substitutes");

    // The forwarded request is the original with the token's extent
    // replaced, so its length is the *credential's*, not the surrogate's.
    // Comparing against `request_with(&surrogate)` would be wrong by exactly
    // the difference between the two tokens.
    assert_eq!(outcome.forwarded, request_with(REAL).len());
    assert_eq!(outcome.returned, ORIGIN_RESPONSE.len());

    // Non-vacuity, from the origin's own mouth.
    let received = rig.origin.wait_for_received(Duration::from_secs(5));
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.contains(REAL),
        "the origin did not receive the real credential, so nothing was substituted: {text}"
    );
    assert!(
        !text.contains(&rig.surrogate_a),
        "the surrogate was forwarded upstream: {text}"
    );
    // The rest of the request survived the rewrite byte for byte.
    assert!(
        text.starts_with("GET /repos/o/r/issues HTTP/1.1\r\n"),
        "{text}"
    );
    assert!(text.contains(&format!("Host: {HOST}\r\n")), "{text}");
    assert!(text.contains("Accept: application/json\r\n"), "{text}");

    // And the answer really did reach the client.
    let response = String::from_utf8_lossy(&client.recv(ORIGIN_RESPONSE.len())).to_string();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
}

// ---------------------------------------------------------------------------
// A7 — the client never sees the secret
// ---------------------------------------------------------------------------

/// **A7.** The response arrives, and it carries neither the credential nor
/// the surrogate.
///
/// The half that matters is the *arrival*: a relay that dropped the response
/// would satisfy "the client did not see the secret" trivially, so this test
/// reads the bytes the client actually receives and then searches them. It
/// is the same assertion A1 makes about the origin, pointed the other way.
#[test]
fn the_client_receives_the_response_and_neither_the_credential_nor_the_surrogate() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = rig.port();
    tunnel
        .relay_substituted(&mut port, &mut audit, RelayLimits::default())
        .expect("substitution");

    let response = String::from_utf8_lossy(&client.recv(ORIGIN_RESPONSE.len())).to_string();
    assert_eq!(
        response, ORIGIN_RESPONSE,
        "the response did not arrive intact"
    );
    assert!(
        !response.contains(REAL),
        "the client received the real credential: {response}"
    );
    assert!(
        !response.contains(&rig.surrogate_a),
        "the client received the surrogate: {response}"
    );

    // The relay's own outcome is a number, never a body: returning the
    // forwarded request would make it a second place the secret lives.
    let mut audit = Collected::default();
    let mut port = rig.port();
    let second = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());
    assert!(
        matches!(second, Err(BridgeError::Io(_)) | Err(BridgeError::Substitution(_))),
        "a second relay on the same tunnel answered with something other than a refusal: {second:?}"
    );
}

// ---------------------------------------------------------------------------
// A2 — another session's proof does not resolve to this one
// ---------------------------------------------------------------------------

/// **A2.** Session B's proof resolves to B, never to A, and B's tunnel cannot
/// spend A's token.
///
/// The first half alone would be satisfiable by a bridge that resolved every
/// proof to the same session — which is why the second half is here: if the
/// resolution were pinned to A regardless of the key, A's surrogate would
/// redeem in B's tunnel and this test would go red.
#[test]
fn another_sessions_proof_does_not_resolve_to_this_session() {
    let rig = Rig::new();
    let proof = rig.proof(Who::B, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    assert_eq!(
        tunnel.session, rig.session_b,
        "B's proof resolved to A, which is exactly the escalation under test"
    );

    // A's token, spent in B's tunnel.
    client.send(request_with(&rig.surrogate_a).as_bytes());
    let mut audit = Collected::default();
    let mut port = rig.port();
    let outcome = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());

    assert!(
        matches!(
            outcome,
            Err(BridgeError::Substitution(SubstitutionError::Refused))
        ),
        "a token from another session was redeemed: {outcome:?}"
    );
    rig.origin.assert_nothing_received();
}

// ---------------------------------------------------------------------------
// A4 — WrongSession intact
// ---------------------------------------------------------------------------

/// **A4.** The refusal is the same code and the same equality `redeem_for`
/// has always used, reached now through a signed session instead of an
/// asserted one.
///
/// The equality itself is `surrogate.rs`'s, untouched; what this pins is that
/// ADR-0019 did not weaken it on the way past. The control is the same call
/// with the right session, so the test cannot pass by refusing everything.
#[test]
fn a_surrogate_from_another_session_is_still_refused_and_the_right_one_still_works() {
    let rig = Rig::new();

    // Wrong session first, on its own tunnel.
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(request_with(&rig.surrogate_b).as_bytes());
    let mut audit = Collected::default();
    let mut port = rig.port();
    let refused = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());
    assert!(
        matches!(
            refused,
            Err(BridgeError::Substitution(SubstitutionError::Refused))
        ),
        "B's token redeemed in A's tunnel: {refused:?}"
    );
    // `serve_connect` dials the upstream before the relay runs, so "never
    // dialled" is not the property and asserting it would be asserting a
    // different thing than the one under test. The property is that nothing
    // was *forwarded*.
    rig.origin.assert_nothing_received();

    // Control: the same port, the matching session, the matching token.
    let rig2 = Rig::new();
    let proof = rig2.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig2.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(request_with(&rig2.surrogate_a).as_bytes());
    let mut audit = Collected::default();
    let mut port = rig2.port();
    tunnel
        .relay_substituted(&mut port, &mut audit, RelayLimits::default())
        .expect("the matching token must still work, or this test proves nothing");
    assert!(
        String::from_utf8_lossy(&rig2.origin.wait_for_received(Duration::from_secs(5)))
            .contains(REAL),
        "the control tunnel did not substitute, so the refusal above proves nothing"
    );
}

/// **A2, the second layer.** A signature made under one key, presented with
/// a *different* key's blob, resolves to nothing.
///
/// This is the falsifier for the blob guard in `SessionStore::resolve`, and it
/// was missing. Every other arm in this file presents a blob and a signature
/// that belong together, so a resolver that dropped the requirement that they
/// match — and verified against whichever registered key happened to verify
/// first — would have stayed green through all of them. The two layers only
/// have independent witnesses when a test deliberately mismatches them.
#[test]
fn a_signature_under_one_key_presented_with_another_keys_blob_resolves_to_nothing() {
    let rig = Rig::new();
    let target = endpoint(HOST, 443);

    // Session A's blob is what is *presented*, and the nonce the bridge
    // checks is derived from the presented blob — so the nonce is derived
    // from A's blob here too.
    //
    // That detail is the whole test. A first version derived the nonce from
    // B's blob instead, which made the signature fail against every key for a
    // reason that had nothing to do with the blob guard, and the mutation that
    // removed the guard left the suite green. A falsification that does not
    // falsify is not evidence, and this is the second time in this block that
    // one nearly passed for one.
    let presented_blob = public_key_blob(&rig.key_a.verifying_key());
    let nonce = proof_nonce(&presented_blob, &target, 1);
    // Signed by B, presented under A's blob.
    let signature = rig.key_b.sign(&nonce).to_bytes();
    let proof = format!("{}.{}", b64(&presented_blob), b64(&signature));

    let error = rig.tunnel_refused(Some(proof), 443);
    assert!(
        matches!(error, BridgeError::NoSessionProof),
        "a mismatched blob and signature resolved to a session: {error:?}. With the \
         blob guard present the lookup lands on A and A's key rejects B's signature; \
         with it removed, B's key verifies and the tunnel comes up as B."
    );
    assert_eq!(rig.origin.accepted(), 0);
}

// ---------------------------------------------------------------------------
// A3 (corrected) — the proof does not transfer to another destination
// ---------------------------------------------------------------------------

/// **A3, as the design actually provides it.** A proof minted for
/// `HOST:443` does not verify against `HOST:8443`.
///
/// Not freshness, and the module header says why: the nonce is derived from
/// the destination because a server-issued nonce would cost a round trip an
/// ordinary HTTP client cannot pay. What this pins is the half that stops an
/// attacker moving a captured proof to a host the operator never authorised.
#[test]
fn a_proof_does_not_transfer_to_another_destination() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);

    let error = rig.tunnel_refused(Some(proof), OTHER_PORT);
    assert!(
        matches!(error, BridgeError::NoSessionProof),
        "the transferred proof was refused for the wrong reason: {error:?}"
    );
    assert_eq!(
        rig.origin.accepted(),
        0,
        "an unverified proof reached the upstream: the tunnel was opened anyway"
    );
}

// ---------------------------------------------------------------------------
// A5 — the destination is authorised before the proof is looked at
// ---------------------------------------------------------------------------

/// **A5.** A target outside the allow-list is refused without one signature
/// verification and without one socket.
///
/// `accepted() == 0` alone is weak: a bridge that dialled first and refused
/// second also ends with no origin traffic worth seeing. The `calls == 0`
/// counter is the direct witness — it fails if the proof is examined at all,
/// which is the ordering claim.
#[test]
fn an_unauthorised_destination_is_refused_before_the_proof_is_looked_at() {
    let peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: 1000,
        gid: 1000,
    });
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = SessionStore::new();
    let session = store.create("uat-010-unauthorised".into(), &peer);
    store
        .register_key(session, &peer, public_key_blob(&key.verifying_key()))
        .expect("register");

    let origin = Origin::start();
    let ca = SessionCa::new("uat-010-unauthorised", 9, Duration::from_secs(3600));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
    let mut client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let (server_side, _) = listener.accept().expect("accepts");

    let blob = public_key_blob(&key.verifying_key());
    let target = endpoint("evil.example.net", 443);
    let nonce = proof_nonce(&blob, &target, 1);
    let signature = key.sign(&nonce).to_bytes();
    let proof = format!("{}.{}", b64(&blob), b64(&signature));

    client
        .write_all(
            format!(
                "CONNECT evil.example.net:443 HTTP/1.1\r\nHost: evil.example.net\r\n{SESSION_PROOF_HEADER}: {proof}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write");
    client.flush().expect("flush");

    // A policy that allows only HOST:443.
    let bridge = cleartext_bridge(ConnectPolicy {
        allowed: vec![endpoint(HOST, 443)],
    });
    let leaves = SessionLeaves { ca: Arc::new(ca) };
    let upstream = FixedUpstream { addr: origin.addr };
    let calls = Arc::new(Mutex::new(0usize));
    let proofs = CountingProofs {
        inner: Arc::new(Mutex::new(store)),
        calls: Arc::clone(&calls),
    };

    let error = bridge
        .serve_connect(
            server_side,
            &leaves,
            &upstream,
            Some(&proofs),
            Instant::now(),
        )
        .expect_err("an unauthorised destination must be refused");
    assert!(matches!(error, BridgeError::Connect(_)), "{error:?}");
    assert_eq!(
        *calls.lock().expect("count"),
        0,
        "the session proof was verified for a destination the policy refused"
    );
    assert_eq!(origin.accepted(), 0, "the origin was dialled anyway");
}

// ---------------------------------------------------------------------------
// A9 — fail closed
// ---------------------------------------------------------------------------

/// **A9.** Three ways to fail, and in each of them the upstream receives
/// nothing at all.
///
/// A tunnel with no proof, a tunnel whose proof is signed by a key nobody
/// registered, and a request with no authorization header to substitute. The
/// third is the one that is easy to get wrong by omission: forwarding it
/// unsubstituted would send the client's own credential to the outside world
/// and report a provider error rather than the truth.
#[test]
fn without_a_valid_proof_or_a_credential_the_tunnel_closes_and_nothing_is_forwarded() {
    // (1) No proof at all.
    let rig = Rig::new();
    let error = rig.tunnel_refused(None, 443);
    assert!(matches!(error, BridgeError::NoSessionProof), "{error:?}");
    assert_eq!(rig.origin.accepted(), 0);

    // (2) A proof signed by a key that is registered to nobody.
    let rig = Rig::new();
    let proof = rig.proof(Who::Stranger, HOST, 443);
    let error = rig.tunnel_refused(Some(proof), 443);
    assert!(matches!(error, BridgeError::NoSessionProof), "{error:?}");
    assert_eq!(rig.origin.accepted(), 0);

    // (3) A valid tunnel, but the request carries nothing to substitute.
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(b"GET /repos/o/r/issues HTTP/1.1\r\nHost: api.github.test\r\n\r\n");

    let mut audit = Collected::default();
    let mut port = rig.port();
    let outcome = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());
    assert!(
        matches!(
            outcome,
            Err(BridgeError::Substitution(SubstitutionError::NoCredential))
        ),
        "a request with no credential was not refused: {outcome:?}"
    );
    rig.origin.assert_nothing_received();
}

// ---------------------------------------------------------------------------
// A8 — the audit record carries no secret, and the chain verifies
// ---------------------------------------------------------------------------

/// **A8.** Through the real `AuditLog`, through the real chain.
///
/// Serialised rather than merely held: an in-memory `Debug` is a different
/// surface from what a durable audit file will contain. And the record is the
/// *operation* — destination and family included — rather than a placeholder
/// that only proves somebody called an audit function.
#[test]
fn the_audit_record_names_the_operation_and_carries_no_secret() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut log = AuditLog::new(0);
    let mut port = rig.port();
    {
        let mut recorder = SubstitutionRecorder::new(&mut log, 1_700_000_000);
        tunnel
            .relay_substituted(&mut port, &mut recorder, RelayLimits::default())
            .expect("substitution");
    }

    let records = log.query(0);
    assert!(
        !records.is_empty(),
        "a credentialed CONNECT left no audit record, so the claim that it is \
         audited without the secret is unfalsifiable"
    );
    log.verify()
        .expect("the audit chain verifies after a credentialed CONNECT");

    let substitution = records
        .iter()
        .find(|r| {
            matches!(
                r.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { .. }
            )
        })
        .expect("the record is a substitution, not some other event");

    let rendered = serde_json::to_string(&substitution.event).expect("the event serializes");
    assert!(
        !rendered.contains(REAL),
        "the audit event carried the credential: {rendered}"
    );
    assert!(
        !rendered.contains(&rig.surrogate_a),
        "the audit event carried the surrogate: {rendered}"
    );

    let asv_ipc_protocol::AuditEventDto::CredentialSubstituted {
        session,
        destination,
        family,
        outcome,
    } = &substitution.event
    else {
        unreachable!("the record was found by that variant")
    };
    assert_eq!(
        session,
        &rig.session_a.to_string(),
        "the wrong session was recorded"
    );
    assert_eq!(
        destination,
        &format!("{HOST}:443"),
        "the destination was not recorded"
    );
    assert_eq!(family, "github", "the family was not recorded");
    assert_eq!(outcome, "substituted", "the outcome was not recorded");
}

/// **A8, the refusal half.** A refused substitution is recorded too, and
/// still carries nothing.
///
/// Without this the suite would pass on a broker that audits only successes —
/// which is the half an operator actually needs: "a client tried to spend
/// something here" is the interesting record.
#[test]
fn a_refused_substitution_is_audited_without_the_secret() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_b).as_bytes());

    let mut log = AuditLog::new(0);
    let mut port = rig.port();
    {
        let mut recorder = SubstitutionRecorder::new(&mut log, 1_700_000_000);
        let outcome = tunnel.relay_substituted(&mut port, &mut recorder, RelayLimits::default());
        assert!(
            matches!(outcome, Err(BridgeError::Substitution(_))),
            "{outcome:?}"
        );
    }

    let records = log.query(0);
    log.verify().expect("the chain verifies after a refusal");

    let refused = records
        .iter()
        .find_map(|r| match &r.event {
            asv_ipc_protocol::AuditEventDto::CredentialSubstituted { outcome, .. } => {
                Some(outcome.clone())
            }
            _ => None,
        })
        .expect("a refusal left no audit record");
    assert_eq!(refused, "refused");

    for record in &records {
        let rendered = serde_json::to_string(&record.event).expect("serializes");
        assert!(
            !rendered.contains(REAL),
            "a refusal record carried the credential: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// A10 — the witness itself is not weak
// ---------------------------------------------------------------------------

/// The non-vacuity guard, stated on its own.
///
/// A suite that only ever asserted "no error" would be green against a bridge
/// that substituted nothing. This pins the two observations that make the
/// other tests mean anything: the origin *received* the canary, and the
/// client's response was the origin's own bytes rather than silence.
///
/// It also pins the digest of the canary rather than the canary itself, so
/// the check survives a refactor that renames the constant.
#[test]
fn the_substitution_is_observable_from_both_ends_and_not_vacuous() {
    let rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = rig.port();
    tunnel
        .relay_substituted(&mut port, &mut audit, RelayLimits::default())
        .expect("substitution");

    // End one: the origin really received the secret.
    let received = rig.origin.wait_for_received(Duration::from_secs(5));
    assert_eq!(rig.origin.accepted(), 1, "the origin was never dialled");
    let digest = Sha256::digest(received.as_slice());
    assert!(
        digest.len() == 32 && String::from_utf8_lossy(&received).contains(REAL),
        "the origin's bytes are not the substituted request"
    );

    // End two: the client really got an answer.
    let response = client.recv(ORIGIN_RESPONSE.len());
    assert_eq!(
        response,
        ORIGIN_RESPONSE.as_bytes(),
        "the response did not reach the client"
    );

    // And exactly one record, for exactly one substitution.
    assert_eq!(
        audit.0.len(),
        1,
        "expected one audit record, got {:?}",
        audit.0
    );
    assert_eq!(audit.0[0].outcome, "substituted");
    assert_eq!(audit.0[0].destination, format!("{HOST}:443"));
}

// ---------------------------------------------------------------------------
// C1 — a tunnel that already exists can be torn down (V1-C2)
//
// These are here rather than in `connect_listener_lifecycle.rs` because they
// need what only this file has: a real ADR-0019 proof, a real session CA, a
// real TLS client and a real origin. A stubbed cancellation test would prove
// that a mock reports a mock's reason.
//
// The shape of all three is the same: establish a tunnel, put the relay in a
// state where it is genuinely blocked, then change the world from outside and
// require the relay to notice. The block is the part that carries the claim —
// a relay that returned early would satisfy "the tunnel ended" without ever
// having been cancelled, so every test below asserts the relay was **still
// running** immediately before the signal.
// ---------------------------------------------------------------------------

/// What a relay decided, in the form the bridge reports it.
///
/// Named because the pair of `Result<SubstitutionOutcome, BridgeError>` in the
/// signature below appeared twice, and a reader comparing the channel type with
/// the join type has to check that they really are the same type.
type RelayVerdict = Result<SubstitutionOutcome, BridgeError>;

/// Runs a relay on a worker thread and reports its verdict.
///
/// The result comes back through a channel rather than a `join` so the test can
/// ask the question that matters — *has it finished yet?* — at a moment of its
/// choosing, which is the only way to tell a cancelled relay from one that
/// failed on its own.
fn relay_on_worker_with(
    tunnel: EstablishedTunnel,
    registry: Arc<Mutex<SurrogateRegistry>>,
    limits: RelayLimits,
) -> (
    std::thread::JoinHandle<RelayVerdict>,
    std::sync::mpsc::Receiver<RelayVerdict>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        let mut tunnel = tunnel;
        let mut audit = Collected::default();
        let mut port = SubstitutionPort::new(
            registry as Arc<dyn asv_broker::surrogate::SurrogateLending + Send + Sync>,
            Arc::new(CanaryStore) as Arc<dyn SecretPort + Send + Sync>,
            OperationFamily::GitHub,
            "github",
        );
        let outcome = tunnel.relay_substituted(&mut port, &mut audit, limits);
        let _ = tx.send(outcome.clone());
        outcome
    });
    (handle, rx)
}

/// Nothing has arrived yet, so a later "it ended" is attributable to the signal
/// rather than to the relay having failed or finished on its own.
///
/// `CANCEL_POLL` is 50 ms, so 200 ms is four poll intervals — long enough that
/// a relay still blocked at 200 ms was blocked and not merely slow. Asserting
/// the absence of an event is the one place a sleep is the honest tool: the
/// alternative is a test that cannot tell "cancelled" from "already gone".
fn assert_still_running<T>(rx: &std::sync::mpsc::Receiver<T>, what: &str) {
    // The payload is deliberately not printed: `TryRecvError<T>` is only
    // `Debug` when `T` is, and requiring that of a helper that only needs to
    // know *whether* something arrived would push a pointless bound onto every
    // caller.
    match rx.try_recv() {
        Err(std::sync::mpsc::TryRecvError::Empty) => {}
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            panic!("{what} finished before it was supposed to")
        }
        Ok(_) => panic!("{what} returned before it was supposed to"),
    }
}

/// **C1.1.** A session revoked *after* its tunnel is established loses the
/// tunnel.
///
/// The revocation lands while the relay is blocked reading the client's inner
/// request head — the tunnel is real (session proven, TLS terminated, origin
/// connected) and the client has simply not asked for anything yet. That is the
/// state a session revocation is supposed to reach, and it is the state in which
/// a broker that only checks the signal before the handshake is still serving.
#[test]
fn revoking_an_established_session_tears_down_its_tunnel() {
    let rig = Rig::new();
    let signal = Arc::new(asv_broker::connect_listener::ShutdownSignal::new());
    let proof = rig.proof(Who::A, HOST, 443);

    // The client never sends a request, so the relay blocks on the inner head.
    let (_client, tunnel) = rig
        .tunnel_cancellable(Some(proof), 443, signal.clone())
        .expect("an authorised tunnel");

    let (handle, rx) = relay_on_worker_with(tunnel, rig.registry, RelayLimits::default());
    std::thread::sleep(Duration::from_millis(200));
    assert_still_running(&rx, "the relay");

    signal.revoke(rig.session_a.to_string().as_str());

    let outcome = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("a revoked session must not leave the relay blocked forever");
    let _ = handle.join().expect("the relay thread must not panic");
    assert!(
        matches!(
            outcome,
            Err(BridgeError::Cancelled(
                asv_broker::tls_bridge::CancelReason::SessionRevoked
            ))
        ),
        "a revoked session must cancel its tunnel, got {outcome:?}"
    );

    // Nothing was forwarded, and nothing was substituted: the cancel arrived
    // before the relay had a request to do anything with.
    rig.origin.assert_nothing_received();
}

/// **C1.2.** Shutting the broker down tears down tunnels too, and says so.
///
/// The same teardown reached by a different door, and the reason is different:
/// an operator who stopped the broker needs to read `shutdown`, because the
/// session was perfectly valid and "revoked" would send them looking for a
/// compromise that did not happen.
#[test]
fn shutting_down_tears_down_an_established_tunnel() {
    let rig = Rig::new();
    let signal = Arc::new(asv_broker::connect_listener::ShutdownSignal::new());
    let proof = rig.proof(Who::A, HOST, 443);

    let (_client, tunnel) = rig
        .tunnel_cancellable(Some(proof), 443, signal.clone())
        .expect("an authorised tunnel");

    let (handle, rx) = relay_on_worker_with(tunnel, rig.registry, RelayLimits::default());
    std::thread::sleep(Duration::from_millis(200));
    assert_still_running(&rx, "the relay");

    signal.stop();

    let outcome = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("shutdown must not leave the relay blocked forever");
    let _ = handle.join().expect("the relay thread must not panic");
    assert!(
        matches!(
            outcome,
            Err(BridgeError::Cancelled(
                asv_broker::tls_bridge::CancelReason::Shutdown
            ))
        ),
        "shutdown must cancel the tunnel and report itself as the reason, got {outcome:?}"
    );
}

/// **C1.3.** Revocation is scoped: another session's tunnel keeps working.
///
/// The reciprocal, and the one that stops the previous two from being satisfied
/// by a global kill. `revoke` takes a session id, and the easy wrong
/// implementation — "any tunnel, cancelled" — passes both tests above while
/// letting one agent's revocation take down every other agent's traffic. That
/// is an availability bug that looks like a security feature, so it is tested
/// against a tunnel that must then complete a **real** substitution: the origin
/// has to receive the credential, or the test would pass just as happily on a
/// tunnel that broke for an unrelated reason.
///
/// **The ordering here is the whole test, and the first version got it wrong.**
/// It revoked session B and then sent session A's request, and the
/// falsification run showed that arrangement is blind to a global kill: the
/// request was already in the socket buffer, so `read_byte_cancellable`
/// returned on its first successful read and never reached the `WouldBlock`
/// branch — the only place `cancel_reason` is ever consulted. A relay that
/// consults nothing at all, and a relay that consults it and is told "yes,
/// cancelled" for somebody else's session, are indistinguishable from outside
/// a tunnel that never has to wait.
///
/// So the revocation has to land while A is parked on the poll, and the request
/// after it. The relay must still be running *after* B is revoked — that
/// assertion is the one that a global kill cannot satisfy.
#[test]
fn revoking_another_session_leaves_this_tunnel_working() {
    let rig = Rig::new();
    let signal = Arc::new(asv_broker::connect_listener::ShutdownSignal::new());
    let proof = rig.proof(Who::A, HOST, 443);

    let (mut client, tunnel) = rig
        .tunnel_cancellable(Some(proof), 443, signal.clone())
        .expect("an authorised tunnel");

    // Nothing has been sent, so the relay is parked in the poll.
    let (handle, rx) = relay_on_worker_with(tunnel, rig.registry, RelayLimits::default());
    std::thread::sleep(Duration::from_millis(200));
    assert_still_running(&rx, "the relay before any revocation");

    signal.revoke(rig.session_b.to_string().as_str());

    // Four poll intervals later, an unrelated session's revocation has not
    // reached this tunnel. This is the assertion a global kill fails.
    std::thread::sleep(Duration::from_millis(200));
    assert_still_running(
        &rx,
        "the relay after *another* session was revoked — revocation is not scoped \
         to the session it names",
    );

    // And the tunnel still works, all the way to a real credential at the origin.
    client.send(request_with(&rig.surrogate_a).as_bytes());
    let outcome = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("an unaffected tunnel must complete");
    let _ = handle.join().expect("the relay thread must not panic");

    assert!(
        outcome.is_ok(),
        "revoking session B cancelled session A's tunnel: {outcome:?}"
    );

    // Non-vacuity: the substitution really happened, from the origin's mouth.
    let received = rig.origin.wait_for_received(Duration::from_secs(5));
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.contains(REAL),
        "the origin did not receive the credential, so the tunnel did not work: {text}"
    );
}

// ---------------------------------------------------------------------------
// C2.8 increment 3b — one tunnel, many requests.
//
// Every test below drives a **real** TLS tunnel to a **real** origin over a
// **real** socket, with a real session proof and a real surrogate redemption per
// request. Nothing here mocks the relay, because the property under test *is*
// the relay: which bytes it forwards, which it withholds, and where it decides a
// message ends.
//
// **The relay runs on its own thread, and that is not a convenience.** A
// one-request relay is called *after* the client has sent its request, so a test
// can `send` then `relay_substituted`. A loop is the other way round: the relay
// has to be running *while* the client speaks to it, which is two threads and is
// also the shape the product has — a broker process and a client process. The
// first version of these tests called the relay at the end and every one of them
// hung on a client waiting for an answer from a relay that had not started.
// ---------------------------------------------------------------------------

/// The relay, running, and a bounded handle on how it ended.
struct Relaying {
    handle: std::thread::JoinHandle<RelayVerdict>,
    ended: std::sync::mpsc::Receiver<RelayVerdict>,
}

impl Relaying {
    /// Blocks until the relay returns, bounded, and says what it returned.
    ///
    /// The timeout is the important part. A relay that never returns — a
    /// deadlock, a refusal that forgot to close, a loop that lost track of where
    /// the next message starts — would otherwise hang the suite, and a suite
    /// that hangs is worse than one that fails: it says nothing at all about what
    /// went wrong and stops every other test from running.
    fn finish(self, what: &str) -> RelayVerdict {
        let verdict = self
            .ended
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|e| panic!("{what}: the relay never finished ({e:?})"));
        // Joined, not dropped. The channel carried the verdict, so a relay that
        // returned it *and then* panicked would look identical from here, and a
        // panic inside a background thread is otherwise silent: the test passes
        // and the reason is on a thread nobody joined.
        let _ = self
            .handle
            .join()
            .unwrap_or_else(|_| panic!("{what}: the relay thread panicked"));
        verdict
    }
}

fn start_relay(tunnel: EstablishedTunnel, rig: &Rig, limits: RelayLimits) -> Relaying {
    let (handle, ended) = relay_on_worker_with(tunnel, Arc::clone(&rig.registry), limits);
    Relaying { handle, ended }
}

/// The response a keep-alive origin gives a `GET`: a whole message with a
/// declared length and no reason to close.
fn ok_body(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn get(path: &str, surrogate: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {surrogate}\r\n\r\n")
        .into_bytes()
}

/// **The claim the increment exists for.** Five requests on one connection, five
/// real credential substitutions, five answers, and the connection closes only
/// when the client closes it.
///
/// The control is the last assertion. An origin that has run out of script closes
/// the connection, and a relay that quietly gave up after three requests looks
/// identical from the client — so the test asks the *destination* what it
/// received, and asks for a number rather than a boolean.
#[test]
fn one_tunnel_carries_five_requests_and_substitutes_every_one() {
    let rig = Rig::with_script(vec![ok_body("one"), ok_body("two"), ok_body("three")], 16);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    let surrogate = rig.surrogate_a.clone();

    for (path, answer) in [("/a", "one"), ("/b", "two"), ("/c", "three")] {
        client.send(&get(path, &surrogate));
        assert_eq!(
            client.read_head_str(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                answer.len()
            ),
            "the answer to {path} did not arrive whole"
        );
        assert_eq!(client.recv(answer.len()), answer.as_bytes().to_vec());
    }

    // The client hangs up at a message boundary, which is how every keep-alive
    // connection ends. A relay that reported it as a fault would be logging an
    // ordinary event as an incident.
    drop(client);
    let outcome = relay
        .finish("three requests then a client hang-up")
        .expect("three well-framed requests on one tunnel");
    assert_eq!(
        outcome.requests, 3,
        "the loop stopped before the client did"
    );
    assert!(
        !outcome.request_budget_spent,
        "the tunnel ended on a budget with {} requests allowed",
        RelayLimits::default().max_requests
    );

    let seen = String::from_utf8_lossy(&rig.scripted().received()).to_string();
    assert_eq!(
        seen.matches(REAL).count(),
        3,
        "the destination did not receive the credential on every request:\n{seen}"
    );
    assert_eq!(
        seen.matches(&surrogate).count(),
        0,
        "a surrogate reached the destination:\n{seen}"
    );
}

/// **A request body is relayed by the framing its head declared, and the next
/// request is read only where the body ended.**
///
/// This is the test that says the loop is not "scan for `\r\n\r\n`". The body
/// here contains that terminator twice, so a relay that scanned for it would
/// treat the middle of the form post as the next request — and would substitute a
/// credential into it. The credential count is the assertion: one substitution
/// per request, whatever the body contained.
#[test]
fn a_request_body_is_relayed_by_its_framing_and_the_next_head_is_read_after_it() {
    let body = "field=a\r\n\r\nfield=b\r\n\r\n&trailer=injected";
    let rig = Rig::with_script(vec![ok_body("first"), ok_body("second")], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    let surrogate = rig.surrogate_a.clone();

    client.send(
        format!(
            "POST /submit HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {surrogate}\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    eprintln!("DIAG sent post");
    client.read_head_str();
    client.recv(5);
    client.send(&get("/next", &surrogate));
    client.read_head_str();
    client.recv(6);
    drop(client);

    assert_eq!(
        relay
            .finish("a body then a plain request")
            .expect("a body-carrying request followed by a plain one")
            .requests,
        2
    );

    let seen = String::from_utf8_lossy(&rig.scripted().received()).to_string();
    assert_eq!(
        seen.matches(REAL).count(),
        2,
        "the credential was not substituted once per request, so the body was \
         re-read as a request:\n{seen}"
    );
    assert!(
        seen.contains(body),
        "the body did not arrive whole, so it was not relayed by its length:\n{seen}"
    );
}

/// A chunked response is relayed **verbatim**, framing included, and the request
/// after it still finds the relay at a message boundary.
///
/// The assertion is on the exact bytes. A relay that re-framed a chunked body —
/// buffering it and emitting one `Content-Length` — would also *work*, and it
/// would also be a relay that rewrote the framing of a message carrying a
/// credential, which is the one thing this relay does not do.
#[test]
fn a_chunked_response_is_relayed_byte_for_byte() {
    let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let framing = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let rig = Rig::with_script(
        vec![format!("{head}{framing}").into_bytes(), ok_body("after")],
        8,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    let surrogate = rig.surrogate_a.clone();

    client.send(&get("/stream", &surrogate));
    assert_eq!(
        client.read_head_str(),
        head,
        "the chunked head did not arrive"
    );
    let body = String::from_utf8(client.recv(framing.len())).expect("ascii body");
    assert_eq!(
        body, framing,
        "the chunked body was re-framed rather than relayed verbatim"
    );
    // And the connection is still usable, which is the half a truncating relay
    // fails and a re-framing one would get right by accident.
    client.send(&get("/next", &surrogate));
    client.read_head_str();
    assert_eq!(client.recv(5), b"after".to_vec());
    drop(client);

    assert_eq!(
        relay
            .finish("a chunked response then a plain one")
            .expect("a chunked response followed by a plain one")
            .requests,
        2
    );
    assert_eq!(rig.scripted().served(), 2);
}

/// An interim response is forwarded and is **not** the end of the exchange.
///
/// `100 Continue` is the case that matters: a relay that treated it as the answer
/// would close the tunnel while the client was still waiting to send its body, and
/// both peers would be waiting on each other with nothing in the log to explain it.
#[test]
fn an_interim_response_is_forwarded_and_the_real_answer_still_arrives() {
    let rig = Rig::with_script(
        vec![
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ],
        8,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    client.send(&get("/interim", &rig.surrogate_a.clone()));
    assert_eq!(client.read_head_str(), "HTTP/1.1 100 Continue\r\n\r\n");
    assert_eq!(
        client.read_head_str(),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
    );
    assert_eq!(client.recv(2), b"ok".to_vec());
    drop(client);

    let outcome = relay
        .finish("an interim response")
        .expect("an interim response is not a failure");
    assert_eq!(
        outcome.requests, 1,
        "the interim response was counted as the answer, so the loop ended one \
         response early"
    );
}

/// A response with no length and no chunking ends when the origin closes, and the
/// client receives exactly what the origin wrote.
///
/// The case that must **not** be refused: a server answering without a
/// `Content-Length` is common enough that a relay which declined it would break a
/// large share of real traffic. It is also the only framing whose extent the relay
/// cannot know in advance — which is why the lifetime budget, not the per-message
/// one, is the cap that applies to it.
#[test]
fn a_close_delimited_response_is_relayed_until_the_origin_closes() {
    let rig = Rig::with_script(
        vec![b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed".to_vec()],
        8,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    client.send(&get("/stream", &rig.surrogate_a.clone()));
    assert_eq!(
        client.read_head_str(),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    );
    assert_eq!(client.recv(8), b"streamed".to_vec());
    drop(client);

    assert_eq!(
        relay
            .finish("a close-delimited response")
            .expect("a close-delimited response is ordinary HTTP")
            .requests,
        1,
        "a close-delimited response is ordinary HTTP and must be counted"
    );
}

/// **The two things a sequential pump refuses, and refuses *before* writing a byte
/// to the origin.**
///
/// Each is a case where the ordinary request-then-response order would hang rather
/// than fail: both peers would be waiting on the other, nothing would time out, and
/// the only record would be a tunnel that stopped being interesting. The control
/// is the assertion that the origin received nothing at all — a refusal that got as
/// far as forwarding the head would have already put a surrogate on the wire.
#[test]
fn the_shapes_a_sequential_pump_cannot_carry_are_refused_before_anything_is_forwarded() {
    for (name, extra) in [
        (
            "Expect: 100-continue",
            "Content-Length: 4\r\nExpect: 100-continue\r\n",
        ),
        ("Upgrade", "Upgrade: websocket\r\n"),
    ] {
        let rig = Rig::with_script(vec![ok_body("never written")], 8);
        let (mut client, tunnel) = rig
            .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
            .expect("an authorised tunnel");
        let relay = start_relay(tunnel, &rig, RelayLimits::default());
        client.send(
            format!(
                "POST /x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\n{extra}\r\ndata",
                rig.surrogate_a
            )
            .as_bytes(),
        );
        let verdict = relay.finish(name);
        assert!(
            matches!(
                verdict,
                Err(BridgeError::Limit {
                    budget: "sequential_pump",
                    ..
                })
            ),
            "{name} was refused as {verdict:?}, and the reason an operator reads is \
             the whole point of the variant"
        );
        // Give the origin a moment in which it could have received something. A
        // refusal that raced ahead of the write would satisfy this immediately,
        // so the wait is what makes it a measurement rather than a hope.
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            rig.scripted().served(),
            0,
            "{name} reached the origin before being refused, so the relay wrote to a \
             protocol it had just said it would not carry"
        );
        drop(client);
    }
}

/// A `101` is refused by the same rule, and for the same reason: it is not an HTTP
/// message, and a relay that forwarded it would be asked to carry opaque bytes in
/// both directions at once.
#[test]
fn a_protocol_switch_from_the_origin_is_refused() {
    let rig = Rig::with_script(
        vec![b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec()],
        8,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    client.send(&get("/ws", &rig.surrogate_a.clone()));
    let verdict = relay.finish("a 101");
    assert!(
        matches!(
            verdict,
            Err(BridgeError::Limit {
                budget: "sequential_pump",
                ..
            })
        ),
        "a 101 was refused as {verdict:?}"
    );
    drop(client);
}

/// **Framing the relay will not guess at.** A head that names two different lengths
/// is refused and the tunnel ends, rather than one of them being picked.
///
/// The point is not that the request is refused — it is that the refusal is
/// *before* anything reaches the origin. A relay that picked the first
/// `Content-Length` and forwarded the head would have handed the destination a
/// message the client never sent, and the second length would still be sitting in
/// the client's buffer waiting to be read as a request.
#[test]
fn a_head_with_two_different_lengths_is_refused_before_anything_is_forwarded() {
    let rig = Rig::with_script(vec![ok_body("never written")], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    client.send(
        format!(
            "POST /x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\n\
             Content-Length: 4\r\nContent-Length: 40\r\n\r\ndata",
            rig.surrogate_a
        )
        .as_bytes(),
    );
    let verdict = relay.finish("an ambiguous head");
    assert!(
        matches!(verdict, Err(BridgeError::Protocol(_))),
        "an ambiguous head was refused as {verdict:?}"
    );
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        rig.scripted().served(),
        0,
        "an ambiguous head reached the origin"
    );
    drop(client);
}

/// A tunnel that reaches its request budget ends **at a message boundary** — a
/// normal end the client recovers from by reconnecting, not a truncation.
///
/// The distinction is the whole of `BridgeError::Limit` versus
/// `SubstitutionOutcome::request_budget_spent`. Ending a connection between two
/// whole messages is what every relay that limits a connection does; ending one in
/// the middle of a response is a lie to the client. The test asserts the count, so
/// a relay that stopped one request early cannot satisfy it.
#[test]
fn a_tunnel_that_reaches_its_request_budget_ends_between_two_whole_messages() {
    let rig = Rig::with_script(
        vec![
            ok_body("one"),
            ok_body("two"),
            ok_body("three"),
            ok_body("four"),
        ],
        16,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            max_requests: 2,
            ..RelayLimits::default()
        },
    );
    let surrogate = rig.surrogate_a.clone();
    for _ in 0..2 {
        client.send(&get("/x", &surrogate));
        client.read_head_str();
        client.recv(3);
    }
    drop(client);

    let verdict = relay.finish("a request budget");
    let outcome = verdict.expect("a budget spent between messages is a normal end");
    assert_eq!(outcome.requests, 2, "the loop did not stop at the budget");
    assert!(
        outcome.request_budget_spent,
        "the tunnel ended at the request budget and did not say so, so an operator \
         watching connections change cannot tell a finished client from a capped one"
    );
    assert_eq!(
        rig.scripted().served(),
        2,
        "the origin answered more requests than the tunnel carried"
    );
}

/// A per-message body over the limit is refused, and the refusal names the budget
/// rather than reading as a socket fault.
///
/// **The naming is the assertion.** A budget that ran out is a number somebody
/// chose, and an operator whose only record says `io_error` goes looking at a
/// socket. The variant exists so the record can say what happened, and this test
/// is what stops the class from collapsing back into `other`.
#[test]
fn a_body_over_the_per_message_limit_is_refused_and_named() {
    let rig = Rig::with_script(vec![ok_body("never written")], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            max_body: 64,
            ..RelayLimits::default()
        },
    );
    client.send(
        format!(
            "POST /x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\n\
             Content-Length: 4096\r\n\r\n",
            rig.surrogate_a
        )
        .as_bytes(),
    );
    let verdict = relay.finish("an over-limit body");
    assert!(
        matches!(
            verdict,
            Err(BridgeError::Limit {
                budget: "max_body",
                ..
            })
        ),
        "an over-limit body was refused as {verdict:?}, which reports a deliberate \
         limit as something else"
    );
    drop(client);
}

/// A response that runs past the tunnel's lifetime budget is **refused before
/// its body is forwarded**, not after.
///
/// The distinction this whole `BridgeError::Limit` distinction rests on, and the
/// one the falsification campaign found unwatched. The budget used to be spent by
/// adding the body's length to `returned` once the copy was finished, which meant
/// an origin declaring a `Content-Length` of eight gigabytes had all eight
/// gigabytes forwarded to the client before the tunnel noticed. The copy is
/// bounded now, and the observation that proves it is the byte count on the
/// client: a refused response delivers its head and nothing else.
///
/// The limits are ordered so the *parser's* bound cannot be what refuses:
/// `max_body` is above the declared length and `max_response` below it but above
/// the head, so the lifetime budget is the only one that can fire and the check
/// that fires is the body's rather than the head's.
#[test]
fn a_response_past_the_lifetime_budget_is_refused_before_its_body_is_forwarded() {
    let body = "x".repeat(512);
    let scripted = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let head_len = scripted.len() - body.len();
    let rig = Rig::with_script(vec![scripted], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            // Above the declared length, so the per-message bound cannot refuse.
            max_body: 4096,
            // Below the head plus the declared length and above the head alone.
            max_response: 200,
            ..RelayLimits::default()
        },
    );
    client.send(&get("/big", &rig.surrogate_a.clone()));
    let verdict = relay.finish("a response over the lifetime budget");
    // Read after the relay has finished, so what the client sees is the whole
    // story rather than a race with a thread that is still writing.
    let head = client.read_head_str();
    let seen = client.recv_within(body.len(), Duration::from_millis(500));

    assert_eq!(
        head,
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()),
        "a refused response still relays the origin's head verbatim"
    );
    assert!(
        matches!(
            verdict,
            Err(BridgeError::Limit {
                budget: "max_response",
                ..
            })
        ),
        "a response past the lifetime budget ended as {verdict:?}, so the budget \
         was spent after the copy: the tunnel put the {} byte head on the wire and \
         {} of the {} body bytes the origin declared before it noticed",
        head_len,
        seen.len(),
        body.len()
    );
    assert!(
        seen.is_empty(),
        "the relay forwarded {} body bytes it had already refused to afford",
        seen.len()
    );
    drop(client);
}

/// A close-delimited response that runs past the lifetime budget is **refused**,
/// not cut at the cap and reported as a complete one.
///
/// The framing with no `Content-Length` and no `Transfer-Encoding` ends when the
/// origin closes, so nothing in the message says how long it is. The cap is
/// therefore the copy itself — and a body that *exactly fills* the cap is
/// indistinguishable from one that is longer, so the relay looks one byte past
/// it. Without that look the copy stopped at the budget, the loop asked for the
/// next head, the origin had closed, and the tunnel returned `Ok`: the client
/// held a head promising 512 bytes, 181 of them, and a clean end. That is the
/// one outcome this relay refuses to produce anywhere else.
#[test]
fn a_close_delimited_response_past_the_lifetime_budget_is_refused_rather_than_cut() {
    let head_text = "HTTP/1.1 200 OK\r\n\r\n";
    let body = "y".repeat(512);
    let rig = Rig::with_script(vec![format!("{head_text}{body}").into_bytes()], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            max_body: 4096,
            max_response: 200,
            ..RelayLimits::default()
        },
    );
    client.send(&get("/stream", &rig.surrogate_a.clone()));
    let verdict = relay.finish("a close-delimited response over the lifetime budget");
    let head = client.read_head_str();
    let seen = client.recv_within(body.len(), Duration::from_millis(500));

    assert_eq!(
        head, head_text,
        "the origin's head was not relayed verbatim"
    );
    assert!(
        matches!(
            verdict,
            Err(BridgeError::Limit {
                budget: "max_response",
                ..
            })
        ),
        "a close-delimited response past the lifetime budget ended as {verdict:?}, so \
         it was cut at the cap and reported as complete"
    );
    assert_eq!(
        seen,
        vec![b'y'; 200 - head_text.len()],
        "the client should hold exactly the body the budget allowed, and the refusal \
         is the byte after it"
    );
    drop(client);
}

/// **The control for the probe the row above needs**: a close-delimited response
/// that lands exactly on the budget is complete, and a look one byte past the cap
/// that finds nothing must not turn a finished message into a refusal.
///
/// Without this, "always refuse when the cap is reached" passes every test in the
/// suite and every real response. The body is sized from the head and the budget
/// rather than written as a number, so a drift in either shows up here instead of
/// as a tunnel that refuses every streaming response.
#[test]
fn a_close_delimited_response_that_lands_exactly_on_the_budget_is_not_refused() {
    let head_text = "HTTP/1.1 200 OK\r\n\r\n";
    let budget = 200usize;
    let body = "z".repeat(budget - head_text.len());
    let rig = Rig::with_script(vec![format!("{head_text}{body}").into_bytes()], 8);
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            max_body: 4096,
            max_response: budget,
            ..RelayLimits::default()
        },
    );
    client.send(&get("/exact", &rig.surrogate_a.clone()));
    client.read_head_str();
    let seen = client.recv_within(body.len(), Duration::from_millis(500));
    // The client hangs up before the relay is asked how it ended, and that is
    // load-bearing rather than tidiness: a completed response leaves the loop
    // waiting for the *client's* next request, so a test that holds the client
    // open is measuring its own patience. The first version of this did exactly
    // that and reported the socket's read timeout as a verdict.
    drop(client);
    let outcome = relay
        .finish("a close-delimited response landing on the budget")
        .expect("a body that fills the budget exactly is a complete body");

    assert_eq!(
        seen,
        body.as_bytes().to_vec(),
        "a body that lands on the budget was not delivered whole"
    );
    assert_eq!(
        outcome.returned, budget,
        "the head and the body together are the budget, and the count says so"
    );
    assert_eq!(outcome.requests, 1, "one request, one response");
}

/// A response **head** is charged to the lifetime budget before it is sent, and
/// a tunnel that has already returned more than its budget says so at the first
/// byte rather than after the body it is refusing.
///
/// A head cannot run away — `max_head` bounds it — but it is a message like any
/// other and the budget governing the body it introduces has to govern it too.
/// The limits are chosen so the first response fits and the second head does
/// not: two 37 byte heads against a 60 byte budget, so the second is 23 bytes of
/// head over the line and has nothing else about it worth mentioning.
#[test]
fn a_response_head_past_the_lifetime_budget_is_refused_before_it_is_sent() {
    let empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let rig = Rig::with_script(
        vec![empty.as_bytes().to_vec(), empty.as_bytes().to_vec()],
        8,
    );
    let (mut client, tunnel) = rig
        .tunnel(Some(rig.proof(Who::A, HOST, 443)), 443)
        .expect("an authorised tunnel");
    let relay = start_relay(
        tunnel,
        &rig,
        RelayLimits {
            max_response: 60,
            ..RelayLimits::default()
        },
    );
    let surrogate = rig.surrogate_a.clone();

    client.send(&get("/one", &surrogate));
    client.read_head_str();
    client.send(&get("/two", &surrogate));
    let verdict = relay.finish("a second head past the lifetime budget");
    let leaked = client.recv_within(empty.len(), Duration::from_millis(500));

    assert!(
        matches!(
            verdict,
            Err(BridgeError::Limit {
                budget: "max_response",
                ..
            })
        ),
        "a second response head past the lifetime budget ended as {verdict:?}, so \
         the head went on the wire past the lifetime budget and the tunnel noticed \
         only afterwards"
    );
    assert!(
        leaked.is_empty(),
        "the client holds {} bytes of the head the relay was supposed to refuse",
        leaked.len()
    );
    drop(client);
}

/// A revocation reaches a tunnel that is **inside** the loop, not only one that is
/// waiting for its first request.
///
/// This is the test the `relay_back` defect was really about, extended to the
/// case the loop creates. Before the loop there was exactly one blocking read on
/// the client side and one on the response side, both of which had to be made
/// cancellable; now there are as many as the tunnel carries messages, and
/// cancellation has to be consulted at each one. A loop that only checked at its
/// first read would be a tunnel that revokes itself exactly when a client is
/// mid-exchange, which is the state a revocation most often has to interrupt.
#[test]
fn a_revocation_reaches_a_tunnel_that_is_inside_the_loop() {
    use asv_broker::tls_bridge::{Cancel, CancelReason};

    #[derive(Debug)]
    struct Revoke(Arc<std::sync::atomic::AtomicBool>);
    impl Cancel for Revoke {
        fn cancel_reason(&self, session: Option<&AgentSessionId>) -> Option<CancelReason> {
            if self.0.load(Ordering::SeqCst) {
                Some(CancelReason::SessionRevoked)
            } else {
                let _ = session;
                None
            }
        }
    }

    let rig = Rig::with_script(vec![ok_body("never written")], 8);
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel: Arc<dyn Cancel + Send + Sync> = Arc::new(Revoke(Arc::clone(&flag)));
    let (mut client, tunnel) = rig
        .tunnel_cancellable(Some(rig.proof(Who::A, HOST, 443)), 443, cancel)
        .expect("an authorised tunnel");
    let relay = start_relay(tunnel, &rig, RelayLimits::default());
    let surrogate = rig.surrogate_a.clone();

    // One exchange that completes, so the relay is provably *inside* the loop
    // rather than still reading its first head — which is the only state from
    // which this says anything.
    client.send(&get("/first", &surrogate));
    client.read_head_str();
    client.recv(5);
    // Now the client is idle, waiting for a request to be worth making, and the
    // relay is blocked reading the next one.
    assert_still_running(&relay.ended, "the relay");
    flag.store(true, Ordering::SeqCst);

    let verdict = relay.finish("a revocation inside the loop");
    assert!(
        matches!(
            verdict,
            Err(BridgeError::Cancelled(CancelReason::SessionRevoked))
        ),
        "a revocation inside the loop ended the relay as {verdict:?}, so a revoke \
         could not reach a tunnel between two messages"
    );
    drop(client);
}
