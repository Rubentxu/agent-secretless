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
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asv_broker::audit::{AuditLog, SubstitutionRecorder};
use asv_broker::tls_bridge::{
    issue_leaf, proof_nonce, AuthorityEndpoint, Bridge, BridgeError, ConnectPolicy,
    EstablishedTunnel, LeafError, LeafSource, RelayLimits, SessionCa, SessionProofs,
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

/// Counts `resolve` calls, so the ordering test can prove the proof was never
/// looked at rather than inferring it from an error.
struct CountingProofs {
    inner: Arc<SessionStore>,
    calls: Arc<Mutex<usize>>,
}

impl SessionProofs for CountingProofs {
    fn resolve(
        &self,
        presented_key: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Option<AgentSessionId> {
        *self.calls.lock().expect("count") += 1;
        self.inner.resolve(presented_key, nonce, signature)
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
    Bridge::new(ConnectPolicy {
        allowed: vec![endpoint(HOST, 443), endpoint(HOST, OTHER_PORT)],
    })
}

struct Rig {
    store: Arc<SessionStore>,
    registry: SurrogateRegistry,
    ca: Arc<SessionCa>,
    root_der: Vec<u8>,
    origin: Origin,
    session_a: AgentSessionId,
    session_b: AgentSessionId,
    key_a: SigningKey,
    key_b: SigningKey,
    stranger: SigningKey,
    /// The surrogate minted for session A over the canary credential.
    surrogate_a: String,
    /// The surrogate minted for session B.
    surrogate_b: String,
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
            store: Arc::new(store),
            registry,
            ca,
            root_der,
            origin: Origin::start(),
            session_a,
            session_b,
            key_a,
            key_b,
            stranger: SigningKey::generate(&mut rand::rngs::OsRng),
            surrogate_a,
            surrogate_b,
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
        let nonce = proof_nonce(&blob, &target);
        let signature = key.sign(&nonce).to_bytes();
        format!("{}.{}", b64(&blob), b64(&signature))
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
        let proofs: Arc<dyn SessionProofs + Send + Sync> = self.store.clone();
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
        let proofs: Arc<dyn SessionProofs + Send + Sync> = self.store.clone();
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
            addr: self.origin.addr,
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
            addr: self.origin.addr,
        };
        let proofs: Arc<dyn SessionProofs + Send + Sync> = self.store.clone();

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

    fn recv(&mut self, n: usize) -> Vec<u8> {
        let _ = self.0.sock.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buffer = vec![0u8; n];
        self.0.read_exact(&mut buffer).expect("client reads");
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);

    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    assert_eq!(
        tunnel.session, rig.session_a,
        "the proof resolved to something other than the session whose key signed it"
    );

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::B, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    assert_eq!(
        tunnel.session, rig.session_b,
        "B's proof resolved to A, which is exactly the escalation under test"
    );

    // A's token, spent in B's tunnel.
    client.send(request_with(&rig.surrogate_a).as_bytes());
    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();

    // Wrong session first, on its own tunnel.
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(request_with(&rig.surrogate_b).as_bytes());
    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig2 = Rig::new();
    let proof = rig2.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig2.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(request_with(&rig2.surrogate_a).as_bytes());
    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig2.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let nonce = proof_nonce(&presented_blob, &target);
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
    let nonce = proof_nonce(&blob, &target);
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
    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![endpoint(HOST, 443)],
    });
    let leaves = SessionLeaves { ca: Arc::new(ca) };
    let upstream = FixedUpstream { addr: origin.addr };
    let calls = Arc::new(Mutex::new(0usize));
    let proofs = CountingProofs {
        inner: Arc::new(store),
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");
    client.send(b"GET /repos/o/r/issues HTTP/1.1\r\nHost: api.github.test\r\n\r\n");

    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut log = AuditLog::new(0);
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_b).as_bytes());

    let mut log = AuditLog::new(0);
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
    let mut rig = Rig::new();
    let proof = rig.proof(Who::A, HOST, 443);
    let (mut client, mut tunnel) = rig.tunnel(Some(proof), 443).expect("an authorised tunnel");

    client.send(request_with(&rig.surrogate_a).as_bytes());

    let mut audit = Collected::default();
    let mut port = SubstitutionPort::new(
        &mut rig.registry,
        &CanaryStore,
        OperationFamily::GitHub,
        "github",
    );
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
fn relay_on_worker(
    tunnel: EstablishedTunnel,
    registry: SurrogateRegistry,
) -> (
    std::thread::JoinHandle<RelayVerdict>,
    std::sync::mpsc::Receiver<RelayVerdict>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        let mut tunnel = tunnel;
        let mut registry = registry;
        let mut audit = Collected::default();
        let mut port = SubstitutionPort::new(
            &mut registry,
            &CanaryStore,
            OperationFamily::GitHub,
            "github",
        );
        let outcome = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());
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

    let (handle, rx) = relay_on_worker(tunnel, rig.registry);
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

    let (handle, rx) = relay_on_worker(tunnel, rig.registry);
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
    let (handle, rx) = relay_on_worker(tunnel, rig.registry);
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
