//! C2.8 — the leg from the broker to the destination.
//!
//! This is the hop the previous revision of this path had no shape for at all:
//! `serve_connect` resolved a `SocketAddr` and dialled a bare `TcpStream`, and
//! the bytes that crossed it were the request the relay had just rewritten —
//! `Authorization: Bearer <the real credential>`. The agent-to-broker hop is
//! TLS with a per-session leaf. The broker-to-destination hop was not TLS, on
//! every tunnel, with nothing in the configuration saying so.
//!
//! The properties, and the second is the one that matters:
//!
//! 1. A destination whose certificate verifies against the **operator's**
//!    anchors, and whose name is the route's name, is reached over TLS — and
//!    the rewritten request arrives on the other end of it.
//! 2. A destination whose certificate does not verify is refused, and **the
//!    credential is never written to it**. Refused at the handshake, which is
//!    the only point where "before" still means anything.
//! 3. A bridge with no transport declared reaches no destination at all — the
//!    fail-closed default that a bare `TcpStream` did not have.
//! 4. An empty anchor store verifies nothing, rather than falling back to
//!    trusting the internet.
//! 5. An explicit `cleartext` route still reaches a plain destination — the
//!    control that keeps 1-4 from being a gate that only ever says no.
//! 6. The table an operator actually wrote, through the policy production
//!    actually installs, is what decides the transport — and a route that says
//!    `tls` is dialled over TLS.
//! 7. A destination the route table does not know is not dialled at all, even
//!    when the bridge's policy would have allowed the attempt.
//!
//! Properties 6 and 7 exist because the falsification campaign in
//! `tests/upstream_tls_falsification.py` caught a **hole** where a defect was
//! assumed: the first five were all measured through a test-local policy, and
//! nothing in the workspace exercised `RouteTransports`, the one production
//! uses. A mutation that turned a route's `tls` declaration into `cleartext`
//! left the whole suite green. Read `the_route_table_says_how_its_destination
//! _is_reached` for what that cost and what it fixed.
//!
//! The origin is a real TLS server built from a session CA, because the
//! property is a *trust* property: a fixture that trusted everything would make
//! properties 1 and 2 indistinguishable. And the tunnel is driven all the way
//! through `relay_substituted`, because a handshake that completes proves the
//! socket is encrypted and says nothing about whether the credential went over
//! it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asv_broker::connect_routes::{ConnectRouteSet, UpstreamTransport};
use asv_broker::connect_runtime::RouteTransports;
use asv_broker::tls_bridge::{
    issue_leaf, AuthorityEndpoint, Bridge, BridgeError, CleartextUpstream, ConnectPolicy,
    LeafError, LeafSource, RelayLimits, SessionCa, SessionProofs, SubstitutionAudit,
    SubstitutionOutcome, SubstitutionRecord, UpstreamResolver, UpstreamTransportPolicy,
    VerifiedLeaf, SESSION_PROOF_HEADER,
};
use asv_broker::{SubstitutionPort, SurrogateRegistry};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_domain::{AgentSessionId, Authority, CredentialClass, CredentialId, OperationFamily};
use asv_policy::PolicyEngine;
use asv_tls_acceptor::LeafMaterial;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

const HOST: &str = "origin.example.com";
const PORT: u16 = 443;

/// The credential the operator planted, and the only one the destination may
/// ever see. Shaped so "it came from us" is not a coincidence.
const REAL: &str =
    "npm_ASVcanaryUpstreamTls2b4d6f8a0c2e4f6a8b0c2e4f6a8b0c2e4f6a8b0c2e4f6a8b0c2e4f6a";
/// The credential the surrogate stands for, in the wire form the vault uses.
const CRED: &str = "9c2f4a10-6b3e-4d51-8f27-1a5e0b93cc40";

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// A TLS origin presenting a leaf for `HOST`, and a witness on what it got.
///
/// The `received` buffer is the whole of the second property: "the credential
/// was not written" is only observable from the far end of the socket, and a
/// test asserting it from the broker's own error would be the broker agreeing
/// with itself.
struct TlsOrigin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    handshook: Arc<Mutex<bool>>,
}

impl TlsOrigin {
    fn start(ca: &SessionCa) -> Self {
        let leaf = issue_leaf(ca, HOST, Instant::now()).expect("issue the origin's leaf");
        // **The chain, not just the leaf.** A session CA is two levels — root,
        // intermediate, leaf — and a trust store holding only the root can only
        // build a path if the peer presents the intermediate. Passing the
        // end-entity alone fails with `UnknownIssuer`, which reads as "the
        // anchor is wrong" and is not: the anchor is right and the chain is
        // short. A real server sends both, so this one does too.
        let material = LeafMaterial::new(
            ca.root_der.clone(),
            vec![leaf.leaf_der.clone(), ca.intermediate_der.clone()],
            leaf.leaf_key.serialize_der(),
        )
        .expect("leaf material");
        let config = Arc::new(material.server_config().expect("server config"));

        let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let handshook = Arc::new(Mutex::new(false));
        let (r, h) = (Arc::clone(&received), Arc::clone(&handshook));

        thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let Ok(connection) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(connection, socket);
            // If the handshake fails the origin records nothing and the buffer
            // stays empty — which is exactly what property 2 observes.
            if tls.conn.complete_io(&mut tls.sock).is_err() {
                return;
            }
            *h.lock().expect("handshook") = true;
            let mut buf = [0u8; 4096];
            if let Ok(n) = tls.read(&mut buf) {
                r.lock().expect("body").extend_from_slice(&buf[..n]);
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });

        Self {
            addr,
            received,
            handshook,
        }
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("body").clone()
    }

    fn handshook(&self) -> bool {
        *self.handshook.lock().expect("handshook")
    }

    /// Wait for the origin to have read something, bounded.
    ///
    /// The origin is on its own thread, so reading straight after the relay
    /// returns is a race: an empty read would fail a test for being early
    /// rather than for being wrong — and a probe with no wait would be a test
    /// that cannot fail.
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
}

// ---------------------------------------------------------------------------
// Harnesses
// ---------------------------------------------------------------------------

struct FixedUpstream {
    addr: SocketAddr,
}

impl UpstreamResolver for FixedUpstream {
    fn resolve(&self, _target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        Ok(self.addr)
    }
}

/// Answers with one transport for every destination, named the way a route
/// file names it.
#[derive(Debug)]
struct Always(UpstreamTransport);

impl UpstreamTransportPolicy for Always {
    fn transport_for(&self, _target: &AuthorityEndpoint) -> Result<UpstreamTransport, BridgeError> {
        Ok(self.0)
    }
}

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

/// Resolves a proof to a session by its counter, so one listener can carry
/// tunnels belonging to **different** sessions at the same time.
///
/// The counter is the only part of a proof a fixture can choose freely, and it
/// is enough: the test needs N tunnels from N sessions, not N verified
/// signatures. What is under test is what happens to a set of tunnels when one
/// session is revoked while the rest keep running.
/// A counter no two rigs share.
///
/// `fetch_add` rather than a `Cell` on each rig: the rigs are created in a loop
/// from one place, and a counter that could repeat would let a second tunnel
/// silently answer to the first one's session — which is precisely the mistake
/// the scoping assertion exists to catch, so the fixture must not be able to
/// make it by accident.
fn next_counter() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

#[derive(Default)]
struct ProofsByCounter {
    sessions: std::sync::Mutex<std::collections::HashMap<u64, AgentSessionId>>,
}

impl ProofsByCounter {
    fn register(&self, counter: u64, session: AgentSessionId) {
        self.sessions
            .lock()
            .expect("proof map")
            .insert(counter, session);
    }
}

/// A newtype, because `SessionProofs` is not object-safe to hand to the bridge
/// as a reference to a trait object and the test needs a table it can share
/// between rigs it creates one after another.
struct SessionProofsRef(Arc<ProofsByCounter>);

impl SessionProofs for SessionProofsRef {
    fn authenticate(
        &self,
        proof: &asv_broker::tls_bridge::SessionProof,
        target: &AuthorityEndpoint,
    ) -> Result<AgentSessionId, asv_broker::ProofRejection> {
        self.0.authenticate(proof, target)
    }
}

impl SessionProofs for ProofsByCounter {
    fn authenticate(
        &self,
        proof: &asv_broker::tls_bridge::SessionProof,
        _target: &AuthorityEndpoint,
    ) -> Result<AgentSessionId, asv_broker::ProofRejection> {
        self.sessions
            .lock()
            .expect("proof map")
            .get(&proof.counter)
            .copied()
            .ok_or(asv_broker::ProofRejection::NoSuchSession)
    }
}

/// The credential store's only job: hand out the canary for the one credential
/// a surrogate was minted over, and refuse every other.
///
/// Refusing the rest is the point. A store that answered anything would make
/// these tests unable to distinguish "the credential reached the destination"
/// from "some credential reached the destination".
struct CanaryStore;

impl SecretPort for CanaryStore {
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        if credential != CRED {
            return Err(SecretError::NotFound(credential.to_string()));
        }
        sink.accept(REAL.as_bytes())
    }
}

/// Keeps the records instead of discarding them. Nothing in this file asserts
/// on them, and that is deliberate: the properties here are about the socket
/// and about the destination's view of it, which a log written by the thing
/// under test could not witness.
#[derive(Default)]
struct Collected(Vec<SubstitutionRecord>);

impl SubstitutionAudit for Collected {
    fn record(&mut self, record: SubstitutionRecord) -> Result<(), BridgeError> {
        self.0.push(record);
        Ok(())
    }
}

fn endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(HOST).expect("host"), PORT).expect("endpoint")
}

/// A trust store holding exactly one anchor.
fn trusting(anchor_der: &[u8]) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(anchor_der.to_vec()))
        .expect("the anchor is a certificate this crate just minted");
    Arc::new(roots)
}

/// A client that trusts `root_der` and completes the bridge's TLS handshake.
fn client_handshake(
    root_der: &[u8],
    stream: TcpStream,
) -> Result<rustls::StreamOwned<ClientConnection, TcpStream>, BridgeError> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let config = ClientConfig::builder()
        .with_root_certificates(trusting(root_der).as_ref().clone())
        .with_no_client_auth();
    let name = ServerName::try_from(HOST.to_string())
        .map_err(|e| BridgeError::Handshake(format!("{e}")))?;
    let connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| BridgeError::Handshake(e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| BridgeError::Handshake(format!("client handshake failed: {e}")))?;
    Ok(tls)
}

/// The whole path: client TLS to the bridge, CONNECT, the relay, the upstream
/// handshake, the request rewritten and forwarded.
struct Rig {
    ca: Arc<SessionCa>,
    listener: TcpListener,
    origin_addr: SocketAddr,
    session: AgentSessionId,
    /// The counter this rig's proof spends, which is also how the shared
    /// [`ProofsByCounter`] knows which session a tunnel belongs to.
    counter: u64,
    proofs: Arc<ProofsByCounter>,
}

impl Rig {
    fn new(ca: SessionCa, origin_addr: SocketAddr) -> Self {
        Self::with_proofs(
            Arc::new(ca),
            origin_addr,
            Arc::new(ProofsByCounter::default()),
            AgentSessionId::new(),
        )
    }

    /// A rig sharing a proof table, so several tunnels can be in flight at once
    /// and each can belong to a different session.
    ///
    /// The CA arrives as an `Arc` because [`SessionCa`] is not `Clone` — it owns
    /// a `rcgen::KeyPair` — and a dozen rigs each minting their own CA would make
    /// the client handshake a second variable in a test whose subject is the
    /// revocation.
    /// `session` is an argument because several tunnels have to belong to
    /// **one** session for a revocation to have something to cancel. Minting a
    /// session per rig looks equivalent and is the opposite: revoking one of
    /// them then leaves the rest legitimately untouched, and the first version
    /// of this test reported `1 of 8` for exactly that reason — a correct
    /// product refusing to cancel tunnels it had no authorisation over, read as
    /// a cancellation that did not scale.
    fn with_proofs(
        ca: Arc<SessionCa>,
        origin_addr: SocketAddr,
        proofs: Arc<ProofsByCounter>,
        session: AgentSessionId,
    ) -> Self {
        let counter = next_counter();
        proofs.register(counter, session);
        Self {
            ca,
            listener: TcpListener::bind("127.0.0.1:0").expect("bridge binds"),
            origin_addr,
            session,
            counter,
            proofs,
        }
    }

    /// The wire form of this rig's proof: `<key>.<counter>.<signature>`.
    ///
    /// The key and the signature are the same fixed blob in every rig. Only the
    /// counter carries meaning, and that is enough: what is under test is what
    /// happens to a set of tunnels when one session is revoked, not whether a
    /// signature verifies — which the broker's own verifier tests cover.
    fn proof_value(&self) -> String {
        format!("QUFB.{}.QkJC", self.counter)
    }

    fn bridge(&self, transport: UpstreamTransport, roots: Arc<RootCertStore>) -> Bridge {
        Bridge::new(ConnectPolicy {
            allowed: vec![endpoint()],
        })
        .with_upstream(Arc::new(Always(transport)), roots)
    }

    /// The same bridge, cancellable by a signal shared with other tunnels.
    ///
    /// A separate constructor rather than a defaulted argument, because the
    /// tests above deliberately build bridges that **cannot** be cancelled: a
    /// bridge with no cancel source is the shape that makes "the relay ended"
    /// mean "the relay finished", and giving every rig a signal would quietly
    /// remove the distinction those tests rest on.
    fn cancellable_bridge(
        &self,
        transport: UpstreamTransport,
        cancel: Arc<asv_broker::connect_listener::ShutdownSignal>,
    ) -> Bridge {
        Bridge::new(ConnectPolicy {
            allowed: vec![endpoint()],
        })
        .with_upstream(
            Arc::new(Always(transport)),
            Arc::new(RootCertStore::empty()),
        )
        .with_cancel(cancel)
    }

    /// Establish the tunnel and nothing else, returning the relay's two inputs.
    ///
    /// **Split from [`Rig::relay`] because "before a single byte is written" is
    /// only observable as *where* the failure happened.** A lazy handshake fails
    /// in the same test, with the same empty origin buffer, because a
    /// destination whose handshake failed cannot read the bytes that would have
    /// convicted it. The only thing that separates "refused before the tunnel
    /// existed" from "refused after the relay handed over the secret" is
    /// whether `serve_connect` ever returned a tunnel at all — and the first
    /// version of this file asserted only the buffer and called it the security
    /// property, which the falsification campaign proved it was not.
    ///
    /// **The order here is the bridge's, and it is not a choice this test gets
    /// to make.** `serve_connect` reads the CONNECT head in the clear, answers
    /// `200 Connection Established` in the clear, and only then does the TLS
    /// handshake. Handshaking first, or starting the bridge after reading the
    /// ack, is a deadlock that surfaces as a read timeout — which is how the
    /// first version of this file failed all five of its tests.
    fn establish(
        &self,
        bridge: Bridge,
    ) -> Result<
        (
            asv_broker::tls_bridge::EstablishedTunnel,
            rustls::StreamOwned<ClientConnection, TcpStream>,
        ),
        BridgeError,
    > {
        let mut client =
            TcpStream::connect(self.listener.local_addr().expect("bridge addr")).expect("connect");
        let (server_side, _) = self.listener.accept().expect("bridge accepts");
        let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
        client
            .write_all(
                format!(
                    "CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}\r\n\
                     {SESSION_PROOF_HEADER}: {proof}\r\n\r\n",
                    proof = self.proof_value()
                )
                .as_bytes(),
            )
            .expect("write CONNECT");
        client.flush().expect("flush");

        // The bridge starts **now**: it is the one that writes the ack, and it
        // is about to block in the client handshake that this thread has to
        // answer.
        let (leaves, upstream, proofs) = (
            SessionLeaves {
                ca: Arc::clone(&self.ca),
            },
            FixedUpstream {
                addr: self.origin_addr,
            },
            // The shared table, not a fixed session: the cancellation test
            // stands up several rigs at once and each tunnel has to belong to
            // the session the test will revoke.
            SessionProofsRef(Arc::clone(&self.proofs)),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = tx.send(bridge.serve_connect(
                server_side,
                &leaves,
                &upstream,
                Some(&proofs),
                Instant::now(),
            ));
        });

        let mut ack = Vec::new();
        let mut byte = [0u8; 1];
        while !ack.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).expect("read the CONNECT ack");
            ack.push(byte[0]);
        }
        assert!(
            String::from_utf8_lossy(&ack).starts_with("HTTP/1.1 200"),
            "the bridge refused the CONNECT before any TLS: {}",
            String::from_utf8_lossy(&ack)
        );

        let tls = client_handshake(&self.ca.root_der, client)?;
        let tunnel = match rx.recv() {
            Ok(outcome) => outcome?,
            Err(_) => panic!("the bridge thread died before answering"),
        };
        worker.join().expect("the bridge thread");
        Ok((tunnel, tls))
    }

    /// Relay whatever the peer sends, to completion.
    fn relay(
        &self,
        (mut tunnel, mut tls): (
            asv_broker::tls_bridge::EstablishedTunnel,
            rustls::StreamOwned<ClientConnection, TcpStream>,
        ),
    ) -> Result<SubstitutionOutcome, BridgeError> {
        let (mut port, surrogate) = self.port();
        // The client writes on its own thread: the relay reads from the peer,
        // and a test that wrote from this thread would deadlock on the first
        // read rather than failing on anything it names.
        let request = format!(
            "GET /v1/repos/o/r HTTP/1.1\r\nHost: {HOST}\r\n\
             Authorization: Bearer {surrogate}\r\nAccept: application/json\r\n\r\n"
        );
        let writer = thread::spawn(move || {
            let _ = tls.write_all(request.as_bytes());
            let _ = tls.flush();
            // Hold the connection open until the relay has finished with it, so
            // the relay's read finds the response rather than a reset.
            thread::sleep(Duration::from_millis(700));
        });

        let mut audit = Collected::default();
        let outcome = tunnel.relay_substituted(&mut port, &mut audit, RelayLimits::default());
        drop(writer);
        outcome
    }

    /// A port with one credential behind it, and the surrogate standing for it.
    ///
    /// The token comes back too, because the request has to present *this* one:
    /// a literal typed into the request would be a token nothing can redeem, and
    /// the tunnel would then fail on the credential rather than on anything
    /// these tests are about.
    fn port(&self) -> (SubstitutionPort, String) {
        let mut registry = SurrogateRegistry::new();
        let now = asv_broker::surrogate::now_secs();
        // The registry *is* the holder: the port redeems through it, so there is
        // nothing to register anywhere else. Binding the surrogate here is
        // still worth doing, because the token it returns is the one the client
        // is about to present, and a test that minted one and then let it fall
        // out of scope would be testing a tunnel whose credential is unknown.
        let (surrogate, _, _) = registry
            .mint(
                self.session,
                credential_id(),
                CredentialClass::Generic,
                3600,
                1,
                now,
            )
            .expect("mint the session's surrogate");
        assert!(
            surrogate.starts_with("asv1_"),
            "the minted surrogate does not look like one, so the request below would \
             present a token nothing can redeem: {surrogate}"
        );
        (
            SubstitutionPort::new(
                Arc::new(std::sync::Mutex::new(registry))
                    as Arc<dyn asv_broker::surrogate::SurrogateLending + Send + Sync>,
                Arc::new(CanaryStore) as Arc<dyn SecretPort + Send + Sync>,
                OperationFamily::GitHub,
                "github",
            ),
            surrogate,
        )
    }
}

fn credential_id() -> CredentialId {
    CredentialId::from_wire(CRED).expect("canonical id")
}

/// A route file, spelled the way an operator spells one.
///
/// **JSON, not a `ConnectRoute` literal.** The thing under test reaches the
/// transport through a field that `serde` has to accept, and a struct built in
/// Rust would pass whether or not the file format could express what the route
/// says. `--connect-routes` is a file; a test that skipped the file would be
/// measuring the struct.
fn route_file(authority: &str, transport: &str) -> String {
    format!(
        r#"[{{
  "authority": "{authority}",
  "port": {PORT},
  "operation_family": "git_hub",
  "credential": "{CRED}",
  "minimum_posture": "STRONG_SECRETLESS",
  "upstream": "{transport}"
}}]"#
    )
}

/// The table `main.rs` would have built from `--connect-routes`.
///
/// The stock policy permits no route at all, which is the fail-closed reading,
/// so this supplies the permissive text explicitly and locally. A fixture that
/// leaned on a default would make "the route was authorized" and "nothing was
/// checked" the same observation.
fn route_set(routes_json: &str) -> ConnectRouteSet {
    ConnectRouteSet::load(
        routes_json,
        &PolicyEngine::from_policy_text(
            r#"permit (principal, action == Action::"connect_route", resource is Host);"#,
        )
        .expect("test policy must validate"),
    )
    .expect("the route file must load")
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

/// **1.** A destination whose certificate verifies against the operator's
/// anchors, and whose name is the route's name, is reached over TLS — and the
/// **real credential** arrives over that leg.
#[test]
fn a_destination_whose_certificate_verifies_is_reached_over_tls() {
    let ca = SessionCa::new("origin-ca", 3, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca);
    let roots = trusting(&ca.root_der);
    let rig = Rig::new(ca, origin.addr);

    let bridge = rig.bridge(UpstreamTransport::Tls, roots);
    // The relay is allowed to end badly — the origin answers one request and
    // the harness does not model a full exchange. What it must not do is fail
    // at the handshake, and what the origin must have is the request.
    let established = rig
        .establish(bridge)
        .expect("a verifying destination is reached");
    let _ = rig.relay(established);

    assert!(
        origin.handshook(),
        "the destination never completed a handshake, so the credential was never \
         encrypted onto this leg"
    );
    let seen =
        String::from_utf8_lossy(&origin.wait_for_received(Duration::from_secs(5))).to_string();
    assert!(
        !seen.is_empty(),
        "the origin completed a handshake and then received nothing, so the request \
         was not relayed over the encrypted leg"
    );
    assert!(
        seen.contains(REAL),
        "the destination did not receive the real credential: {seen}"
    );
    assert!(
        !seen.contains("placeholder"),
        "the destination received the surrogate instead of the credential: {seen}"
    );
}

/// **2.** A destination whose certificate does not verify is refused, and the
/// credential is never written to it.
///
/// The property the whole change exists for, and it has two halves that can
/// come apart. The error says the handshake was refused. The origin's buffer
/// says the credential never arrived. Either alone would be weak: a relay that
/// failed *after* writing would produce a trust-shaped error over a full
/// buffer.
#[test]
fn a_destination_whose_certificate_does_not_verify_is_refused_before_any_byte() {
    let trusted = SessionCa::new("trusted-ca", 5, Duration::from_secs(3600));
    // A different CA: the origin's certificate is well-formed and correctly
    // signed, and signed by somebody this broker was told not to trust. A
    // broken certificate would be refused for the wrong reason.
    let untrusted = SessionCa::new("untrusted-ca", 7, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&untrusted);
    let roots = trusting(&trusted.root_der);
    let rig = Rig::new(trusted, origin.addr);

    let bridge = rig.bridge(UpstreamTransport::Tls, roots);
    // **`establish`, not `relay`.** The claim is that the refusal happened
    // before the tunnel existed, and `relay` would have it happen after the
    // request had been written to a socket that had not proved who it was. An
    // origin whose handshake failed cannot report the bytes it never got to
    // read, so the buffer below is the second half of this claim and not the
    // whole of it.
    let error = rig
        .establish(bridge)
        .expect_err("a destination this broker does not trust must be refused, not reached");
    assert!(
        matches!(error, BridgeError::Handshake(_)),
        "an untrusted destination was refused as {error:?}, which blames something \
         other than the certificate"
    );

    // Give the origin its chance: if the relay had written the rewritten
    // request before failing, the bytes would be here. The wait is bounded, so
    // a relay that never writes fails the assertion rather than the suite.
    thread::sleep(Duration::from_millis(400));
    let seen = origin.received();
    assert!(
        seen.is_empty(),
        "the origin received {} bytes although its certificate did not verify: {:?}",
        seen.len(),
        String::from_utf8_lossy(&seen)
    );
}

/// **3.** A bridge that has not been told how to reach anything reaches nothing.
///
/// The fail-closed default, and the reason the old behaviour was not a default
/// but a silent one: nothing said "cleartext" and everything crossed in the
/// clear. Here the answer is a refusal with a reason, and the destination is
/// never dialled.
#[test]
fn a_bridge_with_no_transport_declared_reaches_no_destination() {
    let ca = SessionCa::new("no-transport-ca", 13, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca);
    let rig = Rig::new(ca, origin.addr);

    // `Bridge::new` alone: no `.with_upstream`, which is the shape a caller
    // gets before it has configured anything.
    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![endpoint()],
    });
    let error = rig
        .establish(bridge)
        .expect_err("a bridge with no declared transport reaches nothing");
    match &error {
        BridgeError::Upstream(detail) => assert!(
            detail.contains("no upstream transport is declared"),
            "the refusal does not say what is missing: {detail}"
        ),
        other => panic!("the refusal blamed something else entirely: {other:?}"),
    }
    assert!(
        !origin.handshook(),
        "the origin completed a handshake even though no transport was declared, so \
         the refusal happened after the connection rather than before it"
    );
}

/// **4.** An empty anchor store refuses a TLS destination rather than trusting
/// whatever the internet says.
///
/// A broker started without `--connect-roots` has an empty store. That is the
/// important one, because the alternative — a bundled public root set — is one
/// line and it is wrong twice: it would trust any host on the internet with
/// this product's credentials, and it would refuse every destination an
/// operator runs on a private CA.
#[test]
fn an_empty_anchor_store_verifies_nothing() {
    let ca = SessionCa::new("empty-roots-ca", 17, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca);
    let rig = Rig::new(ca, origin.addr);

    let bridge = rig.bridge(UpstreamTransport::Tls, Arc::new(RootCertStore::empty()));
    let error = rig.establish(bridge).expect_err(
        "a broker with no anchors must refuse every TLS destination, not fall back to \
         trusting it",
    );
    assert!(
        matches!(error, BridgeError::Handshake(_)),
        "an empty anchor store refused as {error:?}, which suggests something other \
         than the empty store did the refusing"
    );
    thread::sleep(Duration::from_millis(400));
    assert!(
        origin.received().is_empty(),
        "an untrusted destination received the request anyway"
    );
}

/// **5.** The explicit cleartext route still reaches a plain destination.
///
/// The control that keeps property 3 from being a vacuous refusal: a gate that
/// only ever says "no" passes every test in this file. An operator with a
/// plain-HTTP destination is not making a mistake, so the route that says so
/// has to keep working — and the `CleartextUpstream` value exists for exactly
/// the fixtures that dials a loopback origin in the clear.
#[test]
fn a_route_that_says_cleartext_reaches_a_plain_destination() {
    let ca = SessionCa::new("cleartext-ca", 23, Duration::from_secs(3600));
    let listener = TcpListener::bind("127.0.0.1:0").expect("plain origin binds");
    let origin_addr = listener.local_addr().expect("plain origin addr");
    let received = Arc::new(Mutex::new(Vec::new()));
    let (r,) = (Arc::clone(&received),);
    thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        if let Ok(n) = socket.read(&mut buf) {
            r.lock().expect("body").extend_from_slice(&buf[..n]);
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });

    let rig = Rig::new(ca, origin_addr);
    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![endpoint()],
    })
    .with_upstream(
        Arc::new(CleartextUpstream),
        Arc::new(RootCertStore::empty()),
    );
    let established = rig.establish(bridge).expect("a cleartext route is dialled");
    let _ = rig.relay(established);

    let deadline = Instant::now() + Duration::from_secs(5);
    let seen = loop {
        let body = received.lock().expect("body").clone();
        if !body.is_empty() || Instant::now() >= deadline {
            break String::from_utf8_lossy(&body).to_string();
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        seen.contains(REAL),
        "a route that said cleartext did not reach its destination with the credential: {seen}"
    );
}

/// **6.** The policy production actually installs — [`RouteTransports`] over a
/// route table read from a file — reaches a `tls` route over TLS.
///
/// **This test is here because the falsification campaign found it missing, and
/// that is worth stating plainly.** The five properties above are all measured
/// through `Always`, a test-local policy that answers whatever it is handed.
/// The implementation production uses is `RouteTransports`, and **nothing in the
/// workspace exercised it**: a mutation that made `RouteTransports` answer
/// `Cleartext` for a route that said `tls` — turning the declaration into
/// decoration and putting the real credential on the wire in the clear — left
/// the entire suite green. Every other row in that campaign had a witness. This
/// one had a hole, and the hole was a test, not a defect.
///
/// A property asserted only of the harness is a property of the harness.
#[test]
fn the_route_table_says_how_its_destination_is_reached() {
    let ca = SessionCa::new("route-table-ca", 29, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca);
    let roots = trusting(&ca.root_der);
    let routes = route_set(&route_file(HOST, "tls"));
    let rig = Rig::new(ca, origin.addr);

    // The bridge's own policy is the table's rather than a hand-written one, so
    // the authorization and the transport come from the same file an operator
    // wrote — which is the shape `main.rs` gives them.
    let bridge = Bridge::new(routes.to_connect_policy())
        .with_upstream(Arc::new(RouteTransports(Arc::new(routes))), roots);
    let established = rig
        .establish(bridge)
        .expect("a route that declared tls is dialled over tls");
    let _ = rig.relay(established);

    assert!(
        origin.handshook(),
        "the route table said tls and the destination never completed a handshake, so the \
         declaration was not what the broker dialled"
    );
    let seen =
        String::from_utf8_lossy(&origin.wait_for_received(Duration::from_secs(5))).to_string();
    assert!(
        seen.contains(REAL),
        "the route table said tls and the destination never saw the credential: {seen}"
    );
}

/// **7.** A destination the route table does not know is not dialled at all.
///
/// The two gates are built separately — `ConnectPolicy` decides what may be
/// *attempted*, the route table decides what may be *spent* — and nothing forces
/// them to agree. This is the state where they disagree, and it is the state
/// where a default is most tempting and least acceptable: nothing said how to
/// reach the destination, and the answer a default would give is the credential
/// in the clear.
///
/// **The fixture is built to disagree on purpose.** The table names one host and
/// the bridge's policy authorizes another. Had they agreed, the bridge's policy
/// would have refused first and this test would have measured that refusal
/// instead — which is a real property, and already asserted elsewhere, and not
/// the one this file exists to hold.
#[test]
fn a_destination_no_route_declares_is_not_dialled() {
    let ca = SessionCa::new("no-route-ca", 31, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca);
    let roots = trusting(&ca.root_der);
    let routes = route_set(&route_file("other.example.com", "tls"));
    let rig = Rig::new(ca, origin.addr);

    // The bridge's policy authorizes `HOST`; the table has never heard of it.
    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![endpoint()],
    })
    .with_upstream(Arc::new(RouteTransports(Arc::new(routes))), roots);

    let error = rig
        .establish(bridge)
        .expect_err("a destination no route declares how to reach must not be dialled at all");
    match &error {
        BridgeError::Upstream(detail) => assert!(
            detail.contains("no route declares how to reach"),
            "the refusal does not say what is missing: {detail}"
        ),
        other => panic!("the refusal blamed something else entirely: {other:?}"),
    }
    assert!(
        !origin.handshook(),
        "the origin completed a handshake although no route declared how to reach it, so \
         the broker dialled a destination nothing had authorized"
    );
}

/// A destination that never finishes answering.
///
/// **Promises more than it sends, on purpose.** A head with
/// `Content-Length: 64` and two bytes behind it leaves the relay copying a
/// response direction that never ends, which is the only state in which there
/// is anything to cancel. An origin that answered properly would let the relay
/// return, and a revocation sent afterwards would be measured against a broker
/// that had already finished the work — the same mistake the shutdown test made
/// before `OriginMode::Stall` existed in the vertical.
struct StallingOrigin {
    addr: SocketAddr,
    received: Arc<Mutex<usize>>,
}

impl StallingOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("stalling origin binds");
        let addr = listener.local_addr().expect("stalling origin addr");
        let received: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&received);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    *counter.lock().expect("received") += 1;
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nok");
                    let _ = stream.flush();
                    // Never ends, and never times out: this connection is
                    // ended by the other side, which is the event under test.
                    let _ = stream.set_read_timeout(None);
                    let mut buf = [0u8; 256];
                    while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
                });
            }
        });
        Self { addr, received }
    }

    fn requests(&self) -> usize {
        *self.received.lock().expect("received")
    }

    /// Bounded, because the origin is on its own threads and an unbounded
    /// wait is a hung test rather than a failed one.
    fn wait_for_requests(&self, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.requests() >= n {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

/// **8.** A revocation that lands while a dozen tunnels are in flight ends that
/// session's tunnels and nobody else's.
///
/// This is the last thing C2.8 owed, and it could not be measured through the
/// binaries: `asv run` stops its shim *before* it ends a session, so end to end
/// a tunnel closing is equally consistent with the shim dying and with the
/// broker cancelling. That is a structural reason, not a preference, and it is
/// why the file about revocation wiring says so in its own header. So the
/// subject here is the broker, with the client half held still.
///
/// Three properties, and the third is the one the earlier measurements could
/// not see:
///
/// 1. **Every** tunnel of the revoked session ends, and reports
///    `SessionRevoked` rather than an I/O error or a budget.
/// 2. They end *promptly* — a cancellation that arrives whenever the relay next
///    happens to write is not a cancellation under load.
/// 3. **The other session's tunnels are untouched.** A `revoke` that cancelled
///    everything, or that matched on something coarser than the session, would
///    satisfy 1 and 2 perfectly while refusing paying clients. This is the
///    half a single-tunnel revocation test cannot see, because with one tunnel
///    there is nothing to spare.
#[test]
fn a_revocation_under_load_ends_one_sessions_tunnels_and_nobody_elses() {
    const REVOKED: usize = 8;
    const UNTOUCHED: usize = 4;
    const TOTAL: usize = REVOKED + UNTOUCHED;

    let ca = Arc::new(SessionCa::new(
        "revoke-under-load",
        41,
        Duration::from_secs(3600),
    ));
    let origin = StallingOrigin::start();
    let proofs = Arc::new(ProofsByCounter::default());
    let signal = Arc::new(asv_broker::connect_listener::ShutdownSignal::new());

    // One rig per tunnel, all sharing a proof table so each tunnel belongs to
    // the session the test will revoke — and therefore to a session the test
    // will *not*, for the second group.
    // Two sessions, and the tunnels distributed across them: REVOKED of the
    // first, UNTOUCHED of the second. Every counter is distinct, so each tunnel
    // resolves to its own session through the shared table.
    let revoked_session = AgentSessionId::new();
    let untouched_session = AgentSessionId::new();
    let rigs: Vec<Rig> = (0..TOTAL)
        .map(|i| {
            let session = if i < REVOKED {
                revoked_session
            } else {
                untouched_session
            };
            Rig::with_proofs(Arc::clone(&ca), origin.addr, Arc::clone(&proofs), session)
        })
        .collect();
    assert_ne!(
        revoked_session, untouched_session,
        "both groups resolved to the same session, so nothing here could distinguish \
         a scoped revoke from one that cancels everything"
    );

    // Establish and start each tunnel on its own thread, in one pass:
    // `establish` answers the client handshake and returns, and `relay` then
    // blocks until the tunnel is cancelled, so the two cannot be one call.
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Result<SubstitutionOutcome, BridgeError>)>();
    for (index, rig) in rigs.into_iter().enumerate() {
        let bridge = rig.cancellable_bridge(UpstreamTransport::Cleartext, Arc::clone(&signal));
        let established = rig.establish(bridge).expect("a tunnel to be established");
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((index, rig.relay(established)));
        });
    }
    drop(tx);

    // Every tunnel is relaying before anything is revoked. Without this the
    // revocation could land on tunnels that have already finished, and the
    // test would measure nothing while being green.
    assert!(
        origin.wait_for_requests(TOTAL, Duration::from_secs(30)),
        "only {} of {TOTAL} tunnels reached the destination, so the revocation below \
         would not be landing on a full set of in-flight tunnels",
        origin.requests()
    );

    // The revocation, and nothing else.
    signal.revoke(&revoked_session.to_string());

    // 1 and 2: the revoked session's tunnels end, promptly, with the right reason.
    let mut revoked_ended = 0usize;
    let deadline = Instant::now() + Duration::from_secs(20);
    while revoked_ended < REVOKED {
        let Ok((index, outcome)) = rx.recv_timeout(Duration::from_millis(200)) else {
            if Instant::now() >= deadline {
                break;
            }
            continue;
        };
        if index >= REVOKED {
            // A tunnel of the other session finished. Nothing in this
            // measurement expects that, and it is the failure the scoping
            // assertion is about — recorded here so the message below can say
            // which one ended.
            panic!(
                "tunnel {index} belongs to the session that was not revoked and ended \
                 anyway: {outcome:?}"
            );
        }
        match outcome {
            Err(BridgeError::Cancelled(reason)) => {
                assert_eq!(
                    reason,
                    asv_broker::tls_bridge::CancelReason::SessionRevoked,
                    "the tunnel was cancelled, but for {reason} rather than for the \
                     revocation this test performed"
                );
                revoked_ended += 1;
            }
            other => panic!(
                "a revoked session's tunnel ended as {other:?}, which blames something \
                 other than the revocation — an operator reading this would go looking \
                 in the wrong place"
            ),
        }
    }
    assert_eq!(
        revoked_ended, REVOKED,
        "{revoked_ended} of {REVOKED} tunnels of the revoked session ended within 20s; a \
         cancellation that arrives whenever the relay next writes is not a cancellation \
         under load"
    );

    // 3: the other session's tunnels are still running, and still holding the
    // credential. This is the assertion with no control in the tests before it.
    assert!(
        rx.try_recv().is_err(),
        "a tunnel of the untouched session ended when another session was revoked"
    );
    assert!(
        !signal.is_revoked(&untouched_session.to_string()),
        "revoking one session marked another one revoked, so a client paying for a \
         concurrent session cannot tell that from an attack"
    );
}
