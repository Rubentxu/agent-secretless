//! C2.8 / M9 — what the broker's **client** leg negotiates with the destination.
//!
//! `docs/tls-compatibility-matrix.md` measures one surface: the TLS **server**
//! the bridge presents to the agent, built by `LeafMaterial::server_config`
//! and shared with the acceptor. The matrix says so in its own words — the
//! rows "describe **both** TLS surfaces in the workspace" — and that was true
//! when it was written. C2.8 made it false.
//!
//! The hop the previous revision of this path had no shape for is now TLS, and
//! `Bridge::dial_upstream` builds a `rustls::ClientConfig` of its own:
//!
//! ```text
//! rustls::ClientConfig::builder()
//!     .with_root_certificates(self.destination_roots.as_ref().clone())
//!     .with_no_client_auth();
//! ```
//!
//! Three cells of that builder are set, and the three cells that are **not**
//! set are inherited from a library default: the protocol version range, the
//! ALPN protocols offered, and the provider. `connect_upstream_tls.rs` measures
//! what this leg *trusts* — the anchors, the name, the eager handshake — and
//! says nothing about what it *negotiates*. So the ALPN hazard the matrix
//! pinned for the server side is, on the client side, unwatched: and the two
//! hazards are mirror images.
//!
//! On the server side, a bridge that selected `h2` would hand an `h2`-capable
//! agent a connection the bridge cannot parse. On the client side, a broker
//! that **offered** `h2` to the destination would get a destination that
//! believes it is speaking HTTP/2, and then relay `curl`'s HTTP/1.1 bytes into
//! it — a tunnel whose inner bytes are framed for a protocol the destination
//! selected and the agent never agreed to. `curl` and `reqwest` both offer
//! `h2`, so this is the shape a routine request takes, not an edge case.
//!
//! **The observation is the destination's, never the broker's.** Every
//! property here is read off the `ServerConnection` on the far end of the
//! socket. A broker reporting its own `ClientConfig` would be the broker
//! agreeing with itself, and the matrix already records two such empty
//! assertions caught in this repository.
//!
//! **No relay is driven.** The upstream handshake completes inside
//! `serve_connect`, so a tunnel that comes back is a handshake that completed,
//! and the origin has recorded the negotiation by then. The credential's
//! journey is `connect_upstream_tls.rs`'s subject, measured there, once; this
//! file would only be a second place to get it wrong.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asv_broker::connect_routes::UpstreamTransport;
use asv_broker::tls_bridge::{
    issue_leaf, AuthorityEndpoint, Bridge, BridgeError, LeafError, LeafSource, SessionCa,
    SessionProofs, UpstreamResolver, UpstreamTransportPolicy, VerifiedLeaf, SESSION_PROOF_HEADER,
};
use asv_domain::{AgentSessionId, Authority};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    SupportedProtocolVersion,
};

const HOST: &str = "origin.example.com";
const PORT: u16 = 443;

// ---------------------------------------------------------------------------
// What the destination saw
// ---------------------------------------------------------------------------

/// The destination's account of the connection the broker opened.
///
/// `handshook` is separate from the three negotiation cells because they are
/// only meaningful together: a refused handshake leaves all three `None`, and
/// a test that read `alpn == None` off a handshake that never happened would
/// pass for the wrong reason. Every assertion that reads a negotiation cell
/// asserts `handshook` first.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct Observed {
    handshook: bool,
    version: Option<&'static str>,
    alpn: Option<Vec<u8>>,
    client_certificates: usize,
}

impl Observed {
    /// What the destination reports, as text, for a failure message that has
    /// to say which of the three it was.
    fn describe(&self) -> String {
        format!(
            "handshook={} version={:?} alpn={:?} client_certs={}",
            self.handshook,
            self.version,
            self.alpn
                .as_ref()
                .map(|a| String::from_utf8_lossy(a).into_owned()),
            self.client_certificates
        )
    }
}

// ---------------------------------------------------------------------------
// The origin, in the shapes under test
// ---------------------------------------------------------------------------

/// How the destination is configured to negotiate.
///
/// Every cell is a choice the destination makes, so a test can move one and
/// watch what the broker's client leg does about it. Defaults are the ones a
/// real destination would have: every version, no ALPN, no client auth.
#[derive(Clone)]
struct Shape {
    alpn: Vec<Vec<u8>>,
    versions: Vec<&'static SupportedProtocolVersion>,
    /// When set, the destination accepts no connection without a certificate
    /// it can verify. The roots are the same anchors the leaf was minted from.
    demand_client_cert: bool,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            alpn: Vec::new(),
            versions: vec![&rustls::version::TLS13, &rustls::version::TLS12],
            demand_client_cert: false,
        }
    }
}

impl Shape {
    /// A destination that offers both HTTP/2 and HTTP/1.1, which is what
    /// `reqwest` and every modern server do.
    fn offering_alpn() -> Self {
        Self {
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ..Self::default()
        }
    }

    fn only(version: &'static SupportedProtocolVersion) -> Self {
        Self {
            versions: vec![version],
            ..Self::default()
        }
    }

    fn demanding_client_cert() -> Self {
        Self {
            demand_client_cert: true,
            ..Self::default()
        }
    }
}

/// A real TLS destination, on a real socket, that keeps the origin's side of
/// the negotiation.
struct TlsOrigin {
    addr: SocketAddr,
    observed: Arc<Mutex<Observed>>,
    /// Set once the origin has finished looking at the connection, so a test
    /// never reads a half-written record.
    settled: Arc<Mutex<bool>>,
}

impl TlsOrigin {
    fn start(ca: &SessionCa, shape: Shape) -> Self {
        let leaf = issue_leaf(ca, HOST, Instant::now()).expect("issue the origin's leaf");
        let config = server_config(ca, &leaf, &shape);

        let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let observed = Arc::new(Mutex::new(Observed::default()));
        let settled = Arc::new(Mutex::new(false));
        let (o, s) = (Arc::clone(&observed), Arc::clone(&settled));

        thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                *s.lock().expect("settled") = true;
                return;
            };
            let Ok(connection) = ServerConnection::new(config) else {
                *s.lock().expect("settled") = true;
                return;
            };
            let mut tls = rustls::StreamOwned::new(connection, socket);
            // A refused handshake is a result, not an absence: the record is
            // marked settled with every cell still `None`, which is what a
            // destination that demanded a client certificate the broker does
            // not have looks like.
            if tls.conn.complete_io(&mut tls.sock).is_err() {
                *s.lock().expect("settled") = true;
                return;
            }
            let record = Observed {
                handshook: true,
                version: tls.conn.protocol_version().map(|v| match v {
                    rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
                    rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
                    _ => "other",
                }),
                alpn: tls.conn.alpn_protocol().map(<[u8]>::to_vec),
                client_certificates: tls
                    .conn
                    .peer_certificates()
                    .map(<[CertificateDer<'_>]>::len)
                    .unwrap_or(0),
            };
            *o.lock().expect("observed") = record;
            *s.lock().expect("settled") = true;

            // Hold the connection so the broker's relay finds a live peer
            // rather than a reset, and answer one request if one arrives.
            let mut buf = [0u8; 4096];
            if tls.read(&mut buf).is_ok() {
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });

        Self {
            addr,
            observed,
            settled,
        }
    }

    /// The origin's account, once it has one.
    ///
    /// Bounded, because the origin is on its own thread: a test that read
    /// straight after `serve_connect` returned would be racing the record it
    /// is asserting on, and would fail for being early rather than for being
    /// wrong.
    fn wait(&self, timeout: Duration) -> Observed {
        let deadline = Instant::now() + timeout;
        while !*self.settled.lock().expect("settled") {
            assert!(
                Instant::now() < deadline,
                "the destination never settled its record of the connection"
            );
            thread::sleep(Duration::from_millis(10));
        }
        self.observed.lock().expect("observed").clone()
    }
}

/// The origin's server config, built from the same leaf material the
/// production bridge mints from, with the three cells the shape controls set
/// explicitly.
fn server_config(
    ca: &SessionCa,
    leaf: &asv_broker::tls_bridge::LeafCertificate,
    shape: &Shape,
) -> Arc<ServerConfig> {
    let chain = vec![
        CertificateDer::from(leaf.leaf_der.clone()),
        CertificateDer::from(ca.intermediate_der.clone()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.leaf_key.serialize_der()));
    // The version list is a pair of rustls' own constants, so there is no
    // failure to handle here; the builder is infallible in this version.
    let builder = ServerConfig::builder_with_protocol_versions(&shape.versions);

    let mut config = if shape.demand_client_cert {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(trusting(ca)))
            .build()
            .expect("a verifier over the anchor this CA just minted");
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .expect("server config demanding a client certificate")
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config")
    };
    config.alpn_protocols = shape.alpn.clone();
    Arc::new(config)
}

// ---------------------------------------------------------------------------
// Harnesses
// ---------------------------------------------------------------------------

fn endpoint() -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(HOST).expect("host"), PORT).expect("endpoint")
}

/// A trust store holding exactly one anchor.
fn trusting(ca: &SessionCa) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.root_der.clone()))
        .expect("the anchor is a certificate this crate just minted");
    roots
}

struct FixedUpstream {
    addr: SocketAddr,
}

impl UpstreamResolver for FixedUpstream {
    fn resolve(&self, _target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        Ok(self.addr)
    }
}

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

struct OneProof(AgentSessionId);

impl SessionProofs for OneProof {
    /// One proof, one counter, one session.
    ///
    /// The counter is read off the proof's wire form because `authenticate`
    /// takes the parsed proof and the destination, and the subject of this file
    /// is what the two TLS legs negotiate — not whether a signature verifies,
    /// which the broker's own verifier tests cover. The counter is the only
    /// part of a proof a fixture may choose freely.
    fn authenticate(
        &self,
        proof: &asv_broker::tls_bridge::SessionProof,
        _target: &AuthorityEndpoint,
    ) -> Result<AgentSessionId, asv_broker::ProofRejection> {
        if proof.counter == 1 {
            Ok(self.0)
        } else {
            Err(asv_broker::ProofRejection::NoSuchSession)
        }
    }
}

/// The whole path up to the upstream handshake, and nothing after it.
///
/// The ordering is the bridge's and not this file's: `serve_connect` reads the
/// CONNECT head in the clear, answers `200` in the clear, handshakes with the
/// agent, and only then dials the destination. Starting the bridge late
/// deadlocks on the first read.
///
/// The CA arrives as an `Arc` because [`SessionCa`] is not `Clone` — it owns an
/// `rcgen::KeyPair` — and the bridge needs it on a thread of its own. That is
/// the same reason production carries it in an `Arc`, so the test and the
/// product agree about the shape rather than the test inventing one.
fn establish(ca: Arc<SessionCa>, origin_addr: SocketAddr) -> Result<(), BridgeError> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
    let bridge = Bridge::new(asv_broker::tls_bridge::ConnectPolicy {
        allowed: vec![endpoint()],
    })
    .with_upstream(
        Arc::new(Always(UpstreamTransport::Tls)),
        Arc::new(trusting(&ca)),
    );

    let mut client =
        TcpStream::connect(listener.local_addr().expect("bridge addr")).expect("connect");
    let (server_side, _) = listener.accept().expect("bridge accepts");
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    client
        .write_all(
            format!(
                "CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}\r\n\
                 {SESSION_PROOF_HEADER}: QUFB.1.QkJC\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write CONNECT");
    client.flush().expect("flush");

    let (leaves, upstream, proofs) = (
        SessionLeaves {
            ca: Arc::clone(&ca),
        },
        FixedUpstream { addr: origin_addr },
        OneProof(AgentSessionId::new()),
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

    // The agent side of the bridge, which the destination never sees.
    let config = ClientConfig::builder()
        .with_root_certificates(trusting(&ca))
        .with_no_client_auth();
    let name = ServerName::try_from(HOST.to_string())
        .map_err(|e| BridgeError::Handshake(format!("{e}")))?;
    let connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| BridgeError::Handshake(e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(connection, client);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| BridgeError::Handshake(format!("client handshake failed: {e}")))?;

    let received = match rx.recv() {
        Ok(outcome) => outcome.map(|_| ()),
        Err(_) => panic!("the bridge thread died before answering"),
    };
    worker.join().expect("the bridge thread");
    received
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_destination_offering_alpn_is_given_no_selection_by_the_broker() {
    let ca = SessionCa::new("alpn-unselected", 41, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::offering_alpn());

    establish(Arc::new(ca), origin.addr).expect("the broker reaches the destination");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the upstream handshake did not complete: {}",
        seen.describe()
    );
    assert_eq!(
        seen.alpn,
        None,
        "the broker's upstream leg offered an ALPN protocol to a destination that \
         accepts h2: {}. Nothing on the agent side of the tunnel speaks HTTP/2, so a \
         destination that selected it would be framing bytes neither end agreed to.",
        seen.describe()
    );
}

#[test]
fn the_alpn_observation_detects_a_selection_when_a_client_offers_one() {
    let ca = SessionCa::new("alpn-observed", 43, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::offering_alpn());

    // The same destination, reached by a client that does offer ALPN. Without
    // this the assertion above is an assertion of absence with nothing behind
    // it, which is the shape that reads green because it never looks.
    connect_directly(
        &ca,
        origin.addr,
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
        None,
    )
    .expect("a direct client completes the handshake");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the direct handshake did not complete: {}",
        seen.describe()
    );
    assert_eq!(
        seen.alpn.as_deref(),
        Some(&b"h2"[..]),
        "the destination could not observe an ALPN selection even when one was \
         offered, so the pin above is not measuring anything: {}",
        seen.describe()
    );
}

#[test]
fn the_broker_reaches_a_destination_offering_only_tls13() {
    let ca = SessionCa::new("tls13-only", 47, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::only(&rustls::version::TLS13));

    establish(Arc::new(ca), origin.addr).expect("the broker reaches a TLS 1.3 only destination");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the upstream handshake did not complete: {}",
        seen.describe()
    );
    assert_eq!(
        seen.version,
        Some("TLSv1.3"),
        "the upstream leg did not reach the destination's only version: {}",
        seen.describe()
    );
}

#[test]
fn the_broker_reaches_a_destination_offering_only_tls12() {
    let ca = SessionCa::new("tls12-only", 53, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::only(&rustls::version::TLS12));

    establish(Arc::new(ca), origin.addr).expect("the broker reaches a TLS 1.2 only destination");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the upstream handshake did not complete: {}",
        seen.describe()
    );
    assert_eq!(
        seen.version,
        Some("TLSv1.2"),
        "the upstream leg's floor is above TLS 1.2, so a destination pinned there is \
         unreachable: {}",
        seen.describe()
    );
}

#[test]
fn the_broker_presents_no_client_certificate_to_a_destination_that_demands_one() {
    let ca = SessionCa::new("client-auth-refused", 31, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::demanding_client_cert());

    // **The broker's own return value is deliberately not asserted on, and
    // cannot be.** In TLS 1.3 the client sends its Finished and considers the
    // handshake over before the server has processed the empty certificate
    // message, so `dial_upstream` returns `Ok` and `serve_connect` hands back
    // a tunnel that the destination has already refused. Asserting
    // `establish(...).is_err()` here would be asserting a property of the
    // protocol rather than of the broker, and it would break — correctly, but
    // uninformatively — if the negotiation ever fell to TLS 1.2. The witness is
    // the destination's record and nothing else.
    let _ = establish(Arc::new(ca), origin.addr);

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        !seen.handshook,
        "the destination completed a handshake that requires a verified client \
         certificate, so the broker must be presenting one: {}",
        seen.describe()
    );
    assert_eq!(
        seen.client_certificates,
        0,
        "the destination saw a client certificate from a broker that has none: {}",
        seen.describe()
    );
}

#[test]
fn a_client_holding_the_issuers_certificate_completes_against_a_destination_that_demands_one() {
    let ca = SessionCa::new("client-auth-accepted", 37, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::demanding_client_cert());

    // The control for the test above: if nothing could ever satisfy this
    // destination, "the broker presented no certificate" would be true of every
    // client and mean nothing.
    //
    // **A client certificate, and not the destination's own leaf.** The second
    // version of this file presented `issue_leaf`'s output and the handshake
    // was refused for a reason that is correct rather than incidental: that
    // leaf carries `ExtendedKeyUsage: serverAuth` and nothing else, and a
    // verifier is right to reject a server certificate presented as a client
    // one. Reusing the production leaf here would have made the control
    // unfalsifiable in the worst direction — it would have failed for a reason
    // unrelated to the property and invited "fixing" the test by loosening the
    // verifier, which is how a control becomes decoration.
    //
    // **The chain, not just the leaf.** The session CA is three levels and a
    // verifier whose trust store holds only the root can only build a path if
    // the peer presents the intermediate. Sending the end-entity alone fails
    // with `UnknownIssuer`, which reads as "the anchor is wrong" and is not.
    let certificate = client_certificate(&ca);
    connect_directly(&ca, origin.addr, &[], Some(certificate))
        .expect("a client holding a certificate from the issuer completes the handshake");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the direct handshake did not complete: {}",
        seen.describe()
    );
    // **Two, not one.** `peer_certificates` reports the whole chain the peer
    // presented, and this client sent its leaf *and* the intermediate — which
    // is what lets the verifier build a path to the root the trust store holds.
    // Asserting `1` would be asserting that the chain arrived short, which is
    // the mistake `UnknownIssuer` produces; the first version of this file made
    // it and the count is the receipt.
    assert_eq!(
        seen.client_certificates,
        2,
        "the destination did not see the leaf and the intermediate the client \
         presented: {}",
        seen.describe()
    );
}

/// A leaf from the session's own intermediate, minted for client
/// authentication.
///
/// Signed by the same intermediate as the server leaves so the destination's
/// trust store needs no second anchor: the control differs from the broker in
/// exactly one respect, which is the one under test.
fn client_certificate(ca: &SessionCa) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().expect("rcgen client key");
    let mut params = rcgen::CertificateParams::new(vec!["asv-test-client".to_string()])
        .expect("a name for a client certificate");
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "asv-test-client".to_string());
    let certificate = params
        .signed_by(&key, &ca.intermediate_cert, &ca.intermediate_key)
        .expect("the intermediate signs a client certificate");
    (
        vec![
            CertificateDer::from(certificate.der().to_vec()),
            CertificateDer::from(ca.intermediate_der.clone()),
        ],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

#[test]
fn the_broker_negotiates_tls13_against_a_destination_taking_the_defaults() {
    let ca = SessionCa::new("defaults", 59, Duration::from_secs(3600));
    let origin = TlsOrigin::start(&ca, Shape::default());

    establish(Arc::new(ca), origin.addr).expect("the broker reaches an ordinary destination");

    let seen = origin.wait(Duration::from_secs(10));
    assert!(
        seen.handshook,
        "the upstream handshake did not complete: {}",
        seen.describe()
    );
    assert_eq!(
        seen.version,
        Some("TLSv1.3"),
        "against a destination taking the defaults the upstream leg did not land on \
         TLS 1.3; this row is an observation of this host, not a guarantee: {}",
        seen.describe()
    );
}

/// A direct client to a destination, for the two controls.
///
/// The ALPN it offers and the certificate it presents are arguments because
/// both controls need one client that differs from the broker in exactly one
/// respect, and a fixture that cannot express that difference cannot prove the
/// broker's behaviour is what produced the observation.
fn connect_directly(
    ca: &SessionCa,
    addr: SocketAddr,
    alpn: &[Vec<u8>],
    certificate: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<(), String> {
    let socket = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
    let builder = ClientConfig::builder();
    let mut config = match certificate {
        Some((chain, key)) => builder
            .with_root_certificates(trusting(ca))
            .with_client_auth_cert(chain, key)
            .map_err(|e| e.to_string())?,
        None => builder
            .with_root_certificates(trusting(ca))
            .with_no_client_auth(),
    };
    config.alpn_protocols = alpn.to_vec();
    let name = ServerName::try_from(HOST.to_string()).map_err(|e| e.to_string())?;
    let connection = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| e.to_string())?;
    Ok(())
}
