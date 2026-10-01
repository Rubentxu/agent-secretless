//! M9 — the CONNECT traffic path, and the pinning refusal that must survive it.
//!
//! `handle_connect` authorised a target and returned; nothing listened on a
//! socket. These tests are the first that exercise a path where bytes actually
//! move: a client sends CONNECT, the bridge authorises, terminates TLS with a
//! per-session leaf, dials the upstream, and hands the pair back.
//!
//! The client in `session_leaf_handshakes_and_bytes_reach_the_upstream` is a
//! full `rustls::ClientConfig` with server-name verification on. Not
//! `dangerous()`, not a bypass. A test that disables verification proves
//! nothing about whether a real peer would accept the certificate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asv_broker::tls_bridge::{
    issue_leaf, AuthorityEndpoint, Bridge, BridgeError, ConnectPolicy, LeafError, LeafSource,
    SessionCa, UpstreamResolver, VerifiedLeaf,
};
use asv_domain::Authority;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

const HOST: &str = "api.example.com";

/// A leaf source backed by one real session CA.
///
/// The broker's production implementation holds the vault; this holds a CA.
/// Both satisfy the trait, and neither is reachable *from* the bridge.
struct SessionLeaves {
    ca: SessionCa,
}

impl LeafSource for SessionLeaves {
    fn issue_for(&self, host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError> {
        let certificate = issue_leaf(&self.ca, host, now)?;
        VerifiedLeaf::from_certificate(&self.ca, certificate)
            .map_err(|_| LeafError::InvalidHost("leaf material could not be assembled".to_string()))
    }
}

/// Counts how many leaves the bridge asks for, and for which hosts.
///
/// REQ-1 needs more than "an error came back". Removing the authorisation
/// still produces an error — a handshake timeout, because the unauthorised
/// client was never going to shake hands — so the error type alone is a weak
/// witness. This is the direct one: a target the policy refused must never
/// reach leaf issuance, and minting a certificate for it is work the bridge
/// should not be doing at all.
struct CountingLeaves {
    ca: SessionCa,
    issued: Arc<Mutex<Vec<String>>>,
}

impl LeafSource for CountingLeaves {
    fn issue_for(&self, host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError> {
        self.issued.lock().expect("issued").push(host.to_string());
        let certificate = issue_leaf(&self.ca, host, now)?;
        VerifiedLeaf::from_certificate(&self.ca, certificate)
            .map_err(|_| LeafError::InvalidHost("leaf material could not be assembled".to_string()))
    }
}

/// Resolves every target to one address, so a test needs no DNS.
struct FixedUpstream {
    addr: SocketAddr,
}

impl UpstreamResolver for FixedUpstream {
    fn resolve(&self, _target: &AuthorityEndpoint) -> Result<SocketAddr, BridgeError> {
        Ok(self.addr)
    }
}

/// A plain TCP origin that records what it accepted and what it received.
struct Origin {
    addr: SocketAddr,
    accepted: Arc<Mutex<usize>>,
    received: Arc<Mutex<Vec<u8>>>,
}

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
            let mut buffer = [0u8; 1024];
            if let Ok(n) = socket.read(&mut buffer) {
                r.lock().expect("body").extend_from_slice(&buffer[..n]);
                let _ = socket.write_all(b"pong");
            }
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

    /// Waits for the origin thread to have read something.
    ///
    /// The origin runs on its own thread, so reading the buffer straight after
    /// writing is a race: an empty read would fail the test for being early
    /// rather than for being wrong. This is the wait, and it is bounded — a
    /// bridge that never delivers fails here instead of hanging the suite.
    fn wait_for_received(&self, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        loop {
            let body = self.received.lock().expect("body").clone();
            if !body.is_empty() || Instant::now() >= deadline {
                return body;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn endpoint(host: &str, port: u16) -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(host).expect("host"), port).expect("endpoint")
}

fn bridge_allowing(host: &str, port: u16) -> Bridge {
    Bridge::new(ConnectPolicy {
        allowed: vec![endpoint(host, port)],
    })
}

/// Connects to `listener`, sends the CONNECT head, and returns both halves:
/// the client end the test keeps, the server end the bridge will own.
fn connect_pair(listener: &TcpListener, host: &str, port: u16) -> (TcpStream, TcpStream) {
    let mut client =
        TcpStream::connect(listener.local_addr().expect("bridge addr")).expect("connect");
    let (server_side, _) = listener.accept().expect("bridge accepts");
    client
        .write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .expect("write CONNECT");
    client.flush().expect("flush");
    (client, server_side)
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

/// A client that trusts exactly one root and nothing else.
fn client_trusting(root_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("the session root is a valid trust anchor");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Completes a client handshake over an already-connected socket.
fn handshake(
    config: Arc<ClientConfig>,
    stream: TcpStream,
) -> Result<rustls::StreamOwned<ClientConnection, TcpStream>, rustls::Error> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let name = ServerName::try_from(HOST.to_string()).expect("server name");
    let connection = ClientConnection::new(config, name)
        .map_err(|_| rustls::Error::General("client rejected the server name".into()))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| rustls::Error::General(format!("client handshake failed: {e}")))?;
    Ok(tls)
}

/// REQ-1 — authorisation happens before any upstream socket is opened.
///
/// The assertion that matters is `accepted() == 0`. An `Err` alone would not
/// prove the ordering: a bridge that dialled first and authorised second would
/// also return an error, and the origin would have seen the connection.
#[test]
fn an_unauthorised_target_opens_no_upstream_socket() {
    let origin = Origin::start();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");

    let bridge = Bridge::new(ConnectPolicy {
        allowed: vec![endpoint("other.example.com", 443)],
    });

    // HOST is not in the allow-list.
    let (_client, server_side) = connect_pair(&listener, HOST, 443);
    let leaves = CountingLeaves {
        ca: SessionCa::new("req1", 3, Duration::from_secs(3600)),
        issued: Arc::new(Mutex::new(Vec::new())),
    };
    let result = bridge.serve_connect(
        server_side,
        &leaves,
        &FixedUpstream { addr: origin.addr },
        Instant::now(),
    );

    let error = result.expect_err("HOST is not in the allow-list");
    assert!(
        matches!(error, BridgeError::Connect(_)),
        "refused by CONNECT policy, got {error:?}"
    );
    assert_eq!(
        leaves.issued.lock().expect("issued").clone(),
        Vec::<String>::new(),
        "no leaf may be minted for a target the policy refused"
    );
    assert_eq!(
        origin.accepted(),
        0,
        "the origin must never be dialled for an unauthorised target"
    );
}

/// REQ-2 and REQ-3 — the session leaf is presented, and the tunnel is live.
///
/// What this proves is narrower than "bytes traverse the bridge on their own",
/// and the narrowing is the design: `serve_connect` returns the two halves
/// rather than relaying them, because a duplex relay has no shape in this
/// rustls version that does not deadlock. So the test drives the loop itself,
/// which is what the eventual runtime caller will do.
///
/// The bytes that reach the origin were decrypted by the bridge and written by
/// the client through a TLS connection whose certificate is the session leaf.
/// That is the part that did not exist before.
#[test]
fn session_leaf_handshakes_and_the_tunnel_is_live_in_both_directions() {
    let origin = Origin::start();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
    let ca = SessionCa::new("req2", 5, Duration::from_secs(3600));
    let root_der = ca.root_der.clone();
    let bridge = bridge_allowing(HOST, 443);

    let (mut client, server_side) = connect_pair(&listener, HOST, 443);
    let handle = {
        let leaves = SessionLeaves { ca };
        let upstream = FixedUpstream { addr: origin.addr };
        thread::spawn(move || bridge.serve_connect(server_side, &leaves, &upstream, Instant::now()))
    };

    let ack = read_head(&mut client);
    assert!(
        ack.starts_with("HTTP/1.1 200"),
        "an authorised target is established before the handshake, got {ack:?}"
    );

    let mut tls = handshake(client_trusting(&root_der), client).expect("session leaf must verify");
    let mut tunnel = handle.join().expect("bridge thread").expect("tunnel");

    assert_eq!(
        tunnel.target.host(),
        HOST,
        "the tunnel is for the host the client asked for"
    );

    // `tunnel.client` is the bridge's end of the connection *to the client*.
    // Writing to it sends to the client; reading from it yields what the
    // client sent, decrypted. The copy between the two halves is the relay,
    // and the test performs it — a relay the bridge does not yet own is not
    // something a test can assert about the bridge.
    tls.write_all(b"ping").expect("client writes");
    tls.flush().expect("flush");

    let mut decrypted = [0u8; 4];
    tunnel
        .client
        .read_exact(&mut decrypted)
        .expect("the bridge decrypts what the client sent");
    assert_eq!(
        &decrypted, b"ping",
        "the bridge sees plaintext, not ciphertext"
    );

    tunnel
        .upstream
        .write_all(&decrypted)
        .expect("relay to the upstream");
    tunnel.upstream.flush().expect("flush");
    assert_eq!(
        origin.wait_for_received(Duration::from_secs(5)),
        b"ping".to_vec(),
        "bytes the client sent must arrive at the upstream"
    );

    // And the other direction, so the tunnel is not half-usable.
    let mut pong = [0u8; 4];
    tunnel
        .upstream
        .read_exact(&mut pong)
        .expect("the origin replied");
    tunnel.client.write_all(&pong).expect("relay back");
    tunnel.client.flush().expect("flush");
    let mut echoed = [0u8; 4];
    tls.read_exact(&mut echoed).expect("client reads the reply");
    assert_eq!(
        &echoed, b"pong",
        "the upstream's bytes must reach the client"
    );
}

/// A leaf source that always answers with the wrong host's leaf.
///
/// Every other source in this file complies, which means the host binding has
/// no witness at all: `verify_host_at` could be deleted and the suite would
/// stay green. This source exists to give it one.
struct WrongHostLeaves {
    ca: SessionCa,
}

impl LeafSource for WrongHostLeaves {
    fn issue_for(&self, _host: &str, now: Instant) -> Result<VerifiedLeaf, LeafError> {
        let certificate = issue_leaf(&self.ca, "other.example.com", now)?;
        VerifiedLeaf::from_certificate(&self.ca, certificate)
            .map_err(|_| LeafError::InvalidHost("leaf material could not be assembled".to_string()))
    }
}

/// REQ-2 — the bridge re-checks the host binding instead of trusting the source.
///
/// A session authorised for `api.example.com` must not end up presenting a leaf
/// bound to `other.example.com`, even if the leaf source hands one over. The
/// bridge checks it itself, at the point of decision, because a source is a
/// component and a boundary is not.
#[test]
fn a_leaf_minted_for_another_host_is_refused() {
    let origin = Origin::start();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
    let bridge = bridge_allowing(HOST, 443);

    let (_client, server_side) = connect_pair(&listener, HOST, 443);
    let error = bridge
        .serve_connect(
            server_side,
            &WrongHostLeaves {
                ca: SessionCa::new("wrong-host", 17, Duration::from_secs(3600)),
            },
            &FixedUpstream { addr: origin.addr },
            Instant::now(),
        )
        .expect_err("a leaf for another host must be refused");

    assert!(
        matches!(error, BridgeError::Leaf(LeafError::HostMismatch { .. })),
        "refused on the host binding, got {error:?}"
    );
    assert_eq!(
        origin.accepted(),
        0,
        "the origin must not be dialled when the binding does not hold"
    );
}

/// UAT-011 — a client that pins the upstream certificate is refused.
///
/// The pinned certificate is minted under a *different* CA — the one the
/// upstream would present — so the session leaf the bridge presents does not
/// match it. That is the situation the UAT describes: a client that cannot
/// accept the session CA.
///
/// Two assertions, and the second is the one that matters. The first says the
/// client refused. The second says the bridge got as far as the handshake and
/// failed *there*: a bridge that refused earlier would satisfy the first and
/// mean nothing, and one that quietly made the pinning client succeed would
/// be the failure UAT-011 exists to prevent.
#[test]
fn a_pinning_client_is_refused_and_the_bridge_does_not_patch_it() {
    let upstream_ca = SessionCa::new("upstream-ca", 9, Duration::from_secs(3600));
    let upstream_leaf = issue_leaf(&upstream_ca, HOST, Instant::now()).expect("upstream leaf");
    let pinned_der = upstream_leaf.leaf_der.clone();

    let origin = Origin::start();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bridge binds");
    let session_ca = SessionCa::new("session-ca", 13, Duration::from_secs(3600));
    let bridge = bridge_allowing(HOST, 443);

    let (client, server_side) = connect_pair(&listener, HOST, 443);
    let mut ack_reader = client.try_clone().expect("clone");
    let handle = {
        let leaves = SessionLeaves { ca: session_ca };
        let upstream = FixedUpstream { addr: origin.addr };
        thread::spawn(move || bridge.serve_connect(server_side, &leaves, &upstream, Instant::now()))
    };

    assert!(
        read_head(&mut ack_reader).starts_with("HTTP/1.1 200"),
        "the target is authorised, so the refusal has to come from the certificate"
    );

    let client_result = handshake(Arc::new(pinning_config(pinned_der)), client);
    assert!(
        client_result.is_err(),
        "a client pinning the upstream certificate must not accept the session leaf"
    );

    let bridge_result = handle.join().expect("bridge thread");
    let bridge_error = bridge_result.expect_err("the bridge must not complete the handshake");
    assert!(
        matches!(bridge_error, BridgeError::Handshake(_)),
        "the bridge must fail at the handshake, not earlier and not silently, got {bridge_error:?}"
    );
}

/// Builds a client configuration that accepts exactly one certificate.
fn pinning_config(expected: Vec<u8>) -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier { expected }))
        .with_no_client_auth()
}

/// Accepts one certificate and nothing else.
///
/// Signature verification is asserted rather than performed: this verifier is
/// here to pin the *identity*, and the certificate it accepts arrives over a
/// session channel the client itself opened. A verifier that silently accepted
/// every certificate would make the test prove nothing.
#[derive(Debug)]
struct PinningVerifier {
    expected: Vec<u8>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}
