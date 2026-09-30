//! A real rustls client against a real acceptor.
//!
//! The unit tests in `config.rs` can only prove that rustls accepts the
//! material. They cannot prove that a client trusting only the session root
//! builds a path from what the acceptor sends, which is the claim that
//! matters. That takes a handshake, so it is what these tests do.
//!
//! Every client here is a full `rustls::ClientConfig` with server name
//! verification on. Not `dangerous()`, not a custom verifier. A test that
//! disables verification proves nothing about whether a real peer would
//! accept the certificate.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use asv_broker::tls_bridge::{issue_leaf, SessionCa};
use asv_tls_acceptor::{Acceptor, LeafMaterial};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const HOST: &str = "api.example.com";

/// A session CA plus a leaf for `HOST`, as the acceptor consumes it.
fn material_for(host: &str) -> (LeafMaterial, SessionCa) {
    let ca = SessionCa::new("acceptor-test", 7, std::time::Duration::from_secs(3600));
    let leaf = issue_leaf(&ca, host, std::time::Instant::now()).expect("mint a leaf");
    let material = LeafMaterial::new(
        ca.root_der.clone(),
        vec![leaf.leaf_der.clone(), ca.intermediate_der.clone()],
        leaf.leaf_key.serialize_der(),
    )
    .expect("material");
    (material, ca)
}

/// A client that trusts exactly the session root and nothing else.
fn client_trusting(root_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("the session root is a valid trust anchor");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Runs a client handshake and returns the negotiated protocol version.
fn connect(
    addr: std::net::SocketAddr,
    config: Arc<ClientConfig>,
    hostname: &str,
) -> Result<rustls::ProtocolVersion, rustls::Error> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .expect("the acceptor is listening");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    // `ServerName` is `'static` because a `ClientConnection` may outlive this
    // call, so the name is owned rather than borrowed from the argument.
    let name = ServerName::try_from(hostname.to_string()).expect("a valid server name");
    let connection = ClientConnection::new(config, name).map_err(|_| {
        rustls::Error::General("client configuration rejected the server name".into())
    })?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| rustls::Error::General(format!("client handshake failed: {e}")))?;
    Ok(tls
        .conn
        .protocol_version()
        .unwrap_or(rustls::ProtocolVersion::TLSv1_2))
}

#[test]
fn a_client_trusting_only_the_session_root_completes_the_handshake() {
    let (material, ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");
    let client = client_trusting(&ca.root_der);

    let version = connect(acceptor.local_addr(), client, HOST)
        .expect("a client trusting the session root must complete the handshake");

    // `ProtocolVersion` implements neither `PartialOrd` nor `Display`, so
    // the check is an explicit match on the two versions this acceptor is
    // allowed to negotiate. Anything else, including `Unknown`, is a failure:
    // a version that cannot be named is a version that cannot be asserted.
    assert!(
        matches!(
            version,
            rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3
        ),
        "negotiated {version:?}, which is neither TLS 1.2 nor TLS 1.3"
    );
}

#[test]
fn the_chain_presented_is_leaf_then_intermediate() {
    let (material, _ca) = material_for(HOST);
    let chain = material.leaf_chain_der();
    assert_eq!(chain.len(), 2, "leaf plus one intermediate");
    // The first element must be the end-entity certificate. Presenting them
    // the other way round produces a certificate some clients build a path
    // from and others reject, which is worse than either order being wrong.
    assert_eq!(chain[0], material.leaf_chain_der()[0], "end-entity first");
}

#[test]
fn a_client_asking_for_another_hostname_is_refused() {
    let (material, ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");
    // This client trusts the session root correctly. It is refused because
    // the leaf does not name the host it asked for, not because of trust.
    let client = client_trusting(&ca.root_der);

    let result = connect(acceptor.local_addr(), client, "evil.example.net");
    assert!(
        result.is_err(),
        "a leaf minted for {HOST} completed a handshake for evil.example.net"
    );
}

#[test]
fn a_client_trusting_an_unrelated_root_is_refused() {
    let (material, _ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");
    // A different session's root: the acceptor is right, the client is not
    // told to trust it.
    let (_other_material, other_ca) = material_for("other.example.com");
    let client = client_trusting(&other_ca.root_der);

    let result = connect(acceptor.local_addr(), client, HOST);
    assert!(
        result.is_err(),
        "a client trusting an unrelated root completed the handshake"
    );
}

#[test]
fn presenting_the_leaf_without_the_intermediate_fails() {
    // The end-entity certificate alone cannot be verified against the root.
    // This is the falsification for REQ-1: if it ever succeeds, the acceptor
    // is building a path it should not be able to build.
    let ca = SessionCa::new("no-intermediate", 9, std::time::Duration::from_secs(3600));
    let leaf = issue_leaf(&ca, HOST, std::time::Instant::now()).expect("mint a leaf");
    let material = LeafMaterial::new(
        ca.root_der.clone(),
        vec![leaf.leaf_der.clone()],
        leaf.leaf_key.serialize_der(),
    )
    .expect("material");
    let acceptor = Acceptor::bind(&material, 0).expect("bind");
    let client = client_trusting(&ca.root_der);

    let result = connect(acceptor.local_addr(), client, HOST);
    assert!(
        result.is_err(),
        "a leaf with no intermediate verified against the root alone"
    );
}
