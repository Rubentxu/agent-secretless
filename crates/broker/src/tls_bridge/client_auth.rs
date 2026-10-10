//! R2.E.2 — the broker as an mTLS client, proved against a destination that
//! demands a certificate.
//!
//! The issuance rows in `mtls/tests.rs` parse the DER this broker signs. They
//! cannot tell whether a peer will *accept* it, and that is the question a
//! certificate exists to answer. So this module runs the handshake: a real
//! `rustls` server on a real socket, with `WebPkiClientVerifier` demanding a
//! client certificate signed by the session CA, and the broker's own
//! `dial_upstream` as the client.
//!
//! Each row names the mutation that turns it red.
//!
//! The fixture is deliberately smaller than the one in
//! `tests/connect_upstream_negotiation.rs`, which measures the same hop for a
//! different reason and parameterises the server's shape. This module only
//! ever needs the demanding variant, so a second parameterised harness would
//! be a second thing to drift from the first.
//!
//! What every row here shares: the destination's own verdict is the oracle.
//! Not an assertion about a struct, and not a parser's opinion — what a peer
//! that trusts only the root made of the certificate the broker presented.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use super::mtls::deployment::{ClientBinding, MtlsDeployment};
use super::mtls::{ClientGrant, ClientIdentity};
use super::{
    issue_leaf, Authority, AuthorityEndpoint, Bridge, BridgeError, ConnectPolicy, SessionCa,
    UpstreamTransportPolicy,
};
use crate::connect_routes::UpstreamTransport;

const HOST: &str = "internal.svc.example";
const HOUR: Duration = Duration::from_secs(3600);

/// A trust store holding exactly one anchor.
fn trusting(ca: &SessionCa) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.root_der.clone()))
        .expect("the anchor is a certificate this module just minted");
    roots
}

/// A destination that answers exactly one connection.
///
/// `finish` reports the certificates the destination accepted, or why it
/// refused. Both are needed: a server that silently dropped the connection
/// would be indistinguishable from one that was never reached, and the
/// negative rows are exactly the ones where that difference decides whether
/// the row is measuring anything.
struct TlsDestination {
    addr: SocketAddr,
    handle: Option<std::thread::JoinHandle<Result<Vec<Vec<u8>>, String>>>,
}

impl TlsDestination {
    fn start(ca: &SessionCa, demand_client_cert: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = listener.local_addr().expect("the bound address");

        let leaf = issue_leaf(ca, HOST, Instant::now()).expect("a leaf for the destination");
        let chain = vec![
            CertificateDer::from(leaf.leaf_der.clone()),
            CertificateDer::from(ca.intermediate_der.clone()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.leaf_key.serialize_der()));

        let builder = ServerConfig::builder();
        let config = if demand_client_cert {
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(trusting(ca)))
                .build()
                .expect("a verifier over the anchor this CA just minted");
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        }
        .with_single_cert(chain, key)
        .expect("the destination's own certificate");

        let handle = std::thread::spawn(move || {
            let (socket, _) = listener
                .accept()
                .map_err(|e| format!("the destination never accepted: {e}"))?;
            let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
            let connection = ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
            let mut tls = StreamOwned::new(connection, socket);
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|e| e.to_string())?;
            // The destination's own record of what arrived. Not a
            // re-derivation of it.
            Ok(tls
                .conn
                .peer_certificates()
                .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
                .unwrap_or_default())
        });

        Self {
            addr,
            handle: Some(handle),
        }
    }

    #[allow(clippy::type_complexity)]
    fn finish(mut self) -> Result<Vec<Vec<u8>>, String> {
        self.handle
            .take()
            .expect("one connection per destination")
            .join()
            .expect("the destination thread")
    }
}

/// Every destination gets TLS. The socket is opened by the row, so this only
/// has to answer the question `dial_upstream` asks of it.
#[derive(Debug)]
struct AlwaysTls;

impl UpstreamTransportPolicy for AlwaysTls {
    fn transport_for(&self, _target: &AuthorityEndpoint) -> Result<UpstreamTransport, BridgeError> {
        Ok(UpstreamTransport::Tls)
    }
}

fn endpoint(port: u16) -> AuthorityEndpoint {
    AuthorityEndpoint::new(Authority::canonicalize(HOST).expect("host"), port)
        .expect("a port this test chose")
}

fn identity(ca: &SessionCa, host: &str) -> Arc<ClientIdentity> {
    let grant = ClientGrant::for_identity("svc-a.internal", HOUR).expect("a canonical name");
    Arc::new(ClientIdentity::issue(ca, &grant, host, Instant::now()).expect("issuance"))
}

fn bridge(ca: &SessionCa, identity: Option<Arc<ClientIdentity>>) -> Bridge {
    let mut bridge = Bridge::new(ConnectPolicy::default())
        .with_upstream(Arc::new(AlwaysTls), Arc::new(trusting(ca)));
    if let Some(identity) = identity {
        bridge = bridge.with_client_identity(identity);
    }
    bridge
}

fn dial(bridge: &Bridge, destination: &TlsDestination) -> Result<(), String> {
    let socket = TcpStream::connect(destination.addr).map_err(|e| e.to_string())?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
    bridge
        .dial_upstream(socket, &endpoint(destination.addr.port()))
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// **Mutation: leave `.with_no_client_auth()` in place of the identity** — the
/// destination refuses the handshake and the row fails on the destination's
/// own verdict rather than on anything this module asserts.
///
/// This is the row that turns "we sign a client certificate" into "a peer
/// accepts one", and it is the only kind of row in this file a parser could
/// not have written.
#[test]
fn un_destino_que_exige_certificado_acepta_la_identidad_concedida() {
    let ca = SessionCa::new("s-r2e2", 11, HOUR);
    let destination = TlsDestination::start(&ca, true);
    let mine = identity(&ca, HOST);
    let bridge = bridge(&ca, Some(Arc::clone(&mine)));

    dial(&bridge, &destination).expect("the destination accepted the identity");
    let presented = destination
        .finish()
        .expect("the destination completed the handshake");
    assert_eq!(
        presented,
        mine.chain_der(),
        "the destination must have accepted the leaf this broker signed, chain and all"
    );
}

/// **Mutation: drop the `presents_to` guard and use the identity for every
/// destination** — this row goes red, and the row after it says what the
/// guard is for.
#[test]
fn la_identidad_no_se_presenta_a_un_destino_distinto() {
    let ca = SessionCa::new("s-r2e2", 12, HOUR);
    // Granted for `other.svc.example`; this destination is
    // `internal.svc.example`. Both real, both reachable, one granted.
    let mine = identity(&ca, "other.svc.example");
    let destination = TlsDestination::start(&ca, true);
    let bridge = bridge(&ca, Some(mine));

    let refusal = dial(&bridge, &destination).expect_err("the hop must be refused");
    assert!(
        refusal.contains("other.svc.example"),
        "the refusal must name the host the identity was granted to, got: {refusal}"
    );
}

/// **Mutation: answer a mismatched identity with no client auth instead of a
/// refusal** — the handshake completes, the row stays green, and a grant that
/// stopped matching became a silent downgrade rather than an outage.
///
/// Filed as a second row rather than a comment on the one above because
/// "refused" and "reached with no certificate" are different outcomes and a
/// single assertion cannot tell them apart.
#[test]
fn un_destino_distinto_no_llega_de_ninguna_forma() {
    let ca = SessionCa::new("s-r2e2", 13, HOUR);
    let mine = identity(&ca, "other.svc.example");
    let destination = TlsDestination::start(&ca, true);
    let bridge = bridge(&ca, Some(mine));

    let refusal = dial(&bridge, &destination).expect_err("the hop must be refused");
    assert!(
        refusal.contains("was not granted to"),
        "the refusal must be about the binding, not a downstream handshake: {refusal}"
    );
    // And the destination must never have been reached with anything: a
    // refusal produced by the destination itself would still read as a
    // refusal here.
    assert!(
        destination.finish().is_err(),
        "the destination completed a handshake it should never have been offered"
    );
}

/// **Mutation: make `with_client_identity` apply to every builder user, or
/// default the field to a shared identity** — every pre-R2.E caller starts
/// presenting a certificate it was never granted, and this row is the control
/// that says the default is still "no identity".
#[test]
fn un_bridge_sin_identidad_llega_como_antes() {
    let ca = SessionCa::new("s-r2e2", 14, HOUR);
    let destination = TlsDestination::start(&ca, false);
    let bridge = bridge(&ca, None);

    dial(&bridge, &destination).expect("a bridge with no identity still reaches a service");
    assert!(
        destination.finish().is_ok(),
        "the destination completed the handshake"
    );
}

/// **Mutation: send the leaf alone** — the destination, which trusts only the
/// root, cannot build a path and refuses.
#[test]
fn la_cadena_lleva_el_intermedio_para_que_el_destino_pueda_encadenar() {
    let ca = SessionCa::new("s-r2e2", 15, HOUR);
    let chain = identity(&ca, HOST).chain_der();

    assert_eq!(chain.len(), 2, "a leaf alone chains to nothing");
    assert_eq!(
        chain[1], ca.intermediate_der,
        "the second link is the intermediate the destination needs"
    );
}

/// **Mutation: present an identity whose granted lifetime has passed** — the
/// destination refuses, the operator sees a transport failure, and nothing in
/// the message says the session's identity simply aged out.
#[test]
fn una_identidad_caducada_no_se_presenta() {
    let ca = SessionCa::new("s-r2e2", 16, HOUR);
    let grant = ClientGrant::for_identity("svc-a.internal", HOUR).expect("name");
    // Issued an hour and a second ago, so it is past the lifetime it was
    // granted even though its CA is still perfectly valid.
    let stale = ClientIdentity::issue(
        &ca,
        &grant,
        HOST,
        Instant::now() - HOUR - Duration::from_secs(1),
    )
    .expect("issuance");
    assert!(stale.is_expired(Instant::now()));

    let destination = TlsDestination::start(&ca, true);
    let bridge = bridge(&ca, Some(Arc::new(stale)));

    let refusal = dial(&bridge, &destination).expect_err("a stale identity is not offered");
    assert!(
        refusal.contains("reissued"),
        "the refusal must say the identity aged out: {refusal}"
    );
}

/// **Mutation: derive `Debug` on `ClientIdentity`** — a PKCS#8 private key
/// reaches the log line of anything holding an `Arc` of it.
#[test]
fn el_debug_de_una_identidad_no_imprime_su_clave() {
    let ca = SessionCa::new("s-r2e2", 17, HOUR);
    let rendered = format!("{:?}", identity(&ca, HOST));

    // Both spellings, because checking one base is how the previous
    // campaign's `ClientCsr` row stayed green under the one mutation it was
    // written for: a derived `Debug` prints a byte array in decimal.
    for marker in ["private", "key:", "secret", "pkcs8", "[48", "[45"] {
        assert!(
            !rendered.to_lowercase().contains(marker),
            "the rendering mentions {marker:?}: {rendered}"
        );
    }
    assert!(
        rendered.contains("svc-a.internal"),
        "the identity is the useful part to print"
    );
    assert!(
        rendered.contains("chain_len"),
        "the shape is the rest of what is worth printing"
    );
}

/// **Mutation: add `Clone` to `ClientIdentity`, or hand callers the key** — a
/// second copy of the private key exists somewhere the first copy's lifetime
/// does not govern.
///
/// The positive half is the one that can be written as a row: sharing an
/// `Arc` must not produce a second key. The negative half — that the type is
/// not `Clone` — is a compile-time property and is declared as such in the
/// falsification harness rather than dressed up as a passing test.
#[test]
fn compartir_una_identidad_no_hace_una_segunda_clave() {
    let ca = SessionCa::new("s-r2e2", 18, HOUR);
    let mine = identity(&ca, HOST);
    let shared = Arc::clone(&mine);

    assert!(
        Arc::ptr_eq(&mine, &shared),
        "the two handles must be one identity, not two copies of a key"
    );
}

/// **Mutation: compare the binding by suffix, or accept whatever the
/// destination asks for** — a grant for `svc.example` would then authenticate
/// `other.svc.example`, and a server that requests a certificate gets one.
#[test]
fn la_identidad_solo_llega_al_host_exacto() {
    let mine = identity(&SessionCa::new("s-r2e2", 19, HOUR), HOST);

    assert!(mine.presents_to(HOST));
    for other in [
        "other.svc.example",
        "internal.svc.example.evil.test",
        "INTERNAL.SVC.EXAMPLE",
        "internal.svc.exampl",
        "svc.example",
    ] {
        assert!(
            !mine.presents_to(other),
            "{other:?} must not be reached with an identity issued for {HOST}"
        );
    }
}

/// **Mutation: bind a name that is not a destination** — an identity ends up
/// carrying a host no `Authority` would have accepted as one, and the
/// comparison in `presents_to` is against a string the route never produces.
#[test]
fn una_identidad_no_se_emite_para_un_host_que_no_es_un_host() {
    let ca = SessionCa::new("s-r2e2", 20, HOUR);
    let grant = ClientGrant::for_identity("svc-a.internal", HOUR).expect("name");

    for host in [
        "",
        "internal.svc.example:443",
        "user@internal.svc.example",
        "*.svc.example",
    ] {
        let refusal = ClientIdentity::issue(&ca, &grant, host, Instant::now())
            .expect_err("a non-destination is not a destination");
        assert!(
            matches!(refusal, super::mtls::ClientCertError::Unusable(_)),
            "expected an unusable destination, got {refusal:?}"
        );
    }
}

/// **Mutation: mint the identity from whatever the request names, skipping the
/// declaration** — this row goes red, and the chain it measures is the one
/// that makes `MtlsDeployment` reachable from a product surface at all:
/// declaration, then identity, then bridge, then a real destination.
///
/// Everything upstream of here resolves a destination; nothing upstream
/// resolves it *from an operator's decision*, which is what this row is the
/// only place to check.
#[test]
fn una_declaracion_del_operador_produce_la_identidad_que_llega_al_destino() {
    let ca = SessionCa::new("s-r2e2", 21, HOUR);
    let deployment = MtlsDeployment::new(
        vec![ClientBinding::new("svc-a.internal", HOST, HOUR).expect("a canonical pair")],
        vec![],
    )
    .expect("one destination, one identity");

    let declared = deployment
        .identity_for(&ca, HOST, Instant::now())
        .expect("issuance")
        .expect("the destination is declared");

    let destination = TlsDestination::start(&ca, true);
    let bridge = bridge(&ca, Some(Arc::new(declared)));

    dial(&bridge, &destination).expect("the destination accepted the declared identity");
    let presented = destination
        .finish()
        .expect("the destination completed the handshake");
    assert_eq!(
        presented.len(),
        2,
        "the destination accepted a leaf and the intermediate it needed to chain"
    );
}

/// **Mutation: resolve the declaration by suffix, or fall back to a default
/// identity when nothing matches** — the row above stays green and the
/// destination, which was never declared, is authenticated anyway.
#[test]
fn una_declaracion_para_otro_destino_no_produce_una_identidad_usable() {
    let ca = SessionCa::new("s-r2e2", 22, HOUR);
    let deployment = MtlsDeployment::new(
        vec![ClientBinding::new("svc-a.internal", "other.svc.example", HOUR).expect("pair")],
        vec![],
    )
    .expect("ok");

    assert!(
        deployment
            .identity_for(&ca, HOST, Instant::now())
            .expect("no error")
            .is_none(),
        "a destination nobody declared must have no identity to attach"
    );
}
