//! A loopback TLS acceptor that presents one session leaf.
//!
//! Synchronous, one thread per connection. The shape is borrowed from
//! `asv-connector-http`'s fake origin rather than invented, and for a reason
//! beyond brevity: this acceptor is going to sit behind the eBPF redirect
//! that hands it pre-accepted sockets. An async runtime here would be a
//! rewrite the day eBPF lands.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;

use crate::config::{AcceptorError, LeafMaterial};

/// How long a single connection may take before it is abandoned.
///
/// Not a test convenience. The eBPF redirect will feed this acceptor
/// connections that may be reset mid-handshake, and a server that blocks
/// forever on a half-open socket is a denial of service that needs no
/// attacker at all.
///
/// Public so a test can assert against it rather than hard-code the same
/// number in two places.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A bound listener that presents one session leaf.
pub struct Acceptor {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Acceptor {
    /// Binds a loopback listener on `port`. Pass 0 to let the OS choose.
    pub fn bind(material: &LeafMaterial, port: u16) -> Result<Self, AcceptorError> {
        let config = Arc::new(
            material
                .server_config()
                .map_err(|e| AcceptorError::Io(format!("server config: {e}")))?,
        );
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|e| AcceptorError::Io(e.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| AcceptorError::Io(e.to_string()))?;

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        let accept_config = Arc::clone(&config);
        let accept_stop = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { return };
                let config = Arc::clone(&accept_config);
                handles.push(thread::spawn(move || {
                    let _ = handshake_once(stream, &config);
                }));
            }
        });

        // The accept thread owns the per-connection handles; this one only
        // exists so `Acceptor::drop` can join the outer loop. The config is
        // not kept here: the thread already holds its own `Arc`, and a second
        // one on the struct would be a field nobody reads.
        Ok(Self {
            local_addr,
            stop,
            handles: vec![handle],
        })
    }

    /// The address the acceptor is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop with one throwaway connection, the same
        // trick the fake origin uses.
        let _ = TcpStream::connect(self.local_addr);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Completes one handshake and returns the negotiated connection.
///
/// The caller gets the connection back so a test can assert on the negotiated
/// protocol and SNI, and so a future cycle can speak something over it
/// without redoing the handshake plumbing.
pub fn handshake_once(
    stream: TcpStream,
    config: &ServerConfig,
) -> Result<StreamOwned<ServerConnection, TcpStream>, AcceptorError> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| AcceptorError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| AcceptorError::Io(e.to_string()))?;

    let connection = ServerConnection::new(Arc::new(config.clone()))
        .map_err(|e| AcceptorError::HandshakeFailed(e.to_string()))?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|e| AcceptorError::HandshakeFailed(e.to_string()))?;
    Ok(tls)
}
