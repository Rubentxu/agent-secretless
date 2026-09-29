//! Local in-process PostgreSQL server for tests (M6 design v2, fake origin).
//!
//! Mirrors `asv-connector-http::fake_origin`: a real socket on loopback
//! that speaks enough of the PostgreSQL startup protocol to drive the
//! real connector without touching a real database.
//!
//! The fake records how many times `connect` happened, and it returns a
//! synthetic `AuthenticationOk` for every accepted pair, so a unit test
//! for M6-S3 can assert the listener was *not* entered.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the listener has recorded.
#[derive(Debug, Default)]
pub struct FakePgCounters {
    pub connections: AtomicUsize,
    pub startups: AtomicUsize,
}

/// Handle to the running fake server.
pub struct FakePg {
    pub address: String,
    pub port: u16,
    counters: Arc<FakePgCounters>,
    /// The task handle. Drop it (or call `shutdown`) to stop accepting.
    _task: tokio::task::JoinHandle<()>,
}

impl FakePg {
    /// Number of TCP connections accepted.
    pub fn connection_count(&self) -> usize {
        self.counters.connections.load(Ordering::SeqCst)
    }

    /// Number of `StartupMessage`s parsed.
    pub fn startup_count(&self) -> usize {
        self.counters.startups.load(Ordering::SeqCst)
    }
}

/// Starts a fake PostgreSQL server on a random loopback port.
pub async fn start() -> std::io::Result<FakePg> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let address = format!("127.0.0.1:{}", port);
    let counters = Arc::new(FakePgCounters::default());
    let task = tokio::spawn(run(listener, counters.clone()));
    Ok(FakePg {
        address,
        port,
        counters,
        _task: task,
    })
}

async fn run(listener: TcpListener, counters: Arc<FakePgCounters>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                counters.connections.fetch_add(1, Ordering::SeqCst);
                let c = counters.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(stream, c).await {
                        eprintln!("fake_pg: connection error: {}", err);
                    }
                });
            }
            Err(err) => {
                eprintln!("fake_pg: accept error: {}", err);
                return;
            }
        }
    }
}

async fn handle(mut stream: TcpStream, counters: Arc<FakePgCounters>) -> std::io::Result<()> {
    // Read the StartupMessage: 4 bytes length, 4 bytes protocol (196608),
    // then key/value pairs of {length, name, value} terminated by a
    // zero-length pair, then a single zero byte.
    //
    // We do not fully parse the protocol — we only need to count the
    // start of a session so a test can assert a startup happened (or
    // didn't). The remainder is a synthetic `AuthenticationOk` so the
    // test can drive the broker's `connect` without a real database.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    stream.read_exact(&mut body).await?;

    counters.startups.fetch_add(1, Ordering::SeqCst);

    // Reply: `R` (Authentication) + length 8 + code 0 (AuthenticationOk).
    let mut reply = Vec::with_capacity(9);
    reply.push(b'R');
    reply.extend_from_slice(&8u32.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}