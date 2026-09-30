//! M9 — the TLS acceptor that presents a per-session leaf.
//!
//! `asv-broker` mints real x509: a two-tier session CA and one leaf per host.
//! This crate is the other end. It takes the material as DER and presents it
//! over a real TLS handshake, and that is the whole of its job.
//!
//! # Why a separate crate
//!
//! Rule D2 of the dependency architecture: a connector must not depend on
//! the vault, and that rule is enforced by a test. An acceptor fed by session
//! CAs is downstream of the vault, so putting it in `asv-connector-http`
//! would turn a hard rule into a comment. Putting it in `asv-broker` would
//! widen the secret-bearing process to hold a network server for the sake of
//! one call site.
//!
//! So the acceptor depends on `rustls` and nothing else. It has no `SessionCa`,
//! no session id, and no constructor that takes a CA key: it can present what
//! it is given and cannot mint. A crate that cannot reach a private key cannot
//! leak one, and that is the property the boundary exists to hold.
//!
//! Verify it rather than take it on trust:
//!
//! ```text
//! cargo tree -p asv-tls-acceptor --edges normal
//! ```
//!
//! No vault, no broker, no domain.
//!
//! # What is not here
//!
//! The eBPF redirect that would make the bridge transparent. This is a
//! server you can connect to, not a bridge that intercepts, and the two are
//! not the same thing.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod server;

pub use config::{AcceptorError, LeafMaterial};
pub use server::{handshake_once, Acceptor, HANDSHAKE_TIMEOUT};
