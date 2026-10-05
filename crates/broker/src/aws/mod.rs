//! AWS — the cloud providers ASV is responsible for.
//!
//! Ownership per the standing law: `OAuth/STS/mTLS -> ASV`. This module holds
//! the protocol encodings; the transport and the secret port live in
//! `connector-http`, mirroring how `oauth2` and `oauth2_port` split.
//!
//! **R2.C.1 was the signing core, and it has no product surface yet.** It says
//! so; see [`sigv4`] for what is deliberately not there.
//!
//! **R2.C.2.a is `sts:AssumeRole` in both directions** — the request ASV signs
//! and the response it reads. [`sts`].
//!
//! **R2.C.2.b is the transport and the cache.** [`client`] signs and sends over
//! a pinned, private-address-refusing transport; [`port`] caches the
//! short-lived session and hands out its three signing values through a sink
//! that takes all three.
//!
//! **None of it is reachable by an agent.** There is no broker operation and no
//! CLI verb behind any of these types, so per M11's rule item 2 stays open — a
//! caller exists, but no agent can name one. That is R2.C.3.

pub mod calendar;
pub mod client;
pub mod identity;
pub mod port;
pub mod sigv4;
pub mod sts;

pub use sigv4::{SigV4Signer, SignError, SignRequest, SignedRequest};
