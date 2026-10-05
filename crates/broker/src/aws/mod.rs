//! AWS — the cloud providers ASV is responsible for.
//!
//! Ownership per the standing law: `OAuth/STS/mTLS -> ASV`. This module holds
//! the protocol encodings; the transport and the secret port live in
//! `connector-http`, mirroring how `oauth2` and `oauth2_port` split.
//!
//! **R2.C.1 was the signing core.** `sigv4` is the pure half — it signs,
//! it opens no socket, and it is what the vectors in its own tests pin down.
//!
//! **R2.C.2.a is `sts:AssumeRole` in both directions** — the request ASV signs
//! and the response it reads. `sts`.
//!
//! **R2.C.2.b is the transport and the cache.** `client` signs and sends
//! over a pinned, private-address-refusing transport; `port` caches the
//! short-lived session and hands out its three signing values through a sink
//! that takes all three.
//!
//! **R2.C.3 is what put a product surface on all of it.** The `asv aws` verb
//! opens its own session, the broker exposes `AwsBinding`, and `aws.*` is
//! advertised so an agent can find the verb by name. The chain from an agent's
//! word to a signed request is therefore closed at one operation.
//!
//! **What remains open is a different claim, and M11 is why it matters.** One
//! operation is not a catalogue: `s3:GetObject`, the regional STS endpoints and
//! the live call against AWS are named gaps, not a summary line. A vertical
//! that names one operation establishes a path; it does not establish a
//! provider, and nothing above should be read as saying it does.

pub mod audience;
pub mod s3;
pub mod calendar;
pub mod client;
pub mod identity;
pub mod port;
pub mod sigv4;
pub mod sts;

pub use sigv4::{SigV4Signer, SignError, SignRequest, SignedRequest};
