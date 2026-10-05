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
//! and the response it reads. It is also not a provider: there is no socket, no
//! `SecretPort` and no broker operation behind it, so nothing about it is
//! reachable by an agent yet. That half is [`sts`]'s last paragraph, and
//! R2.C.2.b is the one that has to earn it.

pub mod calendar;
pub mod client;
pub mod sigv4;
pub mod sts;

pub use sigv4::{SigV4Signer, SignError, SignRequest, SignedRequest};
