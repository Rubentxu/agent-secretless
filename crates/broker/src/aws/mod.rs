//! AWS — the cloud providers ASV is responsible for.
//!
//! Ownership per the standing law: `OAuth/STS/mTLS -> ASV`. This module holds
//! the protocol encodings; the transport and the secret port live in
//! `connector-http`, mirroring how `oauth2` and `oauth2_port` split.
//!
//! **R2.C.1 is the signing core only.** It has no product surface yet and says
//! so; see [`sigv4`] for what is deliberately not here.

pub mod sigv4;

pub use sigv4::{SigV4Signer, SignError, SignRequest, SignedRequest};
