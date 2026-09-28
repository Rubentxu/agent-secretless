//! HTTP transport for brokered, semantic API calls (M4 design v2 D1, D7).
//!
//! This crate holds no session or policy state. That is the point: the broker
//! decides *whether* a call may happen, this crate decides *how* the bytes
//! travel, and keeping them apart means the transport can be fuzzed in
//! isolation with no credential material anywhere in scope.
//!
//! Three properties are load-bearing, and each one exists because its absence
//! is a real attack:
//!
//! 1. **Address pinning.** DNS is resolved once, checked, and then pinned into
//!    the client. A second lookup inside the HTTP stack would let a resolver
//!    answer `api.github.com` with `127.0.0.1` after the check passed.
//! 2. **Private-address refusal.** A loopback, link-local, or RFC1918 address
//!    is never a legitimate API audience, so reaching one means the host is not
//!    what the policy approved.
//! 3. **Same-origin redirects only, and never a re-emitted credential header**
//!    (D7). Reissuing an authenticated request against an attacker-chosen
//!    `Location` hands over the credential, so a cross-origin hop is denied
//!    rather than followed.
//!
//! R6: this crate must never read the environment (D9). A source-scanning
//! regression test enforces it, so a new config reader fails the build instead
//! of waiting for a review.

pub mod transport;

pub use transport::{resolve_and_pin, AddressPolicy, PinnedClient, TransportError};
