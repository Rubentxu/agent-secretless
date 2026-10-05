//! R2.E.1 — mTLS: the broker signs the identity it decides, not the one the agent names.
//!
//! M11's rule for a provider is *real provider, real operation, real
//! secretless property, negative adversarial tests*. This module is the first
//! half of R2.E: the issuance half. The operation half — a broker that
//! presents a client certificate on an outbound mTLS connection — is a
//! separate increment, and this module is deliberately built so that half
//! needs nothing new from here.
//!
//! # What already existed, and why this does not add a second issuer
//!
//! [`SessionCa`](crate::tls_bridge::SessionCa) in `tls_bridge` is a real two-tier x509
//! authority: a self-signed root, an intermediate it signs, and leaves the
//! intermediate signs. Reusing it is the whole point. A second issuer would be
//! two answers to the same question — "which key is trusted for this
//! session?" — and the architecture rules in
//! `12-CAPABILITY-OWNERSHIP-AND-NO-OVERLAP.md` say one question has one owner.
//! So the CA, its TTL, its expiry check and its two-tier chain are all
//! borrowed, and this module only adds the one thing `issue_leaf` cannot do:
//! sign a key the broker never generated.
//!
//! # The posture, stated exactly
//!
//! [`issue_leaf`](crate::tls_bridge::issue_leaf) mints a key inside the broker and **returns it** in
//! [`LeafCertificate::leaf_key`](crate::tls_bridge::LeafCertificate::leaf_key), because the caller has to complete a TLS
//! handshake. That is exposure of private key material to a caller, which in
//! this codebase's vocabulary is not the strong posture. A CSR inverts it:
//! the agent generates the key pair, the private half never crosses the
//! boundary, and the broker learns only the public half. The broker is then
//! signing an identity it cannot impersonate, which is the difference between
//! a helper that can be pointed at a service and a key that can be stolen
//! and replayed.
//!
//! The cost of that inversion is that a CSR is attacker-controlled ASN.1, and
//! the temptation is to sign what it asks for. That is the defect this module
//! exists to not have.
//!
//! # The property
//!
//! **The certificate names the identity the broker granted, and no SAN, no
//! distinguished name, no key usage and no extended key usage survives from
//! the request.**
//!
//! This matters because [`rcgen::CertificateSigningRequestParams::from_der`]
//! populates `CertificateParams` from the request: the subject, the SANs, the
//! requested key usages and the requested EKUs all arrive as *data the agent
//! chose*. A CA that signs those fields has built a certificate authority for
//! its own subscribers — a subscriber can request `*.internal`, a `CA:TRUE`
//! basic-constraint, and a `keyCertSign` key usage, and if the CA honours the
//! request the subscriber is a CA. This module reads only
//! `CertificateSigningRequestParams::public_key` out of the request and
//! discards the rest, so the request's opinion of who the agent is never
//! reaches the signed certificate.
//!
//! Everything the agent gets to say is the one thing it is supposed to be able
//! to say: "here is the public half of a key I hold". The private half is not
//! a field of [`ClientCsr`](crate::tls_bridge::mtls::issue::ClientCsr), not a field of [`IssuedClientCert`](crate::tls_bridge::mtls::issue::IssuedClientCert), and there is
//! no API in this module through which a private key could enter or leave.
//!
//! # What is not claimed here
//!
//! - **No proof of possession is performed beyond the CSR's own signature.**
//!   `from_der` verifies that the request was signed by the key it carries, so
//!   the requester demonstrably held the private half at request time. It
//!   says nothing about whether that half still works, which only the peer's
//!   handshake can establish. This is a signing API, not an authenticating
//!   one.
//! - **The identity is a name, not an authorization.** Granting
//!   `svc-a.internal` a certificate says the broker vouches for that name. Who
//!   is entitled to *hold* it is the connector's question, and answering it
//!   needs the operation half and the policy plane.
//! - **The wildcard question is answered by a type, not by a check.**
//!   [`asv_domain::Authority`] admits a bare lowercase ASCII DNS name and
//!   nothing else, and `*` is not a legal label, so a wildcard cannot be
//!   represented in a [`ClientGrant`](crate::tls_bridge::mtls::grant::ClientGrant)(grant::ClientGrant). The rejection is structural; the test
//!   that proves it exists because the type would otherwise have to be
//!   questioned at every call site.
//!
//! # Why `mtls` hangs off `tls_bridge`
//!
//! It shares the [`SessionCa`](crate::tls_bridge::SessionCa) that module defines, and
//! `lib.rs` registers one module per domain. The `#[path]` attribute is the
//! same indirection `crates/cli/src/main.rs` and `crates/cli/src/agent/mod.rs`
//! already use to reach a subdirectory from a module that is itself a single
//! file.

pub mod grant;
pub mod issue;

pub use grant::{ClientGrant, MIN_CLIENT_CERT_TTL};
pub use issue::{ClientCertError, ClientCsr, IssuedClientCert, issue_client_certificate};

#[cfg(test)]
mod tests;
