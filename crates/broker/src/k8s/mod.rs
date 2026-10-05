//! Kubernetes — the request core for the API reverse proxy.
//!
//! # Why this is a provider and not an adapter
//!
//! The R3 adapters take a credential that already exists and keep it out of a
//! tool's config. Kubernetes is the other half: the interesting property is not
//! hiding a token from a file, it is that **the agent never holds one at all**.
//! The agent names an operation, a namespace and a resource; ASV holds a
//! short-lived, audience-bound ServiceAccount token and adds it. So this belongs
//! in R2 beside OAuth2 and STS, not in R3 beside npm.
//!
//! # What exists here, and what does not
//!
//! **`request` is R2.D.1**: the method and the path, and the refusals that keep
//! the agent-supplied parts where they were put. It is a pure function — no
//! socket, no clock, no token, no vault — which is the only reason it can be
//! checked against an oracle at all.
//!
//! **R2.D.2** is the transport and the `SecretPort`, and **R2.D.3** is the
//! broker operation and the CLI verb. Neither exists. Nothing in this module is
//! reachable from a product surface, and the module says so rather than letting
//! a test imply otherwise: per M11's rule a provider does not count as closed on
//! an encoding alone.
//!
//! # What R2.D.2 must not do
//!
//! The token is a single bearer value, so it fits the existing
//! [`SecretPort`](asv_connector_http::SecretPort) shape unchanged —
//! `lend` hands borrowed bytes to a sink that builds the request and takes them
//! back, and `forget` is required with no default, so a cache of a derived
//! token is something a new port cannot forget to consider.
//!
//! The property R2.D.2 has to preserve is the one this module establishes: the
//! `Authorization` header is assembled **inside** the sink and sent before the
//! borrow ends. A `String` holding `Bearer <token>` that outlives the call is
//! the same leak with a different name, and it is the reason the OAuth2 port
//! takes a `&mut dyn SecretSink` rather than returning bytes.

pub mod request;

pub use request::{ApiError, ApiRequest, Scope, Verb};
