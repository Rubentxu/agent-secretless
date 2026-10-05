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
//! **R2.D.2** is the transport and the `SecretPort`, and **`port` is its
//! secretless half**: the projected ServiceAccount token read, checked and
//! lent, so that it is a borrowed value for the length of one `accept` and
//! nothing afterwards. A Kubernetes token is a *single* bearer value, so it fits
//! the base [`SecretPort`](asv_connector_http::SecretPort) contract unchanged —
//! which is the very contract
//! [`AwsSecretPort`](crate::aws::port::AwsSecretPort) refuses, because an AWS
//! session is three values and the single-value sink builds a bearer header. The
//! shape that forced AWS to refuse is the shape Kubernetes fits exactly, which
//! is the argument for keeping the base contract narrow rather than growing a
//! trait per provider.
//!
//! **R2.D.3** is the broker operation and the CLI verb, and the transport that
//! actually opens the socket. Neither exists. Nothing in this module is
//! reachable from a product surface, and the module says so rather than letting
//! a test imply otherwise: per M11's rule a provider does not count as closed on
//! an encoding and a port together.
//!
//! # What R2.D.3 must not do
//!
//! The token is lent as borrowed bytes and the `Authorization` header is
//! assembled **inside** the sink and sent before the borrow ends. A `String`
//! holding `Bearer <token>` that outlives the call is the same leak under
//! another name, and it is why `SecretPort` takes a `&mut dyn SecretSink`
//! rather than returning bytes: the sink is a thing that *uses* the credential,
//! and returning one would make stashing it the caller's easiest option.

pub mod port;
pub mod request;

pub use port::{K8sSecretPort, MAX_TOKEN_BYTES};
pub use request::{ApiError, ApiRequest, Scope, Verb};
