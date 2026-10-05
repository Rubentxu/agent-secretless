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
//! **`port` is R2.D.2's secretless half**: the projected ServiceAccount token
//! read, checked and lent, so that it is a borrowed value for the length of one
//! `accept` and nothing afterwards. A Kubernetes token is a *single* bearer
//! value, so it fits the base [`SecretPort`](asv_connector_http::SecretPort)
//! contract unchanged — which is the very contract
//! [`AwsSecretPort`](crate::aws::port::AwsSecretPort) refuses, because an AWS
//! session is three values and the single-value sink builds a bearer header. The
//! shape that forced AWS to refuse is the shape Kubernetes fits exactly, which
//! is the argument for keeping the base contract narrow rather than growing a
//! trait per provider.
//!
//! **`client` is R2.D.3.1**: the transport that actually opens the socket. It
//! borrows from the pinned client the rest of the product already uses rather
//! than assembling an HTTP stack of its own, and it is where the bearer header
//! is built — which is the one place in this module where the token exists
//! outside the port, and it exists there for the length of a single attempt.
//!
//! **`binding` is R2.D.3.1c**: what the operator declares for one API server —
//! the audience, the port, the token path — and the refusals that make at load
//! what the request never can. It exists because Kubernetes is the one provider
//! here whose correct audience is normally a *private* address, which the pinned
//! transport refuses by default; the exception for that is a narrow type rather
//! than a flag.
//!
//! **What R2.D.3 still owes** is the broker operation and the CLI verb. Neither
//! exists, so nothing in this module is reachable from a product surface yet,
//! and the module says so rather than letting a test imply otherwise: per M11's
//! rule a provider does not count as closed on an encoding, a port and a
//! transport together.
//!
//! # The difference from AWS, and why this module is careful about it
//!
//! Every other provider here *signs*. An AWS SigV4 signature is derived from
//! the long-lived key and can be held, replayed against the host it was signed
//! for, and logged without consequence. A Kubernetes bearer token has no such
//! transform: `Authorization: Bearer <token>` **is** the credential, so anything
//! that reads the header can act as the ServiceAccount.
//!
//! That is why the header is assembled inside the sink, handed out exactly
//! once, re-borrowed from the port on every redirect hop rather than carried
//! forward, and never followed across an origin boundary. A `String` holding
//! `Bearer <token>` that outlives the call is the same leak under another name,
//! and it is why `SecretPort` takes a `&mut dyn SecretSink` rather than
//! returning bytes: the sink is a thing that *uses* the credential, and
//! returning one would make stashing it the caller's easiest option.

pub mod binding;
pub mod client;
pub mod metadata;
pub mod port;
pub mod request;

pub use binding::{DeploymentError, InCluster, K8sBinding, K8sDeployment};
pub use client::{K8sClient, K8sClientError, K8sReply};
pub use metadata::{secret_metadata, MetadataError, SecretMetadata};
pub use port::{K8sSecretPort, MAX_TOKEN_BYTES};
pub use request::{ApiError, ApiRequest, Scope, Verb};
