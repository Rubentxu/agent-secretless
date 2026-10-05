//! R2.D.3.1c — what the operator declares for one Kubernetes API server.
//!
//! [`request`](super::request) builds a path, [`port`](super::port) lends a
//! token, [`client`](super::client) sends it. None of those three knows *which*
//! API server, and that is the point: an agent must never be able to name the
//! audience. A request that carried its own `host` would let the broker send a
//! bearer token somewhere the operator never declared, and the token would be
//! valid there — that is the whole difference between this provider and one
//! that signs.
//!
//! So the deployment is a *declaration*, loaded at startup, and the request
//! names only a credential. The broker answers from the declared entry, and an
//! agent cannot reach a cluster it was not configured for by phrasing,
//! guessing an id, or editing a config file.
//!
//! # The part that is genuinely different from every other provider here
//!
//! [`AddressPolicy`] refuses
//! private addresses, and it is right to: a private address is where cloud
//! metadata services and other tenants live. A Kubernetes API server is almost
//! always a **ClusterIP** — a private address — and `kubernetes.default.svc`
//! resolves to one. So a correct in-cluster deployment *must* be able to reach
//! something the transport refuses by default.
//!
//! That is exactly the shape of thing that becomes a silent bypass, so the
//! exception is a type rather than a flag and it is narrow on purpose:
//!
//! - it exists only for an audience whose name is cluster DNS — `*.svc` or
//!   `*.svc.cluster.local`. An IP literal cannot opt in, so there is no way to
//!   write `allow 10.0.0.5`.
//! - it cannot be used for a public audience, so it cannot become a blanket
//!   "skip the address check".
//! - it is carried on the binding, so a `Debug` of the thing that holds it
//!   shows that the exception is in force rather than hiding it.
//!
//! # What this is not
//!
//! This is configuration, not reachability. The broker operation that reads a
//! `K8sBinding` does not exist yet, and nothing in this module is reachable
//! from a product surface. What exists is the declaration and the refusals it
//! makes at load time, which is the part that has to be right before the
//! operation can be written on top of it.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use asv_connector_http::transport::AddressPolicy;
use asv_domain::{Authority, CredentialId};

use super::client::K8sClient;
use super::port::K8sSecretPort;

/// The default API server port. Spelled rather than defaulted by a constant so
/// that a deployment carrying a different one is visible in its `Debug`.
pub const DEFAULT_KUBELET_PORT: u16 = 6443;

/// Where a pod that did not ask for anything else gets its ServiceAccount
/// token from.
///
/// This is a fact about Kubernetes rather than a choice, and it lives here
/// instead of in a test fixture for a reason that showed up the hard way: the
/// first version of this constant was written into a test helper, so the row
/// that "pinned" the path was pinning its own fixture and would have stayed
/// green through any change to the product. An operator gets this path from
/// `kubectl describe pod`, so it has to be somewhere they can read.
pub const PROJECTED_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Why a deployment could not be loaded.
///
/// Every arm is a refusal at load time. None of them is recoverable by
/// re-reading the configuration: a deployment that names an audience the
/// transport would refuse to connect to is wrong, and a broker that started
/// anyway would be wrong later, at the moment it mattered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentError {
    /// The audience is a private address and the deployment did not declare
    /// the in-cluster exception.
    ///
    /// The message names both halves, because an operator who reads only
    /// "connection refused" will add a network rule rather than declare the
    /// exception, and will end up with a broader hole than they meant.
    #[error(
        "audience {audience} is a private address; an in-cluster deployment must \
         declare it with K8sDeployment::in_cluster so the exception is on the record"
    )]
    PrivateAudienceUndeclared {
        /// The audience that resolved privately.
        audience: Authority,
    },

    /// The exception was declared, but the audience is not a cluster DNS name.
    ///
    /// The exception exists for `kubernetes.default.svc` and names like it. An
    /// IP literal that declares itself in-cluster has said nothing an operator
    /// could have verified, and allowing it would make the exception a way to
    /// reach any private address the broker can see.
    #[error("audience {audience} is not a cluster DNS name, so it cannot be declared in-cluster")]
    NotAClusterName {
        /// The audience that tried to opt in.
        audience: Authority,
    },

    /// The exception was declared for an audience that is public anyway.
    ///
    /// Harmless on its own, and refused because a configuration carrying an
    /// exception that does nothing is a configuration nobody has read.
    #[error(
        "audience {audience} is public; declaring the in-cluster exception for it means nothing"
    )]
    ExceptionOnAPublicAudience {
        /// The audience carrying an exception it does not need.
        audience: Authority,
    },

    /// The token path is not absolute.
    ///
    /// The port refuses this too, and refusing it twice is the point: this one
    /// fires at load, so a wrong path is a startup error rather than a runtime
    /// one on the first call an operator makes at 3am.
    #[error("the token path {path:?} is not absolute; a relative path depends on the broker's working directory")]
    RelativeTokenPath {
        /// The path as it was declared.
        path: String,
    },

    /// The declared port is zero, which never connects.
    #[error("port 0 never connects; an in-cluster API server is on {DEFAULT_KUBELET_PORT}")]
    ZeroPort,
}

/// The declared exception that lets one audience be a private address.
///
/// A unit struct with a method rather than a bare `bool`, so that writing the
/// exception down at the call site is the only way to obtain one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InCluster;

impl InCluster {
    /// Obtains the exception. Named so that the call site reads as a decision.
    pub fn declared() -> Self {
        InCluster
    }

    /// Whether `audience` is a name Kubernetes DNS would have produced.
    ///
    /// `*.svc` and `*.svc.cluster.local`, and nothing else. The check is on the
    /// name and not on the resolved addresses, so it holds before any lookup
    /// happens and cannot be satisfied by a DNS answer.
    fn matches(audience: &Authority) -> bool {
        let name = audience.as_str();
        name.ends_with(".svc")
            || name.ends_with(".svc.cluster.local")
            // A trailing dot is legal in DNS and `Authority` may carry one.
            || name.trim_end_matches('.').ends_with(".svc")
            || name
                .trim_end_matches('.')
                .ends_with(".svc.cluster.local")
    }
}

/// What the operator configured for one Kubernetes API server.
///
/// **Every field is non-secret.** The audience, the namespace and the token path
/// are things an operator types; the token itself is never here, it is at
/// `token_path` and reaches nothing but a borrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sDeployment {
    /// The credential a request may name to reach this deployment.
    ///
    /// Keyed by the vault's own `CredentialId` rather than by a label, for the
    /// reason `AwsDeployment` is: a label is a spelling the caller would have to
    /// be told, and the first version of the AWS field was exactly that and
    /// every call was refused against a deployment nobody could name.
    pub credential: CredentialId,
    /// The pinned API server. Never from a request — see the module docs.
    pub audience: Authority,
    /// The port the API server answers on.
    pub port: u16,
    /// Where the kubelet projects the ServiceAccount token.
    pub token_path: PathBuf,
    /// Set when the operator declared that this audience is reached over the
    /// cluster's private network.
    ///
    /// A Kubernetes API server is nearly always a ClusterIP, so this is the
    /// normal case and not an exception to the normal case — which is exactly
    /// why it is spelled out rather than defaulted. See
    /// [`DeploymentError::PrivateAudienceUndeclared`].
    pub in_cluster: Option<InCluster>,
}

impl K8sDeployment {
    /// Declares an in-cluster deployment and obtains the exception.
    pub fn in_cluster(mut self) -> Self {
        self.in_cluster = Some(InCluster::declared());
        self
    }

    /// The address policy this deployment needs.
    ///
    /// Loopback is never permitted, even in-cluster: an API server reached
    /// through loopback is a sidecar or a port-forward, and a sidecar is not
    /// the control plane the token was minted for.
    ///
    /// Read by the caller that builds the client, because resolution happens
    /// there. It lives on the deployment anyway, so the policy a deployment
    /// needs travels with the declaration rather than being restated at every
    /// construction site.
    pub fn address_policy(&self) -> AddressPolicy {
        AddressPolicy {
            allow_loopback: false,
        }
    }

    /// Checks the declaration without touching the network.
    ///
    /// Split from [`K8sBinding::new`] so the refusals can be reasoned about, and
    /// so an operator running a dry run gets the same answer the broker would.
    /// `resolves_private` is passed in rather than looked up, because a
    /// deployment check that performed DNS would be a second resolution and the
    /// pinned client is very deliberately the only one.
    pub fn check(&self, resolves_private: bool) -> Result<(), DeploymentError> {
        if self.port == 0 {
            return Err(DeploymentError::ZeroPort);
        }
        if !self.token_path.is_absolute() {
            return Err(DeploymentError::RelativeTokenPath {
                path: self.token_path.display().to_string(),
            });
        }
        if !resolves_private {
            // Public audience. An exception here means nobody read the file.
            return match self.in_cluster {
                Some(_) => Err(DeploymentError::ExceptionOnAPublicAudience {
                    audience: self.audience.clone(),
                }),
                None => Ok(()),
            };
        }
        match self.in_cluster {
            None => Err(DeploymentError::PrivateAudienceUndeclared {
                audience: self.audience.clone(),
            }),
            Some(_) if !InCluster::matches(&self.audience) => {
                Err(DeploymentError::NotAClusterName {
                    audience: self.audience.clone(),
                })
            }
            Some(_) => Ok(()),
        }
    }
}

/// A checked deployment, its client, and the port over its token.
pub struct K8sBinding {
    pub deployment: K8sDeployment,
    client: Arc<K8sClient>,
    port: Arc<K8sSecretPort>,
}

impl fmt::Debug for K8sBinding {
    /// The deployment and nothing else.
    ///
    /// `K8sSecretPort` holds no token, so this is not a leak here — but the
    /// rule is written down anyway rather than inherited, because the port
    /// having no state today is exactly the kind of thing a later cache would
    /// undo silently.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("K8sBinding")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl K8sBinding {
    /// Wires a checked deployment to a client and a port over its token.
    ///
    /// The client is *taken* rather than built here, which is the same split
    /// `AwsBinding::new` uses and for the same reason: construction performs
    /// the DNS pin, and a type that cannot be constructed without a network is
    /// a type whose wiring cannot be exercised by a row. The caller resolves,
    /// pins and hands it over; this wires.
    ///
    /// The port is built over the declared path and reads nothing: a token
    /// rotated by the kubelet underneath a live broker cannot fail a restart,
    /// and the read happens at `lend`.
    pub fn new(
        deployment: K8sDeployment,
        client: Arc<K8sClient>,
    ) -> Result<Self, super::client::K8sClientError> {
        let port = K8sSecretPort::new(deployment.token_path.clone())?;
        Ok(Self {
            deployment,
            client,
            port: Arc::new(port),
        })
    }

    /// The client this deployment sends with.
    pub fn client(&self) -> &K8sClient {
        &self.client
    }

    /// The port this deployment lends its token through.
    pub fn port(&self) -> &K8sSecretPort {
        &self.port
    }

    /// Whether this binding is the one a request's credential names.
    ///
    /// Compared as a `CredentialId` rather than as text: a wire id that parses
    /// is one record and two spellings of it are the same record, so there is
    /// no case-folding decision to get wrong.
    pub fn serves(&self, credential: &CredentialId) -> bool {
        &self.deployment.credential == credential
    }
}

#[cfg(test)]
mod tests;
