//! Where a client identity comes from: an operator's declaration, resolved
//! per destination.
//!
//! [`ClientIdentity`] is a key and a certificate the broker generated
//! for itself. Nothing yet says *when* one
//! should exist, *for which destination*, or *under what name*, and without
//! those three answers the type is only reachable from a test — which is the
//! "code without a consumer" shape this repository does not accept.
//!
//! This is the declaration that supplies them, and it is deliberately the same
//! shape as [`K8sDeployment`](crate::k8s::binding::K8sDeployment) and
//! [`AwsDeployment`](crate::aws_binding::AwsDeployment): a deployment names
//! what the operator granted, a request names what the agent wants, and the
//! two are compared rather than merged. An agent that asks to reach
//! `internal.svc.example` as `someone.else` gets nothing, because the
//! destination it named is in the declaration and the identity it asked for is
//! not.
//!
//! # What this buys, and what it does not
//!
//! It buys **rotation**: a certificate is short-lived, so something has to be
//! able to say that the next one carries a different name, and a declaration
//! is the only place that answer can live. Replacing this value with one that
//! names a different identity is the whole rotation operation, and the
//! certificate it mints is already on its way to expiring.
//!
//! It does not buy **authorization**. A binding says the broker will vouch for
//! a name to a destination; whether the caller is entitled to ask for that
//! binding is the policy plane's question, and answering it needs the IPC
//! surface. Declaring the separation here is what keeps this module from
//! growing a permission system it has no business owning.
//!
//! # One destination, one identity
//!
//! The declaration is a list and the list is checked for a repeated
//! destination at construction. First-one-wins would be the alternative, and it
//! is the wrong one: an operator who declares the same destination twice has
//! made a mistake, and resolving it by order means the file's formatting
//! decides which identity a destination is authenticated as.

use std::time::{Duration, Instant};

use asv_domain::Authority;

use super::grant::{ClientGrant, MIN_CLIENT_CERT_TTL};
use super::issue::ClientCertError;
use super::present::ClientIdentity;
use crate::tls_bridge::SessionCa;

/// One operator-declared client identity, for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientBinding {
    identity: Authority,
    destination: Authority,
    ttl: Duration,
}

impl ClientBinding {
    /// Declare `identity` for `destination`, valid for `ttl`.
    ///
    /// Both names are canonicalized here, where the declaration enters the
    /// program, so that no later comparison has to decide spellings. The TTL
    /// is checked for the same reason [`ClientGrant`] does not check it: one
    /// rule, in one place, and the rule that actually gates issuance stays in
    /// the issuer.
    pub fn new(identity: &str, destination: &str, ttl: Duration) -> Result<Self, DeploymentError> {
        Ok(Self {
            identity: canonical(identity, DeploymentError::UnusableIdentity)?,
            destination: canonical(destination, DeploymentError::UnusableDestination)?,
            ttl,
        })
    }

    /// The name this binding authenticates as.
    pub fn identity(&self) -> &str {
        self.identity.as_str()
    }

    /// The one destination this binding may be presented to.
    pub fn destination(&self) -> &str {
        self.destination.as_str()
    }

    /// The lifetime a certificate minted from this binding may have.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// A set of bindings, checked for the one thing that would make it ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsDeployment {
    bindings: Vec<ClientBinding>,
}

impl MtlsDeployment {
    /// A declaration with no bindings: every destination is reached without a
    /// client identity, which is the same behaviour as a bridge that was never
    /// given one.
    pub fn empty() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// A declaration from a list, refusing a destination declared twice.
    pub fn new(bindings: Vec<ClientBinding>) -> Result<Self, DeploymentError> {
        for (index, binding) in bindings.iter().enumerate() {
            if let Some(first) = bindings[..index]
                .iter()
                .find(|other| other.destination() == binding.destination())
            {
                return Err(DeploymentError::DuplicateDestination {
                    destination: binding.destination().to_string(),
                    first: first.identity().to_string(),
                    second: binding.identity().to_string(),
                });
            }
        }
        Ok(Self { bindings })
    }

    /// The identity this declaration has for `host`, minted now.
    ///
    /// `Ok(None)` is the ordinary answer for a destination nobody declared,
    /// and it is not a refusal: it is how a bridge knows to reach that
    /// destination as it reached every destination before R2.E.2.
    pub fn identity_for(
        &self,
        ca: &SessionCa,
        host: &str,
        now: Instant,
    ) -> Result<Option<ClientIdentity>, ClientCertError> {
        // Canonicalized for the same reason the binding was: the caller names
        // a host the way a route names it, and the comparison below is exact
        // only if both sides are in the same form. A host that is not a
        // canonical name at all resolves to nothing rather than to an error,
        // because a route that could not name the host would never have
        // reached this function.
        let canonical = match Authority::canonicalize(host) {
            Ok(authority) => authority,
            Err(_) => return Ok(None),
        };
        let Some(binding) = self
            .bindings
            .iter()
            .find(|binding| binding.destination() == canonical.as_str())
        else {
            return Ok(None);
        };
        let grant = ClientGrant::for_identity(binding.identity(), binding.ttl())?;
        Ok(Some(ClientIdentity::issue(
            ca,
            &grant,
            canonical.as_str(),
            now,
        )?))
    }

    /// Whether any binding names `host`.
    pub fn declares(&self, host: &str) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.destination() == host)
    }

    /// How many bindings this declaration holds.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether the declaration holds none.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

fn canonical(raw: &str, arm: fn(String) -> DeploymentError) -> Result<Authority, DeploymentError> {
    Authority::canonicalize(raw).map_err(|e| arm(e.to_string()))
}

/// Why a declaration could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentError {
    /// The same destination was declared more than once.
    ///
    /// Every arm of this enum is a refusal, and this one is the interesting
    /// case: the declaration is not wrong in any single line, it is only
    /// ambiguous as a whole, so nothing at the line level could have caught
    /// it.
    #[error("{destination} is declared twice, as {first} and as {second}; a destination has one identity or none")]
    DuplicateDestination {
        /// The destination both bindings name.
        destination: String,
        /// The identity of the earlier binding.
        first: String,
        /// The identity of the later one.
        second: String,
    },

    /// The name to authenticate as is not a name a certificate can carry.
    #[error("{0}")]
    UnusableIdentity(String),

    /// The destination is not a destination.
    #[error("{0}")]
    UnusableDestination(String),
}

/// The floor a declaration's lifetime is measured against, re-exported so a
/// caller reading a [`ClientBinding`] does not have to know which module owns
/// the constant.
pub const BINDING_MIN_TTL: Duration = MIN_CLIENT_CERT_TTL;

#[cfg(test)]
#[path = "deployment/tests.rs"]
mod tests;
