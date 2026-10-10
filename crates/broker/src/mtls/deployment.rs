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

use asv_domain::{Authority, CredentialId};

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

/// One operator-declared grant, for one vault credential.
///
/// R2.E.3.2: the broker signs a CSR the agent brought, and what gets signed
/// is the identity the operator declared for the credential — never a name
/// the request supplied. The shape mirrors [`ClientBinding`] so the dispatch
/// path treats the two with the same vocabulary, and what differs is the
/// access pattern: `ClientBinding` is destination-keyed (the broker presents
/// a cert when reaching a host), `SigningBinding` is credential-keyed (the
/// broker signs when an agent asks for one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningBinding {
    credential: CredentialId,
    identity: Authority,
    ttl: Duration,
}

impl SigningBinding {
    /// Declare `credential` as the holder of an identity, valid for `ttl`.
    ///
    /// The credential is parsed at construction (not stored as a free-form
    /// string) for the same reason [`ClientBinding`] canonicalizes: the value
    /// enters the program here, and a declaration that *exists* is a
    /// declaration that already passed the only check worth running on it.
    pub fn new(credential: &str, identity: &str, ttl: Duration) -> Result<Self, DeploymentError> {
        let credential = CredentialId::from_wire(credential)
            .map_err(|_| DeploymentError::UnusableCredential(credential.to_string()))?;
        Ok(Self {
            credential,
            identity: canonical(identity, DeploymentError::UnusableIdentity)?,
            ttl,
        })
    }

    /// The vault credential this binding answers for.
    pub fn credential(&self) -> &CredentialId {
        &self.credential
    }

    /// The name this binding authenticates as.
    pub fn identity(&self) -> &str {
        self.identity.as_str()
    }

    /// The lifetime a certificate minted from this binding may have.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether this binding is the one a request's credential names.
    ///
    /// Compared as a `CredentialId` rather than as text: a wire id that parses
    /// is one record and two spellings of it are the same record, so there
    /// is no case-folding decision to get wrong.
    pub fn serves(&self, credential: &CredentialId) -> bool {
        &self.credential == credential
    }

    /// The grant the issuer needs, built here so the issuance path does not
    /// have to know how a binding is shaped.
    pub fn to_grant(&self) -> Result<ClientGrant, ClientCertError> {
        ClientGrant::for_identity(self.identity.as_str(), self.ttl)
    }
}

/// A set of bindings, checked for the one thing that would make it ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsDeployment {
    bindings: Vec<ClientBinding>,
    signers: Vec<SigningBinding>,
}

impl MtlsDeployment {
    /// A declaration with no bindings: every destination is reached without a
    /// client identity, which is the same behaviour as a bridge that was never
    /// given one.
    pub fn empty() -> Self {
        Self {
            bindings: Vec::new(),
            signers: Vec::new(),
        }
    }

    /// A declaration from a list, refusing a destination declared twice.
    pub fn new(
        bindings: Vec<ClientBinding>,
        signers: Vec<SigningBinding>,
    ) -> Result<Self, DeploymentError> {
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
        for (index, signer) in signers.iter().enumerate() {
            if let Some(first) = signers[..index]
                .iter()
                .find(|other| other.credential() == signer.credential())
            {
                return Err(DeploymentError::DuplicateCredential {
                    credential: signer.credential().to_wire(),
                    first: first.identity().to_string(),
                    second: signer.identity().to_string(),
                });
            }
        }
        Ok(Self { bindings, signers })
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

    /// The signing binding for `credential`, or `None` if no such binding is
    /// declared.
    ///
    /// The same shape as `identity_for`: `None` is the ordinary answer for a
    /// credential nobody declared, and it is not a refusal. An agent that asks
    /// for a credential the operator did not register gets nothing, and the
    /// dispatch path turns that into a `Denied` with the configured list.
    pub fn signer_for(&self, credential: &CredentialId) -> Option<&SigningBinding> {
        self.signers.iter().find(|signer| signer.serves(credential))
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

    /// A signing binding named a credential that is not a canonical vault id.
    #[error("{0} is not a canonical credential id")]
    UnusableCredential(String),

    /// The same credential was declared as a signer more than once.
    #[error("credential {credential} is declared twice, as {first} and as {second}; a credential has one identity or none")]
    DuplicateCredential {
        /// The credential both bindings name.
        credential: String,
        /// The identity of the earlier binding.
        first: String,
        /// The identity of the later one.
        second: String,
    },
}

/// The floor a declaration's lifetime is measured against, re-exported so a
/// caller reading a [`ClientBinding`] does not have to know which module owns
/// the constant.
pub const BINDING_MIN_TTL: Duration = MIN_CLIENT_CERT_TTL;

#[cfg(test)]
#[path = "deployment/tests.rs"]
mod tests;
