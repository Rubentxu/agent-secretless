//! What the broker decided, as a value the request cannot widen.
//!
//! The grant is the half of this module that does not come from the wire. It
//! exists as its own type, rather than as three arguments to
//! [`issue_client_certificate`](super::issue::issue_client_certificate), for one
//! reason: it makes "the agent named this" and "the broker decided this" two
//! different types that cannot be confused at a call site, and it is the type
//! — not a comment — that a future caller has to construct.

use std::time::Duration;

use asv_domain::Authority;

use super::issue::ClientCertError;

/// The shortest certificate this module will mint.
///
/// Below this a certificate is a liability rather than a credential: it cannot
/// be used by a peer that has any clock skew, and it expires while the agent
/// that asked for it is still setting up the connection it was for. Five
/// minutes is the conventional floor for short-lived client certificates and
/// is deliberately far below any grant that would be worth issuing anyway.
pub const MIN_CLIENT_CERT_TTL: Duration = Duration::from_secs(300);

/// An authorization to hold one client identity, for at most one lifetime.
///
/// Both fields are private with no accessors that return the stored `String`,
/// because the only way to build one is [`ClientGrant::for_identity`], which
/// canonicalizes. A grant that exists is a grant with a canonical identity,
/// so the check downstream of it does not have to be repeated by every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    identity: Authority,
    ttl: Duration,
}

impl ClientGrant {
    /// Grant `identity` for `ttl`.
    ///
    /// `identity` is canonicalized here rather than at issuance, because this
    /// is where the value enters the program: whoever holds the grant has
    /// already decided the name, and the issuance path should never be
    /// deciding spellings.
    ///
    /// `ttl` is **not** validated here. It is a request, and what is granted is
    /// a separate number decided at issuance against the CA's remaining life.
    /// Validating it at construction would split one rule across two places
    /// and make the issuance path look unconditional when it is not.
    pub fn for_identity(identity: &str, ttl: Duration) -> Result<Self, ClientCertError> {
        let identity = Authority::canonicalize(identity)
            .map_err(|e| ClientCertError::UnusableIdentity(e.to_string()))?;
        Ok(Self { identity, ttl })
    }

    /// The identity this grant authorizes.
    pub fn identity(&self) -> &Authority {
        &self.identity
    }

    /// The lifetime that was asked for, which is an upper bound and not a
    /// promise.
    ///
    /// Named `requested_ttl` rather than `ttl` for the same reason
    /// `S3Target` keeps one `path` field that is both the signed string and
    /// the sent one: a name that says which of the two numbers this is
    /// survives further than a comment does.
    pub fn requested_ttl(&self) -> Duration {
        self.ttl
    }
}
