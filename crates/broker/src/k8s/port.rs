//! The Kubernetes `SecretPort` — where a ServiceAccount token is read, and where
//! it stops existing.
//!
//! # Why this provider fits the base contract that AWS had to refuse
//!
//! [`AwsSecretPort`](crate::aws::port::AwsSecretPort) implements `lend` by
//! refusing, always: an AWS session is three values, the single-value
//! [`SecretSink`] builds a bearer `Authorization` header, and handing it a
//! session token would be handing it one of three. The refusal is structural —
//! there is no conversion to offer — and it is the reason the trait is shaped
//! the way it is.
//!
//! A Kubernetes ServiceAccount token is **one** bearer value. So this port
//! implements the base contract unchanged, with no second trait and no second
//! sink type, and the shape that forced AWS to refuse is the shape Kubernetes
//! fits exactly. That is worth stating because it is the argument for keeping
//! the base contract narrow: a connector that grew a bespoke trait per provider
//! would have had to invent this one, and the invention would have been
//! avoidable.
//!
//! # The property, and how it is made true rather than asserted
//!
//! **The token is a borrowed value for the length of one `accept`, and is
//! nothing afterwards.** Not "is not returned", not "is not logged" — *nothing*.
//! Three things make that structural rather than conventional:
//!
//! - The port reads the token into a [`Zeroizing`] buffer, so the bytes are
//!   wiped when `lend` returns rather than when some later drop runs. A `Vec`
//!   would be freed, not wiped, and freed memory is readable memory.
//! - The port has **no getter**. There is no method that returns the token, so
//!   there is no call site that could be written to use one.
//! - The port holds **no cache**, which is a decision argued below rather than
//!   an omission.
//!
//! The first version of this design cached the token, because the AWS port
//! caches and symmetry seemed free. It is not free, and the reason is recorded
//! in the AWS module: a cache whose margin is at or above the credential's
//! lifetime silently disables itself, and the failure is a port answering with
//! a credential nobody can diagnose. A projected ServiceAccount token is
//! already refreshed by the kubelet on a short period and lives at a path that
//! is replaced in place, so reading it per `lend` is both fresher and simpler
//! than any cache, and its failure mode is a `401` that says what it is.
//!
//! # The refusals, and the one that carries the property
//!
//! **A token carrying a control character is refused, not sanitised.** The token
//! becomes an `Authorization` header value, and the canonical request joins
//! header values — so a newline in a token is a second header, and a token the
//! broker believes it signed for one audience could be aimed at another. A
//! projected token is three base64url segments joined by `.`, so it can never
//! legitimately contain a control character: the refusal costs nothing and
//! closes the whole class. This is the same refusal the SigV4 core makes for a
//! header value, arrived at from the other direction.
//!
//! The rest are cheaper. An **empty** token is a request with no identity, which
//! the API server answers `401` for reasons unrelated to what the agent asked.
//! A token past [`MAX_TOKEN_BYTES`] is either not a token or an attempt to push
//! a header past what the transport will send, and the bound is read before the
//! bytes are interpreted rather than after.
//!
//! A **relative** token path is refused because a projected token path is
//! always absolute, and a relative one would resolve against whatever working
//! directory the broker happened to have been started in — a difference nobody
//! reading the configuration would notice and everybody debugging it would.
//!
//! One rule, applied everywhere: **a token this port does not understand is
//! refused, not repaired at the edges.** Nothing here trims, lowercases,
//! truncates or escapes; a credential that needed any of those is a credential
//! being served to something other than what it is.

use std::fs;
use std::path::{Path, PathBuf};

use asv_connector_http::{SecretError, SecretPort, SecretSink};
use zeroize::Zeroizing;

/// The largest token this port will read.
///
/// Kubernetes' own bound on a projected token is generous; this is not that
/// bound, and it is not trying to be. It is the point at which a token stops
/// being a credential and starts being a way to push bytes at a transport, and
/// the number is stated rather than inherited so that a change to it is a
/// decision someone can argue with.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// A port over a projected ServiceAccount token.
///
/// Holds the **path** and nothing else. There is no field that can hold a
/// token, which is the reason the property holds without depending on a caller
/// doing the right thing.
#[derive(Debug, Clone)]
pub struct K8sSecretPort {
    token_path: PathBuf,
}

impl K8sSecretPort {
    /// A port over the token mounted at `token_path`.
    ///
    /// Refuses a path that is empty or relative, **in one check rather than
    /// two**. The first version of this had an `is_empty` arm and an
    /// `is_absolute` arm, and falsifying it found the first one could never be
    /// the arm that refused: `PathBuf::from("")` is not absolute, so the second
    /// arm caught it first. Two checks for one property is two
    /// implementations of it, and the one that runs second is the one whose
    /// message a reader sees.
    ///
    /// Nothing is read here: a constructor that opened the file would be a
    /// constructor that could fail on a credential that is legitimately rotated
    /// underneath it, and the failure would arrive as a construction error
    /// rather than as a refused lend.
    pub fn new(token_path: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let token_path = token_path.into();
        if token_path.as_os_str().is_empty() || !token_path.is_absolute() {
            return Err(SecretError::Unavailable(format!(
                "{token_path:?} is not a usable ServiceAccount token path: it must be \
                 absolute and non-empty, because a relative one would resolve against \
                 whatever working directory the broker was started in and nobody \
                 reading the configuration would notice"
            )));
        }
        Ok(Self { token_path })
    }

    /// The configured path, for the configuration surface and for diagnostics.
    ///
    /// Deliberately returns the *path* and not the token. A method named after
    /// the credential is the first step of every leak in this tree, and this one
    /// exists so that the diagnostics that want it have something to print.
    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// Read, check and lend the token.
    ///
    /// The buffer is [`Zeroizing`], so it is wiped when this returns whatever
    /// the sink did, including if the sink returned an error. There is no path
    /// out of here that leaves the bytes readable.
    fn read_and_lend(&self, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        let raw = fs::read(&self.token_path).map_err(|e| {
            SecretError::Unavailable(format!(
                "the projected ServiceAccount token at {} could not be read: {e}",
                self.token_path.display()
            ))
        })?;

        // Bounded before anything looks at the contents, so an oversized file
        // is refused without being interpreted.
        if raw.len() > MAX_TOKEN_BYTES {
            return Err(SecretError::Unavailable(format!(
                "the projected ServiceAccount token at {} is {} bytes, past the {} this \
                 port will read",
                self.token_path.display(),
                raw.len(),
                MAX_TOKEN_BYTES
            )));
        }

        let token: Zeroizing<Vec<u8>> = Zeroizing::new(raw);

        if token.is_empty() {
            return Err(SecretError::Unavailable(format!(
                "the projected ServiceAccount token at {} is empty, and an empty bearer is a \
                 request with no identity",
                self.token_path.display()
            )));
        }

        // The refusal that carries the property. A newline here is a second
        // header; nothing about the token is escaped, trimmed or repaired,
        // because a token that needed repair is a token being served to
        // something other than what it is.
        if let Some(offset) = token.iter().position(|b| b.is_ascii_control()) {
            return Err(SecretError::Unavailable(format!(
                "the projected ServiceAccount token at {} carries a control character at \
                 byte {offset}, and it becomes an Authorization header value: a newline in a \
                 header is a second header",
                self.token_path.display()
            )));
        }

        sink.accept(&token)
    }
}

impl SecretPort for K8sSecretPort {
    /// Lends the token to `sink`, which is expected to build and send the
    /// request inside `accept`.
    ///
    /// The `credential` argument is the vault-side id this port is serving, and
    /// it is accepted but not used to locate anything: the token comes from the
    /// mounted path, because that is where a projected token lives and reading
    /// it from the vault would be a second copy of a credential the kubelet is
    /// already rotating. `forget` below is what that decision costs, and it
    /// costs nothing, because there is no derived state to drop.
    fn lend(&self, credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        if credential.is_empty() {
            return Err(SecretError::Unavailable(
                "no credential id was named for the Kubernetes port".into(),
            ));
        }
        self.read_and_lend(sink)
    }

    /// Drops the cached token, so the next lend re-reads.
    ///
    /// Required on `SecretPort` with no default since R2.B, which is what makes
    /// the revocation property structural rather than a convention. Here it has
    /// nothing to drop, and that is the honest implementation of it: the port
    /// caches nothing, so a `DeleteCredential` takes effect on the very next
    /// request rather than at the end of a margin. An explicit no-op with that
    /// reason is different from an author who never considered it, and the
    /// trait exists to make the difference visible.
    fn forget(&self, _credential: &str) {
        // Nothing is held. See above: this is a considered no-op, not a
        // missing implementation.
    }
}

#[cfg(test)]
mod tests;
