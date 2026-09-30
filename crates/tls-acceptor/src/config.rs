//! Turning DER blobs into a `rustls::ServerConfig`.
//!
//! The crate's whole job is one line: take the material a session CA produced
//! and hand it to rustls in the shape rustls expects. Everything here exists
//! to make that conversion fail loudly rather than silently.

use std::fmt;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Why a `LeafMaterial` could not be turned into a server config.
///
/// The variants are kept distinct on purpose. `KeyRejected` and
/// `ChainRejected` look identical from the outside and mean opposite things
/// to whoever has to fix it, so they are not merged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcceptorError {
    /// The chain was empty, so there is no end-entity certificate to
    /// present. A configuration bug, never a runtime condition.
    #[error("leaf chain is empty: there is no certificate to present")]
    EmptyChain,

    /// The chain's first element is empty. Distinct from `EmptyChain`
    /// because this one means the ordering was violated: the end-entity
    /// certificate is the first element, not any element.
    #[error("leaf chain's end-entity certificate is empty")]
    EmptyEndEntity,

    /// The root is empty. The acceptor does not verify anything itself, but
    /// an empty root is always a caller mistake and is caught here so it
    /// surfaces at construction rather than as a confusing handshake error
    /// later.
    #[error("root certificate is empty")]
    EmptyRoot,

    /// The private key DER is not one rustls can use.
    #[error("private key rejected: {0}")]
    KeyRejected(String),

    /// rustls refused the certificate chain as configured.
    #[error("certificate chain rejected: {0}")]
    ChainRejected(String),

    /// The handshake itself failed. Transport level, carries rustls's own
    /// message.
    #[error("tls handshake failed: {0}")]
    HandshakeFailed(String),

    /// A socket operation failed while binding or accepting.
    #[error("io error: {0}")]
    Io(String),
}

/// Everything needed to present one leaf, as DER.
///
/// The type is deliberately incapable of minting: it has no CA key, no
/// session id and no constructor that takes one. It can present what it is
/// given and nothing else, which is the property the crate boundary is for.
pub struct LeafMaterial {
    /// The session root, kept so a caller can hand it to whatever verifies
    /// the acceptor. Not used for the handshake itself: TLS servers do not
    /// verify their own chain.
    root_der: Vec<u8>,
    /// `[end-entity, ...intermediates]`, in that order. The order is
    /// load-bearing. TLS sends this list in order, and a client that cannot
    /// build a path reports a trust failure that looks nothing like a
    /// missing intermediate.
    leaf_chain_der: Vec<Vec<u8>>,
    /// The end-entity private key, DER-encoded.
    leaf_key_der: Vec<u8>,
}

impl LeafMaterial {
    /// Builds the material, rejecting the shapes that are certainly wrong.
    ///
    /// The deeper check is deferred to `server_config`, which is where
    /// rustls can say something specific about the key and the chain.
    pub fn new(
        root_der: Vec<u8>,
        leaf_chain_der: Vec<Vec<u8>>,
        leaf_key_der: Vec<u8>,
    ) -> Result<Self, AcceptorError> {
        if root_der.is_empty() {
            return Err(AcceptorError::EmptyRoot);
        }
        let end_entity = leaf_chain_der.first().ok_or(AcceptorError::EmptyChain)?;
        if end_entity.is_empty() {
            return Err(AcceptorError::EmptyEndEntity);
        }
        Ok(Self {
            root_der,
            leaf_chain_der,
            leaf_key_der,
        })
    }

    /// The session root, for handing to a verifier.
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The chain as it will be presented: end-entity first.
    pub fn leaf_chain_der(&self) -> &[Vec<u8>] {
        &self.leaf_chain_der
    }

    /// Builds the rustls server config.
    ///
    /// The chain is handed over in the order it was given. Reordering it
    /// here would be a quiet way to produce a certificate that some clients
    /// accept and others do not.
    pub fn server_config(&self) -> Result<ServerConfig, AcceptorError> {
        let key = PrivateKeyDer::try_from(self.leaf_key_der.clone())
            .map_err(|error| AcceptorError::KeyRejected(error.to_string()))?;
        let chain: Vec<CertificateDer<'static>> = self
            .leaf_chain_der
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|error| AcceptorError::ChainRejected(error.to_string()))
    }
}

/// Hand-written because the derived one would print `leaf_key_der` in full.
///
/// A `Debug` that leaks a private key is the kind of defect that reaches
/// production through a log line nobody reads, so the field is reduced to
/// its length. `root_der` and the chain are public certificates and are
/// summarised the same way for consistency: a `Debug` output is for
/// identifying a value, not for dumping it.
impl fmt::Debug for LeafMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafMaterial")
            .field("root_der_len", &self.root_der.len())
            .field(
                "leaf_chain_der_lens",
                &self
                    .leaf_chain_der
                    .iter()
                    .map(Vec::len)
                    .collect::<Vec<usize>>(),
            )
            .field("leaf_key_der_len", &self.leaf_key_der.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(root: &[u8], chain: &[&[u8]], key: &[u8]) -> Result<LeafMaterial, AcceptorError> {
        LeafMaterial::new(
            root.to_vec(),
            chain.iter().map(|c| c.to_vec()).collect(),
            key.to_vec(),
        )
    }

    #[test]
    fn empty_root_is_rejected() {
        assert_eq!(
            material(&[], &[b"leaf"], b"key").unwrap_err(),
            AcceptorError::EmptyRoot
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert_eq!(
            material(b"root", &[], b"key").unwrap_err(),
            AcceptorError::EmptyChain
        );
    }

    #[test]
    fn empty_end_entity_is_rejected() {
        assert_eq!(
            material(b"root", &[b"", b"intermediate"], b"key").unwrap_err(),
            AcceptorError::EmptyEndEntity
        );
    }

    #[test]
    fn debug_prints_no_key_bytes() {
        // A key-shaped blob whose bytes are unique enough to search for.
        let key: Vec<u8> = (0u8..=255).cycle().take(64).collect();
        let material = material(b"root", &[b"leaf", b"intermediate"], &key).expect("material");
        let rendered = format!("{material:?}");

        // The real claim is that no key *bytes* appear. The field is named
        // `leaf_key_der_len` on purpose: reporting the length of a private
        // key is useful for identifying a value and leaks nothing.
        assert!(
            !rendered.contains("0, 1, 2, 3"),
            "Debug leaked key bytes: {rendered}"
        );
        assert!(
            !rendered.contains("[0, 1, 2"),
            "Debug leaked the key as a byte array: {rendered}"
        );
        assert!(
            rendered.contains("leaf_key_der_len: 64"),
            "Debug should still report the key's length: {rendered}"
        );
    }

    #[test]
    fn a_non_key_is_rejected_rather_than_accepted() {
        // "not a key" is valid DER-shaped input for nothing rustls accepts.
        let material = material(b"root", &[b"leaf"], b"not a key").expect("material");
        match material.server_config() {
            Err(AcceptorError::KeyRejected(_)) => {}
            other => panic!("expected KeyRejected, got {other:?}"),
        }
    }
}
