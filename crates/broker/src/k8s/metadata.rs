//! R2.D.3.1b — the reply filter, so a Secret's value is never the answer.
//!
//! [`K8sClient`](super::K8sClient) returns a body. For most resources that body
//! *is* the answer. For a `Secret` it is not, and handing it back would make
//! this provider the one thing M11's rule is about avoiding: a broker that
//! fetches a credential and then gives it to the agent, with a policy check in
//! front, which is a surrogate written by extra steps.
//!
//! # The operation this makes possible
//!
//! [`SecretMetadata`] answers a question an operator actually asks — *does this
//! secret exist, what type is it, when was it last written* — and there is no
//! field in it that a value could occupy. That is the strong posture, and it is
//! structural rather than a refusal: not "we check and then drop it", but a
//! type that cannot be asked to carry one. Adding a value-bearing field later
//! is a visible change to this struct and to every caller that destructures it,
//! which is what makes the omission reviewable rather than merely asserted.
//!
//! # The part that is easy to get wrong
//!
//! The obvious implementation parses the reply into a
//! [`serde_json::Value`] and reads the fields out of it. That
//! is wrong, and it is wrong in the way that matters here: `Value` **is** the
//! value. A `Secret` document parsed into one holds every key of `data` as a
//! `String`, on the heap, in a second allocation, and the "we never returned
//! it" claim is then true only in the sense that nobody read the field.
//!
//! So the document is deserialized **straight into a view** that has the
//! metadata fields and nothing else, and `data` is handled by
//! `count_entries`, a map visitor that increments a counter and routes both
//! the key and the value to
//! [`IgnoredAny`](https://docs.rs/serde/latest/serde/de/struct.IgnoredAny.html).
//! `IgnoredAny` walks a value and allocates nothing, so the secret's bytes stay
//! inside the reply buffer and are dropped with it.
//!
//! That is the whole claim, and it is worth being precise about what it is not.
//! The bytes **are** in memory — the API server sent them and the reply buffer
//! holds them, because a Kubernetes `Secret` has no metadata-only endpoint. What
//! is claimed is that nothing copies them out of that buffer. A stronger claim,
//! that the value is never resident, would need a streaming HTTP body reader
//! that discards as it reads, and that is a different piece of work.
//!
//! # Why it is a module here and not a row inside the operation
//!
//! Because the property belongs to the *shape of the answer*, and the answer
//! crosses a module boundary to reach the operation. Testing it at the
//! operation would test that operation; testing it here tests that a
//! `K8sReply` in hand cannot be turned into a value-carrying answer by anyone.

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::K8sReply;

/// Why a reply could not be read as an object's metadata.
///
/// Every arm is a refusal. There is no "read what I could" variant, because a
/// partial answer to "does this secret exist" is a worse answer than none: it
/// looks like the object was found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// The origin did not answer with a success status.
    ///
    /// Refused before the body is looked at, so a `404` produces this rather
    /// than a parse error about an error document the API server served.
    #[error("the API server answered {0}, so there are no metadata to read")]
    NotFound(u16),

    /// The body is not the JSON document the API server is documented to
    /// return.
    #[error("the reply is not a JSON object this client can read: {0}")]
    Unreadable(String),

    /// The document is JSON but not a Secret.
    #[error("the reply is a {kind:?} and not a Secret")]
    NotASecret {
        /// Whatever `kind` said, or `"nothing"` when the document had none.
        kind: String,
    },
}

/// What a Secret looks like from the outside.
///
/// Built by deserializing straight into a private view, so there is no window
/// in which the document exists as a `Value` with the secret in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    /// The object's name, as the API server spells it.
    pub name: String,
    /// The namespace the object was read from.
    pub namespace: String,
    /// The Secret's type — `Opaque`, `kubernetes.io/tls`, and so on.
    pub secret_type: String,
    /// The resource version, which changes on every write.
    pub resource_version: String,
    /// How many keys the Secret holds.
    ///
    /// A count, never the keys. Key *names* are not secret and are often
    /// wanted, but they are also the first half of a credential hunt, and a
    /// broker that lists them is a broker an agent can point at a directory.
    /// Counting is what "is it populated" actually needs.
    key_count: usize,
}

impl SecretMetadata {
    /// How many keys the Secret holds.
    ///
    /// A method rather than a public field, because the field is an artefact
    /// of counting rather than data the broker kept, and a public field would
    /// read as the latter.
    pub fn key_count(&self) -> usize {
        self.key_count
    }
}

/// The private view the document is deserialized into.
///
/// `data` has no field of its own: [`count_entries`] produces the number, and
/// the member's value is never bound to anything.
#[derive(Debug, Deserialize)]
struct SecretView {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    metadata: ObjectMetaView,
    #[serde(rename = "data", default, deserialize_with = "count_entries")]
    key_count: usize,
}

#[derive(Debug, Default, Deserialize)]
struct ObjectMetaView {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(rename = "type", default)]
    secret_type: String,
    #[serde(rename = "resourceVersion", default)]
    resource_version: String,
}

/// Counts a JSON object's members without binding any of them.
///
/// Both the key and the value go to [`IgnoredAny`], which walks them and
/// allocates nothing. The alternative — deserializing into a
/// `HashMap<String, String>` and calling `.len()` — would allocate a `String`
/// per key *and* per value, and the value is the credential.
fn count_entries<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    struct CountingVisitor;

    impl<'de> Visitor<'de> for CountingVisitor {
        type Value = usize;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object whose members are counted and discarded")
        }

        fn visit_map<A>(self, mut map: A) -> Result<usize, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut counted = 0usize;
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                counted += 1;
            }
            Ok(counted)
        }
    }

    deserializer.deserialize_map(CountingVisitor)
}

/// Reads a `Secret` reply as metadata, leaving the value where it is.
pub fn secret_metadata(reply: &K8sReply) -> Result<SecretMetadata, MetadataError> {
    if !reply.is_success() {
        return Err(MetadataError::NotFound(reply.status));
    }

    // Straight from the bytes. There is no intermediate `Value`, so there is
    // no moment at which the whole document — value included — exists as a
    // tree of heap strings.
    let view: SecretView = serde_json::from_slice(&reply.body)
        .map_err(|error| MetadataError::Unreadable(error.to_string()))?;

    // The kind is checked before any metadata is handed back, so a reply that
    // is a Pod or a Status is refused on its own terms rather than yielding a
    // Secret-shaped answer read out of something else.
    match view.kind.as_deref() {
        Some("Secret") => {}
        other => {
            return Err(MetadataError::NotASecret {
                kind: other.unwrap_or("nothing").to_string(),
            })
        }
    }

    Ok(SecretMetadata {
        name: view.metadata.name,
        namespace: view.metadata.namespace,
        secret_type: view.metadata.secret_type,
        resource_version: view.metadata.resource_version,
        key_count: view.key_count,
    })
}

#[cfg(test)]
mod tests;
