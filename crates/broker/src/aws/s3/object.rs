//! R2.C.4b — the answer to "is this object there, and what is it" that holds no
//! object.
//!
//! [`super::S3Target`] decides *where* a request goes. This decides what comes
//! back, and the decision it makes is not to read the body at all.
//!
//! # Why the body is never read, which is the whole design
//!
//! S3 answers a failure with an XML document:
//!
//! ```text
//! <Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>
//! ```
//!
//! And `asv-broker` has **no XML parser**, on purpose and by decision:
//! `aws::sts` documents that a parser brings a DTD, a DTD is an XXE surface, and
//! the reader it wrote instead implements no entity mechanism at all — the five
//! predefined entities only, every other one a refusal, a bare `&` a refusal, a
//! document declaring a DTD a refusal. That decision is load-bearing across the
//! whole provider and this module is not the place to quietly undo it by
//! needing a body.
//!
//! So the status line is the signal and the body is discarded unread. Two
//! things follow that are worth stating rather than leaving implied:
//!
//! - An S3 error is identified by its **status**, not by its code. `NoSuchKey`
//!   and `AccessDenied` are both `4xx`, and the operation reports the status
//!   rather than pretending to know which one happened.
//! - Nothing in the answer can hold object bytes, because nothing reads them.
//!   `ObjectMetadata` is built entirely from response **headers**.
//!
//! # What this costs, stated plainly
//!
//! An operation that returns only metadata cannot answer "what is in it". That
//! is the point rather than a limitation, but it does mean the honest set of
//! agent-reachable S3 questions is "does it exist, what type, how big, when was
//! it last written" — which is what an operator actually asks before deciding to
//! do something with an object, and which the Kubernetes side answers with the
//! same shape.
//!
//! The alternative, returning the body, has no secretless property at all: a
//! broker that fetches an object and hands it to the agent is a proxy with a
//! policy check in front of it. If the body is ever needed, the path is a
//! broker that *uses* it — an adapter, in R3 — and not a verb that streams it.

/// What the transport reports back, decoupled from any HTTP client.
///
/// Headers rather than a client type, so this is answerable without a socket
/// and without the module taking a dependency on which HTTP stack is in use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectResponse {
    /// The status line's code.
    pub status: u16,
    /// The response headers, names lowercased, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl ObjectResponse {
    /// Every value of a header, matched case-insensitively, in arrival order.
    ///
    /// A plural, and that is a correction rather than a style choice. The
    /// first version of this returned the *first* match, and the row that
    /// checks an optional header for a control character came back green under
    /// an injected second `x-amz-version-id` — because the first, clean one is
    /// what a lookup returns. A duplicated header is exactly the log-injection
    /// vector, and the reader was blind to the half of it that matters.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The single value of a header, refused if it was sent more than once.
    ///
    /// A duplicate is ambiguous rather than merely unusual: two
    /// `content-length` values are two answers to "how big is it", and picking
    /// one would make the answer depend on the order the origin happened to
    /// serialise them in.
    pub fn header<'a>(&'a self, name: &'a str) -> Result<Option<&'a str>, ObjectError> {
        let mut found = self.values(name);
        let first = found.next();
        if found.next().is_some() {
            return Err(ObjectError::RepeatedHeader {
                // A header name is short and bounded, and the error outlives
                // the borrow, so it is copied. Naming the header is what makes
                // the refusal actionable.
                header: name.to_string(),
            });
        }
        Ok(first)
    }
}

/// Why a response could not be read as an object's metadata.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectError {
    /// The origin refused, or the object is not there.
    ///
    /// Carries the status and nothing else. The body — which for S3 is an XML
    /// document this workspace deliberately cannot parse — is not read, and
    /// the message says so, because an operator who sees a bare `403` and
    /// nothing else will assume the worst of their policy.
    #[error("S3 answered {status}; its body is an XML error document that this broker does not parse, so the status is the whole answer")]
    Refused {
        /// The status the origin returned.
        status: u16,
    },

    /// A header the answer is built from is missing.
    #[error("the response has no {header:?} header, so there is nothing to answer {question:?} with")]
    MissingHeader {
        /// The header that should have been there.
        header: &'static str,
        /// The question that header was the answer to.
        question: &'static str,
    },

    /// A header that should carry a number does not.
    #[error("{header:?} is {value:?}, which is not the number it has to be")]
    NotANumber {
        /// The header's name.
        header: &'static str,
        /// What it said.
        value: String,
    },

    /// An `ETag` that is not a quoted string.
    ///
    /// The quotes are stripped and the result is the value; an unquoted one is
    /// refused rather than accepted, because an `ETag` is an opaque token that
    /// gets compared against what a later write returns, and normalising the
    /// shape of it here would make that comparison depend on this module.
    #[error("the ETag is {value:?}, which is not a quoted opaque tag")]
    MalformedETag {
        /// What the header said.
        value: String,
    },

    /// A header the origin sent more than once.
    #[error("the {header:?} header was sent more than once, and two answers to one question are not an answer")]
    RepeatedHeader {
        /// The header's name, as the caller spelled it.
        header: String,
    },

    /// A header value carrying a control character.
    ///
    /// These values end up in a `Debug`, an audit record and an operator's
    /// terminal. A newline in one is a forged log line, and the refusal is
    /// here rather than left to whatever formats the value downstream.
    #[error("the {header:?} header carries a control character, which would be a second line in whatever prints it")]
    ControlCharacter {
        /// The header's name.
        header: &'static str,
    },
}

/// What an object looks like from the outside.
///
/// Every field comes from a header. There is no field a body could occupy, and
/// the destructuring row in this module's tests is what holds that: adding one
/// breaks the build rather than failing an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// The bucket the object was addressed in.
    pub bucket: String,
    /// The key the object was addressed by.
    pub key: String,
    /// `content-length`, as a number.
    pub content_length: u64,
    /// `ETag`, unquoted. The value a later write is compared against.
    pub etag: String,
    /// `last-modified`, kept as the origin sent it.
    ///
    /// Not parsed into an instant. A timestamp that fails to parse is a fact
    /// about the origin, and this operation has no clock and no calendar to
    /// compare it against — parsing it would add a dependency to answer a
    /// question nobody is asking yet.
    pub last_modified: String,
    /// `content-type`, when the origin sent one. S3 does not always.
    pub content_type: Option<String>,
    /// `x-amz-version-id`, on a versioned bucket.
    pub version_id: Option<String>,
    /// `x-amz-storage-class`, when the bucket is not the default class.
    pub storage_class: Option<String>,
}

impl ObjectMetadata {
    /// Whether the origin described a non-empty object.
    ///
    /// Asked often enough to be a method, and deliberately not a field: it is
    /// a reading of two of them rather than something the origin said.
    pub fn is_populated(&self) -> bool {
        self.content_length > 0
    }
}

/// Reads a response as an object's metadata, leaving the body unread.
///
/// The body is never touched, not even to check whether it is empty. That is
/// the design rather than an omission: see the module docs.
pub fn object_metadata(
    response: &ObjectResponse,
    bucket: &str,
    key: &str,
) -> Result<ObjectMetadata, ObjectError> {
    if !(200..300).contains(&response.status) {
        return Err(ObjectError::Refused {
            status: response.status,
        });
    }

    // Every value of every header this function reads is checked, not just
    // the one a lookup would return. The rule the campaign found the hard way.
    for header in [
        "content-length",
        "etag",
        "last-modified",
        "content-type",
        "x-amz-version-id",
        "x-amz-storage-class",
    ] {
        for value in response.values(header) {
            if value.bytes().any(|b| b.is_ascii_control()) {
                return Err(ObjectError::ControlCharacter { header });
            }
        }
    }

    let length = require(response, "content-length", "how big is it")?;
    let content_length: u64 = length
        .parse()
        .map_err(|_| ObjectError::NotANumber {
            header: "content-length",
            value: length.to_string(),
        })?;

    let etag = require(response, "etag", "which version is it")?;
    let etag = etag
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| ObjectError::MalformedETag {
            value: etag.to_string(),
        })?
        .to_string();

    Ok(ObjectMetadata {
        bucket: bucket.to_string(),
        key: key.to_string(),
        content_length,
        etag,
        last_modified: require(response, "last-modified", "when was it last written")?.to_string(),
        content_type: optional(response, "content-type")?,
        version_id: optional(response, "x-amz-version-id")?,
        storage_class: optional(response, "x-amz-storage-class")?,
    })
}

/// A header that has to be there.
fn require<'a>(
    response: &'a ObjectResponse,
    header: &'static str,
    question: &'static str,
) -> Result<&'a str, ObjectError> {
    response
        .header(header)?
        .ok_or(ObjectError::MissingHeader { header, question })
}


/// A header that may be absent, checked for control characters if it is not.
///
/// The check is here rather than at the call site so that adding a header to
/// this type later cannot skip it — which is exactly how a log-injection
/// vector gets introduced by somebody who did not know they were adding one.
fn optional(
    response: &ObjectResponse,
    header: &'static str,
) -> Result<Option<String>, ObjectError> {
    match response.header(header)? {
        None => Ok(None),
        Some(value) if value.bytes().any(|b| b.is_ascii_control()) => {
            Err(ObjectError::ControlCharacter { header })
        }
        Some(value) => Ok(Some(value.to_string())),
    }
}

#[cfg(test)]
mod tests;
