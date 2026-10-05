//! R2.C.4a — S3 addressing: the bucket, the key, and the one path that is both
//! signed and sent.
//!
//! [`SignRequest::s3_path`](super::sigv4::SignRequest) already exists and
//! already encodes an S3 path once rather than twice, and
//! [`encode_component`] already implements the
//! rule AWS publishes. What did not exist is the step before them: turning a
//! bucket and a key into an audience and a path. The roadmap names this as the
//! second operation's first cost, and it is called out there as *not free*.
//!
//! # The property, stated as the thing that has to be true
//!
//! **The path that is signed is the path that is sent.** Not "equivalent", not
//! "decodes to the same thing" — the same string, produced once.
//!
//! That sounds like a tautology until you write the two paths separately, which
//! is what the obvious implementation does: one `encode_component` for the
//! request line and another for the canonical request. Encode the key's `/`
//! differently in the two places and the signature is computed over one
//! resource while the request fetches another. AWS rejects that, loudly, with a
//! signature mismatch — but the failure an operator sees is "your credentials
//! are wrong", and the credentials are fine. So the property here is that the
//! two cannot be written separately, rather than that a test checks they agree.
//!
//! # Why the bucket name is validated at all
//!
//! A bucket name becomes part of a **hostname**. `My_Bucket` and
//! `my.bucket..name` are not stylistically wrong, they are different hosts from
//! the ones the operator meant, and DNS will try to resolve them. So the rules
//! are the ones S3 publishes — lowercase, no underscores, no adjacent dots, not
//! IP-shaped, 3–63 characters — and the refusals say which one was broken,
//! because an operator who is told "invalid bucket" and not which rule has to
//! bisect the name by hand.
//!
//! # What this is not
//!
//! There is no request, no socket and no `SecretPort` here. This is the part
//! that can be wrong in a way nothing downstream can detect, which is why it
//! gets its own rows instead of being trusted to the client's first live call.

use asv_domain::Authority;

use super::sigv4::encode_component;

/// The S3 signing service name. Different from `sts`, and getting it wrong
/// produces a signature AWS accepts for nothing.
pub const S3_SERVICE: &str = "s3";

/// How a bucket is placed in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// `{bucket}.s3.{region}.amazonaws.com/{key}`.
    ///
    /// The default, and the only style that works over TLS for a bucket
    /// containing a dot, because the certificate is a wildcard over one label.
    VirtualHosted,
    /// `s3.{region}.amazonaws.com/{bucket}/{key}`.
    ///
    /// Kept because it is the only style that works for a bucket name that is
    /// literally an IP-shaped string, which S3 refuses to create but which a
    /// signature can still be computed over.
    PathStyle,
}

/// Why a bucket and a key could not be turned into a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum S3Error {
    /// The bucket name breaks one of S3's published rules.
    ///
    /// Named per rule because the whole point of validating it is that an
    /// operator can act on the answer, and "invalid bucket" sends them to
    /// bisect a 63-character string by hand.
    #[error("bucket {bucket:?} is not usable: {reason}")]
    InvalidBucket {
        /// The name as it was given.
        bucket: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// The key is empty, or carries a character that has no place in a path.
    #[error("object key {key:?} is not usable: {reason}")]
    InvalidKey {
        /// The key as it was given.
        key: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// The key walks out of its prefix.
    ///
    /// A `..` segment is refused rather than normalised, and the distinction is
    /// the point: normalising produces a path the operator did not name, and
    /// the signature would be computed over the *normalised* one while a
    /// reader of the request line sees the original.
    #[error("object key {key:?} contains a {segment:?} segment; a key is refused rather than rewritten")]
    Traversal {
        /// The key as it was given.
        key: String,
        /// The segment that walked.
        segment: String,
    },

    /// The region is empty, and the credential scope would be incomplete.
    #[error("an S3 audience needs a region; the credential scope is date/region/s3/aws4_request")]
    NoRegion,
}

/// A validated bucket and key, resolved to an audience and a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Target {
    /// The audience, already including the bucket in virtual-hosted style.
    pub authority: Authority,
    /// The path to put on the request line.
    ///
    /// This is the *only* path in the type, and it is what gets signed. There
    /// is no second field to drift out of step with it — see the module docs.
    pub path: String,
    /// The region the credential scope is built from.
    pub region: String,
}

impl S3Target {
    /// Resolves a bucket and a key into an audience and one path.
    pub fn resolve(
        bucket: &str,
        key: &str,
        region: &str,
        addressing: Addressing,
    ) -> Result<Self, S3Error> {
        check_bucket(bucket)?;
        check_key(key)?;
        if region.is_empty() {
            return Err(S3Error::NoRegion);
        }

        // Encoded once, here, and then used for both. The alternative — calling
        // the encoder at the request line and again inside the signer — is the
        // bug this module is shaped to make impossible.
        let encoded_key = encode_component(key.as_bytes(), true);

        let (host, path) = match addressing {
            Addressing::VirtualHosted => (
                format!("{bucket}.s3.{region}.amazonaws.com"),
                format!("/{encoded_key}"),
            ),
            Addressing::PathStyle => (
                format!("s3.{region}.amazonaws.com"),
                format!("/{}/{encoded_key}", encode_component(bucket.as_bytes(), false)),
            ),
        };

        Ok(Self {
            authority: Authority::canonicalize(&host).map_err(|_| S3Error::InvalidBucket {
                bucket: bucket.to_string(),
                reason: "the resulting host is not a usable authority",
            })?,
            path,
            region: region.to_string(),
        })
    }

    /// The path in the form the signer wants, which for S3 is the same string.
    ///
    /// A method rather than a field, and it returns the same value on purpose:
    /// a future contributor who thinks the canonical form should differ will
    /// find a one-line function that says `self.path.clone()` and a row that
    /// fails if they change it.
    pub fn canonical_path(&self) -> String {
        self.path.clone()
    }
}

/// Checks a bucket name against S3's published rules.
fn check_bucket(bucket: &str) -> Result<(), S3Error> {
    let invalid = |reason: &'static str| S3Error::InvalidBucket {
        bucket: bucket.to_string(),
        reason,
    };
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err(invalid("a bucket name is 3 to 63 characters"));
    }
    // The lower-case rule is not checked separately. The first version of
    // this had an explicit `is_ascii_uppercase` arm with its own message, and
    // the falsification campaign reported the row it was filed against
    // surviving the removal: the catch-all below already refuses `Acme`, and
    // its message still says "lowercase". The arm was a second way to say
    // something the first one already said.
    if bucket.contains('_') {
        return Err(invalid("a bucket name has no underscore, which is what DNS labels allow and S3 does not"));
    }
    if bucket.contains("..") {
        return Err(invalid("a bucket name has no adjacent dots"));
    }
    if bucket.starts_with('.') || bucket.ends_with('.') || bucket.starts_with('-') || bucket.ends_with('-')
    {
        return Err(invalid("a bucket name starts and ends with a letter or a digit"));
    }
    if !bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(invalid("a bucket name is lowercase letters, digits, dots and hyphens"));
    }
    // An IP-shaped name is refused because TLS cannot present a wildcard
    // certificate for one, which is why virtual-hosted addressing breaks on it
    // — and a signature computed for a host nobody can prove is not a host
    // anybody should send a credential to.
    if looks_like_ipv4(bucket) {
        return Err(invalid("a bucket name may not be an IPv4 address; a certificate cannot cover it"));
    }
    Ok(())
}

/// Whether a name is four dot-separated decimal octets.
///
/// Hand-rolled rather than parsed as an address, because `192.168.0.1` is a
/// valid `Ipv4Addr` and a perfectly ordinary string, and the rule is about what
/// the name *looks* like to a certificate authority.
fn looks_like_ipv4(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// Checks a key for the characters that have no place in a path.
fn check_key(key: &str) -> Result<(), S3Error> {
    let invalid = |reason: &'static str| S3Error::InvalidKey {
        key: key.to_string(),
        reason,
    };
    if key.is_empty() {
        return Err(invalid("a key is not empty; an empty one names the bucket itself"));
    }
    if let Some(byte) = key.bytes().find(|b| b.is_ascii_control()) {
        return Err(S3Error::InvalidKey {
            key: key.to_string(),
            reason: if byte == b'\n' || byte == b'\r' {
                "carries a line break, which is a second request"
            } else {
                "carries a control character"
            },
        });
    }
    if key.split('/').any(|segment| segment == ".." || segment == ".") {
        return Err(S3Error::Traversal {
            key: key.to_string(),
            segment: key
                .split('/')
                .find(|segment| *segment == ".." || *segment == ".")
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
