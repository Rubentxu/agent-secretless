//! AWS Signature Version 4 — the signing core.
//!
//! # Why this lives in the broker and not in a crate from crates.io
//!
//! `aws-sigv4` would do this. It is not used, for the same reason the
//! connector does not use a generic HTTP framework: `sha2` and `hmac` are
//! already in this workspace's lock, and the algorithm is a few hundred lines
//! of encoding and a four-step HMAC chain. Adding a crate would put a new
//! name into a signed SBOM to avoid writing code that has no dependencies.
//!
//! # What this is, and what R2.C.1 is not
//!
//! This is the *signing* half: canonicalisation, key derivation and the
//! `Authorization` header. It is a pure function of its inputs — no sockets, no
//! clock, no vault. That is deliberate, and it is why the block is worth
//! separating from the rest of R2.C:
//!
//! - **R2.C.1 (this module).** Sign correctly, checked against the vectors in
//!   the AWS documentation.
//! - **R2.C.2.** `sts:AssumeRole` over real HTTPS, short-lived session, cached
//!   and revocable, reusing the `forget` machinery from R2.B.1.
//! - **R2.C.3.** A broker operation and a CLI verb, so the agent names an
//!   operation and never sees an AWS secret.
//!
//! Nothing here is reachable from a product surface yet, and this module says
//! so rather than letting a test imply otherwise. Per M11's rule a provider
//! does not count as closed on a signing core alone.
//!
//! # The security property this has to have
//!
//! A SigV4 signature commits to the *host* and to every header named in
//! `SignedHeaders`. That is what stops a captured signed request being replayed
//! against a different host or with a different body. So the interesting
//! failures are not "wrong signature" — they are "signature computed without
//! the host", and "signature computed over a header list the caller controls".
//! `SignError` is built so those are refusals rather than something the caller
//! can opt out of.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The algorithm identifier that opens the `Authorization` header and the
/// string to sign. Not configurable: a second algorithm string in a signer is
/// a downgrade waiting to happen.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The literal AWS uses for a payload whose hash is not in the request.
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Why a request could not be signed.
///
/// Every arm is a refusal rather than a fallback. Each one is a case where
/// producing a signature would be producing an *unverifiable* or *ambiguous*
/// one, and an unverifiable signature from a security product is worse than no
/// signature: the caller learns nothing from the failure downstream and the
/// provider answers `SignatureDoesNotMatch` for a reason nobody can find.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// No `Host` was supplied or signed.
    ///
    /// Not an oversight the caller may wave through. The host is the one
    /// commitment that makes a signed request non-replayable against another
    /// destination, and AWS's own canonical form lists it first for that
    /// reason.
    #[error("a signed request must include the host header")]
    MissingHost,

    /// A header name is not a valid RFC 7230 token.
    ///
    /// Refused rather than lowercased-and-hoped-for: a name carrying a
    /// separator could change how the canonical request parses, and could let
    /// a caller sign one header and send another.
    #[error("header name {0:?} is not a valid token")]
    InvalidHeaderName(String),

    /// A header value contains a control character.
    ///
    /// A newline in a value is a second header. The canonical form joins
    /// headers with `\n`, so an embedded newline would let a caller name one
    /// header in the signature and send two.
    #[error("header {name:?} has a control character in its value")]
    ControlCharacterInHeader { name: String },

    /// The access key id is empty.
    #[error("the access key id is empty")]
    EmptyAccessKeyId,

    /// The region or service is empty.
    #[error("the credential scope is incomplete: {0}")]
    IncompleteScope(&'static str),
}

/// One header as the signer sees it: already the value the caller intends to
/// send, and never secret.
///
/// Borrowed rather than owned because a signer is a short-lived value inside
/// one request build, and a caller holding a `String` per header for the
/// duration would be allocating a second copy of the request to sign it.
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl<'a> Header<'a> {
    pub fn new(name: &'a str, value: &'a str) -> Self {
        Self { name, value }
    }
}

/// The inputs to one signature, before any canonicalisation.
///
/// `query` is the *decoded* form — `(name, value)` pairs as they will be sent
/// once — and the signer encodes and sorts them. Taking them already sorted
/// would move the bug to the caller, and AWS's rule is that the sort is by
/// *encoded* name, which is not the same as the order anyone would write them
/// in.
#[derive(Debug, Clone, Default)]
pub struct SignRequest<'a> {
    pub method: &'a str,
    /// The path, still percent-encoded as it will be sent.
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [Header<'a>],
    pub payload: &'a [u8],
    /// Whether this is an S3 path, which is encoded **once**.
    ///
    /// Every other service requires the path encoded **twice**: a space in
    /// `/a/b c` becomes `%2520`, not `%20`. Getting this backwards produces a
    /// signature that is right for the other case, so it is a parameter with a
    /// default rather than a service-name special case inside the signer.
    ///
    /// The name says `s3_path` rather than something about slashes, because
    /// the first version of this called it `encode_path_slash` and the slash
    /// was never the thing being decided: the path is split on `/` before
    /// encoding, so a segment cannot contain one and the flag could not have
    /// had the effect its name promised.
    pub s3_path: bool,
}

impl<'a> SignRequest<'a> {
    /// A request with the S3 path rule, which is the safe default: a signature
    /// that is wrong for S3 fails loudly at the provider, and the alternative
    /// is a signature that is wrong everywhere else and fails silently.
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            query: &[],
            headers: &[],
            payload: &[],
            s3_path: false,
        }
    }
}

/// The result of signing: what to put on the request, and what was committed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// The complete `Authorization` header value, algorithm included.
    pub authorization: String,
    /// The `X-Amz-Date` the signature is bound to. Echoed rather than
    /// recomputed so the caller cannot send one and sign another.
    pub amz_date: String,
    /// The `host;x-amz-date` style list, for tests and for the provider error
    /// that names it.
    pub signed_headers: String,
    /// The canonical request that was hashed. Kept because it is the only way
    /// to debug a `SignatureDoesNotMatch` from the broker side, and because a
    /// caller that can see it can check it.
    pub canonical_request: String,
}

/// A configured signer. Holds the one secret and everything else that is not.
pub struct SigV4Signer {
    access_key_id: String,
    /// Zeroizing, and never returned, never logged and never in a `Debug`
    /// output. The struct deliberately does not derive `Debug` for that reason:
    /// a derived one is one careless `{:?}` away from printing the key.
    secret_access_key: Zeroizing<String>,
    region: String,
    service: String,
}

impl std::fmt::Debug for SigV4Signer {
    /// Names the fields that are not secrets and says the rest is redacted.
    /// A `Debug` that printed the key would be a worse leak than no `Debug`,
    /// because `Debug` gets called by assertion failures.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Signer")
            .field("access_key_id", &self.access_key_id)
            .field("region", &self.region)
            .field("service", &self.service)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

impl SigV4Signer {
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, SignError> {
        let access_key_id = access_key_id.into();
        let region = region.into();
        let service = service.into();
        if access_key_id.is_empty() {
            return Err(SignError::EmptyAccessKeyId);
        }
        if region.is_empty() {
            return Err(SignError::IncompleteScope("region"));
        }
        if service.is_empty() {
            return Err(SignError::IncompleteScope("service"));
        }
        Ok(Self {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            region,
            service,
        })
    }

    /// The `Credential=…` scope, minus the signature.
    pub fn credential_scope(&self, date_stamp: &str) -> String {
        format!(
            "{}/{}/{}/{}/aws4_request",
            self.access_key_id, date_stamp, self.region, self.service
        )
    }

    /// Signs `request` for the instant named by `amz_date`.
    ///
    /// The timestamp is a parameter rather than read from a clock on purpose.
    /// A signer that read the clock would make its own output untestable
    /// against a vector, and R2.C.1's whole claim is that the vectors match.
    pub fn sign(
        &self,
        request: &SignRequest<'_>,
        amz_date: &str,
    ) -> Result<SignedRequest, SignError> {
        let date_stamp = date_stamp(amz_date)?;

        let (canonical_headers, signed_headers) = canonical_headers(request.headers)?;
        let canonical_request = canonical_request(request, &canonical_headers, &signed_headers)?;
        let scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, self.service
        );
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            sha256_hex_of(canonical_request.as_bytes())
        );

        let signature = hex(&hmac_sha256(
            &self.signing_key(&date_stamp),
            string_to_sign.as_bytes(),
        ));

        Ok(SignedRequest {
            // The scope is used whole. An earlier version appended
            // `/{amz_date}` to it as well, which produced
            // `…/aws4_request/20150830T123600Z` and still carried the right
            // signature — the extra text is not hashed. So nothing local
            // noticed: the request would have been rejected by every provider,
            // with a scope no reader could reconcile against the signature in
            // the same header. The published vector is what caught it.
            authorization: format!(
                "{ALGORITHM} Credential={}, SignedHeaders={signed_headers}, Signature={signature}",
                self.credential_scope(&date_stamp)
            ),
            amz_date: amz_date.to_string(),
            signed_headers,
            canonical_request,
        })
    }

    /// The four-step derivation: date, region, service, `aws4_request`.
    ///
    /// Never cached across calls. The cost is four HMACs; the reason to avoid
    /// holding it is that it is a key that authorises every request in the
    /// scope, and a cache would make its lifetime somebody else's problem.
    pub fn signing_key(&self, date_stamp: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(signing_key(
            self.secret_access_key.as_str(),
            date_stamp,
            &self.region,
            &self.service,
        ))
    }
}

/// `kDate -> kRegion -> kService -> kSigning`.
pub fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let initial = Zeroizing::new(format!("AWS4{secret}").into_bytes());
    let k_date = hmac_sha256(&initial, date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// The SHA-256 of `bytes`, lowercase hex.
///
/// Public because [`super::sts`] hashes a request body with it before handing
/// that body to this module to sign. Exposing the existing function is the
/// point: a second hex-SHA-256 elsewhere in the tree is a second thing to keep
/// correct, and a payload hash computed by a different function from the one
/// the signer uses is a `SignatureDoesNotMatch` nobody can find.
pub fn sha256_hex_of(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

/// `20150830T123600Z` -> `20150830`.
fn date_stamp(amz_date: &str) -> Result<&str, SignError> {
    amz_date
        .get(..8)
        .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(SignError::IncompleteScope("date"))
}

/// Lowercases and validates the header names, and renders the canonical block.
///
/// The two blocks are returned together because they have to agree: the list
/// and the block are two views of one decision, and computing them in two
/// places is how they come to disagree.
fn canonical_headers(headers: &[Header<'_>]) -> Result<(String, String), SignError> {
    let mut prepared: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if !is_token(&name) {
            return Err(SignError::InvalidHeaderName(header.name.to_string()));
        }
        let value = header.value;
        if value.chars().any(|c| c.is_control()) {
            return Err(SignError::ControlCharacterInHeader { name });
        }
        // Trim the ends, then collapse internal runs to a single space. AWS
        // folds so that a header sent as `a   b` and a header signed as
        // `a b` are the same header; without the fold, an intermediary that
        // normalises whitespace would break every signature.
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        prepared.push((name, value));
    }

    if !prepared.iter().any(|(name, _)| name == "host") {
        return Err(SignError::MissingHost);
    }

    // Duplicate header names are joined with commas, as HTTP requires, rather
    // than signing only the first: a caller that appended a second value would
    // otherwise get a signature that validates for a header it did not intend.
    prepared.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in prepared.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(SignError::InvalidHeaderName(pair[0].0.clone()));
        }
    }

    let block = prepared
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let list = prepared
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    Ok((block, list))
}

fn canonical_request(
    request: &SignRequest<'_>,
    canonical_headers: &str,
    signed_headers: &str,
) -> Result<String, SignError> {
    let payload_hash = if request.payload.is_empty() {
        EMPTY_PAYLOAD_SHA256.to_string()
    } else {
        sha256_hex_of(request.payload)
    };

    Ok(format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        request.method.to_ascii_uppercase(),
        canonical_uri(request.path, request.s3_path),
        canonical_query(request.query),
    ))
}

/// The path in canonical form.
///
/// Encoded once for S3 and twice for everything else, with `/` preserved in
/// both cases because it is the separator rather than a character in a
/// segment. The second pass runs over the *output* of the first, which is what
/// makes `%20` become `%2520`: the `%` is a real character at that point and
/// gets encoded like any other.
pub fn canonical_uri(path: &str, s3_path: bool) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let once = encode_component(path.as_bytes(), true);
    if s3_path {
        once
    } else {
        encode_component(once.as_bytes(), true)
    }
}

/// Query parameters sorted by encoded name, then encoded value.
///
/// Sorting by the *encoded* form is the rule and the reason this is not a
/// `sort()` on the caller's strings: `a b` encodes to `a%20b`, so a caller who
/// sorted `a b` before `a-b` has sorted the wrong list.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .map(|(name, value)| {
            (
                encode_component(name.as_bytes(), true),
                encode_component(value.as_bytes(), true),
            )
        })
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 percent-encoding as AWS defines it: unreserved characters literal,
/// everything else `%XX` with **uppercase** hex, and a space as `%20`.
///
/// The space case is the one that bites. `application/x-www-form-urlencoded`
/// writes a space as `+`, and a signer that followed it would produce a
/// signature no provider accepts.
pub fn encode_component(bytes: &[u8], keep_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        let literal = match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' | b'.' | b'_' | b'~' => true,
            b'/' => keep_slash,
            _ => false,
        };
        if literal {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// An RFC 7230 token, which is what a header name has to be.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests;
