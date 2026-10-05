//! `sts:AssumeRole` — the request ASV makes so an agent never holds an AWS
//! long-lived key.
//!
//! # Why this file exists before anything talks to AWS
//!
//! The whole point of R2.C is that the agent names an operation and the broker
//! holds the secret. So there has to be a place where a long-lived key becomes
//! a short-lived session, and that place is here. It is also the only place
//! where an XML document from a third party gets read, which is why the
//! reader below is written the way it is.
//!
//! # The XML, and why there is no parser
//!
//! `Cargo.lock` has no XML parser in it, and none is being added.
//!
//! `AssumeRoleResult` is a fixed schema with four values that matter. A general
//! parser brings a DTD, and a DTD is an XXE surface: a response that names an
//! external entity can make the reader open a file or a socket, and the
//! document that arrives is not the one that was signed. The mandate names this
//! for Maven's `settings.xml` — DTD off, entities off, network resolution off,
//! size and depth limits — and a general parser can only be made to *comply*
//! with that by configuration. This reader cannot violate it, because it
//! implements no entity mechanism at all:
//!
//! - `&amp;` `&lt;` `&gt;` `&quot;` `&apos;` and numeric character references
//!   are decoded, because AWS itself emits them and a session token can
//!   contain `+` and `/` and `=`;
//! - there is no depth, no DTD handling and no external reference of any kind;
//! - the whole response is bounded before a byte of it is looked at.
//!
//! - the five predefined entities and numeric character references are decoded,
//!   because AWS itself emits them and a session token contains `+`, `/` and
//!   `=` that have to survive a round trip;
//! - **every other entity is a refusal**, as is a bare `&` and as is a document
//!   declaring a DTD. Nothing is ever resolved, so `&xxe;` and
//!   `<!ENTITY xxe SYSTEM "file:///etc/passwd">` have nothing to attack: no code
//!   path in this file turns a name into a fetch;
//! - there is no depth, no DTD handling and no external reference of any kind;
//! - the whole response is bounded before a byte of it is looked at.
//!
//! A narrow reader for a narrow schema is not the version of this that is
//! usually written down; it is the version that is smaller.
//!
//! # One rule, applied everywhere
//!
//! **A document this reader does not understand is refused, not guessed at.**
//! Two `AccessKeyId` elements, an unclosed tag, a body that is not UTF-8, an
//! instant that is not the documented shape, an entity that is not defined, a
//! credential field carrying whitespace — all of them leave through the same
//! door, and none is repaired on the way. The lenient alternative at each one is
//! a reader willing to mint a session out of a document nobody should have been
//! able to send, which is the failure this file exists to make impossible.
//!
//! **What is deliberately absent, and is R2.C.2.b.** No HTTP client here, no
//! `SecretPort`, and no socket. This is the encoding in both directions, and it
//! is where the bugs live.

use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

/// The service name SigV4 uses for STS. Not configurable: a signer that let
/// the caller name the service would sign for a different service than the one
/// being addressed.
pub const STS_SERVICE: &str = "sts";

/// The `Version` every STS request carries. Pinned, like the service name.
pub const API_VERSION: &str = "2011-06-15";

/// The largest response this reader will look at.
///
/// AWS's `AssumeRole` response is well under a kilobyte. The bound is not about
/// AWS: it is about the reader being handed something it did not expect, and a
/// reader that allocates in proportion to its input before it has decided
/// whether the input is one of the two documents it knows is not a reader that
/// can be pointed at untrusted input.
///
/// Set below the point where a legitimate response would be refused, and above
/// the point where a hostile one becomes cheap to send.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// What STS refused, named rather than flattened.
///
/// Each arm sends an operator to a different place: a wrong role ARN is a
/// configuration fix, a denied call is an IAM decision, and a throttle is a
/// retry. Collapsing them into "the provider said no" is how a misconfigured
/// role gets reported as an outage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StsError {
    /// The response was larger than [`MAX_RESPONSE_BYTES`], and was not parsed.
    #[error("the STS response is larger than {MAX_RESPONSE_BYTES} bytes and was refused unread")]
    ResponseTooLarge,

    /// The document was neither an `AssumeRoleResponse` nor an `ErrorResponse`.
    #[error("the STS response is not a document this reader knows: {0}")]
    UnrecognisedDocument(String),

    /// An `ErrorResponse` whose code this code does not name.
    #[error("STS refused with {code}: {message}")]
    Provider { code: String, message: String },

    /// A credential field was absent or empty.
    #[error("the STS response is missing {0}")]
    Missing(&'static str),

    /// The `Expiration` was not the timestamp shape AWS documents.
    #[error("the Expiration {0:?} is not an RFC 3339 instant")]
    MalformedExpiration(String),

    /// The session expired before it could be used.
    ///
    /// Separate from `Missing` because it is a *clock* answer and not a
    /// document answer: the document was complete and the credential is gone.
    /// Serving it anyway would be the worst outcome available, since a caller
    /// would get a confident answer that fails at the provider.
    #[error("the STS session expired at {0:?}, before it was used")]
    AlreadyExpired(String),

    /// The request cannot be built at all.
    #[error("the AssumeRole request is incomplete: {0}")]
    IncompleteRequest(&'static str),
}

/// A temporary credential: what STS hands back and what ASV lends per request.
///
/// The two secret fields are `Zeroizing` and have no public accessor. The
/// non-secret ones are public because an operator reading a receipt needs them
/// and a receipt with none of them is a receipt nobody can act on.
pub struct AwsSession {
    /// Which key this is. Not a secret, and the thing a receipt names.
    pub access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
    /// When the provider says this stops working. A timestamp rather than a
    /// duration, because the value is compared against a clock at two different
    /// moments and a duration would have to be re-based at each one.
    pub expires_at: SystemTime,
    /// The role this session is for. Named so a receipt can say what authority
    /// was exercised, which is the whole audit story for a role assumption.
    pub role_arn: String,
    /// The session name AWS shows in CloudTrail, so an operator reading the
    /// provider's own log can correlate it with the broker's.
    pub role_session_name: String,
}

impl std::fmt::Debug for AwsSession {
    /// Prints what an operator needs and redacts what they must never see.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSession")
            .field("access_key_id", &self.access_key_id)
            .field("role_arn", &self.role_arn)
            .field("role_session_name", &self.role_session_name)
            .field("expires_at", &self.expires_at)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .finish()
    }
}

impl AwsSession {
    /// Hands the three signing values to a sink, and takes them back.
    ///
    /// A `&dyn SecretSink` rather than three getters, for the same reason
    /// `SecretPort::lend` does it: the point of the type is that there is no
    /// method which returns a copy, so a caller cannot hold one by accident.
    pub fn with_signing_values(&self, sink: &mut dyn AwsSecretSink) -> Result<(), StsError> {
        sink.accept(
            self.access_key_id.as_bytes(),
            self.secret_access_key.as_bytes(),
            self.session_token.as_bytes(),
        )
    }

    /// Whether the session is still usable at `now`.
    ///
    /// `skew` is the margin a caller wants: a credential that expires in a
    /// second is not usable, and a caller that has to remember to subtract a
    /// margin will forget on the operation that does not look urgent.
    pub fn usable_at(&self, now: SystemTime, skew: Duration) -> bool {
        self.expires_at
            .duration_since(now)
            .map(|left| left > skew)
            .unwrap_or(false)
    }
}

/// One use of a temporary credential's three values.
pub trait AwsSecretSink {
    fn accept(
        &mut self,
        access_key_id: &[u8],
        secret_access_key: &[u8],
        session_token: &[u8],
    ) -> Result<(), StsError>;
}

/// What ASV asks STS for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssumeRole {
    /// The role to assume. Named by the operator, never by the agent's
    /// request body.
    pub role_arn: String,
    /// The name AWS records for this session.
    ///
    /// Operator-supplied and **not** derived from anything secret, because it
    /// lands in the provider's own audit log. A session name built from a
    /// request id is fine; one built from a token is a leak with a log format.
    pub role_session_name: String,
    /// How long AWS should keep the session, bounded below and above by the
    /// provider rather than by the caller — see [`AssumeRole::new`].
    pub duration_seconds: u32,
    /// The external id, when the role's trust policy demands one.
    ///
    /// **Often a shared secret, and the doc is explicit about it**: AWS suggests
    /// "a passphrase or account number", and the whole point of the parameter is
    /// that only someone holding it may assume the role. So in the strong posture
    /// this comes out of the vault like the long-lived key does, and it is never
    /// part of an agent's request. Enumerating it from a tool call would be the
    /// same mistake as exporting the key it protects.
    pub external_id: Option<String>,
}

impl AssumeRole {
    /// The shortest and longest sessions AWS's default role chain allows.
    pub const MIN_DURATION_SECONDS: u32 = 900;
    pub const MAX_DURATION_SECONDS: u32 = 43_200;

    /// The documented length bounds, in characters.
    ///
    /// Named rather than inlined at the check because a bound that appears in
    /// two places is a bound that will be updated in one of them, and the copy
    /// that drifts is the one nobody reads.
    pub const ROLE_ARN_LEN: std::ops::RangeInclusive<usize> = 20..=2048;
    pub const SESSION_NAME_LEN: std::ops::RangeInclusive<usize> = 2..=64;
    pub const EXTERNAL_ID_LEN: std::ops::RangeInclusive<usize> = 2..=1224;

    /// Builds a request, refusing what AWS would refuse anyway.
    ///
    /// A caller asking for a year is refused here rather than being sent to AWS
    /// and coming back with an error. The reason is the mandate's own: the
    /// strong posture is a short-lived credential, and a signer that will mint
    /// whatever it is asked for is not offering one.
    ///
    /// **Lengths are enforced, character classes are not.** The documented
    /// bounds — `RoleArn` 20..=2048, `RoleSessionName` 2..=64, `ExternalId`
    /// 2..=1224 — are stable and an operator gets them wrong, so they are
    /// checked here. The patterns (`[\w+=,.@-]*` and friends) are versioned
    /// AWS detail, and a local copy of one goes stale silently: it would start
    /// refusing something the provider accepts. What *is* enforced from the
    /// pattern is the absence of whitespace in the two fields whose documented
    /// pattern has none, because "asv session" is the most likely typo there is
    /// and it costs a round trip and an `AccessDenied` that reads like an IAM
    /// problem.
    pub fn new(
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        duration_seconds: u32,
        external_id: Option<String>,
    ) -> Result<Self, StsError> {
        let role_arn = role_arn.into();
        let role_session_name = role_session_name.into();
        if !Self::ROLE_ARN_LEN.contains(&role_arn.chars().count()) {
            return Err(StsError::IncompleteRequest("role ARN"));
        }
        let session_len = role_session_name.chars().count();
        if !Self::SESSION_NAME_LEN.contains(&session_len) {
            return Err(StsError::IncompleteRequest("role session name"));
        }
        if role_session_name.chars().any(char::is_whitespace) {
            return Err(StsError::IncompleteRequest("role session name"));
        }
        if !(Self::MIN_DURATION_SECONDS..=Self::MAX_DURATION_SECONDS).contains(&duration_seconds) {
            return Err(StsError::IncompleteRequest("duration"));
        }
        if let Some(external_id) = &external_id {
            if !Self::EXTERNAL_ID_LEN.contains(&external_id.chars().count())
                || external_id.chars().any(char::is_whitespace)
            {
                return Err(StsError::IncompleteRequest("external id"));
            }
        }
        Ok(Self {
            role_arn,
            role_session_name,
            duration_seconds,
            external_id,
        })
    }

    /// The form body STS expects, as a byte string.
    ///
    /// Percent-encoded, with `+` for a space — which is what
    /// `application/x-www-form-urlencoded` means and is the *opposite* of the
    /// SigV4 path rule. The two coexisting in one file is the reason the
    /// encoder here is its own function rather than a reuse of
    /// `sigv4::encode_component`: a shared one would be a shared bug.
    pub fn form_body(&self) -> String {
        let mut params: Vec<(&str, String)> = vec![
            ("Action", "AssumeRole".to_string()),
            ("Version", API_VERSION.to_string()),
            ("RoleArn", self.role_arn.clone()),
            ("RoleSessionName", self.role_session_name.clone()),
            ("DurationSeconds", self.duration_seconds.to_string()),
        ];
        if let Some(external_id) = &self.external_id {
            params.push(("ExternalId", external_id.clone()));
        }
        // Sorted, because a canonical body is what gets hashed, and a body that
        // hashed differently depending on the order the caller happened to
        // build it in is a signer that cannot be debugged.
        params.sort_by(|a, b| a.0.cmp(b.0));
        params
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    form_encode(name.as_bytes()),
                    form_encode(value.as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The SHA-256 of the body, which SigV4 signs as the payload hash.
    pub fn payload_hash(&self) -> String {
        crate::aws::sigv4::sha256_hex_of(self.form_body().as_bytes())
    }
}

/// `application/x-www-form-urlencoded`: a space is `+`, `+` is `%2B`.
fn form_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Reads an `AssumeRoleResponse` into a session.
///
/// `now` is a parameter for the same reason `SigV4Signer::sign` takes the
/// timestamp: a reader that read the clock would be untestable against a
/// fixture, and the expiry check is the part most worth testing.
pub fn parse_assume_role(
    body: &[u8],
    request: &AssumeRole,
    now: SystemTime,
) -> Result<AwsSession, StsError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(StsError::ResponseTooLarge);
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| StsError::UnrecognisedDocument("the body is not UTF-8".into()))?;

    // Before anything is looked for. The Query API emits no DTD, so a document
    // carrying one has been shaped by something, and a reader that ignored the
    // declaration would be one step from honouring it.
    if text.contains("<!DOCTYPE") {
        return Err(StsError::UnrecognisedDocument(
            "the document declares a DTD, which an STS response does not".into(),
        ));
    }

    if let Some((code, message)) = read_error_response(text)? {
        return Err(StsError::Provider { code, message });
    }
    if !text.contains("<AssumeRoleResult") {
        return Err(StsError::UnrecognisedDocument(
            "no AssumeRoleResult and no Error".into(),
        ));
    }

    let access_key_id = credential(text, "AccessKeyId")?;
    let secret_access_key = credential(text, "SecretAccessKey")?;
    let session_token = credential(text, "SessionToken")?;
    let expiration = decode_predefined(element(text, "Expiration")?, "Expiration")?;
    let expires_at = parse_rfc3339(&expiration)?;

    let session = AwsSession {
        access_key_id,
        secret_access_key: Zeroizing::new(secret_access_key),
        session_token: Zeroizing::new(session_token),
        expires_at,
        role_arn: request.role_arn.clone(),
        role_session_name: request.role_session_name.clone(),
    };
    if !session.usable_at(now, Duration::ZERO) {
        return Err(StsError::AlreadyExpired(expiration));
    }
    Ok(session)
}

/// A credential field: read, decoded, and checked to be something a credential
/// can be.
///
/// The whitespace check is the one worth explaining, because it looks pedantic
/// and is not. All three values are base64 or a base64 alphabet, so a credential
/// never contains a space, a tab or a newline. The one place that rule earns its
/// keep is the AWS documentation itself, which prints the sample `SessionToken`
/// across five indented lines. That folding cannot arrive on a socket — the
/// token becomes an HTTP header value, and a header value cannot contain a
/// newline — but a reader that trimmed or un-folded quietly would mint a session
/// whose token is wrong by exactly the whitespace it decided to remove, and
/// would report success while doing it. Refusing says *this document is not a
/// credential* instead.
fn credential(text: &str, name: &'static str) -> Result<String, StsError> {
    let raw = decode_predefined(element(text, name)?, name)?;
    if raw.is_empty() {
        return Err(StsError::Missing(name));
    }
    if let Some(found) = raw.chars().find(|c| c.is_whitespace()) {
        return Err(StsError::UnrecognisedDocument(format!(
            "<{name}> contains {found:?}, which a credential never does"
        )));
    }
    Ok(raw)
}

/// Reads `<Error><Code>` and `<Error><Message>`, if this is an error document.
///
/// The errors propagate rather than being flattened into a default, because an
/// error document this reader cannot read properly is a document it should not be
/// quoting a code from: `AccessDenied` and "Unknown" send an operator to
/// different places in the same morning.
fn read_error_response(text: &str) -> Result<Option<(String, String)>, StsError> {
    if !text.contains("<Error") {
        return Ok(None);
    }
    let code = match element(text, "Code") {
        Ok(raw) => decode_predefined(raw, "Code")?,
        Err(StsError::Missing(_)) => "Unknown".to_string(),
        Err(other) => return Err(other),
    };
    let message = match element(text, "Message") {
        Ok(raw) => decode_predefined(raw, "Message")?,
        Err(StsError::Missing(_)) => String::new(),
        Err(other) => return Err(other),
    };
    Ok(Some((code, message)))
}

/// The raw text between the first `<name>…</name>` in `text`.
///
/// The narrowest reader that can do the job, and the ways it could be wrong are
/// refused rather than hoped for:
///
/// - **A duplicated element is a refusal, not a first-wins.** A document that
///   says `AccessKeyId` twice has been shaped by something, and guessing which
///   one is intended is how a signature gets committed to the wrong value. The
///   count is over the whole document, so a tag inside a comment counts too:
///   this reader is comment-unaware, and it fails in the safe direction.
/// - **There is no separate nesting rule**, because a nested element is a second
///   occurrence and the rule above already refuses it. A second rule that can
///   never fire is a rule nobody can trust.
/// - **Nothing is decoded here.** The closing tag is found in the raw text and
///   the content is decoded afterwards, so an entity that looks like a tag
///   cannot become one. Decoding first would let a document move its own
///   boundaries.
///
/// The search is `match_indices` rather than `find` followed by a second `find`,
/// so every index this function slices at is one the string library already
/// proved to be a character boundary. The version this replaced indexed one byte
/// past the opening tag, which lands inside a two-byte character — how a reader
/// pointed at a socket panics on something a socket can perfectly well send.
fn element<'a>(text: &'a str, name: &'a str) -> Result<&'a str, StsError> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut occurrences = text.match_indices(&open);
    let Some((first, _)) = occurrences.next() else {
        return Err(StsError::Missing(field_name(name)));
    };
    if occurrences.next().is_some() {
        return Err(StsError::UnrecognisedDocument(format!(
            "<{name}> appears more than once"
        )));
    }
    let after_open = first + open.len();
    let Some(offset) = text[after_open..].find(&close) else {
        return Err(StsError::UnrecognisedDocument(format!(
            "<{name}> is never closed"
        )));
    };
    Ok(&text[after_open..after_open + offset])
}

/// The five predefined entities and numeric character references, and nothing
/// else. Anything else is a refusal.
///
/// **Not** preserving an unrecognised entity as text, which is the lenient
/// choice and is what this did first. The reasoning that changed it is the same
/// one that governs the duplicate-element rule: everywhere else, a document this
/// reader does not understand is refused rather than guessed at, and guessing
/// that `&xxe;` means the five characters `&xxe;` would have been the one place
/// it guessed. It costs nothing real. A credential cannot contain `&name;` in
/// the first place, so its presence is evidence the document is not what it
/// claims — and a probe that gets a hard refusal learns more about this reader
/// than a 200 carrying a mangled token ever would.
fn decode_predefined(raw: &str, name: &'static str) -> Result<String, StsError> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(semi) = tail.find(';') else {
            return Err(StsError::UnrecognisedDocument(format!(
                "<{name}> contains a bare `&`, which XML does not allow unescaped"
            )));
        };
        let entity = &tail[1..semi];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => match numeric_reference(entity) {
                Some(c) => out.push(c),
                None => {
                    return Err(StsError::UnrecognisedDocument(format!(
                        "<{name}> contains &{entity};, which is not a defined entity"
                    )))
                }
            },
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `&#65;` and `&#x41;`, and nothing else.
fn numeric_reference(entity: &str) -> Option<char> {
    let digits = entity.strip_prefix('#')?;
    let value = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(value)
}

/// The field name a `Missing` error should carry, for the four the reader
/// cares about and a stand-in for anything else.
fn field_name(name: &str) -> &'static str {
    match name {
        "AccessKeyId" => "AccessKeyId",
        "SecretAccessKey" => "SecretAccessKey",
        "SessionToken" => "SessionToken",
        "Expiration" => "Expiration",
        "Code" => "an error Code",
        "Message" => "an error Message",
        _ => "a credential field",
    }
}

/// RFC 3339, to the second, as AWS writes it: `2015-08-04T06:51:37Z`.
///
/// Hand-parsed rather than pulled from a date library, and the reason is the
/// same as the XML: the format here is one shape with one timezone, and a
/// general parser is a general attack surface for a fixed job. Everything the
/// format allows that this does not — offsets other than `Z`, fractional
/// seconds, a leap second — is refused rather than approximated, because a
/// timestamp read wrongly is a credential believed valid after it is not.
fn parse_rfc3339(raw: &str) -> Result<SystemTime, StsError> {
    let malformed = || StsError::MalformedExpiration(raw.to_string());
    let bytes = raw.as_bytes();
    if bytes.len() != 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return Err(malformed());
    }
    if bytes[13] != b':' || bytes[16] != b':' || !raw.ends_with('Z') {
        return Err(malformed());
    }
    let number = |from: usize, to: usize| -> Result<u32, StsError> {
        raw[from..to].parse::<u32>().map_err(|_| malformed())
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(malformed());
    }
    // Days since the epoch, by the civil-from-days inverse, so no date library
    // and no 32-bit-second overflow on a date after 2038.
    let days = days_from_civil(year, month, day);
    let seconds = days as i64 * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    if seconds < 0 {
        return Err(malformed());
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

/// Days since 1970-01-01. Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests;
