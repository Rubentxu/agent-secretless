//! Docker Registry v2 authentication, up to the instant a credential would
//! exist (R2.F).
//!
//! Read this file with one question in mind: *who chose each value?* The
//! registry chose the `realm` and the `scope` in its `401`. The broker chose
//! the scope it will actually ask for, because the one in the challenge is a
//! request rather than a decision, and a request from the party being
//! authenticated is not something to obey. Everything below exists to make
//! that distinction impossible to lose.
//!
//! # What is here, and what is deliberately not
//!
//! Three things: reading a `WWW-Authenticate` challenge, vetting the `realm` it
//! names, and narrowing a token scope to one operation. There is no HTTP
//! client here, no `Authorization` header, and no token held in a field. The
//! broker's [`crate::github::SecretPort`] is where a credential will be lent to
//! a closure and taken back; this module is the policy that decides *which*
//! credential, and it deliberately cannot be handed one.
//!
//! # The three properties
//!
//! 1. **A challenge is data, not an instruction.** The `scope` in a `401` is
//!    what the registry says it would like, usually a superset covering every
//!    action a client might want. [`crate::registry::scope_to_request`] builds the scope from
//!    the operation instead, so a registry that answers `pull,push` to a pull
//!    gets asked for `pull`. Following the challenge verbatim would hand the
//!    broker a push-capable token for a read.
//! 2. **A granted scope is a ceiling, not a grant to use.** A token endpoint
//!    may return a `scope` wider than the one requested.
//!    [`crate::registry::narrow`] intersects the two and refuses when the grant does not cover
//!    the operation, so the effective scope is the narrower of the two
//!    statements and never the wider.
//! 3. **The `realm` is attacker-shaped.** Whoever answers the `401` picks the
//!    host the broker will then send a request to. [`crate::registry::Realm::vet`] takes that
//!    URL apart before any byte is sent: it has to be `https`, carry no
//!    credentials, no query and no fragment, name a host rather than an
//!    address, use the HTTPS port, and resolve only to addresses the
//!    [`AddressPolicy`] permits. A relay that answers `realm="http://169.254.169.254/"`
//!    buys nothing, because the address policy is the same one the rest of the
//!    transport uses and it was not written for this module.

use std::collections::BTreeSet;
use std::fmt;

use asv_domain::{Authority, AuthorityError};
use serde_json::Value;
use url::Url;

use crate::transport::{resolve_and_pin, AddressPolicy, ResolvedAudience, TransportError};

/// The port a token endpoint is reached on. Not a default worth having: a
/// `realm` on any other port is not the endpoint the registry described, and
/// allowing it would turn "send the token request to the host the registry
/// named" into "send it to a port the registry chose".
const TOKEN_PORT: u16 = 443;

/// How a `401` was refused before it became an instruction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    #[error("the challenge offers {found:?}, and only Bearer is negotiated here")]
    NotBearer { found: String },

    #[error("the Bearer challenge names no realm")]
    MissingRealm,

    #[error("the Bearer challenge says {parameter} twice; a reader that picks one of them picks for the sender")]
    RepeatedParameter { parameter: &'static str },

    #[error("the Bearer challenge is not readable: {0}")]
    Malformed(String),
}

/// A `401` asking for a bearer token.
///
/// The `scope` this carries is kept, and it is kept *unused*: nothing in this
/// module reads it to decide anything, because it is the sender's request
/// rather than this side's requirement. [`crate::registry::scope_to_request`] is the function
/// that decides what to ask for, and it takes an [`RegistryOperation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    realm: String,
    service: Option<String>,
    requested_scope: Option<String>,
}

impl BearerChallenge {
    /// Reads a `WWW-Authenticate` header value.
    ///
    /// The parser is written out rather than pulled in because the refusals
    /// *are* the property: a repeated parameter, an unclosed quote, or a
    /// control character each have to stop the header, and a permissive
    /// library would turn any of them into "last one wins" or "strip the
    /// whitespace". Both are decisions the sender chose.
    ///
    /// A header that names several challenges (`Bearer ..., Basic ...`) is
    /// refused rather than half-read. The registry being talked to is the one
    /// that got a `401` from us, so a list is a sender choosing which of its
    /// options this side obeys, and obeying the first is the same as obeying
    /// the sender.
    pub fn parse(header: &str) -> Result<Self, ChallengeError> {
        if header.chars().any(|c| c.is_control()) {
            return Err(ChallengeError::Malformed(
                "a control character cannot be in a header this side reads".to_string(),
            ));
        }

        let (scheme, parameters) = header.split_once(char::is_whitespace).ok_or_else(|| {
            ChallengeError::Malformed("no challenge parameters follow the scheme".into())
        })?;

        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(ChallengeError::NotBearer {
                found: scheme.to_string(),
            });
        }
        if parameters.trim().is_empty() {
            return Err(ChallengeError::Malformed(
                "a Bearer challenge with no parameters asks for nothing".to_string(),
            ));
        }

        let mut realm = None;
        let mut service = None;
        let mut scope = None;
        for (key, value) in parse_parameters(parameters)? {
            let slot = match key.to_ascii_lowercase().as_str() {
                "realm" => &mut realm,
                "service" => &mut service,
                "scope" => &mut scope,
                // An unknown parameter is not an error: RFC 7235 says a
                // recipient ignores what it does not recognise, and refusing
                // would break against a registry that adds one.
                _ => continue,
            };
            if slot.is_some() {
                return Err(ChallengeError::RepeatedParameter {
                    parameter: match key.to_ascii_lowercase().as_str() {
                        "realm" => "realm",
                        "service" => "service",
                        _ => "scope",
                    },
                });
            }
            *slot = Some(value.to_string());
        }

        Ok(Self {
            realm: realm.ok_or(ChallengeError::MissingRealm)?,
            service,
            requested_scope: scope,
        })
    }

    /// The token endpoint, exactly as the registry spelled it. Not vetted:
    /// run it through [`crate::registry::Realm::vet`] before it becomes a destination.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The registry's own name for itself.
    ///
    /// Kept because Docker Hub spells it `registry.docker.io` while serving
    /// from `registry-1.docker.io`, which is the whole reason a
    /// `service == host` assumption is not safe to make here.
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    /// The scope the registry asked for, which this module does not obey.
    pub fn requested_scope(&self) -> Option<&str> {
        self.requested_scope.as_deref()
    }
}

/// Splits `key=value` pairs, honouring RFC 7230 quoted strings.
///
/// Returns slices of `input`, so nothing is copied and nothing is unescaped:
/// a backslash escape inside a quoted string is left in place, because a token
/// endpoint that sent one sent it on purpose and this side has no use for
/// decoding it.
fn parse_parameters(input: &str) -> Result<Vec<(&str, &str)>, ChallengeError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        if i == key_start {
            return Err(ChallengeError::Malformed(format!(
                "expected a parameter name at byte {key_start}"
            )));
        }
        let key = &input[key_start..i];

        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return Err(ChallengeError::Malformed(format!(
                "parameter {key:?} has no value"
            )));
        }
        i += 1;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }

        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err(ChallengeError::Malformed(format!(
                    "the value of {key:?} is never closed"
                )));
            }
            let value = &input[start..i];
            i += 1;
            value
        } else {
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            if i == start {
                return Err(ChallengeError::Malformed(format!(
                    "the value of {key:?} is empty"
                )));
            }
            &input[start..i]
        };

        out.push((key, value));
    }

    Ok(out)
}

/// RFC 7230 `tchar`.
fn is_token_byte(b: u8) -> bool {
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
}

/// Why a `realm` was refused as a destination.
#[derive(Debug, thiserror::Error)]
pub enum RealmError {
    #[error("the realm is not a URL: {0}")]
    Unreadable(String),

    #[error("the realm is {scheme:?}, where a bearer token would travel in the clear")]
    NotHttps { scheme: String },

    #[error("the realm carries {what}, which a token endpoint has no use for")]
    Refused { what: &'static str },

    #[error("the realm names no host")]
    NoHost,

    #[error("the realm asks for port {port}, and only {expected} is a token endpoint")]
    UnexpectedPort { port: u16, expected: u16 },

    /// The host did not survive the codebase's own rules for "the same host",
    /// reported rather than summarised: a literal address, a percent escape
    /// and a bare `localhost` are three different problems, and a caller
    /// debugging a relay needs to know which one it was.
    #[error(transparent)]
    UnusableHost(#[from] AuthorityError),

    #[error(transparent)]
    Unreachable(#[from] TransportError),
}

/// A `realm` that has been taken apart and found to point somewhere this
/// transport is willing to go.
///
/// Constructing one is the only way to get one, and the only constructor is
/// [`crate::registry::Realm::vet`]. A `Realm` is therefore not "a realm" but "a realm that
/// survived", which is the distinction a caller needs and the one a plain
/// `Url` would throw away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    authority: Authority,
    path: String,
    resolved: ResolvedAudience,
}

impl Realm {
    /// Takes a `realm` apart and vets it, resolving and pinning its host.
    ///
    /// The order is the cheapest-and-most-certain first: syntax, then scheme,
    /// then the parts of the URL nobody needs, then the address, and only then
    /// a DNS lookup. A `realm` that is going to be refused should cost as
    /// little as possible, because a relay can send as many as it likes.
    pub fn vet(raw: &str, policy: AddressPolicy) -> Result<Self, RealmError> {
        let url = Url::parse(raw).map_err(|e| RealmError::Unreadable(e.to_string()))?;

        if url.scheme() != "https" {
            return Err(RealmError::NotHttps {
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RealmError::Refused {
                what: "a username or password",
            });
        }
        if url.query().is_some() {
            return Err(RealmError::Refused { what: "a query" });
        }
        if url.fragment().is_some() {
            return Err(RealmError::Refused { what: "a fragment" });
        }
        if let Some(port) = url.port() {
            if port != TOKEN_PORT {
                return Err(RealmError::UnexpectedPort {
                    port,
                    expected: TOKEN_PORT,
                });
            }
        }

        let host = url.host_str().ok_or(RealmError::NoHost)?;
        // `canonicalize` is the same routine the Cedar allowlist and the
        // pinned client use to decide what "the same host" means, so the realm
        // cannot get a spelling past that one cares about. It also refuses an
        // address literal, which is the cheap way to refuse 127.0.0.1 and
        // 169.254.169.254 without a lookup.
        let authority = Authority::canonicalize(host)?;

        let resolved = resolve_and_pin(&authority, TOKEN_PORT, policy)?;

        Ok(Self {
            authority,
            path: url.path().to_string(),
            resolved,
        })
    }

    /// The vetted host.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The token endpoint's path, e.g. `/token`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The addresses the host resolved to, already checked against the policy.
    pub fn resolved(&self) -> &ResolvedAudience {
        &self.resolved
    }
}

/// What the broker is about to do to a repository.
///
/// This is the whole of what a scope may be derived from. It is an enum
/// because the set of things worth granting a token for is short and known,
/// and a string passed in from a caller would let "the operation" become
/// whatever the caller typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryOperation {
    /// Read an image.
    Pull,
    /// Write an image.
    Push,
}

impl RegistryOperation {
    /// The action keyword that names this operation in a scope.
    pub fn action(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
        }
    }
}

/// Why a repository name or a scope was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    #[error("the repository name is empty")]
    EmptyName,

    #[error("the repository name is {len} bytes, over the {max} a repository name may be")]
    NameTooLong { len: usize, max: usize },

    #[error("the repository name is not ASCII")]
    NameNotAscii,

    #[error("the repository name has an empty component")]
    EmptyComponent,

    #[error("the repository name component {component:?} ends in a separator")]
    TrailingSeparator { component: String },

    #[error("the repository name component {component:?} carries {byte:#04x}, which the distribution spec does not allow")]
    NameCharacter { component: String, byte: u8 },

    #[error("the scope is {found:?}, and this is not a `repository:` scope")]
    NotARepositoryScope { found: String },

    #[error("the scope is not readable: {0}")]
    MalformedScope(String),

    #[error("the scope is for a {kind}, and a {other} grant does not cover a {kind}")]
    WrongKind { kind: String, other: String },

    #[error("the grant is for {granted:?}, and it does not cover {required:?}")]
    WrongRepository { required: String, granted: String },

    #[error("the grant is missing {missing:?}, which the operation needs")]
    InsufficientGrant { missing: String },

    #[error("the token response has no readable scope: {0}")]
    NoScopeInTokenResponse(String),
}

/// The longest a repository name may be, per the distribution specification.
const MAX_REPOSITORY_NAME: usize = 255;

/// A repository name that cannot carry anything inside a scope.
///
/// The distribution spec's grammar is not decoration here. A scope reads
/// `repository:<name>:<actions>`, so a name containing `:` would close the
/// name early and everything after it would be read as actions — a repository
/// named `img:pull,repository:admin/secret:pull` would ask for two scopes, the
/// second of which belongs to somebody else. The grammar is what makes the
/// separator mean only one thing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryName(String);

impl RepositoryName {
    /// Checks a name against the distribution specification's grammar.
    pub fn parse(raw: &str) -> Result<Self, ScopeError> {
        if raw.is_empty() {
            return Err(ScopeError::EmptyName);
        }
        if raw.len() > MAX_REPOSITORY_NAME {
            return Err(ScopeError::NameTooLong {
                len: raw.len(),
                max: MAX_REPOSITORY_NAME,
            });
        }
        if !raw.is_ascii() {
            return Err(ScopeError::NameNotAscii);
        }

        for component in raw.split('/') {
            check_component(component)?;
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepositoryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`, one path component of a repository name.
fn check_component(component: &str) -> Result<(), ScopeError> {
    if component.is_empty() {
        return Err(ScopeError::EmptyComponent);
    }
    let bytes = component.as_bytes();
    let mut i = 0usize;
    loop {
        // An alphanumeric run, one or more. The parentheses are load-bearing:
        // `&&` binds tighter than `||`, so without them the digit test would
        // index past the end of the component.
        let run = i;
        while i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i].is_ascii_digit()) {
            i += 1;
        }
        if i == run {
            let byte = bytes.get(i).copied().unwrap_or(b'\0');
            return Err(ScopeError::NameCharacter {
                component: component.to_string(),
                byte,
            });
        }
        if i == bytes.len() {
            return Ok(());
        }
        // A separator run: `.`, `_`, `__`, or one or more `-`.
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < bytes.len() && bytes[i] == b'-' {
                    i += 1;
                }
            }
            other => {
                return Err(ScopeError::NameCharacter {
                    component: component.to_string(),
                    byte: other,
                })
            }
        }
        if i == bytes.len() {
            // A trailing separator is `img-`, which the grammar does not allow.
            return Err(ScopeError::TrailingSeparator {
                component: component.to_string(),
            });
        }
    }
}

/// A `repository:<name>:<actions>` scope.
///
/// The fields are private and there is no constructor that takes a string, so
/// the only way to hold one is to have built it from a checked
/// [`RepositoryName`] or parsed it through [`RegistryScope::parse`], which
/// applies the same grammar. A scope assembled by concatenation is the shape
/// this type exists to make unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryScope {
    repository: RepositoryName,
    actions: BTreeSet<String>,
}

impl RegistryScope {
    /// Builds the scope for one operation on one repository.
    pub fn for_operation(operation: RegistryOperation, repository: RepositoryName) -> Self {
        let mut actions = BTreeSet::new();
        actions.insert(operation.action().to_string());
        Self {
            repository,
            actions,
        }
    }

    /// Reads a scope string, applying the repository grammar to the name in it.
    ///
    /// Used for the `scope` a token endpoint reports having granted: that
    /// string arrives from the same party as the token, so it gets the same
    /// scrutiny as a challenge, and a name in it that cannot be checked is a
    /// name that is refused.
    pub fn parse(raw: &str) -> Result<Self, ScopeError> {
        let malformed = |why: &str| ScopeError::MalformedScope(why.to_string());

        let rest = raw.strip_prefix("repository:").ok_or_else(|| {
            if raw.contains(':') && !raw.starts_with("repository:") {
                ScopeError::NotARepositoryScope {
                    found: raw.split(':').next().unwrap_or(raw).to_string(),
                }
            } else {
                malformed("a scope reads `repository:<name>:<actions>`")
            }
        })?;

        // The name is everything up to the *last* colon, so a name that
        // survived the grammar cannot contain one and there is exactly one
        // separator left to split on. Splitting on the last colon rather than
        // the first is what makes that argument hold; the grammar is the
        // reason it holds.
        let (name, actions) = rest
            .rsplit_once(':')
            .ok_or_else(|| malformed("a scope names no actions"))?;
        let repository = RepositoryName::parse(name)?;

        let mut set = BTreeSet::new();
        for action in actions.split(',') {
            if action.is_empty() {
                return Err(malformed("an action list has an empty entry"));
            }
            set.insert(action.to_string());
        }
        if set.is_empty() {
            return Err(malformed("a scope grants no action"));
        }

        Ok(Self {
            repository,
            actions: set,
        })
    }

    pub fn repository(&self) -> &RepositoryName {
        &self.repository
    }

    pub fn actions(&self) -> &BTreeSet<String> {
        &self.actions
    }

    /// Renders the scope in the form a token endpoint is asked with.
    pub fn as_str(&self) -> String {
        let actions: Vec<&str> = self.actions.iter().map(String::as_str).collect();
        format!("repository:{}:{}", self.repository, actions.join(","))
    }
}

impl fmt::Display for RegistryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// The scope to ask the token endpoint for.
///
/// Derived from the operation, never from [`BearerChallenge::requested_scope`],
/// and that is the whole point: the registry's `401` names a scope because it
/// is describing what it *would* honour, which is routinely every action at
/// once. This function takes no challenge and has no parameter that could
/// carry one, so the widening has to be written somewhere else on purpose to
/// happen here.
pub fn scope_to_request(
    operation: RegistryOperation,
    repository: &RepositoryName,
) -> RegistryScope {
    RegistryScope::for_operation(operation, repository.clone())
}

/// The scope the broker may use, given what the endpoint says it granted.
///
/// The result is the intersection, and the grant is treated as a ceiling
/// rather than as a permission: a grant of `repository:x:pull,push` against a
/// required `repository:x:pull` yields `repository:x:pull`, and the extra
/// action is dropped rather than carried. A grant that does not cover the
/// requirement is refused, including one for a different repository — which is
/// the shape a confused-deputy token would have.
pub fn narrow(
    required: &RegistryScope,
    granted: &RegistryScope,
) -> Result<RegistryScope, ScopeError> {
    if required.repository != granted.repository {
        return Err(ScopeError::WrongRepository {
            required: required.as_str(),
            granted: granted.as_str(),
        });
    }
    if !granted.actions.is_superset(&required.actions) {
        let missing: Vec<&str> = required
            .actions
            .difference(&granted.actions)
            .map(String::as_str)
            .collect();
        return Err(ScopeError::InsufficientGrant {
            missing: missing.join(","),
        });
    }
    Ok(required.clone())
}

/// Reads the `scope` out of a token endpoint's response body.
///
/// The body also holds the token. This function parses the JSON and returns
/// only the scope, so the credential is never copied into a field, a `Debug`
/// output or a log line by the act of learning what was granted. The token
/// itself is lent later, by a port that has no way to return one.
pub fn granted_scope_from_token_response(body: &str) -> Result<RegistryScope, ScopeError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| ScopeError::NoScopeInTokenResponse(e.to_string()))?;
    let scope = value.get("scope").and_then(Value::as_str).ok_or_else(|| {
        ScopeError::NoScopeInTokenResponse("the response carries no scope".into())
    })?;
    RegistryScope::parse(scope)
}

// Declared last, as `github.rs` does. The intra-module doc links in this file's
// header carry their full `crate::registry::` path for the same reason they are
// written that way rather than as bare names: bare ones in a module header do
// not resolve here, and three warnings nobody reads is a warning nobody reads.
#[cfg(test)]
mod tests;
