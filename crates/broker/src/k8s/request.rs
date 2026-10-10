//! Kubernetes API — the request core, and nothing else.
//!
//! # What this increment is, and is not
//!
//! This is the *encoding* half of the Kubernetes reverse proxy: given what an
//! agent named, the method and the path. It opens no socket, holds no token and
//! reads no clock, and the split is the same one R2.C.1 used for the SigV4
//! core. The reason to separate them is that this half is a pure function of its
//! inputs, which is the only reason it can be checked against an oracle at all.
//!
//! - **R2.D.1 (this module).** Turn a named operation into a method and a path,
//!   and refuse everything that would let the named parts mean something other
//!   than what they were named as.
//! - **R2.D.2.** The transport and the `SecretPort`: a short-lived,
//!   audience-bound ServiceAccount token, borrowed for the length of one
//!   request and never named, attached to what this module built.
//! - **R2.D.3.** The broker operation and the CLI verb, so an agent names a
//!   Kubernetes operation and never sees a token.
//!
//! **Nothing here is reachable from a product surface, and the module says so
//! rather than letting a test imply otherwise.** Per M11's rule a provider does
//! not count as closed on an encoding alone, and R2.D is not closed: R2.D.2 and
//! R2.D.3 do not exist yet.
//!
//! # The security property, stated as a sentence
//!
//! **The agent-supplied parts cannot escape their position in the request.**
//!
//! That is the whole claim, and it is narrower than it sounds on purpose. This
//! module takes three strings from a caller and puts each of them at a fixed
//! place in a URL: a namespace, a resource, a name. A proxy that concatenates
//! them without checking does not need a vulnerability in Kubernetes, in the
//! transport, or in the token handling. `GET pods/../../secrets` is a legal
//! string. Handed to a builder that does `format!("/api/v1/namespaces/{ns}/{resource}/{name}")`
//! it addresses something the agent never named, and the request that leaves
//! the process is well-formed, correctly authenticated, and aimed somewhere
//! else.
//!
//! So the checks below are not input validation in the defensive-programming
//! sense. They are the load-bearing part of the provider, and they are written
//! down as such because the alternative — a builder that trusts its inputs —
//! produces a proxy that is insecure in a way no test in R2.D.2 or R2.D.3 can
//! detect from the outside.
//!
//! # Why the API group is not agent-selectable
//!
//! Every path here is built under `api/v1`, and that is a decision rather than
//! an omission. The group is what authorization is scoped to: a rule that grants
//! `get pods` in the core group says nothing about any other group, so letting
//! the caller name the group would mean letting the caller pick which
//! authorization applies to its own request. Pinning the core group removes that
//! from the request entirely, at the cost of not covering the other groups — a
//! cost R2.D.2 is the right place to revisit, and revisiting it must not be by
//! adding a string parameter.
//!
//! # What is deliberately absent
//!
//! **Subresources.** `pods/{name}/log` is not reachable here. A subresource is a
//! second segment chosen by the same caller, and the first increment has no
//! reason to let a caller name two path segments in a row when one is already
//! enough to be interesting.
//!
//! **Arbitrary query strings.** The `?` is refused rather than escaped, for the
//! same reason `%` is: an escape that produces a different path on the way
//! through the next hop is not an escape.
//!
//! **Every verb Kubernetes defines.** [`Verb`] is a closed set, and it does not
//! include `CONNECT`, `TRACE` or `PATCH`.
//!
//! One rule, applied everywhere: **a request this module does not understand is
//! refused, not guessed at.** Two paths for the same resource, a name where a
//! collection belongs, a method the operation does not have — all of them leave
//! through the same door, and none of them is repaired on the way out.

use std::fmt;

/// The method an operation maps to.
///
/// A closed set rather than a `&str`, and the difference is the point: a proxy
/// that takes a method string forwards whatever it is handed, including a
/// verb the API server does not implement and including `TRACE`, which exists
/// to echo a request back and which no legitimate agent operation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verb {
    /// Read one named object.
    Get,
    /// Read a collection.
    List,
    /// Create one object in a collection.
    Create,
    /// Remove one named object.
    Delete,
}

impl Verb {
    /// The HTTP method this operation sends.
    pub fn method(self) -> &'static str {
        match self {
            Verb::Get => "GET",
            Verb::List => "GET",
            Verb::Create => "POST",
            Verb::Delete => "DELETE",
        }
    }

    /// Whether this operation addresses a single object rather than a
    /// collection.
    ///
    /// Used as a refusal, not as a convenience. `Get` without a name is a list
    /// wearing a get's clothes: the agent said "this pod" and the request would
    /// say "every pod", and nothing downstream can tell the difference because
    /// the method is the same. The operation named and the operation performed
    /// have to be the same operation.
    pub fn takes_name(self) -> bool {
        matches!(self, Verb::Get | Verb::Delete)
    }

    /// Whether this operation creates, and therefore takes a body.
    pub fn takes_body(self) -> bool {
        matches!(self, Verb::Create)
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Verb::Get => "get",
            Verb::List => "list",
            Verb::Create => "create",
            Verb::Delete => "delete",
        };
        f.write_str(name)
    }
}

/// Where the addressed object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    /// `/api/v1/namespaces/{namespace}/{resource}[/{name}]`
    Namespaced {
        /// The namespace the object is claimed to be in.
        ///
        /// `&'a str` rather than `&'static str` for the reason
        /// [`ApiRequest`] is: a request that names a non-static namespace
        /// string would otherwise be forced to `Box::leak` the string, and a
        /// long-running broker would leak on every call. The lifetime ties
        /// the namespace to the request that produced it, so the borrow
        /// checker is what outlives the call rather than the allocator.
        namespace: &'a str,
    },
    /// `/api/v1/{resource}/{name}` — nodes, namespaces, persistent volumes.
    Cluster,
}

/// What an agent named.
///
/// Every field is a name, and every field is checked before it is placed. There
/// is deliberately no field for a query, a body or a path prefix, and adding one
/// is the change that would need this module's refusals re-argued rather than
/// merely extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRequest<'a> {
    /// The operation, from a closed set.
    pub verb: Verb,
    /// Where the object lives.
    pub scope: Scope<'a>,
    /// The plural resource name, as the API server spells it: `pods`, `secrets`.
    pub resource: &'a str,
    /// The object's name, for the operations that take one.
    pub name: Option<&'a str>,
}

/// Why a request could not be built.
///
/// Every arm is a refusal. There is no variant meaning "adjusted", because a
/// builder that repairs its input is a builder whose output is a request the
/// caller did not name, and the whole property of this module is that the named
/// parts stay where they were put.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// A name segment is not a valid RFC 1123 DNS subdomain.
    ///
    /// This is the refusal that does the work. A subdomain is lowercase
    /// alphanumerics, `-` and `.`, which excludes `/`, `%`, `?`, `#`, every
    /// control character, and every whitespace character in one predicate —
    /// and excluding `.` and `..` as whole segments is what closes the walk
    /// out of the namespace, because a name that cannot contain `/` cannot
    /// contain `../` either.
    #[error("{what} {value:?} is not a name this proxy will place in a path")]
    NotAName {
        /// Which field was refused.
        what: &'static str,
        /// What was refused.
        value: String,
    },

    /// A namespace is not a valid RFC 1123 DNS label.
    ///
    /// A namespace cannot contain `.` even though a resource name can, and that
    /// is a real difference in the API server rather than a choice here: the
    /// namespace is a path segment of its own, and allowing a dot in it would
    /// make `ns.example` and a segment traversal hard to tell apart by reading.
    #[error("namespace {0:?} is not a DNS label")]
    NotANamespace(String),

    /// A single-object operation arrived without a name.
    ///
    /// See [`Verb::takes_name`]. `get` with no name is a `list` that reports
    /// itself as a `get`, and the request that leaves the process cannot be
    /// distinguished from the honest one by anything downstream.
    #[error("{0} addresses one object, so it needs a name")]
    MissingName(Verb),

    /// A collection operation arrived with a name.
    ///
    /// The mirror of the above: `list` with a name would address a collection at
    /// a path that reads like an object, and the API server would answer `404`
    /// for reasons that have nothing to do with the agent's mistake.
    #[error("{0} addresses a collection, so it takes no name")]
    UnexpectedName(Verb),

    /// An empty segment.
    ///
    /// Not covered by the DNS rules above, because a name is checked as a
    /// *whole* and `""` is trivially free of forbidden characters. Left alone it
    /// produces `//` in the path, which a proxy may normalise and a server may
    /// not — the two disagreeing about a path is how a request ends up aimed
    /// somewhere the caller never wrote.
    #[error("{what} is empty, and an empty segment changes what the path means")]
    EmptySegment {
        /// Which field was refused.
        what: &'static str,
    },
    // Two arms this enum does not have, and the absence is the point.
    //
    // There is no "namespace mismatch" and no "unsupported group". A namespace
    // can be missing from a request or present for a cluster-scoped resource
    // only if `Scope` allowed it, and `Scope` does not: `Namespaced` carries the
    // namespace as a field that cannot be absent, and `Cluster` has nowhere to
    // put one. An arm for a case the type system already refuses would be a
    // claim the code cannot keep -- a branch nothing can reach, which reads in
    // a reviewer as "handled" and is not.
    //
    // The same argument is why `SignRequest` in the AWS core has no "no host
    // supplied" *field* and only a refusal: the header list is the field, and
    // its absence is an error rather than an empty value.
}

impl ApiRequest<'_> {
    /// The method this request sends.
    pub fn method(&self) -> &'static str {
        self.verb.method()
    }

    /// The path, or a refusal.
    ///
    /// This is the function the module exists for. Everything it returns has
    /// been checked as a whole segment, and everything it refuses has been
    /// refused for being a *name* rather than for being unusual.
    pub fn path(&self) -> Result<String, ApiError> {
        // The verb/name agreement is checked before any segment is placed, so
        // that a malformed call is refused on its own terms rather than on
        // whichever segment happens to be examined first.
        match (self.verb.takes_name(), self.name) {
            (true, None) => return Err(ApiError::MissingName(self.verb)),
            (false, Some(_)) => return Err(ApiError::UnexpectedName(self.verb)),
            (true, Some(_)) | (false, None) => {}
        }

        let resource = checked_subdomain("resource", self.resource)?;

        let mut path = String::with_capacity(resource.len() + 32);
        match self.scope {
            Scope::Namespaced { namespace } => {
                // `checked_label` is the refusal that does the work: a 64-byte
                // namespace is one the API server will refuse, and a proxy
                // that builds it anyway produces a 404 that says nothing about
                // the real cause. The earlier form of this function called
                // `checked_label` and assigned its result; the lifetime
                // broadening that removed `Box::leak` dropped the call.
                // Restoring it here keeps the request's *and* the response's
                // failures on the same side of the boundary.
                let namespace = checked_label("namespace", namespace)?;
                path.push_str("/api/v1/namespaces/");
                path.push_str(&namespace);
                path.push('/');
            }
            Scope::Cluster => path.push_str("/api/v1/"),
        }
        path.push_str(&resource);
        if let Some(name) = self.name {
            let name = checked_subdomain("name", name)?;
            path.push('/');
            path.push_str(&name);
        }
        Ok(path)
    }
}

/// A DNS label: lowercase alphanumerics and `-`, no dots, at most 63 bytes.
///
/// The length bound is the API server's, not a convenience. A namespace longer
/// than 63 is one the server will refuse, and a proxy that builds it anyway
/// produces a `404` that says nothing about the real cause.
fn checked_label(what: &'static str, value: &str) -> Result<String, ApiError> {
    if value.is_empty() {
        return Err(ApiError::EmptySegment { what });
    }
    if value.len() > 63 {
        return Err(ApiError::NotANamespace(value.to_string()));
    }
    if value
        .bytes()
        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err(ApiError::NotANamespace(value.to_string()));
    }
    // A label may not begin or end with `-`. Left unchecked, `-ns` and `ns-`
    // are addresses the caller never named in any readable sense, and the
    // server's own error will point at the resource rather than the namespace.
    if value.starts_with('-') || value.ends_with('-') {
        return Err(ApiError::NotANamespace(value.to_string()));
    }
    Ok(value.to_string())
}

/// A DNS subdomain: labels joined by `.`, at most 253 bytes.
fn checked_subdomain(what: &'static str, value: &str) -> Result<String, ApiError> {
    if value.is_empty() {
        return Err(ApiError::EmptySegment { what });
    }
    if value.len() > 253 {
        return Err(not_a_name(what, value));
    }
    if value
        .bytes()
        .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'))
    {
        return Err(not_a_name(what, value));
    }
    // `.` and `..`, a leading or trailing dot, and `a..b` are all the same
    // defect wearing different clothes, and the per-label loop below refuses
    // every one of them by shape. The first version of this function also had
    // an explicit `== "." || == ".."` arm, a `starts_with('.')` arm and a
    // `contains("..")` arm, on the reasoning that the traversal cases deserve
    // to be named. Falsifying it showed those three could never be the arm
    // that refused: the loop catches `.` and `..` as empty labels, and catches
    // `a..b` as an empty label between two that are not. They were unreachable
    // rules that read in review as handled.
    //
    // So the traversal argument is made once, by the loop, and the reason it is
    // *sufficient* is that a label which is non-empty and bounded by the
    // alphabet above cannot contain a `/`, and therefore cannot contain `../`
    // either. Naming a case the loop already covers would be a second
    // implementation of one rule, and two implementations of one rule is how
    // they come to disagree.
    for label in value.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(not_a_name(what, value));
        }
    }
    Ok(value.to_string())
}

/// Shorthand for the not-a-name arm, which carries a `String`.
fn not_a_name(what: &'static str, value: &str) -> ApiError {
    ApiError::NotAName {
        what,
        value: value.to_string(),
    }
}

#[cfg(test)]
mod tests;
