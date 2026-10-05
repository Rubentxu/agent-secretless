//! What a package registry is addressed by — and why it is not an [`Authority`].
//!
//! # The reason this type exists
//!
//! The first version of this adapter canonicalised a registry host with
//! [`asv_domain::Authority`], because canonicalisation is what an audience needs
//! and `Authority` is the audience type the tree already had. That was wrong, and
//! the row that proved it is `a_local_registry_on_a_port_is_an_audience_not_a_refusal`.
//!
//! `Authority` is D5's answer to "which API host may this operation reach", and it
//! refuses a port and refuses a single-label host. Both refusals are correct
//! *there*: the APIs in this system are public HTTPS endpoints on bare
//! multi-label hosts, and admitting `evil.example:8443` to that list would
//! admit a different service on the same name.
//!
//! **A package registry is not that.** The most common non-public registry in npm
//! is a self-hosted one on localhost — `localhost:4873` is Verdaccio's default —
//! and self-hosted registries inside a network are routinely on a port. So
//! importing `Authority`'s restriction here would have made the adapter refuse
//! the exact case it exists to serve, and the refusal would have looked like a
//! malformed file rather than a type chosen for the wrong domain.
//!
//! That is the law "no two components may answer the same semantic question
//! independently" arriving in a new place: `Authority` answers *API audience*,
//! this answers *registry endpoint*, and they are different questions with
//! different answers. Reusing one to answer the other is how a restriction meant
//! for one becomes a bug in the other.
//!
//! # What canonicalisation means here
//!
//! A registry endpoint is `host`, or `host:port`, or a bracketed IPv6 literal
//! with an optional port. It is **not** a scheme, a path, a query or userinfo —
//! those are stripped by the caller before this type sees the string, and a
//! string carrying one is refused rather than cleaned, because a registry URL
//! this crate cannot fully account for is a registry it would be naming in a
//! report an operator acts on.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A package registry's endpoint, canonicalised to exactly one spelling.
///
/// `Eq` here is canonical-form equality, which is the point: two spellings of
/// the same endpoint are the same endpoint, so a credential bound to one is a
/// credential bound to the other. That is the property a later [`plan`] needs and
/// the reason a plain `String` would not do.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RegistryAudience {
    host: String,
    port: Option<u16>,
}

impl RegistryAudience {
    /// Canonicalises `raw`, or refuses.
    ///
    /// Accepts `host`, `host:port`, `[ipv6]` and `[ipv6]:port`.
    pub fn parse(raw: &str) -> Result<Self, RegistryAudienceError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(RegistryAudienceError::Empty);
        }
        if raw.contains("://") {
            return Err(RegistryAudienceError::HasScheme { raw: raw.into() });
        }
        if raw.contains('/') {
            return Err(RegistryAudienceError::HasPath { raw: raw.into() });
        }
        if raw.contains('@') {
            return Err(RegistryAudienceError::HasUserinfo { raw: raw.into() });
        }

        let (host, port) = split_host_and_port(raw)?;
        let host = canonical_host(&host)?;
        Ok(Self { host, port })
    }

    /// The host, lowercased and validated. No port.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, when the endpoint named one.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The endpoint as a URL, with a scheme, for a human reading a report.
    ///
    /// Always `https`. A registry that speaks plain HTTP is a registry this
    /// product will not broker a credential to, and saying so here is better
    /// than emitting a URL an operator copies into something that will send a
    /// token in the clear.
    pub fn url(&self) -> String {
        match self.port {
            Some(port) => format!("https://{}:{port}", self.host),
            None => format!("https://{}", self.host),
        }
    }
}

impl fmt::Display for RegistryAudience {
    /// Written out by hand rather than delegating to `to_string()`.
    ///
    /// `ToString` is derived from `Display`, so `f.write_str(&self.to_string())`
    /// is a call that reaches this function through `to_string`, which reaches
    /// it again — infinite recursion, and a **stack overflow** rather than a
    /// failed row. The row that caught it was
    /// `a_local_registry_on_a_port_keeps_its_port`, because that was the first
    /// one to format an audience. A test that aborts the process is a louder
    /// failure than a wrong answer and no less useful.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

impl From<RegistryAudience> for String {
    fn from(audience: RegistryAudience) -> Self {
        audience.to_string()
    }
}

impl TryFrom<String> for RegistryAudience {
    type Error = RegistryAudienceError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// Splits `host[:port]`, handling the bracketed IPv6 form.
fn split_host_and_port(raw: &str) -> Result<(String, Option<u16>), RegistryAudienceError> {
    if let Some(rest) = raw.strip_prefix('[') {
        // `[::1]` or `[::1]:4873`. The closing bracket is mandatory here: an
        // unbracketed IPv6 literal is ambiguous against a port, and guessing
        // which the operator meant is how a credential ends up at the wrong
        // service.
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| RegistryAudienceError::UnclosedIpv6Bracket { raw: raw.into() })?;
        let host = host.to_string();
        return match after {
            "" => Ok((host, None)),
            other => other
                .strip_prefix(':')
                .ok_or_else(|| RegistryAudienceError::TrailingGarbage { raw: raw.into() })
                .and_then(|port| parse_port(port, raw))
                .map(|port| (host, Some(port))),
        };
    }
    // More than one colon and no brackets is an unbracketed IPv6 literal, which
    // is ambiguous with a port and is refused rather than interpreted.
    let colons = raw.matches(':').count();
    if colons > 1 {
        return Err(RegistryAudienceError::AmbiguousIpv6 { raw: raw.into() });
    }
    match raw.split_once(':') {
        None => Ok((raw.to_string(), None)),
        Some((host, port)) => parse_port(port, raw).map(|port| (host.to_string(), Some(port))),
    }
}

fn parse_port(port: &str, raw: &str) -> Result<u16, RegistryAudienceError> {
    if port.is_empty() {
        return Err(RegistryAudienceError::TrailingColon { raw: raw.into() });
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RegistryAudienceError::PortNotANumber {
            raw: raw.into(),
            port: port.into(),
        });
    }
    // `u16` accepts `0`; an endpoint does not. The check is here rather than
    // left to a later "port 0 means the kernel picks one" reading, because a
    // report naming `host:0` is a report naming an endpoint that does not exist.
    let port: u16 = port
        .parse()
        .map_err(|_| RegistryAudienceError::PortOutOfRange { raw: raw.into() })?;
    if port == 0 {
        return Err(RegistryAudienceError::PortOutOfRange { raw: raw.into() });
    }
    Ok(port)
}

/// Lowercases and validates a host.
///
/// A single label **is** accepted here, and that is the difference from
/// `Authority`: `localhost` is a real registry host and refusing it would
/// refuse the self-hosted case this adapter exists to serve. What is refused is
/// a name that could not be resolved to a single service: empty labels, a label
/// starting or ending with a hyphen, and a label of illegal characters.
fn canonical_host(raw: &str) -> Result<String, RegistryAudienceError> {
    if raw.is_empty() {
        return Err(RegistryAudienceError::EmptyHost);
    }
    // An IPv4 literal is already canonical; an IPv6 one is handled by the
    // bracket branch and arrives here with its colons.
    if raw.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(raw.to_string());
    }
    if raw.contains(':') {
        // Reached only via brackets, where `raw` is a bare IPv6 literal.
        return raw
            .parse::<std::net::Ipv6Addr>()
            .map(|address| address.to_string())
            .map_err(|_| RegistryAudienceError::NotAHost { host: raw.into() });
    }
    let mut labels = Vec::new();
    for label in raw.split('.') {
        if label.is_empty() {
            return Err(RegistryAudienceError::EmptyLabel { host: raw.into() });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RegistryAudienceError::LabelEdgeHyphen { host: raw.into() });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RegistryAudienceError::NotAHost { host: raw.into() });
        }
        labels.push(label.to_ascii_lowercase());
    }
    Ok(labels.join("."))
}

/// Why a registry endpoint could not be canonicalised.
///
/// Every variant refuses. None of them cleans up: a report that silently
/// repaired a registry URL would be naming a service the operator did not write.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryAudienceError {
    #[error("the registry endpoint is empty")]
    Empty,
    #[error("the registry endpoint has no host")]
    EmptyHost,
    #[error("{raw:?} carries a scheme; the endpoint is a host, not a URL")]
    HasScheme { raw: String },
    #[error("{raw:?} carries a path; the endpoint is a host, not a URL")]
    HasPath { raw: String },
    #[error("{raw:?} carries userinfo; credentials do not belong in a registry endpoint")]
    HasUserinfo { raw: String },
    #[error("{raw:?} has no closing bracket around its IPv6 literal")]
    UnclosedIpv6Bracket { raw: String },
    #[error(
        "{raw:?} is an unbracketed IPv6 literal, which cannot be told apart from a host and a \
         port; write it as [address] or [address]:port"
    )]
    AmbiguousIpv6 { raw: String },
    #[error("{raw:?} ends in a colon with no port after it")]
    TrailingColon { raw: String },
    #[error("{port:?} in {raw:?} is not a number")]
    PortNotANumber { raw: String, port: String },
    #[error("the port in {raw:?} is outside 1-65535")]
    PortOutOfRange { raw: String },
    #[error("{host:?} has an empty label")]
    EmptyLabel { host: String },
    #[error("{host:?} has a label that starts or ends with a hyphen")]
    LabelEdgeHyphen { host: String },
    #[error("{host:?} is not a host name")]
    NotAHost { host: String },
    #[error("{raw:?} has trailing characters after the port")]
    TrailingGarbage { raw: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The row that justifies the type.** Verdaccio's default is
    /// `localhost:4873`, and it is the reason this is not an `Authority`:
    /// `Authority::canonicalize("localhost:4873")` is an error by design, so an
    /// adapter built on it would refuse the most common private registry npm
    /// has, and the refusal would look like a malformed file.
    #[test]
    fn a_local_registry_on_a_port_is_an_audience_not_a_refusal() {
        let audience = RegistryAudience::parse("localhost:4873").expect("verdaccio's default");
        assert_eq!(audience.host(), "localhost");
        assert_eq!(audience.port(), Some(4873));
        assert_eq!(audience.to_string(), "localhost:4873");
        assert_eq!(audience.url(), "https://localhost:4873");

        // And the contrast that makes the row falsifiable: the API-audience
        // type really does refuse the same string, so this is a difference in
        // the two types rather than a claim about one of them.
        assert!(
            asv_domain::Authority::canonicalize("localhost:4873").is_err(),
            "if Authority ever accepts a port, this type's reason to exist is gone"
        );
    }

    #[test]
    fn a_single_label_host_is_accepted_because_localhost_is_one() {
        let audience = RegistryAudience::parse("localhost").expect("a single label is a host");
        assert_eq!(audience.port(), None);
        assert_eq!(audience.url(), "https://localhost");
    }

    #[test]
    fn two_spellings_of_one_endpoint_are_one_audience() {
        // The property a later binding needs: a credential bound to
        // `NPM.Example.Test:443` is a credential bound to `npm.example.test`.
        let shouted = RegistryAudience::parse("NPM.Example.Test:443").expect("canonicalises");
        let quiet = RegistryAudience::parse("npm.example.test").expect("canonicalises");
        assert_eq!(shouted.host(), quiet.host());
        assert_ne!(
            shouted, quiet,
            "the ports differ, so these are different endpoints"
        );
    }

    #[test]
    fn case_is_folded_and_the_port_is_kept() {
        let audience = RegistryAudience::parse("Registry.NPMjs.ORG").expect("canonicalises");
        assert_eq!(audience.host(), "registry.npmjs.org");
        assert_eq!(audience.to_string(), "registry.npmjs.org");
    }

    #[test]
    fn an_ipv6_literal_is_accepted_in_its_bracketed_form() {
        let audience = RegistryAudience::parse("[::1]:4873").expect("bracketed IPv6");
        assert_eq!(audience.port(), Some(4873));
        assert!(audience.host().contains(':'), "{}", audience.host());
    }

    #[test]
    fn an_unbracketed_ipv6_literal_is_refused_rather_than_guessed() {
        // `::1` could be a host and a port, and reading it either way sends a
        // credential to a service the operator did not name.
        let error = RegistryAudience::parse("::1").expect_err("ambiguous");
        assert!(
            matches!(error, RegistryAudienceError::AmbiguousIpv6 { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_scheme_or_path_is_refused_rather_than_stripped() {
        for (raw, expected) in [
            (
                "https://registry.example.test",
                RegistryAudienceErrorKind::Scheme,
            ),
            ("registry.example.test/npm", RegistryAudienceErrorKind::Path),
            (
                "user@registry.example.test",
                RegistryAudienceErrorKind::Userinfo,
            ),
        ] {
            let error = RegistryAudience::parse(raw).expect_err(raw);
            // `assert_eq!`, not `matches!`. `matches!(x, expected)` treats
            // `expected` as a *binding* pattern, which matches anything — the
            // first version of this row could not fail, and the compiler's
            // "unused variable" warning was the only thing that said so. A
            // warning about an unused binding is a warning about a row that
            // asserts nothing.
            assert_eq!(kind_of(&error), expected, "{raw}: {error}");
        }
    }

    /// A `not a host` string with spaces, which is the case the auth-selector
    /// row depends on.
    #[test]
    fn a_host_with_spaces_is_not_a_host() {
        let error = RegistryAudience::parse("not a host").expect_err("spaces are not a host");
        assert!(
            matches!(error, RegistryAudienceError::NotAHost { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_port_outside_the_valid_range_is_refused() {
        for raw in ["host:0", "host:65536", "host:99999"] {
            let error = RegistryAudience::parse(raw).expect_err(raw);
            assert!(
                matches!(error, RegistryAudienceError::PortOutOfRange { .. }),
                "{raw}: {error}"
            );
        }
    }

    #[test]
    fn an_empty_label_is_refused() {
        // `a..b` resolves nowhere, and a name that resolves nowhere in a report
        // an operator acts on is worse than a refusal.
        let error = RegistryAudience::parse("a..b").expect_err("empty label");
        assert!(
            matches!(error, RegistryAudienceError::EmptyLabel { .. }),
            "{error}"
        );
    }

    #[test]
    fn the_serialised_form_is_the_canonical_spelling() {
        // `serde(try_from)` and `serde(into)` mean a report cannot contain a
        // non-canonical audience, however it was built.
        let audience = RegistryAudience::parse("NPM.Example.Test:4873").expect("canonicalises");
        let json = serde_json::to_string(&audience).expect("serialises");
        assert_eq!(json, "\"npm.example.test:4873\"");
        let back: RegistryAudience = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, audience);
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RegistryAudienceErrorKind {
        Scheme,
        Path,
        Userinfo,
    }

    fn kind_of(error: &RegistryAudienceError) -> RegistryAudienceErrorKind {
        match error {
            RegistryAudienceError::HasScheme { .. } => RegistryAudienceErrorKind::Scheme,
            RegistryAudienceError::HasPath { .. } => RegistryAudienceErrorKind::Path,
            RegistryAudienceError::HasUserinfo { .. } => RegistryAudienceErrorKind::Userinfo,
            other => panic!("{other}"),
        }
    }
}
