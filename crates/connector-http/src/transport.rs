//! Address resolution, policy and client construction (D1, D7).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use asv_domain::Authority;
use url::Url;

/// Why a transport operation was refused.
///
/// Every variant is a refusal. There is no "connected anyway" path: the
/// transport either satisfies the pinning rules or it does not run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("audience is not routable: {0}")]
    UnroutableAudience(String),

    #[error("DNS resolution failed for {host}: {reason}")]
    ResolutionFailed { host: String, reason: String },

    #[error("audience {audience} resolved to {address}, which is not a public address")]
    NonPublicAddress { audience: String, address: IpAddr },

    #[error("redirect to {target} leaves the approved origin {origin}")]
    CrossOriginRedirect { origin: String, target: String },

    #[error("too many redirects (limit is {limit})")]
    TooManyRedirects { limit: usize },

    #[error("URL is not usable: {0}")]
    InvalidUrl(String),
}

/// Which resolved addresses may be connected to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddressPolicy {
    /// Allow loopback. Only tests and local fake servers need this; the
    /// production path leaves it off, which is why the fake-server tests are
    /// explicit about turning it on rather than inheriting it.
    pub allow_loopback: bool,
}

impl AddressPolicy {
    /// Whether `address` may be connected to under this policy.
    ///
    /// The refusals are: loopback, unspecified, private, link-local (which
    /// covers cloud metadata at 169.254.169.254), shared address space, and
    /// the documentation/benchmark ranges that should never be an API peer.
    pub fn permits(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return self.allow_loopback && !Self::is_documentation_v4(v4);
                }
                !v4.is_unspecified()
                    && !v4.is_private()
                    && !v4.is_link_local()
                    && !v4.is_broadcast()
                    && !v4.is_documentation()
                    && !Self::is_shared_v4(v4)
                    && !Self::is_reserved_v4(v4)
                    && !Self::is_documentation_v4(v4)
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return self.allow_loopback;
                }
                !v6.is_unspecified()
                    // unique local, fc00::/7
                    && v6.segments()[0] & 0xfe00 != 0xfc00
                    // link local, fe80::/10
                    && v6.segments()[0] & 0xffc0 != 0xfe80
                    // an IPv4-mapped address inherits the v4 verdict verbatim
                    && !v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| !self.permits(IpAddr::V4(v4)))
            }
        }
    }

    /// `100.64.0.0/10`, carrier-grade NAT. `is_shared` is still unstable, so
    /// the range is written out; the point is refusing it, not the API.
    fn is_shared_v4(v4: Ipv4Addr) -> bool {
        matches!(v4.octets(), [100, 64..=127, _, _])
    }

    /// `240.0.0.0/4`, reserved for future use.
    fn is_reserved_v4(v4: Ipv4Addr) -> bool {
        v4.octets()[0] & 0xf0 == 0xf0
    }

    fn is_documentation_v4(v4: Ipv4Addr) -> bool {
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        matches!(
            v4.octets(),
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
        )
    }
}

/// The result of resolving an audience: the addresses that passed the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAudience {
    pub authority: Authority,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

/// Resolves `authority` to the addresses a pinned client may use.
///
/// This performs the *only* DNS lookup the request will use. The caller pins
/// the result into the client, so the HTTP stack never re-resolves the name.
pub fn resolve_and_pin(
    authority: &Authority,
    port: u16,
    policy: AddressPolicy,
) -> Result<ResolvedAudience, TransportError> {
    if port == 0 {
        return Err(TransportError::UnroutableAudience(authority.to_string()));
    }
    let addresses =
        resolve(authority.as_str()).map_err(|reason| TransportError::ResolutionFailed {
            host: authority.to_string(),
            reason,
        })?;
    if addresses.is_empty() {
        return Err(TransportError::ResolutionFailed {
            host: authority.to_string(),
            reason: "no A or AAAA records".to_string(),
        });
    }
    for address in &addresses {
        if !policy.permits(*address) {
            return Err(TransportError::NonPublicAddress {
                audience: authority.to_string(),
                address: *address,
            });
        }
    }
    Ok(ResolvedAudience {
        authority: authority.clone(),
        port,
        addresses,
    })
}

/// Resolving through the system resolver. Split out so the policy above can
/// be tested without a network.
fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
    // Port 0 never connects: this lookup exists only to enumerate addresses.
    (host, 0u16)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .map(|socket| socket.ip())
                .collect::<std::collections::BTreeSet<IpAddr>>()
                .into_iter()
                .collect()
        })
        .map_err(|error| error.to_string())
}

/// A client whose DNS answers are pinned to vetted addresses.
pub struct PinnedClient {
    inner: reqwest::blocking::Client,
}

/// How many redirect hops D7 permits before denying.
pub const MAX_REDIRECTS: usize = 3;

impl PinnedClient {
    /// Builds a client for one operation against already-vetted addresses.
    ///
    /// The address list is re-checked against `policy` here even though
    /// [`resolve_and_pin`] already filtered it. That redundancy is the point:
    /// `ResolvedAudience` is a public struct, so a caller can build one by
    /// hand, and a `build` that trusted its input would turn a type-level
    /// promise into a convention. Cheaper to re-filter than to trust.
    ///
    /// Redirects are disabled in the client itself: the loop in
    /// [`PinnedClient::follow_same_origin`] is the only thing that may follow a
    /// hop, and it re-checks the origin before doing so.
    pub fn build(
        resolved: &ResolvedAudience,
        policy: AddressPolicy,
    ) -> Result<Self, TransportError> {
        if resolved.port == 0 {
            return Err(TransportError::UnroutableAudience(
                resolved.authority.to_string(),
            ));
        }
        if resolved.addresses.is_empty() {
            return Err(TransportError::ResolutionFailed {
                host: resolved.authority.to_string(),
                reason: "no A or AAAA records".to_string(),
            });
        }
        for address in &resolved.addresses {
            if !policy.permits(*address) {
                return Err(TransportError::NonPublicAddress {
                    audience: resolved.authority.to_string(),
                    address: *address,
                });
            }
        }
        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false);
        // Every surviving address is registered, not just the first: collapsing
        // the list would silently turn pinning into "whichever got picked".
        for address in &resolved.addresses {
            builder = builder.resolve(
                resolved.authority.as_str(),
                SocketAddr::new(*address, resolved.port),
            );
        }
        let inner = builder
            .build()
            .map_err(|error| TransportError::InvalidUrl(error.to_string()))?;
        Ok(Self { inner })
    }

    /// The base URL for `path` on the pinned audience.
    pub fn url(&self, resolved: &ResolvedAudience, path: &str) -> Result<Url, TransportError> {
        Url::parse(&format!(
            "https://{}:{}{}",
            resolved.authority, resolved.port, path
        ))
        .map_err(|error| TransportError::InvalidUrl(error.to_string()))
    }

    /// The underlying client. Exposed so a caller can inject headers once,
    /// in its own process, via the secret port.
    pub fn client(&self) -> &reqwest::blocking::Client {
        &self.inner
    }

    /// Whether `next` stays on the approved origin (D7).
    ///
    /// Comparison is on the *canonical* origin, not the raw string, so a
    /// different spelling of the same host is still same-origin while a
    /// lookalike suffix is not.
    pub fn is_same_origin(origin: &Url, next: &Url) -> bool {
        match (origin.host_str(), next.host_str()) {
            (Some(a), Some(b)) => {
                let a = a.trim_end_matches('.').to_ascii_lowercase();
                let b = b.trim_end_matches('.').to_ascii_lowercase();
                a == b
                    && origin.scheme() == next.scheme()
                    && effective_port(origin) == effective_port(next)
            }
            _ => false,
        }
    }

    /// Follows at most [`MAX_REDIRECTS`] same-origin hops.
    ///
    /// This is deliberately not a method on the client: redirect acceptance is
    /// a pure function of the URLs, so it can be tested with no client, no
    /// network and no credential in scope.
    ///
    /// The caller supplies `send_attempt`, which receives the request to make.
    /// A hop is only followed after the origin check passes, and this layer
    /// never adds a header: the caller re-injects the credential per hop from
    /// the secret port, so it is never carried across a hop by this code.
    pub fn follow_same_origin<F>(
        mut url: Url,
        origin: &Url,
        mut send_attempt: F,
    ) -> Result<Url, TransportError>
    where
        F: FnMut(&Url) -> Result<Option<Url>, TransportError>,
    {
        let mut hops = 0usize;
        loop {
            match send_attempt(&url)? {
                None => return Ok(url),
                Some(next) => {
                    hops += 1;
                    if hops > MAX_REDIRECTS {
                        return Err(TransportError::TooManyRedirects {
                            limit: MAX_REDIRECTS,
                        });
                    }
                    if !Self::is_same_origin(origin, &next) {
                        return Err(TransportError::CrossOriginRedirect {
                            origin: origin.origin().ascii_serialization(),
                            target: next.origin().ascii_serialization(),
                        });
                    }
                    url = next;
                }
            }
        }
    }
}

fn effective_port(url: &Url) -> u16 {
    url.port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(raw: &str) -> std::net::Ipv6Addr {
        raw.parse().expect("valid IPv6 literal")
    }

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("valid test URL")
    }

    /// The heart of property 2: a public API audience is never loopback,
    /// RFC1918, link-local (the cloud metadata address) or documentation range.
    #[test]
    fn private_and_metadata_addresses_are_refused_by_default() {
        let policy = AddressPolicy::default();
        for hostile in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(169, 254, 169, 254), // cloud metadata
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(100, 64, 0, 1), // shared address space
            Ipv4Addr::new(192, 0, 2, 5),  // documentation
        ] {
            assert!(
                !policy.permits(IpAddr::V4(hostile)),
                "must refuse {hostile}"
            );
        }
        assert!(policy.permits(IpAddr::V4(Ipv4Addr::new(140, 82, 112, 3))));
        assert!(!policy.permits(IpAddr::V6(v6("::1"))));
        assert!(!policy.permits(IpAddr::V6(v6("fe80::1"))));
        assert!(!policy.permits(IpAddr::V6(v6("fc00::1"))));
    }

    /// The fake-server tests need loopback; production does not. Opting in has
    /// to be visible, never inherited.
    #[test]
    fn loopback_is_only_permitted_when_explicitly_requested() {
        assert!(!AddressPolicy::default().permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(AddressPolicy {
            allow_loopback: true
        }
        .permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    /// Property 3: same-origin is a canonical comparison, and a lookalike
    /// suffix or a scheme change is a different origin.
    #[test]
    fn same_origin_survives_spelling_but_not_lookalikes() {
        let origin = url("https://api.github.com/repos/a/b/issues/1");
        assert!(PinnedClient::is_same_origin(
            &origin,
            &url("https://API.GITHUB.COM/other")
        ));
        assert!(!PinnedClient::is_same_origin(
            &origin,
            &url("https://api.github.com.evil.example/other")
        ));
        assert!(!PinnedClient::is_same_origin(
            &origin,
            &url("http://api.github.com/other")
        ));
        assert!(!PinnedClient::is_same_origin(
            &origin,
            &url("https://api.github.com:8443/other")
        ));
    }

    /// A cross-origin `Location` is denied, not followed. This is the
    /// difference between refusing and reissuing unauthenticated (D7).
    #[test]
    fn a_cross_origin_redirect_is_denied_rather_than_followed() {
        let origin = url("https://api.github.com/repos/a/b/issues/1");
        let evil = url("https://evil.example/steal");
        let mut attempts = 0;
        let result = PinnedClient::follow_same_origin(origin.clone(), &origin, |_| {
            attempts += 1;
            Ok(Some(evil.clone()))
        });
        assert!(result.is_err(), "cross-origin hop must be denied");
        assert_eq!(attempts, 1, "must not retry a denied hop");
    }

    /// The hop budget is finite, so a same-origin redirect loop terminates.
    #[test]
    fn a_same_origin_redirect_loop_stops_at_the_limit() {
        let origin = url("https://api.github.com/a");
        let next = url("https://api.github.com/b");
        let mut attempts = 0;
        let result = PinnedClient::follow_same_origin(origin.clone(), &origin, |_| {
            attempts += 1;
            Ok(Some(next.clone()))
        });
        assert!(matches!(
            result,
            Err(TransportError::TooManyRedirects { limit: 3 })
        ));
        assert_eq!(attempts, 4, "one attempt plus the three permitted hops");
    }

    /// A port of zero is never a legitimate destination, and it is refused
    /// before any lookup happens.
    #[test]
    fn a_zero_port_is_refused_without_resolving() {
        let authority = Authority::canonicalize("does-not-resolve.invalid").expect("valid");
        let result = resolve_and_pin(&authority, 0, AddressPolicy::default());
        assert!(matches!(result, Err(TransportError::UnroutableAudience(_))));
    }

    /// Carrier-grade NAT, reserved, broadcast and unspecified space, plus
    /// IPv4-mapped forms of a refused address. A mapped literal is the classic
    /// way to smuggle loopback or RFC1918 past a v4-only check, so the mapped
    /// branch has to inherit the v4 verdict rather than re-decide.
    #[test]
    fn smuggled_address_forms_are_refused() {
        let policy = AddressPolicy::default();
        for raw in ["100.127.255.255", "255.255.255.255", "0.0.0.0"] {
            let addr: IpAddr = raw.parse().expect("valid literal");
            assert!(!policy.permits(addr), "{raw} must be refused");
        }
        for raw in ["::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            assert!(
                !policy.permits(IpAddr::V6(v6(raw))),
                "IPv4-mapped {raw} must inherit the v4 refusal"
            );
        }
    }

    /// Over-refusing is a bug too: it would break the real API. These share
    /// lead octets with the refused ranges above, so a sloppy mask catches
    /// them.
    #[test]
    fn public_addresses_are_not_over_refused() {
        let policy = AddressPolicy::default();
        for raw in [
            "140.82.112.3",    // api.github.com
            "185.199.108.153", // GitHub Pages
            "99.86.1.1",       // shares the 100.64/10 lead octet boundary
            "39.255.1.1",      // shares the 240.0.0.0/4 lead octet boundary
            "2606:50c0:8000::154",
        ] {
            let addr: IpAddr = raw.parse().expect("valid literal");
            assert!(policy.permits(addr), "{raw} must be permitted");
        }
    }

    /// Resolution fails closed. A name that does not resolve is an error, not
    /// an empty address list that later degrades into "any address".
    #[test]
    fn an_unresolvable_audience_fails_closed() {
        let authority = Authority::canonicalize("this-name-does-not-exist.invalid").expect("valid");
        let result = resolve_and_pin(&authority, 443, AddressPolicy::default());
        assert!(
            matches!(result, Err(TransportError::ResolutionFailed { .. })),
            "got {result:?}"
        );
    }

    /// `ResolvedAudience` is a public struct, so a caller can construct one
    /// that never went through [`resolve_and_pin`]. `build` must not trust it:
    /// a hand-built list carrying a private or metadata address is refused,
    /// and an empty list is refused rather than becoming "connect anywhere".
    #[test]
    fn a_hand_built_audience_cannot_bypass_the_address_policy() {
        let hostile = ResolvedAudience {
            authority: Authority::canonicalize("api.github.com").expect("valid"),
            port: 443,
            addresses: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        };
        assert!(matches!(
            PinnedClient::build(&hostile, AddressPolicy::default()),
            Err(TransportError::NonPublicAddress { .. })
        ));

        let empty = ResolvedAudience {
            authority: hostile.authority.clone(),
            port: 443,
            addresses: vec![],
        };
        assert!(matches!(
            PinnedClient::build(&empty, AddressPolicy::default()),
            Err(TransportError::ResolutionFailed { .. })
        ));

        let zero_port = ResolvedAudience {
            authority: hostile.authority.clone(),
            port: 0,
            addresses: vec![IpAddr::V4(Ipv4Addr::new(140, 82, 112, 3))],
        };
        assert!(matches!(
            PinnedClient::build(&zero_port, AddressPolicy::default()),
            Err(TransportError::UnroutableAudience(_))
        ));
    }

    /// A well-formed public audience builds a client, and construction alone
    /// makes no request: no network, no credential, nothing to leak.
    #[test]
    fn a_public_audience_builds_without_touching_the_network() {
        let public = ResolvedAudience {
            authority: Authority::canonicalize("api.github.com").expect("valid"),
            port: 443,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 3)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 3)),
            ],
        };
        assert!(PinnedClient::build(&public, AddressPolicy::default()).is_ok());
    }

    /// Every refusal names the audience and the address, so an audit record can
    /// explain the denial without the caller re-deriving anything.
    #[test]
    fn refusals_name_the_audience_and_the_address() {
        let error = TransportError::NonPublicAddress {
            audience: "api.github.com".to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("api.github.com"), "{rendered}");
        assert!(rendered.contains("169.254.169.254"), "{rendered}");
    }
}
