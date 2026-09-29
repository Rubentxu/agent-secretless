//! Address resolution, policy and pinned client construction (M6-R1, D1, D7).
//!
//! The connector only ever connects to a resolved address it has pinned.
//! This is the same shape as `asv-connector-http::transport`: a single
//! lookup, a single permit check, a single pinned client. Re-resolving
//! inside the stack would let a DNS server answer `127.0.0.1` after the
//! check passed; refusing to re-resolve later becomes the structural
//! reason no subsequent hop reaches an attacker-chosen address.

use std::net::{IpAddr, Ipv4Addr};

use asv_domain::Authority;

/// A resolved PostgreSQL audience: the authority string plus the set
/// of pinned addresses that passed the policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPgAudience {
    pub authority: Authority,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

/// The audience, runtime, and database/role the connector must reach.
///
/// Bundled so the broker passes one thing into the factory rather than
/// four positional arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgAudience {
    pub authority: Authority,
    pub database: String,
    pub role: String,
    pub port: u16,
}

impl PgAudience {
    /// Whether the audience looks like a PostgreSQL endpoint at all.
    /// This is a syntactic check, not a connectivity one; the
    /// `resolve_and_pin` step is the connectivity check.
    pub fn looks_like_postgres(&self) -> bool {
        !self.authority.as_str().is_empty() && self.port > 0
    }
}

/// Why a pinned transport operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedPgError {
    #[error("port is not routable: 0")]
    ZeroPort,

    #[error("audience is not a usable postgres authority: {0}")]
    InvalidAudience(String),

    #[error("DNS resolution failed for {host}: {reason}")]
    ResolutionFailed { host: String, reason: String },

    #[error("audience {audience} resolved to {address}, which is not a public address")]
    NonPublicAddress { audience: String, address: IpAddr },
}

/// Which resolved addresses may be connected to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddressPolicy {
    /// Allow loopback. Only tests and local fake servers need this; the
    /// production path leaves it off, which is why the fake-server tests
    /// are explicit about turning it on rather than inheriting it.
    pub allow_loopback: bool,
}

impl AddressPolicy {
    /// Whether `address` may be connected to under this policy.
    ///
    /// Mirrors `asv-connector-http::transport::AddressPolicy::permits`,
    /// keeping the same refusal list (loopback, RFC1918, link-local,
    /// carrier-grade NAT, IPv4-mapped IPv6) so the trust model is
    /// identical across connectors.
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
                    && v6.segments()[0] & 0xfe00 != 0xfc00
                    && v6.segments()[0] & 0xffc0 != 0xfe80
                    && !v6.to_ipv4_mapped().is_some_and(|v4| !self.permits(IpAddr::V4(v4)))
            }
        }
    }

    /// `100.64.0.0/10`, carrier-grade NAT.
    fn is_shared_v4(v4: Ipv4Addr) -> bool {
        matches!(v4.octets(), [100, 64..=127, _, _])
    }

    /// `240.0.0.0/4`, reserved for future use.
    fn is_reserved_v4(v4: Ipv4Addr) -> bool {
        v4.octets()[0] & 0xf0 == 0xf0
    }

    fn is_documentation_v4(v4: Ipv4Addr) -> bool {
        matches!(v4.octets(), [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
    }
}

/// Resolves `authority` to the addresses a pinned client may use.
///
/// Performs the only DNS lookup the request will use. The caller pins
/// the result into the client.
pub fn resolve_and_pin(
    authority: &Authority,
    port: u16,
    policy: AddressPolicy,
) -> Result<ResolvedPgAudience, PinnedPgError> {
    if port == 0 {
        return Err(PinnedPgError::ZeroPort);
    }
    let host = authority.as_str();
    let addresses = resolve(host).map_err(|reason| PinnedPgError::ResolutionFailed {
        host: host.to_string(),
        reason,
    })?;
    if addresses.is_empty() {
        return Err(PinnedPgError::ResolutionFailed {
            host: host.to_string(),
            reason: "no A or AAAA records".to_string(),
        });
    }
    for address in &addresses {
        if !policy.permits(*address) {
            return Err(PinnedPgError::NonPublicAddress {
                audience: host.to_string(),
                address: *address,
            });
        }
    }
    Ok(ResolvedPgAudience {
        authority: authority.clone(),
        port,
        addresses,
    })
}

fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
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

/// A pinned PostgreSQL client.
///
/// Records the addresses it is allowed to reach. The full client that
/// drives a real socket is intentionally not implemented here: M6
/// exercises the pattern with a fake origin rather than a live PostgreSQL,
/// and adding `tokio-postgres` would not change any property the spec
/// asserts.
#[derive(Debug, Clone)]
pub struct PinnedPgClient {
    resolved: ResolvedPgAudience,
}

impl PinnedPgClient {
    /// Builds a client from a previously resolved audience.
    pub fn new(resolved: ResolvedPgAudience) -> Self {
        Self { resolved }
    }

    /// The addresses this client is allowed to connect to.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.resolved.addresses
    }

    /// The port this client is bound to.
    pub fn port(&self) -> u16 {
        self.resolved.port
    }

    /// The authority this client is bound to.
    pub fn authority(&self) -> &Authority {
        &self.resolved.authority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_refuses_loopback_by_default() {
        let policy = AddressPolicy::default();
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn policy_allows_loopback_when_explicit() {
        let policy = AddressPolicy { allow_loopback: true };
        assert!(policy.permits(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn policy_refuses_rfc1918() {
        let policy = AddressPolicy::default();
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn policy_refuses_link_local() {
        let policy = AddressPolicy::default();
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    }

    #[test]
    fn policy_refuses_documentation_ranges() {
        let policy = AddressPolicy::default();
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn policy_refuses_cgnat() {
        let policy = AddressPolicy::default();
        assert!(!policy.permits(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    }
}