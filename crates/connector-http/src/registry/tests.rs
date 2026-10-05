//! Rows for the registry bearer flow.
//!
//! Every row names the mutation that turns it red, in the comment above it.
//! A row that cannot name one is asserting a shape rather than a behaviour,
//! and this module is held to the same standard as the rest of the crate.
//!
//! Two of the rows reach a resolver (`a_realm_that_resolves_to_loopback_is_refused`
//! and `a_vetted_realm_reports_the_addresses_it_was_checked_against`). They use
//! `localhost.localdomain`, which ships with systemd and has been in
//! `/etc/hosts` on every distribution this project targets since RHEL 7. The
//! rows that must not depend on a resolver use a name that has no records, the
//! same trick `an_unresolvable_audience_fails_closed` uses in the transport.

use std::net::{IpAddr, Ipv4Addr};

use asv_domain::AuthorityError;

use super::*;

/// A host that resolves to loopback and has two labels, so it survives
/// `Authority::canonicalize` and reaches the address policy — which is the only
/// interesting way to reach it.
const LOOPBACK_NAME: &str = "localhost.localdomain";

/// The challenge Docker Hub actually answers a pull with. If a change to the
/// parameter scanner stops this from parsing, the parser has stopped
/// describing the thing it exists to describe.
const DOCKER_HUB_CHALLENGE: &str = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull,push""#;

// ---------------------------------------------------------------- the challenge

/// A challenge with no realm says nothing about where to get a token, and a
/// reader that invented a destination would be picking one.
///
/// Mutation: return a challenge with an empty realm instead of `MissingRealm`.
#[test]
fn a_challenge_without_a_realm_is_refused() {
    assert_eq!(
        BearerChallenge::parse(r#"Bearer service="registry.docker.io""#),
        Err(ChallengeError::MissingRealm)
    );
    assert_eq!(
        BearerChallenge::parse("Bearer"),
        Err(ChallengeError::Malformed(
            "no challenge parameters follow the scheme".to_string()
        ))
    );
}

/// Only Bearer is negotiated. A `Basic` challenge names a realm too, and
/// following one is how a client ends up posting a password somewhere.
///
/// Mutation: accept any scheme (`if false`), or compare case-sensitively and
/// refuse the lowercase spelling registries may legally send.
#[test]
fn a_challenge_that_is_not_bearer_is_refused() {
    for (header, scheme) in [
        (r#"Basic realm="https://auth.docker.io/token""#, "Basic"),
        (
            r#"Negotiate realm="https://auth.docker.io/token""#,
            "Negotiate",
        ),
        (r#"Bearer2 realm="https://auth.docker.io/token""#, "Bearer2"),
    ] {
        assert_eq!(
            BearerChallenge::parse(header),
            Err(ChallengeError::NotBearer {
                found: scheme.to_string()
            }),
            "{header} must be refused"
        );
    }
    // RFC 7235 schemes are case-insensitive, so this one has to be read.
    let lower = BearerChallenge::parse(r#"bearer realm="https://auth.docker.io/token""#)
        .expect("the scheme is case-insensitive");
    assert_eq!(lower.realm(), "https://auth.docker.io/token");
}

/// A repeated parameter means the sender is choosing which of two values this
/// side honours. A reader that takes the last one is following the sender.
///
/// Mutation: delete the `slot.is_some()` guard, so the last value wins
/// silently and a `realm` that redirects the token request passes.
#[test]
fn a_repeated_parameter_is_refused_rather_than_last_one_winning() {
    for (header, parameter) in [
        (
            r#"Bearer realm="https://a.example/token",realm="https://b.example/token""#,
            "realm",
        ),
        (
            r#"Bearer realm="https://a.example/token",service="x",service="y""#,
            "service",
        ),
        (
            r#"Bearer realm="https://a.example/token",scope="repository:a:pull",scope="repository:b:pull""#,
            "scope",
        ),
    ] {
        assert_eq!(
            BearerChallenge::parse(header),
            Err(ChallengeError::RepeatedParameter { parameter }),
            "{header} must be refused"
        );
    }
}

/// An unclosed quote means the header did not finish being what it claims to
/// be. Reading to end-of-input instead treats the sender's truncation as
/// permission.
///
/// Mutation: accept the run to end-of-input as though the quote were closed.
#[test]
fn an_unclosed_quote_is_refused() {
    for header in [
        r#"Bearer realm="https://auth.docker.io/token"#,
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io"#,
    ] {
        assert!(
            matches!(
                BearerChallenge::parse(header),
                Err(ChallengeError::Malformed(_))
            ),
            "{header} must be refused"
        );
    }
}

/// A control character *inside* a value is the case that depends on the
/// guard. Without it the realm is read verbatim, control and all, and the
/// header parses.
///
/// The campaign found this by asking the other question first. A version of
/// this row used a trailing CRLF, and it stayed green with the `is_control`
/// guard removed — because the parameter scanner refuses `\r` as a malformed
/// parameter name, not because of the guard. The row was measuring a refusal
/// that had nothing to do with the code it named.
///
/// Mutation: delete the `is_control` guard.
#[test]
fn a_control_character_inside_a_value_is_refused() {
    for header in [
        "Bearer realm=\"https://auth.docker.io/to\u{1}ken\"",
        "Bearer realm=\"https://auth.docker.io/token\",service=\"regi\u{7}ntry\"",
    ] {
        assert!(
            matches!(
                BearerChallenge::parse(header),
                Err(ChallengeError::Malformed(_))
            ),
            "{header:?} must be refused"
        );
    }
}

/// A CRLF after the challenge is a smuggled header, and it never reaches the
/// realm.
///
/// This row records the outcome rather than the mechanism, and the campaign is
/// why that distinction is written down: with the `is_control` guard removed
/// the header is *still* refused, but by the parameter scanner naming `\r` a
/// malformed parameter name. Both are refusals and only one is the one this
/// module documents, so the row says which one it is relying on instead of
/// implying the guard does the work.
///
/// Filed as compound: the mutation that turns it red is not a single line, and
/// the row that does depend on the guard is the one above.
#[test]
fn a_trailing_crlf_never_reaches_the_realm() {
    let error =
        BearerChallenge::parse("Bearer realm=\"https://auth.docker.io/token\"\r\nX-Injected: 1")
            .expect_err("a smuggled header is refused");
    assert!(matches!(error, ChallengeError::Malformed(_)), "{error}");
    assert!(
        !error.to_string().contains("auth.docker.io"),
        "the refusal must not quote the realm back, in case a header value ends up in a log: {error}"
    );
}

/// The shape registries really send, read end to end. Every other row in this
/// module is a refusal, and a set of refusals that also refuses the real thing
/// is a broken connector rather than a strict one.
#[test]
fn the_challenge_docker_hub_sends_is_read() {
    let challenge =
        BearerChallenge::parse(DOCKER_HUB_CHALLENGE).expect("docker hub's challenge reads");
    assert_eq!(challenge.realm(), "https://auth.docker.io/token");
    assert_eq!(challenge.service(), Some("registry.docker.io"));
    assert_eq!(
        challenge.requested_scope(),
        Some("repository:library/alpine:pull,push")
    );
}

/// Docker Hub serves from `registry-1.docker.io` and names its token service
/// `registry.docker.io`. Any code that infers one from the other asks the
/// wrong audience for a token.
///
/// Mutation: derive the service from the realm's host instead of reading the
/// `service` parameter the registry sent.
#[test]
fn the_service_is_not_the_registry_host() {
    let challenge = BearerChallenge::parse(DOCKER_HUB_CHALLENGE).expect("reads");
    let realm_host = Url::parse(challenge.realm())
        .expect("the realm parses")
        .host_str()
        .expect("a realm has a host")
        .to_string();
    assert_eq!(realm_host, "auth.docker.io");
    assert_eq!(challenge.service(), Some("registry.docker.io"));
    assert_ne!(challenge.service(), Some(realm_host.as_str()));
}

// -------------------------------------------------------------------- the realm

/// A realm reached over anything but https is a bearer token in the clear,
/// handed to whoever answers.
///
/// Mutation: drop the scheme check, so `http://auth.docker.io/token` is
/// followed with the token in the request.
#[test]
fn a_plaintext_realm_is_refused() {
    for realm in [
        "http://auth.docker.io/token",
        "file:///etc/passwd",
        "ftp://auth.docker.io/token",
    ] {
        assert!(
            matches!(
                Realm::vet(realm, AddressPolicy::default()),
                Err(RealmError::NotHttps { .. })
            ),
            "{realm} must be refused"
        );
    }
}

/// Credentials in the realm URL are the classic way a client ends up posting a
/// password it was never asked to hold.
///
/// Mutation: drop the userinfo check. `Authority::canonicalize` happens to
/// catch the same string later, so this row is the one that names the problem
/// rather than the one that catches it.
#[test]
fn a_realm_carrying_credentials_is_refused() {
    for realm in [
        "https://user:pass@auth.docker.io/token",
        "https://token@auth.docker.io/token",
    ] {
        let error = Realm::vet(realm, AddressPolicy::default())
            .expect_err("a realm with credentials is never a destination");
        assert!(
            matches!(
                error,
                RealmError::Refused {
                    what: "a username or password"
                }
            ),
            "{realm} produced {error}"
        );
    }
}

/// A query is where a relay would put its own identifier, and the token
/// request would then carry it to a host the registry did not name.
///
/// Mutation: drop the query check.
#[test]
fn a_realm_carrying_a_query_is_refused() {
    let error = Realm::vet(
        "https://auth.docker.io/token?service=evil",
        AddressPolicy {
            allow_loopback: true,
        },
    )
    .expect_err("a query is refused before any lookup");
    assert!(
        matches!(error, RealmError::Refused { what: "a query" }),
        "{error}"
    );
}

/// A fragment is never sent to a server, so a realm carrying one means the
/// sender is confused about what it is sending — or is relying on the two sides
/// disagreeing about it.
///
/// Mutation: drop the fragment check.
#[test]
fn a_realm_carrying_a_fragment_is_refused() {
    let error = Realm::vet(
        "https://auth.docker.io/token#admin",
        AddressPolicy {
            allow_loopback: true,
        },
    )
    .expect_err("a fragment is refused");
    assert!(
        matches!(error, RealmError::Refused { what: "a fragment" }),
        "{error}"
    );
}

/// Only the HTTPS port is a token endpoint. Any other port turns "the host the
/// registry named" into "the host the registry named, on a port it chose",
/// which is enough to reach a listener the policy never vetted.
///
/// Mutation: accept any port.
#[test]
fn a_realm_on_another_port_is_refused() {
    let error = Realm::vet(
        "https://auth.docker.io:8443/token",
        AddressPolicy {
            allow_loopback: true,
        },
    )
    .expect_err("port 8443 is not a token endpoint");
    assert!(
        matches!(
            error,
            RealmError::UnexpectedPort {
                port: 8443,
                expected: 443
            }
        ),
        "{error}"
    );
    // The default port written out is the same destination, and must not be
    // refused for spelling it.
    assert!(Realm::vet(
        "https://auth.docker.io:443/token",
        AddressPolicy {
            allow_loopback: true
        }
    )
    .is_ok());
}

/// A realm naming an address is a realm naming a target directly, and the
/// useful ones to refuse first are loopback and the cloud metadata address.
///
/// Two different rules catch them, and which one fires is worth pinning: a
/// bracketed IPv6 literal never reaches the resolver because
/// `Authority::canonicalize` refuses it, while an IPv4 literal is a
/// well-formed four-label name and is caught by the address policy itself.
///
/// Mutation: return the `Authority` before resolving it, so
/// `https://169.254.169.254/` becomes a destination the moment the scheme
/// check is passed.
#[test]
fn an_address_literal_realm_is_refused() {
    // The production policy: loopback off, as everywhere else.
    for (realm, address) in [
        ("https://169.254.169.254/token", "169.254.169.254"),
        ("https://127.0.0.1/token", "127.0.0.1"),
        ("https://10.0.0.5/token", "10.0.0.5"),
    ] {
        let error = Realm::vet(realm, AddressPolicy::default())
            .expect_err("an address literal is not a public token endpoint");
        assert!(
            matches!(
                error,
                RealmError::Unreachable(TransportError::NonPublicAddress { .. })
            ),
            "{realm} produced {error}"
        );
        assert!(
            error.to_string().contains(address),
            "{realm} produced {error}"
        );
    }

    // A bracketed literal is refused earlier, by name rather than by address:
    // it carries a colon, so it never becomes a four-label host.
    let ipv6 = Realm::vet("https://[fd00::1]/token", AddressPolicy::default())
        .expect_err("a bracketed literal is not a host name");
    assert!(
        matches!(
            ipv6,
            RealmError::UnusableHost(AuthorityError::NotBareHost { .. })
        ),
        "{ipv6}"
    );
}

/// The refusal above is the address policy, not a rule about literals: a policy
/// that permits the address permits the realm. Without this row the previous
/// one would also pass if `Realm::vet` simply refused every literal, which
/// would look identical and mean something much weaker.
///
/// Mutation: refuse an address literal structurally, whatever the policy says.
#[test]
fn the_same_literal_is_vetted_by_the_policy_and_not_by_its_shape() {
    let permitted = AddressPolicy {
        allow_loopback: true,
    };
    let realm = Realm::vet("https://127.0.0.1/token", permitted).expect("the policy permits it");
    assert_eq!(realm.authority().as_str(), "127.0.0.1");
    assert_eq!(
        realm.resolved().addresses,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
    assert!(Realm::vet("https://127.0.0.1/token", AddressPolicy::default()).is_err());
}

/// A bare label is not a routable authority, and `localhost` is the one an
/// attacker reaches for first. Refusing it here means it never reaches the
/// resolver at all.
///
/// Mutation: drop the `SingleLabel` refusal, or canonicalize without it, so
/// `localhost` resolves to loopback and the address policy has to catch it
/// later — which it does, but only if the caller remembered the policy.
#[test]
fn a_bare_label_realm_is_refused() {
    let error = Realm::vet(
        "https://localhost/token",
        AddressPolicy {
            allow_loopback: true,
        },
    )
    .expect_err("a bare label is not routable");
    assert!(
        matches!(
            error,
            RealmError::UnusableHost(AuthorityError::SingleLabel { .. })
        ),
        "{error}"
    );
}

/// The join: a realm whose host is a perfectly well-formed name that resolves
/// to loopback is still refused, and refused by the same policy the rest of
/// the transport uses. This is the row that a `Url` in place of a `Realm`
/// would fail, because a `Url` has no opinion about where it points.
///
/// Mutation: return the `Authority` without resolving it, or pass
/// `AddressPolicy::default()` with `allow_loopback` forced on.
#[test]
fn a_realm_that_resolves_to_loopback_is_refused() {
    let error = Realm::vet(
        &format!("https://{LOOPBACK_NAME}/token"),
        AddressPolicy::default(),
    )
    .expect_err("loopback is not a token endpoint in production");
    assert!(
        matches!(
            error,
            RealmError::Unreachable(TransportError::NonPublicAddress { .. })
        ),
        "{error}"
    );
}

/// And the same vetting reaches a `Realm` when the policy permits the address,
/// so the row above is a policy decision rather than a permanent refusal of
/// every realm.
///
/// Mutation: refuse on a structural rule that fires for any host, which would
/// make the previous row pass for the wrong reason.
#[test]
fn a_vetted_realm_reports_the_addresses_it_was_checked_against() {
    let policy = AddressPolicy {
        allow_loopback: true,
    };
    let realm = Realm::vet(&format!("https://{LOOPBACK_NAME}/token"), policy).expect("permitted");
    assert_eq!(realm.authority().as_str(), LOOPBACK_NAME);
    assert_eq!(realm.path(), "/token");
    assert_eq!(realm.resolved().port, 443);
    assert!(
        !realm.resolved().addresses.is_empty(),
        "a vetted realm carries the addresses it was checked against"
    );
    for address in &realm.resolved().addresses {
        assert!(policy.permits(*address), "{address} was vetted");
    }
}

// --------------------------------------------------------------------- the scope

/// The scope asked for is computed from the operation. The challenge names a
/// wider one on every pull this project has ever seen, and obeying it hands a
/// read a token that can also write.
///
/// Mutation: give `scope_to_request` the challenge and read
/// `requested_scope()` — the widening then has to be written down somewhere to
/// survive review.
#[test]
fn the_scope_asked_for_comes_from_the_operation_and_not_the_challenge() {
    let challenge = BearerChallenge::parse(DOCKER_HUB_CHALLENGE).expect("reads");
    assert_eq!(
        challenge.requested_scope(),
        Some("repository:library/alpine:pull,push"),
        "the fixture is only meaningful while the challenge still asks for both"
    );

    let repository = RepositoryName::parse("library/alpine").expect("valid");
    let asked = scope_to_request(RegistryOperation::Pull, &repository);
    assert_eq!(asked.as_str(), "repository:library/alpine:pull");
    assert!(
        !asked.as_str().contains("push"),
        "a pull must not ask for a push"
    );
}

/// An operation names exactly one action, so there is no input that can turn a
/// pull into a pull-and-push without someone writing it.
///
/// Mutation: have `for_operation` add every action instead of the one named.
#[test]
fn an_operation_names_exactly_one_action() {
    for (operation, action) in [
        (RegistryOperation::Pull, "pull"),
        (RegistryOperation::Push, "push"),
    ] {
        let repository = RepositoryName::parse("library/alpine").expect("valid");
        let scope = RegistryScope::for_operation(operation, repository);
        assert_eq!(scope.actions().len(), 1);
        assert!(scope.actions().contains(action));
        assert_eq!(
            scope.as_str(),
            format!("repository:library/alpine:{action}")
        );
    }
}

/// A scope reads `repository:<name>:<actions>`, so a name containing `:` ends
/// the name early and everything after it is read as actions. This is the
/// injected-scope attack, and the grammar is what stops it.
///
/// Mutation: check the name with a rule that tolerates `:` — a prefix check, a
/// "no whitespace" check, or `split(':').count() <= 3`.
#[test]
fn a_repository_name_cannot_inject_actions_into_a_scope() {
    for hostile in [
        "alpine:pull,push",
        "alpine:push,repository:admin/secret:pull",
        "alpine:",
        "alpine:registry:catalog:*",
        "alpine\n:push",
        "alpine%3Apush",
        "alpine :pull",
    ] {
        assert!(
            RepositoryName::parse(hostile).is_err(),
            "{hostile:?} must not become a repository name"
        );
    }
    // The scope a naive concatenation would have produced: two scopes, the
    // second of which belongs to somebody else. It does not read back as one.
    let naive = format!(
        "repository:{}:pull",
        "alpine:push,repository:admin/secret:pull"
    );
    assert!(
        naive.contains("repository:admin/secret:pull"),
        "the fixture still shows the attack shape"
    );
    assert!(
        RegistryScope::parse(&naive).is_err(),
        "and that shape does not read back as a single scope"
    );
}

/// Names the distribution specification does not allow are refused before
/// they can be quoted into a scope, including the near-misses that a hand-
/// written check lets through.
///
/// Each case names the *reason*, not merely that a refusal happened. An earlier
/// version of this row only asserted `is_err()`, and a campaign run against it
/// found a mutation that turned the trailing-separator refusal into a different
/// refusal — still an error, so still green, which is exactly the kind of
/// accidental survival this row is supposed to make impossible.
///
/// Mutation: relax any single rule in `check_component` — the uppercase, the
/// trailing separator, the empty component, the over-long name.
#[test]
fn a_repository_name_outside_the_spec_is_refused() {
    fn kind(error: &ScopeError) -> &'static str {
        match error {
            ScopeError::EmptyName => "empty",
            ScopeError::NameTooLong { .. } => "too long",
            ScopeError::NameNotAscii => "non-ascii",
            ScopeError::EmptyComponent => "empty component",
            ScopeError::TrailingSeparator { .. } => "trailing separator",
            ScopeError::NameCharacter { .. } => "character",
            _ => "other",
        }
    }

    for (hostile, expected) in [
        ("", "empty"),
        ("/alpine", "empty component"),
        ("alpine/", "empty component"),
        ("library//alpine", "empty component"),
        ("Alpine", "character"),
        ("al-pine-", "trailing separator"),
        ("al_pine_", "trailing separator"),
        ("al pine", "character"),
        ("alpine@evil", "character"),
        ("alpine?x=1", "character"),
        ("alpine#f", "character"),
        ("alpine%2f", "character"),
        ("alpine..x", "character"),
        ("alpine.", "trailing separator"),
        ("alpiñe", "non-ascii"),
    ] {
        let error = match RepositoryName::parse(hostile) {
            Ok(_) => panic!("{hostile:?} must be refused"),
            Err(e) => e,
        };
        assert_eq!(
            kind(&error),
            expected,
            "{hostile:?} was refused for the wrong reason: {error}"
        );
    }

    // And the near-misses that *are* legal, so a grammar tightened into
    // uselessness is caught by the same row.
    for legal in [
        "al-pine",
        "ali__ne",
        "ali---ne",
        "alpine_x",
        "library/alpine",
        "a/b/c",
        "0",
        "a0",
        "registry.example.com/team/app",
    ] {
        assert!(
            RepositoryName::parse(legal).is_ok(),
            "{legal:?} is legal per the distribution spec"
        );
    }

    // Over-long, by one byte and at the limit.
    let long = "a".repeat(MAX_REPOSITORY_NAME + 1);
    assert!(matches!(
        RepositoryName::parse(&long),
        Err(ScopeError::NameTooLong { .. })
    ));
    assert!(RepositoryName::parse(&"a".repeat(MAX_REPOSITORY_NAME)).is_ok());
}

/// A scope read off the wire survives the same grammar a name written by this
/// side does, so a token endpoint cannot report a grant for a name that could
/// never have been asked for.
///
/// Mutation: `RegistryScope::parse` splitting on the first colon instead of
/// the last, which turns `repository:alpine:pull` into name `alpine:pull` and
/// accepts an injected one.
#[test]
fn a_scope_read_off_the_wire_goes_through_the_same_grammar() {
    assert_eq!(
        RegistryScope::parse("repository:library/alpine:pull")
            .expect("valid")
            .as_str(),
        "repository:library/alpine:pull"
    );
    assert_eq!(
        RegistryScope::parse("repository:alpine:pull,push")
            .expect("valid")
            .as_str(),
        "repository:alpine:pull,push"
    );
    for hostile in [
        "repository:alpine:pull,",
        "repository:alpine:",
        "repository:",
        "repository:alpine",
        "repository:alpine:pull,repository:admin:pull",
    ] {
        assert!(
            RegistryScope::parse(hostile).is_err(),
            "{hostile:?} must be refused"
        );
    }
    // A scope for something that is not a repository is not silently treated as
    // one.
    assert!(matches!(
        RegistryScope::parse("registry:catalog:*"),
        Err(ScopeError::NotARepositoryScope { .. })
    ));
}

/// The effective scope is the intersection. A grant wider than the operation is
/// a ceiling, and taking the ceiling is how a pull becomes a write.
///
/// Mutation: return `granted.clone()` instead of the intersection.
#[test]
fn the_effective_scope_is_the_intersection_and_not_the_wider_one() {
    let required = RegistryScope::parse("repository:alpine:pull").expect("valid");
    let granted = RegistryScope::parse("repository:alpine:pull,push").expect("valid");
    let effective = narrow(&required, &granted).expect("the grant covers the pull");
    assert_eq!(effective.as_str(), "repository:alpine:pull");
    assert!(
        !effective.as_str().contains("push"),
        "the extra action must not survive the narrowing"
    );
    // Order in the grant is not order in the request.
    let granted_reordered = RegistryScope::parse("repository:alpine:push,pull").expect("valid");
    assert_eq!(
        narrow(&required, &granted_reordered)
            .expect("covers")
            .as_str(),
        "repository:alpine:pull"
    );
}

/// A grant that does not cover the operation is refused, including the
/// reversed case where the grant is wider in the name and narrower in the
/// action.
///
/// Mutation: drop the superset check, or check containment the other way round.
#[test]
fn a_grant_that_does_not_cover_the_operation_is_refused() {
    let required = RegistryScope::parse("repository:alpine:push").expect("valid");
    let granted = RegistryScope::parse("repository:alpine:pull").expect("valid");
    assert_eq!(
        narrow(&required, &granted),
        Err(ScopeError::InsufficientGrant {
            missing: "push".to_string()
        })
    );
    let required_both = RegistryScope::parse("repository:alpine:pull,push").expect("valid");
    assert_eq!(
        narrow(&required_both, &granted),
        Err(ScopeError::InsufficientGrant {
            missing: "push".to_string()
        }),
        "a grant that covers one of two needed actions covers neither operation"
    );
}

/// A token for one repository is not a token for another, and the refusal names
/// both so an audit record can say which confused deputy was in play.
///
/// Mutation: compare only the actions, or only the `repository:` prefix.
#[test]
fn a_grant_for_another_repository_is_refused() {
    let required = RegistryScope::parse("repository:library/alpine:pull").expect("valid");
    for hostile in [
        "repository:alpine:pull",
        "repository:library/other:pull",
        "library/alpine:pull",
    ] {
        let granted = match RegistryScope::parse(hostile) {
            Ok(g) => g,
            // `library/alpine:pull` is not a repository scope at all, which is
            // a refusal too — just an earlier one.
            Err(_) => continue,
        };
        assert!(
            matches!(
                narrow(&required, &granted),
                Err(ScopeError::WrongRepository { .. })
            ),
            "{hostile} must not cover {required}"
        );
    }
    assert!(narrow(
        &required,
        &RegistryScope::parse("repository:library/alpine:pull").expect("valid")
    )
    .is_ok());
}

/// A token response is read for its scope and nothing else. The body holds the
/// token, and the scope this returns cannot hold it — the return type has no
/// field to put one in, and the rendered value does not contain one.
///
/// Mutation: return a value that formats the body, or copy the token into a
/// field on the way through.
#[test]
fn a_token_response_yields_its_scope_and_never_its_token() {
    let body = r#"{"token":"eyJhbGciOi.super.secret","access_token":"same.secret.again","expires_in":300,"issued_at":"2026-01-01T00:00:00Z","scope":"repository:library/alpine:pull"}"#;
    let scope = granted_scope_from_token_response(body).expect("the scope reads");
    assert_eq!(scope.as_str(), "repository:library/alpine:pull");

    let rendered = format!("{scope} {scope:?}");
    for secret in ["super.secret", "same.secret.again", "eyJhbGciOi"] {
        assert!(
            !rendered.contains(secret),
            "the token leaked into the scope's rendering: {rendered}"
        );
    }
}

/// And a response whose grant is wider than the operation is still only a
/// ceiling: the parsed grant feeds the narrowing, and the narrower of the two
/// is what comes out.
///
/// Mutation: use the parsed grant directly instead of narrowing it.
#[test]
fn a_wide_grant_from_the_token_endpoint_is_still_narrowed() {
    let body = r#"{"token":"secret-value","scope":"repository:library/alpine:pull,push,delete"}"#;
    let granted = granted_scope_from_token_response(body).expect("the scope reads");
    let required = scope_to_request(
        RegistryOperation::Pull,
        &RepositoryName::parse("library/alpine").expect("valid"),
    );
    let effective = narrow(&required, &granted).expect("the grant covers the pull");
    assert_eq!(effective.as_str(), "repository:library/alpine:pull");
    assert!(
        !effective.as_str().contains("delete"),
        "an action nobody asked for must not survive"
    );
}

/// A response with no readable scope is a refusal, not a default. Assuming full
/// grant because the endpoint stayed quiet is the shape of the bug this whole
/// module exists to prevent.
///
/// Mutation: return the required scope when the response has none.
#[test]
fn a_token_response_without_a_scope_is_refused() {
    for body in [
        r#"{"token":"secret-value"}"#,
        r#"{"token":"secret-value","scope":null}"#,
        r#"{"token":"secret-value","scope":""}"#,
        r#"not json at all"#,
        r#"{"token":"secret-value","scope":"registry:catalog:*"}"#,
    ] {
        assert!(
            granted_scope_from_token_response(body).is_err(),
            "{body} must be refused rather than treated as a grant"
        );
    }
}
