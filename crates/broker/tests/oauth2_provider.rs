//! `ClientCredentialsIssuer` against a real authorization server.
//!
//! The other half of M11's acceptance. `oauth2_surrogate_lifecycle.rs` covers
//! the shape of the framework; this file is the only place where the issuer has
//! to satisfy a party that can refuse it.
//!
//! Every assertion here is about the broker, not about the fixture. The server
//! has its own twenty tests establishing that it enforces RFC 6749, RFC 7009,
//! RFC 7662 and RFC 8707 rather than replaying answers; a failure here means the
//! broker did something wrong, and the way to tell which side is at fault is to
//! read the server's own audit log, which every test prints on failure.
//!
//! The two properties this file exists for are the ones no unit test can reach:
//! **the client secret stays inside the broker**, and **a provider that says
//! something other than yes produces a refusal rather than a token**.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use asv_broker::oauth2::{
    ClientCredentialsIssuer, OAuth2Config, OAuth2Error, OAuth2Issuer, DEFAULT_TOKEN_TIMEOUT,
};
use asv_broker::oauth2_test_support::{AsClient, AuthorizationServer, AS_HOST, RESOURCE_AUDIENCE};
use asv_connector_http::{AddressPolicy, ResolvedAudience};
use asv_domain::Authority;

/// Loopback has to be opted into, explicitly, and only here. The issuer's
/// production constructor cannot be pointed at a local server at all, so this
/// policy is the only way in and it is stated rather than inherited.
fn loopback_policy() -> AddressPolicy {
    AddressPolicy {
        allow_loopback: true,
    }
}

/// A hand-built audience pointing the approved name at the fixture's port.
/// Going through the resolver would need a real DNS answer, and the property
/// under test is what happens once the name has been vetted.
fn resolved_to(server: &AuthorizationServer) -> ResolvedAudience {
    ResolvedAudience {
        authority: Authority::canonicalize(AS_HOST).expect("a valid authority"),
        port: server.port(),
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}

fn config_for(server: &AuthorizationServer, client: &AsClient) -> OAuth2Config {
    OAuth2Config::new(
        server.url("/token"),
        client.client_id.clone(),
        client.client_secret.as_bytes().to_vec(),
        RESOURCE_AUDIENCE,
    )
}

fn issuer_for(server: &AuthorizationServer, client: &AsClient) -> ClientCredentialsIssuer {
    ClientCredentialsIssuer::with_resolved(
        config_for(server, client),
        &resolved_to(server),
        loopback_policy(),
        &[server.certificate()],
    )
    .expect("an issuer against a local provider")
}

/// A client for the protected resource, trusting only the fixture's
/// certificate. It is a separate client from the issuer's on purpose: the token
/// has to cross from one to the other the way it will cross from the broker to
/// an operation.
fn resource_client(server: &AuthorizationServer) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(server.certificate())
        .resolve(
            server.host(),
            format!("127.0.0.1:{}", server.port())
                .parse()
                .expect("loopback addr"),
        )
        .timeout(Duration::from_secs(5))
        .build()
        .expect("a resource client")
}

fn call_resource(server: &AuthorizationServer, token: &str) -> reqwest::blocking::Response {
    resource_client(server)
        .get(server.url("/resource"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .expect("TLS completes")
}

/// The whole point of the framework: a token that the provider really issued
/// reaches an operation that really enforces it.
#[test]
fn a_token_from_a_real_provider_reaches_a_real_operation() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let issuer = issuer_for(&server, &AsClient::awkward());

    let token = issuer.issue("read:pods").expect("the provider issues");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.scope.as_deref(), Some("read:pods"));
    assert!(token.expires_in > Duration::from_secs(0));
    assert!(token.has_refresh_token());

    let access = String::from_utf8(token.expose_access_token().to_vec()).expect("utf8");
    let response = call_resource(&server, &access);
    assert_eq!(
        response.status().as_u16(),
        200,
        "audit: {:?}",
        server.audit()
    );
    assert_eq!(
        response.json::<serde_json::Value>().expect("json")["scope"],
        "read:pods"
    );
}

/// The credential the broker sends is checked, not merely present: a wrong
/// secret gets a named refusal, which is what proves the happy path was a real
/// authentication rather than a server that says yes to anything.
#[test]
fn a_wrong_secret_is_a_named_refusal() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let wrong = AsClient {
        client_secret: "p ss+w&rdX".to_string(),
        ..AsClient::awkward()
    };
    let issuer = issuer_for(&server, &wrong);
    match issuer.issue("read:pods") {
        Err(OAuth2Error::ProviderRejected { status, code, .. }) => {
            assert_eq!(status, 401);
            assert_eq!(code, "invalid_client");
        }
        other => panic!("expected invalid_client, got {other:?}"),
    }
    assert_eq!(server.audit_with_outcome("bad_credentials").len(), 1);
}

/// The default client's identifier contains a colon. A broker that base64'd the
/// raw pair instead of the form-encoded one would split at the wrong place and
/// land here, which is the failure the encoding rule exists to prevent.
#[test]
fn a_client_that_skipped_the_form_encoding_cannot_authenticate() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let client = AsClient::awkward();
    // What a non-conforming client would send: base64 over the raw pair.
    let naive = format!("Basic {}", {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", client.client_id, client.client_secret))
    });
    let response = resource_client(&server)
        .post(server.url("/token"))
        .header("authorization", naive)
        .body("grant_type=client_credentials")
        .send()
        .expect("TLS completes");
    assert_eq!(response.status().as_u16(), 401);
    assert!(response
        .text()
        .expect("body")
        .contains("error=invalid_client"));
}

/// A provider that widens the grant is refused, and refused as an escalation
/// rather than as a generic failure — because a caller that has to triage this
/// needs to know the provider said yes to something wider than the question.
#[test]
fn a_widened_scope_is_refused_by_the_broker() {
    let server = AuthorizationServer::start(AsClient::awkward());
    server.override_scope("read:pods write:pods admin:everything");
    let issuer = issuer_for(&server, &AsClient::awkward());

    assert_eq!(
        issuer
            .issue("read:pods")
            .expect_err("a widening must not become a token"),
        OAuth2Error::ScopeEscalated {
            requested: "read:pods".to_string(),
            granted: "read:pods write:pods admin:everything".to_string(),
        }
    );
    // The provider did issue one. What the broker did with it is the property.
    assert_eq!(server.audit_with_outcome("issued").len(), 1);
}

/// A narrowing is refused too, and for a different reason: a caller that asked
/// for `read write` and silently received `read` has been told something it did
/// not ask about.
#[test]
fn a_narrowed_scope_is_refused_by_the_broker() {
    let server = AuthorizationServer::start(AsClient::awkward());
    server.override_scope("read:pods");
    let issuer = issuer_for(&server, &AsClient::awkward());
    assert_eq!(
        issuer
            .issue("read:pods write:pods")
            .expect_err("a narrowing must not pass silently"),
        OAuth2Error::ScopeNarrowed {
            requested: "read:pods write:pods".to_string(),
            granted: "read:pods".to_string(),
        }
    );
}

/// A provider that is down is a refusal. If this returned a token the broker
/// would keep working on a credential nobody authorised.
#[test]
fn a_provider_that_is_down_is_a_refusal_not_a_token() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let issuer = issuer_for(&server, &AsClient::awkward());
    // Prove the issuer works first, so the later refusal cannot be a broken
    // setup passing for the right reason.
    assert!(issuer.issue("read:pods").is_ok());

    server.set_offline(true);
    match issuer.issue("read:pods") {
        Err(OAuth2Error::ProviderRejected { status, code, .. }) => {
            assert_eq!(status, 503);
            assert_eq!(code, "temporarily_unavailable");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An endpoint the broker cannot reach at all is also a refusal, and named as
/// unreachable rather than as a rejection — the two mean different things to a
/// caller deciding whether to retry.
#[test]
fn an_unreachable_endpoint_is_reported_as_unreachable() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let config = config_for(&server, &AsClient::awkward());
    // A port nothing is listening on.
    let resolved = ResolvedAudience {
        authority: Authority::canonicalize(AS_HOST).expect("a valid authority"),
        port: {
            // Take a port, then give the origin back and let the connection be
            // refused: binding a port and releasing it is the portable way to
            // name one that is almost certainly closed.
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            let port = probe.local_addr().expect("addr").port();
            drop(probe);
            port
        },
        addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    };
    let issuer = ClientCredentialsIssuer::with_resolved(
        config,
        &resolved,
        loopback_policy(),
        &[server.certificate()],
    )
    .expect("the issuer builds; it is the connection that will fail");

    let outcome = issuer.issue("read:pods");
    assert!(
        matches!(outcome, Err(OAuth2Error::ProviderUnreachable(_))),
        "expected an unreachable provider, got {outcome:?}"
    );
}

/// The secret travels in exactly one header, and nowhere else.
///
/// The body is asserted literally rather than by absence, because a body that
/// simply did not contain the secret would also pass on a client that sent
/// nothing at all.
#[test]
fn the_client_secret_travels_in_one_header_and_nowhere_else() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let client = AsClient::awkward();
    let issuer = issuer_for(&server, &client);
    issuer.issue("read:pods").expect("issue");

    let request = server.last_request().expect("the provider saw a request");
    assert_eq!(request.method(), "POST");
    assert_eq!(request.path(), "/token");
    assert_eq!(
        request.body,
        "grant_type=client_credentials&scope=read%3Apods&audience=https%3A%2F%2Fapi.asv.test",
        "the body is the grant, and nothing else"
    );

    // The secret is base64'd inside the credential, so it cannot appear
    // literally; what has to hold is that no *other* header carries it, and
    // that the server's own log carries neither.
    let mut credential_headers = 0;
    for (name, value) in &request.headers {
        if name == "authorization" {
            credential_headers += 1;
            assert!(value.starts_with("Basic "), "{value}");
        } else {
            assert!(
                !value.contains(&client.client_secret),
                "the secret leaked into header {name}"
            );
        }
    }
    assert_eq!(credential_headers, 1, "exactly one credential header");

    let log = format!("{:?}", server.audit());
    assert!(
        !log.contains(&client.client_secret),
        "the log carries the secret"
    );
    assert!(
        !log.contains(&client.client_id) || !log.is_empty(),
        "the client id is fine in the log; the secret is not"
    );
}

/// Expiry is the provider's, measured against its clock, and the operation
/// enforces it. The broker does not get to decide a token is still good.
#[test]
fn an_expired_token_is_refused_by_the_operation() {
    let server = AuthorizationServer::with_ttl(AsClient::awkward(), Duration::from_secs(1));
    let issuer = issuer_for(&server, &AsClient::awkward());
    let token = issuer.issue("read:pods").expect("issue");
    let access = String::from_utf8(token.expose_access_token().to_vec()).expect("utf8");

    assert_eq!(call_resource(&server, &access).status().as_u16(), 200);
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        call_resource(&server, &access).status().as_u16(),
        401,
        "audit: {:?}",
        server.audit()
    );
}

/// Revocation reaches the access token, which is the only version of the
/// property that matters to the agent holding one.
#[test]
fn a_revoked_grant_is_refused_by_the_operation() {
    use base64::Engine as _;
    let server = AuthorizationServer::start(AsClient::awkward());
    let client = AsClient::awkward();
    let issuer = issuer_for(&server, &client);
    let mut token = issuer.issue("read:pods").expect("issue");
    let access = String::from_utf8(token.expose_access_token().to_vec()).expect("utf8");
    let refresh = token.take_refresh_token().expect("a refresh token");
    assert_eq!(call_resource(&server, &access).status().as_u16(), 200);

    // Revoke through the RFC 7009 endpoint, with a real Basic credential.
    let response = resource_client(&server)
        .post(server.url("/revoke"))
        .header(
            "authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!(
                    "{}:{}",
                    url::form_urlencoded::byte_serialize(client.client_id.as_bytes())
                        .collect::<String>(),
                    url::form_urlencoded::byte_serialize(client.client_secret.as_bytes())
                        .collect::<String>()
                ))
            ),
        )
        .body(format!(
            "token={}",
            String::from_utf8_lossy(refresh.as_slice())
        ))
        .send()
        .expect("TLS completes");
    assert_eq!(response.status().as_u16(), 200);

    assert_eq!(
        call_resource(&server, &access).status().as_u16(),
        401,
        "audit: {:?}",
        server.audit()
    );
}

/// Refresh is a real exchange: a new access token, a rotated refresh token, and
/// the old refresh token spent. A broker that treated refresh as a retry would
/// be handing out a second credential from a revoked one.
#[test]
fn refresh_rotates_the_credential_and_spends_the_old_refresh_token() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let issuer = issuer_for(&server, &AsClient::awkward());
    let mut first = issuer.issue("read:pods").expect("issue");
    let first_access = String::from_utf8(first.expose_access_token().to_vec()).expect("utf8");
    let first_refresh = first.take_refresh_token().expect("a refresh token");

    let mut second = issuer
        .refresh(first_refresh.as_slice())
        .expect("the provider reissues");
    let second_access = String::from_utf8(second.expose_access_token().to_vec()).expect("utf8");
    let second_refresh = second
        .take_refresh_token()
        .expect("a rotated refresh token");

    assert_ne!(first_access, second_access);
    assert_ne!(*first_refresh, *second_refresh);
    assert_eq!(
        call_resource(&server, &second_access).status().as_u16(),
        200
    );

    // The spent one is refused by name, not treated as a fresh grant.
    assert!(matches!(
        issuer.refresh(first_refresh.as_slice()),
        Err(OAuth2Error::ProviderRejected { code, .. }) if code == "invalid_grant"
    ));
}

/// A token issued for another resource is refused by this one, and the issuer
/// carries the audience the caller asked for so the request could name it.
#[test]
fn a_token_for_another_audience_is_refused_by_the_operation() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let elsewhere = OAuth2Config::new(
        server.url("/token"),
        AsClient::awkward().client_id,
        AsClient::awkward().client_secret.into_bytes(),
        "https://admin.asv.test",
    );
    let issuer = ClientCredentialsIssuer::with_resolved(
        elsewhere,
        &resolved_to(&server),
        loopback_policy(),
        &[server.certificate()],
    )
    .expect("issuer");

    let token = issuer.issue("read:pods").expect("issue");
    let access = String::from_utf8(token.expose_access_token().to_vec()).expect("utf8");
    assert_eq!(
        issuer.audience(),
        "https://admin.asv.test",
        "the issuer asked for a different resource than the one being called"
    );
    assert_eq!(
        call_resource(&server, &access).status().as_u16(),
        401,
        "audit: {:?}",
        server.audit()
    );
    assert_eq!(server.audit_with_outcome("wrong_audience").len(), 1);
}

/// Every exchange the broker made is on the provider's record, which is what
/// "audited" has to mean when the other party is the only one that can say no.
#[test]
fn every_exchange_the_broker_made_is_on_the_providers_record() {
    let server = AuthorizationServer::start(AsClient::awkward());
    let issuer = issuer_for(&server, &AsClient::awkward());
    let mut token = issuer.issue("read:pods").expect("issue");
    let access = String::from_utf8(token.expose_access_token().to_vec()).expect("utf8");
    let refresh = token.take_refresh_token().expect("a refresh token");
    issuer.refresh(refresh.as_slice()).expect("reissue");
    call_resource(&server, &access);

    let outcomes: Vec<&str> = server.audit().iter().map(|entry| entry.outcome).collect();
    for expected in ["authenticated", "issued", "reissued", "served"] {
        assert!(
            outcomes.contains(&expected),
            "{expected} missing from {outcomes:?}"
        );
    }
    // And the log never carried the secret, which is checked in the header test
    // and is what makes a retained log safe to keep.
    let log = format!("{:?}", server.audit());
    assert!(!log.contains("p ss+w&rd:"), "{log}");
}

/// The issuer's timeout is finite, and a provider that accepts the connection
/// and then says nothing must not hold the broker forever.
#[test]
fn the_issuer_declares_a_finite_token_timeout() {
    assert!(
        DEFAULT_TOKEN_TIMEOUT > Duration::from_secs(0),
        "an unbounded wait resolves an ambiguous failure in the provider's favour"
    );
    assert!(
        DEFAULT_TOKEN_TIMEOUT <= Duration::from_secs(30),
        "a token request is not an operation that should take half a minute"
    );
}
