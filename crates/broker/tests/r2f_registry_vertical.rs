//! R2.F.3 — the registry vertical: a declaration, a session, and two halves of
//! an OCI pull.
//!
//! R2.F.3a put `Action::RegistryPull` and `Resource::Registry` in the policy
//! crate, and R2.F.3b-1 put `RegistryDeclarations` in the broker. Neither was
//! reachable: an agent had no verb that ended at a registry, and no session
//! could name one. This file is the part that makes them reachable, and — more
//! to the point — the part that makes the *property* observable.
//!
//! # The property under test
//!
//! **An agent chooses the repository; the deployment chooses the host.**
//!
//! Every other brokered operation in this codebase reaches an audience that is
//! either a compile-time constant (`GITHUB_AUTHORITY`) or a declared
//! destination (`pg_destinations`). A registry is the first one where the
//! request carries the host as a field, and that field is a **selector**, not a
//! destination. The whole design rests on the selector being unable to become a
//! destination, so most of this file is about the two ways that could fail:
//! the string reaching `resolve_and_pin` (a lookalike host), or the string
//! reaching the resource Cedar evaluates (a rule that inverts).
//!
//! The second property, added because the first one alone is easy to fake, is
//! that the **surrogate and the declaration must name the same credential**.
//! Both halves of the grant are separate statements and either alone is
//! insufficient — see `a_surrogate_for_another_credential_serves_no_registry`.
//!
//! # What is real here, and what is not
//!
//! Real: `BrokerState` dispatch, the policy gate, a real `VaultStore` and the
//! real `VaultSecretPort`, the real `RegistryClient`, a real Registry v2 `401`,
//! a real token exchange over TLS, and a real retry. The declarations go
//! through `registry_declaration::load`, the same file-reading path an operator
//! uses, so a row cannot pass against a declaration the product cannot parse.
//!
//! Not real: Docker Hub. The origins are local TLS servers under
//! `localhost.localdomain`, which is also the **declared** authority — the
//! declaration names the host, so the test's host has to be the one the
//! operator declared.
//!
//! # Every row names the mutation that would make it red
//!
//! A row whose mutation is "someone changes something" is not a row.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use asv_broker::{handle, BrokerState, ConnectorFactory, VaultSecretPort};
use asv_connector_http::fake_origin::{Observed, OriginResponse, TlsOrigin};
use asv_connector_http::registry::client::{RegistryClient, RegistryError};
use asv_connector_http::{AddressPolicy, Certificate, GithubClient, ResolvedAudience, SecretPort};
use asv_connector_pg::{PgError, PostgresClient};
use asv_domain::{AgentSessionId, Authority, CredentialId, SecretBytes};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};
use asv_policy::PolicyEngine;
use asv_vault::{KdfParams, VaultKey, VaultStore};

/// The real credential. It must never appear in anything an agent can see.
///
/// A registry-shaped password on purpose: a canary that did not look like the
/// thing the connector would send would let a leak row pass by matching a
/// shape nothing in the product ever produces.
const CANARY: &str = "hunter2-the-real-registry-password";

/// A canonical vault id, spelled the way `asv credentials` prints it.
const CRED: &str = "3f7c1d92-4a6b-4c1e-9d3f-2b8e5a7c0d14";

/// A *second* credential, in the vault, that no declaration serves.
///
/// Present so a row can mint a surrogate for it and ask for a registry. If the
/// vault held only one credential the row would be untestable, because the
/// interesting question is what happens when two valid credentials exist.
const OTHER_CRED: &str = "b1d2e3f4-5a6b-4c1e-9d3f-2b8e5a7c0d99";

/// The declared authority. Two labels because `Authority::canonicalize` refuses
/// a bare one, and because the origins certify for it.
const NAME: &str = "localhost.localdomain";

/// The repository a pulling agent is asking about.
const REPOSITORY: &str = "library/alpine";

/// A manifest a registry would answer with.
const MANIFEST: &[u8] = br#"{"schemaVersion":2,"layers":[{"digest":"sha256:aa"}]}"#;

/// A blob's real bytes. The digest below is what they actually hash to.
const BLOB: &[u8] = b"the real layer bytes";

/// The sha256 of [`BLOB`], written out.
///
/// A literal rather than computed: a fixture that computed the digest from the
/// same bytes it serves would agree with a client that never checked anything,
/// which is the failure this row exists to catch.
const BLOB_DIGEST: &str = "sha256:33b165b0358616e47f04a318fae5ca7ef8895bff4da61a51804cf5e653f2e2bc";

/// Prepends the permit the mint itself needs.
///
/// `MintSurrogate` is gated by the policy too, under a read verb, so a fixture
/// policy that replaced the default wholesale would refuse to mint and every
/// row would be asserting about a panic. Composing it in means each policy below
/// states only what its row is about, and none of them silently depends on the
/// rest of the default policy still being installed.
fn composed(extra: &str) -> String {
    format!(
        "permit (principal, action == Action::\"github_issue_read\", resource is Api);\n{extra}"
    )
}

/// Permits a pull from any declared registry, and nothing else.
///
/// `resource is Registry` with no attribute predicate, so the repository has
/// to be proven by a *different* row with a narrower policy. A policy that
/// filtered on the repository would make every other row here depend on it and
/// none of them would isolate anything.
const PULL_ANY: &str = r#"
permit (principal, action == Action::"registry_pull", resource is Registry);
"#;

/// Permits a pull from one named repository and no other.
const PULL_ONE_REPOSITORY: &str = r#"
permit (
    principal,
    action == Action::"registry_pull",
    resource is Registry
)
when { resource.repository == "library/alpine" };
"#;

/// Permits a push from any declared registry, and nothing else.
///
/// **Not the same as [`PULL_ANY`] and never combined with it.** A push row that
/// ran under a policy permitting both could not say which permission produced
/// the outcome, and the whole question a write row asks is whether the *push*
/// permission is what let it through.
const PUSH_ANY: &str = r#"
permit (principal, action == Action::"registry_push", resource is Registry);
"#;

/// Permits pushes, which every pull row below must still be refused against.
///
/// Without this row the negatives would have a simpler explanation — "pulls
/// are denied because only pushes were permitted" — than the one they are
/// actually about.
const PUSH_ONLY: &str = r#"
permit (principal, action == Action::"registry_push", resource is Registry);
"#;

/// A factory pointed at local origins.
///
/// Three relaxations, each named where it is made, and each scoped to *how* a
/// host is reached rather than to *whether* it may be. The address policy still
/// runs, still refusing non-loopback, and every other production guard — the
/// realm vetting, the scope narrowing, the digest re-hashing, the credential
/// never being named — runs unmodified. A fixture that turned a security check
/// off would be testing a different product than the one that ships.
struct LocalFactory {
    /// The audience a declared registry resolves to.
    resolved: ResolvedAudience,
    /// Roots for the registry origin and the token origin, in that order.
    roots: Vec<Certificate>,
    /// The token origin's port.
    ///
    /// A field rather than re-derived from a root, so a fixture that silently
    /// pointed the realm at the registry's port would fail loudly instead of
    /// producing a loop this file could not explain.
    realm_port: u16,
}

impl LocalFactory {
    fn new(
        resolved: ResolvedAudience,
        registry_root: Certificate,
        realm_root: Certificate,
        realm_port: u16,
    ) -> Self {
        Self {
            resolved,
            roots: vec![registry_root, realm_root],
            realm_port,
        }
    }

    /// The one relaxation: build a client that trusts the test CAs and reaches
    /// the token endpoint on the test's port.
    ///
    /// `reaching_realm_on` and `reaching_realm_at` are the reason those
    /// builders exist, and they skip the *lookup*, not the policy: the realm is
    /// still vetted for being `https`, for carrying no credentials, and for
    /// naming a host rather than an address. A realm of `http://169.254.169.254/`
    /// still buys nothing.
    fn client(&self, credential: CredentialId, secrets: Arc<dyn SecretPort>) -> RegistryClient {
        RegistryClient::trusting(
            secrets,
            credential.to_wire(),
            AddressPolicy {
                allow_loopback: true,
            },
            self.roots.clone(),
        )
        .reaching_realm_on(self.realm_port)
        .reaching_realm_at(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    }
}

impl ConnectorFactory for LocalFactory {
    fn github(
        &self,
        _audience: Authority,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<GithubClient, asv_connector_http::GithubError> {
        Ok(GithubClient::pinned_to(
            self.resolved.clone(),
            AddressPolicy {
                allow_loopback: true,
            },
            secrets,
        )
        .trusting(vec![self.roots[0].clone()]))
    }

    fn registry(
        &self,
        _audience: Authority,
        credential: CredentialId,
        secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<RegistryClient, RegistryError> {
        Ok(self.client(credential, secrets))
    }

    /// The seam that makes the real authorisation path reachable in a test.
    ///
    /// Production resolves the declared authority through DNS and refuses every
    /// non-public address. A test cannot do that and still point at loopback,
    /// so the trust decision lives here — on the trait, where the rest of the
    /// broker can see it — and this row returns the origin the declaration
    /// named.
    ///
    /// Note what this method does **not** do: it does not read a host from
    /// anywhere. It is handed the declared authority and returns it. A factory
    /// that resolved a *different* name would be reintroducing the exact escape
    /// the declaration closed.
    fn resolve_registry(&self, audience: &Authority) -> Result<ResolvedAudience, RegistryError> {
        assert_eq!(
            audience.as_str(),
            NAME,
            "the broker resolved an authority the declaration does not name: {audience}"
        );
        Ok(self.resolved.clone())
    }

    fn postgres(
        &self,
        audience: Authority,
        database: String,
        role: String,
        _secrets: Arc<dyn asv_connector_http::SecretPort>,
    ) -> Result<PostgresClient, PgError> {
        Ok(PostgresClient::new(audience, database, role))
    }
}

/// A broker with a real vault, a real declaration file and real origins.
struct Vertical {
    state: BrokerState,
    peer: WorkloadIdentity,
    /// The registry origin: the one that answers `401` and then the manifest.
    registry: TlsOrigin,
    /// The token origin.
    realm: TlsOrigin,
    session: AgentSessionId,
    credential: CredentialId,
    other_credential: CredentialId,
    _dir: tempfile::TempDir,
}

impl Vertical {
    /// A vertical whose registry answers a real `401` and then a manifest.
    ///
    /// Two origins rather than one because the two halves of the exchange are
    /// genuinely two servers: the registry names a `realm` and the token is
    /// fetched from wherever that realm points. A single origin that answered
    /// both would not exercise the part of the loop where the host the registry
    /// *chose* is the host the credential goes to, which is most of what is
    /// being tested here.
    fn new(declared: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let passphrase = secrecy::SecretString::from("r2f-passphrase".to_string());

        let mut store = VaultStore::create(
            dir.path().join("v.asv"),
            &passphrase,
            KdfParams::fast_for_tests(),
        )
        .expect("create vault");
        let key: VaultKey = store
            .header()
            .unlock(&passphrase)
            .expect("unlock with the passphrase just used");
        for (id, name) in [(CRED, "r2f-registry"), (OTHER_CRED, "r2f-other")] {
            store
                .insert(
                    &key,
                    asv_vault::CredentialMetadata::new(
                        id,
                        name,
                        asv_vault::CredentialKind::Opaque,
                        "registry",
                        "Rubentxu",
                        1,
                    ),
                    // Distinct values, so a row that could tell which credential
                    // reached the wire could say which one it was.
                    SecretBytes::new(if id == CRED {
                        CANARY.as_bytes().to_vec()
                    } else {
                        b"hunter2-the-OTHER-registry-password".to_vec()
                    }),
                )
                .expect("insert the credential");
        }

        let mut state = BrokerState::default();
        // Projected through the same inventory pass the broker runs at startup,
        // so this fixture cannot pass by seeding a field production never
        // writes.
        let loaded = asv_broker::inventory::load(&mut state, &store);
        assert_eq!(
            (loaded.loaded, loaded.skipped, loaded.collisions),
            (2, 0, 0),
            "the fixture vault holds exactly two credentials; any other count means \
             the inventory projection changed under this suite"
        );
        state.secrets = Some(Arc::new(VaultSecretPort::new(
            Arc::new(std::sync::Mutex::new(store)),
            Arc::new(key),
        )));

        // The declaration goes through the operator's file, so this fixture
        // cannot declare something the product would refuse to load.
        let declaration_path = dir.path().join("registries.json");
        std::fs::write(&declaration_path, declared).expect("write the declaration file");
        state.registries =
            asv_broker::registry_declaration::load(&declaration_path).expect("valid declarations");

        state.policy = PolicyEngine::from_policy_text(&composed(PULL_ANY))
            .expect("the fixture policy is valid");

        // The token origin: a realm that grants exactly what it was asked for,
        // which is what a real endpoint does and what leaves the narrowing in
        // R2.F.1 as something these rows depend on rather than re-test.
        let realm = TlsOrigin::start(
            NAME,
            Arc::new(|observed: &Observed| {
                let asked = asked_scope(&observed.request_line);
                OriginResponse::json(
                    200,
                    format!(
                        r#"{{"token":"issued-token-value","expires_in":300,"scope":"{asked}"}}"#
                    ),
                )
            }),
        );

        // Captured before the closure, because the closure takes ownership of
        // the origin and the port is still needed here for the factory.
        let realm_url = realm.url("/token");
        let realm_port = realm.port;
        let registry = TlsOrigin::start(
            NAME,
            Arc::new(move |observed: &Observed| {
                let challenge = format!(
                    r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:{REPOSITORY}:pull,push""#
                );
                let has_bearer = observed
                    .headers
                    .iter()
                    .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
                if !has_bearer {
                    return OriginResponse::new(401, "")
                        .with_header("www-authenticate", &challenge);
                }
                // The write is answered before the read branch, and the order is
                // load-bearing rather than tidy: the upload path
                // `/blobs/uploads/?digest=` *contains* `/blobs/`, so a handler
                // that tested for the read path first would answer a push with
                // the bytes of a pull -- and the rows would go green against a
                // broker that had sent the wrong body to the registry.
                if observed.request_line.starts_with("PUT ") {
                    OriginResponse::new(201, "")
                } else if observed.request_line.contains("/blobs/") {
                    OriginResponse::new(200, String::from_utf8_lossy(BLOB).to_string())
                        .with_header("content-type", "application/octet-stream")
                } else {
                    OriginResponse::new(200, String::from_utf8_lossy(MANIFEST).to_string())
                        .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                }
            }),
        );

        state.connectors = Box::new(LocalFactory::new(
            ResolvedAudience {
                authority: Authority::canonicalize(NAME).expect("a two-label name"),
                port: registry.port,
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            },
            registry.certificate(),
            realm.certificate(),
            realm_port,
        ));

        let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        peer.pin_pidfd().expect("pin this test's own process");
        let session = state
            .sessions
            .lock()
            .expect("no test holds this")
            .create("/repo".into(), &peer);

        Self {
            state,
            peer,
            registry,
            realm,
            session,
            credential: CredentialId::from_wire(CRED).expect("canonical wire form"),
            other_credential: CredentialId::from_wire(OTHER_CRED).expect("canonical wire form"),
            _dir: dir,
        }
    }

    /// A vertical declaring `NAME` as served by [`CRED`].
    fn declared() -> Self {
        Self::new(&format!(
            r#"[{{"registry":"{NAME}","credential":"{CRED}"}}]"#
        ))
    }

    /// A vertical whose declaration file is `text`.
    fn declaring(text: &str) -> Self {
        Self::new(text)
    }

    /// Installs `text`, with the mint permit composed in.
    fn policy(&mut self, text: &str) {
        self.state.policy =
            PolicyEngine::from_policy_text(&composed(text)).expect("the fixture policy is valid");
    }

    /// Mints, returning the raw answer so a row can observe a refusal.
    fn try_mint(&mut self, credential: CredentialId, max_uses: u32) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::MintSurrogate {
                session: self.session,
                credential,
                max_uses,
                ttl_secs: 60,
            },
        )
    }

    /// A surrogate over the declared credential, panicking if the mint failed.
    fn mint(&mut self) -> String {
        self.mint_over(self.credential)
    }

    /// A surrogate over `credential`, panicking if the mint failed.
    fn mint_over(&mut self, credential: CredentialId) -> String {
        match self.try_mint(credential, 5) {
            Response::SurrogateMinted { surrogate, .. } => surrogate,
            other => panic!("the fixture must mint a surrogate, got {other:?}"),
        }
    }

    fn pull_manifest(
        &mut self,
        surrogate: &str,
        registry: &str,
        repository: &str,
        reference: &str,
    ) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PullManifest {
                session: self.session,
                surrogate: surrogate.to_string(),
                registry: registry.to_string(),
                repository: repository.to_string(),
                reference: reference.to_string(),
            },
        )
    }

    fn pull_blob(
        &mut self,
        surrogate: &str,
        registry: &str,
        repository: &str,
        digest: &str,
    ) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PullBlob {
                session: self.session,
                surrogate: surrogate.to_string(),
                registry: registry.to_string(),
                repository: repository.to_string(),
                digest: digest.to_string(),
            },
        )
    }

    /// The common case: a pull from the declared registry and repository.
    fn read(&mut self, surrogate: &str) -> Response {
        self.pull_manifest(surrogate, NAME, REPOSITORY, "latest")
    }

    fn push_blob(
        &mut self,
        surrogate: &str,
        registry: &str,
        repository: &str,
        digest: &str,
        bytes: &[u8],
    ) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PushBlob {
                session: self.session,
                surrogate: surrogate.to_string(),
                registry: registry.to_string(),
                repository: repository.to_string(),
                digest: digest.to_string(),
                bytes: bytes.to_vec(),
            },
        )
    }

    fn push_manifest(
        &mut self,
        surrogate: &str,
        registry: &str,
        repository: &str,
        reference: &str,
        manifest: &[u8],
    ) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PushManifest {
                session: self.session,
                surrogate: surrogate.to_string(),
                registry: registry.to_string(),
                repository: repository.to_string(),
                reference: reference.to_string(),
                manifest: manifest.to_vec(),
            },
        )
    }

    /// A body whose content address is computed here, the way the CLI does it.
    ///
    /// Deliberately computed by the row rather than copied from the broker's
    /// answer: a test that asks the broker for the digest and then asserts the
    /// broker published that digest is asserting that the broker agrees with
    /// itself.
    fn digest_of(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    }

    fn connections(&self) -> usize {
        self.registry.connections()
    }

    /// Every request the registry origin saw.
    fn seen(&self) -> Vec<Observed> {
        self.registry.observed()
    }

    /// The last request the registry origin saw, or a panic naming the count.
    fn last_request(&self) -> Observed {
        self.registry
            .last()
            .expect("the registry saw a request; if it did not, the row asserts about nothing")
    }
}

/// Enough base64 to decode one `Basic` header.
///
/// A local decoder rather than a dependency, so the row reads as what it says:
/// the credential arrived, encoded, and this is the encoding. `Standard` with
/// padding, which is what every HTTP client emits.
struct Base64;

impl Base64 {
    fn value(input: u8) -> Option<u8> {
        Some(match input {
            b'A'..=b'Z' => input - b'A',
            b'a'..=b'z' => input - b'a' + 26,
            b'0'..=b'9' => input - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    fn decode(input: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        let mut chunk = Vec::with_capacity(4);
        for byte in input {
            if *byte == b'=' {
                break;
            }
            chunk.push(*byte);
            if chunk.len() == 4 {
                let mut bits = 0u32;
                for symbol in &chunk {
                    bits = (bits << 6) | Base64::value(*symbol).ok_or(())? as u32;
                }
                out.push((bits >> 16) as u8);
                out.push((bits >> 8) as u8);
                out.push(bits as u8);
                chunk.clear();
            }
        }
        if chunk.len() == 1 {
            return Err(());
        }
        if chunk.len() > 1 {
            let mut bits = 0u32;
            for symbol in &chunk {
                bits = (bits << 6) | Base64::value(*symbol).ok_or(())? as u32;
            }
            bits <<= 6 * (4 - chunk.len());
            for index in 0..chunk.len() - 1 {
                out.push((bits >> (16 - 8 * index)) as u8);
            }
        }
        Ok(out)
    }
}

/// The scope a request line asked for, decoded.
///
/// `reqwest` percent-encodes the query, so a fixture that guessed the encoding
/// would be a fixture that only works for the spelling it guessed.
fn asked_scope(request_line: &str) -> String {
    request_line
        .split("scope=")
        .nth(1)
        .and_then(|rest| rest.split(['&', ' ']).next())
        .unwrap_or("")
        .replace("%3A", ":")
        .replace("%2F", "/")
}

fn assert_denial(response: Response, what: &str) -> ErrorCode {
    match response {
        Response::Error { code, message } => {
            assert!(
                !message.contains(CANARY),
                "the credential leaked into the denial for {what}: {message}"
            );
            code
        }
        other => panic!("expected a refusal for {what}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The operation is real
// ---------------------------------------------------------------------------

/// A pull succeeds, the registry was really asked, and the token really was
/// fetched from the realm the registry named.
///
/// This row exists so the rest of the file is not a set of refusals that would
/// all pass against a broker that had stopped working. The `Authorization`
/// assertion on the *second* request is the part that makes it load-bearing:
/// it proves the vault really was unlocked and the real credential really did
/// reach the realm, so the successes below are successes of the whole chain.
///
/// Mutation: skip the token exchange and attach the long credential to the
/// first request.
#[test]
fn a_declared_registry_serves_a_pull_and_the_chain_is_real() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    let response = v.read(&surrogate);
    let Response::ManifestRead {
        body,
        digest,
        media_type,
    } = response
    else {
        panic!("the declared pull must succeed, got {response:?}");
    };

    assert_eq!(body, MANIFEST, "the manifest bytes must be the ones served");
    assert_eq!(
        media_type.as_deref(),
        Some("application/vnd.oci.image.manifest.v1+json")
    );
    // Computed by the broker from the bytes, so the agent has something it can
    // verify against. See the next row for why this is the digest and not the
    // one a header asserted.
    assert_eq!(
        digest,
        asv_connector_http::registry::client::ContentDigest::of(MANIFEST).to_string()
    );

    // Two requests to the registry: the anonymous challenge and the retry.
    let seen = v.seen();
    assert_eq!(seen.len(), 2, "{seen:#?}");
    assert!(
        !seen[0]
            .headers
            .iter()
            .any(|(name, _)| name == "authorization"),
        "the first request must carry no credential: {:?}",
        seen[0].headers
    );
    assert!(
        seen[1]
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("Bearer ")),
        "the retry must carry the issued token: {:?}",
        seen[1].headers
    );

    // And the long credential went to the realm, which is a different origin.
    let token_requests = v.realm.observed();
    assert_eq!(token_requests.len(), 1, "{token_requests:#?}");
    // The realm is asked with HTTP Basic, so the credential is base64 on the
    // wire. Decoding it and comparing is what makes this a proof that the
    // vault's value arrived, rather than a proof that *some* authorization
    // header was sent.
    let presented = token_requests[0]
        .headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| {
            panic!(
                "the realm must have been asked to authenticate: {:?}",
                token_requests[0].headers
            )
        });
    let encoded = presented
        .strip_prefix("Basic ")
        .unwrap_or_else(|| panic!("the realm must be asked with Basic auth, got {presented}"));
    let decoded = Base64::decode(encoded.as_bytes()).expect("Basic auth is base64");
    assert_eq!(
        String::from_utf8_lossy(&decoded),
        CANARY,
        "the realm must have been given the real credential"
    );

    // The scope asked for was the operation's, not the challenge's. The
    // challenge offered `pull,push`; a client that forwarded it would have
    // asked for — and been given — a push-capable token for a read.
    assert_eq!(
        asked_scope(&token_requests[0].request_line),
        format!("repository:{REPOSITORY}:pull"),
        "the token must be narrowed to the operation being performed"
    );
}

/// The manifest's digest is recomputed from the body, not taken from a header.
///
/// The `Docker-Content-Digest` header is a claim by the registry about bytes
/// this side has not seen. Comparing the two would leave the check circular:
/// the registry would be checked against itself. So the header is ignored
/// entirely and the digest is computed, which means a registry that lies in
/// that header and serves the right bytes still gets the right answer, and one
/// that serves different bytes under the same header cannot pass.
///
/// The registry here answers with a header naming a digest its body does not
/// have.
///
/// Mutation: read `Docker-Content-Digest` and forward it.
#[test]
fn the_manifest_digest_is_computed_and_a_lying_header_is_ignored() {
    let realm = TlsOrigin::start(
        NAME,
        Arc::new(|observed: &Observed| {
            let asked = asked_scope(&observed.request_line);
            OriginResponse::json(
                200,
                format!(r#"{{"token":"issued-token-value","expires_in":300,"scope":"{asked}"}}"#),
            )
        }),
    );
    let liar = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let realm_url = realm.url("/token");
    let realm_port = realm.port;
    let registry = TlsOrigin::start(
        NAME,
        Arc::new(move |observed: &Observed| {
            let challenge = format!(
                r#"Bearer realm="{realm_url}",service="registry.docker.io",scope="repository:{REPOSITORY}:pull""#
            );
            let has_bearer = observed
                .headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer "));
            if has_bearer {
                OriginResponse::new(200, String::from_utf8_lossy(MANIFEST).to_string())
                    .with_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .with_header("docker-content-digest", liar)
            } else {
                OriginResponse::new(401, "").with_header("www-authenticate", &challenge)
            }
        }),
    );

    // The vertical's own factory is replaced so the two origins above are the
    // ones on the wire; everything else — vault, declaration, policy, session,
    // surrogate — is the production path.
    let mut v = Vertical::declared();
    v.state.connectors = Box::new(LocalFactory::new(
        ResolvedAudience {
            authority: Authority::canonicalize(NAME).expect("a two-label name"),
            port: registry.port,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        },
        registry.certificate(),
        realm.certificate(),
        realm_port,
    ));
    let surrogate = v.mint();

    let response = v.read(&surrogate);
    let Response::ManifestRead { body, digest, .. } = response else {
        panic!("the pull must succeed so the digest is observable, got {response:?}");
    };

    assert_eq!(body, MANIFEST);
    assert_ne!(
        digest, liar,
        "the registry's own header was forwarded as the answer; the header is a \
         claim about bytes this side never checked"
    );
    assert_eq!(
        digest,
        asv_connector_http::registry::client::ContentDigest::of(MANIFEST).to_string()
    );
}

/// A blob is verified against the digest the request named.
///
/// The client re-hashes what arrived and refuses a mismatch, so this row is
/// about the broker not getting in the way of that check: the digest the
/// request named has to reach the connector as a `ContentDigest`, and the
/// digest the broker answers with has to be the one the bytes were *verified*
/// to have.
///
/// Mutation: pass the requested digest through instead of the verified one, so
/// a registry serving the wrong bytes under a right-looking answer passes.
#[test]
fn a_blob_is_verified_against_the_digest_it_was_asked_for() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    // The declared digest of `BLOB`, computed once here by the row itself and
    // then handed to the request. Computing it in the fixture is not the check:
    // the check is that the broker's answer names the same one *after* the
    // connector hashed the bytes.
    let real = asv_connector_http::registry::client::ContentDigest::of(BLOB).to_string();

    let response = v.pull_blob(&surrogate, NAME, REPOSITORY, &real);
    let Response::BlobRead { bytes, digest } = response else {
        panic!("the declared blob pull must succeed, got {response:?}");
    };

    assert_eq!(bytes, BLOB, "the bytes must be the ones served");
    assert_eq!(
        digest, real,
        "the answer must name the digest the bytes were verified to have"
    );

    // The digest really did travel: the registry saw a blob path carrying it.
    let last = v.last_request();
    assert!(
        last.request_line.contains("/blobs/sha256:"),
        "the blob request must carry the content address: {}",
        last.request_line
    );
}

/// The digest literal in this file is the digest of the bytes it names.
///
/// A fixture whose hard-coded `BLOB_DIGEST` did not match `BLOB` would let
/// `a_blob_is_verified_against_the_digest_it_was_asked_for` pass for the
/// wrong reason — against a registry that served the expected bytes regardless
/// of what was asked. This row pins the two constants together so that one
/// cannot drift away from the other unnoticed.
///
/// Mutation: change either constant without the other.
#[test]
fn the_written_digest_is_the_digest_of_the_written_bytes() {
    assert_eq!(
        asv_connector_http::registry::client::ContentDigest::of(BLOB).to_string(),
        BLOB_DIGEST,
        "BLOB_DIGEST no longer describes BLOB, so the blob row proves nothing"
    );
}

// ---------------------------------------------------------------------------
// The declaration is the control
// ---------------------------------------------------------------------------

/// A registry the deployment did not declare is refused, and nothing is dialled.
///
/// This is the allowlist, and it is deliberately placed **before** the policy:
/// an undeclared registry is not a destination an operator can grant in a
/// rule, so a policy that permitted every `Registry` resource still would not
/// reach it. The row installs that broadest policy on purpose — without it, a
/// denial here would have a simpler explanation than the one being tested.
///
/// The `connections() == 0` assertion is the load-bearing half. A refusal
/// that still dialled would spend nothing but would have resolved a name and
/// opened a connection on the way to refusing, which is the shape of a probe.
///
/// Mutation: consult the policy before the declaration lookup.
#[test]
fn an_undeclared_registry_is_refused_before_any_socket() {
    let mut v = Vertical::declared();
    // The broadest policy that could possibly permit this read.
    v.policy(
        r#"
permit (principal, action == Action::"registry_pull", resource is Registry);
permit (principal, action == Action::"registry_push", resource is Registry);
"#,
    );
    let surrogate = v.mint();

    let code = assert_denial(
        v.pull_manifest(&surrogate, "registry-1.docker.io", REPOSITORY, "latest"),
        "an undeclared registry",
    );
    assert_eq!(code, ErrorCode::Denied);
    assert_eq!(
        v.connections(),
        0,
        "the refusal must precede the socket, not follow it"
    );
}

/// An empty declaration file refuses every registry request.
///
/// `BrokerState::default()` ships an empty `RegistryDeclarations`, and this row
/// says that is the fail-closed reading rather than a default that happens to
/// permit nothing because the test forgot to configure it. The declaration file
/// here is empty on purpose, so the refusal comes from a *deployment that
/// chose to declare nothing* rather than from a broker that was never told.
///
/// Mutation: treat an empty declaration file as "any registry is allowed".
#[test]
fn an_empty_declaration_refuses_every_registry() {
    let mut v = Vertical::declaring("[]");
    let surrogate = v.mint();

    assert_eq!(
        assert_denial(v.read(&surrogate), "an empty declaration"),
        ErrorCode::Denied
    );
    assert_eq!(v.connections(), 0);
}

/// The request's host is a selector: a spelling that canonicalizes to the
/// declared one is served, and the *declared* name is what is dialled.
///
/// This is the row that distinguishes `Authority::canonicalize` from
/// approval. `LOCALHOST.LOCALDOMAIN` canonicalizes to the same authority, so
/// this broker serves it — which is correct, because it is the same host under
/// a different spelling, not a different host. What must not happen is the
/// dialled name following the request's spelling: the origin asserts it saw
/// the declared name in its `Host` header, so an implementation that used the
/// request's string for the URL would fail here even though it "worked".
///
/// The mutation this names is the dangerous one: using the request's string as
/// the destination rather than as a selector. With the canonicalization above
/// still in place, that mutation passes this row and fails the next one.
///
/// Mutation: build the URL from the request's `registry` string.
#[test]
fn a_different_spelling_of_the_declared_host_is_the_same_host() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    let response = v.pull_manifest(&surrogate, &NAME.to_uppercase(), REPOSITORY, "latest");
    assert!(
        matches!(response, Response::ManifestRead { .. }),
        "a spelling that canonicalizes to the declared host must be served, got {response:?}"
    );

    // The name that went on the wire is the declaration's.
    let last = v.last_request();
    let host = last
        .host_header
        .as_deref()
        .unwrap_or_else(|| panic!("the registry saw a request: {:?}", last.request_line));
    // The host header carries the port, so the name is compared rather than
    // the whole value. The port is the test's and says nothing about which
    // *name* was dialled, which is the whole subject of this row.
    assert_eq!(
        host.split(':').next(),
        Some(NAME),
        "the request went out under a name the declaration did not write: {host}"
    );
}

/// A host that is not the declared one is refused even when it looks like it.
///
/// `NAME` is `localhost.localdomain`, and this asks for
/// `evil.localhost.localdomain` — a name that *ends with* the declared one. A
/// lookup by suffix would match it, and the agent would be handed the registry
/// credential for a host the operator never declared. The declaration's lookup
/// is an equality on a canonicalized authority, and this is the row that says
/// so at the broker rather than only in the declaration unit test.
///
/// Mutation: look the declaration up with `ends_with` instead of equality.
#[test]
fn a_host_ending_with_the_declared_one_is_not_the_declared_one() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    let code = assert_denial(
        v.pull_manifest(
            &surrogate,
            "evil.localhost.localdomain",
            REPOSITORY,
            "latest",
        ),
        "a lookalike host",
    );
    assert_eq!(code, ErrorCode::Denied);
    assert_eq!(
        v.connections(),
        0,
        "a lookalike host must not be resolved or dialled"
    );
}

/// The repository that reaches the policy is the one the request named.
///
/// The property is that the request's repository is *answerable* — that an
/// operator can write a rule about one repository without writing a rule per
/// registry. The narrow policy permits `library/alpine` and nothing else, and
/// the control row (same policy, same surrogate, permitted repository) is in the
/// same test so a denial cannot be explained by the policy being wrong.
///
/// Mutation: build the resource from a constant repository, or from the
/// declared authority's path.
#[test]
fn the_requested_repository_is_the_one_the_policy_sees() {
    let mut v = Vertical::declared();
    v.policy(PULL_ONE_REPOSITORY);
    let surrogate = v.mint();

    // The control: this policy does permit *something*, so the refusal below
    // is about the repository and not about a policy that permits nothing.
    let permitted = v.read(&surrogate);
    assert!(
        matches!(permitted, Response::ManifestRead { .. }),
        "the narrow policy must permit the repository it names, got {permitted:?}"
    );

    let refused = v.pull_manifest(&surrogate, NAME, "other/secret", "latest");
    assert_eq!(
        assert_denial(refused, "a repository the policy does not name"),
        ErrorCode::Denied
    );
}

// ---------------------------------------------------------------------------
// The surrogate is the grant
// ---------------------------------------------------------------------------

/// A surrogate for another credential serves no registry.
///
/// This is the second property, and it is the one a test that only checked
/// "the declaration refused the wrong host" would miss entirely. Both halves
/// of the grant are separate statements:
///
/// - the **declaration** says which credential serves this registry, and
/// - the **surrogate** says which credential this session was granted.
///
/// A session holding a genuine, unexpired, in-budget surrogate for
/// `OTHER_CRED` satisfies the second statement. If the broker only checked
/// that — if it asked "does this surrogate redeem?" and nothing more — it would
/// then dial the declared registry with `CRED`'s secret, which that session was
/// never granted. The check that refuses it is an equality between the
/// credential the surrogate stands for and the credential the declaration
/// names.
///
/// `redeem_for` does check something about the credential: that its *class*
/// backs `OperationFamily::Registry`. That is not the same question, and this
/// row is why — `OTHER_CRED` is in the vault, is the same class, and mints
/// successfully.
///
/// Mutation: compare nothing (accept any redeemable surrogate), or compare the
/// family instead of the credential.
#[test]
fn a_surrogate_for_another_credential_serves_no_registry() {
    let mut v = Vertical::declared();
    // Minted for the *other* credential, in the same session, from the same
    // vault. It is a real token with real uses left.
    let surrogate = v.mint_over(v.other_credential);

    let code = assert_denial(
        v.read(&surrogate),
        "a surrogate standing for another credential",
    );
    assert_eq!(code, ErrorCode::Denied);
    assert_eq!(
        v.connections(),
        0,
        "the mismatched surrogate must be refused before the socket; a token \
         spent on a read the session was not granted is the whole failure"
    );

    // And the refusal says which credential it expected, so an operator
    // debugging it is not left guessing. The message names the *declared*
    // credential, which is not a secret.
    match v.read(&surrogate) {
        Response::Error { message, .. } => {
            assert!(message.contains(CRED), "{message}");
            assert!(message.contains(OTHER_CRED), "{message}");
        }
        other => panic!("expected the same refusal, got {other:?}"),
    }
}

/// A surrogate is refused when the policy permits a push but not a pull.
///
/// The control for the rows above: this refusal is attributable to the policy
/// and not to the credential comparison, because the surrogate here *is* over
/// the declared credential. A handler that checked the credential before the
/// policy would pass this row too, which is why the two halves are separate
/// rows rather than one row asserting both.
///
/// Mutation: use `Action::RegistryPush` for a pull, or evaluate no policy.
#[test]
fn a_policy_that_permits_push_only_refuses_the_pull() {
    let mut v = Vertical::declared();
    v.policy(PUSH_ONLY);
    let surrogate = v.mint();

    assert_eq!(
        assert_denial(v.read(&surrogate), "a push-only policy"),
        ErrorCode::Denied
    );
    assert_eq!(v.connections(), 0);
}

/// A blob read goes through the declaration too.
///
/// The first version of this row asserted that a blob read was a *separate
/// policy decision* from a manifest read. It is not, and the row was wrong:
/// both arms ask for `Action::RegistryPull` against the same
/// `Resource::Registry`, which is also what the registry's own scope does —
/// `repository:<name>:pull` covers both halves, so splitting them here would
/// make the broker's model disagree with the protocol's. A row that asserts a
/// distinction the design does not make is a row that passes for the wrong
/// reason.
///
/// The property that *is* real is narrower and is this one: the blob arm runs
/// the same `authorize_registry` as the manifest arm, so it cannot be used as a
/// way around the allowlist. The arm's own policy outcome is not re-tested here;
/// `a_policy_that_permits_push_only_refuses_the_pull` covers that both arms
/// share.
///
/// Mutation: replace the blob arm's `authorize_registry` with a declaration
/// built from the request's own registry string.
#[test]
fn a_blob_read_goes_through_the_declaration_too() {
    let mut v = Vertical::declared();
    // The broadest policy that could possibly permit this read, so the refusal
    // below cannot be explained by the policy.
    v.policy(
        r#"
permit (principal, action == Action::"registry_pull", resource is Registry);
permit (principal, action == Action::"registry_push", resource is Registry);
"#,
    );
    let surrogate = v.mint();
    let real = asv_connector_http::registry::client::ContentDigest::of(BLOB).to_string();

    // The control: the same request against the declared registry is served.
    let permitted = v.pull_blob(&surrogate, NAME, REPOSITORY, &real);
    assert!(
        matches!(permitted, Response::BlobRead { .. }),
        "the declared blob pull must succeed so the refusal below is about the \
         host, got {permitted:?}"
    );

    // And an undeclared one is refused without a socket.
    let refused = v.pull_blob(&surrogate, "registry-1.docker.io", REPOSITORY, &real);
    assert_eq!(
        assert_denial(refused, "an undeclared registry on the blob arm"),
        ErrorCode::Denied
    );
}

// ---------------------------------------------------------------------------
// Nothing about the failure leaks
// ---------------------------------------------------------------------------

/// No refusal carries the credential, whichever refusal it is.
///
/// One row over every denial path, because a leak check that only covers the
/// "interesting" refusal is a leak check that will miss the one somebody adds
/// later. Each case below exercises a *different* arm of the handler — the
/// declaration, the credential comparison, the policy, the reference parse —
/// because they build their messages in different places and a single one of
/// them proves only that place.
///
/// Mutation: format a credential into any of the four messages.
#[test]
fn no_refusal_carries_the_credential() {
    let mut v = Vertical::declared();

    // The declaration arm.
    let s1 = v.mint();
    let declaration = v.pull_manifest(&s1, "elsewhere.example", REPOSITORY, "latest");
    assert_denial(declaration, "the declaration arm");

    // The credential-comparison arm.
    let s2 = v.mint_over(v.other_credential);
    let comparison = v.read(&s2);
    assert_denial(comparison, "the credential-comparison arm");

    // The policy arm. Minted *first*: the mint is itself gated, so withdrawing
    // the policy before minting would fail at the mint and this row would be
    // asserting about a denial in the wrong place.
    let s3 = v.mint();
    v.policy("");
    let policy = v.read(&s3);
    assert_denial(policy, "the policy arm");

    // The parse arm.
    let mut w = Vertical::declared();
    let s4 = w.mint();
    let parse = w.pull_manifest(&s4, NAME, REPOSITORY, "NOT A REFERENCE::");
    assert_denial(parse, "the parse arm");
}

/// A malformed reference is refused before a socket, not after.
///
/// The reference is agent-supplied and the client would send it into a URL, so
/// it is parsed here rather than downstream. This row separates "rejected as
/// malformed" from "the fetch failed", because an agent that cannot tell those
/// apart cannot tell whether its call was wrong.
///
/// Mutation: pass the reference through unparsed.
#[test]
fn a_malformed_reference_is_refused_before_the_socket() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    let code = assert_denial(
        v.pull_manifest(&surrogate, NAME, REPOSITORY, "not a reference::"),
        "a malformed reference",
    );
    assert_eq!(
        code,
        ErrorCode::InvalidRequest,
        "a malformed reference is the caller's error and must not be reported \
         as an upstream failure"
    );
    assert_eq!(v.connections(), 0);
}

/// A malformed digest is refused before the socket, and is not a blob read.
///
/// The digest is the only reference that can be checked, which is why it is a
/// separate type in the connector and is parsed as one here. A digest that is
/// not a `sha256:<64 hex>` is not a content address, and treating it as one
/// would be letting a name stand in for a check.
///
/// Mutation: accept any string as a digest, or forward it to the connector.
#[test]
fn a_digest_that_is_not_a_content_address_is_refused() {
    let mut v = Vertical::declared();
    let surrogate = v.mint();

    // Four shapes a caller might send, none of which is a content address: a
    // tag, a truncated hash, the wrong algorithm, and nothing at all.
    for bad in ["latest", "sha256:short", "sha512:0000", ""] {
        let code = assert_denial(
            v.pull_blob(&surrogate, NAME, REPOSITORY, bad),
            "a digest that is not a content address",
        );
        assert_eq!(code, ErrorCode::InvalidRequest, "for {bad:?}");
    }
    assert_eq!(v.connections(), 0);
}
// ---------------------------------------------------------------------------
// The advertisement
// ---------------------------------------------------------------------------

/// The broker says it can pull, so an agent does not have to guess.
///
/// This row exists because of a defect this very work introduced. `PullManifest`
/// and `PullBlob` were added to the enum, dispatched, tested — and **not
/// announced**: `selfreport::capability_of` classifies each request, and both
/// fell through to the plumbing arm, so the answer to "can this product pull
/// from a registry" was no. Nothing failed. The vertical above was green, the
/// campaign above was 9/9 red, and the product was unreachable in the only way
/// an agent would ever learn it exists.
///
/// The mutation is to drop either name from `compiled_capabilities`.
///
/// Note what this row does *not* cover: the CLI verb. A broker that advertises
/// an operation whose verb does not exist is the mirror defect, and it is
/// covered in `crates/cli` by
/// `every_operational_relation_parses_as_a_real_command`.
#[test]
fn an_agent_asking_what_the_broker_can_do_is_told_about_registry() {
    let mut v = Vertical::declared();
    let response = handle(
        &mut v.state,
        &v.peer,
        Request::AgentInfo {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
    );
    let capabilities = match response {
        Response::BrokerInfo { capabilities, .. } => capabilities,
        other => panic!("expected a self-description, got {other:?}"),
    };
    for expected in ["registry.manifest.read", "registry.blob.read"] {
        assert!(
            capabilities.iter().any(|c| c == expected),
            "the broker serves {expected} and does not advertise it, so an agent \
             reading its capabilities is told the product cannot do it: {capabilities:?}"
        );
    }
}

/// The two advertised names are two, not one collapsed name.
///
/// An agent that sees one `registry.read` cannot tell whether fetching a
/// manifest also fetches the layers it names. Collapsing the pair into one
/// capability would make the advertisement true and useless: it would state a
/// guarantee the broker does not make, because a manifest names content
/// addresses that have to be asked for separately.
///
/// The mutation that puts it red is dropping either name from
/// `selfreport::compiled_capabilities`. **Not** mapping both requests onto one
/// string in `capability_of`: that function lives inside `#[cfg(test)]`, so it
/// is what the sync rows read rather than what the broker advertises, and no
/// mutation of it changes what an agent reads. `every_advertised_capability_is_
/// handled` and `every_handled_operation_is_advertised` are the rows that read
/// it.
#[test]
fn a_manifest_and_a_blob_are_advertised_as_two_operations() {
    let mut v = Vertical::declared();
    let response = handle(
        &mut v.state,
        &v.peer,
        Request::AgentInfo {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
    );
    let capabilities = match response {
        Response::BrokerInfo { capabilities, .. } => capabilities,
        other => panic!("expected a self-description, got {other:?}"),
    };
    let registry: Vec<&String> = capabilities
        .iter()
        .filter(|c| c.starts_with("registry."))
        .collect();
    // Scoped to the reads, deliberately, rather than counting every registry
    // name. The property this row protects is that a pull is **two** requests
    // and one name would hide which is being served. Counting all of them made
    // the row a tripwire for an unrelated feature: adding push turned it red
    // without either read having been folded onto one name. The push names are
    // pinned by `a_push_is_advertised_as_two_more_operations` below.
    let reads: Vec<&&String> = registry.iter().filter(|c| c.ends_with(".read")).collect();
    let pushes: Vec<&&String> = registry.iter().filter(|c| c.ends_with(".push")).collect();
    assert_eq!(
        reads.len(),
        2,
        "a registry pull is two requests and one name would hide which is \
         being served: {reads:?}"
    );
    assert_eq!(
        pushes.len(),
        2,
        "a registry push is two requests for the same reason: {pushes:?}"
    );
    // Every registry name is a read or a push. A third kind would land here
    // without either row noticing, so the split is checked rather than assumed.
    assert_eq!(
        reads.len() + pushes.len(),
        registry.len(),
        "a registry capability that is neither a read nor a push: {registry:?}"
    );
}

/// The push names, on their own.
///
/// The mutation that puts this red is dropping `registry.manifest.push` or
/// `registry.blob.push` from `selfreport::compiled_capabilities`. Without a
/// row of its own, the two names would be checked only by the count above,
/// which cannot tell "both present" from "one present and one stranger".
#[test]
fn a_push_is_advertised_as_two_more_operations() {
    let mut v = Vertical::declared();
    let response = handle(
        &mut v.state,
        &v.peer,
        Request::AgentInfo {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
    );
    let capabilities = match response {
        Response::BrokerInfo { capabilities, .. } => capabilities,
        other => panic!("expected a self-description, got {other:?}"),
    };
    for name in ["registry.manifest.push", "registry.blob.push"] {
        assert!(
            capabilities.iter().any(|c| c == name),
            "an agent asking what the broker can do is not told about {name}: \
             {capabilities:?}"
        );
    }
}

/// A blob push reaches the declared registry and the registry's own answer is
/// what comes back.
///
/// This is the row the write path did not have. `the_written_digest_is_the_
/// digest_of_the_written_bytes` and `the_manifest_digest_is_computed_and_a_lying_
/// header_is_ignored` both stop before the socket, and
/// `a_policy_that_permits_push_only_refuses_the_pull` proves the *refusal*,
/// so nothing here was exercising the success: an arm that authorized correctly
/// and then handed the connector something unusable would have been green.
///
/// The mutation that puts it red is either (a) writing the blob body under the
/// manifest's path in `blob_upload_path`, or (b) dropping the `201` arm from
/// `put_blob`'s accept list so a genuine success is read as a refusal. Both turn
/// this row red and neither is visible from the rows above.
#[test]
fn a_declared_registry_serves_a_blob_push_and_the_answer_is_the_registrys() {
    let mut v = Vertical::declared();
    v.policy(&format!("{}{PUSH_ANY}", composed("")));

    let bytes = b"a layer".to_vec();
    let digest = Vertical::digest_of(&bytes);
    let surrogate = v.mint();

    let response = v.push_blob(&surrogate, NAME, REPOSITORY, &digest, &bytes);
    let (pushed, count) = match &response {
        Response::BlobPushed { digest: d, bytes } => (d.clone(), *bytes),
        other => panic!("a declared push must be served, got {other:?}"),
    };

    assert_eq!(pushed, digest, "the registry answered a different address");
    assert_eq!(count, bytes.len(), "the count must be the bytes sent");

    // The origin actually saw a `PUT` carrying those bytes. Without this the
    // row would pass on a broker that answered `BlobPushed` from its own
    // bookkeeping without dialling anything.
    let seen = v.seen();
    let puts: Vec<&Observed> = seen
        .iter()
        .filter(|o| o.request_line.starts_with("PUT "))
        .collect();
    assert!(
        !puts.is_empty(),
        "nothing was uploaded: the registry origin saw {:?}",
        seen.iter().map(|o| &o.request_line).collect::<Vec<_>>()
    );
    let path = puts[0].request_line.split_whitespace().nth(1).unwrap_or("");
    assert!(
        path.contains("/blobs/uploads/"),
        "a monolithic blob upload PUTs to /blobs/uploads/?digest=, not a \
         manifest path: {path}"
    );
    assert!(
        path.contains(&digest),
        "the upload path must carry the content address as its query: {path}"
    );
}

/// A manifest push reaches the declared registry under the reference it was
/// asked for.
///
/// Separate from the blob row because a manifest write is the one an operator
/// reasons about by tag: what `latest` points at afterwards is the registry's
/// answer, and the row pins that the reference travelled rather than being
/// derived.
///
/// The mutation that puts it red is resolving the manifest path from the
/// manifest *digest* instead of the reference, which is the plausible mistake
/// and which this row is the only one to catch.
#[test]
fn a_declared_registry_serves_a_manifest_push_under_the_reference() {
    let mut v = Vertical::declared();
    v.policy(&format!("{}{PUSH_ANY}", composed("")));

    let manifest = br#"{"schemaVersion":2}"#.to_vec();
    let surrogate = v.mint();

    let response = v.push_manifest(&surrogate, NAME, REPOSITORY, "latest", &manifest);
    let (reference, pushed) = match &response {
        Response::ManifestPushed {
            reference,
            digest,
            bytes: _,
        } => (reference.clone(), digest.clone()),
        other => panic!("a declared manifest push must be served, got {other:?}"),
    };

    assert_eq!(
        reference, "latest",
        "the registry is told the reference it was given, not one derived from \
         the content"
    );
    assert_eq!(
        pushed,
        Vertical::digest_of(&manifest),
        "the digest the registry stored must be the one recomputed from the \
         bytes, not one the caller supplied"
    );

    let seen = v.seen();
    let puts: Vec<&Observed> = seen
        .iter()
        .filter(|o| o.request_line.starts_with("PUT "))
        .collect();
    assert!(
        !puts.is_empty(),
        "nothing was uploaded: the registry origin saw {:?}",
        seen.iter().map(|o| &o.request_line).collect::<Vec<_>>()
    );
    let path = puts[0].request_line.split_whitespace().nth(1).unwrap_or("");
    assert!(
        path.contains("/manifests/latest"),
        "a manifest is written at the reference it was asked for: {path}"
    );
}

/// A push whose claimed address is not the address of the bytes never opens a
/// socket.
///
/// The row that distinguishes "the registry rejected it" from "this broker
/// never dialed", which is the difference between a transport failure and a
/// refusal the operator caused. `a_blob_is_verified_against_the_digest_it_was_
/// asked_for` covers the read direction; this is the write direction, where a
/// wrong digest is an operator mistake rather than a corruption to detect.
///
/// The mutation that puts it red is moving `ContentDigest::of(body)` after the
/// `attempt(...)` call in `put_blob`, so the mismatch is discovered by the
/// registry instead of by this broker.
#[test]
fn a_push_that_lies_about_the_content_address_is_refused_before_the_socket() {
    let mut v = Vertical::declared();
    v.policy(&format!("{}{PUSH_ANY}", composed("")));

    let bytes = b"a layer".to_vec();
    let liar = format!(
        "sha256:{}",
        "0".repeat(64) // a well-formed address of nothing
    );
    let surrogate = v.mint();
    let before = v.connections();

    let response = v.push_blob(&surrogate, NAME, REPOSITORY, &liar, &bytes);

    assert!(
        !matches!(response, Response::BlobPushed { .. }),
        "a digest that is not the digest of the bytes must not be published, \
         got {response:?}"
    );
    assert_eq!(
        v.connections(),
        before,
        "the mismatch must be found before the registry is dialed"
    );
}
