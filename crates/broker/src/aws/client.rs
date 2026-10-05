//! The live `sts:AssumeRole` call — R2.C.2.b, the transport half.
//!
//! # What composes here, and what is deliberately delegated
//!
//! [`StsClient`] does three things itself and borrows the fourth:
//!
//! 1. builds the body — `AssumeRole::form_body`;
//! 2. signs it with the **long-lived** key, borrowed from a `SecretPort`;
//! 3. stamps the date — [`amz_date`](super::calendar::amz_date);
//! 4. reads the answer — [`parse_assume_role`].
//!
//! The transport between 2 and 4 is `asv-connector-http`'s pinned client, and it
//! needed no work to get here: `PinnedClient::client`, `url` and
//! `follow_same_origin` were already general. That is worth more than a
//! convenience, because this operation needs the *GitHub-grade* transport
//! properties and not the OAuth2-grade ones. A SigV4 signature commits to the
//! host, the path and every signed header, so a request that reached the wrong
//! destination would not merely leak a header — it would present a
//! **valid-looking** signature to whoever it reached, and address pinning plus
//! private-address refusal are the reason the signature still means anything.
//!
//! # The long-lived key has one window, and it is inside `lend`
//!
//! The vault holds one secret: the secret access key. The access key id is the
//! `AKIA…` identifier AWS itself prints in CloudTrail, so it travels as ordinary
//! operator config, along with the region, the role ARN and the session name.
//!
//! The secret is borrowed, the [`SigV4Signer`] is built **inside the sink**, the
//! request is signed, and the signer is dropped — which zeroizes the key —
//! **before the socket is touched**. The tempting alternative, building the
//! signer from a `&str` a caller already holds, is equivalent in the types and
//! different in practice: a caller who can name the key can log it, and nothing
//! further down notices. So the shape is the argument, not a style preference.
//!
//! `SignerSink` is where that happens, and it is the only type here that has ever
//! held the key. It is not `Clone`, has no `Debug`, and hands the signer over
//! once and only once — after which the borrow is over and the key is gone.
//!
//! # One header list, signed and sent
//!
//! `signed_headers` exists because the two copies of the header list this
//! module used to keep could drift, and a drift there is a signature over
//! headers the request does not carry. AWS answers that with
//! `SignatureDoesNotMatch`, which points an operator at their clock. The list is
//! now built once and used for both, so "signed" and "sent" are the same fact —
//! which is what the session path needs, since `x-amz-security-token` has to be
//! inside `SignedHeaders` as well as on the wire.
//!
//! # What this is not
//!
//! Not reachable by an agent. There is no broker operation and no CLI verb
//! behind this type — that is R2.C.3 — so a caller exists but no agent can name
//! one, and per M11's rule item 2 stays open.

use std::time::SystemTime;

use asv_connector_http::transport::{PinnedClient, Redirect, ResolvedAudience, TransportError};
use asv_connector_http::{SecretError, SecretPort, SecretSink};

use super::sigv4::{Header, SigV4Signer, SignError, SignRequest};
use super::sts::{parse_assume_role, AssumeRole, AwsSession, StsError, STS_SERVICE};

/// The endpoint AWS serves STS on.
///
/// Pinned, like the service name and the API version: a client that let the
/// caller name the host would sign a request for one audience and send it to
/// another, and the signature would be the only thing in the request that
/// disagreed with where it went.
pub const STS_ENDPOINT: &str = "sts.amazonaws.com";

/// The path every Query-protocol call posts to.
const STS_PATH: &str = "/";

/// The `Content-Type` STS expects, and the one the body actually is.
const CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// The largest response this client will read off the wire.
///
/// The reader in [`super::sts`] has its own bound with the same number, and this
/// one is here because the transport is where an unbounded body is read into
/// memory. A reader that refuses a 100 MB document *after* allocating 100 MB of
/// it has bounded nothing.
const MAX_RESPONSE_BYTES: usize = super::sts::MAX_RESPONSE_BYTES;

/// The operator's configuration for one AWS credential.
///
/// **Every field is non-secret, and that is the design.** The access key id is
/// the value AWS itself prints in CloudTrail. The role ARN, region and session
/// name are things an operator types. The external id is the awkward one: AWS
/// documents it as possibly "a passphrase", which makes it a shared secret in
/// some deployments — so it belongs in the vault when it is one, and its having
/// a field here is a convenience, not a licence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentialConfig {
    /// `AKIA…`. An identifier, not a secret.
    pub access_key_id: String,
    pub region: String,
    pub role_arn: String,
    pub role_session_name: String,
    pub duration_seconds: u32,
    /// Often a shared secret. See the field on
    /// `AssumeRole::external_id`.
    pub external_id: Option<String>,
}

impl AwsCredentialConfig {
    /// The request this configuration describes, or why it cannot make one.
    pub fn assume_role(&self) -> Result<AssumeRole, StsError> {
        AssumeRole::new(
            self.role_arn.clone(),
            self.role_session_name.clone(),
            self.duration_seconds,
            self.external_id.clone(),
        )
    }
}

/// Why a session could not be obtained.
///
/// The arms are grouped by *what an operator should do*, because that is the
/// thing a flattened error destroys: a refused signature is a clock or a
/// configuration, a refused address is a threat or a mistake, and a named
/// provider refusal is an IAM decision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StsClientError {
    /// The request could not be built. Always a configuration problem.
    #[error("the STS request is not well-formed: {0}")]
    Request(#[from] StsError),

    /// The signature could not be computed, or there was no date to stamp.
    #[error("the STS request could not be signed: {0}")]
    Signing(#[from] SignError),

    /// The transport refused: a private peer, a cross-origin hop, a TLS
    /// failure, a body too large. These are the rows that keep a signed request
    /// from reaching where it was not signed for.
    #[error("the STS transport refused: {0}")]
    Transport(#[from] TransportError),

    /// The long-lived key could not be borrowed.
    #[error("the AWS credential could not be lent: {0}")]
    Secret(#[from] SecretError),

    /// The response was not UTF-8 in the one place the client reads bytes as
    /// text for a diagnostic, so there is nothing to name.
    #[error("STS answered {status}, and this client cannot say more about the body")]
    UnreadableStatus { status: u16 },
}

/// Holds the signer for the duration of one request, and nothing else.
///
/// The only type in this module that has ever seen the long-lived key. It is
/// built inside [`SecretPort::lend`], so the key is a value only between the
/// vault's `accept` and the `take` below — and the `take` is the last moment it
/// exists, because [`SigV4Signer`] zeroizes the key when it drops.
struct SignerSink {
    signer: Option<SigV4Signer>,
    /// Non-secret, and needed inside `accept` because the sink has to build the
    /// signer itself. Kept here rather than passed per call so that `accept`
    /// keeps the one-argument shape `SecretSink` requires.
    access_key_id: String,
    region: String,
}

impl SecretSink for SignerSink {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        // The vault lends bytes and this is where they become a key. A `&str`
        // borrow of the vault's own buffer would not need this, and is not what
        // the port offers: the sink shape is what keeps the port dyn-safe
        // without giving up that the key has no owner outside the call.
        let key = std::str::from_utf8(secret).map_err(|_| {
            SecretError::Unavailable(
                "a secret access key that is not UTF-8 cannot be signed".into(),
            )
        })?;
        self.signer = Some(
            SigV4Signer::new(
                self.access_key_id.clone(),
                key,
                self.region.clone(),
                STS_SERVICE,
            )
            .map_err(|error| {
                SecretError::Unavailable(format!("the credential scope cannot be built: {error}"))
            })?,
        );
        Ok(())
    }
}

impl SignerSink {
    fn new(access_key_id: &str, region: &str) -> Self {
        Self {
            signer: None,
            access_key_id: access_key_id.to_string(),
            region: region.to_string(),
        }
    }

    /// Hands the signer over, once. A second call is a bug rather than an
    /// empty `Option`, and it is named as one.
    fn take(&mut self) -> Result<SigV4Signer, StsClientError> {
        self.signer
            .take()
            .ok_or(StsClientError::Secret(SecretError::Unavailable(
                "the port lent nothing, so nothing could be signed".into(),
            )))
    }
}

/// The headers one signed Query request carries, built once.
///
/// **One list, signed and sent.** The version this replaced wrote the four
/// headers twice -- once for [`SignRequest`] and once for the request builder --
/// with nothing keeping the two copies in step. A drift between them is a
/// signature computed over headers the request does not carry, or a header sent
/// that the signature does not cover, and AWS reports both as
/// `SignatureDoesNotMatch`, which sends an operator to their clock.
///
/// It matters more than usual for the session path, where
/// `x-amz-security-token` has to appear in **both** the signed list and the
/// request: the AWS reference's temporary-credentials example signs with
/// `SignedHeaders=host;user-agent;x-amz-date;x-amz-security-token`. With one
/// list that is a fact about the shape instead of a thing to keep in step.
///
/// `extra` is how a caller adds a header that is part of the signature. It is
/// a parameter rather than a second entry point so that "signed" and "sent"
/// cannot diverge: there is nowhere to put a header that is only one of them.
pub(crate) fn signed_headers(
    host: &str,
    payload_hash: &str,
    amz_date: &str,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("content-type".to_string(), CONTENT_TYPE.to_string()),
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.to_string()),
    ];
    headers.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
    );
    headers
}

/// Signs `payload` over exactly the headers that will be sent.
///
/// The borrowing is the whole point: the signer sees the same names and values
/// the transport will put on the wire, so there is no second list to fall out
/// of step with this one.
pub(crate) fn sign_with(
    signer: &SigV4Signer,
    headers: &[(String, String)],
    payload: &[u8],
    amz_date: &str,
) -> Result<super::sigv4::SignedRequest, StsClientError> {
    let borrowed: Vec<Header<'_>> = headers
        .iter()
        .map(|(name, value)| Header::new(name, value))
        .collect();
    Ok(signer.sign(
        &SignRequest {
            method: "POST",
            path: STS_PATH,
            headers: &borrowed,
            payload,
            ..SignRequest::default()
        },
        amz_date,
    )?)
}

/// The live client. Holds no secret: the key is borrowed per call.
pub struct StsClient {
    transport: PinnedClient,
    audience: ResolvedAudience,
    config: AwsCredentialConfig,
}

impl std::fmt::Debug for StsClient {
    /// Everything here is operator config and a pinned address. The one secret
    /// this type can reach is not a field of it, and the `Debug` says so rather
    /// than printing a redaction for a field that was never there.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StsClient")
            .field("audience", &self.audience.authority)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl StsClient {
    /// Builds a client for an already-resolved audience.
    ///
    /// Takes the audience rather than resolving it, which is what makes this
    /// testable against a real socket without a resolver and without relaxing
    /// the address policy: a test supplies an audience on loopback and the
    /// origin's own root, while production supplies the one `resolve_and_pin`
    /// vetted. The policy is then proven by its own tests instead of being
    /// quietly switched off for everyone.
    pub fn new(
        transport: PinnedClient,
        audience: ResolvedAudience,
        config: AwsCredentialConfig,
    ) -> Self {
        Self {
            transport,
            audience,
            config,
        }
    }

    /// Whether this client would talk to `authority`. Compared on the canonical
    /// authority, so a different spelling of the same host is not a different
    /// destination.
    pub fn serves(&self, authority: &str) -> bool {
        self.audience
            .authority
            .as_str()
            .eq_ignore_ascii_case(authority)
    }

    /// The operator's configuration, for a caller that signs with a session
    /// and needs the same region the client was built for.
    pub(crate) fn config(&self) -> &AwsCredentialConfig {
        &self.config
    }

    /// The pinned audience, for a receipt.
    pub fn audience(&self) -> &ResolvedAudience {
        &self.audience
    }

    /// The `Host` header this client sends: the authority, and the port only
    /// when it is not the scheme's default.
    ///
    /// A `Host` carrying the port when the URL does not is a header that
    /// disagrees with the request line, and SigV4 signs what it sends.
    pub(crate) fn host_header(&self) -> String {
        match self.audience.port {
            443 => self.audience.authority.to_string(),
            port => format!("{}:{port}", self.audience.authority),
        }
    }

    /// Requests a session for the configured role at `now`.
    ///
    /// `now` is a parameter for the reason it is one everywhere in this module:
    /// the signer needs a stamp and the reader needs a clock, and a function
    /// that read the clock itself could not be tested against a fixture at all.
    pub fn assume_role(
        &self,
        secrets: &dyn SecretPort,
        credential: &str,
        now: SystemTime,
    ) -> Result<AwsSession, StsClientError> {
        let request = self.config.assume_role()?;
        let body = request.form_body();
        let payload_hash = request.payload_hash();
        let host = self.host_header();

        let amz_date = super::calendar::amz_date(now).ok_or(SignError::IncompleteScope(
            "the instant is before the epoch or past the year a stamp can express",
        ))?;

        // Built once, and then used twice: to sign and to send. See
        // [`signed_headers`] for why that is one list rather than two.
        let headers = signed_headers(&host, &payload_hash, &amz_date, &[]);

        // The one window in which the key is a value. `lend` calls `accept`,
        // `take` hands the signer over, and the signer is dropped -- zeroizing
        // the key -- at the end of the block below, before `send` is reached.
        let signed = {
            let mut sink = SignerSink::new(&self.config.access_key_id, &self.config.region);
            secrets.lend(credential, &mut sink)?;
            let signer = sink.take()?;
            // The key is gone here. Nothing below can reach it, and the request
            // that follows is already signed.
            sign_with(&signer, &headers, body.as_bytes(), &amz_date)?
        };

        self.send(&signed, &headers, &body, now, |bytes, now| {
            parse_assume_role(bytes, &request, now)
        })
    }

    /// Sends a signed request and reads the answer with `parse`.
    ///
    /// Shared by every Query call rather than copied per operation: the
    /// cross-origin policy, the two size bounds and the status-versus-refusal
    /// decision are the properties worth having exactly once, and a second copy
    /// of them is a second place for them to be subtly different.
    pub(crate) fn send<T>(
        &self,
        signed: &super::sigv4::SignedRequest,
        headers: &[(String, String)],
        body: &str,
        now: SystemTime,
        parse: impl Fn(&[u8], SystemTime) -> Result<T, StsError>,
    ) -> Result<T, StsClientError> {
        let url = self.transport.url(&self.audience, STS_PATH)?;
        let origin = url.clone();
        let authority = self.audience.authority.clone();

        // The closure's error type is spelled out because `#[from]` on three
        // arms leaves the compiler more than one candidate, and a client that
        // cannot name which error it returns is a client whose errors are
        // documented by whichever impl it happened to pick.
        let response = PinnedClient::follow_same_origin(
            url,
            &origin,
            |target| -> Result<Redirect<reqwest::blocking::Response>, StsClientError> {
                let mut builder = self
                    .transport
                    .client()
                    .post(target.clone())
                    .body(body.to_string());
                // The very list the signature was computed over. `Authorization`
                // is the one header added here and not signed, because it *is*
                // the signature.
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                let sent = builder
                    .header("authorization", signed.authorization.clone())
                    .send()
                    .map_err(|error| TransportError::from((authority.clone(), error)))?;
                let status = sent.status();
                let next = sent
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| target.join(value).ok());
                match next {
                    Some(next) if status.is_redirection() => Ok(Redirect::Hop(next)),
                    _ => Ok(Redirect::Done(sent)),
                }
            },
        )?;

        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(StsClientError::Transport(
                TransportError::ResponseTooLarge {
                    audience: authority.to_string(),
                },
            ));
        }
        let bytes = response
            .bytes()
            .map_err(|error| TransportError::from((authority.clone(), error)))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(StsClientError::Transport(
                TransportError::ResponseTooLarge {
                    audience: authority.to_string(),
                },
            ));
        }

        match parse(&bytes, now) {
            Ok(value) => Ok(value),
            // A refusal that names its code is worth more than its status, and
            // the code is the part an operator acts on. A 5xx that happens to
            // carry an ErrorResponse is the same answer.
            Err(error @ StsError::Provider { .. }) => Err(StsClientError::Request(error)),
            // Anything else on a non-2xx is a shape this client does not claim
            // to read, and naming the status is better than attributing it to
            // either a credential or a request.
            Err(_) if !(200..300).contains(&status) => {
                Err(StsClientError::UnreadableStatus { status })
            }
            Err(error) => Err(StsClientError::Request(error)),
        }
    }
}
