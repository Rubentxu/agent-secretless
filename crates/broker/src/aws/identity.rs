//! `sts:GetCallerIdentity` — the operation an agent will actually name, and the
//! first request in this tree **signed with a session rather than with the
//! long-lived key**.
//!
//! # Why this operation first
//!
//! It is the only AWS API that answers *which identity is this request actually
//! acting as* — the question an agent has to be able to ask before it does
//! anything else, and the question an auditor asks afterwards. Every other
//! candidate for a first operation either mutates something or needs addressing
//! and body handling this module deliberately does not have yet.
//!
//! **It is not, and is not claimed to be, evidence that signing works.** The AWS
//! reference says plainly that this operation requires no permissions and
//! "returns the same information when access is denied", so a provider that
//! answers it is not a provider that has checked a signature. The signing
//! evidence stays where it is — R2.C.1's rows against AWS's published vectors,
//! plus the live call. What this module adds is the *reachability* evidence, and
//! the fact that the session-signed code path exists at all.
//!
//! # The session token goes on the wire, and that is the whole difference
//!
//! A request signed with the long-lived key carries a derived signature and no
//! secret: once `signer.sign` returns, the key can be zeroized before the socket
//! is touched, which is what R2.C.2.b does.
//!
//! A request signed with a **session** carries `x-amz-security-token` — the token
//! itself, in a header. The AWS reference's temporary-credentials example signs
//! with `SignedHeaders=host;user-agent;x-amz-date;x-amz-security-token`, so the
//! token has to be *inside the signature* as well as on the request. Its window
//! is therefore unavoidably longer than the signing call, and the honest
//! accounting is:
//!
//! - it is created inside `AwsSecretSink::accept`;
//! - it is copied into the header list, which is the one copy that is a plain
//!   `String` and is **not** zeroized on drop;
//! - that list is dropped when the response has been read.
//!
//! So unlike the long-lived key, this value has one non-zeroizing copy. It is
//! stated here rather than glossed, because the alternative — pretending the
//! token dies with the signature — would be false, and the reason it exists at
//! all is that the protocol requires it on the wire. What the broker still
//! guarantees is unchanged and is what matters to a caller: the token is never
//! returned, never logged, never audited, and never in a response type.
//!
//! # Why the sink sends
//!
//! [`SessionCall`] is an `AwsSecretSink` that performs the entire call inside
//! `accept`, which is not what the name suggests and is deliberate. If `accept`
//! only signed and returned, something downstream would have to carry the token
//! — and whatever carries it is a field on a type that outlives the call. Doing
//! the work inside `accept` keeps the token inside one function's body, which is
//! the only place this codebase lets a credential exist.

use std::time::SystemTime;

use super::client::{sign_with, signed_headers, StsClient, StsClientError};
use super::sigv4::{sha256_hex_of, SigV4Signer};
use super::sts::{self, AwsSecretSink, StsError, MAX_RESPONSE_BYTES, STS_SERVICE};

/// The one header a session-signed request carries that a key-signed one does
/// not, and the reason the header list has to be built before signing.
pub const SESSION_TOKEN_HEADER: &str = "x-amz-security-token";

/// The body `GetCallerIdentity` posts, per the AWS reference's sample request.
///
/// Two parameters, and the ordering is the signer rule rather than a style
/// choice: AWS's sort is by encoded name, and `Action` precedes `Version`.
const BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// The minimum ARN length AWS documents for `GetCallerIdentity`.
///
/// Checked because it is documented, and because an identity the provider says
/// has a length is a shape the provider enforces. A reader that accepted a
/// one-character ARN would be reporting an identity nobody could act on.
const MIN_ARN_LEN: usize = 20;

/// The maximum ARN length AWS documents.
const MAX_ARN_LEN: usize = 2048;

/// Which identity a request was actually made as.
///
/// **Every field is non-secret, and the type has no field that could be.** The
/// ARN names the role and the session name — both things AWS itself prints in
/// CloudTrail — and the account is a twelve-digit number. There is no secret
/// access key and no session token here, so a caller holding one of these
/// cannot be holding a credential, and the property needs no check because there
/// is nothing to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub arn: String,
    pub user_id: String,
    pub account: String,
}

/// Reads a caller-identity document.
///
/// The same narrow reader [`sts`] uses, on the same grounds: one XML reader for
/// STS documents rather than one per operation, and the same rule that a
/// document which cannot be understood is refused rather than guessed at.
pub fn parse_caller_identity(body: &[u8]) -> Result<CallerIdentity, StsError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(StsError::ResponseTooLarge);
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| StsError::UnrecognisedDocument("the body is not UTF-8".into()))?;
    if text.contains("<!DOCTYPE") {
        return Err(StsError::UnrecognisedDocument(
            "the document declares a DTD, which is refused before it is read".into(),
        ));
    }
    if let Some((code, message)) = sts::read_error_response(text)? {
        return Err(StsError::Provider { code, message });
    }

    let arn = sts::text_field(text, "Arn")?;
    if !(MIN_ARN_LEN..=MAX_ARN_LEN).contains(&arn.chars().count()) {
        return Err(StsError::UnrecognisedDocument(format!(
            "<Arn> is {} characters, outside the {MIN_ARN_LEN}..={MAX_ARN_LEN} AWS documents",
            arn.chars().count()
        )));
    }
    Ok(CallerIdentity {
        arn,
        user_id: sts::text_field(text, "UserId")?,
        account: sts::text_field(text, "Account")?,
    })
}

/// Signs one `GetCallerIdentity` call with a session and sends it.
///
/// Private on purpose: [`get_caller_identity`] is the only thing that may drive
/// it, and it drives both halves. A caller that could construct one and call
/// `accept` without taking the answer would be a caller that believes a failed
/// call succeeded, because `accept` returning `Ok` means *the values were
/// consumed*, not *the call worked*. Keeping the type private is what makes that
/// distinction safe rather than a trap.
struct SessionCall<'a> {
    client: &'a StsClient,
    now: SystemTime,
    answered: Option<Result<CallerIdentity, StsClientError>>,
}

impl AwsSecretSink for SessionCall<'_> {
    /// Builds the signer, signs with all three values, sends, and reads.
    ///
    /// The signer is dropped — zeroizing the secret access key — before the
    /// response is read. The session token cannot be: it is in the request.
    fn accept(
        &mut self,
        access_key_id: &[u8],
        secret_access_key: &[u8],
        session_token: &[u8],
    ) -> Result<(), StsError> {
        let signer = SigV4Signer::new(
            std::str::from_utf8(access_key_id)
                .map_err(|_| StsError::IncompleteRequest("an access key id that is not UTF-8"))?,
            std::str::from_utf8(secret_access_key)
                .map_err(|_| StsError::IncompleteRequest("a secret access key that is not UTF-8"))?,
            self.client.config().region.clone(),
            STS_SERVICE,
        )
        // A signer that cannot be built from these is a configuration problem,
        // and `IncompleteRequest` says so rather than blaming the document.
        .map_err(|_| StsError::IncompleteRequest("a session that cannot be signed"))?;

        let amz_date = super::calendar::amz_date(self.now).ok_or(
            StsError::IncompleteRequest("an instant a stamp cannot express"),
        )?;
        let payload_hash = sha256_hex_of(BODY.as_bytes());
        let host = self.client.host_header();

        // The token goes into the list, and the list is both what is signed and
        // what is sent. That is why it is an `extra` here rather than a header
        // chained onto the request afterwards: there is no second place to put a
        // header, so a signed request cannot carry an unsigned token.
        let headers = signed_headers(
            &host,
            &payload_hash,
            &amz_date,
            &[(SESSION_TOKEN_HEADER, std::str::from_utf8(session_token).map_err(
                |_| StsError::IncompleteRequest("a session token that is not UTF-8"),
            )?)],
        );
        let signed = sign_with(&signer, &headers, BODY.as_bytes(), &amz_date)
            .map_err(|error| StsError::IncompleteRequest(&leak_free(error)))?;

        self.answered = Some(self.client.send(
            &signed,
            &headers,
            BODY,
            self.now,
            |bytes, _now| parse_caller_identity(bytes),
        ));
        // The signer, and with it the secret access key, is gone here. What
        // survives is `headers`, and that is the token on the wire.
        Ok(())
    }
}

/// An error rendered without anything that could be a credential.
///
/// The sink's error type is [`StsError`], which cannot carry a transport
/// failure, so a signing failure has to be reduced to a message. Reducing it to
/// the *message* rather than the whole error is what keeps this honest: a
/// formatted `StsClientError` would quote a `SecretError`, and a `SecretError`
/// can carry a reason that came from the port.
fn leak_free(error: StsClientError) -> &'static str {
    match error {
        StsClientError::Signing(_) => "a request that cannot be signed",
        StsClientError::Request(_) => "a request that cannot be built",
        StsClientError::Transport(_) => "a transport that refused the request",
        StsClientError::Secret(_) => "a credential that cannot be lent",
        StsClientError::UnreadableStatus { .. } => "a response that cannot be read",
    }
}

/// Asks AWS which identity the session for `credential` is acting as.
///
/// This is the entry point, and it is the only one: the whole call happens
/// inside the sink so that the three values never exist anywhere but inside one
/// function, and the answer is taken before this returns. A caller cannot get a
/// half-done call, because there is no way to drive the two halves separately.
pub fn get_caller_identity(
    client: &StsClient,
    port: &super::port::AwsSecretPort,
    credential: &str,
    now: SystemTime,
) -> Result<CallerIdentity, StsClientError> {
    let mut call = SessionCall {
        client,
        now,
        answered: None,
    };
    port.lend_session(credential, now, &mut call)?;
    match call.answered {
        Some(answer) => answer,
        // Unreachable while the sink records before returning `Ok`, and named
        // rather than unwrapped so that a future change to that order reports
        // itself instead of panicking on a call an agent made.
        None => Err(StsClientError::Signing(
            super::sigv4::SignError::IncompleteScope("the port lent no session to sign with"),
        )),
    }
}

#[cfg(test)]
mod tests;
