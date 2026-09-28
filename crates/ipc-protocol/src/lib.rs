//! Versioned broker IPC.
//!
//! M0 Exit requires: "untrusted DTOs cannot deserialize into secret-bearing
//! domain types". This module is where that is enforced, and the enforcement is
//! structural rather than conventional:
//!
//! - Nothing in this crate implements [`serde::Serialize`] for a secret-bearing
//!   type, because [`asv_domain::SecretBytes`] has no such impl to call.
//! - Requests are an **externally tagged enum of closed shapes**, never a
//!   generic `{"type": "...", "payload": <opaque>}` bag. There is no path by
//!   which a client can name a type the broker has not explicitly allowed
//!   (`docs/03-ARCHITECTURE.md` §6, "explicit method allowlist").
//! - The wire format in M0 is JSON. The spec deliberately leaves CBOR/postcard/
//!   protobuf open pending fuzz ergonomics, so JSON is used here only to get the
//!   boundary right; the decoder is length-bounded and the method set is closed.

use asv_domain::{
    AgentSessionId, ApprovalId, CapabilityId, CredentialId, CredentialKind, Exportability,
};
use asv_policy::{Approval, AuthorizationRequest, ExplainResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol version. A mismatch is a hard failure, never a downgrade
/// (`docs/03-ARCHITECTURE.md` §6, version negotiation).
///
/// v2 adds the M4 semantic surface. The bump is not cosmetic: an agent that
/// speaks v1 has no way to express a surrogate, and one that speaks v2 but
/// reaches a v1 broker must fail loudly at the gate rather than discover the
/// gap when its first brokered call is denied.
pub const PROTOCOL_VERSION: u16 = 2;

/// Hard ceiling on a single inbound message. Bounded allocation is required for
/// any IPC that faces an untrusted peer (`docs/17-IMPLEMENTATION-BOOTSTRAP.md` §9).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Methods this broker exposes in M0.
///
/// The list is intentionally short. `docs/17-IMPLEMENTATION-BOOTSTRAP.md` §4
/// names exactly these, and notably omits every secret-returning method. Adding
/// a variant here is a security-relevant change and must reference an ADR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and version negotiation.
    Ping { protocol: u16 },
    /// Opens a bounded agent session.
    CreateSession { workspace: String },
    /// Closes a session and invalidates its grants.
    EndSession { session: AgentSessionId },
    /// Returns credential *metadata* only. Never values (ADR-0001).
    ListCredentialMetadata,
    /// Deletes a credential record.
    DeleteCredential { id: CredentialId },
    /// Evaluates a bounded authorization request without exposing secrets.
    Authorize {
        request: AuthorizationRequest,
        capability: Option<CapabilityId>,
        approval: Option<ApprovalId>,
    },
    /// Explains a decision without consuming grants or approvals.
    ExplainAuthorization { request: AuthorizationRequest },
    /// Records an exact human approval for a bounded request.
    SubmitApproval {
        request: AuthorizationRequest,
        ttl_secs: u64,
    },
    /// Mints a short-lived surrogate for an already-authorized session (M4 D3).
    ///
    /// The broker returns a bearer-shaped string the agent may present instead
    /// of a `CredentialId`. Minting is not authorization: it requires a
    /// pinned session, but the *operation* the surrogate will later stand in
    /// for is still evaluated by [`Request::Authorize`] at use time.
    MintSurrogate {
        session: AgentSessionId,
        /// The credential the surrogate will stand in for. The agent never
        /// learns the secret behind this id, and the surrogate is useless
        /// without it.
        credential: CredentialId,
        /// How many operations this surrogate may authorize. Bounded because an
        /// unbounded surrogate is a permanent credential with extra steps.
        max_uses: u32,
        /// Lifetime in seconds, capped by [`MAX_SURROGATE_TTL_SECS`].
        ttl_secs: u64,
    },
    /// Releases a surrogate before its natural expiry.
    RevokeSurrogate {
        session: AgentSessionId,
        surrogate: String,
    },
    /// Semantic GitHub issue read (M4-R9). Read-only and provider-shaped, so
    /// the policy engine evaluates `github.issue.read` rather than a
    /// catch-all HTTP verb.
    ReadIssue {
        session: AgentSessionId,
        surrogate: String,
        /// `owner/repo`, validated before any byte leaves the process.
        repo: String,
        number: u64,
    },
    /// Semantic GitHub issue creation.
    CreateIssue {
        session: AgentSessionId,
        surrogate: String,
        repo: String,
        title: String,
        body: String,
    },
    /// Semantic GitHub release creation.
    CreateRelease {
        session: AgentSessionId,
        surrogate: String,
        repo: String,
        tag: String,
        name: String,
        body: String,
    },
}

/// Broker responses. Every variant is safe to return to an agent: none of them
/// can hold secret material, by construction rather than by review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong {
        protocol: u16,
    },
    SessionCreated {
        session: AgentSessionId,
    },
    SessionEnded {
        session: AgentSessionId,
    },
    CredentialMetadata {
        entries: Vec<CredentialMetadataDto>,
    },
    CredentialDeleted {
        id: CredentialId,
    },
    Authorization {
        explanation: ExplainResult,
    },
    ApprovalIssued {
        approval: Approval,
    },
    /// A freshly minted surrogate. This is the only response that ever carries
    /// a credential-shaped string, and it carries a *surrogate*, never a
    /// secret: the broker keeps the real credential in-process.
    SurrogateMinted {
        surrogate: String,
        /// Absolute expiry, as a UNIX timestamp in seconds. Absolute rather
        /// than a duration so a client cannot extend a grant by resetting a
        /// local timer.
        expires_at: u64,
        max_uses: u32,
    },
    SurrogateRevoked {
        surrogate: String,
    },
    /// The three fields M4-R9 promises for a read, and nothing else. Notably
    /// absent: the raw provider body, which could carry anything upstream
    /// chose to add to it.
    IssueRead {
        title: String,
        body: String,
        state: String,
    },
    IssueCreated {
        number: u64,
        url: String,
    },
    ReleaseCreated {
        tag: String,
        url: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// Hard ceiling on a surrogate's lifetime, in seconds (M4 D3).
///
/// The agent proposes a TTL and the broker clamps it here. A client that could
/// choose an unbounded TTL would make the whole expiry mechanism advisory, so
/// this constant is not a default the broker falls back to, it is a limit the
/// broker enforces over the client's request.
pub const MAX_SURROGATE_TTL_SECS: u64 = 900;

/// Hard ceiling on a surrogate's use budget.
///
/// One is the common case and two already covers a retry. A larger budget
/// turns the surrogate into a bearer token with a long tail, which is the
/// shape ADR-0011 exists to avoid.
pub const MAX_SURROGATE_USES: u32 = 8;

/// Serializable view of credential metadata.
///
/// A DTO, not the domain type, so that the wire shape can evolve independently
/// and so that adding a field to the domain cannot accidentally start
/// transmitting something new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadataDto {
    pub id: Uuid,
    pub label: String,
    pub kind: CredentialKind,
    pub exportability: Exportability,
}

impl From<&asv_domain::CredentialMetadata> for CredentialMetadataDto {
    fn from(m: &asv_domain::CredentialMetadata) -> Self {
        Self {
            id: *m.id.as_uuid(),
            label: m.label.clone(),
            kind: m.kind,
            exportability: m.exportability,
        }
    }
}

/// Stable, non-leaky error codes (`docs/10-CLI-MCP-API.md` §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Peer credentials could not be established.
    Unauthenticated,
    /// Protocol version mismatch.
    VersionMismatch,
    /// Message exceeded `MAX_MESSAGE_BYTES`.
    MessageTooLarge,
    /// The requested method does not exist.
    UnknownMethod,
    /// Policy denied the operation.
    Denied,
    /// The request was well-formed but semantically invalid.
    InvalidRequest,
    /// The surrogate's time window has passed.
    ///
    /// Split from `Denied` for the agent's benefit, not the operator's: "your
    /// token ran out of time" and "your token was never valid" both mean "mint
    /// a new one", but only one of them is worth a bug report. Collapsing them
    /// would make a working integration look broken.
    SurrogateExpired,
    /// The surrogate's use budget is spent.
    ///
    /// Separate from `SurrogateExpired` for the same reason, and with a second
    /// audience: a caller that always exhausts its budget has a budgeting
    /// bug, and the distinct code is what makes that visible.
    SurrogateExhausted,
    /// The provider answered, or failed to, in a way the broker relays.
    ///
    /// Not `Internal`. The broker did its job and the network or the provider
    /// did not, and an agent that cannot tell those apart will retry a
    /// non-retryable failure or file a bug against the broker for a DNS
    /// timeout.
    Upstream,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("message of {size} bytes exceeds the {max} byte limit")]
    MessageTooLarge { size: usize, max: usize },

    #[error("client speaks protocol {client}, broker speaks {broker}")]
    VersionMismatch { client: u16, broker: u16 },

    #[error("malformed request: {0}")]
    Malformed(String),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
}

/// Length-bounded JSON decoder.
///
/// This is the choke point for all untrusted input. It checks the size bound
/// before handing bytes to serde, so a hostile peer cannot make the broker
/// allocate unbounded memory.
pub fn decode_request(input: &[u8]) -> Result<Request, ProtocolError> {
    if input.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            size: input.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let request: Request =
        serde_json::from_slice(input).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    Ok(request)
}

/// Encodes a response with the same size bound, so a response can never grow
/// past what a client agreed to accept.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        serde_json::to_vec(response).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    Ok(bytes)
}

/// Rejects any request whose protocol version the broker does not implement.
pub fn check_version(request: &Request) -> Result<(), ProtocolError> {
    if let Request::Ping { protocol } = request {
        if *protocol != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                client: *protocol,
                broker: PROTOCOL_VERSION,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "ASV-CANARY-8d3a5b0c-DO-NOT-LEAK";

    /// M0 Exit: untrusted DTOs cannot become secret-bearing domain types.
    ///
    /// A JSON document that tries to smuggle secret material in must be
    /// rejected as malformed rather than partially accepted.
    #[test]
    fn unknown_method_is_rejected() {
        let payload = br#"{"method":"get_secret","id":"anything"}"#;
        let err = decode_request(payload).expect_err("get_secret must not decode");
        assert!(matches!(err, ProtocolError::Malformed(_)), "got {err:?}");
        assert!(!String::from_utf8_lossy(payload).contains("ok"), "sanity");
    }

    /// The forbidden-method names from `docs/10-CLI-MCP-API.md` §5 must not
    /// resolve to anything in the protocol, by any casing or nesting.
    #[test]
    fn every_forbidden_method_name_fails_to_decode() {
        let forbidden = [
            "get_secret",
            "GetSecret",
            "export_secret_for_agent",
            "get_decrypted_payload",
            "run_arbitrary_command_with_secret",
        ];
        for name in forbidden {
            let payload = format!(r#"{{"method":"{name}"}}"#);
            let result = decode_request(payload.as_bytes());
            assert!(
                result.is_err(),
                "forbidden method {name} unexpectedly decoded: {result:?}"
            );
        }
    }

    /// A canary value placed in any field must never survive into a response.
    #[test]
    fn canary_in_request_never_reaches_a_response() {
        let payload = format!(r#"{{"method":"create_session","workspace":"{CANARY}"}}"#);
        let request = decode_request(payload.as_bytes()).expect("valid request");
        let response = match &request {
            Request::CreateSession { .. } => Response::SessionCreated {
                session: AgentSessionId::new(),
            },
            other => panic!("unexpected request {other:?}"),
        };
        let encoded = encode_response(&response).expect("encodes");
        let text = String::from_utf8(encoded).expect("utf8");
        assert!(
            !text.contains(CANARY),
            "canary crossed the DTO boundary: {text}"
        );
    }

    /// Size bounds must be enforced before parsing, not after.
    #[test]
    fn oversized_message_is_rejected_before_parsing() {
        let huge = vec![b'a'; MAX_MESSAGE_BYTES + 1];
        let err = decode_request(&huge).expect_err("oversized must be rejected");
        assert!(
            matches!(err, ProtocolError::MessageTooLarge { .. }),
            "got {err:?}"
        );
        // Not a parse error: the bound fired first, which is the point.
        assert!(!matches!(err, ProtocolError::Malformed(_)));
    }

    /// Truncated and garbage input must fail closed, never panic.
    #[test]
    fn malformed_input_fails_closed() {
        for payload in [
            &b""[..],
            &b"{"[..],
            &b"[]"[..],
            &b"null"[..],
            &b"{\"method\":\"ping\""[..],
            &[0xff, 0xfe, 0xfd][..],
        ] {
            assert!(
                decode_request(payload).is_err(),
                "malformed payload unexpectedly accepted: {payload:?}"
            );
        }
    }

    /// Version negotiation is a hard gate with no downgrade path.
    ///
    /// The accepted version is `PROTOCOL_VERSION`, not a literal: pinning the
    /// number here would make every future bump fail this test for a reason
    /// that has nothing to do with negotiation, and the fix would be to
    /// rewrite the test rather than the gate.
    #[test]
    fn version_mismatch_is_rejected() {
        let current = format!(r#"{{"method":"ping","protocol":{PROTOCOL_VERSION}}}"#);
        let ok = decode_request(current.as_bytes()).expect("current version decodes");
        assert!(check_version(&ok).is_ok());

        let old = decode_request(br#"{"method":"ping","protocol":0}"#).expect("decodes");
        let err = check_version(&old).expect_err("v0 must be rejected");
        assert!(
            matches!(
                err,
                ProtocolError::VersionMismatch {
                    client: 0,
                    broker: PROTOCOL_VERSION
                }
            ),
            "got {err:?}"
        );
    }

    /// The metadata DTO is the only credential shape that crosses the wire,
    /// and it has no field capable of carrying material.
    #[test]
    fn metadata_dto_has_no_secret_field() {
        let m = asv_domain::CredentialMetadata::new("github-work", CredentialKind::BearerToken);
        let dto = CredentialMetadataDto::from(&m);
        let json = serde_json::to_string(&dto).expect("dto serializes");
        assert!(json.contains("github-work"));
        assert!(!json.to_lowercase().contains("secret"));
        assert!(!json.to_lowercase().contains("value"));
        assert!(!json.to_lowercase().contains("payload"));
    }

    /// v1 and v2 must not interoperate. If a v2 client could reach a v1
    /// broker, the failure would surface as a denied call rather than as a
    /// version error, and the cause would be misattributed.
    #[test]
    fn the_v2_bump_is_a_hard_boundary() {
        let v1 = decode_request(br#"{"method":"ping","protocol":1}"#).expect("decodes");
        assert!(
            check_version(&v1).is_err(),
            "a v1 client must not be served by a v2 broker"
        );
        let v2 = decode_request(br#"{"method":"ping","protocol":2}"#).expect("decodes");
        assert!(check_version(&v2).is_ok());
    }

    /// Every M4 method must round-trip with its fields intact. A rename or a
    /// dropped field here would silently change the wire contract that the
    /// broker and the agent both compile against.
    #[test]
    fn the_m4_methods_round_trip_on_the_wire() {
        let session = AgentSessionId::new();
        let credential = CredentialId::new();
        for request in [
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 2,
                ttl_secs: 60,
            },
            Request::RevokeSurrogate {
                session,
                surrogate: "asv1_abc".into(),
            },
            Request::ReadIssue {
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                number: 7,
            },
            Request::CreateIssue {
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                title: "t".into(),
                body: "b".into(),
            },
            Request::CreateRelease {
                session,
                surrogate: "asv1_abc".into(),
                repo: "owner/repo".into(),
                tag: "v1".into(),
                name: "n".into(),
                body: "b".into(),
            },
        ] {
            let json = serde_json::to_string(&request).expect("serializes");
            assert!(
                json.len() <= MAX_MESSAGE_BYTES,
                "{json} exceeds the message bound"
            );
            let decoded: Request = serde_json::from_str(&json).expect("round-trips");
            assert_eq!(decoded, request);
        }
    }

    /// A response must never be able to carry secret material. This walks the
    /// M4 responses rather than trusting the doc comment on the enum, because
    /// a doc comment is exactly the kind of claim that rots when a variant is
    /// added.
    #[test]
    fn m4_responses_carry_no_secret_field() {
        for response in [
            Response::SurrogateMinted {
                surrogate: "asv1_abc".into(),
                expires_at: 1,
                max_uses: 1,
            },
            Response::SurrogateRevoked {
                surrogate: "asv1_abc".into(),
            },
            Response::IssueRead {
                title: "t".into(),
                body: "b".into(),
                state: "open".into(),
            },
            Response::IssueCreated {
                number: 1,
                url: "u".into(),
            },
            Response::ReleaseCreated {
                tag: "v1".into(),
                url: "u".into(),
            },
        ] {
            let json = serde_json::to_string(&response).expect("serializes");
            let lowered = json.to_lowercase();
            for forbidden in ["secret", "token", "password", "private_key"] {
                assert!(
                    !lowered.contains(forbidden),
                    "{forbidden} leaked into {json}"
                );
            }
        }
    }

    /// A pinned-in-value test on two constants cannot fail in a useful way: it
    /// either compiles or it does not, so asserting `TTL > 0` here proves
    /// nothing an `if` at the mint site would not. The caps are checked where
    /// they are actually enforced instead, in
    /// `asv_broker::surrogate` (`a_surrogate_dies_exactly_at_its_expiry` and
    /// `a_client_cannot_mint_a_surrogate_that_outlives_the_cap`).
    #[test]
    fn a_mint_request_always_fits_inside_the_wire_bound() {
        // What *is* worth asserting here is the shape: every field a client
        // controls has to be representable without a broker-side truncation
        // surprise, so a full-size request must still be a normal request.
        let request = Request::MintSurrogate {
            session: AgentSessionId::new(),
            credential: CredentialId::new(),
            max_uses: MAX_SURROGATE_USES,
            ttl_secs: MAX_SURROGATE_TTL_SECS,
        };
        let json = serde_json::to_string(&request).expect("serializes");
        assert!(json.len() < MAX_MESSAGE_BYTES / 2, "{json}");
    }
}
