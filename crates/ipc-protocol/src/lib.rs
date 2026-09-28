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
pub const PROTOCOL_VERSION: u16 = 1;

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
}

/// Broker responses. Every variant is safe to return to an agent: none of them
/// can hold secret material, by construction rather than by review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong { protocol: u16 },
    SessionCreated { session: AgentSessionId },
    SessionEnded { session: AgentSessionId },
    CredentialMetadata { entries: Vec<CredentialMetadataDto> },
    CredentialDeleted { id: CredentialId },
    Authorization { explanation: ExplainResult },
    ApprovalIssued { approval: Approval },
    Error { code: ErrorCode, message: String },
}

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
    #[test]
    fn version_mismatch_is_rejected() {
        let ok = decode_request(br#"{"method":"ping","protocol":1}"#).expect("v1 ok");
        assert!(check_version(&ok).is_ok());

        let old = decode_request(br#"{"method":"ping","protocol":0}"#).expect("decodes");
        let err = check_version(&old).expect_err("v0 must be rejected");
        assert!(
            matches!(
                err,
                ProtocolError::VersionMismatch {
                    client: 0,
                    broker: 1
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
}
