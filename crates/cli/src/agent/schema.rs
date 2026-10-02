//! The `asv.agent/v1` envelope — `06-CLI-CONTRACT.md` §2.
//!
//! One shape for every command that speaks machine-readably. Six keys, and
//! only `data` varies between them:
//!
//! ```text
//! schema, product_version, protocol_version, status, data, links, warnings
//! ```
//!
//! Two properties are load-bearing and both are asserted in this module's
//! tests rather than left to review:
//!
//! **The status vocabulary is closed.** `Status` has four variants and
//! serialises to exactly the four spellings in the contract. An agent is
//! expected to switch on this string, so a fifth status is a breaking change
//! and not a convenience — the enum is what makes that visible.
//!
//! **`data` is `Option`, not `Value`.** A missing payload and an empty object
//! are different facts: `error` is set when there is no data, and a document
//! that carries `data: {}` alongside an error is telling the consumer to read
//! a payload that does not exist.

use serde::{Deserialize, Serialize};

/// The schema identifier. A consumer that does not recognise this string must
/// refuse to follow the links rather than guess (AAT-008, fail closed).
pub const SCHEMA: &str = "asv.agent/v1";

/// Overall state, from `06-CLI-CONTRACT.md` §2.
///
/// `Blocked` and `Error` are kept apart on purpose. `Blocked` means the
/// product is installed and knows what is missing, and a listed link will fix
/// it. `Error` means the CLI could not reach that conclusion — it could not
/// read its own installation, for instance. An agent offered `Blocked` can run
/// `asv setup`; an agent offered `Error` must not, because the diagnosis is
/// missing, and guessing at a repair is how an agent does something the user
/// did not ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Everything needed for the requested operation is present.
    Ready,
    /// Usable, with something optional absent. The consumer may proceed.
    Degraded,
    /// Not usable, and the document says which step would change that.
    Blocked,
    /// The diagnosis itself failed. Not repairable by following a link.
    Error,
}

impl Status {
    /// The wire spelling. Kept as a function rather than a `Display` so that
    /// the JSON is produced by an explicit call: a `Display` impl is easy to
    /// reach for from a human renderer, and then the two renderers can drift
    /// on capitalisation.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ready => "ready",
            Status::Degraded => "degraded",
            Status::Blocked => "blocked",
            Status::Error => "error",
        }
    }
}

/// A machine-readable diagnostic that does not stop the operation.
///
/// Separate from `AgentError` because a warning has a code an agent can
/// branch on without the document being a failure — `TPM_UNAVAILABLE` on a
/// machine with no TPM is a warning, and the document is still `ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    /// Stable, screaming-snake identifier. The programmable part.
    pub code: String,
    /// Prose for humans. Never load-bearing.
    pub message: String,
}

/// A terminal failure. `code` is the contract; `message` is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentError {
    pub code: String,
    pub message: String,
}

/// The `asv.agent/v1` document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub schema: String,
    pub product_version: String,
    pub protocol_version: u32,
    pub status: Status,
    /// The command-specific payload. `None` when the command failed, which is
    /// not the same as `Some({})`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentError>,
    pub links: Vec<crate::agent::relations::AgentLink>,
    pub warnings: Vec<Warning>,
}

impl Envelope {
    /// Builds an envelope for a command that produced a payload.
    ///
    /// `status` is a parameter rather than derived, because derivation is a
    /// decision about what the payload means and belongs with whoever read the
    /// installation — see `doctor::DoctorReport::status`.
    pub fn new(status: Status, data: serde_json::Value) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            product_version: crate::build_version().to_string(),
            // Widened from the protocol's `u16` on the way into JSON. The
            // conversion is explicit so that a future protocol bump cannot
            // silently change what this field means.
            protocol_version: u32::from(asv_ipc_protocol::PROTOCOL_VERSION),
            status,
            data: Some(data),
            error: None,
            links: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Builds an envelope for a command that failed before it had a payload.
    pub fn failed(status: Status, code: &str, message: String) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            product_version: crate::build_version().to_string(),
            // Widened from the protocol's `u16` on the way into JSON. The
            // conversion is explicit so that a future protocol bump cannot
            // silently change what this field means.
            protocol_version: u32::from(asv_ipc_protocol::PROTOCOL_VERSION),
            status,
            data: None,
            error: Some(AgentError {
                code: code.to_string(),
                message,
            }),
            links: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Adds a link. Chains, because every caller adds several.
    pub fn with_link(mut self, link: crate::agent::relations::AgentLink) -> Self {
        self.links.push(link);
        self
    }

    /// Adds a warning. Chains, for the same reason.
    pub fn with_warning(mut self, code: &str, message: impl Into<String>) -> Self {
        self.warnings.push(Warning {
            code: code.to_string(),
            message: message.into(),
        });
        self
    }

    /// Serialises to the single line a machine consumer reads.
    ///
    /// Compact rather than pretty: the document is meant to be piped, and a
    /// pretty-printed envelope in a pipeline turns every agent's first step
    /// into a line-wrapping exercise.
    pub fn to_json(&self) -> String {
        // The types here are hand-written and `String`-valued throughout, so
        // serialisation cannot fail. If a future field makes that untrue, a
        // panic here is the correct outcome: a CLI that cannot render its own
        // contract has nothing honest to print.
        serde_json::to_string(self).expect("the asv.agent/v1 envelope always serialises")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: Status) -> Envelope {
        Envelope::new(status, serde_json::json!({"cli_version": "0.26.0"}))
    }

    /// The four spellings in the contract, and only those. An agent switches on
    /// this string, so the set is part of the public interface: a fifth
    /// status is a breaking change, and the test that would notice is here.
    #[test]
    fn the_status_vocabulary_is_exactly_the_four_in_the_contract() {
        let spellings: Vec<&str> = [
            Status::Ready,
            Status::Degraded,
            Status::Blocked,
            Status::Error,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(spellings, ["ready", "degraded", "blocked", "error"]);
    }

    /// `as_str` and the serde spelling must agree. They are two ways of
    /// writing the same four strings, which is exactly the shape of a drift
    /// bug: a human renderer reaching for `as_str` and the JSON reaching for
    /// `Serialize` would eventually disagree on one of them.
    #[test]
    fn the_status_spellings_agree_in_both_renders() {
        for status in [
            Status::Ready,
            Status::Degraded,
            Status::Blocked,
            Status::Error,
        ] {
            let via_serde = serde_json::to_value(status).expect("serialises");
            assert_eq!(via_serde, serde_json::Value::String(status.as_str().into()));
        }
    }

    /// The six fixed keys are always present, whatever the command. A consumer
    /// that has to check whether `links` is missing is a consumer that will
    /// eventually forget to.
    #[test]
    fn the_fixed_keys_are_always_present() {
        let value: serde_json::Value =
            serde_json::from_str(&sample(Status::Ready).to_json()).expect("round-trips");
        for key in [
            "schema",
            "product_version",
            "protocol_version",
            "status",
            "links",
            "warnings",
        ] {
            assert!(
                value.get(key).is_some(),
                "`{key}` missing from the envelope"
            );
        }
    }

    /// A failure carries no payload. `data: {}` next to an error would invite
    /// a consumer to read fields that were never written, and the fields it
    /// invented would be nulls it then has to interpret.
    #[test]
    fn a_failure_carries_no_data_key_at_all() {
        let envelope = Envelope::failed(Status::Blocked, "SETUP_REQUIRED", "no broker".into());
        let value: serde_json::Value =
            serde_json::from_str(&envelope.to_json()).expect("round-trips");
        assert!(
            value.get("data").is_none(),
            "a failure must not emit `data`"
        );
        assert_eq!(value["error"]["code"], "SETUP_REQUIRED");
    }

    /// The schema string is the one an unknown consumer refuses on, so it is
    /// pinned rather than assembled from a version number.
    #[test]
    fn the_schema_string_is_pinned() {
        assert_eq!(sample(Status::Ready).schema, "asv.agent/v1");
    }
}
