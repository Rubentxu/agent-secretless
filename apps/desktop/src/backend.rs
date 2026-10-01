//! The backend the console delegates to.
//!
//! Split out of [`crate::surface`] so the command table and the refusal
//! ordering can be tested without a running broker, and so a test can prove
//! what crosses the bridge.
//!
//! The interesting property is in the signatures: **every method returns
//! metadata, and no method returns a credential value.** There is no
//! `get_secret` here to call, so the shell cannot be written to call one. The
//! one method that takes a secret — [`Backend::add_credential`] — takes it as
//! an *input* and returns an id.

use asv_domain::Exportability;

/// A credential's metadata, as the console is allowed to see it.
///
/// The projection is explicit. A field cannot reach the WebView by being
/// forgotten here, because there is nowhere to forget it from: this is the
/// whole answer, not a filtered version of a larger one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialSummary {
    pub id: String,
    pub label: String,
    pub provider: String,
    pub exportability: Exportability,
    pub has_agent_access: bool,
}

/// Where the console gets its data.
///
/// `Send + Sync` is required because Tauri holds the console as managed state
/// and hands it to whichever worker thread is serving a command. The trait
/// does not demand thread-safety of its own — the broker client behind it is
/// already synchronised — but the console that owns it has to be movable into
/// a thread to be usable at all.
pub trait Backend: Send + Sync {
    fn list_credential_metadata(&self) -> Vec<CredentialSummary>;
    fn add_credential(&self, payload: &serde_json::Value) -> serde_json::Value;
    fn delete_credential(&self, payload: &serde_json::Value) -> serde_json::Value;
    fn list_policies(&self) -> serde_json::Value;
    fn list_approvals(&self) -> serde_json::Value;
    fn decide_approval(&self, payload: &serde_json::Value) -> serde_json::Value;
    fn list_sessions(&self) -> serde_json::Value;
    fn end_session(&self, payload: &serde_json::Value) -> serde_json::Value;
    fn read_audit(&self, payload: &serde_json::Value) -> serde_json::Value;
    fn list_posture(&self) -> serde_json::Value;
    /// Starts the reveal *flow*. Returns a ticket, never a value: the value
    /// is only produced by the re-authenticated continuation that
    /// `asv-operator-core`'s clipboard policy governs.
    fn begin_reveal(&self, payload: &serde_json::Value) -> serde_json::Value;
}

/// A backend that answers nothing.
///
/// The default for a console opened without a broker connection. A console
/// with no backend has no data, which is the correct state to fail into:
/// empty, not permissive.
#[derive(Debug, Default, Clone, Copy)]
pub struct Disconnected;

impl Backend for Disconnected {
    fn list_credential_metadata(&self) -> Vec<CredentialSummary> {
        Vec::new()
    }
    fn add_credential(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
    fn delete_credential(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
    fn list_policies(&self) -> serde_json::Value {
        serde_json::json!({ "items": [], "error": "no broker connection" })
    }
    fn list_approvals(&self) -> serde_json::Value {
        serde_json::json!({ "items": [], "error": "no broker connection" })
    }
    fn decide_approval(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
    fn list_sessions(&self) -> serde_json::Value {
        serde_json::json!({ "items": [], "error": "no broker connection" })
    }
    fn end_session(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
    fn read_audit(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "items": [], "error": "no broker connection" })
    }
    fn list_posture(&self) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
    fn begin_reveal(&self, _p: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "error": "no broker connection" })
    }
}
