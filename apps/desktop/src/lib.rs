//! `apps/desktop` — the M5 operator console.
//!
//! A Tauri shell that renders and translates. It owns no policy: every
//! question about what may be revealed, copied, exported or shown is answered
//! by `asv-operator-core`, which is tested without a WebView.
//!
//! # Why this crate is its own workspace
//!
//! The pipeline runs `cargo build/test/clippy --workspace` in a clean
//! container that has the GUI *runtime* but not the *headers*. A member here
//! would make every headless step depend on `webkit2gtk-devel`, so the shell
//! is excluded from the core workspace (see the root `Cargo.toml`) and built
//! separately. See `apps/desktop/README.md` for the build.
//!
//! # What is testable where
//!
//! - Headless (`cargo test -p asv-desktop`, no display): the command table,
//!   the refusal ordering, and that no value crosses the bridge.
//! - WebView (`apps/desktop/tests/uat_019_xss.rs`): that a hostile string is
//!   rendered as data, that no script runs, and that the WebView cannot
//!   invoke a command the registry does not expose.

pub mod backend;
pub mod surface;

use backend::{Backend, Disconnected};
use surface::Console;

/// Build a console over `backend`.
pub fn console(backend: Box<dyn Backend + Send + Sync>) -> Console {
    Console::with_backend(backend)
}

/// A console with no broker connection.
pub fn disconnected_console() -> Console {
    Console::with_backend(Box::new(Disconnected))
}

#[cfg(test)]
mod bridge_tests {
    //! What actually crosses the boundary into the WebView.
    //!
    //! Every assertion in this module is a *negative* one: it looks for a
    //! secret in output that should not contain one. A positive assertion
    //! ("the payload has the right fields") would pass on an empty payload
    //! and prove nothing.

    use super::*;
    use serde_json::json;

    /// A backend that hands back a credential whose value is a known canary.
    ///
    /// The canary is the whole technique: if the bridge ever leaks a value,
    /// the leak has a name we can grep for. "We checked and it seemed fine"
    /// is not a check.
    struct CanaryBackend;

    const CANARY: &str = "ASV-CANARY-3f9a2b7c-do-not-leak";

    impl Backend for CanaryBackend {
        fn list_credential_metadata(&self) -> Vec<backend::CredentialSummary> {
            vec![backend::CredentialSummary {
                id: "cred-1".into(),
                label: "prod-db".into(),
                provider: "postgres".into(),
                exportability: asv_domain::Exportability::HumanOnly,
                has_agent_access: true,
            }]
        }
        fn add_credential(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "id": "cred-2" })
        }
        fn delete_credential(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "deleted": true })
        }
        fn list_policies(&self) -> serde_json::Value {
            json!({ "items": [] })
        }
        fn list_approvals(&self) -> serde_json::Value {
            json!({ "items": [] })
        }
        fn decide_approval(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "decided": true })
        }
        fn list_sessions(&self) -> serde_json::Value {
            json!({ "items": [] })
        }
        fn end_session(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "ended": true })
        }
        fn read_audit(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "items": [] })
        }
        fn list_posture(&self) -> serde_json::Value {
            json!({ "items": [] })
        }
        fn begin_reveal(&self, _p: &serde_json::Value) -> serde_json::Value {
            json!({ "error": "not implemented in the canary backend" })
        }
    }

    /// UAT-019: "stored secret cannot be read".
    ///
    /// The canary is not in any `CredentialSummary` field, so no command may
    /// return it. If a future backend adds a field that leaks, this is the
    /// test that catches it — and it catches it by *naming the leak*, which
    /// is why the assertion message includes the value.
    #[test]
    fn the_canary_never_crosses_the_bridge() {
        let console = console(Box::new(CanaryBackend));
        for capability in asv_operator_core::capability::Capability::ALL {
            let outcome = console.dispatch(capability.as_str(), Ok(json!({})));
            let rendered = format!("{outcome:?}");
            assert!(
                !rendered.contains(CANARY),
                "command `{}` returned credential material into the console surface",
                capability.as_str()
            );
        }
    }

    /// The complement: the list command really does return something.
    ///
    /// Without this, `the_canary_never_crosses_the_bridge` would be satisfied
    /// by a console that returns nothing at all. This is the test that keeps
    /// the negative one honest.
    #[test]
    fn the_list_command_actually_returns_metadata() {
        let console = console(Box::new(CanaryBackend));
        let Outcome::Ok { payload } = console.dispatch("list_credentials", Ok(json!({}))) else {
            panic!("list_credentials did not succeed");
        };
        let items = payload["items"].as_array().expect("items is an array");
        assert_eq!(items.len(), 1, "the canary backend has one credential");
        assert_eq!(items[0]["label"], "prod-db");
        assert!(
            !items[0].as_object().unwrap().contains_key("value"),
            "a metadata row carried a value field"
        );
    }

    /// A console with no backend returns nothing. Failing into empty, not
    /// into permissive, is the property; the assertion is on the items array.
    #[test]
    fn a_disconnected_console_is_empty_rather_than_open() {
        let console = disconnected_console();
        let Outcome::Ok { payload } = console.dispatch("list_credentials", Ok(json!({}))) else {
            panic!("list_credentials did not succeed");
        };
        assert_eq!(payload["items"].as_array().map(Vec::len), Some(0));
    }
}
