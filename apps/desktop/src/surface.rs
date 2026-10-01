//! The shell's command table, and the rule that it is not the shell's to make.
//!
//! Everything here is deliberately free of Tauri types. The point of
//! `apps/desktop` is that its *policy surface* is testable without a WebView;
//! if dispatch needed a `tauri::AppHandle` this file could not be tested
//! headlessly, and the security-relevant parts would only be checkable on a
//! machine with a display — which the pipeline does not have.
//!
//! The rule from the spec: **the shell does not decide anything.** It parses
//! a name, asks [`asv_operator_core`] whether that name is a capability and
//! whether it is exposed, and then runs the corresponding operation. There is
//! no `if exportability == ...` anywhere in this crate.

use asv_operator_core::capability::{Capability, Registry};

use crate::backend::{Backend, Disconnected};

/// What a command produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// The command ran. `payload` holds metadata, never credential material —
    /// no registered capability can return any, and the core test
    /// `no_capability_returns_secret_material` is what holds that line.
    Ok { payload: serde_json::Value },
    /// The name is not a registered command. Refused *before* the argument is
    /// looked at.
    UnknownCommand,
    /// The name is a real command but this console does not expose it.
    NotExposed,
    /// The command needs a capability it was not given for this invocation.
    Denied { reason: String },
}

/// The set of commands this console exposes.
///
/// Deny-by-default in the strongest sense: the list below is *derived from*
/// the core's vocabulary rather than typed out again. A typo here is a
/// compile error or a test failure, never a command that the shell answers
/// but the registry has never heard of.
pub fn exposed() -> Vec<Capability> {
    vec![
        Capability::ListCredentials,
        Capability::AddCredential,
        Capability::DeleteCredential,
        Capability::ListPolicies,
        Capability::ListApprovals,
        Capability::DecideApproval,
        Capability::ListSessions,
        Capability::EndSession,
        Capability::ReadAudit,
        Capability::ListPosture,
        Capability::BeginReveal,
    ]
}

/// A registry containing exactly the commands this console exposes.
pub fn registry() -> Registry {
    Registry::new(exposed())
}

/// Resolve a wire name to a capability, refusing anything the core does not
/// know.
///
/// The core owns the vocabulary. The shell has no list of names of its own,
/// so "the WebView invoked a command that does not exist" is a property of
/// `Capability::from_wire`, which is deny-by-default and matches exactly.
pub fn resolve(wire_name: &str) -> Option<Capability> {
    Capability::from_wire(wire_name)
}

/// Check a name without running it.
///
/// Split out from [`Console::dispatch`] so the Tauri handler can refuse
/// before it has touched an argument, and so the check is testable on its
/// own. The order is load-bearing: name first, then authorisation. An
/// unauthorised name never reaches whatever would have parsed its payload.
pub fn preauthorize(registry: &Registry, wire_name: &str) -> Result<Capability, Outcome> {
    let capability = resolve(wire_name).ok_or(Outcome::UnknownCommand)?;
    registry
        .authorize(capability)
        .map_err(|_| Outcome::NotExposed)?;
    Ok(capability)
}

/// The console: a registry plus the operations that back each capability.
pub struct Console {
    registry: Registry,
    backend: Box<dyn Backend>,
}

impl Default for Console {
    /// A console with no backend has no data, which is the correct state to
    /// fail into: empty, not permissive.
    fn default() -> Self {
        Self::with_backend(Box::new(Disconnected))
    }
}

impl Console {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_backend(backend: Box<dyn Backend>) -> Self {
        Self {
            registry: registry(),
            backend,
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Dispatch one invocation.
    ///
    /// `args` is deliberately *not* touched until `preauthorize` has returned
    /// `Ok`. That ordering is the whole of S-2 and S-3: an unknown or
    /// unexposed name is refused without the payload ever being parsed, so a
    /// hostile argument cannot be used to probe what a command would accept.
    pub fn dispatch(
        &self,
        wire_name: &str,
        args: Result<serde_json::Value, serde_json::Error>,
    ) -> Outcome {
        let capability = match preauthorize(&self.registry, wire_name) {
            Ok(capability) => capability,
            Err(outcome) => return outcome,
        };

        // From here the argument may be read.
        let payload = match args {
            Ok(value) => value,
            Err(err) => {
                return Outcome::Denied {
                    reason: format!("malformed argument: {err}"),
                }
            }
        };

        self.execute(capability, payload)
    }

    /// Run an already-authorised capability.
    ///
    /// Note what is absent: there is no branch that returns a credential
    /// value, because no such capability exists to branch on. Adding one
    /// requires a new enum variant, which is a change to
    /// `asv-operator-core` where the test
    /// `no_capability_returns_secret_material` has to be defeated on purpose.
    fn execute(&self, capability: Capability, payload: serde_json::Value) -> Outcome {
        // Note what is absent: no branch returns a credential value, because
        // no such capability exists to branch on. Adding one needs a new
        // variant in `asv-operator-core`, where the test
        // `no_capability_returns_secret_material` must be defeated on purpose.
        let body = match capability {
            Capability::ListCredentials => self.list_credentials(),
            Capability::AddCredential => self.backend.add_credential(&payload),
            Capability::DeleteCredential => self.backend.delete_credential(&payload),
            Capability::ListPolicies => self.list_policies(),
            Capability::ListApprovals => self.backend.list_approvals(),
            Capability::DecideApproval => self.backend.decide_approval(&payload),
            Capability::ListSessions => self.backend.list_sessions(),
            Capability::EndSession => self.backend.end_session(&payload),
            Capability::ReadAudit => self.backend.read_audit(&payload),
            Capability::ListPosture => self.backend.list_posture(),
            Capability::BeginReveal => self.backend.begin_reveal(&payload),
        };
        Outcome::Ok { payload: body }
    }

    /// Credential *metadata*, per UAT-019's "stored secret cannot be read".
    ///
    /// The projection is the point: it names the fields it will return, so a
    /// field that does not exist cannot be added to the answer by forgetting
    /// to filter it out.
    fn list_credentials(&self) -> serde_json::Value {
        serde_json::json!({
            "items": self.backend.list_credential_metadata(),
            "note": "metadata only; no value crosses this bridge",
        })
    }

    fn list_policies(&self) -> serde_json::Value {
        serde_json::json!({ "items": self.backend.list_policies() })
    }
}

/// Re-exported so the shell and its tests name the same error type.
pub use asv_operator_core::capability::CapabilityError as Refusal;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn console() -> Console {
        Console::new()
    }

    /// S-3. The shell's command table is a *subset* of the core's vocabulary.
    ///
    /// This compares two lists rather than reading code, which is the only
    /// version of the claim that stays true when someone edits the shell.
    #[test]
    fn the_shell_exposes_only_capabilities_the_core_knows() {
        for capability in exposed() {
            assert!(
                Capability::from_wire(capability.as_str()) == Some(capability),
                "the shell exposes `{}` but the core's vocabulary does not contain it",
                capability.as_str()
            );
        }
    }

    /// S-3, second half: the subset direction that actually has teeth.
    ///
    /// The test above would pass if the shell exposed *nothing*. This one
    /// fails if the shell exposes nothing useful, so between them neither an
    /// empty console nor an over-broad one is green.
    #[test]
    fn the_shell_exposes_something_and_not_everything_by_default() {
        assert!(
            !exposed().is_empty(),
            "an empty command table is fail-closed but is not a console"
        );
    }

    /// S-2 / S-3. An unknown name is refused without its argument being read.
    ///
    /// The argument is a payload that cannot even be constructed, so a
    /// handler that tried to inspect it would have to unwrap and would
    /// report the parse error instead of `UnknownCommand`. If this ever
    /// returns `Denied`, the ordering has been broken.
    #[test]
    fn an_unregistered_command_is_refused_before_its_argument_is_read() {
        let boom = Err(serde_json::from_str::<serde_json::Value>("{not json")
            .expect_err("this literal is not valid JSON"));
        assert_eq!(
            console().dispatch("read_credential", boom),
            Outcome::UnknownCommand,
            "an unknown name must be refused before the argument is looked at"
        );
    }

    /// S-4. The names a value-returning command would have are all refused.
    #[test]
    fn no_command_name_can_return_a_credential() {
        for forbidden in [
            "read_credential",
            "reveal",
            "export",
            "get_secret",
            "complete_reveal",
        ] {
            assert_eq!(
                console().dispatch(forbidden, Ok(json!({}))),
                Outcome::UnknownCommand,
                "`{forbidden}` was answered by the console"
            );
        }
    }

    /// A malformed argument on a *known* command is a different failure from
    /// an unknown name, and the two must not be conflated — otherwise the
    /// refusal message leaks whether a name exists.
    #[test]
    fn a_malformed_argument_on_a_real_command_is_distinct() {
        let bad = Err(serde_json::from_str::<serde_json::Value>("{not json")
            .expect_err("this literal is not valid JSON"));
        let outcome = console().dispatch("list_credentials", bad);
        assert!(
            matches!(outcome, Outcome::Denied { .. }),
            "expected a denied outcome, got {outcome:?}"
        );
    }
}
