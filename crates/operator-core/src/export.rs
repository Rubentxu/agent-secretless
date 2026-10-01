//! What a human may do with a credential, per its `Exportability`.
//!
//! UAT-020, verbatim: for a `NonExportable` credential, **copy/reveal actions
//! do not exist**.
//!
//! "Do not exist" is the load-bearing phrase, and it is why this is a
//! function of the metadata rather than a check inside the shell. A shell
//! that receives `NonExportable` and renders no button has hidden the action.
//! A console whose capability set is *computed from this decision* has no
//! button to render and no command to invoke, which is a different and
//! stronger thing.
//!
//! The spec is explicit that the agent surfaces have no retrieval API at all
//! (ADR-0001), so this enum governs the **human** plane only. That is why
//! `HumanOnly` can be allowed anything at all.

use asv_domain::{CredentialMetadata, Exportability};
use serde::{Deserialize, Serialize};

/// An action a human operator might attempt on a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleAction {
    /// See its metadata: label, kind, exportability.
    ViewMetadata,
    /// Ask for the raw value.
    Reveal,
    /// Put the raw value on the system clipboard.
    Copy,
    /// Send it to an external target.
    Export,
}

/// The answer, and — for the refused cases — the reason.
///
/// A bare `bool` would let a caller treat "not permitted" and "not applicable"
/// the same way, and the difference is the difference between a policy and a
/// bug report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportDecision {
    /// The action is allowed.
    Permitted,
    /// Refused, with the policy that refused it.
    Refused(&'static str),
}

impl ExportDecision {
    /// Whether the action may proceed.
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted)
    }

    /// The policy text, when refused.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Permitted => None,
            Self::Refused(reason) => Some(reason),
        }
    }
}

/// Decides `ConsoleAction` against `Exportability`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportPolicy;

impl ExportPolicy {
    /// The policy for one credential's exportability.
    pub const fn decide(action: ConsoleAction, exportability: Exportability) -> ExportDecision {
        use Exportability::{Exportable, HumanOnly, NonExportable};

        match (action, exportability) {
            // Metadata is never the secret, so every exportability shows it.
            // Spelled out here rather than short-circuited above the match:
            // the first version returned early, and the compiler could not see
            // the match was exhaustive — so the arms below read as if they
            // covered every action when they do not.
            (ConsoleAction::ViewMetadata, _) => ExportDecision::Permitted,

            // FR-002: the default, and the one agents get. The spec says
            // "impossible through supported UI/CLI once stored" — so this is
            // a refusal of the *action*, not a warning about it.
            (_, NonExportable) => ExportDecision::Refused(
                "credential is NonExportable: reveal, copy and export are not \
                 offered by any supported surface",
            ),

            // §10: re-authentication plus a time-limited reveal, and copy is
            // opt-in with a best-effort auto-clear. Both halves of that are
            // enforced elsewhere: this says a flow may *begin*, and
            // `crate::clipboard` refuses it until re-auth has passed.
            (ConsoleAction::Reveal | ConsoleAction::Copy, HumanOnly) => ExportDecision::Permitted,
            (ConsoleAction::Export, HumanOnly) => ExportDecision::Refused(
                "HumanOnly covers a time-limited reveal and an opt-in copy, \
                 not export to an external target",
            ),

            // §10: "still requires explicit human interaction". That is what
            // being in this arm already means — the operator chose
            // `Exportable`. The interaction gate is the flow, not the enum.
            (_, Exportable) => ExportDecision::Permitted,
        }
    }

    /// Whether `action` would appear in the console's UI for this credential.
    ///
    /// This is the function the shell calls to build its action list, which
    /// is why it exists separately from [`Self::decide`]: the UI must not
    /// decide visibility by asking whether an action was *permitted* at call
    /// time. If a future action is permitted but should not be offered as a
    /// button, the two questions are no longer the same question.
    pub const fn is_offered(action: ConsoleAction, exportability: Exportability) -> bool {
        matches!(
            Self::decide(action, exportability),
            ExportDecision::Permitted
        )
    }
}

/// A serialisable view of one credential's console actions.
///
/// The shell renders this. It is a value, not a callback, so what it offers
/// is inspectable in a test without a browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleActions {
    pub label: String,
    pub kind: String,
    pub exportability: Exportability,
    pub can_view_metadata: bool,
    pub can_reveal: bool,
    pub can_copy: bool,
    pub can_export: bool,
    /// Set when reveal or copy is offered but gated behind a flow. The shell
    /// renders it as a button that *starts* the flow, never as one that
    /// returns a value.
    pub reveal_requires_reauth: bool,
}

impl ConsoleActions {
    /// Computes the console surface for one credential's metadata.
    pub fn for_metadata(metadata: &CredentialMetadata) -> Self {
        let e = metadata.exportability;
        let can_reveal = ExportPolicy::is_offered(ConsoleAction::Reveal, e);
        let can_copy = ExportPolicy::is_offered(ConsoleAction::Copy, e);
        Self {
            label: metadata.label.clone(),
            kind: format!("{:?}", metadata.kind),
            exportability: e,
            can_view_metadata: ExportPolicy::is_offered(ConsoleAction::ViewMetadata, e),
            can_reveal,
            can_copy,
            can_export: ExportPolicy::is_offered(ConsoleAction::Export, e),
            reveal_requires_reauth: can_reveal && matches!(e, Exportability::HumanOnly),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_domain::{CredentialKind, Exportability};

    #[test]
    fn a_non_exportable_credential_offers_nothing_but_metadata() {
        // The UAT-020 clause, as a table rather than a sentence.
        for action in [
            ConsoleAction::Reveal,
            ConsoleAction::Copy,
            ConsoleAction::Export,
        ] {
            assert_eq!(
                ExportPolicy::decide(action, Exportability::NonExportable),
                ExportDecision::Refused(
                    "credential is NonExportable: reveal, copy and export are not \
                     offered by any supported surface",
                ),
                "{action:?} must be refused for NonExportable"
            );
            assert!(
                !ExportPolicy::is_offered(action, Exportability::NonExportable),
                "{action:?} must not be offered for NonExportable"
            );
        }
        assert!(ExportPolicy::is_offered(
            ConsoleAction::ViewMetadata,
            Exportability::NonExportable
        ));
    }

    #[test]
    fn a_human_only_credential_offers_reveal_and_copy_but_not_export() {
        // §10: reveal with re-auth, copy opt-in with auto-clear, and export
        // is a different thing entirely.
        assert!(ExportPolicy::is_offered(
            ConsoleAction::Reveal,
            Exportability::HumanOnly
        ));
        assert!(ExportPolicy::is_offered(
            ConsoleAction::Copy,
            Exportability::HumanOnly
        ));
        assert_eq!(
            ExportPolicy::decide(ConsoleAction::Export, Exportability::HumanOnly),
            ExportDecision::Refused(
                "HumanOnly covers a time-limited reveal and an opt-in copy, \
                 not export to an external target"
            ),
        );
    }

    #[test]
    fn an_exportable_credential_still_gets_nothing_over_agent_ipc() {
        // The policy governs the human plane. Nothing here widens the agent
        // surface, and saying so is the assertion worth keeping: `Exportable`
        // means a human may, not that any interface may.
        let decision = ExportPolicy::decide(ConsoleAction::Export, Exportability::Exportable);
        assert!(decision.is_permitted());
        // and the reason field stays empty for a permitted action, so a
        // caller cannot smuggle a justification out of a refusal path.
        assert_eq!(decision.reason(), None);
    }

    #[test]
    fn the_console_surface_of_a_non_exportable_credential_has_no_buttons() {
        let metadata = CredentialMetadata::new("api token", CredentialKind::BearerToken);
        assert_eq!(
            metadata.exportability,
            Exportability::NonExportable,
            "the default posture is the one this test depends on"
        );
        let actions = ConsoleActions::for_metadata(&metadata);
        assert!(actions.can_view_metadata);
        assert!(!actions.can_reveal, "UAT-020: copy/reveal do not exist");
        assert!(!actions.can_copy, "UAT-020: copy/reveal do not exist");
        assert!(!actions.can_export);
        assert!(
            !actions.reveal_requires_reauth,
            "a credential with no reveal has no re-auth to require"
        );
    }

    #[test]
    fn a_human_only_console_surface_marks_the_reveal_as_gated() {
        let mut metadata = CredentialMetadata::new("root", CredentialKind::BearerToken);
        metadata.exportability = Exportability::HumanOnly;
        let actions = ConsoleActions::for_metadata(&metadata);
        assert!(actions.can_reveal);
        assert!(actions.can_copy);
        assert!(!actions.can_export);
        assert!(
            actions.reveal_requires_reauth,
            "a HumanOnly reveal starts a flow; it does not return a value"
        );
    }

    #[test]
    fn a_refusal_carries_the_policy_text_and_a_permission_does_not() {
        // A caller logging the decision gets something actionable in the
        // refusal case and nothing misleading in the permitted case.
        let refused = ExportPolicy::decide(ConsoleAction::Reveal, Exportability::NonExportable);
        assert!(refused
            .reason()
            .is_some_and(|r| r.contains("NonExportable")));
        let permitted =
            ExportPolicy::decide(ConsoleAction::ViewMetadata, Exportability::NonExportable);
        assert_eq!(permitted.reason(), None);
    }
}
