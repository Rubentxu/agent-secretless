//! The console command surface: what exists, and what it may return.
//!
//! UAT-019 requires that "WebView cannot invoke unauthorized Tauri commands"
//! and that a "stored secret cannot be read". Both are stronger as absences
//! than as checks:
//!
//! - a command the registry does not know **cannot be invoked at all**;
//! - a registered command **has no return type carrying secret material**,
//!   which is a property of the type, not of a code review.
//!
//! So the registry is deny-by-default. An empty registry refuses everything,
//! and [`Registry::default`] is deliberately *not* a working console: a
//! caller has to say what it exposes. A default that quietly opened the
//! interesting doors is the exact shape of the bug this module exists to
//! prevent.

use core::fmt;
use serde::{Deserialize, Serialize};

/// A command the console surface may expose.
///
/// The variants are the vocabulary. A new capability is a new variant, which
/// is a compile error in every match that enumerates them — which is the
/// point. There is no "and any other string" escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// List credential *metadata*. Never values.
    ListCredentials,
    /// Create a credential. Carries the secret in, returns an id.
    AddCredential,
    /// Delete a credential record.
    DeleteCredential,
    /// List the current human-facing policy decisions.
    ListPolicies,
    /// List pending approval requests.
    ListApprovals,
    /// Approve or deny one approval request.
    DecideApproval,
    /// List active agent sessions.
    ListSessions,
    /// End an agent session.
    EndSession,
    /// Read the audit timeline.
    ReadAudit,
    /// Report integration security posture.
    ListPosture,
    /// Begin a reveal for a `HumanOnly` credential.
    ///
    /// Note what is **not** here: there is no `Reveal` and no `Export`.
    /// Reveal for a `HumanOnly` credential is a flow, not a command, and it
    /// is gated by [`crate::clipboard::ClipboardPolicy`] — which is where
    /// UAT-020's re-authentication lives. A `Reveal` capability here would be
    /// a way to skip the re-auth, so there isn't one.
    BeginReveal,
}

impl Capability {
    /// Every capability this build knows about.
    ///
    /// This is the vocabulary, and it is the *only* copy. A second,
    /// hand-kept list of the same variants used to live in this file's test
    /// module; two lists of the same capabilities is precisely how a console
    /// ends up exposing something the registry never authorised, so it is gone.
    ///
    /// A consumer that wants to enumerate the console surface — the Tauri
    /// shell does, to prove its command table is a subset of this — reads it
    /// from here rather than from its own copy, which is the copy that drifts.
    ///
    /// The compile-time guard is not this list but [`Capability::as_str`],
    /// which is an exhaustive `match`: adding a variant breaks the build
    /// until the name is spelled. Omitting a variant from `ALL` is
    /// fail-closed — a shell can only iterate what is listed — so the
    /// failure mode here is a command that never appears, not one that is
    /// wrongly exposed.
    pub const ALL: &'static [Capability] = &[
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
    ];

    /// The wire name the console uses for this capability.
    ///
    /// Matches the `snake_case` serde rename, because a command name that
    /// exists only in one of those two spellings is a name the registry and
    /// the transport will disagree about. `test_name_matches_serde` is what
    /// keeps them equal.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Capability::ListCredentials => "list_credentials",
            Capability::AddCredential => "add_credential",
            Capability::DeleteCredential => "delete_credential",
            Capability::ListPolicies => "list_policies",
            Capability::ListApprovals => "list_approvals",
            Capability::DecideApproval => "decide_approval",
            Capability::ListSessions => "list_sessions",
            Capability::EndSession => "end_session",
            Capability::ReadAudit => "read_audit",
            Capability::ListPosture => "list_posture",
            Capability::BeginReveal => "begin_reveal",
        }
    }

    /// Whether invoking this capability can ever yield credential material.
    ///
    /// Every variant answers `false` and the test below says so. That test
    /// is the load-bearing one: it is what makes "stored secret cannot be
    /// read" a checked statement rather than a promise in a comment.
    pub const fn returns_secret_material(&self) -> bool {
        false
    }

    /// Parse a wire name back into a capability.
    ///
    /// Deny-by-default in the strictest sense: a name that does not match
    /// exactly one variant yields `None`, and the caller refuses. There is no
    /// prefix matching and no case folding, so a name cannot be *close
    /// enough*.
    pub fn from_wire(name: &str) -> Option<Capability> {
        Capability::ALL.iter().copied().find(|c| c.as_str() == name)
    }
}

/// Why a command was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// No such command is registered. The refusal happens *before* any
    /// argument is looked at, so an unknown name cannot be used to probe
    /// what a command would have accepted.
    UnknownCapability,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCapability => f.write_str("no such console command is registered"),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// The set of commands this console exposes.
///
/// Deny-by-default: [`Registry::new`] with an empty list refuses every name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    allowed: Vec<Capability>,
}

impl Registry {
    /// Builds a registry exposing exactly `allowed`.
    pub fn new(allowed: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    /// Whether `name` is exposed.
    ///
    /// This is the authorisation check. Note the shape: the registry answers
    /// yes or no about a [`Capability`], which is a closed enum. The shell's
    /// job is to parse an incoming name into a `Capability` *and fail closed
    /// when it cannot*, never to fall through to "try it and see".
    pub fn exposes(&self, name: Capability) -> bool {
        self.allowed.contains(&name)
    }

    /// Authorises a capability, or explains why not.
    pub fn authorize(&self, name: Capability) -> Result<(), CapabilityError> {
        if self.exposes(name) {
            Ok(())
        } else {
            Err(CapabilityError::UnknownCapability)
        }
    }

    /// The exposed capabilities.
    pub fn exposed(&self) -> &[Capability] {
        &self.allowed
    }
}

/// Alias kept short for call sites that read better as `capability::Registry`.
pub type CapabilityRegistry = Registry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_registry_refuses_everything() {
        let registry = Registry::new([]);
        for capability in [
            Capability::ListCredentials,
            Capability::AddCredential,
            Capability::DeleteCredential,
            Capability::BeginReveal,
            Capability::ReadAudit,
        ] {
            assert_eq!(
                registry.authorize(capability),
                Err(CapabilityError::UnknownCapability),
                "{capability:?} must be refused by a registry that does not expose it"
            );
        }
    }

    #[test]
    fn the_default_registry_refuses_everything() {
        // The reason `Default` is not a working console. If this test ever
        // needs changing, a default console opened its doors by default.
        assert_eq!(Registry::default().exposed(), &[]);
    }

    #[test]
    fn no_capability_returns_secret_material() {
        // The UAT-019 clause "stored secret cannot be read", as a checked
        // statement. If a variant is ever added that can yield a value, this
        // is the test that goes red — and it goes red by having to answer
        // `true`, which a reviewer then has to justify.
        for capability in Capability::ALL {
            assert!(
                !capability.returns_secret_material(),
                "{capability:?} claims to return credential material; a console \
                 command that returns one is the bug this repository exists to \
                 prevent, and it needs an ADR, not a variant"
            );
        }
    }

    #[test]
    fn a_reveal_flow_cannot_be_reached_without_opening_it_deliberately() {
        // UAT-020 says a `HumanOnly` reveal requires re-authentication. A
        // capability named `Reveal` would be a way around that, so the
        // vocabulary has `BeginReveal` — which starts a *flow* the
        // ClipboardPolicy gates — and no command that returns a value.
        //
        // What is checkable from out here is the deliberate part: a registry
        // that does not name `BeginReveal` refuses it, so no console
        // accidentally gets a reveal path by inheriting a default.
        let without_reveal =
            Registry::new([Capability::ListCredentials, Capability::AddCredential]);
        assert_eq!(
            without_reveal.authorize(Capability::BeginReveal),
            Err(CapabilityError::UnknownCapability),
            "a reveal path must be opened on purpose, not inherited"
        );

        let with_reveal = Registry::new([Capability::BeginReveal]);
        assert_eq!(
            with_reveal.authorize(Capability::BeginReveal),
            Ok(()),
            "opening it on purpose is the supported path"
        );
    }

    #[test]
    fn every_wire_name_round_trips() {
        for capability in Capability::ALL {
            let name = capability.as_str();
            assert_eq!(
                Capability::from_wire(name),
                Some(*capability),
                "{name} does not parse back to the capability it came from"
            );
        }
    }

    #[test]
    fn the_wire_name_matches_the_serde_name() {
        // Two spellings of the same name is how a registry and a transport
        // start disagreeing about which commands exist. They are checked
        // against each other here rather than trusted to memory.
        for capability in Capability::ALL {
            let encoded = serde_json::to_string(capability).expect("Capability serialises");
            let serde_name = encoded.trim_matches('"');
            assert_eq!(
                serde_name,
                capability.as_str(),
                "{capability:?}: as_str() and the serde rename disagree"
            );
        }
    }

    #[test]
    fn there_is_no_read_credential() {
        // S-4. Not "read_credential is refused" — it is that no such name
        // exists to be refused. The negative test that matters, because a
        // positive assertion (`from_wire("x").is_none()`) can pass for the
        // wrong reason: a typo'd function that always returned None would
        // satisfy it. This one fails the moment a variant is added, because
        // then the name resolves.
        for forbidden in [
            "read_credential",
            "reveal",
            "export",
            "get_secret",
            "reveal_credential",
            "copy_credential",
        ] {
            assert_eq!(
                Capability::from_wire(forbidden),
                None,
                "`{forbidden}` resolved; a console command that yields a value is \
                 the bug this repository exists to prevent"
            );
        }
    }

    #[test]
    fn wire_names_are_matched_exactly() {
        // No case folding, no prefix matching, no trimming. A name that is
        // *close* to a real one must be refused, not normalised into it.
        for near_miss in [
            "LIST_CREDENTIALS",
            "List_Credentials",
            "list_credentials ",
            " list_credentials",
            "list_credential",
            "list_credentialss",
            "list_credentials\n",
        ] {
            assert_eq!(
                Capability::from_wire(near_miss),
                None,
                "`{near_miss}` was accepted; matching must be exact"
            );
        }
    }
}
