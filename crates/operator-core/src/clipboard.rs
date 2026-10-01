//! Re-authentication and clipboard clearing for the one policy that allows a
//! copy: `HumanOnly`.
//!
//! §10 of the spec: *"explicit re-authentication + time-limited reveal, never
//! returned through agent IPC/MCP. Clipboard copy should be opt-in and
//! auto-clear best-effort."*
//!
//! Two words in that sentence are doing the work and both are easy to drop:
//! **time-limited** and **best-effort**. This module keeps both as values the
//! caller has to supply, rather than as defaults that can be forgotten:
//!
//! - a reveal without a TTL is not a time-limited reveal, so [`RevealRequest`]
//!   has no constructor that omits one;
//! - "best-effort" means the clear is *attempted* and the attempt is reported,
//!   not that it silently succeeds. A clipboard that refuses to clear is a
//!   fact the operator needs, so [`ClipboardDecision::ClearFailed`] exists.
//!
//! Neither of those is this crate's to decide alone — the OS owns the
//! clipboard. What this crate owns is the rule, and the rule is testable.

use asv_domain::Exportability;
use core::time::Duration;
use serde::{Deserialize, Serialize};

/// How the operator proved who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthOutcome {
    /// The vault passphrase was supplied and accepted.
    Accepted,
    /// It was not, or the attempt is stale.
    Refused,
    /// No attempt has been made yet.
    NotAttempted,
}

/// A request to reveal or copy a `HumanOnly` credential.
///
/// The two lifetimes are separate on purpose. The *reveal* is time-limited by
/// the spec. The *clipboard* is cleared after a timeout, and that timeout is
/// usually longer, because the operator needs time to paste. Collapsing them
/// into one number is how a clipboard ends up cleared while the operator is
/// still using the value, or a reveal outliving its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealRequest {
    /// How long the revealed value may be used.
    pub reveal_ttl: Duration,
    /// How long the value may sit on the clipboard before a clear is
    /// attempted.
    pub clipboard_clear_after: Duration,
    /// The operator's re-authentication result.
    pub reauth: ReauthOutcome,
}

impl RevealRequest {
    /// Builds a request. Both lifetimes are required: there is deliberately
    /// no `new` without them, and no `Default`.
    pub const fn new(
        reveal_ttl: Duration,
        clipboard_clear_after: Duration,
        reauth: ReauthOutcome,
    ) -> Self {
        Self {
            reveal_ttl,
            clipboard_clear_after,
            reauth,
        }
    }

    /// Whether the request carries a usable window at all.
    ///
    /// A zero TTL is not a "no limit"; it is a window that has already closed.
    /// Treating it as unlimited is the failure this refuses.
    pub const fn has_usable_window(&self) -> bool {
        !self.reveal_ttl.is_zero()
    }
}

/// What the console should do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum ClipboardDecision {
    /// Re-auth has not succeeded; do not reveal and do not touch the
    /// clipboard.
    RefusedNeedsReauth,
    /// The credential's exportability does not allow this at all. Distinct
    /// from `RefusedNeedsReauth`: no amount of re-authentication helps,
    /// because the action does not exist for this credential.
    RefusedNotExportable,
    /// The window is not usable.
    RefusedNoWindow,
    /// Reveal it, and attempt a clipboard clear after the given delay.
    Grant {
        /// The window the operator has.
        reveal_ttl_secs: u64,
        /// When the clear will be attempted.
        clear_after_secs: u64,
    },
    /// A clear was attempted and the OS refused. The value may still be on the
    /// clipboard, and the operator should be told rather than left to assume.
    ClearFailed {
        /// What the OS said, if it said anything.
        detail: String,
    },
}

/// Decides reveal/copy requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClipboardPolicy;

impl ClipboardPolicy {
    /// Evaluates a request against a credential's exportability.
    pub fn decide(exportability: Exportability, request: &RevealRequest) -> ClipboardDecision {
        use Exportability::{Exportable, HumanOnly, NonExportable};

        // Order matters and it is not arbitrary. The exportability check
        // comes first so that a `NonExportable` credential refuses for a
        // reason that re-authentication cannot fix, instead of reporting
        // "needs re-auth" and inviting the operator to try harder.
        if matches!(exportability, NonExportable) {
            return ClipboardDecision::RefusedNotExportable;
        }
        if !matches!(exportability, HumanOnly | Exportable) {
            return ClipboardDecision::RefusedNotExportable;
        }
        if !request.has_usable_window() {
            return ClipboardDecision::RefusedNoWindow;
        }
        if request.reauth != ReauthOutcome::Accepted {
            return ClipboardDecision::RefusedNeedsReauth;
        }
        ClipboardDecision::Grant {
            reveal_ttl_secs: request.reveal_ttl.as_secs(),
            clear_after_secs: request.clipboard_clear_after.as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(ttl: Duration, clear: Duration) -> RevealRequest {
        RevealRequest::new(ttl, clear, ReauthOutcome::Accepted)
    }

    #[test]
    fn a_non_exportable_credential_refuses_even_with_reauth_accepted() {
        // The clause that matters: re-auth is not a key that opens this.
        let request = accepted(Duration::from_secs(30), Duration::from_secs(60));
        assert_eq!(
            ClipboardPolicy::decide(Exportability::NonExportable, &request),
            ClipboardDecision::RefusedNotExportable
        );
    }

    #[test]
    fn a_human_only_credential_needs_reauth_before_anything_happens() {
        for outcome in [ReauthOutcome::NotAttempted, ReauthOutcome::Refused] {
            let request =
                RevealRequest::new(Duration::from_secs(30), Duration::from_secs(60), outcome);
            assert_eq!(
                ClipboardPolicy::decide(Exportability::HumanOnly, &request),
                ClipboardDecision::RefusedNeedsReauth,
                "{outcome:?} must not grant a reveal"
            );
        }
    }

    #[test]
    fn a_grant_carries_both_lifetimes_separately() {
        let decision = ClipboardPolicy::decide(
            Exportability::HumanOnly,
            &accepted(Duration::from_secs(30), Duration::from_secs(120)),
        );
        assert_eq!(
            decision,
            ClipboardDecision::Grant {
                reveal_ttl_secs: 30,
                clear_after_secs: 120,
            },
            "the reveal window and the clipboard timeout are different numbers and \
             the decision must not collapse them"
        );
    }

    #[test]
    fn a_zero_window_is_refused_rather_than_read_as_unlimited() {
        // A zero TTL is a window that has already closed. Reading it as "no
        // limit" is the failure this test exists to prevent.
        let request = accepted(Duration::ZERO, Duration::from_secs(60));
        assert_eq!(
            ClipboardPolicy::decide(Exportability::HumanOnly, &request),
            ClipboardDecision::RefusedNoWindow
        );
    }

    #[test]
    fn a_clear_failure_is_reportable_rather_than_swallowed() {
        // "best-effort" means attempted. If the OS refuses, the operator has
        // to find out, so the variant exists and is constructible.
        let failure = ClipboardDecision::ClearFailed {
            detail: "clipboard owner refused".to_string(),
        };
        let json = serde_json::to_string(&failure).expect("serialisable");
        assert!(json.contains("clear_failed"), "{json}");
        assert!(json.contains("clipboard owner refused"), "{json}");
    }

    #[test]
    fn the_exportability_check_runs_before_the_reauth_check() {
        // Order is a behaviour, not an implementation detail: a
        // NonExportable credential must not be told "needs re-auth", because
        // that invites the operator to believe re-auth would help.
        let request = RevealRequest::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            ReauthOutcome::NotAttempted,
        );
        assert_eq!(
            ClipboardPolicy::decide(Exportability::NonExportable, &request),
            ClipboardDecision::RefusedNotExportable
        );
        assert_eq!(
            ClipboardPolicy::decide(Exportability::HumanOnly, &request),
            ClipboardDecision::RefusedNeedsReauth
        );
    }
}
