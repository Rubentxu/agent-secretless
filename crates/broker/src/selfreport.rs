//! What the broker can say about itself, and where each answer comes from.
//!
//! # Why this is a record rather than a query
//!
//! `harden::install` returns a [`harden::HardenConfig`] describing the
//! protections it actually established. `main` had that value, logged it, and
//! dropped it — so the answer to "is the running broker undumpable?" existed
//! for the length of one log line and was gone afterwards. `asv doctor`, on
//! the other side of a socket, could only answer `unknown`, and `unknown` in
//! a diagnostic is a worse answer than a measured one.
//!
//! So `main` copies the measured values into a [`SelfReport`] the request path
//! can read. Nothing here re-queries the kernel: a capability probe run per
//! request would answer a different question than the one that was asked at
//! startup, and a diagnostic that changes between calls is not a diagnostic.
//!
//! # Fail-closed, not optimistic
//!
//! [`SelfReport::default`] reports every protection as **absent**. A broker
//! assembled in a test, or one that skipped the harden profile, genuinely has
//! none of them — so the default is the truth rather than a placeholder that
//! would have to be overwritten for correctness. A default that claimed the
//! protections were on would mean every future constructor had to remember to
//! correct it, and the ones that forgot would report a hardened broker while
//! running an unhardened one.

use serde::{Deserialize, Serialize};

/// The broker's measured self-description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfReport {
    pub product_version: String,
    /// `PR_SET_DUMPABLE` was set to 0.
    pub dumpable_disabled: bool,
    /// `PR_SET_NO_NEW_PRIVS` is set.
    pub no_new_privs: bool,
    /// A live Landlock ruleset is restricting the process.
    pub landlock_installed: bool,
    /// A live seccomp-bpf deny-list is installed.
    pub seccomp_installed: bool,
    pub cgroup_v2: bool,
    pub capabilities: Vec<String>,
}

impl Default for SelfReport {
    fn default() -> Self {
        Self {
            product_version: env!("CARGO_PKG_VERSION").to_string(),
            // Everything absent. See the module docs: this is the truth for a
            // broker that never installed the profile, and a default that
            // claimed otherwise would report a hardened broker that is not one.
            dumpable_disabled: false,
            no_new_privs: false,
            landlock_installed: false,
            seccomp_installed: false,
            cgroup_v2: false,
            capabilities: compiled_capabilities(),
        }
    }
}

impl SelfReport {
    /// Copies the measured outcome of `harden::install` into the report.
    ///
    /// `dumpable_is_zero` and `no_new_privs_is_set` are read back from the
    /// process rather than taken from the config struct, because those two
    /// are `prctl` calls whose *effect* is the fact. The config records what
    /// was attempted; this records what the kernel agreed to.
    pub fn from_harden(
        cfg: &crate::harden::HardenConfig,
        dumpable_is_zero: bool,
        no_new_privs: bool,
    ) -> Self {
        Self {
            dumpable_disabled: dumpable_is_zero,
            no_new_privs,
            landlock_installed: cfg.landlock_installed,
            seccomp_installed: cfg.seccomp_installed,
            cgroup_v2: cfg.cgroup_v2,
            ..Self::default()
        }
    }
}

/// The capabilities this build actually has a complete path for.
///
/// A `cfg` list, not a roadmap. R9 in `11-RISKS-OPEN-QUESTIONS.md` names the
/// failure directly: discovery announcing a feature that has types but no
/// complete path teaches an agent to try it. Every name here is backed by a
/// `Request` variant that is handled rather than refused as unknown, and
/// `every_advertised_capability_is_handled` is what keeps the two in step.
pub fn compiled_capabilities() -> Vec<String> {
    let mut out = vec![
        // Health and metadata.
        "system.health".to_string(),
        "system.self".to_string(),
        // Sessions and the SSH signer they carry.
        "session.run".to_string(),
        "session.ssh_sign".to_string(),
        // Credential *metadata* only. There is no capability here that
        // returns a secret, and the list is the place a reader looks to
        // decide that.
        "credentials.metadata".to_string(),
        "credentials.create".to_string(),
        "credentials.revoke".to_string(),
        // Semantic connectors.
        "github.issue.read".to_string(),
        "github.issue.create".to_string(),
        "github.release.create".to_string(),
        "postgres.connect".to_string(),
        "postgres.query".to_string(),
    ];
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default claims nothing, because a broker that installed nothing
    /// has nothing.
    ///
    /// Falsifiable in the direction that matters: flip any field to `true` and
    /// this fails, so a future edit cannot make the default optimistic without
    /// a reviewer seeing a red test rather than a security claim.
    #[test]
    fn the_default_reports_no_protections() {
        let d = SelfReport::default();
        assert!(!d.dumpable_disabled);
        assert!(!d.no_new_privs);
        assert!(!d.landlock_installed);
        assert!(!d.seccomp_installed);
        assert!(!d.cgroup_v2);
    }

    /// The default still names the build. A report with no version would make
    /// `doctor`'s `broker_version` field — the one thing DX2 is widening the
    /// protocol to obtain — null on every broker that did not install the
    /// profile, which is most of them in a test.
    #[test]
    fn the_default_still_carries_the_product_version() {
        assert_eq!(
            SelfReport::default().product_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    /// No capability returns a secret. This is the assertion behind the
    /// absence of anything like `credentials.get` in the list, and it is
    /// written as a substring check so that a future name like
    /// `credentials.get_value` cannot slip through on a technicality.
    #[test]
    fn no_advertised_capability_names_a_retrieval() {
        for capability in compiled_capabilities() {
            let lowered = capability.to_lowercase();
            for forbidden in [
                "get",
                "read_value",
                "reveal",
                "export",
                "unlock",
                "plaintext",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "`{capability}` reads as a retrieval capability; nothing in \
                     this list may return a secret (ADR-0001)"
                );
            }
        }
    }

    /// The list is sorted and deduplicated, because it is compared in golden
    /// documents and an unstable order would make them churn.
    #[test]
    fn the_capability_list_is_stable() {
        let list = compiled_capabilities();
        let mut sorted = list.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(list, sorted);
    }
}
