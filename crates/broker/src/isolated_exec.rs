//! M10 — Isolated exec compatibility (prototype pass).
//!
//! Models the worker template registry, the egress policy, the
//! per-template secret injection, the landlock/seccomp profiles, the
//! stdout redactor, and the posture label. The runtime follow-up
//! replaces the data-type dispatcher with the actual `Command` +
//! `fork` + namespace flow.

use std::path::{Path, PathBuf};

use crate::tls_bridge::AuthorityEndpoint;

/// Stable posture label every isolated worker carries.
///
/// The M10 spec is honest about the residual risk: an unavoidable
/// legacy tool runs with raw secrets. The UI (M5 dashboard) shows this
/// label to the user so the exposure is visible.
pub const POSTURE_LABEL: &str = "ISOLATED_PROCESS_EXPOSURE";

/// B1.1: posture label as a typed enum, so the audit log, the UI,
/// and the wire (`AuditEventDto::WorkerSpawned { posture }`) all
/// share one source of truth and a future post-cgroup recovery (B1.3)
/// can flip a variant without stringly-typed branches across the
/// codebase.
///
/// The mapping to the wire string is a total `match` with no wildcard
/// arm: adding a variant forces every call site to acknowledge it.
/// `degraded_reason` is reserved for B1.3 (cgroup-probe enabled,
/// `IsolatedProcessExposure` becomes a fall-back label rather than the
/// steady state). Today it is always `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureLabel {
    /// B1.3 target: a fully namespace-isolated worker with a cgroup
    /// fence. The label the user-facing UI is allowed to call
    /// "strong". Not reachable until B1.3 lands.
    StrongSecretless,
    /// B1.1 honest posture: a fresh user/network namespace, Landlock
    /// rules, seccomp deny-list, and a per-run process-group reaper,
    /// but NO cgroup fence. The worker still holds the secret in its
    /// own memory for the run's lifetime. The UI must surface this
    /// to the operator.
    IsolatedProcessExposure,
}

impl PostureLabel {
    /// Wire name (`AuditEventDto::WorkerSpawned { posture }`). Total:
    /// adding a variant breaks the build until the wire name is
    /// declared here.
    pub const fn wire_name(self) -> &'static str {
        match self {
            PostureLabel::StrongSecretless => "STRONG_SECRETLESS",
            PostureLabel::IsolatedProcessExposure => "ISOLATED_PROCESS_EXPOSURE",
        }
    }
}

impl Default for PostureLabel {
    /// **B1.1 decision (user-authorised option A):** with the cgroup
    /// probe deliberately out of scope, the steady-state posture is
    /// `IsolatedProcessExposure`. B1.3 introduces
    /// `PostureLabel::effective(harden_config)` (the runtime-aware
    /// accessor) and the default stays `IsolatedProcessExposure` for
    /// one more cycle, by deliberate choice: a flip in `Default` would
    /// change every audit row on a cgroup-fence host without an
    /// operator opt-in. The opt-in is a follow-up.
    fn default() -> Self {
        PostureLabel::IsolatedProcessExposure
    }
}

/// B1.3: why a worker run had to fall back to
/// `IsolatedProcessExposure` instead of `StrongSecretless`.
///
/// The wire representation is a `&'static str` produced by
/// [`DegradedReason::as_str`]; the broker never builds a value of this
/// type from a raw string at runtime, so a malformed value cannot reach
/// an audit row by construction. The enum is `Copy` so it sits in a
/// `WorkerSpawned` audit row without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedReason {
    /// `harden::install` did not find cgroup v2 mounted at
    /// `/sys/fs/cgroup`. Either the kernel was built without it
    /// (`CONFIG_CGROUP_*` absent) or the distro never set it up.
    CgroupV2Unavailable,
    /// cgroup v2 was found but the broker could not create its
    /// session slice (e.g. write permission denied on
    /// `/sys/fs/cgroup/asv-broker.session.*`).
    SliceCreationFailed,
    /// Not Linux. The build-time cfg switch on `target_os` already
    /// suppresses the cgroup probe on macOS / BSD / Windows, but this
    /// variant exists so the audit row can be self-explanatory on a
    /// non-Linux run rather than carrying `None` and forcing the UI
    /// to look at the platform.
    NonLinux,
}

impl DegradedReason {
    /// Wire string. The audit row carries the result; the M5 UI
    /// surfaces it to the operator.
    pub const fn as_str(self) -> &'static str {
        match self {
            DegradedReason::CgroupV2Unavailable => "cgroup_v2_unavailable",
            DegradedReason::SliceCreationFailed => "slice_creation_failed",
            DegradedReason::NonLinux => "non_linux",
        }
    }
}

/// B1.3: the runtime-aware posture accessor.
///
/// Returns the label the broker should put on the audit row for
/// *this* run, given the harden profile the process actually
/// installed. The decision is:
///   - `StrongSecretless` if cgroup v2 is mounted AND the broker's
///     session slice was created successfully (the cgroup fence is
///     in place);
///   - `IsolatedProcessExposure` with the corresponding
///     [`DegradedReason`] otherwise.
///
/// `Default for PostureLabel` is intentionally NOT updated to call
/// this: the audit row has to stay opt-in for one release so a
/// flip in the harness does not silently change every prior
/// record's label. A future change to `Default` is a one-liner
/// once the operator opt-in exists; until then, callers that want
/// the runtime label must call this function explicitly.
pub fn strong_secretless_enabled(harden: &crate::harden::HardenConfig) -> bool {
    // Both conditions must hold. A kernel with cgroup v2 mounted
    // but a broker that failed to create its slice (a permission
    // problem) is NOT strong: the worker would run outside the
    // fence the operator asked for.
    harden.cgroup_v2 && harden.slice_created
}

/// B1.3: the runtime-aware posture.
///
/// See [`strong_secretless_enabled`]. Returns the label and, when
/// the label is `IsolatedProcessExposure`, the reason it had to
/// fall back. The reason is `None` on the strong path so the audit
/// row does not grow a column the strong case never uses.
pub fn effective_posture(
    harden: &crate::harden::HardenConfig,
) -> (PostureLabel, Option<DegradedReason>) {
    if strong_secretless_enabled(harden) {
        (PostureLabel::StrongSecretless, None)
    } else {
        let reason = if !harden.cgroup_v2 {
            #[cfg(not(target_os = "linux"))]
            {
                DegradedReason::NonLinux
            }
            #[cfg(target_os = "linux")]
            {
                DegradedReason::CgroupV2Unavailable
            }
        } else {
            // cgroup_v2 was found, but slice creation failed.
            DegradedReason::SliceCreationFailed
        };
        (PostureLabel::IsolatedProcessExposure, Some(reason))
    }
}

/// What the broker will inject into the worker process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretInjectionPlan {
    /// Inject a single environment variable.
    EnvVar {
        /// The variable name (e.g. `"AWS_ACCESS_KEY_ID"`).
        name: String,
    },
    /// A file the worker reads its credential from.
    ///
    /// Modelled, not materialised. M10-R3 requires these bytes to exist ONLY
    /// inside the worker's mount namespace, and honouring that needs a mount
    /// point contract no spec states yet: whatever directory the private
    /// tmpfs is mounted over stops being visible to the worker, and `/run`
    /// costs a tool almost nothing while `/etc` costs it the world. Guessing
    /// that here would be inventing policy rather than implementing a spec.
    ///
    /// Until a contract exists, `spawn` refuses this plan. The previous
    /// implementation served it by writing the secret to an absolute host
    /// path and unlinking it afterwards -- the exposure M10-R3 forbids, and
    /// the thing this product exists to prevent.
    File {
        /// Absolute path the worker would read the credential from.
        path: PathBuf,
        /// File mode (e.g. `0o600`).
        mode: u32,
    },
    /// No secret injection.
    None,
}

impl SecretInjectionPlan {
    /// True if the plan injects nothing.
    pub fn is_none(&self) -> bool {
        matches!(self, SecretInjectionPlan::None)
    }

    /// The wire name of the injection plan (used in audit logs).
    pub fn kind(&self) -> &'static str {
        match self {
            SecretInjectionPlan::EnvVar { .. } => "env_var",
            SecretInjectionPlan::File { .. } => "file",
            SecretInjectionPlan::None => "none",
        }
    }
}

/// Network egress policy for the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPolicy {
    /// Worker may reach only the listed endpoints.
    Allow(Vec<AuthorityEndpoint>),
    /// Worker has no network egress.
    Deny,
}

impl EgressPolicy {
    /// True if the sink is authorised under this policy.
    pub fn authorises(&self, sink: &AuthorityEndpoint) -> bool {
        match self {
            EgressPolicy::Deny => false,
            EgressPolicy::Allow(list) => list.iter().any(|a| a == sink),
        }
    }

    /// Wire name for the audit log.
    pub fn kind(&self) -> &'static str {
        match self {
            EgressPolicy::Allow(_) => "allow_list",
            EgressPolicy::Deny => "deny",
        }
    }
}

/// Landlock profile — which paths the worker may read / write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LandlockProfile {
    /// Paths the worker may read.
    pub allowed_read: Vec<PathBuf>,
    /// Paths the worker may write.
    pub allowed_write: Vec<PathBuf>,
}

impl LandlockProfile {
    /// Empty profile: deny everything.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// True if the worker may read `path`.
    pub fn may_read(&self, path: &Path) -> bool {
        self.allowed_read.iter().any(|p| p == path)
    }

    /// True if the worker may write `path`.
    pub fn may_write(&self, path: &Path) -> bool {
        self.allowed_write.iter().any(|p| p == path)
    }
}

/// Seccomp profile — the syscall allow-list class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Closed allow-list from the M7 spec (production default).
    ClosedAllowList,
    /// Pass-through (debug only).
    PassThrough,
}

impl SeccompProfile {
    /// True if the profile is production-grade.
    pub fn is_production(&self) -> bool {
        matches!(self, SeccompProfile::ClosedAllowList)
    }
}

/// A registered worker template. Immutable at runtime.
#[derive(Debug, Clone)]
pub struct WorkerTemplate {
    /// Unique worker name.
    pub name: String,
    /// Absolute path of the binary.
    pub binary: PathBuf,
    /// Arguments to pass (excluding `argv[0]`).
    pub arguments: Vec<String>,
    /// Secret injection plan.
    pub secret_injection: SecretInjectionPlan,
    /// Network egress policy.
    pub egress_policy: EgressPolicy,
    /// Landlock profile.
    pub landlock_profile: LandlockProfile,
    /// Seccomp profile.
    pub seccomp_profile: SeccompProfile,
    /// M10R-R5: the defence-in-depth stdout/stderr redactor, seeded by
    /// the template author with the exact byte sequences this worker
    /// could leak. Empty = no-op (unchanged output). The runtime routes
    /// every captured byte through it before returning output.
    pub redactor: Redactor,
}

/// The static worker registry. Built at install time.
#[derive(Debug, Clone, Default)]
pub struct WorkerRegistry {
    /// Registered templates.
    pub templates: Vec<WorkerTemplate>,
}

impl WorkerRegistry {
    /// Construct a registry from a template list.
    ///
    /// No template is validated here: a `PassThrough` seccomp profile is
    /// accepted at registration and refused later by `worker::spawn`, before
    /// any child process exists. Registration is not a trust boundary.
    pub fn new(templates: Vec<WorkerTemplate>) -> Self {
        Self { templates }
    }

    /// Look up a template by name. Returns `None` for unknown names.
    /// The runtime MUST refuse to spawn anything not returned from
    /// this function.
    pub fn get(&self, name: &str) -> Option<&WorkerTemplate> {
        self.templates.iter().find(|t| t.name == name)
    }

    /// Number of registered templates.
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// True if the registry has no templates.
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// All registered template names.
    pub fn names(&self) -> Vec<&str> {
        self.templates.iter().map(|t| t.name.as_str()).collect()
    }
}

/// The defence-in-depth stdout/stderr redactor. Replaces every
/// occurrence of every registered secret byte sequence with
/// `[REDACTED]`. Best-effort by definition; the posture is
/// `ISOLATED_PROCESS_EXPOSURE`.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<Vec<u8>>,
}

impl Redactor {
    /// Build a redactor with no secrets. `redact` returns the input
    /// unchanged.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a redactor from a list of secret byte sequences. Empty
    /// entries are dropped.
    pub fn new<I, B>(secrets: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let secrets = secrets
            .into_iter()
            .map(|b| b.as_ref().to_vec())
            .filter(|b| !b.is_empty())
            .collect();
        Self { secrets }
    }

    /// Number of registered secrets.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// True if no secrets are registered.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// A copy of this redactor that also knows `secret`.
    ///
    /// Added for the case the template cannot cover: the runtime resolves an
    /// injected credential *after* the template was built, so a redactor
    /// declared in a worker file structurally cannot know the value — and a
    /// worker file that did know it would be a plaintext secret on disk, which
    /// is the thing this product exists to prevent. The runtime already holds
    /// the value in `secret_bytes` at that moment, so it seeds the redactor
    /// from its own resolution rather than from a file.
    pub fn extended_with(&self, secret: &[u8]) -> Self {
        if secret.is_empty() {
            return self.clone();
        }
        let mut secrets = self.secrets.clone();
        secrets.push(secret.to_vec());
        Self { secrets }
    }

    /// Replace every occurrence of every registered secret with
    /// `[REDACTED]`. The result is the input bytes with each match
    /// replaced. Non-overlapping matches are replaced left-to-right.
    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() || input.is_empty() {
            return input.to_vec();
        }
        // Sort secrets by length descending so the longest match wins
        // (avoids a prefix-of-longer-secret being replaced first).
        let mut secrets = self.secrets.clone();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let marker: &[u8] = b"[REDACTED]";
        let mut result = Vec::with_capacity(input.len());
        let mut cursor = 0;
        while cursor < input.len() {
            let mut matched = None;
            for s in &secrets {
                if cursor + s.len() <= input.len() && &input[cursor..cursor + s.len()] == s {
                    matched = Some(s);
                    break;
                }
            }
            if let Some(s) = matched {
                result.extend_from_slice(marker);
                cursor += s.len();
            } else {
                result.push(input[cursor]);
                cursor += 1;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_bridge::AuthorityEndpoint;
    use asv_domain::Authority;

    fn auth(s: &str) -> Authority {
        Authority::canonicalize(s).expect("test authority")
    }

    fn api_endpoint() -> AuthorityEndpoint {
        AuthorityEndpoint::new(auth("api.example.com"), 443).expect("endpoint")
    }

    fn attacker_endpoint() -> AuthorityEndpoint {
        AuthorityEndpoint::new(auth("attacker.example.net"), 443).expect("endpoint")
    }

    #[test]
    fn secret_injection_plan_is_none_detects_none() {
        assert!(SecretInjectionPlan::None.is_none());
        assert!(!SecretInjectionPlan::EnvVar { name: "T".into() }.is_none());
        assert!(!SecretInjectionPlan::File {
            path: PathBuf::from("/tmp/secret"),
            mode: 0o600
        }
        .is_none());
    }

    #[test]
    fn secret_injection_plan_kind_is_stable() {
        assert_eq!(SecretInjectionPlan::None.kind(), "none");
        assert_eq!(
            SecretInjectionPlan::EnvVar { name: "X".into() }.kind(),
            "env_var"
        );
        assert_eq!(
            SecretInjectionPlan::File {
                path: PathBuf::from("/t"),
                mode: 0o600
            }
            .kind(),
            "file"
        );
    }

    #[test]
    fn egress_deny_blocks_all_sinks() {
        let p = EgressPolicy::Deny;
        assert!(!p.authorises(&api_endpoint()));
        assert!(!p.authorises(&attacker_endpoint()));
        assert_eq!(p.kind(), "deny");
    }

    #[test]
    fn egress_allow_authorises_only_listed() {
        let p = EgressPolicy::Allow(vec![api_endpoint()]);
        assert!(p.authorises(&api_endpoint()));
        assert!(!p.authorises(&attacker_endpoint()));
        assert_eq!(p.kind(), "allow_list");
    }

    #[test]
    fn egress_empty_allow_blocks_everything() {
        // An empty allow-list is the "deny by default" policy.
        let p = EgressPolicy::Allow(vec![]);
        assert!(!p.authorises(&api_endpoint()));
    }

    #[test]
    fn landlock_profile_may_read_or_write_matches_exact_paths() {
        let p = LandlockProfile {
            allowed_read: vec![PathBuf::from("/usr/bin/kubectl")],
            allowed_write: vec![PathBuf::from("/tmp/worker-out")],
        };
        assert!(p.may_read(Path::new("/usr/bin/kubectl")));
        assert!(!p.may_read(Path::new("/usr/bin/anything-else")));
        assert!(p.may_write(Path::new("/tmp/worker-out")));
        assert!(!p.may_write(Path::new("/etc/passwd")));
    }

    #[test]
    fn seccomp_profile_is_production_only_for_closed_allow_list() {
        assert!(SeccompProfile::ClosedAllowList.is_production());
        assert!(!SeccompProfile::PassThrough.is_production());
    }

    #[test]
    fn registry_resolves_known_name() {
        let t = WorkerTemplate {
            name: "kubectl-worker".into(),
            binary: PathBuf::from("/usr/bin/kubectl"),
            arguments: vec!["get".into(), "pods".into()],
            secret_injection: SecretInjectionPlan::EnvVar {
                name: "KUBE_TOKEN".into(),
            },
            egress_policy: EgressPolicy::Allow(vec![api_endpoint()]),
            landlock_profile: LandlockProfile::default(),
            seccomp_profile: SeccompProfile::ClosedAllowList,
            redactor: Redactor::empty(),
        };
        let r = WorkerRegistry::new(vec![t]);
        assert!(r.get("kubectl-worker").is_some());
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
        assert_eq!(r.names(), vec!["kubectl-worker"]);
    }

    #[test]
    fn registry_returns_none_for_unknown_name() {
        let r = WorkerRegistry::default();
        assert!(r.is_empty());
        assert!(r.get("anything").is_none());
        assert!(r.get("bash").is_none());
    }

    #[test]
    fn registry_does_not_allow_arbitrary_binary_resembling_a_registered_name() {
        // A renamed clone is NOT the registered template.
        let r = WorkerRegistry::new(vec![WorkerTemplate {
            name: "kubectl-worker".into(),
            binary: PathBuf::from("/usr/bin/kubectl"),
            arguments: vec![],
            secret_injection: SecretInjectionPlan::None,
            egress_policy: EgressPolicy::Deny,
            landlock_profile: LandlockProfile::default(),
            seccomp_profile: SeccompProfile::ClosedAllowList,
            redactor: Redactor::empty(),
        }]);
        assert!(r.get("kubectl-worker-evil").is_none());
    }

    #[test]
    fn redactor_replaces_exact_secret() {
        let r = Redactor::new([b"AKIA-AKIA"]);
        let out = r.redact(b"prefix AKIA-AKIA suffix");
        assert_eq!(out, b"prefix [REDACTED] suffix");
    }

    #[test]
    fn redactor_replaces_multiple_secrets() {
        let r = Redactor::new([b"AAA", b"BBB"]);
        let out = r.redact(b"AAA xxx BBB yyy AAA");
        assert_eq!(out, b"[REDACTED] xxx [REDACTED] yyy [REDACTED]");
    }

    #[test]
    fn redactor_handles_overlap_with_longest_match_first() {
        // "ABCDEF" must win over "ABCD". Use a Vec<u8> to mix lengths.
        let r = Redactor::new([b"ABCD".to_vec(), b"ABCDEF".to_vec()]);
        let out = r.redact(b"x ABCDEF y");
        assert_eq!(out, b"x [REDACTED] y");
    }

    #[test]
    fn redactor_does_not_match_encoded_secret() {
        // M10 spec scenario: an encoded secret must NOT be redacted.
        // The redactor is honest about being exact-byte only.
        let r = Redactor::new([b"AKIA-AKIA"]);
        let out = r.redact(b"AKlBQQ==");
        assert_eq!(out, b"AKlBQQ==");
    }

    #[test]
    fn redactor_empty_is_a_no_op() {
        let r = Redactor::empty();
        assert!(r.is_empty());
        let out = r.redact(b"AKIA-AKIA");
        assert_eq!(out, b"AKIA-AKIA");
    }

    #[test]
    fn redactor_drops_empty_secrets() {
        // A redactor with only empty entries behaves like an empty redactor.
        let r = Redactor::new([b""]);
        assert!(r.is_empty());
        let out = r.redact(b"AKIA-AKIA");
        assert_eq!(out, b"AKIA-AKIA");
    }

    #[test]
    fn redactor_empty_input_is_returned_unchanged() {
        let r = Redactor::new([b"AAA"]);
        assert_eq!(r.redact(b""), b"");
    }

    #[test]
    fn posture_label_is_stable() {
        // The posture label is part of the public surface; tests that
        // refer to it MUST match the literal.
        assert_eq!(POSTURE_LABEL, "ISOLATED_PROCESS_EXPOSURE");
    }

    // ----- B1.3 tests --------------------------------------------------

    /// Synthetic HardenConfig builder for the B1.3 unit tests. Mirrors
    /// the public `HardenConfig` shape exactly; the constructor exists
    /// here because `HardenConfig::empty()` is private to the broker.
    fn synthetic_harden(cgroup_v2: bool, slice_created: bool) -> crate::harden::HardenConfig {
        crate::harden::HardenConfig {
            cgroup_v2,
            landlock_capable: true,
            landlock_installed: true,
            seccomp_installed: true,
            slice_created,
            slice_path: if slice_created {
                Some(std::path::PathBuf::from("/sys/fs/cgroup/asv-broker.test"))
            } else {
                None
            },
        }
    }

    #[test]
    fn degraded_reason_wire_names_are_stable() {
        // The audit row carries the result; a rename here is a
        // breaking change for every consumer of the audit log.
        assert_eq!(
            DegradedReason::CgroupV2Unavailable.as_str(),
            "cgroup_v2_unavailable"
        );
        assert_eq!(
            DegradedReason::SliceCreationFailed.as_str(),
            "slice_creation_failed"
        );
        assert_eq!(DegradedReason::NonLinux.as_str(), "non_linux");
    }

    #[test]
    fn strong_secretless_enabled_requires_both_conditions() {
        // Cgroup v2 mounted AND slice created: strong.
        assert!(strong_secretless_enabled(&synthetic_harden(true, true)));
        // Cgroup v2 mounted but no slice: NOT strong (permission
        // problem or similar). The worker would run outside the
        // fence the operator asked for.
        assert!(!strong_secretless_enabled(&synthetic_harden(true, false)));
        // No cgroup v2: not strong even with the slice_created
        // flag accidentally true (impossible in practice; the
        // slice creation step requires cgroup v2, but the
        // accessor must not assume the correlation).
        assert!(!strong_secretless_enabled(&synthetic_harden(false, true)));
        // Neither: not strong.
        assert!(!strong_secretless_enabled(&synthetic_harden(false, false)));
    }

    #[test]
    fn effective_posture_returns_strong_when_cgroup_fence_present() {
        let (label, reason) = effective_posture(&synthetic_harden(true, true));
        assert_eq!(label, PostureLabel::StrongSecretless);
        assert_eq!(reason, None);
    }

    #[test]
    fn effective_posture_returns_isolated_with_reason_when_cgroup_v2_missing() {
        let (label, reason) = effective_posture(&synthetic_harden(false, false));
        assert_eq!(label, PostureLabel::IsolatedProcessExposure);
        #[cfg(target_os = "linux")]
        assert_eq!(reason, Some(DegradedReason::CgroupV2Unavailable));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(reason, Some(DegradedReason::NonLinux));
    }

    #[test]
    fn effective_posture_returns_isolated_with_reason_when_slice_creation_failed() {
        // cgroup_v2 is true but slice_created is false. The
        // effective posture must be IsolatedProcessExposure with
        // SliceCreationFailed (NOT CgroupV2Unavailable, because
        // the kernel HAS cgroup v2; the broker failed to set
        // the slice up).
        let (label, reason) = effective_posture(&synthetic_harden(true, false));
        assert_eq!(label, PostureLabel::IsolatedProcessExposure);
        assert_eq!(reason, Some(DegradedReason::SliceCreationFailed));
    }

    #[test]
    fn default_posture_label_is_still_isolated_process_exposure() {
        // B1.3 feature-flag policy: the Default does NOT call
        // effective_posture; the audit row stays opt-in for one
        // release. Pin this so a future flip is a deliberate
        // change, not an accident.
        assert_eq!(
            PostureLabel::default(),
            PostureLabel::IsolatedProcessExposure
        );
    }
}
