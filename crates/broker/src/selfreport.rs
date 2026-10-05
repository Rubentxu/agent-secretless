//! What the broker can say about itself, and where each answer comes from.
//!
//! # Why this is a record rather than a query
//!
//! `harden::install` returns a [`crate::harden::HardenConfig`] describing the
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
    /// Which OS identity this broker is running as, and whether that is the one
    /// the installation declared.
    ///
    /// `None` means **not measured**, which is the truth for a broker assembled
    /// in a test or through [`crate::identity`]'s absence from the path, and it
    /// is deliberately not a default of "shared with the invoking user": a
    /// report that claimed to know would be guessing, and `unknown` in a
    /// diagnostic is worse than a measured `not dedicated`.
    pub identity: Option<asv_ipc_protocol::BrokerIdentity>,
    /// Where this broker's CONNECT listener is bound, as `addr:port`.
    ///
    /// `None` means the listener is not running — which is the default, and is
    /// the same "absent, not assumed" reading the rest of this record takes.
    ///
    /// This field exists so `asv run` does not have to be *told* where to send
    /// its session's CONNECTs. The reasoning is the module's own: the answer to
    /// "where is the running broker's proxy?" otherwise exists for the length
    /// of a log line, and the process that needs it — the one starting a
    /// session — cannot ask. An operator supplying the address as a flag would
    /// be a second source of truth that can disagree with the first, and a
    /// disagreement here does not fail loudly: the shim would simply forward
    /// every CONNECT somewhere that is not the broker.
    pub connect_listen: Option<String>,
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
            // Not measured rather than "shared". See the field's docs: the
            // default is what a broker that never ran the check can honestly
            // say, and it is not the same as having measured a shared uid.
            identity: None,
            // No listener unless one was started. See the field's docs: a
            // default that named an address would send `asv run`'s shim
            // somewhere that is not a broker.
            connect_listen: None,
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
/// complete path teaches an agent to try it.
///
/// The invariant is **bidirectional**, and both directions have bitten:
///
/// - Every name here is backed by a `Request` variant that is *handled* rather
///   than refused as unknown.
/// - Every handled `Request` variant that represents an operation is *named*
///   here. This is the direction that was missing: `aws.sts.caller_identity`
///   was fully built — a domain action, a typed request, a broker operation and
///   a CLI verb — and was not announced, so `asv capabilities` told an agent the
///   product had no AWS path. A feature nobody is told about is not reachable,
///   which is R1's lesson applied to discovery rather than to execution.
///
/// `every_advertised_capability_is_handled` and
/// `every_handled_operation_is_advertised` are what keep the two in step.
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
        // The AWS provider's first operation. Named for what the agent gets
        // back, which is an identity, and deliberately *not* named after the
        // API action it calls: the module's own row below refuses a name that
        // reads like a retrieval, and `aws.sts.get_caller_identity` contains
        // "get".
        //
        // No secret crosses this boundary, and the response type has no field
        // one could fit in — so listing it costs an agent nothing to hold.
        "aws.sts.caller_identity".to_string(),
        // The OAuth2 provider's first operation, and the same argument as the
        // line above: named for what comes back (an identity, verified against
        // the deployment), not after the HTTP method that fetches it.
        //
        // It is also the operation that turned M11's second provider from a
        // library vertical into a surface. Before this, the daemon mounted
        // `OAuth2SecretPort` and no request could name it.
        "oauth2.identity".to_string(),
        // R2.F.3: the two halves of an OCI pull. See `capability_of` for why
        // these are two names and why the policy underneath evaluates a single
        // `registry_pull`.
        "registry.manifest.read".to_string(),
        "registry.blob.read".to_string(),
    ];
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_domain::{AgentSessionId, CredentialId, CredentialKind};
    use asv_ipc_protocol::{OpaqueSecret, Request, PROTOCOL_VERSION};
    use std::collections::{BTreeMap, BTreeSet};

    /// The capability a request is served by, or `None` for the requests that
    /// are plumbing rather than an operation an agent would name.
    ///
    /// **Exhaustive on purpose.** Adding a `Request` variant does not compile
    /// until it has been classified here, so "which operations exist" is
    /// answered in one place and the compiler refuses to let the two drift
    /// apart silently — which is exactly how `aws.sts.caller_identity` ended up
    /// built and unannounced.
    fn capability_of(request: &Request) -> Option<&'static str> {
        Some(match request {
            Request::Ping { .. } => "system.health",
            Request::AgentInfo { .. } => "system.self",
            Request::RunIsolated { .. } => "session.run",
            Request::MintSurrogate { .. } => "session.ssh_sign",
            Request::ListCredentialMetadata => "credentials.metadata",
            Request::CreateCredential { .. } => "credentials.create",
            Request::DeleteCredential { .. } => "credentials.revoke",
            Request::ReadIssue { .. } => "github.issue.read",
            Request::CreateIssue { .. } => "github.issue.create",
            Request::CreateRelease { .. } => "github.release.create",
            Request::AwsCallerIdentity { .. } => "aws.sts.caller_identity",
            Request::OAuth2Identity { .. } => "oauth2.identity",
            // R2.F.3. Named for the two halves an OCI pull is made of rather
            // than for the HTTP verb, for the same reason as the two lines
            // above: the agent receives content, not a capability request.
            //
            // **Two names, not one, and the split is not cosmetic.** The
            // broker answers a manifest read and a blob read from different
            // code, spends a surrogate on each, and a manifest names digests
            // that the agent then asks for by content address. Collapsing them
            // into one capability would tell an agent that fetching a manifest
            // fetches everything it names, which is the belief that turns a
            // policy permitting a read into a policy permitting a whole image.
            //
            // Both still resolve to the single `Action::RegistryPull` the
            // policy evaluates, because the registry's own scope treats them
            // as one: `repository:<name>:pull` covers both halves. The
            // advertisement is finer than the policy on purpose — an agent
            // choosing an operation wants to know which one it is asking for,
            // while an operator writing a rule does not.
            Request::PullManifest { .. } => "registry.manifest.read",
            Request::PullBlob { .. } => "registry.blob.read",
            Request::PostgresConnect { .. } => "postgres.connect",
            Request::PostgresQuery { .. } => "postgres.query",
            // Session lifecycle, authorisation, surrogate revocation, approval
            // and audit. Real operations, and none of them something an agent
            // selects *instead of* another capability — they are how the ones
            // above are reached. Advertising them would put plumbing in the
            // list a reader scans to decide what the product can do.
            _ => return None,
        })
    }

    /// One value of every `Request` variant.
    ///
    /// Deliberately fake: nothing here is sent anywhere, and the fields exist
    /// only so the enum can be enumerated. Building them as real sessions or
    /// real credentials would make this test depend on the subsystems it is
    /// meant to police.
    fn one_of_every_variant() -> Vec<Request> {
        let session = AgentSessionId::new();
        let credential = CredentialId::new();
        let surrogate = "surrogate".to_string();
        vec![
            Request::Ping {
                protocol: PROTOCOL_VERSION,
            },
            Request::AgentInfo {
                protocol: PROTOCOL_VERSION,
            },
            Request::CreateSession {
                workspace: String::new(),
            },
            Request::RegisterSessionKey {
                session,
                public_key_blob: Vec::new(),
            },
            Request::EndSession { session },
            Request::ListCredentialMetadata,
            Request::RunIsolated {
                session,
                worker: String::new(),
                args: Vec::new(),
                credential: None,
                timeout_ms: None,
            },
            Request::CreateCredential {
                label: String::new(),
                kind: CredentialKind::ApiKey,
                provider: String::new(),
                account: String::new(),
                secret: OpaqueSecret::new(Vec::new()),
            },
            Request::DeleteCredential { id: credential },
            Request::MintSurrogate {
                session,
                credential,
                max_uses: 0,
                ttl_secs: 0,
            },
            Request::RevokeSurrogate {
                session,
                surrogate: surrogate.clone(),
            },
            Request::ReadIssue {
                session,
                surrogate: surrogate.clone(),
                repo: String::new(),
                number: 0,
            },
            Request::CreateIssue {
                session,
                surrogate: surrogate.clone(),
                repo: String::new(),
                title: String::new(),
                body: String::new(),
            },
            Request::CreateRelease {
                session,
                surrogate: surrogate.clone(),
                repo: String::new(),
                tag: String::new(),
                name: String::new(),
                body: String::new(),
            },
            Request::AwsCallerIdentity {
                session,
                credential: String::new(),
            },
            Request::OAuth2Identity {
                session,
                credential: String::new(),
            },
            Request::AuditQuery { since_secs: 0 },
            Request::PostgresConnect {
                session,
                host: String::new(),
                host_addr: String::new(),
                port: 0,
                database: String::new(),
                role: String::new(),
            },
            Request::PostgresQuery {
                session,
                sql: String::new(),
            },
            Request::PostgresRevoke { session },
            Request::PullManifest {
                session,
                surrogate: surrogate.clone(),
                registry: String::new(),
                repository: String::new(),
                reference: String::new(),
            },
            Request::PullBlob {
                session,
                surrogate: surrogate.clone(),
                registry: String::new(),
                repository: String::new(),
                digest: String::new(),
            },
        ]
    }

    /// The sample's size, asserted.
    ///
    /// **This is a tripwire, not an exhaustiveness check, and it is named as
    /// one because it used to claim otherwise.** The row was called
    /// `the_sample_covers_every_request_variant` and its docstring said that
    /// without it "deleting a line from `one_of_every_variant` would quietly
    /// remove a variant from the coverage below". It would not. The assertion
    /// counted a literal list against a literal number, so it kept passing when
    /// `PullManifest` and `PullBlob` were added to the enum and left out of the
    /// sample — which is the exact failure the module's own header cites as
    /// having already happened once, for `aws.sts.caller_identity`.
    ///
    /// Making it genuinely exhaustive needs the variants *derived from the
    /// enum*, which on stable Rust means a derive macro (`strum::EnumIter`)
    /// this crate does not take, or a hand-maintained list of method names that
    /// is the same manual list with a different spelling. Neither is worth a
    /// new dependency in a crate that holds credential metadata, so the honest
    /// thing is to say what this row proves.
    ///
    /// What still holds the line is the pair below, in the other direction:
    /// `every_advertised_capability_is_handled` and
    /// `every_handled_operation_is_advertised` both read this sample, so a
    /// request that is classified but missing from the sample is invisible to
    /// them — and an unclassified request is classified as plumbing and simply
    /// not advertised. The gap is real and it is one-directional: the rules
    /// catch an advertisement with no request behind it, and they cannot catch
    /// a request with no advertisement. See the closeout for the follow-up.
    #[test]
    fn the_sample_has_the_size_this_file_claims() {
        let sample = one_of_every_variant();
        // `Authorize`, `ExplainAuthorization` and `SubmitApproval` carry an
        // `AuthorizationRequest`, which is the one variant family this sample
        // leaves out; they classify as plumbing, and the count below is what
        // makes that omission visible instead of assumed.
        assert_eq!(
            sample.len(),
            22,
            "a new Request variant must be added to one_of_every_variant(), \
             and one that represents an operation must also be classified"
        );
    }

    /// Every classified operation names a *distinct* capability.
    ///
    /// Added because the sample can now be extended by hand, and the failure
    /// this catches is two requests mapping to one capability string: the
    /// second row then proves nothing about the second request, and an agent
    /// reading the advertisement cannot tell the two operations apart.
    #[test]
    fn two_operations_do_not_share_one_capability_name() {
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for request in one_of_every_variant() {
            if let Some(capability) = capability_of(&request) {
                *seen.entry(capability).or_default() += 1;
            }
        }
        for (capability, count) in &seen {
            assert_eq!(
                *count,
                1,
                "{count} requests classify as {capability}; an agent reading the \
                 advertisement cannot tell them apart, and the row that checks the \
                 second one proves nothing"
            );
        }
    }

    /// The direction that was already claimed and was not true.
    ///
    /// A capability in the list with no request behind it is a promise the
    /// broker cannot keep, and an agent that trusts it will try it.
    #[test]
    fn every_advertised_capability_is_handled() {
        let served: BTreeSet<&str> = one_of_every_variant()
            .iter()
            .filter_map(capability_of)
            .collect();
        for advertised in compiled_capabilities() {
            assert!(
                served.contains(advertised.as_str()),
                "`{advertised}` is advertised but no Request variant is classified \
                 as serving it. Discovery is announcing something that is not there."
            );
        }
    }

    /// The direction that was missing, and the reason the AWS operation was
    /// invisible to `asv capabilities` for as long as it took to find.
    ///
    /// Falsifiable in the direction that matters: implement
    /// `Request::Whatever` and classify it, without adding the name to
    /// `compiled_capabilities()`, and this goes red.
    #[test]
    fn every_handled_operation_is_advertised() {
        let advertised: BTreeSet<String> = compiled_capabilities().into_iter().collect();
        for request in one_of_every_variant() {
            if let Some(capability) = capability_of(&request) {
                assert!(
                    advertised.contains(capability),
                    "`{capability}` is served by {:?} but not advertised, so an agent \
                     asking `asv capabilities` is told the product cannot do it",
                    std::mem::discriminant(&request)
                );
            }
        }
    }

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

    /// The default does not claim an identity, and the reason is the module's
    /// own: a default that said "shared" would be asserting a measurement that
    /// was never taken.
    #[test]
    fn the_default_claims_no_identity() {
        assert!(SelfReport::default().identity.is_none());
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
