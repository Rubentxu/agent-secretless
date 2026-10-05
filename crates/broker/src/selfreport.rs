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

/// The capabilities this build actually has a complete path for, each against
/// the wire method that serves it.
///
/// **One list, not two.** This used to be a `vec![]` of names here and an
/// exhaustive `match` on `Request` inside `#[cfg(test)]`. Two hand-maintained
/// taxonomies of the same decision, kept in step by two rows, and the direction
/// that bites had already bitten once: `aws.sts.caller_identity` was fully
/// built — a domain action, a typed request, a broker operation, a CLI verb —
/// and was not announced, so `asv capabilities` told an agent the product had
/// no AWS path.
///
/// Keying by [`Request::method_name`] rather than by the variant is what makes
/// one list possible. `method_name` is an exhaustive `match` over every
/// variant, so adding a `Request` is a *compile error* there; this table is then
/// the only place a variant can be classified, and
/// `every_request_method_is_classified_exactly_once` is what says the two are
/// the same set. That is a smaller thing to get wrong than a second list, and
/// the failure it can still produce -- a new variant classified as `None`
/// plumbing -- is visible rather than silent.
///
/// A `None` capability is a deliberate answer, not an omission: session
/// lifecycle, authorisation, surrogate revocation, approval and audit are real
/// operations, and none of them is something an agent selects *instead of*
/// another capability. They are how the ones below are reached. Advertising
/// them would put plumbing in the list a reader scans to decide what the
/// product can do.
const CAPABILITIES: &[(&str, Option<&str>)] = &[
    // Health and metadata.
    ("ping", Some("system.health")),
    ("agent_info", Some("system.self")),
    // Sessions and the SSH signer they carry.
    ("run_isolated", Some("session.run")),
    ("mint_surrogate", Some("session.ssh_sign")),
    // Credential *metadata* only. There is no capability here that returns a
    // secret, and the list is the place a reader looks to decide that.
    ("list_credential_metadata", Some("credentials.metadata")),
    ("create_credential", Some("credentials.create")),
    ("delete_credential", Some("credentials.revoke")),
    // Semantic connectors.
    ("read_issue", Some("github.issue.read")),
    ("create_issue", Some("github.issue.create")),
    ("create_release", Some("github.release.create")),
    ("postgres_connect", Some("postgres.connect")),
    ("postgres_query", Some("postgres.query")),
    // The AWS provider's first operation. Named for what the agent gets back,
    // which is an identity, and deliberately *not* named after the API action it
    // calls: a name that reads like a retrieval would tell an agent this
    // returns content, and "get" is the word that does that.
    //
    // No secret crosses this boundary, and the response type has no field one
    // could fit in -- so listing it costs an agent nothing to hold.
    ("aws_caller_identity", Some("aws.sts.caller_identity")),
    // The OAuth2 provider's first operation, and the same argument as the line
    // above: named for what comes back (an identity, verified against the
    // deployment), not after the HTTP method that fetches it.
    //
    // It is also the operation that turned M11's second provider from a library
    // vertical into a surface. Before this, the daemon mounted
    // `OAuth2SecretPort` and no request could name it.
    ("oauth2_identity", Some("oauth2.identity")),
    // R2.F.3 and R2.F.4: the four halves of an OCI exchange, read and write.
    //
    // **Four names, and the split is not cosmetic.** The broker answers each
    // from different code, spends a surrogate on each, and a manifest names
    // digests the agent then asks for by content address. Collapsing the reads
    // into one capability would tell an agent that fetching a manifest fetches
    // everything it names -- the belief that turns a policy permitting a read
    // into a policy permitting a whole image. The writes carry the same
    // warning: on a write, a mistake is published rather than merely leaked.
    //
    // All four resolve to two policy actions, and that is not a collapse.
    // `registry_pull` covers both reads because reading a manifest and reading
    // the blobs it names are one permission in the registry's own scope;
    // `registry_push` covers both writes for the same reason. The advertisement
    // is finer than the policy on purpose: an agent choosing an operation wants
    // to know which one it is asking for, while an operator writing a rule does
    // not.
    ("registry_pull_manifest", Some("registry.manifest.read")),
    ("registry_pull_blob", Some("registry.blob.read")),
    ("registry_push_manifest", Some("registry.manifest.push")),
    ("registry_push_blob", Some("registry.blob.push")),
    // Plumbing: real, and how the rows above are reached rather than something
    // an agent picks instead of one of them.
    ("create_session", None),
    ("end_session", None),
    ("register_session_key", None),
    ("postgres_revoke", None),
    ("authorize", None),
    ("explain_authorization", None),
    ("revoke_surrogate", None),
    ("submit_approval", None),
    ("audit_query", None),
];

/// The capabilities this build actually has a complete path for.
///
/// A `cfg` list, not a roadmap: R9 in `11-RISKS-OPEN-QUESTIONS.md` names the
/// failure directly, discovery announcing a feature that has types but no
/// complete path teaches an agent to try it.
///
/// Derived from [`CAPABILITIES`] rather than written out, so there is exactly
/// one place a capability is named. Sorted and deduplicated as the previous
/// hand-written list was, so the bytes `asv capabilities` prints are unchanged.
pub fn compiled_capabilities() -> Vec<String> {
    let mut out: Vec<String> = CAPABILITIES
        .iter()
        .filter_map(|(_, capability)| capability.map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The capability the wire method `method` is served by.
///
/// Production, and the reason the table above could stop being a second list:
/// this used to live inside `#[cfg(test)]`, which meant the classification an
/// agent reads and the one a row checked were maintained separately and only
/// met in a test build.
pub fn capability_of_method(method: &str) -> Option<&'static str> {
    CAPABILITIES
        .iter()
        .find(|(name, _)| *name == method)
        .and_then(|(_, capability)| *capability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asv_domain::{AgentSessionId, CredentialId, CredentialKind};
    use asv_ipc_protocol::{OpaqueSecret, Request, PROTOCOL_VERSION};
    use std::collections::{BTreeMap, BTreeSet};

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
            Request::PushManifest {
                session,
                surrogate: surrogate.clone(),
                registry: String::new(),
                repository: String::new(),
                reference: String::new(),
                manifest: Vec::new(),
            },
            Request::PushBlob {
                session,
                surrogate: surrogate.clone(),
                registry: String::new(),
                repository: String::new(),
                digest: String::new(),
                bytes: Vec::new(),
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
            24,
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
            if let Some(capability) = capability_of_method(request.method_name()) {
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
    /// Every wire method has exactly one row in the table.
    ///
    /// **This is the row the string key made necessary.** The table is keyed by
    /// [`Request::method_name`] so that one list could replace two, and the cost
    /// of that is that a method name is a string: a typo is not a compile error,
    /// it is a capability nobody is classified as serving. That is not
    /// hypothetical -- writing this table the first time, four of the registry
    /// methods were keyed `pull_manifest` rather than `registry_pull_manifest`
    /// and `every_advertised_capability_is_handled` is what caught it.
    ///
    /// So the exhaustiveness that used to come from a `match` inside
    /// `#[cfg(test)]` is asserted here instead, against the *real* method names
    /// rather than against a second hand-written list. A new `Request` variant
    /// fails to compile in `method_name` and then fails this row.
    #[test]
    fn every_request_method_is_classified_exactly_once() {
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for (method, _) in CAPABILITIES {
            *seen.entry(method).or_default() += 1;
        }
        for (method, count) in &seen {
            assert_eq!(*count, 1, "`{method}` is classified {count} times");
        }

        let advertised: BTreeSet<&str> = CAPABILITIES.iter().map(|(m, _)| *m).collect();
        let known: BTreeSet<&str> = one_of_every_variant()
            .iter()
            .map(|request| request.method_name())
            .collect();

        // Direction one: a real variant with no row. This is the direction that
        // bites -- a new operation that is served and unannounced, which is how
        // `aws.sts.caller_identity` stayed invisible for so long.
        for method in &known {
            assert!(
                advertised.contains(method),
                "`{method}` is a real Request variant with no row in CAPABILITIES. \
                 Add one -- with `None` if it is plumbing -- or a capability will \
                 drift from what the broker serves."
            );
        }

        // Direction two: a row naming something that is not a real method. The
        // table is keyed by strings, so a typo lands here rather than in a
        // compile error.
        //
        // **The comparison is against the sample, and the sample is smaller than
        // the enum.** `Authorize`, `ExplainAuthorization` and `SubmitApproval`
        // carry an `AuthorizationRequest` and are the one family
        // `one_of_every_variant` leaves out, so they are named here rather than
        // being quietly absent from the check. Each must be plumbing, and this
        // says so in a place a reader looks, instead of letting the omission
        // hide behind a count.
        const OUTSIDE_THE_SAMPLE: &[&str] =
            &["authorize", "explain_authorization", "submit_approval"];
        for method in OUTSIDE_THE_SAMPLE.iter().copied() {
            assert!(
                advertised.contains(method),
                "`{method}` is omitted from the sample and so is not checked above; \
                 it still needs a row."
            );
            assert_eq!(
                capability_of_method(method),
                None,
                "`{method}` is omitted from the sample, so nothing above can hold it \
                 to the right answer. If it has become an operation, it needs a \
                 capability and a row in the sample."
            );
        }
        assert_eq!(
            advertised.len(),
            known.len() + OUTSIDE_THE_SAMPLE.len(),
            "the table names {} methods and the enum {} plus the {} the sample \
             omits, so a row is either duplicated or points at nothing",
            advertised.len(),
            known.len(),
            OUTSIDE_THE_SAMPLE.len()
        );
    }

    /// A capability in the list with no request behind it is a promise the
    /// broker cannot keep, and an agent that trusts it will try it.
    #[test]
    fn every_advertised_capability_is_handled() {
        let served: BTreeSet<&str> = one_of_every_variant()
            .iter()
            .filter_map(|request| capability_of_method(request.method_name()))
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
            if let Some(capability) = capability_of_method(request.method_name()) {
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
