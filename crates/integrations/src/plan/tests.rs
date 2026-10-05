//! R3's `plan` rows.
//!
//! A plan is advice, and advice has a failure mode that code does not: it can
//! be **confidently wrong**. Every row here is chosen so that a specific way of
//! being confidently wrong turns it red — a plan that offers a strategy ASV
//! cannot deliver, that offers the weaker strategy first, that picks one of two
//! equally good credentials without saying so, or that describes a file which
//! has since changed.
//!
//! The two rows that matter most are the structural pair at the end. They
//! assert that the plan cannot *hold* a credential, the same way the discovery
//! report cannot, because a plan names credentials and a plan is the document
//! an agent reads before deciding what to move. If a future change adds a field
//! carrying a value, those two go red rather than the plan quietly becoming a
//! place secrets travel.

use std::path::Path;

use asv_domain::{CredentialId, CredentialKind, CredentialMetadata, Exportability};

use super::*;
use crate::npm::{NpmFile, Registry};

const TOKEN: &str = "npm_AbCdEf0123456789XyZ";

fn fingerprint_for(path: &str) -> FileFingerprint {
    FileFingerprint {
        path: path.into(),
        resolved_path: path.into(),
        inode: 1,
        owner_uid: 1000,
        mode: 0o600,
        size: 0,
        digest: "sha256:0".into(),
    }
}

/// One file, one registry, one `//host/:_authToken` selector.
fn discovery_with(field: AuthField, value: &str) -> NpmDiscovery {
    NpmDiscovery {
        files: vec![NpmFile {
            origin: Origin::User,
            fingerprint: fingerprint_for("/home/u/.npmrc"),
            registry: None,
            scoped_registries: Vec::new(),
            auth_selectors: vec![AuthSelector {
                registry: Registry {
                    audience: crate::RegistryAudience::parse("registry.example.test")
                        .expect("canonicalises"),
                    url: "https://registry.example.test/".into(),
                    path_prefix: String::new(),
                },
                field,
                value_len: value.len(),
                value_is_env_reference: false,
                env_reference: None,
            }],
            settings: Default::default(),
        }],
    }
}

fn token_discovery() -> NpmDiscovery {
    discovery_with(AuthField::AuthToken, TOKEN)
}

fn metadata(label: &str, kind: CredentialKind) -> CredentialMetadata {
    CredentialMetadata::new(label, kind)
}

fn exportable(
    mut credential: CredentialMetadata,
    exportability: Exportability,
) -> CredentialMetadata {
    credential.exportability = exportability;
    credential
}

/// **The schema string is part of the contract, and it is not the discovery's.**
///
/// A consumer that parsed a discovery and is handed a plan has been handed a
/// document about credentials that are not yet moved. A plan that claimed
/// `asv.discovery/v1` would be a plan claiming to be a report about files.
#[test]
fn the_plan_declares_its_own_schema() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("npm", CredentialKind::BearerToken)],
    );
    let json = serde_json::to_string(&plan).expect("serialises");
    assert!(
        json.contains(r#""schema":"asv.integrations.plan/v1""#),
        "{json}"
    );
    assert!(
        !json.contains("asv.discovery/v1"),
        "a plan must not claim the discovery schema: {json}"
    );
}

/// **The order is the recommendation.** An operator reading a plan top-down is
/// being told what to pick, so a plan whose last entry is the strongest strategy
/// is not a plan with a sorting bug — it is a plan that recommends the worst
/// option it offers.
#[test]
fn strategies_are_ordered_strongest_first() {
    let plan = plan_npm(
        &token_discovery(),
        &[exportable(
            metadata("npm-oauth", CredentialKind::OAuth2),
            Exportability::Exportable,
        )],
    );
    let postures: Vec<Posture> = plan.entries[0]
        .strategies
        .iter()
        .map(|strategy| strategy.posture)
        .collect();
    assert_eq!(
        postures,
        Posture::ALL.to_vec(),
        "a plan must offer every available posture, strongest first"
    );
}

/// **A static token is not a short-lived one.**
///
/// Writing a static token to a file and deleting it afterwards does not make it
/// short-lived; it makes a static credential that briefly existed. Offering
/// `SHORT_LIVED_EXPOSURE` for a bearer token would rename the risk rather than
/// reduce it, and an operator reading it would believe they had chosen the
/// better of two postures.
#[test]
fn a_static_token_is_never_offered_short_lived_exposure() {
    let plan = plan_npm(
        &token_discovery(),
        &[exportable(
            metadata("npm-pat", CredentialKind::BearerToken),
            Exportability::Exportable,
        )],
    );
    let postures: Vec<Posture> = plan.entries[0]
        .strategies
        .iter()
        .map(|strategy| strategy.posture)
        .collect();
    assert!(
        !postures.contains(&Posture::ShortLivedExposure),
        "a static bearer token was offered a short-lived posture: {postures:?}"
    );
    assert!(
        postures.contains(&Posture::StrongSecretless),
        "the broker substitutes a bearer token, so strong secretless is available: {postures:?}"
    );
}

/// The positive half of the row above, so it cannot pass by offering nothing.
#[test]
fn an_oauth2_credential_is_offered_short_lived_exposure() {
    let plan = plan_npm(
        &token_discovery(),
        &[exportable(
            metadata("npm-oauth", CredentialKind::OAuth2),
            Exportability::Exportable,
        )],
    );
    let postures: Vec<Posture> = plan.entries[0]
        .strategies
        .iter()
        .map(|strategy| strategy.posture)
        .collect();
    assert!(
        postures.contains(&Posture::ShortLivedExposure),
        "an OAuth2 credential is the one kind with something to mint per use: {postures:?}"
    );
}

/// **A posture ASV cannot deliver is not a posture.**
///
/// `NonExportable` is the *default* exportability, so this is the common path,
/// and the refusal is the whole control: the value cannot leave the vault, so
/// writing it into an ephemeral file for the tool is not something ASV can do.
/// Offering it anyway would send an operator to `adopt` for a step that fails.
#[test]
fn a_non_exportable_credential_is_never_offered_raw_exposure() {
    // `CredentialMetadata::new` defaults to `NonExportable`, and this row does
    // not set it — the default is the thing under test.
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("npm-pat", CredentialKind::BearerToken)],
    );
    let postures: Vec<Posture> = plan.entries[0]
        .strategies
        .iter()
        .map(|strategy| strategy.posture)
        .collect();
    assert_eq!(
        postures,
        vec![Posture::StrongSecretless],
        "a non-exportable credential can only be brokered, never handed out"
    );
}

/// **A database password is not a registry token, and that is a type error.**
///
/// The same rule `CredentialClass` exists for. The question is asked directly
/// against the class rather than through `CredentialClass::backs`, because
/// `OperationFamily` has no `Registry` variant — a gap in `asv-domain` that
/// R2.F.3 owns and this crate does not edit unilaterally.
#[test]
fn a_database_credential_cannot_serve_a_registry() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("postgres", CredentialKind::DatabaseCredential)],
    );
    assert_eq!(
        plan.entries[0].binding,
        Binding::Unbound {
            reason: UnboundReason::EveryCandidateExcluded {
                excluded: vec![Exclusion::DatabaseShaped {
                    kind: CredentialKind::DatabaseCredential,
                }],
            },
        },
        "a database credential must be excluded by name, so the operator can see why"
    );
    assert!(
        plan.entries[0].strategies.is_empty(),
        "nothing was bound, so no strategy is offered"
    );
}

/// **Two credentials that both fit is a question, and `plan` does not answer
/// it by picking one.**
///
/// The inventory carries a `kind` and not the audience a credential is
/// registered for — the broker does not report audiences over IPC — so nothing
/// in these inputs distinguishes a registry token from a CI token. Choosing the
/// first would be a coin flip presented as a decision, and `adopt` would then
/// move the wrong credential with the operator's full confidence.
#[test]
fn two_usable_credentials_are_reported_rather_than_one_chosen() {
    let first = metadata("npm-registry", CredentialKind::BearerToken);
    let second = metadata("ci-pipeline", CredentialKind::BearerToken);
    let plan = plan_npm(&token_discovery(), &[first.clone(), second.clone()]);

    match &plan.entries[0].binding {
        Binding::Ambiguous { candidates } => {
            let ids: Vec<CredentialId> = candidates.iter().map(|c| c.credential).collect();
            assert_eq!(
                ids,
                vec![first.id, second.id],
                "both are named, in inventory order"
            );
        }
        other => panic!("two usable credentials were not reported as ambiguous: {other:?}"),
    }
    assert!(
        plan.entries[0].strategies.is_empty(),
        "an unresolved binding offers no strategy, because none is yet known to be right"
    );
}

/// **An absence the operator cannot see is the ambiguity R3 exists to remove.**
///
/// A selector that found no credential still happened, and the operator
/// configured it. Filtering it out produces a plan that reads as complete: the
/// file's one auth selector simply is not in it.
#[test]
fn a_selector_with_no_credential_is_reported_rather_than_dropped() {
    let plan = plan_npm(&token_discovery(), &[]);
    assert_eq!(
        plan.entries.len(),
        1,
        "the selector vanished: {}",
        serde_json::to_string(&plan).unwrap()
    );
    assert_eq!(
        plan.entries[0].binding,
        Binding::Unbound {
            reason: UnboundReason::NoUsableCredential { inventory_size: 0 },
        }
    );
}

/// **The inventory size is part of the answer**, because "no strategies because
/// you have no credentials" and "no strategies because the one credential you
/// have is the wrong shape" are different facts, and a plan that renders both
/// as an empty list is answering a question nobody asked.
#[test]
fn the_plan_reports_the_inventory_it_was_given() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("a", CredentialKind::BearerToken)],
    );
    assert_eq!(plan.inventory_size, 1);
    let empty = plan_npm(&token_discovery(), &[]);
    assert_eq!(empty.inventory_size, 0);
}

/// **An email address is a contact field, not a credential.** npm sends it as a
/// publish header, and a plan that offered to protect it would be offering to
/// protect something that needs no protection — and would count it as a
/// credential the operator has to adopt.
#[test]
fn an_email_is_not_a_credential_and_gets_no_strategy() {
    let plan = plan_npm(
        &discovery_with(AuthField::Email, "ops@example.test"),
        &[metadata("npm-pat", CredentialKind::BearerToken)],
    );
    assert_eq!(
        plan.entries[0].binding,
        Binding::NotACredential {
            field: AuthField::Email
        }
    );
    assert!(
        plan.entries[0].operations.is_empty(),
        "an email authorises no operation"
    );
    assert!(
        plan.entries[0].strategies.is_empty(),
        "there is nothing to offer a strategy for"
    );
}

/// A misspelled field npm ignores. `NotACredential` rather than `Unbound`
/// because the difference matters to the operator: this key is *not a
/// credential npm will use*, which is a different problem from *a credential
/// with nothing behind it*.
#[test]
fn a_misspelled_auth_field_is_not_a_credential() {
    let plan = plan_npm(
        &discovery_with(AuthField::Unrecognised("_authTokne".into()), TOKEN),
        &[metadata("npm-pat", CredentialKind::BearerToken)],
    );
    assert!(matches!(
        &plan.entries[0].binding,
        Binding::NotACredential {
            field: AuthField::Unrecognised(_)
        }
    ));
    assert!(plan.entries[0].strategies.is_empty());
}

/// **A client certificate authenticates the transport, and `plan` does not model
/// publishing with one.** Claiming publish would put an operation in a plan that
/// `adopt` could not carry out.
#[test]
fn a_client_certificate_is_read_only() {
    let plan = plan_npm(
        &discovery_with(AuthField::CertFile, "/etc/ssl/npm.pem"),
        &[metadata("npm-mtls", CredentialKind::X509ClientIdentity)],
    );
    assert_eq!(
        plan.entries[0].operations,
        BTreeSet::from([Operation::Read]),
        "publish under mTLS is not modelled, so it is not claimed"
    );
}

/// **§7: a binding is not a label.** The entry has to name the credential, the
/// audience it would be used against, and the operations it would authorise —
/// because the whole failure §7 names is a plan that says `npm-token` and stops.
#[test]
fn the_entry_names_credential_audience_and_operations() {
    let credential = metadata("npm-registry", CredentialKind::BearerToken);
    let plan = plan_npm(&token_discovery(), &[credential.clone()]);
    let json = serde_json::to_string(&plan).expect("serialises");

    assert!(
        json.contains(&credential.id.to_string()),
        "the credential is not named: {json}"
    );
    assert!(
        json.contains("registry.example.test"),
        "the audience is not named: {json}"
    );
    assert!(
        json.contains("\"read\""),
        "no read operation is named: {json}"
    );
    assert!(
        json.contains("\"publish\""),
        "no publish operation is named: {json}"
    );

    // And the entry agrees with itself, which is what makes the JSON a report
    // rather than a rendering.
    let entry = &plan.entries[0];
    assert_eq!(entry.audience, "registry.example.test");
    assert_eq!(
        entry.operations,
        BTreeSet::from([Operation::Read, Operation::Publish]),
        "an auth token authorises both directions on a registry"
    );
}

/// **The plan reports what it was given, and nothing else.**
///
/// The characteristic failure of advice is not that it is vague — it is that it
/// is *specific and wrong*. A plan that named the public registry for every
/// selector would look correct on the overwhelmingly common case and be wrong
/// on exactly the case the operator ran `plan` to find out about. And a length
/// of zero makes an empty selector and a 34-byte token identical, which is the
/// one ambiguity a report about credentials cannot have.
#[test]
fn an_entry_reports_the_audience_and_length_its_selector_carried() {
    // `localhost:4873`, not the public registry: a fixture using the common
    // audience cannot tell "reported what it was given" from "reported the
    // default", which is the substitution this row exists to catch.
    let discovery = NpmDiscovery {
        files: vec![NpmFile {
            origin: Origin::User,
            fingerprint: fingerprint_for("/home/u/.npmrc"),
            registry: None,
            scoped_registries: Vec::new(),
            auth_selectors: vec![AuthSelector {
                registry: Registry {
                    audience: crate::RegistryAudience::parse("localhost:4873")
                        .expect("canonicalises"),
                    url: "http://localhost:4873/".into(),
                    path_prefix: String::new(),
                },
                field: AuthField::AuthToken,
                value_len: 34,
                value_is_env_reference: false,
                env_reference: None,
            }],
            settings: Default::default(),
        }],
    };
    let plan = plan_npm(
        &discovery,
        &[metadata("npm-registry", CredentialKind::BearerToken)],
    );

    assert_eq!(
        plan.entries[0].audience, "localhost:4873",
        "the plan named an audience its selector did not carry"
    );
    assert_eq!(
        plan.entries[0].value_len, 34,
        "the plan reported a length the file did not have"
    );
}

/// **The structural property, asserted against the output.** A plan names
/// credentials; if a plan could *hold* one, it would be the document an agent
/// reads immediately before deciding what to move, and a field added by a
/// well-meaning change would turn it into a place secrets travel.
///
/// **This property is structural, not behavioural, and the campaign says so.**
/// The plan's two inputs — a `NpmDiscovery` and a `&[CredentialMetadata]` —
/// contain no secret for it to carry, so *no mutation of this crate can make
/// the plan leak one*. The row is worth keeping anyway: it measures the output
/// against a real token in a real fixture, and the input half of the claim is
/// measured one layer down, by `npm_discover_falsify.py`'s `leak` bucket, which
/// does turn red when a value is added to the parse result.
#[test]
fn the_serialised_plan_contains_no_credential() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("npm-registry", CredentialKind::BearerToken)],
    );
    let json = serde_json::to_string(&plan).expect("serialises");
    assert!(!json.contains(TOKEN), "the token reached the plan: {json}");
    // The length is reported and the value is not, which is the distinction the
    // whole discovery report rests on and the one a plan must not lose.
    assert!(
        json.contains(&TOKEN.len().to_string()),
        "the length is still reported: {json}"
    );
}

/// `Debug` is a different code path from `Serialize`, and a plan safe in JSON
/// routinely is not in a log line.
#[test]
fn the_debug_rendering_contains_no_credential_either() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("npm-registry", CredentialKind::BearerToken)],
    );
    let rendered = format!("{plan:?}");
    assert!(
        !rendered.contains(TOKEN),
        "the token reached Debug: {rendered}"
    );
}

/// **§6: the plan is a promise about specific bytes, and drift voids it.**
///
/// A plan that survived a changed file is worse than no plan, because it looks
/// like an answer: it says what would happen, confidently, about a file that no
/// longer exists in the form it describes.
#[test]
fn a_changed_configuration_refuses_the_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".npmrc");
    write_file(&path, "registry=https://a.test/\n");
    let plan = plan_for_file(
        &path,
        CredentialKind::BearerToken,
        Exportability::Exportable,
    );

    write_file(&path, "registry=https://b.test/\n");

    match plan.revalidate(&FingerprintPolicy::strict(), dir.path(), dir.path()) {
        Err(PlanError::ConfigChanged { path: at, drift }) => {
            assert_eq!(at, path);
            assert!(
                drift.contains(&Drift::Contents),
                "the bytes changed and the plan did not say so: {drift:?}"
            );
        }
        other => panic!("a changed file was accepted by the plan: {other:?}"),
    }
}

/// The positive control, so the row above cannot pass by refusing everything.
#[test]
fn an_unchanged_configuration_revalidates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".npmrc");
    write_file(&path, "registry=https://a.test/\n");
    let plan = plan_for_file(
        &path,
        CredentialKind::BearerToken,
        Exportability::Exportable,
    );

    plan.revalidate(&FingerprintPolicy::strict(), dir.path(), dir.path())
        .expect("an untouched file revalidates");
}

/// **A replacement is not an edit.** Two files with identical bytes have
/// identical digests, so a comparison that looked only at the digest would let a
/// file swapped for an identical copy pass — and the swap is the attack, since
/// the bytes are the same by construction.
#[test]
fn a_replaced_file_is_caught_not_only_by_the_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = dir.path().join("original");
    let replacement = dir.path().join("replacement");
    write_file(&original, "registry=https://a.test/\n");
    write_file(&replacement, "registry=https://a.test/\n");

    let plan = plan_for_file(
        &original,
        CredentialKind::BearerToken,
        Exportability::Exportable,
    );
    std::fs::rename(&replacement, &original).expect("swap it");

    match plan.revalidate(&FingerprintPolicy::strict(), dir.path(), dir.path()) {
        Err(PlanError::ConfigChanged { drift, .. }) => {
            assert!(
                drift.contains(&Drift::Inode),
                "an identical-bytes replacement must be caught by the inode: {drift:?}"
            );
        }
        other => panic!("a replaced file was accepted by the plan: {other:?}"),
    }
}

/// A file that has gone is not a file that is unchanged. `revalidate` reporting
/// success here would be the worst of the three outcomes: it would mean the plan
/// survives the configuration disappearing.
#[test]
fn an_unreadable_file_refuses_the_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".npmrc");
    write_file(&path, "registry=https://a.test/\n");
    let plan = plan_for_file(
        &path,
        CredentialKind::BearerToken,
        Exportability::Exportable,
    );

    std::fs::remove_file(&path).expect("remove it");

    assert!(
        matches!(
            plan.revalidate(&FingerprintPolicy::strict(), dir.path(), dir.path()),
            Err(PlanError::Unreadable { .. })
        ),
        "a vanished file was accepted by the plan"
    );
}

// --- fixtures -------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("write");
    use std::io::Write as _;
    file.write_all(contents.as_bytes()).expect("write");
}

/// A one-selector discovery whose fingerprint is the **real** one for `path`, so
/// `revalidate` has something true to re-check.
fn plan_for_file(
    path: &Path,
    kind: CredentialKind,
    exportability: Exportability,
) -> IntegrationPlan {
    let real = FingerprintPolicy::strict()
        .fingerprint(path)
        .expect("fingerprint");
    let discovery = NpmDiscovery {
        files: vec![NpmFile {
            origin: Origin::User,
            fingerprint: real,
            registry: None,
            scoped_registries: Vec::new(),
            auth_selectors: vec![AuthSelector {
                registry: Registry {
                    audience: crate::RegistryAudience::parse("registry.example.test")
                        .expect("canonicalises"),
                    url: "https://registry.example.test/".into(),
                    path_prefix: String::new(),
                },
                field: AuthField::AuthToken,
                value_len: TOKEN.len(),
                value_is_env_reference: false,
                env_reference: None,
            }],
            settings: Default::default(),
        }],
    };
    plan_npm(
        &discovery,
        &[exportable(metadata("npm-registry", kind), exportability)],
    )
}

/// **A plan is read back, so it must be readable.** `IntegrationPlan` derived
/// `Deserialize` while carrying `schema: &'static str`, and that compiles — but
/// a `&'static str` deserialises only from data that already lives forever, so
/// the moment `adopt` tried to read a plan back off disk it did not compile.
/// **A derive is only instantiated when something asks for it**, which is
/// exactly the shape of defect that looks clean in review and breaks the first
/// time a second writer needs the type.
///
/// This row is the instantiation. Without it the derive is checked by nothing.
#[test]
fn a_plan_round_trips_through_the_shape_a_consumer_actually_reads() {
    let plan = plan_npm(
        &token_discovery(),
        &[metadata("npm-registry", CredentialKind::BearerToken)],
    );
    let json = serde_json::to_string(&plan).expect("serialises");

    let parsed: IntegrationPlan =
        serde_json::from_str(&json).expect("a plan this build produced must be readable by one");
    assert_eq!(
        parsed.schema, PLAN_SCHEMA,
        "the schema survives the round trip"
    );
    assert_eq!(parsed.entries.len(), plan.entries.len());
    assert_eq!(
        parsed, plan,
        "a plan that does not survive its own round trip is not a contract"
    );
}
