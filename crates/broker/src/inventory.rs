//! What the broker knows about the credentials in its own vault.
//!
//! `BrokerState::credentials` is the list that `ListCredentialMetadata` serves
//! and that `MintSurrogate` validates against. For most of the project's life
//! nothing ever filled it: its only writer was `insert_credential`, a
//! test-seeding helper, so a broker that had opened a real vault still answered
//! `entries: []` and refused every real credential as "no such credential".
//! The comment on `BrokerState` even named the intended fix — "M1 makes it
//! encrypted and persistent" — and the second half of that sentence was never
//! done. This module is the second half.
//!
//! # The two vocabularies
//!
//! The vault and the domain type disagree about nearly everything, so this is a
//! translation rather than a cast:
//!
//! | | vault (`asv_vault`) | broker list (`asv_domain`) |
//! |---|---|---|
//! | id | `String` | `CredentialId`, a `Uuid` newtype |
//! | kind | 5 variants | 9 variants, only one name in common |
//! | fields | 10 | 4 |
//!
//! ## Ids
//!
//! A vault id is either a `CredentialId::to_wire()` UUID — which is what the M4
//! surrogate path lends by (`lib.rs`, `read_issue(&credential.to_wire(), …)`) —
//! or a naming convention such as `pg/{database}/{role}` used by the M6 live
//! path. Only the first can become a `CredentialId`. A convention-based id is
//! therefore **excluded and counted**. Diagnostics expose aggregate counts,
//! never the unsupported key. A credential that is absent from the list must
//! not be mistaken for a complete inventory.
//!
//! ## Narrowing
//!
//! Four of the vault's ten fields survive. That is by design, not loss: the
//! domain type is documented as the shape that is safe to list over IPC, show
//! in the dashboard and write to audit records. `provider`, `account`,
//! `resource`, `policy_refs`, `created_at` and `rotated_at` are deliberately
//! not carried here.

use asv_domain::{CredentialId, CredentialKind, CredentialMetadata, Exportability};
use asv_vault::{CredentialKind as VaultKind, Exportability as VaultExportability, VaultStore};
use std::collections::BTreeMap;

use crate::BrokerState;

/// What one load did, so the startup line can say it rather than implying the
/// list is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InventoryLoad {
    /// Credentials the broker can now see and lend by surrogate.
    pub loaded: usize,
    /// Credentials present in the vault that this broker cannot represent.
    pub skipped: usize,
    /// Distinct credential identities that collided during projection.
    pub collisions: usize,
}

/// Fills `state.credentials` from the vault's own inventory.
///
/// Called once at startup, after the vault is open and before its store is
/// moved into the lending port — the store is what knows the records, and the
/// lending port only lends by id.
///
/// Returns what happened so the caller can log aggregate counts. Credentials
/// whose id is not a `CredentialId` wire form are counted in `skipped` without
/// logging the raw id or parser error. The function never fails or aborts the
/// boot, because a vault holding
/// one legacy id is still a vault whose other credentials are usable, and
/// refusing to start would take away access the operator already had.
pub fn load(state: &mut BrokerState, store: &VaultStore) -> InventoryLoad {
    let records = store.list();
    let (credentials, result) = project_records(&records);
    state.credentials.extend(credentials);
    result
}

/// Projects vault metadata into public broker metadata. Group by the exact
/// source key before conversion so a duplicate identity can never be resolved
/// by choosing whichever record happened to arrive first.
fn project_records(
    records: &[&asv_vault::CredentialMetadata],
) -> (Vec<CredentialMetadata>, InventoryLoad) {
    let mut by_id: BTreeMap<&str, Vec<&asv_vault::CredentialMetadata>> = BTreeMap::new();
    for record in records {
        by_id.entry(record.id.as_str()).or_default().push(*record);
    }

    let mut credentials = Vec::new();
    let mut result = InventoryLoad::default();
    for (wire_id, group) in by_id {
        if group.len() > 1 {
            result.collisions += 1;
            result.skipped += group.len();
            continue;
        }

        let record = group[0];
        match CredentialId::from_wire(wire_id) {
            Ok(id) => {
                credentials.push(CredentialMetadata {
                    id,
                    label: record.label.clone(),
                    kind: record.effective_kind(),
                    exportability: exportability(record.exportability),
                });
                result.loaded += 1;
            }
            Err(_) => result.skipped += 1,
        }
    }

    (credentials, result)
}

/// The vault's storage class onto the domain's nine.
///
/// Written out rather than derived: the two enums share only the name
/// `BearerToken`, so a `From` impl would be a guess dressed as a
/// conversion. Exhaustive on purpose — adding a variant to either enum breaks
/// this match at compile time, which is the moment the mapping should be
/// revisited.
///
/// This is a **fallback**, not the answer. A record may carry a
/// `domain_kind` — the kind the operator chose — and when it does, that is
/// what the caller is told. The vault's five remain the storage class and
/// keep every meaning they had; this function only decides what a record with
/// no label reports.
fn kind(kind: VaultKind) -> CredentialKind {
    match kind {
        VaultKind::Opaque => CredentialKind::GenericSecret,
        VaultKind::PrivateKey => CredentialKind::SshPrivateKey,
        VaultKind::BearerToken => CredentialKind::BearerToken,
        VaultKind::Password => CredentialKind::UsernamePassword,
        VaultKind::DatabasePassword => CredentialKind::DatabaseCredential,
    }
}

/// The domain's nine kinds onto the vault's five storage classes — the
/// direction a *write* travels.
///
/// **Total, since the vault gained a `domain_kind` field.** It used to return
/// `None` for four kinds and the broker refused them by name; that was the
/// honest answer then, and it is what stopped an `ApiKey` being written as a
/// `BearerToken` and read back as something the operator did not ask for.
///
/// The refusal is no longer needed because the label now travels beside the
/// storage class. Every kind maps, and the mapping is lossy **in a way the
/// record itself records**: an `ApiKey` is held as a `BearerToken` *and* says
/// so, and the read prefers what it said. Collapsing without recording would
/// be the defect; collapsing while recording is the design.
///
/// Kept adjacent to `kind()` deliberately: the two directions are only correct
/// together, and the round trip is what a test should pin.
pub fn vault_kind(kind: CredentialKind) -> VaultKind {
    match kind {
        CredentialKind::BearerToken | CredentialKind::ApiKey | CredentialKind::OAuth2 => {
            VaultKind::BearerToken
        }
        CredentialKind::UsernamePassword => VaultKind::Password,
        CredentialKind::SshPrivateKey | CredentialKind::X509ClientIdentity => VaultKind::PrivateKey,
        CredentialKind::AwsAccessKey => VaultKind::PrivateKey,
        CredentialKind::DatabaseCredential => VaultKind::DatabasePassword,
        CredentialKind::GenericSecret => VaultKind::Opaque,
    }
}

/// The storage class a vault kind projects to, as a domain kind.
///
/// Exposed so the create verb can ask "does the record already say what the
/// operator asked for?" without restating the mapping. A second copy of that
/// match would be a second thing to forget when a variant is added, and the
/// failure would be a redundant or missing `domain_kind` — invisible until an
/// operator compared a listing against what they typed.
pub fn kind_of(storage: VaultKind) -> CredentialKind {
    kind(storage)
}

/// Projects one just-written vault record into the broker's public metadata.
///
/// Same mapping `load` applies, for the single-record case a create performs.
/// Exists so a credential created while the broker is running is projected by
/// the *same* code that projects it at boot; two copies of this conversion
/// would drift, and the drift would be invisible until a created credential
/// behaved differently from a loaded one.
pub fn project_one(record: &asv_vault::CredentialMetadata) -> Option<CredentialMetadata> {
    CredentialId::from_wire(&record.id)
        .ok()
        .map(|id| CredentialMetadata {
            id,
            label: record.label.clone(),
            // `effective_kind`, not `kind(record.kind)`: the record's own
            // answer, which is the operator's label when there is one. Calling
            // the fallback here would read every one of the four kinds this
            // cycle enables back as a neighbour, and only for a credential
            // created while the broker was running.
            kind: record.effective_kind(),
            exportability: exportability(record.exportability),
        })
}

/// Exportability crosses unchanged, one for one.
///
/// A `NonExportable` credential must not arrive at the broker labelled
/// anything else: this enum is what R1 and the human-only reveal path in ADR-0001
/// key off, so a widened default here would quietly weaken them. Both enums
/// are exhaustive, so a future variant cannot slip through unreviewed.
fn exportability(exportability: VaultExportability) -> Exportability {
    match exportability {
        VaultExportability::NonExportable => Exportability::NonExportable,
        VaultExportability::HumanOnly => Exportability::HumanOnly,
        VaultExportability::Exportable => Exportability::Exportable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use asv_domain::secret::SecretBytes;
    use asv_vault::{KdfParams, VaultStore as Store};
    use secrecy::SecretString;

    const UUID_A: &str = "11111111-2222-3333-4444-555555555555";
    const UUID_B: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn store_with(entries: &[(&str, asv_vault::CredentialKind)]) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = SecretString::from("inventory-unit-pass".to_string());
        let mut store = Store::create(dir.path().join("v.asv"), &pass, KdfParams::fast_for_tests())
            .expect("create");
        let key = store.header().unlock(&pass).expect("unlock");
        for (id, kind) in entries {
            store
                .insert(
                    &key,
                    asv_vault::CredentialMetadata::new(*id, "label", *kind, "github", "acct", 1),
                    SecretBytes::new(b"secret".to_vec()),
                )
                .expect("insert");
        }
        (dir, store)
    }

    /// A vault with the ids M4 already uses is fully visible afterwards.
    #[test]
    fn a_uuid_keyed_vault_loads_completely() {
        let (_dir, store) = store_with(&[
            (UUID_A, asv_vault::CredentialKind::BearerToken),
            (UUID_B, asv_vault::CredentialKind::DatabasePassword),
        ]);
        let mut state = BrokerState::default();

        let result = load(&mut state, &store);

        assert_eq!(
            result,
            InventoryLoad {
                loaded: 2,
                skipped: 0,
                collisions: 0,
            }
        );
        assert_eq!(state.credentials.len(), 2);
        // The two ids survive as the same handles the vault named them by.
        assert!(state.credentials.iter().any(|c| c.id.to_wire() == UUID_A));
        assert!(state.credentials.iter().any(|c| c.id.to_wire() == UUID_B));
    }

    /// The M6 naming convention is not a `CredentialId`, so it is left out and
    /// counted rather than being coerced into something that looks loadable.
    #[test]
    fn a_convention_id_is_skipped_and_counted() {
        let (_dir, store) = store_with(&[
            (UUID_A, asv_vault::CredentialKind::Opaque),
            (
                "pg/shopdb/billing",
                asv_vault::CredentialKind::DatabasePassword,
            ),
        ]);
        let mut state = BrokerState::default();

        let result = load(&mut state, &store);

        assert_eq!(
            result,
            InventoryLoad {
                loaded: 1,
                skipped: 1,
                collisions: 0,
            }
        );
        assert_eq!(
            state.credentials.len(),
            1,
            "the convention id must not load"
        );
    }

    #[test]
    fn noncanonical_uuid_spellings_are_skipped() {
        let uppercase = UUID_B.to_ascii_uppercase();
        let compact = UUID_A.replace('-', "");
        assert!(CredentialId::from_wire(&uppercase).is_err());
        assert!(CredentialId::from_wire(&compact).is_err());
        let (_dir, store) = store_with(&[
            (uppercase.as_str(), asv_vault::CredentialKind::Opaque),
            (compact.as_str(), asv_vault::CredentialKind::Opaque),
        ]);
        let source_ids: Vec<_> = store
            .list()
            .iter()
            .map(|record| record.id.clone())
            .collect();
        assert_eq!(source_ids.len(), 2);
        assert!(source_ids.contains(&uppercase) && source_ids.contains(&compact));
        let mut state = BrokerState::default();

        let result = load(&mut state, &store);

        assert_eq!(result.loaded, 0);
        assert_eq!(result.skipped, 2);
        assert!(state.credentials.is_empty());
    }

    #[test]
    fn colliding_source_records_are_all_excluded() {
        let first = asv_vault::CredentialMetadata::new(
            UUID_A,
            "first",
            asv_vault::CredentialKind::BearerToken,
            "github",
            "acct",
            1,
        );
        let second = asv_vault::CredentialMetadata::new(
            UUID_A,
            "second",
            asv_vault::CredentialKind::BearerToken,
            "github",
            "acct",
            1,
        );

        let (projected, result) = project_records(&[&first, &second]);

        assert!(projected.is_empty(), "neither ambiguous record may win");
        assert_eq!(result.loaded, 0);
        assert_eq!(result.skipped, 2);
        assert_eq!(result.collisions, 1);
    }

    /// Every vault kind lands on a domain kind, and the awkward pairs are
    /// pinned: `Password` is not `DatabasePassword`, and `Opaque` is not
    /// `BearerToken`.
    #[test]
    fn every_vault_kind_maps_to_its_domain_kind() {
        let pairs = [
            (
                asv_vault::CredentialKind::Opaque,
                CredentialKind::GenericSecret,
            ),
            (
                asv_vault::CredentialKind::PrivateKey,
                CredentialKind::SshPrivateKey,
            ),
            (
                asv_vault::CredentialKind::BearerToken,
                CredentialKind::BearerToken,
            ),
            (
                asv_vault::CredentialKind::Password,
                CredentialKind::UsernamePassword,
            ),
            (
                asv_vault::CredentialKind::DatabasePassword,
                CredentialKind::DatabaseCredential,
            ),
        ];
        for (vault, domain) in pairs {
            assert_eq!(kind(vault), domain);
        }
    }

    /// Exportability is never widened in translation. R1 and the ADR-0001
    /// human-only reveal path both key off this value, so a default that
    /// drifted to `Exportable` would weaken them without any test failing
    /// anywhere else.
    #[test]
    fn exportability_crosses_unchanged() {
        assert_eq!(
            exportability(asv_vault::Exportability::NonExportable),
            Exportability::NonExportable
        );
        assert_eq!(
            exportability(asv_vault::Exportability::HumanOnly),
            Exportability::HumanOnly
        );
        assert_eq!(
            exportability(asv_vault::Exportability::Exportable),
            Exportability::Exportable
        );
    }

    /// The list carries metadata, never the secret. A vault holding a distinctive
    /// value must produce a list that does not mention it.
    #[test]
    fn the_loaded_list_contains_no_secret_material() {
        const CANARY: &str = "ASV-CANARY-inventory-91d2-DO-NOT-LEAK";
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = SecretString::from("inventory-canary-pass".to_string());
        let mut store = Store::create(dir.path().join("v.asv"), &pass, KdfParams::fast_for_tests())
            .expect("create");
        let key = store.header().unlock(&pass).expect("unlock");
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    UUID_A,
                    "canary",
                    asv_vault::CredentialKind::BearerToken,
                    "github",
                    "acct",
                    1,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )
            .expect("insert");
        let mut state = BrokerState::default();

        load(&mut state, &store);

        let rendered = format!("{:?}", state.credentials);
        assert!(
            !rendered.contains(CANARY),
            "the secret reached the broker's credential list: {rendered}"
        );
    }
}
