//! R3's `adopt`: the first step that moves a credential.
//!
//! # What is different about this step, stated precisely
//!
//! `discover` and `plan` never materialise a value. That is a property of
//! their types, and it stays true — neither can even reach a vault. `adopt` has
//! to produce a value, because moving it into the vault *is* the job. So the
//! law this module keeps is the narrower and more accurate one:
//!
//! **This crate cannot reach a vault.** Not `discover`, not `plan`, not the
//! function below. There is no client, no socket and no session here. A value
//! extracted by [`NpmAdoption::extract`] goes to exactly one place: the caller's
//! hands, to be handed straight to the broker. The moment the crate could
//! *decide* to send it somewhere is the moment this would be a second
//! credential plane.
//!
//! That is why the extraction is not a method on [`crate::npm::Parsed`] and not
//! reachable from a report: it takes the selector the caller has *already
//! decided* to adopt, so the decision about what moves is made before any value
//! exists in this process.
//!
//! # What `adopt` refuses, and why each refusal is a control
//!
//! - **Drift.** The value is read from bytes identified by a fingerprint. If
//!   those bytes changed since the plan, `adopt` refuses with
//!   [`AdoptError::ConfigChanged`] rather than importing whatever is there now.
//!   §6 of the design doc: `CONFIG_CHANGED` → abort → replan.
//! - **An environment reference.** `${NPM_TOKEN}` has no value in the file to
//!   move. Importing the *name* as if it were a credential would store a
//!   credential that cannot work, and it would look like a success.
//! - **An unrecognised field.** `_authTokne` is a typo npm ignores; there is no
//!   credential to import.
//! - **Already imported.** Two imports of the same selector produce two
//!   credentials with the same meaning, and the operator is left choosing which
//!   one to revoke.
//!
//! # What `adopt` deliberately does not do
//!
//! **It does not touch the file.** Doc 04 §10 is explicit that the original is
//! never deleted just because an import finished, and gives the order:
//! import → verify vault → verify new integration → negative bypass test →
//! human approval → scrub → rescan → receipt. The scrub is a separate,
//! human-approved step, and this module does not reach it. An `adopt` that
//! rewrote the file would skip four of those steps while looking like the
//! whole of the job.

use std::collections::BTreeSet;
use std::path::Path;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::fingerprint::{Drift, FileFingerprint, FingerprintPolicy};
use crate::npm::{AuthField, AuthSelector};

/// One selector `adopt` can act on.
///
/// Named rather than an index: an operator reading a receipt months later needs
/// to know *which* credential was moved, and `entries[2]` does not survive a
/// re-run of `plan` that inserts a selector above it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AdoptSelector {
    /// The file the selector is in, as `plan` reported it.
    pub file: String,
    /// The registry the selector addresses, canonicalised.
    pub audience: String,
    /// npm's own field name for it.
    pub field: AuthField,
}

impl AdoptSelector {
    /// True when this names the same selector as `entry`.
    ///
    /// Compared on all three parts rather than on any one, because a registry
    /// has many selectors and a field appears under many registries: matching on
    /// the audience alone would let an operator adopt `_authToken` when they
    /// meant `_auth`.
    pub fn matches(&self, file: &Path, audience: &str, field: &AuthField) -> bool {
        self.file == file.to_string_lossy() && self.audience == audience && self.field == *field
    }
}

/// Reads a configuration file's values on demand, and is the only part of this
/// crate that ever holds one.
#[derive(Debug, Clone, Copy, Default)]
pub struct NpmAdoption;

impl NpmAdoption {
    /// Extracts the value of one named selector.
    ///
    /// `expected` is the fingerprint the plan recorded. **The bytes are checked
    /// against it before the value is read**, not after: a check after would
    /// mean the value already existed in this process when the refusal
    /// happened.
    pub fn extract(
        policy: &FingerprintPolicy,
        file: &Path,
        selector: &AdoptSelector,
        expected: &FileFingerprint,
    ) -> Result<SecretString, AdoptError> {
        let current = policy
            .fingerprint(file)
            .map_err(|source| AdoptError::Unreadable {
                path: file.to_path_buf(),
                message: source.to_string(),
            })?;
        let drift = expected.drift_from(&current);
        if !drift.is_empty() {
            return Err(AdoptError::ConfigChanged {
                path: file.to_path_buf(),
                drift,
            });
        }
        let contents = read_zeroized(file)?;
        let mut found = None;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            if key.starts_with('[') {
                continue;
            }
            let Some((_, key_suffix)) = key.rsplit_once(':') else {
                continue;
            };
            let key_suffix = key_suffix.trim();
            // `Display` is npm's own spelling of the field, so comparing against it is
            // comparing against the file rather than against a second rendering of it.
            if key_suffix != selector.field.to_string() {
                continue;
            }
            // **The registry is half of the selector's identity, and the first
            // version of this function did not check it.** It matched on the
            // field alone, so an operator asking to adopt the credential for
            // `other.example.test` was served the value from
            // `registry.example.test` — the wrong credential imported, under a
            // receipt naming the wrong audience, looking like a success. The
            // row that caught it is
            // `a_selector_the_file_does_not_declare_is_refused`.
            if !registry_of(key).is_some_and(|found| found == selector.audience) {
                continue;
            }
            if found.is_some() {
                // Two lines set the same field for the same registry. npm's
                // effective value is the last one, and `discover` reports both,
                // so this is a real shape and not a corrupt file. Guessing here
                // would import something other than what the tool would use.
                return Err(AdoptError::AmbiguousLine {
                    field: selector.field.clone(),
                    audience: selector.audience.clone(),
                });
            }
            found = Some(value);
        }
        let value = found.ok_or_else(|| AdoptError::NoSuchSelector {
            selector: selector.clone(),
        })?;
        if value.starts_with("${") && value.ends_with('}') {
            // The file names a variable; it does not carry the credential.
            // Importing the name would store a credential that cannot work, and
            // it would look like a success.
            return Err(AdoptError::EnvReference {
                name: value
                    .trim_matches(|c| c == '{' || c == '}' || c == '$')
                    .to_string(),
                audience: selector.audience.clone(),
            });
        }
        if value.is_empty() {
            return Err(AdoptError::EmptyValue {
                audience: selector.audience.clone(),
            });
        }
        Ok(SecretString::new(value.to_string().into_boxed_str()))
    }
}

/// The canonical audience a `//host/path/:field` key addresses, or `None` when
/// the key is not one.
///
/// The host runs from the `//` to the **first** `/`, because npm scopes a
/// selector to a path and `//host/npm/:_authToken` is a different selector from
/// `//host/:_authToken`. Canonicalised through the same type `discover` uses, so
/// a selector named in one spelling cannot be matched by a line written in
/// another.
fn registry_of(key: &str) -> Option<String> {
    let rest = key.strip_prefix("//")?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    crate::RegistryAudience::parse(host)
        .ok()
        .map(|audience| audience.to_string())
}

/// Reads a file into a buffer that zeroizes itself on drop.
///
/// A `.npmrc` is mostly not secret, so this does not pretend otherwise: it
/// zeroes the whole buffer because the buffer *may* hold one line that is, and
/// "mostly secret" is not a category a `Drop` impl can act on.
fn read_zeroized(path: &Path) -> Result<Zeroizing<String>, AdoptError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|error| AdoptError::Unreadable {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut buffer = Zeroizing::new(String::new());
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_to_string(&mut buffer)
        .map_err(|error| AdoptError::Unreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    Ok(buffer)
}

/// Why `adopt` refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdoptError {
    #[error("the configuration changed since the plan was made: {path} ({drift:?}) — replan")]
    ConfigChanged {
        path: std::path::PathBuf,
        drift: Vec<Drift>,
    },
    #[error("could not read {path}: {message}")]
    Unreadable {
        path: std::path::PathBuf,
        message: String,
    },
    #[error(
        "this file sets {field} for {audience} more than once, and npm's effective value is the \
         last one — name which line you mean rather than have adopt guess"
    )]
    AmbiguousLine { field: AuthField, audience: String },
    #[error("this file declares no such selector: {selector:?}")]
    NoSuchSelector { selector: AdoptSelector },
    #[error(
        "the value for {audience} is a reference to ${name}, not a credential in this file; \
         nothing here can be adopted"
    )]
    EnvReference { name: String, audience: String },
    #[error("the value for {audience} is empty, and an empty credential is not one")]
    EmptyValue { audience: String },
}

/// What an import did, and what has still to happen to it.
///
/// A receipt, not a confirmation. Doc 04 §10 puts five steps between an import
/// and a scrub, and a receipt that said "done" would be claiming all five.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AdoptReceipt {
    /// `asv.integrations.adopt/v1`. A `String` for the same reason as every
    /// other schema field here: these documents are read back by consumers.
    pub schema: String,
    /// The selector that was imported.
    pub selector: AdoptSelector,
    /// The vault credential's id. **Never** its value, and never only its label.
    pub credential: crate::CredentialId,
    /// The label the credential was stored under, which the operator chose.
    pub label: String,
    /// The audience the credential is now bound to.
    pub audience: String,
    /// The operations the binding authorises.
    pub operations: BTreeSet<crate::Operation>,
    /// The file the credential came from, and that has deliberately **not** been
    /// touched. Carried so the scrub step knows where to look and can prove the
    /// file has not changed in between.
    pub source_file: String,
    /// The fingerprint of the source file as it was when the value was read.
    pub source_fingerprint: FileFingerprint,
    /// The steps doc 04 §10 requires before the original may be scrubbed.
    pub outstanding: Vec<PendingStep>,
}

/// One step of §10's sequence that `adopt` does not perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStep {
    /// Prove the credential is retrievable from the vault.
    VerifyVault,
    /// Prove the new integration works with the projection in place.
    VerifyNewIntegration,
    /// Prove the old path no longer works — the negative test that catches a
    /// scrub that only appeared to succeed.
    NegativeBypassTest,
    /// A human decides to remove the original.
    HumanApproval,
    /// Remove the original, rescan, and write the receipt.
    ScrubAndRescan,
}

/// `asv.integrations.adopt/v1`.
///
/// A third schema, distinct from both the discovery and the plan: this document
/// asserts that a credential *was moved*, which neither of the others can say.
pub const ADOPT_SCHEMA: &str = "asv.integrations.adopt/v1";

impl AdoptReceipt {
    /// Wraps a completed import with this build's schema.
    pub fn new(
        selector: AdoptSelector,
        credential: crate::CredentialId,
        label: String,
        audience: String,
        operations: BTreeSet<crate::Operation>,
        source_file: String,
        source_fingerprint: FileFingerprint,
    ) -> Self {
        Self {
            schema: ADOPT_SCHEMA.to_string(),
            selector,
            credential,
            label,
            audience,
            operations,
            source_file,
            source_fingerprint,
            // §10 in order. Written out rather than derived, because the whole
            // value of the field is that it is the list a reader can check the
            // product against.
            outstanding: vec![
                PendingStep::VerifyVault,
                PendingStep::VerifyNewIntegration,
                PendingStep::NegativeBypassTest,
                PendingStep::HumanApproval,
                PendingStep::ScrubAndRescan,
            ],
        }
    }
}

/// The selector this module would act on for a discovered one, if it could.
///
/// Kept as the one place the two vocabularies meet, so `adopt` matching and
/// `plan` reporting cannot drift apart.
pub fn selector_for(file: &Path, selector: &AuthSelector) -> AdoptSelector {
    AdoptSelector {
        file: file.to_string_lossy().into_owned(),
        // From the selector itself rather than from a plan entry, so there is
        // no way for the two to disagree about which registry this names.
        audience: selector.registry.audience.to_string(),
        field: selector.field.clone(),
    }
}
#[cfg(test)]
mod tests;
