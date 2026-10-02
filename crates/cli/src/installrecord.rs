//! Who put this installation here, recorded by whoever installed it.
//!
//! DX4 gives the product two independent installation channels, and
//! `04-ADR-DISTRIBUTION.md` is explicit about the consequence: "`asv update`
//! no debe competir con el package manager. Si la instalación es gestionada por
//! mise/apt/rpm/homebrew, informa del mecanismo correcto." Answering that
//! question wrong is not a cosmetic defect — it is a tool overwriting files
//! another tool owns.
//!
//! # Why a file and not the environment
//!
//! The previous answer was `ASV_INSTALLER`. An environment variable is set by
//! whoever is asking, disappears between invocations, and can be set to any
//! value at all. It is a claim made in the same breath as the question, which
//! is precisely the property that makes it useless: `asv update` reading
//! `installed_via` from the environment would be reading what its own caller
//! told it, and the caller is the thing that might be wrong.
//!
//! So the record is a file next to the private broker, written by the
//! installer at the moment it places files. The CLI reads it; the CLI never
//! writes it. That asymmetry is the point — the thing that installed owns the
//! answer, and the thing being updated only observes it.
//!
//! # Why an absent record is not an error, and a broken one is not a fallback
//!
//! Absence means the installation was not made by an installer: a `cargo
//! install`, a checkout, a test tree. That is a real and common answer, and it
//! is reported as [`InstalledVia::Source`]. But a record that exists and cannot
//! be parsed is *not* the same thing. It means an installer ran, wrote
//! something, and the something is unreadable — so the owner of the
//! installation is unknown, and an update path that guesses here is the exact
//! failure the ADR warns about. So it is reported as
//! [`Provenance::Unreadable`] and surfaces as a warning, never as `source`.
//!
//! # The record is not trusted for anything but provenance
//!
//! It answers exactly one question. It does not decide where the broker is —
//! that is [`crate::layout`]'s job, and it uses the same directory for a
//! different reason. A record claiming a version the binary does not report is
//! a discrepancy worth a warning, not a reason to believe the record.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file name, in the private runtime directory.
pub const RECORD_FILE: &str = "install.json";
/// The record's own schema, so a future format is a different file.
pub const RECORD_SCHEMA: &str = "asv.install/v1";

/// Who placed the files in this installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledVia {
    /// `scripts/install.sh` ran and placed the bundle.
    Installer,
    /// The mise plugin ran and placed the same bundle.
    Mise,
    /// A system package manager owns these files.
    PackageManager,
    /// Nobody placed them: a checkout, a `cargo install`, a test tree.
    Source,
}

impl InstalledVia {
    /// The spelling used on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            InstalledVia::Installer => "installer",
            InstalledVia::Mise => "mise",
            InstalledVia::PackageManager => "package-manager",
            InstalledVia::Source => "source",
        }
    }

    /// Whether this channel owns the files, and must be the one to update them.
    ///
    /// `Source` is the one value that does not own anything. An update tool
    /// that treats "installed from source" as "mine to overwrite" has invented
    /// an owner.
    pub fn owns_updates(self) -> bool {
        !matches!(self, InstalledVia::Source)
    }

    /// The mechanism a user should be told to use.
    pub fn update_hint(self) -> Option<&'static str> {
        match self {
            InstalledVia::Installer => Some("re-run the installer"),
            InstalledVia::Mise => Some("mise upgrade agent-secretless"),
            InstalledVia::PackageManager => Some("the package manager that installed it"),
            InstalledVia::Source => None,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "installer" => Some(InstalledVia::Installer),
            "mise" => Some(InstalledVia::Mise),
            "package-manager" => Some(InstalledVia::PackageManager),
            "source" => Some(InstalledVia::Source),
            _ => None,
        }
    }
}

/// Where the answer came from, so nobody reads a guess as a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// A record was found and parsed.
    Record,
    /// No record exists, and the installation is therefore a source tree.
    NoRecord,
    /// A record exists and could not be read. The owner is unknown.
    Unreadable,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Record => "record",
            Provenance::NoRecord => "no-record",
            Provenance::Unreadable => "unreadable",
        }
    }
}

/// The document the installer writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    pub schema: String,
    pub installed_via: InstalledVia,
    /// The product version the archive claimed.
    pub version: String,
    /// The `<root>` the bundle was installed into.
    pub install_root: PathBuf,
    /// The sha256 of the archive the files came from, when verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
    /// When it was written, as an RFC 3339 timestamp.
    pub installed_at: String,
}

/// What was found, with the reason preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Found(Box<InstallRecord>),
    Absent,
    Unreadable { reason: String },
}

impl RecordOutcome {
    pub fn provenance(&self) -> Provenance {
        match self {
            RecordOutcome::Found(_) => Provenance::Record,
            RecordOutcome::Absent => Provenance::NoRecord,
            RecordOutcome::Unreadable { .. } => Provenance::Unreadable,
        }
    }
}

/// The private runtime directory this executable belongs to, if it has one.
///
/// Same derivation as `layout::sibling_libexec` and deliberately the same
/// rule: `<root>/bin/asv` means `<root>/libexec/asv`. The record sits beside
/// the broker because that is the one directory an installation is guaranteed
/// to have created — the bin directory may be shared with other tools, and a
/// record there would be describing something that is not only ours.
pub fn record_path_for(exe: &Path) -> Option<PathBuf> {
    let bin_dir = exe.parent()?;
    if bin_dir.file_name() != Some(std::ffi::OsStr::new("bin")) {
        return None;
    }
    let root = bin_dir.parent()?;
    Some(root.join(crate::layout::LIBEXEC_LEAF).join(RECORD_FILE))
}

/// Where the record for *this* process is, from the running executable.
pub fn record_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    record_path_for(&exe)
}

/// Read the record at `path`.
///
/// A missing file is `Absent`, not a failure: most installations in the
/// development matrix are checkouts. Anything else that prevents a parse is
/// `Unreadable` with the reason, because "the installer wrote something I
/// cannot read" and "no installer ran" lead to opposite update behaviour.
pub fn read_at(path: &Path) -> RecordOutcome {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return RecordOutcome::Absent,
        Err(err) => {
            return RecordOutcome::Unreadable {
                reason: format!("cannot read {}: {err}", path.display()),
            }
        }
    };
    match serde_json::from_str::<InstallRecord>(&text) {
        Ok(record) if record.schema == RECORD_SCHEMA => RecordOutcome::Found(Box::new(record)),
        Ok(record) => RecordOutcome::Unreadable {
            reason: format!(
                "{} declares schema {:?}, this build understands {RECORD_SCHEMA}",
                path.display(),
                record.schema
            ),
        },
        Err(err) => RecordOutcome::Unreadable {
            reason: format!("{} is not a valid install record: {err}", path.display()),
        },
    }
}

/// Read this installation's record, whatever the layout allows.
pub fn observe() -> RecordOutcome {
    match record_path() {
        Some(path) => read_at(&path),
        None => RecordOutcome::Absent,
    }
}

/// The answer `doctor` reports, with the provenance attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationOrigin {
    pub installed_via: InstalledVia,
    pub provenance: Provenance,
    pub record: Option<Box<InstallRecord>>,
    /// Set when a record exists but could not be read.
    pub reason: Option<String>,
}

impl InstallationOrigin {
    /// No record, and therefore a source tree. A real answer, not a default:
    /// most installations in the development matrix are checkouts.
    pub fn source_without_record() -> Self {
        Self {
            installed_via: InstalledVia::Source,
            provenance: Provenance::NoRecord,
            record: None,
            reason: None,
        }
    }

    /// A record that named a channel.
    pub fn from_record(record: InstallRecord) -> Self {
        Self {
            installed_via: record.installed_via,
            provenance: Provenance::Record,
            record: Some(Box::new(record)),
            reason: None,
        }
    }

    /// A record that exists and cannot be read. Ownership is unknown, and the
    /// provenance is what says so.
    pub fn unreadable(reason: impl Into<String>) -> Self {
        Self {
            installed_via: InstalledVia::Source,
            provenance: Provenance::Unreadable,
            record: None,
            reason: Some(reason.into()),
        }
    }
}

/// Observe, and never guess past what was found.
pub fn origin() -> InstallationOrigin {
    match observe() {
        RecordOutcome::Found(record) => InstallationOrigin {
            installed_via: record.installed_via,
            provenance: Provenance::Record,
            record: Some(record),
            reason: None,
        },
        RecordOutcome::Absent => InstallationOrigin {
            installed_via: InstalledVia::Source,
            provenance: Provenance::NoRecord,
            record: None,
            reason: None,
        },
        RecordOutcome::Unreadable { reason } => InstallationOrigin {
            // Unknown ownership is reported as `source` *with its provenance
            // attached*, and `provenance: unreadable` is what tells a reader
            // this is not a finding. The alternative — refusing to report a
            // channel at all — hides the question the operator came to ask.
            installed_via: InstalledVia::Source,
            provenance: Provenance::Unreadable,
            record: None,
            reason: Some(reason),
        },
    }
}

/// Parse a channel name, for the installer writing the record and for tests.
pub fn parse_installed_via(text: &str) -> Option<InstalledVia> {
    InstalledVia::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::TempTree;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn good_record(via: &str) -> String {
        serde_json::json!({
            "schema": RECORD_SCHEMA,
            "installed_via": via,
            "version": "0.25.0",
            "install_root": "/home/u/.local",
            "installed_at": "2026-10-02T00:00:00Z",
        })
        .to_string()
    }

    #[test]
    fn the_record_sits_beside_the_broker_and_not_in_bin() {
        // `<root>/bin/asv` → `<root>/libexec/asv/install.json`.
        let got = record_path_for(Path::new("/opt/asv/bin/asv")).unwrap();
        assert_eq!(got, Path::new("/opt/asv/libexec/asv/install.json"));
    }

    #[test]
    fn an_executable_outside_a_bin_directory_has_no_record_location() {
        // A `cargo install` tree and a test binary are not installations, and
        // inventing a root for them is how a checkout points at a colleague's
        // home directory.
        assert!(record_path_for(Path::new("/var/tmp/target/debug/asv")).is_none());
        assert!(record_path_for(Path::new("asv")).is_none());
    }

    #[test]
    fn a_record_names_the_channel_that_wrote_it() {
        let tree = TempTree::new("install-record-channel");
        let path = tree.path.join("install.json");
        for (text, expected) in [
            ("installer", InstalledVia::Installer),
            ("mise", InstalledVia::Mise),
            ("package-manager", InstalledVia::PackageManager),
        ] {
            write(&path, &good_record(text));
            let outcome = read_at(&path);
            let RecordOutcome::Found(record) = outcome else {
                panic!("{text} should parse");
            };
            assert_eq!(record.installed_via, expected);
            assert_eq!(read_at(&path).provenance(), Provenance::Record);
        }
    }

    #[test]
    fn an_absent_record_is_not_a_failure() {
        let tree = TempTree::new("install-record-absent");
        let outcome = read_at(&tree.path.join("nothing.json"));
        assert_eq!(outcome, RecordOutcome::Absent);
        assert_eq!(outcome.provenance(), Provenance::NoRecord);
    }

    #[test]
    fn a_corrupt_record_is_unreadable_and_never_reads_as_source() {
        // The failure this exists to prevent: an installer ran, wrote a
        // record, and something truncated it. Reporting `source` here would
        // tell an update path that nobody owns these files.
        let tree = TempTree::new("install-record-corrupt");
        let path = tree.path.join("install.json");
        write(&path, "{\"schema\": \"asv.install/v1\", \"installed_via\"");
        let outcome = read_at(&path);
        assert!(matches!(outcome, RecordOutcome::Unreadable { .. }));
        assert_eq!(outcome.provenance(), Provenance::Unreadable);
    }

    #[test]
    fn a_record_from_a_newer_format_is_unreadable_not_ignored() {
        // Guessing at a future format would be worse than refusing: the whole
        // value of the record is that it is written by the thing that knows.
        let tree = TempTree::new("install-record-future");
        let path = tree.path.join("install.json");
        let body = good_record("installer").replace(RECORD_SCHEMA, "asv.install/v2");
        write(&path, &body);
        let outcome = read_at(&path);
        let RecordOutcome::Unreadable { reason } = outcome else {
            panic!("a v2 record must not be silently accepted: {outcome:?}");
        };
        assert!(reason.contains("asv.install/v2"), "{reason}");
    }

    #[test]
    fn an_unknown_channel_name_is_unreadable() {
        // Falling back to `source` for an unrecognised name would make a
        // future channel look like a checkout, which is how mise would end up
        // being overwritten by something that does not own it.
        let tree = TempTree::new("install-record-unknown-channel");
        let path = tree.path.join("install.json");
        write(&path, &good_record("nix-store"));
        assert!(matches!(read_at(&path), RecordOutcome::Unreadable { .. }));
    }

    #[test]
    fn only_source_declines_to_own_an_update() {
        assert!(InstalledVia::Installer.owns_updates());
        assert!(InstalledVia::Mise.owns_updates());
        assert!(InstalledVia::PackageManager.owns_updates());
        assert!(!InstalledVia::Source.owns_updates());
        assert_eq!(InstalledVia::Source.update_hint(), None);
        assert_eq!(
            InstalledVia::Mise.update_hint(),
            Some("mise upgrade agent-secretless")
        );
    }

    #[test]
    fn the_wire_spelling_is_what_the_installer_writes() {
        // Pinned because the installer in `scripts/` writes these strings by
        // hand: a rename here without a matching change there produces a
        // record that parses as unreadable on every user's machine.
        for (via, text) in [
            (InstalledVia::Installer, "installer"),
            (InstalledVia::Mise, "mise"),
            (InstalledVia::PackageManager, "package-manager"),
            (InstalledVia::Source, "source"),
        ] {
            assert_eq!(via.as_str(), text);
            assert_eq!(parse_installed_via(text), Some(via));
        }
        assert_eq!(parse_installed_via("mise-upgrade"), None);
    }
}
