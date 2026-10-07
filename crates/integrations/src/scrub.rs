//! The irreversible half of a migration, and the contract it happens through.
//!
//! # Why this module exists at all
//!
//! `MigrationReceipt::source_file` has described the original configuration as
//! "now scrubbed" since the receipt was written, and until this module existed
//! nothing in the workspace performed one. Every step of §10 up to
//! [`Approved`](crate::migration::Approved) was a real transition over real
//! facts; step 5 was a type that said a scrub had been *permitted* and a field
//! that said what the file now looked like, filled in by whoever called
//! [`rescan`](crate::migration::Scrubbed::rescan). A receipt claiming a scrub no
//! code carries out is the same defect as a plan claiming `STRONG_SECRETLESS`
//! with nothing behind it.
//!
//! # What this trait does and does not guarantee
//!
//! It guarantees that a scrub is **performable and measurable**: some
//! implementation removes credential fields from a real file and reports what it
//! removed by name.
//!
//! It does **not** guarantee that any scrub was performed.
//! [`Approved::scrub`](crate::migration::Approved::scrub) remains a pure state
//! transition that touches no disk, by decision: the caller composes the scrub
//! and the receipt, and ordering those two steps is the caller's
//! responsibility. That is a real hole and it is real here, not behind a
//! `TODO` — a caller that skips [`ScrubSource::scrub`] can still reach a
//! `Completed` and a well-formed receipt. The type system does not close it, and
//! this paragraph is the only thing standing between a future reader and the
//! belief that it does.
//!
//! Closing it structurally would mean moving the write inside the transition —
//! `Approved::scrub_into(path)` executing the removal and deriving the rescan by
//! reading the file back. That was measured against this design and declined: it
//! couples the lifecycle to one filesystem primitive and would have to be
//! re-thought for every family in B2.2. The trade is accepted deliberately,
//! not overlooked, and the caller that closes §10 owns it.

use std::path::Path;

/// What a scrub removed, and what it left.
///
/// The field **names** are returned; the values never were in this module's
/// hands and must not become so. A report that names `_authToken` is
/// actionable; one that quoted it would put the registry token back into a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubReport {
    /// The auth fields that were removed.
    pub removed: Vec<String>,
    /// How many lines the file had before the scrub.
    pub lines_before: usize,
    /// Lines left in it, so a reader can see that nothing else moved.
    pub lines_after: usize,
}

/// The ways a scrub can refuse.
///
/// Separate from [`ProjectionError`](crate::project::ProjectionError) because a
/// refusal here is not a refusal to write: writing was allowed and already
/// happened, and folding the two together would let a caller report "the
/// projection was refused" for a file it has already overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    /// The file is a symlink, so this would land on a file nobody was shown.
    SymlinkedConfiguration {
        /// Which path was refused.
        path: String,
    },
    /// The file holds no credential, so scrubbing it would prove nothing.
    NothingToScrub {
        /// Which path was inspected.
        path: String,
    },
    /// The read or the write failed.
    Io(String),
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrubError::SymlinkedConfiguration { path } => write!(
                f,
                "{path:?} is a symlink. This is the irreversible half of a migration, and \
                 the file it lands on has to be the file the operator was shown, so it is \
                 refused rather than followed. Resolve it first."
            ),
            ScrubError::NothingToScrub { path } => write!(
                f,
                "{path:?} carries no credential, so there is nothing to scrub. A scrub that \
                 removed nothing has proved nothing, and treating it as success would let a \
                 migration close against a file that never held one."
            ),
            ScrubError::Io(detail) => {
                write!(f, "the scrub could not be carried out: {detail}")
            }
        }
    }
}

impl std::error::Error for ScrubError {}

/// A family of configuration whose credentials can be removed from a file.
///
/// ## What an implementation owes
///
/// - **Only credential fields go.** Everything else in the file survives, byte
///   for byte. An implementation that rewrites the whole file has to be able to
///   say it did, and `lines_after` is where that shows.
/// - **A refusal is a refusal, not a partial success.** Removing some fields and
///   leaving the token behind is the worst outcome: it looks migrated and is not.
///   Read the whole file first, decide, and only then write.
/// - **No value crosses back out.** See [`ScrubReport`].
///
/// ## What the trait deliberately does not carry
///
/// The file to clean is passed in rather than held by the implementation. The
/// caller knows which file the migration adopted, from the receipt; an
/// implementation that owned its path would have to be given that same path at
/// construction, which buys nothing and adds a second source of truth for it.
pub trait ScrubSource {
    /// Removes every credential field this family writes, from the file at
    /// `path`.
    fn scrub(&self, path: &Path) -> Result<ScrubReport, ScrubError>;
}

#[cfg(test)]
mod tests {
    use super::{ScrubError, ScrubReport};

    /// A refusal the operator cannot act on is a refusal they will route around.
    ///
    /// These two carry a path, say what was found, and say what to do next. The
    /// test is that the advice survives — an edit that trims the message to the
    /// error name alone still renders it, so this is the thing that notices.
    #[test]
    fn a_refusal_names_the_file_and_the_next_move() {
        let symlink = ScrubError::SymlinkedConfiguration {
            path: "/home/u/.npmrc".to_string(),
        }
        .to_string();
        for (phrase, why) in [
            ("/home/u/.npmrc", "not the refusal, which is the file"),
            ("Resolve it first", "not a statement of what went wrong"),
        ] {
            assert!(symlink.contains(phrase), "{why}: {symlink}");
        }

        let empty = ScrubError::NothingToScrub {
            path: "/home/u/settings.xml".to_string(),
        }
        .to_string();
        for (phrase, why) in [
            (
                "nothing to scrub",
                "the operator has to learn that there was nothing to remove",
            ),
            ("proved nothing", "why an empty result is not success"),
        ] {
            assert!(empty.contains(phrase), "{why}: {empty}");
        }
    }

    /// The report is what a receipt is built from. If it ever grows a field, the
    /// change should have to be a deliberate one, so the shape is pinned.
    #[test]
    fn the_report_is_three_facts_and_no_value() {
        let report = ScrubReport {
            removed: vec!["_authToken".to_string()],
            lines_before: 3,
            lines_after: 2,
        };
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.lines_before - report.lines_after, 1);
        let rendered = format!("{report:?}");
        assert!(
            !rendered.contains("npm_"),
            "a report is a receipt input; a value here would be a receipt output: {rendered}"
        );
    }
}
