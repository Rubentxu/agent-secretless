//! Operator-console policy for M5.
//!
//! This crate holds the decisions a human control plane has to make, and
//! nothing else. It does not open a socket, read a vault, render a pixel, or
//! know what a WebView is.
//!
//! The split is the whole design, so it is worth stating as a rule rather
//! than a preference: **the console shell asks this crate, and the shell
//! decides nothing.** If the shell grows an `if exportability == …` of its
//! own, there are now two policies and one of them is lying — and the tests
//! here would still be green, because they test this crate.
//!
//! That placement is also what makes the exit criteria checkable. UAT-019 and
//! UAT-020 are mostly about logic, not pixels, and logic in a crate with no
//! GUI dependency runs in the pipeline. A policy that can only be verified by
//! launching a browser is not a gate; it is a manual check that decays.
//!
//! What lives here:
//! - [`capability`]: which console commands exist, and that none of them
//!   returns credential material. UAT-019.
//! - [`export`]: what a human may do with a credential, per `Exportability`.
//!   UAT-020.
//! - [`clipboard`]: re-authentication and auto-clear for the one policy that
//!   allows a copy at all. UAT-020.
//! - [`untrusted`]: strings that came from outside become data, not markup.
//!   UAT-019.

pub mod capability;
pub mod clipboard;
pub mod export;
pub mod untrusted;

pub use capability::{Capability, CapabilityError, CapabilityRegistry, Registry};
pub use clipboard::{ClipboardDecision, ClipboardPolicy, ReauthOutcome};
pub use export::{ConsoleAction, ExportDecision, ExportPolicy};
pub use untrusted::{SafeText, Untrusted};
