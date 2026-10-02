//! Two renderers over one result.
//!
//! `09-IMPLEMENTATION-GUIDE.md` §2 asks for `command parsing → application
//! result → renderer`, and the reason is UAT-DX-005: for the same state, the
//! human output and the JSON "may render differently but must represent the
//! same fundamental facts". Two handlers that each print their own lines can
//! only satisfy that by coincidence and by review.
//!
//! So both renderers read the same [`crate::doctor::DoctorReport`], and the
//! equivalence is checked by parsing the human output back — see
//! `render::tests::the_two_renderers_report_the_same_facts`.

pub mod human;
pub mod json;

#[cfg(test)]
mod tests;
