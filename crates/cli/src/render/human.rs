//! The human rendering of a doctor report.
//!
//! # Why the format is fixed-width and machine-parseable
//!
//! UAT-DX-005 requires the two renderings to represent the same facts, and
//! the only way to *check* that rather than assert it is to read the facts
//! back out of the human text. So the layout is not a matter of taste: every
//! check is one line of
//!
//! ```text
//! <state> <id> <detail>
//! ```
//!
//! with the state in a fixed-width column and the id in the next, and an
//! optional indented `fix:` line under it. `render::tests` parses those lines
//! back and compares the set against the JSON. Reformatting this output to
//! something prettier breaks that test, which is the correct outcome: the
//! prettiness was not free.
//!
//! The remedy is on its own line because the detail and the remedy are
//! different kinds of sentence, and an operator skimming twelve lines needs to
//! be able to read the states without the advice interleaved.

use crate::doctor::{Check, CheckState, DoctorReport};

/// Width of the state column, including the trailing space.
const STATE_WIDTH: usize = 8;
/// Width of the id column.
const ID_WIDTH: usize = 24;

pub fn doctor(report: &DoctorReport) -> String {
    let mut out = String::new();

    out.push_str(&format!("asv doctor — {}\n\n", report.status().as_str()));

    for check in &report.checks {
        out.push_str(&check_line(check));
        if let Some(remedy) = &check.remedy {
            out.push_str(&format!("{}fix: {remedy}\n", " ".repeat(STATE_WIDTH)));
        }
    }

    out.push('\n');
    out.push_str(&summary(report));
    out.push('\n');
    out
}

fn check_line(check: &Check) -> String {
    // The two-space indent is load-bearing: `render::tests` recognises a
    // check line by it, and a remedy line by the deeper indent plus `fix:`.
    // Removing it to gain a little width would silently stop the equivalence
    // check from reading any checks at all — and would make it pass, because
    // "the human rendering showed 0 of 12" is only a failure if the comparison
    // notices. It does notice, and that is what the `assert!(parsed.len() >=
    // 10)` in that test is for.
    let mut line = format!(
        "  {:<STATE_WIDTH$}{:<ID_WIDTH$}{}",
        check.state.as_str(),
        check.id,
        check.detail
    );
    while line.ends_with(' ') {
        line.pop();
    }
    line.push('\n');
    line
}

/// One line naming what is wrong, so the answer is above the fold rather than
/// twelve lines down.
fn summary(report: &DoctorReport) -> String {
    let blocking = report.blocking();
    let warnings = report
        .checks
        .iter()
        .filter(|c| c.state == CheckState::Warn)
        .count();
    let unknown = report
        .checks
        .iter()
        .filter(|c| c.state == CheckState::Unknown)
        .count();

    let mut parts = Vec::new();
    if !blocking.is_empty() {
        parts.push(format!("blocking: {}", blocking.join(", ")));
    }
    if warnings > 0 {
        parts.push(format!("{warnings} warning(s)"));
    }
    if unknown > 0 {
        parts.push(format!("{unknown} not observable"));
    }
    if parts.is_empty() {
        return "nothing to fix".to_string();
    }
    parts.join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_column_is_wide_enough_for_its_longest_word() {
        // "unknown" is seven characters. If this ever fails, the parser in
        // `render::tests` starts reading states out of the id column and every
        // equivalence check becomes quietly wrong.
        assert!(STATE_WIDTH > CheckState::Unknown.as_str().len());
    }
}
