//! The machine rendering.
//!
//! One line, no pretty-printing. The document is meant to be piped, and a
//! consumer should not have to handle a line-wrapped envelope.
//!
//! There is no formatting logic here on purpose. The JSON is
//! `serde_json::to_string` of the envelope, and every fact in it was put there
//! by [`crate::doctor::DoctorReport::to_envelope`]. A renderer that decided
//! what to include would be a second place where the two renderings could
/// disagree, which is the defect UAT-DX-005 exists to prevent.
use crate::agent::schema::{AgentError, Envelope, Status};
use crate::ipc::ApplicationResult;

/// One line of `asv.agent/v1`.
pub fn envelope(value: &Envelope) -> String {
    value.to_json()
}

/// Pretty-printed, for a human who ran `--json` and wants to read it.
///
/// Only reachable through an explicit flag, and never through the pipeline
/// path, because the pipeline path is the one an agent parses.
pub fn envelope_pretty(value: &Envelope) -> String {
    serde_json::to_string_pretty(value).expect("the asv.agent/v1 envelope always serialises")
}

/// The envelope for an existing IPC command.
///
/// `06-CLI-CONTRACT.md` §5 publishes `asv://rels/status` and
/// `asv://rels/credentials/list` with `--json` in their argv, so those two
/// commands owe a machine rendering. This is where the mapping lives, for the
/// same reason it lives for `doctor`: a handler that built its own JSON would
/// be a second place where the contract could be got wrong.
pub fn for_result(result: &ApplicationResult) -> Envelope {
    let status = match result {
        ApplicationResult::Ok { .. } => Status::Ready,
        // A refusal from the broker is a blocked document, not a crash: the
        // envelope has to survive it so a consumer can read the code and
        // decide what to do.
        ApplicationResult::Refused { .. } => Status::Blocked,
    };

    let mut envelope = Envelope::new(status, serde_json::json!({ "result": result.data() }));

    if let ApplicationResult::Refused { code, message } = result {
        envelope.error = Some(AgentError {
            code: code.clone(),
            message: message.clone(),
        });
    }
    for rel in crate::agent::relations::AgentRel::operational() {
        envelope = envelope.with_link(rel.descriptor());
    }
    envelope
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::schema::Status;

    #[test]
    fn the_compact_form_is_exactly_one_line() {
        let mut value = Envelope::new(Status::Ready, serde_json::json!({"a": "b\nc"}));
        value = value.with_warning("X", "line one\nline two");
        let rendered = envelope_pretty(&value);
        // Pretty-printed is multi-line by design; the point of this assertion
        // is the inverse, checked below. Here we only pin that the pretty
        // renderer does not escape into a different document.
        assert!(rendered.contains("asv.agent/v1"));

        let compact = envelope(&value);
        assert_eq!(
            compact.lines().count(),
            1,
            "a value containing a newline escaped into a second line: {compact}"
        );
    }
}
