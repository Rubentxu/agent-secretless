//! UAT-DX-005: *"Para el mismo estado, el modo humano y `--json` pueden
//! renderizar distinto pero deben representar los mismos hechos
//! fundamentales."*
//!
//! # How "the same facts" is checked
//!
//! Not by reading both renderings and judging. The human output is **parsed
//! back** and compared, check by check, against the JSON. That is the only
//! version of this assertion that can fail.
//!
//! The alternative — "the two look about the same" — is a review comment, and
//! a review comment does not notice the twelfth check. So the format in
//! [`human::doctor`] is fixed-width and parseable, and if somebody reformats
//! it, this test goes red rather than the equivalence quietly becoming false.
//! That is the intended cost: prettiness is not free here.

use super::*;

use crate::agent::schema::Status as EnvelopeStatus;
use crate::doctor::{
    CheckState, DirState, DoctorReport, FileState, Hardening, Observation, SocketOutcome, TriState,
};
use crate::layout::BrokerLookup;

/// One fact recovered from the human rendering.
#[derive(Debug, PartialEq, Eq)]
struct ParsedCheck {
    state: String,
    id: String,
    detail: String,
    remedy: Option<String>,
}

/// Reads the human output back.
///
/// Written as a hand parser rather than a regex dependency: the format is six
/// columns wide and a `regex` crate in the CLI would be a new dependency for
/// a test.
fn parse_human(text: &str) -> Vec<ParsedCheck> {
    let mut out = Vec::new();
    let mut pending: Option<ParsedCheck> = None;

    for line in text.lines() {
        // A check line: two spaces, then one of the four states.
        let trimmed = line.strip_prefix("  ").unwrap_or("");
        let (state, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((s, r)) if CheckState::ALL.iter().any(|k| k.as_str() == s) => (s, r),
            _ => {
                if let Some(check) = pending.take() {
                    out.push(check);
                }
                continue;
            }
        };

        if let Some(check) = pending.take() {
            out.push(check);
        }

        let rest = rest.trim_start();
        let (id, detail) = match rest.split_once(char::is_whitespace) {
            Some((i, d)) => (i.to_string(), d.trim_start().to_string()),
            None => (rest.to_string(), String::new()),
        };
        pending = Some(ParsedCheck {
            state: state.to_string(),
            id,
            detail,
            remedy: None,
        });
    }
    if let Some(check) = pending.take() {
        out.push(check);
    }
    out
}

/// The remedy lines are indented under the state column and start with `fix:`.
fn parse_remedies(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("fix: ") {
            if let Some(id) = current.take() {
                out.push((id, rest.to_string()));
            }
        } else if let Some((state, rest)) = trimmed.split_once(char::is_whitespace) {
            if CheckState::ALL.iter().any(|k| k.as_str() == state) {
                current = rest.split_whitespace().next().map(str::to_string);
            }
        }
    }
    out
}

fn sample(stop_broker: bool) -> Observation {
    Observation {
        cli_version: "0.26.0".into(),
        socket: if stop_broker {
            SocketOutcome::Unreachable {
                reason: "no answer at /run/user/1000/asv/broker.sock".into(),
            }
        } else {
            SocketOutcome::Answered {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            }
        },
        broker_lookup: BrokerLookup::Found("/home/u/.local/libexec/asv/asv-brokerd".into()),
        config_dir: DirState::Present { mode: 0o700 },
        data_dir: DirState::Present { mode: 0o755 },
        vault: FileState::Present { mode: 0o600 },
        vault_unlockable: TriState::Yes,
        service_unit: FileState::Absent,
        unit_target: Some("/home/u/.local/libexec/asv/asv-brokerd".into()),
        hardening: Hardening {
            landlock: TriState::No,
            seccomp: TriState::Unknown,
            broker_dumpable: TriState::Unknown,
        },
        channel: "stable",
        managed_by: "direct",
    }
}

/// Every check appears in both renderings, in the same order, with the same
/// state.
///
/// Run against both a healthy and a broken installation, because the two
/// exercise different branches of the human renderer: the summary line only
/// appears when something is wrong, and the remedy lines only appear for
/// failures.
#[test]
fn the_two_renderers_report_the_same_checks_with_the_same_states() {
    for (label, obs) in [("healthy", sample(false)), ("broken", sample(true))] {
        let report = DoctorReport::judge(obs);
        let human = human::doctor(&report);
        let parsed = parse_human(&human);

        let value: serde_json::Value =
            serde_json::from_str(&json::envelope(&report.to_envelope())).expect("round-trips");
        let json_checks = value["data"]["checks"].as_array().expect("checks array");

        assert_eq!(
            parsed.len(),
            json_checks.len(),
            "{label}: the human rendering showed {} of {} checks",
            parsed.len(),
            json_checks.len()
        );
        assert!(
            parsed.len() >= 10,
            "{label}: only {} checks reached either renderer; the sample is \
             too small to mean anything",
            parsed.len()
        );

        for (from_human, from_json) in parsed.iter().zip(json_checks) {
            assert_eq!(
                from_human.id,
                from_json["id"].as_str().unwrap(),
                "{label}: check order differs between the renderings"
            );
            assert_eq!(
                from_human.state,
                from_json["state"].as_str().unwrap(),
                "{label}: `{}` is {} in the human rendering and {} in the JSON",
                from_human.id,
                from_human.state,
                from_json["state"]
            );
        }
    }
}

/// The same, for the advice. A remedy that reaches the JSON and not the
/// terminal is a remedy the human never sees, which is the rendering
/// difference UAT-DX-005 exists to catch.
#[test]
fn the_two_renderers_carry_the_same_remedies() {
    let report = DoctorReport::judge(sample(true));
    let human = human::doctor(&report);
    let value: serde_json::Value =
        serde_json::from_str(&json::envelope(&report.to_envelope())).unwrap();

    let human_remedies = parse_remedies(&human);
    let json_remedies: Vec<(String, String)> = value["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| !c["remedy"].is_null())
        .map(|c| {
            (
                c["id"].as_str().unwrap().to_string(),
                c["remedy"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    assert_eq!(
        human_remedies, json_remedies,
        "the two renderings disagree about what to do about it"
    );
}

/// The coarse status is in both, spelled the same way.
#[test]
fn the_status_agrees_between_renderings() {
    let report = DoctorReport::judge(sample(true));
    let expected = report.status().as_str();

    let human = human::doctor(&report);
    assert!(
        human.starts_with(&format!("asv doctor — {expected}")),
        "the human rendering does not open with the status: {human}"
    );

    let value: serde_json::Value =
        serde_json::from_str(&json::envelope(&report.to_envelope())).unwrap();
    assert_eq!(value["status"], expected);
}

/// The human rendering's summary names the blocking checks, so an operator
/// does not have to read all twelve lines to find out what is wrong.
#[test]
fn the_summary_names_what_is_blocking() {
    let report = DoctorReport::judge(sample(true));
    let human = human::doctor(&report);

    for id in report.blocking() {
        assert!(
            human.contains("blocking:") && human.contains(id),
            "the summary does not name the blocking check `{id}`:\n{human}"
        );
    }
}

/// A `ready` installation still has a summary, and it still has something to
/// say: the broker's core-dump setting is not observable from here, so the
/// line reports that rather than claiming there is nothing to see.
///
/// An earlier version of this test asserted `nothing to fix`, which was false
/// — the summary was right and the test was wrong. It is the shape of the
/// mistake this whole module is about: a tidy expectation over a document
/// that had more to say.
#[test]
fn a_ready_installation_says_what_it_could_not_check() {
    let mut obs = sample(false);
    obs.data_dir = DirState::Present { mode: 0o700 };
    obs.service_unit = FileState::Present { mode: 0o644 };
    obs.hardening = Hardening {
        landlock: TriState::Yes,
        seccomp: TriState::Yes,
        broker_dumpable: TriState::Unknown,
    };

    let report = DoctorReport::judge(obs);
    assert_eq!(report.status(), EnvelopeStatus::Ready);

    let human = human::doctor(&report);
    assert!(
        human.starts_with("asv doctor — ready"),
        "the status line is wrong: {human}"
    );
    assert!(
        !human.contains("blocking:"),
        "a ready installation listed something as blocking:\n{human}"
    );
    assert!(
        human.contains("1 not observable"),
        "the summary did not report the one fact it could not check:\n{human}"
    );
    assert!(
        human.contains("broker.dumpable"),
        "the unknown check is not in the body at all:\n{human}"
    );
}

/// The parser used above has to actually reject lines that are not checks, or
/// it would agree with anything. A remedy line must not be read as a check.
#[test]
fn the_parser_rejects_lines_that_are_not_checks() {
    let text = "asv doctor — blocked\n\n  fail  broker.socket  no answer\n         fix: start it\n  ok    cli.version  0.26.0\n\nblocking: broker.socket\n";
    let parsed = parse_human(text);

    assert_eq!(parsed.len(), 2, "parsed {parsed:?}");
    assert_eq!(parsed[0].id, "broker.socket");
    assert_eq!(parsed[1].id, "cli.version");
    // The remedy line did not become a third check with the state "fix:".
    assert!(parsed.iter().all(|c| c.state != "fix:"));
}
