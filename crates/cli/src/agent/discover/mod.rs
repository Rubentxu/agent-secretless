//! `asv agent discover --json` — the only thing an agent needs to know.
//!
//! # The exit criterion, restated
//!
//! DX2's exit: "an agent that knows only `asv agent discover --json` can
//! discover state, diagnose an absent broker, and reach a supported operation
//! without additional hardcoded commands."
//!
//! Three consequences, and they are what shape this file:
//!
//! **It must work with nothing else.** No `--help` first, no reading the
//! README, no assuming a socket path. One command, no arguments, no
//! environment beyond what the installer already set.
//!
//! **A missing broker is a document, not a crash.** AAT-002 wants a stable
//! code and a link to the fix, and refuses to have the agent told to start
//! `asv-brokerd` — a binary that is deliberately not on PATH and that the
//! user should never need to name. So the links published are `doctor` and
//! `setup`, and nothing else.
//!
//! **It must not claim what it cannot see.** The document reports
//! `derivation: UNKNOWN` and an empty capability list when the broker cannot
//! be asked, and says in a warning that an empty list is not evidence of
//! absence. R9: announcing a feature that is not there teaches an agent to
//! try it.

use serde_json::json;

use crate::agent::relations::AgentRel;
use crate::agent::schema::{Envelope, Status};
use crate::capabilities::CapabilityReport;
use crate::ipc::BrokerFacts;

/// AAT-002's stable codes. Screaming-snake because that is what the contract
/// says a consumer branches on, and because a code that changes when the
/// message is reworded is not a code.
pub mod code {
    /// The broker did not answer. The installation may be fine; the service is
    /// not running.
    pub const BROKER_UNAVAILABLE: &str = "BROKER_UNAVAILABLE";
    /// `asv setup` has not been run: there is no vault and no unit.
    pub const SETUP_REQUIRED: &str = "SETUP_REQUIRED";
    /// A broker answered, in a protocol this CLI does not speak.
    pub const PROTOCOL_MISMATCH: &str = "PROTOCOL_MISMATCH";
    /// The CLI's own schema is not one this build serves.
    pub const SCHEMA_UNSUPPORTED: &str = "SCHEMA_UNSUPPORTED";
}

/// What `discover` concluded, kept apart from the rendering so the human and
/// JSON forms cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub status: Status,
    pub code: Option<String>,
    pub broker: Option<BrokerFacts>,
    pub broker_reachable: bool,
    pub protocol_compatible: bool,
    pub installation_ready: bool,
}

/// Runs the discovery: one dial, one document.
pub fn discover(socket: &std::path::Path, installation_ready: bool) -> Discovery {
    let outcome = crate::observe_broker_at(socket);

    let (broker, reachable, compatible) = match outcome {
        crate::doctor::SocketOutcome::Answered { .. } => {
            match crate::ipc::fetch_broker_facts(socket) {
                Some(facts) => {
                    let ok = facts.protocol == asv_ipc_protocol::PROTOCOL_VERSION;
                    (Some(facts), true, ok)
                }
                // A broker that answers `Ping` but not `AgentInfo` is a
                // broker from before this increment. Reachable, and not
                // compatible with what discovery needs to say.
                None => (None, true, false),
            }
        }
        _ => (None, false, false),
    };

    let (status, code) = classify(reachable, compatible, installation_ready, broker.is_some());

    Discovery {
        status,
        code,
        broker,
        broker_reachable: reachable,
        protocol_compatible: compatible,
        installation_ready,
    }
}

/// The one place the four raw facts become a status and a code.
///
/// Split out so the table can be read — and tested — without going through a
/// socket. This is a decision table, and a decision table buried inside a
/// function that also does I/O is a decision table nobody checks.
fn classify(
    reachable: bool,
    compatible: bool,
    installation_ready: bool,
    facts_available: bool,
) -> (Status, Option<String>) {
    if !reachable {
        return (
            Status::Blocked,
            Some(
                if installation_ready {
                    code::BROKER_UNAVAILABLE
                } else {
                    code::SETUP_REQUIRED
                }
                .to_string(),
            ),
        );
    }
    if !compatible {
        return (Status::Error, Some(code::PROTOCOL_MISMATCH.to_string()));
    }
    if !facts_available {
        // Reachable and speaking our protocol, but it would not describe
        // itself. Treated as incompatible rather than as a thinner
        // description: a document that silently omits the broker's
        // capabilities is the failure R9 is about.
        return (Status::Error, Some(code::PROTOCOL_MISMATCH.to_string()));
    }
    (Status::Ready, None)
}

impl Discovery {
    /// The `asv.agent/v1` document.
    pub fn to_envelope(&self) -> Envelope {
        let capabilities = CapabilityReport::from_broker(
            self.broker.as_ref(),
            self.broker_reachable,
            self.protocol_compatible,
        );

        let origin = crate::installrecord::origin();

        let data = json!({
            "broker": {
                "reachable": self.broker_reachable,
                "compatible": self.protocol_compatible,
                "version": self.broker.as_ref().map(|b| b.product_version.clone()),
                "hardening": self.broker.as_ref().map(|b| json!({
                    "dumpable_disabled": b.dumpable_disabled,
                    "no_new_privs": b.no_new_privs,
                    "landlock_installed": b.landlock_installed,
                    "seccomp_installed": b.seccomp_installed,
                })),
                // **Beside the hardening, not inside it**, and only here
                // because it would otherwise have no consumer at all. The
                // falsification campaign caught exactly that: dropping the
                // field where the CLI reads the response left every test green,
                // because a value that travels from the broker and dies in the
                // CLI is decoration wearing the shape of a measurement — the
                // same defect as a mechanism with no caller, found three times
                // in this repository now.
                //
                // `agent discover` is the surface an autonomous caller reads
                // rather than a human, so the three states are named rather
                // than left to be inferred from a missing key.
                "identity": self.broker.as_ref().map(|b| match &b.identity {
                    None => json!({ "state": "not_measured" }),
                    Some(identity) => json!({
                        "state": if identity.dedicated { "dedicated" } else { "shared" },
                        "uid": identity.uid,
                        "declared_uid": identity.declared_uid,
                    }),
                }),
            },
            "installation": {
                "ready": self.installation_ready,
                "channel": crate::doctor::detect_channel(),
                "managed_by": crate::doctor::detect_managed_by(),
                // DX4, and deliberately with its provenance. `channel` is a
                // path heuristic; this is the record the installer wrote. An
                // agent told "mise" must be able to tell that from an agent
                // told "mise" because its path happens to contain a mise
                // directory, because the first one has a mise that owns the
                // update path and the second one does not.
                "installed_via": origin.installed_via.as_str(),
                "installed_via_source": origin.provenance.as_str(),
                "update_via": origin.installed_via.update_hint(),
            },
            "capabilities": capabilities.capabilities.iter().map(|c| json!({
                "name": c.name,
                "compiled": c.compiled,
                "reachable": c.reachable,
                "configured": c.configured,
                "authorization": c.authorization,
            })).collect::<Vec<_>>(),
            "capability_derivation": capabilities.derivation,
        });

        let mut envelope = Envelope::new(self.status, data);

        if let Some(code) = &self.code {
            envelope.error = Some(crate::agent::schema::AgentError {
                code: code.clone(),
                message: message_for(code, self.broker_reachable, self.broker.as_ref()),
            });
        }

        // Only the links that lead somewhere. A stopped broker gets `doctor`
        // and `setup`; a live one gets the operational set. The list is
        // filtered by the broker's own answer — publishing
        // `postgres/connect` from a build that has no Postgres is R9.
        for rel in AgentRel::publishable_for(self.broker_reachable) {
            // AAT-008: the operation links are withheld from a peer whose
            // protocol is unknown, because following one would mean guessing
            // what its answer means. The system links survive — `doctor` is
            // how the mismatch is diagnosed, and withholding it would be
            // failing closed in the direction that leaves the user with
            // nothing at all.
            if self.broker_reachable && !self.protocol_compatible && !is_system(rel) {
                continue;
            }
            if self.broker_reachable
                && self.protocol_compatible
                && !capability_supports(rel, &capabilities)
            {
                continue;
            }
            envelope = envelope.with_link(rel.descriptor());
        }

        if !self.broker_reachable {
            envelope.warnings.push(crate::agent::schema::Warning {
                code: "CAPABILITIES_UNKNOWN".into(),
                message: "the capability list is empty because the broker could not be \
                          asked, not because this build has none."
                    .into(),
            });
        }

        envelope
    }

    /// The human rendering. Short on purpose — the machine form is the
    /// contract, and this is for a person who ran it in a terminal.
    pub fn render_human(&self) -> String {
        let mut out = format!("asv agent discover — {}\n\n", self.status.as_str());

        match (&self.code, self.broker_reachable) {
            (Some(code), reachable) => {
                out.push_str(&format!("{code}\n"));
                out.push_str(&format!(
                    "  {}\n\n",
                    message_for(code, reachable, self.broker.as_ref())
                ));
            }
            (None, _) => {}
        }

        out.push_str(&format!(
            "broker:   {}\n",
            match &self.broker {
                Some(b) => format!("{} (protocol v{})", b.product_version, b.protocol),
                None if self.broker_reachable => "reachable, but did not describe itself".into(),
                None => "not reachable".into(),
            }
        ));
        out.push_str(&format!(
            "setup:    {}\n\n",
            if self.installation_ready {
                "done"
            } else {
                "not run"
            }
        ));

        out.push_str("next steps:\n");
        for rel in AgentRel::publishable_for(self.broker_reachable) {
            let link = rel.descriptor();
            out.push_str(&format!(
                "  asv {}   {}\n",
                link.invoke.argv.join(" "),
                link.rel
            ));
        }
        out
    }
}

/// Whether a relation describes the installation rather than an operation
/// performed by the broker.
fn is_system(rel: AgentRel) -> bool {
    matches!(
        rel.operation(),
        "system.status" | "system.doctor" | "system.setup" | "system.capabilities"
    )
}

/// Whether the broker actually has what this relation operates.
fn capability_supports(rel: AgentRel, capabilities: &CapabilityReport) -> bool {
    match rel.operation() {
        "credentials.metadata.list" => capabilities
            .capabilities
            .iter()
            .any(|c| c.name == "credentials.metadata"),
        "session.run" => capabilities
            .capabilities
            .iter()
            .any(|c| c.name == "session.run"),
        // System relations are about the installation, not a capability, and
        // the broker being reachable is what makes them useful.
        _ => true,
    }
}

/// Prose for a code. `message` is for humans; `code` is the contract.
///
/// Returns `String` rather than `&'static str` because one code has to name a
/// number. `PROTOCOL_MISMATCH` used to say *"Upgrade so both come from the same
/// release"* without saying which release the broker is on, so an agent handed
/// that sentence had to run `doctor` to learn the single fact that decides what
/// to do next. A failure that names the remedy without the number is a
/// half-answer, and `asv agent discover --json` is documented as the only thing
/// an agent needs.
fn message_for(code: &str, reachable: bool, broker: Option<&BrokerFacts>) -> String {
    match code {
        code::BROKER_UNAVAILABLE => {
            "the broker is not answering. The installation may be complete and the \
             service stopped; `asv doctor` says which."
                .into()
        }
        code::SETUP_REQUIRED => {
            "this installation has not been set up. `asv setup` creates the runtime \
             layout, the vault and the service."
                .into()
        }
        code::PROTOCOL_MISMATCH => match broker {
            Some(b) => format!(
                "a broker answered that this CLI does not speak to: it speaks protocol \
                 v{} and product {}, this build speaks protocol v{}. Upgrade so both \
                 come from the same release. Nothing was changed.",
                b.protocol,
                b.product_version,
                asv_ipc_protocol::PROTOCOL_VERSION
            ),
            // A broker that answered but did not describe itself leaves no version
            // to name. The remedy is unchanged; only the number is absent, and it
            // is absent because it was never told, not because it was withheld.
            None => "a broker answered that this CLI does not speak to, but did not \
                     say which protocol it speaks. Upgrade so both come from the \
                     same release. Nothing was changed."
                .into(),
        },
        code::SCHEMA_UNSUPPORTED => {
            "this build does not serve the asv.agent/v1 schema. Refusing to describe \
             itself against a contract it does not implement."
                .into()
        }
        _ if reachable => "the broker answered in a way this build cannot use.".into(),
        _ => "the broker could not be asked.".into(),
    }
}

#[cfg(test)]
mod tests;
