//! Capability derivation — what this installation can actually do, right now.
//!
//! # Four questions that are not one question
//!
//! `09-IMPLEMENTATION-GUIDE.md` §4 separates them, and R2 in
//! `11-RISKS-OPEN-QUESTIONS.md` says why: an `available = true` gets read as
//! "permitted", and a capability system that conflates *exists* with *allowed*
//! is a system an agent will over-trust.
//!
//! So each capability answers four separate questions, and the derived
//! document keeps them separate:
//!
//! | question | who answers it |
//! |---|---|
//! | **compiled** — is there code for it in this build | the broker, over IPC |
//! | **reachable** — can this process be asked at all | the CLI, by dialling |
//! | **configured** — is the thing it needs present | the CLI, from the layout |
//! | **authorization** — will policy allow *this* call | the broker, per request |
//!
//! The last one is not answered here and is not answerable here. Cedar
//! evaluates the actual request at the actual moment; a capability list that
//! claimed to know the answer would be a second authorization system, and R2
//! names that as the risk.
//!
//! # Why the list comes from the broker
//!
//! R9: "capabilities derived from the runtime; not from the roadmap or from
//! types that exist but have no complete path." The CLI has no way to know
//! what the broker process can do — it is a different binary, possibly a
//! different version, and a stale static list is exactly the "announces a
//! feature that does not exist" failure. When the broker cannot be reached,
//! the list is **empty**, not "probably these".

use serde_json::json;

use crate::agent::relations::AgentRel;
use crate::agent::schema::{Envelope, Status};

/// One capability and the four answers to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// The dotted name, as the broker spells it.
    pub name: String,
    /// There is a complete path for this in the running build.
    pub compiled: bool,
    /// The broker answering is possible at all.
    pub reachable: bool,
    /// What it needs is present. `None` where the question does not apply.
    pub configured: Option<bool>,
    /// Never a boolean. See the module docs.
    pub authorization: &'static str,
}

/// The full picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    /// `COMPILED` when the broker was asked and answered; `UNKNOWN` when it
    /// was not, which is a third state and not a synonym for "empty".
    pub derivation: &'static str,
    pub broker_reachable: bool,
    pub protocol_compatible: bool,
    pub capabilities: Vec<Capability>,
    /// The `rel` that operates this capability, when there is one.
    pub relations: Vec<String>,
}

impl CapabilityReport {
    /// Builds from what the broker reported, or from its absence.
    pub fn from_broker(
        broker: Option<&crate::ipc::BrokerFacts>,
        broker_reachable: bool,
        protocol_compatible: bool,
    ) -> Self {
        let Some(facts) = broker else {
            return Self {
                derivation: "UNKNOWN",
                broker_reachable,
                protocol_compatible,
                capabilities: Vec::new(),
                relations: relations_for(&[]),
            };
        };

        let capabilities = facts
            .capabilities
            .iter()
            .map(|name| Capability {
                name: name.clone(),
                compiled: true,
                reachable: true,
                configured: configured_for(name),
                authorization: "evaluated_on_request",
            })
            .collect();

        Self {
            derivation: "COMPILED",
            broker_reachable,
            protocol_compatible,
            capabilities,
            relations: relations_for(&facts.capabilities),
        }
    }

    pub fn status(&self) -> Status {
        if !self.broker_reachable {
            return Status::Blocked;
        }
        if !self.protocol_compatible {
            return Status::Error;
        }
        Status::Ready
    }

    pub fn to_envelope(&self) -> Envelope {
        let data = json!({
            "derivation": self.derivation,
            "broker_reachable": self.broker_reachable,
            "protocol_compatible": self.protocol_compatible,
            "capabilities": self.capabilities.iter().map(|c| json!({
                "name": c.name,
                "compiled": c.compiled,
                "reachable": c.reachable,
                "configured": c.configured,
                // A string, never a bool. An agent reading `false` here would
                // conclude it is denied, when the truth is that nobody has
                // asked yet. R2 is the whole reason.
                "authorization": c.authorization,
            })).collect::<Vec<_>>(),
            "relations": self.relations,
        });

        let mut envelope = Envelope::new(self.status(), data);
        for rel in AgentRel::publishable_for(self.broker_reachable) {
            envelope = envelope.with_link(rel.descriptor());
        }
        if !self.broker_reachable {
            envelope.warnings.push(crate::agent::schema::Warning {
                code: "CAPABILITIES_UNKNOWN".into(),
                message: "the capability list is empty because the broker could not be \
                          asked, not because this build has none. An empty list here is \
                          not evidence of absence."
                    .into(),
            });
        }
        envelope
    }

    /// The human rendering.
    ///
    /// Empty list and unknown list are printed differently on purpose. They
    /// look identical as a list and mean opposite things, and the difference is
    /// the difference between "this product does less than you think" and "you
    /// could not find out".
    pub fn render_human(&self) -> String {
        let mut out = format!("asv capabilities — {}\n\n", self.status().as_str());

        if !self.broker_reachable {
            out.push_str(
                "the broker could not be asked, so this list is unknown.\n\
                 An empty list here is not evidence that the product has no capabilities.\n\n",
            );
            out.push_str("run: asv doctor\n");
            return out;
        }

        if self.capabilities.is_empty() {
            out.push_str("the broker reports no capabilities.\n");
            return out;
        }

        out.push_str(&format!(
            "{:<28} {:<9} {:<11} {}\n",
            "CAPABILITY", "COMPILED", "CONFIGURED", "AUTHORIZATION"
        ));
        for c in &self.capabilities {
            out.push_str(&format!(
                "{:<28} {:<9} {:<11} {}\n",
                c.name,
                yes_no(c.compiled),
                match c.configured {
                    Some(v) => yes_no(v),
                    None => "n/a",
                },
                c.authorization
            ));
        }
        out
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Whether the thing this capability needs is present in this installation.
///
/// Only asked where the CLI is genuinely the authority — the layout on disk.
/// Everything else is left to the broker, because the broker is the one that
/// knows whether a connector works.
fn configured_for(name: &str) -> Option<bool> {
    match name {
        // A session needs the broker; the broker is answering, so yes.
        "session.run" | "session.ssh_sign" => Some(true),
        // Credential operations need a vault this user can open.
        n if n.starts_with("credentials.") => {
            let layout = crate::layout::for_current_user();
            Some(layout.vault.exists())
        }
        // Postgres needs a connector configuration this CLI cannot see.
        n if n.starts_with("postgres.") => None,
        // GitHub goes through a session and a leased credential.
        n if n.starts_with("github.") => Some(true),
        // Same shape, one step further out: the AWS *deployment* — which
        // credential, which audience, which role — is broker configuration this
        // CLI cannot read, so the honest answer is that the client needs
        // nothing to try. Whether a deployment is actually configured is the
        // broker's fact and is answered when the operation runs.
        //
        // Reporting `false` here would be a claim nobody measured, and `n/a`
        // would be the truthful-but-useless answer: a reader seeing `n/a` cannot
        // tell "I cannot see it" from "there is nothing to see", and that
        // distinction is the whole reason this field is a tri-state.
        n if n.starts_with("aws.") => Some(true),
        // Same shape one step further out. A registry pull needs a
        // *declaration* — which host, which credential — that lives in the
        // daemon's configuration, and this CLI cannot read it. So the honest
        // answer is that the client needs nothing to try: the link is
        // published, and whether a deployment has declared anything is the
        // broker's fact, answered when the pull runs. Reporting `false` would
        // be a claim nobody measured, and it would be wrong for a deployment
        // that *has* declared one.
        n if n.starts_with("registry.") => Some(true),
        _ => None,
    }
}

/// The `rel` values that can operate a given set of capabilities.
///
/// Driven by the capability list rather than published whole, so a broker
/// without `postgres.connect` does not hand out a Postgres link. That is R9
/// again: discovery announcing a feature that is not there.
fn relations_for(capabilities: &[String]) -> Vec<String> {
    AgentRel::operational()
        .iter()
        .filter(|rel| {
            let op = rel.operation();
            match op {
                // R0.3b. `system.upgrade` is always published regardless of
                // capability set: it is the recovery relation an agent
                // follows when protocol mismatch is the reason the broker
                // cannot be asked, and that is the very state in which
                // filtering by capability would hide the only link that
                // points at a runnable command.
                //
                // R2.D.3. `k8s.read` is treated the same way: the broker
                // operation is wired but the deployment registry has not
                // landed, so the link's job today is to advertise the gap,
                // not to advertise a working capability. A broker that does
                // not serve `k8s.read` cannot hide the gap by omission —
                // hiding it would be the same failure the GitHub three
                // closed at R2.A by publishing rather than withholding.
                //
                // R2.E.3. Same reasoning as R2.D.3: the broker validates
                // the CSR, refuses with `Denied` until R2.E.3.2 lands, and
                // publishing the link is the answer to "is mTLS there yet?"
                // rather than withholding it.
                "system.status"
                | "system.doctor"
                | "system.setup"
                | "system.capabilities"
                | "system.upgrade" => true,
                "k8s.read" | "mtls.sign" => true,
                "credentials.metadata.list" => {
                    capabilities.iter().any(|c| c == "credentials.metadata")
                }
                "session.run" => capabilities.iter().any(|c| c == "session.run"),
                // Driven by the broker's own advertisement rather than by a
                // hard-coded list, so a registry relation cannot be published
                // by a broker that does not serve it — which is R9 again:
                // discovery announcing a feature that is not there.
                //
                // The GitHub three are deliberately *not* written this way. They
                // are, and reading one list for those and another for these
                // would be the drift this line is meant to remove; they keep
                // their explicit arms until this arm is the only arm.
                op if op.starts_with("registry.") => capabilities.iter().any(|c| c == op),
                _ => false,
            }
        })
        .map(|r| r.uri().to_string())
        .collect()
}

#[cfg(test)]
mod tests;
