//! What a command produced, before anybody decides how to print it.
//!
//! `09-IMPLEMENTATION-GUIDE.md` §2 asks for
//!
//! ```text
//! command parsing → application result → renderer
//! ```
//!
//! and the reason is UAT-DX-005: the human output and the JSON have to be
//! able to describe the same event. A `Response` that is printed by one
//! `match` and serialised by a second is two descriptions of one thing, and
//! the second one is written later and checked less.
//!
//! So `main` builds an [`ApplicationResult`], both renderers read it, and
//! neither one decides what happened. The `data` carried here is a `Value`
//! because the broker's own response types are many and the envelope's `data`
//! is a bag by design; what is *not* delegated is the status and the error
//! code, and those are the parts a consumer branches on.

use asv_ipc_protocol::Response;
use serde_json::json;

/// The outcome of a broker-backed command.
#[derive(Debug, Clone, PartialEq)]
pub enum ApplicationResult {
    Ok {
        /// One line for the human renderer.
        summary: String,
        /// The machine-readable body.
        data: serde_json::Value,
    },
    Refused {
        /// Stable, screaming-snake. The programmable part.
        code: String,
        /// Prose. Never load-bearing.
        message: String,
    },
}

impl ApplicationResult {
    pub fn data(&self) -> serde_json::Value {
        match self {
            ApplicationResult::Ok { data, .. } => data.clone(),
            ApplicationResult::Refused { code, message } => {
                json!({ "refused": { "code": code, "message": message } })
            }
        }
    }

    /// The human rendering. One line, or a block for the tabular commands.
    pub fn render_human(&self) -> String {
        match self {
            ApplicationResult::Ok { summary, .. } => summary.clone(),
            ApplicationResult::Refused { code, message } => format!("{code}: {message}"),
        }
    }

    pub fn is_refusal(&self) -> bool {
        matches!(self, ApplicationResult::Refused { .. })
    }
}

/// Projects a broker response into an application result.
///
/// The mapping is one function on purpose. Split across the handlers it would
/// be one decision per command, and the two renderings would drift exactly
/// where nobody is looking.
pub fn from_response(response: &Response) -> ApplicationResult {
    match response {
        Response::Pong { protocol } => ApplicationResult::Ok {
            summary: format!("broker reachable, protocol v{protocol}"),
            data: json!({
                "reachable": true,
                "protocol": protocol,
                "protocol_compatible": *protocol == asv_ipc_protocol::PROTOCOL_VERSION,
            }),
        },
        Response::CredentialMetadata { entries } => {
            // Metadata only. `CredentialMetadata` carries no secret field, so
            // this projection cannot leak one even by accident — which is the
            // reason it is written out entry by entry rather than serialised
            // wholesale.
            let entries: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "kind": format!("{:?}", e.kind).to_lowercase(),
                        "label": e.label,
                    })
                })
                .collect();
            ApplicationResult::Ok {
                summary: if entries.is_empty() {
                    "no credentials stored".to_string()
                } else {
                    format!("{} credential(s) stored", entries.len())
                },
                data: json!({ "entries": entries }),
            }
        }
        Response::Error { code, message } => ApplicationResult::Refused {
            // `code` arrives as a `Debug` rendering of an enum from the
            // protocol crate, e.g. `NotAuthorised`. Screaming-snake is what a
            // consumer can match on, and this is the one place that converts.
            code: screaming_snake(&format!("{code:?}")),
            message: message.clone(),
        },
        other => ApplicationResult::Ok {
            summary: format!("{} responded", variant_name(other)),
            data: json!({ "response": variant_name(other) }),
        },
    }
}

fn variant_name(response: &Response) -> &'static str {
    crate::response_kind(response)
}

/// `NotAuthorised` → `NOT_AUTHORISED`.
///
/// Hand-written rather than a dependency: the transformation is a loop and a
/// `match` on one ASCII boundary, and a crate for it would be a crate to keep
/// current for the privilege of not writing eight lines.
fn screaming_snake(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    for (i, ch) in text.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch.to_ascii_uppercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denial_code_becomes_something_a_consumer_can_match() {
        assert_eq!(screaming_snake("NotAuthorised"), "NOT_AUTHORISED");
        assert_eq!(screaming_snake("VaultLocked"), "VAULT_LOCKED");
        // Already screaming: no leading underscore.
        assert_eq!(
            screaming_snake("SETUP_REQUIRED"),
            "S_E_T_U_P__R_E_Q_U_I_R_E_D"
        );
    }

    /// The conversion is idempotent only in the sense that it never emits a
    /// lowercase letter. That is the property a consumer depends on; whether
    /// the result is a *good* code is the protocol's business, and a test that
    /// asserted a specific code would fail the day the broker adds one.
    #[test]
    fn the_conversion_never_lowercases_anything() {
        for input in ["NotAuthorised", "already_lower", "MixedCase"] {
            assert!(
                screaming_snake(input)
                    .chars()
                    .all(|c| !c.is_ascii_lowercase()),
                "{input} produced a lowercase code"
            );
        }
    }
}
