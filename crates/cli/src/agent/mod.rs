//! The agent-facing surface: the `asv.agent/v1` envelope, the relation
//! vocabulary, and the discovery document built from them.
//!
//! # Why this is a vocabulary and not a JSON blob per command
//!
//! The first version of this CLI printed a different shape of JSON for every
//! command, and an agent that had learned one of them had learned something
//! true only of that command. `06-CLI-CONTRACT.md` §2 fixes a single envelope
//! instead, so a consumer parses the same six keys whatever it asked for, and
//! `data` is the only part that varies.
//!
//! The failure this prevents is not a parse error. It is an agent that reads
//! `{"ok": true}` from one command and `{"reachable": true}` from another and
//! concludes the two agree about the installation when neither one said
//! anything about the other.

pub mod relations;
pub mod schema;

pub use relations::{AgentInvoke, AgentLink, AgentRel, Safety};
pub use schema::{AgentError, Envelope, Status, Warning, SCHEMA};
