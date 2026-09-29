//! ASV privileged helper (`asv-ebpfd`).
//!
//! This crate is a **skeleton** (M7 roadmap). Its job is to make the
//! surface of what a privileged caller can ask for small and
//! inspectable. The full eBPF redirect path lives in M8 (R&D) and
//! M9 (ship); this crate only owns the verb set and the
//! parse-and-reject-the-rest dispatcher.
//!
//! # Verb set (M7-R5)
//!
//! The broker connects to `asv-ebpfd` over a Unix-domain socket and
//! sends one of four verbs as the first line of each request:
//!
//!  - `session.attach` — bind a session to a cgroup slice
//!  - `session.detach` — unbind a session from its cgroup slice
//!  - `cgroup.read`    — read a cgroup file the broker named
//!  - `seccomp.dump`   — dump the broker's current seccomp filter
//!
//! Anything else returns `Err(VerbError::Unknown)` and the connection
//! is closed by the helper. There is no verb that accepts arbitrary
//! BPF bytecode, generic cgroup writes, or any privilege-escalation
//! primitive.

#![cfg_attr(
    any(test, feature = "test-support"),
    allow(dead_code, unused_imports)
)]

pub mod verbs;

pub use verbs::{parse_verb, Verb, VerbError};
