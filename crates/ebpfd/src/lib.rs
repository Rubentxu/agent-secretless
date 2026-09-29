//! ASV privileged helper (`asv-ebpfd`).
//!
//! This crate is the **closed-surface vocabulary** of the privileged helper
//! the broker talks to over a Unix-domain socket. Its job is to make the
//! surface of what a privileged caller can ask for small and inspectable.
//!
//! # Verb set (M7-R5 + M8-R1)
//!
//! The broker connects to `asv-ebpfd` and sends one of eight verbs:
//!
//!  - `session.attach` — bind a session to a cgroup slice
//!  - `session.detach` — unbind a session from its cgroup slice
//!  - `cgroup.read`    — read a cgroup file the broker named
//!  - `seccomp.dump`   — dump the broker's current seccomp filter
//!  - `cgroup.attach`  — attach a loaded BPF program to a cgroup id
//!  - `cgroup.detach`  — detach a BPF program from a cgroup id
//!  - `program.load`   — load a shipped (signed) BPF program by name
//!  - `program.unload` — unload a previously loaded BPF program
//!
//! Anything else returns `Err(VerbError::Unknown)` and the connection is
//! closed by the helper. There is no verb that accepts arbitrary BPF
//! bytecode, generic cgroup writes, or any privilege-escalation primitive.
//!
//! # Prototype skeleton (M8-S5)
//!
//! `cgroup_attach_skeleton` is the documented ABI for the M9 implementation
//! that performs a real `bpf_link_create(BPF_LINK_TYPE_CGROUP)` syscall.
//! In M8 the body is a no-op that returns `Ok(AttachHandle(0))`. M9 fills
//! it in.

// NOTE: no `test-support` feature is declared; the allowance below is
// test-only via `cfg(test)`.
#![cfg_attr(test, allow(dead_code, unused_imports))]

pub mod verbs;

pub use verbs::{
    cgroup_attach_skeleton, format_audit_line, parse_cgroup_id, parse_verb, program_lookup,
    AttachHandle, AuditCounter, HelperError, ProgramId, Verb, VerbError,
};
