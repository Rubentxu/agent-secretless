#![no_main]

//! Fuzz target for the IPC request decoder boundary.
//!
//! `asv_ipc_protocol::decode_request` is the first code that touches bytes
//! coming from an untrusted agent peer. It must be total: any input either
//! decodes to a `Request` or returns `Err(ProtocolError)`; a panic here is
//! a remote-memory-safety defect in the broker's front door.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The decoder enforces MAX_MESSAGE_BYTES internally; we do not pre-trim.
    let _ = asv_ipc_protocol::decode_request(data);
});
