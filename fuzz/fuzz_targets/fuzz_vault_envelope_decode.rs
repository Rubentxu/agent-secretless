//! Fuzz target for the on-disk vault envelope decoder.
//!
//! The boundary under test is [`asv_vault::VaultFile::decode`] — the first
//! code that touches a stolen or corrupted vault file: magic, length-prefixed
//! header JSON, length-prefixed body ciphertext. Everything expensive
//! (Argon2id, authenticated decryption) happens after it, which is exactly
//! why this seam is fuzzed on its own: it consumes attacker-controlled
//! length fields and slice bounds on every unlock, and running the KDF per
//! input would spend the fuzzing budget on deliberately slow crypto instead
//! of on the parser.
//!
//! # The oracle
//!
//! 1. **Total function.** `decode` returns `Ok` or `Err` for every input
//!    whatsoever; a panic is the defect. The length arithmetic claims to be
//!    `checked_add` end to end with every slice taken after a bound that
//!    proves it — this target is that sentence's adversary.
//! 2. **Round trip.** Every accepted input must survive
//!    `decode`-then-`encode` unchanged: `decode(encode(v)) == Ok(v)`. An
//!    envelope the parser accepts but cannot re-emit would mean the file
//!    format and its own parser disagree about the format.
//!
//! The target does no filesystem and no crypto work; a seed vault's body is
//! opaque ciphertext to this boundary either way.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match asv_vault::VaultFile::decode(data) {
        Ok(vault_file) => {
            let re_encoded = vault_file
                .encode()
                .expect("an accepted envelope must re-encode: encode only fails on header \
                         serialization, and the header already round-tripped through serde");
            let decoded_again = asv_vault::VaultFile::decode(&re_encoded)
                .expect("an envelope this parser emitted must parse");
            assert_eq!(
                vault_file, decoded_again,
                "round trip changed the envelope: the parser and the writer \
                 disagree about the on-disk format"
            );
        }
        Err(_) => {}
    }
});
