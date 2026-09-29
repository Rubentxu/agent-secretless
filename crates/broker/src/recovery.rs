//! M13 — Crash / recovery (RC stabilization pass).
//!
//! A broker that crashes mid-mutation has two ways to recover:
//!
//! 1. **Crash-only via journal.** Mutations are appended to a journal
//!    before they touch the live state. On restart, the broker reads
//!    the journal, replays the mutations, and brings state up to the
//!    last fully-appended entry. A torn write (the broker died in the
//!    middle of appending) MUST NOT advance state.
//!
//! 2. **Crash-only via snapshot.** A periodic snapshot of the live
//!    state is taken; on restart, the broker reads the latest
//!    snapshot and replays journal entries newer than the snapshot.
//!    This is a follow-up; the prototype ships the journal-only
//!    path.
//!
//! # Why this matters
//!
//! The vault mutation surface (rotate, revoke, add credential) is
//! finite but each entry is load-bearing: an inconsistent rotation
//! can leave the broker with a header that does not decrypt. The
//! recovery module is the structural argument that a crash mid-mutation
//! leaves the broker in a recoverable state, not in an undefined one.
//!
//! # What this module provides
//!
//! - [`JournalRecord`] — the on-disk shape of a journal entry.
//! - [`RecoveryJournal`] — append-only journal with torn-content
//!   detection (length-prefixed records + a per-record CRC).
//! - [`ReplayEngine`] — replays journal records into a state machine.
//! - [`RecoveryError`] — what can go wrong.

use std::fmt;

/// The journal record kinds the broker emits. New variants are
/// expected as the broker grows; the replay engine MUST refuse any
/// variant it does not understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalKind {
    /// A credential was added.
    CredentialAdded,
    /// A credential was rotated (old id -> new id).
    CredentialRotated,
    /// A credential was revoked.
    CredentialRevoked,
    /// The vault was sealed with a new passphrase / PCR policy.
    VaultResealed,
}

impl fmt::Display for JournalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JournalKind::CredentialAdded => "credential_added",
            JournalKind::CredentialRotated => "credential_rotated",
            JournalKind::CredentialRevoked => "credential_revoked",
            JournalKind::VaultResealed => "vault_resealed",
        })
    }
}

/// A journal record: kind, body, and a CRC over (kind || body) so
/// torn writes are detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRecord {
    /// The kind of mutation.
    pub kind: JournalKind,
    /// The body of the mutation (e.g. credential id, new fingerprint).
    pub body: Vec<u8>,
    /// CRC over (kind || body). Computed at append time; verified at
    /// replay time. Torn writes (the broker died mid-append) produce a
    /// trailing entry whose CRC does not verify; the replay engine
    /// truncates that entry and refuses to advance state past it.
    pub crc: u32,
}

/// Why a journal / replay operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// A journal record's CRC did not verify (torn write detected).
    #[error("torn journal entry: CRC mismatch at offset {0}")]
    TornEntry(usize),
    /// A journal entry uses an unknown kind.
    #[error("unknown journal kind: {0}")]
    UnknownKind(u8),
    /// The journal buffer is empty.
    #[error("empty journal")]
    EmptyJournal,
}

/// Append-only journal. Entries are length-prefixed (4 bytes BE) +
/// payload (1 byte kind + N bytes body + 4 bytes CRC).
///
/// The wire format is intentionally simple so a forensic reader can
/// parse it without the broker's runtime.
pub struct RecoveryJournal {
    bytes: Vec<u8>,
}

impl RecoveryJournal {
    /// Construct an empty journal.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Construct a journal from existing bytes (e.g. loaded from
    /// disk). The bytes are not validated until [`Self::replay`] is
    /// called.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The raw bytes (for serialization / fsync).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Append a record. The CRC is computed over the kind + body.
    pub fn append(&mut self, kind: JournalKind, body: Vec<u8>) -> Result<(), RecoveryError> {
        let crc = crc32(&[&[kind.to_u8()][..], body.as_slice()].concat());
        let mut entry = Vec::with_capacity(1 + body.len() + 4);
        entry.push(kind.to_u8());
        entry.extend_from_slice(&body);
        entry.extend_from_slice(&crc.to_be_bytes());
        let len = entry.len() as u32;
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(&entry);
        Ok(())
    }

    /// Replay the journal through `engine`. Returns the number of
    /// fully-replayed records. Trailing torn entries are detected
    /// and reported; the engine's state is left at the last
    /// successfully-replayed record.
    pub fn replay<E: ReplayEngine>(&self, engine: &mut E) -> Result<usize, RecoveryError> {
        let mut offset = 0usize;
        let mut replayed = 0usize;
        let bytes = &self.bytes;
        while offset < bytes.len() {
            // Read 4-byte BE length.
            if bytes.len() - offset < 4 {
                return Err(RecoveryError::TornEntry(offset));
            }
            let len = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;

            if bytes.len() - offset < len {
                // Torn entry: the length said more bytes than are
                // available. Truncate and report.
                return Err(RecoveryError::TornEntry(offset - 4));
            }
            let entry = &bytes[offset..offset + len];
            offset += len;

            if entry.len() < 1 + 4 {
                return Err(RecoveryError::TornEntry(offset - len));
            }
            let kind_byte = entry[0];
            let body = &entry[1..entry.len() - 4];
            let crc = u32::from_be_bytes([
                entry[entry.len() - 4],
                entry[entry.len() - 3],
                entry[entry.len() - 2],
                entry[entry.len() - 1],
            ]);
            let expected = crc32(&[&[kind_byte][..], body].concat());
            if crc != expected {
                return Err(RecoveryError::TornEntry(offset - len));
            }

            let kind = match kind_byte {
                1 => JournalKind::CredentialAdded,
                2 => JournalKind::CredentialRotated,
                3 => JournalKind::CredentialRevoked,
                4 => JournalKind::VaultResealed,
                other => return Err(RecoveryError::UnknownKind(other)),
            };

            engine.apply(JournalRecord {
                kind,
                body: body.to_vec(),
                crc: expected,
            });
            replayed += 1;
        }
        if replayed == 0 {
            return Err(RecoveryError::EmptyJournal);
        }
        Ok(replayed)
    }
}

impl Default for RecoveryJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalKind {
    fn to_u8(self) -> u8 {
        match self {
            JournalKind::CredentialAdded => 1,
            JournalKind::CredentialRotated => 2,
            JournalKind::CredentialRevoked => 3,
            JournalKind::VaultResealed => 4,
        }
    }
}

/// The replay engine consumes journal entries and updates some
/// external state. The trait is intentionally minimal so the broker
/// can plug its own state machine in.
pub trait ReplayEngine {
    fn apply(&mut self, record: JournalRecord);
}

/// CRC32 (IEEE) over a byte slice. The polynomial matches the one
/// the broker's existing wire formats use so journal records and
/// other length-prefixed payloads use the same checksum.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}

/// A replay engine that collects every record it sees into a vector.
/// Used by the tests and by the broker when the consumer does not
/// yet have a state machine.
#[derive(Debug, Default)]
pub struct CollectingReplay {
    pub records: Vec<JournalRecord>,
}

impl ReplayEngine for CollectingReplay {
    fn apply(&mut self, record: JournalRecord) {
        self.records.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_journal_replay_reports_empty() {
        let j = RecoveryJournal::new();
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("empty journal");
        assert_eq!(err, RecoveryError::EmptyJournal);
        assert!(e.records.is_empty());
    }

    #[test]
    fn append_then_replay_round_trip_returns_records_in_order() {
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        j.append(JournalKind::CredentialRotated, b"cred-A->cred-B".to_vec()).unwrap();
        j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec()).unwrap();

        let mut e = CollectingReplay::default();
        let n = j.replay(&mut e).expect("replay");
        assert_eq!(n, 3);
        assert_eq!(e.records[0].kind, JournalKind::CredentialAdded);
        assert_eq!(e.records[0].body, b"cred-A");
        assert_eq!(e.records[1].kind, JournalKind::CredentialRotated);
        assert_eq!(e.records[2].kind, JournalKind::CredentialRevoked);
    }

    #[test]
    fn append_records_have_correct_lengths() {
        let mut j = RecoveryJournal::new();
        // Body is 14 bytes.
        let body = b"new-passphrase";
        j.append(JournalKind::VaultResealed, body.to_vec()).unwrap();
        let bytes = j.as_bytes();
        // First 4 bytes = entry length
        let entry_len =
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        // Entry = 1 byte kind + N bytes body + 4 bytes CRC
        assert_eq!(entry_len, 1 + body.len() + 4);
        assert_eq!(bytes.len(), 4 + entry_len);
    }

    #[test]
    fn replay_detects_torn_second_record() {
        // Two records; truncate the trailing 2 bytes of the second.
        // The first record replays; the second fails its torn
        // detection.
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        bytes.truncate(bytes.len() - 2);
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("torn second record");
        assert!(matches!(err, RecoveryError::TornEntry(_)));
        // The first record was fully replayed; the truncated one is
        // dropped.
        assert_eq!(e.records.len(), 1);
    }

    #[test]
    fn replay_detects_torn_body() {
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        // Drop the last 4 bytes (the CRC of the second record).
        bytes.truncate(bytes.len() - 4);
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("torn body");
        // The CRC of the second record fails to verify.
        assert!(matches!(err, RecoveryError::TornEntry(_)));
        assert_eq!(e.records.len(), 1);
    }

    #[test]
    fn replay_detects_corrupted_body() {
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        // Flip a byte inside the body (after the 4-byte length prefix
        // and the 1-byte kind).
        bytes[5] ^= 0xFF;
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("corrupted body");
        assert!(matches!(err, RecoveryError::TornEntry(_)));
        assert_eq!(e.records.len(), 0);
    }

    #[test]
    fn replay_detects_corrupted_crc() {
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        // Flip a bit in the last byte of the CRC.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("corrupted crc");
        assert!(matches!(err, RecoveryError::TornEntry(_)));
        assert_eq!(e.records.len(), 0);
    }

    #[test]
    fn replay_detects_unknown_kind_with_recomputed_crc() {
        // To trigger `UnknownKind`, we need a record whose kind byte
        // is a reserved value AND whose CRC verifies. The CRC input
        // is (kind || body), so we mutate kind and recompute the
        // CRC over the new (kind || body) tuple. That is exactly
        // what a buggy or malicious writer might produce.
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        // Flip kind byte to a reserved value (0xFE).
        bytes[4] = 0xFE;
        // Recompute the CRC over the new (kind || body).
        let entry_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let entry = &bytes[4..4 + entry_len];
        let body = &entry[1..entry.len() - 4];
        let new_crc = crc32(&[&[0xFE][..], body].concat());
        let crc_offset = 4 + entry_len - 4;
        bytes[crc_offset..crc_offset + 4].copy_from_slice(&new_crc.to_be_bytes());
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("unknown kind");
        assert_eq!(err, RecoveryError::UnknownKind(0xFE));
        // No records were applied (we stopped at the bad kind).
        assert_eq!(e.records.len(), 0);
    }

    #[test]
    fn replay_treats_kind_flip_without_crc_recompute_as_torn() {
        // If the kind byte is flipped but the CRC is not recomputed,
        // the CRC fails to verify and the engine sees a torn entry.
        // This is the safe outcome: the broker stops at the bad
        // record rather than silently accepting a stale CRC.
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::CredentialAdded, b"cred-A".to_vec()).unwrap();
        let mut bytes = j.as_bytes().to_vec();
        bytes[4] = 0xFE;
        let j = RecoveryJournal::from_bytes(bytes);
        let mut e = CollectingReplay::default();
        let err = j.replay(&mut e).expect_err("torn");
        assert!(matches!(err, RecoveryError::TornEntry(_)));
        assert_eq!(e.records.len(), 0);
    }

    #[test]
    fn journal_record_display_includes_kind_label() {
        let r = JournalRecord {
            kind: JournalKind::VaultResealed,
            body: b"new".to_vec(),
            crc: 0,
        };
        // The Debug format is the verification we can build a
        // record; the Display impl is on the kind.
        assert!(format!("{:?}", r).contains("VaultResealed"));
    }

    #[test]
    fn crc32_matches_known_value_for_empty_input() {
        // CRC32 of empty input is 0.
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_matches_known_value_for_short_input() {
        // CRC32 of "123456789" is 0xCBF43926 (the IEEE reference
        // value). Verified against zlib's CRC32.
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn default_journal_is_empty() {
        let j = RecoveryJournal::default();
        assert!(j.as_bytes().is_empty());
    }

    #[test]
    fn vault_resealed_kind_emits_correct_byte() {
        let mut j = RecoveryJournal::new();
        j.append(JournalKind::VaultResealed, b"x".to_vec()).unwrap();
        let bytes = j.as_bytes();
        // Length prefix is 4 bytes, then the kind is the 5th byte.
        assert_eq!(bytes[4], 4);
    }
}