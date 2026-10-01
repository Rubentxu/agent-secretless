//! UAT-035 — journal replay never advances state past a torn write.
//! Crash / recovery — journal replay never advances state past a torn write.
//!
//! Not a normative UAT: `14-UAT-ADVERSARIAL.md` defines UAT-001..UAT-034 and
//! UAT-035 is not among them. This suite was written ahead of the spec and took
//! a number nothing reserves. It is the M13 crash/recovery regression, and it
//! asserts the journal property directly:
//!
//!   A torn write MUST NOT advance state past the last fully-appended record.
use asv_broker::recovery::{
    CollectingReplay, JournalKind, RecoveryError, RecoveryJournal, ReplayEngine,
};

#[test]
fn uat_035_replay_round_trip_through_disk_simulation() {
    // Append three records, "flush" to a byte buffer (simulated disk),
    // reload, replay.
    let mut j = RecoveryJournal::new();
    j.append(JournalKind::CredentialAdded, b"cred-A".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRotated, b"cred-A->cred-B".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec())
        .unwrap();

    let bytes = j.as_bytes().to_vec();
    let j = RecoveryJournal::from_bytes(bytes);
    let mut engine = CollectingReplay::default();
    let n = j.replay(&mut engine).expect("replay");
    assert_eq!(n, 3);
    assert_eq!(engine.records.len(), 3);
    assert_eq!(engine.records[0].kind, JournalKind::CredentialAdded);
    assert_eq!(engine.records[1].kind, JournalKind::CredentialRotated);
    assert_eq!(engine.records[2].kind, JournalKind::CredentialRevoked);
}

#[test]
fn uat_035_torn_write_at_end_truncates_last_record() {
    // Simulate a crash mid-append: the broker wrote the length
    // prefix and part of the body but died before completing.
    let mut j = RecoveryJournal::new();
    j.append(JournalKind::CredentialAdded, b"cred-A".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec())
        .unwrap();
    let mut raw = j.as_bytes().to_vec();
    // Truncate the last 3 bytes — the broker died 3 bytes into the
    // CRC of the second record.
    raw.truncate(raw.len() - 3);
    let j = RecoveryJournal::from_bytes(raw);
    let mut engine = CollectingReplay::default();
    let err = j.replay(&mut engine).expect_err("torn");
    assert!(matches!(err, RecoveryError::TornEntry(_)));
    // The first record applied; the second is dropped.
    assert_eq!(engine.records.len(), 1);
}

#[test]
fn uat_035_corrupted_record_in_middle_stops_replay() {
    // A single byte flip in the middle of a record must stop the
    // replay at the corrupted record; earlier records apply.
    let mut j = RecoveryJournal::new();
    j.append(JournalKind::CredentialAdded, b"cred-A".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRotated, b"cred-A->cred-B".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRevoked, b"cred-B".to_vec())
        .unwrap();
    let mut raw = j.as_bytes().to_vec();
    // Flip a bit in the middle of the second record's body. The
    // first record's bytes are 0..(4 + 11) = 0..15. Flip byte 18
    // (deep inside the second record's body).
    raw[18] ^= 0x40;
    let j = RecoveryJournal::from_bytes(raw);
    let mut engine = CollectingReplay::default();
    let err = j.replay(&mut engine).expect_err("corrupt middle");
    assert!(matches!(err, RecoveryError::TornEntry(_)));
    // The first record applied; the second is dropped; the third is
    // never reached.
    assert_eq!(engine.records.len(), 1);
    assert_eq!(engine.records[0].kind, JournalKind::CredentialAdded);
}

#[test]
fn uat_035_empty_journal_does_not_advance_state() {
    let j = RecoveryJournal::new();
    let mut engine = CollectingReplay::default();
    let err = j.replay(&mut engine).expect_err("empty");
    assert_eq!(err, RecoveryError::EmptyJournal);
    assert_eq!(engine.records.len(), 0);
}

#[test]
fn uat_035_full_record_set_with_all_kinds_applies_in_order() {
    let mut j = RecoveryJournal::new();
    j.append(JournalKind::CredentialAdded, b"cred-A".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRotated, b"cred-A->cred-B".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRevoked, b"cred-A".to_vec())
        .unwrap();
    j.append(JournalKind::VaultResealed, b"new-passphrase".to_vec())
        .unwrap();

    let bytes = j.as_bytes().to_vec();
    let j = RecoveryJournal::from_bytes(bytes);
    let mut engine = CollectingReplay::default();
    let n = j.replay(&mut engine).expect("replay");
    assert_eq!(n, 4);
    assert_eq!(engine.records[0].kind, JournalKind::CredentialAdded);
    assert_eq!(engine.records[1].kind, JournalKind::CredentialRotated);
    assert_eq!(engine.records[2].kind, JournalKind::CredentialRevoked);
    assert_eq!(engine.records[3].kind, JournalKind::VaultResealed);
    assert_eq!(engine.records[3].body, b"new-passphrase");
}

#[test]
fn uat_035_replay_engine_applies_all_records() {
    // Verify the ReplayEngine trait contract: apply() is called once
    // per record and the records retain their body bytes.
    struct BodySum(usize);
    impl ReplayEngine for BodySum {
        fn apply(&mut self, record: asv_broker::recovery::JournalRecord) {
            self.0 += record.body.len();
        }
    }

    let mut j = RecoveryJournal::new();
    j.append(JournalKind::CredentialAdded, b"abcdef".to_vec())
        .unwrap();
    j.append(JournalKind::CredentialRotated, b"ghi".to_vec())
        .unwrap();
    let mut engine = BodySum(0);
    let _ = j.replay(&mut engine).expect("replay");
    assert_eq!(engine.0, 6 + 3);
}
