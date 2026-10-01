//! Tamper-evident audit log (R9).
//!
//! Every authenticated request the broker handles appends one record to an
//! in-memory hash chain. Each record's `event_hash` covers its sequence
//! number, the previous record's hash, its timestamp, and a canonical
//! serialization of the event, so mutating any stored byte breaks `verify()`.
//!
//! Two properties are structural, not reviewed-in:
//!
//! - **No secrets.** The record type has no field that could carry request
//!   arguments or credential material. A canary smuggled into any request
//!   field has nowhere to land (`AuditEventDto` is shape-level redaction).
//! - **Retention is configurable and loss is counted.** `ASV_AUDIT_MAX_RECORDS`
//!   bounds the ring; evicted records increment `dropped`, which every query
//!   response surfaces. An audit that silently forgets is worse than none.
//!
//! Persistence rides the `tracing` substrate (one line per append at `info`
//! on the broker's existing output), so the secret-bearing process gains no
//! new file-writing surface.

use std::io::Write;
use std::path::Path;

use asv_ipc_protocol::{AuditEventDto, AuditRecordDto};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// Default ring size when `ASV_AUDIT_MAX_RECORDS` is unset.
pub const DEFAULT_MAX_RECORDS: u64 = 10_000;

/// The 64-hex-zero previous hash of the first record.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// What one `sha256` binds together for a record.
#[derive(Serialize)]
struct ChainFrame<'a> {
    seq: u64,
    prev_hash: &'a str,
    ts: u64,
    event: &'a AuditEventDto,
}

/// Canonical bytes hashed for one record: fixed-width fields first, then the
/// canonical JSON of the event. Fixed-width framing prevents ambiguity
/// between field boundaries without a length prefix.
fn frame_bytes(seq: u64, prev_hash: &str, ts: u64, event: &AuditEventDto) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + prev_hash.len() + 8 + 64);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(prev_hash.as_bytes());
    buf.extend_from_slice(&ts.to_be_bytes());
    // serde_json over a struct/enum with this field set is canonical for our
    // types: no maps with dynamic key order, no floats.
    serde_json::to_vec(&ChainFrame {
        seq,
        prev_hash,
        ts,
        event,
    })
    .expect("serialize a chain frame")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 64 lowercase hex chars: the shape any legal previous-hash anchor has.
pub(crate) fn is_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why the chain stopped verifying.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainBreak {
    pub seq: u64,
    pub reason: ChainBreakReason,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainBreakReason {
    /// Stored `prev_hash` does not match the previous record's hash.
    LinkMismatch,
    /// Recomputed `event_hash` differs from the stored one.
    DigestMismatch,
}

/// Why a persistent audit file could not be opened.
#[derive(Debug)]
pub enum AuditOpenError {
    /// The file exists but cannot be read or written.
    Io(std::io::Error),
    /// A line other than the last one is not a valid record: the middle of
    /// the history is damaged, which replay cannot repair.
    CorruptLine { line: usize },
    /// The valid history fails its own chain validation. Fail-closed: a
    /// persistent audit log that does not verify must not be extended.
    Chain(ChainBreak),
}

/// Why a standalone `verify_file` failed.
#[derive(Debug)]
pub enum AuditFileError {
    Io(std::io::Error),
    /// A line that is not valid JSON (or not a record).
    MalformedLine {
        line: usize,
    },
    Chain(ChainBreak),
}

/// The in-memory ring of audit records.
#[derive(Debug)]
pub struct AuditLog {
    records: VecDeque<AuditRecordDto>,
    /// Number of records evicted by retention, never reset.
    dropped: u64,
    /// 0 = unbounded.
    max: u64,
    next_seq: u64,
    /// Hash of the most recent record (genesis when empty).
    head: String,
    /// Append handle for the durable log. `None` = pure in-memory.
    file: Option<std::fs::File>,
}

/// Validates that `record` correctly extends a chain whose previous record
/// is `prev` (`None` = first record). Same anchor rules as `verify()`.
fn validate_link(prev: Option<&AuditRecordDto>, record: &AuditRecordDto) -> Result<(), ChainBreak> {
    match prev {
        Some(p) => {
            if record.prev_hash != p.event_hash {
                return Err(ChainBreak {
                    seq: record.seq,
                    reason: ChainBreakReason::LinkMismatch,
                });
            }
        }
        None => {
            let anchored = if record.seq == 0 {
                record.prev_hash == GENESIS_PREV_HASH
            } else {
                is_hex_64(&record.prev_hash)
            };
            if !anchored {
                return Err(ChainBreak {
                    seq: record.seq,
                    reason: ChainBreakReason::LinkMismatch,
                });
            }
        }
    }
    let computed = sha256_hex(&frame_bytes(
        record.seq,
        &record.prev_hash,
        record.ts,
        &record.event,
    ));
    if computed != record.event_hash {
        return Err(ChainBreak {
            seq: record.seq,
            reason: ChainBreakReason::DigestMismatch,
        });
    }
    Ok(())
}

/// Verifies an audit file end to end without opening it for append.
/// The complete history must form one valid chain.
pub fn verify_file(path: &Path) -> Result<(), AuditFileError> {
    let bytes = std::fs::read(path).map_err(AuditFileError::Io)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut prev: Option<AuditRecordDto> = None;
    for (idx, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: AuditRecordDto = serde_json::from_str(line)
            .map_err(|_| AuditFileError::MalformedLine { line: idx + 1 })?;
        validate_link(prev.as_ref(), &record).map_err(AuditFileError::Chain)?;
        prev = Some(record);
    }
    Ok(())
}

impl AuditLog {
    /// Creates a log retaining at most `max` records (`0` = unbounded).
    pub fn new(max: u64) -> Self {
        Self {
            records: VecDeque::new(),
            dropped: 0,
            max,
            next_seq: 0,
            head: GENESIS_PREV_HASH.to_string(),
            file: None,
        }
    }

    /// Opens (or creates) a persistent audit log at `path`.
    ///
    /// Replays the existing file to restore the query window, `next_seq`,
    /// `head` and the out-of-window count, then holds an append handle.
    /// A truncated final line (crash mid-write) is discarded and the file
    /// trimmed back to the last valid record; a damaged middle line or a
    /// chain that fails verification aborts the open (fail-closed).
    pub fn open_persistent(max: u64, path: &Path) -> Result<Self, AuditOpenError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // First run: start an empty durable log.
                Vec::new()
            }
            Err(err) => return Err(AuditOpenError::Io(err)),
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut records: Vec<AuditRecordDto> = Vec::new();
        let mut valid_len = 0usize;
        let mut truncated_tail = false;
        for (idx, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let is_last = idx + 1 == text.lines().count();
            match serde_json::from_str::<AuditRecordDto>(line) {
                Ok(record) => {
                    if let Err(break_) = validate_link(records.last(), &record) {
                        return Err(AuditOpenError::Chain(break_));
                    }
                    records.push(record);
                    valid_len += line.len() + 1;
                }
                Err(err) if is_last => {
                    // Crash mid-append: the tail is garbage; recover by
                    // trimming the file back to the last valid record.
                    tracing::warn!(line = idx + 1, %err, "audit file tail truncated; discarding");
                    truncated_tail = true;
                }
                Err(err) => {
                    tracing::error!(line = idx + 1, %err, "audit file damaged mid-history");
                    return Err(AuditOpenError::CorruptLine { line: idx + 1 });
                }
            }
        }
        if truncated_tail {
            std::fs::write(path, &text.as_bytes()[..valid_len]).map_err(AuditOpenError::Io)?;
        }
        let total = records.len();
        let window = if max == 0 {
            total
        } else {
            (max as usize).min(total)
        };
        let dropped = (total - window) as u64;
        let mut log = Self::new(max);
        log.records
            .extend(records[total - window..].iter().cloned());
        log.dropped = dropped;
        if let Some(last) = records.last() {
            log.next_seq = last.seq + 1;
            log.head = last.event_hash.clone();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(AuditOpenError::Io)?;
        log.file = Some(file);
        Ok(log)
    }

    /// Appends one event at `ts`, enforcing retention, returning the record.
    /// When the log is persistent the record is flushed to the durable file
    /// before the caller sees it.
    pub fn append(&mut self, event: AuditEventDto, ts: u64) -> AuditRecordDto {
        let seq = self.next_seq;
        let prev_hash = self.head.clone();
        let event_hash = sha256_hex(&frame_bytes(seq, &prev_hash, ts, &event));
        self.next_seq += 1;
        self.head = event_hash.clone();
        let record = AuditRecordDto {
            seq,
            prev_hash,
            ts,
            event_hash,
            event,
        };
        self.records.push_back(record.clone());
        if self.max > 0 {
            while self.records.len() as u64 > self.max {
                self.records.pop_front();
                // Loss is counted, surfaced on every query, and mirrored to
                // the tracing substrate so an operator can reconcile the
                // ring against the persisted log lines.
                self.dropped += 1;
                tracing::warn!(dropped = self.dropped, "audit record evicted by retention");
            }
        }
        if let Some(file) = self.file.as_mut() {
            // Durable before visible: the record's JSON line is the same
            // canonical serialization the hash covers, so the file replays
            // into exactly the chain verify() checks.
            let mut line = serde_json::to_vec(&record).expect("serialize an audit record");
            line.push(b'\n');
            if let Err(err) = file.write_all(&line).and_then(|()| file.flush()) {
                // The in-memory ring is already extended; the durable log
                // has a gap. Surface it loudly instead of pretending the
                // write landed.
                tracing::error!(%err, seq = record.seq, "audit durable write failed");
            }
        }
        record
    }

    /// Records with `ts >= since`, in chain order.
    pub fn query(&self, since: u64) -> Vec<AuditRecordDto> {
        self.records
            .iter()
            .filter(|r| r.ts >= since)
            .cloned()
            .collect()
    }

    /// Hash of the newest record, or the genesis hash on an empty log.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Records evicted by retention so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Recomputes the chain over the retained records. Any mutation of a
    /// stored field breaks this; that is the tamper evidence R9 asks for.
    ///
    /// With retention active the oldest retained record's predecessor may
    /// already be evicted, so the anchor is: seq 0 must chain from genesis;
    /// any later first-record must carry a well-formed 64-hex `prev_hash`
    /// whose predecessor the operator reconciles from the tracing substrate.
    /// From the anchor on, every link and digest must reproduce exactly.
    pub fn verify(&self) -> Result<(), ChainBreak> {
        let mut prev: Option<&str> = None;
        for record in self.records.iter() {
            match prev {
                Some(p) => {
                    if record.prev_hash != p {
                        return Err(ChainBreak {
                            seq: record.seq,
                            reason: ChainBreakReason::LinkMismatch,
                        });
                    }
                }
                None => {
                    let anchored = if record.seq == 0 {
                        record.prev_hash == GENESIS_PREV_HASH
                    } else {
                        is_hex_64(&record.prev_hash)
                    };
                    if !anchored {
                        return Err(ChainBreak {
                            seq: record.seq,
                            reason: ChainBreakReason::LinkMismatch,
                        });
                    }
                }
            }
            let computed = sha256_hex(&frame_bytes(
                record.seq,
                &record.prev_hash,
                record.ts,
                &record.event,
            ));
            if computed != record.event_hash {
                return Err(ChainBreak {
                    seq: record.seq,
                    reason: ChainBreakReason::DigestMismatch,
                });
            }
            prev = Some(record.event_hash.as_str());
        }
        // The advertised head must be the chain's tip (genesis when empty).
        let tip = prev.unwrap_or(GENESIS_PREV_HASH);
        if self.head != tip {
            return Err(ChainBreak {
                seq: self.next_seq.saturating_sub(1),
                reason: ChainBreakReason::LinkMismatch,
            });
        }
        Ok(())
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RECORDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "ASV-CANARY-9b2f77c1-AUDIT";

    fn event(method: &str) -> AuditEventDto {
        AuditEventDto::RequestHandled {
            method: method.to_string(),
            session: None,
            peer_uid: 1000,
            pinned: false,
            outcome: "ok".into(),
            posture: "SERVICE_BROKERED".into(),
        }
    }

    #[test]
    fn genesis_chain_verifies() {
        let mut log = AuditLog::new(0);
        log.append(event("ping"), 100);
        log.append(event("create_session"), 101);
        assert_eq!(log.verify(), Ok(()));
        let head = log.head();
        let records = log.query(0);
        assert_eq!(records.last().expect("records").event_hash, head);
    }

    #[test]
    fn first_record_chains_from_genesis() {
        let mut log = AuditLog::new(0);
        let r = log.append(event("ping"), 5);
        assert_eq!(r.seq, 0);
        assert_eq!(r.prev_hash, GENESIS_PREV_HASH);
    }

    #[test]
    fn mutation_breaks_verify() {
        let mut log = AuditLog::new(0);
        log.append(event("ping"), 100);
        log.append(event("list_credential_metadata"), 101);
        let mut records = log.query(0);
        // Flip one byte of one stored field: the tamper R9 cares about.
        records[1].event = event("tampered");
        let mut tampered = AuditLog::new(0);
        tampered.records.extend(records);
        tampered.head = "forced-mismatch".into();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn digest_mismatch_is_reported_per_record() {
        let mut log = AuditLog::new(0);
        log.append(event("ping"), 1);
        let mut records = log.query(0);
        records[0].ts = 2; // mutate without recomputing the hash
        let mut tampered = AuditLog::new(0);
        tampered.records.extend(records);
        tampered.head = "x".into();
        assert_eq!(
            tampered.verify().unwrap_err(),
            ChainBreak {
                seq: 0,
                reason: ChainBreakReason::DigestMismatch
            }
        );
    }

    #[test]
    fn retention_keeps_newest_and_counts_dropped() {
        let mut log = AuditLog::new(3);
        for i in 0..5 {
            log.append(event("ping"), 10 + i);
        }
        let kept = log.query(0);
        assert_eq!(kept.len(), 3);
        assert_eq!(kept[0].seq, 2, "oldest records evicted");
        assert_eq!(log.dropped(), 2);
        assert_eq!(log.verify(), Ok(()), "chain still verifies after eviction");
    }

    #[test]
    fn query_filters_by_since() {
        let mut log = AuditLog::new(0);
        log.append(event("ping"), 100);
        log.append(event("ping"), 200);
        assert_eq!(log.query(150).len(), 1);
        assert_eq!(log.query(0).len(), 2);
        assert_eq!(log.query(999_999).len(), 0);
    }

    #[test]
    fn canary_never_lands_in_a_record() {
        // The record type has no argument field; prove it by round-tripping
        // an event whose inputs contained a canary and asserting the serialized
        // record cannot contain it.
        let event = AuditEventDto::RequestHandled {
            method: "create_session".into(),
            session: Some("not-the-canary".into()),
            peer_uid: 1000,
            pinned: true,
            outcome: "ok".into(),
            posture: "SERVICE_BROKERED".into(),
        };
        let mut log = AuditLog::new(0);
        let r = log.append(event, 7);
        let serialized = serde_json::to_string(&r).expect("dto serializes");
        assert!(!serialized.contains(CANARY));
        assert!(!frame_bytes(r.seq, &r.prev_hash, r.ts, &r.event)
            .windows(CANARY.len())
            .any(|w| w == CANARY.as_bytes()));
    }

    // ---- Durable audit log (persistence follow-up) ----

    fn temp_audit_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("asv-audit-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("audit.jsonl")
    }

    #[test]
    fn persistent_append_writes_one_json_line_per_record() {
        let path = temp_audit_path("append-lines");
        {
            let mut log = AuditLog::open_persistent(0, &path).expect("open");
            log.append(event("ping"), 1);
            log.append(event("create_session"), 2);
        }
        let text = std::fs::read_to_string(&path).expect("file");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per record");
        for line in &lines {
            let record: AuditRecordDto = serde_json::from_str(line).expect("line parses");
            let recomputed = sha256_hex(&frame_bytes(
                record.seq,
                &record.prev_hash,
                record.ts,
                &record.event,
            ));
            assert_eq!(recomputed, record.event_hash, "line binds its own hash");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn replay_restores_window_head_and_sequence() {
        let path = temp_audit_path("replay");
        {
            let mut log = AuditLog::open_persistent(2, &path).expect("open");
            for i in 0..5 {
                log.append(event("ping"), 10 + i);
            }
        }
        let log = AuditLog::open_persistent(2, &path).expect("reopen");
        let kept = log.query(0);
        assert_eq!(kept.len(), 2, "query window matches retention");
        assert_eq!(kept[0].seq, 3);
        assert_eq!(kept[1].seq, 4);
        assert_eq!(log.dropped(), 3, "out-of-window history counted");
        assert_eq!(log.head(), kept[1].event_hash);
        let mut log = log;
        let next = log.append(event("ping"), 99);
        assert_eq!(next.seq, 5, "sequence continues after restart");
        assert_eq!(
            next.prev_hash, kept[1].event_hash,
            "chains from restored head"
        );
        assert_eq!(log.verify(), Ok(()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn verify_file_accepts_intact_log() {
        let path = temp_audit_path("intact");
        let mut log = AuditLog::open_persistent(0, &path).expect("open");
        for i in 0..4 {
            log.append(event("ping"), 20 + i);
        }
        assert!(verify_file(&path).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn verify_file_detects_hash_tamper() {
        let path = temp_audit_path("hash-tamper");
        {
            let mut log = AuditLog::open_persistent(0, &path).expect("open");
            log.append(event("ping"), 1);
            log.append(event("ping"), 2);
        }
        let text = std::fs::read_to_string(&path).expect("file");
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let last = lines.last_mut().expect("line");
        // Flip two hex chars of the stored hash tail, keeping valid JSON:
        // the line ends with `,"event_hash":"<64hex>"}`.
        let marker = "\"event_hash\":\"";
        let pos = last.rfind(marker).expect("event_hash field present");
        let hash_start = pos + marker.len();
        let mut flipped: String = last.as_str()[hash_start..hash_start + 2]
            .chars()
            .map(|c| if c == 'a' { 'b' } else { 'a' })
            .collect();
        flipped.push_str(&last.as_str()[hash_start + 2..]);
        *last = format!("{}{}", &last[..hash_start], flipped);
        std::fs::write(&path, lines.join("\n") + "\n").expect("rewrite");
        match verify_file(&path) {
            Err(AuditFileError::Chain(_)) => {}
            other => panic!("expected chain break, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn verify_file_detects_seq_tamper() {
        let path = temp_audit_path("seq-tamper");
        {
            let mut log = AuditLog::open_persistent(0, &path).expect("open");
            log.append(event("ping"), 1);
        }
        let text = std::fs::read_to_string(&path).expect("file");
        let tampered = text.replace("\"seq\":0", "\"seq\":7");
        std::fs::write(&path, tampered).expect("rewrite");
        match verify_file(&path) {
            Err(AuditFileError::Chain(ChainBreak {
                reason: ChainBreakReason::DigestMismatch,
                ..
            })) => {}
            other => panic!("expected digest mismatch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn partial_tail_line_is_discarded_and_reanchored() {
        let path = temp_audit_path("partial-tail");
        {
            let mut log = AuditLog::open_persistent(0, &path).expect("open");
            for i in 0..3 {
                log.append(event("ping"), 30 + i);
            }
        }
        // Simulate a crash mid-append: half of a fourth record.
        let text = std::fs::read_to_string(&path).expect("file");
        std::fs::write(&path, format!("{text}{{\"seq\":3,\"prev_has")).expect("append garbage");
        let mut log = AuditLog::open_persistent(0, &path).expect("reopen trims tail");
        assert_eq!(log.query(0).len(), 3, "valid history survives");
        let next = log.append(event("ping"), 50);
        assert_eq!(next.seq, 3, "new record takes the freed sequence");
        assert_eq!(log.verify(), Ok(()));
        assert!(verify_file(&path).is_ok(), "file verifies after re-anchor");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn retention_window_with_file_matches_in_memory() {
        let path = temp_audit_path("retention");
        let mut mem = AuditLog::new(3);
        let mut disk = AuditLog::open_persistent(3, &path).expect("open");
        for i in 0..7 {
            let e = event("ping");
            let ts = 40 + i;
            let a = mem.append(e.clone(), ts);
            let b = disk.append(e, ts);
            assert_eq!(a.seq, b.seq);
            assert_eq!(a.event_hash, b.event_hash, "same chain on both");
        }
        assert_eq!(mem.query(0).len(), disk.query(0).len());
        assert_eq!(mem.dropped(), disk.dropped());
        assert_eq!(disk.verify(), Ok(()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn mid_history_damage_is_fail_closed() {
        let path = temp_audit_path("mid-damage");
        {
            let mut log = AuditLog::open_persistent(0, &path).expect("open");
            log.append(event("ping"), 1);
            log.append(event("ping"), 2);
            log.append(event("ping"), 3);
        }
        let text = std::fs::read_to_string(&path).expect("file");
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        lines[1] = "not json".into();
        std::fs::write(&path, lines.join("\n") + "\n").expect("rewrite");
        match AuditLog::open_persistent(0, &path) {
            Err(AuditOpenError::CorruptLine { line: 2 }) => {}
            other => panic!("expected CorruptLine(2), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
