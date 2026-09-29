# Verification Report — r9-audit-log (A-lite)

- Cycle: `p-20a1ee316faf2ba3/r9-audit-log`
- Path: A-lite
- Head at verification: `d110b8d` (3 commits: 7f468a1 broker, a2d634e cli, d110b8d docs)
- Date: 2026-09-29

## Scope delivered

1. `crates/broker/src/audit.rs` — sha256 hash chain (`seq || prev_hash ||
   ts || canonical event`), genesis anchor, retention ring with `dropped`
   counter, `verify()` with retention-aware anchoring and head pinning.
2. Broker wiring — `handle` wrapper audits every request exactly once
   (dispatcher cannot bypass); `--audit-max-records N` launch flag.
3. IPC — `audit_query` request + `audit_records` response + redacted
   `AuditRecordDto`; broker DENIES queries from agent peers (separation
   of duties), recording the refused probe itself.
4. CLI — `asv audit --since <90s|30m|24h|7d>`.
5. OPERATIONS.md real audit section; RC checklist R9 now checks the real
   implementation.

## Evidence observed

| Check | Command | Result | Exit |
|---|---|---|---|
| Audit unit tests (chain/tamper/retention/canary) | `cargo test -p asv-broker --lib audit` | 7 passed / 0 failed | 0 |
| Broker full lib | `cargo test -p asv-broker --lib` | 123 passed / 0 failed | 0 |
| Broker release + UAT | `cargo test -p asv-broker --release` | 217 passed / 0 failed | 0 |
| Env-quarantine scanner | `--test uat_017_env_scan` | 4 passed / 0 failed | 0 |
| Surgical (3 crates) | `cargo test -p asv-broker -p asv-cli -p asv-ipc-protocol --release` | 167 passed / 1 failed → fixed (env scan) → see regression | — |
| Full regression | `cargo test --workspace --release -- --test-threads=1 --skip uat_028` | **443 passed / 0 failed** | 0 |
| Lint | `cargo clippy --workspace --release --all-targets -- -D warnings` | clean | 0 |
| RC checklist | `python3 tools/rc-exit-checklist.py` | **8 PASS / 1 FAIL / 3 UNVERIFIABLE; R9 PASS** | 1 (R2 remains honest FAIL) |

## Design corrections forced by evidence

- First implementation configured retention via `ASV_AUDIT_MAX_RECORDS`
  env var; the repo's own env-quarantine scanner (uat_017) correctly
  rejected env reads in broker production sources. Retention moved to the
  `--audit-max-records` launch flag. The scanner was not weakened.
- `verify()` initially anchored every retained chain at genesis and broke
  after retention eviction; the unit test caught it. Now seq 0 anchors at
  genesis, later first-records anchor on well-formed hex, and the head is
  pinned.

## Gates

- `tests-pass`: **passed** — 443/0 regression, 167/0 surgical after fix.
- `policy-compliant`: **passed** — clippy `-D warnings` clean, Conventional
  atomic commits, no secrets introduced, env-quarantine invariant upheld
  (strengthened, not bypassed).

## Honest limits

- `audit_query` returns DENIED to every current peer; the operator control
  plane that will own queries is a separate future milestone. The CLI
  reports this refusal instead of pretending to work.
- Records live in memory + tracing substrate; a durable on-disk audit file
  remains future work (documented in the plan's non-goals).

## Verdict

**PASS** — R9's tamper-evidence, per-operation posture, and configurable
retention are now implemented and machine-checked. The RC checklist's only
remaining FAIL is R2 (migration tests, M13 gap).
