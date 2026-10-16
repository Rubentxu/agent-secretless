# B1.8 Implementation Receipt — failed audit writes are counted and visible

Block: B1.8 of `docs/plans/b1-delivery-roadmap.md` (branch `b1/worker-lifetime`).
Closes audit finding H-02: the dispatcher discarded the audit append result, so
an operation could complete while its audit record never reached the durable
log, silently.

## What landed

- **`BrokerState.audit_write_failures: AtomicU64`** — sticky for the life of
  the process; a gap that healed does not un-happen. Set by the dispatcher in
  `handle` when `append` returns `Err`; the same site emits `tracing::error!`
  naming the gap and the surface that reports it.
- **`Response::Pong.audit_write_failures: u64` with `#[serde(default)]`** —
  the surface `asv status` already uses. Compatibility pinned in both
  directions by wire tests: `pong_without_audit_field_reads_as_zero` (old
  broker, new CLI) and `pong_tolerates_unknown_fields` (new broker must not
  strand an old CLI; serde ignores what it does not know).
- **CLI**: `status --json` projects `audit_write_failures`; the human output
  prints `audit: N durable audit write(s) failed since start; those records
  were not persisted` only when N > 0 (healthy stays silent). The doctor probe
  pattern widens to `..`; its behavior is unchanged.
- **Documented ordering**: the Pong is built before the request's own audit
  append runs, so the status that first crosses a failing write reports 0 and
  the next one reports the gap. Pinned by the dispatcher test.

## Evidence (all run on this tree)

| Check | Command | Result |
|---|---|---|
| RED | `cargo test -p asv-broker --locked --lib a_failed_durable_audit_write_is_counted` | FAILED: `left: 0, right: 1` — with the discarded error the counter stayed 0 |
| GREEN | same | ok |
| Broker lib | `cargo test -p asv-broker --locked --lib` | **687 passed**, 0 failed |
| Wire | `cargo test -p asv-ipc-protocol --locked --lib` | **19 passed** (incl. the 2 new) |
| CLI bin | `cargo build -p asv-cli --locked` + `cargo test -p asv-cli --locked --bin asv` | build OK; **135 passed** |
| E2E | `cargo test -p asv-broker --locked --test eph_audit_gap` | ok — real brokerd, real socket: first `status --json` count 0, second count 1, human warning present, broker alive, durable file unchanged, tracing::error on brokerd stdout |
| Formatting | `cargo fmt --all -- --check` | exit 0 |

One defect was caught by the parent's own build verification after the worker
finished: the human-print arm matched the new field by reference and compared
`&u64 > 0` (E0308); the CLI had never been compiled because the requested
command was `--lib` on a binary-only crate. Fixed in-slice (one dereference,
commented); `asv-cli` builds and its 135 tests pass.

## Injection method (E2E)

The ephemeral test pre-fills the `--audit-file` to the `RLIMIT_FSIZE` ceiling
and applies the limit inside `pre_exec` (SIGXFSZ ignored, isolated to the
child), so the broker's durable audit writes fail with EFBIG while the fresh
vault (measured under the limit) and the socket keep working. No production
test hook was added; the only test seam in production files is
`AuditLog::set_file_for_tests`, `#[cfg(test)]` and `pub(crate)`.

## Decisions

- Sticky counter, never reset: an operator who saw the gap must be able to
  trust `status` afterwards; healing is logged, not forgotten.
- No new audit event variant and no protocol bump: the count rides Pong with
  a defaulted field, which is the smallest wire-compatible surface.
- Permanent coverage is the dispatcher test, the two wire tests, and the CLI
  suites; the real-process E2E retires with the block per the delivery
  strategy.

Risk: item 3 — `Response::Pong` is a shared contract; all consumers in the
workspace were updated and the wire tests pin old-reader/new-reader
compatibility, but external IPC clients outside this repository would see the
new field (ignored by serde, additive). Verified: broker lib 687, ipc 19, cli
bin 135, E2E green.
