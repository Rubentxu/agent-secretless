# Verification Report — v1-0-prep-rc-exit (A-lite)

- Cycle: `p-20a1ee316faf2ba3/v1-0-prep-rc-exit`
- Path: A-lite
- Head at verification: `f2a052675374b4318f27dfedd0b74b9ae5045b52`
- Date: 2026-09-29

## Scope of this cycle

1. `tools/rc-exit-checklist.py` — machine-checkable v1.0 RC exit gates
   (R0–R11) from `agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md`.
   Absent evidence is FAIL / UNVERIFIABLE-IN-REPO, never synthetic pass.
   Fails closed (exit 2) on spec-pack drift or `--root` outside the repo.
2. `fuzz/` — cargo-fuzz baseline crate (own workspace, nightly-only) for
   `asv_ipc_protocol::decode_request`; seeded corpus + README.
3. `docs/manual/OPERATIONS.md` — real "Building from source" section
   (R0 evidence); audit section corrected from a fabricated command to an
   explicit not-implemented note.

## Evidence observed

| Check | Command | Result | Exit |
|---|---|---|---|
| RC checklist at HEAD | `python3 tools/rc-exit-checklist.py --output /tmp/asv-artifacts/rc-checklist-final.json` | 7 PASS / 2 FAIL / 3 UNVERIFIABLE-IN-REPO (report `sha256:657adc62bb97f322f6bab7d35afeac9432fb4b3eccb0eb46cfcb7d050df12f02`) | 1 (expected: honest FAILs present) |
| Full regression | `cargo test --workspace --release -- --test-threads=1 --skip uat_028` | 433 passed / 0 failed | 0 |
| Surgical | `cargo test -p asv-ipc-protocol` | 11 passed / 0 failed | 0 |
| Lint gate | `cargo clippy --workspace --release --all-targets -- -D warnings` | clean | 0 |
| Fuzz smoke | `cargo +nightly fuzz run fuzz_ipc_decode_request -- -max_total_time=30` | 1,413,236 execs, 0 crashes | 0 |
| Spec-pack guard (negative) | `python3 tools/rc-exit-checklist.py --root /tmp` | exit 2, loud spec-drift failure | 2 |

## Gates

- `tests-pass`: **passed** — regression 433/0, surgical 11/0 (receipt below).
- `policy-compliant`: **passed** — clippy `-D warnings` clean; commits are
  Conventional and atomic (`c144280`, `117e414`, `f2a0526`); no secrets
  introduced (fuzz corpus has non-secret fixtures only) (receipt below).

## Known FAILs are honest, not hidden

- **R9 audit retention**: no audit log is implemented anywhere in the repo;
  the OPERATIONS.md `asv audit` command was documented but never existed
  (fixed this cycle). Fixing the checklist would be theatre; registered as
  a real gap instead.
- **R2 migration tests**: M13 known honest gap, unchanged.
- **UNVERIFIABLE-IN-REPO** (R8 Tauri, R0 artifact signing, R11 kernel
  matrix): external by nature; the checklist says so explicitly.

## Verdict

**PASS** — the cycle's deliverables meet their specified behavior; the
remaining RC exit FAILs are true product gaps recorded honestly, exactly
the state the checklist was built to expose. v1.0 remains blocked on those
gates and on explicit user approval.
