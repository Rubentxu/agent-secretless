# B1.5 — fmt drift housekeeping (DRAFT)

**Status**: DRAFT
**Branch**: `b1/fmt-drift-housekeeping`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-5`
**Off**: `b1/worker-lifetime` HEAD `d3cdff0` (B1.1 + B1.2 + B1.3 + B1.4 + yank policy DECIDED)
**Author**: Jcode (autonomous, user pre-approved with "apruebo cualquier criterio"; the B1.5 definition is "fmt drift housekeeping" per the B1.4 receipt's open list)

## What B1.5 ships

Pays the pre-existing `cargo fmt` drift that has been on the
"opción A" pendiente list since the B1.1 receipt. The drift
was uncovered when the B1.4 block ran `cargo fmt --all -- --check`
as part of the post-merge gates; the diff was 11 hunks across
6 files, all pre-existing in `b1/worker-lifetime` and none
introduced by B1.4.

The drift is a `rustfmt` 1.6+ style preference change: match
arms and method chains that the prior rustfmt collapsed to
one line, the current rustfmt expands back to multi-line.
The shape is mechanical: line-length wraps for method chains
(`.append(...).expect("...")`) and arm-collapse decisions for
match expressions. There is no semantic change.

## The 11 hunks, by file

| File | Hunks | What rustfmt did |
|---|---|---|
| `crates/broker/src/audit.rs` | 4 | 1 arm-collapse (RetentionGap), 3 method-chain wraps in tests |
| `crates/broker/src/connect_runtime.rs` | 1 | 1 arm-collapse (RetentionGap) |
| `crates/broker/src/worker.rs` | 4 | 4 method-chain wraps |
| `crates/cli/src/main.rs` | 1 | 1 line-length wrap |
| `crates/integrations/src/lib.rs` | 1 | 1 line-length wrap |
| `crates/broker/src/audit.rs` (`AuditAppendError::Io`) | 0 | (already correct) |

Total: 11 hunks, ~56 lines net change, 0 semantic change.

## Why now

The B1.4 receipt left this as "opción A pendiente" with the
user's explicit understanding. With the B1 series fully
delivered, tag `b1.4` released, branch and tag pushed to
origin, and GitHub Release published, this is the next
housekeeping block. Running `cargo fmt --all` produces the
diff; committing it produces a clean `cargo fmt --all -- --check`
that no longer reports drift in `b1/worker-lifetime`.

The risk of doing this is low: rustfmt is deterministic for
a given version, the diff is small and reviewable, and the
test count is the regression guard. The risk of NOT doing
this is medium: every future block has to either ignore the
drift (carrying the technical debt forward) or do the work
inline (which expands scope of unrelated blocks, the
exact pattern the user has rejected).

## What is NOT in B1.5

- No `cargo fmt` config change. The drift is current
  rustfmt output; the diff is what `rustfmt` produces on
  this code today.
- No rustfmt version pin. The drift accumulated over
  rustfmt 1.5 → 1.6+; pinning the version is a separate
  policy decision (B1.6 candidate).
- No source code change beyond the rustfmt output. The
  diff is purely whitespace and brace placement.
- No dependency change. `Cargo.lock` is untouched.
- No new tests. The regression guard is the existing
  686/686 broker `--lib` + 21/21 UAT-040 + 4/4 uat_017
  test counts: if rustfmt's mechanical edit breaks anything,
  the tests catch it.

## Plan

1. Run `cargo fmt --all` in the worktree.
2. Verify `cargo build --workspace` is clean.
3. Run `cargo test -p asv-broker --lib` and
   `cargo test -p asv-broker --test uat_040_isolated_worker_runtime`
   and `cargo test -p asv-broker --test uat_017_env_scan` —
   all 711 tests (686 + 21 + 4) must remain green.
4. Run `python3 scripts/check-clippy-ratchet.py` — must
   remain at 0/0.
5. Run `cargo fmt --all -- --check` — must report zero
   diffs.
6. Commit the rustfmt output as a single commit on
   `b1/fmt-drift-housekeeping` with the diff stat in the
   commit message.
7. Write the B1.5 implementation receipt.
8. Merge to `b1/worker-lifetime` with `--no-ff`.
9. Tag `b1.5` annotated.
10. Push to origin + GitHub Release (the user's call;
    same as B1.4).

## Awaiting user review

- [ ] User confirms the "rustfmt 1.6+ style change is the
      cause" framing.
- [ ] User confirms the "one commit" plan (vs splitting
      per-file).
- [ ] User confirms tag name `b1.5` (vs `b0.0.1` or
      `housekeeping-1`).
- [ ] User decides whether to also pin `rustfmt` to a
      version (separate B1.6 candidate).
