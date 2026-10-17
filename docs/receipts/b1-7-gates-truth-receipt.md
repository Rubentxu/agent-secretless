# B1.7 Implementation Receipt — gates truth (spec pin, M14/M15 exits, comments)

Block: B1.7 of `docs/plans/b1-delivery-roadmap.md` (branch `b1/worker-lifetime`).
Scope: documentation, configuration comments and one ephemeral check. **No
production code changed.**

## What landed

- **`agent-secretless-vault-spec/SHA256SUMS` re-pinned** for `docs/15-ROADMAP.md`
  and `docs/16-SECURITY-RELEASE-GATES.md`. The `spec-integrity` pipeline stage has
  been red since the pin at `5456836`: the R4 where-blocks-stand row and the M15
  milestone section (`34041b1`, `e3014948`) and the R11 rows re-derived to 2137
  (`258411a`, `b15fe06`) landed after the pin without a re-normalisation. The
  documents were right; the pin was stale. `sha256sum --check --strict` is green
  again (measured, exit 0).
- **M14/M15 exit warnings closed in the spec pack** (`docs/15-ROADMAP.md`):
  both milestones have no numbered UAT of their own — M14's exit criterion is a
  property of the tree measured by the R3.A/R3.B suites; M15's chain is measured
  by the R4.B suites. Both exit blocks now say so and delegate release
  certification to `16-SECURITY-RELEASE-GATES.md` (R11 full-suite row + UAT claim
  coverage row), which is the delegation `tools/check-gates.py` already
  understands (`delegated` path, no warning). Warnings went **7 → 5** (measured).
- **The 5 remaining warnings are accepted state, now said out loud**: they are
  the filename-only claims of historically named test files
  (`uat_010_connect_allow_list.rs`, `uat_011_redirect_denier.rs`,
  `uat_012_trust_injection.rs`, `uat_017_env_scan.rs`, `uat033_live.rs`), each
  documented with its reason in the "UAT claim coverage" row of
  `16-SECURITY-RELEASE-GATES.md` (the files deliberately claim no UAT; renaming
  them would rewrite normative references for no behavioral gain). Renaming was
  considered and rejected for exactly that reason.
- **`pipeline.kts` comments re-derived to the present**: the static stage no
  longer describes the 263-warning debt that `27a8f1d` paid (baseline reads 0),
  and the spec-gates stage no longer claims "34/34 UAT, 0 warnings" (now 40/40
  with 0 hard defects, 0 orphaned, 5 accepted filename-only warnings). Comments
  only; no stage command changed.
- **README badge removed** (both `README.md` and `README-es.md`): it pointed at
  `.github/workflows/verify.yml`, which does not exist anywhere in the
  repository. The CI authority is PipelineK (`pipeline.kts`); nothing replaced
  the badge.

## Evidence (all commands run on this tree, HEAD `a42b353`)

| Check | Command | Result |
|---|---|---|
| RED (before fixes) | `python3 tests/ephemeral/b1-7/eph_gates_truth.py` | exit 1 — 2 checksum mismatches (`15-ROADMAP.md`, `16-SECURITY-RELEASE-GATES.md`), 7 warnings (5 filename + M14 + M15) |
| GREEN (after fixes) | same | exit 0 — 10/10 assertions PASS |
| Gate map | `python3 tools/check-gates.py` | exit 0 — 40/40 UAT gated, 0 orphaned, **0 hard defects, 5 warnings** (exactly the documented filename-only set) |
| Spec integrity | `sha256sum --check --strict SHA256SUMS` (spec dir) | exit 0 |
| Formatting | `cargo fmt --all -- --check` | exit 0 |
| Whitespace | `git diff --check` | clean |

## Decisions recorded

1. Re-pin instead of revert: every post-pin edit of the two documents is a
   documented, committed change (hashes listed above); nothing looked accidental.
2. The 5 filename-only warnings stay. Closing them by renaming the files would
   touch the normative references that cite those names (`15-ROADMAP.md:115,
   467, 478, 2286`; `16-SECURITY-RELEASE-GATES.md:338`;
   `tools/rc-exit-checklist.py`) for zero behavioral gain. The accepted state is
   now visible in the `spec-gates` stage comment instead of only in the gates
   doc.
3. Follow-up (not this block): a permanent pin of the accepted-5 warning set
   once the ephemeral check retires (the pipeline stage currently fails on hard
   defects only, by design).

## Slice boundary

This block closes the 43-commit / ~4.7k-line stretch since `origin/main`
(v0.38.3). Per the delivery strategy, the next block (B1.8) starts after the
`b1.7` tag; integration to main is the owner's call at block close.

Risk: none — documentation, configuration comments, checksum re-pin and an
ephemeral read-only check; no production code path changed.
