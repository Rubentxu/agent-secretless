# CI policy — PipelineK is the authority

This repository does not use GitHub Actions. `pipeline.kts`, run through
PipelineK, is the single definition of what the gates are, and it runs on the
machine that made the change.

```bash
pipelinek validate pipeline.kts   # check the DSL compiles
pipelinek run pipeline.kts        # run every gate
```

## Why local, and what that costs

The gates used to be `.github/workflows/verify.yml` on `ubuntu-latest`. Migrating
them to PipelineK was worth doing for one concrete reason: a hosted runner is
the only place a change meets an OS, a toolchain and a PostgreSQL version the
author does not use, and this project kept finding things there. The UAT-033
suite fails on PostgreSQL 16 with a rustls TLS handshake error and passes
against PostgreSQL 18 — a difference a local-only pipeline cannot see.

That is the trade being made, stated rather than discovered later:

- **Lost:** a second machine. A change that builds only on this host, or only
  against this PostgreSQL, is now invisible until someone else runs it.
- **Gained:** every gate is reproducible in one command, with no runner quota,
  no cache to invalidate, and no 3-minute wait to learn that `cargo fmt` failed.

If a future change needs a genuine matrix — several OSes, several database
versions — that is a real need, and the right answer is to ask for it
explicitly rather than to let a workflow reappear by default. The `ci-policy`
stage below exists to make that a conversation instead of an accident.

## The prohibition is enforced, not just stated

`scripts/ci-policy.sh` runs as the **first** stage of every pipeline run and
fails if any `*.yml` or `*.yaml` file exists under `.github/workflows`.

Deleting the workflow file alone would not hold. A future contributor adds a
workflow, it never runs on anyone's machine, and the divergence between what CI
claims to check and what anyone actually checks is invisible until something
breaks. The guard turns that into a red run in under a second.

It is deliberately first. It started last, on the reasoning that a policy check
should not mask the gates before it — but a stage after a failure never
executes, so a last-positioned guard stops running the moment anything else
goes red, which is precisely when its verdict is least likely to be missed.

`.github/CODEOWNERS` is **not** covered by this policy. It governs code review,
not CI, and this project is hosted on GitHub regardless of who runs its gates.

## The stages

| Stage | What it gates | Notes |
|---|---|---|
| `ci-policy` | no GitHub Actions | fails fast, before any build |
| `static` | `cargo fmt`, `cargo clippy` ratchet, `cargo audit --deny warnings` (if installed) | clippy baseline is held, not promoted; audit line is an explicit `if/else` (V1P-G1-T9) so a yank is a hard fail, not a "not installed" skip |
| `release-law` | `scripts/check-release-bump.py` — every commit since the last tag must carry a Conventional type, and the workspace version must derive from those types | runs after `static` and before `build`; the next version is a precondition for any release build, not a claim about the present tree |
| `gate-status` | 8 sub-checks (claim-vs-repository): `check-gate-status`, `check-project-identity`, `check-release-config`, `check-doc-claims`, distribution bundle, install path contract, plus their falsifiability suites and the `check-gate-status`/`release_config_drift`/`doc_claims_drift` re-runs | the falsifiability suite is what makes each guard a guard rather than a script |
| `test-counts` | `tests/test_counts_drift.py` — nine cases, eight of which must refuse | arithmetic of two logs the release certification produced |
| `build` | `cargo build --workspace --locked` | also produces the binaries the harness attacks |
| `test` | `cargo test --workspace --locked` | |
| `agent-contract` | the shape and meaning of the document an agent actually receives | goldens pin shape, property tests pin meaning |
| `distribution-channels` | two install paths produce the same bytes; refuses on tampered bundle and on bundle carrying a binary no component declares | |
| `skill-contract` | the published skill still describes this build | cross-repository; exits 77 to translate "no sibling checkout" into a skip, not a pass |
| `integration-uat033` | the M6 property against a real PostgreSQL | `ASV_UAT033_REQUIRE=1`, so a missing substrate is a failure, not a green skip |
| `adversarial` | the threat harness and its falsifiability suite | same stage on purpose: a harness that cannot fail is what the second command catches |
| `spec-integrity` | `sha256sum --check --strict SHA256SUMS` | |
| `spec-gates` | `tools/check-gates.py` | exit-code is the design: `return 1 if hard else 0`. Warnings are advisory; hard defects fail the run |
| `truthfulness` | the R0 exit gate, run on every change: `provenance_falsification`, `release_authority_drift`, `documented_install_drift`, `r0_gate_drift` | 45-min budget; `check-documented-install.py` and `r0_gate.py` are NOT here because they need a published release (R0.2b, R0.4b) |

`spec-gates` exits 0 when hard defects are 0, regardless of warnings. Warnings are
informative (UAT ids not declared in test file headers, milestones with no UAT id
in their exit block) and do not by themselves fail a run. Promoting them would
bury the real findings under defects nobody is fixing this week.

## Pre-push guard

`scripts/check-pre-push.sh` is the local hook that runs `cargo fmt --all -- --check`
and `python3 scripts/check-clippy-ratchet.py` before a push. It is **layered, not
redundant** with `static`:

- The hook runs *before* the commit leaves the machine, so a refused push never
  produces a remote-side fix-up.
- The pipeline catches what the hook missed (network race, a different machine
  that builds but this one does not, a stage that exists in the pipeline but is
  too expensive to run locally — `cargo test`, `cargo build`, the integration
  suites).
- The hook does not run `cargo audit` (the yank) because the operator may be on
  a machine without `cargo-audit` installed. The `static` stage's `if/else`
  is the gate that runs on a machine that has it.

Wire-up is documented in the script's header. The SDDK pre-push at
`~/.config/git/sddk-hooks/pre-push` calls `.git/hooks/pre-push.local` through its
legacy hook slot, so installing the hook as `.git/hooks/pre-push.local` keeps
both layers (SDDK ledger gate + fmt/clippy gate) active on every push.

## What changed in v0.38.0 and v1.0-PREP

The pipeline has grown from 8 stages to 14 since the v0.37.0 release. The
additions are not new authorities; they are scripts the repository already
shipped in `scripts/` but that nothing was calling:

- `release-law` (added in V1P-G1-T3) wires `check-release-bump.py` so a missed
  classification is caught before a release build, not during one.
- `gate-status` (pre-existing) was unchanged; the falsifiability suites
  `tests/{gate_status_drift,project_identity_drift,release_config_drift,
  doc_claims_drift}.py` were already in place.
- `static` (V1P-G1-T9) had a `(A && B) || C` line that swallowed every failure
  as the "not installed" branch. Replaced with `if/else` so a yank is a hard
  fail, not a false skip. Reproduced empirically; the receipt is
  `docs/receipts/v1-0-prep-pipeline-receipt.md` §4.1.
- `pipeline.release.kts` (V1P-G1-T3) gained a `test-counts` stage between
  `tag` and `build` that runs both profiles of `cargo test` and feeds the logs
  to `check-test-counts.py`. The V1-C0 rebaseline found a 174-test drift
  between docs and tree; this stage is the prevention.

## The spec pack was red here for three releases, and the cause was a stale manifest

`spec-integrity` failed on four entries from v0.17.1 onward, on hosted CI and
then here. All four were legitimate, reviewed changes that the manifest had
simply not caught up with:

- `adrs/README.md` → `adrs/adr-index.md`, renamed in `9997e2b` to fix a vault
  id collision (two files both deriving the node id `README`).
- Three documents edited in `33d8538` to correct a p95 budget that had been
  derived from debug-profile numbers, and in `04ae9a0` to add a gate-status
  table recording M11 and M12 as **NOT MET**.

The gate had worked correctly: it detected that the pack changed after the last
sign. The manifest was refreshed once each change had been traced to a commit
that states its rationale and whose figures agree with the code
(`P95_BUDGET_US = 6_000`, `MAX_BUDGET_MULTIPLE = 6.0`). Reverting those
documents to match a stale manifest would have undone a measured performance
fix and deleted a record of two unmet milestones — that is the corrupting
option, and it is the one that looks like rigor if you do not read what the
gate protects.

The refreshed manifest was mutation-tested rather than trusted: appending one
byte to `01-PRODUCT-SPEC.md` makes the check exit 1, and restoring it returns
exit 0. A re-signed manifest that accepts anything would pass its own check
and be worthless.

`docs/exploration/` is untracked in git and correctly outside the signed set;
the manifest's file set was verified to equal the pack's actual file set.
