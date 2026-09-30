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
| `static` | `cargo fmt`, `cargo clippy -D warnings` | |
| `build` | `cargo build --workspace --locked` | also produces the binaries the harness attacks |
| `test` | `cargo test --workspace --locked` | |
| `integration-uat033` | the M6 property against a real PostgreSQL | `ASV_UAT033_REQUIRE=1`, so a missing substrate is a failure, not a green skip |
| `adversarial` | the threat harness and its falsifiability suite | same stage on purpose: a harness that cannot fail is what the second command catches |
| `spec-integrity` | `sha256sum --check --strict SHA256SUMS` | |
| `spec-gates` | `tools/check-gates.py` | advisory, as it was in the workflow it replaces |

`spec-gates` stays advisory deliberately. It reports known roadmap UAT
gate-map defects that are tracked in the backlog, and the workflow that defined
it recorded the exit code rather than enforcing it. Promoting it would bury the
real findings under a defect nobody is fixing this week.

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
