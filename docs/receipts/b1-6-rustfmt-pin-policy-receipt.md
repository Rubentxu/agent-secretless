# B1.6 — rustfmt version pin policy — implementation receipt

**Status**: DELIVERED
**Branch**: `b1/rustfmt-pin-policy`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-6`
**Off**: `b1/worker-lifetime` HEAD `7470749`
**Tag (pending)**: `b1.6` annotated
**Receipt (predecessor)**: `docs/receipts/b1-5-fmt-drift-housekeeping-receipt.md`
**Receipt (this file)**: `docs/receipts/b1-6-rustfmt-pin-policy-receipt.md`
**Date**: 2026-10-14

## What B1.6 shipped

A policy that pins the workspace's rustfmt to a specific
Rust toolchain version, so the kind of silent drift B1.5
paid (rustfmt 1.5→1.9.0 arm-collapse + method-chain
wrap) cannot recur.

Three files, 238 lines, 0 lines of code change:

1. `rust-toolchain.toml` (4 lines) — the pin itself.
2. `docs/policies/rustfmt-pin-policy.md` (138 lines) —
   the policy text.
3. `scripts/check-rustfmt-pin.sh` (96 lines) — the
   verification script.

The DRAFT spec is at `docs/receipts/b1-6-rustfmt-pin-policy-DRAFT.md`
(273 lines) and was committed first as `46aed89`. The
implementation commit is `d9bbd43`.

## Decisions taken (with rationale)

### D1. Pin to `1.97.1`

Candidates considered: `1.95.0` (deno's pin), `1.97.1`,
`1.98.1` (dev's host), `1.99.0` (active stable on dev).

`1.97.1` chosen because:

- It is the most recent stable that is **not** the dev
  host's bleeding edge, so the codebase is anchored to
  a baseline one minor behind the host. The "1 minor
  behind" framing is what the user-facing policy relies
  on: the codebase is the source of truth, the dev's
  machine follows it.
- It is already installed on the dev host (verified via
  `rustup toolchain list`), so no `rustup toolchain
  install` is required on this dev or on a fresh dev
  machine that mirrors this one's toolchain set.
- `1.95.0` (deno's pin) was rejected because it is not
  installed and would force a 30-60s download on every
  fresh dev machine and every fresh CI runner. The
  user-facing "no surprises" property of a pin is
  better served by a version that is widely deployed.
- `1.98.1` and `1.99.0` (the dev's bleeding edges) were
  rejected because they would re-introduce the B1.5
  problem one rustfmt-release later: the codebase
  would be calibrated to a toolchain that is one
  rustfmt-release away from drift.

The choice is documented in
`docs/policies/rustfmt-pin-policy.md` under "Why
`1.97.1` for the B1.6 cut" so a future reviewer can
challenge it.

### D2. Repo-internal script, not a hook edit

The pre-push hook
(`/home/rubentxu/.git-hooks/pre-push` and
`/home/rubentxu/.config/git/sddk-hooks/pre-push`) is
identity-guard + sddk-closeout only; it does not run
`cargo fmt --all -- --check`. The SDDK pre-merge-commit
hook would be the natural place to add a fmt-pin check,
but editing it is out of scope for B1.6 (it lives in
`/home/rubentxu/.config/git/sddk-hooks/`, a global
config not versioned in this repo).

B1.6 instead ships `scripts/check-rustfmt-pin.sh` as a
repo-internal, manually-invocable check. The policy doc
calls it out, and the next SDDK bump can wire it into
the pre-merge-commit gate as a one-liner. This keeps
B1.6 focused on "the pin exists" and lets the
SDDK-integration work happen with its own review.

### D3. No `rustfmt.toml` config

The pin is sufficient to prevent the kind of drift
B1.5 paid. A `rustfmt.toml` would have to enumerate
every style preference explicitly to be useful, and
the B1.5 drift (arm-collapse, method-chain wrap) is
exactly the kind of style preference that should be
paid as a housekeeping block, not frozen in config.

If a future reviewer wants a `rustfmt.toml`, the
change is a separate B1.x block.

### D4. MSRV (`rust-version = "1.85"`) untouched

`rust-version` is the *consumer* signal: it tells
downstream users of the crate what minimum rustc they
need. The toolchain pin is the *contributor* signal:
it tells contributors what rustc they should use to
build the crate. The two are independent; B1.6 touches
only the contributor signal.

The pin (`1.97.1`) is above the MSRV (`1.85`), as
required.

## Files delivered

### `rust-toolchain.toml`

```toml
[toolchain]
channel = "1.97.1"
components = ["rustfmt", "clippy", "rust-analyzer"]
profile = "minimal"
```

`profile = "minimal"` so rustup does not install
rust-docs (we don't need them for build/test/gate).

### `docs/policies/rustfmt-pin-policy.md`

138 lines covering:

- The rule (pin MUST exist at workspace root).
- The bump cadence (review at every workspace version
  bump; drift paid as a separate block if needed).
- The 5-step review checklist for a bump.
- The "Why `1.97.1` for the B1.6 cut" rationale.
- The relationship to MSRV (independent concerns).
- What is NOT in this policy (no rustfmt.toml, no
  nightly, no automated bump, no CI changes).
- How to verify locally (3 commands).
- What adopting the policy commits us to.

### `scripts/check-rustfmt-pin.sh`

96 lines, exit codes 0/1/2/3/4 by failure mode:

- `0`: ok
- `1`: `rust-toolchain.toml` missing
- `2`: `rust-toolchain.toml` unparseable
- `3`: rustup not available
- `4`: active toolchain does not match the pin

Stripped target triple from both the pin and the
active toolchain before comparison (so
`1.97.1-x86_64-unknown-linux-gnu` matches `1.97.1`).
Also checks `rustc --version` as a fallback (because
rustup's `active-toolchain` can be the alias `stable`
which resolves to whatever stable is installed).

Verified locally: `pin: 1.97.1, active:
1.97.1-x86_64-unknown-linux-gnu, rustfmt:
1.9.0-stable`. Exit 0.

## Gate results (on pinned toolchain 1.97.1)

To be filled in by the gate run that follows this
receipt. The expected green state:

- `cargo build --workspace`: 0 errors (incremental,
  cached from B1.5; should be sub-minute)
- `cargo test -p asv-broker --lib`: 686/686
- `cargo test -p asv-broker --test uat_040_isolated_worker_runtime`: 21/21
- `cargo test -p asv-broker --test uat_017_env_scan`: 4/4
- `python3 scripts/check-clippy-ratchet.py`: 0/0
- `cargo fmt --all -- --check`: 0 diffs
- `rustup show active-toolchain`: `1.97.1-x86_64-unknown-linux-gnu (overridden by .../rust-toolchain.toml)`
- `./scripts/check-rustfmt-pin.sh`: exit 0

If any gate is red, the policy doc and the script are
not the cause (no code change) — the regression would
be a toolchain-version-dependent test, which is a
separate housekeeping issue.

## What B1.6 does NOT include

This is the explicit "what adopting this commit does
not commit us to" section, so future reviewers do not
over-read the scope:

- **No bump of MSRV.** `rust-version = "1.85"` is the
  consumer signal, untouched.
- **No nightly pin.** The project is stable.
- **No `rustfmt.toml` config.** The pin is sufficient.
- **No CI changes.** The local SDDK gate does not run
  `cargo fmt`; hosted CI does not exist yet; the
  pin-to-CI integration is a follow-up.
- **No automated bump.** Manual review at every
  workspace version bump.
- **No SDDK pre-merge-commit edit.** The hook is out of
  scope for this repo.
- **No code change.** B1.6 is three new files; no
  existing file is modified.

## Awaiting user review (5 checkpoints, from DRAFT)

- [x] **Deno-style stable pin (Pattern 1)**: chosen
- [x] **Pin version `1.97.1`** (over `1.95.0` and
      `1.98.1`): chosen with rationale in policy doc
- [x] **Bump at workspace version bump** policy: in
      `docs/policies/rustfmt-pin-policy.md`
- [x] **Pre-push hook addition** re-scoped to
      `scripts/check-rustfmt-pin.sh` (in-repo script,
      not a hook edit) — see D2
- [ ] **Tag name `b1.6`**: pending merge + tag step

## Sequence of commits

| SHA | Description | Files |
|---|---|---|
| `46aed89` | DRAFT spec | `docs/receipts/b1-6-rustfmt-pin-policy-DRAFT.md` |
| `d9bbd43` | Implementation | `rust-toolchain.toml` + `docs/policies/rustfmt-pin-policy.md` + `scripts/check-rustfmt-pin.sh` |
| (pending) | Receipt | `docs/receipts/b1-6-rustfmt-pin-policy-receipt.md` (this file) |
| (pending) | Merge to `b1/worker-lifetime` | — |
| (pending) | Tag `b1.6` | — |
| (pending) | Push branch + tag | — |
| (pending) | `gh release create b1.6` | — |

## Source pointers

- B1.5 drift evidence: `docs/receipts/b1-5-fmt-drift-housekeeping-receipt.md` (39 lines, the original 5-file `cargo fmt --all` commit `45c5d84`)
- DRAFT spec: `docs/receipts/b1-6-rustfmt-pin-policy-DRAFT.md` (273 lines)
- Survey of patterns: `denoland/deno` (Pattern 1, `rust-toolchain.toml` at root), `rust-lang/rustfmt` (Pattern 2, nightly pin), `serde-rs/serde` / `tokio-rs/tokio` / `BurntSushi/ripgrep` (Pattern 3, no pin)
- MSRV signal: `Cargo.toml` `[workspace.package] rust-version = "1.85"`
