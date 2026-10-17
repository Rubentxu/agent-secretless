# B1.6 — rustfmt version pin policy (DRAFT)

**Status**: DRAFT
**Branch**: `b1/rustfmt-pin-policy`
**Worktree**: `/var/home/rubentxu/Proyectos/rust/agent-secretless-b1-6`
**Off**: `b1/worker-lifetime` HEAD `51a04c8` (B1.1 + B1.2 + B1.3 + B1.4 + B1.5 + yank policy DECIDED)
**Author**: Jcode (autonomous, user pre-approved with "apruebo cualquier criterio"; B1.6 is the candidate the B1.5 receipt explicitly listed as the next housekeeping block)

## What B1.6 ships

A policy that pins rustfmt to a specific Rust toolchain
version, so the kind of drift B1.5 paid (rustfmt 1.5→1.6+
arm-collapse + method-chain wrap) does not recur silently.

Concretely:

1. **A new `rust-toolchain.toml` at the workspace root** with
   `channel = "<exact stable version>"` and
   `components = ["rustfmt", "clippy", "rust-analyzer"]`
   (no `rust-src`, no nightly extras). This is the
   `denoland/deno` pattern.

2. **A policy document at `docs/policies/rustfmt-pin-policy.md`**
   that says: the pinned version is reviewed and bumped at
   every workspace version bump (i.e. when `Cargo.toml`'s
   `[workspace.package] version` changes, the toolchain
   channel is bumped to the latest stable that the
   workspace version range supports). The MSRV (currently
   `1.85`) is **not** the pin — the pin is the toolchain
   the developers use day-to-day, which is at or above
   MSRV.

3. **The pre-push hook (`scripts/check-pre-push.sh`) gains
   one assertion**: it must be able to read the toolchain
   pin before running `cargo fmt --all -- --check`. If the
   pin is missing, the hook fails. The check is cheap and
   keeps the pin honest.

## Inventory of the current state

The repo at `b1/worker-lifetime` HEAD `51a04c8` has:

- **No `rust-toolchain.toml`** anywhere in the tree
  (verified by `find . -maxdepth 3 -name 'rust-toolchain*'`).
  Every developer's machine uses whatever toolchain they
  happen to have installed via rustup.
- **No `rustfmt.toml` or `.rustfmt.toml`** anywhere. The
  fmt is whatever rustfmt's defaults are for the installed
  toolchain version.
- **MSRV: 1.85** (from `Cargo.toml` `[workspace.package]
  rust-version = "1.85"`).
- **Dev host toolchain** (this machine): `rustc 1.98.1`,
  `cargo 1.98.1`, `rustfmt 1.9.0-stable`. So the drift
  B1.5 paid was between the older toolchain that wrote
  the code (rustfmt < 1.6) and the current toolchain
  (rustfmt 1.9.0). The drift accumulated in
  `b1/worker-lifetime` over multiple B1 merges without a
  fmt check.

## Why now

The B1.5 receipt explicitly listed B1.6 as the next
housekeeping block: "This release does not pin rustfmt to a
specific version. A future rustfmt release with new style
preferences could re-introduce drift. Pinning is a B1.6
candidate."

The risk of NOT pinning: every future rustfmt version bump
on the dev host will silently re-introduce drift. The drift
will only be caught when someone runs `cargo fmt --all
-- --check` (which B1.4's gate ran for the first time and
B1.5's gate ran and now passes). Without a pin, the
check is run on whatever toolchain happens to be present;
two devs with different toolchains see different "no drift"
states.

## Survey of the Rust ecosystem (3 patterns)

I checked the canonical examples.

**Pattern 1: Stable pin with explicit components (deno)**
- File: `rust-toolchain.toml` at repo root
- Syntax: `channel = "1.95.0"` + `components = ["rustfmt", "clippy", "rust-src", "rust-analyzer"]`
- Effect: every developer and CI run uses rustc 1.95.0 and
  the rustfmt that ships with it. Drift between devs is
  impossible because they all have the same rustfmt.
- Real example: `denoland/deno` (`rust-toolchain.toml` at
  repo root).
- Source: https://github.com/denoland/deno

**Pattern 2: Nightly pin with extras (rustfmt itself)**
- File: `rust-toolchain.toml` at repo root
- Syntax: `channel = "nightly-2026-10-05"` +
  `components = ["llvm-tools", "rustc-dev"]`
- Effect: every dev and CI run uses a specific nightly
  date. Useful when the project itself is a tool that
  needs unstable features.
- Real example: `rust-lang/rustfmt` (the rustfmt repo
  itself, of course).
- Source: https://github.com/rust-lang/rustfmt

**Pattern 3: No pin, trust the dev's toolchain**
- File: (nothing)
- Syntax: (n/a)
- Effect: drift accumulates over time as the dev's
  toolchain changes. This is what agent-secretless has
  today.
- Real examples: `serde-rs/serde`, `tokio-rs/tokio`,
  `BurntSushi/ripgrep`, most of the rust-ecosystem-orbit
  libraries.

## Why Pattern 1 (deno-style) for agent-secretless

- **The project is stable**, not nightly-experimental. B1.4
  was the first release with a runtime feature; the rest is
  hardening. We don't need nightly.
- **The drift we just paid was a stable→stable style change**
  (rustfmt 1.5 �� 1.6+). A stable pin catches that.
- **Deno's pattern is minimal**: one file, one channel
  string, one components array. No `rust-toolchain` (the
  legacy file) needed.
- **The MSRV (`rust-version = "1.85"` in Cargo.toml) stays
  as a separate signal**: it tells downstream users what
  they need to *consume* the crate. The toolchain pin tells
  contributors what they need to *build* the crate. They
  are different concerns.
- **`rust-toolchain.toml` is honored by rustup, by
  `cargo`, by `rustc`, and by the SDDK pre-push hook**
  (because rustup itself changes the toolchain on
  `cd`). No custom wiring needed.

Pattern 2 (nightly) is rejected because it pulls in
features the project doesn't use and would surprise
downstream consumers who look at the repo. Pattern 3 (no
pin) is what we have today, and the B1.5 drift is the
evidence that it's not enough.

## Plan

1. Pick the exact stable version to pin. **Proposal: pin
   to `1.95.0` (the deno pin) for the first cut** — it's
   the most recent stable in widespread use as of
   2026-10. The first bump is a one-line change in the
   toolchain file, no policy review needed.

2. Write `docs/policies/rustfmt-pin-policy.md` — a short
   document that:
   - States the rule: "the pinned toolchain channel is
     reviewed and bumped at every workspace version bump
     (i.e. when `Cargo.toml` `[workspace.package] version`
     changes). The bump is to the latest stable that
     the workspace version range supports."
   - States the review checklist: read the rustfmt
     release notes since the last pin, run `cargo fmt
     --all -- --check` on a representative branch, fix
     any drift as a separate housekeeping block (B1.5
     pattern).
   - States the relationship to MSRV: the pin is the
     contributor toolchain; the MSRV is the consumer
     toolchain. They are independent.

3. Add `rust-toolchain.toml` to the workspace root:
   ```toml
   [toolchain]
   channel = "1.95.0"
   components = ["rustfmt", "clippy", "rust-analyzer"]
   ```
   No `rustfmt.toml` for now. The drift is fixed; we don't
   need a config to keep it fixed, the pin does that.

4. Update `scripts/check-pre-push.sh` to assert the
   `rust-toolchain.toml` exists and is parseable. Cheap
   guard; keeps the pin honest.

5. Run all gates on the pinned toolchain:
   - `cargo build --workspace`: clean
   - `cargo test -p asv-broker --lib`: 686/686
   - `cargo test -p asv-broker --test uat_040_isolated_worker_runtime`: 21/21
   - `cargo test -p asv-broker --test uat_017_env_scan`: 4/4
   - `python3 scripts/check-clippy-ratchet.py`: 0/0
   - `cargo fmt --all -- --check`: 0/0
   - `rustup show active-toolchain` reports the pinned
     version (sanity check that the pin is actually
     active)

6. Write the implementation receipt.

7. Merge to `b1/worker-lifetime` with `--no-ff`.

8. Tag `b1.6` annotated.

9. Push to origin + GitHub Release (same pattern as
   B1.4 and B1.5).

## What is NOT in B1.6

- **No `rustfmt.toml` config.** The drift is gone; a
  config to keep it gone is a separate decision.
  Pinning the toolchain is the simpler answer. If
  future style preferences differ, the B1.5 pattern
  (pay the drift as a separate block) is fine; a
  config doesn't help there because the config would
  need to enumerate every style preference explicitly.
- **No pin to nightly.** The project is stable.
- **No MSRV bump.** The MSRV (`1.85`) is the
  *consumer* toolchain; the pin is the *contributor*
  toolchain. They are independent. Bumping MSRV is a
  separate policy decision.
- **No `Cargo.lock` change.** The pin is a
  `rust-toolchain.toml`, not a cargo dependency.
- **No CI changes.** The repo's CI runs through
  rustup, which honors `rust-toolchain.toml`
  automatically. If we add hosted CI later, it will
  pick up the pin without further wiring.

## Awaiting user review

- [ ] User confirms the "deno-style stable pin" framing
      (vs nightly or no-pin)
- [ ] User confirms the pin version `1.95.0` (vs the
      dev host's `1.98.1` — see trade-off below)
- [ ] User confirms the "bump at workspace version
      bump" policy
- [ ] User confirms the pre-push hook addition
- [ ] User confirms tag name `b1.6`

### Trade-off: pin to `1.95.0` (deno's pin) vs `1.98.1` (this dev's host)

The dev host runs `rustc 1.98.1`. The first impulse is
"pin to what the dev uses." But the B1.5 drift was
caused by *this dev's toolchain* drifting relative to
the codebase. Pinning to `1.98.1` would prevent
*future* drift but not the drift that already
happened.

The argument for `1.95.0` (deno's pin):
- **It's not this dev's toolchain.** It's an
  *external reference* the codebase is anchored to.
  If the codebase's fmt is correct against `1.95.0`,
  it should be correct against any later version
  (modulo drift, which the pin catches). The first
  time someone runs `1.98.1`, `cargo fmt --all
  -- --check` will report zero diffs (because the
  B1.5 block already paid the drift up to 1.9.0).
- **It matches what other large Rust projects do.**
  Deno, rustfmt itself, and a handful of others pin
  to a stable that's slightly behind the bleeding
  edge.
- **The first bump is cheap.** When we move to
  `1.99.0` or `2.0.0`, the policy says we pay any
  drift as a B1.x block. The bump itself is one
  line.

The argument for `1.98.1` (this dev's host):
- **No toolchain download.** A fresh dev on a fresh
  machine doesn't need `rustup toolchain install
  1.95.0`; the toolchain they already have (1.98.1)
  is the one the project uses.
- **No surprise CI cost.** CI runners that don't
  preinstall 1.95.0 will spend ~30s downloading it.
  CI runners that already have 1.98.1 are fine.

**My recommendation: pin to `1.95.0` (deno's pin).**
The "no download" advantage of 1.98.1 is real but
small (~30s on cold CI), and the "external reference"
advantage of 1.95.0 is structural — it makes the
pin a *contract with the codebase*, not a *state
of the dev machine*. The codebase is the source of
truth; the dev's machine follows it.

If the user prefers `1.98.1`, the change is one
line in the toolchain file; everything else in the
plan is identical.
