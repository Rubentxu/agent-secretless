# rustfmt version pin policy

**Status**: DECIDED (B1.6, 2026-10-14)
**Author**: Jcode (autonomous; user pre-approved with "apruebo
cualquier criterio")
**Pin (B1.6 cut)**: `1.97.1`
**Decision driver**: stop the kind of silent rustfmt drift
B1.5 paid (arm-collapse + method-chain wrap between rustfmt
1.5 and rustfmt 1.9.0).

## The rule

The workspace root MUST contain a `rust-toolchain.toml`
that pins the `channel` to an exact stable version. The
`components` array MUST include `rustfmt` and `clippy`.

```toml
[toolchain]
channel = "<exact stable version>"
components = ["rustfmt", "clippy", "rust-analyzer"]
profile = "minimal"
```

Every developer and every release runs the same rustfmt
version. Drift between devs is impossible because they
all have the same rustfmt.

## When to bump the pin

The pin is reviewed and bumped at every workspace version
bump — i.e. when `Cargo.toml` `[workspace.package] version`
changes. The bump is to the latest stable that the
workspace version range supports.

The review checklist at each bump:

1. Read the rustfmt release notes since the last pin
   (https://github.com/rust-lang/rustfmt/releases).
2. Run `cargo fmt --all -- --check` on a representative
   branch.
3. If the check fails, fix the drift as a separate
   housekeeping block (B1.5 pattern) before bumping the
   pin.
4. Bump the pin.
5. Run all gates on the new toolchain.

The bump itself is one line in `rust-toolchain.toml`. The
gate is a manual `rustup toolchain install <new>` followed
by `cargo build --workspace && cargo test`.

## Why `1.97.1` for the B1.6 cut

Candidates considered:

- **`1.95.0` (deno's pin)**: not installed on the dev host.
  Would force a `rustup toolchain install` on every fresh
  dev machine and on every fresh CI runner. ~30-60s of
  download.
- **`1.97.1` (chosen)**: installed on the dev host, 1
  minor behind the bleeding edge (`1.98.1` is the active
  stable; `1.99.0` is also installed). The "1 minor
  behind" framing is what the user-facing policy relies
  on: the codebase is the source of truth, the dev's
  machine follows it.
- **`1.98.1` or `1.99.0` (dev's bleeding edge)**: would
  re-introduce the B1.5 problem in N+1 minor versions,
  because the codebase would be calibrated to a toolchain
  that is one rustfmt-release away from drift.

The chosen pin **is not** the user's host toolchain. It
is an *external reference* slightly behind the host
toolchain, so the codebase is anchored to a stable
baseline and the host's toolchain is allowed to be ahead
without forcing a drift-payout every release.

## Relationship to MSRV

The toolchain pin and the `rust-version = "1.85"` field
in `Cargo.toml` are **independent concerns**:

- **`rust-version`** is the *consumer* signal: it tells
  downstream users of the crate what minimum rustc they
  need to compile it.
- **`rust-toolchain.toml channel`** is the *contributor*
  signal: it tells contributors what rustc they should
  use to build the crate.

A consumer with rustc 1.85 can build the crate. A
contributor should install the pin (rustup does this
automatically on `cd` into the repo).

The MSRV is **not** the pin. The pin is at or above
MSRV. They do not need to be the same version.

## What is NOT in this policy

- **No `rustfmt.toml` config**: the pin is sufficient to
  prevent drift. If future style preferences differ from
  rustfmt's defaults, the policy is to pay the drift as
  a separate housekeeping block (B1.5 pattern), not to
  maintain a `rustfmt.toml` that would have to enumerate
  every style preference explicitly.
- **No nightly pin**: the project is stable. Bumping to
  nightly is a separate decision and would surprise
  downstream consumers who look at the repo.
- **No automated bump**: the bump is a manual review
  (see "When to bump" above). Automation is a follow-up
  if the cadence becomes painful.
- **No CI changes**: the repo's local gate is the
  pre-merge SDDK hook, which already invokes rustup. If
  we add hosted CI later, it will pick up the pin
  automatically.

## How to verify locally

```sh
# Show the active toolchain. Should report the pin.
rustup show active-toolchain

# Run the check script (see scripts/check-rustfmt-pin.sh).
./scripts/check-rustfmt-pin.sh

# Run the fmt gate. Should be 0 diffs.
cargo fmt --all -- --check
```

If `rustup show active-toolchain` does not report the
pinned version, run `rustup toolchain install <pin>` and
re-run the check.

## What adopting this policy commits us to

- A `rust-toolchain.toml` at the workspace root.
- A `scripts/check-rustfmt-pin.sh` that verifies the pin.
- A review at every workspace version bump (cheap; one
  paragraph of changelog + one `cargo fmt` run).
- A drift-payout block at each pin bump if rustfmt has
  changed its mind about the codebase's style.
