#!/usr/bin/env bash
# scripts/check-rustfmt-pin.sh
#
# Verifies that the workspace's rust-toolchain.toml is
# present, parseable, and that rustup has activated the
# pinned toolchain.
#
# Exit codes:
#   0  ok
#   1  rust-toolchain.toml missing
#   2  rust-toolchain.toml unparseable
#   3  rustup not available
#   4  active toolchain does not match the pin
#
# Usage: ./scripts/check-rustfmt-pin.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PIN_FILE="$ROOT/rust-toolchain.toml"

# 1. file exists
if [[ ! -f "$PIN_FILE" ]]; then
  echo "❌ $PIN_FILE not found." >&2
  echo "   The workspace's rustfmt pin policy requires a" >&2
  echo "   rust-toolchain.toml at the workspace root." >&2
  echo "   See docs/policies/rustfmt-pin-policy.md." >&2
  exit 1
fi

# 2. parse the channel (no full TOML parser; this is a
#    one-key file. If we add a targets= or profile= field
#    the parse stays the same.)
PIN_CHANNEL="$(grep -E '^channel\s*=' "$PIN_FILE" \
  | head -1 \
  | sed -E 's/^channel\s*=\s*"?([^"]+)"?\s*$/\1/' \
  | tr -d '[:space:]')"
if [[ -z "$PIN_CHANNEL" ]]; then
  echo "❌ $PIN_FILE: cannot parse 'channel' field." >&2
  echo "   Expected: channel = \"<version>\"" >&2
  exit 2
fi

# 3. rustup is available
if ! command -v rustup >/dev/null 2>&1; then
  echo "❌ rustup not on PATH; cannot verify active toolchain." >&2
  echo "   Install rustup and re-run, or activate the toolchain" >&2
  echo "   manually and re-run." >&2
  exit 3
fi

# 4. active toolchain matches the pin
ACTIVE="$(rustup show active-toolchain 2>/dev/null \
  | awk '{print $1}' \
  | tr -d '[:space:]')"
if [[ -z "$ACTIVE" ]]; then
  echo "❌ rustup show active-toolchain returned empty." >&2
  exit 3
fi

# Normalise: "stable-x86_64-unknown-linux-gnu" → "stable"
# Normalise: "1.97.1-x86_64-unknown-linux-gnu" → "1.97.1"
# Normalise: "nightly-2026-10-05-x86_64-..." → "nightly-2026-10-05"
ACTIVE_BARE="$(echo "$ACTIVE" \
  | sed -E 's/-x86_64-unknown-linux-gnu$//' \
  | sed -E 's/-x86_64-apple-darwin$//' \
  | sed -E 's/-x86_64-pc-windows-msvc$//')"
PIN_BARE="$(echo "$PIN_CHANNEL" \
  | sed -E 's/-x86_64-unknown-linux-gnu$//' \
  | sed -E 's/-x86_64-apple-darwin$//' \
  | sed -E 's/-x86_64-pc-windows-msvc$//')"

# The alias "stable" resolves to whatever stable is
# installed; only accept it if it equals the pin or if
# the pin is itself "stable".
if [[ "$ACTIVE_BARE" != "$PIN_BARE" ]]; then
  # Check if rustc --version matches
  RUSTC_VER="$(rustc --version 2>/dev/null \
    | awk '{print $2}' \
    | tr -d '[:space:]')"
  if [[ "$RUSTC_VER" != "$PIN_BARE" ]]; then
    echo "❌ active toolchain does not match the pin." >&2
    echo "   pin:    $PIN_BARE  (from $PIN_FILE)" >&2
    echo "   active: $ACTIVE  (rustc $RUSTC_VER)" >&2
    echo "   Run: rustup toolchain install $PIN_BARE" >&2
    echo "   or:  cd into the repo (rustup will activate it)" >&2
    exit 4
  fi
fi

echo "✓ rustfmt pin ok"
echo "  pin:    $PIN_BARE  (from rust-toolchain.toml)"
echo "  active: $ACTIVE  (rustc $(rustc --version | awk '{print $2}'))"
echo "  rustfmt: $(rustfmt --version 2>/dev/null | awk '{print $2}')"
exit 0
