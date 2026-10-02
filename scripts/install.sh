#!/bin/sh
# The installer. Thin on purpose.
#
# `04-ADR-DISTRIBUTION.md` lists what an installer does; `scripts/install.py`
# does it. This file exists so there is one documented, stable entry point that
# a person can run and mise can call, and so the two do not drift into two
# installers.
#
# It resolves no platform, selects no release, verifies nothing and writes
# nothing. Everything of substance is in the Python file, because shell is the
# wrong place for checksum comparison and "is this archive the set of
# components we declared" — see §7 of the implementation guide.
#
# What it deliberately does NOT do, and cannot:
#
#   * it does not build. There is no toolchain invocation on any path here or
#     in install.py, and tests/distribution_channels.py fails if the word
#     `cargo` appears in either file outside a comment. "Never compiles Rust on
#     the target machine" is a property here, not a promise.
#   * it does not create the vault, the passphrase or the service. That is
#     `asv setup`, which is idempotent and already tested. A second
#     implementation of the passphrase path would be a second security-relevant
#     code path.
#
# Usage:
#   scripts/install.sh --version 0.25.0 --prefix "$HOME/.local"
#   mise use -g agent-secretless        # routes to packaging/mise/install.sh

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to install agent-secretless" >&2
    echo "       the installer is a thin wrapper; it is python3 that verifies" >&2
    exit 1
fi

exec python3 "$here/install.py" "$@"
