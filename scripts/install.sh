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

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to install agent-secretless" >&2
    echo "       the installer is a thin wrapper; it is python3 that verifies" >&2
    exit 1
fi

# Where this repository lives on the raw host.
#
# It is the one thing in this file that is not passed in, and it is checked
# against `DEFAULT_BASE_URL` in `install.py` by `scripts/check-release-config.py`,
# because two spellings of the same repository is two places to forget.
RAW_BASE="https://raw.githubusercontent.com/Rubentxu/agent-secretless"

# Two ways to arrive here, and neither falls back into the other.
#
# `$0` names a file: run the install.py beside it. That is `./scripts/install.sh`,
# `packaging/mise/install.sh`, and the release job.
#
# `$0` does not name a file: this is the piped case. A script read from stdin has
# `$0` set to the *shell*, so `dirname -- "$0"` is `.` — the directory the user
# happened to be standing in. This file resolved install.py that way for its
# whole life, so every piped run looked for `$PWD/install.py`, found nothing and
# exited 2. `./scripts/install.sh` kept working, which is exactly why it went on
# working unnoticed: the path that works is not the path anyone is told to use.
#
# In the piped case there is no sibling, so install.py is fetched from the tag
# matching `--version`. That is the trust decision the pipe already made — this
# file was itself downloaded over TLS before it had a say — with one improvement:
# the installer and the artefacts it installs come from a single pinned tag
# rather than from `main` and a release independently.
#
# What this does NOT do is verify anything. `install.py` requires the release
# signature before it reads `sha256.sum`, and that is what makes the bytes it
# fetches checkable. This wrapper is not part of that chain and must not be
# described as if it were.
if [ -f "$0" ]; then
    here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ -f "$here/install.py" ]; then
        exec python3 "$here/install.py" "$@"
    fi
    echo "error: there is no install.py beside this script." >&2
    echo "       looked for: $here/install.py" >&2
    echo "       This wrapper works from a checkout, or piped, where it fetches" >&2
    echo "       install.py from the release tag. Run it one of those two ways." >&2
    exit 1
fi

# `--version` is required by install.py, so it is guaranteed to be there; this
# only has to find it to know which tag to pin. Both spellings argparse accepts
# are handled, because reading only one of them is a bug that waits for someone
# to type the other.
version=""
prev=""
for arg in "$@"; do
    case "$prev" in
        --version) version="$arg" ;;
    esac
    case "$arg" in
        --version=*) version="${arg#--version=}" ;;
    esac
    prev="$arg"
done

if [ -z "$version" ]; then
    echo "error: no --version given, and this script was piped, so install.py" >&2
    echo "       has to be fetched from a tag this needs to name." >&2
    echo "       Use the documented command:" >&2
    echo "         curl -LsSf $RAW_BASE/main/scripts/install.sh \\" >&2
    echo "           | sh -s -- --version X.Y.Z --prefix \"\$HOME/.local\"" >&2
    exit 1
fi

workdir=$(mktemp -d) || exit 1
cleanup() {
    rm -f "$workdir/install.py" && rmdir "$workdir"
}
trap cleanup EXIT HUP INT TERM

url="$RAW_BASE/v$version/scripts/install.py"
if ! curl -LsSf "$url" -o "$workdir/install.py"; then
    echo "error: could not fetch $url" >&2
    echo "       install.py is not one of the release assets — the release ships" >&2
    echo "       the bundle, its checksums and the signed authority. The installer" >&2
    echo "       itself is fetched from the tag, so it matches what it installs." >&2
    exit 1
fi

python3 "$workdir/install.py" "$@"
