#!/bin/sh
# The step mise runs. It is the same installer, told who it is.
#
# `09-IMPLEMENTATION-GUIDE.md` §8: "Mise debe instalar el mismo bundle
# producido por release. No crear otro sistema de packaging." The way to
# honour that is to have exactly one installer and pass it a different
# `--installed-via`. A second mise-specific downloader would be a second
# packaging system wearing mise's name, and the two would disagree about
# version selection the first time a release was yanked from one.
#
# The only thing this file adds is the identity it writes into the install
# record, and the fact that it fails when the shared installer is missing
# rather than falling back to something of its own.
#
# mise invokes an install step with the destination as the last argument and
# the requested version in MISE_PLUGIN_VERSION, so the two are translated here
# rather than in the shared code, which has no reason to know about mise.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

installer="$repo/scripts/install.py"
if [ ! -f "$installer" ]; then
    echo "error: the shared installer is missing at $installer" >&2
    echo "       mise installs the same bundle as scripts/install.sh; there is" >&2
    echo "       no second packaging path, so this is fatal rather than a fallback" >&2
    exit 1
fi

version=${MISE_PLUGIN_VERSION:-}
if [ -z "$version" ]; then
    echo "error: MISE_PLUGIN_VERSION is not set; mise must say which version" >&2
    echo "       it wants, so the install record can name it" >&2
    exit 1
fi

prefix=${1:-}
# `$1` has been consumed as the destination. Without this shift it is still in
# "$@" below and reaches the installer as a stray positional argument, which
# argparse rejects — so the step would fail for a reason that has nothing to
# do with mise, and the failure would be read as a broken release.
if [ "$#" -gt 0 ]; then
    shift
fi

exec python3 "$installer" \
    --version "$version" \
    --prefix "$prefix" \
    --installed-via mise \
    "$@"
