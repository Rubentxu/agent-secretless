#!/usr/bin/env bash
# Install the broker as a systemd *user* service.
#
# This script deliberately downloads nothing and installs no binaries. It copies
# one file into place. The binaries come from whichever channel you used —
# mise, the release's own installer, or a `cargo install` — and the reason for
# the split is trust surface: a service installer is a thing a user runs again
# when a unit needs fixing, possibly months later, possibly on a machine where
# nobody is watching a download. Keeping it local means it cannot become a
# supply-chain path, and it means re-running it is always safe.
#
# It writes the unit and reloads systemd. It does NOT start the service,
# because a broker with no vault refuses to start, and a service that fails on
# first boot reads as a broken install rather than a not-yet-configured one.
# The exact commands to finish are printed at the end.
#
# Usage:
#   scripts/install-broker-service.sh              # install or update
#   scripts/install-broker-service.sh --uninstall  # remove the unit
#   scripts/install-broker-service.sh --print      # show the resolved unit

set -euo pipefail

UNIT_NAME="asv-brokerd.service"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/packaging/${UNIT_NAME}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_DEST="${UNIT_DIR}/${UNIT_NAME}"

VAULT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/asv"
VAULT_PATH="${VAULT_DIR}/vault.asv"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/asv"
PASSPHRASE_PATH="${CONFIG_DIR}/passphrase"

MODE="install"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall) MODE="uninstall"; shift ;;
    --print)     MODE="print"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$MODE" == "print" ]]; then
  exec cat "$UNIT_SRC"
fi

# --- preconditions -------------------------------------------------------
#
# Checked before anything is written, so a failure leaves the machine exactly
# as it was rather than half-installed.

if [[ "$(uname -s)" != "Linux" ]]; then
  cat >&2 <<EOF
install-broker-service: the broker is a Linux-only service.

It uses SO_PEERCRED, Landlock and seccomp, and the CLI does not compile off
Unix at all. A unit for another platform would install successfully and then
fail in a way that looks like a bug.
EOF
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "install-broker-service: systemctl not found. This script needs systemd." >&2
  exit 1
fi

if ! systemctl --user show-environment >/dev/null 2>&1; then
  cat >&2 <<EOF
install-broker-service: there is no systemd *user* session here.

A user manager is normally started by your login session. Over SSH without a
session, or in some container images, it is absent, and a user unit has
nowhere to live.

Check with:  systemctl --user status
If that fails, log in normally and re-run this script.
EOF
  exit 1
fi

# The private runtime's location comes from distribution/manifest.toml, which
# is the only place it is written down. `~/.local/bin` — where an earlier
# version of this script looked — is where the *public CLI* goes, and putting
# the secret-bearing process there is what UAT-DX-002 forbids.
BROKER_BIN="${HOME}/.local/libexec/asv/asv-brokerd"

if [[ ! -x "$BROKER_BIN" ]]; then
  cat >&2 <<EOF
install-broker-service: ${BROKER_BIN} is not installed.

The unit is written to run the broker from that path, which is where
distribution/manifest.toml installs the private runtime. Install the bundle
first, or edit ExecStart in ${UNIT_DEST} afterwards to point wherever you put
it. This script will not install binaries for you.
EOF
  # Not fatal: the unit is still useful to install, and the user may be about
  # to place the binary. Say it loudly and carry on rather than refusing.
fi

# --- act -----------------------------------------------------------------

if [[ "$MODE" == "uninstall" ]]; then
  if [[ -f "$UNIT_DEST" ]]; then
    systemctl --user disable --now "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_DEST"
    systemctl --user daemon-reload
    echo "removed ${UNIT_DEST}"
  else
    echo "no unit at ${UNIT_DEST}; nothing to remove"
  fi
  # The vault and the passphrase are deliberately left alone. They are the
  # user's data and may hold credentials this project cannot recreate.
  echo "left ${VAULT_PATH} and ${PASSPHRASE_PATH} untouched"
  exit 0
fi

if [[ ! -f "$UNIT_SRC" ]]; then
  echo "install-broker-service: cannot find ${UNIT_SRC}" >&2
  exit 1
fi

mkdir -p "$UNIT_DIR"

# Installed verbatim: the unit uses %h and %t specifiers, so the file in the
# repository is byte-for-byte the file that runs. Nothing rewrites it, so
# `systemctl --user cat` and this file can be diffed against each other.
install -m 0644 "$UNIT_SRC" "$UNIT_DEST"

# 0700: the broker refuses to bind into a directory anyone else can write, and
# the unit is a copy of that rule into the data directory.
mkdir -p "$VAULT_DIR" "$CONFIG_DIR"
chmod 0700 "$VAULT_DIR" "$CONFIG_DIR"

systemctl --user daemon-reload

cat <<EOF
installed ${UNIT_DEST}

Created (both 0700):
  ${VAULT_DIR}
  ${CONFIG_DIR}

The service is NOT started. A broker with no vault refuses to start, so
starting it now would fail in a way that reads as a broken install. Three
steps finish the setup:

  1. create a vault:
       asv-vault-tool create --vault ${VAULT_PATH} \\
         --passphrase "\$(head -c 24 /dev/urandom | base64 | tr -d '\\n')" --fast

  2. write that passphrase to a file the broker can read:
       install -m 0600 /dev/stdin ${PASSPHRASE_PATH}
     (the passphrase is never passed on a command line, by rule D9)

  3. start it:
       systemctl --user enable --now ${UNIT_NAME}
       systemctl --user status ${UNIT_NAME}

Then, from any shell in this session:
       asv status
EOF
