#!/usr/bin/env bash
# Disposable PostgreSQL substrate for the UAT-033 live suites.
#
# `uat033_broker.rs` and `uat033_live.rs` prove the M6 property against a real
# server: the broker reaches PostgreSQL with a brokered password, and the
# policy gate denies a statement before it lands. Neither can prove that
# without a server, so both fall back to a skip that prints `ok` and passes.
#
# That is not a harmless default. A real authorization bypass shipped through
# this gap once: `pg_policy::classify` called `SELECT ... INTO` a read, the
# read-only policy permitted it, a table was created on a real server, and
# every test in the workspace stayed green — because the tests that would have
# seen it were skips. A test that cannot fail is not a test. This script
# exists so there is one command between a clean checkout and those tests
# actually running, and so `ASV_UAT033_REQUIRE=1` can be set honestly.
#
# Usage:
#   scripts/uat033-pg-substrate.sh up      # build and start; writes $ROOT/env.sh
#   scripts/uat033-pg-substrate.sh env     # print `export ...` lines for eval
#   scripts/uat033-pg-substrate.sh run     # up, run both suites, down
#   scripts/uat033-pg-substrate.sh down    # stop and remove everything
#   scripts/uat033-pg-substrate.sh status  # is it up, and on what port
#
# Override the location with ASV_UAT033_SUBSTRATE_ROOT (default
# $TMPDIR/asv-uat033-pg). Override the binaries with ASV_UAT033_PG_BINDIR.
#
# Exit status is meaningful: `run` fails if a suite skips or fails, so it is
# safe to use as a CI step.

set -euo pipefail

ROOT="${ASV_UAT033_SUBSTRATE_ROOT:-${TMPDIR:-/tmp}/asv-uat033-pg}"
DATA="$ROOT/data"
ENV_FILE="$ROOT/env.sh"

# Fixed so `run` is reproducible and a stale cluster is easy to identify. The
# tests only need a TCP port; the value is written to env.sh, not hard-coded
# into the suites.
DB_NAME="${ASV_UAT033_PG_DB:-asv_uat033}"
DB_ROLE="${ASV_UAT033_PG_ROLE:-asv_uat033}"
DB_SUPERUSER="asv_admin"

die() { echo "asv-uat033-substrate: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

# ---------------------------------------------------------------- binaries ---
# `pg_ctl` is not on PATH everywhere, and where it is, `initdb` — the binary
# this script actually needs — frequently is not beside it. Debian and Ubuntu
# put the server binaries under a versioned prefix, Fedora under another, and
# a source or Homebrew install under a third. Guessing wrong here is the most
# common way this script fails on a machine that does have PostgreSQL, so probe
# in order of authority and check the result rather than trusting a glob.
#
# `pg_config --bindir` is the authoritative answer when it exists; the globs
# are the fallback for images that ship the binaries without it.
find_bindir() {
  local candidate
  if [[ -n "${ASV_UAT033_PG_BINDIR:-}" ]]; then
    if has_pg_binaries "$ASV_UAT033_PG_BINDIR"; then
      echo "$ASV_UAT033_PG_BINDIR"; return
    fi
    die "ASV_UAT033_PG_BINDIR=${ASV_UAT033_PG_BINDIR} has no pg_ctl and initdb"
  fi
  if command -v pg_config >/dev/null 2>&1; then
    candidate="$(pg_config --bindir 2>/dev/null || true)"
    if has_pg_binaries "$candidate"; then echo "$candidate"; return; fi
  fi
  if command -v pg_ctl >/dev/null 2>&1; then
    candidate="$(dirname "$(command -v pg_ctl)")"
    if has_pg_binaries "$candidate"; then echo "$candidate"; return; fi
  fi
  for candidate in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
                   /opt/homebrew/opt/postgresql*/bin /usr/local/pgsql/bin \
                   /usr/bin /usr/local/bin; do
    if has_pg_binaries "$candidate"; then echo "$candidate"; return; fi
  done
  die "no PostgreSQL server binaries found (need both pg_ctl and initdb). \
Install the postgresql server package, or set ASV_UAT033_PG_BINDIR."
}

# A bindir is only usable if it has BOTH binaries. `initdb` in particular is
# server-side and is the one most often missing from a client-only install,
# and a bindir with only pg_ctl fails later with a much less obvious error.
has_pg_binaries() {
  [[ -n "${1:-}" && -x "$1/pg_ctl" && -x "$1/initdb" ]]
}

# ------------------------------------------------------------------- certs ---
# A CA and a leaf, never one self-signed certificate.
#
# This is not a style preference. `uat033_broker.rs` and `uat033_live.rs` add
# the CA to the connector's trust store, and when the server presents that same
# self-signed certificate as its end-entity, rustls rejects it with
# `CaUsedAsEndEntity`. A single `openssl req -x509` produces exactly that and
# every connect test fails with a message that points at TLS rather than at
# the missing second certificate.
#
# SANs, both load-bearing:
#   127.0.0.1    the address the suites connect to (`ASV_UAT033_PG_ADDR`)
#   pg.local.test  the name `a_pinned_name_is_the_one_the_certificate_is_checked_against`
#                pins on the factory, to prove the certificate check uses the
#                operator's name and not the one the request supplied
#   localhost    conventional, and what `--host` resolves to if a caller uses it
make_certs() {
  step "generating a CA and a server certificate"
  openssl req -new -x509 -days 30 -nodes \
    -keyout "$ROOT/ca.key" -out "$ROOT/ca.crt" \
    -subj "/CN=asv-uat033-ca" >/dev/null 2>&1

  openssl req -new -nodes \
    -keyout "$DATA/server.key" -out "$ROOT/server.csr" \
    -subj "/CN=$DB_NAME" >/dev/null 2>&1

  cat > "$ROOT/server.ext" <<'EXT'
subjectAltName=DNS:localhost,DNS:pg.local.test,IP:127.0.0.1
extendedKeyUsage=serverAuth
EXT

  openssl x509 -req -in "$ROOT/server.csr" \
    -CA "$ROOT/ca.crt" -CAkey "$ROOT/ca.key" -CAcreateserial \
    -days 30 -out "$DATA/server.crt" \
    -extfile "$ROOT/server.ext" >/dev/null 2>&1

  chmod 600 "$DATA/server.key"
  openssl verify -CAfile "$ROOT/ca.crt" "$DATA/server.crt" >/dev/null \
    || die "the generated chain does not verify; refusing to start a substrate that cannot pass TLS"
}

# -------------------------------------------------------------------- up -----
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

cmd_up() {
  command -v openssl >/dev/null 2>&1 || die "openssl is required to build the TLS material"

  local bindir; bindir="$(find_bindir)"
  export PATH="$bindir:$PATH"

  # Refuse to build on top of a running cluster: a half-configured substrate
  # is the hardest kind to debug, because the tests fail for reasons that have
  # nothing to do with the product.
  if [[ -f "$DATA/postmaster.pid" ]]; then
    die "a cluster already exists at $DATA. Run 'down' first."
  fi
  if [[ -d "$ROOT" ]]; then
    step "clearing any previous substrate at $ROOT"
    rm -rf "$ROOT"
  fi
  mkdir -p "$ROOT"

  # The password is a leak canary: `the_broker_process_never_carries_the_password`
  # and `psql_authenticates_without_the_password_in_proc` assert it never appears
  # in a child's environment. So it is generated into a 0600 file, and the file
  # path — not the value — is all that goes into the environment.
  local password
  password="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '%s' "$password" > "$ROOT/password"
  chmod 600 "$ROOT/password"

  local port; port="$(free_port)"

  step "initialising the cluster on port $port"
  "$bindir/initdb" -D "$DATA" -U "$DB_SUPERUSER" \
    --auth-local=trust --auth-host=scram-sha-256 -E UTF8 \
    > "$ROOT/initdb.log" 2>&1 \
    || { tail -20 "$ROOT/initdb.log" >&2; die "initdb failed"; }

  cat >> "$DATA/postgresql.conf" <<CONF
# asv-uat033 disposable substrate
port = $port
listen_addresses = '127.0.0.1'
unix_socket_directories = '$ROOT'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
password_encryption = scram-sha-256
fsync = off
full_page_writes = off
CONF

  # SCRAM only. The suites exist to prove a SCRAM role and a password file, so
  # a trust or md5 line here would make them pass without testing anything.
  cat >> "$DATA/pg_hba.conf" <<'HBA'
host all all 127.0.0.1/32 scram-sha-256
HBA

  make_certs

  step "starting the server"
  "$bindir/pg_ctl" -D "$DATA" -l "$ROOT/pg.log" -w start >/dev/null \
    || { tail -20 "$ROOT/pg.log" >&2; die "the server did not start"; }

  step "creating the role and database"
  "$bindir/psql" -h "$ROOT" -p "$port" -U "$DB_SUPERUSER" -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE ROLE \"$DB_ROLE\" LOGIN PASSWORD '$password'" >/dev/null
  "$bindir/psql" -h "$ROOT" -p "$port" -U "$DB_SUPERUSER" -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_SUPERUSER\"" >/dev/null

  # PostgreSQL 15 revoked CREATE on schema public from PUBLIC. Without this the
  # role can read but not create, and every M6-R5 scenario that asserts a table
  # was or was not created fails for a reason that has nothing to do with the
  # gate under test.
  "$bindir/psql" -h "$ROOT" -p "$port" -U "$DB_SUPERUSER" -d "$DB_NAME" -v ON_ERROR_STOP=1 \
    -c "GRANT ALL ON SCHEMA public TO \"$DB_ROLE\"" >/dev/null

  # Prove the substrate is usable before declaring success, so a broken
  # environment fails here rather than inside a test that reports "connection
  # refused" against code that is fine.
  step "verifying the substrate accepts a TLS SCRAM login"
  PGPASSWORD="$password" "$bindir/psql" \
    "host=127.0.0.1 port=$port dbname=$DB_NAME user=$DB_ROLE sslmode=require" \
    -v ON_ERROR_STOP=1 -c "create table _probe (id int); drop table _probe;" \
    >/dev/null 2>&1 \
    || die "the substrate started but the SCRAM role cannot create a table; the suites would skip or fail for the wrong reason"

  cat > "$ENV_FILE" <<ENV
# generated by scripts/uat033-pg-substrate.sh — do not edit
export ASV_UAT033_PG_ADDR=127.0.0.1
export ASV_UAT033_PG_PORT=$port
# The suites read this as bytes and add it to the trust store, so it is the CA
# PEM file. Pointing it at the cluster directory is "Is a directory".
export ASV_UAT033_PG_ROOT=$ROOT/ca.crt
# Must equal ASV_UAT033_PG_ADDR. uat033_live.rs writes a passfile keyed on the
# address but launches psql with --host \$ASV_UAT033_PG_NAME; if the two differ,
# libpq finds no matching line and answers "no password supplied".
export ASV_UAT033_PG_NAME=127.0.0.1
export ASV_UAT033_PG_ROLE=$DB_ROLE
export ASV_UAT033_PG_DB=$DB_NAME
export ASV_UAT033_PG_PASSWORD_FILE=$ROOT/password
export ASV_UAT033_PSQL=$bindir/psql
# A missing substrate is then a failure rather than a silent skip.
export ASV_UAT033_REQUIRE=1
ENV

  step "substrate ready on port $port"
  echo "run the suites with:  eval \"\$(scripts/uat033-pg-substrate.sh env)\"; cargo test --workspace --locked" >&2
  echo "or simply:            scripts/uat033-pg-substrate.sh run" >&2
}

# ------------------------------------------------------------------- env -----
cmd_env() {
  [[ -f "$ENV_FILE" ]] || die "no substrate at $ROOT. Run 'up' first."
  cat "$ENV_FILE"
}

# ---------------------------------------------------------------- status -----
cmd_status() {
  if [[ ! -f "$DATA/postmaster.pid" ]]; then
    echo "down ($ROOT)"
    return 1
  fi
  local bindir; bindir="$(find_bindir)"
  local port
  port="$(grep -E '^port = ' "$DATA/postgresql.conf" | tail -1 | cut -d= -f2 | tr -d ' ')"
  if "$bindir/pg_isready" -h 127.0.0.1 -p "$port" >/dev/null 2>&1; then
    echo "up on port $port ($ROOT)"
  else
    echo "stale: postmaster.pid present but nothing answering on $port ($ROOT)"
    return 1
  fi
}

# ------------------------------------------------------------------- run -----
# The point of the whole script. It runs the suites with ASV_UAT033_REQUIRE=1,
# so a substrate that failed to come up is a failure rather than 18 green skips.
# Without that variable this command would report success while testing nothing.
cmd_run() {
  local failed=0
  trap 'cmd_down || true' EXIT

  cmd_up
  # shellcheck disable=SC1090
  source "$ENV_FILE"

  step "running the UAT-033 suites against the substrate"
  set +e
  cargo test --locked -p asv-connector-pg --test uat033_live -- --nocapture
  local connector=$?
  cargo test --locked -p asv-broker --test uat033_broker -- --nocapture
  local broker=$?
  set -e

  if [[ $connector -ne 0 || $broker -ne 0 ]]; then
    step "FAILED: connector=$connector broker=$broker"
    failed=1
  else
    step "both UAT-033 suites passed against a real PostgreSQL"
  fi
  return $failed
}

# ------------------------------------------------------------------ down -----
cmd_down() {
  if [[ -f "$DATA/postmaster.pid" ]]; then
    local bindir; bindir="$(find_bindir)"
    step "stopping the server"
    "$bindir/pg_ctl" -D "$DATA" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  if [[ -d "$ROOT" ]]; then
    step "removing $ROOT"
    rm -rf "$ROOT"
  fi
}

case "${1:-up}" in
  up)     cmd_up ;;
  env)    cmd_env ;;
  run)    cmd_run ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  # Not a user command: it makes the binary discovery testable on its own. CI
  # depends on this resolving on an image whose layout differs from the
  # developer's, and that difference is exactly what is awkward to reproduce
  # by hand, so it is exposed rather than buried.
  print-bindir) find_bindir ;;
  -h|--help|help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '${1}'. Try: up, env, run, down, status" ;;
esac
