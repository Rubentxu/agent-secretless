# Agent Secretless Vault (ASV)

[![verify](https://github.com/rubentxu/agent-secretless/actions/workflows/verify.yml/badge.svg)](https://github.com/rubentxu/agent-secretless/actions/workflows/verify.yml)

A local credential control plane that lets an AI agent **use an identity without
ever being handed the credential material**.

The agent keeps doing what it already does: `git push`, `ssh`, `gh`, `curl`. ASV
authenticates on the agent's behalf, outside the agent process. The agent never
holds a key long enough for it to leak.

```text
agent ──(surrogate / socket)──▶ broker ──(real credential)──▶ remote
        no secret material                the only holder
```

> **Status: pre-1.0 RC preparation (M13 + gates R2/R3/R5/R6 done).**
>
> The workspace compiles with **719 tests green** (`--release`, canonical flakes
> excluded; the count is re-derived every CI run by the `R11 README test count`
> gate, so this line cannot go stale again). The vault, SSH signing, HTTP/PostgreSQL brokering, policy, OAuth2
> framework, TPM sealing and crash recovery exist and are tested. Remaining
> before a 1.0 that the maintainer has not yet approved: signed reproducible
> artifacts (R0), full certification pass (R11), and the M5 operator dashboard.
> `agent-secretless-vault-spec/docs/15-ROADMAP.md` is the planning authority.

## Why this exists

If you give an AI agent shell access, every credential on the machine is one
`env`, one `~/.git-credentials` or one shell-history read away. ASV removes
that class of leak: the agent asks the broker to perform the sensitive
operation, the broker holds the credential, the agent gets the result — never
the material.

## The invariant

**The agent-facing API has no way to read a secret.** Not `getSecret`, not
`exportSecret`, not any alias that recreates one (ADR-0001). This is not a
convention a future contributor could quietly break; it is enforced by the
type system:

| Enforcement | Where | How it is proven |
|---|---|---|
| `SecretBytes` has no `Clone` or `Serialize`, and its `Debug` prints only `SecretBytes(<redacted>)` | `crates/domain/src/secret.rs` | no call site can clone or serialize a secret, and a stray `{:?}` in a log line is safe by construction |
| IPC requests are a closed enum with no secret-carrying variant | `crates/ipc-protocol/src/lib.rs` | every forbidden method name fails at the decoder, before a handler sees it |
| Identity comes from the kernel, never from the peer | `crates/identity/src/lib.rs` | a client that lies about its own uid is still reported truthfully by `SO_PEERCRED` |
| Production broker/connector sources never call `std::env::var*` | `crates/broker/tests/uat_017_env_scan.rs` | a source scanner fails the build if a credential-shaped environment read reappears (the D9 rule) |

## What it does today

- **Encrypted local vault** — Argon2id + XChaCha20-Poly1305 envelope, versioned
  format, authenticated headers, owner-only files. Backup/restore under a
  *separate* recovery passphrase. Passphrase **rekey** that re-wraps the same
  data key, so pre-rotation backups keep working (`crates/vault`).
- **Broker daemon** (`asv-brokerd`) — Unix-socket IPC (protocol v2), `SO_PEERCRED`
  identity, Cedar policy with **deny-by-default**, fail-closed startup: it opens
  `--vault`/`--passphrase-file` at boot or refuses every brokered operation.
  Core dumps are disabled via `RLIMIT_CORE=0` before any secret exists.
- **Connectors** — GitHub (HTTP, semantic authority), PostgreSQL (full decision
  logic; live transport pending), SSH (the agent requests *signatures*, never
  the private key).
- **OAuth2 client-credentials framework** for short-lived surrogate issuance
  (prototype, M11).
- **TPM sealing prototype** — PCR policy binding and an offline recovery blob
  (M12; `SoftwareTpm` is a placeholder, no real hardware path yet).
- **Crash recovery** — append-only journal with length prefixes and CRC32;
  a torn write is detected and replayed or discarded, never half-applied (M13).
- **Environment quarantine** — `asv run` scrubs credential-bearing variables
  from the agent's environment before the workload starts.

## What it does *not* do (yet)

Stated plainly, because a security project that oversells itself is worthless:

- **No operator dashboard.** The Tauri 2 UI is M5, not started.
- **`LiveConnectorFactory::postgres` returns a real client, not
  `UnsupportedInThisBuild`.** The enum variant still exists, but it is the
  *trait default* at `crates/broker/src/lib.rs:191`; the production override
  is at `:257`. UAT-033 runs against a real PostgreSQL in CI. *(This line
  said the opposite for several milestones: it was reading the trait default
  and reporting it as production behaviour.)*
- **The M7 hardening profile is opt-in, not unwired.** `harden::install_with`
  is called from `crates/broker/src/main.rs:195` behind `--harden`; the broker
  ships with `RLIMIT_CORE=0` only when it is not passed. *(This line previously
  said it was "not wired into the binary", which was false.)*
- **A dedicated broker uid is not used.** The broker runs as you, so a process
  running as you can read its memory; only `PR_SET_DUMPABLE=0` and Landlock
  stand in the way. A separate uid (M7) is what makes that denial
  unconditional.
- **No signed artifacts yet (R0).** Reproducible-build and signing tooling
  (cosign/sigstore) is the next gate.
- **TPM support is a prototype.** `SoftwareTpm` stands in for hardware; do not
  trust it as hardware-bound.
- **Same-uid memory reads succeed.** A process running as you can read the
  broker's memory, because the broker runs as you. Only a dedicated broker uid
  (M7) makes denial unconditional.
- **1.0 has not been declared.** The maintainer gates it explicitly; iteration
  continues below 1.0.

## Quick start

```bash
cargo build --release -p asv-broker
cargo test --workspace --release -- --test-threads=1 \
    --skip uat_028 --skip one_hundred_brokered_reads
# expected: passed=692 failed=0 ignored=1
```

Try the broker with a vault:

```bash
SOCK="$HOME/.asv/broker.sock"
PASS=/tmp/vault.pass   # passphrase file; keep it out of shell history

# create a vault (head -c reads /dev/urandom: no secret in shell history)
head -c 24 /dev/urandom | base64 | tr -d '\n' > "$PASS"
asv-vault-tool create --vault /tmp/vault.asv --passphrase "$(cat "$PASS")" --fast

# start the broker: configuration by argv, passphrase by file (rule D9:
# broker/connector production code never reads the environment for secrets)
asv-brokerd "$SOCK" --vault /tmp/vault.asv --passphrase-file "$PASS" &

asv --socket "$SOCK" status
```

The broker binds its socket `0600` inside a `0700` directory and **refuses to
start if the socket already exists**, so it cannot hijack or clobber a running
instance. If only one of `--vault` / `--passphrase-file` is given, it exits
rather than starting half-configured.

## Workspace layout

```text
crates/
  domain/         core types, SecretBytes, Authority canonicalization
  ipc-protocol/   versioned, length-bounded request/response (protocol v2)
  identity/       SO_PEERCRED + pidfd workload identity
  vault/          encrypted envelope, backup/restore, rekey, TPM prototype
  policy/         Cedar integration, deny-by-default decisions
  broker/         request handling, sessions, recovery, asv-brokerd daemon
  cli/            the asv binary: a control plane, never a secret reader
  connector-http/ GitHub connector with semantic authority binding
  connector-pg/   PostgreSQL connector (decision logic complete)
  ssh-agent/      signature service: the key never leaves the broker
  ebpfd/          eBPF / privilege separation research (M8/M9)
tools/
  check-gates.py  audits the UAT -> milestone gate map in the spec pack
```

## Honest verification

Security tooling that cannot fail is worse than no tooling, because it buys
confidence it has not earned. This repository is built around that idea.

**The harness is proven able to fail.** `tests/adversarial/test_falsifiability.py`
injects three real leaks into the source, rebuilds, and requires the harness to
reject each one. Every probe carries a self-check that plants a canary in the
exact vector it scans and requires the probe to find it; a probe that cannot
detect its own canary reports `INVALID` instead of passing vacuously.

**Structural invariants are scanned, not trusted.** UAT-017 walks the broker and
connector sources and fails the build on any credential-shaped `env::var*` —
it caught exactly that regression during the R5 vault wiring, and the fix
(argv flags instead of environment variables) is the shipped design.

**Migration tests exist because the format says so.** The R2 gate lists
"migration tests"; `crates/vault/tests/uat_036_rekey_migration.rs` pins the
passphrase-rekey contract: old passphrase dies, new one opens, pre-rotation
backups still restore, a wrong current passphrase writes zero bytes.

Run everything:

```bash
cargo clippy --workspace --all-targets
cargo test --workspace --release -- --test-threads=1
python3 tests/adversarial/run_harness.py            # 11 probes + self-checks
python3 tests/adversarial/test_falsifiability.py    # the harness can fail
python3 tools/check-gates.py                        # spec gate-map audit
```

**This is checked on CI, not just locally.** Putting the same gates in GitHub
Actions immediately found two defects that every local run had missed. A
security project that only its author's machine can break is not verified.

## Recent milestone history

| Milestone | Scope | Evidence |
|---|---|---|
| M11 ✅ | OAuth2 client-credentials framework prototype | tag `m11-oauth2-framework` |
| M12 ✅ | TPM sealing + recovery blob prototype | tag `m12-tpm-vault` |
| M13 ✅ | Crash/recovery journal, audit baseline, SBOM, ops manual | tag `m13-rc-stabilization` |
| R3 ✅ | Zero-live-pin session leak check (UAT-030) | `3e5c42c` |
| R5 ✅ | Vault wired into the broker binary, fail-closed | `e2a6f65` |
| R6/R11 ✅ | Fuzz evidence: 2×30s runs, ~460k execs, 0 crashes | `8d3a7b5` |
| R2 ✅ | Passphrase rekey + migration tests, core dumps disabled | `dba2e73`, `82e08fd` |

Remaining toward a (maintainer-approved) 1.0: **R0** signed reproducible
artifacts, **R11** final certification, M5 dashboard, live PostgreSQL transport.

## Security posture is stated, never implied

Every integration declares one of `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` or
`UNSUPPORTED` (ADR-0014). A compatibility shim is never labelled as equivalent
to signing or proxying, because that is how "secretless" quietly becomes a lie.

## Specification

`agent-secretless-vault-spec/` holds the full pack: 20 documents, 15 ADRs, and a
`SHA256SUMS` manifest (verified intact). It is imported verbatim and is not
edited in place.

## Security

Please do not report vulnerabilities through public issues. See
[SECURITY.md](SECURITY.md) for what counts as a vulnerability here, what is a
known limitation of the current milestone, and how to check a boundary yourself.

## License

MIT. See [LICENSE](LICENSE).

The specification pack under `agent-secretless-vault-spec/` is included under
the same terms.

---

📚 **Readme in Spanish / Leerlo en español:** [README-es.md](README-es.md)
