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

> **Status: pre-1.0, at v0.30.0. Not certified, and the gates say so.**
>
> The workspace compiles and **1805 tests are enumerated**. Under `cargo test`,
> 1804 of them run and pass and 1 is gated out of debug builds by construction:
> the p95 latency budget carries `#[cfg_attr(debug_assertions, ignore)]`,
> because a latency budget measured against debug ed25519 is a statement about
> `debug_assertions` rather than about the product. It runs and passes under
> `--release` — measured here at 1490us against a 6000us budget — so the release
> run below executes 1803 of them. The count and the quick start's arithmetic are
> re-derived every CI run by the `R11 README test count` gate, which subtracts
> the `--skip` filters the quick start documents rather than checking a sum, so
> a block that skips a test and then claims the full count fails instead of
> passing on an arithmetic that could not have happened. Vault, SSH signing, the
> HTTP and PostgreSQL brokers, Cedar policy, the operator console and the
> CONNECT TLS bridge exist and are exercised. The OAuth2 framework is
> **implemented and in production use** against a **self-hosted** authorization
> server — a real one
> speaking RFC 6749/7009/7662/8707, not a third-party IdP, and that difference
> is the half of M11 that is still open. TPM sealing remains a **prototype**
> with no production path, because that needs hardware this host does not
> have.
>
> **Verifiable status lives in
> [`16-SECURITY-RELEASE-GATES.md`](agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md),
> not in this file.** A status table in a README is a claim nothing checks; the
> one that had drifted was here, and it is now a table in the gates document
> that `scripts/check-gate-status.py` verifies against the repository.
> [`15-ROADMAP.md`](agent-secretless-vault-spec/docs/15-ROADMAP.md) is the
> planning authority, including the sequence from here to v1.0.

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
- **Broker daemon** (`asv-brokerd`) — Unix-socket IPC (protocol v10), `SO_PEERCRED`
  identity, Cedar policy with **deny-by-default**, fail-closed startup: it opens
  `--vault`/`--passphrase-file` at boot or refuses every brokered operation.
  Core dumps are disabled via `RLIMIT_CORE=0` before any secret exists.
- **Operator console** — a Tauri 2 control plane over a local web view: no remote
  origin, a strict CSP, and no way for the front-end to request a stored secret
  value. The full add → grant → agent use → revoke flow is proven against a real
  broker process in CI. *(This README said for several milestones that the
  dashboard was "not started" and "remaining before 1.0". Both were false: M5
  shipped.)*
- **Connectors** — GitHub (HTTP, semantic authority), PostgreSQL (full decision
  logic, plus a live transport proven against a real server when the pipeline
  brings the substrate up), SSH (the agent requests *signatures*, never the
  private key). `LiveConnectorFactory::postgres` returns a real client, not
  `UnsupportedInThisBuild`; the enum variant still exists, but it is the *trait
  default* at `crates/broker/src/lib.rs:191` and the production override is at
  `:257`. *(This README previously reported the trait default as production
  behaviour, and said "live transport pending" and "UAT-033 runs against a real
  PostgreSQL in CI" in the same breath. The first was true of a local `cargo
  test` and the second true only of the pipeline.)*
- **TLS bridge on the CONNECT path** — per-session ephemeral CA, strict
  destination authorization, and the real credential substituted inside the
  tunnel while the client holds only a single-use surrogate.
  **Not** an eBPF socket redirect: that research gate returned NO-GO and the
  explicit-proxy path is what shipped.
- **OAuth2 client-credentials framework** for short-lived surrogate issuance —
  **implemented, with a production consumer** (M11). `asv-brokerd
  --oauth2-clients PATH` declares credentials this broker trades for short-lived
  tokens: the client secret is read from the vault, spent on one HTTPS POST to
  the token endpoint, and what the operation receives is a short-lived access
  token the provider issued. The secret stops at the broker. A granted scope
  that differs from the one requested aborts, a token with no positive
  `expires_in` is refused, a non-HTTPS token endpoint is refused outright, and a
  provider that stops answering stops the operation rather than falling back to
  the vault. Five mutations, five reds
  (`tests/oauth2_falsification.py`). The provider is self-hosted; V1-C3 stays
  host-dependent for compatibility with an operator's real IdP.
- **TPM sealing prototype** — PCR policy binding and an offline recovery blob
  (M12; `SoftwareTpm` is a placeholder, no real hardware path yet).
- **Crash recovery** — append-only journal with length prefixes and CRC32;
  a torn write is detected and replayed or discarded, never half-applied (M13).
- **Environment quarantine** — `asv run` scrubs credential-bearing variables
  from the agent's environment before the workload starts.

## What it does *not* do (yet)

Stated plainly, because a security project that oversells itself is worthless.
Each item says where its detail lives, because none of it is a guess.

- **The claim about memory is still the narrower one, and that is now a
  checked fact rather than a footnote.** The broker runs as you by default,
  which means a process running as you can read its memory. What the tests
  prove is the kernel-level fact underneath: a process under the same uid
  **lacking `CAP_SYS_PTRACE`** is refused by the kernel when it opens
  `/proc/<broker>/mem`, and the identical attack against a *dumpable* sibling
  of the same uid succeeds — so the refusal is attributable to the hardening
  rather than to the open having failed for some unrelated reason. A separate
  uid is what makes the denial unconditional, and **the broker can now be made
  to insist on one**: `--identity-uid` declares the uid the installation
  expects and the binary refuses to start as any other, before it binds its
  socket or reads the passphrase; `--require-dedicated-identity` makes the
  *absence* of a declaration fatal too, so a packaged install cannot quietly
  degrade into the development shape. `packaging/asv-brokerd.dedicated.service`
  is the unit that declares one. **What is still host-dependent is creating the
  system account and proving the unit on a machine that has one** — this host
  has no `sudo`, and nothing in the repository can assert what `getent
  passwd` answers on yours.
- **The same-uid attack is now executed, not documented.** UAT-003's strongest
  clause was `#[ignore]`d for several milestones — its reason named the fix,
  *"requires a child process to attempt the open"*, and the fix was never
  built. It runs now, and it was the only ignored test in the suite.
  *(This line previously said the clause was still ignored. Writing the test
  also turned up a real defect next door: under `--harden` the broker was
  sandboxed out of its own **passphrase file**, because the ruleset is
  installed at startup and the passphrase is read after it, and the declared
  path set had never covered the passphrase's directory. The shipped unit does
  not pass `--harden`, which is why nobody hit it.)*
- **The M7 hardening profile is opt-in, not unwired.** `harden::install_with`
  is called from `crates/broker/src/main.rs:195` behind `--harden`; the broker
  ships with `RLIMIT_CORE=0` only when it is not passed. *(This line previously
  said it was "not wired into the binary", which was false.)*
- **The install path verifies a signature, and cannot be told not to.**
  `scripts/install.py` requires `sha256.sum` to carry a valid minisign signature
  from the project key before it reads a single line of it, and the manifest
  that decides which components install is inside that signed authority. A
  missing signature, an invalid one, a self-consistent archive/checksum pair
  published by someone else, or a substituted key are all refusals — there is
  no flag that downgrades any of them. Installing therefore requires the
  `rsign` verifier; that is a new dependency and a deliberate one, and
  `tests/provenance_falsification.py` is the receipt.
- **The signing key is passwordless.** The v0 key is generated with
  `rsign generate -W` and protected by file permissions alone. That is a
  recorded gap to close before 1.0, not a property.
- **TPM support is a prototype.** `SoftwareTpm` stands in for hardware; do not
  trust it as hardware-bound.
- **No eBPF socket redirection.** The M8 research gate is NO-GO: no BPF program
  was ever written, and this build host cannot load one. `asv-ebpfd` is the
  egress/telemetry helper, which is a different job and is unaffected.
- **The CONNECT bridge has no production listener yet.** The substitution
  capability is verified end to end and is not wired into a running
  `asv-brokerd`, one request is served per tunnel, and the proof's nonce is
  derived from the destination — which resists a proof being transferred to
  another destination but is not freshness. That is V1-C2, and the M9 row in the
  gates document says the same thing with the receipts behind it.
- **The console has no TLS-interception indicator.** An operator cannot see from
  the UI that an intercepting path exists. Carried forward, not closed.
- **1.0 has not been declared.** The maintainer gates it explicitly; iteration
  continues below 1.0.

## Installing a release

```bash
# the verifier is required: the installer refuses to proceed without it
cargo install rsign2          # or your distribution's package manager
curl -LsSf https://raw.githubusercontent.com/Rubentxu/agent-secretless/main/scripts/install.sh \
  | sh -s -- --version 0.30.0 --prefix "$HOME/.local"
```

The installer requires `sha256.sum` to carry a valid minisign signature before
it reads a single line of it, and the manifest that decides which components
install is inside that signed authority. **The release signing key id is
`54CB5B8D3C7419FB`.** Compare it against this line — a number you can reach
without downloading the thing you are checking. A download that substituted the
key would otherwise be checking itself.

`release.pub` travels with the release and is *not* the authority: whoever
substitutes the download substitutes that file too. The authority is the key
embedded in the installer, and `--trusted-key PATH` takes one you obtained out
of band.

The key itself is passwordless (`rsign generate -W`), protected by file
permissions alone. That is a recorded gap to close before 1.0.

## Quick start

```bash
cargo build --release -p asv-broker
cargo test --workspace --release -- --test-threads=1 \
    --skip uat_028 --skip one_hundred_brokered_reads
# expected: passed=1803 failed=0 ignored=0
```

1803 rather than 1805 because the command above skips two of them: `uat_028`
starts a real `sshd` and needs a host to run it, and the p95 budget is asserted
separately in `--release` so the quick start stays a quick start. The two
skips are reported as filtered, not as ignored, so 1803 + 2 filtered is the 1805
enumerated.

That number was `passed=692` in this file for several milestones, and nothing
checked it — a stale count in a README is a claim like any other, and this
guard (`scripts/check-doc-claims.py`) now re-derives it instead of leaving it
to memory. It checked `passed + ignored` as a sum at first, which is how a
`passed=1194` sat in this block for a while: the sum was right, the claim was
impossible, and a guard that only sums cannot see that the command in the same
block skips the two tests the number is counting.

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
  ipc-protocol/   versioned, length-bounded request/response (protocol v10)
  identity/       SO_PEERCRED + pidfd workload identity
  vault/          encrypted envelope, backup/restore, rekey, TPM prototype
  policy/         Cedar integration, deny-by-default decisions
  broker/         request handling, sessions, recovery, asv-brokerd daemon
  cli/            the asv binary: a control plane, never a secret reader
  connector-http/ GitHub connector with semantic authority binding
  connector-pg/   PostgreSQL connector (decision logic complete)
  ssh-agent/      signature service: the key never leaves the broker
  ebpfd/          egress/telemetry helper (8-verb vocabulary, no BPF program)
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

## Milestone status

**This section used to be a table here, and it was wrong.** It marked M11, M12
and M13 as complete with a tick glyph while the gates document — the authority
— had M11 and M12 as **NOT MET** and M13 **partial**. A second copy of the
status in the most-read file in the repository is a second authority, which is
the one thing this project does not need.

Milestone status now lives in exactly one place:
[`16-SECURITY-RELEASE-GATES.md`](agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md).
It is checked against the repository by `scripts/check-gate-status.py`, so it
fails the build when a row stops matching reality.

What is left here is the sequence, because a reader who wants to know what
happens next does not need a table of what already happened:
[`15-ROADMAP.md`](agent-secretless-vault-spec/docs/15-ROADMAP.md) carries the
path from v0.28.0 to v1.0 and then to v1.1.

## Security posture is stated, never implied

Every integration declares one of `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` or
`UNSUPPORTED` (ADR-0014). A compatibility shim is never labelled as equivalent
to signing or proxying, because that is how "secretless" quietly becomes a lie.

## Specification

`agent-secretless-vault-spec/` holds the full pack: 21 documents, 20 ADRs, and a
`SHA256SUMS` manifest (verified intact). It is imported as research and is not
edited in place except where a decision it records has since been made — each
such edit carries its date and its reason.

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
