# Agent Secretless Vault (ASV)

A local credential control plane that lets an AI agent **use an identity
without ever being given the credential material**. Shell-first: the agent keeps
running `git`, `ssh`, `gh`, `curl`; ASV authenticates outside the agent process.

> **Status: M0 in progress.** Milestone M0 builds a compiling workspace whose
> boundaries match the security model. The vault, SSH signing, HTTP brokering
> and dashboard are later milestones. See `agent-secretless-vault-spec/docs/15-ROADMAP.md`
> for the planning authority.

## The invariant

The agent-facing API has no `getSecret`, `exportSecret`, or any alias that
recreates one (ADR-0001). In M0 this is enforced three ways:

| Enforcement | Where | How it is proven |
|---|---|---|
| `SecretBytes` has no `Debug`/`Clone`/`Serialize` derive | `crates/domain/src/secret.rs` | canary tests over Debug, collections, panics |
| IPC methods are a closed enum of non-secret shapes | `crates/ipc-protocol/src/lib.rs` | every forbidden method name fails to decode |
| Identity comes from the kernel, never from the peer | `crates/identity/src/lib.rs` | a client that lies about its uid is still reported by `SO_PEERCRED` |

## Workspace

```text
crates/
  domain/         core types, the secret wrapper, posture enum
  ipc-protocol/   versioned, length-bounded request/response
  identity/       SO_PEERCRED + pidfd workload identity
  broker/         request handling and the asv-brokerd daemon
  cli/            the asv binary (control plane, never a secret reader)
tests/
  adversarial/    leak-sentinel threat harness
tools/
  check-gates.py  audits the UAT -> milestone gate map in the spec
```

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
python3 tests/adversarial/run_harness.py     # adversarial leak probes
python3 tools/check-gates.py                 # spec gate-map audit
```

The harness exits non-zero when a canary escapes, and its checks are themselves
falsifiable: injecting a raw token into the session environment makes it fail on
two independent probes.

## Running it

```bash
asv-brokerd /run/user/$(id -u)/asv/broker.sock &
asv --socket /run/user/$(id -u)/asv/broker.sock status
asv --socket /run/user/$(id -u)/asv/broker.sock session --workspace "$PWD"
asv --socket /run/user/$(id -u)/asv/broker.sock credentials
```

The broker binds its socket with mode `0600` inside a `0700` directory and
refuses to start if the socket already exists, so it cannot hijack or clobber a
running instance.

## Security posture is stated, never implied

Every integration reports one of `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` or
`UNSUPPORTED` (ADR-0014). A compatibility mechanism is never labelled as
equivalent to signing or proxying.

## Specification

`agent-secretless-vault-spec/` holds the full pack: 20 documents, 14 ADRs, and
a `SHA256SUMS` manifest. It is imported verbatim and is not edited in place;
defects found in it are recorded and gated rather than silently patched.
