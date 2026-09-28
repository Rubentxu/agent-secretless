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

> **Status: M0. Foundations only.**
>
> This repository contains the compiling workspace, the enforced boundaries and
> the adversarial test harness. **There is no vault yet**, so there is no secret
> to protect and nothing here should be treated as a working credential store.
> The vault, SSH signing, HTTP brokering and the Tauri dashboard are later
> milestones. `agent-secretless-vault-spec/docs/15-ROADMAP.md` is the planning
> authority.
>
> What M0 does prove is that the *boundaries* hold, and that the checks
> enforcing them can actually fail. See
> [Honest verification](#honest-verification) for what is and is not verified.

## The invariant

**The agent-facing API has no way to read a secret.** Not `getSecret`, not
`exportSecret`, not any alias that recreates one (ADR-0001). This is not a
convention that a future contributor could quietly break; it is enforced by the
type system:

| Enforcement | Where | How it is proven |
|---|---|---|
| `SecretBytes` has no `Clone` or `Serialize`, and its `Debug` prints only `SecretBytes(<redacted>)` | `crates/domain/src/secret.rs` | no call site can clone or serialize a secret, and a stray `{:?}` in a log line is safe by construction |
| IPC requests are a closed enum with no secret-carrying variant | `crates/ipc-protocol/src/lib.rs` | every forbidden method name fails at the decoder, before a handler sees it |
| Identity comes from the kernel, never from the peer | `crates/identity/src/lib.rs` | a client that lies about its own uid is still reported truthfully by `SO_PEERCRED` |

The first row is stronger than a missing `Debug` impl. If `Debug` simply did not
exist, the first person to add a log line would get a compile error and could
"fix" it by deriving it. Here the content is unreachable through every trait
the type implements, and the value is zeroized on drop.

The identity row is the interesting one. An agent process is assumed hostile
and untrusted, so the broker never asks it who it is: it asks the kernel, via
`SO_PEERCRED` and `pidfd_open` (ADR-0003).

## Quick start

```bash
cargo build --workspace
cargo test --workspace
```

Try it:

```bash
SOCK="$HOME/.asv/broker.sock"
asv-brokerd "$SOCK" &
asv --socket "$SOCK" status
asv --socket "$SOCK" session --workspace "$PWD"
asv --socket "$SOCK" credentials
```

The broker binds its socket `0600` inside a `0700` directory and **refuses to
start if the socket already exists**, so it cannot hijack or clobber a running
instance.

## Workspace layout

```text
crates/
  domain/         core types and the secret wrapper
  ipc-protocol/   versioned, length-bounded request/response
  identity/       SO_PEERCRED + pidfd workload identity
  broker/         request handling and the asv-brokerd daemon
  cli/            the asv binary: a control plane, never a secret reader
tests/
  adversarial/    the threat harness and its falsification test
tools/
  check-gates.py  audits the UAT -> milestone gate map in the spec pack
```

## Honest verification

Security tooling that cannot fail is worse than no tooling, because it buys
confidence it has not earned. This repository is built around that idea.

**The harness is proven able to fail.** `tests/adversarial/test_falsifiability.py`
injects three real leaks into the source, rebuilds, and requires the harness to
reject each one:

| Injected leak | Detected as |
|---|---|
| raw request bytes written to the broker log | `broker-isolation` |
| request field reflected into the IPC response | `broker-isolation` |
| request field echoed to the CLI's stderr | `cli-argv` |

Each one fails through a different probe. If the harness were broken in the way
it was once broken, this script would report it.

**It was broken that way.** The harness in the first M0 commit reported 5/5
green while planting its canary nowhere. It was structurally incapable of
reporting FAIL, so its result was evidence of nothing at all.
`test_falsifiability.py` exists as the regression test for exactly that.

Run everything:

```bash
cargo clippy --workspace --all-targets
python3 tests/adversarial/run_harness.py            # 11 probes + self-checks
python3 tests/adversarial/test_falsifiability.py    # the harness can fail
python3 tools/check-gates.py                        # spec gate-map audit
```

Every probe carries a self-check that plants a canary in the exact vector the
probe scans and requires the probe to find it. A probe that cannot detect its
own planted canary reports `INVALID` and fails the run, rather than passing
vacuously.

**This is checked on CI, not just locally.** Putting the same gates in GitHub
Actions immediately found two defects that every local run had missed: a
workflow that never built the binaries it attacked, and a build that passed
locally while failing under CI's `-D warnings`. The harness reported both
loudly instead of going green. A security project that only its author's
machine can break is not verified.

## What is *not* protected yet

Stated plainly, because a security project that oversells itself is worthless:

- **There is no vault.** No secret is stored, encrypted or retrieved. M0
  verifies boundary *properties*, not protection of secret material.
- **Same-uid memory reads succeed.** A process running as you can read the
  broker's memory, because the broker runs as you. Only a dedicated broker uid
  (M7) makes denial unconditional. The harness reports the kernel's actual
  verdict rather than claiming a boundary the OS does not offer.
- **`argv` is readable by your uid.** Anything you pass as a CLI flag is
  visible to every process you own, via `ps` and shell history. No software can
  change that. The design response is never to put a secret in `argv`; the M0
  CLI satisfies this by having no credential-ingestion command at all, and M1
  adds the no-echo TTY channel the threat model requires.
- **Five defects remain in the spec pack.** The signed pack is normative and is
  imported byte-for-byte. Defects found in it are recorded as tracked backlog
  items, not silently patched. `tools/check-gates.py` reports them.

## Security posture is stated, never implied

Every integration declares one of `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` or
`UNSUPPORTED` (ADR-0014). A compatibility shim is never labelled as equivalent
to signing or proxying, because that is how "secretless" quietly becomes a lie.

## Specification

`agent-secretless-vault-spec/` holds the full pack: 20 documents, 15 ADRs, and a
`SHA256SUMS` manifest (37 files, verified intact). It is imported verbatim and
is not edited in place.

## Roadmap

| Milestone | Scope |
|---|---|
| **M0** ✅ | Compiling workspace, enforced boundaries, adversarial harness |
| M1 | Encrypted vault, no-echo credential ingestion |
| M2 | `asv run`: isolated agent execution |
| M4 | SSH signing via the agent socket |
| M7 | Dedicated broker uid, hardening profile |
| M9–M10 | eBPF redirection, isolated exec |

## License

MIT. See [LICENSE](LICENSE).

The specification pack under `agent-secretless-vault-spec/` is included under
the same terms.
