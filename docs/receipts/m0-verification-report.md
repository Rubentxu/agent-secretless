# M0 verification report

Cycle `p-20a1ee316faf2ba3/m0-foundations-v2`, work item
`f5781180-1a29-4ca6-ad52-b8cbc2605e6f`, phase Verify, path A-min.

This report records what was observed, not what was intended. Every claim below
names the command that produced it.

## Verdict

M0 Foundations meets its stated specification. The evidence is adversarial and
falsifiable: the harness is proven unable to pass when a real leak exists.

## Verification observed

| Command | Result |
|---|---|
| `cargo test --workspace` | 35 passed, 0 failed |
| `cargo clippy --workspace --all-targets` | 0 warnings |
| `cargo fmt --all -- --check` | clean |
| `python3 tests/adversarial/run_harness.py` | 11 passed, 0 leaked, 0 invalid, exit 0 |
| `python3 tests/adversarial/test_falsifiability.py` | 3/3 injected leaks detected, exit 0 |
| `python3 tools/check-gates.py` | 5 hard defects, tracked in SDDK backlog |
| `agent-secretless-vault-spec/SHA256SUMS` | 37/37 unchanged |

Command output digests:

```text
cargo test --workspace   sha256:6112b618b4e3323661b2c2a014a3f67fdc4f4a4653d162d145dacc93c647138a
run_harness.py           sha256:935ffcd572d2e1b9a3fedc3e69dab939e2f3b56545425334dca66849e33bacf7
```

## Falsifiability

`test_falsifiability.py` injects three real leaks, rebuilds, and requires the
harness to reject each one:

| Injection | Caught by | Vector |
|---|---|---|
| `secret-in-broker-log` | `broker-isolation` | raw request bytes in the broker log |
| `secret-in-ipc-response` | `broker-isolation` | request field reflected into response bytes |
| `secret-in-cli-output` | `cli-argv` | request field echoed to stderr |

Each fails through a distinct probe. Two earlier injections did not: the one
named `secret-in-ipc-response` merely added a `tracing::warn!`, so it was caught
by the log probe and the response boundary was never tested. It now alters the
response, and the report above reflects the corrected mapping.

## Two defects verification found

**A real leak in the broker.** The 64 KiB read buffer retained the full raw
request for the process lifetime, so a same-uid peer could read a client's own
request bytes out of the broker's heap. Fixed by zeroizing the buffer after
decoding. Retaining the *decoded* request is not a leak, since it is data the
client just sent.

**An unfalsified claim about argv.** The CLI probe's docstring and PASS message
both stated it inspected the process cmdline. It did not: `subprocess.run` with
`capture_output` sees only stdout and stderr, and the child is gone before
anything could be read. Implementing the check made it fail, and the failure was
correct. On Linux `argv` is readable by every same-uid process, so a value
passed as a CLI flag is visible in `/proc/<pid>/cmdline` for the life of the
process, and no ASV change can prevent it. The probe now reports what ASV
actually controls, and `selfcheck-cmdline` proves the reader works so the
wording is falsifiable.

## Boundaries M0 does not establish

Stated so this report cannot be read as claiming more than it verifies:

- **argv visibility.** A same-uid peer can read any process's argv. There is no
  ASV control over this; the design response is to never put a secret in argv
  at all, which the M0 CLI satisfies by having no credential-ingestion command.
  M1 adds the no-echo TTY channel the threat model requires.
- **Broker memory.** A same-uid peer can read broker memory. Only a dedicated
  broker uid (M7) makes denial unconditional. The harness reports the kernel
  verdict verbatim instead of asserting a boundary that does not exist.
- **No vault.** There is no secret to protect yet, so these checks demonstrate
  boundary *properties*, not protection of stored secret material.
- **Not in the pack.** Five roadmap UAT gate-map defects remain in the signed
  pack as triaged SDDK backlog items (3x P0, 2x P1). The pack is normative and
  unmodified; `tools/check-gates.py` reports them rather than patching.

## Release readiness

The `origin` remote is unverified: `gh repo view` reports the repository does
not exist. No push has been attempted. Release is blocked on that decision and
on the cycle's release phase.
