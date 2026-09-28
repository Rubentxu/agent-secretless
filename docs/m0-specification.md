# M0 Foundations specification

Cycle `p-20a1ee316faf2ba3/m0-foundations-v2`, work item
`f5781180-1a29-4ca6-ad52-b8cbc2605e6f`, path A-min.

## Objective

A compiling Rust workspace whose boundaries match the security model, with
every boundary backed by a check that is capable of failing.

## Requirements

Each requirement is stated so that a reviewer can name the command that would
detect its violation.

### R1 - The agent-facing API has no secret-returning method

Derived from ADR-0001 and `docs/02-THREAT-MODEL.md` (NFR-SEC-002). Not "we did
not write one" but "one cannot be added without a deliberate act".

**Verified by**

- `Request` is a closed enum with no variant able to carry secret material
  (`crates/ipc-protocol/src/lib.rs`).
- `SecretBytes` has no `Clone`, `Serialize` or `Display`, and its `Debug` impl
  writes only `SecretBytes(<redacted>)`. The guarantee is not the absence of a
  derive but the absence of any path to the content: a stray `{:?}` is safe by
  construction, no call site can clone or serialize the value, and it is
  zeroized on drop. Verified at `crates/domain/src/secret.rs:64`.
- `cargo test -p asv-cli no_subcommand_exposes_a_secret` asserts the rendered
  clap surface contains none of `get_secret`, `export_secret`, `show_secret`,
  `reveal`, `password`, `token`.
- `every_forbidden_method_name_fails_to_decode` asserts that a request naming
  any forbidden method fails at the decoder, before reaching a handler.

### R2 - Identity is kernel-attested, never peer-asserted

Derived from ADR-0003. A hostile agent process cannot lie about its own uid.

**Verified by**

- `SO_PEERCRED` supplies uid/pid/gid at connect time; `pidfd_open` pins the peer
  against PID reuse.
- `peer_cannot_forge_its_own_identity` connects with a spoofed credential and
  asserts the broker still observes the real uid.
- `forbidden_method_is_refused_by_a_running_broker` and the socket-permission
  probe exercise this through real processes, not in-process fakes.

### R3 - The broker socket cannot be hijacked

Derived from ADR-0002 trust-domain separation.

**Verified by**

- The socket is bound `0600` inside a `0700` directory; the harness asserts the
  observed mode is not group- or world-accessible.
- `broker_refuses_to_hijack_an_existing_socket` starts a second broker against a
  live socket and asserts a non-zero exit naming the reason.

### R4 - No leak crosses a trust boundary, and that claim is falsifiable

This is the requirement that the first harness violated.

**Verified by**

- `tests/adversarial/run_harness.py` plants a canary in the vectors a secret
  would occupy and attacks a real `asv-brokerd` and a real `asv` process.
- Six self-checks plant the canary in the exact vector each probe scans and
  require it to be found. A probe that cannot detect its own planted canary
  reports `INVALID`, which fails the run.
- `tests/adversarial/test_falsifiability.py` injects three real leaks into the
  source, rebuilds, and requires the harness to reject each one before
  restoring the tree.

**What M0 does not claim**

`argv` is readable by every same-uid process, and `ps` and shell history see it
regardless of what the binary does. A value passed as a CLI flag is therefore
visible in `/proc/<pid>/cmdline` for the life of the process, and no ASV change
can prevent it. M0 does not claim an argv boundary. What it does control is
that the CLI offers no secret-ingestion surface and never echoes a request
field back; both are checked, and `selfcheck-cmdline` proves the cmdline reader
works, so the kernel wording is falsifiable rather than asserted.

**Regression that motivated this requirement**

The harness shipped in commit `28c0ee4` reported 5/5 green while planting its
canary nowhere. It was structurally incapable of reporting FAIL, so its result
was evidence of nothing. `test_falsifiability.py` is the regression test.

## Out of scope for M0

Explicitly not claimed, and not to be read as evidence of working:

- Vault persistence and encryption (M1).
- SSH signing and the surrogate bridge (M4).
- A dedicated broker uid, which is what makes memory-read denial unconditional
  (M7). In M0 a same-uid peer can read broker memory; the harness reports that
  verdict rather than asserting a boundary that does not exist.
- eBPF redirection (M9) and isolated exec (M10).

## Acceptance

```text
cargo test --workspace                      35 passed, 0 failed
cargo clippy --workspace --all-targets      0 warnings
cargo fmt --all -- --check                  clean
python3 tests/adversarial/run_harness.py    11 passed, 0 leaked, 0 invalid
python3 tests/adversarial/test_falsifiability.py   3/3 leaks detected
python3 tools/check-gates.py                5 hard defects (tracked, not patched)
agent-secretless-vault-spec/SHA256SUMS      37/37 unchanged
```

## Known defects carried forward

Five roadmap UAT gate-map defects are registered as triaged SDDK backlog items
(three P0, two P1) rather than patched in the signed spec pack. The pack is
normative and unmodified; `tools/check-gates.py` reports the defects instead.

The `origin` remote is unverified: `git ls-remote` reports "Repository not
found". No push has been attempted.
