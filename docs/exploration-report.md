# Exploration report: ASV M0 Foundations

Status: accepted evidence for SDDK cycle `p-20a1ee316faf2ba3/m0-foundations-v2`,
transition `phase.explore.complete`, gate `exploration-sufficient`.

## What was read

Normative sources, all unmodified: `agent-secretless-vault-spec/` (20 documents,
14 ADRs). The binding constraints for M0 come from:

- **adrs/0001-no-agent-secret-retrieval-api.md** - the agent-facing API must have no
  `getSecret` or any alias that recreates it. This is the invariant M0 makes
  structural.
- **adrs/0014-integration-posture-taxonomy.md** - a compatibility mechanism is never
  labelled as equivalent to signing or proxying, so posture must be an explicit
  ranked enum rather than a boolean.
- **docs/02-THREAT-MODEL.md** - the agent process is hostile to its own confidentiality.
  Identity therefore cannot be asserted by the peer.
- **docs/15-ROADMAP.md** / **docs/16-SECURITY-RELEASE-GATES.md** - M0 is a compiling
  workspace, not a working vault.

## Findings

### F1 - The UAT gate map in the roadmap is not executable as written

`tools/check-gates.py` parses the milestone exit-gate blocks and cross-checks them
against the UAT definitions and the capability introduction milestones. Five hard
defects, all confirmed against the source documents:

| UAT | Problem |
|---|---|
| UAT-005 | gated by M2, but `surrogate-replay` is not introduced until M4 (M4 also claims it) |
| UAT-013 | gated by M7, but `ebpf-socket-redirect` is not introduced until M9 (M9 also claims it) |
| UAT-021 | gated by M7, but `isolated-exec-worker` is not introduced until M10 (M10 also claims it) |
| UAT-027 | defined in docs/14 but no milestone gates on it |
| UAT-030 | defined in docs/14 but no milestone gates on it |

The first three are worse than untidy: a milestone exit gate is a release blocker, so
M2 and M7 would block on capabilities that cannot exist yet. The last two mean two
adversarial UATs can never block anything at all.

All five are registered as triaged backlog items under cycle
`p-20a1ee316faf2ba3/m0-foundations-v2` (three P0, two P1). The signed spec pack was
**not** edited; the checker is falsifiable and was proven against mutated copies.

### F2 - Kernel peer credentials are the only trustworthy identity source

docs/02-THREAT-MODEL.md treats the agent process as hostile. Identity asserted over the
wire is therefore worthless. `SO_PEERCRED` gives uid/pid/gid from the kernel at
connect time, and `pidfd_open` pins the peer against PID reuse. This is what makes a
future surrogate bridge verifiable, and it is why `crates/identity` reads only from
the kernel.

### F3 - A secret wrapper must fail closed by construction

Rather than auditing every call site, `SecretBytes` omits `Debug`, `Clone` and
`Serialize` entirely and provides a redacting `Debug`. Absence of the trait is the
guarantee: no future call site can accidentally log or serialize a secret, because the
code would not compile.

### F4 - Locating a cargo-built binary is harder than it looks

Cargo sets `CARGO_BIN_EXE_*` only for binaries of the crate under test, so the
broker integration test cannot use it for the `asv` CLI. Worse, cargo does not
export the target directory as an environment variable when it is redirected
through `[build] target-dir` in `~/.cargo/config.toml`, which this machine does.
Probing `CARGO_TARGET_DIR` or assuming `<workspace>/target` therefore finds
nothing on a correctly configured machine and turns a green build into a false
failure.

Two different anchors solve it, one per context:

- The Rust integration test anchors on `std::env::current_exe()`, which always
  lives in `<target>/<profile>/deps/`.
- The standalone Python harness has no such anchor, so it asks
  `cargo metadata --no-deps` for the real `target_directory`.

Both are needed: a single "clever" resolution path would have left one of the
two callers silently broken.

## Verification observed at report time

- `cargo test --workspace` -> 35 passed, 0 failed
- `cargo clippy --workspace --all-targets` -> 0 warnings
- `cargo fmt --all -- --check` -> clean
- `tests/adversarial/run_harness.py` -> 10 probes and self-checks, exit 0
- `tests/adversarial/test_falsifiability.py` -> 3/3 injected leaks detected, exit 0
- Spec pack `SHA256SUMS` -> 37/37 match

### F5 - The first harness was green because it could not fail

The harness shipped in the initial M0 commit generated a canary, compared it
against probe output, and never planted it in anything. Every probe passed
vacuously: the harness was structurally incapable of reporting FAIL, so its 5/5
result was evidence of nothing.

Falsifying it exposed three further problems, all now fixed:

1. The harness launched `python3` children against a synthetic environment and
   never invoked an ASV binary, so it probed nothing the product does. It now
   starts a real `asv-brokerd` and a real `asv` CLI process.
2. Each probe needed to prove it could detect a leak at all. Five self-checks
   now plant the canary in the exact vector a probe scans and require it to be
   found, so a probe that cannot fail is reported INVALID rather than PASS.
3. Binary discovery assumed `<workspace>/target`, but this machine redirects the
   target directory through `~/.cargo/config.toml`, which cargo does not export
   as an environment variable. The harness now asks `cargo metadata` for the
   real path.

Two of my own falsification injections were also wrong and are recorded here
because the failure mode is instructive: one changed `SecretBytes::Debug` when
no vault exists to format one, and another read an environment variable the
harness never set. Both were reported as "harness passed". A missing canary and
a broken injection look identical from the outside, which is why the
injections now carry a comment requiring each to sit on an executed path.

A separate, genuine finding came out of the memory probe. The 64 KiB read buffer
in the broker held the full raw request for the process lifetime, so a
same-uid peer could read a client's own request bytes out of the broker's heap.
The buffer is now zeroized after decoding. Retaining the *decoded* request is
not a leak, since it is data the client just sent; the harness reports the
memory verdict verbatim rather than pretending a same-uid boundary exists.

## Known unknowns

- The `origin` remote `https://github.com/rubentxu/agent-secretless.git` returns
  "Repository not found". It was configured by inference and is **unverified**. No push
  has been attempted.
- eBPF, isolated exec, SSH signing and the dashboard are M9, M10, M4 and M3
  respectively. Nothing in M0 should be read as evidence that they work.
