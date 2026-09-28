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

### F4 - Cross-crate integration tests cannot rely on CARGO_BIN_EXE

Cargo only sets `CARGO_BIN_EXE_*` for binaries of the crate under test, so the broker
integration test cannot use it for the `asv` CLI. It also does not surface
`CARGO_TARGET_DIR` when the target dir comes from cargo's global config rather than the
environment, so probing the env alone silently misses a real target dir. The reliable
anchor is the test binary's own path, which always lives in `<target>/<profile>/deps/`.

## Verification observed at report time

- `cargo test --workspace` -> 35 passed, 0 failed
- `cargo clippy --workspace --all-targets` -> 0 warnings
- `cargo fmt --all -- --check` -> clean
- `tests/adversarial/run_harness.py` -> 5/5, exit 0, output digest
  `sha256:ea41623633206d973ac635c283b4eb0661629790753659e09f546a9d2be03991`
- Spec pack `SHA256SUMS` -> 37/37 match

The harness is falsifiable: injecting a raw token into the session environment makes it
exit 1 on two independent probes.

## Known unknowns

- The `origin` remote `https://github.com/rubentxu/agent-secretless.git` returns
  "Repository not found". It was configured by inference and is **unverified**. No push
  has been attempted.
- eBPF, isolated exec, SSH signing and the dashboard are M9, M10, M4 and M3
  respectively. Nothing in M0 should be read as evidence that they work.
