# Test Strategy

## 1. Philosophy

A credential broker is not proven by “API returned 200”. It is proven by both:

1. intended operation succeeds,
2. hostile process cannot extract or misuse credential beyond granted capability.

## 2. Test layers

### Unit

- ADTs/invariants,
- URL/authority normalization,
- policy mapping,
- surrogate parser/generator,
- crypto envelope format,
- redaction types,
- capability expiry/use count.

### Property tests

- URL normalization equivalence/adversarial encodings,
- redirect policy,
- parser fuzzing,
- secret types never serialize,
- surrogate cannot collide with accepted real formats where prohibited.

### Fuzz

Targets:

- IPC decoder,
- HTTP connector header logic,
- credential file parser/import,
- audit serialization,
- proxy protocol parsers,
- SSH agent protocol,
- eBPF userspace event decoder.

### Integration

Real local services:

- OpenSSH test server,
- mock HTTPS provider,
- PostgreSQL container,
- OAuth mock,
- DNS/redirect attack server.

### Adversarial harness

A malicious child launched inside `asv run` executes extraction techniques and records whether any real secret was recovered.

## 3. Surgical vs certification suites

### Development loop

Run tests for changed connector/component plus focused adversarial cases.

### Integration/release

Run full security harness across:

- all supported integration classes,
- supported kernel profiles,
- UI capability tests,
- fuzz regression corpus,
- vault migration/backup recovery.

## 4. Required regression corpus

Every discovered leak becomes a permanent fixture with:

- exploit script,
- expected denial/non-disclosure,
- platform constraints,
- issue/reference.

## 5. Leak sentinel

Testing can use high-entropy canary secrets unique per test.

After operations, scan controlled outputs/artifacts:

- stdout/stderr,
- agent-visible logs,
- `/tmp` session files,
- environment snapshots,
- captured network to unauthorized sink,
- crash/core outputs if any.

Do not make production depend on canary scanning; it is a test oracle.

## 6. Performance

Bench:

- policy authorization,
- SSH signing throughput,
- proxy request overhead,
- eBPF redirect overhead,
- broker memory footprint,
- session startup latency.

## 7. Compatibility CI

Linux matrix should include at least:

- current Fedora-family kernel,
- current Ubuntu LTS kernel,
- eBPF disabled profile,
- Landlock/memfd_secret feature detection paths.

Do not make unsupported kernel features silently required for portable mode.

## 8. The build directory is part of what a test measures

Most of the end-to-end corpus spawns the real `asv` and `asv-brokerd` binaries,
so a test measures the product only if the binary on disk is the one this tree
built. Two ways that quietly stops being true, both observed in practice:

**A stale binary.** Restoring a file that a harness mutated — even byte for
byte — updates its mtime. That is enough for the freshness check to decide the
binary predates its sources, and every e2e in the package then reports the
staleness instead of the property it went to measure. `binary::locate` fails
loudly on purpose: the alternative is a suite that passes against code nobody
is looking at. The fix is `cargo build --workspace`, which is also why `cargo
test` alone is not sufficient — it does not necessarily produce the binary the
locator resolves.

**Two checkouts sharing one target directory.** Cargo derives the unit hash of
a workspace member from its path *relative to the workspace*, not from the
absolute root. Two checkouts of the same repository therefore produce the same
hash, and if they share a `CARGO_TARGET_DIR` the second links artifacts
compiled by the first, with the first's paths embedded in the debug info. A
test then fails naming a file that does not exist, in a checkout where nothing
is wrong.

This is not hypothetical for anyone using `git worktree`, which is the obvious
way to isolate an experiment. Rules that follow from it:

- **An isolated checkout needs its own `CARGO_TARGET_DIR`.** Sharing one is
  never safe, whatever the isolation is for.
- `cargo clean -p <package>` does not repair it. It clears the package whose
  failure is visible and leaves its workspace dependencies holding the other
  checkout's artifacts. Clean every workspace member, or use a fresh directory.
- Before believing that a failing test found a defect, check whether its
  artifact carries another checkout's path:
  `grep -c <suspect-path> $CARGO_TARGET_DIR/debug/deps/<test-binary>`.

A suite result is evidence about a tree *and a build directory*. Recording the
target directory alongside the commit is what makes a failure reproducible.
