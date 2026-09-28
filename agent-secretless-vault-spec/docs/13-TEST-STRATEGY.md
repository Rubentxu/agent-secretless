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
