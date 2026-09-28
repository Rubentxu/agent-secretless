# M0 implementation receipt

Cycle: p-20a1ee316faf2ba3/m0-foundations-v2
Work item: f5781180-1a29-4ca6-ad52-b8cbc2605e6f (M0 Foundations)
Gate: implementation-complete, receipt gate-implementation-complete-a40a058c6ee3cbe9-1

## Commits
f468c7a docs(m0): state the specification with its verification commands
9a2ded5 fix(m0): make the adversarial harness falsifiable and scrub request bytes
2bfd728 docs(m0): record exploration evidence and the five UAT gate defects
28c0ee4 feat(m0): add compiling workspace with enforced secretless boundaries

## Verification observed

```text
cargo test --workspace                  exit 0, 35 passed
cargo clippy --workspace --all-targets  exit 0, 0 warnings
cargo fmt --all -- --check              exit 0, clean
tests/adversarial/run_harness.py        10 passed, 0 leaked, 0 invalid
tests/adversarial/test_falsifiability.py  3/3 injected leaks detected
tools/check-gates.py                    5 hard defects, tracked in SDDK backlog
spec pack SHA256SUMS                    37/37 verified unchanged
```

## Command output digests

```text
cargo test    sha256:826930e68e4729bf1cd7fd2c4a7d5b7b08b6b2acd00bddf98f25594422ff9e4f
cargo clippy  sha256:a99ef3444d26245ce39cf5ac38be13651a180787271e74c51d6ce7e24f0f7df5
cargo fmt     sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
harness       sha256:3be889635699421e3f719c012e65ba67796f83e6220f5cc45031fd5d9ab6faec
```

## Scope boundary

No vault, no SSH signing, no dedicated broker uid. A same-uid peer can read broker memory in M0; that verdict is reported, not denied.
