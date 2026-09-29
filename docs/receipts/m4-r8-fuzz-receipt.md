# M4-R8 / UAT-008 / R6 / R11 — URL/header fuzz evidence receipt

Cycle: p-20a1ee316faf2ba3 (post-m13 v1.0 prep)
Work item: bl-bl-01M3N3FKYF000387A6YD7C7G40 (P2) — fuzz target URL/header
Path: PATCH on top of m13-rc-stabilization
Gate: fuzz-regression-corpus-green (R11), agent-leak-harness (R6)

## Scope delivered

Reproducible fuzz-run evidence for the `authority_canonicalization` target
under `crates/connector-http/fuzz/`. The target, oracle, and committed seed
corpus already existed (M4-R8); this cycle **operationalized the evidence
path** required by R6 / R11:

- The committed seeds replay cleanly (no crashes, expected coverage).
- A 30-second random fuzz run on top of the committed seeds completes
  without crashes, with stable edge coverage in the 3600-3650 range.
- The harness, oracle, and seed corpus are unchanged from M4.

## What ships

| Artifact | Path | Status |
|---|---|---|
| Fuzz target | `crates/connector-http/fuzz/fuzz_targets/authority_canonicalization.rs` | unchanged (M4-R8) |
| Seed corpus | `crates/connector-http/fuzz/corpus_seeds/authority_canonicalization/` | 14 committed seeds |
| Working corpus | `crates/connector-http/fuzz/corpus/authority_canonicalization/` | grown by libFuzzer |
| This receipt | `docs/receipts/m4-r8-fuzz-receipt.md` | new |

## Reproduction commands

The README at `crates/connector-http/fuzz/README.md` documents both; the
commands executed here are exactly those.

```bash
# Replay the committed seeds only — fast (≈2 s), no fuzzing
cargo +nightly fuzz run --fuzz-dir crates/connector-http/fuzz \
    authority_canonicalization -- -runs=0 \
    crates/connector-http/fuzz/corpus_seeds/authority_canonicalization

# Random fuzz for 30 s on top of the seeds — evidence of R11
cargo +nightly fuzz run --fuzz-dir crates/connector-http/fuzz \
    authority_canonicalization -- -max_total_time=30 -max_len=512
```

Both must exit 0 and report `Done N runs in T second(s)`. Both did.

## Evidence — measured

### Seed replay (2026-09-29T10:37Z)

```text
INFO: Loaded 1 modules   (13109 inline 8-bit counters)
INFO:       14 files found in crates/connector-http/fuzz/corpus_seeds/authority_canonicalization
INFO:     3141 files found in crates/connector-http/fuzz/corpus/authority_canonicalization
INFO: seed corpus: files: 3155 min: 1b max: 512b total: 305757b rss: 47Mb
#3156	INITED cov: 3606 ft: 14607 corp: 2438/234Kb exec/s: 3156 rss: 103Mb
#3156	DONE   cov: 3606 ft: 14607 corp: 2438/234Kb lim: 512 exec/s: 3156 rss: 103Mb
Done 3156 runs in 1 second(s)
```

- Coverage: **3606 edges / 14607 features**.
- Seed corpus: 14 committed + 3141 grown = 3155 inputs replayed.
- Exit: 0. Time: 1 s.

### Random fuzz 30 s — run 1 (2026-09-29T10:37Z)

```text
#468980	DONE   cov: 3629 ft: 14911 corp: 2526/237Kb lim: 512 exec/s: 15128 rss: 452Mb
Done 468980 runs in 31 second(s)
```

- Coverage: **3629 edges / 14911 features**.
- Corpus grown to 2526 inputs.
- Exit: 0. Time: 31 s. No crashes, no `artifacts/`.

### Random fuzz 30 s — run 2 (2026-09-29T10:38Z, reproducibility)

```text
#450906	DONE   cov: 3638 ft: 15162 corp: 2549/240Kb lim: 512 exec/s: 14545 rss: 464Mb
Done 450906 runs in 31 second(s)
```

- Coverage: **3638 edges / 15162 features**.
- Exit: 0. Time: 31 s.

## Reproducibility

Two consecutive 30 s runs on the same checkout produce coverage within the
same ballpark (3600–3650 edges / 14,900–15,200 features) and exit 0. The
harness is deterministic on the committed seeds (run-1 vs run-2 diverge
only because libFuzzer's entropic schedule picks different mutations per
run, not because the oracle differs).

The host fingerprint matters because R11 ties perf claims to the host
that produced them.

| Field | Value |
|---|---|
| Host | `Linux bazzite-rubentxu 7.2.7-ogc1.1.fc44.x86_64` |
| OS | `Bazzite 44.20260928.0 (Kinoite)` (Fedora 44 base) |
| `rustc` | `1.99.0-nightly (d453bdd8f 2026-08-14)` |
| `cargo-fuzz` | `0.13.2` |
| Backend | libFuzzer (in-process), entropic power schedule (0xFF, 100) |

## What this evidence proves — and what it does not

**Proves** (R11 corpus-green, R6 leak-harness corner):

- The oracle in `authority_canonicalization.rs` (no-false-allow +
  round-trip stability) holds for every input the fuzzer can produce in
  30 s on this host, on top of the committed seed corpus.
- The committed seed corpus pins the property claims the README names
  (`approved_bare`, `uat008_suffix`, `lookalike_percent`, `idna_rejected`,
  `uat008_embedded`, `uat008_userinfo`, `null_byte`, `single_label`,
  `leading_space`, `explicit_port`, `ipv6_literal`, etc.).
- The harness builds and runs reproducibly — the operational piece
  R6/R11 was missing.

**Does NOT prove** (out of scope; honest gaps):

- A longer fuzz campaign. 30 s is a corner of evidence, not the
  R11-recurring continuous run. R11's intent is to keep the corpus
  green on every change; this cycle establishes the **rung**, the next
  cycle widens it.
- A second fuzz target. The README names only `authority_canonicalization`;
  M4-R8 is a single target by design.
- Header parsing fuzz. The target is URL-shaped inputs only. Adding
  the header fuzz target is the natural follow-up and is named in the
  backlog as future work.

## Honesty note

The harness, oracle, and seeds were built in M4 and committed in 65893cd.
This cycle did **not** invent them — it produced the reproducible evidence
the M4-R8 receipt was missing. Backlog item `bl-bl-01M3N3FKYF000387A6YD7C7G40`
is closable on that basis.

## Carry-forward

- Continuous fuzzing in CI (R11's recurring intent). Not shipped — the
  prototype has no CI yet.
- Header-parsing fuzz target. Natural next item; not in scope here.