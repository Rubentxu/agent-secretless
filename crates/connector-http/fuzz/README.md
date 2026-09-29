# M4-R8 — URL/header fuzz corpus

`corpus_seeds/authority_canonicalization/` holds the inputs that are **committed**
and therefore part of the M4 exit evidence. Every file is named after the
property it pins, so the corpus reads as a list of claims rather than a pile of
hex.

`corpus/` is working state. `cargo fuzz run` writes there and grows it by
thousands of inputs per run; it is git-ignored because every entry in it is
reproducible from the seeds by re-running the target.

## How to run

```bash
# One-shot, long enough to be evidence (this is what produced the M4 receipt)
cargo +nightly fuzz run --fuzz-dir crates/connector-http/fuzz \
    authority_canonicalization -- -max_total_time=120 -max_len=512

# Replay the committed seeds only, no fuzzing
cargo +nightly fuzz run --fuzz-dir crates/connector-http/fuzz \
    authority_canonicalization -- -runs=0 \
    crates/connector-http/fuzz/corpus_seeds/authority_canonicalization
```

`--fuzz-dir` is required: the fuzz crate is not a workspace member, so
`cargo fuzz` cannot infer where it is from the repository root.

## What the seeds pin

| Seed | Requirement | Why it is here |
|---|---|---|
| `approved_bare` | M4-R3 | `api.github.com` is the approved authority and must be accepted |
| `approved_mixed_case` | M4-R3 | `API.GITHUB.COM` canonicalizes to the approved authority |
| `approved_trailing_dot` | M4-R3 | `api.github.com.` canonicalizes to the approved authority |
| `uat008_suffix` | UAT-008 | `api.github.com.evil.example` must not be authorized |
| `uat008_userinfo` | UAT-008 | `api.github.com@evil.example` must not be authorized |
| `uat008_embedded` | UAT-008 | an approved URL in a query parameter is not an approval |
| `lookalike_suffix` | M4-S8 | the bare-host spelling of the UAT-008 suffix attack |
| `lookalike_percent` | M4-S8 | percent-encoding must not smuggle a label separator |
| `idna_rejected` | design D5 | IDNA is denied, not supported; a decision, not a gap |
| `null_byte` | M4-S8 | an embedded NUL must not truncate the host |
| `leading_space` | M4-S8 | whitespace smuggling past a textual allowlist comparison |
| `single_label` | M4-S8 | `localhost` can never be an approved audience |
| `ipv6_literal` | design D5 | an IP literal has no DNS answer to pin |
| `explicit_port` | M4-S8 | a non-default port is a different origin |

## Falsification

A green run is only meaningful if the target can go red. Both mutations below
were injected into `Authority::canonicalize` and both were caught within 45 s,
at the independent oracle (`fuzz_targets/authority_canonicalization.rs:83`),
not at a restatement of the implementation:

1. `if labels.len() < 2` → `if labels.len() < 2 && false` — accepts `localhost`.
2. `label.ends_with('-')` → `label.ends_with('-') && false` — accepts a
   trailing-hyphen label.

Both mutations were reverted and the crash artifacts deleted. A fuzz target
that has never been seen red is a guess, not a guard.
