# M4 Traceability — requirements, scenarios and UAT to evidence

Every M4 claim, the executable thing that discharges it, and what was actually
run. A row with no evidence is a row that is not done, whatever the
implementation plan checkbox says.

`HEAD` for this table: `d96d035` (M4 implementation complete).
Verification host: see the `UAT-030` row — the requirement asks for it and the
number is not portable without it.

## Requirements

| Req | Statement (abridged) | Discharged by | Evidence |
|---|---|---|---|
| M4-R1 | A surrogate carries no secret and the provider rejects it | `crates/broker/tests/uat_005_replay.rs` | `a_surrogate_sent_straight_to_the_provider_is_not_a_credential`, `a_surrogate_in_an_ordinary_shell_is_inert` |
| M4-R2 | A surrogate is usable only by the session it was issued to | `crates/broker/tests/uat_005_replay.rs` | `a_surrogate_copied_into_another_session_buys_nothing` |
| M4-R3 | Canonicalization has no false allow | `crates/connector-http/fuzz/` + `crates/connector-http/tests/uat_008_url_tricks.rs` | 2,522,433 fuzz executions, 0 crashes; 14 committed seeds |
| M4-R4 | The DNS answer is constrained at connect time | `crates/connector-http/src/transport.rs` (`resolve_and_pin`, `AddressPolicy`) | `private_and_metadata_addresses_are_refused_by_default`, `smuggled_address_forms_are_refused`, `a_hand_built_audience_cannot_bypass_the_address_policy` |
| M4-R5 | Credentials are not forwarded across origins | `crates/connector-http/src/github/tests.rs`, `transport.rs` | `a_cross_origin_redirect_never_sends_the_credential_to_the_target`, `a_cross_origin_redirect_never_reaches_the_other_origin` |
| M4-R6 | Failure is closed, never downgraded | `crates/broker/tests/uat_017_crash.rs`, `uat_017_env_scan.rs` | `a_live_broker_without_a_vault_refuses_instead_of_degrading`, `retrying_after_the_broker_restarts_is_still_denied` |
| M4-R7 | Rotation preserves the stable reference | `crates/broker/tests/uat_027_rotation.rs` | `rotation_under_a_live_session_keeps_the_same_surrogate_and_uses_the_new_token`, `the_credential_id_stays_stable_and_resolvable_across_rotation` |
| M4-R8 | Canonicalization is fuzzable | `crates/connector-http/fuzz/` | see `fuzz/README.md`, including the two injected mutations that were caught |
| M4-R9 | Brokered reads meet UAT-030 | `crates/broker/tests/uat_030_perf.rs` | `one_hundred_brokered_reads_stay_under_the_p95_budget`, `a_teardown_leaves_no_sessions_no_surrogates_and_no_grants` |

## Scenarios

| Scenario | Requirement | Evidence |
|---|---|---|
| M4-S1 surrogate rejected upstream | M4-R1 | `uat_005_replay.rs` |
| M4-S2 replay from a sibling session | M4-R2 | `uat_005_replay.rs` |
| M4-S3 case normalization and authority confusion | M4-R3 | `uat_008_url_tricks.rs` + fuzz corpus |
| M4-S4 rebinding to a private address | M4-R4 | `transport.rs` address-policy tests |
| M4-S5 cross-origin 302 | M4-R5 | `github/tests.rs` + `transport.rs` wire tests |
| M4-S6 broker dies mid-operation | M4-R6 | `uat_017_crash.rs` |
| M4-S7 rotate under a live session | M4-R7 | `uat_027_rotation.rs` |
| M4-S8 corpus finds no false allow | M4-R8 | `fuzz/README.md` |
| M4-S9 repeated reads and signatures | M4-R9 | `uat_030_perf.rs` |

## Exit UAT

M4's exit gate in `15-ROADMAP.md` names UAT-005..010, 017, 027, 030 and a
URL/header fuzz corpus.

| UAT | What it requires | Evidence |
|---|---|---|
| UAT-005 | Placeholder replay outside the session | `crates/broker/tests/uat_005_replay.rs` |
| UAT-006 | Hostile destination: `evil.example` is denied before credential injection | `crates/connector-http/tests/uat_008_url_tricks.rs`, `transport.rs` |
| UAT-007 | Cross-origin redirect does not forward the credential | `crates/connector-http/src/github/tests.rs` |
| UAT-008 | URL parser tricks, no false allow | `crates/connector-http/tests/uat_008_url_tricks.rs` + fuzz corpus |
| UAT-009 | DNS rebinding is controlled by destination policy | `transport.rs` (`resolve_and_pin`, `AddressPolicy`) |
| UAT-010 | HTTP surrogate bridge: real auth upstream, surrogate only in the client | `crates/broker/tests/uat_005_replay.rs`, `github/tests.rs` |
| UAT-017 | Broker crash fails closed | `crates/broker/tests/uat_017_crash.rs`, `uat_017_env_scan.rs` |
| UAT-027 | Rotation preserves the stable credential id | `crates/broker/tests/uat_027_rotation.rs` |
| UAT-030 | 100 brokered reads, p95 < 5 ms, no leak after teardown | `crates/broker/tests/uat_030_perf.rs` |
| fuzz | URL/header corpus, no false allow | `crates/connector-http/fuzz/` |

## The UAT-030 host

The UAT requires the host to be recorded, because "normal workstation" has no
numeric definition and a p95 without a host is not a measurement. The test
prints it on every run. At `d96d035`:

```text
UAT-030 host=Intel(R) Xeon(R) CPU E5-2682 v4 @ 2.50GHz reads=100 p50=4 p95=4 worst=5 budget=5ms
```

p95 is 4 ms against a 5 ms budget, and the worst single sample is 5 ms. Read
that margin honestly: it is 1 ms on a shared vCPU, and the file's own header
says most of it is the TLS handshake to the loopback origin, not the
authorization check. The gate is executable and it currently passes here. It is
not a claim that the same number holds on a laptop on a train, and the host
being printed is what makes that difference legible instead of invisible.

Re-running the test on another host prints that host instead, and the gate is
then falsifiable there too.

## Design deviations

**D10 named the wrong file, and the implemented one is broader.**
The design said the UAT-030 harness would be
`crates/policy/tests/p95_authz.rs`: 100 `authorize` calls, p95 in-test, host
from `/proc/cpuinfo`. What shipped is
`crates/broker/tests/uat_030_perf.rs`, which measures the whole brokered read
as the agent experiences it — session ownership, surrogate budget, policy
decision, vault unlock, TLS round trip, response decode.

The wider measurement is deliberate, and its own header states why: a p95 that
excluded the credential access would not tell an operator whether brokered
reads feel slow, which is what `NFR-PERF-001` is protecting. It also exposes a
risk the narrow version would have hidden: most of the 4 ms is the TLS
handshake to the loopback origin, so the budget is much tighter than a pure
`authorize` micro-benchmark would have implied. Keeping the number honest was
worth more than keeping the design's filename.

This is a deviation from the approved design and is recorded as one, not
absorbed silently. Nothing else in D1..D11 deviated.

## What the falsification attempts were

Two mutations were injected into `Authority::canonicalize` and reverted, to
show the new fuzz target can go red:

- `labels.len() < 2` → `labels.len() < 2 && false`
- `label.ends_with('-')` → `label.ends_with('-') && false`

Both were caught within 45 s at the independent oracle rather than at a
restatement of the implementation. Details and the corpus table are in
`crates/connector-http/fuzz/README.md`.

One guard was red for the wrong reason before the corpus existed: the first
draft asserted an accepted authority never equals the approved authority, which
`api.github.com` itself violates. It was replaced by the only-m-approved-
spelling property, which is the sentence M4-S8 actually makes.

## What this table does not claim

- It does not claim the fuzzing found no bug. It claims 2.5 M executions found
  no crash *after* the two mutations were reverted, and that the two mutations
  it was able to inject were caught. Both facts are in `fuzz/README.md`.
- It does not claim UAT-006/007/009/010 have dedicated files. Their vectors
  are covered inside `uat_008_url_tricks.rs`, `github/tests.rs` and the
  transport unit tests; the traceability is a citation in this table, not a
  filename. Renaming those to per-UAT files would be cosmetic and is not
  claimed.
- It does not claim a p95 below 5 ms on any machine. It claims the gate is
  executable, the host is named, and the measurement excludes upstream
  provider latency exactly as `NFR-PERF-001` does.
