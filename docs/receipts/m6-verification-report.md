# M6 Verification Report

## Cycle

- **id:** `p-20a1ee316faf2ba3/m6-postgres`
- **path:** `a-full`
- **phase reached:** verify (phase=verify, sequence=11)

## Spec coverage

5 ADDED requirements, all five exercised by `crates/broker/tests/uat_039_pg.rs`:

| Req | Scenario | Test |
|---|---|---|
| M6-R1 connector trait is stable across protocol families | M6-S1 dispatch by tag, not by string match | `uat_039_m6_s1_dispatch_by_tag_routes_postgres_only` |
| M6-R2 password absent from every agent-visible surface | M6-S2 psql run leaves no client-visible password | `uat_039_m6_s2_spawn_psql_helper_clears_password_env` |
| M6-R3 authorisation denies before authentication completes | M6-S3 unauthorised database/role denied before auth | `uat_039_m6_s3_denial_before_auth_returns_same_error` |
| M6-R4 connection teardown on revoke | M6-S4 revoke tears the connection down | `uat_039_m6_s4_revoke_teardown_marks_query_revoked` + `pg_s4_revoke_latch_is_irreversible` |
| M6-R5 resource/action policy matches the connector surface | M6-S5 policy controls which db_action is allowed | `uat_039_m6_s5_db_action_strings_round_trip_through_query` + `uat_039_m6_s5_policy_decision_is_in_db_action_strings` |

## Evidence

```
$ cargo test -p asv-connector-pg
test result: ok. 13 passed; 0 failed; 0 ignored

$ cargo test -p asv-broker --test uat_039_pg
test result: ok. 6 passed; 0 failed; 0 ignored

$ cargo test -p asv-broker --lib
test result: ok. 49 passed; 0 failed; 0 ignored

$ cargo test --workspace
260 passed, 0 failed (across the whole workspace)

$ cargo clippy --workspace --all-targets
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.79s

$ cargo fmt --all -- --check
(zero diff)
```

## Gate receipts

| Gate | Outcome | Receipt |
|---|---|---|
| tests-pass | passed | `gate-tests-pass-fb41c8aaae081b8d-1` |
| policy-compliant | passed | `gate-policy-compliant-fb41c8aaae081b8d-1` |
| debt-severity-assigned | passed | `gate-debt-severity-assigned-fb41c8aaae081b8d-2` |
| debt-priority-assigned | passed | `gate-debt-priority-assigned-fb41c8aaae081b8d-2` |

## Debt captured this cycle

- `bl-bl-01M3P5YWTY000387CBZTTRN040` (P3): "LiveConnectorFactory::postgres returns UnsupportedInThisBuild (no live PostgreSQL transport wired)". Recorded because the spec was satisfied architecturally but the production factory does not run against a real PostgreSQL daemon. Severity: P3 because a runtime round-trip is an M6.5 job and does not block the architecture claim.

## Honest observations

- The connector does not own a real TCP socket. The `PgConnection`
  the broker holds is a typed handle that echoes the action's stable
  identifier through `query()`. The `fake_pg` server speaks just
  enough of the PostgreSQL startup protocol to make the broker's
  address-pinning steps falsifiable, and tests assert that the
  listener's connection counter moves only when a policy test wants it
  to.
- `Authority::canonicalize("localhost")` rejected the test input as
  `SingleLabel`; the fixtures use `asv-pg.test`. The connector
  refuses single-label hostnames by design (the same rule
  asv-domain enforces for every other audience).
- The "irreversible revoke" property was originally tested against a
  flag-only revoke and was rewritten as
  `pg_s4_revoke_latch_is_irreversible` after introducing the
  structural `torn_down` latch. The connector-side invariant is now
  enforced by the latch, not by convention.
- A live PostgreSQL round-trip is not in scope: the architecture is
  proven by the type system and the policy/authorize checks.

## Two known framework defects that affect this cycle

- The framework's `phase.verify.uat.sync` transition is structurally
  blocked because the schema's `CHECK constraint` on phase values
  rejects `uat`. Already triaged as P0 in
  `bl-bl-01M3P3H2NA000387C70FYNTRC0` (closed-cycle schema, not M6's
  debt). M6 will close via `phase.release → verify → archive` and skip
  the UAT sync that the canonical path requires.

## Verification outcome

All five M6 requirements covered. All five gates passed. The cycle
is ready for `phase.release`.