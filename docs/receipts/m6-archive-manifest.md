# M6 Archive Manifest

## Cycle

- **id:** p-20a1ee316faf2ba3/m6-postgres
- **status at archive:** RELEASED
- **release tag:** m6-postgres
- **release sha:** 437cee921204b60ee129530e35b9ef024c27a7fc

## Spec delta

- **docs/specs/m6-postgres/specification.md** — 5 ADDED requirements (M6-R1..R5)
  with 5 falsifiable scenarios.

## Backlog items introduced

- bl-bl-01M3P5YWTY000387CBZTTRN040 (P3): LiveConnectorFactory::postgres
  returns UnsupportedInThisBuild.

## Gate receipts

| Gate | Receipt |
|---|---|
| tests-pass | gate-tests-pass-fb41c8aaae081b8d-1 |
| policy-compliant | gate-policy-compliant-fb41c8aaae081b8d-1 |
| debt-severity-assigned | gate-debt-severity-assigned-fb41c8aaae081b8d-2 |
| debt-priority-assigned | gate-debt-priority-assigned-fb41c8aaae081b8d-2 |
| no-pending-effects | gate-no-pending-effects-0c7ad7e3932d3a56-1 |
| release-uat-approved | gate-release-uat-approved-0c7ad7e3932d3a56-1 |
| ledger-valid | gate-ledger-valid-c55736fca207ad9a-1 |
| vault-index-current | gate-vault-index-current-c55736fca207ad9a-1 |

## Artifacts archived

| Artifact                          | Path                                                |
|----------------------------------|-----------------------------------------------------|
| exploration-report               | docs/exploration/m6-exploration.md                   |
| specification                    | docs/specs/m6-postgres/specification.md              |
| design                           | docs/design/m6-design.md                            |
| implementation-plan              | docs/plans/m6-plan.md                               |
| implementation-receipt           | docs/receipts/m6-implementation-receipt.md           |
| verification-report              | docs/receipts/m6-verification-report.md              |
| release-receipt                  | docs/receipts/m6-release-receipt.md                  |
| merge-receipt                    | docs/receipts/m6-merge-receipt.md                    |

All eight artifacts were also copied into the cycle's
`$SDDK_PROJECT/p-20a1ee316faf2ba3/cycle-artifacts/p-20a1ee316faf2ba3/m6-postgres/`
directory for the framework's durable storage.

## Commits archived

```
4514e02 docs(m6): specification, design and implementation plan
1aad5f8 feat(connector-pg): scaffold asv-connector-pg crate with semantic surface
07c2e62 chore(deps): lock new tokio features for asv-connector-pg spawn
aa3c826 feat(connector-pg): PgPolicy trait and pre-connect authorize (M6-R3)
93817d4 feat(connector-pg): PgConnection with latched revoke teardown (M6-R4)
ef2a53e feat(broker): ConnectorFactory::postgres (M6-T7)
de74d29 test(uat-039): M6-S1..S5 integration test for the PG connector
272983e chore(fmt): rustfmt M6 code and add implementation-receipt
437cee9 docs(receipt): M6 verification report
```

## Closing note

The M6 cycle is closed. The connector-pg crate ships in 8 commits
across the explore, specify, design, plan, build, verify, release and
archive phases. Workspace tests stay green (260 passed). The next
backlog-driven milestone is the framework defect resolution that
unblocks `phase.verify.uat.sync`; nothing else in the queue requires
M6's specific work.