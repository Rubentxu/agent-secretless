# M6 Release Receipt

- **cycle:** p-20a1ee316faf2ba3/m6-postgres
- **release tag:** `m6-postgres`
- **release sha:** 437cee921204b60ee129530e35b9ef024c27a7fc
- **released_baseline:** m4-http-broker (the immediately previous
  closed cycle; M5 was skipped per project decision)
- **development_head:** 437cee921204b60ee129530e35b9ef024c27a7fc
- **actual_release_tag:** m6-postgres
- **binary_sha256:** n/a (no binary release this cycle; the cycle
  ships a new library crate, not a release artefact)

## Commits pushed since cycle start

```
4514e02 docs(m6): specification, design and implementation plan
1aad5f8 feat(connector-pg): scaffold asv-connector-pg crate with semantic surface
07c2e62 chore(deps): lock new tokio features for asv-connector-pg spawn
aa3c826 feat(connector-pg): PgPolicy trait and pre-connect authorize (M6-R3)
93817d4 feat(connector-pg): PgConnection with latched revoke teardown (M6-R4)
ef2a53e feat(broker): ConnectorFactory::postgres (M6-T7)
de74d29 test(uat-039): M6-S1..S5 integration test for the PG connector
272983e chore(fmt): rustfmt M6 code and add implementation-receipt
437cee9 docs(receipt): M6 verification report  <- HEAD
```

## Remote state

```
$ git rev-parse origin/main
437cee921204b60ee129530e35b9ef024c27a7fc

$ git rev-parse HEAD
437cee921204b60ee129530e35b9ef024c27a7fc

$ git rev-parse m6-postgres
437cee921204b60ee129530e35b9ef024c27a7fc

HEAD == origin/main == m6-postgres.
```

## Gates passed before release

- tests-pass
- policy-compliant
- debt-severity-assigned
- debt-priority-assigned

## Risk notes

- The architectural claim of M6 is proven by the type system and by
  the six-test `uat_039_pg` integration suite. A live PostgreSQL
  round-trip is not in scope for this cycle. Triaged as P3 in
  `bl-bl-01M3P5YWTY000387CBZTTRN040`.
- The framework's `phase.verify.uat.sync` is structurally blocked by
  a schema CHECK constraint that rejects `uat` as a phase (P0 in
  `bl-bl-01M3P3H2NA000387C70FYNTRC0`). M6 closes via
  `phase.verify.complete → phase.release.complete → phase.archive` and
  does not require the UAT sync transition that the canonical
  A-full path would otherwise demand.

## Next roadmap step

The next milestone after M6 is the resolution of the framework's
UAT sync defect, then the milestones that depend on
`phase.verify.uat.sync` becoming available again. The immediate
follow-ups are tracked in the live backlog (12 items M4 + 1 M6).