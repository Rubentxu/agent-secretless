# ADR-0004 — Cedar as initial authorization engine

- Status: Accepted
- Date: 2026-09-28

## Decision

Use Cedar for policy evaluation with a deny-by-default model.

Map authorization into Principal, Action, Resource and Context. Model both human and agent/workload identities so policy can restrict agents acting on behalf of users.

## Consequences

- Strong typed policy schema and explainable authorization model.
- Approval lifecycle remains an application concern; approval validity is supplied as trusted authorization context.
