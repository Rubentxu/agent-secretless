# ADR-0027 — Distribution is allowlist-driven from an explicit product component manifest

- Status: Proposed
- Date: 2026-10-02

## Decision

Release packaging must enumerate public, private-runtime, optional and forbidden executables.

Target shape:

```text
public:          asv
private-runtime: asv-brokerd
optional:        asv-console
forbidden:       asv-vault-tool
```

Glob-based packaging is forbidden.

## Consequences

- Test binaries cannot accidentally ship.
- mise/deb/rpm/direct installer consume the same component model.
- Distribution UAT can compare Cargo metadata against the product manifest.
