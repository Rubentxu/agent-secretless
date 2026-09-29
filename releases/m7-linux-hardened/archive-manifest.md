# M7 Linux Hardened — Archive Receipt

## Cycle closed

- **name**: m7-linux-hardened
- **closed_at**: 2026-09-29T09:28:00Z (estimated; CI clock)
- **release_sha**: `ab8bdac`
- **tag**: `m7-linux-hardened` (annotated; SHA `ab8bdac`)

## Archived artifacts

The cycle's documentation artifacts were already captured by
`docs/specs/m7-linux-hardened/specification.md`, `docs/exploration/m7-exploration.md`,
and `docs/design/m7-design.md`. They are listed in the release receipt
and re-read here for the archive ledger.

| Artifact | Purpose |
| --- | --- |
| `docs/specs/m7-linux-hardened/specification.md` | ADDED requirements M7-R1..R5 |
| `docs/exploration/m7-exploration.md` | Codebase inventory + threat model |
| `docs/design/m7-design.md` | Harden module design + Landlock/Seccomp probe ABI |
| `releases/m7-linux-hardened/release-report.md` | Requirement coverage + gaps |
| `releases/m7-linux-hardened/merge-receipt.md` | Git history summary |

## Knowledge synced

- The `parse_verb` function in `asv-ebpfd` is the closed-surface
  enforcement point for the privileged helper. New verbs MUST be
  added by editing the `Verb` enum and the exhaustive match in
  `parse_verb`. The compile-time check `uat_024_verb_enum_has_no_load_variant`
  is the regression guard.
- The `harden::install` function in `asv-broker` is the single
  integration point for Linux process hardening. Adding new steps
  (e.g. namespace pinning) MUST extend the install order without
  changing the existing predicates so the UAT-005 idempotency
  assertion still holds.

## Follow-ups (deferred)

- **M8 eBPF R&D gate**: full Seccomp filter install + Landlock
  path ruleset. The current M7 code proves kernel support; M8
  proves enforcement.
- **M9 production deploy**: the `harden::install` call is currently
  invoked from the test harness; the broker binary's `init` function
  is the wiring point.