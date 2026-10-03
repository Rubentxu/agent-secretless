# ADR-0028 — Agent skills remain external protocol clients

- Status: Proposed
- Date: 2026-10-02

## Decision

Official ASV skills live in the external agent-skill repository and consume the versioned agent protocol.

ASV binaries contain no prompts or Markdown skills.

## Consequences

- Product and agent guidance evolve independently.
- skills.sh remains a natural distribution channel.
- Compatibility is protocol-based rather than tied to exact product release.
