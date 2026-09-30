# M9 Release Receipt

- **cycle:** `p-20a1ee316faf2ba3/m9-tls-acceptor`
- **release tag:** `v0.15.0` (annotated)
- **release sha:** `3f73a7979b7b84d5898a22b9bcad7d6503cb8a52`
- **released_baseline:** `v0.14.0` (`60b03cf`)
- **development_head:** `3f73a7979b7b84d5898a22b9bcad7d6503cb8a52`
- **actual_release_tag:** `v0.15.0`
- **binary_sha256:** n/a (no binary release; the cycle ships a new
  library crate, `asv-tls-acceptor`, not a release artefact)
- **release_type:** minor — a new crate is a new capability

## Postconditions, verified against the remote

| check | result |
|---|---|
| `HEAD == origin/main` | yes, both `3f73a79` |
| `git ls-remote origin 'refs/tags/v0.15.0^{}'` | `3f73a797...` |
| `git rev-parse 'v0.15.0^{commit}'` | `3f73a797...` |
| `git cat-file -t v0.15.0` | `tag` (annotated, not lightweight) |
| worktree clean at release | yes |

Capability receipts: `cap-git-push-5760c6138f1a` and
`cap-git-tag-6b57d01d96db`, both `succeeded`.

## Verification at release

- `cargo test --workspace`: 515 passed, 0 failed, 0 ignored
- `cargo test -p asv-tls-acceptor`: 13 passed, 0 failed
  (5 unit, 6 handshake, 2 OpenSSL)
- `cargo fmt --check`: clean
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- 7 falsifications, each red on a distinct test or property
- 5 consecutive runs, 0 flakes

## Acceptance provenance

Human acceptance for S-1..S-4 is an **owner override**. The owner declared
the gates approved in session at `2026-09-30T10:26:17Z` **without executing
the scenarios**. The earlier record (`actor: agent:jcode`, 10:10:13Z) said
verbatim "No human acceptance performed" and did not authorize release; the
owner's grant superseded it on the owner's authority, not on agent
judgement. Machine evidence is unchanged and independently reproducible.

Gate receipts: `gate-release-uat-approved-869d739054c8ea38-1`,
`gate-no-pending-effects-869d739054c8ea38-1`,
`gate-ledger-valid-a19f9ecdb9c45a72-1`,
`gate-vault-index-current-a19f9ecdb9c45a72-1`.

## What this release does NOT contain

**M9 is not complete.** The eBPF redirect is not implemented.
`asv-ebpfd` holds parsing only (11 tests) and carries no `libbpf`, no
`bpf-sys`, and no syscall path to load or attach a program. Four probes on
this host refused `bpf(BPF_MAP_CREATE)`: `EPERM` bare, `EPERM` in a user
namespace whose `CapEff` reported `CAP_SYS_ADMIN`, `EACCES` rootless, and
`EPERM` even with `--privileged`. The remaining route needs `sudo`, which the
session did not have.

The acceptor is therefore verified standalone. No evidence yet shows a
redirected connection reaching it. See `m9-ebpf-capability-block.md`.
