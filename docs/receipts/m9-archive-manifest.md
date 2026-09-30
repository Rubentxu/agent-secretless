# M9 Archive Manifest

## Cycle

- **id:** `p-20a1ee316faf2ba3/m9-tls-acceptor`
- **path:** `A-full`
- **milestone:** M9 — transparent TLS bridge
- **goal:** present the session leaf to a TLS client without handing over
  the private key
- **status:** `CLOSED`, phase `archive`, 9 artifacts, lease released
- **ledger:** 436 events, chain continuity verified, `verify-references`
  `dangling: 0`

## Published subject

- **main_sha:** `3f73a7979b7b84d5898a22b9bcad7d6503cb8a52`
- **tag:** `v0.15.0` (annotated; peels to the same SHA)
- **release_type:** minor

## Commits

| sha | type | summary |
|---|---|---|
| `e7ee75b` | feat(tls-acceptor) | present a session leaf over a real TLS handshake |
| `1726686` | chore(release) | bump to 0.15.0 |
| `17ef211` | test(tls-acceptor) | verify the handshake with openssl, not only with rustls |
| `c4ac525` | test(tls-acceptor) | make the chain-order assertion actually assert |
| `866476b` | test(tls-acceptor) | cover REQ-6, which no test exercised |
| `3f73a79` | test(uat) | v0.15.0 acceptance plan and report for the TLS acceptor |

## Bridges

- M9 spec REQ-1..REQ-6 → `e7ee75b` plus the three test commits. REQ-3,
  REQ-5 and REQ-6 are only exercised by the later commits, so the published
  subject is the range, not the single feature commit.
- M9 verify report → `866476b`. The 13-test count is the state at this
  commit.
- UAT plan and report → `3f73a79`. Placed at the repo root because
  `sddk uat status` resolves them relative to the cwd and never consults
  XDG storage; the release precondition could not proceed until they were
  committed there.

## Verification at close

- `cargo test --workspace`: 515 passed, 0 failed, 0 ignored
- `cargo test -p asv-tls-acceptor`: 13 passed, 0 failed
- `cargo fmt --check`: clean
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `sddk vault validate`: 19 nodes, 0 errors, 0 warnings
- 7 falsifications, each red on a distinct test or property
- 5 consecutive runs, 0 flakes

## Acceptance provenance

Human acceptance for S-1..S-4 is an **owner override**. The owner declared
the gates approved in session at `2026-09-30T10:26:17Z` without executing
the scenarios. The earlier record (`actor: agent:jcode`, 10:10:13Z) said
verbatim "No human acceptance performed" and did not authorize release.

## Carried forward, not closed

**M9 is not complete.** The eBPF redirect is not implemented. `asv-ebpfd`
holds parsing only (11 tests) and has no `libbpf`, no `bpf-sys`, and no
syscall path to load or attach a program. Four probes on this host refused
`bpf(BPF_MAP_CREATE)`: `EPERM` bare, `EPERM` in a user namespace whose
`CapEff` reported `CAP_SYS_ADMIN`, `EACCES` rootless, `EPERM` with
`--privileged`. The remaining route needs `sudo`.

This cycle is archived as *the acceptor is released*, not as *M9 is done*.

Also outstanding: the acceptor does not join per-connection handshakes on
shutdown (LOW, deferred to the eBPF supervisor). M11 lacks live OAuth2. M12
lacks TPM. UAT-012/013 are not executable on this host. Four SDDK UAT
tooling defects are triaged in the backlog; see `m9-uat-tooling-defects.md`.
