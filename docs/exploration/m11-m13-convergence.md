# M11-M13 convergence — status, evidence, and what is NOT claimed

Cycle: `p-20a1ee316faf2ba3/m11-m13-rc-convergence`
Date: 2026-09-30

## Why this document exists

M11, M12 and M13 shipped as annotated git tags (`m11-oauth2-framework`,
`m12-tpm-vault`, `m13-rc-stabilization`) on 2026-09-29, but without an SDDK
cycle and without a semver. That left the roadmap asserting milestone
completion with no cycle receipt behind it. This cycle reconciles the tags
against the roadmap, records what each one actually delivers, and states
plainly what remains prototype.

The tags were not empty. Each carries real code and real tests, and those
tests were re-run during this cycle rather than assumed.

## What each milestone delivers

### M11 — OAuth2 provider framework (`93ed1ae`)

- `crates/broker/src/oauth2.rs` (369 lines): closed-set issuer trait,
  content-addressed placeholder token, `StaticClientCredentialsIssuer`.
- `crates/broker/tests/uat_030_oauth2_surrogate_lifecycle.rs`: 6 tests,
  re-run green in this cycle.
- Design holds the invariant: the agent only ever holds access bytes;
  refresh bytes stay in the broker.

Honest label: **framework, not a shipped provider.** The issuer is
`StaticClientCredentialsIssuer`; there is no live OAuth2 AS interaction and
no PKCE. The roadmap lists OAuth2 as item 4 of 7 in M11's connector
ordering, so this is the framework slice, not the milestone.

### M12 — TPM / hardware-backed vault (`91d19d6`)

- `crates/vault/src/tpm.rs` (541 lines): `TpmDevice` trait, `TpmSealed`
  on-disk shape, `PcrPolicy`, `RecoveryBlob`.
- `crates/vault/tests/uat_034_tpm_device_bound_theft.rs`: 8 tests, re-run
  green in this cycle.
- The module's own doc says "prototype pass" and names `SoftwareTpm` as a
  content-addressed placeholder standing in for a real TCG TPM2 client.

**The decisive finding: this host has no TPM.** `/dev/tpm*` does not exist,
`/sys/class/tpm` is empty, and `/proc/cpuinfo` exposes no TPM flag. The
`tss2` command-line tools are installed, but a userspace TPM stack cannot
substitute for the device.

Therefore the UAT-034 result must be read exactly as: the *structural* shape
(sealed blob, PCR policy, recovery blob, device-bound theft scenario) is
exercised against a software placeholder. **No hardware-backed guarantee
is claimed, and none can be tested on this machine.** Swapping `SoftwareTpm`
for a real TCG client is the remaining M12 work, and it is gated on a host
with a TPM, not on code that can be written here.

### M13 — RC security stabilization (`4956255`)

- `crates/broker/src/recovery.rs` (442 lines) plus
  `uat_035_crash_recovery.rs`: 6 tests, re-run green in this cycle.
- `docs/manual/OPERATIONS.md`.
- SBOM under `target/`.

Gates re-verified in this cycle rather than trusted from the tag message:

| Gate | Result |
|---|---|
| `cargo audit` | 0 advisories across 335 dependencies |
| workspace suite | 486 passed / 0 failed / 1 ignored |
| clippy `-D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `sddk vault validate` | 37 nodes, 0 errors, 0 warnings |

## Work done in this cycle

### Landlock allow set narrowed (P2 debt, `e59e229`)

`bl-bl-01M3PS45V9000387DJAFC0YK00` was a security defect, not cosmetics. The
ruleset allowed `/home` and `/var/home` in full, read and write — every
user's home directory, writable by the process that holds secrets. The file
comment admitted why: the vault and audit paths default to
`~/.local/state`, the ruleset is irreversible, and with no way to declare
real paths the broad rule was the only way to avoid a broker that could not
open its own vault. So it was simultaneously too permissive and a
deployment trap.

`InstallPaths` resolves both: the caller declares the directories in use
(`main.rs` supplies the socket, vault and audit parents, all already
explicit CLI input), and the static set shrinks to `/tmp`, `/run`,
`/var/tmp` plus the system read paths. A default install is now NARROWER
than before.

Covered by `uat_048_landlock_install_paths.rs` in forked children, because
`restrict_self()` is irreversible. Falsified: re-adding the sibling
directory to the write set turns the denial test red with "undeclared
directory was writable".

### Vault node id collision (`9997e2b`)

`VAULT002`, pre-existing since the baseline import `1d920ab`:
`adrs/README.md` and `README.md` both derived the node id `README`.
Renamed to `adrs/adr-index.md`; no document referenced the old path.

## What is NOT claimed

1. **No hardware-backed vault.** M12 is structural only, for the reason
   above. It cannot be otherwise on this host.
2. **No live OAuth2 provider.** M11 is a framework with one static issuer.
3. **No M11-M13 semver.** These tags are not versions. The cycle that
   produced them did not run release, and moving `v0.11.0` would be a lie:
   its content predates every fix in this cycle.
4. **No UAT acceptance for M11-M13.** The v0.11.0 UAT plan covers the M10
   runtime surface. M12's device-bound theft test passed against a software
   placeholder, which is not the same claim the roadmap's M12 exit
   describes.

## Roadmap position

M13's exit is "all release gates in `16-SECURITY-RELEASE-GATES.md` pass",
and the roadmap explicitly delegates M11 and M13 completion to that document
rather than gating them on a fixed UAT set. The v1.0 story additionally
lists "transparent eBPF bridge only if M8/M9 passed", which is conditional on
the M8 research gate and outside this cycle.

The honest next milestone is not another tag. It is M12 on TPM hardware, and
M11 with a real provider behind the framework. Both need inputs this host
does not have.
