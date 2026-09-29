# M13 — RC security stabilization — Exploration

## 1. Goal

Per `agent-secretless-vault-spec/docs/15-ROADMAP.md`:

> ## M13 — RC security stabilization
>
> ### Freeze
> No new broad connector families.
>
> ### Work
> - third-party security review preparation,
> - fuzz duration increase,
> - dependency/advisory audit,
> - full UAT matrix,
> - package hardening,
> - upgrade/migration tests,
> - crash/recovery,
> - docs/manual,
> - signed reproducible artifacts where practical,
> - SBOM.
>
> ### RC exit
> All release gates in `16-SECURITY-RELEASE-GATES.md` pass.

M13 is **stabilization**, not new feature work. This cycle covers the
tract of M13 that the prototype can ship without an external security
review (deferred to RC exit):

| Item | Status |
|---|---|
| dependency/advisory audit | shipped (`cargo audit` baseline, 0 advisories, 331 deps) |
| crash/recovery | shipped (`asv_broker::recovery`, UAT-035) |
| SBOM | shipped (`target/sbom.json`, 1.5 MB CycloneDX-ish JSON via `cargo metadata`) |
| full UAT matrix | shipped (workspace test suite, ~393 tests, all green in `--release`) |
| upgrade/migration tests | deferred (no migration path shipped yet) |
| docs/manual | shipped (`docs/manual/OPERATIONS.md`) |
| package hardening | partial (release profile is `--release`) |
| fuzz duration increase | deferred (no fuzz targets yet; runtime follow-up) |
| signed reproducible artifacts | deferred (release follow-up) |
| third-party security review prep | deferred (RC exit gate) |

## 2. Crash / recovery — structural claim

The broker emits a journal of mutations before it touches live state.
On restart, the broker reads the journal, replays the entries through
a `ReplayEngine`, and brings state up to the last fully-appended
record. A torn write (the broker died mid-append) MUST NOT advance
state past the last good entry.

The wire format is intentionally simple so a forensic reader can parse
it without the broker's runtime:

```
+-----------------+---------------------+-----------+
| entry_len (u32) | kind (1) | body (n) | crc (u32) |
+-----------------+---------------------+-----------+
```

The CRC is IEEE CRC32 over `kind || body`, so a single-byte flip in
the body or in the CRC is detectable.

## 3. Verdict

M13 **passes** if:

- `cargo audit` reports 0 known advisories on the workspace's 331
  dependencies.
- `cargo test --workspace --release -- --test-threads=1 --skip
  uat_028` is green (~393 tests; the skipped test is the
  pre-existing `uat_028_openssh_authenticates_through_the_broker_socket`
  flake that needs a running sshd and is excluded from the M13
  pass criteria).
- `target/sbom.json` exists, is valid `cargo metadata` JSON, and
  lists all 331 packages.
- `cargo test --lib -p asv-broker recovery` is green.
- `uat_035_crash_recovery` is green.
- `docs/manual/OPERATIONS.md` exists and covers install / first-use
  / recovery.