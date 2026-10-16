# B1.10 Implementation Receipt — the recovery journal is wired

Block: B1.10 of `docs/plans/b1-delivery-roadmap.md` (branch
`b1/worker-lifetime`). Closes audit finding H-04: the recovery module existed
since M13 with a normative UAT (UAT-035) and zero production callers, while
two documents claimed the journal was already protecting mutations. The spec
already decided the direction — UAT-035 is M13's exit UAT — so the module was
wired, not retired.

## What landed

- **Intent-only journaling, fsync'd before the write.** Every vault mutation
  (`CreateCredential`, `DeleteCredential` — the only two production mutation
  paths today) records an intent (kind + credential id, never secret
  material) to the journal file and `sync_all()`s it BEFORE the vault write.
  The intent is cleared — durably — as soon as the write RETURNS, on success
  and on clean failure alike. Invariant: a surviving entry always means the
  mutation was in flight when the process died.
- **Startup reconciliation with operator language.** brokerd opens the
  journal beside the vault by default (`--journal-file` overrides), replays
  it, and reports each surviving intent against the loaded inventory:
  creation completed / DID NOT COMPLETE (the material left with the crashed
  process — re-issue), revocation completed / DID NOT COMPLETE (the vault
  STILL holds it — re-issue the revocation; the security-relevant case). A
  torn tail is discarded and a corrupt record stops the replay (the module's
  CRC discipline, UAT-035's own rows); only the valid prefix is reported and
  the vault stays the source of truth. After reconciliation the journal
  restarts empty; a crash between report and reset re-reports the same
  intents (at-least-once visibility, never lost state).
- **Operator surface.** `Response::Pong` gains
  `recovered_journal_intents: u64` with `#[serde(default)]` (additive, both
  wire directions tolerant — same pattern B1.8 used); `asv status` prints
  `recovery: N interrupted vault mutation(s) reconciled from the journal at
  startup` when it is non-zero.
- **The two stale comments now describe reality**: `Cargo.toml`
  (`[profile.dist]`) and `packaging/asv-brokerd.service` (Restart=on-failure
  rationale) — both had claimed a fsync'd journal since before it existed.

## Evidence (all run on this tree)

| Check | Command | Result |
|---|---|---|
| Unit: protocol | `cargo test -p asv-broker --locked --lib journal` | intent durable before the write (on-disk bytes replay to 1 record), cleared after (file empty); torn journal reconciles only the valid prefix; empty journal reconciles nothing |
| Unit: reconciliation | `... --lib intents_are_reconciled` | 3 intents reconciled against a 1-credential inventory; sticky counter; at-least-once re-count |
| E2E | `cargo test -p asv-broker --locked --test eph_crash_replay` | crash-shaped seeded journal → `recovered_journal_intents == 2` on the wire, both reconciliation lines in the broker's own stdout (`DID NOT COMPLETE` / `COMPLETED`), journal restarted empty; clean mutation leaves no intent; SIGKILL + restart → 0 |
| Falsification | startup reconciliation line disabled → E2E | **RED** (count 0 ≠ 2); restored → **GREEN** |
| Suites | broker --lib **692**, ipc-protocol --lib **21**, asv-cli bin **135** | all pass |
| Formatting | `cargo fmt --all -- --check` | clean |

## Decisions

- Intent-only, no repair: the vault write is atomic and the journal carries
  no secret material (it never can), so replay cannot and must not re-apply
  a mutation. The product is precise visibility plus the structural claim
  M13's module docs made, now wired.
- Only the two real mutation paths are journaled. `CredentialRotated` and
  `VaultResealed` remain enum variants with no production call site; the
  reconciliation reports them if an old journal ever carries one, instead of
  pretending the paths exist.
- Journaling is on by default beside the vault — that is what makes the
  dist profile and systemd comments true by default, which was the point of
  H-04. `--journal-file` exists for split-mount deployments.
- The worker delegation was degraded this block (the explorer also failed);
  the block was implemented inline by the parent from the explored design.

Risk: item 3 — `Response::Pong` gains an additive field (both wire directions
pinned by the existing compat tests, updated for the new field) and the two
mutation arms gained a pre-write step that refuses the mutation when the
journal cannot record (fail-closed: `Upstream` + explicit message). All
internal consumers updated; broker 692 / ipc 21 / cli 135 / E2E green.
