# ADR-0017 — How an operator's revocation actually takes effect

- **Status**: Accepted
- **Date**: 2026-10-01
- **Supersedes**: nothing. **Extends**: ADR-0016 (how a human credential
  reaches the vault), ADR-0015 (control-plane admission), ADR-0011 (surrogate
  lifetime and uses), ADR-0002 (separate broker and UI).
- **Implements**: `REQ-A-Revocation-Reaches-The-File`,
  `REQ-B-The-Inventory-Follows-The-File`,
  `REQ-C-Tokens-Stop-Working-And-Stop-Counting`,
  `REQ-D-An-Unadmitted-Caller-Learns-Nothing`,
  `REQ-E-No-Message-Asserts-A-Capability-That-Exists`,
  `REQ-F-An-Admitted-Caller-Is-Told-The-Truth`,
  `REQ-G-Revocation-Survives-A-Restart`.

## Context

ADR-0016 opened the door and stopped. Its consequences section said so in
writing:

> **`DeleteCredential` remains un-wired.** It is admitted by the same rule and
> still writes nothing, so revocation does not survive a restart. Closing that
> is its own decision.

This is that decision. The state it inherited: `VaultWritePort::remove`
existed and had **zero** production callers; the broker's `DeleteCredential`
arm returned an unconditional refusal whose text claimed the vault write path
"is not available in this broker" — a statement that had been false since
ADR-0016 landed. Meanwhile M5's exit UAT reads "end-to-end add credential →
grant → agent use → **revoke**", so the last step of the milestone had no
implementation behind it at all.

Two questions were open when the design began, and both are decisions here
rather than deferrals.

## Decision

1. **The file goes first and goes alone.** The granted path is
   admission → `writer.remove` → inventory `retain` → surrogate revocation →
   `Response::CredentialDeleted`. Nothing follows the file until the file has
   actually changed, so a vault that refuses the write leaves the broker's
   mirror and its token table exactly as they were. This is the ordering the
   create path already established; delete adopts it rather than inventing a
   second rule.

2. **An unadmitted caller is refused before the id is ever read, and the
   refusal never mentions it.** The anti-oracle property is a property of
   *where* the admission check sits, not of a comparison performed later. A
   caller refused by ADR-0015 receives byte-identical answers for an id that
   exists and one that does not, because the denial is computed from process
   evidence alone.

3. **An admitted caller is told the truth about an id that is not there.**
   `VaultError::NotFound` becomes `InvalidRequest` with `"no such credential"`,
   never a successful deletion. This is *not* a weakening of the property
   above, and conflating the two is how a fix for one becomes a regression in
   the other: a caller that reaches this branch is the operator's own enrolled
   principal, pidfd-pinned and outside every broker slice, and it can already
   read the entire inventory through `ListCredentialMetadata`. Answering
   "no such credential" discloses nothing it does not already hold, while
   silent success would assert a revocation that never happened — the exact
   class of lie the previous refusal text was.

4. **Surrogates are revoked by credential, and it is not the control.** A new
   `SurrogateRegistry::revoke_credential` drops every token standing for the
   credential and reports how many. The vault alone would already have made
   those tokens useless — `with_secret` gates on the in-memory body, which the
   same `transact` that wrote the deletion has emptied. What the registry
   revocation buys is that the registry stops *claiming* those tokens are live,
   and that the failure an agent meets is a clean refusal at revoke time rather
   than a "no such credential" surprise when it spends a token it was told it
   still had. The count is logged so the operator learns what was in flight.

5. **Session capabilities are untouched, and the reason is structural.**
   `CapabilityGrant` and `Approval` carry a `Resource`, and `Resource` is a
   closed enum of `Repository | Database | Host | Api`. No variant can hold a
   `CredentialId`, so no per-credential grant exists to revoke. Adding one
   would couple a model that deliberately does not couple in order to fix
   nothing: the agent's access is already dead, because the vault is what
   answers.

6. **Rotation stays out.** `insert` still fails closed on an existing id.
   Replacing a secret and revoking one are different operations with different
   audit stories, and the create path already took that position.

## Why the granted path is testable without a fake

The obvious way to test the success branch is to inject an admission stub.
That was available — `BrokerState` already injects `ConnectorFactory`,
`SecretPort` and the PostgreSQL runtime — and it was **rejected**.

A seam that can answer "this caller is enrolled" is a seam that could also be
wired to a test double in production, and the one property ADR-0015 buys is
that the human's identity is never self-asserted. Instead each of its three
conditions is obtained honestly in the test: a real `pidfd_open` on the test
process; condition 1 holding *by observation*, because
`parse_cgroup_membership` reports only slices carrying the broker's prefix and
a test process is in none; and an enrolment record set from this binary's real
`/proc/self/exe` and the real SHA-256 of those bytes.

The consequence is worth stating because it generalises: a test that admits a
caller honestly is testing the same code path a human takes, so a regression
in the predicate cannot hide behind a test-only escape.

## What the falsification found

Mutation M5 — appending the requested id to the refusal string — **came back
green**. It re-opens the exact oracle that
`credential_deletion_is_refused_and_does_not_confirm_existence` claims to
close, and that test passed anyway, because it asserted only that both
messages *contained* `"refused:"` and `"pidfd-pinned"` and never compared them
to each other.

The gap was pre-existing and not exploitable before this cycle — the old arm
emitted one fixed message for every id. It became reachable the moment the arm
grew a per-id branch, which is why the repair belongs here. The test now
compares the two refusals byte for byte, and the mutation is caught.

The same pass found a second vacuous oracle: `no_subcommand_exposes_a_secret`
in the CLI read `Command::to_string()`, which is `Display` and renders the
command's *name* — the literal string `"asv"`. It was checking one word
against six forbidden ones. It now reads `render_long_help()`, and re-run
against the real help text it still passes: no subcommand exposes a secret.
The property held; the test had never checked it.

Neither of these is a defect this cycle introduced. Both are defects this
cycle's falsification happened to walk into, and both are recorded here
because a fix that reports only its own green tests is not a fix.

## Consequences

- **ADR-0016's "remains un-wired" consequence is now false and is amended by
  this ADR.** The spec pack is updated in the same change.
- **The operator has a verb.** `asv delete-credential <ID>` exists because a
  broker accepting a request is not the same as a human being able to ask.
  Without it the feature is code-complete and unusable, and the M5 exit walk
  cannot be performed by anyone.
- **Durability is asserted from a second process, not from the writer's own
  handle.** The in-process tests share one weakness: they assert against the
  same `VaultStore` the write went through, so a defect that mutated memory and
  never persisted would pass all of them. `crates/broker/tests/
  revoke_survives_restart.rs` kills the broker and starts a different process
  on the same file, and the assertion is made from there. Removing the write
  turns that test red with the credential *back*, which is the defect this
  ADR exists to close.
- **M5's exit is not yet met.** UAT-019, UAT-020 and the Tauri control plane
  (ADR-0009) remain, and this ADR closes the revoke step of the walkthrough
  only. The trace from exit gate to evidence is still the outstanding
  adjudication, recorded against M9 and not resolved by this change.
