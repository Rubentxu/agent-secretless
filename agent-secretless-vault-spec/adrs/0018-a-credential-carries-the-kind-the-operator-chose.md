# ADR-0018 — A credential carries the kind the operator chose, beside the one it is stored as

- **Status**: Accepted
- **Date**: 2026-10-01
- **Supersedes**: nothing. **Extends**: ADR-0016 (how a human credential reaches
  the vault), ADR-0014 (explicit integration posture), ADR-0001 (no agent
  retrieval).
- **Amends**: ADR-0016's decision to *refuse* four kinds rather than mislabel
  them. The reasoning that produced the refusal is kept; the conclusion no
  longer follows from it.
- **Implements**: `REQ-1..REQ-5` of the `vault-kind-label` cycle.

## Context

The domain names nine credential kinds. The vault has five. Four of the nine —
`ApiKey`, `OAuth2`, `X509ClientIdentity`, `AwsAccessKey` — had no storage
class, and `CreateCredential` refused them by name.

That refusal was correct. `VaultKind::BearerToken` is documented *"Bearer token
or API key"*, so `ApiKey → BearerToken` looks free, but the read direction maps
`BearerToken → BearerToken`. An operator who stored an `api_key` would get a
`bearer_token` back. The credential would work, so nothing would look wrong,
and the operator would believe they had stored something they had not.

**A silent kind change is worse than a refusal.** The refusal is what stopped
it, and it was the right call with the information available.

The operator-visible shape of the gap was sharper than the wording suggests:
`parse_credential_kind` in the CLI already accepted all nine spellings. The
command offered `--kind api_key` and the broker rejected it. The list a human
was shown and the set a human could use disagreed.

## The measurement that changed the decision

The triage that opened this cycle recorded that the two candidate fixes both
carry "the same migration cost — smaller, but not free". **That was wrong**, and
correcting it is what made the design possible.

Measured: `crates/vault/Cargo.toml` already depends on `asv-domain`, and
`grep 'serde(' crates/vault/src/store.rs` returns nothing — no field in the
vault body has a serde attribute, and `VaultBody` is `{records}` with no version
field. A new field carrying `#[serde(default)]` is therefore **optional in
read**, and there is no migration: a vault written before the field simply
deserializes to `None`.

## Decision

**The vault keeps its five kinds as the storage class. A new optional
`domain_kind` carries the kind the operator named.**

1. `CredentialKind` in the vault is the **storage class** — how the secret is
   held — and keeps every meaning it has today.
2. `CredentialMetadata::domain_kind: Option<asv_domain::CredentialKind>` with
   `#[serde(default)]` is the **label**. Written only when it differs from what
   the storage class already says, so a record whose fields agree carries no
   redundant copy.
3. `inventory::vault_kind` becomes **total**: every domain kind has a storage
   class, and the label travels beside it. The refusal is gone.
4. `CredentialMetadata::effective_kind()` is the single place that answers
   "what kind is this": the label when present, the storage class otherwise.
   One implementation, so one answer.

## Why not widen the vault's enum

The obvious fix, and the one this decision rejects.

| vault | binary | widening the enum | this ADR |
| --- | --- | --- | --- |
| old | new | works | works |
| new | old | **body fails to parse** → `MalformedBody` → **every credential lost** | unknown key ignored → credential reachable, label coarser |

Serde cannot deserialize an enum variant it does not know, so the failure is at
the level of the whole body, not the one record. A downgrade is exactly when an
operator needs their vault.

Losing every credential to keep one label is not a trade worth making, and
`REQ-4` exists so the next person does not make it by accident.

## Consequences

- **The refusal is gone, and with it the four unstoreable kinds.** `asv
  add-credential --kind api_key` now works, and the listing says `api_key`
  after a restart.
- **One new invariant**: a record may hold a label and a storage class that
  differ, and that is a fact rather than a conflict — an `api_key` *is* held as
  a bearer token. `effective_kind` prefers the label; nothing rewrites
  `kind` to agree, because two fields must not end up answering one question.
- **A pre-existing test asserted the old behaviour** and was rewritten rather
  than deleted. It now pins the round trip, which is the property the refusal
  used to protect: without the label, acceptance alone would be the defect.
- **No CLI, protocol, or dependency change.** The CLI was already correct; the
  broker was the side that refused.
- **`effective_kind` mirrors the broker's mapping inside the vault's own test.**
  The vault cannot depend on the broker, so that one test carries a copy. It is
  the only place the mapping appears twice, and it is a test.
- **M5 is still not met.** UAT-019, UAT-020 and the Tauri control plane remain,
  and the M9 exit-UAT trace is a spec adjudication no code change resolves.
