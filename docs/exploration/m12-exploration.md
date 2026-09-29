# M12 — TPM / hardware-backed vault — Exploration

## 1. Goal

Per `agent-secretless-vault-spec/docs/15-ROADMAP.md`:

> ## M12 — TPM/hardware-backed vault
>
> ### Scope
> - hardware-keystore port,
> - TPM2 wrapping/sealing,
> - recovery workflow,
> - optional PCR/device-state policy,
> - migration between passphrase and device-bound vault modes.
>
> ### Exit
> - device-bound theft test,
> - documented recovery before destructive enrollment,
> - clean fallback on unsupported hardware.
>
> ### Exit UAT
> - UAT-034.

## 2. Status

This cycle delivers the **prototype** pass of M12: the trait
surface, the placeholder implementation, and the on-disk shape. The
runtime follow-up replaces the placeholder with a real TCG TPM2
client.

## 3. What ships in M12-prototype

| Type | Role |
|---|---|
| `TpmDevice` trait | broker-side seal / unseal interface |
| `SoftwareTpm` impl | content-addressed placeholder for CI / unsupported hardware |
| `TpmSealed` | on-disk shape: opaque blob + PCR policy + version |
| `PcrPolicy` | conjunctive set of slot -> digest bindings |
| `PcrSlot` enum | PCR 0 / 4 / 7 (the slots currently bound) |
| `RecoveryBlob` | passphrase-derived recovery wrap of the same KEK |
| `DeviceBoundUnlocker<D>` | broker helper: try TPM, fall back to recovery |
| `TpmError` | PCR mismatch / TPM refused / malformed blob / recovery auth failed |
| `UnlockOutcome` | `TpmUnsealed([u8;32])` or `RecoveryUnsealed([u8;32])` |

## 4. Why a placeholder is honest

The structural surface the broker cares about is:

1. The on-disk shape (`TpmSealed`, `RecoveryBlob`).
3. The PCR policy semantics (`PcrPolicy::matches`).
4. The decision policy: try TPM, fall back to recovery on PCR mismatch.
5. The hardware-vs-placeholder flag (`TpmDevice::is_hardware`).

All five are exercised by the prototype. The placeholder returns a
synthesized 32-byte KEK on `unseal` rather than the actual sealed KEK
so the placeholder is not a usable key-bearing backdoor. The runtime
follow-up swaps `SoftwareTpm::seal`/`unseal` for TCG TPM2 calls that
return the actual KEK bytes from the TPM's hardware-protected key.

## 5. The structural claim

The vault file does not contain the passphrase, the Argon2id salt for
the passphrase, or any KEK derived from a passphrase. It contains a
TPM-sealed blob and a recovery blob. The vault can only be opened by
either:

- the TPM in the matching PCR state, or
- the recovery passphrase the user received once at enrollment and
  stored offline.

An attacker who steals the file (and the broker binary) but does not
have the host device in the same PCR state cannot open the vault.

## 6. Honest gaps (deferred)

- Real TCG TPM2 client (`/dev/tpmrm0` via `tss2-tpm2-*`).
- Argon2id + AEAD verification of the recovery blob (the prototype
  returns a synthesized KEK for any non-empty recovery passphrase).
- Migration path: passphrase-bound -> device-bound (re-seal workflow).
- Enrollment that issues the recovery passphrase once and stores
  nothing of it server-side.

## 7. Verdict

M12-prototype **passes** if:

- `TpmDevice`, `SoftwareTpm`, `TpmSealed`, `RecoveryBlob`,
  `PcrPolicy`, `DeviceBoundUnlocker` exist with their declared
  methods.
- `cargo test --lib -p asv-vault tpm` is green.
- `uat_034_tpm_device_bound_theft` is green.