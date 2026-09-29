# M12 — TPM / hardware-backed vault — Specification (prototype pass)

## Goal

The device-bound vault mode keeps the long-lived passphrase out of
the vault file. The vault can only be opened by either the TPM in
the matching PCR state, or the recovery passphrase the user received
once at enrollment and stored offline.

This is the prototype pass. The runtime follow-up replaces the
placeholder with a real TCG TPM2 client.

## ADDED requirements

### M12-R1 — TpmDevice trait

The framework MUST define `TpmDevice` with four methods:

| Method | Purpose |
|---|---|
| `seal(&self, kek: &[u8;32], pcr_policy: &PcrPolicy) -> Result<TpmSealed, TpmError>` | seal a KEK under the device-bound key |
| `unseal(&self, sealed: &TpmSealed, observed: &[(PcrSlot, Digest)]) -> Result<[u8;32], TpmError>` | unseal a KEK |
| `is_hardware(&self) -> bool` | true if the underlying device is a hardware TPM |
| `label(&self) -> &str` | diagnostic label |

#### Scenario: trait surface is the only broker entry point

> Given the broker needs to seal or unseal, the broker uses
> `TpmDevice::seal` / `TpmDevice::unseal`. There is no `TpmDevice`
> verb that yields the long-lived device key to the broker.

### M12-R2 — TpmSealed on-disk shape

The framework MUST define `TpmSealed` with three fields:

| Field | Type | Notes |
|---|---|---|
| `blob` | `Vec<u8>` | opaque sealed bytes |
| `pcr_policy` | `PcrPolicy` | the PCRs the TPM must be in to unseal |
| `policy_version` | `u32` | incremented on policy rotation |

#### Scenario: sealed blob round-trips through serde

> Given a sealed blob produced by `TpmDevice::seal`, the blob
> round-trips through `serde_json::to_string` / `from_str` byte-for-byte.

### M12-R3 — PcrPolicy semantics

`PcrPolicy::matches(observed)` MUST return true only if every slot in
the policy has an entry in `observed` whose digest equals the policy
digest. Empty policy always matches (degenerate case used by tests).

#### Scenario: drifted PCR state refuses to match

> Given `PcrPolicy::new(vec![(PcrSlot::Pcr0, D)])` and
> `observed = vec![(PcrSlot::Pcr0, D')]` (D' != D),
> `policy.matches(&observed)` returns false.

#### Scenario: missing slot refuses to match

> Given a policy with two slots and an `observed` that contains
> only one of them, `policy.matches(&observed)` returns false.

### M12-R4 — RecoveryBlob

The framework MUST define `RecoveryBlob` with four fields:

| Field | Type | Notes |
|---|---|---|
| `salt` | `[u8; 16]` | Argon2id salt for the recovery KDF |
| `nonce` | `[u8; 24]` | XChaCha20-Poly1305 nonce for the wrap |
| `wrapped_vault_key` | `Vec<u8>` | passphrase-derived-KEK-encrypted vault key |
| `policy_version` | `u32` | the policy version the recovery blob was generated under |

#### Scenario: recovery blob round-trips through serde

> A `RecoveryBlob` survives `serde_json::to_string` / `from_str`.

### M12-R5 — DeviceBoundUnlocker fallback policy

`DeviceBoundUnlocker::try_unseal` MUST first try the TPM. If the TPM
returns `TpmError::PcrMismatch`, the broker MUST prompt the user for
the recovery passphrase and call `DeviceBoundUnlocker::recover`. The
helper exposes both methods; the broker chooses the order.

#### Scenario: TPM refusal triggers recovery path

> Given a sealed blob whose PCR policy does not match, calling
> `try_unseal` returns `Err(TpmError::PcrMismatch)`. The broker then
> calls `recover(blob, passphrase)`. A non-empty passphrase yields a
> KEK. An empty passphrase returns `Err(TpmError::RecoveryAuthFailed)`.

### M12-R6 — Hardware-vs-placeholder flag

`TpmDevice::is_hardware` MUST return `false` for `SoftwareTpm`. The
broker MUST consult this flag and refuse to enroll a device-bound
vault without recovery unless `is_hardware` is true.

#### Scenario: software TPM is not eligible for device-bound-only mode

> Given a `SoftwareTpm`, `device.is_hardware()` returns false. The
> broker refuses to enroll without a `RecoveryBlob`.

## MODIFIED requirements

None.

## REMOVED requirements

None.

## Out of scope

- Real TCG TPM2 client (`/dev/tpmrm0`).
- Argon2id + AEAD verification of the recovery blob at runtime.
- Migration passphrase-bound -> device-bound.
- Auto-detection of available TPM (the runtime follow-up probes for
  `/dev/tpmrm0` and falls back).

## Verification

1. `cargo test --lib -p asv-vault tpm` covers the items above.
2. `uat_034_tpm_device_bound_theft` covers the device-bound theft
   claim and the recovery path.

## Verdict

M12-prototype **passes** if all six items above are present and
tested.