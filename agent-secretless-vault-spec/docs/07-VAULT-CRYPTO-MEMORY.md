# Vault, Cryptography and Secret Memory

## 1. Storage goals

- stolen database must not reveal secrets,
- broker can use secrets without exposing them to normal callers,
- secret lifetime in plaintext memory is minimized,
- crypto primitives are standard, reviewed libraries rather than custom algorithms,
- future hardware-backed key sealing is possible.

## 2. Metadata vs secret material

Separate records:

```text
CredentialMetadata
  id
  label
  kind
  account/provider/resource
  policy references
  exportability
  created/rotated timestamps

CredentialPayload
  algorithm/version
  nonce
  ciphertext
  authentication tag
  wrapped data-encryption key reference
```

Consider encrypting sensitive metadata (account names, hosts) as a privacy option, but do not make metadata encryption block early implementation.

## 3. Key hierarchy

```text
Master/KEK
   |
   +--> wraps per-record or per-vault DEKs
              |
              +--> AEAD encrypts credential payloads
```

Recommended primitives to evaluate:

- Argon2id for passphrase derivation,
- XChaCha20-Poly1305 or AES-GCM for authenticated encryption,
- OS CSPRNG for salts/nonces/keys.

Do not invent a cipher or KDF.

## 4. Unlock modes

### Passphrase

Portable baseline. Argon2id parameters calibrated on first setup and versioned for future migration.

### OS-backed key

Use platform keystore/keyring as an optional wrapping layer, but do not assume it protects against the same logged-in user running hostile code.

### TPM2

High-security Linux/Windows option:

- seal wrapping key to TPM,
- optionally combine with human passphrase,
- optionally bind to acceptable PCR/device state,
- support recovery/export workflow before enabling strict device binding.

`tss-esapi` is a plausible Rust integration layer and should be isolated behind a hardware-keystore port.

## 5. IOTA Stronghold evaluation

Stronghold is interesting because it provides procedure-oriented secret use and protected runtime/storage concepts, and Tauri offers a Stronghold plugin.

However:

- ASV must not expose Stronghold operations directly to WebView JavaScript,
- the broker rather than the Tauri frontend should own storage operations,
- current Stronghold low-level documentation includes a warning that the library has not had a formal third-party security audit.

Decision: perform a bounded evaluation spike; do not make Stronghold an irreversible core dependency before comparing it with a small audited-format design using established RustCrypto primitives.

## 6. Memory handling

Use secret-specific types:

```rust
SecretBox<T>
Zeroizing<T>
```

Rules:

- no `Debug` for raw secret values,
- no `Serialize` for internal secret types,
- avoid clones,
- preallocate buffers where practical,
- zeroize immediately after connector use,
- never convert to `String` unless protocol library requires it,
- avoid formatting macros around secret bytes,
- fuzz error paths to ensure no accidental formatting.

## 7. `memfd_secret`

On supported Linux kernels, evaluate `memfd_secret()` for selected broker secret buffers/master material. It provides anonymous RAM-backed memory with stronger isolation properties than ordinary mappings and is not a substitute for process isolation.

Fallback:

- `mlock` where permitted,
- non-dumpable process,
- guard/protection pages where useful,
- zeroization.

Feature detection must be runtime and gracefully degrade.

## 8. Process hardening

Broker service:

- dedicated UID,
- `PR_SET_DUMPABLE=0`,
- core dumps disabled,
- no untrusted child processes,
- minimal filesystem access,
- `NoNewPrivileges`,
- systemd hardening where installed as service,
- narrow Unix sockets,
- no listening TCP admin API by default.

A dedicated UID is especially important because same-user process inspection is otherwise a recurring source of leakage risk.

## 9. Secret ingestion

### Baseline UI path

Tauri password field -> minimal Rust IPC command -> broker -> clear DOM field immediately.

Constraints:

- no remote frontend scripts,
- no telemetry around form values,
- clipboard disabled by default,
- frontend logging disabled for value-bearing events.

### Hardened path

A dedicated native secure-input helper accepts the secret, writes it to broker over an authenticated local channel, zeroizes and exits. The WebView never receives the value.

Provide no-echo TTY equivalent for CLI users.

## 10. Human reveal/copy

`NonExportable`: impossible through supported UI/CLI once stored.

`HumanOnly`: explicit re-authentication + time-limited reveal, never returned through agent IPC/MCP. Clipboard copy should be opt-in and auto-clear best-effort.

`Exportable`: still requires explicit human interaction.

## 11. Backup and recovery

- encrypted backup only,
- versioned file format,
- authenticated metadata/header,
- recovery key/passphrase flow documented,
- TPM-bound mode must offer an explicit recovery design before enabling irreversible sealing.

## 12. Rotation

Connector/provider layer should support rotation workflows without changing agent configuration because policies reference stable credential IDs, not token strings.
