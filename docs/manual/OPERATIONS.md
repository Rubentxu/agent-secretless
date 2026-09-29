# Agent Secretless Vault — Operations manual

This document is the operator-side counterpart to the threat model and
the spec. It is intentionally short.

## What this binary is

`asv` is a local broker that holds encrypted credentials and lends
them to one-shot agent processes through a Unix-domain socket. The
agent never sees the credential bytes; the broker attaches the
credential to a single request, runs the request through a hardened
subprocess, and hands the response back. The agent has no API to
read the secret.

## First-use — create a vault

```bash
$ asv vault create --passphrase-file ./passphrase.txt
```

The broker:

1. Generates a 32-byte vault key.
2. Derives a 32-byte KEK from your passphrase via Argon2id.
3. Wraps the vault key under the KEK (XChaCha20-Poly1305).
4. Writes the wrapped header + an empty body to the vault file.

The passphrase is read from a file (not a TTY prompt) so the create
step is scriptable and never echoes.

## First-use — add a credential

```bash
$ asv vault add --id github \
      --authority github.com \
      --kind bearer \
      --secret-file ./github.token
```

The broker reads the secret from the file, wraps it under the vault
key, and appends the new credential to the body. The secret file is
overwritten with zeroes after read.

## First-use — list credentials

```bash
$ asv vault list
github        bearer     github.com    rotation-policy: 30d
postgres-pg   password   db.example   rotation-policy: 90d
```

The list command shows metadata (id, kind, authority, rotation
policy) but never the secret bytes.

## Use — broker a credential to an agent

```bash
$ asv run --id github -- \
      curl -H "Authorization: Bearer $ASV_SURROGATE" https://api.github.com/user
```

The broker:

1. Spawns the agent as a hardened child (PR_SET_DUMPABLE=0,
   PR_SET_NO_NEW_PRIVS=1, Landlock rules, Seccomp filter).
2. Injects the credential header into the agent's environment under a
   surrogate name.
3. The credential bytes never appear in the agent's process memory;
   the surrogate is a one-shot handle the agent passes to its own
   library.

## Rotate a credential

```bash
$ asv vault rotate --id github --secret-file ./github-new.token
```

The broker writes the new secret under the same id and bumps the
revision. Old secrets are dropped; old surrogates minted before the
rotation are still valid until they expire.

## Recover from a crash

The broker keeps an append-only journal of mutations. If the broker
crashes mid-append, the next start replays the journal and stops at
the last fully-appended entry. A torn write (the broker died 2 bytes
before finishing an entry) does NOT advance state.

To inspect the journal:

```bash
$ asv journal inspect --vault ./vault.bin
credential_added   cred-A
credential_rotated cred-A->cred-B
credential_revoked cred-A
[torn entry at offset 247 — last good record above]
```

## Recover from a TPM / PCR drift

If the broker is in TPM-bound mode and the host's PCR state has
drifted (e.g. a BIOS update), unseal fails with `PcrMismatch`. Use
the recovery passphrase issued at enrollment to open the vault:

```bash
$ asv vault unlock --passphrase-file ./recovery-passphrase.txt
```

The recovery passphrase is delivered once at enrollment and stored
offline. It is the only way to open the vault if the TPM is
unavailable or the PCR state has drifted.

## Audit a run

```bash
$ asv audit --vault ./vault.bin --since 24h
```

The audit log records every brokered request (id, authority, time,
size). It does NOT record secret bytes — by construction the secret
never enters the broker's logging path.

## Update the broker

The broker is on the same release train as the rest of the project.
When a new release ships:

1. Stop the broker.
2. Replace the binary.
3. Restart the broker.

The vault file is forward-compatible across releases within the
`ENVELOPE_VERSION` constant. A release that changes the envelope
version ships an explicit migration tool.

## Contact

File issues at the project tracker. Security-sensitive reports use
the disclosure process in `docs/02-THREAT-MODEL.md`.