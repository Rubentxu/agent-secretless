# fuzz/ — cargo-fuzz baseline

Fuzz targets exercise the security-critical parsing boundary of the broker.
Stable builds and CI never compile this directory: it is its own workspace
and requires nightly Rust via `cargo-fuzz`.

## Targets

| Target | Boundary under test | Invariant |
|---|---|---|
| `fuzz_ipc_decode_request` | `asv_ipc_protocol::decode_request` | total function: `Ok(Request)` or `Err(ProtocolError)`, never panic |
| `fuzz_vault_envelope_decode` | `asv_vault::VaultFile::decode` | total function over untrusted bytes: `Ok` or `Err`, never panic; every accepted input survives `decode`-then-`encode` unchanged |

## Running (nightly only)

```bash
rustup install nightly          # once
cargo install cargo-fuzz        # once

cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run fuzz_ipc_decode_request -- -max_total_time=30
```

Any crash is written to `fuzz/crash-<sha>`; minimize with
`cargo +nightly fuzz tmin <crash-file>` and file the defect against
`asv-ipc-protocol`.

## Seeds

`corpus/fuzz_ipc_decode_request/` holds a valid request, an oversized
payload (hits `MAX_MESSAGE_BYTES`), and malformed JSON so runs start from
meaningful states.
