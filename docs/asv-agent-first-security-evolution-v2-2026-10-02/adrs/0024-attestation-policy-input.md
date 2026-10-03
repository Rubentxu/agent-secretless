# ADR-0024 — Attestation is a policy input, not a product-specific dependency

- Status: Proposed
- Date: 2026-10-02

## Decision

Introduce an `AttestationPort` that yields a closed verdict (`Trusted`, `Untrusted`, `Stale`, `Unsupported`).

Keylime, TPM, Trustee, Intel TDX, AMD SEV-SNP and future mechanisms are adapters.

## Consequences

- ASV can implement attested secret/authority release.
- Domain does not depend on a hardware vendor.
- Confidential computing can be adopted for remote/isolated workers without infecting the local core.
