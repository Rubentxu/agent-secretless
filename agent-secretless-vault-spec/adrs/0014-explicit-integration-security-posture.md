# ADR-0014 — Every integration declares its security posture

- Status: Accepted
- Date: 2026-09-28

## Decision

Expose one of:

```text
STRONG_SECRETLESS
SHORT_LIVED_EXPOSURE
ISOLATED_PROCESS_EXPOSURE
RAW_PROCESS_EXPOSURE
UNSUPPORTED
```

in UI, diagnostics and audit.

## Rationale

“Temporary” does not mean “unreadable”. Users need to know whether the target process can actually possess the credential.
