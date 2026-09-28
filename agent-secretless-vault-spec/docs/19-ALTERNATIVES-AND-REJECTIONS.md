# Alternatives, Compatibility Tricks and Rejections

This document prevents future implementation agents from rediscovering attractive but misleading approaches and accidentally weakening the architecture.

## 1. Temporary real environment variables

### Idea

```bash
TOKEN=real-secret some-cli
```

### Benefit

Very compatible and easy.

### Problem

The target process owns the secret. It can print, encode, persist or exfiltrate it. Environment values may also surface through dumps/logging/process inspection depending on platform and setup.

### Decision

Not a strong-secretless mechanism. Allowed only as explicitly degraded isolated/raw mode.

---

## 2. Placeholder environment variables

### Idea

```bash
TOKEN=__ASV_SURROGATE_xxx__ some-cli
```

### Decision

Accepted **when the real substitution/signing occurs outside the process**, e.g. protocol/TLS proxy.

The placeholder itself is a good compatibility primitive precisely because it is not the secret.

---

## 3. `LD_PRELOAD` hook on `getenv()`

### Idea

Return the real token only when the CLI calls `getenv("TOKEN")`.

### Problem

The returned secret is now in the untrusted process. Static binaries, setuid rules, non-glibc runtimes and direct environment access also break coverage.

### Decision

Rejected as secretless mechanism.

Potentially useful only to return **surrogates** or redirect APIs, never real secrets.

---

## 4. Hook TLS functions (`SSL_write`, rustls, Go TLS, etc.)

### Idea

Let the client hold placeholder plaintext, then patch it immediately before TLS encryption.

### Problems

- TLS stacks vary enormously.
- ABI/version coupling.
- same-process memory still contains injected library and potentially secret buffers,
- target can introspect itself,
- hard to guarantee copies/lifetimes,
- brittle debugging and crash behavior.

### Decision

Rejected as core. Userspace proxy outside process is safer and more maintainable.

---

## 5. eBPF/uProbe `bpf_probe_write_user`

### Idea

Patch placeholder in user memory from a uprobe.

### Problem

Kernel/eBPF documentation explicitly warns against using this helper for security due to TOCTOU. It also reintroduces secret bytes into target memory and is runtime-specific.

### Decision

Rejected. See ADR-0006.

---

## 6. seccomp user notification for credential substitution

### Idea

Trap `connect`, `send`, `open` or similar syscalls in a supervisor and alter arguments/data.

### Problems

- TLS plaintext usually exists before syscall and syscall sees ciphertext,
- user-notify CONTINUE has documented TOCTOU caveats and is not intended as a general security-policy enforcement mechanism,
- syscall diversity and async I/O make generic rewriting difficult.

### Decision

Do not use it as the credential security boundary. seccomp remains useful to **reduce allowed syscalls** in workers.

---

## 7. Magic FUSE files

### Idea

CLI reads `/run/asv/token`; FUSE returns secret just-in-time.

### Problem

The process receives the secret. A malicious script can simply read the file itself or copy from application memory.

### Decision

Rejected for strong-secretless. A FUSE path could expose non-secret handles/surrogates, but has little advantage over sockets.

---

## 8. Named pipes/FIFOs returning secret

Same flaw as FUSE: temporal delivery is still delivery. Rejected for strong mode.

---

## 9. Git credential helper

### Benefit

Excellent Git-native UX.

### Problem

The helper returns username/password/token to Git. Thus Git can hold the credential in process memory.

### Decision

Compatibility mode only. Prefer SSH-agent or HTTPS proxy.

---

## 10. Docker credential helper

Same conceptual limitation as Git credential helper: it protects at-rest storage but hands the credential to the requesting Docker client process.

Useful for normal password-management goals, not sufficient for hostile-agent non-disclosure.

---

## 11. Temporary credential file on `tmpfs`

Avoids disk persistence but not process disclosure. Any permitted process can read the file and the consuming process receives the secret.

Decision: degraded mode only.

---

## 12. Short-lived token

A major risk reduction but not non-disclosure.

If a provider-native token must be handed to a client process, classify `SHORT_LIVED_EXPOSURE` and make TTL/scope aggressively small.

---

## 13. Local reverse proxy with endpoint rewrite

### Idea

Point client API endpoint to `127.0.0.1`, broker authenticates upstream.

### Assessment

Excellent where the CLI/provider supports custom endpoint configuration. No TLS MITM is needed if the client intentionally connects to the local ASV endpoint.

### Decision

Preferred over transparent interception whenever tool configuration can be applied unobtrusively by launch profile/shim.

---

## 14. Explicit `HTTP(S)_PROXY`

### Assessment

Useful transport redirection but ordinary HTTPS CONNECT does not expose HTTP headers to proxy. Credential substitution requires either:

- application-aware endpoint/reverse-proxy mode, or
- TLS interception using session trust.

### Decision

Accepted as transport mechanism with those limitations.

---

## 15. eBPF transparent socket redirect

### Assessment

Strong fit for transparency and enforcement because it can steer a cgroup's selected connections without modifying every command.

It still does not solve TLS credential injection by itself. Pair with broker/proxy.

### Decision

Accepted behind research gate.

---

## 16. SSH agent / remote signer

### Assessment

Ideal. Private key never needs to enter client process. Mature protocol semantics.

### Decision

First reference vertical and design benchmark for other connectors.

---

## 17. Hardware key / PKCS#11/FIDO/TPM signing

### Assessment

Excellent for private-key material. It cannot directly make arbitrary bearer tokens non-exportable, but should be supported for signing/mTLS/vault wrapping.

### Decision

Planned after software verticals are stable.

---

## 18. Generic MITM CA installed system-wide

### Benefit

Maximum transparency.

### Problem

Creates a persistent local root capable of intercepting unrelated traffic; compromise impact is too large.

### Decision

Rejected by default. Transparent TLS uses ephemeral session-scoped trust only.
