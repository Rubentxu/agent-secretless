# Security Policy

## Reporting a vulnerability

**Preferred channel: a private security advisory.** Use
[Security Advisories](https://github.com/rubentxu/agent-secretless/security/advisories/new)
rather than a public issue.

Please do not open a public issue for anything that could leak a credential,
bypass a boundary, or expose secret material. A public issue is world-readable
from the moment it is filed, and a proof-of-concept is a working exploit.

Include: what you observed, the exact commands or code, and the boundary you
believe was crossed. A `PASS` from the harness is not evidence that a boundary
holds; if you found a way to make a probe miss something, that is the most
valuable report this project can receive.

If the advisory form is unavailable, open a regular issue that says only "private
security report, please open a private channel" with no technical detail, and
wait for a reply before sharing anything.

## Supported versions

M0 is pre-release. There is no stable version and no support commitment. The
only supported thing is `main`, and it changes without notice.

This is stated plainly because the usual version-support table would be a lie
at this stage: there is no vault, no released artifact and no stability promise
to make.

## What counts as a vulnerability here

The threat model treats the agent process as hostile and untrusted, so the
boundaries that matter are the ones an agent must not cross:

- Retrieving secret material through the agent-facing API (ADR-0001). Any
  reachable path from a request to a secret's bytes is critical, including
  aliases that recreate `getSecret`.
- Forging workload identity, or defeating the `SO_PEERCRED` and `pidfd` chain
  (ADR-0003).
- Reaching the broker socket without the kernel-attested rights it requires
  (ADR-0002).
- A secret reaching a vector the design says it cannot reach: the agent
  environment, `/proc`, `argv`, agent-readable files, stdout/stderr, or an
  unauthorized network sink (R6).

## What is a known limitation, not a vulnerability

These are accepted properties of the current milestone. Reporting them as
vulnerabilities wastes time that would be better spent on something new.

- **Same-uid processes can read broker memory.** The broker runs as the invoking
  user, so a peer under the same uid can read its memory. A dedicated broker uid
  is M7. The harness reports the kernel's actual verdict instead of claiming a
  boundary the OS does not offer.
- **`argv` is readable by the same uid.** Anything passed as a CLI flag is
  visible via `ps` and shell history. No software can change this. The response
  is to never pass a secret in `argv`; the M0 CLI has no credential-ingestion
  command at all, and M1 adds the no-echo TTY channel the threat model requires.
- **No vault exists yet.** M0 verifies boundary properties, not protection of
  stored secret material, because there is nothing stored.

## How the boundaries are checked

Every claim above is backed by a check that is capable of failing. If you want
to confirm a property yourself:

```bash
python3 tests/adversarial/run_harness.py          # 11 probes, each with a self-check
python3 tests/adversarial/test_falsifiability.py  # the harness must fail on injected leaks
```

The second command injects three real leaks, rebuilds, and requires the harness
to reject each one. If it ever reports fewer than 3/3, that is itself a
vulnerability report: the harness has stopped being able to detect leaks.

## Hardening

The harness is not a guarantee. It is a canary: it catches what someone thought
to test. A boundary that was never probed is a boundary that has not been
verified, and the harness's own history is the proof of that. It once reported
5/5 green while planting its canary nowhere.
