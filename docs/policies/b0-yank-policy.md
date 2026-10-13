# B0 release yank policy

**Status**: DECIDED on 2026-10-13. Path C adopted.
**Scope**: the B0 release is the first publication of
`asv-broker` (and the rest of the `asv-*` workspace crates) to
crates.io. The B0 release carries the B1 series (B1.1 worker
lifetime, B1.2 signal-mask audit, B1.3 cgroup-probe +
`degraded_reason`, B1.4 runtime-posture-aware opt-in flag). The
release is opt-in to the runtime posture: deployments that do
not pass `--runtime-posture-aware` keep the B1.1 honest label
(`IsolatedProcessExposure` + `degraded_reason: None`).

**Triggering condition for this policy**: a critical bug is
discovered in B0 *after* `cargo publish` lands, where the bug
is in the runtime path (the worker spawn / cgroup fence /
posture decision) and cannot be patched in place. The question
is: what do we do to the published crate version?

## Adopted policy: Path C

Publish a B0.1 patch alongside, and yank B0 only for
security-class bugs. The default is "don't disrupt downstream
for ordinary bugs." The exception is reserved for the class
of bugs that *warrant* disruption.

### Yank-worthy criteria (the 4 bullets)

A bug in B0 is yank-worthy iff it is in the broker runtime
(worker spawn, cgroup fence, posture decision, audit chain)
AND it allows one of:

1. **Remote code execution** in the broker or any path the
   broker can reach (worker, connector, IPC).
2. **Secret exfiltration** that the runtime posture was
   supposed to prevent (e.g. cgroup-fence escape,
   landlock-bypass, seccomp-bypass).
3. **Audit log forgery or truncation** that allows a
   compromised operator to hide an action that the audit
   chain is supposed to surface.
4. **Crate metadata forgery** (wrong checksum, wrong
   description, wrong author) that the yank is the only
   way to undo.

A bug in posture classification logic, in worker scheduling,
in connector dispatch, or in any of the B0 *features* (not
*invariants*) is **not** yank-worthy. Publish a patch; do
not yank.

A bug in the B0 *invariants* (the four bullets above) is
yank-worthy. Yank and publish the patch in the same release.

### Decision tree

```
Is the bug in the broker runtime (worker spawn, cgroup
fence, posture decision, audit chain)?

  NO  -> Patch and publish B0.1. No yank.
  YES -> Does the bug allow one of:
         - RCE
         - secret exfiltration the runtime was
           supposed to prevent
         - audit log forgery or truncation that
           hides a recorded action
         - crate metadata forgery

           NO  -> Patch and publish B0.1. No yank.
           YES -> Yank B0, publish B0.1 in the same
                  release. Write a security advisory.
```

## Why Path C (and not A or B)

Path A (yank and replace) was rejected because the social
cost of a yank is high for ordinary bugs: every downstream
user gets a warning storm, and the yank is visible in the
public crate history. A yank is a strong signal and should
be reserved for the class of bugs that warrant it.

Path B (never yank) was rejected because it leaves users
who pinned to B0 (with `=0.38.0` or similar exact pins)
exposed to a security-class bug indefinitely. The `cargo
update` flow does not reach them.

Path C is the cargo book's own framing: yanks are for cases
where the version *should not be used at all*. The four
bullets above enumerate what "should not be used at all"
means for the broker.

## What this policy does NOT cover

- **Force-push of the git tag.** A yank on crates.io is
  independent of the git tag. The tag `b1.4` stays.
- **Downstream notification.** Crates.io yanks do not
  email subscribers; the user of this policy is responsible
  for writing a security advisory (RustSec) when the yank
  criterion is met.
- **In-place fixes.** A `dist-manifest.json` change is a
  policy decision of its own; it is not a yank.
- **Pre-1.0 vs post-1.0.** This is a pre-1.0 release; the
  social contract of "yank on security bug" applies to any
  version. The yank policy does not change at 1.0.

## What adopting this policy commits us to

When a bug is reported against B0, the bug is processed
through the decision tree above. The result is one of:

- **Path B (patch only)**: open a hotfix branch, fix,
  merge to `b1/worker-lifetime`, tag `b0.1`, publish.
  No security advisory required.
- **Path A (yank + patch)**: open a hotfix branch, fix,
  merge to `b1/worker-lifetime`, tag `b0.1`, `cargo yank`
  the B0 version on crates.io, publish B0.1, write a
  RustSec advisory.

The decision must be made **before** the B0.1 publish, not
after. A yank is not retroactive; if B0.1 is already
published, the yank does not help.
