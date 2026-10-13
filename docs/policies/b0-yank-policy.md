# B0 release yank policy — draft for user review

**Status**: DRAFT. The user has not yet chosen between the three
paths; this document lays out the choice space, the consequences
of each, and the recommendation. The receipt for the policy
itself will be filed when the user picks.

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

## Path A: yank and replace

`cargo yank` the B0 version on crates.io and publish a B0.1 (or
B0.0.1) immediately. B0 disappears from `cargo new` resolution
by default; existing lockfiles that pinned it keep working but
emit a warning on every build; new projects cannot pick it up.

**Pros**:
- The "broken" version stops being the path of least resistance.
- A user who runs `cargo update` after the yank is forced to the
  fix.
- The yank is reversible: `cargo unyank` brings it back if the
  fix turns out to be worse than the bug.
- This is the documented crates.io workflow for exactly this
  case (cargo book §"cargo yank"). It is what the ecosystem
  expects.

**Cons**:
- A yank breaks **every** downstream user, not just the ones
  who would have hit the bug. Some of them may have
  CI on `cargo update` and now see a warning storm.
- The yank is an irreversible-feeling operator action: the
  social cost of undoing a yank is high even when the cargo
  unyank is one command.
- It does not actually remove the version from lockfiles. A
  user who has `asv-broker = "0.38.0"` in their lockfile keeps
  building against the broken version until they explicitly
  update.
- The yank is visible in the public crate's history. Some
  users / security scanners treat a yanked version as a
  signal of "this project had a problem," regardless of
  whether the fix landed.

## Path B: publish a B0.1 patch alongside, never yank

Publish B0.1 with the fix. Leave B0 live. Users who update
naturally pick up B0.1; users who pinned to B0 stay on B0
until they update. The yank is reserved for a hypothetical
future case where the bug is severe enough to warrant it.

**Pros**:
- No surprise disruption to downstream users. The fix is
  available; the path to it is the normal `cargo update` flow.
- No public history of a yank. The crate's record is
  "released B0, then released B0.1" — boring and predictable.
- Aligns with the spirit of crates.io: yanks are for security
  issues and license violations, not for "we shipped a bug"
  (cargo book: yanks are not for code-rot; they are for
  situations where the version should not be used at all).

**Cons**:
- A user who has `asv-broker = "0.38"` in their Cargo.toml
  (caret) auto-updates to B0.1, which is the fix. A user
  with `asv-broker = "=0.38.0"` (exact) does NOT update. If
  the bug is severe, this leaves a meaningful fraction of
  users exposed.
- A user who has read the bug report and wants to NOT pick
  up the fix has to explicitly pin to B0 with a comment
  about why. The default is "update" which is good for
  security but bad if the fix has its own regression risk.
- This is a "soft" policy: it depends on the B0.1 actually
  being a strict improvement. If the fix has any new
  behavior, you have shipped two versions and have to
  support both.

## Path C: publish a B0.1 patch, **and** yank B0 only for
security-class bugs

Hybrid: Path B is the default. Path A is reserved for
security-class bugs (RCE, secret exfiltration, audit log
forgery, cgroup-fence escape). The yank criterion is
written down *now*, before any bug exists, so the decision
in the moment is a checklist, not a panic.

**Pros**:
- The default is "don't disrupt downstream for ordinary
  bugs." Most bugs fall in Path B.
- The exception is reserved for the class of bugs that
  *warrant* disruption. Security scanners and downstream
  users have a single rule: "this project yanks on
  security-class bugs and patches in place for everything
  else."
- The criterion is explicit and reviewable. A future
  operator reading this document can apply it without
  re-debating the policy.
- Aligns with the cargo book's own framing: yanks are
  for cases where the version *should not be used*.

**Cons**:
- Requires the user to write down the criterion now.
  This is the document the user is reading. If the
  criterion is wrong, the policy is wrong in advance.
- "Security-class" is a judgment call. A cgroup-fence
  escape that only triggers on a misconfigured host
  might be Path B or Path A depending on how you
  frame it.
- Requires a security advisory process. We don't have
  one yet; this policy is the first step toward one.

## Recommendation

**Path C** with the following criteria for "yank-worthy":

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

A bug in posture classification logic, in worker
scheduling, in connector dispatch, in any of the B0
*features* (not *invariants*) is Path B: publish a
patch, do not yank.

A bug in the B0 *invariants* (the four bullets above)
is Path A: yank and publish the patch.

The decision tree is in §"Decision tree" below.

## Decision tree

```
Is the bug in the broker runtime (worker spawn, cgroup
fence, posture decision, audit chain)?

  NO  -> Path B. Patch and publish B0.1. No yank.
  YES -> Does the bug allow one of:
         - RCE
         - secret exfiltration the runtime was
           supposed to prevent
         - audit log forgery or truncation that
           hides a recorded action
         - crate metadata forgery
         
           NO  -> Path B. Patch and publish B0.1.
                  No yank.
           YES -> Path A. Yank B0, publish B0.1 in
                  the same release. Write a security
                  advisory.
```

## What this policy does NOT cover

- **Force-push of the git tag.** A yank on crates.io is
  independent of the git tag. The tag `b1.4` stays.
- **Downstream notification.** Crates.io yanks do not
  email subscribers; the user of the policy is responsible
  for writing a security advisory (RustSec) if the yank
  is Path A.
- **In-place fixes.** A `dist-manifest.json` change is a
  policy decision of its own; it is not a yank.
- **Pre-1.0 vs post-1.0.** This is a pre-1.0 release; the
  social contract of "yank on security bug" is what the
  cargo book describes for any version. The yank policy
  does not change at 1.0.

## Awaiting user decision

- [ ] User picks A, B, or C
- [ ] If C: user confirms the 4-bullet security criterion
- [ ] User decides whether to also file a GitHub Security
      Advisory template as part of this policy
- [ ] User decides the first-publish cadence (B0 = tag
      `b1.4`? B0 = next workspace version bump? B0 = a
      separate release tag?)
