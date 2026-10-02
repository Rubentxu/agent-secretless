# M2 Implementation Receipt — Agent sessions + SSH signer

The first complete vertical. This receipt exists because the roadmap asserts
M2 is closed and, before it, nothing in `docs/receipts/` pointed at what
"closed" meant for this milestone. The `M11-M13 semver` gate row names that gap
directly: milestone work shipped by riding inside a release, so the assertion
had nothing to point at.

## What landed

- `crates/identity/` — `WorkloadIdentity` built from `SO_PEERCRED`, with the
  pidfd pin that later milestones build their admission rules on.
- `crates/ssh-agent/` — the signer. It holds the key, performs the signature
  and returns the signature; the key material never crosses the socket.
- `crates/broker/src/lib.rs` — session creation bound to the peer's PID, and
  the session store whose `belongs_to` every later authorization calls first.
- `crates/broker/src/surrogate.rs` — the session-scoped, time-bounded,
  constant-time-compared token registry this milestone introduced.

## Commits

- `6e8e029` feat(ssh): add broker-owned agent sessions and strict asv run
- `7a006b5` fix(ssh): keep agent connections open for OpenSSH
- `f41e041` fix(test): resolve the ssh account from passwd, not ambient $USER
- `dbe0628` test(broker): 100 SSH signatures over the real ssh-agent socket
- `0494a92` chore(release): prepare v0.3.0 for M2

## Exit UAT

UAT-001 — *SSH private key never leaves broker.*

## Evidence

```
$ cargo test --release -p asv-identity -p asv-ssh-agent
test result: ok. 5 passed   (asv-identity lib)
test result: ok. 7 passed   (asv-ssh-agent lib)
test result: ok. 4 passed   (m2_socket_uat)
test result: ok. 1 passed   (uat_028_ssh_server)
```

The 4-test socket suite drives the signer over a real Unix socket against a
real `ssh-agent`, and `uat_028_ssh_server` verifies a signature against an
actual OpenSSH server rather than a stub. The 100-signature test exists because
a socket that answers once is not a socket that answers under load.

## Known limitations

- **UAT-001 is not declared by a header.** The property is proved in
  `crates/ssh-agent/src/lib.rs` and in the socket suite, but no file carries
  the `//! UAT-001 — ...` line, so `check-gates.py` cannot see it. It is one of
  the ids accounted for in the `UAT claim coverage` row, not an omission.
  The row named only eleven ids and left UAT-001 and UAT-014 out of its
  enumeration entirely, so citing it here was citing a row that did not
  mention the thing being cited; the row has since been corrected to carry
  both. The witnesses are
  `crates/ssh-agent/tests/m2_socket_uat.rs::uat_001_real_socket_lists_public_key_and_signs_without_export`
  and, for UAT-014,
  `::uat_014_revoke_removes_socket_and_blocks_new_operations` — the same file,
  whose first doc line claims nothing and whose name does not look like a UAT,
  so it is invisible to both the header scan and the filename inference.
- M2 predates the surrogate class binding this cycle added. Its tests still
  pass because `GenericSecret` and `BearerToken` both map to
  `CredentialClass::Generic`, which backs every family — correct for an SSH
  key, but the mapping is permissive by design and the reason is recorded in
  `CredentialClass::from_kind`.

## Honest observations

- The `f41e041` fix exists because a test read the ambient `$USER`. A test that
  passes on one machine and fails on another is a test of the environment, and
  the milestone is only closed because that was fixed rather than papered over.
