# M4 verification report

Cycle: p-20a1ee316faf2ba3/m4-http-broker
Phase: verify
HEAD verified: 90d7504 (+ rustfmt commit fbf2f86)
Host: Intel Xeon E5-2682 v4 @ 2.50 GHz, Linux, OpenSSL 3.5.8

## Verdict

M4's nine requirements are implemented and each is discharged by an executable
check. The mapping is in `docs/receipts/m4-traceability.md`; the evidence is in
`docs/receipts/m4-implementation-receipt.md`.

The milestone is **not** shippable, and the reason is not a defect in what M4
built. It is that the shipping binary never opens the vault, so the feature
does not exist at runtime. That is recorded as a blocker below, not smoothed
into a pass.

## What was verified

```text
cargo test --workspace --no-fail-fast        240 passed, 0 failed, 29 binaries
                                              (one run at 239; no failure)
cargo clippy --workspace --all-targets        0 warnings
cargo fmt --all -- --check                    clean
tests/adversarial/run_harness.py              14 passed, 0 leaked, 0 invalid
tests/adversarial/test_falsifiability.py      4/4 injected leaks detected
tools/check-gates.py                          0 hard defects, 0 warnings, 0 orphaned UAT
spec pack SHA256SUMS                          37/37 verified unchanged
cargo +nightly fuzz run authority_canonicalization
                                              2,522,433 runs, 0 crashes
```

## Findings

### F0 — BLOCKER: no client can issue any brokered request

The M4 brokered verbs — `ReadIssue`, `CreateIssue`, `CreateRelease`,
`MintSurrogate`, `RevokeSurrogate`, `Authorize`, `SubmitApproval` — exist in
the IPC protocol and the broker matches and handles every one of them
(`crates/broker/src/lib.rs:316-490`). But nothing outside the test suite ever
*constructs* one.

Counted across every non-test source file in `crates/`:

```text
ReadIssue        0 emitters      RevokeSurrogate  0 emitters
CreateIssue      0 emitters      Authorize        0 emitters
CreateRelease    0 emitters      SubmitApproval   0 emitters
MintSurrogate    0 emitters
```

The `asv` client (`crates/cli/src/main.rs:30-48`) exposes exactly four
subcommands: `Status`, `Session`, `Run`, `Credentials`. It maps those to
`Ping`, `CreateSession` and `ListCredentialMetadata`, and handles
`Command::Run` locally by spawning a child process. It can print
`Response::IssueRead` and `Response::ReleaseCreated` (`main.rs:210-216`), but
there is no subcommand that produces those requests in the first place — the
response arms are unreachable from the CLI.

So M4 built a working, tested, fail-closed implementation of seven operations
that no shipped binary can invoke. The `asv run` path (M2's strict session with
a broker-owned SSH signer) is the closest thing to a client, and it does not go
through these requests either.

This is larger than the CLI-wiring item already in the backlog, and it is
disjoint from F1: even with a vault open (proven below), there is no way to
ask the broker to do the thing. F1 alone would leave a broker that refuses;
F0 plus F1 means a broker that is correct and unreachable.

Scope: this is the client surface for M4, which M2's `asv run` was supposed
to grow. It is a milestone-level gap, not a bug to patch inside verify.

### F1 — BLOCKER: the brokered HTTP path is unreachable in the shipped binary

`crates/broker/src/main.rs:49` constructs `BrokerState::default()`, whose
`secrets` field is `None`. `BrokerState::default()` is not a test shortcut; it
is what `asv-brokerd` does on every start. So the real broker denies every
brokered operation with *"no credential store is open, so no brokered
operation can run"* (`crates/broker/src/lib.rs:532`).

Fail-closed is the correct behaviour and it is well documented in the code. The
problem is that M4's entire user-visible value is on the other side of that
refusal. A packaged `asv-brokerd` will never perform a brokered GitHub read,
issue create or release create, because nothing ever opens a vault.

Every test that exercises the path injects `VaultSecretPort` by hand. The
production startup path has no equivalent step, and no test covers it.

This was already known in the backlog as P1
(`bl-bl-01M3N3FKVT000387A6Y7FQ18R0`, captured in the apply phase). The entry
says "the CLI"; the real location is the broker daemon, which is more precise
and more serious: the CLI is only an IPC client and never builds a
`BrokerState` at all.

Falsified, not just read: the finding was probed by actually wiring a vault
into the startup path (`VaultStore::create` → `header().unlock` →
`state.secrets = Some(VaultSecretPort::new(...))`), building the binary and
starting it. It reports `PROBE: vault wired, secrets.is_some()=true` and
listens normally. The three pieces compose exactly as the tests assume, so
F1 is a genuine missing startup step and not a symptom of some second defect
lurking behind the refusal. The probe was reverted; the tree carries no probe
code.

Scope call: wiring the vault means deciding where the vault path comes from,
how the unlock factor reaches the broker without an environment variable (D9
forbids `std::env::var*` in broker and connector production sources), and what
happens when it is absent. That is design work with a security surface of its
own, and it does not belong to a verification phase. It is escalated as a
blocker for the release decision, not quietly closed.

### F2 — the M4 exit gate names SSH signatures that nothing measures

UAT-030 (`14-UAT-ADVERSARIAL.md`) requires *"100 brokered read requests **and
SSH signatures** exhibits no resource leak after session teardown"*.
`crates/broker/tests/uat_030_perf.rs` performs 100 brokered reads and checks
teardown, and it never signs anything over SSH.

The leak assertion is also narrower than the UAT asks: it covers sessions,
surrogates and grants, and it does cover the pidfd pin
(`sessions.is_pinned(session)`), which contradicts the backlog note claiming
the pin is unobservable. So the pin is checked; the signatures are not.

Also P1 in the backlog (`bl-bl-01M3N3FM0Q000387A6YVC5TJW0`). Recorded as a
partial exit, not as a pass.

### F3 — two flaky tests, cause not established

`uat_030_perf` and `uat_028_ssh_server` each failed once under full-workspace
concurrency and passed on every isolated and repeated run since
(uat_030: 5/5 isolated, 3/3 under load, 6 clean consecutive workspace runs).
Both bind an ephemeral port and start a listener, so port contention is the
likely cause. That is **inferred, not proven** — no characterisation run was
done. Not a blocker; not something to report as a settled green either.

### F4 — `sddk cycle narrative` does not reflect cycle state

`narrative` prints *"Cycle completed"* for every cycle in the project,
including `m4-http-broker`, which is `OPEN` in phase `verify`. Verified across
all five cycles: m0, m1, m2 and m3 are `CLOSED` and m4 is `OPEN`, and all five
render the same sentence. The string does not read the cycle status.

This is a defect in the SDDK CLI, not in this repository's cycle. It matters
here because the operator view is the one a human reads to decide whether a
milestone is done, and it currently says every milestone is.

### F5 — backlog item about the M4-R8 fuzz corpus is now satisfied

`bl-bl-01M3N3FKYF000387A6YD7C7G40` (P2) records that the table-driven
UAT-008 test only pins known cases. That was correct at capture time. Task
3.1a has since added a property-based fuzz target with an oracle written
independently of the implementation, and it was shown to catch two injected
mutations. The item is resolved by `db66542`.

## The P0 from the previous session, re-verified

`bl-bl-01M3N3FM36000387A6YMXJP4W0` (P0) reported that `sddk cycle
status/rebuild/lock/next` could not resolve the open m4 cycle, and hypothesised
a phantom branch `feat/m4-http-broker` that never existed in this repository.

The branch facts still hold and were re-confirmed: `git branch -a` shows only
`main` and `origin/main`, the reflog contains no checkout, and the ledger
records `branch=feat/m4-http-broker` across all 19 m4 events.

The *symptom* does not reproduce. Every command the item named now resolves the
cycle correctly:

```text
sddk cycle status --cycle …/m4-http-broker   → OPEN / verify
sddk cycle next    --cycle …/m4-http-broker   → frontier from Open/Verify
sddk cycle lock status                         → lease: none
```

The gate was evaluated and the `phase.build.complete` transition applied
successfully against the same cycle id, which is the strongest evidence that
nothing is blocking resolution. The item's own conclusion (a) — that the ledger
state is correct and must not be rebuilt — is confirmed and acted on.

So: the branch mismatch is a real, unexplained ledger/Git divergence worth
recording, but it is **not** the release blocker the item claimed. What
actually blocks release is F1. The P0 is recommended for downgrade to P2 with
the divergence kept as its content.

## Release recommendation

**Do not ship M4 yet.** F0 means the milestone's operations have no client, and
F1 means the broker holding the credentials would refuse them anyway. M5
(dashboard) and the packaging work in M7 would be built on a path that cannot
execute and cannot be reached.

Suggested order:

1. Client surface for the seven brokered verbs (F0) — this is M2/M4 interface
   work, and it decides what `asv run` looks like.
2. Vault bootstrap and unlock-factor design for `asv-brokerd` (F1), honouring
   D9's ban on `std::env::var*` in broker and connector production sources.
3. The SSH-signature half of UAT-030 (F2).
4. Re-verify.

F0 and F1 together are the difference between "M4 works" and "M4 has a
correct implementation of a feature nothing can call". Worth deciding whether
M4's own exit criteria ever required a client, or whether the cycle was
scoped to broker-and-connector only with the client deferred by default.
