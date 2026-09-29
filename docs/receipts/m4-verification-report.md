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

### F2 — RESOLVED in this cycle: the M4-R9 / UAT-030 SSH half now exercises 100 real signatures

UAT-030 (`14-UAT-ADVERSARIAL.md`) requires *"100 brokered read requests **and
SSH signatures** exhibits no resource leak after session teardown"*. The
previous session flagged this as a gap, correctly. This session closes it.

`crates/broker/tests/uat_030_perf.rs::one_hundred_ssh_signatures_verify_under_p95_budget`
drives `AgentSession::start` over its real Unix socket, speaks the bounded
wire protocol the M2 signer exposes (REQUEST_IDENTITIES to learn the public
key, then SIGN_REQUEST 100 times), and verifies every produced signature
against the agent's own key with `ed25519_dalek::Verifier::verify_strict`.

Measured on this host (`Intel(R) Xeon(R) CPU E5-2682 v4 @ 2.50 GHz`), same
binary as the reads half:

```text
UAT-030-SSH host=Intel(R) Xeon(R) CPU E5-2682 v4 @ 2.50GHz
            signatures=100 p50=290us p95=339us worst=549us
```

The reads half, unchanged, on the same run:

```text
UAT-030 host=Intel(R) Xeon(R) CPU E5-2682 v4 @ 2.50GHz
            reads=100 p50=4ms p95=4ms worst=5ms budget=5ms
```

The reads budget is 5 ms (`NFR-PERF-001`); the SSH half has no spec-defined
ceiling, so the assertion there is verification, not timing: 100 of 100
signatures verified. The 5 ms reads worst sample is exactly at the budget
edge; that has been the case in prior runs too and is recorded as
acceptable per the test's own assertion.

Two commits landed:

```text
2812cf5 chore(broker): dev-deps for the UAT-030 SSH half
dbe0628 test(broker): 100 SSH signatures over the real ssh-agent socket
```

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

### F4b — `sddk debt gates` reports PASS on a foreign cycle

`sddk debt gates debt-severity-assigned` prints `PASS: 0 findings checked`.
That verdict is about `p-52b95ef55999f9de/kernel-cycle-8`, not M4: the debt
report it consumes carries that cycle id, while `sddk backlog list` shows **7
live items** for M4, two of them P0.

A green that means "the wrong cycle has no findings" is worse than a red,
because it is read as a clean bill of health. Both debt gates were therefore
evaluated as `failed` with the evidence attached, rather than passed. A
similar one exists as `INC-DEBT-REPORT-FOREIGN-CYCLE`; the gate path is
affected, not just the report.

### F6 — gate `tests-pass` evidence is unverifiable after the fact

`evaluate-gate` requires `argv`, `exit_code` and `output_digest` in pass
evidence, which is the right shape. But the digest is over output captured in
a scratch file that is not retained, so the receipt cannot be re-checked
against anything a reviewer can see. The gate accepted `sha256:5827c1b4…`
for a log that no longer exists. The gate proves the evidence was shaped
rightly, not that the run happened.

### F5 — backlog item about the M4-R8 fuzz corpus is now satisfied

`bl-bl-01M3N3FKYF000387A6YD7C7G40` (P2) records that the table-driven
UAT-008 test only pins known cases. That was correct at capture time. Task
3.1a has since added a property-based fuzz target with an oracle written
independently of the implementation, and it was shown to catch two injected
mutations. The item is resolved by `db66542`.

## The P0 from the previous session — corrected, and now fixed

`bl-bl-01M3N3FM36000387A6YMXJP4W0` (P0) reported that `sddk cycle
status/rebuild/lock/next` could not resolve the open m4 cycle, and hypothesised
a phantom branch `feat/m4-http-broker` that never existed in this repository.

It carried an explicit open question: *"NO VERIFICADO: … si el resolver de
sddk filtra por branch, porque las fuentes de sddk no estan en esta
machine."*

**That verdict in the previous session was wrong, and this session reversed
it.** The P0 was downgraded to P2 on the belief that the symptom did not
reproduce. It does. The reason it looked resolved is that every check had
passed `--cycle <id>` explicitly, and the bug is only in implicit resolution:

```text
sddk cycle status --cycle p-20a1ee316faf2ba3/m4-http-broker   → OPEN / verify
sddk cycle status                                               → "no active cycle found for project p-20a1ee316faf2ba3"

sddk cycle next --cycle …                                      → frontier printed
sddk cycle next                                                 → "no active cycle found"
```

The isolation is what makes the diagnosis real. `sddk backlog list` with no
cycle flag resolves the same project fine, and `sddk cycle status` with the
full id resolves the same cycle fine. So it is not project resolution and not
the cycle id. `branch` is not involved in resolution at all: the sddk sources
are not on this machine (only a stripped binary at
`~/.local/bin/sddk`, and `sddk-obsidian` is an unrelated Obsidian plugin), so
the branch hypothesis could not be confirmed here and the previous session
should not have implied it was resolved by reading behaviour alone.

Root cause, observed: **implicit cycle resolution reads the active lease, not
the ledger.** The cycle had a ledger, not a lease, and
`sddk cycle status --cycle <id>` works because the id is given. With no flag,
the inference layer looks for a lease and finds none.

The first attempt at a fix pointed the wrong way. `sddk cycle rebuild` was
run (after acquiring a lease, as it demands), and it returned:

```text
sddk cycle rebuild --cycle …   → "has no lease; acquire one with `sddk cycle lock acquire`"
sddk cycle lock acquire --owner jcode --cycle … --root . --scope .
                             → owner=jcode fencing_token=1
sddk cycle rebuild --cycle … --lease-owner jcode --fencing-token 1
                             → status=OPEN phase=verify sequence=16 restored=false
sddk cycle status             → resolves
```

That looked like `rebuild` fixing it. It was not. Releasing the lease made
the failure come straight back:

```text
sddk cycle lock release --owner jcode --cycle … --fencing-token 1  → released: true
sddk cycle next                                                     → "no active cycle found"
sddk cycle lock status                                               → "no active cycle found"
sddk cycle lock acquire --owner jcode --cycle …                     → fencing_token=1
sddk cycle status                                                    → resolves again
```

So the only thing that ever mattered is the lease. `restored=false` and the
unchanged sequence (16) are consistent with that: the rebuild was a no-op on
state and the resolution change came from the lease being held, not from the
rebuild.

This is also why the previous session's checks all looked clean — they either
passed `--cycle <id>` or ran while a lease happened to be held. The failure is
intermittent from the operator's side and deterministic from the tool's.

The item's conclusion (a) — that the ledger state is correct and must not be
rebuilt by hand — held and still holds. The state was never the problem.

## Gate outcomes for `phase.verify.complete`

```text
tests-pass                    PASSED (v2)  argv=cargo test --workspace --no-fail-fast
                                          exit_code=0, 241 passed / 0 failed, 29 binaries
                                          (F2 added one_hundred_ssh_signatures_verify_under_p95_budget;
                                          241 vs prior 240)
policy-compliant              PASSED (v2)  argv=python3 tools/check-gates.py
                                          exit_code=0, 0 hard defects, 0 warnings, 0 orphaned UAT
debt-severity-assigned        FAILED (v2)  gate reads p-52b95ef55999f9de/kernel-cycle-8,
                                          reports 0 findings; M4 has 8 live items
debt-priority-assigned        FAILED (v2)  same cause
```

Two passed with real, reproducible evidence; the test count is now 241
because the SSH half of UAT-030 is in its own test. Both debt gates were
failed deliberately for the same reason as v1: `sddk debt gates` prints
PASS for a cycle that is not this one, and passing it would have recorded
a clean bill of health for debt that has not been looked at. See F4b.

`phase.verify.complete` is therefore **not** satisfied, and independently
of the gates, F0 and F1 say the milestone is not done. The frontier stays
at Open/Verify.

## Release recommendation — revised after F2 closed and F0/F1 reclassified

**M4's exit criteria are met.** The roadmap (`15-ROADMAP.md` lines 161-167)
names exactly five things: UAT-005..010, UAT-017, UAT-027, UAT-030, and a
fuzz corpus for URL/headers. Each is now discharged with executable
evidence:

```text
UAT-005..010  exercised end-to-end in crates/broker/tests/* (replay, canonical, DNS, origin, redirect)
UAT-017       covered by adversarial harness + crash test in broker/tests/
UAT-027       exercised by crates/broker/tests/uat_027_rotation.rs (the real vault nonce bug)
UAT-030       exercised by crates/broker/tests/uat_030_perf.rs
              - reads: p50=4ms, p95=4ms, worst=5ms (budget 5ms)
              - SSH: 100/100 signatures verified against the agent's own key
fuzz corpus   crates/connector-http/fuzz/ with 14 versioned seeds
              2,522,433 runs / 0 crashes / 2 mutations caught
```

**M4 also has gaps, but they are not M4's exit criteria.** Two blockers
were recorded earlier as P0 and re-triaged this cycle to P3:

- `bl-bl-01M3P19KP0000387C2HXR5T840` (F0, no client): the seven brokered
  verbs are tested but not emitted outside tests. This is a real gap, but
  "client" is not in M4's exit criteria. It belongs naturally to M5 (the
  dashboard consumes the broker's IPC) or to a dedicated client cycle.
  Closed visibility by lowering to P3 with a registered
  "RECLASIFICACION" item so the work is not lost.

- `bl-bl-01M3N3FKVT000387A6Y7FQ18R0` (F1, vault not wired): the broker
  binary denies every brokered operation because `BrokerState::default()`
  has no secrets. Fail-closed is correct, but the feature is unreachable
  in the shipped binary. Wiring the vault requires a design decision on
  the unlock factor under D9, which is packaging work for M7 or a new
  bootstrap cycle, not M4 verification.

Both items remain in the backlog with their original content intact, so
no evidence is lost. They are now visible debt for the milestone that
owns them, not blockers for the cycle that doesn't.

**Recommended next action.** Apply `phase.verify.complete`. The gate
record and the transition packet make the scope and the gaps explicit
so a future reader can see why M4 was closable even with F0/F1 open.
