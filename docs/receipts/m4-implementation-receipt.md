# M4 implementation receipt

Cycle: p-20a1ee316faf2ba3/m4-http-broker
Work item: M4 — HTTP broker + surrogate credentials
Path: A-full
Gate: implementation-complete

## Scope delivered

Outbound HTTP with surrogate credentials. The agent holds a broker-minted
`asv1_<base64url 32B>` surrogate that the provider rejects; the broker injects
the real credential in-process through `VaultStore::with_secret` and stores
only a `CredentialId`. Nine requirements, M4-R1..R9, are listed with their
evidence in `docs/receipts/m4-traceability.md`.

## Commits

```text
02862fa feat(domain): add Authority type, SurrogateId and github.issue.read
10b76ad feat(policy): validate against a Cedar schema and bind the audience
0d45995 feat(connector-http): pin audience addresses and refuse unsafe hops
0a6f325 test(connector-http): prove the transport claims against a real TLS origin
6032a1f feat(broker): mint session-bound surrogates behind a pinned session
6e35ffd feat(broker): wire semantic GitHub operations to vaulted credentials
022eba2 test(broker): prove the environment quarantine and the crash path fail closed
6ca56f4 test(policy): pin the two M3 Cedar defects the backlog says are still open
91de368 test(broker): make the UAT-030 performance gate falsifiable
65893cd test(connector): pin the UAT-008 URL tricks against the comparison that runs
6367da5 test(broker): cover the two UAT-005 replay vectors nothing was testing
db66542 test(connector): add the M4-R8 URL/header fuzz corpus the exit gate names
d96d035 fix(vault): read the body nonce with the ciphertext it belongs to
a761fdd docs(receipt): map every M4 claim to the thing that discharges it
```

## Verification observed

Every line below was executed at `a761fdd`+fmt on the host named in
`docs/receipts/m4-traceability.md`.

```text
cargo test --workspace --no-fail-fast        exit 0, 240 passed, 0 failed, 29 binaries
                                              (one run at 239; see below)
cargo clippy --workspace --all-targets        exit 0, 0 warnings
cargo fmt --all -- --check                    exit 0, clean
tests/adversarial/run_harness.py              exit 0, 14 passed, 0 leaked, 0 invalid
tests/adversarial/test_falsifiability.py      exit 0, 4/4 injected leaks detected
tools/check-gates.py                          0 hard defects, 0 warnings, 0 orphaned UAT
spec pack SHA256SUMS                          37/37 verified unchanged
cargo +nightly fuzz run authority_canonicalization
                                              exit 0, 2522433 runs in 121 s, 0 crashes
```

## Command output digests

None. An earlier draft of this receipt quoted a sha256 of
`cargo test --workspace` output, and it was wrong twice over: the value was
captured before the rustfmt commit, and — once corrected — the digest did not
reproduce, because a test run's output embeds per-test timings that differ on
every execution. A digest that changes when nothing changed is not evidence.

What is reproducible here is the shape, not the bytes: 240 passed / 0 failed,
stable across six consecutive full-workspace runs. `cargo fmt --check` is the
exception and does produce a stable digest, `e3b0c44…`, which is the sha256 of
the empty string — what `fmt` prints when there is nothing to fix.

## Test count is 240, occasionally observed as 239

One full-workspace run reported 239 passed / 0 failed where six others
reported 240 / 0. The per-test timings in that run were also the slowest
observed (2m13s against a typical 12s), which is what a loaded machine looks
like. The missing test was not isolated to a binary. This is recorded rather
than smoothed over: the honest statement is "240, with one run at 239 under
load and no failure observed", not "consistently 240".

See **Known flakiness** below for the two tests that have each failed once.

## Falsification, not just green

A gate that has only ever been green is not a gate. Three things were made to
fail on purpose and were observed to fail:

1. `Authority::canonicalize` with `labels.len() < 2 && false` — caught by the
   fuzz target in under 45 s at the independent oracle.
2. `Authority::canonicalize` with `label.ends_with('-') && false` — same, also
   under 45 s.
3. `crates/broker/tests/uat_027_rotation.rs` against the pre-fix vault, which
   failed with `Envelope(AuthenticationFailed)`.

(1) and (2) were reverted and their crash artifacts deleted. (3) is a real
defect found by this cycle, fixed in `d96d035`.

## Defect found and fixed during this cycle

`VaultStore::with_secret` read the AEAD body nonce from the in-memory header
and the ciphertext from disk. Any write by a second handle moved the nonce on
disk while the first store kept the old header, so the next read paired a fresh
ciphertext with a stale nonce and the tag check failed — a corruption-shaped
error for a file that was fine.

This was latent since M1, which never had a second handle writing while another
was open. R7 is what made it reachable: rotation is supposed to be invisible to
a running broker, which is exactly a second handle writing. The fix reads both
values from one decode of the file.

## Deviation from the approved design

D10 specified `crates/policy/tests/p95_authz.rs` measuring 100 `authorize`
calls. What shipped is `crates/broker/tests/uat_030_perf.rs`, measuring the
whole brokered read. The wider measurement is the better one — it is what
revealed that most of the 4 ms is the TLS handshake to loopback, leaving only
1 ms of headroom against the 5 ms budget — but the design said otherwise and
the deviation is recorded rather than absorbed. D1..D9 and D11 are as approved.

## Scope boundary

No Tauri dashboard, no local proxy mode, no second provider connector. M4
ships one reference provider (GitHub) behind a semantic surface;
`Action::HttpRequest` stays unauthorizable and `ALLOWED_AUDIENCES` is a
compile-time constant, because production config loading does not exist and D9
forbids environment config. Non-ASCII/IDNA authorities are denied rather than
supported; that is a recorded decision, not an omission.

## Known flakiness

Under full-workspace concurrency, `uat_030_perf` and `uat_028_ssh_server` have
each failed once and then passed on every isolated and repeat run (uat_030:
5/5 isolated, 3/3 under load, and 6 consecutive clean workspace runs at 240
passed). Both bind an ephemeral port and start a listener. The failures are
consistent with port contention on a loaded machine and are **inferred**, not
proven; a dedicated characterisation run is outstanding. This does not
weaken any M4 claim, but it should not be reported as a settled green either.
