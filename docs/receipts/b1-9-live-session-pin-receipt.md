# B1.9 Implementation Receipt — live session pin (pidfd)

Block: B1.9 of `docs/plans/b1-delivery-roadmap.md` (branch `b1/worker-lifetime`).
Closes audit finding H-03: session ownership was answered by integer PID
equality against a recorded boolean, so a process that died left its session
ownable by whoever recycled the PID next — the ambiguity ADR-0003's pidfd
exists to close, reopened one layer above the connection.

## What landed

- **The session record owns a duplicate pidfd.** `WorkloadIdentity::
  cloned_pidfd()` (`dup` — another handle to the SAME process, released
  independently) carries the connection's pin into `SessionRecord`. The old
  `pinned: bool` is derived from presence; `into_pidfd()`, which had zero
  callers, stays for future owners that want the move semantics.
- **One ownership answer.** `SessionStore::owns()` requires PID equality AND,
  when the session carries a pin, `pidfd_is_alive()` — `libc::poll` with a
  zero timeout, decided on `revents`, `EINTR` retried once, anything else
  fail-closed. `belongs_to` and `register_key` delegate to it; `EndSession`
  routes through the same evidence (documented trade-off: a dead owner's
  session can no longer be ended by a recycled PID; the record and its handle
  are released at broker restart).
- **`is_pinned` is live evidence.** The gate for surrogate minting and
  isolated execution now asks the kernel whether the pinned process is still
  there, instead of repeating what was true when the session opened.
- **Fail-closed creation.** `try_create` refuses a PINNED peer whose pin
  cannot be duplicated (descriptor exhaustion) instead of silently downgrading
  it to PID-only ownership; the dispatcher maps it to `Denied` with the reason
  in the message. `create` remains a compatibility wrapper for the existing
  external fixtures, which pin the live test process and can never reach the
  failure path.
- **UAT-030 made structural.** "Every pin must release when the session ends"
  was a counter; now the record owns the handle and `end()` drops it.

## Evidence (all run on this tree)

| Check | Command | Result |
|---|---|---|
| RED | `cargo test -p asv-broker --locked --lib a_dead_owners_session` | FAILED — `belongs_to`/`is_pinned` both true for a fresh identity claiming the dead owner's PID |
| GREEN | same | ok |
| Identity | `cargo test -p asv-identity --locked --lib` | **8 passed** (3 new: two clones of a live pin both alive; unpinned clones to `Ok(None)`; a terminated child reports dead) |
| Broker lib | `cargo test -p asv-broker --locked --lib` | **688 passed** (all self-pinned fixtures stay green — their process is alive) |
| CLI link | `cargo build -p asv-cli --locked` | clean |
| E2E | `cargo test -p asv-broker --locked --test eph_pin_liveness` | ok — real brokerd: a third-PID helper is pinned via real SO_PEERCRED + pidfd and mints through it; after the helper exits, `MintSurrogate` on that session is refused with the ownership message; a fresh session works |
| Formatting | `cargo fmt --all -- --check` | clean |

## Decisions

- `dup`, not `into_pidfd`: the connection and the session share the pin;
  each handle releases independently, and both answer the same liveness.
- Unpinned sessions keep PID-only ownership — the documented M0
  log-and-continue decision — and remain the conservative direction for
  surrogates (no pin, no mint).
- No wire change: every refusal message and response shape is unchanged; the
  `MintSurrogate`/`CreateSession` flows an agent already speaks keep working.
- The worker delegation failed three times in a row ("assistant reported an
  error"); the block was implemented inline by the parent from the same
  approved design, with the RED step observed before any fix.

## Known trade-offs (deliberate, documented in code)

- A session whose owner died cannot be ended by a recycled PID; the record
  and its fd are released at broker restart. Bounded by agent lifetime.
- Connection-level audit rows (`pinned` field) still describe the connection
  at request time; session-level liveness is the gate, not the audit field.

Risk: item 3 — session ownership is a shared contract consumed by every
session-scoped verb and by external CONNECT fixtures. All internal consumers
route through `owns()`; the 688-row broker suite, the identity suite and the
real-process E2E pin the behavior. An external client that depended on a dead
process's session surviving PID reuse was relying on the defect this block
closes.
