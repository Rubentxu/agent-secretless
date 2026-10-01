# ADR-0016 — How a human credential reaches the vault

- **Status**: Accepted
- **Date**: 2026-10-01
- **Supersedes**: nothing. **Extends**: ADR-0015 (control-plane admission),
  ADR-0002 (separate broker and UI), ADR-0009 (Tauri control plane),
  ADR-0003 (peer credentials and pidfd).
- **Implements**: `REQ-CreateVerb-Derives-Its-Refusal`,
  `REQ-Create-Path-Discloses-Nothing`.

## Context

M5's exit UAT is "end-to-end add credential → grant → agent use → revoke".
The first step had no implementation: a running broker could hold a vault and
lend from it, but nothing could put a credential in, and every credential in
this repository's history had been seeded by a test.

ADR-0015 already decided *whether* a privileged caller is the human. It did not
decide *how the secret travels*, and the recorded finding listed that as an
open design question with three candidate answers and no safe default.

## Decision

1. **A privileged write uses the existing socket, and ADR-0015's three
   conditions decide it.** No new channel, no second trust boundary, in this
   release.
2. **The secret is a field of the request.** The decode buffer is zeroized
   before `handle()` runs, and admission is evaluated before the write.
3. **The secret is never in argv or the environment.** The CLI reads it from
   stdin. `/proc/<pid>/cmdline` and `/proc/<pid>/environ` are same-uid
   readable, which is a kernel property this product does not claim to
   control; designing around a channel that is not secret would contradict
   the claim the adversarial harness exists to check.
4. **Enrolment is written at enrolment, stored beside the vault, and read back
   at broker start.** The record is a `0600` file next to the vault, in
   `sha256sum` format: one `<digest>  <path>` per line, the format this
   repository already uses and re-signs for the spec pack. Enrolment is done by
   `asv-brokerd --vault PATH --enrol-principal PATH`, which writes the record
   and exits without opening the vault.
5. **The broker mints the credential id.** The operator supplies a label,
   kind, provider and account; the wire id is a fresh v4 UUID and the vault
   write is an `insert`, which fails closed on collision.

## Why not the alternatives

**A file the broker opens, path in the request.** This is the intuitive way to
keep a secret off the wire, and it is worse. The vault is encrypted at rest;
a plaintext file is a strictly larger disclosure than a heap buffer that is
zeroized at the decode boundary. The defence this option is reaching for
already exists, and it was written by someone reasoning about exactly this
(`main.rs:334-338`).

**A separate operator control socket.** Architecturally the right end state,
and ADR-0009 already points at it. It is a new authentication story, it does
not exist, and landing nothing until it does is worse than landing a verb
behind a gate that has already been proven against four hostile cases.

**Letting the agent session create credentials.** The socket is `0600`, but
the agent runs as the operator's own uid. That authorises the agent to plant
credentials, which is the same argument that already disqualified the uid
check for `DeleteCredential`.

## Two things this decision does not do, recorded so nobody has to re-derive them

**The secret is not a file, and it is not a file descriptor either.** The
finding listed "an fd the broker opens" as the strongest option, and it is
stronger in principle: with `SCM_RIGHTS` the secret never becomes protocol data
at all, which is the property `crates/ipc-protocol` states as the reason no
secret-bearing *domain* type has a wire representation. It was not taken, for
two measured reasons rather than taste. The exposure a request field actually
carries is a brief copy in a buffer `serve()` already zeroizes at the decode
boundary, over a `0600` socket, disclosing nothing the submitting peer did not
already hold; and `SCM_RIGHTS` means `recvmsg` on the broker's single read
path, an fd to close correctly on every early return, and a class of
resource-handling bug in a secret-bearing process. A narrower channel was
available and the cost was real. If the exposure model changes — a
same-uid-reads-the-broker's-memory threat, or a second control socket arriving
— this is the decision to revisit, and the admission rule is unaffected either
way.

**ADR-0015's "stored with the vault" is narrowed to "beside the vault".** The
enrolment record is a sidecar at `<vault>.control-plane`, not a field inside the
encrypted body. Grafting an admission record into the body would couple two
independent trust domains and re-encrypt the whole vault every time a
principal is added, for no property ADR-0015 asks for. What the sidecar keeps
is the substance: written at enrolment, `0600`, read at start, surviving a
restart, and naming principals rather than pids. A missing record is an empty
enrolment and admits nobody; a record that exists and cannot be parsed is a
**fatal** error at start, because reading a damaged authorisation file as
"nobody is enrolled" would make it indistinguishable from an operator who
enrolled nobody.

## Consequences

- **The decode precedes the decision.** A refused caller still causes the
  bytes to be materialised briefly in a zeroized buffer. They never reach the
  vault, the inventory, a response, or a log. Admission governs the *write*;
  the buffer's lifetime is bounded either way. This is stated rather than
  glossed because it is the honest cost of reusing one socket.
- **`DeleteCredential` remains un-wired.** It is admitted by the same rule and
  still writes nothing, so revocation does not survive a restart. Closing that
  is its own decision.
- **M5's real transport is still ADR-0009's.** This ADR is a floor, not a
  destination. If the control-plane socket lands, this decision is revisited
  and the secret's path narrows — the admission rule does not change.
- **Enrolment is operator-supplied and unverified by default.** A broker
  started without `--control-plane-principal` admits nobody, which is the same
  inert-but-safe posture the three existing control-plane verbs have today. A
  verb that can only ever refuse is not a shipped feature; REQ-5 exists so
  that a full configured run is exercised, not so that the default changes.
