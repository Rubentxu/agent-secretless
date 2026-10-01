# ADR-0015 — Control-plane admission: what separates the human from an agent

- Status: Accepted
- Date: 2026-10-01
- Supersedes nothing. Completes the session launch record that ADR-0003
  describes and the code never built.

## Context

A running broker cannot be given a credential. `Request` has no
`CreateCredential`; the CLI's `Credentials` subcommand is documented "List
credential metadata. Never values"; the only writer in the workspace is the
out-of-band `asv-vault-tool`. `15-ROADMAP.md` gates M5 on "end-to-end add
credential → grant → agent use → revoke", and that chain's first step does not
exist.

`VaultStore::upsert` works. The missing thing is not the write, it is the rule
saying who may ask for it. `Request::DeleteCredential` is a deliberate closed
door, and its own comment gives the reason: every peer reaching the socket runs
as the operator's uid, so a uid check would pass for the agent as readily as
for the human.

ADR-0003 already settled the mechanism — peer credentials, a pidfd, and a
"pidfd/session launch record", with "self-declared agent names are metadata,
not authentication". The broker implements the credentials and the pidfd.
`SessionStore` keeps a `peer_pid` and a `pinned` flag per agent session. The
record of *who is not an agent* was never built, and until it is, "is this peer
the human?" has nothing to consult.

## The trap

Two checks are available, and each fails in a different direction.

**Inferring from absence fails open.** "Not a known agent session" is
satisfied by every peer the broker has not enumerated: a process that connected
directly, one whose session record was dropped, one started before the broker
came up. Absence from the store is a fact about the record, not about the
process, so this check hands the capability to exactly the peers the boundary
exists to exclude.

**Matching an enrolled identity alone fails to a confused deputy.** "The peer
is running the enrolled desktop binary" is satisfied by any process that
execs that binary. A digest binds the file, not the arguments or the process
around it, and an agent under broker control can run programs.

## Decision

A privileged verb is admitted only when **all three** hold, and refused when
any one is missing.

1. **The caller is not under broker control.** It is not inside a
   broker-managed session or cgroup. This is the decisive check against the
   agent: escaping a cgroup is what ADR-0006, ADR-0007 and the existing
   hardening work are about, and a caller that has escaped has already lost far
   more than this capability.
2. **The caller is positively enrolled.** It matches a principal the operator
   enrolled. Without this, check 1 is absence-based and fails open.
3. **The caller is pidfd-pinned at decision time.** Without a pin, the pid
   checked and the process acting can differ, which is the PID-reuse ambiguity
   ADR-0003 exists to remove.

A separate control-plane socket is expected and is **not** sufficient. ADR-0009
makes the desktop unprivileged, so it runs as the operator's uid, and so does
every agent process that operator started; a socket the operator can open, the
agent can open. The socket shrinks the candidate set and makes check 1 cheap.
It carries no authority on its own, and the reason is recorded here so the next
reader does not reach for it and believe the boundary is done.

Enrolment keys on a **principal, not a pid**: the executable path together
with its content digest. Pids do not survive a broker restart and the desktop
is long-lived while the broker is not. The pid is checked per connection.

## Relationship to other decisions

- **ADR-0002** puts the UI in a distinct process and trust domain. Distinct
  processes alone do not separate them here, because the desktop is
  unprivileged and shares the operator's uid with every agent process that
  operator started. This ADR supplies the part ADR-0002's decision needs in
  order to be enforceable at the socket: the record that says which process is
  on which side of it.
- **ADR-0003** supplies the mechanism — peer credentials, the pidfd, and the
  session launch record. This ADR completes the record half, which the code
  never built, and states the rule the pidfd is consulted under.
- **ADR-0005** ranks how a credential is *reached*. This ADR is a different
  axis: it decides who may *manage* the store that holds them. A caller can be
  perfectly entitled to reach a credential by the strongest rung of that ladder
  and still be refused the right to add one.
- **ADR-0009** makes Tauri the human control plane with no secret-retrieval
  API. This ADR decides how the broker knows it is talking to that control
  plane, which ADR-0009 assumes but does not specify.
- **M4 D4** is the precedent this extends, already implemented as the narrow
  refusal described below.

## Consequences

- Check 3 is already implemented as a narrow refusal: `MintSurrogate` denies
  with "surrogate minting requires a pidfd-pinned session"
  (`crates/broker/src/lib.rs:610`) while the rest of the broker keeps treating
  an unpinned peer as weaker-but-usable. This rule extends that directed
  pattern to privileged verbs; it does not reverse the M0 decision to be
  permissive about ordinary ones. `main.rs` logging "pidfd association
  unavailable, continuing with peer credentials" stops being sufficient for a
  privileged verb.
- The enrolment record is written at enrolment, stored with the vault, and read
  back at broker start, so it names principals rather than processes and
  survives a restart. It is not readable by, and confers nothing on, a process
  the broker launched as an agent session.
- A credential-write verb becomes implementable against something real. Until
  it exists, `DeleteCredential` stays a closed door, which is correct.
- 08-IDENTITY-POLICY-CAPABILITIES §2 asks for blended human + agent identity.
  That is only expressible once the broker can tell the two apart, which is
  what this ADR makes possible.
- Cedar still decides *policy* — which principal may perform which action on
  which resource. This ADR decides *admission*: who is even eligible to be a
  principal. The two are separate and neither substitutes for the other.

## Not decided here

No `CreateCredential` verb, no Tauri work, and no change to fail-open
behaviour for ordinary verbs. `FND-broker-cannot-receive-credentials` remains
open: the model exists now, the implementation does not, and the two are
different claims.
