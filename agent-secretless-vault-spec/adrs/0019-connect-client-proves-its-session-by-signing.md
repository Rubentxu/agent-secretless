# ADR-0019 — A CONNECT client proves its session by signing, because the kernel does not know it

- **Status**: Accepted
- **Date**: 2026-10-02
- **Supersedes**: nothing. **Extends**: ADR-0011 (session-scoped surrogate
  credentials), ADR-0012 (session-scoped TLS CA), ADR-0015 (control-plane
  admission).
- **Amends**: nothing. It does not touch `WrongSession`, the credential
  class, or the policy engine.
- **Resolves**: `FND-m9-connect-substitution`, referenced by
  `15-ROADMAP.md:372` and `14-UAT-ADVERSARIAL.md:112` but never written
  down. Referencing options is not having them.

## Context

UAT-010 requires that a surrogate reach the provider and the real
credential never reaches the client. It is covered on the broker's
semantic path. It is **not** covered on the CONNECT path, and the code
says so itself (`crates/broker/src/tls_bridge.rs:714-716`):

> What this does not do is substitute the surrogate for a real
> credential on the way upstream. The caller sees the decrypted bytes.
> That is why UAT-010 still has no suite.

The obstacle is identity, not parsing. `SurrogateRegistry::redeem_for`
binds a surrogate to the session that minted it
(`crates/broker/src/surrogate.rs:182`): a token presented from another
session gets `WrongSession`. An ordinary HTTP client behind `HTTPS_PROXY`
presents a CONNECT and has no session, so it has no surrogate, so
substitution cannot happen.

The broker's whole identity model is pid-based — `SessionStore` records
`peer_pid` (`lib.rs:54`) and `owned_by` compares it
(`lib.rs:112`) — which suggests the obvious answer: read the peer's pid
off the accepted socket and look up its session.

**That answer is wrong, and it was measured rather than assumed.**
`asv_identity::peer_credentials` takes a `BorrowedFd` and calls
`getsockopt(SOL_SOCKET, SO_PEERCRED)`, which reads as if it works on any
connected socket. On this kernel:

```text
AF_UNIX stream socket : pid=1210483 uid=1000 gid=1000   (this process)
AF_INET  connected    : pid=0      uid=-1   gid=-1
AF_INET  listener     : pid=0      uid=-1   gid=-1
```

The same call, in the same process, returns the correct pid over
`AF_UNIX` and the unavailable sentinel over `AF_INET`. That isolates the
cause to the socket type and leaves no room to argue.

So a CONNECT arriving on TCP carries **no kernel identity at all**.

## The options

| # | Option | Cost |
|---|---|---|
| 1 | The token is its own proof | A surrogate redeemable without a session. Gives up `WrongSession`, which is half of why a surrogate is a capability and not a password. **Rejected** |
| 2 | Identity from the kernel (peer pid) | **Rejected by measurement**, above |
| 3 | The client signs a per-tunnel nonce with its session signer | Requires the broker to know the session's public key |
| 4 | CONNECT does not substitute; declared unsupported for credentialed destinations | Honest and small; leaves M9 open |

## Decision

**Option 3**, with **option 4 as its failure mode**.

A CONNECT client proves its session by signing a 32-byte nonce generated
per tunnel, with the Ed25519 signer that session already owns
(`SSH_AUTH_SOCK`, `crates/ssh-agent/src/lib.rs:75-116`). The bridge
verifies the signature against the public key registered for a **live**
session and resolves it to an `AgentSessionId`.

Option 4 is what the product does whenever option 3 cannot be satisfied.
The tunnel is refused rather than forwarded with an unsubstituted
surrogate. Forwarding a surrogate and letting the provider reject it is
**not** fail-closed: it sends the client's credential to the outside
world and reports a provider error instead of the truth.

## What this does not weaken

`WrongSession` is untouched. It is still the equality at
`surrogate.rs:182`. What changes is where the `AgentSessionId` handed to
`redeem_for` comes from: a verified signature instead of an assertion.

A surrogate minted in session B, presented in a tunnel proven to be
session A, still gets `WrongSession` — because the tunnel's session is A.
Same code, same comparison, same refusal. A client cannot present
another session's proof because it does not hold that session's key.

## Consequences

- **`ASV_SESSION_ID` stops being a fiction.** `crates/cli/src/main.rs:607`
  writes it with the CLI's pid and **nothing in the repository reads it** —
  verified by grep across every source extension. The child of every
  session is told which session it is, and no party ever checks. This is
  the same class of defect as the H2 and H3 findings. `asv run` opens a
  real broker session and hands out its real id.
- **The protocol bumps v3 → v4.** Registering a key needs a new variant,
  and `crates/ipc-protocol/src/lib.rs:135` requires a new variant to
  reference an ADR and to make old clients fail at the version gate
  rather than on an unknown method. A v3 CLI against a v4 broker is
  refused. That is the protocol working, not a regression.
- **The bridge must understand the inner request.** It terminates TLS, so
  the request is already in clear; substituting the `Authorization` header
  means rewriting it. "Not a parser away" in the roadmap described the
  identity as the blocker, and it was.
- **No production listener.** This decision covers the capability of the
  CONNECT path, verified end to end. It does not add a network surface.

## Rejected, with the reason

- A proof with no signature, or a signature against a key not registered
  to a live session: accepted by no code path.
- A nonce replayed into a second tunnel: rejected; the nonce is per
  tunnel.
- Ordering that redeems before authorising the destination: a target
  outside the allow-list must not be able to induce a signature
  verification, let alone a credential loan.
