# ADR-0020 — Adoption before hardware: TPM2 leaves the v1.0 critical path

- **Status**: Accepted
- **Date**: 2026-10-04
- **Supersedes**: nothing. **Extends**: ADR-0005 (credential access security
  hierarchy), ADR-0008 (isolated exec is compatibility, not secretless),
  ADR-0014 (explicit integration security posture).
- **Amends**: the *sequencing* in `15-ROADMAP.md`. It changes no spec, no
  interface and no guarantee. `TpmDevice`, `SoftwareTpm`, the M12 scope and the
  M12 exit UAT are untouched and stay exactly as they are.
- **Resolves**: the ordering conflict in which a host-dependent milestone sat
  on the v1.0 critical path and the milestones that make the product adoptable
  sat behind the tag.

## Context

The roadmap has always been numbered by milestone, and the numbering was read
as the critical path:

```text
M10 → M11 → M12 (TPM) → M13 (certification) → v1.0
                                                       ↓
                              M14 adapters → M15 planning → M16/M17 → M18
```

Two facts about that path have become expensive.

**M12 cannot close on any host this project builds on.** Its guarantee is
hardware-backed sealing, and it needs a `/dev/tpmrm0`. The M12 row has said so
since it was written: no device, `/sys/class/tpm` empty, no TPM CPU flag. A
milestone that can only close on a different machine cannot be a gate for a
release, and it cannot be honestly simulated either — `swtpm` is a TPM 2.0
*implementation*, it is not silicon, and `is_hardware` is false for it by
construction.

**Meanwhile the blocks that decide whether anybody adopts the product sit after
the tag.** M14 — the credential workflow adapters — is what turns a security
runtime into something a person or an agent can use in a real project. M15 is
what makes authority specific to an operation rather than to a session. Both
are the difference between "correct" and "used".

So the path to v1.0 was gated on the one milestone that cannot close, and was
not gated on the two that would have made v1.0 worth shipping. Every cycle spent
on M12 was a cycle not spent on adoption, and M12 still did not move, because
it was never going to move without different hardware.

## Decision

**The v1.0 critical path is rebaselined to optimize daily secretless work and
ease of adoption, not the completion percentage of historical milestones.**

```text
R0  Truthfulness + distribution + skill
R1  M10 production reachability
R2  M11 providers worth having (Git/GitHub, OAuth2, STS, Kubernetes)
R3  M14 credential workflow adapters
R4  M15 plan-bound authority
R5  M13 certification of the useful product  ──► v1.0
R6  M16 durable automation + PipelineK
R7  ecosystem expansion
R8  M12 TPM2 hardware, for real
R9  M17 attestation / trusted execution
R10 M18 stabilization of the next line
```

Six consequences, each of which is a decision and not a consequence of one:

1. **TPM2 leaves the v1.0 gate.** M12 becomes `prototype` with hardware
   validation *deferred to R8*. `TpmDevice`, `SoftwareTpm`, their contracts,
   their fast tests and their documentation are kept, so the capability is still
   here and still costs nothing to carry.
2. **M14 and M15 are advanced**, because they are what a user adopts. M14 does
   not get its own vault, OAuth, executor or signer; it reuses M4, M10 and M11.
3. **M16 is post-v1.0.** PipelineK is durable orchestration authority; ASV is
   identity, credential and policy authority. Building a durable workflow engine
   inside ASV before ASV is adoptable would be building the second half of a
   product nobody has installed.
4. **M17 depends on real M12.** Attestation is a claim about what executed, and
   the first honest source of that claim is the TPM evidence R8 produces. A
   verdict built on `swtpm` would be a verdict about a simulator.
5. **M18 stabilizes the next line** — adapters plus plan-bound authority plus
   durable automation plus optional hardware trust — not the first.
6. **v1.0's security baseline rests on what already exists**: encrypted vault,
   no-exportability, the broker boundary, policy, dedicated identity, seccomp,
   Landlock, cgroups and session isolation. Every one of those is implemented
   and testable on any host. Hardware trust is an addition to that baseline,
   never a substitute for it.

### The condition under which M12 returns to the critical path

A deferred block with no return condition is a deprioritization nobody ever
revisits. M12 comes back the moment one of these is real, not on a schedule:

- a customer requirement that names hardware binding;
- an enterprise compliance obligation;
- a vault that must be physically bound to a device;
- attested secret release;
- a remote broker whose host is not trusted;
- Keylime or Trustee integration;
- confidential computing.

Each of those is a *requirement*, and a requirement arrives as one. "It would
be nice" is not on that list, and neither is the fact that the work is already
half done.

## What this decision does not say

**It does not downgrade what was measured.** The TPM 2.0 client is real, the
command encodings are pinned against the reference client reading the same
device, and the seal path has been measured end to end and is durable: a
primary parent created from a fixed template, a child created with an
`authPolicy` this client computes, and an `Unseal` under a policy session that
returns the sealed bytes in the clear. That is the R8 starting point, and it is
recorded in `16-SECURITY-RELEASE-GATES.md` as measurement.

**`swtpm` and `SoftwareTpm` are not hardware evidence and never will be.** The
rule is unchanged: only a host that answers on `/dev/tpmrm0` closes M12, and the
exit is `enroll → seal → reboot → unlock` plus `change measured state → unlock
→ DENIED`.

**It does not claim v1.0 is more secure without TPM2.** It claims v1.0 is
shippable, adoptable and honest about what it does not have. A v1.0 that says
so is worth more than a v1.0 that is still waiting.

## Consequences

- The roadmap gains a named order that answers "what next" without re-deriving
  it from milestone numbers.
- M12's software work stops consuming cycles while its measurement is kept, and
  R8 becomes a bounded block rather than an open-ended one.
- The risk this accepts is real and stated: a v1.0 ships without hardware trust.
  The mitigation is not a claim but a property — everything v1.0 does assert
  about itself is machine-checked, and the gate that is not satisfied stays
  visibly unsatisfied instead of being marked green.
- A requirement arriving later does not need a new debate about the roadmap. It
  names itself against the list above, and the order changes for a reason that
  is written down.
