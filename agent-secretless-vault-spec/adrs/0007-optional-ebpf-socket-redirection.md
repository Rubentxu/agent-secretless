# ADR-0007 — Use eBPF for optional session-aware socket redirection and egress control

- Status: Accepted with research gate — **gate decided NO-GO on 2026-10-01**; the
  socket-redirection feature does not ship, the egress/telemetry half stands
- Date: 2026-09-28

## Decision

Investigate `cgroup/connect4`, `connect6` and peer-address hooks to transparently route selected connections from an ASV session to a local proxy while retaining original-destination metadata.

Also use cgroup eBPF for egress allow/deny and session attribution.

## Conditions

Production feature ships only after roadmap M8 GO criteria pass.

## Consequences

Agent commands may remain unchanged even for tools ignoring `HTTPS_PROXY`, while secrets stay in userspace broker/proxy. Linux-specific complexity is isolated behind platform ports.

## Amendment — 2026-10-01: the research gate returned NO-GO

The decision above is not withdrawn. Its condition is what resolved, and it
resolved negatively, so the *consequences* paragraph is partly void and partly
still binding. The split matters, because collapsing it would either discard a
design that is in force or keep a promise that cannot be kept.

**Not shipping — the transparent redirect.** M8's own go criteria are in
`15-ROADMAP.md` and the evidence in `16-SECURITY-RELEASE-GATES.md`; two legs,
either sufficient: the research produced no program (`cgroup_attach_skeleton`
performs no syscall, no ELF object exists, and `ProgramId::Connect4RedirectV1`
names a shipped object that was never written), and the build host cannot load
a BPF object anyway (`BPF_MAP_CREATE` → `EPERM`, measured; see
`docs/receipts/m9-ebpf-capability-block.md`).

The consequence "agent commands may remain unchanged even for tools ignoring
`HTTPS_PROXY`" therefore does not hold. It is delivered for tools that *honour*
proxy settings, through the explicit CONNECT bridge, and for no others. A CLI
that ignores `HTTPS_PROXY` is not covered by anything in this repository.

**Still binding — egress and attribution.** The second decision paragraph
stands unchanged: cgroup eBPF for egress allow/deny and session attribution is
the `asv-ebpfd` helper's role, its module doc already describes it that way, and
nothing in the NO-GO touches it. The privileged-helper separation in
`06-TRANSPARENT-BRIDGE-EBPF.md` §9 is likewise unaffected.

**Unchanged — where substitution happens.** The negative results of this ADR's
sibling, ADR-0006, are untouched: no BPF writes real credential bytes into
agent memory, and substitution stays in broker/proxy memory. The M8 NO-GO does
not relax anything ADR-0006 established; it only removes the one mechanism that
might have made the transparent path feasible.
