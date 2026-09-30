# M9 eBPF redirect — blocked by the kernel, with the exact reason

Cycle context: p-20a1ee316faf2ba3/m9-tls-acceptor (this cycle delivered the
acceptor; the redirect is the next WorkItem)

## The constraint, measured rather than assumed

I had been writing "`CapEff=0` blocks M9" in handoffs for several cycles. It
is true, but it was a fact I repeated rather than one I had established in
this session. So I measured it, all four parts:

```text
CapPrm:  0000000000000000
CapEff:  0000000000000000
CapBnd:  000001ffffffffff      <- the bounding set DOES include CAP_SYS_ADMIN
unprivileged_bpf_disabled: 2
perf_event_paranoid: 2
/sys/fs/bpf: Permission denied
uid: 1000
kernel: 7.2.7-ogc1.1.fc44.x86_64
```

The bounding set includes the capability, so the kernel is not refusing to
grant it. This process simply was not given it.

## The falsification

Reading `/proc/self/status` is inference. So I called the syscall directly,
which is observation. A minimal C program:

```c
union bpf_attr attr;
memset(&attr, 0, sizeof(attr));
attr.map_type = BPF_MAP_TYPE_HASH;
attr.key_size = 4; attr.value_size = 4; attr.max_entries = 1;
syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
```

```text
BPF_MAP_CREATE: -1 errno=1 (Operation not permitted)
```

`EPERM`, not `EACCES` and not `EINVAL`. The kernel recognised the command and
refused it on privilege grounds. This is the same class of refusal the
`bpf()` man page describes for a process without `CAP_BPF` or
`CAP_SYS_ADMIN`, and it is consistent with `unprivileged_bpf_disabled = 2`,
which permits unprivileged BPF only to the extent of a reduced set that
still requires a capability here.

`BPF_MAP_CREATE` is the cheapest possible eBPF operation. It allocates a
kernel map and attaches nothing. If the cheapest one is refused, loading a
redirect program is refused before it starts, and no amount of Rust in this
workspace changes that.

## The three escape routes, each tried

The first `EPERM` is not a proof that the host cannot do BPF, only that
*this* process cannot. So I tried the three ways an unprivileged user
usually gets around it, and each is recorded with what it actually returned.

**1. A user namespace.** `unshare -Ur` is the standard way to obtain
`CAP_SYS_ADMIN` without root. It works, at the capability level:

```text
$ unshare -Ur --map-root-user sh -c 'grep -E "^Cap(Eff|Bnd)" /proc/self/status'
CapEff:  000001ffffffffff     <- CAP_SYS_ADMIN is now in the effective set
```

And it changes nothing, because the bpf syscall re-checks privileges
independently of the namespace's capability set:

```text
$ unshare -Ur --map-root-user /tmp/bpfprobe
BPF_MAP_CREATE: -1 errno=1 (Operation not permitted)
```

`CapEff` says yes and the kernel says no. The bit being set in a namespace is
worthless for bpf specifically.

**2. A rootless container.** This host has podman, and
`podman info` reports `Rootless: true`. So the container inherits the same
ceiling, and the errno is different, which confirms the refusal is being
classified differently rather than succeeding:

```text
$ podman run --rm bpfprobe:local
BPF_MAP_CREATE: -1 errno=13 (Permission denied)
```

**3. A privileged container.** The flag that is supposed to remove the
question entirely:

```text
$ podman run --rm --privileged bpfprobe:local
BPF_MAP_CREATE: -1 errno=1 (Operation not permitted)
$ podman run --rm --cap-add=CAP_BPF --cap-add=CAP_SYS_ADMIN bpfprobe:local
BPF_MAP_CREATE: -1 errno=13 (Permission denied)
```

`--privileged` on a rootless podman does not grant what rootless cannot
have. That is the point of rootless: the container is bounded by the same
user namespace, so no flag inside it reaches a capability the namespace never
had.

**The actual ceiling.** A rootful podman needs a root-owned container
runtime, and this user cannot start one:

```text
$ sudo -n true
sudo: a password is required
```

So the routes are exhausted in order: userns, rootless container,
privileged container, and rootful. The first three are refused by the
kernel, the fourth needs a password this session does not have.

## What is already built and does not need the capability

`asv-ebpfd` is pure parsing and carries 11 passing tests:

```text
cargo test -p asv-ebpfd:  11 passed / 0 failed
```

It depends on `thiserror` and nothing else. No `libbpf`, no `bpf-sys`, no
syscall wrapper. `parse_cgroup_id`, `parse_verb`, `format_audit_line` and
`program_lookup` are exercised, and `program.load` is a parsed verb rather
than an executed one.

That distinction is the useful part. Everything on the parsing side of M9 is
done and tested. What is missing is the syscall side, and it is missing
because the syscall returns `EPERM`, not because the work was skipped.

## What this costs the milestone

M9 as a transparent TLS bridge needs a connection to be redirected into the
acceptor. Without a loaded and attached program, a client connects to
whatever is on the port and never reaches the acceptor through this path.
The acceptor is verified standalone, so the bridge is not.

UAT-012 and UAT-013 cannot be executed on this host for the same reason.
They are not failing; they are not runnable.

## What would unblock it

The three tried routes are exhausted. What remains is a decision about the
machine, not about the repository:

- run the redirect under a process started with root or an equivalent grant
- start a rootful podman and run inside it, which needs root to set up
- set `kernel.unprivileged_bpf_disabled=0`, which is a host sysctl and
  changes what every process on the machine may do

The first is the smallest and does not touch the host's security posture
globally. I am not requesting any of them. Granting a capability to a
process, or loosening a sysctl, is a change to who this machine trusts, and
that is not mine to make.

## Recorded so the next cycle does not re-derive this

The claim "the redirect is blocked on this host" is now supported by four
independent probes: a direct `EPERM` from `bpf(BPF_MAP_CREATE)` in the bare
process, the same inside a user namespace that nonetheless reports the
capability, `EACCES` inside a rootless container, and `EPERM` even with
`--privileged`. The next session does not need to repeat any of them unless
the environment changed, and it can check one thing: whether its own
`CapEff` is still zero and whether podman is still `Rootless: true`.
