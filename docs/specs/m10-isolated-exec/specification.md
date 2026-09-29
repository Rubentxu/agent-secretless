# M10 — Isolated exec compatibility — Specification

## Goal

M10 ships in two passes:

1. **M10-prototype** (this cycle) — data types + dispatcher +
   posture label + redactor. Includes the worker template registry,
   egress policy enum, secret injection plan, landlock/seccomp
   profile types, and the stdout redactor.
2. **M10-runtime follow-up** (next cycle) — the actual `Command` +
   `fork` + namespace flow, the Landlock/Seccomp per-template
   installation, the cgroup slice creation, and the UI surface.

This spec covers only the prototype pass.

## ADDED requirements

### M10-R1 — WorkerTemplate + WorkerRegistry

The broker MUST provide `WorkerTemplate` and `WorkerRegistry` types
that model the static declarations and the lookup mechanism.

| Type | Field | Description |
|---|---|---|
| `WorkerTemplate` | `name: String` | unique id |
|  | `binary: PathBuf` | absolute path of the binary |
|  | `arguments: Vec<String>` | argv (excluding argv[0]) |
|  | `secret_injection: SecretInjectionPlan` | M10-R3 |
|  | `egress_policy: EgressPolicy` | M10-R2 |
|  | `landlock_profile: LandlockProfile` | M10-R4 |
|  | `seccomp_profile: SeccompProfile` | M10-R4 |
| `WorkerRegistry` | `templates: Vec<WorkerTemplate>` | immutable |

`WorkerRegistry::get(name)` returns `Some(&WorkerTemplate)` for
registered names and `None` for arbitrary / unregistered names. The
registry is built at install time and is immutable at runtime.

#### Scenario: registered worker resolves, arbitrary binary does not

> Given `WorkerRegistry::new(vec![worker("kubectl-worker")])`,
> `registry.get("kubectl-worker")` returns `Some`. `registry.get("bash")`
> returns `None`. The broker refuses to spawn any name that returns
> `None`.

### M10-R2 — EgressPolicy

The broker MUST model the worker's egress with `EgressPolicy`:

```rust
pub enum EgressPolicy {
    Allow(Vec<AuthorityEndpoint>),
    Deny,
}
```

`Deny` means the worker has no network egress at all. `Allow(list)`
restricts egress to the listed endpoints (the runtime follow-up uses
the M8 verbs to attach the BPF redirect).

#### Scenario: Allow list does not include the sink

> Given `EgressPolicy::Allow([api.example.com:443])` and a sink
> `attacker.example.net:443`, the egress authorisation fails. The
> worker process cannot open the sink socket.

### M10-R3 — SecretInjectionPlan

The broker MUST model the per-worker secret injection:

```rust
pub enum SecretInjectionPlan {
    EnvVar { name: String },
    File { path: PathBuf, mode: u32 },
    None,
}
```

The broker MUST materialise the secret bytes ONLY inside the worker's
mount namespace; the parent process tree MUST NEVER observe the bytes.

#### Scenario: EnvVar plan is honoured

> A worker template with `SecretInjectionPlan::EnvVar { name: "KUBE_TOKEN" }`
> causes the broker to inject `KUBE_TOKEN=<value>` into the worker's
> environment. The parent process tree observes nothing.

### M10-R4 — LandlockProfile + SeccompProfile

The broker MUST model per-worker landlock + seccomp profiles:

```rust
pub struct LandlockProfile { pub allowed_read: Vec<PathBuf>, pub allowed_write: Vec<PathBuf> }
pub enum SeccompProfile { ClosedAllowList, PassThrough }
```

`PassThrough` is for debug only; production workers MUST use
`ClosedAllowList`.

### M10-R5 — Redactor (defense-in-depth)

The broker MUST provide a `Redactor` that replaces every byte sequence
matching any registered secret with `[REDACTED]`. The redactor is
**best-effort**: an adversary can encode / transform the secret. The
M10 spec labels this posture `ISOLATED_PROCESS_EXPOSURE` honestly.

```rust
pub struct Redactor { secrets: Vec<Vec<u8>> }
impl Redactor {
    pub fn redact(&self, input: &[u8]) -> Vec<u8>;
}
```

#### Scenario: exact secret is redacted

> Given a redactor with `secrets = [b"AKIA..."]`, `redact(b"prefix AKIA... suffix")`
> returns `b"prefix [REDACTED] suffix"`.

#### Scenario: encoded secret is NOT redacted

> Given the same redactor, `redact(b"AKlBQQ==")` returns the input
> unchanged. The redactor is exact-byte only; the spec is honest about
> this limitation.

### M10-R6 — Posture label

The broker MUST attach the posture label `ISOLATED_PROCESS_EXPOSURE`
to every worker session. The label is a stable string in
`asv_broker::isolated_exec::POSTURE_LABEL`.

## MODIFIED requirements

None. M10 is additive on top of M7+M8+M9.

## REMOVED requirements

None.

## Out of scope (deferred to M10-runtime follow-up)

- The actual `std::process::Command` + namespace setup.
- The Landlock + Seccomp per-template installation (uses M8 verbs).
- The cgroup slice creation per worker.
- The audit log emission for each secret injection.
- The UI surface (M5 dashboard indicator for the posture label).

## Verification

1. `cargo test -p asv-broker --lib isolated_exec` covers all six items.
2. `uat_021_isolated_worker_egress` (egress policy denial) and
   `uat_022_transformed_stdout_leak` (redactor limitation documented)
   pass.
3. The exploration doc and the design doc are present.

## Verdict

The M10-prototype cycle **passes** if all six items above are present
and tested. M10-runtime follow-up is scheduled as the next cycle.