# M10 — Isolated exec compatibility — Prototype pass

## 1. Goal

Per `agent-secretless-vault-spec/docs/15-ROADMAP.md`:

> ## M10 — Isolated exec compatibility
>
> **Goal:** support unavoidable legacy tools without lying about guarantees.
>
> ### Scope
>
> - registered worker templates only,
> - separate identity/namespaces,
> - Landlock/seccomp,
> - egress enforcement,
> - secret env/file injection inside worker only,
> - exact-secret stdout redaction as defense-in-depth,
> - posture label `ISOLATED_PROCESS_EXPOSURE`.

## 2. Codebase inventory

### 2.1 Already shipped (M7, M8)

- `asv_broker::harden::install()` — prctl(PR_SET_DUMPABLE),
  cgroup v2 detection, Landlock probe, Seccomp probe.
- `asv_broker::tls_bridge::Bridge` — CONNECT allow-list + redirect
  denial.
- `asv_ebpfd` — closed-verb helper for cgroup/program operations.

### 2.2 Missing for M10

- A `WorkerTemplate` registry: the only workers allowed are those
  declared at install time.
- An `IsolatedWorker` struct: the runtime payload of a spawned worker,
  including cgroup slice, landlock ruleset, and egress policy.
- A `SecretInjectionPlan` class: the list of env vars / files that the
  broker writes inside the worker's mount namespace and which the
  worker reads directly.
- A `Redactor` struct: the stdout/stderr filter that replaces exact
  secret bytes with `[REDACTED]`. It is the defense-in-depth backstop
  that the M10 spec demands; it MUST NOT be the only defence.

## 3. Spike W1 — WorkerTemplate

The template is a static declaration:

```rust
pub struct WorkerTemplate {
    pub name: String,                       // "kubectl-worker"
    pub binary: PathBuf,                    // /usr/bin/kubectl
    pub arguments: Vec<String>,             // ["get", "pods"]
    pub secret_injection: SecretInjectionPlan,
    pub egress_policy: EgressPolicy,
    pub landlock_profile: LandlockProfile,
    pub seccomp_profile: SeccompProfile,
}
```

The registry is built at install time; runtime cannot add templates.

```rust
pub struct WorkerRegistry { templates: Vec<WorkerTemplate> }
impl WorkerRegistry {
    pub fn get(&self, name: &str) -> Option<&WorkerTemplate>;
}
```

A worker MUST resolve through the registry; arbitrary binaries are
rejected.

## 4. Spike W2 — EgressPolicy

```rust
pub enum EgressPolicy {
    /// Worker may reach the explicit allow-list only.
    Allow(Vec<AuthorityEndpoint>),
    /// Worker may not reach any network.
    Deny,
}
```

In M10-prototype, `EgressPolicy` is a data type; the runtime follow-up
wires the Landlock + cgroup socket hook that enforces it (combining M8
verbs).

## 5. Spike W3 — SecretInjectionPlan

```rust
pub enum SecretInjectionPlan {
    /// Inject a single env var (e.g. AWS_ACCESS_KEY_ID).
    EnvVar { name: String },
    /// Write a file at `path` inside the worker's mount namespace.
    File { path: PathBuf, mode: u32 },
    /// No injection (worker runs without secrets).
    None,
}
```

The plan is per-template. The broker materialises the secret only inside
the worker's mount namespace; the parent process tree NEVER observes the
secret bytes.

## 6. Spike W4 — Landlock / Seccomp profile

```rust
pub struct LandlockProfile {
    pub allowed_read: Vec<PathBuf>,
    pub allowed_write: Vec<PathBuf>,
}

pub enum SeccompProfile {
    /// Allow-list from M7 spec (default).
    ClosedAllowList,
    /// Pass-through (debug only).
    PassThrough,
}
```

The runtime follow-up wires these into `harden::install` per-template.

## 7. Spike W5 — Redactor

The redactor is the structural defense-in-depth: every byte the
worker's stdout/stderr contains that matches a known secret is replaced
with `[REDACTED]` before the broker forwards it to the agent's
controlling process.

```rust
pub struct Redactor { secrets: Vec<Vec<u8>> }
impl Redactor {
    pub fn redact(&self, input: &[u8]) -> Vec<u8>;
}
```

The redactor is **best-effort** by definition: an adversary can
encode/transform the secret (base64, hex, split across lines). The M10
spec labels this honestly: the posture is `ISOLATED_PROCESS_EXPOSURE`.
The redactor is a backstop, not a guarantee.

## 8. Posture label

Every worker spawned by the broker has the posture label
`ISOLATED_PROCESS_EXPOSURE` attached to its session. The UI (M5
dashboard) reads this label and shows the user that an unavoidable
legacy tool is running with raw secrets.

## 9. Spike W6 — End-to-end composition

The M10-prototype composes:

```
WorkerRegistry::get("kubectl-worker")
  -> SecretInjectionPlan::EnvVar { name: "KUBE_TOKEN" }
  -> EgressPolicy::Allow([api.example.com:443])
  -> LandlockProfile { read: [/usr/bin/kubectl], write: [] }
  -> SeccompProfile::ClosedAllowList
  -> Redactor { secrets: [<kube-token-bytes>] }
```

The runtime follow-up replaces the dispatcher's body with the
`std::process::Command` + `nix::unistd::fork` flow that establishes the
mount namespace.

## 10. Verdict

M10-prototype **passes** if:

- `WorkerTemplate`, `WorkerRegistry`, `EgressPolicy`,
  `SecretInjectionPlan`, `LandlockProfile`, `SeccompProfile`,
  `Redactor` are real types with real constructors.
- `WorkerRegistry::get` returns `Some` for registered names and `None`
  for arbitrary binaries.
- `Redactor::redact` replaces every occurrence of every registered
  secret.
- `uat_021_isolated_worker_egress` (egress confinement via policy)
  and `uat_022_transformed_stdout_leak` (redactor as defense-in-depth)
  pass.
- The runtime follow-up cycle is documented in the archive manifest.

## 11. Honest gaps (deferred to M10-runtime follow-up)

- The actual `std::process::Command` + namespace setup.
- The Landlock + Seccomp per-template installation (uses M8 verbs).
- The cgroup slice creation per worker.
- The audit log emission for each secret injection.
- The UI surface (M5 dashboard indicator for `ISOLATED_PROCESS_EXPOSURE`).