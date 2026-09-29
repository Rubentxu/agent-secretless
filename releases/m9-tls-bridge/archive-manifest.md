# M9 — Transparent TLS bridge — Archive Receipt

## Gate closed

- **name**: m9-tls-bridge
- **type**: R&D gate (M9-prototype pass)
- **verdict**: PASS — M9-runtime follow-up may start
- **closed_at**: 2026-09-29T09:49:00Z (estimated; CI clock)
- **release_sha**: see commit log
- **tag**: `m9-tls-bridge` (annotated)

## Archived artifacts

| Artifact | Purpose |
| --- | --- |
| `docs/specs/m9-tls-bridge/specification.md` | M9-R1..M9-R5 requirements + scenarios |
| `docs/exploration/m9-exploration.md` | Spike T1..T8 + decision matrix |
| `releases/m9-tls-bridge/release-report.md` | Requirement coverage + gaps |
| `releases/m9-tls-bridge/merge-receipt.md` | Git history summary |

## Knowledge synced

- The `tls_bridge::Bridge` dispatcher is the M9-runtime follow-up's
  primary extension point. The runtime replaces
  `Bridge::handle_connect` with the rustls server handshake and adds
  `Bridge::handle_http` for surrogate substitution.
- `ConnectPolicy::allowed` MUST be built from the connector audience
  set at session start. The runtime follow-up replaces the linear
  scan with a `HashSet` when the audience grows past ~100 entries.
- `TrustInjector` is the trait; new adapters (Python, Node, Java,
  Go, Git) MUST be added as new types implementing the trait.
- `authorize_redirect` is symmetric in the sense that it does not
  preserve direction; this is the correct invariant for cross-origin
  denial.

## Follow-ups (deferred to M9-runtime follow-up)

- `rustls::Server` + `hyper` HTTP/1.1 + HTTP/2 runtime.
- The full trust-injection adapter list (Python, Node, Java, Go, Git).
- The Aya-generated BPF ELF (uses `M8` verbs `CgroupAttach`,
  `ProgramLoad`, `cgroup_attach_skeleton`).
- The UI surface (M5 dashboard indicator).
- Real x509 generation (`rcgen` or `rustls` cert builder).

## M9 prototype verdict

The M9-prototype cycle **passes**. The five M9-R1..M9-R5 scenarios
have unit + integration coverage; the runtime follow-up may start.