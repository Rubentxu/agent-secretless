# ADR-0002 — Separate broker, Tauri UI and privileged eBPF helper

- Status: Accepted
- Date: 2026-09-28

## Decision

Use distinct processes/trust domains:

- `asv-brokerd`: secret-bearing broker under dedicated service identity.
- `asv-desktop`: unprivileged Tauri human UI.
- `asv-ebpfd`: optional privileged but secret-free cgroup/eBPF helper.

## Rationale

Putting vault, WebView and BPF privileges in one desktop process creates an unnecessarily catastrophic compromise boundary.

## Consequences

IPC/versioning complexity increases, but privilege and secret exposure are sharply reduced.
