# ADR-0009 — Tauri is a human control plane, not the broker

- Status: Accepted
- Date: 2026-09-28

## Decision

Tauri 2 provides the KeePass-like UX but does not own the long-lived vault runtime or agent data plane.

WebView capabilities are minimal; frontend has no API to retrieve stored secret values. Assets are local and CSP is restrictive.

Hardened ingestion can use a native helper so secret text never enters WebView JS.
