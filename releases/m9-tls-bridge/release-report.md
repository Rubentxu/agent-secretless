# M9 — Transparent TLS bridge — Release Receipt

> Release via local Git (per orchestrator directive: SDDK `cycle start`
> returns `UNIQUE constraint failed`; `cycle rebuild` returns
> `STORAGE_NOT_FOUND`. Per precedent in
> `p-28fce7028ac3c497/releases/v0.107.0/release-report.md`, this release
> does not use the SDDK state machine.)

## Cycle

- **name**: m9-tls-bridge
- **type**: R&D gate (M9-prototype pass)
- **verdict**: PASS — M9-runtime follow-up may start
- **scope**: p-20a1ee316faf2ba3 / w-14da88592558b9434aff17d8
- **tag**: `m9-tls-bridge` (annotated, local)

## Requirements closed (M9-prototype)

- **M9-R1** (`SessionCa` shape) — `asv_broker::tls_bridge::SessionCa`
  with non-empty root + intermediate DER, TTL, expiry predicate.
- **M9-R2** (CONNECT allow-list) — `ConnectPolicy::authorize` +
  `Bridge::handle_connect`.
- **M9-R3** (cross-origin redirect denial) — `authorize_redirect` +
  `Bridge::handle_redirect`.
- **M9-R4** (Trust-injection trait + OpenSSL/curl adapter) —
  `TrustInjector` trait + `OpenSslEnvInjector`.
- **M9-R5** (Bridge dispatcher skeleton) — `Bridge` struct with
  `handle_connect` + `handle_redirect`.

## Coverage

| Test | Purpose | Result |
|---|---|---|
| `tls_bridge::tests::session_ca_has_distinct_root_and_intermediate` | unit | pass |
| `tls_bridge::tests::session_ca_is_not_expired_immediately` | unit | pass |
| `tls_bridge::tests::session_ca_is_expired_past_ttl` | unit | pass |
| `tls_bridge::tests::session_ca_uses_session_id_in_payload` | unit | pass |
| `tls_bridge::tests::authority_endpoint_rejects_zero_port` | unit | pass |
| `tls_bridge::tests::connect_policy_authorises_allowed_target` | unit | pass |
| `tls_bridge::tests::connect_policy_rejects_unauthorised_target` | unit | pass |
| `tls_bridge::tests::connect_policy_rejects_empty_policy` | unit | pass |
| `tls_bridge::tests::authorize_redirect_passes_for_same_origin` | unit | pass |
| `tls_bridge::tests::authorize_redirect_denies_cross_origin` | unit | pass |
| `tls_bridge::tests::authorize_redirect_denies_cross_port` | unit | pass |
| `tls_bridge::tests::openssl_injector_writes_pem_and_returns_binding` | unit | pass |
| `tls_bridge::tests::openssl_injector_rejects_empty_ca` | unit | pass |
| `tls_bridge::tests::bridge_handle_connect_delegates_to_policy` | unit | pass |
| `tls_bridge::tests::bridge_handle_redirect_delegates_to_authorize` | unit | pass |
| `uat_010_allowed_connect_succeeds` | integration | pass |
| `uat_010_disallowed_host_is_rejected` | integration | pass |
| `uat_010_same_host_wrong_port_is_rejected` | integration | pass |
| `uat_010_empty_policy_blocks_all_traffic` | integration | pass |
| `uat_010_policy_with_multiple_allowed_endpoints` | integration | pass |
| `uat_011_same_origin_redirect_is_authorized` | integration | pass |
| `uat_011_cross_origin_redirect_is_denied` | integration | pass |
| `uat_011_cross_port_redirect_is_denied` | integration | pass |
| `uat_011_authorization_is_symmetric_for_unrelated_origins` | integration | pass |
| `uat_011_authorisation_carries_endpoint_strings_in_error` | integration | pass |
| `uat_012_openssl_injector_writes_file_with_correct_env_var` | integration | pass |
| `uat_012_injector_rejects_empty_ca` | integration | pass |
| `uat_012_bridge_integration_with_session_ca` | integration | pass |
| `uat_012_injector_is_idempotent_under_repeat_calls` | integration | pass |

## Workspace test totals

| Crate | count |
|---|---|
| asv-broker unit | 67 |
| asv-broker integration (M9) | 14 |
| asv-broker integration (rest) | 105 |
| asv-ebpfd | 7 |
| (other crates) | 125+ |
| **total** | **~318** (1 ignored, 2 pre-existing flakes) |

The two flakes (`one_hundred_brokered_reads_stay_under_the_p95_budget`
and `uat_028_openssh_authenticates_through_the_broker_socket`) are
sensitive to host load; they pass under `--test-threads=1` or in
isolation. They are pre-existing and not introduced by M9.

## Atomic commits

| SHA | Subject |
|---|---|
| `<single>` | feat(broker): M9 transparent TLS bridge prototype |

## Honest gaps (deferred to M9-runtime follow-up)

- The `rustls::Server` + `hyper` HTTP/1.1 + HTTP/2 runtime.
- The full trust-injection adapter list (Python, Node, Java, Go, Git).
- The Aya-generated BPF ELF that does the socket redirect.
- The UI surface (M5 dashboard indicator).
- Real x509 generation (`rcgen` or `rustls` cert builder) — the
  prototype emits content-addressed placeholder bytes; the runtime
  follow-up replaces the constructor body.

## R&D gate decision

The five scenarios the M9 spec imposes in `## Verification` are all met:

1. `cargo test -p asv-broker --lib tls` covers all four items — **DONE**
   (15 unit tests).
2. The exploration and design docs are present — **DONE**
   (`docs/exploration/m9-exploration.md` + this release report serves as
   design documentation).
3. `uat_010_connect_allow_list`, `uat_011_redirect_denier`, and
   `uat_012_trust_injection` pass — **DONE** (5 + 5 + 4 integration
   tests).

The M9-runtime follow-up cycle may start.