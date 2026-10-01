# TLS compatibility matrix — the CONNECT path, measured

M9 exit criterion, `agent-secretless-vault-spec/docs/15-ROADMAP.md:331-332`:
*"TLS compatibility matrix published from tests."*

This is that artifact. It is **measured**, not asserted: every row marked
*measured* names the test that produces it, and every row that is not measured
says so in the same table rather than being left out.

Substrate, from `Cargo.lock` at the commit that published this:

| Component | Version |
|---|---|
| `rustls` | 0.23.45 |
| `tokio-rustls` | 0.26.6 |
| `rcgen` | 0.13.2 |

The server configuration is built in one place,
`crates/tls-acceptor/src/config.rs:113`, and both the acceptor and the bridge
consume it — `crates/broker/src/tls_bridge.rs:739-742` calls the same
`server_config()`. So these rows describe **both** TLS surfaces in the
workspace, which is why the acceptor's own tests count as witnesses.

## The matrix

| # | Property | Value | How it is known | Witness |
|---|---|---|---|---|
| 1 | TLS 1.3 | accepted | measured | `connect_serve.rs::a_client_offering_tls13_negotiates_tls13` |
| 2 | TLS 1.2 | accepted (the floor) | measured | `connect_serve.rs::a_client_offering_only_tls12_still_completes` |
| 3 | TLS 1.1 / 1.0 | **cannot be offered** | structural | `rustls::version` exposes only `TLS12` and `TLS13`; no constant exists to configure a lower one, so this is a property of the library, not a test of ours |
| 4 | ALPN | **no protocol selected** | measured + falsified | `connect_serve.rs::a_client_offering_h2_and_http11_gets_no_alpn_selected` |
| 5 | Client authentication | none requested | measured | `connect_serve.rs::session_leaf_handshakes_and_the_tunnel_is_live_in_both_directions` — a client holding no certificate completes the handshake |
| 6 | Chain presented | leaf, then intermediate | measured | `tls-acceptor/tests/handshake.rs::the_chain_presented_is_leaf_then_intermediate` |
| 7 | Host binding | exact host only | measured | `connect_serve.rs::a_leaf_minted_for_another_host_is_refused`, `handshake.rs::a_client_asking_for_another_hostname_is_refused` |
| 8 | Trust anchor | the session root, per session | measured | `handshake.rs::a_client_trusting_an_unrelated_root_is_refused` |
| 9 | Certificate pinning client | refused **at the handshake** | measured | `connect_serve.rs::a_pinning_client_is_refused_and_the_bridge_does_not_patch_it` (UAT-011) |
| 10 | Unauthorised target | no upstream socket opened | measured | `connect_serve.rs::an_unauthorised_target_opens_no_upstream_socket` |
| 11 | Cipher suites | `rustls` default suite list | observed, **not pinned** | `tls-acceptor/tests/openssl_client.rs::openssl_negotiates_a_suite_belonging_to_its_reported_version` |
| 12 | Key-exchange groups | `ring` provider default | **not pinned** | no test names a group |
| 13 | Signature algorithms | client-side accept list | **not pinned** | no test constrains which schemes the broker accepts |
| 14 | Session resumption / tickets | unexamined | **not tested** | no test enables resumption in either direction |
| 15 | Renegotiation | unexamined | **not tested** | rustls rejects renegotiation by default; nothing here pins that |
| 16 | SNI-driven leaf selection | per target, from the CONNECT authority | measured (indirectly) | the leaf is minted for `target.host()`, and row 7 covers the binding |
| 17 | HTTP/2 on this path | **not supported** | derived from row 4 | row 4 plus the "does not own the relay" fact below |
| 18 | Cross-implementation interop | a real OpenSSL client completes | measured | `tls-acceptor/tests/openssl_client.rs`, three tests shelling out to `openssl s_client` |

## What an independent implementation actually negotiated

Rows 11-13 name no default, so the matrix would otherwise be silent about the
most real-world-relevant cells. `openssl_client.rs` answers them with a client
that shares no code with this one, and prints what it got:

```text
client:     OpenSSL 3.6.3 9 Jun 2026
negotiated: TLSv1.3 / TLS_AES_256_GCM_SHA384 (ALPN offered h2,http/1.1)
```

That is the observed pair on this host, on 2026-10-01, and it is reproducible
with one command:

```bash
cargo test -p asv-tls-acceptor --test openssl_client openssl_negotiates -- --nocapture
```

Three things follow from it, and the third is the one that matters:

1. An independent client negotiates **TLS 1.3** with the shared config.
2. It negotiates a **TLS 1.3 suite**, so the reported version and the reported
   cipher belong to each other — the one genuinely falsifiable property of a
   default pair, and what that test asserts.
3. **It completed the handshake while offering `h2` and `http/1.1` through
   ALPN.** That is cross-implementation evidence for row 4: a real
   third-party client that offers `h2` gets a working connection instead of
   an `h2` negotiation it could not speak.

It is deliberately *not* a pin. The test asserts coherence, not a specific
default, so OpenSSL changing its preference would not fail it. The floor and
ceiling are pinned separately, by the rustls clients in `connect_serve.rs`.
A matrix that pretended OpenSSL's current choice was a guarantee would be
wrong the day OpenSSL is upgraded.

## Row 4 is the one that matters, and it was an accident

The server config sets neither `alpn_protocols` nor
`with_protocol_versions`. Every cell above that concerns version or ALPN was
therefore inherited from a library default, and none of it was tested anywhere
in the workspace before this artifact.

That is not a hypothetical risk. `serve_connect` returns `EstablishedTunnel`
and stops — the bridge does not own the relay, does not parse the inner
request, and has no HTTP parser in its dependency set. An `h2` negotiation
would hand the caller a connection carrying HPACK frames it has no way to
read. And `reqwest` with `rustls-tls` offers `h2` and `http/1.1` to nearly any
modern server, so an ordinary CLI reaching this bridge through `HTTPS_PROXY`
is the normal case, not an edge case.

**Falsification M1** added `config.alpn_protocols = vec![b"h2", b"http/1.1"]`
to `tls_bridge.rs:739` — the single line an engineer would add while
"improving" the bridge, and nothing about that line reads as a security
change. The result:

```text
test a_client_offering_h2_and_http11_gets_no_alpn_selected ... FAILED
  left: Some([104, 50])     <- "h2"
 right: None
```

One test red, and it named the protocol the bridge cannot speak. The property
is real, load-bearing, and previously unwatched.

## Falsifications

Each mutation changed production code, was observed, and was reverted. The
tree carries no production diff; these are recorded because a matrix whose
rows were never contradicted is a matrix of hopes.

| ID | Mutation | Expected to break | Observed |
|---|---|---|---|
| M1 | `tls_bridge.rs`: set `alpn_protocols = [h2, http/1.1]` on the server config | row 4 | **1 test red**, `Some("h2")` vs `None` |
| M2 | `config.rs`: `builder_with_protocol_versions(&[&TLS12])` | row 1 | **red**: `a_client_offering_tls13_negotiates_tls13` — `received fatal alert: ProtocolVersion` |
| M3 | `config.rs`: `builder_with_protocol_versions(&[&TLS13])` | row 2 | **red**: `a_client_offering_only_tls12_still_completes` — `received fatal alert: ProtocolVersion` |
| M4 | `openssl_client.rs`: invert the branch that matches the reported version | the coherence assertion | **red**: `reported TLSv1.3 but negotiated TLS_AES_256_GCM_SHA384, which is a TLS 1.3 suite` |

M2 and M3 also reddened
`the_observation_method_detects_a_selection_when_a_server_offers_alpn`, because
that control drives the same shared `server_config()` with a TLS-1.3-only
client. That is the mutation's reach, not a defect in the control.

## Why the negative control exists

`a_client_offering_h2_and_http11_gets_no_alpn_selected` asserts `None`. An
assertion of absence is only as strong as the ability of the same code to
observe presence, so
`the_observation_method_detects_a_selection_when_a_server_offers_alpn` runs
the identical client against the *same* `server_config()` with the single
field the bridge omits, and requires the selection to be visible.

This is the second time in this repository that a positive assertion was
caught being empty — `credential_ingest_boundary.rs` found two — and the cost
of finding them was a false green, not a red. The control is not decoration.

## What this matrix does not claim

- **That the bridge is broadly compatible.** Rows 1-10 describe one narrow
  path: an HTTP/1.1 CONNECT client terminating TLS against a per-session leaf.
  Rows 11-15 are unpinned, and an unpinned row is a row that can change
  without any test noticing.
- **That M9 is closer to done.** It is not. M9's exit requires UAT-010 on the
  CONNECT path, which is `FND-m9-connect-substitution` and needs an ADR, plus
  UAT-012 and UAT-013, which are blocked by a measured `EPERM` on
  `BPF_MAP_CREATE`. This artifact closes one of the two criteria on the
  roadmap's M9 exit list, and only one.
- **That rows 11-15 are safe as they are.** Row 11 is now *observed* with an
  independent client and asserted only for coherence with the version; 12-15
  remain unwatched. Observed is not pinned: a default can change without
  failing a single test, and the OpenSSL pair quoted above is a measurement of
  this host today, not a guarantee about tomorrow.
- **That this is the same document as
  `agent-secretless-vault-spec/docs/12-COMPATIBILITY-MATRIX.md`.** It is not.
  That one is a catalogue of which tools work with which mechanism and is a
  planning artefact. This one is measured protocol behaviour and cites tests.
  Neither substitutes for the other, and this one does not satisfy the
  criterion that `12-` was ever mistaken for.
