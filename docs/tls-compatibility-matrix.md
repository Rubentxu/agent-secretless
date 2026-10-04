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
`server_config()`. So these rows describe **both TLS surfaces in the
workspace**, which is why the acceptor's own tests count as witnesses.

> **That sentence was true when written and C2.8 made it false.** Rows 1-18
> describe the **server** leg — the TLS the bridge presents to the agent. The
> broker-to-destination hop is now TLS too, built from a `rustls::ClientConfig`
> of its own at `crates/broker/src/tls_bridge.rs:883`, and it is a **third**
> surface that rows 1-18 do not describe. Those rows are numbered as the server
> leg below, and the client leg has its own table further down, because merging
> them into one would let a reader take row 4 as a statement about both.

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

## The client leg — the hop C2.8 added

`Bridge::dial_upstream` builds the broker's side of the second hop:

```text
crates/broker/src/tls_bridge.rs:883
    rustls::ClientConfig::builder()
        .with_root_certificates(self.destination_roots.as_ref().clone())
        .with_no_client_auth();
```

Three cells are set. The three that are **not** — the protocol version range,
the ALPN protocols offered, and the crypto provider — are inherited from a
library default, and `connect_upstream_tls.rs` measures what this leg *trusts*
while saying nothing about what it *negotiates*. So the ALPN hazard row 4 pins
for the server side was, on the client side, unwatched, and **the two are mirror
images**:

- server side (row 4): a bridge that *selected* `h2` would hand an `h2`-capable
  agent a connection the bridge cannot parse;
- client side (row 21): a broker that *offered* `h2` would get a destination
  that believes it is speaking HTTP/2, and then relay `curl`'s HTTP/1.1 bytes
  into it — a tunnel whose inner bytes are framed for a protocol the
  destination chose and the agent never agreed to.

`curl` and `reqwest` both offer `h2`, so this is the shape a routine request
takes rather than an edge case.

Every row below is read off the **destination's** `ServerConnection`. A broker
reporting its own `ClientConfig` would be the broker agreeing with itself, and
this repository has already been bitten by two empty positive assertions.

| # | Property | Value | How it is known | Witness |
|---|---|---|---|---|
| 19 | Verified name | the route's host, never the resolved address | measured, and falsified by the sibling campaign | `connect_upstream_tls.rs`, T4 |
| 20 | Trust anchors | the operator's, from `--connect-roots`; an empty store verifies nothing | measured, and falsified by the sibling campaign | `connect_upstream_tls.rs`, T3; the real-binary default in `main.rs` |
| 21 | ALPN offered | **no protocol offered** | measured + falsified | `connect_upstream_negotiation.rs::a_destination_offering_alpn_is_given_no_selection_by_the_broker` |
| 22 | TLS 1.3 | reached against a TLS-1.3-only destination (the ceiling) | measured + falsified | `the_broker_reaches_a_destination_offering_only_tls13` |
| 23 | TLS 1.2 | reached against a TLS-1.2-only destination (the floor) | measured + falsified | `the_broker_reaches_a_destination_offering_only_tls12` |
| 24 | Observed version, ordinary destination | TLS 1.3 on this host | **observed, not pinned** | `the_broker_negotiates_tls13_against_a_destination_taking_the_defaults` — coherence of the default, not a guarantee about tomorrow |
| 25 | Client authentication | the broker presents **none** | measured, **falsified by a control pair rather than a mutation** | `the_broker_presents_no_client_certificate_to_a_destination_that_demands_one`, with `a_client_holding_the_issuers_certificate_completes_against_a_destination_that_demands_one` |
| 26 | Cipher suites, key-exchange groups, signature algorithms, resumption | — | **not pinned, and not testable here** | the workspace enables `rustls` with `ring` and no alternative provider, so there is no second value to move and no test that could notice the first one moving |

### Row 25 is weaker than row 4, and says so

Row 4 is falsified by a mutation that sets `alpn_protocols` on the server.
Row 25 has **no such mutation**: the only change that could redden it is one
that gives the broker a client certificate, and the bridge holds no key
material it could use, so the mutation does not exist as a one-line edit.

What it has instead is a **mutually falsifying pair**, which is a weaker
instrument and is labelled as one. The pin goes red if the destination's demand
were not real, because a destination accepting anything would record
`handshook=true`. The control goes red if the certificate were not verifiable,
because a destination accepting nothing would never handshook. Two tests, each
reddening when the other's premise is removed, with no production change.

That control was wrong twice before it was right, and both failures are worth
recording because both read as *the anchor is wrong*:

1. it presented the leaf without the intermediate, so the verifier could not
   build a path to the root it held and answered `UnknownIssuer`;
2. it presented the destination's own leaf, which `issue_leaf` stamps
   `ExtendedKeyUsage: serverAuth` and nothing else — a verifier is right to
   reject a server certificate presented as a client one.

The control now mints a real `clientAuth` leaf from the same intermediate, so
it differs from the broker in exactly the one respect under test.

### A TLS 1.3 fact this row had to be written around

`the_broker_presents_no_client_certificate_to_a_destination_that_demands_one`
does **not** assert that `establish` returns an error, and cannot. In TLS 1.3
the client sends its `Finished` and considers the handshake over before the
server has processed the empty certificate message, so `dial_upstream` returns
`Ok` and `serve_connect` hands back a tunnel the destination has already
refused. Asserting on the broker's return value would be asserting a property
of the protocol rather than of the broker, and it would break — correctly, but
uninformatively — the day the negotiation falls to TLS 1.2.

The first version of that test did exactly that, and it failed with the
destination's record reading `handshook=false version=None client_certs=0`
while `establish` had returned `Ok`. The witness is the destination's record and
nothing else.

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

### The client leg's own campaign

The rows above all mutate the **server** configuration. The client leg has a
separate campaign, `tests/upstream_negotiation_falsification.py`, because the
two configurations are different code and a campaign that edited one while
citing the other's rows would be measuring nothing. **3 of 3 red on the
assertion each row names, with no mutation residue in the tree:**

| ID | Mutation | Expected to break | Observed |
|---|---|---|---|
| N1 | `tls_bridge.rs:883`: set `config.alpn_protocols = [h2, http/1.1]` on the **client** config | row 21 | **red**: `a_destination_offering_alpn_is_given_no_selection_by_the_broker` — the destination recorded a selection, the exact mirror of M1 |
| N2 | pin the client to `TLS12` only | row 22 | **red**: `the_broker_reaches_a_destination_offering_only_tls13` — `expect` on `establish`, fatal `ProtocolVersion` |
| N3 | pin the client to `TLS13` only | row 23 | **red**: `the_broker_reaches_a_destination_offering_only_tls12` — `expect` on `establish`, fatal `ProtocolVersion` |

Three things about how those ran are worth more than the pass count:

1. **N1's first attempt did not compile**, and the runner reported `SKIP`, not a
   pass. `with_alpn_protocols` is a *server*-side builder method in rustls
   0.23; the client's is a public field. A row that cannot compile has measured
   nothing while looking like it had, which is why a `SKIP` is never counted.
2. **N2 and N3 are caught by the `expect` on `establish`, not by the version
   assertion behind it**, for the same reason T3 and T4 above name theirs: a
   destination that answers with a fatal alert means no tunnel comes back, so
   there is no version left to read off it.
3. **N3 is invisible to the cell this document quotes most.** The
   observed-ceiling test still passes, because it negotiates TLS 1.3, which is
   all it ever claimed. The mutation is visible only to the floor row — a limit
   quoted as a limit.

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
- **That the client leg is as pinned as the server leg.** It is not, in two
  ways, and both are structural rather than unfinished. **Row 25 is falsified
  by a control pair, not by a mutation**, because the bridge holds no key
  material a mutation could use to present a certificate. **Row 26 is not
  pinnable at all**, because the workspace enables `ring` with no alternative
  provider, so there is no second value to move into and no test that could
  notice the first one moving. A matrix that presented rows 25 and 26 with the
  same weight as row 21 would be claiming a symmetry that does not exist.
- **That the two legs agree by construction.** They do not share a builder.
  `LeafMaterial::server_config()` produces the server side; the client side is
  three chained calls written separately. The `session_config` rows describe
  the first, the `client leg` rows the second, and nothing in the build fails
  if one is changed and the other is not — which is exactly what N1 through N3
  had to be written to notice.
- **That this is the same document as
  `agent-secretless-vault-spec/docs/12-COMPATIBILITY-MATRIX.md`.** It is not.
  That one is a catalogue of which tools work with which mechanism and is a
  planning artefact. This one is measured protocol behaviour and cites tests.
  Neither substitutes for the other, and this one does not satisfy the
  criterion that `12-` was ever mistaken for.
