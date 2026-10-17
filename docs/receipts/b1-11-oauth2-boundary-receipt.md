# B1.11 Implementation Receipt — the OAuth2 boundary holds

Block: B1.11 of `docs/plans/b1-delivery-roadmap.md` (branch
`b1/worker-lifetime`). Closes audit findings **H-05** (provider error
bodies reach the agent through the token endpoint's error path) and
**H-06** (the refresh grant double-encodes the token). Refs:
`02-THREAT-MODEL.md`, `15-ROADMAP.md` M11 / row R2.B.

## What landed

- **One rule for every provider-facing error surface** —
  `crates/broker/src/provider_errors.rs` is the single point: an error the
  broker reports about a provider carries **broker-chosen fields only**.
  The status (which the broker observed) and an error code from a closed
  vocabulary the broker enumerates (RFC 6749 §5.2's six, plus
  `server_error`/`temporarily_unavailable` — what real token endpoints
  answer when broken or down — and RFC 8707's `invalid_target`). Anything
  else collapses to `unrecognized_error`. The provider's own text never
  rides along. The resource-server path (`oauth2_binding.rs`,
  `IdentityError::Refused { status }`) already followed this rule; both
  surfaces now cite the same module, so they cannot drift apart silently.
- **`ProviderRejected` has no description field.** Before B1.11 it carried
  up to 200 characters of `error_description` (or of a non-§5.2 body) and
  the `error` code verbatim — two channels a hostile or misconfigured IdP
  could put anything into, including the client credential it was just
  shown. Removing the field makes the leak unrepresentable at the type
  level: there is nowhere left for a stranger's bytes to sit.
- **`request_form` encodes exactly once.** Values arrive as raw bytes and
  are form-encoded in the wiped buffer the form already owns.
  `refresh()` no longer pre-encodes the token: `a+b` used to travel as
  `a%252Bb` (double encoding), the provider answered `invalid_grant`, and
  a working refresh was silently broken for any token containing an
  escapable character.
- **Fixture gains hostile mode** (`reflect_in_errors`) and a controlled
  `next_refresh_token`, both behind the `test-support` feature that keeps
  them out of shipped builds. Hostile mode reflects a chosen string into
  every token-endpoint `error_description`, form-encoded correctly — a
  reflection the client cannot parse would prove nothing.

## Evidence (all observed RED on the pre-fix tree, GREEN after)

- **RED, unit** (`oauth2.rs`): `an_error_body_that_reflects_the_secret_is_sanitized`
  — the rendered error was `provider rejected the request (401
  invalid_client): client sent secret "p ss+w&rd:"`. GREEN: description
  gone, status + named code survive. `a_hostile_error_code_is_not_relayed_either`
  — the code field carried the secret too; GREEN: closed vocabulary.
- **RED, real TLS** (`tests/oauth2_provider.rs`):
  `a_hostile_error_body_does_not_reach_the_caller` — the fixture's own
  audit (`bad_credentials`, 1) and `last_request` prove the exchange
  happened and the reflection was live. GREEN with status 401 +
  `invalid_client` intact.
- **RED→GREEN, refresh** (`tests/oauth2_provider.rs`):
  `a_plus_b_refresh_token_survives_a_single_encoding` — the fixture hands
  out exactly `a+b`; before: `invalid_grant`; after: a rotated access
  token and a fresh refresh token over real TLS.
- **RED→GREEN, E2E ephemeral** (`crates/cli/tests/eph_b1_11_boundary.rs`,
  deleted at close per the block pattern): real `asv oauth2 whoami`
  (prose and `--json`) against a broker serving a hostile issuer over a
  real UDS socket. Before: the secret sat in the operator's stderr, in
  full. After: exit 1, both renderings clean, and the fixture's audit
  shows two hostile rejections — one per rendering — so the absence is
  the boundary's doing, not a broker that never asked.
- **Suites on the final tree**: broker `--lib` 696 (692 baseline + 4 new),
  `oauth2_provider` 16, `oauth2_vertical` 10, `r2b2_oauth2_vertical` 25,
  `r2b_oauth2_revocation` 5, `oauth2_surrogate_lifecycle` 7, CLI 135,
  `ipc-protocol` 21, `identity` 8; `cargo fmt --check` clean; clippy
  ratchet 0 (two inherited B1.9/B1.10 warnings fixed in passing,
  `51cb52c`); `cargo build --workspace` green.
- **Behavior change, deliberate**: the two pre-B1.11 rows that pinned the
  relay (`a_provider_error_body_is_named`,
  `a_non_conforming_error_body_is_kept_rather_than_discarded`) were
  rewritten to the new rule — that relay was H-05 itself. The
  non-§5.2-body row keeps the status and proves `bad gateway` no longer
  travels.

## Deviations from the plan

- The ephemeral E2E moved from `tests/ephemeral/b1-11/` to
  `crates/cli/tests/eph_b1_11_boundary.rs`: cargo only discovers Rust
  integration tests at a crate's `tests/` root (B1.9's lesson), and the
  crate had to be `asv-cli`'s, because only there does `CARGO_BIN_EXE_asv`
  exist. Same convention B1.9/B1.10 established.
- The ephemeral needed three dev-only dependencies in `asv-cli`
  (`asv-broker` with `test-support`, `asv-connector-http`, `asv-identity`);
  they are removed again at close so the tagged tree carries no unused
  manifest entries. The receipt records the exact shape for re-creation.

## Commits

- `51cb52c` style(broker): restore the clippy ratchet baseline to zero
- `880f753` fix(broker): provider error bodies stop at the boundary (H-05, H-06)
- `72ce0c0` test(cli): ephemeral whoami boundary check against a hostile IdP (B1.11)
- close commit (this receipt, release notes, ephemeral retirement)

**Risk: item 2 (security boundary — untrusted IdP error surfaces).**
Verification: the RED rows above at unit, TLS and E2E layers, plus the
independent native review of the slice.
