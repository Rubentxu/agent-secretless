//! M4-R8 — URL/header fuzz target for authority canonicalization.
//!
//! The claim under test (M4-S8): *no malformed input is authorized for the
//! approved authority*. That is a claim about a property, not about a list of
//! known-bad strings, so it is written as a property and handed to the fuzzer
//! rather than as a table someone has to remember to extend.
//!
//! # What is actually being fuzzed
//!
//! [`asv_domain::Authority`] is the security boundary. Its only constructor is
//! fallible, so a caller cannot skip canonicalization — that is the whole point
//! of D5. Everything downstream (the Cedar audience allowlist, address pinning,
//! the `Host:` header) consumes what this function returns. So the target is
//! the function itself, plus the two pure predicates that consume its result.
//!
//! The target deliberately does no network I/O. A fuzz target that opened
//! sockets would spend its budget on timeouts, and the property being searched
//! is a string property.
//!
//! # The oracle
//!
//! `canonicalize` returns `Ok` or `Err`, and both outcomes are checked:
//!
//! 1. **No false allow.** If the input is anything other than a bare
//!    lowercase ASCII DNS name, it must be rejected. The oracle is written as
//!    an independent re-implementation of the acceptance rules, so a bug that
//!    weakens `canonicalize` cannot silently agree with itself.
//! 2. **Round-trip stability.** An accepted authority must equal its own
//!    re-canonicalization, and must be accepted again. A value that is accepted
//!    but not stable would let an allowlist comparison be spelling-dependent,
//!    which is the exact failure D5 exists to prevent.
//!
//! Properties 1 and 2 together are what make "no false allow" falsifiable: a
//! mutation that lets a lookalike through breaks 1, and one that produces an
//! unstable form breaks 2.
#![no_main]

use libfuzzer_sys::fuzz_target;
use url::Url;

use asv_connector_http::transport::PinnedClient;
use asv_domain::Authority;

/// The one authority this build is approved to talk to.
///
/// D6 makes the allowlist a compile-time constant, and M4 is a single-provider
/// milestone, so the fuzz oracle has exactly one approved value to protect.
const APPROVED: &str = "api.github.com";

fuzz_target!(|data: &[u8]| {
    // Interpret the input as a candidate authority. `from_utf8` failures are
    // not a finding: a non-UTF-8 blob cannot be an ASCII host, and the
    // rejection happens one layer down in the caller's own string handling.
    let Ok(candidate) = std::str::from_utf8(data) else {
        return;
    };

    // Skip inputs that are not plausibly host-shaped. Fuzzing arbitrary bytes
    // spends the whole budget on strings that are rejected by the first ASCII
    // check, which teaches the fuzzer nothing about the interesting boundary.
    // The cap keeps a single input from dominating a run.
    if candidate.is_empty() || candidate.len() > 512 {
        return;
    }

    let parsed = Authority::canonicalize(candidate);

    match &parsed {
        Ok(authority) => {
            // Property 2: an accepted authority is a fixed point of its own
            // canonicalization. Without this, `API.GITHUB.COM` could be
            // accepted and then compare unequal to the allowlist entry.
            let canonical = authority.as_str();
            assert_eq!(
                Authority::canonicalize(canonical).as_ref().map(Authority::as_str),
                Ok(canonical),
                "accepted authority {canonical:?} is not a fixed point of canonicalize"
            );

            // Property 1 (soundness half): anything accepted must really look
            // like a bare lowercase ASCII DNS name. This is the independent
            // oracle, not a restatement of the implementation.
            assert!(
                oracle_accepts(canonical),
                "canonicalize accepted {canonical:?} (from input {candidate:?}) \
                 but it is not a bare lowercase ASCII DNS name with >= 2 labels"
            );
            assert!(
                canonical.is_ascii(),
                "accepted authority {canonical:?} is not ASCII"
            );
            assert!(
                !canonical.contains('@') && !canonical.contains('%'),
                "accepted authority {canonical:?} carries userinfo or percent-encoding"
            );
            assert!(
                !canonical.contains('/') && !canonical.contains(':'),
                "accepted authority {canonical:?} carries a scheme or port"
            );
            assert!(
                !canonical.starts_with('[') && !canonical.ends_with(']'),
                "accepted authority {canonical:?} is an IP literal"
            );
            assert_eq!(
                canonical,
                canonical.to_ascii_lowercase(),
                "accepted authority {canonical:?} is not lowercase"
            );
            assert!(
                !canonical.ends_with('.'),
                "accepted authority {canonical:?} kept a trailing dot"
            );
            assert!(
                canonical.split('.').count() >= 2,
                "accepted authority {canonical:?} has fewer than two labels"
            );

            // The load-bearing consequence, stated directly. The approved
            // authority obviously canonicalizes to itself, so the property is
            // not "never equals APPROVED" — it is that *only* the approved
            // spelling does. Any lookalike that reaches equality is a false
            // allow, and that is the exact sentence M4-S8 makes.
            if canonical == APPROVED {
                assert!(
                    is_approved_spelling(candidate),
                    "input {candidate:?} canonicalized to the approved authority \
                     without being an approved spelling of it"
                );
            }
        }
        Err(_) => {
            // Rejection is the safe outcome; there is nothing to assert. The
            // pressure to add a check here is a mistake: a `canonicalize` that
            // rejects too much is an availability bug, not a security one, and
            // the over-refusal properties are pinned by the unit tests in
            // `asv-domain` instead.
        }
    }

    // The header side of "URL/header fuzz". A `Location` the provider controls
    // is a header, and it is the one header that can move a credential to a
    // different host. If the candidate parses as a URL, its own origin must
    // never be treated as same-origin with the approved authority unless it
    // genuinely is the approved authority.
    if let Ok(url) = Url::parse(candidate) {
        let Ok(approved) = Authority::canonicalize(APPROVED) else {
            unreachable!("the approved authority is a compile-time constant")
        };
        let approved_url = Url::parse(&format!("https://{approved}")).expect("the origin parses");

        if !PinnedClient::is_same_origin(&approved_url, &url) {
            // Same-origin refused, which is the property D7 depends on.
            // Nothing further to assert — the interesting case is the mirror.
        } else {
            // Same-origin accepted. Then the host *must* really be the
            // approved authority: a lookalike host, a userinfo spelling, or a
            // backslash that some parsers fold into a path separator must never
            // reach this branch. `host_str` is the parsed host, so a browser
            // style confusion is caught here rather than trusted away.
            let host = url.host_str().unwrap_or_default();
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            assert_eq!(
                host, APPROVED,
                "a URL over input {candidate:?} was judged same-origin with the \
                 approved authority but its host is {host:?}"
            );
            assert!(
                url.username().is_empty(),
                "a URL over input {candidate:?} was judged same-origin while \
                 carrying userinfo"
            );
        }
    }
});

/// Which spellings of the approved authority are legitimate.
///
/// D6 and M4-R3 say the approved authority may be written in mixed case and
/// with a single trailing dot, and nothing else. Everything else that reduces
/// to the same string is an attack shape, not a spelling: userinfo before an
/// `@`, a suffix, a percent-encoded form, an embedded NUL, a leading or
/// trailing space.
///
/// This is the function that makes the "no false allow" claim checkable. If a
/// future change to `canonicalize` started accepting, say, a Unicode
/// fullwidth dot, this is what would catch it.
fn is_approved_spelling(candidate: &str) -> bool {
    let Some(without_dot) = candidate.strip_suffix('.') else {
        // Either the bare form or a spelling with a trailing dot.
        return candidate.eq_ignore_ascii_case(APPROVED);
    };
    without_dot.eq_ignore_ascii_case(APPROVED)
}

/// The independent oracle: would a bare lowercase ASCII DNS name with at
/// least two labels accept this string?
///
/// Written separately from [`Authority::canonicalize`] on purpose. If the
/// oracle were the implementation, a mutation that weakened the real function
/// would weaken its own referee and the target would report green.
///
/// This is intentionally *stricter* than a full DNS name check in one
/// respect and *looser* in another, mirroring what an allowlist comparison
/// actually needs: ASCII, lowercase, no separators that can be re-interpreted,
/// and enough labels that a bare `localhost` can never be approved.
fn oracle_accepts(candidate: &str) -> bool {
    if candidate.is_empty() || !candidate.is_ascii() {
        return false;
    }
    if candidate != candidate.to_ascii_lowercase() {
        return false;
    }
    for forbidden in ['@', '%', '/', ':', '\\', '?', '#', '[', ']'] {
        if candidate.contains(forbidden) {
            return false;
        }
    }
    if candidate.starts_with('-') || candidate.ends_with('-') {
        return false;
    }
    if candidate.starts_with('.') || candidate.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = candidate.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels
        .iter()
        .all(|label| !label.is_empty() && label.len() <= 63 && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}
