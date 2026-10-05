//! Rows for S3 addressing.
//!
//! Two kinds of row here. The refusals are the ordinary work. The one that
//! matters is the pair at the end, which is about the signature and the request
//! line being the same string — the property the module is shaped around and
//! the one an implementation that encoded twice would get wrong quietly.

use super::{Addressing, S3Error, S3Target, check_bucket, check_key, looks_like_ipv4};

/// The resolution, unwrapped. For rows that expect it to work.
fn target(bucket: &str, key: &str) -> S3Target {
    attempt(bucket, key).expect("a usable bucket and key")
}

/// The resolution, still a `Result`. For the refusal rows, which is the whole
/// point of having a second name for it: a helper that unwrapped would make
/// every refusal row a type error instead of a measurement.
fn attempt(bucket: &str, key: &str) -> Result<S3Target, S3Error> {
    S3Target::resolve(bucket, key, "eu-west-1", Addressing::VirtualHosted)
}

/// # The addressing
///
/// Written from S3's published rules, not from this implementation's output,
/// for the reason every oracle in this provider is written that way: an
/// implementation graded against its own output notices nothing.

#[test]
fn a_bucket_becomes_the_host_and_the_key_becomes_the_path() {
    let resolved = target("acme-artifacts", "2026/10/report.json");

    assert_eq!(
        resolved.authority.as_str(),
        "acme-artifacts.s3.eu-west-1.amazonaws.com"
    );
    assert_eq!(resolved.path, "/2026/10/report.json");
    assert_eq!(resolved.region, "eu-west-1");
}

#[test]
fn a_slash_in_the_key_is_a_separator_and_stays_one() {
    // The slashes are the key's own structure. Encoding them would make the
    // object unreachable by any other S3 client, which is a loud failure —
    // but only after the signature has been computed over the wrong resource.
    let resolved = target("acme-artifacts", "a/b/c.txt");
    assert_eq!(resolved.path, "/a/b/c.txt");
}

#[test]
fn a_space_in_the_key_is_encoded_once() {
    let resolved = target("acme-artifacts", "2026/Q4 plan.md");
    assert_eq!(resolved.path, "/2026/Q4%20plan.md");
}

#[test]
fn a_character_outside_the_unreserved_set_is_percent_encoded_with_upper_case_hex() {
    // AWS publishes uppercase hex and encodes everything but `A-Za-z0-9-_.~`.
    // Lowercase hex is accepted by some servers and rejected by S3, so a signer
    // that emits it produces a signature that is right for no one.
    let resolved = target("acme-artifacts", "käy/日本.txt");
    assert_eq!(resolved.path, "/k%C3%A4y/%E6%97%A5%E6%9C%AC.txt");
}

#[test]
fn an_unreserved_character_is_left_alone() {
    let resolved = target("acme-artifacts", "a-b_c.d~e/f");
    assert_eq!(resolved.path, "/a-b_c.d~e/f");
}

#[test]
fn path_style_puts_the_bucket_in_the_path_and_not_the_host() {
    let resolved = S3Target::resolve("acme-artifacts", "a/b.txt", "eu-west-1", Addressing::PathStyle)
        .expect("path style is a supported shape");

    assert_eq!(resolved.authority.as_str(), "s3.eu-west-1.amazonaws.com");
    assert_eq!(resolved.path, "/acme-artifacts/a/b.txt");
}

// # The bucket rules
//
// Each rule is a different host from the one the operator meant, which is why
// they are refusals rather than normalisation.

#[test]
fn an_upper_case_bucket_name_is_refused() {
    let err = attempt("Acme", "k").expect_err("upper case is a different host");
    assert!(matches!(err, S3Error::InvalidBucket { .. }), "{err:?}");
    assert!(format!("{err}").contains("lowercase"), "{err}");
}

#[test]
fn an_underscore_in_a_bucket_name_is_refused() {
    // DNS labels allow it and S3 does not, so a resolver and a signature can
    // disagree about whether the host exists.
    let err = attempt("acme_artifacts", "k").expect_err("underscore");
    assert!(format!("{err}").contains("underscore"), "{err}");
}

#[test]
fn adjacent_dots_in_a_bucket_name_are_refused() {
    let err = attempt("acme..artifacts", "k").expect_err("adjacent dots");
    assert!(format!("{err}").contains("adjacent dots"), "{err}");
}

#[test]
fn an_ip_shaped_bucket_name_is_refused() {
    // A wildcard certificate cannot cover one, so nothing can prove the host
    // is the one the signature was made for.
    let err = attempt("192.168.0.1", "k").expect_err("IP-shaped");
    assert!(format!("{err}").contains("IPv4"), "{err}");
}

#[test]
fn a_bucket_name_that_is_too_short_or_too_long_is_refused() {
    assert!(attempt("ab", "k").is_err(), "two characters is not a bucket");
    let long = "a".repeat(64);
    assert!(attempt(&long, "k").is_err(), "64 characters is not a bucket");
}

#[test]
fn a_bucket_name_that_starts_or_ends_with_a_separator_is_refused() {
    // Asserted by *reason*, not merely by "it errored". The first version of
    // this row used `is_err()` and passed under a mutation that deleted the
    // rule entirely — because `Authority::canonicalize` refuses a host whose
    // label starts with a hyphen, one layer up. The row was green for a reason
    // that had nothing to do with the check it was written for, and naming the
    // rule is what makes it mean that check.
    for name in ["-acme", "acme-", ".acme", "acme."] {
        let err = attempt(name, "k").expect_err(name);
        assert!(
            format!("{err}").contains("starts and ends with"),
            "{name}: the bucket rule must be what refuses this, not the authority \
             underneath it. Got: {err}"
        );
    }
}

#[test]
fn the_refusal_names_the_rule_that_was_broken() {
    // An operator told "invalid bucket" has to bisect a 63-character string by
    // hand. Every arm here names one rule, which is the whole reason for the
    // error being a struct rather than a string.
    for (name, expected) in [
        ("Acme", "lowercase"),
        ("acme_artifacts", "underscore"),
        ("acme..artifacts", "adjacent dots"),
        ("192.168.0.1", "IPv4"),
    ] {
        let err = attempt(name, "k").expect_err(name);
        assert!(
            format!("{err}").contains(expected),
            "{name}: the refusal must name the rule, got {err}"
        );
    }
}

// # The key rules

#[test]
fn a_key_carrying_a_line_break_is_refused() {
    // A newline in a request line is a second request. It is encoded on the
    // wire and so cannot be smuggled that way — but the point is that the
    // refusal is here rather than being left to whatever sits downstream of the
    // encoder and happens to be strict today.
    let err = attempt("acme-artifacts", "a\nb").expect_err("newline");
    assert!(format!("{err}").contains("second request"), "{err}");
}

#[test]
fn a_key_carrying_a_control_character_is_refused() {
    let err = attempt("acme-artifacts", "a\u{0}b").expect_err("NUL");
    assert!(format!("{err}").contains("control character"), "{err}");
}

#[test]
fn an_empty_key_is_refused() {
    // An empty key names the bucket, which is a different request entirely.
    let err = attempt("acme-artifacts", "").expect_err("empty");
    assert!(format!("{err}").contains("not empty"), "{err}");
}

#[test]
fn a_key_containing_a_dot_dot_segment_is_refused_rather_than_rewritten() {
    // Normalising would produce a path the operator did not name, and the
    // signature would be computed over the normalised one.
    let err = attempt("acme-artifacts", "a/../../etc/passwd").expect_err("traversal");
    assert!(matches!(err, S3Error::Traversal { .. }), "{err:?}");
    assert!(format!("{err}").contains("refused rather than rewritten"), "{err}");
}

#[test]
fn a_key_containing_a_single_dot_segment_is_refused_too() {
    // `./a` normalises to `a`. A key is not a path expression.
    let err = attempt("acme-artifacts", "./a").expect_err("dot segment");
    assert!(matches!(err, S3Error::Traversal { .. }), "{err:?}");
}

#[test]
fn a_key_containing_dots_that_are_not_a_segment_is_fine() {
    // `..` inside a filename is not traversal. Refusing it would make ordinary
    // keys unusable, and a refusal that is wrong often enough gets disabled.
    let resolved = target("acme-artifacts", "archive..zip/config");
    assert_eq!(resolved.path, "/archive..zip/config");
}

#[test]
fn an_empty_region_is_refused() {
    // The credential scope is date/region/service/aws4_request, and a missing
    // region is a scope the provider will not accept.
    let err = S3Target::resolve("acme-artifacts", "k", "", Addressing::VirtualHosted)
        .expect_err("no region");
    assert_eq!(err, S3Error::NoRegion);
}

// # The property the module exists for

#[test]
fn the_path_that_is_signed_is_the_path_that_is_sent() {
    // There is one path in the type and `canonical_path` returns it unchanged.
    // A contributor who believes the canonical form should differ — encoded
    // twice, or with the bucket folded in — changes this row and not the type.
    for key in [
        "2026/10/report.json",
        "Q4 plan.md",
        // A literal `%2F` in a key. It has to become `%252F`, because the
        // percent is a real character in the key and encoding it once is what
        // makes the request name the object the operator meant. This case was
        // not in the first version of this row, which used `a/../b` as an
        // example and was refused by the traversal rule — the refusal was
        // right and the example was wrong.
        "a%2Fb/c",
        "käy/日本.txt",
        "a+b?c#d",
    ] {
        let resolved = target("acme-artifacts", key);
        assert_eq!(
            resolved.canonical_path(),
            resolved.path,
            "{key:?}: the signed path and the sent path are different strings"
        );
    }
}

#[test]
fn the_signed_path_is_encoded_exactly_once() {
    // Once for S3, twice for everything else. Encoding it twice produces a
    // signature over `%2520` for a path that will be sent as `%20`, and the
    // failure an operator sees is a credentials error rather than an encoding
    // one.
    let resolved = target("acme-artifacts", "Q4 plan.md");
    assert_eq!(resolved.canonical_path(), "/Q4%20plan.md");
    assert!(
        !resolved.canonical_path().contains("%2520"),
        "the path was encoded twice"
    );
}

// # The positive rows
//
// A resolver that refused everything would pass every refusal above.

#[test]
fn a_resolver_that_refused_everything_would_fail_these() {
    let resolved = target("acme-artifacts", "2026/10/report.json");
    assert_eq!(resolved.authority.as_str(), "acme-artifacts.s3.eu-west-1.amazonaws.com");
    assert_eq!(resolved.path, "/2026/10/report.json");
    assert!(check_bucket("acme-artifacts").is_ok());
    assert!(check_key("2026/10/report.json").is_ok());
    assert!(!looks_like_ipv4("acme-artifacts"));
    assert!(looks_like_ipv4("192.168.0.1"));
}
