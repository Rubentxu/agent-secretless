//! R2.C.1 — the SigV4 core, against the vectors AWS publishes.
//!
//! # The oracle
//!
//! Every expected value below is from the AWS Signature Version 4
//! documentation. They were **not** copied from this implementation's output:
//! they were computed first by a separate Python implementation written from
//! the specification, and the two were compared. That matters because the
//! failure mode for a signing primitive is a signature that is wrong in a way
//! nothing local notices, and an implementation graded against its own output
//! would notice nothing at all.
//!
//! If a vector here ever disagrees with this signer, **the vector is not
//! edited**. Which side is wrong gets worked out, because "make the test pass"
//! on a signing primitive is how a provider starts answering
//! `SignatureDoesNotMatch` for a reason nobody can find.
//!
//! # What these rows are for
//!
//! The vectors establish that the arithmetic is right. They cannot establish
//! the *property*, because all of them are requests that should succeed. The
//! rows after them are the ones that would have caught a signer willing to
//! produce a signature for a request it should refuse.

use asv_broker::aws::sigv4::{
    canonical_query, canonical_uri, encode_component, signing_key, Header, SigV4Signer, SignError,
    SignRequest,
};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const ACCESS_KEY: &str = "AKIDEXAMPLE";
const REGION: &str = "us-east-1";
const SERVICE: &str = "service";
const AMZ_DATE: &str = "20150830T123600Z";

fn signer() -> SigV4Signer {
    SigV4Signer::new(ACCESS_KEY, SECRET, REGION, SERVICE).expect("the fixture is complete")
}

/// The documented `get-vanilla` case: the simplest request that still exercises
/// canonicalisation, key derivation and the header.
#[test]
fn the_documented_get_vanilla_case_signs_to_the_published_signature() {
    let request = SignRequest::new("GET", "/");
    let signed = signer()
        .sign(
            &SignRequest {
                headers: &[
                    Header::new("Host", "example.amazonaws.com"),
                    Header::new("X-Amz-Date", AMZ_DATE),
                ],
                ..request
            },
            AMZ_DATE,
        )
        .expect("a request with a host signs");

    assert_eq!(
        signed.authorization,
        "AWS4-HMAC-SHA256 \
         Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert_eq!(signed.signed_headers, "host;x-amz-date");
    assert_eq!(signed.amz_date, AMZ_DATE);
}

/// The canonical request itself, so a mismatch is legible.
///
/// A signature constant in a failure message tells you that something differs
/// without telling you what. The canonical request is the input to the one
/// hash in the chain that a human can actually read, so it is asserted on its
/// own rather than only through the signature.
#[test]
fn the_canonical_request_is_the_documented_one() {
    let signed = signer()
        .sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("Host", "example.amazonaws.com"),
                    Header::new("X-Amz-Date", AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        )
        .expect("sign");

    let expected = concat!(
        "GET\n",
        "/\n",
        "\n",
        "host:example.amazonaws.com\n",
        "x-amz-date:20150830T123600Z\n",
        "\n",
        "host;x-amz-date\n",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(signed.canonical_request, expected);
}

/// The signing key for a different region and service, from the same
/// documentation.
///
/// A second data point that shares nothing with `get-vanilla` but the secret:
/// if the derivation chain were collapsed to one step, or the date or service
/// dropped, this would still be the only row that noticed.
#[test]
fn the_signing_key_matches_the_documented_iam_derivation() {
    let key = signing_key(SECRET, "20150830", "us-east-1", "iam");
    assert_eq!(
        hex_of(&key),
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    );
}

// ---------------------------------------------------------------------------
// The encoding rules, which are where a signer quietly diverges
// ---------------------------------------------------------------------------

/// A space is `%20` and never `+`.
///
/// `application/x-www-form-urlencoded` writes a space as `+`, and a signer that
/// followed it produces a signature no provider accepts — while still looking
/// entirely reasonable.
///
/// **Mutation:** encode a space as `+`, and this goes red.
#[test]
fn a_space_is_percent_twenty_and_never_a_plus() {
    assert_eq!(encode_component(b"a b", true), "a%20b");
    assert_eq!(encode_component(b"a+b", true), "a%2Bb");
}

/// Hex digits are uppercase.
///
/// Both cases are accepted by the grammar AWS specifies, and a mismatch is a
/// signature that fails at the provider with nothing to compare against.
///
/// **Mutation:** lowercase the hex, and this goes red.
#[test]
fn percent_encoding_uses_uppercase_hex() {
    // The unreserved set, and nothing else. A space inside this literal was a
    // typo in the first version of this row, and it failed for the right
    // reason by accident: the assertion was wrong, not the encoder.
    assert_eq!(encode_component(b"~az09-_.", true), "~az09-_.");
    // The separator is the one byte whose treatment the caller decides, and
    // both answers are legitimate — which is why the first version of this row
    // asked for `%2F` while passing `keep_slash: true`, and got `/`.
    assert_eq!(encode_component(b"/", true), "/");
    assert_eq!(encode_component(b"/", false), "%2F");
    assert_eq!(encode_component(&[0xff], true), "%FF");
}

/// The path is encoded twice unless the caller says it is S3.
///
/// The real rule, which the first version of this row got wrong in a way that
/// made the implementation wrong too: the path is split on `/` and each
/// segment encoded, so a segment can never contain a slash and no flag can
/// change that. What actually differs between S3 and everything else is
/// **double encoding** — a space becomes `%2520` outside S3 and `%20` in it.
///
/// **Mutation:** return the single-encoded path for every service, and the
/// non-S3 case goes red.
#[test]
fn the_path_is_encoded_twice_unless_it_is_s3() {
    assert_eq!(canonical_uri("/a/b c", false), "/a/b%2520c");
    assert_eq!(canonical_uri("/a/b c", true), "/a/b%20c");
    // `/` is the separator in both, and is preserved in both. Encoding it would
    // make the path not a path.
    assert_eq!(canonical_uri("/a/b", false), "/a/b");
    assert_eq!(canonical_uri("/a/b", true), "/a/b");
    // An empty path is `/` in canonical form, never the empty string: the
    // canonical request's URI line is mandatory and an empty one shifts every
    // subsequent line.
    assert_eq!(canonical_uri("", false), "/");
    assert_eq!(canonical_uri("", true), "/");
}

/// Query parameters sort by their *encoded* names.
///
/// `a b` encodes to `a%20b`, so sorting the caller's unencoded strings puts
/// `a-b` first and `a b` second, which is the wrong order. This is the one
/// rule in the query path that cannot be delegated to a caller without the
/// bug following the delegation.
///
/// **Mutation:** sort before encoding, and this goes red.
#[test]
fn query_parameters_sort_by_encoded_name() {
    let sorted = canonical_query(&[("a b", "1"), ("a-b", "2"), ("A", "3")]);
    // Byte order, on the *encoded* names: `A` (0x41) first, then the two
    // lowercase ones, where `a%20b` beats `a-b` because `%` is 0x25 and `-` is
    // 0x2d. The first version of this row had that the other way round, on the
    // reasoning that `%` was "above" the hyphen — it is not, and the row failed.
    assert_eq!(sorted, "A=3&a%20b=1&a-b=2");
    // And the order the caller wrote them in is irrelevant, which is the point.
    assert_eq!(
        canonical_query(&[("a-b", "2"), ("A", "3"), ("a b", "1")]),
        sorted
    );

    // The pair that actually distinguishes sorting-before-encoding from
    // sorting-after. `}` is 0x7D and encodes to `%7D`; `-` is 0x2D and encodes
    // to itself. Unencoded, `a-b` sorts first. Encoded, `a%7Db` sorts first —
    // because every encoded character starts with `%` at 0x25 while every
    // unreserved one is 0x2D or above, so encoding moves the encoded set
    // *below* the unreserved set and can reverse a pair.
    //
    // The first version of this row used `a b` against `a-b`, and
    // sorting-before-encoding passed it: `a b` encodes to `a%20b`, which sorts
    // before `a-b` in *both* orders, so the row could not tell the two apart and
    // the mutation it was written for did not bite.
    assert_eq!(
        canonical_query(&[("a}b", "1"), ("a-b", "2")]),
        "a%7Db=1&a-b=2",
        "the encoded order must be able to reverse the unencoded one, or \
         sorting before encoding is indistinguishable from sorting after"
    );
}

// ---------------------------------------------------------------------------
// The refusals, which are the property
// ---------------------------------------------------------------------------

/// A request with no `Host` is refused.
///
/// This is the row the whole "the signature commits to the destination"
/// property rests on. A signature computed without the host validates for any
/// host the interceptor likes, which is the difference between a signed
/// request and a signed *value*.
///
/// **Mutation:** drop the `MissingHost` check, and this goes red.
#[test]
fn a_request_without_a_host_is_refused() {
    let attempt = signer().sign(
        &SignRequest {
            method: "GET",
            path: "/",
            headers: &[Header::new("X-Amz-Date", AMZ_DATE)],
            ..SignRequest::default()
        },
        AMZ_DATE,
    );
    assert_eq!(attempt, Err(SignError::MissingHost));
}

/// A host reached by a route that is not a token is refused, not lowercased.
///
/// `x-amz-date: 20150830T123600Z\r\nhost: evil.example` is a header name
/// carrying a separator. If it were accepted, the canonical block would name
/// one header and the request would carry two — and `SignedHeaders` is what a
/// reviewer reads to decide what was committed to.
///
/// **Mutation:** normalise the name instead of refusing it, and this goes red.
#[test]
fn a_header_name_carrying_a_separator_is_refused() {
    for name in [
        "x-amz-date: 20150830T123600Z\r\nhost: evil.example",
        "x-amz date",
        "x-amz-date;host",
        "",
    ] {
        let attempt = signer().sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("Host", "example.amazonaws.com"),
                    Header::new(name, AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        );
        assert_eq!(
            attempt,
            Err(SignError::InvalidHeaderName(name.to_string())),
            "`{name:?}` was not refused"
        );
    }
}

/// A header value carrying a newline is refused.
///
/// The canonical block joins headers with `\n`, so an embedded newline is a
/// second header in the thing that was hashed. That is the same attack as the
/// name case, arriving through the other door.
///
/// **Mutation:** strip control characters instead of refusing, and this goes
/// red.
#[test]
fn a_header_value_carrying_a_newline_is_refused() {
    for value in [
        "20150830T123600Z\r\nx-evil: yes",
        "20150830T123600Z\nx-evil: yes",
        "20150830T123600Z\0",
    ] {
        let attempt = signer().sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("Host", "example.amazonaws.com"),
                    Header::new("X-Amz-Date", value),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        );
        assert_eq!(
            attempt,
            Err(SignError::ControlCharacterInHeader {
                name: "x-amz-date".into()
            }),
            "`{value:?}` was not refused"
        );
    }
}

/// Two headers of the same name are refused rather than one of them signed.
///
/// HTTP allows repeated headers, joined with a comma. Signing only the first
/// would let a caller sign `x-amz-date: A` and send `x-amz-date: A, B`, so the
/// signature would validate for a header it did not describe.
///
/// **Mutation:** keep the first and drop the rest, and this goes red.
#[test]
fn a_duplicated_header_name_is_refused() {
    let attempt = signer().sign(
        &SignRequest {
            method: "GET",
            path: "/",
            headers: &[
                Header::new("Host", "example.amazonaws.com"),
                Header::new("X-Amz-Date", AMZ_DATE),
                Header::new("X-Amz-Date", AMZ_DATE),
            ],
            ..SignRequest::default()
        },
        AMZ_DATE,
    );
    assert_eq!(
        attempt,
        Err(SignError::InvalidHeaderName("x-amz-date".into()))
    );
}

/// An incomplete scope is refused when the signer is built, not when it signs.
///
/// Region and service go into the credential scope and into the key
/// derivation. Discovering at sign time that the region is empty means a
/// credential was lent, an HTTP request was built, and only then did the signer
/// refuse — and the failure would read like a provider problem.
///
/// **Mutation:** default an empty region to something, and this goes red.
#[test]
fn an_incomplete_credential_scope_is_refused_at_construction() {
    // Compared on the error arm rather than with `assert_eq!` on the whole
    // `Result`, because `SigV4Signer` deliberately has no `PartialEq`: the
    // obvious way to make this test compile would be to derive it, and that
    // would put a `PartialEq` on a type holding a secret key.
    for (region, service, key, expected) in [
        (
            "",
            SERVICE,
            ACCESS_KEY,
            SignError::IncompleteScope("region"),
        ),
        (
            REGION,
            "",
            ACCESS_KEY,
            SignError::IncompleteScope("service"),
        ),
        (REGION, SERVICE, "", SignError::EmptyAccessKeyId),
    ] {
        assert_eq!(
            SigV4Signer::new(key, SECRET, region, service).err(),
            Some(expected),
            "region={region:?} service={service:?} key={key:?} was accepted"
        );
    }
}

/// A timestamp the signer cannot take a date from is refused.
///
/// `date_stamp` slices the first eight bytes. Without the digit check, a
/// timestamp of `2015-08-3` would produce a date stamp of `2015-08-` and a
/// credential scope that is not the one signed — a scope that names a date no
/// provider will recognise.
///
/// **Mutation:** drop the digit check, and this goes red.
#[test]
fn a_timestamp_the_scope_cannot_be_derived_from_is_refused() {
    for date in ["", "2015", "2015-08-3", "2015083T", "abcdefgh"] {
        let attempt = signer().sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("Host", "example.amazonaws.com"),
                    Header::new("X-Amz-Date", AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            date,
        );
        assert_eq!(
            attempt,
            Err(SignError::IncompleteScope("date")),
            "`{date:?}` was accepted as a signing instant"
        );
    }
}

// ---------------------------------------------------------------------------
// What the signature actually commits to
// ---------------------------------------------------------------------------

/// Every signed dimension changes the signature.
///
/// The vectors show the arithmetic is right for one request. This shows the
/// *coverage*: a signature that does not move when the host, the path, the
/// body or the instant changes is not a commitment to any of them, and a
/// downgrade attack only needs one of the five.
///
/// A signer that ignored the payload, say, would still pass every published
/// vector — all of them have an empty body — and would accept a tampered
/// body. That is the shape this row exists to close.
///
/// **Mutation:** drop the payload hash from the canonical request, and this
/// goes red on the body case alone.
#[test]
fn every_signed_dimension_changes_the_signature() {
    // The header arrays are bound rather than written inline: a `SignRequest`
    // borrows them, and a `vec![]` of requests holding references into
    // temporaries is the shape that would let the last variant sign against
    // freed memory.
    let original_headers = [
        Header::new("Host", "example.amazonaws.com"),
        Header::new("X-Amz-Date", AMZ_DATE),
    ];
    let other_host_headers = [
        Header::new("Host", "evil.example.com"),
        Header::new("X-Amz-Date", AMZ_DATE),
    ];
    let base = SignRequest {
        method: "GET",
        path: "/resource",
        headers: &original_headers,
        ..SignRequest::default()
    };
    let original = signer().sign(&base, AMZ_DATE).expect("sign").authorization;

    let variants: Vec<(&str, SignRequest<'_>, &str)> = vec![
        (
            "host",
            SignRequest {
                headers: &other_host_headers,
                ..base.clone()
            },
            AMZ_DATE,
        ),
        (
            "path",
            SignRequest {
                path: "/other",
                ..base.clone()
            },
            AMZ_DATE,
        ),
        (
            "method",
            SignRequest {
                method: "PUT",
                ..base.clone()
            },
            AMZ_DATE,
        ),
        (
            "body",
            SignRequest {
                payload: b"a body",
                ..base.clone()
            },
            AMZ_DATE,
        ),
        ("instant", base.clone(), "20150831T123600Z"),
    ];

    for (dimension, request, date) in variants {
        let changed = signer()
            .sign(&request, date)
            .unwrap_or_else(|e| panic!("{dimension}: the variant must still sign, got {e}"))
            .authorization;
        assert_ne!(
            changed, original,
            "the signature did not change when the {dimension} did, so it does not \
             commit to the {dimension}"
        );
    }
}

/// A signed header's name is matched case-insensitively and its value folded.
///
/// HTTP header names are case-insensitive, so a request that sends
/// `X-Amz-Date` has to produce the same signature as one that sends
/// `x-amz-date` — otherwise a proxy that lowercases a name breaks every
/// signature, and a caller who discovers that "fixes" it by signing the
/// lowercased name only would commit to a header it never sends.
///
/// **Mutation:** match header names case-sensitively, and this goes red.
#[test]
fn header_names_match_case_insensitively_and_values_fold() {
    let canonical = signer()
        .sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("host", "example.amazonaws.com"),
                    Header::new("X-Amz-Date", AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        )
        .expect("sign");

    let shouting = signer()
        .sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("HOST", "example.amazonaws.com"),
                    Header::new("x-amz-date", AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        )
        .expect("sign");

    assert_eq!(
        canonical.authorization, shouting.authorization,
        "header name case changed the signature, so a proxy that lowercases a \\
         header name would break every request"
    );

    // And whitespace inside a value is folded, because an intermediary is
    // entitled to normalise it.
    let padded = signer()
        .sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("host", "example.amazonaws.com"),
                    Header::new("x-amz-date", "  20150830T123600Z  "),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        )
        .expect("sign");
    assert_eq!(
        canonical.authorization, padded.authorization,
        "surrounding whitespace changed the signature"
    );
}

/// The secret never appears in anything the signer hands back.
///
/// A signing key is a key; a `Debug` that printed one would put it in every
/// assertion failure that touched a signer, which is the most-read place a
/// secret ends up.
#[test]
fn the_secret_never_appears_in_the_signer_output() {
    let signer = signer();
    let rendered = format!("{signer:?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug printed the secret: {rendered}"
    );
    assert!(
        !rendered.contains(&hex_of(&signer.signing_key("20150830"))),
        "Debug printed the signing key: {rendered}"
    );

    let signed = signer
        .sign(
            &SignRequest {
                method: "GET",
                path: "/",
                headers: &[
                    Header::new("host", "example.amazonaws.com"),
                    Header::new("x-amz-date", AMZ_DATE),
                ],
                ..SignRequest::default()
            },
            AMZ_DATE,
        )
        .expect("sign");
    for surface in [
        signed.authorization.as_str(),
        signed.canonical_request.as_str(),
        signed.signed_headers.as_str(),
        signed.amz_date.as_str(),
    ] {
        assert!(!surface.contains(SECRET), "the secret reached {surface:?}");
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
