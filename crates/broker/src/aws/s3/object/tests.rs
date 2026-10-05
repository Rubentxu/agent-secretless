//! Rows for the S3 response filter.
//!
//! The refusals are the ordinary work. The two rows at the end are the module's
//! claim: the answer is built entirely from headers, and there is nowhere in it
//! for object bytes to go.

use super::{object_metadata, ObjectError, ObjectMetadata, ObjectResponse};

const BUCKET: &str = "acme-artifacts";
const KEY: &str = "2026/10/report.json";

/// What a real S3 `GET` answers with.
///
/// Header names lowercased and in the order S3 sends them, because the reader
/// is not supposed to care about either and a row that depended on the order
/// would be testing the fixture.
fn get_ok() -> ObjectResponse {
    ObjectResponse {
        status: 200,
        headers: vec![
            ("content-length".into(), "20481".into()),
            ("etag".into(), "\"d41d8cd98f00b204e9800998ecf8427e\"".into()),
            (
                "last-modified".into(),
                "Tue, 05 Oct 2026 09:12:44 GMT".into(),
            ),
            ("content-type".into(), "application/json".into()),
            ("x-amz-version-id".into(), "3HL4kqtJvjVBH40Nrjfkd".into()),
        ],
    }
}

fn read(response: &ObjectResponse) -> Result<ObjectMetadata, ObjectError> {
    object_metadata(response, BUCKET, KEY)
}

/// # The happy path

#[test]
fn the_answer_is_built_from_the_headers() {
    let metadata = read(&get_ok()).expect("a well-formed object response");

    assert_eq!(metadata.bucket, BUCKET);
    assert_eq!(metadata.key, KEY);
    assert_eq!(metadata.content_length, 20481);
    assert_eq!(metadata.etag, "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(metadata.last_modified, "Tue, 05 Oct 2026 09:12:44 GMT");
    assert_eq!(metadata.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        metadata.version_id.as_deref(),
        Some("3HL4kqtJvjVBH40Nrjfkd")
    );
    assert!(metadata.is_populated());
}

#[test]
fn the_etag_arrives_unquoted() {
    // The quotes are S3's framing. What a later write is compared against is
    // the value inside them, and a comparison that had to strip them first
    // would make the correctness of a conditional write depend on this module.
    let metadata = read(&get_ok()).expect("readable");
    assert!(!metadata.etag.contains('"'), "the quotes are still there");
}

#[test]
fn an_optional_header_may_be_absent() {
    // S3 does not always send `content-type`, and a versioned bucket may not
    // send a version id. An absent optional header is not a refusal — the
    // object exists either way.
    let bare = ObjectResponse {
        status: 200,
        headers: vec![
            ("content-length".into(), "0".into()),
            ("etag".into(), "\"abc\"".into()),
            (
                "last-modified".into(),
                "Tue, 05 Oct 2026 09:12:44 GMT".into(),
            ),
        ],
    };
    let metadata = read(&bare).expect("three headers is a complete answer");

    assert_eq!(metadata.content_type, None);
    assert_eq!(metadata.version_id, None);
    assert!(
        !metadata.is_populated(),
        "a zero-length object is not populated"
    );
}

#[test]
fn an_empty_object_is_an_answer_and_not_a_refusal() {
    // "Does it exist" and "is it populated" are different questions, and
    // collapsing them makes an operator debug the wrong object.
    let empty = ObjectResponse {
        status: 200,
        headers: vec![
            ("content-length".into(), "0".into()),
            ("etag".into(), "\"d41d8cd98f00b204e9800998ecf8427e\"".into()),
            (
                "last-modified".into(),
                "Tue, 05 Oct 2026 09:12:44 GMT".into(),
            ),
        ],
    };

    let metadata = read(&empty).expect("an empty object exists");
    assert_eq!(metadata.content_length, 0);
    // The first version of this row stopped at `content_length == 0` and
    // never called `is_populated`, so the campaign reported the mutation that
    // makes `is_populated` always false as a survivor. The assertion belongs
    // in the row named after the behaviour, not in the one named after the
    // value.
    assert!(
        !metadata.is_populated(),
        "an object that exists and is empty is not populated"
    );
}

/// # Refusals
///
/// The first of these is the one the module exists for.

#[test]
fn a_refused_response_is_refused_by_status_and_the_body_is_never_read() {
    // S3 answers a missing key with `404` and an XML `<Error>` document. This
    // workspace has no XML parser, on purpose: a parser brings a DTD, a DTD is
    // an XXE surface. So the status is the whole answer and the body is not
    // touched — which means the refusal has to say so, or an operator sees a
    // bare `403` and assumes the worst of their policy.
    let denied = ObjectResponse {
        status: 403,
        headers: vec![("content-length".into(), "310".into())],
    };

    let err = read(&denied).expect_err("a 403 is a refusal");

    assert_eq!(err, ObjectError::Refused { status: 403 });
    assert!(
        format!("{err}").contains("does not parse"),
        "the refusal must say the body was not read: {err}"
    );
}

#[test]
fn a_missing_key_is_refused_the_same_way_and_its_code_is_not_guessed() {
    // `NoSuchKey` and `AccessDenied` are both `4xx`. The module reports the
    // status and does not pretend to know which happened, because reading the
    // code means reading the XML and there is no parser here by decision.
    let missing = ObjectResponse {
        status: 404,
        headers: vec![("content-length".into(), "215".into())],
    };

    assert_eq!(
        read(&missing).expect_err("a 404 is a refusal"),
        ObjectError::Refused { status: 404 }
    );
}

#[test]
fn a_missing_required_header_is_refused_by_name() {
    // "There is no ETag" is actionable. "The object could not be read" is not.
    let mut response = get_ok();
    response.headers.retain(|(name, _)| name != "etag");

    let err = read(&response).expect_err("no ETag");

    assert_eq!(
        err,
        ObjectError::MissingHeader {
            header: "etag",
            question: "which version is it"
        },
        "{err:?}"
    );
}

#[test]
fn a_content_length_that_is_not_a_number_is_refused_rather_than_defaulted() {
    let mut response = get_ok();
    response
        .headers
        .retain(|(name, _)| name != "content-length");
    response
        .headers
        .push(("content-length".into(), "twenty kilobytes".into()));

    let err = read(&response).expect_err("not a number");

    assert!(matches!(err, ObjectError::NotANumber { .. }), "{err:?}");
    assert!(format!("{err}").contains("twenty kilobytes"), "{err}");
}

#[test]
fn an_unquoted_etag_is_refused() {
    // An ETag is an opaque token compared against what a later write returns.
    // Accepting an unquoted one and normalising it here would make the
    // correctness of a conditional write depend on this module's idea of shape.
    let mut response = get_ok();
    response.headers.retain(|(name, _)| name != "etag");
    response
        .headers
        .push(("etag".into(), "d41d8cd98f00b204e9800998ecf8427e".into()));

    let err = read(&response).expect_err("an ETag is quoted");

    assert!(matches!(err, ObjectError::MalformedETag { .. }), "{err:?}");
}

#[test]
fn a_header_carrying_a_newline_is_refused() {
    // These values reach a `Debug`, an audit record and a terminal. A newline
    // in one is a forged log line, and the refusal belongs here rather than in
    // whatever formats the value downstream.
    let mut response = get_ok();
    response.headers.retain(|(name, _)| name != "last-modified");
    response.headers.push((
        "last-modified".into(),
        "Tue, 05 Oct 2026 09:12:44 GMT\nGET /admin HTTP/1.1".into(),
    ));

    let err = read(&response).expect_err("a newline is a forged line");

    assert_eq!(
        err,
        ObjectError::ControlCharacter {
            header: "last-modified"
        },
        "{err:?}"
    );
}

#[test]
fn a_control_character_in_an_optional_header_is_refused_too() {
    // The other half of the same rule, and the one that is easy to lose: the
    // optional headers go through a different helper, and a check that only
    // covers the required ones leaves a log-injection vector in the field
    // nobody was looking at.
    let mut response = get_ok();
    response
        .headers
        .push(("x-amz-version-id".into(), "abc\r\nX-Injected: 1".into()));

    let err = read(&response).expect_err("a CRLF is a forged header");

    assert_eq!(
        err,
        ObjectError::ControlCharacter {
            header: "x-amz-version-id"
        },
        "{err:?}"
    );
}

// # The claim the module makes
//
// A destructuring row on purpose. A field added later breaks this build, which
// is the property: the omission is reviewable by the compiler rather than by a
// test that has to remember to look.

#[test]
fn no_field_of_the_answer_can_hold_the_object() {
    let metadata = read(&get_ok()).expect("readable");
    let ObjectMetadata {
        bucket,
        key,
        content_length,
        etag,
        last_modified,
        ..
    } = metadata;

    assert_eq!(bucket, BUCKET);
    assert_eq!(key, KEY);
    assert_eq!(content_length, 20481);
    assert!(!etag.is_empty());
    assert!(!last_modified.is_empty());
}

#[test]
fn the_response_type_has_nowhere_to_put_a_body() {
    // The first version of this row built two `ObjectResponse` values and
    // asserted they read the same, on the theory that one "had a body". It
    // could not: `ObjectResponse` has no body field, so the two fixtures
    // differed in their headers and the row failed for a reason that had
    // nothing to do with bodies. Which is the claim, so it is stated as the
    // claim -- a destructuring row, where adding a body field breaks the build.
    let response = get_ok();
    let ObjectResponse { status, headers } = &response;

    assert_eq!(*status, 200);
    assert!(!headers.is_empty());
}

#[test]
fn a_duplicated_header_is_refused_rather_than_resolved_by_arrival_order() {
    // Two `content-length` values are two answers to "how big is it", and
    // picking one would make the answer depend on the order the origin happened
    // to serialise them in. This row and the control-character one above are
    // the same bug found twice: the first version of the reader returned the
    // first match, so a duplicated header was invisible no matter which of the
    // two carried the payload.
    let mut response = get_ok();
    response.headers.push(("content-length".into(), "1".into()));

    let err = read(&response).expect_err("a repeated header is ambiguous");

    assert!(matches!(err, ObjectError::RepeatedHeader { .. }), "{err:?}");
    assert!(format!("{err}").contains("content-length"), "{err}");
}

// # The positive rows

#[test]
fn a_reader_that_refused_everything_would_fail_these() {
    let metadata = read(&get_ok()).expect("a real response is readable");
    assert_eq!(metadata.content_length, 20481);
    assert_eq!(metadata.etag, "d41d8cd98f00b204e9800998ecf8427e");
}
