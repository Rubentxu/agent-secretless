//! Rows for the reply filter.
//!
//! The property under test is negative in a way the others in this module are
//! not: not "this works" but "this cannot produce a value". That is much harder
//! to assert, and most of these rows are about the *shape* of what comes back
//! rather than its contents.

use super::{secret_metadata, MetadataError, SecretMetadata};
use crate::k8s::K8sReply;

/// A reply whose `data` holds a value that must not survive the read.
fn reply_with(secret: &str) -> K8sReply {
    K8sReply {
        status: 200,
        body: format!(
            r#"{{
              "kind": "Secret",
              "apiVersion": "v1",
              "metadata": {{
                "name": "{secret}",
                "namespace": "payments",
                "type": "Opaque",
                "resourceVersion": "482913"
              }},
              "data": {{
                "username": "cGF5bWVudHMvc3Zjogc2VjcmV0LXZhbHVl",
                "password": "c3VwZXItc2VjcmV0LXZhbHVl",
                "ca.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
              }}
            }}"#
        )
        .into_bytes(),
    }
}

fn named(secret: &str) -> SecretMetadata {
    secret_metadata(&reply_with(secret)).expect("a well-formed Secret reply")
}

/// # The shape
///
/// If these hold, the type cannot carry a value. That is stronger than any
/// assertion about what the code does, because it is about what the code
/// *could* do.

#[test]
fn the_answer_carries_the_facts_an_operator_asks_and_nothing_else() {
    let metadata = named("db-credentials");
    assert_eq!(metadata.name, "db-credentials");
    assert_eq!(metadata.namespace, "payments");
    assert_eq!(metadata.secret_type, "Opaque");
    assert_eq!(metadata.resource_version, "482913");
}

#[test]
fn a_populated_secret_is_counted_rather_than_read() {
    assert_eq!(named("db-credentials").key_count(), 3);
}

#[test]
fn the_count_does_not_come_with_the_key_names() {
    // The names are not secret and are often wanted. They are also the first
    // half of a credential hunt, so this row pins that the count is a count.
    let rendered = format!("{:?}", named("db-credentials"));
    for leaked in ["username", "password", "ca.crt"] {
        assert!(
            !rendered.contains(leaked),
            "a key name escaped into the answer: {rendered}"
        );
    }
}

#[test]
fn no_field_of_the_answer_can_hold_the_value() {
    // Written as a destructuring row on purpose. A field added later breaks
    // this compile, which is the property being claimed: the omission is
    // reviewable by the compiler rather than by a test that has to remember to
    // look.
    let metadata = named("db-credentials");
    let SecretMetadata {
        name,
        namespace,
        secret_type,
        resource_version,
        ..
    } = metadata;
    assert_eq!(
        (name, namespace, secret_type, resource_version),
        (
            "db-credentials".to_string(),
            "payments".to_string(),
            "Opaque".to_string(),
            "482913".to_string()
        )
    );
}

#[test]
fn the_base64_of_the_value_is_not_copied_out_of_the_reply() {
    // The value in the fixture is base64, and a filter that decoded it, or
    // that copied the map, would leave one of these behind. The reply itself
    // still holds them — that is not claimed otherwise — but nothing that
    // outlives the call does.
    let reply = reply_with("db-credentials");
    let metadata = secret_metadata(&reply).expect("a well-formed Secret reply");
    let answer = format!("{metadata:?}");

    for value in [
        "cGF5bWVudHMvc3Zjogc2VjcmV0LXZhbHVl",
        "c3VwZXItc2VjcmV0LXZhbHVl",
    ] {
        assert!(
            !answer.contains(value),
            "the answer repeated a value: {answer}"
        );
    }
}

/// # Refusals

#[test]
fn a_refusal_status_is_refused_before_the_body_is_parsed() {
    // A Kubernetes `404` body is a `Status` object, and parsing it as a Secret
    // would either fail with a confusing message or, worse, succeed on a
    // document that happens to have the right shape.
    let err = secret_metadata(&K8sReply {
        status: 404,
        body: br#"{"kind":"Status","code":404,"message":"secrets \"db\" not found"}"#.to_vec(),
    })
    .expect_err("a 404 is not metadata");

    assert!(matches!(err, MetadataError::NotFound(404)), "{err:?}");
}

#[test]
fn a_document_that_is_not_a_secret_is_refused_on_its_kind() {
    let err = secret_metadata(&K8sReply {
        status: 200,
        body: br#"{"kind":"Pod","metadata":{"name":"api-0","namespace":"payments"}}"#.to_vec(),
    })
    .expect_err("a Pod is not a Secret");

    assert_eq!(
        err,
        MetadataError::NotASecret {
            kind: "Pod".to_string()
        },
        "{err:?}"
    );
}

#[test]
fn a_document_with_no_kind_at_all_is_refused() {
    // A `Status` object served with a 200 — which a proxy can do — has no
    // `kind` worth trusting. Defaulting it to "Secret" would be the worst
    // possible default.
    let err = secret_metadata(&K8sReply {
        status: 200,
        body: br#"{"metadata":{"name":"db-credentials","namespace":"payments"}}"#.to_vec(),
    })
    .expect_err("a document with no kind is not a Secret");

    assert_eq!(
        err,
        MetadataError::NotASecret {
            kind: "nothing".to_string()
        },
        "{err:?}"
    );
}

#[test]
fn a_body_that_is_not_json_is_refused_rather_than_half_read() {
    let err = secret_metadata(&K8sReply {
        status: 200,
        body: b"<html>502 Bad Gateway</html>".to_vec(),
    })
    .expect_err("an HTML error page is not metadata");

    assert!(matches!(err, MetadataError::Unreadable(_)), "{err:?}");
}

#[test]
fn a_secret_with_no_data_still_answers() {
    // An empty Secret is a real object and a real answer. Refusing it would
    // make "does this exist" and "is this populated" the same question, and
    // they are not.
    let metadata = secret_metadata(&K8sReply {
        status: 200,
        body: br#"{"kind":"Secret","metadata":{"name":"empty","namespace":"payments"},"data":{}}"#
            .to_vec(),
    })
    .expect("an empty Secret is a Secret");

    assert_eq!(metadata.name, "empty");
    assert_eq!(metadata.key_count(), 0);
}

#[test]
fn a_secret_with_no_data_member_at_all_answers_with_a_zero_count() {
    let metadata = secret_metadata(&K8sReply {
        status: 200,
        body: br#"{"kind":"Secret","metadata":{"name":"bare","namespace":"payments"}}"#.to_vec(),
    })
    .expect("a Secret with no data member is still a Secret");

    assert_eq!(metadata.key_count(), 0);
    assert_eq!(
        metadata.secret_type, "",
        "an absent type is empty, not guessed"
    );
}

/// # The positive rows

#[test]
fn a_reply_carrying_no_metadata_still_answers_rather_than_hanging_up() {
    // `metadata` is defaulted, so a Secret the API server answered with almost
    // nothing still produces an answer instead of an error. An operation that
    // has to distinguish "refused" from "answered with nothing" cannot do it
    // if the second one is a parse failure.
    let metadata = secret_metadata(&K8sReply {
        status: 200,
        body: br#"{"kind":"Secret"}"#.to_vec(),
    })
    .expect("a Secret with no metadata is still answered");

    assert_eq!(metadata.name, "");
    assert_eq!(metadata.namespace, "");
}

#[test]
fn a_filter_that_refused_every_secret_would_fail_these() {
    // The counterpart to the rows above, and why they are here. A filter that
    // returned an error for every well-formed document would pass every
    // refusal row in this file, and the only thing that catches it is a row
    // that demands an answer.
    let metadata = named("db-credentials");
    assert_eq!(metadata.name, "db-credentials");
    assert_eq!(metadata.key_count(), 3);
}
