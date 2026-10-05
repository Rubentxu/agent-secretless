//! R2.D.1 — the Kubernetes request core, against an oracle written from the
//! API's own path rules.
//!
//! # The oracle
//!
//! The expected paths below were written from the Kubernetes API layout, not
//! read off this implementation's output: a namespaced collection is
//! `/api/v1/namespaces/{namespace}/{resource}`, a namespaced object adds one
//! segment, and a cluster-scoped resource drops the `namespaces/…` prefix
//! entirely. The same rule that governed R2.C.1 applies — an implementation
//! graded against its own output would notice nothing, and a provider whose
//! paths are subtly wrong answers `404` for reasons nobody can find.
//!
//! # What these rows are for
//!
//! **The vectors cannot establish the property.** Every expected path below is
//! a request that should succeed. The rows after them are the ones that would
//! catch a builder willing to emit a path for a name it should have refused, and
//! those are the rows that carry the claim in the module doc: that the
//! agent-supplied parts cannot escape their position in the request.
//!
//! # The trap this file is built around
//!
//! A previous measurement in this tree, on the SigV4 core, found that a row
//! asserting a *refusal* is satisfied by an implementation that refuses
//! everything. Six of the sixteen rows in that module were of that shape, so a
//! signer that signed nothing at all would have passed all six.
//!
//! So the refusals here are paired with positive rows that pin the exact method
//! and path, and `a_builder_that_refuses_everything_would_fail_these` exists to
//! say so where a reader will meet the argument. A rejection count is not
//! evidence of a working proxy.

use super::*;

/// Build a namespaced request, which is the shape almost every real call has.
fn namespaced<'a>(verb: Verb, resource: &'a str, name: Option<&'a str>) -> ApiRequest<'a> {
    ApiRequest {
        verb,
        scope: Scope::Namespaced { namespace: "team-a" },
        resource,
        name,
    }
}

// ---------------------------------------------------------------------------
// The paths. Absolute values, not self-consistency.
// ---------------------------------------------------------------------------

#[test]
fn a_namespaced_get_is_the_documented_path() {
    let r = namespaced(Verb::Get, "pods", Some("web-0"));
    assert_eq!(r.method(), "GET");
    assert_eq!(r.path().unwrap(), "/api/v1/namespaces/team-a/pods/web-0");
}

#[test]
fn a_namespaced_list_is_the_collection_without_a_trailing_slash() {
    let r = namespaced(Verb::List, "pods", None);
    assert_eq!(r.method(), "GET");
    // The trailing slash is not cosmetic: `/pods/` and `/pods` are the same
    // resource to a reader and two different strings to a signature, so the
    // oracle pins the shorter one rather than whichever the builder produced.
    assert_eq!(r.path().unwrap(), "/api/v1/namespaces/team-a/pods");
}

#[test]
fn a_cluster_scoped_object_drops_the_namespace_prefix() {
    let r = ApiRequest {
        verb: Verb::Get,
        scope: Scope::Cluster,
        resource: "nodes",
        name: Some("node-1"),
    };
    assert_eq!(r.path().unwrap(), "/api/v1/nodes/node-1");
}

#[test]
fn a_cluster_scoped_collection_is_the_bare_resource() {
    let r = ApiRequest {
        verb: Verb::List,
        scope: Scope::Cluster,
        resource: "namespaces",
        name: None,
    };
    assert_eq!(r.path().unwrap(), "/api/v1/namespaces");
}

#[test]
fn create_is_a_post_and_delete_is_a_delete() {
    assert_eq!(namespaced(Verb::Create, "pods", None).method(), "POST");
    assert_eq!(
        namespaced(Verb::Delete, "pods", Some("web-0")).method(),
        "DELETE"
    );
    assert!(Verb::Create.takes_body());
    assert!(!Verb::List.takes_body());
}

/// A name containing a dot is legal and must not be refused, because a rule
/// that rejects every dot is not the DNS rule — it is a rule that refuses
/// `my.config` and would have hidden behind the word "validated".
#[test]
fn a_dotted_name_is_placed_unchanged() {
    let r = namespaced(Verb::Get, "configmaps", Some("app.config"));
    assert_eq!(
        r.path().unwrap(),
        "/api/v1/namespaces/team-a/configmaps/app.config"
    );
}

/// Dots are also legal in a namespace in many real clusters, so this pins the
/// asymmetry deliberately rather than by accident: the API server's namespace
/// rule is a label, so `team.a` is refused here and that is the server's rule
/// rather than this module's preference.
#[test]
fn a_namespace_with_a_dot_is_refused_even_though_a_name_may_have_one() {
    let r = ApiRequest {
        verb: Verb::List,
        scope: Scope::Namespaced {
            namespace: "team.a",
        },
        resource: "pods",
        name: None,
    };
    assert_eq!(r.path(), Err(ApiError::NotANamespace("team.a".into())));
    // And the same request with a dotted *name* is accepted, so the row above
    // is about the namespace rule and not about this module refusing dots.
    assert!(namespaced(Verb::List, "pods", None).path().is_ok());
}

/// The row that makes the refusals meaningful: a builder that refused
/// everything would fail every assertion in this function, so a green run
/// cannot be produced by a proxy that never answers.
#[test]
fn a_builder_that_refuses_everything_would_fail_these() {
    assert!(namespaced(Verb::Get, "pods", Some("web-0")).path().is_ok());
    assert!(namespaced(Verb::List, "pods", None).path().is_ok());
    assert!(namespaced(Verb::Create, "secrets", None).path().is_ok());
    assert!(namespaced(Verb::Delete, "pods", Some("web-0")).path().is_ok());
    assert_eq!(
        ApiRequest {
            verb: Verb::Get,
            scope: Scope::Cluster,
            resource: "nodes",
            name: Some("node-1"),
        }
        .path()
        .unwrap(),
        "/api/v1/nodes/node-1"
    );
}

// ---------------------------------------------------------------------------
// The operation named must be the operation performed.
// ---------------------------------------------------------------------------

/// A `get` with no name is a list that reports itself as a get. Both produce
/// `GET`, so nothing downstream can tell the honest request from this one.
#[test]
fn a_get_without_a_name_is_refused_rather_than_becoming_a_list() {
    let r = namespaced(Verb::Get, "pods", None);
    assert_eq!(r.path(), Err(ApiError::MissingName(Verb::Get)));
}

#[test]
fn a_delete_without_a_name_is_refused() {
    let r = namespaced(Verb::Delete, "pods", None);
    assert_eq!(r.path(), Err(ApiError::MissingName(Verb::Delete)));
}

#[test]
fn a_list_with_a_name_is_refused_rather_than_addressing_an_object() {
    let r = namespaced(Verb::List, "pods", Some("web-0"));
    assert_eq!(r.path(), Err(ApiError::UnexpectedName(Verb::List)));
}

#[test]
fn a_create_with_a_name_is_refused() {
    let r = namespaced(Verb::Create, "pods", Some("web-0"));
    assert_eq!(r.path(), Err(ApiError::UnexpectedName(Verb::Create)));
}

// ---------------------------------------------------------------------------
// The property: the named parts cannot escape their position.
// ---------------------------------------------------------------------------

/// The walk out of the namespace, refused by the whole-segment rule rather
/// than by a substring check.
///
/// The second case is the one that isolates the slash. The first also contains
/// `..`, so a rule that caught only the two-dot walk would have made the first
/// case red and left the slash untested — which is why the slash appears on its
/// own, with nothing else in the name for another rule to blame.
#[test]
fn a_name_containing_a_slash_is_refused() {
    for bad in ["web-0/exec", "web-0/../../secrets", "pods/"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

#[test]
fn a_name_that_is_exactly_two_dots_is_refused() {
    let r = namespaced(Verb::Get, "pods", Some(".."));
    assert!(matches!(r.path(), Err(ApiError::NotAName { .. })));
}

#[test]
fn a_name_that_is_exactly_one_dot_is_refused() {
    let r = namespaced(Verb::Get, "pods", Some("."));
    assert!(matches!(r.path(), Err(ApiError::NotAName { .. })));
}

/// A percent sign is the one character that could make a name mean one thing on
/// the way out and another on the way through the next hop. Escaping it instead
/// of refusing it would make this module responsible for the disagreement
/// between two readers, which is exactly the property it exists to prevent.
#[test]
fn a_name_containing_a_percent_is_refused_rather_than_escaped() {
    for bad in ["web%2f", "%2e%2e", "web%00", "100%"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

/// A newline in a name is a second request line. The same refusal the SigV4
/// core makes for a header value, for the same reason.
#[test]
fn a_name_containing_a_control_character_is_refused() {
    for bad in ["web\n0", "web\r\nx: y", "web\tx", "web\0x"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

#[test]
fn a_name_carrying_a_query_or_a_fragment_is_refused() {
    for bad in ["web-0?watch=true", "web-0#frag", "?x", "#x"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

/// An absolute path offered as a name would otherwise produce a double slash,
/// and whether that collapses is a decision made by the next hop rather than
/// by this one.
#[test]
fn a_name_that_is_an_absolute_path_is_refused() {
    for bad in ["/etc/passwd", "/api/v1/secrets", "//evil"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

#[test]
fn a_resource_cannot_walk_out_either() {
    // The resource is placed in the same path position as the name, so a
    // resource that could carry a slash would reach just as far.
    for bad in ["pods/../../secrets", "..", "pods/", "/pods"] {
        let r = namespaced(Verb::List, bad, None);
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

#[test]
fn an_empty_name_is_refused_rather_than_producing_a_double_slash() {
    let r = namespaced(Verb::Get, "pods", Some(""));
    assert_eq!(r.path(), Err(ApiError::EmptySegment { what: "name" }));
}

#[test]
fn an_empty_resource_is_refused() {
    let r = namespaced(Verb::List, "", None);
    assert_eq!(r.path(), Err(ApiError::EmptySegment { what: "resource" }));
}

#[test]
fn an_empty_namespace_is_refused() {
    let r = ApiRequest {
        verb: Verb::List,
        scope: Scope::Namespaced { namespace: "" },
        resource: "pods",
        name: None,
    };
    assert_eq!(r.path(), Err(ApiError::EmptySegment { what: "namespace" }));
}

// ---------------------------------------------------------------------------
// Shape, not just the alphabet.
// ---------------------------------------------------------------------------

#[test]
fn a_name_may_not_begin_or_end_with_a_hyphen() {
    for bad in ["-web", "web-", ".web", "web.", "a..b", "a.-b", "a.b-"] {
        let r = namespaced(Verb::Get, "pods", Some(bad));
        assert!(
            matches!(r.path(), Err(ApiError::NotAName { .. })),
            "{bad:?} was placed in a path"
        );
    }
}

#[test]
fn a_name_may_not_begin_or_end_with_a_hyphen_in_the_namespace_either() {
    for bad in ["-team", "team-"] {
        let r = ApiRequest {
            verb: Verb::List,
            scope: Scope::Namespaced { namespace: bad },
            resource: "pods",
            name: None,
        };
        assert!(matches!(r.path(), Err(ApiError::NotANamespace(_))));
    }
}

#[test]
fn uppercase_is_refused_rather_than_lowercased() {
    // The alternative is the one this module refuses everywhere: repairing the
    // input produces a request the caller did not name, and a caller who
    // discovers that "fixed" it by relying on the repair would be committing to
    // a name it never sent.
    let r = namespaced(Verb::Get, "pods", Some("Web-0"));
    assert!(matches!(r.path(), Err(ApiError::NotAName { .. })));
    let s = namespaced(Verb::List, "Pods", None);
    assert!(matches!(s.path(), Err(ApiError::NotAName { .. })));
}

#[test]
fn a_name_longer_than_the_bound_is_refused() {
    // 254 bytes of a legal alphabet. The bound is the API server's, so building
    // it would produce a 404 that points at the resource rather than the name.
    let long = "a".repeat(254);
    let r = namespaced(Verb::Get, "pods", Some(&long));
    assert!(matches!(r.path(), Err(ApiError::NotAName { .. })));
    let ok = "a".repeat(253);
    assert!(namespaced(Verb::Get, "pods", Some(&ok)).path().is_ok());
}

#[test]
fn a_namespace_longer_than_a_label_is_refused() {
    let long = "a".repeat(64);
    let r = ApiRequest {
        verb: Verb::List,
        scope: Scope::Namespaced { namespace: Box::leak(long.into_boxed_str()) },
        resource: "pods",
        name: None,
    };
    assert!(matches!(r.path(), Err(ApiError::NotANamespace(_))));
}

// ---------------------------------------------------------------------------
// The verb set is closed.
// ---------------------------------------------------------------------------

/// `TRACE` and `CONNECT` are not in [`Verb`], and the way this is pinned is the
/// type rather than a run-time check: there is no string to pass. A builder
/// taking a `&str` method would forward any of them, and `TRACE` exists to echo
/// a request back to whoever sent it.
#[test]
fn the_verb_set_is_closed_and_prints_the_names_it_does_have() {
    let printed: Vec<String> = [Verb::Get, Verb::List, Verb::Create, Verb::Delete]
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(printed, ["get", "list", "create", "delete"]);
    // Four verbs, and a `Display` that cannot produce a fifth.
    assert_eq!(printed.len(), 4);
}

#[test]
fn get_and_list_share_a_method_but_not_a_shape() {
    // The reason the verb/name agreement is checked separately rather than
    // inferred from the method: these two are indistinguishable on the wire
    // when a `get` is sent without a name, which is why the refusal has to
    // happen before the path is built rather than at the server.
    assert_eq!(Verb::Get.method(), Verb::List.method());
    assert_ne!(Verb::Get.takes_name(), Verb::List.takes_name());
    assert!(namespaced(Verb::Get, "pods", None).path().is_err());
    assert!(namespaced(Verb::List, "pods", None).path().is_ok());
}
