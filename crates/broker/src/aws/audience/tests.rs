//! Rows for the audience/region agreement.
//!
//! Most of them are about hosts that contain the right characters and are not
//! the endpoint, because that is the whole failure mode this module closes.

use asv_domain::{Authority, CredentialId};

use super::{
    is_global_sts, is_region_shaped, regional_sts_label, AudienceError, AwsDeployment,
    GLOBAL_STS_ENDPOINT,
};

fn authority(name: &str) -> Authority {
    Authority::canonicalize(name).expect("canonical authority")
}

fn deployment(audience: &str, region: &str) -> AwsDeployment {
    AwsDeployment {
        credential: CredentialId::from_wire("5f1c2a80-9d3e-4a77-b6c1-0e2f3a4b5c6d")
            .expect("a wire credential id"),
        audience: authority(audience),
        region: region.to_string(),
        role_arn: "arn:aws:iam::123456789012:role/demo".to_string(),
        role_session_name: "asv-session".to_string(),
        duration_seconds: 3600,
    }
}

// # The two shapes that are allowed

#[test]
fn the_global_endpoint_is_allowed_for_any_region() {
    // It is the region-agnostic one. That is what `STS_ENDPOINT` pins today and
    // what every existing deployment uses, so refusing it would break them
    // for a distinction they do not make.
    for region in ["us-east-1", "eu-west-1", "ap-southeast-2"] {
        deployment(GLOBAL_STS_ENDPOINT, region)
            .check_audience()
            .unwrap_or_else(|e| panic!("the global endpoint for {region}: {e}"));
    }
}

#[test]
fn a_regional_endpoint_is_allowed_for_exactly_its_own_region() {
    deployment("sts.eu-west-1.amazonaws.com", "eu-west-1")
        .check_audience()
        .expect("the region's own endpoint");
}

/// # The confused deputy

#[test]
fn a_regional_endpoint_for_another_region_is_refused() {
    // The signature would be bound to `eu-west-1` and the request would go to
    // `us-east-1`. The operator wrote both fields and produced a credential
    // used outside its scope.
    let err = deployment("sts.us-east-1.amazonaws.com", "eu-west-1")
        .check_audience()
        .expect_err("a regional endpoint for another region");

    assert_eq!(
        err,
        AudienceError::RegionMismatch {
            audience: authority("sts.us-east-1.amazonaws.com"),
            pinned: "us-east-1".to_string(),
            configured: "eu-west-1".to_string(),
        },
        "{err:?}"
    );
}

#[test]
fn the_refusal_names_both_regions() {
    // "Wrong region" sends an operator to check their credentials. Naming both
    // sides sends them to check the two lines of their own config, which is
    // where the answer is.
    let err = deployment("sts.us-east-1.amazonaws.com", "eu-west-1")
        .check_audience()
        .expect_err("mismatch");
    let rendered = format!("{err}");

    assert!(rendered.contains("us-east-1"), "the pinned one: {rendered}");
    assert!(
        rendered.contains("eu-west-1"),
        "the configured one: {rendered}"
    );
}

/// # The hosts that contain the right characters
///
/// These are the rows the module exists for. A `contains("sts.")` check, or an
/// `ends_with(".amazonaws.com")` on the prefix, passes every one of them.

#[test]
fn an_attacker_bucket_whose_name_contains_sts_is_refused() {
    // S3's virtual-hosted addressing puts a bucket name in the host, and a
    // bucket is something anyone can create. `mysts.s3.us-east-1.amazonaws.com`
    // contains "sts." and a real region, and is not STS.
    let hostile = "mysts.s3.us-east-1.amazonaws.com";
    let err = deployment(hostile, "us-east-1")
        .check_audience()
        .expect_err("an S3 bucket is not an STS endpoint");

    assert!(
        matches!(err, AudienceError::NotAnStsEndpoint { .. }),
        "{err:?}"
    );
    assert_eq!(regional_sts_label(&authority(hostile)), None);
}

#[test]
fn a_host_that_merely_ends_with_sts_is_refused() {
    // `evil-sts.eu-west-1.amazonaws.com` ends with the region and the AWS
    // suffix, and the prefix check has to be anchored to the *start* of the
    // name or the leading junk goes unnoticed.
    let hostile = "evil-sts.eu-west-1.amazonaws.com";
    assert_eq!(regional_sts_label(&authority(hostile)), None);
    assert!(deployment(hostile, "eu-west-1").check_audience().is_err());
}

#[test]
fn a_host_with_the_shape_before_a_foreign_suffix_is_refused() {
    // The suffix has to be the end of the name, not a fragment of it.
    let hostile = "sts.eu-west-1.amazonaws.com.attacker.example";
    assert_eq!(regional_sts_label(&authority(hostile)), None);
    assert!(deployment(hostile, "eu-west-1").check_audience().is_err());
}

#[test]
fn a_region_label_carrying_a_dot_is_not_a_label() {
    // `sts.x.eu-west-1.amazonaws.com` has a region that is two labels. A
    // comparison that split on the first dot would read the region as `x` and
    // match a deployment configured for `x`; one that split on the last would
    // read `eu-west-1` and match that. Neither is what the host means.
    let hostile = "sts.x.eu-west-1.amazonaws.com";
    assert_eq!(regional_sts_label(&authority(hostile)), None);
}

#[test]
fn an_empty_region_label_never_reaches_this_module() {
    // The first version of this row asserted that `sts..amazonaws.com` is
    // refused, on the assumption that the label check was what refused it. It
    // is not: `Authority::canonicalize` refuses a name with an empty label, so
    // the host cannot be constructed at all. The row is kept and rewritten
    // because knowing *which layer* closes a case is the difference between a
    // check you can reason about and one you are relying on by luck — and a
    // future loosening of `Authority` would leave the label check here as the
    // only thing standing there.
    assert_eq!(regional_sts_label(&authority(GLOBAL_STS_ENDPOINT)), None);
    assert!(
        Authority::canonicalize("sts..amazonaws.com").is_err(),
        "an empty label must not be constructible as an authority"
    );
}

/// # What is not an STS endpoint at all

#[test]
fn a_first_party_api_that_is_not_sts_is_refused() {
    // GitHub is in the same allowlist. Being first-party is not the question;
    // being the endpoint this deployment's credential scope belongs to is.
    let err = deployment("api.github.com", "us-east-1")
        .check_audience()
        .expect_err("GitHub is not STS");

    assert!(
        matches!(err, AudienceError::NotAnStsEndpoint { .. }),
        "{err:?}"
    );
    assert!(
        format!("{err}").contains("sts."),
        "the refusal names the shapes: {err}"
    );
}

/// # The region is validated first
///
/// The order is the property. A region containing a dot would turn a
/// whole-label comparison into a substring one.

#[test]
fn a_region_that_is_not_shaped_like_one_is_refused_before_the_audience_is_read() {
    // `evil.example` as a region would make `sts.evil.example.amazonaws.com` a
    // match if the audience were compared first.
    for region in [
        "",
        "eu west 1",
        "eu.west.1",
        "EU-WEST-1",
        "eu-west-1/x",
        "a",
    ] {
        let err = deployment(GLOBAL_STS_ENDPOINT, region)
            .check_audience()
            .expect_err("not a region");
        assert!(
            matches!(err, AudienceError::NotARegion { .. }),
            "{region:?}: got {err:?}"
        );
    }
}

#[test]
fn a_region_with_a_dot_is_refused_even_when_the_audience_would_match() {
    let err = deployment("sts.evil.eu-west-1.amazonaws.com", "evil.eu-west-1")
        .check_audience()
        .expect_err("a region with a dot is refused first");
    assert!(matches!(err, AudienceError::NotARegion { .. }), "{err:?}");
}

#[test]
fn the_real_region_shapes_are_accepted() {
    for region in [
        "us-east-1",
        "eu-west-1",
        "ap-southeast-2",
        "us-gov-west-1",
        "cn-north-1",
        "il-central-1",
    ] {
        assert!(is_region_shaped(region), "{region} is a real region");
    }
}

/// # The positive rows
//
// A check that refused everything would pass every refusal above.

#[test]
fn a_check_that_refused_everything_would_fail_these() {
    assert!(is_global_sts(&authority(GLOBAL_STS_ENDPOINT)));
    assert!(!is_global_sts(&authority("sts.eu-west-1.amazonaws.com")));
    assert_eq!(
        regional_sts_label(&authority("sts.eu-west-1.amazonaws.com")),
        Some("eu-west-1")
    );
    assert_eq!(regional_sts_label(&authority("sts.amazonaws.com")), None);
    deployment(GLOBAL_STS_ENDPOINT, "us-east-1")
        .check_audience()
        .expect("the global endpoint");
    deployment("sts.eu-west-1.amazonaws.com", "eu-west-1")
        .check_audience()
        .expect("the region's own endpoint");
}
