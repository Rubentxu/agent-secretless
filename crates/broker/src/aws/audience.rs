//! R2.C.5 — the audience and the region may not disagree.
//!
//! [`AwsDeployment`] carries a `region` and
//! an `audience` as two independent fields, and the credential scope is built
//! from one while the request goes to the other. AWS accepts that — the global
//! endpoint routes by the region in the signature — which is exactly what makes
//! it dangerous here: the operator believes they pinned something, and what
//! they pinned is not tied to what they sign for.
//!
//! # The property
//!
//! **A deployment signs for a region and talks to the endpoint for that region,
//! or to the global one.** Those are the two shapes, and nothing else.
//!
//! Not "an audience that mentions the region" — the *whole label* has to be it.
//! Every one of the following is a host that contains the right characters and
//! is not the endpoint:
//!
//! - `evil-sts.eu-west-1.amazonaws.com` — the region is not a label of its own;
//! - `sts.eu-west-1.amazonaws.com.attacker.example` — the suffix is not the end;
//! - `mysts.s3.us-east-1.amazonaws.com` — **an attacker's own S3 bucket**, whose
//!   name makes the host contain `sts.` and a real region.
//!
//! That third one is the reason this is not a `contains` check. S3's
//! virtual-hosted addressing puts a bucket name in the host, and a bucket is
//! something anyone can create.
//!
//! # What this does not decide
//!
//! Whether a regional endpoint is *approved* is the policy crate's question,
//! and `asv_policy::audience_is_approved` still lists only the global endpoint.
//! That half of the open item is a change to that function's contract — it needs
//! the region passed alongside the audience — and it is **not** made here,
//! because the honest statement is that this module makes the deployment
//! self-consistent and does not make a regional endpoint reachable. A
//! deployment pinned to a regional endpoint will load, sign correctly for its
//! region, and then be refused by policy until the other half lands. That is
//! the correct order: the refusal is loud, and it is the policy crate's
//! decision to make rather than something a broker should quietly widen.

use asv_domain::Authority;

use crate::aws_binding::AwsDeployment;

/// The host AWS serves STS from, regardless of region.
pub const GLOBAL_STS_ENDPOINT: &str = "sts.amazonaws.com";

/// The label AWS puts between `sts.` and `.amazonaws.com` on a regional
/// endpoint. Not a constant that is ever compared — it is documentation of the
/// shape, and [`regional_sts_label`] is the only thing that parses it.
const REGIONAL_STS_PREFIX: &str = "sts.";
const AWS_SUFFIX: &str = ".amazonaws.com";

/// Why a deployment's audience does not match the region it signs for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudienceError {
    /// The audience is neither the global endpoint nor a regional one.
    ///
    /// The message names the two shapes that would have been accepted, because
    /// an operator who has pinned a host by hand and is told "not an STS
    /// endpoint" will not guess which of the two they meant.
    #[error(
        "audience {audience} is neither {GLOBAL_STS_ENDPOINT} nor \
         sts.<region>{AWS_SUFFIX}; a deployment signs for one region and talks \
         to that region's endpoint or the global one"
    )]
    NotAnStsEndpoint {
        /// The audience as it was declared.
        audience: Authority,
    },

    /// A regional endpoint for a region this deployment does not sign for.
    ///
    /// This is the confused-deputy refusal: the signature is bound to
    /// `configured` and the request would go to `pinned`, and the operator who
    /// wrote both has produced a credential scoped to somewhere it is not
    /// being used.
    #[error(
        "audience {audience} is the {pinned} endpoint, but this deployment \
         signs for {configured}; a request signed for one region and sent to \
         another is a credential used outside its scope"
    )]
    RegionMismatch {
        /// The audience that was declared.
        audience: Authority,
        /// The region in that audience.
        pinned: String,
        /// The region the credential scope is built from.
        configured: String,
    },

    /// The region is not shaped like a region.
    ///
    /// Checked *before* the audience is compared, and that order is the point.
    /// A region string containing a dot would otherwise turn a whole-label
    /// match into a substring match, because `sts.<region>.amazonaws.com` would
    /// match across the dot it introduced.
    #[error("region {region:?} is not shaped like an AWS region")]
    NotARegion {
        /// The region as it was declared.
        region: String,
    },
}

/// The region label of a regional STS endpoint, if the audience is exactly one.
///
/// Returns `None` for the global endpoint, for anything that is not
/// `sts.<one label>.amazonaws.com`, and — the case the whole module is about —
/// for a host that merely *contains* that shape.
pub fn regional_sts_label(audience: &Authority) -> Option<&str> {
    let name = audience.as_str();

    let rest = name.strip_prefix(REGIONAL_STS_PREFIX)?;
    let label = rest.strip_suffix(AWS_SUFFIX)?;

    // Exactly one label. `evil-sts.eu-west-1` leaves `evil-sts` after the
    // prefix is stripped only if the prefix matched, so the prefix check above
    // already rules out the leading-junk case; what is left is a label that
    // still contains a dot, which is the `sts.x.evil.amazonaws.com` shape and
    // the `mysts.s3.eu-west-1.amazonaws.com` one.
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label)
}

/// Whether the audience is the region-agnostic endpoint.
pub fn is_global_sts(audience: &Authority) -> bool {
    audience.as_str() == GLOBAL_STS_ENDPOINT
}

/// Whether a region is shaped like one.
///
/// Deliberately strict and deliberately hand-rolled. AWS's own grammar is
/// `[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d+` plus the `us-iso*` and `eusc-*`
/// variants that appear over time, and a parser that tracks that list goes
/// stale the same way a static endpoint list does — which is the problem this
/// whole item exists to avoid. What matters for the property above is not
/// whether AWS will accept the name but whether it can smuggle a dot, a slash
/// or a label boundary into a whole-label comparison.
pub fn is_region_shaped(region: &str) -> bool {
    if region.is_empty() || region.len() > 32 {
        return false;
    }
    // Lowercase alphanumerics in dash-separated parts, and at least one part
    // ending in a digit.
    //
    // There is no "at least two parts" rule here any more. The falsification
    // campaign filed the mutation that removes it and got a survivor, which
    // meant the other two rules were carrying it: every single-part region it
    // was written to catch -- "a", "eu west 1", "eu.west.1" -- fails either
    // the character set or the digit rule. A check that never changes an answer
    // is a second way to say something, and the bucket validator in
    // `aws::s3` lost an arm to the same finding.
    let parts: Vec<&str> = region.split('-').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    {
        return false;
    }
    parts.iter().any(|part| part.ends_with(|b: char| b.is_ascii_digit()))
}

impl AwsDeployment {
    /// Checks that the audience is one this region's credential may be sent to.
    ///
    /// Called before a deployment is wired into a binding, so an
    /// inconsistent deployment is a load-time refusal rather than a signature
    /// computed for one region and sent to another.
    pub fn check_audience(&self) -> Result<(), AudienceError> {
        if !is_region_shaped(&self.region) {
            return Err(AudienceError::NotARegion {
                region: self.region.clone(),
            });
        }
        if is_global_sts(&self.audience) {
            return Ok(());
        }
        match regional_sts_label(&self.audience) {
            Some(label) if label == self.region => Ok(()),
            Some(label) => Err(AudienceError::RegionMismatch {
                audience: self.audience.clone(),
                pinned: label.to_string(),
                configured: self.region.clone(),
            }),
            None => Err(AudienceError::NotAnStsEndpoint {
                audience: self.audience.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
