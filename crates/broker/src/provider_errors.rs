//! The one rule every provider-facing error surface follows.
//!
//! A third party's error body is text a stranger wrote. A hostile or merely
//! misconfigured provider can put anything in it — including, as the audit's
//! H-05 measured, the client credential it was just shown, reflected in
//! `error_description`. So the rule, the same one the resource-server path
//! ([`crate::oauth2_binding`]) already follows when it reports a `Refused`
//! by status alone:
//!
//! **An error this broker reports about a provider carries broker-chosen
//! fields only. The status, which the broker itself observed; a code from the
//! closed vocabulary below, which the broker enumerates; and never the
//! provider's own text.**
//!
//! The token endpoint's error path ([`crate::oauth2::provider_rejected`]) and
//! the resource path share this module as the single point where that rule
//! lives, so the two cannot drift back apart without a test noticing.

/// The error codes this broker is willing to name from a token endpoint.
///
/// RFC 6749 §5.2 names six; `server_error` and `temporarily_unavailable`
/// (§4.1.2.1) are what real token endpoints answer when they are broken or
/// down, and `invalid_target` is the RFC 8707 refusal for an audience the
/// client may not ask a token for. The list is closed on purpose: `error` is
/// provider-controlled text like any other field, and a provider that
/// reflects a credential into it must not get a second route to the caller.
///
/// Anything else a provider sends in the `error` field collapses to
/// [`UNRECOGNIZED_ERROR`]: reported, bounded, and not the provider's word.
pub const TOKEN_ENDPOINT_ERROR_CODES: &[&str] = &[
    // RFC 6749 §5.2.
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    // RFC 6749 §4.1.2.1, as returned by token endpoints in practice.
    "server_error",
    "temporarily_unavailable",
    // RFC 8707 resource indicators.
    "invalid_target",
];

/// What a caller sees when the provider's `error` field was not one this
/// broker names: a refusal to relay the provider's word, not an empty code.
pub const UNRECOGNIZED_ERROR: &str = "unrecognized_error";

/// Maps a provider-supplied `error` field onto the closed vocabulary.
///
/// `None` (no field, an empty body, a body that is not a form at all) and any
/// unrecognized value both collapse to [`UNRECOGNIZED_ERROR`], so the space
/// of codes a caller can ever see is exactly [`TOKEN_ENDPOINT_ERROR_CODES`]
/// plus that one.
pub fn bounded_code(raw: Option<&str>) -> String {
    match raw.map(str::trim).filter(|code| !code.is_empty()) {
        Some(code) if TOKEN_ENDPOINT_ERROR_CODES.contains(&code) => code.to_string(),
        _ => UNRECOGNIZED_ERROR.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every vocabulary code survives; this is the property an operator's
    /// triage depends on, and it is also the list of strings that keeps the
    /// vocabulary from being widened by a provider.
    #[test]
    fn every_named_code_is_relayed_verbatim() {
        for code in TOKEN_ENDPOINT_ERROR_CODES {
            assert_eq!(&bounded_code(Some(code)), code);
        }
    }

    /// Anything else — an unknown extension, a reflected credential, an empty
    /// field, no field at all — collapses to the one refusal word.
    #[test]
    fn anything_else_collapses_to_the_refusal_word() {
        for raw in [
            Some("p ss+w&rd:"),
            Some("admin"),
            Some(""),
            Some("  "),
            None,
        ] {
            assert_eq!(bounded_code(raw), UNRECOGNIZED_ERROR, "{raw:?}");
        }
    }
}
