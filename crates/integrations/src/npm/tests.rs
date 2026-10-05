//! The npm family's rows.
//!
//! The one that matters most is [`the_serialised_report_contains_no_credential`]:
//! everything else here describes *what* was found, and that one asserts the
//! property the whole crate is built to hold. It is asserted against the
//! serialised JSON rather than against the struct on purpose — a claim about
//! the fields written today is not a claim about what a caller receives, and
//! what a caller receives is what reaches a terminal, a log and an agent's
//! context.

use super::*;

const TOKEN: &str = "npm_AbCdEf0123456789XyZ";

fn npmrc_with_token() -> String {
    format!("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={TOKEN}\n")
}

fn fingerprint_for(path: &str) -> crate::fingerprint::FileFingerprint {
    crate::fingerprint::FileFingerprint {
        path: path.into(),
        resolved_path: path.into(),
        inode: 1,
        owner_uid: 1000,
        mode: 0o600,
        size: 0,
        digest: "sha256:0".into(),
    }
}

fn one_file(parsed: Parsed) -> NpmDiscovery {
    NpmDiscovery {
        files: vec![NpmFile {
            origin: Origin::Project,
            fingerprint: fingerprint_for("/home/u/.npmrc"),
            registry: parsed.registry,
            scoped_registries: parsed.scoped_registries,
            auth_selectors: parsed.auth_selectors,
            settings: parsed.settings,
        }],
    }
}

/// **The property this whole crate exists to hold, asserted against the
/// serialised report rather than against the struct.**
///
/// A field added tomorrow, a derived `Debug`, a flattened nested struct — none
/// of them can leak through this assertion. A struct-shape assertion could be
/// satisfied by the types I happened to write and would say nothing about the
/// next edit.
#[test]
fn the_serialised_report_contains_no_credential() {
    let discovery = one_file(parse(&npmrc_with_token()).expect("parses"));
    // Assert on the selector *before* serialising, in a scope of its own:
    // `into_discovery` consumes the value, and a row that re-parsed after the
    // move would be measuring a second object rather than the one it printed.
    // And the selector is genuinely described, so this row is not passing
    // because the report happens to be empty.
    {
        assert_eq!(discovery.files[0].auth_selectors.len(), 1);
        let selector = &discovery.files[0].auth_selectors[0];
        assert_eq!(selector.field, AuthField::AuthToken);
        assert_eq!(selector.registry.audience.to_string(), "registry.npmjs.org");
        assert_eq!(selector.value_len, TOKEN.len());
    }
    let json = serde_json::to_string(&discovery.into_discovery()).expect("serialises");
    assert!(
        !json.contains(TOKEN),
        "the token reached the report: {json}"
    );
}

/// `Debug` is a different code path from `Serialize`, and a report that is safe
/// in JSON routinely is not in a log line. They have gone their separate ways
/// before, so they are asserted separately.
#[test]
fn the_debug_rendering_contains_no_credential_either() {
    let rendered = format!("{:?}", parse(&npmrc_with_token()).expect("parses"));
    assert!(
        !rendered.contains(TOKEN),
        "the token reached Debug: {rendered}"
    );
}

/// The reason the field is read after the **last** colon rather than the first:
/// a local registry on a port is an ordinary line for anyone running verdaccio,
/// and splitting on the first colon would read its host as `localhost` and its
/// port as the field name.
#[test]
fn a_local_registry_on_a_port_keeps_its_port() {
    let parsed = parse("//localhost:4873/:_authToken=abc123\n").expect("parses");
    let selector = &parsed.auth_selectors[0];
    assert_eq!(selector.registry.audience.to_string(), "localhost:4873");
    assert_eq!(selector.field, AuthField::AuthToken);
    assert_eq!(selector.registry.path_prefix, "/");
}

/// `path_prefix` is load-bearing for a later binding: a selector for one path
/// does not cover another, and a report that dropped it would let `plan` bind
/// a credential to a wider audience than npm would actually send it to.
#[test]
fn an_auth_selector_is_scoped_to_its_path() {
    let parsed = parse("//registry.example.test/npm/:_authToken=abc123\n").expect("parses");
    assert_eq!(parsed.auth_selectors[0].registry.path_prefix, "/npm/");
    assert_eq!(
        parsed.auth_selectors[0].registry.audience.to_string(),
        "registry.example.test"
    );
}

#[test]
fn an_env_reference_is_reported_by_name_and_never_read() {
    // The variable is **set**, and to a value of a different length, because a
    // read of an absent variable is indistinguishable from no read at all. The
    // first version of this row left it unset: a parser that resolved the
    // environment got `None`, fell back to the literal, and reported the right
    // number for the wrong reason. The campaign caught that as a survivor, and
    // it is the reason a mutation that touches `std::env` is only meaningful
    // here with something to resolve.
    //
    // Setting an environment variable is process-wide and the test harness runs
    // these rows on parallel threads. That is only sound because nothing else
    // in this test binary reads the environment: `env_reference` matches on the
    // literal text, so this is the only `getenv` in the process, and removing
    // the variable afterwards leaves the next row the same environment it
    // started with.
    const NAME: &str = "ASV_TEST_NPM_TOKEN_MUST_NOT_BE_READ";
    const CANARY: &str = "resolved-value-of-an-entirely-different-length";
    std::env::set_var(NAME, CANARY);
    let parsed = parse(&format!(
        "//registry.example.test/:_authToken=${{{NAME}}}\n"
    ))
    .expect("parses");
    std::env::remove_var(NAME);

    let selector = &parsed.auth_selectors[0];
    assert!(selector.value_is_env_reference);
    assert_eq!(selector.env_reference.as_deref(), Some(NAME));
    // The length is of `${ASV_TEST_NPM_TOKEN_MUST_NOT_BE_READ}`, because that
    // is what the file contains -- and the canary is a different length, so
    // resolving it would change this number.
    assert_eq!(selector.value_len, format!("${{{NAME}}}").len());
    assert_ne!(
        selector.value_len,
        CANARY.len(),
        "the canary and the literal must differ in length, or the row cannot tell"
    );
}

#[test]
fn an_interpolation_that_is_not_a_single_name_is_not_treated_as_one() {
    for value in ["${A}${B}", "${}", "${A-B}", "prefix${A}"] {
        let parsed =
            parse(&format!("//registry.example.test/:_authToken={value}\n")).expect("parses");
        let selector = &parsed.auth_selectors[0];
        assert_eq!(
            selector.env_reference, None,
            "{value:?} was reported as a variable name"
        );
        assert!(!selector.value_is_env_reference, "{value:?}");
    }
}

/// Not a warning. Following an `include` would describe a file the operator did
/// not name, and `plan` cannot revalidate what `discover` never read.
#[test]
fn an_include_directive_refuses_the_whole_file() {
    let error = parse("include=/etc/npm/extra\nregistry=https://a.test/\n")
        .expect_err("include refuses the file");
    assert!(
        matches!(error, ParseError::IncludeRefused { at_line: 1 }),
        "{error}"
    );
}

/// A typo npm ignores. Dropping the line would leave an operator believing no
/// credential is configured, when the truth is that one is and it is
/// misspelled.
///
/// The first version of this row asserted the selector list was **empty**, and
/// it failed — correctly, and for a better reason than the one it was written
/// for. The parser does not drop the key: it records it as
/// [`AuthField::Unrecognised`], so the report names the misspelling. An empty
/// list and a list holding an unrecognised field look the same to a reader who
/// only counts entries, and only one of them tells the operator their
/// configuration is broken. The assertion is on the field, not on an absence.
#[test]
fn an_unrecognised_auth_field_is_reported_rather_than_dropped() {
    let parsed = parse("//registry.example.test/:_authTokne=abc123\n").expect("parses");
    assert_eq!(
        parsed.auth_selectors.len(),
        1,
        "the key vanished from the report"
    );
    assert_eq!(
        parsed.auth_selectors[0].field,
        AuthField::Unrecognised("_authTokne".to_string()),
        "the report must name the field as misspelled rather than as a known one"
    );
    assert_eq!(
        parsed.auth_selectors[0].registry.audience.host(),
        "registry.example.test"
    );
}

/// Nothing downstream may act on an audience this tool could not verify, and an
/// operator has to be told which line is wrong.
#[test]
fn a_registry_that_will_not_canonicalize_becomes_a_finding_and_not_an_audience() {
    let parsed = parse("//not a host/:_authToken=abc123\n").expect("parses");
    assert!(
        parsed.auth_selectors.is_empty(),
        "an unverified host must not reach the typed list"
    );
    assert_eq!(parsed.findings.len(), 1);
    assert_eq!(parsed.findings[0].severity, Severity::Warning);
    assert!(
        parsed.findings[0].message.contains("not a host"),
        "the finding does not name the host: {:?}",
        parsed.findings[0]
    );
}

/// The honest absence. Substituting the public registry would produce a report
/// indistinguishable from a real observation, which is the one thing a report
/// about credentials cannot be.
#[test]
fn no_registry_is_invented_for_a_file_that_declares_none() {
    let parsed = parse("//registry.example.test/:_authToken=abc\n").expect("parses");
    assert_eq!(parsed.registry, None);
}

#[test]
fn a_scoped_registry_is_canonicalized_like_any_other() {
    let parsed = parse("@acme:registry=https://npm.acme.test/\n").expect("parses");
    assert_eq!(parsed.scoped_registries[0].scope, "@acme");
    assert_eq!(
        parsed.scoped_registries[0].registry.audience.to_string(),
        "npm.acme.test"
    );
}

/// npm splits on the **first** `=`, so a URL with a query string is ordinary.
/// Splitting on the last one would silently rewrite the audience.
#[test]
fn a_value_containing_equals_is_kept_whole() {
    let parsed = parse("registry=https://registry.example.test/?token=abc\n").expect("parses");
    assert_eq!(
        parsed.registry.expect("a registry is set").url,
        "https://registry.example.test/?token=abc"
    );
}

/// The setting a parser does not model is recorded as **present and
/// undescribed**, which is a different report from "there is nothing here".
///
/// This row exists because two mutations survived against a different one. Both
/// of them attack the tail of `parse_line` -- the branch that records a key
/// whose value is neither a known-safe setting nor a credential -- and the row
/// they were aimed at used an `//`-prefixed key, which returns long before
/// that branch: an unrecognised *auth field* is reported as
/// `AuthField::Unrecognised`, and never becomes a `SettingValue` at all. Two
/// rows that both end in the word "unrecognised" and neither measure the other's
/// code is exactly how a property ends up looking covered.
///
/// The three claims here are the ones the branch can get wrong: the key is
/// there, its value is a length, and the length is not the value.
#[test]
fn an_unmodelled_setting_is_reported_by_length_and_never_by_value() {
    const SECRET: &str = "hunter2-the-password-nobody-modelled";
    let parsed = parse(&format!("some-unknown-setting={SECRET}\n")).expect("parses");
    assert!(
        parsed.settings.contains_key("some-unknown-setting"),
        "an unmodelled key must be reported as present, not dropped: {:?}",
        parsed.settings
    );
    assert_eq!(
        parsed.settings["some-unknown-setting"],
        SettingValue::Opaque { len: SECRET.len() },
        "an unmodelled value is a length, because this parser does not know \
         whether it is a credential"
    );
    let json = serde_json::to_string(&parsed.settings).expect("serialises");
    assert!(!json.contains(SECRET), "the value reached JSON: {json}");
}

#[test]
fn comments_blank_lines_and_sections_are_handled() {
    let parsed = parse("; a comment\n# another\n\n[scope]\nkey=value\n").expect("parses");
    // The section qualifies the key inside it, so this is `scope:key` and not a
    // top-level setting named `key`.
    assert!(
        parsed.settings.contains_key("scope:key"),
        "{:?}",
        parsed.settings
    );
}

/// Reporting the keys that did parse would be a report that reads complete,
/// about a file whose meaning this parser does not have.
#[test]
fn a_line_that_is_not_a_key_value_refuses_the_file() {
    let error = parse("registry=https://a.test/\ngarbage\n").expect_err("refused");
    assert!(
        matches!(error, ParseError::NotAKeyValue { at_line: 2 }),
        "{error}"
    );
}

#[test]
fn an_absurdly_long_key_is_refused_rather_than_reported() {
    let key = "a".repeat(600);
    let error = parse(&format!("{key}=v\n")).expect_err("refused");
    match error {
        ParseError::KeyTooLong { at_line, limit, .. } => {
            assert_eq!(at_line, 1);
            assert_eq!(limit, MAX_KEY_BYTES);
        }
        other => panic!("{other}"),
    }
}

/// `_auth` is base64 of `user:password`, which is low enough entropy that any
/// per-value digest would be a confirmation oracle. The *file* digest is safe
/// because confirming a guess against it means guessing the whole file; a
/// digest of one extracted value would not be, so there is not one.
#[test]
fn an_opaque_auth_value_is_reported_by_length_only() {
    let encoded = "dXNlcjpwYXNzd29yZA==";
    let parsed = parse(&format!("//registry.example.test/:_auth={encoded}\n")).expect("parses");
    let selector = &parsed.auth_selectors[0];
    assert_eq!(selector.field, AuthField::Auth);
    assert_eq!(selector.value_len, encoded.len());
    let json = serde_json::to_string(selector).expect("serialises");
    assert!(!json.contains(encoded), "the value reached JSON: {json}");
}

#[test]
fn discovery_reports_every_audience_once_and_in_a_stable_order() {
    let parsed = parse(
        "//b.example.test/:_authToken=1\n//a.example.test/:_authToken=2\n//b.example.test/:username=u\n",
    )
    .expect("parses");
    let audiences: Vec<String> = one_file(parsed)
        .audiences()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        audiences,
        vec!["a.example.test".to_string(), "b.example.test".to_string()]
    );
}

/// Project overrides user overrides global. A report listing them in another
/// order would describe an effective configuration nobody has.
#[test]
fn the_candidate_order_is_the_precedence_npm_itself_uses() {
    let candidates = Npm::candidates(Path::new("/home/u"), Path::new("/work/project"));
    assert_eq!(
        candidates.iter().map(|c| c.origin).collect::<Vec<_>>(),
        vec![Origin::Project, Origin::User, Origin::Global]
    );
    assert_eq!(candidates[0].path, PathBuf::from("/work/project/.npmrc"));
    assert_eq!(candidates[1].path, PathBuf::from("/home/u/.npmrc"));
    assert_eq!(candidates[2].path, PathBuf::from("/home/u/.npm/npmrc"));
}
