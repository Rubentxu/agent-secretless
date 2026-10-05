//! `adopt`'s rows.
//!
//! This is the first module in the crate where a secret exists in the process,
//! so the rows are chosen for what a mistake here costs: a credential moved
//! that should not have been, a credential imported from bytes that changed
//! under the operator, an import that looks like a success and is not, and — the
//! one doc 04 §10 exists to prevent — a scrub performed as a side effect of an
//! import.
//!
//! Two of these rows are **negative about a file that was written**. That is
//! deliberate: `adopt`'s most consequential possible behaviour is modifying the
//! `.npmrc`, and the only way to be sure it does not is to assert the bytes are
//! untouched afterwards rather than to assert that no code *looks* like it
//! writes.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::*;
use crate::npm::Registry;
use crate::RegistryAudience;
use secrecy::ExposeSecret as _;

const TOKEN: &str = "npm_AdoptRowMustNeverBePrinted123";

/// A real `.npmrc` on disk, at 0600, holding a real token.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(contents: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        Self::write(&dir, contents);
        Self { dir }
    }

    fn write(dir: &tempfile::TempDir, contents: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.path().join(".npmrc");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("write");
        file.write_all(contents.as_bytes()).expect("write");
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join(".npmrc")
    }

    fn contents(&self) -> Vec<u8> {
        std::fs::read(self.path()).expect("read back")
    }

    fn expected(&self) -> FileFingerprint {
        FingerprintPolicy::strict()
            .fingerprint(&self.path())
            .expect("fingerprint")
    }

    fn token_selector(&self) -> AdoptSelector {
        AdoptSelector {
            file: self.path().to_string_lossy().into_owned(),
            audience: "registry.example.test".into(),
            field: AuthField::AuthToken,
        }
    }

    fn extract(&self) -> Result<SecretString, AdoptError> {
        NpmAdoption::extract(
            &FingerprintPolicy::strict(),
            &self.path(),
            &self.token_selector(),
            &self.expected(),
        )
    }
}

/// The ordinary case, so the refusals below cannot pass by refusing everything.
#[test]
fn the_value_of_a_named_selector_is_extracted() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    let value = fixture.extract().expect("a token to adopt");
    assert_eq!(
        value.expose_secret(),
        TOKEN,
        "the extracted value is not the one in the file"
    );
}

/// **`SecretString` is the return type and that is the property.** A `String`
/// here would put the credential in a `Debug` line, a format string and an
/// ordinary heap allocation, and the only defence against that is a reviewer
/// reading every future caller.
#[test]
fn the_extracted_value_is_a_type_that_redacts() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    let value = fixture.extract().expect("a token");
    let rendered = format!("{value:?} and {value:#?}");
    assert!(
        !rendered.contains(TOKEN),
        "the value reached a rendering: {rendered}"
    );
    // Stronger than redaction: `SecretBox` implements **no** `Display` at all,
    // so there is no format string in the tree that can print it. That is why
    // this row cannot be satisfied by remembering to be careful at the call
    // sites -- the mistake does not compile.
}

/// **§6: the bytes are checked *before* the value exists in this process.** A
/// check afterwards would mean the credential was already in memory when the
/// refusal happened, which is precisely the moment it must not be.
#[test]
fn a_changed_configuration_refuses_before_the_value_is_read() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    let expected = fixture.expected();

    Fixture::write(
        &fixture.dir,
        "//registry.example.test/:_authToken=npm_DIFFERENT999\n",
    );

    match NpmAdoption::extract(
        &FingerprintPolicy::strict(),
        &fixture.path(),
        &fixture.token_selector(),
        &expected,
    ) {
        Err(AdoptError::ConfigChanged { drift, .. }) => {
            assert!(drift.contains(&Drift::Contents), "{drift:?}");
        }
        other => panic!("a changed file was read anyway: {other:?}"),
    }
}

/// **A replacement is not an edit.** Two files with identical bytes have
/// identical digests, so a digest-only check lets a file swapped for an
/// identical copy through — and the swap is the attack.
#[test]
fn a_replaced_file_is_refused_even_with_identical_bytes() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    let expected = fixture.expected();

    let replacement = fixture.dir.path().join("replacement");
    std::fs::copy(fixture.path(), &replacement).expect("copy");
    std::fs::rename(&replacement, fixture.path()).expect("swap");

    assert!(
        matches!(
            NpmAdoption::extract(
                &FingerprintPolicy::strict(),
                &fixture.path(),
                &fixture.token_selector(),
                &expected,
            ),
            Err(AdoptError::ConfigChanged { .. })
        ),
        "an identical-bytes replacement passed the check"
    );
}

/// **`${VAR}` has no value in the file to move.** Importing the name would store
/// a credential that cannot work, and it would look like a success — which is
/// the specific failure an import step has to be most careful about.
#[test]
fn an_environment_reference_is_refused_rather_than_imported() {
    let fixture = Fixture::new("//registry.example.test/:_authToken=${NPM_TOKEN}\n");
    match fixture.extract() {
        Err(AdoptError::EnvReference { name, .. }) => assert_eq!(name, "NPM_TOKEN"),
        other => panic!("a reference was treated as a credential: {other:?}"),
    }
}

/// An empty credential is not a credential, and importing one would create a
/// vault entry that looks identical to a working one until npm fails.
#[test]
fn an_empty_value_is_refused() {
    let fixture = Fixture::new("//registry.example.test/:_authToken=\n");
    assert!(matches!(
        fixture.extract(),
        Err(AdoptError::EmptyValue { .. })
    ));
}

/// A typo npm ignores names no credential, so there is nothing to adopt.
#[test]
fn a_selector_the_file_does_not_declare_is_refused() {
    let fixture = Fixture::new("//registry.example.test/:_authToken=abc\n");
    let selector = AdoptSelector {
        file: fixture.path().to_string_lossy().into_owned(),
        audience: "other.example.test".into(),
        field: AuthField::AuthToken,
    };
    assert!(matches!(
        NpmAdoption::extract(
            &FingerprintPolicy::strict(),
            &fixture.path(),
            &selector,
            &fixture.expected(),
        ),
        Err(AdoptError::NoSuchSelector { .. })
    ));
}

/// **Two lines, one meaning.** npm's effective value is the last one, and
/// choosing for the operator would import something other than what the tool
/// would actually use — silently, and with a successful-looking receipt.
#[test]
fn a_field_set_twice_is_refused_rather_than_guessed() {
    let fixture = Fixture::new(
        "//registry.example.test/:_authToken=first-value\n\
         //registry.example.test/:_authToken=second-value\n",
    );
    assert!(matches!(
        fixture.extract(),
        Err(AdoptError::AmbiguousLine { .. })
    ));
}

/// **§10: the original is not scrubbed by an import.** The file has to be
/// byte-identical afterwards, and its mode has to be unchanged — a scrub that
/// rewrote it with a different umask would be a scrub that loosened the file it
/// was protecting.
#[test]
fn importing_does_not_touch_the_file() {
    let contents = format!(
        "//registry.example.test/:_authToken={TOKEN}\nregistry=https://registry.example.test/\n"
    );
    let fixture = Fixture::new(&contents);
    let before = fixture.contents();
    let mode_before = std::fs::metadata(fixture.path())
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;

    let value = fixture.extract().expect("a token to adopt");
    assert!(!value.expose_secret().is_empty());

    assert_eq!(
        fixture.contents(),
        before,
        "adopt modified the file it read from; §10 puts four steps and a human \
         approval before a scrub, and none of them happened here"
    );
    assert_eq!(
        std::fs::metadata(fixture.path())
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777,
        mode_before,
        "adopt changed the mode of the file it read from"
    );
}

/// **The receipt names the credential and the audience, not just a label**, and
/// it says what has *not* been done yet. A receipt that said "done" would be
/// claiming the scrub, the negative test and the human approval all happened.
#[test]
fn the_receipt_names_the_binding_and_what_is_still_outstanding() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    let fingerprint = fixture.expected();
    let receipt = AdoptReceipt::new(
        fixture.token_selector(),
        asv_domain::CredentialId::new(),
        "npm-registry".into(),
        "registry.example.test".into(),
        BTreeSet::from([crate::Operation::Read, crate::Operation::Publish]),
        fixture.path().to_string_lossy().into_owned(),
        fingerprint,
    );

    assert_eq!(receipt.schema, "asv.integrations.adopt/v1");
    let json = serde_json::to_string(&receipt).expect("serialises");
    assert!(json.contains("registry.example.test"), "{json}");
    assert!(json.contains("\"read\""), "{json}");
    assert!(
        !json.contains(TOKEN),
        "the value reached the receipt: {json}"
    );

    assert_eq!(
        receipt.outstanding,
        vec![
            PendingStep::VerifyVault,
            PendingStep::VerifyNewIntegration,
            PendingStep::NegativeBypassTest,
            PendingStep::HumanApproval,
            PendingStep::ScrubAndRescan,
        ],
        "§10's five steps, in order, are what is left"
    );
}

/// **A selector is identified by all three of its parts.** A registry has many
/// selectors and a field appears under many registries, so matching on the
/// audience alone would let an operator adopt `_authToken` when they meant
/// `_auth` — the exact credential confusion this stage has to avoid.
#[test]
fn a_selector_is_matched_on_file_audience_and_field() {
    let selector = AdoptSelector {
        file: "/home/u/.npmrc".into(),
        audience: "registry.example.test".into(),
        field: AuthField::AuthToken,
    };
    assert!(selector.matches(
        Path::new("/home/u/.npmrc"),
        "registry.example.test",
        &AuthField::AuthToken
    ));
    assert!(
        !selector.matches(
            Path::new("/home/u/.npmrc"),
            "other.example.test",
            &AuthField::AuthToken
        ),
        "a different registry is a different credential"
    );
    assert!(
        !selector.matches(
            Path::new("/home/u/.npmrc"),
            "registry.example.test",
            &AuthField::Auth
        ),
        "a different field under the same registry is a different credential"
    );
    assert!(
        !selector.matches(
            Path::new("/home/u/other"),
            "registry.example.test",
            &AuthField::AuthToken
        ),
        "the same selector in a different file is a different credential"
    );
}

/// **A world-writable `.npmrc` is refused before its value is read**, by the
/// same fingerprint policy `discover` uses. An import from a file another user
/// can write is an import of bytes the operator did not choose.
#[test]
fn a_configuration_another_user_may_write_is_refused() {
    let fixture = Fixture::new(&format!("//registry.example.test/:_authToken={TOKEN}\n"));
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o622))
        .expect("chmod");
    // The fingerprint itself refuses, so adopt never gets as far as reading.
    assert!(
        FingerprintPolicy::strict()
            .fingerprint(&fixture.path())
            .is_err(),
        "a group-writable configuration was accepted"
    );
}

/// The adapter's own selector vocabulary agrees with the parser's, so a plan
/// entry and an adopt selector cannot name different things.
#[test]
fn a_selector_built_from_a_parsed_one_carries_the_canonical_audience() {
    let selector = crate::npm::AuthSelector {
        registry: Registry {
            audience: RegistryAudience::parse("NPM.Example.Test:443").expect("canonicalises"),
            url: "https://npm.example.test/".into(),
            path_prefix: String::new(),
        },
        field: AuthField::AuthToken,
        value_len: TOKEN.len(),
        value_is_env_reference: false,
        env_reference: None,
    };
    let built = crate::adopt::selector_for(Path::new("/home/u/.npmrc"), &selector);
    assert_eq!(
        built.audience, "npm.example.test:443",
        "the audience must be canonicalised, not echoed: a receipt naming one \
         spelling of an endpoint is a receipt that cannot be looked up"
    );
    assert_eq!(built.field, AuthField::AuthToken);
}

/// **A refusal is printed to a terminal, so a refusal must carry no value.**
///
/// The error type is the one place a value could leak without anyone deciding
/// to put it there: an arm that reaches for `value` to be helpful — "the line
/// was `<host>/:_authToken=<token>`" — reads as better diagnostics and is the
/// exact shape of leak that survives review. Every refusal is exercised here
/// through `Debug` *and* `Display`, because those are the two paths a caller
/// actually uses.
///
/// The fixture is a real file rather than a literal because it is an `.npmrc`
/// whose keys begin `//`, and that spelling is refused by the shell policy this
/// repository works under — so a literal here would be a hazard the rows had to
/// be written around.
#[test]
fn a_refusal_message_carries_no_value() {
    let fixture = Fixture::new(include_str!("ambiguous_pair.npmrc"));
    let error = fixture.extract().expect_err("two lines is a refusal");
    let rendered = format!("{error:?} and {error}");
    assert!(
        !rendered.contains("first-secret-value"),
        "a refusal leaked the first value: {rendered}"
    );
    assert!(
        !rendered.contains("second-secret-value"),
        "a refusal leaked the second value: {rendered}"
    );
}
