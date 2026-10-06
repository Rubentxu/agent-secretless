//! Rows for the Gradle family.
//!
//! # Why these assert over the serialised form
//!
//! The same argument the other two families make: what a caller receives is
//! what reaches a terminal, a log and an agent's context, so the rows that
//! matter assert over the **serialised JSON** and the `Debug` rendering rather
//! than over the struct. A field added tomorrow is caught there and not by a
//! struct-shape assertion written today.
//!
//! # What is different about the rows here
//!
//! Maven's central rows are about a secret the adapter might leak. Gradle's
//! central rows are the mirror image: about **not claiming a secret that is not
//! there**. Most of a `gradle.properties` is JVM flags, and an adapter that
//! reported each entry as a credential would report "4 credentials" on a file
//! holding two flags. Those rows are therefore as load-bearing as Maven's.

use std::path::{Path, PathBuf};

use super::*;

/// A working directory and a user home, both empty.
fn sandbox(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("asv-gradle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let cwd = root.join("project");
    std::fs::create_dir_all(home.join(".gradle")).expect("create the home");
    std::fs::create_dir_all(&cwd).expect("create the project");
    (home, cwd)
}

fn write(cwd: &Path, name: &str, body: &str) {
    std::fs::write(cwd.join(name), body).expect("write the fixture");
}

fn discover(home: &Path, cwd: &Path) -> GradleDiscovery {
    Gradle
        .discover(&FingerprintPolicy::strict(), home, cwd)
        .expect("discovery produces a report")
}

/// The properties a real publishing build writes.
fn publishing() -> String {
    "\
storeUser=acme-deploy
storePassword=hunter2-not-a-real-password
keyAlias=release-2026
keyPassword=another-not-real
org.gradle.jvmargs=-Xmx2g
org.gradle.daemon.idletimeout=3600000
"
    .to_string()
}

// ---------------------------------------------------------------- the shape

/// The three files Gradle reads, and the two origins they map onto.
#[test]
fn the_candidates_are_the_files_gradle_itself_reads() {
    let (home, cwd) = sandbox("candidates");
    let candidates = Gradle::candidates(&home, &cwd);
    let paths: Vec<String> = candidates
        .iter()
        .map(|c| c.path.display().to_string())
        .collect();
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with("project/gradle.properties")),
        "a project-level gradle.properties is a candidate: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with(".gradle/gradle.properties")),
        "the user-level one is a candidate: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with(".gradle/init.gradle")),
        "the init script is a candidate: {paths:?}"
    );
}

/// **The exit-criterion row, stated as a measurement rather than a hope.**
///
/// Adding this family widened no shared type: the two origins Gradle uses were
/// both already in [`crate::Origin`] before it existed. Maven's measurement
/// found a cost; this one is the negative result that makes the criterion a
/// property of the tree rather than of which family arrived second.
#[test]
fn adding_this_family_needs_no_origin_the_previous_two_did_not_already_have() {
    use crate::Origin::{Project, User};
    // The full set a third family could legitimately need is these two, and
    // npm already modelled both before Gradle existed.
    assert_ne!(Project, User);
    let (home, cwd) = sandbox("origins");
    let origins: Vec<crate::Origin> = Gradle::candidates(&home, &cwd)
        .into_iter()
        .map(|c| c.origin)
        .collect();
    assert!(
        origins.iter().all(|o| matches!(o, Project | User)),
        "Gradle used only origins npm already had: {origins:?}"
    );
}

/// There is deliberately no depth ceiling, and a properties file is why.
#[test]
fn the_format_is_flat_so_there_is_no_depth_ceiling_to_write() {
    // A file whose only shape is newlines and separators cannot nest, so the
    // machinery Maven needed has nothing to bound. The constant is public so
    // that a future maintainer looking for the missing ceiling finds this
    // explanation rather than an absence.
    assert_eq!(
        MAX_PROPERTIES_ENTRIES, 4096,
        "breadth is the only pathological shape a flat format has"
    );
}

// ------------------------------------------------------- what is a credential

/// The titular row: the credential is named and its length is reported.
#[test]
fn a_store_password_is_named_and_never_read() {
    let (home, cwd) = sandbox("store");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let file = &report.files[0];
    let password = file
        .credentials
        .iter()
        .find(|c| c.kind == GradleCredential::RepositoryStorePassword)
        .expect("storePassword is reported");
    assert_eq!(password.key, "storePassword");
    assert_eq!(
        password.len,
        Some("hunter2-not-a-real-password".len()),
        "the length, not the value"
    );
    assert!(!password.is_env_reference);
}

/// `keyAlias` is an alias, not a secret, and the report says which one it is.
#[test]
fn a_key_alias_is_reported_as_an_alias_rather_than_as_a_credential_hiding_one() {
    let (home, cwd) = sandbox("alias");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let alias = report.files[0]
        .credentials
        .iter()
        .find(|c| c.kind == GradleCredential::SigningKeyAlias)
        .expect("keyAlias is reported");
    assert_eq!(alias.key, "keyAlias");
    assert_eq!(alias.len, Some("release-2026".len()));
}

/// **The mirror of Maven's central row.** A JVM flag is not a credential, and
/// an adapter that said it was would report four credentials on this file.
#[test]
fn a_jvm_flag_is_named_and_measured_rather_than_called_a_credential() {
    let (home, cwd) = sandbox("jvm");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let file = &report.files[0];
    assert_eq!(
        file.credentials.len(),
        4,
        "exactly the four named credential keys, and not one JVM flag"
    );
    let jvm = file
        .undescribed
        .iter()
        .find(|u| u.key == "org.gradle.jvmargs")
        .expect("the JVM flag is still reported");
    assert_eq!(jvm.len, "-Xmx2g".len());
}

/// The two claims stay apart: present-and-not-described is not absent.
#[test]
fn a_file_with_no_credentials_says_it_has_none_and_still_says_what_it_read() {
    let (home, cwd) = sandbox("none");
    write(
        &cwd,
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g\norg.gradle.parallel=true\n",
    );
    let report = discover(&home, &cwd);
    let file = &report.files[0];
    assert!(
        file.credentials.is_empty(),
        "two JVM settings are not credentials"
    );
    assert_eq!(
        file.undescribed.len(),
        2,
        "and the report still says what was in the file"
    );
}

/// Matching is exact: `storePasswordBackup` is somebody else's key.
#[test]
fn a_key_that_merely_starts_like_a_credential_is_not_one() {
    let (home, cwd) = sandbox("exact");
    write(
        &cwd,
        "gradle.properties",
        "storePasswordBackup=not-a-credential\nStorePassword=nor-this\n",
    );
    let report = discover(&home, &cwd);
    let file = &report.files[0];
    assert!(
        file.credentials.is_empty(),
        "neither spelling is Gradle's: {:?}",
        file.credentials
    );
    assert_eq!(file.undescribed.len(), 2);
}

// ------------------------------------------------------ the env-reference rule

/// A reference is named, never resolved, and never measured.
#[test]
fn a_dollar_reference_is_named_never_resolved_and_never_measured() {
    let (home, cwd) = sandbox("env");
    write(
        &cwd,
        "gradle.properties",
        "storePassword=${ORG_GRADLE_PROJECT_storePassword}\n",
    );
    let report = discover(&home, &cwd);
    let password = &report.files[0].credentials[0];
    assert!(password.is_env_reference);
    assert_eq!(
        password.env_reference.as_deref(),
        Some("ORG_GRADLE_PROJECT_storePassword")
    );
    assert_eq!(
        password.len, None,
        "the 37 characters in the file are text standing in for a credential, \
         and a report offering that number is offering one plausible-looking \
         wrong answer"
    );
}

/// Maven's spelling is accepted too: a build written against it is not a
/// hypothetical, and a properties file is exactly where it would land.
#[test]
fn the_maven_spelling_of_a_reference_is_accepted_as_well() {
    let (home, cwd) = sandbox("envmaven");
    write(
        &cwd,
        "gradle.properties",
        "keyPassword=${env.SIGNING_PASSWORD}\n",
    );
    let report = discover(&home, &cwd);
    let password = &report.files[0].credentials[0];
    assert_eq!(password.env_reference.as_deref(), Some("SIGNING_PASSWORD"));
    assert_eq!(password.len, None);
}

/// A literal `${` that is not a whole reference is not treated as one.
#[test]
fn a_dollar_that_is_not_a_reference_is_still_a_literal() {
    let (home, cwd) = sandbox("notenv");
    write(
        &cwd,
        "gradle.properties",
        "org.gradle.jvmargs=${not_closed\n",
    );
    let report = discover(&home, &cwd);
    let entry = &report.files[0].undescribed[0];
    assert_eq!(entry.key, "org.gradle.jvmargs");
    assert!(entry.len > 0);
}

// ------------------------------------------------------------------ parsing

/// `:` and whitespace are separators too, and getting that wrong glues a
/// separator onto the front of a value.
#[test]
fn all_three_java_separators_are_honoured() {
    let (home, cwd) = sandbox("separators");
    write(&cwd, "gradle.properties", "a:one\nb two\nc=three\n");
    let report = discover(&home, &cwd);
    let file = &report.files[0];
    let keys: Vec<&str> = file.undescribed.iter().map(|u| u.key.as_str()).collect();
    assert_eq!(keys, ["a", "b", "c"]);
    let lengths: Vec<usize> = file.undescribed.iter().map(|u| u.len).collect();
    assert_eq!(lengths, [3, 3, 5], "no separator leaked into a value");
}

/// Comments are not entries.
#[test]
fn a_hash_or_bang_comment_is_not_an_entry() {
    let (home, cwd) = sandbox("comments");
    write(
        &cwd,
        "gradle.properties",
        "# a comment\n! another\n\nreal=1\n",
    );
    let report = discover(&home, &cwd);
    assert_eq!(report.files[0].undescribed.len(), 1);
    assert_eq!(report.files[0].undescribed[0].key, "real");
}

/// Continuations are honoured, because dropping the second half would silently
/// truncate a value and the report would describe text the file does not hold.
#[test]
fn a_continuation_is_honoured_so_a_long_value_is_not_truncated() {
    let (home, cwd) = sandbox("continuation");
    write(
        &cwd,
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx4g \\\n  -XX:MaxMetaspaceSize=1g\n",
    );
    let report = discover(&home, &cwd);
    let entry = &report.files[0].undescribed[0];
    assert_eq!(entry.key, "org.gradle.jvmargs");
    assert!(
        entry.len > "-Xmx4g".len(),
        "the continuation's text is part of the value, not dropped: {}",
        entry.len
    );
}

/// npm's lesson: a line this parser cannot read refuses the file rather than
/// becoming a length that describes nothing on disk.
#[test]
fn a_line_with_no_separator_refuses_the_file_rather_than_guessing() {
    let (home, cwd) = sandbox("nosep");
    write(&cwd, "gradle.properties", "good=1\nthisisnotanentry\n");
    let report = discover(&home, &cwd);
    assert!(
        report.files.is_empty(),
        "the file is refused, not half-read"
    );
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].message.contains("separator"));
}

/// A value running off the end of the file is incomplete, and reporting the
/// partial length would describe text the file does not contain.
#[test]
fn a_dangling_continuation_refuses_the_file_rather_than_reporting_a_partial_value() {
    let (home, cwd) = sandbox("dangling");
    write(&cwd, "gradle.properties", "key=value\\");
    let report = discover(&home, &cwd);
    assert!(report.files.is_empty());
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].message.contains("backslash"));
}

/// An escape inside a key does not end it.
#[test]
fn an_escaped_separator_does_not_end_the_key() {
    let (home, cwd) = sandbox("escaped");
    write(&cwd, "gradle.properties", "a\\=b=value\n");
    let report = discover(&home, &cwd);
    assert_eq!(report.files[0].undescribed[0].key, "a=b");
}

/// A well-formed unicode escape is decoded.
#[test]
fn a_unicode_escape_is_decoded_rather_than_left_as_seven_characters() {
    let (home, cwd) = sandbox("unicode");
    write(&cwd, "gradle.properties", r"k=\u00e9");
    let report = discover(&home, &cwd);
    assert_eq!(
        report.files[0].undescribed[0].len,
        "\u{e9}".len(),
        "one decoded character, not the six source characters"
    );
}

/// A malformed escape is left literal rather than guessed at.
#[test]
fn a_malformed_unicode_escape_is_left_literal_rather_than_guessed_at() {
    let (home, cwd) = sandbox("badunicode");
    write(&cwd, "gradle.properties", r"k=\u00");
    let report = discover(&home, &cwd);
    // The value is reported at the length of what the file literally holds.
    assert!(report.files[0].undescribed[0].len > 0);
    assert!(report.files.is_empty() == false);
}

/// An empty value is empty, not a zero-byte secret.
#[test]
fn an_empty_value_is_reported_as_empty_rather_than_as_zero_bytes_of_secret() {
    let (home, cwd) = sandbox("empty");
    write(&cwd, "gradle.properties", "storePassword=\n");
    let report = discover(&home, &cwd);
    let password = &report.files[0].credentials[0];
    assert_eq!(password.len, Some(0));
}

// ------------------------------------------------------------------- ceilings

/// Refused on size before it is read, so an enormous file never lands in
/// memory as a string.
#[test]
fn a_file_over_the_byte_ceiling_is_refused_without_being_read() {
    let (home, cwd) = sandbox("big");
    let oversized = format!("k={}\n", "x".repeat(MAX_PROPERTIES_BYTES as usize + 1));
    write(&cwd, "gradle.properties", &oversized);
    let report = discover(&home, &cwd);
    assert!(report.files.is_empty());
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].message.contains("ceiling"));
}

/// Breadth is the only pathological shape a flat format has.
#[test]
fn a_file_over_the_entry_ceiling_is_refused() {
    let (home, cwd) = sandbox("many");
    let body: String = (0..=MAX_PROPERTIES_ENTRIES)
        .map(|i| format!("k{i}=v\n"))
        .collect();
    write(&cwd, "gradle.properties", &body);
    let report = discover(&home, &cwd);
    assert!(report.files.is_empty());
    assert_eq!(report.findings.len(), 1);
    assert!(report.findings[0].message.contains("entries"));
}

// ------------------------------------------------------------- policy, findings

/// The policy npm has and Gradle inherits: refuse the file, keep the report.
#[test]
fn a_world_writable_file_is_refused_without_losing_the_run() {
    use std::os::unix::fs::PermissionsExt;
    let (home, cwd) = sandbox("writable");
    let path = cwd.join("gradle.properties");
    write(&cwd, "gradle.properties", &publishing());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
        .expect("make it world-writable");

    let report = discover(&home, &cwd);

    assert!(report.files.is_empty(), "the file is refused");
    assert_eq!(report.findings.len(), 1, "and the operator is told");
    assert_eq!(report.findings[0].severity, crate::Severity::Refused);
}

/// Absence is not a finding: most projects have no `gradle.properties`.
#[test]
fn a_machine_with_no_gradle_file_gets_an_empty_report_and_no_findings() {
    let (home, cwd) = sandbox("absent");
    let report = discover(&home, &cwd);
    assert!(report.files.is_empty());
    assert!(
        report.findings.is_empty(),
        "nothing to find is not something to be told about: {:?}",
        report.findings
    );
}

/// A parse failure is a finding, not a run failure. Propagating it would make
/// one unusual properties file read as "Gradle is not configured", which is the
/// answer most operators will accept and act on.
#[test]
fn a_parse_failure_is_a_finding_and_the_run_still_succeeds() {
    let (home, cwd) = sandbox("parsefail");
    write(&cwd, "gradle.properties", "notanentry\n");
    let report = discover(&home, &cwd);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.files.len(), 0);
}

// -------------------------------------------------------------- the wire forms

/// Nothing in the serialised report is a value.
#[test]
fn the_serialised_report_contains_no_credential() {
    let (home, cwd) = sandbox("json");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let json = serde_json::to_string(&report).expect("serialise");
    assert!(
        !json.contains("hunter2-not-a-real-password"),
        "the password reached the wire: {json}"
    );
    assert!(
        !json.contains("another-not-real"),
        "so did the key password"
    );
    assert!(json.contains("storePassword"), "the name is still there");
}

/// And the same for `Debug`, which is what a log line would print.
#[test]
fn the_debug_rendering_contains_no_credential_either() {
    let (home, cwd) = sandbox("debug");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let rendered = format!("{report:?}");
    assert!(
        !rendered.contains("hunter2-not-a-real-password"),
        "{rendered}"
    );
}

/// The report reaches the shape the CLI prints. A module that compiles but
/// cannot be wrapped cannot be reached from a product surface.
#[test]
fn the_gradle_report_reaches_the_envelope_the_cli_prints() {
    let (home, cwd) = sandbox("envelope");
    write(&cwd, "gradle.properties", &publishing());
    let report = discover(&home, &cwd);
    let discovery = report.into_discovery();
    assert_eq!(discovery.family, "gradle");
    assert!(matches!(discovery.report, crate::AnyReport::Gradle(_)));
}

/// The family is dispatchable by the name an agent would type.
#[test]
fn the_family_is_named_the_way_an_agent_names_it() {
    assert_eq!(Gradle::FAMILY, "gradle");
}
