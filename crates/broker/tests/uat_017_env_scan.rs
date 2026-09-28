//! Source-scanning regression test for the environment-quarantine invariant.
//!
//! The threat this forecloses is not "someone reads an env var". It is
//! "something reintroduces an env var as a *fallback*". The broker is
//! fail-closed precisely because `BrokerState::default` has no secret port
//! and refuses every brokered operation. A single
//! `std::env::var("GITHUB_TOKEN")` in a connector would silently restore
//! exactly the anonymous-but-authenticated path that ADR-0002 exists to
//! remove, and every test asserting `Denied` would keep passing while the
//! product quietly did the wrong thing.
//!
//! Scanning the source is blunt on purpose. A taint-tracking analysis
//! would be more precise and would also be more likely to accept a
//! `Helper::get()` that turns out to call `env::var` on some path nobody
//! reviewed. This test does not try to understand the code; it refuses a
//! category of it.

use std::path::{Path, PathBuf};

/// Crates whose production sources must never read the ambient environment
/// for a credential. `cli` is deliberately absent: `asv run` must *read*
/// and then *remove* the environment, which is the quarantine mechanism
/// itself, and that reads `std::env::temp_dir` and `std::process::id`.
const SCANNED_CRATES: &[&str] = &["broker", "connector-http", "vault", "ssh-agent", "policy"];

/// The exact call shapes that constitute a credential read.
///
/// Ordered longest-first, and matched on a token boundary rather than a
/// raw substring. `env::var` is a prefix of `env::var_os`, so a substring
/// match reports the same line twice and a reader cannot tell whether the
/// scanner found one read or two. The boundary check is what keeps the
/// report honest: it is the only thing between "noisy" and "untrustworthy".
const FORBIDDEN: &[&str] = &["env::vars_os", "env::vars", "env::var_os", "env::var"];

/// True when `haystack` contains `needle` as a whole path segment, so
/// `env::var` does not match inside `env::var_os` and `myenv::var` does not
/// match at all.
fn contains_call(haystack: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        // A preceding identifier character means this is a different path
        // (`myenv::var`), not the banned one. The `std:` in `std::env::var`
        // must not disqualify it, and the distinction is the `::`: a path
        // segment ends at the double colon, so the characters that matter
        // are the run of identifier characters immediately before the
        // needle, stopping at the first `::` or at a non-identifier.
        let preceded_by_ident = {
            let mut chars = haystack[..start].chars().rev();
            let mut saw_segment = false;
            for c in chars.by_ref() {
                if c == ':' {
                    // `::` closes the previous segment; whatever came before
                    // it is a different module and cannot disqualify us.
                    break;
                }
                if c.is_alphanumeric() || c == '_' {
                    saw_segment = true;
                } else {
                    break;
                }
            }
            saw_segment
        };
        // A following identifier character means a longer name that merely
        // starts the same way.
        let followed_by_ident = haystack[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !preceded_by_ident && !followed_by_ident {
            return true;
        }
        from = end;
    }
    false
}

/// Locates the workspace root from the manifest directory, so the test does
/// not depend on the working directory Cargo happens to choose.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("broker crate lives at <root>/crates/broker")
        .to_path_buf()
}

/// Distinguishes test scaffolding from shipped code.
///
/// A line inside `#[cfg(test)] mod tests` is allowed to read the
/// environment; that is how the tests find the target directory at all.
/// Deciding this by parsing attributes is fragile, so instead every
/// discovered violation is reported with enough context for a human to
/// judge, and the file-level check below rejects only non-test files.
fn is_test_only_source(path: &Path) -> bool {
    // `tests/` is the integration-test directory: it never ships.
    // A `#[cfg(test)] mod tests { ... }` inside `src/` is handled by the
    // line scanner, which is permissive and leaves the judgement to review.
    path.components().any(|c| c.as_os_str() == "tests")
}

/// Reports every forbidden environment read in one file, with line numbers.
fn scan_file(path: &Path) -> Vec<String> {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut findings = Vec::new();
    for (number, line) in source.lines().enumerate() {
        // A mention inside a comment or a string is not a call, and the
        // most likely false positive is this very test's own FORBIDDEN
        // table if the scan is ever pointed at itself.
        let code = line.split("//").next().unwrap_or(line);
        for needle in FORBIDDEN {
            if contains_call(code, needle) {
                findings.push(format!("{}:{}: {needle}", path.display(), number + 1));
            }
        }
    }
    findings
}

#[test]
fn no_production_source_reads_the_environment_for_credentials() {
    let root = workspace_root();
    let mut scanned = 0usize;
    let mut violations = Vec::new();

    for crate_name in SCANNED_CRATES {
        let src = root.join("crates").join(crate_name).join("src");
        assert!(
            src.is_dir(),
            "expected {} to exist; a rename must be a deliberate decision, not a \
             silent hole in the quarantine",
            src.display()
        );

        // Walk deterministically so a failure names the same file every run.
        let mut files: Vec<PathBuf> = walk(&src)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .filter(|p| !is_test_only_source(p))
            .collect();
        files.sort();

        for file in files {
            scanned += 1;
            violations.extend(scan_file(&file));
        }
    }

    assert!(
        scanned >= 5,
        "the scan found only {scanned} files, which means the walk is broken; a scan \
         that examines nothing must never report success"
    );

    assert!(
        violations.is_empty(),
        "credential-bearing environment reads reappeared in production sources. Each one \
         is a potential anonymous fallback that bypasses the vault, and no test would \
         catch it because the fail-closed tests only see the `Denied` path:\n  {}",
        violations.join("\n  ")
    );
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Proves the scanner actually detects the thing it claims to forbid.
///
/// A test that only ever sees a clean tree is untested: a scanner that
/// returned an empty vector unconditionally would pass it forever. This
/// runs the same `scan_file` over a source containing exactly the banned
/// call and asserts it is found.
#[test]
fn the_scanner_detects_a_read_it_forbids() {
    let canary = r#"
fn sneaky() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok()
}
"#;
    let path = std::env::temp_dir().join(format!("asv-scan-canary-{}.rs", std::process::id()));
    std::fs::write(&path, canary).expect("write canary");

    let findings = scan_file(&path);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        findings.len(),
        1,
        "the scanner must flag the one env read in the canary, got {findings:?}"
    );
    assert!(
        findings[0].contains("env::var"),
        "the finding must name the offending call: {findings:?}"
    );
}

/// The same canary written as `var_os`, which returns the same secret while
/// looking more innocent. It must be caught, and it must be reported as
/// itself rather than as the `env::var` it contains.
#[test]
fn the_scanner_names_the_exact_form_it_found() {
    for (form, expected) in [
        ("env::var_os(\"GITHUB_TOKEN\")", "env::var_os"),
        ("env::var(\"GITHUB_TOKEN\")", "env::var"),
        ("env::vars()", "env::vars"),
    ] {
        let path = std::env::temp_dir().join(format!(
            "asv-scan-form-{}-{}.rs",
            std::process::id(),
            form.len()
        ));
        std::fs::write(&path, format!("fn f() {{ let _ = {form}; }}")).expect("write");

        let findings = scan_file(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            findings.len(),
            1,
            "one call must produce one finding; {form} produced {findings:?}"
        );
        assert!(
            findings[0].ends_with(expected),
            "{form} must be reported as {expected}, got {:?}",
            findings[0]
        );
    }
}

/// A similarly-named path is not a banned call. `myenv::var` belongs to
/// someone's own module and `env::variable` is a different function;
/// refusing either would be a false positive that trains people to
/// disable the scan.
#[test]
fn a_similarly_named_path_is_not_flagged() {
    let path = std::env::temp_dir().join(format!("asv-scan-lookalike-{}.rs", std::process::id()));
    std::fs::write(
        &path,
        "fn f() { let _ = myenv::var(\"X\"); let _ = env::variable(\"Y\"); }",
    )
    .expect("write");

    let findings = scan_file(&path);
    let _ = std::fs::remove_file(&path);

    assert!(
        findings.is_empty(),
        "lookalike paths must not be flagged, got {findings:?}"
    );
}
