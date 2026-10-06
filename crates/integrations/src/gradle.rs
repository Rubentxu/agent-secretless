//! R3.B.2 — Gradle, the third family, and the second measurement.
//!
//! # What adding this family is actually for
//!
//! R3's exit criterion says a new adapter must be addable without touching
//! broker or domain. Maven (R3.B.1) measured it once and the measurement found
//! a cost: `Candidate::origin` had to be lifted out of `npm::Origin` before a
//! second family could express its precedence. That was a real result, but a
//! criterion measured once is a criterion that could still be an accident.
//!
//! This family measures it a second time, and the interesting number is a
//! **negative** one: adding Gradle required no shared-type change at all.
//! [`crate::Origin`] already had the two levels Gradle reads, so nothing in
//! `lib.rs` had to widen for it to exist. That is the first evidence that the
//! criterion describes the shape of the tree rather than the accident of which
//! family arrived second.
//!
//! It also shows the criterion holds for a *different format*. Maven needed
//! four XML protections from §5 and three of them came free from `roxmltree`.
//! A properties file has no DTD, no entities and **no nesting**, so the
//! `MAX_DEPTH` machinery and the quote-aware pre-scan have nothing to do here.
//! The criterion is about the adapter's shape, and a format with none of those
//! hazards still fits it.
//!
//! # What this family is, and is not
//!
//! **It is `discover` and safe parse, on `gradle.properties` and init scripts.**
//! `plan`, `adopt`, `binding` and the rest of R3's pipeline do not exist for
//! Gradle and are not simulated here.
//!
//! It reads the two files Gradle itself reads for user and project
//! configuration, plus the init script. It does **not** read
//! `~/.gradle/credentials/`, which is a binary store, and it does not parse
//! Groovy — so a repository declared inline in a `build.gradle` with a literal
//! password is invisible to this report. That is a real limit, named here
//! rather than papered over.
//!
//! # The property that makes this family different from the other two
//!
//! Most of a `gradle.properties` is **not** a credential. On the machine this
//! was written on, the user's file contains exactly two keys and neither is
//! one: `org.gradle.jvmargs` and `org.gradle.daemon.idletimeout`.
//!
//! So the shape of the honest report is inverted relative to the other two
//! families. Maven's `undescribed` is a rare corner; Gradle's is **the bulk of
//! every file**. An adapter that treated each line as a potential credential
//! would report "4 credentials found" on a file holding two JVM flags, and an
//! operator would learn to distrust the number.
//!
//! The two claims are kept apart, the same way Maven kept
//! *present-and-not-described* apart from *absent*:
//!
//! - [`GradleCredential`] — a key this adapter names and knows what it is for.
//! - [`UndescribedEntry`] — a key it does not model, reported **with its
//!   length** so an operator can see that something is there without the
//!   report ever reading it.
//!
//! # The env-reference rule, inherited
//!
//! `storePassword=${ORG_GRADLE_PROJECT_storePassword}` is a reference, not a
//! password. Reporting `password_len: 37` there measures the text standing in
//! for the credential, and a report offering that number alongside the
//! variable's name is offering one plausible-looking wrong answer. So it
//! reports the name and `None`, exactly as Maven does for `${env.…}`.
//!
//! Gradle's own convention is `${VAR}` rather than Maven's `${env.VAR}`, and
//! both are accepted: a Gradle build genuinely written against the Maven
//! spelling is not a hypothetical.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fingerprint::{FileFingerprint, FingerprintPolicy};
use crate::{Adapter, Candidate, Finding};

/// The largest `gradle.properties` this adapter will read.
///
/// Checked against the byte length **before** the file is materialised, so a
/// file larger than this is refused without being read at all. 256 KiB is
/// orders of magnitude above a real one — the largest in the wild are a few
/// kilobytes — so this refuses a file that is not configuration.
pub const MAX_PROPERTIES_BYTES: u64 = 1 << 18;

/// A ceiling on the number of key/value entries in one file.
///
/// The properties format has no nesting, so there is no depth to bound; breadth
/// is the only shape an attacker or a merge accident can make pathological.
/// A file with more than this many keys is not a configuration file.
pub const MAX_PROPERTIES_ENTRIES: usize = 4096;

/// There is deliberately **no depth ceiling** here, and its absence is the
/// finding rather than an omission.
///
/// Maven needed [`crate::maven::MAX_DEPTH`] because `roxmltree` recurses once
/// per level and counts nodes on the way back out, so a document nested N deep
/// exhausts the stack before any limit is consulted. That failure mode needs
/// nesting to exist. A properties file is a flat list of lines, so there is no
/// recursion to bound and a pre-scan would have nothing to scan.
///
/// Writing the constant anyway "for symmetry" would have been the wrong kind of
/// consistency: it would have bought a ceiling that cannot be violated, which
/// is not a safety property, and it would have implied the two families share a
/// hazard they do not.
pub const NO_DEPTH_LIMIT: () = ();

/// The Gradle family.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gradle;

impl crate::Adapter for Gradle {
    const FAMILY: &'static str = "gradle";

    type Report = GradleDiscovery;
    type Error = GradleError;

    /// **The measurement this family exists to take.**
    ///
    /// Gradle reads a project-level `gradle.properties`, a user-level one, and
    /// an init script. Every one of those maps onto a level
    /// [`crate::Origin`] already had — `Project` and `User` — so adding this
    /// family widened nothing. That is the second measurement of the exit
    /// criterion, and unlike the first it did not cost a change.
    ///
    /// `cwd` **is** consulted here, unlike in Maven, because Gradle genuinely
    /// has a project-level file. It is still an argument rather than something
    /// read from the environment, for the same reason as everywhere else in
    /// this crate: a report about the caller's configuration must not resolve
    /// *this process's* paths.
    fn candidates(home: &Path, cwd: &Path) -> Vec<Candidate> {
        vec![
            Candidate {
                path: cwd.join("gradle.properties"),
                origin: crate::Origin::Project,
            },
            Candidate {
                path: home.join(".gradle").join("gradle.properties"),
                origin: crate::Origin::User,
            },
            Candidate {
                path: home.join(".gradle").join("init.gradle"),
                origin: crate::Origin::User,
            },
        ]
    }

    fn discover(
        &self,
        policy: &FingerprintPolicy,
        home: &Path,
        cwd: &Path,
    ) -> Result<Self::Report, Self::Error> {
        let mut files = Vec::new();
        let mut findings = Vec::new();

        for candidate in Self::candidates(home, cwd) {
            if !candidate.path.exists() {
                // Absence is not a finding. Most projects have no
                // `gradle.properties` at all, and "none was found" is not a
                // sentence an operator needs from a tool they may not use.
                continue;
            }
            let fingerprint = match policy.fingerprint(&candidate.path) {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    // A refusal is a finding, not a failure: a world-writable
                    // user properties file does not make the project one
                    // unreadable, and an operator has to know it was skipped.
                    findings.push(Finding {
                        severity: crate::Severity::Refused,
                        subject: candidate.path.display().to_string(),
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let text = match read_capped(&candidate.path) {
                Ok(text) => text,
                Err(error) => {
                    // A refusal is a finding, not a run failure — and this one
                    // is where that is easiest to get wrong, because the `?`
                    // that reads naturally here propagates straight out of
                    // `discover` and turns "one file is too large" into "this
                    // family could not look at anything". An operator then
                    // learns nothing about the other two files.
                    findings.push(Finding {
                        severity: crate::Severity::Refused,
                        subject: candidate.path.display().to_string(),
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            match parse_properties(&text) {
                Ok(properties) => {
                    let (credentials, undescribed) = classify(properties);
                    files.push(GradleFile {
                        origin: candidate.origin,
                        fingerprint,
                        credentials,
                        undescribed,
                    });
                }
                // A parse failure is a finding and the run still succeeds.
                // Propagating it would make one unusual properties file read
                // as "Gradle is not configured", which is the answer most
                // operators will accept and act on.
                Err(error) => findings.push(Finding {
                    severity: crate::Severity::Refused,
                    subject: candidate.path.display().to_string(),
                    message: error.to_string(),
                }),
            }
        }

        Ok(GradleDiscovery { files, findings })
    }
}

/// Everything one Gradle discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradleDiscovery {
    pub files: Vec<GradleFile>,
    /// Files that were found and not read, and why.
    pub findings: Vec<Finding>,
}

impl From<GradleDiscovery> for crate::AnyReport {
    fn from(report: GradleDiscovery) -> Self {
        Self::Gradle(report)
    }
}

impl GradleDiscovery {
    /// Wraps this family's report in the shape the CLI prints.
    ///
    /// Present for the same reason as the other two families' `into_discovery`:
    /// a module that compiles but cannot be wrapped cannot be reached from a
    /// product surface, and therefore cannot pass anything.
    pub fn into_discovery(self) -> crate::Discovery {
        crate::Discovery::new(Gradle::FAMILY, crate::AnyReport::Gradle(self))
    }
}

/// One configuration file, described.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GradleFile {
    pub origin: crate::Origin,
    pub fingerprint: FileFingerprint,
    /// The keys this adapter names, because it knows what they are for.
    pub credentials: Vec<GradleCredentialEntry>,
    /// Every other key: **named and measured, never read.**
    ///
    /// This is the bulk of a real file. See the module docs for why the
    /// honest report is mostly this list rather than mostly credentials.
    pub undescribed: Vec<UndescribedEntry>,
}

/// One key this adapter recognises as carrying a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GradleCredentialEntry {
    /// The key exactly as it appears in the file. A `pom.xml` or a `build.gradle`
    /// refers to these by name, so a report that normalised the spelling would
    /// not be reportable verbatim by a caller.
    pub key: String,
    /// What the credential is for, so a report says "the publishing password"
    /// rather than making the operator know that `storePassword` is the one
    /// that signs an upload.
    pub kind: GradleCredential,
    /// The value's length in bytes, never the value.
    pub len: Option<usize>,
    /// Whether the value is an environment reference rather than a literal.
    pub is_env_reference: bool,
    /// The variable's name, when it is one. A name is not a value.
    pub env_reference: Option<String>,
}

/// The credential-bearing keys Gradle reads from a properties file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GradleCredential {
    /// `storeUser` — the account a publication authenticates as.
    RepositoryStoreUser,
    /// `storePassword` — the password for that publication.
    RepositoryStorePassword,
    /// `keyAlias` — which signing key a publication is signed with. An alias,
    /// not a secret, and it is reported as one so the report does not imply
    /// there is a credential hiding behind it.
    SigningKeyAlias,
    /// `keyPassword` — the private key's password.
    SigningKeyPassword,
    /// `systemProp.http.proxyUser` — the proxy account.
    ProxyUser,
    /// `systemProp.http.proxyPassword` — the proxy password.
    ProxyPassword,
}

/// A key this adapter does not model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UndescribedEntry {
    /// The key's name. A name is not a secret, and Gradle keys are names.
    pub key: String,
    /// The value's length, never the value.
    ///
    /// The number is the whole point of this row. An operator deciding whether
    /// to adopt a credential needs to know that a 40-byte value sits under an
    /// unfamiliar key; they do not need to be shown the 40 bytes, which is the
    /// difference between a report and a leak.
    pub len: usize,
}

/// Why a Gradle discovery could not produce a report at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GradleError {
    /// The file is larger than [`MAX_PROPERTIES_BYTES`].
    TooLarge { path: String, len: u64 },
    /// The file could not be read.
    Io { path: String, message: String },
}

impl fmt::Display for GradleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GradleError::TooLarge { path, len } => write!(
                f,
                "{path} is {len} bytes, past the {MAX_PROPERTIES_BYTES}-byte ceiling; \
                 refused without being read"
            ),
            GradleError::Io { path, message } => {
                write!(f, "{path} could not be read: {message}")
            }
        }
    }
}

impl std::error::Error for GradleError {}

/// Reads a file, refusing it on size before any of it is materialised.
fn read_capped(path: &Path) -> Result<String, GradleError> {
    let metadata = std::fs::metadata(path).map_err(|e| GradleError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    if metadata.len() > MAX_PROPERTIES_BYTES {
        return Err(GradleError::TooLarge {
            path: path.display().to_string(),
            len: metadata.len(),
        });
    }
    std::fs::read_to_string(path).map_err(|e| GradleError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

/// One `key=value` pair as it appears in a properties file.
type Pair = (String, String);

/// Parses the Java properties format Gradle uses.
///
/// **Deliberately narrow, and it refuses rather than guesses.** A line with no
/// unescaped separator, or a continuation that runs off the end of the file, is
/// an error instead of a best-effort reading. npm's family refuses `.npmrc` for
/// the same reason: a value this parser invented would be a length in the
/// report that describes nothing on disk.
///
/// Continuations (`\` at end of line) are honoured because real Gradle files use
/// them for long argument lists, and dropping the second half would silently
/// truncate a value.
fn parse_properties(text: &str) -> Result<Vec<Pair>, GradleParseError> {
    let mut pairs = Vec::new();
    // Key and value are accumulated separately and never joined into one
    // "key=value" string to be split apart again. Doing that round-trip looks
    // harmless and is not: an **escaped** separator inside a key survives the
    // join and is then mistaken for the real one, so `a\=b=value` came back
    // as the key `a`.
    let mut pending_key: Option<String> = None;
    let mut pending_value = String::new();

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        // A line ending in an odd number of backslashes continues.
        let continues = ends_with_continuation(line);
        let piece = if continues {
            strip_continuation(line)
        } else {
            line
        };

        // `is_some()` rather than `take()`: taking the key here would leave
        // `pending_key` empty again, so a value continued across **three**
        // lines would start a new entry on the third instead of appending.
        if pending_key.is_some() {
            pending_value.push_str(piece);
        } else {
            let trimmed = piece.trim_start();
            // Blank lines and comments are not entries and carry no value.
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                if continues {
                    return Err(GradleParseError::DanglingContinuation { line: line_number });
                }
                continue;
            }
            let (key, value) = split_entry(trimmed, line_number)?;
            pending_value = value;
            pending_key = Some(key);
        }

        if continues {
            continue;
        }
        if pairs.len() >= MAX_PROPERTIES_ENTRIES {
            return Err(GradleParseError::TooManyEntries {
                limit: MAX_PROPERTIES_ENTRIES,
            });
        }
        let key = pending_key
            .take()
            .expect("the key is set on every path that reaches here");
        pairs.push((key, std::mem::take(&mut pending_value)));
    }

    if pending_key.is_some() {
        // The file ended in the middle of a value. Reporting the partial value
        // would report a length for text the file does not contain.
        return Err(GradleParseError::DanglingContinuation {
            line: text.lines().count(),
        });
    }

    Ok(pairs)
}

/// What went wrong inside a properties file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GradleParseError {
    /// A line carried no `=`, `:` or whitespace separator.
    NoSeparator { line: usize },
    /// A value was empty where the separator promised one.
    EmptyKey { line: usize },
    /// A backslash-continuation ran off the end of the file.
    DanglingContinuation { line: usize },
    /// More entries than [`MAX_PROPERTIES_ENTRIES`].
    TooManyEntries { limit: usize },
}

impl fmt::Display for GradleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GradleParseError::NoSeparator { line } => write!(
                f,
                "line {line} carries no '=', ':' or whitespace separator; \
                 refusing the file rather than guessing what it meant"
            ),
            GradleParseError::EmptyKey { line } => {
                write!(f, "line {line} has a separator but no key")
            }
            GradleParseError::DanglingContinuation { line } => write!(
                f,
                "line {line} ends in a backslash and the file ends with it; \
                 the value is incomplete"
            ),
            GradleParseError::TooManyEntries { limit } => write!(
                f,
                "more than {limit} entries; refused as breadth rather than read \
                 one key at a time"
            ),
        }
    }
}

/// True when `line` ends in an odd number of backslashes, which is what makes
/// it a continuation rather than a value ending in an escaped backslash.
fn ends_with_continuation(line: &str) -> bool {
    line.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1
}

/// Removes the single trailing backslash that made this a continuation.
fn strip_continuation(line: &str) -> &str {
    &line[..line.len() - 1]
}

/// Splits one entry into key and value, unescaping both.
///
/// Java allows `=`, `:` or whitespace as the first unescaped separator, and
/// whitespace is also allowed around it. Getting that wrong is how a value ends
/// up with its own separator glued to the front of it.
fn split_entry(line: &str, number: usize) -> Result<Pair, GradleParseError> {
    let bytes: Vec<char> = line.chars().collect();
    let mut index = 0usize;
    let mut key = String::new();
    let mut separator: Option<usize> = None;

    while index < bytes.len() {
        let c = bytes[index];
        if c == '\\' {
            // An escape consumes the next character, whatever it is.
            match bytes.get(index + 1) {
                Some(next) => {
                    index += push_unescaped(&mut key, *next, &bytes, index);
                }
                None => {
                    // A trailing backslash is a dangling continuation, and the
                    // caller already screened for that.
                    return Err(GradleParseError::DanglingContinuation { line: number });
                }
            }
            continue;
        }
        if c == '=' || c == ':' {
            separator = Some(index);
            break;
        }
        if c.is_whitespace() {
            // Whitespace ends the key, but only a *separator* follows: the
            // value may start with the next character.
            separator = Some(index);
            break;
        }
        key.push(c);
        index += 1;
    }

    let Some(separator) = separator else {
        return Err(GradleParseError::NoSeparator { line: number });
    };
    if key.is_empty() {
        return Err(GradleParseError::EmptyKey { line: number });
    }

    // Skip the separator itself and any whitespace after it.
    let mut rest = separator + 1;
    while rest < bytes.len() && bytes[rest].is_whitespace() {
        rest += 1;
    }

    let mut value = String::new();
    while rest < bytes.len() {
        let c = bytes[rest];
        if c == '\\' {
            match bytes.get(rest + 1) {
                Some(next) => {
                    rest += push_unescaped(&mut value, *next, &bytes, rest);
                }
                None => return Err(GradleParseError::DanglingContinuation { line: number }),
            }
            continue;
        }
        value.push(c);
        rest += 1;
    }

    Ok((key, value))
}

/// Decodes one escape sequence into `out`, returning how many **source**
/// characters it consumed starting at `at`.
///
/// The count is the whole reason this returns something. A caller that
/// assumed two characters — the backslash and whatever follows it — decoded
/// `\u00e9` and then read the four hex digits again as literals, producing
/// `é00e9` and a length that described a string the file does not contain.
/// `\uXXXX` consumes six; everything else consumes two.
fn push_unescaped(out: &mut String, c: char, all: &[char], at: usize) -> usize {
    match c {
        'n' => {
            out.push('\n');
            2
        }
        'r' => {
            out.push('\r');
            2
        }
        't' => {
            out.push('\t');
            2
        }
        'f' => {
            out.push('\u{c}');
            2
        }
        'u' => {
            // `\uXXXX` is four hex digits. A short run is left as the literal
            // characters rather than guessed at: reporting a wrong length
            // because a malformed escape was interpreted optimistically is the
            // failure this parser is refusing to make everywhere else.
            let digits: String = all
                .get(at + 2..at + 6)
                .map(|slice| slice.iter().collect())
                .unwrap_or_default();
            if digits.len() == 4 && digits.chars().all(|d| d.is_ascii_hexdigit()) {
                if let Some(decoded) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(decoded);
                    // Six source characters: `\`, `u`, and the four digits.
                    return 6;
                }
            }
            out.push('\\');
            out.push('u');
            // Two, because the digits after this are read as the ordinary
            // literal characters they are — which is what leaving a malformed
            // escape alone is supposed to mean.
            2
        }
        other => {
            out.push(other);
            2
        }
    }
}

/// Turns parsed pairs into the two lists the report carries.
fn classify(pairs: Vec<Pair>) -> (Vec<GradleCredentialEntry>, Vec<UndescribedEntry>) {
    let mut credentials = Vec::new();
    let mut undescribed = Vec::new();
    for (key, value) in pairs {
        match credential_kind(&key) {
            Some(kind) => {
                let (len, is_env_reference, env_reference) = describe_value(&value);
                credentials.push(GradleCredentialEntry {
                    key,
                    kind,
                    len,
                    is_env_reference,
                    env_reference,
                });
            }
            None => undescribed.push(UndescribedEntry {
                key,
                len: value.len(),
            }),
        }
    }
    (credentials, undescribed)
}

/// The credential a key carries, if it is one this adapter names.
///
/// Matching is exact and case-sensitive because Gradle's property names are
/// case-sensitive and `StorePassword` is not `storePassword`. A prefix match
/// would be more generous and would also quietly turn `storePasswordBackup`
/// into a credential, which is the sort of thing an operator has to notice.
fn credential_kind(key: &str) -> Option<GradleCredential> {
    Some(match key {
        "storeUser" => GradleCredential::RepositoryStoreUser,
        "storePassword" => GradleCredential::RepositoryStorePassword,
        "keyAlias" => GradleCredential::SigningKeyAlias,
        "keyPassword" => GradleCredential::SigningKeyPassword,
        "systemProp.http.proxyUser" => GradleCredential::ProxyUser,
        "systemProp.http.proxyPassword" => GradleCredential::ProxyPassword,
        _ => return None,
    })
}

/// Describes a value without ever reporting it.
///
/// Gradle's own convention is `${VAR}`; Maven's `${env.VAR}` is accepted too,
/// because a properties file is exactly where a build written against the
/// other spelling would land.
fn describe_value(value: &str) -> (Option<usize>, bool, Option<String>) {
    let trimmed = value.trim();
    if let Some(name) = trimmed
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        let name = name.strip_prefix("env.").unwrap_or(name);
        if !name.is_empty() {
            // The text in the file is a reference, not the credential. Its
            // length measures nothing and is therefore not reported.
            return (None, true, Some(name.to_string()));
        }
    }
    (Some(value.len()), false, None)
}
#[cfg(test)]
#[path = "gradle/tests.rs"]
mod tests;
