//! The npm family: what a `.npmrc` says, described without reading a credential.
//!
//! # The property this module exists to hold
//!
//! `discover` reports a `.npmrc`. An operator reads the report, decides, and
//! later something acts on the file. **In between, the report has been through a
//! terminal, a log, a CI artefact and an agent's context** — so if a token can
//! reach the report, it has been in five places that are not the vault, and the
//! discovery step was the one that put it there.
//!
//! So the report does not redact. It has nowhere to put a secret. There is no
//! `token: String` that a future edit fills in and no `Debug` that prints one,
//! because [`NpmDiscovery`] and everything it contains is made of hostnames,
//! field names, lengths and booleans. The value of an auth selector is
//! reported as its **length** and whether it is an environment reference.
//!
//! That is why there is no `value_digest` either, which looks like the careful
//! choice and is not: a digest of one extracted value is an oracle for that
//! value, and `_auth` is base64 of `user:password`, which is low-entropy enough
//! to confirm a guess. The *file* digest in [`FileFingerprint`] is safe by
//! contrast, because confirming a guess against it means guessing every byte of
//! the file including the secret.
//!
//! # What is deliberately not read
//!
//! - **No interpolation.** npm expands `${NPM_TOKEN}` from the environment. This
//!   does not: the environment belongs to whoever ran the command, which is not
//!   the trust domain the config file is in, and a report that resolved it would
//!   be reporting a value the file does not contain. The variable *name* is
//!   reported, because that is what an operator needs in order to know what to
//!   project.
//! - **No `include:`.** npm's `include` pulls in another file. Following it
//!   would mean describing a file the operator did not name and fingerprinting
//!   a config whose meaning we only half know, so it is refused with a message
//!   naming the two ways to make it work. `plan` cannot revalidate what
//!   `discover` never read.
//! - **No defaulting.** A `.npmrc` that declares no registry is reported as
//!   declaring no registry. Substituting `registry.npmjs.org` would be a
//!   convenient lie with the same shape as a real observation, and an operator
//!   cannot tell the two apart in a report.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::registry_audience::RegistryAudience;

use crate::fingerprint::{FileFingerprint, FingerprintError, FingerprintPolicy};
use crate::{Adapter, AnyReport, Candidate, Discovery, Finding, Severity};

/// The npm adapter.
///
/// A zero-sized type, because the family's discovery depends on nothing but
/// the filesystem and a policy — there is no configuration to construct, and a
/// builder here would be an invitation to put one somewhere that matters.
#[derive(Debug, Clone, Copy, Default)]
pub struct Npm;

impl Adapter for Npm {
    const FAMILY: &'static str = "npm";

    type Report = NpmDiscovery;
    type Error = NpmError;

    /// Where npm looks, in the order npm looks.
    ///
    /// Project first, then the user config, then the global one, because that
    /// is the order in which later files override earlier ones and a report
    /// that listed them in another order would describe an effective config
    /// nobody has. `npm_config_userconfig` and friends are **not** honoured here
    /// for the same reason `${VAR}` is not: the environment is the caller's, not
    /// the file's, and a discovery that silently changed which files it read
    /// based on an environment variable could be pointed somewhere by whoever
    /// set it.
    fn candidates(home: &Path, cwd: &Path) -> Vec<Candidate> {
        vec![
            Candidate {
                path: cwd.join(".npmrc"),
                origin: Origin::Project,
            },
            Candidate {
                path: home.join(".npmrc"),
                origin: Origin::User,
            },
            Candidate {
                path: home.join(".npm").join("npmrc"),
                origin: Origin::Global,
            },
        ]
    }

    fn discover(
        &self,
        policy: &FingerprintPolicy,
        home: &Path,
        cwd: &Path,
    ) -> Result<NpmDiscovery, NpmError> {
        let mut found = Vec::new();
        let mut findings = Vec::new();
        for candidate in Self::candidates(home, cwd) {
            match policy.fingerprint(&candidate.path) {
                Ok(fingerprint) => {
                    let contents = read_refused(&candidate.path, &fingerprint)?;
                    let parsed = parse(&contents).map_err(|error| NpmError::Parse {
                        path: candidate.path.clone(),
                        error,
                    })?;
                    findings.extend(parsed.findings.iter().cloned());
                    found.push(NpmFile {
                        origin: candidate.origin,
                        fingerprint,
                        registry: parsed.registry,
                        scoped_registries: parsed.scoped_registries,
                        auth_selectors: parsed.auth_selectors,
                        settings: parsed.settings,
                    });
                }
                Err(FingerprintError::Unreadable { error, .. })
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    // An absent file is not a finding. npm's own precedence
                    // means most machines have one or two of the three, and a
                    // report listing three refusals where two are "there is
                    // nothing here" would train the reader to skim it.
                    continue;
                }
                Err(error) => {
                    findings.push(Finding {
                        severity: Severity::Refused,
                        subject: candidate.path.display().to_string(),
                        message: error.to_string(),
                    });
                }
            }
        }
        if found.is_empty() && findings.is_empty() {
            return Err(NpmError::NothingFound);
        }
        Ok(NpmDiscovery { files: found })
    }
}

/// Read a file whose fingerprint has already been taken.
///
/// A second `open`, and therefore a second chance for the file to change between
/// the fingerprint and the parse. That window is real and it is not closed here
/// — closing it means parsing the bytes the fingerprint was taken over, which is
/// R3's `adopt` step to get right. What is done is making the window
/// *addressable*: [`NpmFile::fingerprint`] is the state at read time, and
/// `plan` revalidates against the live file before anything is written. A
/// report that said "this is the file" when it had read a different one would
/// be the actual bug, and the fix for that is to revalidate rather than to
/// pretend the first read is authoritative.
fn read_refused(path: &Path, _fingerprint: &FileFingerprint) -> Result<String, NpmError> {
    std::fs::read_to_string(path).map_err(|error| NpmError::Unreadable {
        path: path.to_path_buf(),
        error,
    })
}

/// Which of npm's files this is.
///
/// The levels are documented once, on the crate-level [`Origin`], because the
/// second family's precedence had to fit the same vocabulary -- which is the
/// point R3's exit criterion asks for. A re-export rather than a type alias so
/// `npm::Origin` keeps naming what npm's own report contains.
pub use crate::Origin;

/// One file, described.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmFile {
    pub origin: Origin,
    pub fingerprint: FileFingerprint,
    /// The default registry, if this file sets one. `None` means it sets none,
    /// and never means "the default one".
    pub registry: Option<Registry>,
    /// Per-scope registries, `package.json`'s `publishConfig` family of settings
    /// as they appear in an `.npmrc`.
    pub scoped_registries: Vec<ScopedRegistry>,
    /// `//host/:_authToken` and its relatives.
    pub auth_selectors: Vec<AuthSelector>,
    /// Non-secret settings worth knowing about, sorted by key.
    pub settings: BTreeMap<String, SettingValue>,
}

/// A registry an auth selector or a scope points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    /// The canonical endpoint a later binding would name.
    ///
    /// **Not** an `asv_domain::Authority`, and the type says why: an API
    /// audience is a bare multi-label host and has to be, while a package
    /// registry is very often `localhost:4873` or `registry.internal:8080`.
    /// See [`crate::registry_audience`] for the whole argument.
    pub audience: RegistryAudience,
    /// The URL as written, kept for the operator who has to edit the file. Not
    /// used for any comparison.
    pub url: String,
    /// The path component, when the registry is not at the host root. npm scopes
    /// auth selectors by path, and a selector for `//host/npm/` does not cover
    /// `//host/`.
    pub path_prefix: String,
}

/// A `@scope:registry` line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedRegistry {
    pub scope: String,
    pub registry: Registry,
}

/// A `//host/:field` line — where a credential would live, without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSelector {
    pub registry: Registry,
    pub field: AuthField,
    /// The length of the value, in bytes.
    ///
    /// Reported because "there is a credential here and it is empty" and "there
    /// is a credential here" are different findings, and neither is legible from
    /// the field name alone. A length is not a value: it does not narrow a
    /// high-entropy token meaningfully and it is not an oracle for a low-entropy
    /// one, because the caller would still have to produce the value.
    pub value_len: usize,
    /// Whether the value is `${VAR}` rather than a literal.
    pub value_is_env_reference: bool,
    /// The variable name, when it is one. A name is not a value.
    pub env_reference: Option<String>,
}

/// The field an auth selector carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthField {
    AuthToken,
    /// Base64 of `user:password` — the low-entropy one, and the reason this
    /// crate emits no per-value digests.
    Auth,
    Username,
    Password,
    Email,
    CertFile,
    KeyFile,
    /// A key starting `//` whose field is not one of the above.
    ///
    /// Reported rather than ignored, and **not** guessed at. A key like
    /// `//host/:_authTokne` is a typo that npm ignores, and a report that
    /// quietly dropped it would leave an operator believing their credential is
    /// configured.
    Unrecognised(String),
}

impl std::fmt::Display for AuthField {
    /// The spelling npm uses, which is also the one an operator would grep for.
    ///
    /// `Display` rather than a method on the CLI side because the spelling is a
    /// fact about npm's configuration format rather than about a front end: a
    /// second renderer that spelled it differently would produce a report that
    /// does not match the file it describes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AuthToken => "_authToken",
            Self::Auth => "_auth",
            Self::Username => "username",
            Self::Password => "_password",
            Self::Email => "email",
            Self::CertFile => "certfile",
            Self::KeyFile => "keyfile",
            Self::Unrecognised(name) => name,
        })
    }
}

/// A non-secret setting, and whether its value is worth reporting verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingValue {
    /// Safe to print: `true`, a path, a URL npm will not treat as a credential.
    Literal(String),
    /// A value that may be sensitive, reported as its length only.
    Opaque { len: usize },
    /// A `${VAR}` reference: the name is reported, the value is not read.
    EnvReference(String),
}

/// Settings whose value is a path or a boolean and is safe to print, and
/// settings that get the opaque treatment.
const OPAQUE_SETTINGS: &[&str] = &["_password", "password", "token"];

/// Everything one npm discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmDiscovery {
    pub files: Vec<NpmFile>,
}

impl NpmDiscovery {
    /// Every audience named by an auth selector, in a stable order.
    ///
    /// What `plan` will bind against, and what a caller asking "which registries
    /// does this project talk to" wants. Sorted and deduplicated so the answer
    /// does not depend on file order.
    pub fn audiences(&self) -> Vec<RegistryAudience> {
        let mut out: Vec<RegistryAudience> = self
            .files
            .iter()
            .flat_map(|file| file.auth_selectors.iter())
            .map(|selector| selector.registry.audience.clone())
            .collect();
        // Sorted by the canonical spelling rather than by `Ord` on the struct,
        // so the order in a report is one a reader can predict and does not
        // change if the struct gains a field.
        out.sort_by_key(|audience| audience.to_string());
        out.dedup();
        out
    }
}

impl From<NpmDiscovery> for AnyReport {
    fn from(report: NpmDiscovery) -> Self {
        Self::Npm(report)
    }
}

impl NpmDiscovery {
    /// Wraps this family's report in the shape the CLI prints.
    pub fn into_discovery(self) -> Discovery {
        Discovery::new(Npm::FAMILY, AnyReport::Npm(self))
    }
}

/// Why npm discovery could not produce a report.
#[derive(Debug, thiserror::Error)]
pub enum NpmError {
    #[error("no .npmrc was found in the project, the home directory or the npm prefix")]
    NothingFound,
    #[error("cannot read {path}: {error}")]
    Unreadable {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    // The line number is in the inner error, which names it, so this wrapper
    // does not carry one. `ParseError`'s own field is `at_line` rather than
    // `line` because `format!` has a built-in `line` capture: `{line}` resolves
    // to `std::line!()` and the derive fails with "expected value, found macro
    // `line`". A field name that shadows a macro is one that gets renamed by
    // whoever hits it next.
    #[error("{path}: {error}")]
    Parse {
        path: PathBuf,
        #[source]
        error: ParseError,
    },
}

/// What the parser makes of a `.npmrc`'s bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub registry: Option<Registry>,
    pub scoped_registries: Vec<ScopedRegistry>,
    pub auth_selectors: Vec<AuthSelector>,
    pub settings: BTreeMap<String, SettingValue>,
    pub findings: Vec<Finding>,
}

/// Why a `.npmrc` could not be parsed at all.
///
/// Every variant refuses the **file**, not one line. An ini whose meaning
/// depends on a directive this parser does not implement cannot be described,
/// and describing the parts that parsed would be a report that reads complete.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("`include:` is not followed; it would describe a file you did not name")]
    IncludeRefused { at_line: usize },
    #[error("`{key}` is longer than {limit} bytes")]
    KeyTooLong {
        at_line: usize,
        key: String,
        limit: usize,
    },
    #[error("line is not `key=value`")]
    NotAKeyValue { at_line: usize },
}

/// The longest key this parser will look at.
///
/// npm's own limit is not the reason. The reason is that a `.npmrc` is a file
/// an operator may not control, and a key is copied into a report that a human
/// reads; a megabyte-long key is a way to put a megabyte into a terminal.
const MAX_KEY_BYTES: usize = 512;

/// Parse `.npmrc` contents.
///
/// Not a general ini parser and does not claim to be: npm's dialect is what
/// this needs, and the ways the two differ are the ways a *security* report
/// would be wrong. `[section]` headers are honoured because npm honours them
/// (an `include` inside a section is still an `include`), `\`-continuations are
/// honoured because npm honours them, and everything else is refused by not
/// existing.
pub fn parse(contents: &str) -> Result<Parsed, ParseError> {
    let mut out = Parsed::default();
    let mut section = String::new();

    for (index, raw) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            // **Slice the inside**, do not strip the ends independently.
            //
            // The first version called `strip_suffix(']')` on the whole line and
            // used its result as the section name, which is `"[scope"` — the
            // opening bracket included, because nothing had removed it. Every
            // key in the section then came out as `[scope:key`, a section header
            // this parser invented, in a report nobody had reason to doubt. The
            // second version checked for both brackets and still got it wrong,
            // for the same reason: two independent `strip_*` calls on one string
            // are not a slice. The row is
            // `comments_blank_lines_and_sections_are_handled`, and it is the
            // reason the code reads the way it does.
            let Some(inner) = trimmed
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            else {
                return Err(ParseError::NotAKeyValue {
                    at_line: line_number,
                });
            };
            section = inner.trim().to_string();
            continue;
        }
        // npm treats a key as ending at the first `=`, so a value may contain
        // more of them — a URL with a query string is the ordinary case.
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(ParseError::NotAKeyValue {
                at_line: line_number,
            });
        };
        let key = key.trim();
        let value = value.trim();
        if key.len() > MAX_KEY_BYTES {
            return Err(ParseError::KeyTooLong {
                at_line: line_number,
                key: key.chars().take(64).collect(),
                limit: MAX_KEY_BYTES,
            });
        }
        // A section qualifies the keys inside it, so `[_auth]` in a section is
        // `section:_auth` and the auth detection below sees the same shape npm
        // would.
        let key = if section.is_empty() {
            key.to_string()
        } else {
            format!("{section}:{key}")
        };

        // Refused before anything else looks at it, because `include` changes
        // what the rest of the file means and there is no correct way to report
        // a config whose meaning is somewhere else.
        if key == "include" || key.starts_with("include:") {
            return Err(ParseError::IncludeRefused {
                at_line: line_number,
            });
        }

        classify(&key, value, &mut out);
    }
    Ok(out)
}

/// One `key=value`, sorted into the report.
fn classify(key: &str, value: &str, out: &mut Parsed) {
    if let Some(field) = auth_field(key) {
        match registry_from_auth_key(key) {
            Ok(registry) => out.auth_selectors.push(AuthSelector {
                registry,
                field,
                value_len: value.len(),
                value_is_env_reference: env_reference(value).is_some(),
                env_reference: env_reference(value),
            }),
            // A selector whose host will not canonicalize is still a selector:
            // dropping it would leave an operator believing no credential is
            // configured, when the truth is that one is and this tool cannot say
            // where it points. Reported as a finding and absent from the typed
            // list, so nothing downstream can act on an unverified audience.
            Err(message) => out.findings.push(Finding {
                severity: Severity::Warning,
                subject: key.to_string(),
                message,
            }),
        }
        return;
    }
    if let Some(scope) = key.strip_suffix(":registry") {
        if scope.starts_with('@') {
            match registry(value, "") {
                Ok(registry) => out.scoped_registries.push(ScopedRegistry {
                    scope: scope.to_string(),
                    registry,
                }),
                Err(message) => out.findings.push(Finding {
                    severity: Severity::Warning,
                    subject: key.to_string(),
                    message,
                }),
            }
            return;
        }
    }
    if key == "registry" {
        match registry(value, "") {
            Ok(registry) => out.registry = Some(registry),
            Err(message) => out.findings.push(Finding {
                severity: Severity::Warning,
                subject: key.to_string(),
                message,
            }),
        }
        return;
    }
    if key == "always-auth" || key == "cafile" || key == "strict-ssl" || key == "proxy" {
        out.settings
            .insert(key.to_string(), SettingValue::Literal(value.to_string()));
        return;
    }
    if OPAQUE_SETTINGS.contains(&key) {
        out.settings.insert(
            key.to_string(),
            match env_reference(value) {
                Some(name) => SettingValue::EnvReference(name),
                None => SettingValue::Opaque { len: value.len() },
            },
        );
        return;
    }
    // Anything else is a setting this parser does not model. It is not reported
    // as absent — the key is recorded as opaque so the report says "there is
    // something here I am not describing", which is different from "there is
    // nothing here".
    out.settings
        .insert(key.to_string(), SettingValue::Opaque { len: value.len() });
}

/// The auth field a `//`-prefixed key names, if it names one this knows.
fn auth_field(key: &str) -> Option<AuthField> {
    if !key.starts_with("//") {
        return None;
    }
    // The field is whatever follows the **last** colon, because the registry may
    // contain one of its own: `//localhost:4873/:_authToken` is a real and
    // common local-registry line, and splitting on the first colon would read
    // its host as `localhost`.
    let (_, suffix) = key.rsplit_once(':')?;
    Some(match suffix {
        "_authToken" => AuthField::AuthToken,
        "_auth" => AuthField::Auth,
        "username" => AuthField::Username,
        "_password" => AuthField::Password,
        "email" => AuthField::Email,
        "certfile" => AuthField::CertFile,
        "keyfile" => AuthField::KeyFile,
        other => AuthField::Unrecognised(other.to_string()),
    })
}

/// The registry a `//`-prefixed key addresses.
///
/// The host is taken from between `//` and the first `/`, so a local registry on
/// a port keeps its port, and the path prefix is carried separately because npm
/// scopes a selector to a path: one selector does not cover another path on the
/// same host.
fn registry_from_auth_key(key: &str) -> Result<Registry, String> {
    let body = key.trim_start_matches("//");
    let (host_and_path, _field) = body.rsplit_once(':').unwrap_or((body, ""));
    let (host, path_prefix) = match host_and_path.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (host_and_path, String::new()),
    };
    let audience = RegistryAudience::parse(host).map_err(|error| {
        format!("the auth selector for {host:?} has no canonical endpoint: {error}")
    })?;
    let url = format!("{}{path_prefix}", audience.url());
    Ok(Registry {
        audience,
        url,
        path_prefix,
    })
}

/// The `${VAR}` a value refers to, without reading what it points at.
fn env_reference(value: &str) -> Option<String> {
    let inner = value.strip_prefix("${")?.strip_suffix('}')?;
    // A name only. `${A}${B}` is not a name, and treating it as one would
    // report a variable that does not exist.
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(inner.to_string())
}

/// A registry from a URL, split into its endpoint and path and canonicalised.
///
/// A bare host is accepted, because that is how people write registries in
/// practice and refusing it would refuse the common case to enforce a spelling
/// npm tolerates. A scheme is stripped rather than trusted: the endpoint is what
/// a credential would later be bound to, and it comes from `RegistryAudience`
/// either way, so a scheme in the file cannot smuggle a different host in.
fn registry(value: &str, path_prefix: &str) -> Result<Registry, String> {
    let without_scheme = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    let (host, path) = split_registry_url(without_scheme, path_prefix)?;
    let audience = RegistryAudience::parse(&host)
        .map_err(|error| format!("the registry host {host:?} is not an endpoint: {error}"))?;
    Ok(Registry {
        audience,
        url: value.to_string(),
        path_prefix: if path_prefix.is_empty() {
            path
        } else {
            path_prefix.to_string()
        },
    })
}

/// The host and path of a registry URL, with the path defaulting to the root.
fn split_registry_url(value: &str, path_prefix: &str) -> Result<(String, String), String> {
    let (host, path) = match value.split_once('/') {
        Some((host, path)) => (host.to_string(), format!("/{path}")),
        None => (value.trim_end_matches('/').to_string(), String::new()),
    };
    if host.is_empty() {
        return Err("the registry has no host".to_string());
    }
    Ok((
        host,
        if path_prefix.is_empty() {
            path
        } else {
            path_prefix.to_string()
        },
    ))
}

#[cfg(test)]
mod tests;
