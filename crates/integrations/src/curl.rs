//! R3.B.3 — curl, the fourth family, and the third measurement.
//!
//! # What adding this family is actually for
//!
//! R3's exit criterion says a new adapter must be addable without touching
//! broker or domain. Maven measured it once and paid for it, lifting
//! `Candidate::origin` out of `npm::Origin` before a second family could speak.
//! Gradle measured it a second time and paid nothing. Two measurements is
//! still a sample, and the question this family answers is the one the
//! criterion is actually phrased in terms of: **does the shared vocabulary
//! still hold for a fourth shape?**
//!
//! curl is the shape the first three did not cover, and it is worth being
//! precise about which shape that is, because it is not the format.
//!
//! # The three things this family does differently
//!
//! **1. curl reads exactly one file. The other three read all of theirs.**
//!
//! npm layers project over user over global. Maven layers `settings.xml` over
//! `settings-security.xml` and lets both apply. Gradle layers project over user
//! over init script. All three merge, and all three can be described by listing
//! what each file contributed.
//!
//! curl does not merge. It walks an ordered list and takes **the first file
//! that exists**; the rest are never opened. `~/.curlrc` holding a credential
//! is invisible to a user who also has `~/.config/curlrc`, and no amount of
//! reading either file reveals that.
//!
//! So the honest report is not "here are the files". It is **which file won**,
//! plus the ones that were shadowed and never read — reported by path only,
//! because reading them is exactly what curl does not do.
//!
//! **2. The credential is compound, and no other family's is.**
//!
//! npm has tokens, Maven has passwords, Gradle has a user and a password in two
//! keys. curl puts **a username and a password on one line**, in
//! `user = "name:secret"`. That is a different report shape, not the same shape
//! with a longer value: an operator asking "who does this authenticate as" and
//! "what is the secret" is asking two questions, and reporting one length for
//! the pair answers neither.
//!
//! **3. curl does not expand environment variables, so there is no env-reference
//! case here at all.**
//!
//! npm expands `${NPM_TOKEN}`, Maven expands `${env.MVN_TOKEN}`, Gradle accepts
//! `${VAR}`. All three therefore carry an `env_reference` field, and all three
//! can tell a reference from a literal.
//!
//! A literal in a `.curlrc` **is** a literal. There is no spelling that stands
//! in for a variable, so the field would be a column that is `false` on every
//! row of every real file. It is absent rather than always-false: a column
//! that cannot discriminate is not information, and a report carrying it teaches
//! an operator to read a distinction that is not there.
//!
//! # The limit this family cannot cross
//!
//! **The first two entries of curl's lookup list are environment variables, and
//! this adapter cannot resolve them.** curl reads `$CURL_HOME/.curlrc` before
//! anything else, then `$XDG_CONFIG_HOME/curlrc`.
//!
//! [`crate::Adapter::discover`] takes `home` and `cwd` as arguments precisely so
//! that a report is about the *caller's* configuration and not about this
//! process's environment. Honouring `CURL_HOME` would mean reading
//! `std::env::var`, which is the thing the signature exists to prevent: two
//! calls to `discover` from one process would then be able to disagree about
//! the answer, and a report an agent acts on would depend on which process
//! happened to ask.
//!
//! So this adapter reads the two locations it can resolve and **says in the
//! report that it cannot see the rest**. A user with `CURL_HOME` set is told
//! their real configuration was not among the files examined, rather than being
//! handed a confident report about the wrong file. An adapter that resolved
//! `CURL_HOME` itself would be more complete and less true.
//!
//! # What this family is, and is not
//!
//! **It is `discover` and safe parse, on `.curlrc` files.** `plan`, `adopt`,
//! `binding` and the rest of R3's pipeline do not exist for curl and are not
//! simulated here.
//!
//! The project-level `.curlrc` is reachable by curl **only** through an
//! explicit `--config`, never automatically. It is listed as a candidate
//! because a repository that ships a `.curlrc` and scripts call
//! `curl -K .curlrc` is a real shape, and the report says which it was.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fingerprint::{FileFingerprint, FingerprintPolicy};
use crate::{Adapter, Candidate, Finding};

/// The largest `.curlrc` this adapter will read.
///
/// Checked against the byte length **before** the file is materialised. curl
/// itself imposes no size limit but does cap a single line at 10 MB since
/// 8.2.0, and a configuration file two orders of magnitude past that is not
/// configuration — it is a payload someone wrote into a file curl executes.
pub const MAX_CURLRC_BYTES: u64 = 1 << 18;

/// A ceiling on the number of option lines in one file.
///
/// curl's format has no nesting and no continuations, so there is no recursion
/// to bound and no depth to cap; breadth is the only axis on which a file can be
/// made pathological. A file with more than this many options is not a config.
pub const MAX_CURLRC_LINES: usize = 4096;

/// There is deliberately **no depth ceiling**, and its absence is the finding.
///
/// Maven needed [`crate::maven::MAX_DEPTH`] because `roxmltree` recurses once
/// per level. Gradle said the same of itself and was right. A `.curlrc` is a
/// flat list of lines parsed in a single pass with no recursion, so a depth
/// ceiling here would be a number that cannot be violated — which is not a
/// safety property, only the appearance of one.
pub const NO_DEPTH_LIMIT: () = ();

/// The curl family.
#[derive(Debug, Clone, Copy, Default)]
pub struct Curl;

impl crate::Adapter for Curl {
    const FAMILY: &'static str = "curl";

    type Report = CurlDiscovery;
    type Error = CurlError;

    /// **The measurement this family exists to take.**
    ///
    /// curl's own precedence is two environment-derived paths and one home
    /// path. [`crate::Origin`] already had the level this can express
    /// honestly — `User`, for both resolvable entries — so adding this family
    /// widened nothing in the shared vocabulary. That is the third measurement,
    /// and the second consecutive one that cost no change.
    ///
    /// What it did cost is a **correction**, and the correction is the finding.
    /// A first version of this adapter listed the project `.curlrc` first, on
    /// the reasoning that every other family on this list reads a project file
    /// and `Origin::Project` was already there to name it. That ordering is
    /// wrong, and wrong in the worst direction available: it made the project
    /// file shadow the home file, so a user with both would be told their
    /// credential lived in the one curl never reads automatically.
    ///
    /// The reason is that **curl has no project-level configuration**. A
    /// `.curlrc` beside the project is read only when something passes
    /// `--config .curlrc`, and that is a command-line choice this adapter
    /// cannot observe. So the project file is reported **apart from** the
    /// lookup, as [`CurlDiscovery::project_config`], and it never takes part in
    /// deciding which file won.
    ///
    /// This is the third family to fit [`crate::Origin`] without a change, and
    /// the first where fitting it required noticing that one of its levels does
    /// not apply. The criterion says a new adapter must be addable without
    /// touching broker or domain; it does not say every adapter has the same
    /// shape, and a family bent into `Project`-first to match its neighbours
    /// would have satisfied the criterion by lying about the tool.
    fn candidates(home: &Path, cwd: &Path) -> Vec<Candidate> {
        vec![
            // curl's second entry, at its default location. `$XDG_CONFIG_HOME`
            // when set is not resolvable here — see the module docs.
            Candidate {
                path: home.join(".config").join("curlrc"),
                origin: crate::Origin::User,
            },
            // curl's third entry, and the one an operator is most likely to have.
            Candidate {
                path: home.join(".curlrc"),
                origin: crate::Origin::User,
            },
            // **Not part of the lookup.** Listed so `candidates` names every
            // path this adapter looks at; `discover` splits it off so it can
            // never shadow the two above. See the method docs.
            Candidate {
                path: cwd.join(".curlrc"),
                origin: crate::Origin::Project,
            },
        ]
    }

    fn discover(
        &self,
        policy: &FingerprintPolicy,
        home: &Path,
        cwd: &Path,
    ) -> Result<Self::Report, CurlError> {
        let candidates = Self::candidates(home, cwd);
        let (automatic, project): (&[Candidate], &[Candidate]) = candidates.split_at(2);
        let mut findings: Vec<Finding> = Vec::new();
        let mut lookup: Vec<CurlFile> = Vec::new();

        // curl takes the first file that exists and stops. Reproducing that
        // order matters: reporting a merged view would describe a configuration
        // curl never runs.
        for candidate in automatic {
            if !candidate.path.exists() {
                continue;
            }
            // The first existing, readable file is the one curl uses. Every
            // later candidate is shadowed by it and is not opened at all.
            if let Some(winner) = lookup.iter().find(|f| f.fingerprint.is_some()) {
                lookup.push(shadowed(candidate, &winner.path));
                continue;
            }
            if let Some(file) = describe(candidate, policy, &mut findings) {
                lookup.push(file);
            }
        }

        // Read on its own terms, outside the lookup it is not part of.
        let project_config = project
            .iter()
            .find(|candidate| candidate.path.exists())
            .and_then(|candidate| describe(candidate, policy, &mut findings));

        // curl reads `$CURL_HOME/.curlrc` and `$XDG_CONFIG_HOME/curlrc` ahead of
        // every path this adapter can resolve, and neither is derivable without
        // reading the environment. Rather than silently reporting a narrower
        // truth, the report says so.
        let env_paths_unseen = true;

        Ok(CurlDiscovery {
            lookup,
            project_config,
            findings,
            env_paths_unseen,
        })
    }
}

/// A file that exists and will not be opened, because an earlier one won.
fn shadowed(candidate: &Candidate, winner: &Path) -> CurlFile {
    CurlFile {
        origin: candidate.origin,
        path: candidate.path.clone(),
        fingerprint: None,
        credentials: Vec::new(),
        options: Vec::new(),
        shadowed_by: Some(winner.to_path_buf()),
    }
}

/// Fingerprints, reads and parses one candidate, recording why it could not.
///
/// Every refusal is a **finding** and the run still succeeds. A family that
/// aborted on the first unreadable file would report "curl is not configured"
/// about a machine that has three `.curlrc` files, and that is the answer
/// operators accept and act on.
fn describe(
    candidate: &Candidate,
    policy: &FingerprintPolicy,
    findings: &mut Vec<Finding>,
) -> Option<CurlFile> {
    let refused = |message: String| Finding {
        severity: crate::Severity::Refused,
        subject: candidate.path.display().to_string(),
        message,
    };

    let fingerprint = match policy.fingerprint(&candidate.path) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            findings.push(refused(error.to_string()));
            return None;
        }
    };
    let text = match read_capped(&candidate.path) {
        Ok(text) => text,
        Err(error) => {
            findings.push(refused(error.to_string()));
            return None;
        }
    };
    match parse_curlrc(&text) {
        Ok(options) => {
            let (credentials, rest) = classify(options);
            Some(CurlFile {
                origin: candidate.origin,
                path: candidate.path.clone(),
                fingerprint: Some(fingerprint),
                credentials,
                options: rest,
                shadowed_by: None,
            })
        }
        Err(error) => {
            findings.push(refused(error.to_string()));
            None
        }
    }
}

/// Everything one curl discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurlDiscovery {
    /// curl's automatic lookup, in curl's own order, **including the entries it
    /// never opened**.
    ///
    /// Separate from [`Self::project_config`] on purpose. The project file is
    /// not a lower-precedence layer of the same thing; it is not part of the
    /// lookup at all, and listing it inside would put it in the same list whose
    /// order decides which file wins.
    pub lookup: Vec<CurlFile>,
    /// A `.curlrc` beside the working directory, which curl reads **only** when
    /// a command names it with `--config`. Reported, because a repository that
    /// ships one and scripts call `curl -K .curlrc` is a real shape — and
    /// labelled, because an operator reading it as their effective
    /// configuration would be reading a file curl never chose.
    pub project_config: Option<CurlFile>,
    /// Files that were found and not read, and why.
    pub findings: Vec<Finding>,
    /// Always `true`, and never anything else.
    ///
    /// curl reads `$CURL_HOME/.curlrc` and `$XDG_CONFIG_HOME/curlrc` ahead of
    /// every path this adapter can resolve, and neither is derivable without
    /// reading the environment — which [`crate::Adapter::discover`] exists to
    /// avoid. A reader who does not see this field will take the file list for
    /// the whole of what curl could have used, so it is stated rather than
    /// left as a footnote in a module doc nobody opens.
    pub env_paths_unseen: bool,
}

impl From<CurlDiscovery> for crate::AnyReport {
    fn from(report: CurlDiscovery) -> Self {
        Self::Curl(report)
    }
}

impl CurlDiscovery {
    /// Wraps this family's report in the shape the CLI prints.
    pub fn into_discovery(self) -> crate::Discovery {
        crate::Discovery::new(Curl::FAMILY, crate::AnyReport::Curl(self))
    }

    /// The one file curl would actually read, if one was found and readable.
    ///
    /// The first entry with a fingerprint, or `None`. Convenience over a
    /// filter in every caller, and named for what it answers.
    /// The one file curl would read on its own, if one was found and readable.
    ///
    /// The first entry of the **lookup** carrying a fingerprint, or `None`. The
    /// project config is deliberately excluded: it is not in the lookup, and a
    /// method named `effective` that could return it would be answering a
    /// question curl was never asked.
    pub fn effective(&self) -> Option<&CurlFile> {
        self.lookup.iter().find(|file| file.fingerprint.is_some())
    }

    /// Every file the report carries a claim about, lookup and project alike.
    ///
    /// For callers that want "was there anything here at all" without caring
    /// which list it came from.
    pub fn considered(&self) -> Vec<&CurlFile> {
        self.lookup
            .iter()
            .chain(self.project_config.iter())
            .collect()
    }
}

/// One `.curlrc`, described — or explicitly not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CurlFile {
    pub origin: crate::Origin,
    pub path: PathBuf,
    /// `None` when this file was **not read**, which is not the same as being
    /// read and holding nothing.
    ///
    /// curl takes one file and stops, so a report that filled this in for every
    /// entry would be describing a merge curl does not perform.
    pub fingerprint: Option<FileFingerprint>,
    /// The credential-bearing options, which are the only lines whose values
    /// this adapter models.
    pub credentials: Vec<CurlCredentialEntry>,
    /// Every other option, named and measured.
    ///
    /// The bulk of a real `.curlrc`, for the same reason it is the bulk of a
    /// `gradle.properties`: a file of twenty lines may hold one credential, and
    /// an adapter that reported "20 entries" as though it meant twenty secrets
    /// would be reporting a number no operator could act on.
    pub options: Vec<CurlOption>,
    /// Set when an earlier candidate exists, which makes this one unread.
    ///
    /// A path, never a fingerprint: the file was not opened, so there is no
    /// inode and no digest to report, and inventing one would be the report
    /// claiming it read something it did not.
    pub shadowed_by: Option<PathBuf>,
}

/// One credential-bearing option.
///
/// **Compound by construction.** curl's `user` carries `name:secret` on one
/// line, so this reports two lengths and neither value. Reporting the length of
/// the whole line would answer neither question an operator has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CurlCredentialEntry {
    /// The option as written, without its leading dashes and in lower case:
    /// `user` or `proxy-user`. Normalised deliberately, because curl accepts
    /// `--user`, `-u` and `user` for the same option and a report listing three
    /// rows for one credential would be counting spellings.
    pub option: String,
    pub kind: CurlCredential,
    /// Length of the username half, in bytes. A name is not a secret, but it is
    /// still not printed here: a report that prints usernames hands out the half
    /// of the pair an attacker needs to target, and the length is what tells an
    /// operator whether something is there.
    pub user_len: usize,
    /// Length of the password half in bytes, never the password.
    pub password_len: usize,
    /// Whether a password half was present at all.
    ///
    /// `user = "alice"` authenticates as `alice` with an empty password, which
    /// is a real and reachable configuration and a different fact from one
    /// where no password was written.
    pub has_password: bool,
}

/// The options this adapter names as carrying a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurlCredential {
    /// `user` / `-u` — HTTP Basic or Digest credentials, `name:secret`.
    User,
    /// `proxy-user` — the same pair, spent on the proxy instead.
    ProxyUser,
}

/// An option this adapter does not model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CurlOption {
    /// The option name, normalised as above.
    pub option: String,
    /// Whether a value was given at all. `silent` and `silent = yes` are both
    /// flags; `--max-time 30` is not.
    pub has_value: bool,
    /// The value's length in bytes when there is one, never the value.
    pub len: Option<usize>,
}

/// Why a curl discovery could not produce a report at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurlError {
    /// The file is larger than [`MAX_CURLRC_BYTES`].
    TooLarge { path: String, len: u64 },
    /// The file could not be read.
    Io { path: String, message: String },
}

impl fmt::Display for CurlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurlError::TooLarge { path, len } => write!(
                f,
                "{path} is {len} bytes, past the {MAX_CURLRC_BYTES}-byte ceiling; \
                 refused without being read"
            ),
            CurlError::Io { path, message } => {
                write!(f, "{path} could not be read: {message}")
            }
        }
    }
}

impl std::error::Error for CurlError {}

/// Reads a file, refusing it on size before any of it is materialised.
fn read_capped(path: &Path) -> Result<String, CurlError> {
    let metadata = std::fs::metadata(path).map_err(|e| CurlError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    if metadata.len() > MAX_CURLRC_BYTES {
        return Err(CurlError::TooLarge {
            path: path.display().to_string(),
            len: metadata.len(),
        });
    }
    std::fs::read_to_string(path).map_err(|e| CurlError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

/// One parsed option line.
///
/// Public because [`parse_curlrc`] is: a caller that wants to inspect what the
/// parser read — which is what a row proving the parser refuses rather than
/// guesses needs — cannot name the type it is handed otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOption {
    /// Normalised: lowercase, leading dashes removed.
    name: String,
    /// `None` for a flag written with no value.
    value: Option<String>,
}

/// Parses the curl config format.
///
/// **It refuses rather than guesses, for the reason the other two families do.**
/// A value this parser invented would be a length in the report describing
/// nothing on disk, and an operator acting on a length they cannot reproduce is
/// worse off than one who was told the file could not be read.
///
/// The format, from `curl --help config` and the `-K` man entry:
///
/// - one option per physical line; there are no continuations;
/// - option and value are separated by whitespace, `:`, or `=`;
/// - **if the option was written with leading dashes, `:` and `=` are not
///   separators** — only whitespace is;
/// - a value containing whitespace, or starting with `:` or `=`, is
///   double-quoted, and inside quotes `\\`, `\"`, `\t`, `\n`, `\r` and `\v` are
///   escapes; a backslash before any other letter is ignored;
/// - `#` in the first non-blank column makes the line a comment.
pub fn parse_curlrc(text: &str) -> Result<Vec<ParsedOption>, CurlParseError> {
    let mut options = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;

        // "# in the first non-blank column", so leading whitespace does not
        // turn a comment into an option. Trimming first would make
        // "   # comment" parse as an option named "#", which curl never does.
        let trimmed_start = raw.trim_start();
        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            continue;
        }

        let line = trimmed_start.trim_end();
        if options.len() >= MAX_CURLRC_LINES {
            return Err(CurlParseError::TooManyLines { number });
        }

        let (name, rest) = split_option(line)?;

        if name.is_empty() {
            return Err(CurlParseError::Malformed { number });
        }

        let value = match rest {
            None => None,
            Some(raw_value) => Some(unescape_value(raw_value, number)?),
        };

        options.push(ParsedOption { name, value });
    }

    Ok(options)
}

/// Splits a line into its option name and the raw value that followed.
///
/// Returns the **normalised** name: leading dashes removed and lower-cased, so
/// `--user`, `-u` and `USER` are one option rather than three rows in a report.
///
/// The separator is the first of whitespace, `:` or `=` — but only whitespace
/// when the option was written with leading dashes, which is curl's rule and the
/// one a parser gets wrong most easily. `user = "x"` has a space *and* an `=`;
/// reading the space and stopping leaves `= "x"` as the value, and every
/// downstream length is then a measurement of a character the file does not
/// contain.
fn split_option(line: &str) -> Result<(String, Option<&str>), CurlParseError> {
    let dashed = line.starts_with('-');
    let body = line.trim_start_matches('-');

    if body.is_empty() {
        // "-" or "--" alone. curl treats these as separators, not options, so
        // the line has no name and the caller reports it as malformed.
        return Ok((String::new(), None));
    }

    let end = if dashed {
        body.find(char::is_whitespace)
    } else {
        body.find(|c: char| c.is_whitespace() || c == ':' || c == '=')
    };

    // "If the option is specified with one or two dashes, there can be no
    // colon or equals character between the option and its parameter."
    //
    // Checked against the **name** and not the whole line, and before any early
    // return. Both matter: `--data a=b` has an `=` and is perfectly valid,
    // because the `=` is inside the value; and the case this rule exists to
    // catch is `--user=alice`, which has *no whitespace at all* — so a check
    // placed after the no-separator branch is a check that never fires.
    let name_end = end;
    let name = match name_end {
        Some(at) => &body[..at],
        None => body,
    };
    if dashed && (name.contains(':') || name.contains('=')) {
        return Err(CurlParseError::DashedSeparator {
            name: name.to_string(),
        });
    }

    let Some(end) = end else {
        return Ok((normalise(body), None));
    };

    // Skip the separator itself when it is `:` or `=`, and the whitespace around
    // it, so `user = "x"` and `user=x` both yield `"x"`.
    let mut rest = body[end..].trim_start();
    if let Some(&c) = rest.as_bytes().first() {
        if c == b':' || c == b'=' {
            rest = rest[1..].trim_start();
        }
    }

    Ok((
        normalise(name),
        if rest.is_empty() { None } else { Some(rest) },
    ))
}

/// Lower-cases and keeps the option name as curl itself compares it.
fn normalise(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Decodes a quoted value, honouring curl's escape table.
///
/// curl's rule is short and specific: inside double quotes `\\`, `\"`, `\t`,
/// `\n`, `\r` and `\v` are escapes and **a backslash before any other letter is
/// ignored** — the backslash goes and the letter stays. Getting that wrong is
/// how a Windows path in a `.curlrc` comes back a byte short.
fn unescape_value(raw: &str, number: usize) -> Result<String, CurlParseError> {
    let raw = raw.trim();
    if raw.len() < 2 || !raw.starts_with('"') {
        // An unquoted value is taken literally. This is not a guess: curl
        // accepts it, and rejecting every unquoted value would refuse the file
        // most `.curlrc` files actually are.
        return Ok(raw.to_string());
    }
    if !raw.ends_with('"') {
        return Err(CurlParseError::UnterminatedQuote { number });
    }

    let inner = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(next) = chars.next() else {
            // A trailing backslash inside the quotes: curl drops it.
            break;
        };
        match next {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            'v' => out.push('\u{0b}'),
            // "A backslash preceding any other letter is ignored."
            other => out.push(other),
        }
    }
    Ok(out)
}

/// What went wrong inside a `.curlrc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurlParseError {
    /// A line whose option could not be separated from its value.
    Malformed { number: usize },
    /// A quoted value that never closed.
    UnterminatedQuote { number: usize },
    /// A dashed option followed by `:` or `=`, which curl does not accept.
    DashedSeparator { name: String },
    /// More option lines than [`MAX_CURLRC_LINES`].
    TooManyLines { number: usize },
}

impl fmt::Display for CurlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurlParseError::Malformed { number } => {
                write!(f, "line {number} has no option name")
            }
            CurlParseError::UnterminatedQuote { number } => {
                write!(f, "line {number} opens a quote it never closes")
            }
            CurlParseError::DashedSeparator { name } => write!(
                f,
                "`{name}` puts a ':' or '=' after a dashed option; curl accepts only \
                 whitespace there, so this is not a spelling of anything"
            ),
            CurlParseError::TooManyLines { number } => write!(
                f,
                "line {number} is past the {MAX_CURLRC_LINES}-line ceiling; \
                 refused without being read further"
            ),
        }
    }
}

impl std::error::Error for CurlParseError {}

/// Splits parsed options into the two lists the report carries.
fn classify(options: Vec<ParsedOption>) -> (Vec<CurlCredentialEntry>, Vec<CurlOption>) {
    let mut credentials = Vec::new();
    let mut rest = Vec::new();

    for option in options {
        let kind = match option.name.as_str() {
            "user" | "u" => Some(CurlCredential::User),
            "proxy-user" => Some(CurlCredential::ProxyUser),
            _ => None,
        };

        match kind {
            Some(kind) => credentials.push(credential_entry(option, kind)),
            None => rest.push(CurlOption {
                option: option.name,
                has_value: option.value.is_some(),
                len: option.value.map(|value| value.len()),
            }),
        }
    }

    (credentials, rest)
}

/// Builds one credential row from a `name:secret` value.
///
/// The split is on the **first** colon, which is what curl does: a password
/// containing a colon is legal and splitting on the last one would truncate the
/// username into `alice:extra`.
fn credential_entry(option: ParsedOption, kind: CurlCredential) -> CurlCredentialEntry {
    let value = option.value.unwrap_or_default();
    let (user, password) = match value.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        // No colon: curl authenticates with an empty password.
        None => (value.as_str(), None),
    };

    CurlCredentialEntry {
        option: option.name,
        kind,
        user_len: user.len(),
        password_len: password.map_or(0, str::len),
        has_password: password.is_some(),
    }
}
#[cfg(test)]
#[path = "curl/tests.rs"]
mod tests;
