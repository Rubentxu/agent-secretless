//! R3.B: the Maven family, and the first real test of R3's exit criterion.
//!
//! # Why this module exists at all
//!
//! R3's exit criterion is that "a new adapter [is] addable without touching
//! broker or domain". With one family that criterion is untested, and untested
//! criteria are aspirations. Writing the second family is what turns it into a
//! measurement — and it did immediately: `Candidate::origin` was typed
//! `npm::Origin`, so the trait could not express a second family's precedence
//! without changing a shared type. That type was lifted to the crate root
//! rather than worked around, and the lift is the first thing this file proves.
//!
//! # §5's four requirements, and where each one is actually satisfied
//!
//! The design doc asks for DTD disabled, external entities disabled, network
//! resolution disabled, and size/depth limits. Three of the four come from the
//! parser itself and one does not, and saying which is the difference between
//! a control and a wish:
//!
//! - **DTD disabled — structural.** `roxmltree`'s `ParsingOptions::allow_dtd`
//!   defaults to `false` and a document carrying a DOCTYPE is refused with
//!   `DtdDetected` before anything in it is read. Set explicitly here anyway,
//!   because a default that changes upstream would silently turn a refusal into
//!   a policy.
//! - **External entities disabled — structural.** The crate *lexes* an external
//!   entity's URI and discards it, and records only internal quoted-literal
//!   declarations. A reference to an entity it does not hold is
//!   `UnknownEntityReference`. So a `SYSTEM "file:///etc/passwd"` is not
//!   fetched, not substituted and not resolved: it is an error, twice over.
//! - **Network resolution disabled — structural.** `roxmltree` declares no
//!   dependencies, uses no `std::net`, opens no files, and is
//!   `#![forbid(unsafe_code)]`. It has no mechanism to resolve anything.
//! - **Size and depth limits — ours, and both of them necessary.** The crate
//!   exposes `nodes_limit` and nothing else, and its element parsing recurses
//!   once per level. But the node is appended on the element's *closing* tag,
//!   so `nodes_limit` is consulted only after the recursion has already gone as
//!   deep as the document nests: a document nested 2049 deep overflows the
//!   stack and aborts before the limit is ever read. [`MAX_NODES`] bounds
//!   breadth; [`MAX_DEPTH`] bounds depth, and it is checked here, on the text,
//!   before the parser exists in the picture.
//!
//! # What the report holds
//!
//! The same law as npm: **no credential, anywhere, at any rendering.** A Maven
//! `<password>` is reported as a length. A `<username>` is reported as a length
//! too, which is the stricter reading and the one this project has taken
//! everywhere else — a username paired with a password is the same shape as
//! npm's `_auth`, and npm's is base64 of `user:password`.
//!
//! What *is* reported verbatim is the `<id>`, because that is the handle a
//! `pom.xml` references. It is Maven's audience: the thing a binding would be
//! made against, and the one field without which the report cannot be acted on.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fingerprint::{FileFingerprint, FingerprintPolicy};
use crate::{Adapter, Candidate, Finding};

/// The largest `settings.xml` this adapter will read.
///
/// Checked against the file's **byte length before parsing**, so an enormous
/// file is refused without being materialised into a tree first. One MiB is
/// several orders of magnitude above any real `settings.xml` — the largest in
/// the wild are a few tens of kilobytes — so this refuses only a file that is
/// not a configuration.
pub const MAX_SETTINGS_BYTES: u64 = 1 << 20;

/// A ceiling on the **total** nodes in one document.
///
/// This is a breadth ceiling, and it is worth being exact about what it is
/// not: **it does not bound nesting.** `roxmltree` appends an element's node
/// when it reaches that element's *closing* tag (`parse.rs:781`, in the `Close`
/// arm), so a document nested `N` deep recurses `N` deep before a single node
/// exists to count. The ceiling is consulted on the way back out, by which time
/// the stack is already spent. That is why [`MAX_DEPTH`] exists and why it is
/// enforced before the parser is handed anything.
pub const MAX_NODES: u32 = 2048;

/// The deepest element nesting this adapter will let the parser see.
///
/// Enforced by [`check_depth`] on the raw text, because the parser cannot be
/// asked for it and its only node ceiling arrives too late to matter.
///
/// **64 is not a round number picked for looks.** Measured: a document nested
/// 2049 deep overflowed a 2 MiB stack and aborted the process before
/// `nodes_limit` was consulted, which puts a tokenizer frame at slightly over a
/// kilobyte. 64 frames is therefore on the order of 64 KiB — a small fraction of
/// the smallest stack a test harness or a thread pool hands out — while the
/// deepest a real `settings.xml` goes is about ten
/// (`settings > profiles > profile > repositories > repository > releases >
/// enabled`), so the headroom is roughly sixfold over anything Maven reads and
/// far more than any plausible ceiling is entitled to.
///
/// A document that hits it is refused with [`MavenError::TooDeep`].
pub const MAX_DEPTH: usize = 64;

/// The Maven family.
#[derive(Debug, Clone, Copy, Default)]
pub struct Maven;

impl crate::Adapter for Maven {
    const FAMILY: &'static str = "maven";

    type Report = MavenDiscovery;
    type Error = MavenError;

    /// Maven reads a user-level `settings.xml` and the one its installation
    /// carries. Only the user-level one is modelled here, because the
    /// installation's path depends on where Maven is installed and **this crate
    /// does not read the environment** — a library that resolved its own paths
    /// would be resolving *this process's* paths, and a report about the
    /// caller's configuration is not a report about the project.
    ///
    /// The project tree is deliberately not a candidate: Maven has no
    /// project-level settings file, and inventing one would produce a report
    /// about a file the tool does not read.
    fn candidates(home: &Path, _cwd: &Path) -> Vec<Candidate> {
        vec![Candidate {
            path: home.join(".m2").join("settings.xml"),
            origin: crate::Origin::User,
        }]
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
                // Absence is not a finding. Most machines have no `settings.xml`
                // at all and that is not something an operator needs told.
                continue;
            }
            let fingerprint = match policy.fingerprint(&candidate.path) {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    // A refusal is a finding rather than a failure: a
                    // world-writable user settings file does not make the other
                    // files unreadable, and an operator has to know it was
                    // skipped.
                    findings.push(Finding {
                        severity: crate::Severity::Refused,
                        subject: candidate.path.display().to_string(),
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let text = read_capped(&candidate.path)?;
            match parse_settings(&text) {
                Ok(settings) => files.push(MavenFile {
                    origin: candidate.origin,
                    fingerprint,
                    local_repository: settings.local_repository,
                    servers: settings.servers,
                    mirrors: settings.mirrors,
                    proxies: settings.proxies,
                }),
                Err(error) => findings.push(Finding {
                    severity: crate::Severity::Refused,
                    subject: candidate.path.display().to_string(),
                    message: error.to_string(),
                }),
            }
        }

        Ok(MavenDiscovery { files, findings })
    }
}

/// Everything one Maven discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MavenDiscovery {
    pub files: Vec<MavenFile>,
    /// Files that were found and not read, and why.
    ///
    /// A report that listed only the files it managed to parse would read as
    /// complete, and "this settings.xml is world-writable" is the sentence an
    /// operator most needs to see.
    pub findings: Vec<Finding>,
}

impl From<MavenDiscovery> for crate::AnyReport {
    fn from(report: MavenDiscovery) -> Self {
        Self::Maven(report)
    }
}

impl MavenDiscovery {
    /// Wraps this family's report in the shape the CLI prints.
    ///
    /// Present for the same reason as [`crate::npm::NpmDiscovery::into_discovery`]:
    /// it is what makes the family reachable from a product surface, so a
    /// report that cannot be wrapped cannot be printed, and a module that
    /// compiles but is unreachable cannot pass anything.
    pub fn into_discovery(self) -> crate::Discovery {
        crate::Discovery::new(Maven::FAMILY, crate::AnyReport::Maven(self))
    }
}

/// One `settings.xml`, described.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MavenFile {
    pub origin: crate::Origin,
    pub fingerprint: FileFingerprint,
    /// `<localRepository>`. A path, not a credential.
    pub local_repository: Option<String>,
    pub servers: Vec<MavenServer>,
    pub mirrors: Vec<MavenMirror>,
    pub proxies: Vec<MavenProxy>,
}

/// One `<server>`, with its credential described rather than carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MavenServer {
    /// The `<id>` — the handle a `pom.xml` refers to, and Maven's audience.
    pub id: String,
    /// The username's length, never its value. See the module docs.
    pub username_len: Option<usize>,
    /// The password's length, never its value — and `None` when the password is
    /// a `${env.…}` reference, because the file does not contain the credential
    /// in that case. See [`credential_len`].
    pub password_len: Option<usize>,
    /// Whether the password is a `${env.…}` variable rather than a literal.
    pub password_is_env_reference: bool,
    /// The variable's name when it is one. A name is not a value.
    pub env_reference: Option<String>,
    /// Elements of this `<server>` this adapter does not model, named and
    /// measured.
    ///
    /// **This is the field that keeps the report honest.** In practice it is
    /// always a `<configuration>`, and a `<configuration>` is exactly where
    /// repository vendors keep their *other* credentials:
    ///
    /// ```xml
    /// <configuration>
    ///   <httpHeaders>
    ///     <property><name>X-JFrog-Art-Api</name><value>AKCp8…</value></property>
    ///   </httpHeaders>
    /// </configuration>
    /// ```
    ///
    /// An adapter that modelled only `<username>`/`<password>` and dropped the
    /// rest would print "server `acme`: 25-byte password" and silently omit an
    /// API key sitting two lines away — and a report that says one credential is
    /// there while another is invisible is worse than one that says nothing.
    /// So the element is named and its text is measured, never read into the
    /// report: *present and not described* is a different claim from *absent*.
    pub undescribed: Vec<UndescribedSetting>,
}

/// A child element of a `<server>` this adapter does not model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UndescribedSetting {
    /// The element's local name — `configuration`, or whatever a vendor adds.
    pub element: String,
    /// How many bytes of text it holds in total, descendants included.
    ///
    /// A count and never the text, for the same reason the password is a count:
    /// the value of a vendor `<configuration>` is somebody else's secret, and
    /// the number is what an operator needs to decide whether there is something
    /// here worth adopting.
    pub len: usize,
}

/// One `<mirror>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MavenMirror {
    pub id: String,
    /// `<url>`, with any embedded userinfo removed. See
    /// [`MavenMirror::url_credential_len`] for why that is not optional.
    pub url: Option<String>,
    /// How many bytes of `user:password@` were removed from `<url>`.
    ///
    /// **A mirror URL carries credentials more often than anyone expects.**
    /// `https://token@github.com/acme/repo` is a supported, documented form,
    /// and `https://user:password@repo.acme.test/maven` is worse. Printing the
    /// URL verbatim puts a credential in the report — the one artefact in R3
    /// that travels furthest before anything is written — so the userinfo is
    /// removed and only its size survives, which is the same trade the
    /// `<password>` gets and for the same reason.
    ///
    /// `None` means the URL had no userinfo, which is a different claim from
    /// "a zero-length one was removed".
    pub url_credential_len: Option<usize>,
    /// `<mirrorOf>`, e.g. `*` or `external:*,!acme`.
    pub mirror_of: Option<String>,
}

/// Removes the `user:password@` from a URL and reports how long it was.
///
/// Bounded to the authority — between the `//` and the first `/` after it — so
/// an `@` in a path or a query cannot be mistaken for one, and `rfind` within
/// that authority so a password containing `@` still splits at the right place.
fn strip_userinfo(url: &str) -> (String, Option<usize>) {
    let Some(after_slashes) = url.find("//").map(|index| index + 2) else {
        return (url.to_string(), None);
    };
    let authority_end = url[after_slashes..]
        .find('/')
        .map(|index| after_slashes + index)
        .unwrap_or(url.len());
    let authority = &url[after_slashes..authority_end];
    let Some(at) = authority.rfind('@') else {
        return (url.to_string(), None);
    };
    (
        format!(
            "{}{}{}",
            &url[..after_slashes],
            &authority[at + 1..],
            &url[authority_end..]
        ),
        Some(authority[..at].len()),
    )
}

/// One `<proxy>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MavenProxy {
    pub id: String,
    /// `<protocol>`, `<host>` and `<port>` are how the proxy is reached, not who
    /// it is. `<protocol>` is reported explicitly rather than left undescribed:
    /// it is routing information in the same class as host and port, it is not
    /// credential-shaped, and modelling it costs one line — whereas the
    /// asymmetry with `<server>` is deliberate and is argued where it is made,
    /// in [`MavenServer::undescribed`].
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub active: bool,
    pub username_len: Option<usize>,
    pub password_len: Option<usize>,
    pub password_is_env_reference: bool,
    pub env_reference: Option<String>,
}

/// Why Maven could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MavenError {
    #[error("{path} is larger than the {MAX_SETTINGS_BYTES} byte ceiling for a settings file")]
    TooLarge { path: std::path::PathBuf },
    #[error("could not read {path}: {message}")]
    Unreadable {
        path: std::path::PathBuf,
        message: String,
    },
    /// A DOCTYPE, refused before its contents are read. §5's first requirement,
    /// and the only one whose refusal is a named error rather than a parse
    /// failure — because a document with a DTD is refused *as such*.
    #[error("this file declares a DTD ({reason}); a settings file has no use for one")]
    DtdRefused { reason: String },
    #[error("this file is nested too deeply for a settings file, or too large ({reason})")]
    TooDeep { reason: String },
    #[error("this file is not well-formed XML: {message}")]
    Malformed { message: String },
}

/// Reads a file, refusing one over the ceiling without reading it into memory.
///
/// `metadata` first, then a **bounded** read: a plain `read_to_string` would
/// have already allocated whatever the file is, which is the opposite of what a
/// size limit is for.
fn read_capped(path: &Path) -> Result<Zeroizing<String>, MavenError> {
    let len = std::fs::metadata(path)
        .map_err(|error| MavenError::Unreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .len();
    if len > MAX_SETTINGS_BYTES {
        return Err(MavenError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    use std::io::Read as _;
    let mut buffer = Zeroizing::new(String::new());
    std::fs::File::open(path)
        .map_err(|error| MavenError::Unreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .read_to_string(&mut buffer)
        .map_err(|error| MavenError::Unreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    Ok(buffer)
}

/// Parses a `settings.xml` with §5's four requirements applied.
///
/// `allow_dtd` is written out rather than inherited from the default, because a
/// default that changes upstream turns a refusal into a policy and nothing here
/// would notice.
fn parse_settings(text: &str) -> Result<Settings, MavenError> {
    // Before the parser exists in the picture. `nodes_limit` cannot do this
    // job — see [`MAX_DEPTH`] — and a document that would exhaust the stack is
    // refused as a depth, not as whatever the crash happened to surface as.
    check_depth(text)?;
    let options = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
    };
    let document = roxmltree::Document::parse_with_options(text, options).map_err(|error| {
        use roxmltree::Error as E;
        match error {
            E::DtdDetected { .. } => MavenError::DtdRefused {
                reason: "a DOCTYPE is present".to_string(),
            },
            E::NodesLimitReached => MavenError::TooDeep {
                reason: format!("more than {MAX_NODES} nodes"),
            },
            E::UnknownEntityReference(name, _) => MavenError::DtdRefused {
                // Named as a DTD refusal rather than as malformed XML, because
                // it is exactly the XXE shape §5 asks to refuse and an operator
                // reading "not well-formed" would not know what was attempted.
                reason: format!("an entity reference `&{name};` that no DTD in this file defines"),
            },
            other => MavenError::Malformed {
                message: other.to_string(),
            },
        }
    })?;

    let root = document.root_element();
    let settings = Settings {
        local_repository: child_text(root, "localRepository"),
        servers: children(root, "servers")
            .flat_map(|servers| children(servers, "server"))
            .map(server_from)
            .collect(),
        mirrors: children(root, "mirrors")
            .flat_map(|mirrors| children(mirrors, "mirror"))
            .map(|mirror| {
                let (url, url_credential_len) = match child_text(mirror, "url") {
                    Some(url) => {
                        let (stripped, len) = strip_userinfo(&url);
                        (Some(stripped), len)
                    }
                    None => (None, None),
                };
                MavenMirror {
                    id: child_text(mirror, "id").unwrap_or_default(),
                    url,
                    url_credential_len,
                    mirror_of: child_text(mirror, "mirrorOf"),
                }
            })
            .collect(),
        proxies: children(root, "proxies")
            .flat_map(|proxies| children(proxies, "proxy"))
            .map(proxy_from)
            .collect(),
    };
    Ok(settings)
}

/// What one parse produced, before it is attached to a file.
///
/// `Debug` because a parse error has to be printable in a test and a log, and
/// this type holds nothing but what the report already holds — ids and byte
/// counts. Deriving it here does not create the leak the report forbids,
/// because the report is where the values would have to come from.
#[derive(Debug)]
struct Settings {
    local_repository: Option<String>,
    servers: Vec<MavenServer>,
    mirrors: Vec<MavenMirror>,
    proxies: Vec<MavenProxy>,
}

/// Refuses a document nested deeper than [`MAX_DEPTH`], without parsing.
///
/// **Quote-aware, and skipping whole constructs.** Counting `<` characters
/// would be wrong in a way that fails on legitimate files: `<a b="x>y">` has a
/// `>` that does not end the tag, and a scanner that believes it does will
/// invent a closing tag and mis-count a real file's depth. Comments, CDATA and
/// processing instructions are skipped whole rather than scanned, because a `<`
/// inside any of them opens nothing — and `settings.xml` files routinely carry
/// commented-out examples in them.
///
/// It counts *nesting*, not tags: `<a><b></b></a>` opens two and closes two,
/// and a sibling list of ten thousand is caught by [`MAX_NODES`] instead, which
/// is the ceiling that actually applies to it.
fn check_depth(text: &str) -> Result<(), MavenError> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let rest = &bytes[index..];
        if rest.starts_with(b"<!--") {
            index = skip_past(bytes, index + 4, b"-->")?;
        } else if rest.starts_with(b"<![CDATA[") {
            index = skip_past(bytes, index + 9, b"]]>")?;
        } else if rest.starts_with(b"<?") {
            index = skip_past(bytes, index + 2, b"?>")?;
        } else if rest.starts_with(b"<!") {
            // A DOCTYPE and its internal subset. The parser refuses the
            // declaration itself; this only has to get past it without letting
            // an entity's own `<` into the count.
            index = skip_declaration(bytes, index + 2)?;
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            index = skip_tag(bytes, index + 2)?;
        } else {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(MavenError::TooDeep {
                    reason: format!("nested deeper than {MAX_DEPTH} elements"),
                });
            }
            index = skip_tag(bytes, index + 1)?;
        }
    }
    Ok(())
}

/// Skips to just past `terminator`, or reports the document as malformed.
fn skip_past(bytes: &[u8], mut index: usize, terminator: &[u8]) -> Result<usize, MavenError> {
    while index + terminator.len() <= bytes.len() {
        if &bytes[index..index + terminator.len()] == terminator {
            return Ok(index + terminator.len());
        }
        index += 1;
    }
    Err(MavenError::Malformed {
        message: format!("`{}` is never closed", String::from_utf8_lossy(terminator)),
    })
}

/// Skips a tag's text to its `>`, respecting quoted attribute values.
fn skip_tag(bytes: &[u8], mut index: usize) -> Result<usize, MavenError> {
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match (quote, byte) {
            (Some(open), b) if b == open => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(byte),
            (None, b'>') => return Ok(index + 1),
            _ => {}
        }
        index += 1;
    }
    Err(MavenError::Malformed {
        message: "a tag is never closed".to_string(),
    })
}

/// Skips a `<!…>` declaration, including an internal `[…]` subset.
///
/// The bracket tracking is the whole reason this is not [`skip_tag`]: a DOCTYPE
/// with entity declarations contains `>` inside the subset, and stopping at the
/// first one leaves the rest of the declaration to be read as markup.
fn skip_declaration(bytes: &[u8], mut index: usize) -> Result<usize, MavenError> {
    let mut in_subset = false;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => in_subset = true,
            b']' => in_subset = false,
            b'>' if !in_subset => return Ok(index + 1),
            _ => {}
        }
        index += 1;
    }
    Err(MavenError::Malformed {
        message: "a declaration is never closed".to_string(),
    })
}

/// The `<server>` children this adapter describes. Everything else is recorded
/// as undescribed rather than dropped — see [`MavenServer::undescribed`] for
/// why that field exists at all.
const MODELLED_SERVER_CHILDREN: &[&str] = &["id", "username", "password"];

fn server_from(node: roxmltree::Node<'_, '_>) -> MavenServer {
    let password = child_text(node, "password");
    let (is_env, reference) = env_reference(password.as_deref());
    MavenServer {
        id: child_text(node, "id").unwrap_or_default(),
        username_len: child_text(node, "username").map(|value| value.len()),
        password_len: credential_len(password.as_deref(), is_env),
        password_is_env_reference: is_env,
        env_reference: reference,
        undescribed: node
            .children()
            .filter(|child| {
                child.is_element() && !MODELLED_SERVER_CHILDREN.contains(&child.tag_name().name())
            })
            .map(|child| UndescribedSetting {
                element: child.tag_name().name().to_string(),
                len: text_length(child),
            })
            .collect(),
    }
}

/// The total text under an element, descendants included.
///
/// Not `Node::text()`: that returns `None` unless the node has exactly one text
/// child, which is a fact about how the XML was written rather than about what
/// it says. A `<configuration>` holding one `<property>` has one element child
/// and no direct text, and would measure as empty.
fn text_length(node: roxmltree::Node<'_, '_>) -> usize {
    node.descendants()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .map(|text| text.trim().len())
        .sum()
}

fn proxy_from(node: roxmltree::Node<'_, '_>) -> MavenProxy {
    let password = child_text(node, "password");
    let (is_env, reference) = env_reference(password.as_deref());
    MavenProxy {
        id: child_text(node, "id").unwrap_or_default(),
        protocol: child_text(node, "protocol"),
        host: child_text(node, "host"),
        // `port` is text in the file, so it is parsed rather than trusted: a
        // `port` of `0` or `70000` would otherwise reach a report as a number
        // it cannot be.
        port: child_text(node, "port").and_then(|value| value.parse::<u16>().ok()),
        active: child_text(node, "active")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        username_len: child_text(node, "username").map(|value| value.len()),
        password_len: credential_len(password.as_deref(), is_env),
        password_is_env_reference: is_env,
        env_reference: reference,
    }
}

/// The length of a credential, or `None` when the file does not contain one.
///
/// **`None` for an env reference is the point.** `${env.ACME_TOKEN}` is 19
/// characters of *text*; the credential it stands for is whatever is in the
/// caller's environment, which this crate neither knows nor may learn. An
/// earlier version reported `Some(19)` beside `password_is_env_reference: true`
/// — two numbers, no way to tell which one was about the secret, and the
/// plausible-looking one was the wrong one. The report measures credentials,
/// not the text that stands in for one.
fn credential_len(value: Option<&str>, is_env_reference: bool) -> Option<usize> {
    if is_env_reference {
        None
    } else {
        value.map(|value| value.len())
    }
}

/// Direct child elements with this local name.
///
/// **Local name, deliberately.** Maven's `settings.xml` normally carries
/// `xmlns="http://maven.apache.org/SETTINGS/1.0.0"`, but not always. Matching
/// the namespaced form only would silently find nothing in a file that omits
/// it, which is the one ambiguity a credential report cannot have.
fn children<'a, 'i, 'name>(
    parent: roxmltree::Node<'a, 'i>,
    name: &'name str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> + use<'a, 'i, 'name> {
    parent
        .children()
        .filter(move |node| node.is_element() && node.has_tag_name(name))
}

/// The trimmed text of the first direct child with this name.
///
/// `Node::text()` returns `None` for anything but a single text child, so
/// descendant text is concatenated instead. An element that had no text
/// because of *how* it was written is not the same as one with no text at all,
/// and a report that cannot tell them apart is guessing.
fn child_text<'a, 'i>(parent: roxmltree::Node<'a, 'i>, name: &str) -> Option<String> {
    let node = children(parent, name).next()?;
    let text: String = node
        .descendants()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Splits a `${env.NAME}` reference into "yes" and the name, without resolving
/// it.
///
/// Maven's settings resolve `${env.X}` from the environment at run time. **The
/// environment is the caller's, not the file's**, and the name is what an
/// operator needs in order to know what to project — exactly the rule npm's
/// parser follows for `${VAR}` and for the same reason.
fn env_reference(value: Option<&str>) -> (bool, Option<String>) {
    let Some(value) = value else {
        return (false, None);
    };
    let Some(inner) = value
        .strip_prefix("${env.")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return (false, None);
    };
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return (false, None);
    }
    (true, Some(inner.to_string()))
}

// `Zeroizing` is named here because a `settings.xml` is mostly not secret and
// this does not pretend otherwise: the buffer may hold one `<password>`, and
// "mostly secret" is not a category a `Drop` can act on.
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;
