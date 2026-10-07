//! Materialising the path that makes `Why::Brokered` true.
//!
//! # Why this module exists at all
//!
//! `plan` offers an npm credential `STRONG_SECRETLESS` on the strength of
//! `Why::Brokered` — *"the broker substitutes the credential, so the tool never
//! holds it."* That is a true statement about the broker and an empty one about
//! the operator: nothing in the workspace wrote an npm configuration that
//! routed npm through the relay. The only code that wrote a `registry=` line was
//! a test fixture.
//!
//! # What the projection carries, and why it is not "nothing"
//!
//! The first version of this module claimed the rendered file would carry **no
//! credential at all**. That claim was wrong, and it was wrong because nobody
//! read what the relay does with an incoming request.
//!
//! `bearer_token` and `replace_bearer_token` in the broker's TLS bridge find an
//! `Authorization: Bearer` header **the client already sent** and replace the
//! extent of its token. A request with no such header yields
//! `SubstitutionError::NoCredential`, and the tunnel is refused rather than
//! forwarded. So a genuinely empty `.npmrc` produces tunnels the broker will not
//! carry: the file would look like a working secretless configuration and npm
//! would fail against a real registry.
//!
//! What npm must send is a *surrogate* — the broker hands one to the session
//! (`MintSurrogate`), the relay redeems it **in the session that minted it**
//! (`redeem_for` refuses `WrongSession` otherwise) and substitutes the real
//! credential on the way upstream. That is the shape `Why::Brokered` names, and
//! it is why the projection writes `_authToken` at all: the file carries a
//! one-use, session-scoped stand-in that is useless anywhere else, and never the
//! registry token.
//!
//! # Why the surrogate must come from the running session
//!
//! Minting here would be the obvious way to be self-contained, and it is the
//! wrong one: a surrogate minted against a session this process opens and
//! immediately drops can never be redeemed, because no tunnel will ever carry
//! that session's proof. The command therefore reads the surrogate `asv run`
//! already exported (`ASV_SURROGATE_<LABEL>`) rather than minting one.

use std::path::Path;

use crate::registry_audience::RegistryAudience;

/// `asv.integrations.projection/v1`.
///
/// A third document in this crate's family, and the first that is written for a
/// tool to *consume* rather than for an operator to read.
pub const PROJECTION_SCHEMA: &str = "asv.integrations.projection/v1";

/// The first line of every file this module writes.
///
/// Its job is not decoration: [`write`] will not touch a file carrying an auth
/// field *unless* it carries this marker, which is what makes a re-run a
/// refresh rather than a refusal. Without it the command would succeed once and
/// then refuse its own output forever, because the surrogate it wrote last time
/// is itself an auth field.
const MARKER: &str = "# Written by asv (asv.integrations.projection/v1).";

/// The npm fields that carry a credential, spelled as npm spells them.
///
/// Named here rather than parsed ad hoc at the write site, because the refusal
/// in [`write`] is only as good as the list behind it: a field missed here is a
/// credential this module claims not to carry and then carries.
const AUTH_FIELDS: &[&str] = &["_authToken", "_auth", "_password", "username"];

/// Why a projection could not be built or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    /// The endpoint was not a loopback address.
    ///
    /// Its own variant because this is the one input that could turn a
    /// projection into an exfiltration: npm would send its requests, and
    /// whatever the relay substituted, to somewhere off this machine. Loopback
    /// is what makes "the broker is on the other end of this socket" a claim
    /// rather than a hope.
    NotLoopback {
        /// What was offered.
        endpoint: String,
    },
    /// The endpoint has no scheme npm can use as a proxy.
    UnusableEndpoint {
        /// What was offered.
        endpoint: String,
    },
    /// No surrogate was offered, so the file would carry nothing npm can
    /// authenticate with.
    ///
    /// Named rather than defaulting to an empty `_authToken`, because an empty
    /// one produces a tunnel the broker refuses and an npm error that names the
    /// registry rather than this decision.
    MissingSurrogate,
    /// The file already holds a credential this module did not write, so
    /// writing here would destroy it.
    ///
    /// Named with the fields found, because "it already has a credential" is not
    /// actionable and "it has `_authToken`" is.
    AlreadyCarriesCredential {
        /// The fields the existing file sets.
        fields: Vec<String>,
    },
    /// The write itself failed.
    Io(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectionError::NotLoopback { endpoint } => write!(
                f,
                "{endpoint:?} is not a loopback endpoint; a projection points npm at a \
                 relay on this machine, and anything else would send the traffic — and \
                 whatever the relay substituted — somewhere off it"
            ),
            ProjectionError::UnusableEndpoint { endpoint } => write!(
                f,
                "{endpoint:?} is not an endpoint npm can use as an https-proxy"
            ),
            ProjectionError::MissingSurrogate => write!(
                f,
                "no surrogate to write. `asv run` mints one per credential and exports it \
                 as ASV_SURROGATE_<LABEL>; run this inside the session that will carry \
                 the tunnel, because a surrogate minted here could never be redeemed"
            ),
            ProjectionError::AlreadyCarriesCredential { fields } => write!(
                f,
                "this configuration already carries {} ({}) and this projection did not \
                 write them, so replacing it would destroy the original — which is the \
                 scrub, not the projection. §10 puts a storage proof, a positive proof, a \
                 negative test and a human approval in front of that, so it belongs to \
                 `asv integrations migrate`, not here",
                if fields.len() == 1 {
                    "a credential"
                } else {
                    "credentials"
                },
                fields.join(", ")
            ),
            ProjectionError::Io(what) => write!(f, "the projection could not be written: {what}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// A rendered npm configuration whose `_authToken` is a surrogate, not a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmProjection {
    registry: String,
    authority: String,
    proxy: String,
    surrogate: String,
}

impl NpmProjection {
    /// Builds the projection for one registry, one loopback relay and one
    /// surrogate.
    ///
    /// Every input is checked rather than trusted, because each downstream
    /// claim rests on it: that npm holds no registry token needs a surrogate
    /// rather than a blank, and that the broker is the other end needs a socket
    /// on this machine.
    pub fn new(
        registry: &RegistryAudience,
        endpoint: &str,
        surrogate: &str,
    ) -> Result<Self, ProjectionError> {
        if surrogate.is_empty() {
            return Err(ProjectionError::MissingSurrogate);
        }
        let (scheme, authority) =
            endpoint
                .split_once("://")
                .ok_or_else(|| ProjectionError::UnusableEndpoint {
                    endpoint: endpoint.to_string(),
                })?;
        if !matches!(scheme, "http" | "https") {
            return Err(ProjectionError::UnusableEndpoint {
                endpoint: endpoint.to_string(),
            });
        }
        // Loopback in its three spellings, plus `localhost`, which resolves
        // there and is what an operator will type.
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _port)| host)
            .trim_matches(|c| c == '[' || c == ']');
        if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Err(ProjectionError::NotLoopback {
                endpoint: endpoint.to_string(),
            });
        }
        Ok(Self {
            registry: registry.url(),
            authority: registry.to_string(),
            proxy: endpoint.to_string(),
            surrogate: surrogate.to_string(),
        })
    }

    /// The rendered configuration.
    ///
    /// Says in its own text that `_authToken` is a surrogate and what that
    /// means, so a reader who opens the file does not have to take our word for
    /// it from a different document — and so nobody treats the file as a place
    /// a registry token belongs.
    ///
    /// ## The token is written **scoped**, and that is measured, not styled
    ///
    /// npm 11.12.1 refuses an unscoped `_authToken` outright:
    ///
    /// ```text
    /// npm error code ERR_INVALID_AUTH
    /// npm error Invalid auth configuration found: `_authToken` must be
    /// npm error renamed to `//127.0.0.1:40933/:_authToken` in user config
    /// ```
    ///
    /// An unscoped form is not a matter of taste here — it is a file npm will
    /// not load at all, so a projection writing one produces a configuration
    /// that looks finished and fails before it sends anything. The same npm,
    /// given the scoped spelling, sends `authorization: Bearer <surrogate>` on
    /// its first request, which is exactly the bearer `replace_bearer_token`
    /// rewrites.
    ///
    /// The scope is keyed to the **registry**, not to the relay: npm matched
    /// `//127.0.0.1:40933/:_authToken` against `registry=http://127.0.0.1:40933`.
    pub fn render(&self) -> String {
        format!(
            "{MARKER}\n\
             # No registry token is in this file. The scoped token below is a surrogate\n\
             # the broker minted for this session: the relay redeems it and substitutes\n\
             # the real credential on the way upstream, which is what makes the posture\n\
             # STRONG_SECRETLESS rather than a claim about it. It is bound to the session\n\
             # that minted it and stops working when that session ends.\n\
             #\n\
             # The token is scoped to the registry because npm refuses an unscoped\n\
             # _authToken outright (ERR_INVALID_AUTH); the scope is what makes it a\n\
             # credential for this registry and nothing else.\n\
             registry={}\n\
             //{}/:_authToken={}\n\
             https-proxy={}\n",
            self.registry, self.authority, self.surrogate, self.proxy
        )
    }

    /// The endpoint npm will send to.
    pub fn proxy(&self) -> &str {
        &self.proxy
    }

    /// The registry npm will actually reach, once the relay is stripped.
    pub fn registry(&self) -> &str {
        &self.registry
    }
}

/// Which credential fields a configuration sets, if any.
///
/// ## The scope prefix is stripped, and that is a safety property
///
/// npm scopes a credential to a registry as `//host[:port]/:_authToken`, so the
/// key of such a line is `//host[:port]/:_authToken` and not `_authToken`. An
/// earlier version of this function compared the raw key, which meant a file
/// holding a **scoped real token** reported no credentials at all — and
/// [`write`], which trusts this answer, would then have overwritten it without
/// a word. The guard that exists to stop a projection destroying a credential
/// was blind to the only spelling npm now accepts.
///
/// The prefix is only stripped from a key that begins `//`, so a key that
/// merely contains a colon is not silently reinterpreted.
pub fn credential_fields(contents: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
            continue;
        }
        let Some((key, _value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let key = if key.starts_with("//") {
            // `//host/:_authToken` -> `_authToken`. `rsplit_once` rather than
            // `split_once` so a host carrying a port keeps its field name.
            key.rsplit_once(':').map_or(key, |(_scope, field)| field)
        } else {
            key
        };
        if AUTH_FIELDS.contains(&key) {
            found.push(key.to_string());
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Writes the projection to `path`, refusing a credential it did not write.
///
/// The refusal is the safety property of this module and the reason it is not
/// merged into the scrub. Replacing a credential-bearing configuration is the
/// destructive half of a migration, and it is the half every gate exists to
/// guard.
///
/// A file this module wrote before *is* refreshable, because the marker line
/// identifies it and because the value in it is a surrogate this product minted
/// — destroying it destroys nothing.
pub fn write(path: &Path, projection: &NpmProjection) -> Result<(), ProjectionError> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let fields = credential_fields(&existing);
        if !fields.is_empty() && !existing.contains(MARKER) {
            return Err(ProjectionError::AlreadyCarriesCredential { fields });
        }
    }
    // 0600, not the umask default: this file is written by a tool that reads
    // secrets, and a world-readable npm configuration is one an operator never
    // asked for.
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| ProjectionError::Io(e.to_string()))?;
    file.write_all(projection.render().as_bytes())
        .map_err(|e| ProjectionError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RegistryAudience {
        RegistryAudience::parse("registry.npmjs.org").expect("a literal host")
    }

    /// The claim the module's whole existence rests on: the relay substitutes a
    /// bearer the client already sent, so a file with no auth field cannot work.
    #[test]
    fn the_projection_carries_a_surrogate_rather_than_nothing() {
        let rendered = NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1")
            .expect("loopback")
            .render();
        assert!(
            rendered.contains("//registry.npmjs.org/:_authToken=sur-1\n"),
            "npm refuses an unscoped _authToken outright (ERR_INVALID_AUTH), so a projection \
             writing one produces a file npm will not load: {rendered}"
        );
        assert!(
            rendered.contains("https-proxy=http://127.0.0.1:8080\n"),
            "npm sends no Authorization header without it, and the relay substitutes only a \
             bearer that is already there: {rendered}"
        );
        assert_eq!(credential_fields(&rendered), vec!["_authToken".to_string()]);
    }

    #[test]
    fn the_rendered_file_names_what_the_token_is_not() {
        let rendered = NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1")
            .expect("loopback")
            .render();
        assert!(rendered.contains(MARKER));
        assert!(
            rendered.contains("No registry token is in this file"),
            "a reader opening this file must not have to take it on trust from elsewhere: {rendered}"
        );
    }

    #[test]
    fn the_registry_and_the_relay_are_both_named() {
        let projection =
            NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1").expect("loopback");
        assert_eq!(projection.registry(), "https://registry.npmjs.org");
        assert_eq!(projection.proxy(), "http://127.0.0.1:8080");
        let rendered = projection.render();
        assert!(rendered.contains("registry=https://registry.npmjs.org\n"));
        assert!(rendered.contains("https-proxy=http://127.0.0.1:8080\n"));
        // The scope is keyed to the registry, never to the relay: npm matched a
        // scoped token against the registry URL, not against the proxy URL.
        assert!(
            rendered.contains("//registry.npmjs.org/:_authToken="),
            "scoping the token to the relay would hand the credential to whatever else that \
             socket reaches: {rendered}"
        );
        assert!(!rendered.contains("//127.0.0.1:8080/:_authToken="));
    }

    #[test]
    fn an_endpoint_off_this_machine_is_refused() {
        for endpoint in [
            "http://registry.npmjs.org:8080",
            "https://evil.example",
            "http://10.0.0.1:3128",
        ] {
            assert_eq!(
                NpmProjection::new(&registry(), endpoint, "sur-1"),
                Err(ProjectionError::NotLoopback {
                    endpoint: endpoint.to_string()
                }),
                "{endpoint} would send the substituted credential off this machine"
            );
        }
    }

    #[test]
    fn a_scheme_npm_cannot_use_as_a_proxy_is_refused() {
        for endpoint in ["127.0.0.1:8080", "socks5://127.0.0.1:8080", "file:///tmp"] {
            assert_eq!(
                NpmProjection::new(&registry(), endpoint, "sur-1"),
                Err(ProjectionError::UnusableEndpoint {
                    endpoint: endpoint.to_string()
                }),
                "{endpoint} is not an https-proxy value"
            );
        }
    }

    /// `localhost` is what an operator types, and it resolves to loopback.
    #[test]
    fn localhost_is_accepted_because_it_resolves_to_loopback() {
        for host in ["localhost", "[::1]"] {
            let endpoint = format!("http://{host}:8080");
            assert!(
                NpmProjection::new(&registry(), &endpoint, "sur-1").is_ok(),
                "{endpoint} resolves to loopback"
            );
        }
    }

    #[test]
    fn no_surrogate_is_refused_rather_than_written_blank() {
        assert_eq!(
            NpmProjection::new(&registry(), "http://127.0.0.1:8080", ""),
            Err(ProjectionError::MissingSurrogate),
            "an empty _authToken produces a tunnel the broker refuses and an npm error that \
             names the registry instead of this decision"
        );
    }

    /// The defect this file had. A scoped token is the only spelling npm
    /// accepts, and the raw key of such a line carries the scope, which matched
    /// nothing — so `write` would have overwritten a file holding a real
    /// credential without refusing.
    #[test]
    fn a_scoped_credential_is_recognised_rather_than_blind_to() {
        let scoped = "registry=https://registry.npmjs.org\n\
                      //registry.npmjs.org/:_authToken=the-real-one\n";
        assert_eq!(
            credential_fields(scoped),
            vec!["_authToken".to_string()],
            "npm only accepts the scoped spelling, so an unrecognised scope is an \
             unguarded overwrite of somebody's registry token"
        );
    }

    #[test]
    fn a_port_in_the_scope_does_not_eat_the_field_name() {
        let scoped = "//127.0.0.1:8080/:_authToken=t\n//127.0.0.1:8080/:username=u\n";
        assert_eq!(
            credential_fields(scoped),
            vec!["_authToken".to_string(), "username".to_string()]
        );
    }

    #[test]
    fn writing_over_a_scoped_foreign_token_is_refused_and_survives_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        let original = "registry=https://registry.npmjs.org\n\
                       //registry.npmjs.org/:_authToken=the-real-one\n";
        std::fs::write(&path, original).expect("seed");

        let projection =
            NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1").expect("loopback");
        assert_eq!(
            write(&path, &projection),
            Err(ProjectionError::AlreadyCarriesCredential {
                fields: vec!["_authToken".to_string()]
            }),
            "npm's only accepted spelling was the one this guard could not see"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("still there"),
            original,
            "a refused write must leave the original byte for byte"
        );
    }

    /// A key that merely contains a colon is not a scope and must not be
    /// reinterpreted as one.
    #[test]
    fn a_colon_in_an_unscoped_key_is_not_read_as_a_scope() {
        assert!(credential_fields("weird:key=value\n").is_empty());
    }

    #[test]
    fn every_auth_field_npm_writes_is_recognised() {
        let contents = "_authToken=t\n_auth=dXNlcjpwYXNz\nusername=u\n_password=p\nregistry=r\n";
        assert_eq!(
            credential_fields(contents),
            vec![
                "_auth".to_string(),
                "_authToken".to_string(),
                "_password".to_string(),
                "username".to_string()
            ]
        );
    }

    #[test]
    fn a_commented_or_scoped_line_is_not_a_credential() {
        let contents =
            "# _authToken=commented\n; _auth=also commented\n[@scope]\n_authToken=real\n";
        assert_eq!(credential_fields(contents), vec!["_authToken".to_string()]);
    }

    #[test]
    fn writing_over_a_foreign_credential_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "registry=r\n_authToken=the-real-one\n").expect("seed");

        let projection =
            NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1").expect("loopback");
        assert_eq!(
            write(&path, &projection),
            Err(ProjectionError::AlreadyCarriesCredential {
                fields: vec!["_authToken".to_string()]
            }),
            "destroying the original is the scrub, and every §10 gate stands in front of it"
        );
        assert!(
            std::fs::read_to_string(&path)
                .expect("still there")
                .contains("the-real-one"),
            "a refused write must leave the original byte for byte"
        );
    }

    /// The failure this design has to avoid: succeeding once and then refusing
    /// its own output forever, because what it wrote last time is an auth field.
    #[test]
    fn a_projection_may_refresh_its_own_previous_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");

        let first = NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1").expect("ok");
        write(&path, &first).expect("first write");
        let second = NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-2").expect("ok");
        write(&path, &second).expect("refresh its own file");

        let on_disk = std::fs::read_to_string(&path).expect("read back");
        assert!(on_disk.contains("_authToken=sur-2\n"));
        assert!(!on_disk.contains("sur-1"), "the stale surrogate is gone");
    }

    #[test]
    fn the_written_file_is_readable_by_its_owner_and_nobody_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".npmrc");
        let projection =
            NpmProjection::new(&registry(), "http://127.0.0.1:8080", "sur-1").expect("ok");
        write(&path, &projection).expect("write");

        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a world-readable npmrc is one nobody asked for"
        );
    }
}
