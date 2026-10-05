//! Which registries this deployment may reach, and with which credential
//! (M11-R2.F.3).
//!
//! **This file is where the registry allowlist actually lives.** The policy
//! layer says it out loud — `POLICY_TEXT` documents that `Resource::Registry`
//! is *not* gated by `ALLOWED_AUDIENCES` and that the reachable set comes from
//! operator configuration — and that sentence is only true because of what is
//! here. A reader who trusts the allowlist without reading this has trusted a
//! comment.
//!
//! ## Why the set is declared and not enumerated
//!
//! `ALLOWED_AUDIENCES` is two first-party API hosts, and enumerating registry
//! hosts would be the same mistake one size larger: Docker Hub, GHCR, Quay,
//! self-hosted Artifactory, and a per-region ECR endpoint whose region changes
//! with the account. That list would be correct on the day it was written and
//! stale every week after, and — worse — the way to make it correct again would
//! be to *edit a list in the source tree*, which turns an operator's
//! destination into a code change.
//!
//! ## Why the request only ever names a repository
//!
//! The dangerous shape is a request that carries a host. If `Request` had a
//! `registry` field the agent chose, then `authorize_registry` would be a
//! *filter* over hosts the agent picked, and the policy rule an operator wrote
//! — `resource.authority == "registry-1.docker.io" && resource.repository ==
//! "library/alpine"` — would silently invert into "allow everything except
//! `registry-1.docker.io`" the day someone generalised it. The same policy text
//! would mean the opposite thing.
//!
//! So the split is: **the deployment declares the registry, the request
//! proposes the repository, and the broker answers with the declared entry.**
//! An undeclared registry is refused before any credential is lent, before any
//! socket is opened, and before the policy engine is asked — because a policy
//! cannot un-lend a credential and an allowlist the policy can widen is not an
//! allowlist.
//!
//! This is the same bargain `OAuth2Client` struck, and the reason both exist as
//! separate resource variants is that the bargain is the security property.
//! Naming it here as well is deliberate: a reader comparing the two should
//! find the same argument in both places and not have to rediscover it.

use asv_domain::{Authority, CredentialId};

/// One registry the operator declared, and the vault credential that holds the
/// secret it trades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDeclaration {
    /// The registry authority, already canonicalized by [`load`].
    ///
    /// An `Authority` and not a `String` so that a lookalike spelling of a real
    /// registry cannot be constructed at all — the D6 property, kept because it
    /// is free here and because the lookup below is an equality on this value.
    pub authority: Authority,
    /// The credential whose secret is the registry token or password.
    ///
    /// **Never the secret, and never a name the request supplied.** The
    /// declaration is the only thing that says which credential serves which
    /// registry, and the request names a repository instead.
    pub credential: CredentialId,
}

/// Everything the operator declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryDeclarations {
    entries: Vec<RegistryDeclaration>,
}

impl RegistryDeclarations {
    /// The credential serving `registry`, or `None` when it was not declared.
    ///
    /// **The `None` arm is the control**, and it is reached before any policy
    /// is consulted and before any credential is lent. An undeclared registry
    /// is not a policy decision an operator can make in a rule; it is a
    /// destination this deployment does not have.
    pub fn credential_for(&self, registry: &Authority) -> Option<&CredentialId> {
        self.entries
            .iter()
            .find(|entry| &entry.authority == registry)
            .map(|entry| &entry.credential)
    }

    /// How many registries were declared. For the rows that assert a file with
    /// one entry did not silently become three.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a declaration file was refused.
///
/// Startup refusals rather than first-use ones, for the reason
/// `oauth2_port::load_clients` gives: everything here is knowable without the
/// network, and an operator learns about it at startup rather than at the first
/// agent that asks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    #[error("the declaration file could not be read: {reason}")]
    Unreadable { reason: String },
    #[error("the declaration file is not a JSON array of declarations: {0}")]
    Malformed(String),
    #[error("a declaration names a registry twice: {registry}")]
    Duplicate { registry: String },
    #[error("the declaration for {registry} is unusable: {reason}")]
    Unusable { registry: String, reason: String },
}

/// The on-disk shape. Private: callers go through [`load`], which validates.
#[derive(serde::Deserialize)]
struct RawDeclaration {
    registry: String,
    credential: String,
}

/// Loads declarations from a JSON file.
///
/// ```json
/// [
///   { "registry": "registry-1.docker.io",
///     "credential": "00000000-0000-4000-8000-000000000000" }
/// ]
/// ```
///
/// Four refusals, and the second one is the interesting one. An empty
/// registry, a registry that is not a bare host, a credential that is not a
/// vault id, and **two declarations naming one registry** — the last because a
/// registry with two credentials is not a deployment, it is a coin toss, and
/// which credential a pull spends would depend on file order.
pub fn load(path: &std::path::Path) -> Result<RegistryDeclarations, DeclarationError> {
    let text = std::fs::read_to_string(path).map_err(|error| DeclarationError::Unreadable {
        reason: error.to_string(),
    })?;
    let raw: Vec<RawDeclaration> = serde_json::from_str(&text)
        .map_err(|error| DeclarationError::Malformed(error.to_string()))?;

    let mut entries: Vec<RegistryDeclaration> = Vec::with_capacity(raw.len());
    for entry in raw {
        // `Authority::canonicalize` is the whole of the host validation and it
        // is deliberately the same function the lookup compares against: a
        // validator that accepted something the comparer would treat as a
        // different host would be a declaration that loads and never matches.
        let authority = Authority::canonicalize(&entry.registry).map_err(|error| {
            DeclarationError::Unusable {
                registry: entry.registry.clone(),
                reason: format!("{error}"),
            }
        })?;
        let credential = CredentialId::from_wire(&entry.credential).map_err(|error| {
            DeclarationError::Unusable {
                registry: entry.registry.clone(),
                reason: format!("it is not a vault id, so no request could ever name it: {error}"),
            }
        })?;
        if entries
            .iter()
            .any(|existing| existing.authority == authority)
        {
            return Err(DeclarationError::Duplicate {
                registry: authority.to_string(),
            });
        }
        entries.push(RegistryDeclaration {
            authority,
            credential,
        });
    }
    Ok(RegistryDeclarations { entries })
}
#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL: &str = "00000000-0000-4000-8000-000000000000";
    const OTHER: &str = "00000000-0000-4000-8000-000000000001";

    fn write(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "asv-registry-decl-{}-{:p}.json",
            std::process::id(),
            contents
        ));
        std::fs::write(&path, contents).expect("the declaration file is written");
        path
    }

    fn declarations(entries: &str) -> RegistryDeclarations {
        let path = write(entries);
        let loaded = load(&path);
        std::fs::remove_file(&path).ok();
        loaded.expect("the declaration file is valid")
    }

    /// A declared registry answers with its own credential, and an undeclared
    /// one answers with nothing.
    ///
    /// Both halves, because only the first is a positive claim and a
    /// `credential_for` that always returned `Some` would pass it.
    ///
    /// Mutation: return the first entry whatever is asked for.
    #[test]
    fn un_registry_declarado_responde_y_uno_sin_declarar_no() {
        let declared = declarations(&format!(
            r#"[{{"registry":"registry-1.docker.io","credential":"{CREDENTIAL}"}}]"#
        ));
        let hub = Authority::canonicalize("registry-1.docker.io").expect("valid");
        let ghcr = Authority::canonicalize("ghcr.io").expect("valid");

        assert_eq!(
            declared.credential_for(&hub),
            Some(&CredentialId::from_wire(CREDENTIAL).expect("valid id")),
            "a declared registry did not answer with its own credential"
        );
        assert_eq!(
            declared.credential_for(&ghcr),
            None,
            "an undeclared registry answered, so the allowlist is not the \\
             control and the reachable set is whatever the request says"
        );
    }

    /// A request naming a declared registry, or any suffix of it, does not reach
    /// it unless it *is* it.
    ///
    /// **The suffix half of this row is the one that was missing, and the
    /// falsification campaign is what found it.** The row originally only asked
    /// whether a *longer* mirla reaches the registry, and it came back green
    /// under the `ends_with` mutation -- because
    /// `"registry-1.docker.io.evil.example".ends_with("registry-1.docker.io")`
    /// is false. The mutation passes that direction and the attack runs the
    /// other one: a lookup written as `declared.ends_with(requested)` lets a
    /// request naming **`docker.io`** be served the credential declared for
    /// `registry-1.docker.io`, because the declared name ends with the
    /// requested one. Every "did the right registry answer?" row in this file
    /// passes with that mutation in place, which is the definition of a row
    /// that cannot fail for the reason it was written for.
    ///
    /// This is the same one-character mistake the D6 allowlist exists to
    /// refuse, and it is why the lookup is an equality on a canonicalized
    /// `Authority` rather than a string comparison of any kind.
    ///
    /// Mutation: match with `ends_with` instead of equality.
    #[test]
    fn ni_una_mirla_ni_un_sufijo_de_un_registry_declarado_lo_alcanza() {
        let declared = declarations(&format!(
            r#"[{{"registry":"registry-1.docker.io","credential":"{CREDENTIAL}"}}]"#
        ));
        // Every one of these is a valid bare host, which is why they are the
        // interesting inputs: `Authority` accepts them all, so the refusal has
        // to come from the lookup and not from the type.
        for other in [
            // Longer than the declared one: the obvious mirla.
            "registry-1.docker.io.evil.example",
            "evil.example.registry-1.docker.io",
            // **Shorter.** These are the ones the missing half was about.
            "docker.io",
            // A label from the middle, which no suffix rule catches either way
            // and which therefore needs the equality to refuse.
            "1.docker.io",
            // A different registry entirely, in case the rows above all pass by
            // accident of the fixture.
            "ghcr.io",
        ] {
            assert_eq!(
                declared.credential_for(&Authority::canonicalize(other).expect("valid")),
                None,
                "{other:?} reached a registry that was never declared for it"
            );
        }

        // And the control: the declared one still answers, so the loop above
        // is not passing because the fixture declared nothing.
        assert!(
            declared
                .credential_for(&Authority::canonicalize("registry-1.docker.io").expect("valid"))
                .is_some(),
            "the declared registry stopped answering, so the refusals above \
             prove nothing"
        );
    }

    /// Two declarations for one registry are refused at load, not resolved at
    /// first use.
    ///
    /// A registry with two credentials is not a deployment, it is a coin toss,
    /// and which credential a pull spends would depend on the order of a JSON
    /// array — so an operator reading the file cannot tell which secret went to
    /// their CI.
    ///
    /// Mutation: keep both entries and let the lookup take the first.
    #[test]
    fn dos_credenciales_para_un_registry_se_rechusan_al_cargar() {
        let path = write(&format!(
            r#"[{{"registry":"ghcr.io","credential":"{CREDENTIAL}"}},
                 {{"registry":"ghcr.io","credential":"{OTHER}"}}]"#
        ));
        let loaded = load(&path);
        std::fs::remove_file(&path).ok();

        assert_eq!(
            loaded,
            Err(DeclarationError::Duplicate {
                registry: "ghcr.io".into()
            }),
            "two credentials for one registry loaded, so which secret a pull \
             spends depends on the order of the file"
        );
    }

    /// A file with one entry produces exactly one declaration.
    ///
    /// This is the row that says the parser does not invent entries, and it is
    /// here because every other row in this file asserts what
    /// `credential_for` answers — which is vacuous if the set behind it is
    /// always empty, or always has three members regardless of the file.
    ///
    /// Mutation: push a default entry, or drop the ones parsed.
    #[test]
    fn un_fichero_con_una_entrada_produce_una_declaracion() {
        let one = declarations(&format!(
            r#"[{{"registry":"ghcr.io","credential":"{CREDENTIAL}"}}]"#
        ));
        assert_eq!(one.len(), 1);
        assert!(!one.is_empty());

        let none = declarations("[]");
        assert!(none.is_empty(), "an empty file produced entries");
    }

    /// Everything that is not a bare host is refused, and a *different* host is
    /// not one of those things.
    ///
    /// The second half of this row replaced a mistake, and the mistake is worth
    /// recording because it is the same one this file's neighbour in `asv-domain`
    /// has already paid for twice. The first version listed
    /// `registry-1.docker.io.evil.example` among the strings that must be
    /// refused, on the reasoning that it is a mirla of a real registry. It is
    /// not refused, and it should not be: **the registry here is operator
    /// text.** A self-hosted Artifactory at `registry.internal.example` is the
    /// case this whole file exists for, and a suffix rule aimed at the operator
    /// would make a large fraction of real deployments undeployable.
    ///
    /// What matters is the opposite direction, and it is the other row: a
    /// *request* naming `registry-1.docker.io.evil.example` must not be served
    /// the credential declared for `registry-1.docker.io`. The lookup is an
    /// equality on a canonicalized `Authority`, so each answers only for
    /// itself.
    ///
    /// Mutation: split the host off with `split_once("://")` and keep going.
    #[test]
    fn una_declaracion_que_no_es_un_host_puro_se_rechaza() {
        for not_a_host in [
            "https://registry-1.docker.io",
            "registry-1.docker.io:443",
            "registry-1.docker.io/v2/",
            "user@registry-1.docker.io",
            "",
        ] {
            let path = write(&format!(
                r#"[{{"registry":"{not_a_host}","credential":"{CREDENTIAL}"}}]"#
            ));
            let loaded = load(&path);
            std::fs::remove_file(&path).ok();
            assert!(
                matches!(loaded, Err(DeclarationError::Unusable { .. })),
                "{not_a_host:?} loaded as a registry declaration, so a string that \
                 is not a bare host would be both compared and dialled"
            );
        }
    }

    /// A self-hosted registry is a legitimate declaration, and it answers only
    /// for itself.
    ///
    /// The positive half of the row the previous one used to be wrong about. An
    /// operator pointing this product at `registry.internal.example` is the
    /// reason the allowlist is declared rather than enumerated, and a file that
    /// refused it would force them onto Docker Hub — which is the failure mode
    /// an allowlist is supposed to prevent, not cause.
    ///
    /// Mutation: refuse any host that is not in a built-in list.
    #[test]
    fn un_registry_autohospedado_se_declara_y_solo_responde_por_el_mismo() {
        let declared = declarations(&format!(
            r#"[{{"registry":"registry.internal.example","credential":"{CREDENTIAL}"}}]"#
        ));
        let selfhosted = Authority::canonicalize("registry.internal.example").expect("valid");
        let docker = Authority::canonicalize("registry-1.docker.io").expect("valid");

        assert!(
            declared.credential_for(&selfhosted).is_some(),
            "a self-hosted registry was refused, so the only reachable one is \
             Docker Hub and the declaration is a list wearing a policy's name"
        );
        assert_eq!(
            declared.credential_for(&docker),
            None,
            "a self-hosted declaration answered for Docker Hub, so the two are \
             the same entry as far as a request can tell"
        );
    }
}
