//! The relation vocabulary — `06-CLI-CONTRACT.md` §4 and §5.
//!
//! A link is a promise that the named program can be run with that argv and
//! that it will do the thing the `operation` says. Two ways that promise is
//! usually broken, both of which are closed here:
//!
//! **A relation with no command behind it.** `06-CLI-CONTRACT.md` §5 is
//! explicit that additional relations may be published "only if the real
//! implementation is operational". Publishing `asv://rels/approval/request`
//! when the secure transport is still incomplete would send an agent down a
//! path that ends in a refusal it cannot interpret. [`AgentRel::operational`]
//! is the list that discovery filters through, and
//! `every_operational_relation_parses_as_a_real_command` is what keeps the two
//! in step.
//!
//! **A relation whose argv is a shell string.** The descriptor carries a
//! program and an argv *array*, and a caller appends its own arguments as
//! elements. There is no field to interpolate into, so `asv://rels/session/run`
//! cannot become `sh -c "asv run <user text>"` by accident. The field is an
//! array of strings, not a string, and that is the whole mechanism.

use serde::{Deserialize, Serialize};

/// A program plus its arguments, as a literal array.
///
/// `argv` is a `Vec`, never a joined string. A joined string would have to be
/// re-split, and the re-split is where a workspace path containing a space
/// becomes two arguments and a credential name becomes a flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInvoke {
    pub program: String,
    pub argv: Vec<String>,
}

/// What running the link can do to the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Safety {
    /// Reads state and changes nothing.
    ReadOnly,
    /// Changes local configuration belonging to the invoking user.
    LocalConfiguration,
    /// Runs a command under a broker-owned session.
    BoundedExecution,
}

/// One navigable step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLink {
    /// Stable relation URI. The programmable identity of the link.
    pub rel: String,
    /// Dotted operation name, for logs and for the skill to match on.
    pub operation: String,
    pub invoke: AgentInvoke,
    pub safety: Safety,
    /// Whether a human has to approve before the step means anything. An
    /// agent that cannot ask a human has to stop here rather than continue.
    pub requires_human: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl AgentLink {
    fn new(
        rel: &str,
        operation: &str,
        argv: &[&str],
        safety: Safety,
        requires_human: bool,
        description: &str,
    ) -> Self {
        Self {
            rel: rel.to_string(),
            operation: operation.to_string(),
            invoke: AgentInvoke {
                program: "asv".to_string(),
                argv: argv.iter().map(|s| s.to_string()).collect(),
            },
            safety,
            requires_human,
            description: Some(description.to_string()),
        }
    }
}

/// The relation vocabulary.
///
/// The variants exist so that a typo is a compile error. What is *published*
/// is [`AgentRel::operational`], which is a strictly smaller list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRel {
    Status,
    Doctor,
    Setup,
    Capabilities,
    /// R0.3b. A relation an agent can follow when a protocol mismatch leaves
    /// it with no operation it can perform against the running broker. Closes
    /// the gate `tests/r0_gate.py::r0_3b_upgrade_relation` measures, which
    /// looks for an `upgrade`/`recover`/`repair` relation on the surface
    /// `asv capabilities --json` publishes even with no broker reachable.
    Upgrade,
    CredentialList,
    SessionRun,
    // Minted and spent inside a single `asv github` invocation, so the token
    // itself is never in a process the caller owns. Published since R2.A;
    // `operational()` carries the reason they were dark before that.
    GithubIssueRead,
    GithubIssueCreate,
    GithubReleaseCreate,
    // R2.F.3. Published because the verbs exist and the broker answers them;
    // the same condition the three above were dark until. **Not published**
    // would have been the easy mistake: a registry pull works, so an agent
    // that reads `asv capabilities` and finds no registry relation concludes
    // the product cannot pull, and it is right about what it read and wrong
    // about what the product can do. That is the "built and unannounced"
    // failure this module's own header is about.
    RegistryManifestRead,
    RegistryBlobRead,
    /// R2.F.4. A registry write is two more relations for the reason the reads
    /// are two: a push of a manifest and a push of a blob are two requests, and
    /// they are not interchangeable — one is addressed by a tag, the other by a
    /// content address computed from the bytes.
    RegistryManifestPush,
    RegistryBlobPush,
    // Declared, not yet published. See `operational()` for why each is
    // waiting; the comment is the reason so that adding the capability later
    // is a one-line change with the reasoning still attached.
    //
    // Postgres and SSH sign have the same shape of gap the GitHub three had —
    // the broker operation exists and `asv run` reaches it — but the answer is
    // not the same. A GitHub call is one request the broker makes on the
    // caller's behalf. `psql` and `git push` are *long-lived interactive
    // protocols* over a socket the caller holds, and projecting a surrogate
    // into them is the CONNECT problem, not the semantic-operation one. They
    // wait for that to be settled rather than for a CLI verb, so no amount of
    // adding a command here would be the missing piece.
    //
    // Approval and audit stay dark until their transport is complete
    // (`06-CLI-CONTRACT.md` §5): the broker's audit query exists, but
    // `asv audit` is denied by the control plane that has not shipped, and a
    // link an agent follows into a refusal teaches it that the link lied.
    PostgresConnect,
    PostgresQuery,
    SshSign,
    ApprovalStatus,
    AuditRead,
    /// R2.D.3. The K8s read surface (`asv k8s read`). Published because an
    /// agent that asks for a Kubernetes read gets a refusal that names the
    /// gap, which is the answer the roadmap wants — and what an
    /// unpublished link would have hidden.
    K8sRead,
    /// R2.E.3. The mTLS sign surface (`asv mtls sign`). Same reasoning as
    /// `K8sRead`: the broker validates the CSR and refuses with `Denied`
    /// until R2.E.3.2 lands.
    MTlsSign,
}

impl AgentRel {
    /// The relation URI. Stable; an agent may persist it.
    pub fn uri(self) -> &'static str {
        match self {
            AgentRel::Status => "asv://rels/status",
            AgentRel::Doctor => "asv://rels/doctor",
            AgentRel::Setup => "asv://rels/setup",
            AgentRel::Capabilities => "asv://rels/capabilities",
            AgentRel::Upgrade => "asv://rels/upgrade",
            AgentRel::CredentialList => "asv://rels/credentials/list",
            AgentRel::SessionRun => "asv://rels/session/run",
            AgentRel::GithubIssueRead => "asv://rels/github/issue/read",
            AgentRel::GithubIssueCreate => "asv://rels/github/issue/create",
            AgentRel::GithubReleaseCreate => "asv://rels/github/release/create",
            AgentRel::RegistryManifestRead => "asv://rels/registry/manifest/read",
            AgentRel::RegistryBlobRead => "asv://rels/registry/blob/read",
            AgentRel::RegistryManifestPush => "asv://rels/registry/manifest/push",
            AgentRel::RegistryBlobPush => "asv://rels/registry/blob/push",
            AgentRel::K8sRead => "asv://rels/k8s/read",
            AgentRel::MTlsSign => "asv://rels/mtls/sign",
            AgentRel::PostgresConnect => "asv://rels/postgres/connect",
            AgentRel::PostgresQuery => "asv://rels/postgres/query",
            AgentRel::SshSign => "asv://rels/ssh/sign",
            AgentRel::ApprovalStatus => "asv://rels/approval/status",
            AgentRel::AuditRead => "asv://rels/audit/read",
        }
    }

    /// The dotted operation name.
    pub fn operation(self) -> &'static str {
        match self {
            AgentRel::Status => "system.status",
            AgentRel::Doctor => "system.doctor",
            AgentRel::Setup => "system.setup",
            AgentRel::Capabilities => "system.capabilities",
            AgentRel::Upgrade => "system.upgrade",
            AgentRel::CredentialList => "credentials.metadata.list",
            AgentRel::SessionRun => "session.run",
            AgentRel::GithubIssueRead => "github.issue.read",
            AgentRel::GithubIssueCreate => "github.issue.create",
            AgentRel::GithubReleaseCreate => "github.release.create",
            AgentRel::RegistryManifestRead => "registry.manifest.read",
            AgentRel::RegistryBlobRead => "registry.blob.read",
            AgentRel::RegistryManifestPush => "registry.manifest.push",
            AgentRel::RegistryBlobPush => "registry.blob.push",
            AgentRel::K8sRead => "k8s.read",
            AgentRel::MTlsSign => "mtls.sign",
            AgentRel::PostgresConnect => "postgres.connect",
            AgentRel::PostgresQuery => "postgres.query",
            AgentRel::SshSign => "ssh.sign",
            AgentRel::ApprovalStatus => "approval.status",
            AgentRel::AuditRead => "audit.read",
        }
    }

    /// The full descriptor, whether or not it is published.
    pub fn descriptor(self) -> AgentLink {
        match self {
            AgentRel::Status => AgentLink::new(
                self.uri(),
                self.operation(),
                &["status", "--json"],
                Safety::ReadOnly,
                false,
                "Check whether the broker answers",
            ),
            AgentRel::Doctor => AgentLink::new(
                self.uri(),
                self.operation(),
                &["doctor", "--json"],
                Safety::ReadOnly,
                false,
                "Inspect installation and broker health",
            ),
            AgentRel::Setup => AgentLink::new(
                self.uri(),
                self.operation(),
                &["setup", "--json"],
                Safety::LocalConfiguration,
                false,
                "Create the runtime layout and start the broker service",
            ),
            AgentRel::Capabilities => AgentLink::new(
                self.uri(),
                self.operation(),
                &["capabilities", "--json"],
                Safety::ReadOnly,
                false,
                "List the capabilities this installation offers",
            ),
            AgentRel::CredentialList => AgentLink::new(
                self.uri(),
                self.operation(),
                &["credentials", "--json"],
                Safety::ReadOnly,
                false,
                "List stored credential metadata, never values",
            ),
            AgentRel::SessionRun => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--"],
                Safety::BoundedExecution,
                false,
                "Run a command inside a broker-owned session",
            ),
            // R0.3b. Reports the current version, the latest published one,
            // and the documented installer command. Safe to publish even with
            // no broker reachable, because protocol mismatch is precisely the
            // state in which the broker is the thing the agent cannot reach.
            AgentRel::Upgrade => AgentLink::new(
                self.uri(),
                self.operation(),
                &["upgrade", "--check"],
                Safety::ReadOnly,
                false,
                "Report the running version and the published one",
            ),
            AgentRel::GithubIssueRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["github", "issue", "view"],
                Safety::BoundedExecution,
                true,
                "Read a GitHub issue through a broker-leased credential",
            ),
            AgentRel::GithubIssueCreate => AgentLink::new(
                self.uri(),
                self.operation(),
                &["github", "issue", "create"],
                Safety::BoundedExecution,
                true,
                "Create a GitHub issue through a broker-leased credential",
            ),
            AgentRel::GithubReleaseCreate => AgentLink::new(
                self.uri(),
                self.operation(),
                &["github", "release", "create"],
                Safety::BoundedExecution,
                true,
                "Create a GitHub release through a broker-leased credential",
            ),
            AgentRel::RegistryManifestRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["registry", "manifest", "read"],
                Safety::BoundedExecution,
                true,
                "Read an OCI manifest through a broker-leased credential",
            ),
            AgentRel::RegistryBlobRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["registry", "blob", "read"],
                Safety::BoundedExecution,
                true,
                "Read an OCI blob, verified against its content address",
            ),
            // Published together with the `push` verbs in the same change, for
            // the reason `every_operational_relation_parses_as_a_real_command`
            // exists: a link is a promise about a command, and the argv below
            // is checked against the real parser by that row rather than by
            // reading this file.
            AgentRel::RegistryManifestPush => AgentLink::new(
                self.uri(),
                self.operation(),
                &["registry", "manifest", "push"],
                Safety::BoundedExecution,
                true,
                "Publish an OCI manifest through a broker-leased credential",
            ),
            AgentRel::RegistryBlobPush => AgentLink::new(
                self.uri(),
                self.operation(),
                &["registry", "blob", "push"],
                Safety::BoundedExecution,
                true,
                "Publish an OCI blob, addressed by the digest of its own bytes",
            ),
            AgentRel::PostgresConnect => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "psql", "--"],
                Safety::BoundedExecution,
                true,
                "Open a PostgreSQL session through a leased credential",
            ),
            AgentRel::PostgresQuery => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "psql", "-c", "--"],
                Safety::BoundedExecution,
                true,
                "Run one PostgreSQL statement through a leased credential",
            ),
            AgentRel::SshSign => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "git", "push", "--"],
                Safety::BoundedExecution,
                true,
                "Push using the broker-owned SSH signer",
            ),
            AgentRel::ApprovalStatus => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "asv-approval", "status", "--"],
                Safety::BoundedExecution,
                false,
                "Read pending approval state",
            ),
            AgentRel::AuditRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["audit", "--json"],
                Safety::ReadOnly,
                false,
                "Read the broker audit log",
            ),
            // R2.D.3. The K8s read surface; the broker refuses with `Denied`
            // today because R2.D.3.2 (deployment registry, surrogate mint,
            // transport) has not landed. Requires human because reading a
            // Kubernetes object carries the same risk as a credentialed
            // request — the response is the API server's authority on what
            // the agent will see.
            AgentRel::K8sRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["k8s", "read"],
                Safety::BoundedExecution,
                true,
                "Read one Kubernetes object through a broker-leased token",
            ),
            // R2.E.3. Same shape as K8s. The broker validates the CSR and
            // refuses; signing happens at the broker. Requires human
            // because the response is the authority the broker asserts
            // about who the agent is to a third party.
            AgentRel::MTlsSign => AgentLink::new(
                self.uri(),
                self.operation(),
                &["mtls", "sign"],
                Safety::BoundedExecution,
                true,
                "Sign a client certificate with a broker-managed CA",
            ),
        }
    }

    /// The relations this build actually publishes.
    ///
    /// This is a subset of the enum on purpose, and the subset is the claim.
    /// `06-CLI-CONTRACT.md` §5 names six core relations; DX2 completes all six
    /// by shipping `asv capabilities`. R2.A adds the three GitHub ones. The
    /// other five are withheld for the reasons in their variant comments.
    ///
    /// A relation is in this list only if the command behind it parses. That
    /// is not a convention: `every_operational_relation_parses_as_a_real_command`
    /// runs the actual parser, and it is what caught `status --json` being
    /// advertised by a CLI that had no such flag.
    ///
    /// # Why GitHub joined in R2.A
    ///
    /// The three GitHub relations were withheld while their descriptor pointed
    /// at `asv run -- gh issue view --`. That argv was a fiction twice over: the
    /// CLI had no `gh` verb, and `asv run` is the *surrogate* path, which
    /// substitutes a credential at a CONNECT tunnel rather than giving `gh` a
    /// token — so a link that advertised it would have sent an agent to a tool
    /// that cannot do what the link says, on a path that would not have let it
    /// do it anyway.
    ///
    /// The replacement, `asv github …`, is the path where the token never
    /// enters a process at all: the broker lends it to one HTTP header for one
    /// request. Publishing the relation *and* repointing it in the same change
    /// is deliberate — a published link is a promise about a command, and the
    /// two halves of that promise cannot be shipped apart.
    pub fn operational() -> &'static [AgentRel] {
        &[
            AgentRel::Status,
            AgentRel::Doctor,
            AgentRel::Setup,
            AgentRel::Capabilities,
            AgentRel::Upgrade,
            AgentRel::CredentialList,
            AgentRel::SessionRun,
            AgentRel::GithubIssueRead,
            AgentRel::GithubIssueCreate,
            AgentRel::GithubReleaseCreate,
            AgentRel::RegistryManifestRead,
            AgentRel::RegistryBlobRead,
            AgentRel::RegistryManifestPush,
            AgentRel::RegistryBlobPush,
            AgentRel::K8sRead,
            AgentRel::MTlsSign,
        ]
    }

    /// The relations worth publishing from an observed installation.
    ///
    /// `broker_reachable` is the whole decision. With no broker, the only
    /// links published are the two that lead somewhere: `doctor`, which
    /// describes the state, and `setup`, which changes it. Publishing
    /// `credentials/list` or `session/run` into a stopped installation would
    /// be publishing a promise the CLI cannot keep — the agent spends a turn
    /// following it and gets a connection error, which is exactly the
    /// "follows an unknown link and stops" outcome AAT-008 is about, reached
    /// by a different route.
    ///
    /// `doctor` stays published even when healthy, because asking "is this
    /// still true" is the cheapest question an agent can ask and the one it
    /// has most reason to ask again.
    pub fn publishable_for(broker_reachable: bool) -> Vec<AgentRel> {
        if broker_reachable {
            AgentRel::operational().to_vec()
        } else {
            // `upgrade` is reachable even with no broker: protocol mismatch is
            // the state in which the broker cannot be reached, and that is the
            // state in which the recovery relation is the only one that points
            // at a runnable command.
            vec![AgentRel::Doctor, AgentRel::Setup, AgentRel::Upgrade]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::CommandFactory;

    /// The link as the argument list a consumer would build: the program
    /// followed by the argv elements, as separate items. Never joined into a
    /// string — see the module docs on why that field is an array.
    ///
    /// Then whatever the consumer has to supply, per [`completion_for`].
    ///
    /// # Two kinds of relation, and the argv says which
    ///
    /// A **template** ends at `--`: the consumer appends free-form elements,
    /// and the `--` is what stops clap from reading them as flags. That is the
    /// shape `session/run` has, and it exists because the consumer's own
    /// command is the payload.
    ///
    /// A **complete command** has no `--` and no free-form text at all: every
    /// input is a named flag. R2.A's GitHub relations are this shape, and the
    /// trailing `--` had to come off for a concrete reason — behind it, clap
    /// treats everything as trailing positional arguments, so
    /// `asv github issue view -- --repo owner/repo` is rejected with
    /// *unknown argument `--repo`*. A template marker is a promise that
    /// positional text follows, and these verbs have no positional text to
    /// promise.
    fn argv_of(link: &AgentLink) -> Vec<String> {
        let mut argv: Vec<String> = std::iter::once(link.invoke.program.clone())
            .chain(link.invoke.argv.iter().cloned())
            .collect();
        if let Some(completion) = completion_for(&link.rel) {
            argv.extend(completion.iter().map(|s| s.to_string()));
        }
        argv
    }

    /// What a consumer has to supply, or `None` when the link is already the
    /// whole command.
    ///
    /// Keyed on the relation URI rather than on the argv, so a descriptor that
    /// drifts away from its own completion is visibly wrong rather than
    /// silently re-fitted. The credential value is a placeholder id, never a
    /// token — which is also a small standing check that the link asks for a
    /// *reference*.
    fn completion_for(rel: &str) -> Option<&'static [&'static str]> {
        Some(match rel {
            // Already complete: `asv status --json` needs nothing from a
            // consumer, and appending to it is how `asv status --json echo`
            // became a parse failure unrelated to the link under test.
            "asv://rels/status"
            | "asv://rels/doctor"
            | "asv://rels/setup"
            | "asv://rels/capabilities"
            | "asv://rels/credentials/list"
            | "asv://rels/audit/read" => return None,
            "asv://rels/session/run"
            | "asv://rels/postgres/connect"
            | "asv://rels/postgres/query"
            | "asv://rels/ssh/sign" => &["echo"],
            "asv://rels/github/issue/read" => &[
                "--repo",
                "owner/repo",
                "--number",
                "1",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            "asv://rels/github/issue/create" => &[
                "--repo",
                "owner/repo",
                "--title",
                "a title",
                "--body",
                "/dev/null",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            "asv://rels/github/release/create" => &[
                "--repo",
                "owner/repo",
                "--tag",
                "v1",
                "--name",
                "a name",
                "--body",
                "/dev/null",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            // R2.F.3. The credential placeholder is a vault *id* and never a
            // token, for the same reason the three above are: the link a
            // consumer completes must ask for a reference, because a link that
            // asked for the secret would be the product handing the agent the
            // thing it exists to withhold.
            //
            // `--registry` is here as a *selector*, and its example is a real
            // host rather than a syntactically valid placeholder. The link
            // promises that the broker resolves a declaration by equality and
            // dials what the operator wrote, so a caller supplying an
            // undeclared host gets a refusal rather than a connection to
            // somewhere it invented — which is the answer the link should
            // lead to, and not something the completion should hide.
            "asv://rels/registry/manifest/read" => &[
                "--registry",
                "registry-1.docker.io",
                "--repository",
                "library/alpine",
                "--reference",
                "latest",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            "asv://rels/registry/blob/read" => &[
                "--registry",
                "registry-1.docker.io",
                "--repository",
                "library/alpine",
                "--digest",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            // The writes carry `--file`, not a digest the caller supplies. The
            // blob completion has no `--digest` on purpose: the CLI computes the
            // address from the bytes, so a consumer completing one would be
            // making a claim about content nothing has checked.
            "asv://rels/registry/manifest/push" => &[
                "--registry",
                "registry-1.docker.io",
                "--repository",
                "library/alpine",
                "--reference",
                "latest",
                "--file",
                "/dev/null",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            "asv://rels/registry/blob/push" => &[
                "--registry",
                "registry-1.docker.io",
                "--repository",
                "library/alpine",
                "--file",
                "/dev/null",
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            // R2.D.3. The K8s read surface — the same placeholder pattern the
            // GitHub three and the registry four use. A consumer that wants to
            // *check* the surface parses the whole command and runs; the real
            // broker operation refuses with `Denied` until R2.D.3.2 lands.
            "asv://rels/k8s/read" => &[
                "--credential",
                "00000000-0000-4000-8000-000000000000",
                "--namespace",
                "default",
                "--resource",
                "pods",
                "--name",
                "example",
            ],
            // R2.E.3. The mTLS sign surface — the CSR is read from stdin, so
            // the completion is just the credential reference.
            "asv://rels/mtls/sign" => &[
                "--credential",
                "00000000-0000-4000-8000-000000000000",
            ],
            _ => return None,
        })
    }

    /// Whether this relation is a template the consumer completes.
    ///
    /// `06-CLI-CONTRACT.md` §4: *"argumentos aportados por el usuario se
    /// anexan como elementos, no como interpolación textual."* A link that
    /// ends at `--` is where that rule is visible: the argv is a fixed prefix
    /// and the caller's words are appended to it.
    fn is_template(link: &AgentLink) -> bool {
        link.invoke.argv.last().map(String::as_str) == Some("--")
    }

    /// Every published relation must be a command this binary can actually
    /// parse. This is the guard against publishing a promise with nothing
    /// behind it: `AgentRel::operational()` grows, the subcommand list does
    /// not, and the difference is a link that leads nowhere.
    #[test]
    fn every_operational_relation_parses_as_a_real_command() {
        for rel in AgentRel::operational() {
            let link = rel.descriptor();
            let parsed = Cli::command().try_get_matches_from(argv_of(&link));
            assert!(
                parsed.is_ok(),
                "{} advertises `asv {}` and that is not a command: {:?}",
                link.rel,
                link.invoke.argv.join(" "),
                parsed.err()
            );
        }
    }

    /// The URI set is the interface an agent persists, so a rename here is a
    /// silent break for anything that stored the old string.
    ///
    /// Pinned in full, not just the six core relations: R2.A grew the set and
    /// the growth is the kind of change that is supposed to be a decision
    /// rather than a side effect. A test that only counted would have reported
    /// nine and said nothing about *which* nine.
    #[test]
    fn the_core_relation_uris_are_pinned() {
        let uris: Vec<&str> = AgentRel::operational().iter().map(|r| r.uri()).collect();
        assert_eq!(
            uris,
            [
                "asv://rels/status",
                "asv://rels/doctor",
                "asv://rels/setup",
                "asv://rels/capabilities",
                // R0.3b. The recovery relation an agent follows when the
                // running broker speaks a protocol it cannot reach, instead
                // of stalling on `PROTOCOL_MISMATCH` with no command to run.
                "asv://rels/upgrade",
                "asv://rels/credentials/list",
                "asv://rels/session/run",
                // R2.A. The surrogate is minted and spent inside `asv github`,
                // so what a consumer completes is the repository, the number
                // and the credential *id* — never a token.
                "asv://rels/github/issue/read",
                "asv://rels/github/issue/create",
                "asv://rels/github/release/create",
                // R2.F.3. A registry pull is two relations because it is two
                // requests, and an agent choosing an operation needs to know
                // which one it is asking for.
                "asv://rels/registry/manifest/read",
                "asv://rels/registry/blob/read",
                // R2.F.4. The writes are two more for the same reason, and
                // publishing them next to the reads is what keeps a caller
                // from completing one noun for both directions.
                "asv://rels/registry/manifest/push",
                "asv://rels/registry/blob/push",
                // R2.D.3. The K8s read surface — published with a refusal
                // that names the gap, so the agent can read it rather
                // than guess.
                "asv://rels/k8s/read",
                // R2.E.3. The mTLS sign surface, same reasoning.
                "asv://rels/mtls/sign",
            ]
        );
    }

    /// The GitHub relations must name the real verb, not a `gh` subprocess.
    ///
    /// This is the assertion that would catch the descriptor these three
    /// carried before R2.A: `asv run -- gh issue view --`. Two things were
    /// wrong with that argv and this test can only see one of them, which is
    /// why the credential argument is pinned alongside it.
    ///
    /// The mutation this answers: put the `gh` argv back and this fails.
    #[test]
    fn github_links_name_the_typed_verb_not_a_gh_subprocess() {
        for rel in [
            AgentRel::GithubIssueRead,
            AgentRel::GithubIssueCreate,
            AgentRel::GithubReleaseCreate,
        ] {
            let link = rel.descriptor();
            let argv = &link.invoke.argv;
            assert_eq!(
                argv.first().map(String::as_str),
                Some("github"),
                "{} does not start at `asv github`",
                rel.uri()
            );
            assert!(
                !argv.iter().any(|a| a == "gh" || a == "run"),
                "{} routes through a subprocess: {:?}",
                rel.uri(),
                argv
            );
            // Asserted on the argv a consumer actually builds, not on the
            // fixed prefix. The prefix is `["github", "issue", "view", "--"]`
            // and cannot mention a credential, because the credential is
            // exactly what the consumer supplies — so a test on the prefix
            // alone would be asserting something that is not a property of
            // the link.
            let built = argv_of(&link);
            assert!(
                built.iter().any(|a| a == "--credential"),
                "{} does not ask for a credential reference: {:?}",
                rel.uri(),
                built
            );
            assert!(
                built.iter().any(|a| a == "--repo"),
                "{} does not ask for the destination: {:?}",
                rel.uri(),
                built
            );
        }
    }

    /// Every GitHub link stops a human-less agent, including the read.
    ///
    /// `requires_human` is the only signal an agent has before acting, and all
    /// three links keep the `true` they were declared with. The read is the
    /// interesting one: reading an issue changes nothing upstream, so it looks
    /// like the cheap case — and it is not, because it lends a credential to a
    /// third party over the network. Relaxing it to `false` would have been a
    /// one-word change made by the same commit that published the link, with
    /// no policy decision behind it. So the value is pinned rather than
    /// re-decided here, and relaxing it is a separate proposal.
    ///
    /// The mutation this answers: set `GithubIssueRead`'s flag to `false` and
    /// this fails.
    #[test]
    fn github_links_flag_the_ones_that_change_something() {
        for rel in [
            AgentRel::GithubIssueRead,
            AgentRel::GithubIssueCreate,
            AgentRel::GithubReleaseCreate,
        ] {
            assert!(
                rel.descriptor().requires_human,
                "{} lends a credential off-box and must stop a human-less agent",
                rel.uri()
            );
        }
        // The two that write get the stronger statement: they must not read
        // as read-only to anything deciding whether to prompt.
        for rel in [AgentRel::GithubIssueCreate, AgentRel::GithubReleaseCreate] {
            assert_eq!(
                rel.descriptor().safety,
                Safety::BoundedExecution,
                "{} writes upstream, and its safety must not read as read-only",
                rel.uri()
            );
        }
    }

    /// A stopped broker publishes only the two links that lead somewhere,
    /// plus the recovery relation an agent follows when protocol mismatch
    /// is the reason the broker cannot be reached (R0.3b).
    ///
    /// The failure this closes: publishing `credentials/list` into an
    /// installation whose broker is down. The agent follows it, gets
    /// `ASV_CONNECTION_FAILED`, and has learned that the discovery document
    /// describes commands rather than the installation. `upgrade` stays
    /// published because the relation points at a runnable command that
    /// does not need the broker.
    #[test]
    fn a_stopped_broker_publishes_only_the_links_that_reach_something() {
        let published = AgentRel::publishable_for(false);
        let uris: Vec<&str> = published.iter().map(|r| r.uri()).collect();
        assert_eq!(
            uris,
            ["asv://rels/doctor", "asv://rels/setup", "asv://rels/upgrade"]
        );

        for rel in &published {
            let link = rel.descriptor();
            assert!(
                Cli::command().try_get_matches_from(argv_of(&link)).is_ok(),
                "published link `{}` is not a runnable command",
                link.rel
            );
        }
    }

    /// A reachable broker publishes the whole implemented set, so the two
    /// lists cannot be quietly the same one.
    #[test]
    fn a_reachable_broker_publishes_every_operational_relation() {
        assert_eq!(
            AgentRel::publishable_for(true),
            AgentRel::operational().to_vec()
        );
    }

    /// `approval/request` and `audit/read` are named in the contract as the
    /// ones not to publish while the secure transport is incomplete. The
    /// forbidden set is asserted rather than assumed, so that a future change
    /// that adds them to `operational()` fails here instead of shipping.
    #[test]
    fn the_withheld_relations_are_actually_withheld() {
        for rel in AgentRel::operational() {
            let uri = rel.uri();
            assert_ne!(uri, "asv://rels/approval/request");
            assert_ne!(uri, "asv://rels/approval/status");
            assert_ne!(uri, "asv://rels/audit/read");
        }
    }

    /// `argv` is an array, and a `session.run` link ends at `--` so that the
    /// caller's own words become separate elements. If `argv` ever became a
    /// string, `Vec<String>` would stop compiling here — which is the point
    /// of keeping this assertion.
    #[test]
    fn the_session_link_leaves_the_command_line_open() {
        let link = AgentRel::SessionRun.descriptor();
        assert_eq!(link.invoke.argv.last().map(String::as_str), Some("--"));
        assert_eq!(link.safety, Safety::BoundedExecution);
        assert!(
            is_template(&link),
            "a link ending at `--` is a template, and this relation is the one \
             the contract describes as taking the caller's arguments"
        );
    }

    /// Read-only links must not be able to change anything, and the flag is
    /// the only thing an agent has to go on when deciding whether to prompt a
    /// human. `doctor` and `status` are read-only; `setup` changes local
    /// configuration. Getting these the wrong way round teaches an agent to
    /// treat configuration as free.
    #[test]
    fn read_only_links_are_read_only() {
        assert_eq!(AgentRel::Status.descriptor().safety, Safety::ReadOnly);
        assert_eq!(AgentRel::Doctor.descriptor().safety, Safety::ReadOnly);
        assert_eq!(
            AgentRel::CredentialList.descriptor().safety,
            Safety::ReadOnly
        );
        assert_eq!(
            AgentRel::Setup.descriptor().safety,
            Safety::LocalConfiguration
        );
    }
}
