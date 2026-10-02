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
    CredentialList,
    SessionRun,
    // Declared, not yet published. See `operational()` for why each is
    // waiting; the comment is the reason so that adding the capability later
    // is a one-line change with the reasoning still attached.
    //
    // Approval and audit stay dark until their transport is complete
    // (`06-CLI-CONTRACT.md` §5): the broker's audit query exists, but
    // `asv audit` is denied by the control plane that has not shipped, and a
    // link an agent follows into a refusal teaches it that the link lied.
    // GitHub, Postgres and SSH sign are implemented and reachable through
    // `asv run`, but the relationship between "a session exists" and "this
    // relation succeeds" is not yet one the CLI can state, so v1 does not
    // claim it.
    GithubIssueRead,
    GithubIssueCreate,
    GithubReleaseCreate,
    PostgresConnect,
    PostgresQuery,
    SshSign,
    ApprovalStatus,
    AuditRead,
}

impl AgentRel {
    /// The relation URI. Stable; an agent may persist it.
    pub fn uri(self) -> &'static str {
        match self {
            AgentRel::Status => "asv://rels/status",
            AgentRel::Doctor => "asv://rels/doctor",
            AgentRel::Setup => "asv://rels/setup",
            AgentRel::Capabilities => "asv://rels/capabilities",
            AgentRel::CredentialList => "asv://rels/credentials/list",
            AgentRel::SessionRun => "asv://rels/session/run",
            AgentRel::GithubIssueRead => "asv://rels/github/issue/read",
            AgentRel::GithubIssueCreate => "asv://rels/github/issue/create",
            AgentRel::GithubReleaseCreate => "asv://rels/github/release/create",
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
            AgentRel::CredentialList => "credentials.metadata.list",
            AgentRel::SessionRun => "session.run",
            AgentRel::GithubIssueRead => "github.issue.read",
            AgentRel::GithubIssueCreate => "github.issue.create",
            AgentRel::GithubReleaseCreate => "github.release.create",
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
            AgentRel::GithubIssueRead => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "gh", "issue", "view", "--"],
                Safety::BoundedExecution,
                true,
                "Read a GitHub issue through a leased credential",
            ),
            AgentRel::GithubIssueCreate => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "gh", "issue", "create", "--"],
                Safety::BoundedExecution,
                true,
                "Create a GitHub issue through a leased credential",
            ),
            AgentRel::GithubReleaseCreate => AgentLink::new(
                self.uri(),
                self.operation(),
                &["run", "--", "gh", "release", "create", "--"],
                Safety::BoundedExecution,
                true,
                "Create a GitHub release through a leased credential",
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
        }
    }

    /// The relations this build actually publishes.
    ///
    /// This is a subset of the enum on purpose, and the subset is the claim.
    /// `06-CLI-CONTRACT.md` §5 names six core relations; DX2 completes all six
    /// by shipping `asv capabilities`. The other eight are withheld for the
    /// reasons in their variant comments.
    ///
    /// A relation is in this list only if the command behind it parses. That
    /// is not a convention: `every_operational_relation_parses_as_a_real_command`
    /// runs the actual parser, and it is what caught `status --json` being
    /// advertised by a CLI that had no such flag.
    pub fn operational() -> &'static [AgentRel] {
        &[
            AgentRel::Status,
            AgentRel::Doctor,
            AgentRel::Setup,
            AgentRel::Capabilities,
            AgentRel::CredentialList,
            AgentRel::SessionRun,
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
            vec![AgentRel::Doctor, AgentRel::Setup]
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
    /// A relation that ends at `--` is a *template*: the consumer supplies
    /// what goes after it. The parser needs something there, so this supplies
    /// a placeholder, and the distinction is recorded rather than papered over
    /// — a link whose argv does not parse on its own is not broken, it is
    /// waiting, and the test says which it found.
    fn argv_of(link: &AgentLink) -> Vec<&str> {
        let mut argv: Vec<&str> = std::iter::once(link.invoke.program.as_str())
            .chain(link.invoke.argv.iter().map(String::as_str))
            .collect();
        if link.invoke.argv.last().map(String::as_str) == Some("--") {
            argv.push("echo");
        }
        argv
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
    /// silent break for anything that stored the old string. Pinned against
    /// the five DX1 implements out of the six in `06-CLI-CONTRACT.md` §5.
    ///
    /// All six core relations from `06-CLI-CONTRACT.md` §5, spelled as the
    /// contract spells them. DX1 held `capabilities` back because the command
    /// did not exist; this is the moment it does, and the list is complete for
    /// the first time.
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
                "asv://rels/credentials/list",
                "asv://rels/session/run",
            ]
        );
    }

    /// A stopped broker publishes only the two links that lead somewhere.
    ///
    /// The failure this closes: publishing `credentials/list` into an
    /// installation whose broker is down. The agent follows it, gets
    /// `ASV_CONNECTION_FAILED`, and has learned that the discovery document
    /// describes commands rather than the installation.
    #[test]
    fn a_stopped_broker_publishes_only_the_links_that_reach_something() {
        let published = AgentRel::publishable_for(false);
        let uris: Vec<&str> = published.iter().map(|r| r.uri()).collect();
        assert_eq!(uris, ["asv://rels/doctor", "asv://rels/setup"]);

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
