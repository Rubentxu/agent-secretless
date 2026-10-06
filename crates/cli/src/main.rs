//! `asv` — unprivileged CLI (ADR-0002).
//!
//! M0 ships only the two skeleton commands the roadmap names: `status` and the
//! session launcher skeleton. `credential add` and friends are deliberately
//! absent, because a CLI secret-ingestion command is a place where a value
//! could be passed as `argv` and leak into shell history — exactly what
//! `docs/04-SHELL-FIRST-INTEGRATION.md` §9 forbids. M1 adds no-echo ingestion.

use asv_domain::{CredentialId, CredentialKind};
use asv_ipc_protocol::{OpaqueSecret, Request, Response, PROTOCOL_VERSION};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub mod agent;
#[path = "capabilities/mod.rs"]
pub mod capabilities;
pub mod doctor;
pub mod installrecord;
pub mod ipc;
pub mod layout;
pub mod render;
pub mod session_shim;
pub mod setup;
pub mod vaultops;

#[cfg(test)]
mod tests_support;

#[derive(Parser)]
#[command(
    name = "asv",
    version,
    about = "Local credential control plane for AI agents"
)]
struct Cli {
    /// Path to the broker socket.
    #[arg(long, env = "ASV_SOCKET", global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show broker connectivity and protocol version.
    Status {
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Create a bounded session in a workspace. M2 turns this into `asv run`.
    Session {
        /// Workspace path this session is scoped to.
        #[arg(long)]
        workspace: String,
    },
    /// Launch a command in a strict ASV session with a broker-owned SSH signer.
    Run {
        /// Command and arguments after `--`.
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run a registered compatibility worker under the M10 isolation
    /// pipeline (ADR-0008).
    ///
    /// This is the *weaker* of the two ways to run a tool holding a
    /// credential. `asv run` never gives the child the secret — it gets a
    /// surrogate and the broker substitutes at the destination — and that is
    /// the strong path. This verb exists for a legacy tool that cannot use a
    /// surrogate, and it hands the child a real credential inside a sandbox.
    /// The posture is named on every run because a caller that has to ask
    /// which path it is on will assume the strong one.
    RunIsolated {
        /// The registered worker name, as declared in the broker's worker file.
        worker: String,
        /// Arguments appended to the template's own, after `--`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Credential to inject, by id. A *reference*: the broker resolves it,
        /// so no secret is ever an argument to this process.
        #[arg(long)]
        credential: Option<String>,
        /// Requested lifetime in milliseconds. Can only shorten the runtime's
        /// own cap, never raise it.
        #[arg(long)]
        timeout_ms: Option<u64>,
    },
    /// GitHub operations through a broker-leased credential (M11, R2.A).
    ///
    /// The credential named by `--credential` is a **vault id**, not a token.
    /// This process never holds the token: it asks the broker for a one-use
    /// surrogate, hands that to the broker, and the broker lends the real
    /// secret to the HTTP header for the length of one request. There is no
    /// code path in which a GitHub token is in this process's memory, its
    /// `argv`, its environment, or anything it prints.
    ///
    /// This is the *strong* path, and it is the default one to reach for. The
    /// weaker alternative — running `gh` as a child with a token in its
    /// environment — is never offered here, because offering both and calling
    /// them equivalent is how a credential ends up in a process the operator
    /// does not know is holding it.
    Github {
        #[command(subcommand)]
        command: GithubCommand,
    },
    /// Act as an AWS role, without ever holding a credential.
    Aws {
        #[command(subcommand)]
        command: AwsCommand,
    },
    /// Act as a registered OAuth2 client, without ever holding a credential.
    ///
    /// The provider the broker trades a *client secret* for a *short-lived
    /// token*, which is the shape GitHub and AWS do not have: neither of those
    /// mints anything for the agent here, and this one does.
    Oauth2 {
        #[command(subcommand)]
        command: Oauth2Command,
    },
    /// Read from a declared OCI registry, without ever holding a credential.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// List credential metadata. Never values.
    Credentials {
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Bring this installation to a working state. Safe to run repeatedly.
    ///
    /// Creates the runtime directories, an empty vault and a passphrase the
    /// first time, installs the systemd user unit, and starts the broker.
    /// Running it again verifies the existing installation and changes
    /// nothing: an existing vault and an existing passphrase are never
    /// rewritten, because the passphrase is the only key to a credential
    /// store and a tool that "refreshes" it is a tool that can end one.
    Setup {
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Report what is installed, what is running, and what to fix. Never a
    /// single `healthy` boolean: every fact is its own check with its own
    /// remedy, and the overall status is derived from them.
    Doctor {
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// What this installation can do, derived from the running broker.
    Capabilities {
        /// Emit the `asv.agent/v1` envelope instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// The agent-facing surface. One command is enough to start.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Plant a credential in the broker's vault (ADR-0016).
    ///
    /// The secret is read from **stdin**, never from argv and never from the
    /// environment. Both are readable by any same-uid peer through
    /// `/proc/<pid>/cmdline` and `/proc/<pid>/environ`, which is a kernel
    /// property this product does not claim to control — and a design that
    /// depended on env secrecy would contradict the claim the adversarial
    /// harness exists to check. stdin is neither.
    AddCredential {
        /// Human label for the credential.
        #[arg(long)]
        label: String,
        /// Credential kind (`bearer_token`, `username_password`,
        /// `ssh_private_key`, `database_credential`, `generic_secret`).
        #[arg(long, value_name = "KIND")]
        kind: String,
        /// Provider the credential belongs to, e.g. `github`.
        #[arg(long)]
        provider: String,
        /// Account the credential belongs to.
        #[arg(long)]
        account: String,
    },
    /// Revoke a credential: remove it from the vault and drop every surrogate
    /// standing for it.
    ///
    /// Carries no secret, so there is none to read from stdin — the id is the
    /// whole of the request. It still goes through the same control-plane door
    /// as `add-credential`: this is the operator giving up access, and no agent
    /// session may do it.
    DeleteCredential {
        /// The credential id, in the canonical spelling `asv credentials` prints.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Query the broker's audit log (R9). Denied until the operator control
    /// plane ships; the command reports that refusal honestly.
    Audit {
        /// Only records newer than this duration (e.g. `24h`, `30m`).
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
    },
    /// Credential workflow adapters (R3). What a tool's configuration declares,
    /// read without reading its secrets.
    Integrations {
        #[command(subcommand)]
        command: IntegrationsCommand,
    },
}

#[derive(Subcommand)]
enum IntegrationsCommand {
    /// Run one `discover → intent → plan → authorize → execute` attempt, R4.B.1.
    ///
    /// The whole point of R4 is that authority binds to an *operation*, not to
    /// a session. This is the stage where that becomes visible: every step
    /// takes the previous one's output, and the last one refuses if anything
    /// moved. The receipt it writes is the evidence, and it names both what
    /// was promised and what was found.
    ///
    /// Authorization goes to the **broker** over IPC, not to a policy engine in
    /// this process. A second evaluator is a second authority, which is the
    /// failure this project exists to prevent.
    Execute {
        /// The tool family. `npm` or `curl`.
        #[arg(long, value_name = "FAMILY", default_value = "npm")]
        family: String,
        /// Emit the `asv.integrations.execute/v1` receipt instead of prose.
        #[arg(long)]
        json: bool,
        /// The executable to resolve and bind the plan to. A bare name is
        /// looked up on `PATH`; a path is used as given.
        #[arg(long, value_name = "COMMAND", default_value = "npm")]
        tool: String,
        /// Correlates every record this attempt produces.
        #[arg(long, value_name = "ID")]
        transaction: String,
        /// Whoever is accountable for it.
        #[arg(long, value_name = "WHO")]
        principal: String,
        /// The agent acting, as opposed to the principal behind it.
        #[arg(long, value_name = "WHO", default_value = "cli")]
        actor: String,
        /// Where the instruction came from. Two of these are
        /// attacker-influenced by construction, and a policy can single them
        /// out without guessing from the request body.
        #[arg(long, value_name = "ORIGIN", default_value = "human_direct")]
        origin: String,
        /// Seconds from now until the intent expires. An intent with no
        /// deadline is a session wearing a different hat.
        #[arg(long, value_name = "SECONDS", default_value_t = 300)]
        ttl: u64,
        /// A session another process opened.
        ///
        /// **Almost never what you want, and the reason is structural rather
        /// than a policy choice.** The broker records the PID that opened a
        /// session and refuses to evaluate an authorization request from any
        /// other PID, so a session id typed here by an operator can never
        /// authorize the very command carrying it. Left out — the default — this
        /// command opens its own session, which is what every other verb that
        /// reaches the broker already does.
        ///
        /// The flag is for the caller that genuinely has one: a worker launched
        /// inside `asv run` under an already-open session.
        #[arg(long, value_name = "UUID")]
        session: Option<String>,
        /// The workspace the authorization is scoped to.
        #[arg(long, value_name = "DIR")]
        workspace: String,
        /// Directory holding the project-level configuration.
        #[arg(long, value_name = "DIR", default_value = ".")]
        cwd: String,
        /// Home directory holding the user-level configuration.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Follow a configuration symlink whose target resolves inside this
        /// directory. Refused by default, for the reason `discover` refuses.
        #[arg(long, value_name = "DIR")]
        allow_symlink_root: Option<String>,
        /// Do not ask the broker what credentials exist, and plan against an
        /// empty inventory.
        ///
        /// **The receipt then says so.** A plan built on "we did not ask" would
        /// be a plan about an invented inventory, and an execution authorized
        /// over one would look identical to an execution that had asked and
        /// found nothing. Same flag and same meaning as `plan`'s, deliberately:
        /// an operator who learned it in one place learned it in both.
        #[arg(long)]
        no_vault: bool,
    },
    /// Describe what a tool's configuration file declares — R3's first stage.
    ///
    /// Reads the configuration and prints what it says: which registries, which
    /// scopes, which auth selectors, and a fingerprint of each file. **The
    /// report contains no credential**, and that is a property of the report's
    /// types rather than a filter applied on the way out — there is nowhere in
    /// them to put one. An auth selector is reported as its field, its
    /// registry and the *length* of its value.
    ///
    /// This reads the filesystem and nothing else. It does not open a session
    /// and does not reach the vault, because a step that could read a secret
    /// would be a step that could be made to.
    Discover {
        /// The tool family. `npm` today; the list grows by adding an adapter.
        #[arg(long, value_name = "FAMILY", default_value = "npm")]
        family: String,
        /// Emit the `asv.discovery/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
        /// Directory holding the project-level configuration.
        #[arg(long, value_name = "DIR", default_value = ".")]
        cwd: String,
        /// Home directory holding the user- and global-level configuration.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Follow a configuration symlink whose target resolves inside this
        /// directory. Refused by default, and naming the root is the decision
        /// the default refuses to make on the operator's behalf.
        #[arg(long, value_name = "DIR")]
        allow_symlink_root: Option<String>,
    },

    /// Say what could be done about each credential the tool is configured to
    /// use — R3's second stage.
    ///
    /// Reads the same configuration `discover` reads, asks the broker what
    /// credentials exist, and for every auth selector it found reports the
    /// strategies available for it **strongest posture first**. A posture ASV
    /// cannot deliver is not offered: a non-exportable credential is never
    /// offered `raw_process_exposure`, because there is no way to write its
    /// value into a file for the tool.
    ///
    /// The report names credential, audience and operations together, because a
    /// binding recorded as `npm-token` is the thing this step exists to stop.
    ///
    /// **This reads the broker's credential *inventory* — labels, kinds and
    /// exportability — and nothing else.** It never receives a secret, and the
    /// plan's types have nowhere to put one.
    Plan {
        /// The tool family to plan for.
        ///
        /// **Positional and required, unlike `discover`'s `--family`.**
        /// `discover` describes whatever is on disk, so defaulting it to `npm`
        /// is a harmless convenience. `plan` computes bindings for one family,
        /// and defaulting it would be a silent choice of *whose* credentials
        /// this invocation is about — which is exactly the decision §7 says must
        /// be named rather than inferred.
        #[arg(value_name = "FAMILY")]
        family: String,
        /// Emit the `asv.integrations.plan/v2` envelope instead of prose.
        #[arg(long)]
        json: bool,
        /// Directory holding the project-level configuration.
        #[arg(long, value_name = "DIR", default_value = ".")]
        cwd: String,
        /// Home directory holding the user- and global-level configuration.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Follow a configuration symlink whose target resolves inside this
        /// directory. Refused by default, for the reason `discover` refuses it.
        #[arg(long, value_name = "DIR")]
        allow_symlink_root: Option<String>,
        /// Plan against an empty inventory instead of asking the broker.
        ///
        /// The answer it produces is the first-run answer — *these are the
        /// credentials you would need to adopt* — and it is a real plan rather
        /// than a degraded one. It also makes this command runnable with no
        /// broker up, which is how an operator finds out what to adopt before
        /// deciding to adopt anything.
        #[arg(long)]
        no_vault: bool,
    },

    /// Move a credential out of a tool's configuration and into the vault —
    /// R3's third stage, and the first one that moves a secret.
    ///
    /// Reads the value of one named selector, hands it straight to the broker,
    /// and prints a receipt naming the credential, the audience and the
    /// operations. **It does not touch the file.** Doc 04 §10 puts a vault
    /// verification, an integration verification, a negative bypass test and a
    /// human approval between an import and a scrub, and none of those happen
    /// here — the receipt lists them as outstanding so that an import is never
    /// mistaken for a completed migration.
    ///
    /// Every refusal is a control: a configuration that changed since the plan,
    /// a `${VAR}` reference with no value in the file to move, an empty value,
    /// a misspelled field, a field set twice for one registry, and an ambiguous
    /// binding all stop the import rather than producing something that looks
    /// like a credential.
    Adopt {
        /// The tool family.
        #[arg(value_name = "FAMILY")]
        family: String,
        /// Emit the `asv.integrations.adopt/v1` receipt instead of prose.
        #[arg(long)]
        json: bool,
        /// The file holding the credential. Defaults to the user-level
        /// configuration; the plan's receipt names the file it used.
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
        /// Home directory, used to find the default file.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// The registry the selector addresses, canonicalised.
        #[arg(long, value_name = "AUDIENCE")]
        audience: String,
        /// npm's field name for the selector, e.g. `_authToken`.
        #[arg(long, value_name = "FIELD")]
        field: String,
        /// The label to store the credential under.
        #[arg(long, value_name = "LABEL")]
        label: String,
        /// Follow a configuration symlink whose target resolves inside this
        /// directory. Refused by default, for the reason `discover` refuses it.
        #[arg(long, value_name = "DIR")]
        allow_symlink_root: Option<String>,
        /// The `asv integrations plan npm --json` output this import answers.
        ///
        /// **Without it the drift check cannot fail.** `adopt` would fingerprint
        /// the file itself and compare the result against itself, which detects
        /// a change during the command and nothing else — so a credential moved
        /// from bytes that changed since the operator planned would import
        /// without complaint. Passing the plan makes §6 real: the fingerprint
        /// comes from the plan, and a file that has moved since is refused.
        #[arg(long, value_name = "PATH")]
        from_plan: Option<String>,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// The whole agent-facing surface: what this is, whether the broker is
    /// up, what it can do, and the links to follow. Takes no arguments and
    /// needs no prior knowledge — that is the point of it.
    Discover {
        /// Emit the `asv.agent/v1` envelope. The default for a machine reader
        /// and required by the contract; the flag exists so the human and
        /// machine forms are the same command rather than two commands.
        #[arg(long)]
        json: bool,
    },
}

/// The GitHub verbs, grouped by the noun they act on.
///
/// Two levels rather than one flat list, so the noun in the published relation
/// URI (`github/issue/read`, `github/release/create`) is the noun on the
/// command line. A flat `asv github issue-view` would have been shorter to
/// write and would have decoupled the two vocabularies.
#[derive(Subcommand)]
enum GithubCommand {
    /// Act on an issue.
    #[command(subcommand)]
    Issue(GithubIssueCommand),
    /// Act on a release.
    #[command(subcommand)]
    Release(GithubReleaseCommand),
}

/// The AWS verbs.
///
/// **There is no `--role`, no `--region` and no `--audience`**, and their
/// absence is the design rather than a gap. Those three come from the
/// deployment the operator configured, because SigV4 signs the host: a caller
/// that could name the destination could have the broker sign a call for one
/// place and send it somewhere else, and the signature would be the only thing
/// in the request that disagreed with where it went.
#[derive(Subcommand)]
enum AwsCommand {
    /// Report which AWS identity the broker would act as.
    ///
    /// Answers the question an agent has to be able to ask before it does
    /// anything else, and the question an auditor asks afterwards. Nothing
    /// printed here is a credential: the ARN, the user id and the account are
    /// all things AWS itself records in CloudTrail.
    Whoami {
        /// Vault id of the long-lived AWS credential, as `asv credentials`
        /// prints it. A *reference*: the broker resolves it, and neither the
        /// secret access key nor the session token ever reaches this process.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}

/// `asv registry` — reading an OCI registry through the broker.
///
/// **Two nouns because an OCI pull is two requests, and `--registry` is a
/// selector rather than a destination.** Everything the other providers lack is
/// missing here for the same reason: there is no `--domain`, no `--auth-url` and
/// no way to name where the token endpoint is. Those come from the deployment's
/// registry declarations, because a registry names its own authentication host
/// in its `401` and a caller that could name the token endpoint could have the
/// long credential sent to one of its own choosing.
///
/// `--credential` is **not** redundant with `--registry`, and that is the point.
/// The declaration already knows which credential serves the host, so the broker
/// could have looked it up. Making the caller name it is what keeps the
/// equality between "the credential this session was granted" and "the
/// credential this registry is served by" load-bearing: a derived credential
/// would make that comparison trivially true and turn the check into
/// decoration. Naming it is how a mismatch becomes a refusal the agent can act
/// on.
#[derive(Subcommand)]
enum RegistryCommand {
    /// Act on a manifest.
    #[command(subcommand)]
    Manifest(RegistryManifestCommand),
    /// Act on a blob.
    #[command(subcommand)]
    Blob(RegistryBlobCommand),
}

/// The manifest nouns.
#[derive(Subcommand)]
enum RegistryManifestCommand {
    /// Read a manifest. Writes the bytes and prints its content address.
    Read {
        /// Vault id of the credential the deployment lent this registry, as
        /// `asv credentials` prints it. A *reference*: the broker resolves it
        /// and refuses if it is not the credential this registry is served by.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Registry host, e.g. `registry-1.docker.io`. Selects a declaration;
        /// the broker dials the authority the declaration names.
        #[arg(long, value_name = "HOST")]
        registry: String,
        /// Repository path, e.g. `library/alpine`.
        #[arg(long, value_name = "NAME")]
        repository: String,
        /// Tag or digest to read, e.g. `latest`.
        #[arg(long, value_name = "REF")]
        reference: String,
        /// Write the manifest here instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Write a manifest. Prints the content address the registry stored.
    Push {
        /// Vault id of the credential the deployment lent this registry. A
        /// *reference*: the broker resolves it and refuses if it is not the
        /// credential this registry is served by. Mandatory for the same
        /// reason as on `read` — deriving it here would leave the surrogate
        /// with nothing to be compared against.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Registry host. Selects a declaration; never a destination.
        #[arg(long, value_name = "HOST")]
        registry: String,
        /// Repository path, e.g. `library/alpine`.
        #[arg(long, value_name = "NAME")]
        repository: String,
        /// Tag or digest to write. A tag is mutable: whatever it points at
        /// afterwards is the registry's answer, and this verb does not soften
        /// that. Write by digest when that is not what you mean.
        #[arg(long, value_name = "REF")]
        reference: String,
        /// The manifest to publish. Read verbatim; never re-serialised.
        #[arg(long, value_name = "PATH")]
        file: std::path::PathBuf,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}
/// The blob nouns.
#[derive(Subcommand)]
enum RegistryBlobCommand {
    /// Read a blob, verified against the digest it was asked for.
    Read {
        /// Vault id of the credential the deployment lent this registry. See
        /// `manifest read` for why this is not redundant with `--registry`.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Registry host. Selects a declaration; never a destination.
        #[arg(long, value_name = "HOST")]
        registry: String,
        /// Repository path, e.g. `library/alpine`.
        #[arg(long, value_name = "NAME")]
        repository: String,
        /// Content address to read, e.g. `sha256:…`. Only a digest: a tag
        /// names whatever the registry currently holds, and under a content
        /// address that is a claim about bytes nothing has checked.
        #[arg(long, value_name = "DIGEST")]
        digest: String,
        /// Write the blob here instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Write a blob. The content address is computed from the bytes, never asked
    /// for.
    Push {
        /// Vault id of the credential the deployment lent this registry. See
        /// `manifest read` for why this is a *reference* and not redundant with
        /// `--registry`.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Registry host. Selects a declaration; never a destination.
        #[arg(long, value_name = "HOST")]
        registry: String,
        /// Repository path, e.g. `library/alpine`.
        #[arg(long, value_name = "NAME")]
        repository: String,
        /// The blob to publish. Its content address is computed here from the
        /// bytes rather than taken from the operator: a `--digest` flag would
        /// be a claim about bytes nothing has checked, and the broker recomputes
        /// it anyway.
        #[arg(long, value_name = "PATH")]
        file: std::path::PathBuf,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}

/// `asv oauth2` — the second M11 provider, and the first one where the broker
/// trades one credential for another before doing anything.
///
/// **There is no `--scope`, no `--audience`, no `--resource` and no
/// `--token-url`**, and their absence is the same design as the three the AWS
/// verb lacks. All four come from the `--oauth2-clients` file the daemon was
/// started with: the scope in particular, because a scope this process could
/// name would be a scope the agent picked, and picking its own authority is the
/// escalation the whole broker is built to refuse.
#[derive(Subcommand)]
enum Oauth2Command {
    /// Report which derived OAuth2 identity the broker would act as.
    ///
    /// Asks the protected resource what token it actually accepted, and prints
    /// what it said. Nothing printed here is a credential: no access token, and
    /// no client secret — the secret never leaves the broker.
    ///
    /// The `scope` and `audience` printed are **verified against what the
    /// operator configured**, not relayed. If the identity provider granted more
    /// than `--oauth2-clients` declares, this command fails rather than reporting
    /// authority the operator did not ask for. An exit 1 here means the
    /// configuration and the provider have drifted apart, which is a thing to fix
    /// at the IdP.
    Whoami {
        /// Vault id of the OAuth2 client secret, as `asv credentials` prints it.
        /// A *reference*: the broker resolves it against the clients the daemon
        /// was configured with, and the client secret never reaches here.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GithubIssueCommand {
    /// Read one issue. Returns only its title, body and state.
    View {
        /// `owner/repo`, e.g. `Rubentxu/agent-secretless`.
        #[arg(long, value_name = "OWNER/REPO")]
        repo: String,
        /// The issue number.
        #[arg(long)]
        number: u64,
        /// Vault id of the GitHub credential, as `asv credentials` prints it.
        /// A *reference*: the broker resolves it, and the token itself never
        /// reaches this process.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Create one issue.
    Create {
        /// `owner/repo`, e.g. `Rubentxu/agent-secretless`.
        #[arg(long, value_name = "OWNER/REPO")]
        repo: String,
        /// The issue title. Titles are short and single-line by convention, so
        /// this one is an argument rather than a file.
        #[arg(long)]
        title: String,
        /// The issue body: a path, or `-` for stdin. Never a literal.
        ///
        /// A literal body would be an `argv` entry, and `argv` is readable by
        /// any same-uid peer through `/proc/<pid>/cmdline` — a kernel property
        /// this product does not claim to control. The body is also the field
        /// most likely to be long, and a release body is routinely a
        /// multi-paragraph changelog, so "it was too long for argv" would have
        /// been a reason that only applied sometimes.
        #[arg(long, value_name = "FILE")]
        body: String,
        /// Vault id of the GitHub credential. A *reference*, never the token.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GithubReleaseCommand {
    /// Create one release.
    Create {
        /// `owner/repo`, e.g. `Rubentxu/agent-secretless`.
        #[arg(long, value_name = "OWNER/REPO")]
        repo: String,
        /// The tag the release names.
        #[arg(long)]
        tag: String,
        /// The release's display name.
        #[arg(long)]
        name: String,
        /// The release notes: a path, or `-` for stdin. Never a literal.
        #[arg(long, value_name = "FILE")]
        body: String,
        /// Vault id of the GitHub credential. A *reference*, never the token.
        #[arg(long, value_name = "ID")]
        credential: String,
        /// Emit the `asv.agent/v1` envelope instead of prose.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let socket = cli.socket.clone().unwrap_or_else(default_socket);

    let command = match cli.command {
        // `run` opens a real session now (ADR-0019), so it needs the socket
        // the same as every other broker verb. It used to run entirely on
        // its own, which is why it could hand out a session id nothing
        // resolved.
        Command::Run { command } => return run_command(&socket, command),
        command => command,
    };

    // `setup` and `doctor` do not go through the broker. They run when the
    // broker is stopped, which is most of why they exist, and routing them
    // through a socket would mean the command that diagnoses a dead broker
    // dies with it.
    //
    // Matched by reference: the arms below consume `command`, and the rest of
    // `main` still needs it.
    match &command {
        Command::RunIsolated {
            worker,
            args,
            credential,
            timeout_ms,
        } => return run_isolated(&socket, worker, args, credential.as_deref(), *timeout_ms),
        // Like `run-isolated`, this is not one request. It is a session, a
        // mint, the operation and an end, and the CLI is the only party that
        // knows the id of the session it opened. Handled here so the lifetime
        // of that session is a lexical scope rather than something spread
        // across the single-request path below.
        Command::Github { command } => return run_github(&socket, command),
        Command::Aws { command } => return run_aws(&socket, command),
        Command::Oauth2 { command } => return run_oauth2(&socket, command),
        Command::Registry { command } => return run_registry_dispatch(&socket, command),
        // `plan` opens a session and `discover` does not, so the whole
        // subcommand tree is dispatched here rather than in the single-request
        // path below: the two halves differ in whether they have a reason to
        // reach the broker, and that difference belongs in one visible place.
        Command::Integrations { command } => return run_integrations(&socket, command),
        Command::Setup { json } => return run_setup(*json),
        Command::Doctor { json } => return run_doctor(&socket, *json),
        Command::Agent {
            command: AgentCommand::Discover { json },
        } => return run_discover(&socket, *json),
        _ => {}
    }

    // `status` and `credentials` are the two relations the CLI publishes that
    // also owe a machine rendering, so they go through the application-result
    // path: parse, call, result, render. The other broker commands still print
    // from `print_response` and pick up `--json` in DX2, which is when the
    // remaining tabular renderers have somewhere to be ported to.
    let json = match &command {
        Command::Status { json } | Command::Credentials { json } => *json,
        Command::Capabilities { json } => return run_capabilities(&socket, *json),
        _ => false,
    };

    let request = match command {
        Command::Status { .. } => Request::Ping {
            protocol: PROTOCOL_VERSION,
        },
        Command::Session { workspace } => Request::CreateSession { workspace },
        Command::Credentials { .. } => Request::ListCredentialMetadata,
        Command::AddCredential {
            label,
            kind,
            provider,
            account,
        } => {
            let kind = match parse_credential_kind(&kind) {
                Some(kind) => kind,
                None => {
                    eprintln!("asv: unknown credential kind {kind:?}");
                    std::process::exit(2);
                }
            };
            // Read before connecting, so a secret is never sitting in a
            // request while the socket is unavailable. A trailing newline is
            // the one byte stripped, because `echo secret |` is the obvious
            // way to use this and a stored trailing newline would be a
            // credential that silently never works.
            //
            // **One buffer, and it is zeroized.** The first version read into a
            // plain `String` and then made a second one:
            //
            // ```text
            // let secret = String::new();
            // let secret = secret.strip_suffix('\n').unwrap_or(&secret).to_string();
            // ```
            //
            // The `to_string()` copies, the original is shadowed, and neither
            // is zeroized — so the trailing-newline case, which is the *common*
            // one because `echo secret |` is the obvious invocation, left two
            // freed heap buffers holding the credential. `strip_suffix` cannot
            // truncate in place through an immutable borrow, which is what
            // pushed the first version toward copying rather than toward
            // `Zeroizing`.
            //
            // `Zeroizing<String>` gives both: `pop()` truncates in place, and
            // the final `mem::take` hands the one allocation to `OpaqueSecret`,
            // which already zeroizes it. Nothing is ever duplicated, so there
            // is no second copy for this to have missed.
            let mut secret = {
                let mut stdin = std::io::stdin().lock();
                match read_credential(&mut stdin) {
                    Ok(secret) => secret,
                    Err(error) => {
                        eprintln!("asv: cannot read the secret from stdin: {error}");
                        std::process::exit(2);
                    }
                }
            };
            if secret.expose().is_empty() {
                eprintln!("asv: no secret on stdin");
                std::process::exit(2);
            }
            Request::CreateCredential {
                label,
                kind,
                provider,
                account,
                // Moves the allocation rather than copying it. The `Zeroizing`
                // is left holding an empty `String`, whose drop is a no-op, and
                // the bytes end up owned by the type that was already written
                // to zeroize them.
                secret: std::mem::replace(&mut secret, OpaqueSecret::new(Vec::new())),
            }
        }
        Command::DeleteCredential { id } => {
            // Parsed rather than passed through: the broker keys the vault by
            // the canonical wire spelling, so a id that is merely a valid UUID
            // in some other spelling would be accepted here and then miss in
            // the vault, and the operator would be told the credential does not
            // exist. Failing here names the real problem.
            //
            // The error is input-free by construction (`CredentialId`'s parse
            // error carries no text), so nothing the operator typed comes back
            // out through a diagnostic.
            match CredentialId::from_wire(&id) {
                Ok(id) => Request::DeleteCredential { id },
                Err(_) => {
                    eprintln!("asv: {id:?} is not a credential id; copy it from `asv credentials`");
                    std::process::exit(2);
                }
            }
        }
        Command::Audit { since } => {
            let since_secs = match since.as_deref() {
                None => 0,
                Some(spec) => parse_duration_secs(spec).unwrap_or_else(|| {
                    eprintln!("asv: cannot parse duration {spec:?} (try 24h, 30m, 90s)");
                    std::process::exit(2);
                }),
            };
            Request::AuditQuery { since_secs }
        }
        Command::Run { .. } => unreachable!("run handled before broker IPC"),
        Command::RunIsolated { .. } => {
            unreachable!("run-isolated opens its own session and is handled before broker IPC")
        }
        Command::Github { .. } => {
            unreachable!("github opens its own session and is handled before broker IPC")
        }
        Command::Aws { .. } => {
            unreachable!("aws opens its own session and is handled before broker IPC")
        }
        Command::Oauth2 { .. } => {
            unreachable!("oauth2 opens its own session and is handled before broker IPC")
        }
        Command::Registry { .. } => {
            unreachable!("registry opens its own session and is handled before broker IPC")
        }
        // `integrations discover` reads the filesystem and is handled above.
        // It is listed here rather than left to `_` so that the next command
        // someone adds gets a compile error telling them to decide, instead of
        // silently inheriting this arm.
        Command::Setup { .. }
        | Command::Doctor { .. }
        | Command::Capabilities { .. }
        | Command::Agent { .. }
        | Command::Integrations { .. } => {
            unreachable!("these are handled before broker IPC")
        }
    };

    match call(&socket, &request) {
        Ok(response) if json => {
            let result = ipc::from_response(&response);
            println!(
                "{}",
                render::json::envelope(&render::json::for_result(&result))
            );
            if result.is_refusal() {
                std::process::exit(1);
            }
        }
        Ok(response) => print_response(&response),
        Err(e) => {
            // Errors are actionable but never echo request payloads, which is
            // how a workspace path containing a token would otherwise leak.
            eprintln!("ASV_CONNECTION_FAILED: {e}");
            std::process::exit(2);
        }
    }
    Ok(())
}

/// The product version, from the crate metadata.
///
/// One function so that the envelope, `doctor` and the human renderers cannot
/// disagree about it. `env!("CARGO_PKG_VERSION")` at each call site would
/// work today and would be wrong the day one of them wanted a git describe.
pub fn build_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Dials the broker and reports what answered.
///
/// A connection failure is not an error here. It is the single most common
/// state a user is in when they run `doctor` — the service is stopped — and
/// turning it into an `io::Error` would make the one command that exists to
/// describe that state be the command that cannot run in it.
pub fn observe_broker_socket() -> doctor::SocketOutcome {
    observe_broker_socket_at(&default_socket())
}

/// The same, against an explicit socket, so a test can point it at a broker
/// that answers whatever the test needs it to.
pub fn observe_broker_at(socket: &std::path::Path) -> doctor::SocketOutcome {
    observe_broker_socket_at(socket)
}

/// The same, against an explicit socket.
pub fn observe_broker_socket_at(socket: &std::path::Path) -> doctor::SocketOutcome {
    let request = Request::Ping {
        protocol: PROTOCOL_VERSION,
    };
    match call(socket, &request) {
        Ok(Response::Pong { protocol }) => doctor::SocketOutcome::Answered { protocol },
        Ok(other) => doctor::SocketOutcome::Unexpected {
            // The variant name only. A `Display` of the response could carry
            // request-derived data, and `doctor` output is the most-copied
            // output this CLI produces.
            detail: format!("a {} answered instead", response_kind(&other)),
        },
        Err(e) => doctor::SocketOutcome::Unreachable {
            reason: format!("no answer at {}: {}", socket.display(), e),
        },
    }
}

pub fn response_kind(response: &Response) -> &'static str {
    match response {
        Response::IsolatedResult { .. } => "IsolatedResult",
        Response::Pong { .. } => "Pong",
        Response::BrokerInfo { .. } => "BrokerInfo",
        Response::SessionCreated { .. } => "SessionCreated",
        Response::SessionEnded { .. } => "SessionEnded",
        Response::SessionKeyRegistered { .. } => "SessionKeyRegistered",
        Response::CredentialMetadata { .. } => "CredentialMetadata",
        Response::CredentialDeleted { .. } => "CredentialDeleted",
        Response::CredentialCreated { .. } => "CredentialCreated",
        Response::Authorization { .. } => "Authorization",
        Response::ApprovalIssued { .. } => "ApprovalIssued",
        Response::SurrogateMinted { .. } => "SurrogateMinted",
        Response::SurrogateRevoked { .. } => "SurrogateRevoked",
        Response::IssueRead { .. } => "IssueRead",
        Response::IssueCreated { .. } => "IssueCreated",
        Response::ReleaseCreated { .. } => "ReleaseCreated",
        Response::AwsCallerIdentity { .. } => "AwsCallerIdentity",
        Response::OAuth2Identity { .. } => "OAuth2Identity",
        Response::AuditRecords { .. } => "AuditRecords",
        Response::PostgresConnected { .. } => "PostgresConnected",
        Response::PostgresResult { .. } => "PostgresResult",
        Response::PostgresRevoked { .. } => "PostgresRevoked",
        // R2.F.3b (the other session's in-flight work). Added here because
        // this match is exhaustive **on purpose** -- its own comment says an
        // unhandled response must be a compile error -- so a new variant
        // obliges a name rather than permitting a blank line. Two mechanical
        // arms, not a review of the feature they belong to.
        Response::ManifestRead { .. } => "ManifestRead",
        Response::BlobRead { .. } => "BlobRead",
        Response::ManifestPushed { .. } => "ManifestPushed",
        Response::BlobPushed { .. } => "BlobPushed",
        Response::Error { .. } => "Error",
    }
}

fn run_doctor(socket: &std::path::Path, json: bool) -> std::io::Result<()> {
    let mut layout = layout::for_current_user();

    // `--socket` overrides where the broker is looked for, and only that.
    // The rest of the layout is the installation's own, so pointing the
    // command at a different broker does not silently re-point it at a
    // different vault.
    if socket != default_socket() {
        layout.socket_override = Some(socket.to_path_buf());
    }

    let observation = doctor::Observation::gather(&layout);
    let report = doctor::DoctorReport::judge(observation);

    if json {
        println!("{}", render::json::envelope(&report.to_envelope()));
    } else {
        print!("{}", render::human::doctor(&report));
    }

    // A blocked installation exits non-zero so a script can branch on it.
    // Degraded exits zero: it is usable, and a setup script that treats a
    // missing Landlock as a failure will be disabled by its users.
    if report.status() == agent::schema::Status::Blocked {
        std::process::exit(1);
    }
    Ok(())
}

/// `asv agent discover`, the entry point an agent is given.
///
/// The installation state is judged from the layout rather than asked about,
/// because the question it answers is "is there anything to discover" and a
/// command that needs a broker to answer "is the broker up" has already
/// failed.
fn run_discover(socket: &std::path::Path, json: bool) -> std::io::Result<()> {
    let layout = layout::for_current_user();
    let installation_ready = layout.vault.exists() && layout.broker_lookup.is_found();
    let discovery = agent::discover::discover(socket, installation_ready);

    if json {
        println!("{}", render::json::envelope(&discovery.to_envelope()));
    } else {
        print!("{}", discovery.render_human());
    }

    // `blocked` and `error` both exit non-zero so a script can branch; the
    // difference is in the `code`, not in the exit status, because an agent
    // that treated them as the same thing would report "not ready" for a
    // version mismatch, which is a different problem with a different fix.
    if matches!(
        discovery.status,
        agent::schema::Status::Blocked | agent::schema::Status::Error
    ) {
        std::process::exit(1);
    }
    Ok(())
}

fn run_capabilities(socket: &std::path::Path, json: bool) -> std::io::Result<()> {
    let outcome = observe_broker_at(socket);
    let (facts, reachable) = match outcome {
        doctor::SocketOutcome::Answered { .. } => (ipc::fetch_broker_facts(socket), true),
        _ => (None, false),
    };
    let compatible = facts
        .as_ref()
        .map(|f| f.protocol == PROTOCOL_VERSION)
        .unwrap_or(false);

    let report = capabilities::CapabilityReport::from_broker(facts.as_ref(), reachable, compatible);

    if json {
        println!("{}", render::json::envelope(&report.to_envelope()));
    } else {
        print!("{}", report.render_human());
    }
    if matches!(
        report.status(),
        agent::schema::Status::Blocked | agent::schema::Status::Error
    ) {
        std::process::exit(1);
    }
    Ok(())
}

fn run_setup(json: bool) -> std::io::Result<()> {
    let layout = layout::for_current_user();
    let outcome = setup::run(&layout)?;

    let status = if outcome.is_blocked() {
        agent::schema::Status::Blocked
    } else if !outcome.warning_codes.is_empty() {
        agent::schema::Status::Degraded
    } else {
        agent::schema::Status::Ready
    };

    if json {
        let data = serde_json::json!({
            "created_dirs": outcome.created_dirs,
            "created_vault": outcome.created_vault,
            "created_passphrase": outcome.created_passphrase,
            "installed_unit": outcome.installed_unit,
            "vault_verified": outcome.vault_verified,
            "service_started": outcome.service_started,
            "notes": outcome.notes,
        });
        let mut envelope = agent::schema::Envelope::new(status, data);
        for code in &outcome.warning_codes {
            // The code is the contract; the human text lives in `notes`, which
            // both renderings carry, so the warning message is not duplicated
            // into a second place that could drift.
            envelope = envelope.with_warning(code, "");
        }
        if let Some(blocked) = &outcome.blocked {
            envelope.error = Some(agent::schema::AgentError {
                code: blocked.code.clone(),
                message: blocked.message.clone(),
            });
        }
        for rel in agent::relations::AgentRel::publishable_for(!outcome.is_blocked()) {
            envelope = envelope.with_link(rel.descriptor());
        }
        println!("{}", render::json::envelope(&envelope));
    } else {
        for line in &outcome.notes {
            println!("{line}");
        }
        if let Some(blocked) = &outcome.blocked {
            eprintln!();
            eprintln!("asv setup did not finish: {}", blocked.code);
            eprintln!("  {}", blocked.message);
            eprintln!("  next: {}", blocked.remedy);
        }
    }

    if outcome.is_blocked() {
        std::process::exit(1);
    }
    Ok(())
}

/// Where to dial the broker when `--socket` is not given.
///
/// Derived from the running user, and preferring `XDG_RUNTIME_DIR` when the
/// session set one, so a user on a non-default runtime directory finds the
/// broker without reading a manual. The rule itself lives in
/// `asv_ipc_protocol::socket`, which the broker also calls: this function only
/// supplies the override, because the CLI is deliberately exempt from the
/// environment quarantine in `uat_017_env_scan.rs` (`asv run` has to read the
/// environment in order to scrub it) while the broker is not.
///
/// The literal that used to live here was `/run/user/1000/...`, which resolved
/// only for the account that wrote it.
fn default_socket() -> PathBuf {
    asv_ipc_protocol::socket::resolve_socket_path(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        unsafe { libc::getuid() },
    )
}

/// Parses `90s`, `30m`, `24h`, `7d` into seconds. None on garbage.
/// The domain's credential kinds, by their wire spelling.
///
/// Written out rather than derived from the enum because the CLI is where a
/// human types, and a human needs the list of what they may type. The four
/// kinds the vault cannot represent are accepted here and refused by the
/// broker, which is where that knowledge belongs; the CLI does not keep a
/// second copy of which ones those are.
fn parse_credential_kind(text: &str) -> Option<CredentialKind> {
    Some(match text {
        "api_key" => CredentialKind::ApiKey,
        "bearer_token" => CredentialKind::BearerToken,
        "oauth2" => CredentialKind::OAuth2,
        "username_password" => CredentialKind::UsernamePassword,
        "ssh_private_key" => CredentialKind::SshPrivateKey,
        "x509_client_identity" => CredentialKind::X509ClientIdentity,
        "aws_access_key" => CredentialKind::AwsAccessKey,
        "database_credential" => CredentialKind::DatabaseCredential,
        "generic_secret" => CredentialKind::GenericSecret,
        _ => return None,
    })
}

fn parse_duration_secs(spec: &str) -> Option<u64> {
    let spec = spec.trim();
    let (digits, unit) = spec.split_at(spec.len().checked_sub(1)?);
    let n: u64 = digits.parse().ok()?;
    match unit {
        "s" => Some(n),
        "m" => Some(n.checked_mul(60)?),
        "h" => Some(n.checked_mul(3600)?),
        "d" => Some(n.checked_mul(86400)?),
        _ => None,
    }
}

const QUARANTINED_ENV_NAMES: &[&str] = &[
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
];

/// Start this session's shim, if the broker is serving a CONNECT listener.
///
/// `None` is a legitimate answer and not a failure: the CONNECT listener is
/// opt-in (`--connect-listen`), so a broker without one has no address to
/// publish and there is nothing for a shim to forward to. Starting a shim
/// anyway would give the child a proxy that answers `502` for every request,
/// which looks like a broken network rather than an absent feature — so the
/// child is launched with no proxy variables at all, and `asv doctor` is how an
/// operator finds out why.
///
/// The address comes from the broker rather than from a flag on this side. Two
/// sources of truth for "where the CONNECT listener is" can disagree, and the
/// disagreement is silent: the shim would forward every CONNECT somewhere that
/// is not a broker and the session would simply never tunnel.
fn start_session_shim(
    socket: &std::path::Path,
    agent: &asv_ssh_agent::AgentSession,
) -> Option<crate::session_shim::ShimHandle> {
    let facts = crate::ipc::fetch_broker_facts(socket)?;
    let address = facts.connect_listen?;

    let parsed: std::net::SocketAddr = address.parse().ok().or_else(|| {
        eprintln!("asv: the broker reports a CONNECT address it cannot bind: {address:?}");
        None
    })?;

    let client = asv_ssh_agent::AgentClient::new(agent.socket_path());
    let issuer = match asv_ssh_agent::ProofIssuer::discover(client) {
        Ok(issuer) => issuer,
        Err(e) => {
            eprintln!("asv: this session's agent refused to issue proofs: {e}");
            return None;
        }
    };

    match crate::session_shim::SessionShim::bind(issuer, parsed) {
        Ok(shim) => match shim.spawn() {
            Ok(handle) => Some(handle),
            Err(e) => {
                eprintln!("asv: could not start the session shim: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("asv: could not bind the session shim: {e}");
            None
        }
    }
}

/// The environment variable a route's surrogate is published under.
///
/// From the credential's *label*, not from its id: a UUID in a variable name
/// is unreadable to the person who has to debug it, and the label is the
/// operator's own spelling.
///
/// Every character that is not alphanumeric becomes an underscore, so two
/// different labels can never land on one variable name. If they could, the
/// second would silently overwrite the first and one route's tunnel would spend
/// another's token — a failure that looks exactly like a routing bug.
fn env_name_for_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len() + 16);
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    // A label made entirely of punctuation would otherwise produce a bare
    // `ASV_SURROGATE_`, which is a legal variable name and a useless one.
    if out.is_empty() || out.chars().all(|c| c == '_') {
        out.push_str("CREDENTIAL");
    }
    out
}

/// Launches a command inside a real ASV session.
///
/// The session used to be invented. `ASV_SESSION_ID` was set to this
/// process's pid and **nothing in the repository ever read it** — verified
/// by grep across every source extension — so the child of every session
/// was told which session it was, and no party ever checked. That is the
/// same class of defect as the H2 and H3 findings, and ADR-0019 could not
/// be built on top of it: a CONNECT client has to resolve to a session
/// that exists, and the id being handed out named nothing.
///
/// So the session is opened here, over the same kernel-authenticated
/// socket every other verb uses, and the agent's public key is bound to
/// it. If any of that fails the child is **not** launched: a child with no
/// real session is exactly the state this function used to create.
/// Run a registered compatibility worker, inside a session that is opened and
/// ended here.
///
/// Two properties are structural rather than checked. The session is opened
/// before the request and ended after it, so a run cannot outlive the
/// authority that authorised it. And the arguments cross as elements, so there
/// is no argument from which the broker could be asked to run a shell.
fn run_isolated(
    socket: &std::path::Path,
    worker: &str,
    args: &[String],
    credential: Option<&str>,
    timeout_ms: Option<u64>,
) -> std::io::Result<()> {
    let session = match call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    )? {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv run-isolated could not open a session: {other:?}"
            )))
        }
    };

    let outcome = call(
        socket,
        &Request::RunIsolated {
            session,
            worker: worker.to_string(),
            args: args.to_vec(),
            credential: credential.map(|s| s.to_string()),
            timeout_ms,
        },
    );

    // Ended before the result is reported, so a report that never arrives is
    // still bounded by the session's own lifetime.
    let _ = call(socket, &Request::EndSession { session });
    let response = outcome?;

    match &response {
        Response::IsolatedResult { exit_code, .. } => {
            print_response(&response);
            match exit_code {
                Some(0) => Ok(()),
                Some(code) => Err(std::io::Error::other(format!(
                    "worker `{worker}` exited {code}"
                ))),
                None => Err(std::io::Error::other(format!(
                    "worker `{worker}` did not exit normally"
                ))),
            }
        }
        Response::Error { message, .. } => Err(std::io::Error::other(format!(
            "asv run-isolated refused: {}: {message}",
            response_kind(&response),
        ))),
        other => Err(std::io::Error::other(format!(
            "asv run-isolated got an unexpected answer: {other:?}"
        ))),
    }
}

/// How long the one-use surrogate may live.
///
/// The mint and the spend are two calls over a local socket, back to back, so
/// the only thing this has to outlast is process scheduling between them. A
/// minute is orders of magnitude more than that and still short enough that a
/// surrogate that is somehow captured rather than spent is dead before anyone
/// could use it. A longer default would buy nothing and would make the
/// "one operation" claim depend on a timer rather than on `max_uses`.
const GITHUB_SURROGATE_TTL_SECS: u64 = 60;

/// The `workload` an intent carries when no session was ever opened.
///
/// **A literal that says so, rather than an empty string.** The intent names
/// the session it will be authorized under, and that name goes into the intent
/// digest, so a receipt whose workload is blank would be a receipt claiming an
/// operation with no session at all — which is both false (this process asked
/// and failed to get one) and unreadable (a reader cannot tell it from a bug).
/// This string is the difference between "there was no session" and "the
/// session was the empty string".
const UNOPENED_SESSION: &str = "(no session could be opened)";

/// The lifetime of a registry pull's surrogate.
///
/// Same minute as the GitHub verbs and for the same reason: the grant covers
/// one request that happens immediately, and anything longer would be a
/// bearer capability outliving the reason it was minted. There is no
/// operator-tunable value here on purpose — a longer TTL is a policy change,
/// and it belongs in the surrogate's class rather than in a flag.
const REGISTRY_SURROGATE_TTL_SECS: u64 = 60;

/// One GitHub operation, from the product surface to a typed answer.
///
///     asv github issue view        the product surface
///         -> unix socket           versioned IPC, protocol 8
///         -> CreateSession         a real session, owned by this process
///         -> MintSurrogate         one use, one minute, from a vault *id*
///         -> ReadIssue            the broker lends the secret per request
///         -> EndSession           the grant cannot outlive the command
///
/// # What is deliberately not here
///
/// There is no path in this function that can produce a GitHub token, and
/// that is not an omission to be filled in later — it is the reason the command
/// exists. `--credential` names a vault entry; the broker decides what that
/// entry is and lends it. So the strongest statement this code can make is
/// negative, and a future change that wants to add a token here has to
/// explain which of the four hops it removed.
///
/// # Why the surrogate is minted per invocation
///
/// One command, one operation, one use. A long-lived surrogate handed to an
/// agent is a bearer capability that outlives the reason it was minted, and
/// the "single-use" property is what makes the session's end meaningful: after
/// `EndSession` there is nothing left to redeem even if the string were
/// captured.
fn run_github(socket: &std::path::Path, command: &GithubCommand) -> std::io::Result<()> {
    // Parsed before anything opens a session. The broker keys the vault by the
    // canonical wire spelling, so an id that is a valid UUID in some other
    // spelling would be accepted here and then miss in the vault, and the
    // operator would be told the credential does not exist. `CredentialId`'s
    // parse error carries no text, so nothing they typed comes back out.
    let credential = match CredentialId::from_wire(github_credential_arg(command)) {
        Ok(id) => id,
        Err(_) => {
            // A usage error, and reported as one: this is the shape every
            // other argument check in this CLI uses (`parse_credential_kind`,
            // `CredentialId::from_wire` in `delete-credential`), so a script
            // that distinguishes "you called me wrong" from "the broker said
            // no" sees the same exit code here it sees everywhere else. The
            // message quotes nothing, so nothing the operator typed comes back
            // out.
            eprintln!(
                "asv: the --credential value is not a vault id; copy it from `asv credentials`"
            );
            std::process::exit(2);
        }
    };

    // Bodies are read before the session exists, for the same reason
    // `add-credential` reads its secret first: a payload this process is
    // holding should not be sitting in a live grant's lifetime.
    let body = match github_body_arg(command) {
        Some(spec) => Some(match read_github_body(&spec) {
            Ok(text) => text,
            Err(error) => {
                // The path is named because the operator supplied it and the
                // kernel's `No such file or directory` does not say which of
                // the three flags it was about. A body that is silently
                // missing is a release published with empty notes.
                eprintln!("asv: cannot read the body from {spec:?}: {error}");
                std::process::exit(2);
            }
        }),
        None => None,
    };

    let session = match github_call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv github could not open a session: {other:?}"
            )))
        }
    };

    // From here on the session exists, so every exit path has to end it. The
    // one that could skip it is the one where the operation itself failed, and
    // that is precisely the case where a caller would otherwise leave a live
    // grant behind.
    let outcome = github_call(
        socket,
        &Request::MintSurrogate {
            session,
            credential,
            max_uses: 1,
            ttl_secs: GITHUB_SURROGATE_TTL_SECS,
        },
    );

    let response = match &outcome {
        Response::SurrogateMinted { surrogate, .. } => github_call(
            socket,
            &github_request(
                command,
                session,
                surrogate,
                body.as_deref().unwrap_or_default(),
            ),
        ),
        // The mint itself was refused, or answered something else. Reporting
        // that answer *is* the operation's outcome — there is no operation to
        // run without a surrogate, and inventing one would be the whole bug
        // this path exists to avoid.
        other => other.clone(),
    };

    // Ended before the result is reported, so a report that never arrives is
    // still bounded by the session's own lifetime. `github_call` would exit 2
    // on a failure here, which would be wrong: a session that will not close
    // does not unmake the answer the broker already gave, and turning a
    // completed read into "connection failed" would be a worse lie than
    // leaking the session. So the plain transport error is dropped and the
    // grant is left to its own expiry.
    let _ = call(socket, &Request::EndSession { session });

    let json = github_json_flag(command);
    match &response {
        Response::IssueRead { .. }
        | Response::IssueCreated { .. }
        | Response::ReleaseCreated { .. } => {
            if json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                print_response(&response);
            }
            Ok(())
        }
        Response::Error { code, message } => {
            if json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                eprintln!("asv github refused ({code:?}): {message}");
            }
            // A distinct exit code from a connection failure (2). "The broker
            // said no" and "there was no broker" are different events and a
            // script that retries on one must not retry on the other.
            std::process::exit(1);
        }
        other => Err(std::io::Error::other(format!(
            "asv github got an unexpected answer: {other:?}"
        ))),
    }
}

/// Runs one AWS verb.
///
/// **No surrogate, and that is the whole difference from `run_github`.** A
/// surrogate is a bearer token this process would hold; a GitHub token is a
/// single value with a use count, and holding one is a deliberate, bounded
/// exposure. An AWS session is three values, and the whole point of R2.C.3 is
/// that this process gets none of them — so there is nothing to mint, nothing to
/// redeem, and nothing to revoke on the way out. The broker mints, signs, and
/// answers with the identity AWS reported.
fn run_aws(socket: &std::path::Path, command: &AwsCommand) -> std::io::Result<()> {
    let AwsCommand::Whoami { credential, json } = command;

    // Validated before a session exists, for the reason `run_github` does it:
    // a malformed id would be accepted here and then miss in the broker, and the
    // operator would be told a credential does not exist.
    if CredentialId::from_wire(credential).is_err() {
        eprintln!("asv: the --credential value is not a vault id; copy it from `asv credentials`");
        std::process::exit(2);
    }

    let session = match github_call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv aws could not open a session: {other:?}"
            )))
        }
    };

    let response = github_call(
        socket,
        &Request::AwsCallerIdentity {
            session,
            credential: credential.clone(),
        },
    );

    // Ended before the answer is reported, so a report that never arrives is
    // still bounded by the session's own lifetime. A session that will not close
    // does not unmake the answer the broker already gave, and turning a
    // completed read into "connection failed" would be a worse lie than leaving
    // the grant to expire.
    let _ = call(socket, &Request::EndSession { session });

    match &response {
        Response::AwsCallerIdentity {
            arn,
            user_id,
            account,
        } => {
            if *json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                println!("arn:     {arn}");
                println!("user_id: {user_id}");
                println!("account: {account}");
            }
            Ok(())
        }
        Response::Error { code, message } => {
            if *json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                eprintln!("asv aws refused ({code:?}): {message}");
            }
            // Distinct from a connection failure (2), for the reason the GitHub
            // verb documents it: "the broker said no" and "there was no broker"
            // are different events and a script must not retry both alike.
            std::process::exit(1);
        }
        other => Err(std::io::Error::other(format!(
            "asv aws got an unexpected answer: {other:?}"
        ))),
    }
}

/// Runs one OAuth2 verb.
///
/// **No surrogate and no token, and both absences are the design.** A surrogate
/// would be a bearer token this process holds, and the whole point of M11 is
/// that it does not: the client secret stays in the broker, is spent on one
/// token request, and what the broker holds afterwards is an access token that
/// expires on the *provider's* clock. So there is nothing to mint, nothing to
/// redeem, and nothing to revoke on the way out — the broker borrows, asks, and
/// answers with what the resource reported.
/// R3's `discover` and `plan`.
///
/// `discover` takes no socket and that is not a shortcut — it reads files the
/// caller can already read, so a broker round trip would authorise nothing and
/// would create a dependency from the reporting surface to the credential plane
/// for no gain. `plan` does open one, because it cannot answer "what could be
/// done here" without knowing what credentials exist, and only the broker knows
/// that. What it asks for is the credential *inventory* — label, kind,
/// exportability — and never a value.
///
/// The split is the reason this function takes the socket and `discover` does
/// not use it: `plan` is the first stage where a credential is *named*, and
/// naming one is what makes the broker relevant.
fn run_integrations(
    socket: &std::path::Path,
    command: &IntegrationsCommand,
) -> std::io::Result<()> {
    match command {
        IntegrationsCommand::Discover {
            family,
            json,
            cwd,
            home,
            allow_symlink_root,
        } => run_integrations_discover(
            family,
            *json,
            cwd,
            home.as_deref(),
            allow_symlink_root.as_deref(),
        ),
        IntegrationsCommand::Plan {
            family,
            json,
            cwd,
            home,
            allow_symlink_root,
            no_vault,
        } => run_integrations_plan(
            socket,
            family,
            *json,
            cwd,
            home.as_deref(),
            allow_symlink_root.as_deref(),
            *no_vault,
        ),
        IntegrationsCommand::Execute {
            family,
            json,
            tool,
            transaction,
            principal,
            actor,
            origin,
            ttl,
            session,
            workspace,
            cwd,
            home,
            allow_symlink_root,
            no_vault,
        } => run_integrations_execute(
            socket,
            family,
            *json,
            tool,
            transaction,
            principal,
            actor,
            origin,
            *ttl,
            session.as_deref(),
            workspace,
            cwd,
            home.as_deref(),
            allow_symlink_root.as_deref(),
            *no_vault,
        ),
        IntegrationsCommand::Adopt {
            family,
            json,
            file,
            home,
            audience,
            field,
            label,
            allow_symlink_root,
            from_plan,
        } => run_integrations_adopt(
            socket,
            family,
            *json,
            file.as_deref(),
            home.as_deref(),
            audience,
            field,
            label,
            allow_symlink_root.as_deref(),
            from_plan.as_deref(),
        ),
    }
}

/// The shared half of both stages: locate the caller's configuration and read
/// it. One implementation rather than two, because the two commands must agree
/// about which files they are talking about — a `plan` built from a different
/// set of files than the `discover` it follows would be a plan about something
/// the operator was never shown.
fn integrations_home_and_policy(
    home: Option<&str>,
    allow_symlink_root: Option<&str>,
) -> std::io::Result<(
    std::path::PathBuf,
    std::path::PathBuf,
    asv_integrations::FingerprintPolicy,
)> {
    let home = match home {
        Some(home) => std::path::PathBuf::from(home),
        // `HOME` rather than a passwd lookup: this is the *caller's* home, and
        // the crate takes it as an argument precisely so that a library can
        // never decide whose configuration it is reading. The CLI is the layer
        // entitled to answer that, and it answers it about itself.
        None => match std::env::var_os("HOME") {
            Some(home) => std::path::PathBuf::from(home),
            None => {
                eprintln!(
                    "asv: HOME is not set, so the user-level configuration cannot be located; \
                     pass --home"
                );
                std::process::exit(2);
            }
        },
    };
    let mut policy = asv_integrations::FingerprintPolicy::strict();
    if let Some(root) = allow_symlink_root {
        policy = policy.allowing_symlink_root(root);
    }
    Ok((home, std::path::PathBuf::from("."), policy))
}

fn run_integrations_discover(
    family: &str,
    json: bool,
    cwd: &str,
    home: Option<&str>,
    allow_symlink_root: Option<&str>,
) -> std::io::Result<()> {
    use asv_integrations::Adapter as _;

    let (home, _, policy) = integrations_home_and_policy(home, allow_symlink_root)?;
    let cwd = std::path::PathBuf::from(cwd);

    let discovery = match family {
        "npm" => asv_integrations::Npm
            .discover(&policy, &home, &cwd)
            .map(asv_integrations::NpmDiscovery::into_discovery)
            .map_err(|error| error.to_string()),
        "maven" => asv_integrations::Maven
            .discover(&policy, &home, &cwd)
            .map(asv_integrations::MavenDiscovery::into_discovery)
            .map_err(|error| error.to_string()),
        "gradle" => asv_integrations::Gradle
            .discover(&policy, &home, &cwd)
            .map(asv_integrations::GradleDiscovery::into_discovery)
            .map_err(|error| error.to_string()),
        "curl" => asv_integrations::Curl
            .discover(&policy, &home, &cwd)
            .map(asv_integrations::CurlDiscovery::into_discovery)
            .map_err(|error| error.to_string()),
        other => Err(format!(
            "no adapter for {other:?}; this build knows `npm`, `maven`, `gradle` \
             and `curl`. Adding one is a module in asv-integrations, a variant in \
             `AnyReport`, and one match arm here."
        )),
    };

    let discovery = match discovery {
        Ok(discovery) => discovery,
        Err(message) => {
            if json {
                // A failure in the `asv.discovery/v1` shape, so a consumer
                // parsing this command's output has one shape to handle rather
                // than two: prose on the happy path, JSON on the sad one, is a
                // contract nobody can implement against.
                let failure = serde_json::json!({
                    "schema": asv_integrations::DISCOVERY_SCHEMA,
                    "family": family,
                    "error": message,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&failure).unwrap_or_default()
                );
            } else {
                eprintln!("asv: {message}");
            }
            std::process::exit(1);
        }
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&discovery).expect("the report serialises")
        );
        return Ok(());
    }
    print_discovery_prose(&discovery);
    Ok(())
}

/// R3's `plan`: the strategies available for each credential the tool is
/// configured to use.
///
/// The broker is asked **one** question, and it is the metadata question:
/// `ListCredentialMetadata`. The answer is a list of labels, kinds and
/// exportabilities — no audience, no scope, and by construction no value — and
/// that is enough to decide a posture, because a posture is a function of what
/// kind of credential it is and whether it may leave the vault at all.
///
/// It is *not* enough to say which credential serves which registry, which is
/// why two usable credentials come back `ambiguous` rather than resolved. That
/// is a real gap in the input, reported rather than papered over.
fn run_integrations_plan(
    socket: &std::path::Path,
    family: &str,
    json: bool,
    cwd: &str,
    home: Option<&str>,
    allow_symlink_root: Option<&str>,
    no_vault: bool,
) -> std::io::Result<()> {
    use asv_integrations::Adapter as _;

    let (home, _, policy) = integrations_home_and_policy(home, allow_symlink_root)?;
    let cwd = std::path::PathBuf::from(cwd);

    let inventory = if no_vault {
        Vec::new()
    } else {
        match call(socket, &Request::ListCredentialMetadata)? {
            Response::CredentialMetadata { entries } => entries
                .into_iter()
                .map(|entry| asv_domain::CredentialMetadata {
                    id: asv_domain::CredentialId::from_uuid(entry.id),
                    label: entry.label,
                    kind: entry.kind,
                    exportability: entry.exportability,
                })
                .collect(),
            other => {
                // A protocol that answered something else has not told us what
                // credentials exist, and a plan built on "we did not ask" would
                // be a plan about an invented inventory.
                eprintln!(
                    "asv: the broker answered {} to a credential-inventory request; \
                     this command cannot plan against that",
                    response_kind(&other)
                );
                std::process::exit(1);
            }
        }
    };

    let plan = match family {
        "npm" => {
            let discovery = match asv_integrations::Npm.discover(&policy, &home, &cwd) {
                Ok(discovery) => discovery,
                Err(error) => {
                    if json {
                        let failure = serde_json::json!({
                            "schema": asv_integrations::PLAN_SCHEMA,
                            "family": family,
                            "error": error.to_string(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&failure).unwrap_or_default()
                        );
                    } else {
                        eprintln!("asv: {error}");
                    }
                    std::process::exit(1);
                }
            };
            asv_integrations::plan_npm(&discovery, &inventory)
        }
        // R4.B.1's second family. Same four stages, different vocabulary: the
        // discovery produces `Selector::Curl` and nothing else had to change.
        "curl" => {
            let discovery = match asv_integrations::Curl.discover(&policy, &home, &cwd) {
                Ok(discovery) => discovery,
                Err(error) => {
                    if json {
                        let failure = serde_json::json!({
                            "schema": asv_integrations::PLAN_SCHEMA,
                            "family": family,
                            "error": error.to_string(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&failure).unwrap_or_default()
                        );
                    } else {
                        eprintln!("asv: {error}");
                    }
                    std::process::exit(1);
                }
            };
            asv_integrations::plan_curl(&discovery, &inventory)
        }
        other => {
            eprintln!(
                "asv: no plan for {other:?}; this build plans `npm` and `curl`. Adding one is a \
                 module in asv-integrations, a variant in `Selector`, and one match arm here."
            );
            std::process::exit(1);
        }
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).expect("the plan serialises")
        );
        return Ok(());
    }
    print_plan_prose(&plan);
    Ok(())
}

/// The human form of a plan.
fn print_plan_prose(plan: &asv_integrations::IntegrationPlan) {
    if plan.entries.is_empty() {
        println!(
            "{}: no credential selectors found in any configuration file, so there is nothing to \
             plan.",
            plan.family
        );
        return;
    }
    println!(
        "{} plan — {} selector(s), against {} stored credential(s)",
        plan.family,
        plan.entries.len(),
        plan.inventory_size
    );
    for entry in &plan.entries {
        println!();
        println!("{} ({:?})", entry.file.display(), entry.origin);
        // The two families name different things and the type is what stops a
        // renderer from printing one of them for the other. A curl entry has
        // no audience to print because a `.curlrc` names no host.
        match &entry.selector {
            asv_integrations::Selector::Npm {
                field, audience, ..
            } => {
                println!("  -> {audience}");
                println!("  field: {field}");
            }
            asv_integrations::Selector::Curl {
                option,
                kind,
                user_len,
                password_len,
                has_password,
            } => {
                println!("  option: {option} ({kind:?})");
                println!("  name: {user_len} bytes, password: {password_len} bytes");
                if !has_password {
                    println!("    no password half was written: curl sends an empty one.");
                }
            }
        }
        match &entry.binding {
            asv_integrations::Binding::Bound {
                credential,
                label,
                kind,
                ..
            } => println!("  would bind: {label} ({credential}, {kind:?})"),
            asv_integrations::Binding::Ambiguous { candidates } => {
                println!(
                    "  would bind: {} candidates, and this build cannot tell them apart:",
                    candidates.len()
                );
                for candidate in candidates {
                    println!(
                        "    - {} ({}, {:?})",
                        candidate.label, candidate.credential, candidate.kind
                    );
                }
                println!("    name one with `asv integrations adopt` to disambiguate.");
            }
            asv_integrations::Binding::NotACredential { selector } => {
                println!("  not a credential the tool will authenticate with: {selector}");
            }
            asv_integrations::Binding::Unbound { reason } => match reason {
                asv_integrations::UnboundReason::NoUsableCredential { inventory_size } => println!(
                    "  no credential to bind: the vault holds {inventory_size}, and none is a \
                     shape that could serve a registry"
                ),
                asv_integrations::UnboundReason::EveryCandidateExcluded { excluded } => {
                    println!("  no credential to bind; every candidate was excluded:");
                    for exclusion in excluded {
                        match exclusion {
                            asv_integrations::Exclusion::DatabaseShaped { kind } => println!(
                                "    - {kind:?} is database-shaped and can only ever authenticate \
                                 against a database"
                            ),
                        }
                    }
                }
            },
        }
        if entry.strategies.is_empty() {
            println!("  strategies: none — nothing is bound, so nothing is on offer.");
            continue;
        }
        println!("  strategies, strongest first:");
        for strategy in &entry.strategies {
            println!(
                "    {}  ({})",
                strategy.posture.wire_name(),
                describe(strategy)
            );
        }
    }
}

fn describe(strategy: &asv_integrations::Strategy) -> String {
    use asv_integrations::Why as W;
    match &strategy.why {
        W::Brokered { kind } => {
            format!("the broker substitutes a {kind:?}, so the tool never holds the value")
        }
        W::Minted { kind } => {
            format!("a {kind:?} is minted per use, so what lands on disk expires")
        }
        W::Exported { exportability } => {
            format!("the value is written out for the tool, permitted by {exportability:?}")
        }
    }
}

/// The human form of a discovery report.
///
/// Every line is something the operator would otherwise have to read out of a
/// JSON document by hand, and **every line is about a registry or a selector** —
/// there is no line here that could be a credential, because the report has none
/// to print.
fn print_discovery_prose(discovery: &asv_integrations::Discovery) {
    // A `match` rather than the irrefutable `let` this used to be. That form
    // was only possible while `AnyReport` had exactly one variant, and writing
    // the dispatch out means a family added later has to be *described* here —
    // an unreachable arm is a compiler error rather than prose that quietly
    // prints nothing.
    match &discovery.report {
        asv_integrations::AnyReport::Npm(report) => print_npm_discovery(report),
        asv_integrations::AnyReport::Maven(report) => print_maven_discovery(report),
        asv_integrations::AnyReport::Gradle(report) => print_gradle_discovery(report),
        asv_integrations::AnyReport::Curl(report) => print_curl_discovery(report),
    }
}

fn print_npm_discovery(report: &asv_integrations::NpmDiscovery) {
    if report.files.is_empty() {
        println!("no .npmrc was found for this project or this account");
        return;
    }
    for file in &report.files {
        // `Origin` has four levels and npm uses three. `Tool` — where the tool
        // and the operating system disagree about the name for the same place,
        // which is Maven's `$MAVEN_HOME/conf` rather than a "global" — has no
        // npm candidate, so this arm cannot be reached from a report. It is
        // written out rather than papered with `_` because a wildcard here is
        // exactly how a fourth origin would start printing as "user".
        let origin = match file.origin {
            asv_integrations::Origin::Project => "project",
            asv_integrations::Origin::User => "user",
            asv_integrations::Origin::Global => "global",
            asv_integrations::Origin::Tool => "tool",
        };
        let readable = if file.fingerprint.is_untrusted_readable() {
            "  (readable by group or other — a token in here is exposed)"
        } else {
            ""
        };
        println!("{origin} {}", file.fingerprint.path.display());
        println!("  {}{readable}", file.fingerprint.digest);
        if let Some(registry) = &file.registry {
            println!("  registry  {}", registry.audience);
        }
        for scoped in &file.scoped_registries {
            // `scope` already carries its own `@` — npm spells it that way, and
            // the first version printed `@@acme` by adding one.
            println!("  {}  {}", scoped.scope, scoped.registry.audience);
        }
        for selector in &file.auth_selectors {
            let source = match &selector.env_reference {
                Some(name) => format!("from ${name}"),
                None => format!("{} bytes", selector.value_len),
            };
            println!(
                "  credential  {} {} ({source})",
                selector.registry.audience, selector.field
            );
        }
    }
}

/// Maven's prose, and the same law: a `<id>` and a byte count, never a value.
///
/// The `<id>` is printed verbatim on purpose. It is the handle a `pom.xml`
/// refers to — Maven's audience, and the one field in the report that is not a
/// secret *because* it is a name the tool already had to carry in the clear.
fn print_maven_discovery(report: &asv_integrations::MavenDiscovery) {
    // Silence is not an answer here. With a finding pending, "no settings.xml
    // was found" is a claim about a file that exists, and printing it makes a
    // refusal read as an absence — the one confusion this report cannot have.
    if report.files.is_empty() {
        if report.findings.is_empty() {
            println!("no settings.xml was found for this account");
        }
        print_findings(&report.findings);
        return;
    }
    for file in &report.files {
        let origin = match file.origin {
            asv_integrations::Origin::Project => "project",
            asv_integrations::Origin::User => "user",
            asv_integrations::Origin::Global => "global",
            asv_integrations::Origin::Tool => "tool",
        };
        let readable = if file.fingerprint.is_untrusted_readable() {
            "  (readable by group or other — a password in here is exposed)"
        } else {
            ""
        };
        println!("{origin} {}", file.fingerprint.path.display());
        println!("  {}{readable}", file.fingerprint.digest);
        if let Some(local) = &file.local_repository {
            println!("  localRepository  {local}");
        }
        for mirror in &file.mirrors {
            let url = mirror.url.as_deref().unwrap_or("(no url)");
            let of = mirror.mirror_of.as_deref().unwrap_or("(no mirrorOf)");
            println!("  mirror  {}  {url}  <- {of}", mirror.id);
        }
        for server in &file.servers {
            println!("  server  {}", server.id);
            match (&server.env_reference, server.password_len) {
                // The variable is *named*, never resolved: the environment is
                // the caller's, not the file's, and resolving it here would be
                // this process reading a secret it was not asked to read.
                (Some(name), _) => println!("    password  from ${{env.{name}}}"),
                (None, Some(len)) => println!("    password  {len} bytes"),
                (None, None) => println!("    password  (none set)"),
            }
            match server.username_len {
                Some(len) => println!("    username  {len} bytes"),
                None => println!("    username  (none set)"),
            }
            // **Printed, not left to the JSON.** A `<configuration>` this
            // adapter does not model is where Artifactory and Nexus keep an API
            // key, and a prose report that listed only the password would be
            // quietly omitting a second credential. The element is named and
            // measured — never read.
            for undescribed in &server.undescribed {
                println!(
                    "    <{}>  not described by this adapter, {} bytes — check it by hand",
                    undescribed.element, undescribed.len
                );
            }
        }
        for proxy in &file.proxies {
            let host = proxy.host.as_deref().unwrap_or("(no host)");
            let port = proxy
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "(no port)".to_string());
            let state = if proxy.active { "active" } else { "inactive" };
            println!("  proxy  {}  {host}:{port}  ({state})", proxy.id);
            match (&proxy.env_reference, proxy.password_len) {
                (Some(name), _) => println!("    password  from ${{env.{name}}}"),
                (None, Some(len)) => println!("    password  {len} bytes"),
                (None, None) => println!("    password  (none set)"),
            }
        }
    }
    print_findings(&report.findings);
}

fn print_gradle_discovery(report: &asv_integrations::GradleDiscovery) {
    // Same rule as the other two families: with a finding pending, "none was
    // found" is a claim about a file that exists.
    if report.files.is_empty() {
        if report.findings.is_empty() {
            println!("no gradle.properties or init script was found for this project or account");
        }
        print_findings(&report.findings);
        return;
    }
    for file in &report.files {
        let origin = match file.origin {
            asv_integrations::Origin::Project => "project",
            asv_integrations::Origin::User => "user",
            asv_integrations::Origin::Global => "global",
            asv_integrations::Origin::Tool => "tool",
        };
        let readable = if file.fingerprint.is_untrusted_readable() {
            "  (readable by group or other — a password in here is exposed)"
        } else {
            ""
        };
        println!("{origin} {}", file.fingerprint.path.display());
        println!("  {}{readable}", file.fingerprint.digest);
        for credential in &file.credentials {
            println!("  credential  {}  ({:?})", credential.key, credential.kind);
            match (&credential.env_reference, credential.len) {
                // Named, never resolved. The environment is the caller's, not
                // the file's, and resolving it here would be this process
                // reading a secret it was not asked to read.
                (Some(name), _) => println!("    value  from ${{{name}}}"),
                (None, Some(len)) => println!("    value  {len} bytes"),
                (None, None) => println!("    value  (empty)"),
            }
        }
        // **The bulk of the file, and it is not a list of credentials.**
        // Most of a `gradle.properties` is JVM flags and daemon tuning. An
        // operator reading this needs to know two separate things: how many
        // credentials there are, and how much of the file is something this
        // adapter does not model. Printing them as one list would imply the
        // second is a finding, and the first time an operator learned to
        // ignore this report would be the first time it hid something.
        if !file.undescribed.is_empty() {
            println!(
                "  {} other key(s) not described by this adapter",
                file.undescribed.len()
            );
            for entry in &file.undescribed {
                println!("    {}  {} bytes", entry.key, entry.len);
            }
        }
    }
    print_findings(&report.findings);
}

/// curl, and the one family whose precedence is a **choice** rather than a
/// **layering**.
///
/// The other three merge every file they find, so this report could have been a
/// loop with no state. curl takes the first file that exists and never opens the
/// rest, so the report's first job is to say which one that was — an operator
/// with a `~/.curlrc` and a `~/.config/curlrc` has a credential in one of them
/// and no way to tell which without being told.
fn print_curl_discovery(report: &asv_integrations::CurlDiscovery) {
    // Said before the file list, because it qualifies every line below it: two
    // of curl's own lookup paths are environment variables this report cannot
    // resolve, so the list is not the whole of what curl could have used.
    if report.env_paths_unseen {
        println!(
            "note: curl reads $CURL_HOME/.curlrc and $XDG_CONFIG_HOME/curlrc ahead of \
             every path below, and neither is resolvable without reading this process's \
             environment. If you set either, your real configuration is not in this list."
        );
    }

    if report.considered().is_empty() {
        if report.findings.is_empty() {
            println!("no .curlrc was found for this project or account");
        }
        print_findings(&report.findings);
        return;
    }

    // The project file is printed under its own heading and after the lookup,
    // because it is not a lower-precedence layer of the same thing. Printed
    // inline with the others it would read as "the project's configuration,
    // overridden by your home one" — which is the opposite of the truth, since
    // curl reads it only when a command says `--config`.
    let ordered: Vec<&asv_integrations::CurlFile> = report
        .lookup
        .iter()
        .chain(report.project_config.iter())
        .collect();
    let split_at = report.lookup.len();

    for (index, file) in ordered.into_iter().enumerate() {
        if index == split_at {
            println!();
            println!("(the next file is beside the project; curl reads it only when a command names it with --config, never automatically)");
        }
        let origin = match file.origin {
            asv_integrations::Origin::Project => "project",
            asv_integrations::Origin::User => "user",
            asv_integrations::Origin::Global => "global",
            asv_integrations::Origin::Tool => "tool",
        };

        // **The shadowed rows are the point of this family.** They are files
        // that exist and were not opened, which is a different sentence from
        // "a file was opened and had nothing in it". Printing them as empty
        // would be the single most misleading thing this report could do: an
        // operator would learn that their `~/.curlrc` is empty when in fact
        // curl never read it.
        let Some(fingerprint) = file.fingerprint.as_ref() else {
            println!("{origin} {}", file.path.display());
            println!("  not read — shadowed by an earlier file curl would have used");
            if let Some(winner) = file.shadowed_by.as_ref() {
                println!("    shadowed by {}", winner.display());
            }
            continue;
        };

        let readable = if fingerprint.is_untrusted_readable() {
            "  (readable by group or other — a password in here is exposed)"
        } else {
            ""
        };
        println!("{origin} {}", fingerprint.path.display());
        println!("  {}{readable}", fingerprint.digest);

        for credential in &file.credentials {
            println!(
                "  credential  {}  ({:?})",
                credential.option, credential.kind
            );
            // **Two lengths, because there are two questions.** curl's `user`
            // carries `name:secret` on one line, and a single length for the
            // pair answers neither "who does this authenticate as" nor "how long
            // is the secret". No other family has to make this split, which is
            // why this is the first place the report prints two numbers.
            println!("    user       {} bytes", credential.user_len);
            println!(
                "    password   {}",
                if credential.has_password {
                    format!("{} bytes", credential.password_len)
                } else {
                    "(absent — curl authenticates with an empty password)".to_string()
                }
            );
        }

        // The bulk of a real `.curlrc`, and not a list of credentials: most
        // lines are `--silent`, `--max-time` and `--retry`. Same reasoning as
        // Gradle's undescribed keys.
        if !file.options.is_empty() {
            println!(
                "  {} other option(s) not described by this adapter",
                file.options.len()
            );
            for option in &file.options {
                match option.len {
                    Some(len) => println!("    {}  {} bytes", option.option, len),
                    None => println!("    {}  (flag)", option.option),
                }
            }
        }
    }
    print_findings(&report.findings);
}

/// What discovery declined to read, and why.
///
/// Written for the second family rather than the first, which is worth saying:
/// [`asv_integrations::NpmDiscovery`] has no findings because npm's `discover`
/// refuses the whole run when a file will not parse, and this module was written
/// and closed before the second family existed to show that the other policy —
/// refuse the *file*, keep the report — is the one an operator can act on. The
/// two are not merged here: doing so would change npm's committed behaviour, and
/// a report that grew a field is a contract change, not a tidy-up.
fn print_findings(findings: &[asv_integrations::Finding]) {
    for finding in findings {
        eprintln!("asv: {}: {}", finding.subject, finding.message);
    }
}

/// Runs one registry verb, from the product surface to the bytes.
///
///     asv registry manifest read    the product surface
///         -> unix socket            versioned IPC
///         -> CreateSession         a real session, owned by this process
///         -> MintSurrogate         one use, one minute, from a vault *id*
///         -> PullManifest          the broker lends the secret per request
///         -> EndSession            the grant cannot outlive the command
///
/// # What is deliberately not here
///
/// There is no path in this function that can produce a registry token, and no
/// field anywhere below that could hold one — the same negative statement the
/// GitHub verb makes, reached the same way. `--registry` names a *selector*:
/// the authority this process connects to is the one the deployment declared,
/// and if the two disagree the broker refuses before it resolves anything.
///
/// # Where the bytes go, and why the digest is the answer
///
/// The content goes to `--out` or stdout, raw, because a layer is not a
/// sentence and a JSON string with escaped newlines in it would be something
/// every caller had to undo. The digest goes to **stderr** in the human form,
/// and into the envelope in the JSON form, and it is the value worth reading:
/// the broker computed it from the bytes that arrived, so a caller can verify
/// whatever it wrote without trusting the registry that sent it.
///
/// `--json` deliberately does **not** carry the body. It carries the content
/// address, the media type and the length, which is enough to check a file that
/// is already on disk; embedding megabytes of layer in an envelope would make
/// the envelope a thing with a size limit nobody wrote down.
/// Routes a registry verb by direction.
///
/// One place decides read-or-write, so adding a verb to either enum and
/// forgetting this match is a compile error naming the verb, not a silent
/// no-op. The direction is not guessed from the fields: it comes from which
/// enum the verb is in.
fn run_registry_dispatch(
    socket: &std::path::Path,
    command: &RegistryCommand,
) -> std::io::Result<()> {
    match command {
        RegistryCommand::Manifest(RegistryManifestCommand::Read { .. })
        | RegistryCommand::Blob(RegistryBlobCommand::Read { .. }) => run_registry(socket, command),
        RegistryCommand::Manifest(RegistryManifestCommand::Push { .. })
        | RegistryCommand::Blob(RegistryBlobCommand::Push { .. }) => {
            run_registry_push(socket, command)
        }
    }
}

fn run_registry(socket: &std::path::Path, command: &RegistryCommand) -> std::io::Result<()> {
    let (credential_arg, registry, repository, selector, out, json) = match command {
        RegistryCommand::Manifest(RegistryManifestCommand::Read {
            credential,
            registry,
            repository,
            reference,
            out,
            json,
        }) => (
            credential,
            registry,
            repository,
            Selector::Reference(reference),
            out,
            json,
        ),
        RegistryCommand::Blob(RegistryBlobCommand::Read {
            credential,
            registry,
            repository,
            digest,
            out,
            json,
        }) => (
            credential,
            registry,
            repository,
            Selector::Digest(digest),
            out,
            json,
        ),
        // Unreachable through `run_registry_dispatch`, which routes a push here
        // only by mistake. Present so that adding a verb to either enum cannot
        // leave this function silently unhandled: a write reaching a reader
        // that has no `--out` and no reference-to-fetch is a bug worth naming
        // rather than an empty tuple.
        RegistryCommand::Manifest(RegistryManifestCommand::Push { .. })
        | RegistryCommand::Blob(RegistryBlobCommand::Push { .. }) => {
            return Err(std::io::Error::other(
                "asv: a push verb reached the read path; that is a dispatch bug",
            ))
        }
    };

    // Validated before a session exists, for the reason `run_github` does it: a
    // malformed id would be accepted here and then miss in the vault, and the
    // operator would be told a credential does not exist. The parse error
    // carries no text, so nothing they typed comes back out.
    let credential = match CredentialId::from_wire(credential_arg) {
        Ok(id) => id,
        Err(_) => {
            eprintln!(
                "asv: the --credential value is not a vault id; copy it from `asv credentials`"
            );
            std::process::exit(2);
        }
    };

    let session = match github_call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv registry could not open a session: {other:?}"
            )))
        }
    };

    let outcome = github_call(
        socket,
        &Request::MintSurrogate {
            session,
            credential,
            max_uses: 1,
            ttl_secs: REGISTRY_SURROGATE_TTL_SECS,
        },
    );

    let response = match &outcome {
        Response::SurrogateMinted { surrogate, .. } => github_call(
            socket,
            &selector.request(session, surrogate.clone(), registry, repository),
        ),
        // The mint itself was refused, or answered something else. Reporting
        // that answer *is* the operation's outcome — there is no pull without a
        // surrogate, and inventing one would be the whole bug this path exists
        // to avoid.
        other => other.clone(),
    };

    // Ended before the answer is written, so a report that never arrives is
    // still bounded by the session's own lifetime. A session that will not
    // close does not unmake bytes the broker already sent, and turning a
    // completed read into "connection failed" would be a worse lie than
    // leaving the grant to expire.
    let _ = call(socket, &Request::EndSession { session });

    let (body, digest, media_type) = match &response {
        Response::ManifestRead {
            body,
            digest,
            media_type,
        } => (body.clone(), digest.clone(), media_type.clone()),
        Response::BlobRead { bytes, digest } => (bytes.clone(), digest.clone(), None),
        // A refusal and an unexpected answer are reported by the arms below,
        // which distinguish "the broker said no" from "I did not understand
        // the answer". Returning here rather than falling through to the write
        // is what keeps a zero-length file from looking like an empty layer.
        _ => return report_registry_refusal(&response, *json),
    };

    let destination = match out {
        Some(path) => {
            std::fs::write(path, &body).map_err(|error| {
                std::io::Error::other(format!(
                    "asv registry could not write {}: {error}",
                    path.display()
                ))
            })?;
            path.display().to_string()
        }
        None => {
            use std::io::Write as _;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&body).map_err(|error| {
                std::io::Error::other(format!("asv registry could not write to stdout: {error}"))
            })?;
            stdout
                .flush()
                .map_err(|error| std::io::Error::other(format!("asv registry: {error}")))?;
            "-".to_string()
        }
    };

    if *json {
        // The content address is the answer; the bytes are at `out`. See the
        // function's doc for why the envelope does not carry them.
        let result = ipc::from_response(&response);
        let mut data = match result {
            ipc::ApplicationResult::Ok { data, .. } => data,
            _ => serde_json::json!({}),
        };
        data["digest"] = serde_json::json!(digest);
        data["bytes"] = serde_json::json!(body.len());
        data["out"] = serde_json::json!(destination);
        if let Some(media_type) = &media_type {
            data["media_type"] = serde_json::json!(media_type);
        }
        println!(
            "{}",
            render::json::envelope(&render::json::for_result(&ipc::ApplicationResult::Ok {
                summary: format!("{body_len} byte(s) at {destination}", body_len = body.len()),
                data,
            }))
        );
    } else {
        // stderr, so that `... > layer.tar.gz` gets exactly the bytes and an
        // agent reading the metadata is not reading its own payload.
        eprintln!("digest: {digest}");
        eprintln!("bytes:  {}", body.len());
        if let Some(media_type) = &media_type {
            eprintln!("type:   {media_type}");
        }
        eprintln!("out:    {destination}");
    }
    Ok(())
}

/// What a registry verb is asked for.
///
/// A type rather than two functions because the two requests differ in exactly
/// one field, and a pair of functions would let the session, surrogate,
/// registry and repository arguments drift between them — which is the shape
/// of a bug where a blob read silently carries a manifest's reference.
enum Selector<'a> {
    /// A tag or digest naming a manifest.
    Reference(&'a String),
    /// A content address naming a blob.
    Digest(&'a String),
}

impl Selector<'_> {
    fn request(
        &self,
        session: asv_domain::AgentSessionId,
        surrogate: String,
        registry: &String,
        repository: &String,
    ) -> Request {
        match self {
            Selector::Reference(reference) => Request::PullManifest {
                session,
                surrogate,
                registry: registry.clone(),
                repository: repository.clone(),
                reference: (*reference).clone(),
            },
            Selector::Digest(digest) => Request::PullBlob {
                session,
                surrogate,
                registry: registry.clone(),
                repository: repository.clone(),
                digest: (*digest).clone(),
            },
        }
    }
}

/// Reports a refusal from a registry verb.
///
/// Split out so both the refusal and the "I did not understand this answer"
/// cases exit the same way they do in `run_aws`, and so the exit codes mean
/// the same thing here: **1** is "the broker said no" and **2** is "you called
/// me wrong". A script that retries one and not the other is the whole reason
/// those codes are distinct.
fn report_registry_refusal(response: &Response, json: bool) -> std::io::Result<()> {
    match response {
        Response::Error { code, message } => {
            if json {
                let result = ipc::from_response(response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                eprintln!("asv registry refused ({code:?}): {message}");
            }
            std::process::exit(1);
        }
        other => Err(std::io::Error::other(format!(
            "asv registry got an unexpected answer: {other:?}"
        ))),
    }
}

/// `asv registry … push` — the two write verbs of M11-R2.F.4.
///
/// Separate from `run_registry` rather than a branch inside it, because the two
/// directions do not share a shape: a read is addressed by a name and yields
/// bytes with a media type, and a write is addressed by a file and yields an
/// address. Folding them into one function would need a sum type spanning both,
/// and the shared part — validate, open a session, mint a surrogate — is three
/// statements, not three hundred.
fn run_registry_push(socket: &std::path::Path, command: &RegistryCommand) -> std::io::Result<()> {
    let (credential_arg, registry, repository, file, reference, json) = match command {
        RegistryCommand::Manifest(RegistryManifestCommand::Push {
            credential,
            registry,
            repository,
            reference,
            file,
            json,
        }) => (
            credential,
            registry,
            repository,
            file,
            Some(reference),
            json,
        ),
        RegistryCommand::Blob(RegistryBlobCommand::Push {
            credential,
            registry,
            repository,
            file,
            json,
        }) => (credential, registry, repository, file, None, json),
        // `run_registry` already claimed the reads; reaching here means a new
        // noun was added to `RegistryCommand` and this match was not updated,
        // which is what the compiler's exhaustiveness is for.
        RegistryCommand::Manifest(RegistryManifestCommand::Read { .. })
        | RegistryCommand::Blob(RegistryBlobCommand::Read { .. }) => {
            return Err(std::io::Error::other(
                "asv: that registry verb is a read; it is dispatched by run_registry",
            ))
        }
    };

    // Same reason, and the same message, as on `run_registry`: a malformed id
    // accepted here would miss in the vault later and be reported as a missing
    // credential.
    let credential = match CredentialId::from_wire(credential_arg) {
        Ok(id) => id,
        Err(_) => {
            eprintln!(
                "asv: the --credential value is not a vault id; copy it from `asv credentials`"
            );
            std::process::exit(2);
        }
    };

    let bytes = std::fs::read(file).map_err(|error| {
        std::io::Error::other(format!(
            "asv registry could not read {}: {error}",
            file.display()
        ))
    })?;

    // Refused here, by name, rather than discovered by the broker's decoder.
    // `MAX_MESSAGE_BYTES` bounds the whole encoded request, so the payload that
    // provably fits is smaller than the limit, and naming the number is more
    // use to an operator than a `MessageTooLarge` from three layers down.
    //
    // The honest limit of this verb is therefore a few kilobytes under 64 KiB,
    // and this says so: a monolithic PUT cannot publish a layer that weighs
    // megabytes. That is a known boundary of the transport, not a tuning knob.
    if bytes.len() >= asv_ipc_protocol::MAX_MESSAGE_BYTES {
        return Err(std::io::Error::other(format!(
            "asv registry: {} is {} bytes, and this transport publishes at most \
             {} bytes in one request. A layer of this size needs a chunked \
             upload session, which this verb does not implement.",
            file.display(),
            bytes.len(),
            asv_ipc_protocol::MAX_MESSAGE_BYTES
        )));
    }

    let session = match github_call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv registry could not open a session: {other:?}"
            )))
        }
    };

    let outcome = github_call(
        socket,
        &Request::MintSurrogate {
            session,
            credential,
            max_uses: 1,
            ttl_secs: REGISTRY_SURROGATE_TTL_SECS,
        },
    );

    // One request, built from the direction. The digest is computed here from
    // the bytes rather than asked for, and the broker recomputes it again: two
    // independent derivations of one claim, either of which can catch the other.
    let request = match &outcome {
        Response::SurrogateMinted { surrogate, .. } => match reference {
            Some(reference) => Request::PushManifest {
                session,
                surrogate: surrogate.clone(),
                registry: registry.clone(),
                repository: repository.clone(),
                reference: reference.clone(),
                manifest: bytes.clone(),
            },
            None => Request::PushBlob {
                session,
                surrogate: surrogate.clone(),
                registry: registry.clone(),
                repository: repository.clone(),
                digest: content_digest(&bytes),
                bytes: bytes.clone(),
            },
        },
        other => {
            // The mint was refused, or answered something else. Reporting that
            // answer *is* the outcome: there is no push without a surrogate.
            return report_registry_refusal(other, *json);
        }
    };

    let response = github_call(socket, &request);

    // Ended before the answer is reported, for the reason `run_registry` gives.
    let _ = call(socket, &Request::EndSession { session });

    match &response {
        Response::ManifestPushed {
            reference,
            digest,
            bytes,
        } => {
            if *json {
                print_registry_push_json(&response, digest, *bytes);
            } else {
                println!("manifest {reference} pushed as {digest} ({bytes} bytes)");
            }
            Ok(())
        }
        Response::BlobPushed { digest, bytes } => {
            if *json {
                print_registry_push_json(&response, digest, *bytes);
            } else {
                println!("blob {digest} pushed ({bytes} bytes)");
            }
            Ok(())
        }
        // Every refusal and every unexpected answer goes here, which is what
        // keeps "the registry said no" distinguishable from "I did not
        // understand the answer".
        other => report_registry_refusal(other, *json),
    }
}

/// The `asv.agent/v1` envelope for a write. The address is the whole answer and
/// the bytes are already at the registry, so the envelope carries the count and
/// not the content — the same shape `run_registry` uses for a read, mirrored.
fn print_registry_push_json(response: &Response, digest: &str, bytes: usize) {
    let mut data = match ipc::from_response(response) {
        ipc::ApplicationResult::Ok { data, .. } => data,
        _ => serde_json::json!({}),
    };
    data["digest"] = serde_json::json!(digest);
    data["bytes"] = serde_json::json!(bytes);
    println!(
        "{}",
        render::json::envelope(&render::json::for_result(&ipc::ApplicationResult::Ok {
            summary: format!("{bytes} byte(s) pushed as {digest}"),
            data,
        }))
    );
}

/// The content address of `bytes`, in the `sha256:<hex>` spelling the registry
/// protocol uses.
///
/// Written out rather than reused from `asv-connector-http`, which the CLI
/// deliberately does not depend on: the CLI is a client, and pulling a transport
/// crate in to hash a file would invert the dependency the whole broker is
/// built around. The two spellings are the same convention, and the broker
/// parses what this produces with `ContentDigest::parse`.
fn content_digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

fn run_oauth2(socket: &std::path::Path, command: &Oauth2Command) -> std::io::Result<()> {
    let Oauth2Command::Whoami { credential, json } = command;

    // Validated before a session exists, for the reason `run_aws` does it: a
    // malformed id would be accepted here and then miss in the broker, and the
    // operator would be told a credential does not exist.
    if CredentialId::from_wire(credential).is_err() {
        eprintln!("asv: the --credential value is not a vault id; copy it from `asv credentials`");
        std::process::exit(2);
    }

    let session = match github_call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv oauth2 could not open a session: {other:?}"
            )))
        }
    };

    let response = github_call(
        socket,
        &Request::OAuth2Identity {
            session,
            credential: credential.clone(),
        },
    );

    // Ended before the answer is reported, for the reason `run_aws` gives: a
    // report that never arrives is still bounded by the session's own lifetime.
    let _ = call(socket, &Request::EndSession { session });

    match &response {
        Response::OAuth2Identity {
            resource,
            scope,
            audience,
        } => {
            if *json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                println!("resource: {resource}");
                println!("scope:    {scope}");
                println!("audience: {audience}");
            }
            Ok(())
        }
        Response::Error { code, message } => {
            if *json {
                let result = ipc::from_response(&response);
                println!(
                    "{}",
                    render::json::envelope(&render::json::for_result(&result))
                );
            } else {
                eprintln!("asv oauth2 refused ({code:?}): {message}");
            }
            // Exit 1, distinct from a connection failure (2), for the reason the
            // AWS and GitHub verbs document it: "the broker said no" and "there
            // was no broker" are different events and a script must not retry
            // both alike. The scope-mismatch case lands here, and it is the one
            // worth reading: it means the identity provider and
            // `--oauth2-clients` have drifted apart.
            std::process::exit(1);
        }
        other => Err(std::io::Error::other(format!(
            "asv oauth2 got an unexpected answer: {other:?}"
        ))),
    }
}

/// Dials the broker, or reports the failure the way every other verb does.
///
/// A connection failure is exit 2 and the `ASV_CONNECTION_FAILED` line, not a
/// `Response::Error` and not exit 1. Three reasons, and the first is the one
/// that matters: "there was no broker" and "the broker refused" are different
/// events, and a script that retries one must not retry the other.
///
/// The other two are consistency. Returning the `io::Error` up to `main`
/// prints Rust's own `Debug` for it — `Error: Os { code: 2, kind: NotFound … }`
/// — which is not a diagnostic a user can act on, and `main`'s error exit is
/// 1, which is the code the refusal path below uses. The first draft of this
/// function did exactly that, and both mistakes were visible only by running
/// the binary.
fn github_call(socket: &std::path::Path, request: &Request) -> Response {
    // Named for the first caller, and now used by `asv aws` too. Renaming it
    // would touch the GitHub path for a cosmetic reason, and the behaviour it
    // implements -- exit 2 and `ASV_CONNECTION_FAILED` on a transport failure,
    // never a `Response::Error` -- is the verb-agnostic contract every call
    // site already depends on.
    match call(socket, request) {
        Ok(response) => response,
        Err(error) => {
            eprintln!("ASV_CONNECTION_FAILED: {error}");
            std::process::exit(2);
        }
    }
}

/// The `--credential` this invocation names, or a hard error naming which
/// subcommand was wrong.
///
/// The three verbs all require it, so an `Option` here would mean a second
/// code path where it is absent. It is not reachable: `clap` requires the flag
/// on every variant — which is a property the pin test in `relations.rs`
/// re-checks against the real parser rather than trusting.
fn github_credential_arg(command: &GithubCommand) -> &str {
    match command {
        GithubCommand::Issue(GithubIssueCommand::View { credential, .. })
        | GithubCommand::Issue(GithubIssueCommand::Create { credential, .. })
        | GithubCommand::Release(GithubReleaseCommand::Create { credential, .. }) => credential,
    }
}

/// The `--body` this invocation names, or `None` for the read verb.
fn github_body_arg(command: &GithubCommand) -> Option<&str> {
    match command {
        GithubCommand::Issue(GithubIssueCommand::View { .. }) => None,
        GithubCommand::Issue(GithubIssueCommand::Create { body, .. })
        | GithubCommand::Release(GithubReleaseCommand::Create { body, .. }) => Some(body),
    }
}

/// Whether this invocation asked for the machine envelope.
fn github_json_flag(command: &GithubCommand) -> bool {
    match command {
        GithubCommand::Issue(GithubIssueCommand::View { json, .. })
        | GithubCommand::Issue(GithubIssueCommand::Create { json, .. })
        | GithubCommand::Release(GithubReleaseCommand::Create { json, .. }) => *json,
    }
}

/// The IPC request for this verb.
///
/// A `read` sends no body at all, rather than an empty one. The wire types
/// differ — `ReadIssue` has no `body` field — so a shared request with an
/// optional body would be a type that means "either", and the broker would
/// have to decide what a missing body is. Naming three constructions keeps the
/// three shapes the protocol actually has.
fn github_request(
    command: &GithubCommand,
    session: asv_domain::AgentSessionId,
    surrogate: &str,
    body: &str,
) -> Request {
    match command {
        GithubCommand::Issue(GithubIssueCommand::View { repo, number, .. }) => Request::ReadIssue {
            session,
            surrogate: surrogate.to_string(),
            repo: repo.clone(),
            number: *number,
        },
        GithubCommand::Issue(GithubIssueCommand::Create { repo, title, .. }) => {
            Request::CreateIssue {
                session,
                surrogate: surrogate.to_string(),
                repo: repo.clone(),
                title: title.clone(),
                body: body.to_string(),
            }
        }
        GithubCommand::Release(GithubReleaseCommand::Create {
            repo, tag, name, ..
        }) => Request::CreateRelease {
            session,
            surrogate: surrogate.to_string(),
            repo: repo.clone(),
            tag: tag.clone(),
            name: name.clone(),
            body: body.to_string(),
        },
    }
}

/// Reads a body from a file, or from stdin when the spec is `-`.
///
/// A path is the honest interface for these two fields: both are routinely
/// multi-paragraph, and `argv` is world-readable to any same-uid peer through
/// `/proc/<pid>/cmdline`. `-` is there because the other way to supply a body
/// interactively is a shell heredoc, and a heredoc that a caller forgets is a
/// body that silently is not what they meant.
fn read_github_body(spec: &str) -> std::io::Result<String> {
    if spec == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut text)?;
        return Ok(text);
    }
    std::fs::read_to_string(spec)
}

fn run_command(socket: &std::path::Path, command: Vec<String>) -> std::io::Result<()> {
    let Some(program) = command.first() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "asv run requires a command",
        ));
    };

    let session = match call(
        socket,
        &Request::CreateSession {
            workspace: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        },
    )? {
        Response::SessionCreated {
            session,
            surrogates,
        } => (session, surrogates),
        other => {
            return Err(std::io::Error::other(format!(
                "asv run could not open a session: {other:?}"
            )))
        }
    };

    // The session's surrogates, one per authorized route (C2.7-D).
    //
    // These are what make a tunnel actually substitute: the CONNECT path
    // redeems a surrogate per tunnel, so a session that opened without one
    // authenticates, authorizes, terminates TLS and then refuses — every time,
    // naming neither the child nor the route. A surrogate is a bearer token
    // and not a secret, which is why an environment variable is defensible
    // here: the value a child must never see is the credential, and that never
    // leaves the broker.
    let (session, session_surrogates) = session;

    let session_dir = std::env::temp_dir().join(format!(
        "asv-session-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let agent = asv_ssh_agent::AgentSession::start(&session_dir)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Bind the agent's public key to the session just opened. Without this
    // the bridge has nothing to verify a CONNECT proof against, and a
    // session with no key is a session a CONNECT client can never be
    // resolved to. Failing here means no child, which is the point: the
    // alternative is a child that believes it is in a session it is not.
    match call(
        socket,
        &Request::RegisterSessionKey {
            session,
            public_key_blob: agent.public_key_blob(),
        },
    )? {
        Response::SessionKeyRegistered { .. } => {}
        other => {
            return Err(std::io::Error::other(format!(
                "asv run could not bind the session key: {other:?}"
            )))
        }
    }

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    for name in QUARANTINED_ENV_NAMES {
        child.env_remove(name);
    }
    for grant in &session_surrogates {
        child.env(
            format!("ASV_SURROGATE_{}", env_name_for_label(&grant.label)),
            &grant.token,
        );
    }
    child
        .env("SSH_AUTH_SOCK", agent.socket_path())
        .env("ASV_SESSION_ID", session.to_string())
        .env("ASV_SESSION_MODE", "strict");

    // C2.7: the session-local shim — the "last inch" the roadmap recorded as
    // missing. Everything above this line mints the material a CONNECT proof
    // needs; nothing pointed a client at the thing that uses it. So a session
    // could prove who it was and had no way to say so to `curl`.
    //
    // The shim is started here rather than by the child because it owns the
    // session's *only* counter. Three children of one `asv run` each minting
    // their own would present 1, 1, 1 and the second would be refused as a
    // replay of the first — indistinguishable from an attack. One shim per
    // session is the only shape where the counter means anything.
    let shim = start_session_shim(socket, &agent);

    if let Some(handle) = shim.as_ref() {
        let url = format!("http://{}", handle.local_addr());
        {
            // Only the variables that produce a CONNECT. `HTTP_PROXY` is
            // deliberately not set: it makes a client send a plain proxy
            // request, the shim refuses anything that is not a CONNECT, and the
            // result would be a mysterious failure for a request the broker
            // was never going to see. Plain HTTP to an external host is outside
            // the CONNECT path entirely and is recorded as owed, not papered
            // over here.
            for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
                child.env(name, &url);
            }
            // An inherited `NO_PROXY` is a bypass, not a preference: a parent
            // that named a destination there would make the child connect to
            // it directly, with no CONNECT, no proof and no substitution. The
            // whole path is defeated by one inherited variable, so it is
            // cleared rather than merged.
            for name in ["NO_PROXY", "no_proxy"] {
                child.env_remove(name);
            }
        }
    }

    // Spawn failures stop the shim on the way out, not just the normal exit.
    // A child that never ran is exactly when a `?` would have returned with a
    // bound loopback port and a live issuer still attached to it.
    let status = match child.status() {
        Ok(status) => status,
        Err(e) => {
            if let Some(handle) = shim {
                handle.stop();
            }
            return Err(e);
        }
    };

    // Stop the shim before the session ends. A shim that outlived the command
    // would keep its loopback port bound and its proof issuer alive for a
    // session that no longer exists — and a proof minted after that would
    // resolve to nothing, which reads as a broken signer.
    if let Some(handle) = shim {
        handle.stop();
    }
    // The session is closed before the agent is dropped, so a child that
    // outlived its own command cannot keep redeeming surrogates against a
    // session the operator believes has ended.
    let _ = call(socket, &Request::EndSession { session });
    drop(agent); // revoke and remove the socket before returning to the shell
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    Err(std::io::Error::other("child terminated by signal"))
}

/// Reads the credential an operator typed, stripping exactly one newline.
///
/// Split out of the `add-credential` arm so the newline rule can be exercised
/// without a process, a socket or a vault, and so the return type can be named
/// by a row: the buffer is an [`OpaqueSecret`], which zeroizes on drop, and a
/// caller that wanted a `String` back could not bind this.
///
/// The newline rule is the interesting part and it is not "strip trailing
/// whitespace". `echo secret |` produces one `\n` and the obvious use of this
/// command is `echo secret |`, so a stored trailing newline would be a
/// credential that silently never works. Exactly one: a secret that genuinely
/// ends in a newline keeps it, because a rule that strips them all is a rule
/// that corrupts data.
fn read_credential(input: &mut impl std::io::Read) -> std::io::Result<OpaqueSecret> {
    let mut secret = zeroize::Zeroizing::new(String::new());
    std::io::Read::read_to_string(input, &mut secret)?;
    if secret.ends_with('\n') {
        secret.pop();
    }
    Ok(OpaqueSecret::new(std::mem::take(&mut *secret).into_bytes()))
}

/// The serialized request, in a buffer that zeroizes when it is dropped.
///
/// The return type is the property, and it is why this is a function rather than
/// an inline `serde_json::to_vec`. `asv add-credential` serializes an
/// `OpaqueSecret`, whose `Serialize` impl writes the bytes verbatim because the
/// protocol requires the secret on the wire. Every other buffer on this path is
/// careful about that secret; this one held it in a plain `Vec<u8>` that went
/// straight back to the allocator.
fn encode(request: &Request) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(zeroize::Zeroizing::new(
        serde_json::to_vec(request).map_err(|e| std::io::Error::other(e.to_string()))?,
    ))
}

fn call(socket: &std::path::Path, request: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;

    // Both buffers are `Zeroizing`, and that is the whole of the fix.
    //
    // The request buffer holds a credential for exactly one command:
    // `asv add-credential` serializes an `OpaqueSecret`, whose `Serialize` impl
    // writes the bytes out verbatim, because the protocol requires the secret on
    // the wire. Everything else about that type is careful — it is a
    // `Zeroizing<Vec<u8>>` inside, and it redacts its own `Debug` — and the one
    // buffer that actually carries the plaintext is this one, which was a plain
    // `Vec<u8>` handed straight back to the allocator.
    //
    // The response buffer is zeroized on the way out even though no response is
    // supposed to carry a secret, and the reason is that zeroing it *by hand* on
    // the success path would be skipped by every `return` above. A defence
    // wired to one exit path is a defence that quietly stops being one. The
    // whole 64 KiB is cleared rather than just the `n` bytes read, because
    // selecting the used region is exactly the kind of arithmetic that is right
    // until it is not, and 64 KiB is not a cost worth optimising here.
    let payload = encode(request)?;
    if payload.len() > asv_ipc_protocol::MAX_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request exceeds the protocol size limit",
        ));
    }
    stream.write_all(&payload)?;
    stream.flush()?;

    let mut buf = zeroize::Zeroizing::new(vec![0u8; asv_ipc_protocol::MAX_MESSAGE_BYTES]);
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "broker closed the connection without responding",
        ));
    }
    serde_json::from_slice(&buf[..n]).map_err(|e| std::io::Error::other(e.to_string()))
}

fn print_response(response: &Response) {
    match response {
        // Registry reads carry bytes, not text: a manifest is JSON in practice
        // but nothing promises it, and a blob is never text at all. So these
        // report the **digest and the length** and not the body, which is also
        // what an operator needs -- they want to confirm the digest, not read
        // an image through a pager.
        Response::ManifestRead {
            body,
            digest,
            media_type,
        } => {
            println!("manifest {digest} ({} bytes)", body.len());
            if let Some(media_type) = media_type {
                println!("  media type: {media_type}");
            }
        }
        Response::BlobRead { bytes, digest } => {
            println!("blob {digest} ({} bytes)", bytes.len());
        }
        // Registry pushes report the address and the count. The bytes are
        // already at the registry and already on disk here; what an operator
        // needs back is the digest to pin, not the content echoed a second
        // time. Same reason as the read arms above.
        Response::ManifestPushed {
            reference,
            digest,
            bytes,
        } => {
            println!("manifest {reference} pushed as {digest} ({bytes} bytes)");
        }
        Response::BlobPushed { digest, bytes } => {
            println!("blob {digest} pushed ({bytes} bytes)");
        }
        // Not reached from `asv aws whoami`, which renders these three itself so
        // it can label them. Present because the match is exhaustive on purpose:
        // an unhandled response must be a compile error, not a silent blank line
        // to an operator who has just asked AWS a question.
        Response::AwsCallerIdentity {
            arn,
            user_id,
            account,
        } => {
            println!("arn:     {arn}");
            println!("user_id: {user_id}");
            println!("account: {account}");
        }
        // Not reached from `asv oauth2 whoami`, which renders these three itself
        // for the same reason the AWS arm is above. Present because the match is
        // exhaustive on purpose: an unhandled response must be a compile error,
        // not a silent blank line to an operator who has just asked an identity
        // provider a question.
        Response::OAuth2Identity {
            resource,
            scope,
            audience,
        } => {
            println!("resource: {resource}");
            println!("scope:    {scope}");
            println!("audience: {audience}");
        }
        Response::Pong { protocol } => {
            println!("broker reachable, protocol v{protocol}");
        }
        // The compatibility path (ADR-0008), printed with its posture on the
        // same line as the result. A caller reading only the exit code of a
        // run that touched a real credential would otherwise have no way to
        // learn it was on the weaker of the two paths, and the default
        // assumption for anyone who did not ask is the stronger one.
        Response::IsolatedResult {
            worker,
            outcome,
            exit_code,
            stdout,
            stderr,
            duration_ms,
            posture,
        } => {
            println!(
                "{worker}: {outcome} ({}, {duration_ms}ms, {posture})",
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into())
            );
            if !stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(stdout));
            }
            if !stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(stderr));
            }
        }
        // The broker's self-description. Every field here was already
        // obtainable by asking, which is what makes printing it safe: nothing
        // here is derived from a session, a credential, or a workspace. The
        // flags are booleans about the answering process's own hardening, and
        // a caller that could not have learned them by asking would have had
        // to read /proc/<pid>/status of a process it is not allowed to debug.
        Response::BrokerInfo {
            product_version,
            dumpable_disabled,
            landlock_installed,
            seccomp_installed,
            no_new_privs,
            ..
        } => {
            println!("broker {product_version} (protocol {PROTOCOL_VERSION})");
            println!(
                "  dumpable disabled: {dumpable_disabled}   no_new_privs: {no_new_privs}   \
                 landlock: {landlock_installed}   seccomp: {seccomp_installed}"
            );
        }
        Response::SessionCreated {
            session,
            surrogates,
        } => {
            println!("session {session} created");
            // The surrogates are named but not printed. A session that opened
            // silently carrying tokens is a session an operator cannot account
            // for, and one that prints them is a session that has put bearer
            // tokens in a terminal scrollback.
            for grant in surrogates.iter() {
                println!(
                    "  surrogate for {} -> {} ({} uses left)",
                    grant.label, grant.destination, grant.max_uses
                );
            }
        }
        // Reached only if a caller prints the response directly. `asv run`
        // consumes this one itself and never reaches here.
        Response::SessionKeyRegistered { session } => {
            println!("session {session} key registered");
        }
        Response::SessionEnded { session } => {
            println!("session {session} ended");
        }
        Response::CredentialMetadata { entries } => {
            if entries.is_empty() {
                println!("no credentials stored");
                return;
            }
            println!("{:<38} {:<20} LABEL", "ID", "KIND");
            for e in entries {
                println!(
                    "{:<38} {:<20} {}",
                    e.id,
                    format!("{:?}", e.kind).to_lowercase(),
                    e.label
                );
            }
        }
        Response::CredentialDeleted { id } => println!("credential {id} deleted"),
        Response::CredentialCreated { id, label } => {
            // The id and the label the operator supplied. Never the secret: it
            // was read from stdin, sent once, and is not echoed back by a
            // command whose whole output is meant to be safe to paste.
            println!("credential {id} created ({label})");
        }
        Response::Authorization { explanation } => {
            println!(
                "authorization: {:?} ({:?})",
                explanation.decision, explanation.reason
            );
        }
        Response::ApprovalIssued { approval } => {
            println!("approval {} issued for {:?}", approval.id, approval.action);
        }
        Response::SurrogateMinted {
            surrogate,
            expires_at,
            max_uses,
        } => {
            // The token itself is the one thing a terminal must not echo into
            // a scrollback buffer that survives the session. Its budget and
            // lifetime are safe, and are what an operator actually needs.
            let _ = surrogate;
            println!("surrogate minted: {max_uses} use(s), expires at {expires_at}");
        }
        Response::SurrogateRevoked { .. } => {
            println!("surrogate revoked");
        }
        // The body is printed, and it is printed *after* the header. The
        // response carries it on purpose — `IssueRead` promises title, body and
        // state and nothing else — and the arm that used to be here matched
        // `{ title, state, .. }` and dropped it. So the one field a human
        // opened this command to read was the one the command threw away, and
        // `asv github issue view` was an elaborate way to print a title.
        //
        // Header first, so `| head -1` yields the state and not a wall of
        // prose, and the body is skipped when GitHub answered `"body": null`
        // rather than printing a blank line that looks like an empty issue.
        Response::IssueRead { title, body, state } => {
            println!("{title} [{state}]");
            if !body.is_empty() {
                println!("{body}");
            }
        }
        Response::IssueCreated { number, url } => {
            println!("issue {number} created: {url}");
        }
        Response::ReleaseCreated { tag, url } => {
            println!("release {tag} created: {url}");
        }
        Response::AuditRecords {
            records,
            chain_head,
            dropped,
        } => {
            if records.is_empty() {
                println!("no audit records in range");
            } else {
                println!("{:<6} {:<12} {:<22} TS", "SEQ", "OUTCOME", "METHOD");
                for r in records {
                    // Read the fields directly. Formatting them into one string
                    // and splitting on the first space corrupted any method or
                    // worker name containing a space (a worker literally named
                    // "sh -c" rendered as method="worker:sh", outcome="-c").
                    let (method, outcome) = match &r.event {
                        asv_ipc_protocol::AuditEventDto::RequestHandled {
                            method, outcome, ..
                        } => (method.clone(), outcome.clone()),
                        asv_ipc_protocol::AuditEventDto::WorkerSpawned {
                            worker, outcome, ..
                        } => (format!("worker:{worker}"), outcome.clone()),
                        // ADR-0019. A substitution is not a verb the agent
                        // invoked, so it has no method name; the destination is
                        // what an operator reads here. Rendering the session
                        // would be the more useful column in a different
                        // view, and this one has three.
                        asv_ipc_protocol::AuditEventDto::CredentialSubstituted {
                            destination,
                            outcome,
                            ..
                        } => (format!("connect:{destination}"), outcome.clone()),
                        // The connection, not the credential. Same reasoning as
                        // the substitution above and the same prefix, so the
                        // two kinds of proxy record are distinguishable in this
                        // three-column view by the `detail` that rides in the
                        // outcome — a refusal names its class there, which is
                        // what an operator scanning for "what is being refused"
                        // actually needs and the only place it appears.
                        asv_ipc_protocol::AuditEventDto::ConnectHandled {
                            destination,
                            outcome,
                            detail,
                            ..
                        } => (
                            if destination.is_empty() {
                                "connect:<no destination>".to_string()
                            } else {
                                format!("connect:{destination}")
                            },
                            format!("{outcome}:{detail}"),
                        ),
                    };
                    println!("{:<6} {:<12} {:<22} {}", r.seq, outcome, method, r.ts);
                }
            }
            if *dropped > 0 {
                println!("{dropped} older record(s) evicted by retention");
            }
            println!("chain head: {chain_head}");
        }
        Response::PostgresConnected {
            session,
            database,
            role,
        } => {
            println!("postgres session {session} open on {database} as {role}");
        }
        Response::PostgresResult { row_count, rows } => {
            for row in rows {
                println!("{row}");
            }
            eprintln!("({row_count} row(s))");
        }
        Response::PostgresRevoked {
            session,
            backend_terminated,
        } => {
            // The two facts an operator needs are separate: the broker let go,
            // and the server confirmed the backend is gone. Printing them as
            // one "revoked" line would hide which of the two actually happened.
            println!("postgres session {session} revoked");
            if !backend_terminated {
                eprintln!("warning: broker did not observe server-side backend termination");
            }
        }
        Response::Error { code, message } => {
            // `code` is the stable, scriptable part; `message` is for humans.
            eprintln!("{code:?}: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI's whole reason to exist is that it cannot retrieve a secret.
    /// There is no subcommand that could, and the error path cannot smuggle
    /// one out either.
    #[test]
    fn no_subcommand_exposes_a_secret() {
        let rendered = cli_definition();
        let lowered = rendered.to_lowercase();
        for forbidden in [
            "get_secret",
            "export_secret",
            "show_secret",
            "reveal",
            "password",
            "token",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "CLI surface references `{forbidden}`: {rendered}"
            );
        }
    }

    /// A human-readable rendering of the parser, used as the oracle above.
    /// `clap` builds this from the same `Parser` impl the binary uses, so the
    /// test cannot drift from the real surface.
    ///
    /// `render_long_help`, and this detail is load-bearing rather than
    /// cosmetic. `Command::to_string()` is `Display`, which renders the
    /// command's *name* — for this binary the single string `"asv"`. An
    /// assertion over that string cannot fail for any reason except the
    /// program being renamed, so the test that checks no subcommand exposes a
    /// secret was checking one word against six forbidden ones and passing
    /// vacuously. The help text is the actual surface, and that is what is
    /// read here.
    fn cli_definition() -> String {
        use clap::CommandFactory;
        Cli::command().render_long_help().to_string()
    }

    #[test]
    fn request_encoding_stays_within_the_protocol_bound() {
        let req = Request::CreateSession {
            workspace: "/home/user/project".into(),
        };
        let bytes = serde_json::to_vec(&req).expect("serializes");
        assert!(bytes.len() < asv_ipc_protocol::MAX_MESSAGE_BYTES);
    }

    /// A revocation is only reachable if the operator has a verb for it. The
    /// broker accepting the request is not the same as a human being able to
    /// ask, and this cycle exists because a capability with no door was
    /// mistaken for a finished one.
    #[test]
    fn the_operator_has_a_revocation_verb() {
        let rendered = cli_definition();
        assert!(
            rendered.contains("delete-credential"),
            "no verb can revoke a credential: {rendered}"
        );
    }

    /// The id has to arrive in the spelling the vault is keyed by. A valid
    /// UUID in any other spelling — uppercase, braced, unhyphenated — parses
    /// as a UUID and misses in the vault, so the operator would be told the
    /// credential does not exist and would have no way to tell that from a real
    /// answer. Rejecting here is what makes that failure impossible.
    #[test]
    fn a_revocation_id_must_be_canonically_spelled() {
        let canonical = "0f8fad5b-d9cb-469f-a165-70867728950e";
        assert!(
            CredentialId::from_wire(canonical).is_ok(),
            "the canonical form"
        );

        for wrong in [
            "0F8FAD5B-D9CB-469F-A165-70867728950E",   // uppercase
            "{0f8fad5b-d9cb-469f-a165-70867728950e}", // braced
            "0f8fad5bd9cb469fa16570867728950e",       // unhyphenated
            "not-a-uuid",
        ] {
            assert!(
                CredentialId::from_wire(wrong).is_err(),
                "this spelling would miss in the vault: {wrong}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // The two buffers that actually hold a credential on this process.
    //
    // Every other secret path in the product is careful: `OpaqueSecret` is a
    // `Zeroizing<Vec<u8>>` and redacts its own `Debug`, the AWS session token
    // is documented as a plain `String` on the wire, and the broker's responses
    // have no field one could occupy. These two are the client-side remainder,
    // and they were not careful: `add-credential` made two unzeroized copies of
    // what the operator typed, and the buffer the serialized request went into
    // was a plain `Vec<u8>` handed straight back to the allocator.
    //
    // The exposure is bounded and the rows below should not oversell it: `asv`
    // is a short-lived process, so the heap dies with it. What a long-running
    // mode, a core dump or swap would inherit is the reason this is worth
    // fixing now rather than when someone adds that mode.
    // ---------------------------------------------------------------------

    /// The serialized request comes back in a buffer that zeroizes itself.
    ///
    /// The type annotation is the assertion. `encode` is declared as returning
    /// `zeroize::Zeroizing<Vec<u8>>`, so binding it to a plain `Vec<u8>` does
    /// not compile — which is what makes this property structural rather than
    /// a claim a future edit can quietly undo, and it is why `encode` is a
    /// function instead of an inline `serde_json::to_vec`.
    #[test]
    fn the_serialized_request_lives_in_a_buffer_that_zeroizes() {
        let request = Request::CreateCredential {
            label: "example".into(),
            kind: asv_domain::CredentialKind::ApiKey,
            provider: "example".into(),
            account: "example".into(),
            secret: OpaqueSecret::new(b"the-secret-value".to_vec()),
        };
        let payload: zeroize::Zeroizing<Vec<u8>> = encode(&request).expect("encodes");
        assert!(
            payload.windows(6).any(|w| w == b"secret"),
            "the wire form must carry the secret: this is the one request where \
             the buffer below is the only copy of it on this process"
        );
    }

    /// The credential the operator typed is read into a type that zeroizes.
    ///
    /// As above, the annotation is the assertion: a `read_credential` that
    /// returned a `String` could not be bound here.
    #[test]
    fn the_typed_credential_is_read_into_a_buffer_that_zeroizes() {
        let secret: OpaqueSecret = read_credential(&mut b"hunter2".as_slice()).expect("reads");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// The newline a shell adds is not part of the credential.
    ///
    /// `echo secret | asv add-credential` is the obvious invocation, and
    /// storing the trailing newline would be a credential that silently never
    /// works against any provider.
    #[test]
    fn a_trailing_newline_is_not_part_of_the_credential() {
        let secret = read_credential(&mut b"hunter2\n".as_slice()).expect("reads");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// Exactly one. A secret that genuinely ends in a newline keeps it, because
    /// a rule that strips them all is a rule that corrupts data.
    #[test]
    fn only_one_trailing_newline_is_stripped() {
        let secret = read_credential(&mut b"hunter2\n\n".as_slice()).expect("reads");
        assert_eq!(secret.expose(), b"hunter2\n");
    }

    /// A credential with no newline at all is stored whole — the stripping is
    /// not a decode that assumes a shell was involved.
    #[test]
    fn a_credential_with_no_newline_is_stored_whole() {
        let secret = read_credential(&mut b"hunter2".as_slice()).expect("reads");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// Empty input is refused at the call site, and the refusal is about the
    /// emptiness rather than about the read having failed.
    #[test]
    fn a_bare_newline_reads_as_empty() {
        let secret = read_credential(&mut b"\n".as_slice()).expect("reads");
        assert!(
            secret.expose().is_empty(),
            "a lone newline must leave nothing, or `echo | asv add-credential` \
             would store an empty credential rather than refusing"
        );
    }

    /// Leading whitespace is part of the credential.
    ///
    /// This row replaces one that could not fail. The first version here
    /// asserted "the credential is held by a type that owns one allocation",
    /// which read as if it held the *copy count* of the buffer — and it could
    /// not: replacing the `mem::take` with a `to_string()` produces the same
    /// bytes through the same type and the row stays green. A copy is invisible
    /// at runtime, so a row cannot hold that property and pretending one does
    /// is how an unfalsifiable assertion gets to look like evidence.
    ///
    /// The copy count is therefore a source property, held by there being one
    /// `mem::take` between stdin and `OpaqueSecret`, and it is recorded as a
    /// survivor in `cli_buffers_falsify.py` rather than dressed up as a test.
    /// What *is* observable is the newline rule, and this row is the half of it
    /// the first version missed: a `trim()` would pass every other row here,
    /// because none of them begin with a space.
    #[test]
    fn a_leading_space_is_part_of_the_credential() {
        let secret = read_credential(&mut b"  hunter2\n".as_slice()).expect("reads");
        assert_eq!(
            secret.expose(),
            b"  hunter2",
            "only the newline a shell appends is stripped; a credential may \
             legitimately begin with whitespace and `trim()` would corrupt it"
        );
    }
}

/// R3's `adopt`: move one selector's value into the vault.
///
/// **Every buffer this touches is one the secret path already had.** The file
/// is read into a `Zeroizing<String>`, the selector's value leaves it as a
/// `secrecy::SecretString`, the request is built with an `OpaqueSecret` that
/// takes the allocation rather than copying it, and `encode` returns a
/// `Zeroizing<Vec<u8>>`. Nothing here adds a copy of the credential, and there
/// is no branch on which the value is printed: the only things this function
/// writes are the credential's **id** and what is still outstanding.
///
/// The decision about *what* moves was made before this function was called —
/// by the operator, naming an audience and a field — so the moment the value
/// exists in this process there is no longer a question of which credential to
/// take. That ordering is the whole of the safety argument, and it is why
/// `NpmAdoption::extract` takes a selector rather than returning candidates.
fn run_integrations_adopt(
    socket: &std::path::Path,
    family: &str,
    json: bool,
    file: Option<&str>,
    home: Option<&str>,
    audience: &str,
    field: &str,
    label: &str,
    allow_symlink_root: Option<&str>,
    from_plan: Option<&str>,
) -> std::io::Result<()> {
    use asv_integrations::{AdoptReceipt, AdoptSelector, NpmAdoption};

    if family != "npm" {
        eprintln!(
            "asv: no adapter for {family:?}; this build knows `npm`. Adding one is a module in \
             asv-integrations and one match arm here."
        );
        std::process::exit(1);
    }

    // The field arrives as the operator typed it, and is matched against npm's
    // own spelling by `Display`. An unknown spelling is refused here rather
    // than becoming a selector that silently matches nothing.
    let auth_field = match field {
        "_authToken" => asv_integrations::npm::AuthField::AuthToken,
        "_auth" => asv_integrations::npm::AuthField::Auth,
        "username" => asv_integrations::npm::AuthField::Username,
        "_password" => asv_integrations::npm::AuthField::Password,
        other => {
            eprintln!(
                "asv: {other:?} is not an npm auth field this build knows; expected one of \
                 _authToken, _auth, username or _password"
            );
            std::process::exit(2);
        }
    };

    let path = match file {
        Some(file) => std::path::PathBuf::from(file),
        None => {
            let home = match home {
                Some(home) => std::path::PathBuf::from(home),
                None => match std::env::var_os("HOME") {
                    Some(home) => std::path::PathBuf::from(home),
                    None => {
                        eprintln!("asv: HOME is not set, so the configuration cannot be located; pass --file or --home");
                        std::process::exit(2);
                    }
                },
            };
            home.join(".npmrc")
        }
    };

    let mut policy = asv_integrations::FingerprintPolicy::strict();
    if let Some(root) = allow_symlink_root {
        policy = policy.allowing_symlink_root(root);
    }

    // **The fingerprint this import is checked against comes from the plan, not
    // from the file it is about to read.** Computing it here and handing it
    // straight to `extract` would compare the file against itself: it would
    // catch a concurrent edit during the command and nothing else, and §6's
    // "changed since you planned" would be unreachable from the product. With
    // `--from-plan` the identity is the one the operator acted on, and the
    // refusal is reachable.
    let planned = match from_plan {
        Some(plan_path) => match planned_fingerprint(plan_path, &path, audience, &auth_field) {
            Ok(fingerprint) => Some(fingerprint),
            Err(message) => {
                eprintln!("asv: {message}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    if planned.is_none() {
        eprintln!(
            "asv: no --from-plan, so this import cannot tell a configuration that changed since \
             you planned from one that did not. Pass the `asv integrations plan npm --json` output \
             this import answers."
        );
        std::process::exit(2);
    }
    let expected = planned.expect("checked above");

    let selector = AdoptSelector {
        file: path.to_string_lossy().into_owned(),
        audience: audience.to_string(),
        field: auth_field.clone(),
    };

    let value = match NpmAdoption::extract(&policy, &path, &selector, &expected) {
        Ok(value) => value,
        Err(error) => {
            if json {
                let failure = serde_json::json!({
                    "schema": asv_integrations::ADOPT_SCHEMA,
                    "family": family,
                    "error": error.to_string(),
                    "kind": adopt_error_kind(&error),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&failure).unwrap_or_default()
                );
            } else {
                eprintln!("asv: {error}");
            }
            std::process::exit(1);
        }
    };

    // The one allocation the operator's credential occupies from here on. Taken
    // rather than copied, so there is no second copy for a later edit to have
    // forgotten about.
    let secret = OpaqueSecret::new(
        secrecy::ExposeSecret::expose_secret(&value)
            .as_bytes()
            .to_vec(),
    );
    drop(value);

    let response = call(
        socket,
        &Request::CreateCredential {
            label: label.to_string(),
            // A registry token is a bearer token as far as the vault is
            // concerned; the registry it is for is the binding's business, and
            // `plan` is where that is recorded.
            kind: asv_domain::CredentialKind::BearerToken,
            provider: "npm".to_string(),
            account: audience.to_string(),
            secret,
        },
    );

    let id = match response {
        Ok(Response::CredentialCreated { id, .. }) => id,
        Ok(other) => {
            eprintln!(
                "asv: the broker answered {} to a credential creation; nothing was imported",
                response_kind(&other)
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("asv: could not reach the broker, so nothing was imported: {error}");
            std::process::exit(2);
        }
    };

    let receipt = AdoptReceipt::new(
        selector,
        id,
        label.to_string(),
        audience.to_string(),
        std::collections::BTreeSet::from([
            asv_integrations::Operation::Read,
            asv_integrations::Operation::Publish,
        ]),
        path.to_string_lossy().into_owned(),
        // Re-read after the import rather than reusing the plan's: the receipt
        // is evidence about the file as it is *now*, and reusing the plan's
        // fingerprint would make it evidence about a moment that has passed.
        match policy.fingerprint(&path) {
            Ok(fingerprint) => fingerprint,
            Err(_) => expected,
        },
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).expect("the receipt serialises")
        );
    } else {
        print_adopt_prose(&receipt);
    }
    Ok(())
}

/// A stable machine word per refusal, so a consumer can branch on the *reason*
/// without parsing prose — the JSON path carries it beside the message.
fn adopt_error_kind(error: &asv_integrations::AdoptError) -> &'static str {
    use asv_integrations::AdoptError;
    match error {
        AdoptError::ConfigChanged { .. } => "config_changed",
        AdoptError::Unreadable { .. } => "unreadable",
        AdoptError::AmbiguousLine { .. } => "ambiguous_line",
        AdoptError::NoSuchSelector { .. } => "no_such_selector",
        AdoptError::EnvReference { .. } => "env_reference",
        AdoptError::EmptyValue { .. } => "empty_value",
    }
}

/// The human form of an adopt receipt.
fn print_adopt_prose(receipt: &asv_integrations::AdoptReceipt) {
    println!(
        "imported {field} for {audience} into the vault",
        field = receipt.selector.field,
        audience = receipt.audience
    );
    println!("  credential: {} ({})", receipt.credential, receipt.label);
    println!(
        "  operations: {}",
        receipt
            .operations
            .iter()
            .map(|op| op.wire_name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
    println!("  {} was NOT modified.", receipt.source_file);
    println!("  It still contains the credential, and that is deliberate. Before it can be");
    println!("  scrubbed, doc 04 §10 requires:");
    for step in &receipt.outstanding {
        let text = match step {
            asv_integrations::PendingStep::VerifyVault => {
                "prove the credential is retrievable from the vault"
            }
            asv_integrations::PendingStep::VerifyNewIntegration => {
                "prove the new integration works"
            }
            asv_integrations::PendingStep::NegativeBypassTest => {
                "prove the old path no longer works"
            }
            asv_integrations::PendingStep::HumanApproval => {
                "a human decides to remove the original"
            }
            asv_integrations::PendingStep::ScrubAndRescan => "scrub, rescan, and write the receipt",
        };
        println!("    - {text}");
    }
}

/// The fingerprint a plan recorded for one selector.
///
/// Read from the plan rather than recomputed, because the whole value of §6 is
/// that the identity is the one the operator *acted on*. Re-deriving it here
/// would make the comparison a tautology.
fn planned_fingerprint(
    plan_path: &str,
    file: &std::path::Path,
    audience: &str,
    field: &asv_integrations::npm::AuthField,
) -> Result<asv_integrations::FileFingerprint, String> {
    let raw = std::fs::read_to_string(plan_path)
        .map_err(|error| format!("could not read the plan at {plan_path}: {error}"))?;
    let plan: asv_integrations::IntegrationPlan = serde_json::from_str(&raw).map_err(|error| {
        format!(
            "{plan_path} is not an {} document: {error}",
            asv_integrations::PLAN_SCHEMA
        )
    })?;
    let wanted = file.to_string_lossy();
    plan.entries
        .into_iter()
        .find(|entry| {
            entry.file.as_path() == file
                && matches!(
                    &entry.selector,
                    asv_integrations::Selector::Npm {
                        field: found,
                        audience: found_audience,
                        ..
                    } if found == field && found_audience == audience
                )
        })
        .map(|entry| entry.fingerprint)
        .ok_or_else(|| {
            format!(
                "the plan at {plan_path} has no entry for {audience} / {field} in {wanted}; \
                 re-run `asv integrations plan npm --json` and adopt from that"
            )
        })
}
/// Runs one `discover → intent → plan → authorize → execute` attempt and writes
/// a receipt.
///
/// **Six stages, and the order is the argument.** Each one takes the previous
/// one's output: the intent names the tool the plan must cover, the plan binds
/// to the intent, the broker authorizes what the intent asked for, and the
/// check compares the world *now* against what the plan promised earlier. A
/// stage that skipped its predecessor would make the chain a list of steps
/// rather than a chain, and the receipt would then be evidence of nothing.
///
/// The authorization goes over IPC to the broker. This function does not hold
/// a policy engine, does not evaluate Cedar, and must not grow either: a
/// second evaluator is a second authority.
///
/// The exit status is 0 only when the attempt actually executed. A refusal is
/// a refusal whether or not a receipt was written, so a caller that shells out
/// and checks `$?` cannot mistake "the receipt is in stdout" for "it ran".
#[allow(clippy::too_many_arguments)]
fn run_integrations_execute(
    socket: &std::path::Path,
    family: &str,
    json: bool,
    tool_command: &str,
    transaction: &str,
    principal: &str,
    actor: &str,
    origin: &str,
    ttl: u64,
    session: Option<&str>,
    workspace: &str,
    cwd: &str,
    home: Option<&str>,
    allow_symlink_root: Option<&str>,
    no_vault: bool,
) -> std::io::Result<()> {
    use asv_integrations::Adapter as _;

    let (home, _, policy) = integrations_home_and_policy(home, allow_symlink_root)?;
    let cwd_dir = std::path::PathBuf::from(cwd);

    // --- 0. what credentials exist ------------------------------------------
    // Before discovery, because the plan consumes it and the receipt has to
    // carry the plan. R4.B.1 shipped this as `Vec::new()`, which made every
    // receipt an authorization over a plan that named no credential — and
    // because the receipt did not carry the plan, nothing in the document said
    // so.
    let inventory: Vec<asv_domain::CredentialMetadata> = if no_vault {
        Vec::new()
    } else {
        match call(socket, &Request::ListCredentialMetadata) {
            Ok(Response::CredentialMetadata { entries }) => entries
                .into_iter()
                .map(|entry| asv_domain::CredentialMetadata {
                    id: asv_domain::CredentialId::from_uuid(entry.id),
                    label: entry.label,
                    kind: entry.kind,
                    exportability: entry.exportability,
                })
                .collect(),
            Ok(other) => {
                // Same reasoning as `plan`: a protocol that answered something
                // else has not told us what credentials exist, and executing
                // against "we did not ask" is executing against an invention.
                eprintln!(
                    "asv: the broker answered {} to a credential-inventory request; \
                     this command cannot execute against that",
                    response_kind(&other)
                );
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("asv: could not reach the broker for the credential inventory: {error}");
                eprintln!("    pass --no-vault to execute against an empty inventory and say so.");
                std::process::exit(1);
            }
        }
    };

    // --- 1. discover -------------------------------------------------------
    // The typed discovery, kept typed. Routing it through `into_discovery`
    // would erase which family produced it and force the plan stage to either
    // downcast or read the files a second time.
    enum Discovered {
        Npm(Box<asv_integrations::npm::NpmDiscovery>),
        Curl(Box<asv_integrations::curl::CurlDiscovery>),
    }
    let discovered = match family {
        "npm" => match asv_integrations::Npm.discover(&policy, &home, &cwd_dir) {
            Ok(discovery) => Discovered::Npm(Box::new(discovery)),
            Err(error) => {
                eprintln!("asv: discovery failed: {error}");
                std::process::exit(1);
            }
        },
        "curl" => match asv_integrations::Curl.discover(&policy, &home, &cwd_dir) {
            Ok(discovery) => Discovered::Curl(Box::new(discovery)),
            Err(error) => {
                eprintln!("asv: discovery failed: {error}");
                std::process::exit(1);
            }
        },
        other => {
            eprintln!(
                "asv: no execute path for {other:?}; this build knows `npm` and `curl`. \
                 Adding one is a module in asv-integrations, a `Selector` variant, and one \
                 match arm here."
            );
            std::process::exit(1);
        }
    };

    // --- 2. resolve the executable ------------------------------------------
    // Before the plan, because the plan records the tool *it* resolved and the
    // binding takes the plan's. Resolving afterwards would leave the plan with
    // nothing to bind.
    let path_var = std::env::var("PATH").unwrap_or_default();
    let planned_tool = match asv_integrations::resolve_tool(tool_command, &path_var) {
        Ok(resolution) => resolution,
        Err(error) => {
            eprintln!("asv: {error}");
            std::process::exit(1);
        }
    };
    if planned_tool.resolved.is_none() {
        // Refusing to continue is the point of a world-writable refusal being a
        // refusal rather than a note: continuing would bind a plan to a tool
        // nobody vouched for.
        eprintln!("asv: `{tool_command}` did not resolve to a tool this build will vouch for:");
        for candidate in &planned_tool.candidates {
            eprintln!("  {}", candidate.outcome);
        }
        std::process::exit(1);
    }

    // --- 3. plan -------------------------------------------------------------
    let plan = match &discovered {
        Discovered::Npm(discovery) => asv_integrations::plan_npm(discovery, &inventory),
        Discovered::Curl(discovery) => asv_integrations::plan_curl(discovery, &inventory),
    }
    .with_tool(planned_tool.resolved.clone().expect("checked above"));

    // --- 3b. the session this attempt will be authorized under ----------------
    //
    // **Opened here, by this process, unless the caller brought one it already
    // owns — and here rather than at the authorization step because the intent
    // names the session as its workload.** A session resolved after the intent
    // was hashed would put a different workload in the receipt from the one the
    // broker evaluated, which is the exact class of disagreement this block
    // exists to make impossible.
    //
    // The broker records the PID that opened a session and refuses to evaluate
    // an authorization request from any other PID, so R4.B.1's mandatory
    // `--session` meant this command could never be authorised by anything an
    // operator could type: any id they pasted belonged to another process, and
    // the answer was always "session is not owned by the authenticated peer".
    // Found by running the chain against a live broker rather than by reading
    // the policy.
    //
    // Opening our own is what `run_isolated`, `registry` and `github` already
    // do. A session brought from outside is still honoured, because a worker
    // inside `asv run` genuinely has one — and when the broker refuses it, the
    // reason it gives is carried into the receipt rather than summarised away.
    //
    // **A broker that cannot be reached is not a reason to write nothing.**
    // This step used to exit, which meant a machine with no broker produced no
    // receipt at all and `--no-vault` stopped being usable before an operator
    // had decided to adopt anything — the same first-run property `plan` has.
    // The failure now becomes a verdict the receipt carries, so the document
    // still answers the only two questions anybody has: what would this have
    // spent, and what stopped it.
    let session: Option<String> = match session {
        Some(borrowed) => Some(borrowed.to_string()),
        None => match call(
            socket,
            &Request::CreateSession {
                workspace: workspace.to_string(),
            },
        ) {
            Ok(Response::SessionCreated { session, .. }) => Some(session.to_string()),
            Ok(other) => {
                eprintln!(
                    "asv: could not open a session to authorize under: the broker answered {}",
                    response_kind(&other)
                );
                None
            }
            Err(error) => {
                eprintln!("asv: could not reach the broker to open a session: {error}");
                None
            }
        },
    };

    // --- 4. build the intent ------------------------------------------------
    let origin = match origin {
        "human_direct" => asv_domain::IntentOrigin::HumanDirect,
        "scheduled_workflow" => asv_domain::IntentOrigin::ScheduledWorkflow,
        "trusted_tool" => asv_domain::IntentOrigin::TrustedTool,
        "retrieved_content" => asv_domain::IntentOrigin::RetrievedContent,
        "untrusted_tool_output" => asv_domain::IntentOrigin::UntrustedToolOutput,
        "delegated_agent" => asv_domain::IntentOrigin::DelegatedAgent,
        other => {
            eprintln!(
                "asv: unknown origin {other:?}; expected one of human_direct, \
                 scheduled_workflow, trusted_tool, retrieved_content, \
                 untrusted_tool_output, delegated_agent"
            );
            std::process::exit(1);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let intent = asv_domain::ActionIntent {
        transaction: transaction.to_string(),
        principal: principal.to_string(),
        actor: actor.to_string(),
        workload: session.clone().unwrap_or_else(|| UNOPENED_SESSION.into()),
        action: action_for(family),
        resource: resource_for(family),
        tool: plan.tool.clone(),
        config_fingerprint: None, // filled from the plan below
        origin,
        expires_at_unix: now.saturating_add(ttl),
    };
    // The intent's configuration claim is the plan's digest, so the two
    // cannot disagree at this point and `bind_to` still checks it — a plan
    // that recomputed it differently would be caught rather than believed.
    let intent = asv_domain::ActionIntent {
        config_fingerprint: Some(plan.config_digest()),
        ..intent
    };
    if let Err(problem) = intent.contains_no_secret_material() {
        eprintln!("asv: refusing to build an intent: {problem}");
        std::process::exit(1);
    }

    // --- 5. bind ------------------------------------------------------------
    let binding = match plan.bind_to(&intent) {
        Ok(binding) => binding,
        Err(error) => {
            eprintln!("asv: the plan does not describe this intent: {error}");
            std::process::exit(1);
        }
    };
    let intent_digest = match intent.digest() {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("asv: {error}");
            std::process::exit(1);
        }
    };

    // --- 6. authorize, through the broker ------------------------------------
    let verdict = authorize_over_ipc(socket, &intent, session.as_deref(), workspace, json);

    // --- 7. check the world again --------------------------------------------
    // Re-resolved, never reused. Reusing the plan's resolution would compare
    // the plan against itself and always agree, which is the check this whole
    // block exists to make impossible.
    let observed_tool = match asv_integrations::resolve_tool(tool_command, &path_var) {
        Ok(resolution) => resolution,
        Err(error) => {
            eprintln!("asv: {error}");
            std::process::exit(1);
        }
    };
    let outcome = asv_integrations::decide(
        &intent,
        &intent_digest,
        &binding,
        observed_tool.resolved.as_ref(),
        Some(plan.config_digest()).as_deref(),
        now,
        &verdict,
    );

    let receipt = asv_integrations::ExecuteReceipt::new(
        family,
        &intent,
        &binding,
        &plan,
        &planned_tool,
        &observed_tool,
        verdict,
        outcome,
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).expect("the receipt serialises")
        );
    } else {
        print_execute_prose(&receipt);
    }
    if receipt.is_executed() {
        Ok(())
    } else {
        // A refusal is a refusal whether or not a receipt was written.
        std::process::exit(1);
    }
}

/// The domain action a family's operations authorise.
///
/// **Chosen by the caller, not inferred from the plan**, and the reason is
/// worth stating: a plan that picked its own action would be able to describe
/// an operation it had just decided was safe. The operator names the
/// operation; the plan says what the credentials would unlock.
fn action_for(family: &str) -> asv_domain::Action {
    match family {
        "npm" => asv_domain::Action::RegistryPush,
        _ => asv_domain::Action::HttpRequest,
    }
}

/// The resource a family's operations address.
///
/// For npm the registry is real: a `plan` entry carries it and the broker
/// checks it against the credential's audience. For curl there is nothing to
/// check, because a `.curlrc` names no host and the URL arrives per
/// invocation — so this is the literal host `plan` could describe and an
/// operator reading the receipt can see it is a placeholder.
fn resource_for(family: &str) -> asv_domain::Resource {
    match family {
        "npm" => asv_domain::Resource::Api {
            audience: asv_domain::Authority::canonicalize("registry.npmjs.org")
                .expect("a literal, canonical host"),
        },
        _ => asv_domain::Resource::Host {
            hostname: "(named per invocation: a .curlrc names no host)".into(),
        },
    }
}

/// Asks the broker to authorize this intent, and returns its verdict.
///
/// **The broker is the only authority here.** A failure to reach it is a
/// `Deny`, not an `Executed` and not a panic: "we could not ask" and "we asked
/// and were told no" must not look the same to a caller.
///
/// `None` means no session was ever opened — the broker was unreachable when
/// this process went looking — so there is nobody to ask. That is a `Deny` on
/// the same grounds as the IPC failure below it, and it is answered here rather
/// than at the call site so that every route into "could not ask" produces one
/// reason code instead of two.
fn authorize_over_ipc(
    socket: &std::path::Path,
    intent: &asv_domain::ActionIntent,
    session: Option<&str>,
    workspace: &str,
    _json: bool,
) -> asv_integrations::AuthorizationVerdict {
    let Some(session) = session else {
        return asv_integrations::AuthorizationVerdict::Deny {
            reason: "no session could be opened, so no authority could be asked for".into(),
            reason_code: "BrokerUnreachable".into(),
        };
    };
    let session_id: asv_domain::AgentSessionId = match session.parse() {
        Ok(id) => id,
        Err(error) => {
            eprintln!("asv: --session must be a UUID: {error}");
            std::process::exit(1);
        }
    };
    let request = asv_policy::AuthorizationRequest {
        session: session_id,
        action: intent.action.clone(),
        resource: intent.resource.clone(),
        context: asv_policy::PolicyContext {
            workspace: workspace.to_string(),
            protected_ref: None,
            // The intent's digest is what the policy evaluated against, so a
            // decision can be tied back to the exact request that produced it.
            request_digest: intent.digest().ok(),
            peer_uid: unsafe { libc::geteuid() },
        },
    };
    match call(socket, &Request::ExplainAuthorization { request }) {
        Ok(Response::Authorization { explanation }) => {
            match explanation.decision {
                asv_domain::Decision::Allow => asv_integrations::AuthorizationVerdict::Permit {
                    decision: format!("allow by {}", explanation.rule),
                },
                asv_domain::Decision::Deny { reason } => {
                    asv_integrations::AuthorizationVerdict::Deny {
                        reason,
                        reason_code: format!("{:?}", explanation.reason),
                    }
                }
                // **Not a permit.** `RequireApproval` means a human has not
                // said yes yet, and mapping it onto `Permit` would make an
                // unreviewed publish look authorised. It carries the
                // approval id, which is a handle and not a secret.
                asv_domain::Decision::RequireApproval { approval } => {
                    asv_integrations::AuthorizationVerdict::Deny {
                        reason: format!(
                            "a human approval is required and none was presented ({approval})"
                        ),
                        reason_code: format!("{:?}", explanation.reason),
                    }
                }
            }
        }
        // **The broker's own refusal is carried, not summarised.**
        //
        // `Response::Error` is the shape a session check rejects with — "the
        // session is not owned by the authenticated peer", "the workspace is
        // outside the grant" — and every one of those messages is the exact
        // thing an operator needs and cannot guess. Folding them into "the
        // broker answered Error" would be true and useless: it names the
        // protocol shape and drops the reason. Found by running the chain
        // against a live broker with a session that was never created.
        Ok(Response::Error { message, .. }) => asv_integrations::AuthorizationVerdict::Deny {
            reason: format!("the broker refused the authorization: {message}"),
            reason_code: "Refused".into(),
        },
        Ok(other) => asv_integrations::AuthorizationVerdict::Deny {
            reason: format!(
                "the broker answered {} to an authorization request",
                response_kind(&other)
            ),
            reason_code: "UnexpectedResponse".into(),
        },
        Err(error) => asv_integrations::AuthorizationVerdict::Deny {
            reason: format!("could not reach the broker to authorize: {error}"),
            reason_code: "BrokerUnreachable".into(),
        },
    }
}

/// The human form of a receipt: the three questions, in the order an operator
/// asks them.
fn print_execute_prose(receipt: &asv_integrations::ExecuteReceipt) {
    println!(
        "asv {} execute — {}",
        receipt.family,
        receipt.outcome.headline()
    );
    println!();
    println!("asked for:");
    println!("  transaction: {}", receipt.intent.transaction);
    println!("  principal:   {}", receipt.intent.principal);
    println!("  actor:       {}", receipt.intent.actor);
    println!("  origin:      {}", receipt.origin.wire_name());
    println!("  action:      {}", receipt.intent.action);
    println!("  expires at:  {}", receipt.intent.expires_at_unix);
    println!(
        "  intent:      {}",
        receipt.intent.digest().unwrap_or_default()
    );
    println!();
    println!("promised about the world:");
    println!(
        "  tool:    {}",
        describe_tool(receipt.binding.tool.as_ref())
    );
    println!(
        "  config:  {}",
        receipt.config_digest().unwrap_or("(none)").to_string()
    );
    match &receipt.planned_tool.resolved {
        Some(planned) => println!("  resolved: {}", planned.path.display()),
        None => println!("  resolved: (nothing)"),
    }
    println!();
    println!("authorized:");
    match &receipt.authorization {
        asv_integrations::AuthorizationVerdict::Permit { decision } => {
            println!("  {decision}")
        }
        asv_integrations::AuthorizationVerdict::Deny {
            reason,
            reason_code,
        } => println!("  DENIED ({reason_code}): {reason}"),
    }
    println!();
    // The credentials section comes before the outcome on purpose. "Executed"
    // and "executed, spending nothing" are different facts, and a reader who
    // meets the verdict first has no reason to go looking for the difference.
    println!("at stake:");
    let stake = receipt.credentials_at_stake();
    if stake.is_empty() {
        println!(
            "  nothing: {} credential(s) were offered, {} selector(s) in the plan, \
             and none bound.",
            receipt.plan.inventory_size,
            receipt.plan.entries.len()
        );
    } else {
        println!(
            "  {} credential(s) offered, {} selector(s) in the plan",
            receipt.plan.inventory_size,
            receipt.plan.entries.len()
        );
        for (label, id) in receipt.credentials_named() {
            // Both halves: `deploy-token` is what the operator typed into
            // `add-credential`, and the id is what they can paste into
            // `asv credentials delete`. Printing only the first makes the
            // credential un-actionable; printing only the second makes it
            // un-recognisable.
            println!("  would spend: {label} ({id})");
        }
        if receipt.unbound_count() > 0 {
            println!(
                "  and {} selector(s) bound to nothing, which is a different \
                 outcome from binding everything.",
                receipt.unbound_count()
            );
        }
    }
    println!();
    println!("outcome:");
    println!("  {}", receipt.outcome.headline());
}

fn describe_tool(tool: Option<&asv_domain::ToolIdentity>) -> String {
    match tool {
        Some(tool) => format!("{} ({})", tool.path.display(), tool.digest),
        None => "(the intent named no tool)".into(),
    }
}
