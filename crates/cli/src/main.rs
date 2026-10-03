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
            let mut secret = String::new();
            if let Err(error) =
                std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut secret)
            {
                eprintln!("asv: cannot read the secret from stdin: {error}");
                std::process::exit(2);
            }
            let secret = secret.strip_suffix('\n').unwrap_or(&secret).to_string();
            if secret.is_empty() {
                eprintln!("asv: no secret on stdin");
                std::process::exit(2);
            }
            Request::CreateCredential {
                label,
                kind,
                provider,
                account,
                secret: OpaqueSecret::new(secret.into_bytes()),
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
        Command::Setup { .. }
        | Command::Doctor { .. }
        | Command::Capabilities { .. }
        | Command::Agent { .. } => {
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
        Response::AuditRecords { .. } => "AuditRecords",
        Response::PostgresConnected { .. } => "PostgresConnected",
        Response::PostgresResult { .. } => "PostgresResult",
        Response::PostgresRevoked { .. } => "PostgresRevoked",
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
        Response::SessionCreated { session } => session,
        other => {
            return Err(std::io::Error::other(format!(
                "asv run could not open a session: {other:?}"
            )))
        }
    };

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
    child
        .env("SSH_AUTH_SOCK", agent.socket_path())
        .env("ASV_SESSION_ID", session.to_string())
        .env("ASV_SESSION_MODE", "strict");

    let status = child.status()?;
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

fn call(socket: &std::path::Path, request: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;

    let payload = serde_json::to_vec(request).map_err(|e| std::io::Error::other(e.to_string()))?;
    if payload.len() > asv_ipc_protocol::MAX_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request exceeds the protocol size limit",
        ));
    }
    stream.write_all(&payload)?;
    stream.flush()?;

    let mut buf = vec![0u8; asv_ipc_protocol::MAX_MESSAGE_BYTES];
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
        Response::Pong { protocol } => {
            println!("broker reachable, protocol v{protocol}");
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
        Response::SessionCreated { session } => {
            println!("session {session} created");
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
        Response::IssueRead { title, state, .. } => {
            println!("issue {title:?} [{state}]");
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
}
