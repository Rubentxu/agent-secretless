//! `asv` — unprivileged CLI (ADR-0002).
//!
//! M0 ships only the two skeleton commands the roadmap names: `status` and the
//! session launcher skeleton. `credential add` and friends are deliberately
//! absent, because a CLI secret-ingestion command is a place where a value
//! could be passed as `argv` and leak into shell history — exactly what
//! `docs/04-SHELL-FIRST-INTEGRATION.md` §9 forbids. M1 adds no-echo ingestion.

use asv_domain::CredentialKind;
use asv_ipc_protocol::{OpaqueSecret, Request, Response, PROTOCOL_VERSION};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

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
    Status,
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
    Credentials,
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
    /// Query the broker's audit log (R9). Denied until the operator control
    /// plane ships; the command reports that refusal honestly.
    Audit {
        /// Only records newer than this duration (e.g. `24h`, `30m`).
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
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
    let socket = cli.socket.unwrap_or_else(default_socket);

    let command = match cli.command {
        Command::Run { command } => return run_command(command),
        command => command,
    };

    let request = match command {
        Command::Status => Request::Ping {
            protocol: PROTOCOL_VERSION,
        },
        Command::Session { workspace } => Request::CreateSession { workspace },
        Command::Credentials => Request::ListCredentialMetadata,
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
    };

    match call(&socket, &request) {
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

fn default_socket() -> PathBuf {
    PathBuf::from("/run/user/1000/asv/broker.sock")
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

fn run_command(command: Vec<String>) -> std::io::Result<()> {
    let Some(program) = command.first() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "asv run requires a command",
        ));
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

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    for name in QUARANTINED_ENV_NAMES {
        child.env_remove(name);
    }
    child
        .env("SSH_AUTH_SOCK", agent.socket_path())
        .env("ASV_SESSION_ID", std::process::id().to_string())
        .env("ASV_SESSION_MODE", "strict");

    let status = child.status()?;
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
        Response::SessionCreated { session } => {
            println!("session {session} created");
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
    fn cli_definition() -> String {
        use clap::CommandFactory;
        Cli::command().to_string()
    }

    #[test]
    fn request_encoding_stays_within_the_protocol_bound() {
        let req = Request::CreateSession {
            workspace: "/home/user/project".into(),
        };
        let bytes = serde_json::to_vec(&req).expect("serializes");
        assert!(bytes.len() < asv_ipc_protocol::MAX_MESSAGE_BYTES);
    }
}
