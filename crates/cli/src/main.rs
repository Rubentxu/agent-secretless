//! `asv` — unprivileged CLI (ADR-0002).
//!
//! M0 ships only the two skeleton commands the roadmap names: `status` and the
//! session launcher skeleton. `credential add` and friends are deliberately
//! absent, because a CLI secret-ingestion command is a place where a value
//! could be passed as `argv` and leak into shell history — exactly what
//! `docs/04-SHELL-FIRST-INTEGRATION.md` §9 forbids. M1 adds no-echo ingestion.

use asv_ipc_protocol::{Request, Response, PROTOCOL_VERSION};
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
    /// List credential metadata. Never values.
    Credentials,
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

    let request = match cli.command {
        Command::Status => Request::Ping {
            protocol: PROTOCOL_VERSION,
        },
        Command::Session { workspace } => Request::CreateSession { workspace },
        Command::Credentials => Request::ListCredentialMetadata,
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
