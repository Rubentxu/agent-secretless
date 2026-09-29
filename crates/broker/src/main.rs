//! `asv-brokerd` — the secret-bearing broker process (ADR-0002).
//!
//! M0 scope: prove that a Unix-domain connection carries kernel-attested peer
//! identity into request handling. Vault, policy and connectors are later
//! milestones; nothing here can return a secret even in principle, because the
//! response enum has no variant that could hold one.

use std::sync::Arc;

use asv_broker::{BrokerState, VaultSecretPort};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{decode_request, encode_response, Response};
use asv_vault::VaultStore;
use secrecy::SecretString;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use zeroize::Zeroize;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Parse CLI flags. `--vault` and `--passphrase-file` are mutually
    // dependent: either both are present or neither is, and the bin refuses
    // to start otherwise. The passphrase is read from a file — never from
    // argv or env — to keep shell history (`docs/04-SHELL-FIRST-INTEGRATION.md`
    // §9) from absorbing a secret-shaped argument, and to honour D9 (no
    // `std::env::var*` in broker/connector production sources). The first
    // positional argument is the socket path; flags may appear before or
    // after it. Anything else is rejected.
    let mut args = std::env::args_os().skip(1);
    let mut socket_path: PathBuf = PathBuf::from("/run/user/1000/asv/broker.sock");
    let mut vault_path: Option<PathBuf> = None;
    let mut passphrase_path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        let arg = match arg.into_string() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("asv: arguments must be valid UTF-8");
                std::process::exit(1);
            }
        };
        match arg.as_str() {
            "--vault" => {
                vault_path = args.next().map(PathBuf::from);
                if vault_path.is_none() {
                    eprintln!("asv: --vault requires a path argument");
                    std::process::exit(1);
                }
            }
            "--passphrase-file" => {
                passphrase_path = args.next().map(PathBuf::from);
                if passphrase_path.is_none() {
                    eprintln!("asv: --passphrase-file requires a path argument");
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: asv-brokerd [SOCKET] [--vault PATH] [--passphrase-file PATH]"
                );
                std::process::exit(0);
            }
            other if other.starts_with("--") || other.starts_with('-') => {
                eprintln!("asv: unknown flag: {other}");
                std::process::exit(2);
            }
            _ => {
                // Positional: take it as the socket path if not yet set.
                socket_path = PathBuf::from(arg);
            }
        }
    }
    match (&vault_path, &passphrase_path) {
        (None, None) => {}
        (Some(v), Some(p)) if v.exists() && p.exists() => {}
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "asv: --vault and --passphrase-file must be passed together; refusing to start"
            );
            std::process::exit(1);
        }
        _ => {
            eprintln!("asv: --vault or --passphrase-file points at a missing path");
            std::process::exit(1);
        }
    }

    // Refuse to clobber an existing socket: that would either hijack a running
    // broker or destroy evidence of one. Both are worse than a failed start.
    if socket_path.exists() {
        eprintln!(
            "asv: refusing to start, socket already exists: {}",
            socket_path.display()
        );
        std::process::exit(1);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        // Restrictive permissions are the first isolation layer: a socket the
        // agent's own uid can open is still gated by SO_PEERCRED + policy, but
        // world-writable would hand every local user a connection attempt.
        set_socket_dir_mode(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    set_socket_mode(&socket_path)?;
    tracing::info!(path = %socket_path.display(), protocol = asv_ipc_protocol::PROTOCOL_VERSION, "broker listening");

    let mut state = BrokerState::default();

    // Open the vault when one was requested. Failures here are
    // fail-closed: a broker that cannot read its vault cannot lend any
    // secret, and pretending otherwise would silently bypass the
    // deny-by-default property the broker's contract depends on.
    if let (Some(vault_path), Some(passphrase_path)) = (vault_path, passphrase_path) {
        let passphrase = read_passphrase(&passphrase_path).unwrap_or_else(|err| {
            eprintln!("asv: cannot read passphrase file {}: {err}", passphrase_path.display());
            std::process::exit(1);
        });
        let store = VaultStore::open(&vault_path, &passphrase).unwrap_or_else(|err| {
            eprintln!("asv: cannot open vault {}: {err:?}", vault_path.display());
            std::process::exit(1);
        });
        let key = Arc::new(store.header().unlock(&passphrase).unwrap_or_else(|err| {
            eprintln!("asv: cannot unlock vault {}: {err:?}", vault_path.display());
            std::process::exit(1);
        }));
        state.secrets = Some(Arc::new(VaultSecretPort::new(Arc::new(store), key)));
        tracing::info!(vault = %vault_path.display(), "vault opened and unlocked");
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(e) = serve(&mut state, stream) {
                    // One bad connection must not take the broker down
                    // (UAT-017 requires fail-closed, not fail-crashed).
                    tracing::warn!(error = %e, "connection failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }

    Ok(())
}

fn serve(state: &mut BrokerState, stream: UnixStream) -> std::io::Result<()> {
    // Identity first, before reading a single request byte. This ordering is
    // the whole point of ADR-0003: the peer's claims are never consulted.
    use std::os::fd::AsFd;
    let creds = asv_identity::peer_credentials(&stream.as_fd())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
    let mut identity = WorkloadIdentity::from_peer(creds);
    if let Err(e) = identity.pin_pidfd() {
        // Not fatal: peer credentials are already kernel-attested. The weaker
        // evidence is logged so a policy can require pinning if it wants to.
        tracing::debug!(error = %e, "pidfd association unavailable, continuing with peer credentials");
    }

    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    // The raw request bytes may carry secret-shaped material: a hostile client
    // controls every field. Leaving them in a heap buffer keeps them readable by
    // any same-uid peer for the process lifetime, which is exactly the leak the
    // adversarial harness looks for. Zeroize as soon as decoding is done.
    let mut buf = vec![0u8; asv_ipc_protocol::MAX_MESSAGE_BYTES + 1];
    let n = reader.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }

    let response = match decode_request(&buf[..n]) {
        Ok(request) => asv_broker::handle(state, &identity, request),
        Err(e) => Response::Error {
            // A decode failure is either an unknown method or a malformed
            // frame. Both are refusals; neither is ever partially applied.
            code: asv_ipc_protocol::ErrorCode::UnknownMethod,
            message: e.to_string(),
        },
    };

    // Scrub the request bytes before anything else can return or panic, so the
    // material does not outlive this call even on the error path.
    buf.zeroize();

    let bytes = match encode_response(&response) {
        Ok(b) => b,
        Err(e) => return Err(std::io::Error::other(e.to_string())),
    };
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
fn set_socket_mode(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // 0600: only the owning user may connect. The broker is expected to run
    // under a dedicated uid in a packaged install (M7); in dev this is the
    // best available approximation.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
fn set_socket_dir_mode(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Reads a passphrase from a file. The bytes are wrapped in `SecretString` so
/// they share the rest of the vault's handling: zeroized on drop, never
/// re-formatted by `Debug`, never persisted in a panic message.
fn read_passphrase(path: &std::path::Path) -> std::io::Result<SecretString> {
    let mut bytes = std::fs::read(path)?;
    // Trailing newline: passphrase files are typically created by
    // `echo secret > passphrase.txt` and the newline is not part of the
    // secret. Trimming it here is what makes the round-trip
    // "what the operator typed == what the vault opens" true.
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    let text = String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(SecretString::new(text.into_boxed_str()))
}

use std::io::{Read, Write};
