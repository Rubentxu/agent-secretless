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

fn main() -> std::io::Result<()> {
    // R2 (16-SECURITY-RELEASE-GATES): "broker core dumps disabled". A core
    // dump of a broker holding unlocked vault keys would write that key
    // material to a file any log collector could read. This runs before
    // anything else: disabling dumps after the first secret exists would
    // leave a crash window in which the keys were already dumpable.
    disable_core_dumps();

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
    let mut harden = false;
    // R9 audit retention. A flag, not an environment variable: the broker's
    // env-quarantine invariant (uat_017) scans for env reads in production
    // sources, and operator configuration belongs in the launch contract.
    let mut audit_max_records: Option<u64> = None;
    // Durable audit log. Same flag-not-env rule: the file survives broker
    // restarts, so the query window and chain head restore across runs.
    let mut audit_file: Option<PathBuf> = None;
    // ADR-0016: enrol an operator principal, then exit. Not a socket verb and
    // deliberately not gated by admission — a caller cannot be required to hold
    // the permission it is asking to be granted. This is the operator's own act
    // on their own machine, and the broker is simply the program that owns the
    // record's format and the directory discipline it needs.
    let mut enrol_principal: Option<PathBuf> = None;
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
            "--harden" => {
                // M7 hardening profile: dumpable=0, no-new-privs, Landlock,
                // seccomp. Opt-in so a dev box or an old kernel can still run
                // the broker; a packaged install (M7) passes it by default.
                harden = true;
            }
            "--audit-max-records" => {
                let value = args.next().and_then(|v| v.into_string().ok());
                match value.and_then(|v| v.trim().parse::<u64>().ok()) {
                    Some(n) => audit_max_records = Some(n),
                    None => {
                        eprintln!("asv: --audit-max-records requires a number (0 = unbounded)");
                        std::process::exit(1);
                    }
                }
            }
            "--audit-file" => {
                audit_file = args.next().map(PathBuf::from);
                if audit_file.is_none() {
                    eprintln!("asv: --audit-file requires a path argument");
                    std::process::exit(1);
                }
            }
            "--enrol-principal" => {
                let path = args.next().map(PathBuf::from);
                if path.is_none() {
                    eprintln!("asv: --enrol-principal requires a path argument");
                    std::process::exit(1);
                }
                enrol_principal = path;
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: asv-brokerd [SOCKET] [--vault PATH] [--passphrase-file PATH] [--audit-max-records N] [--audit-file PATH] [--enrol-principal PATH] [--harden]"
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
    // Enrolment runs before the vault checks, because it is not a vault
    // operation: it locates the record by the vault's path, writes it, and
    // exits. Requiring `--passphrase-file` here would be asking the operator
    // for the secret to a command that never opens the vault.
    if let Some(principal) = enrol_principal {
        let Some(vault) = vault_path.as_ref() else {
            eprintln!("asv: --enrol-principal needs --vault to locate the enrolment record");
            std::process::exit(1);
        };
        match asv_broker::admission::enrol(vault, &principal) {
            Ok(record) => println!("enrolled {} into {}", principal.display(), record.display()),
            Err(error) => {
                eprintln!("asv: {error}");
                std::process::exit(1);
            }
        }
        return Ok(());
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

    // M7-R1/R3/R4: when --harden is passed, install the hardening profile
    // BEFORE the socket bind and any vault open. The ordering is normative:
    // the spec requires the Landlock ruleset to be in place before
    // `VaultStore::open`, and dumpable=0 to hold before any secret can
    // exist in memory. prctl failures are fail-closed (they are the core
    // of M7-R1); missing kernel features (Landlock on < 5.13, seccomp
    // denied by the sandbox) degrade loudly to a warning instead of
    // killing a broker the operator explicitly asked to harden.
    if harden {
        // The Landlock ruleset is irreversible, so the paths the broker is
        // actually pointed at have to be allowed BEFORE it installs, or the
        // broker would sandbox itself out of its own vault. All three come
        // from explicit CLI input; none is read from the environment, which
        // the quarantine invariant forbids.
        let mut install_paths = asv_broker::harden::InstallPaths::with_write_paths([socket_path
            .parent()
            .unwrap_or(std::path::Path::new("/run"))
            .to_path_buf()]);
        if let Some(v) = &vault_path {
            // --vault names a FILE. The parent directory is the unit
            // Landlock can grant, so allow the directory and not the file.
            let dir = v.parent().filter(|p| !p.as_os_str().is_empty());
            if let Some(dir) = dir {
                install_paths.write_paths.push(dir.to_path_buf());
            }
        }
        if let Some(a) = &audit_file {
            let dir = a.parent().filter(|p| !p.as_os_str().is_empty());
            if let Some(dir) = dir {
                install_paths.write_paths.push(dir.to_path_buf());
            }
        }
        let cfg = asv_broker::harden::install_with(install_paths).unwrap_or_else(|err| {
            eprintln!("asv: --harden failed on a mandatory step: {err}");
            std::process::exit(1);
        });
        let dumpable_zero = asv_broker::harden::dumpable_is_zero();
        let no_new_privs = asv_broker::harden::no_new_privs_is_set();
        // Honest labels: `landlock_installed` and `seccomp_installed` are
        // REAL — a live Landlock ruleset (restrict_self succeeded) and a
        // live seccomp-bpf deny-list (ptrace/process_vm_readv/kexec_load/
        // bpf/init_module/finit_module/userfaultfd/perf_event_open are
        // denied with SIGSYS). The closed allow-list profile remains M8.
        tracing::info!(
            dumpable_zero,
            no_new_privs,
            cgroup_v2 = cfg.cgroup_v2,
            landlock = cfg.landlock_installed,
            seccomp_filter = cfg.seccomp_installed,
            "M7 harden profile applied (dumpable=0, no-new-privs, seccomp deny-list)"
        );
        if !cfg.landlock_installed {
            tracing::warn!(
                landlock = cfg.landlock_installed,
                "kernel lacks Landlock (< 5.13); file sandbox NOT active"
            );
        }
        if !cfg.seccomp_installed {
            tracing::warn!("kernel rejected seccomp filter; syscall filtering NOT active");
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
        // A bare filename like `broker.sock` has an empty-string parent:
        // there is no directory to create or restrict, and `chmod("")`
        // would fail with ENOENT. Only touch the filesystem for a real
        // parent directory.
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            // Restrictive permissions are the first isolation layer: a socket the
            // agent's own uid can open is still gated by SO_PEERCRED + policy, but
            // world-writable would hand every local user a connection attempt.
            set_socket_dir_mode(parent)?;
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    set_socket_mode(&socket_path)?;
    tracing::info!(path = %socket_path.display(), protocol = asv_ipc_protocol::PROTOCOL_VERSION, "broker listening");

    let mut state = BrokerState::default();
    if let Some(path) = audit_file.as_deref() {
        // Durable audit (R9 follow-up). Fail-closed: a chain that does not
        // verify on disk is not extended; a broken durable log must be
        // investigated, not silently re-based.
        let max = audit_max_records.unwrap_or(asv_broker::audit::DEFAULT_MAX_RECORDS);
        let log = asv_broker::audit::AuditLog::open_persistent(max, path).unwrap_or_else(|err| {
            eprintln!(
                "asv: refusing to start with a broken audit log at {}: {err:?}",
                path.display()
            );
            std::process::exit(1);
        });
        tracing::info!(path = %path.display(), restored = log.query(0).len(), dropped = log.dropped(), "durable audit log opened");
        state.audit = log;
    } else if let Some(max) = audit_max_records {
        // Operator-configured retention (R9). 0 = unbounded. Logged so the
        // launch contract is visible in the broker's own output.
        state.audit = asv_broker::audit::AuditLog::new(max);
        tracing::info!(max_records = max, "audit retention configured");
    }

    // Open the vault when one was requested. Failures here are
    // fail-closed: a broker that cannot read its vault cannot lend any
    // secret, and pretending otherwise would silently bypass the
    // deny-by-default property the broker's contract depends on.
    if let (Some(vault_path), Some(passphrase_path)) = (vault_path, passphrase_path) {
        let passphrase = read_passphrase(&passphrase_path).unwrap_or_else(|err| {
            eprintln!(
                "asv: cannot read passphrase file {}: {err}",
                passphrase_path.display()
            );
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
        // The broker's own list of what it holds. Without this the vault is
        // open and lending, yet `ListCredentialMetadata` answers `[]` and
        // `MintSurrogate` refuses every real credential as unknown — a broker
        // that cannot see its own vault. Loaded here, while the store is still
        // owned by this function; the lending port below only lends by id.
        let inventory = asv_broker::inventory::load(&mut state, &store);

        // ADR-0015/0016: the enrolment record lives beside the vault and is
        // read here, at start, so it survives a restart and names principals
        // rather than pids. A missing record is the normal state and admits
        // nobody. A record that exists and cannot be read is fatal: treating a
        // damaged authorisation file as "nobody enrolled" would hide the
        // difference between an operator who enrolled nothing and something
        // that damaged the file granting credential-write authority.
        match asv_broker::admission::load_enrolment(&vault_path) {
            Ok(enrolment) => {
                tracing::info!(
                    principals = enrolment.principals().len(),
                    "control-plane enrolment record loaded"
                );
                state.control_plane = enrolment;
            }
            Err(error) => {
                eprintln!("asv: cannot read the control-plane enrolment record: {error}");
                std::process::exit(1);
            }
        }

        // One store instance, shared. The lending port needs `&self` and the
        // writer needs `&mut self`, and `with_secret` gates on the in-memory
        // body — so a second handle on the same file would answer `NotFound`
        // for a credential that had just been written to it.
        let store = Arc::new(std::sync::Mutex::new(store));
        state.vault_writer = Some(Arc::new(asv_broker::VaultWritePort::new(
            Arc::clone(&store),
            Arc::clone(&key),
        )));
        state.secrets = Some(Arc::new(VaultSecretPort::new(Arc::clone(&store), key)));
        tracing::info!(
            vault = %vault_path.display(),
            credentials = inventory.loaded,
            skipped = inventory.skipped,
            collisions = inventory.collisions,
            "vault opened and unlocked"
        );
    }

    // M6: the runtime the live PostgreSQL transport runs on. Built here, in the
    // process that owns it, rather than inside the broker, so the threads that
    // hold database sockets have the same lifetime as the process. A broker
    // without one refuses every PostgreSQL request, which is the honest answer:
    // it cannot have a session it cannot serve.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|err| {
            eprintln!("asv: cannot start the async runtime: {err}");
            std::process::exit(1);
        });
    state.runtime = Some(asv_broker::PgRuntime::from_handle(runtime.handle().clone()));
    // The handle is kept alive for the whole loop below. Dropping the runtime
    // while a session task still holds a socket would close that socket without
    // the broker having observed a teardown, which is the one outcome M6-R4
    // exists to prevent.
    let _runtime = runtime;

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

/// Sets RLIMIT_CORE to (0, 0) so the kernel refuses to write a core dump
/// of this process, ever.
///
/// R2 (16-SECURITY-RELEASE-GATES): "broker core dumps disabled". A core of
/// a broker holding unlocked vault keys is a plain-text key file written
/// wherever `kernel.core_pattern` points — often world-readable, often
/// shipped by a crash collector. The rlimit is inherited by every child,
/// so a crash in any tokio worker is covered too.
///
/// Not a hard error: an seccomp/apparmor profile that denies setrlimit
/// must not stop the broker from serving, but the skip is loudly logged
/// so a hardened deployment (M7) can alert on it.
#[cfg(unix)]
fn disable_core_dumps() {
    let rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlimit) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            error = %err,
            "could not disable core dumps; a crash may write key material to the core pattern path"
        );
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {
    // Non-unix builds have no vault unlock path in this binary today; the
    // no-op keeps the call site total without pretending protection exists.
}

#[cfg(test)]
mod core_dump_tests {
    /// The R2 claim "broker core dumps disabled" must be observable: after
    /// `disable_core_dumps`, this process's own RLIMIT_CORE soft limit is 0,
    /// which is exactly what the kernel checks before writing a core.
    #[test]
    #[cfg(unix)]
    fn disable_core_dumps_sets_rlimit_core_to_zero() {
        super::disable_core_dumps();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(
            rc,
            0,
            "getrlimit failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            limit.rlim_cur, 0,
            "RLIMIT_CORE soft limit must be 0 after disable_core_dumps"
        );
    }
}
