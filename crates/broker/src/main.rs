//! `asv-brokerd` — the secret-bearing broker process (ADR-0002).
//!
//! M0 scope: prove that a Unix-domain connection carries kernel-attested peer
//! identity into request handling. Vault, policy and connectors are later
//! milestones; nothing here can return a secret even in principle, because the
//! response enum has no variant that could hold one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asv_broker::{BrokerState, VaultSecretPort};
use asv_identity::WorkloadIdentity;
use asv_ipc_protocol::{decode_request, encode_response, Response};
use asv_vault::VaultStore;
use secrecy::SecretString;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use zeroize::Zeroize;
// For `--connect-roots`: the trait is what turns a PEM file into certificates,
// and the file is read with the library's own reader rather than a hand-rolled
// one. Only the trait is imported; the type it is implemented for is named at
// the call site.
use rustls::pki_types::pem::PemObject as _;

/// Set by the signal handler, read by the watcher thread.
///
/// A process-wide flag rather than something owned by `main`, because a signal
/// handler receives no context and there is no way to hand it one. The handler
/// is the only writer and the watcher is the only reader, so the atomic is the
/// whole of the communication.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// How often the watcher asks whether a signal arrived.
///
/// The same order of magnitude as the bridge's own `CANCEL_POLL`, and for the
/// same reason it is a poll rather than a wake-up: the work this gates is
/// already happening on a timer, so the flag decides *when it is noticed*, not
/// how often anything is checked.
const SHUTDOWN_POLL: Duration = Duration::from_millis(50);

/// How long a signalled broker waits for its tunnels before leaving anyway.
///
/// **A bound, not a promise.** A tunnel whose client has stopped reading cannot
/// be made to finish, and a broker that waits forever for one is a broker an
/// operator has to `SIGKILL` — which is the kernel teardown this whole path
/// exists to replace. The window is long enough for a healthy relay to notice
/// and end, and the log says when it expired so an operator can see a slow
/// drain rather than infer one.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// The signal handler. Stores a flag and returns.
///
/// **Nothing else happens here, and that is the whole design.** A signal
/// handler runs on whatever thread the signal landed on, in a context where
/// allocating, locking a mutex, writing to a socket, or formatting a string is
/// undefined behaviour. `ShutdownSignal::stop` does all four — it takes a
/// `Mutex` and a `Notify` — so calling it from here would be a way to deadlock
/// or corrupt the heap at exactly the moment the process is least able to
/// survive it. One relaxed store is the whole of what is safe.
extern "C" fn on_shutdown_signal(_signum: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Make the operator's signals reach the broker's own cancellation mechanism,
/// and leave afterwards.
///
/// **This is the caller `ShutdownSignal::stop` did not have.** The signal
/// existed, the accept loop watched it, and the bridge polled it every 50 ms
/// to tear down in-flight tunnels — and nothing in a running broker ever set
/// it. An operator's `SIGTERM` therefore did what the kernel does to every
/// process: it killed the broker, and every tunnel died with it as a side
/// effect of the file descriptors closing. The product's own path to ending a
/// tunnel was exercised only by tests, which is the same defect
/// `ShutdownSignal::revoke` turned out to have one increment earlier, found
/// again in the sibling method.
///
/// The difference this makes is not cosmetic and not about tidiness. A tunnel
/// the kernel tears down is a tunnel that ends with no recorded reason: no
/// `cancelled` class, no `shutdown` in the durable chain, and an operator
/// reading the audit trail sees a connection that simply stopped. A tunnel
/// ended through this path is recorded as the deliberate, classed event it is.
fn install_ordered_shutdown(
    shutdown: Arc<asv_broker::connect_listener::ShutdownSignal>,
    in_flight: Arc<asv_broker::connect_listener::InFlight>,
) {
    // `libc::signal` rather than `tokio::signal`, and the reason is that the
    // `signal` feature is not enabled for this workspace's tokio. Turning it on
    // would add `signal-hook-registry` and its registry machinery to a product
    // that deliberately runs under Landlock, seccomp and a dumpable-bit
    // lockdown, to obtain something `libc` — already a direct dependency —
    // provides in six lines. A dependency is a thing to spend, not a thing to
    // spend on a reimplementation of a syscall.
    //
    // `SIGINT` as well as `SIGTERM`: an operator pressing Ctrl-C at a terminal
    // is asking the same thing, and leaving Ctrl-C to kill the process while
    // SIGTERM drains would make the two paths disagree for no reason.
    // Through a data pointer, not straight from the function item: a bare
    // `fn` item cast to an integer is a function pointer treated as an integer,
    // and the two-step cast is what actually converts a function to an address.
    // `sighandler_t` is `size_t` on this target, which is why the cast looks
    // like a number at all.
    let handler = on_shutdown_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }

    std::thread::spawn(move || {
        while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            std::thread::sleep(SHUTDOWN_POLL);
        }
        tracing::info!("shutdown signal received; ending every tunnel this broker authorised");
        // The mechanism is the product's own: the accept loop stops accepting,
        // and every tunnel in flight is cancelled through the bridge's poll
        // rather than by its socket closing under it.
        shutdown.stop();

        // The drain, and the reason it is written this way.
        //
        // The first version of this loop waited for `shutdown.is_stopped()` to
        // become false, which is a flag `stop` sets *before it returns* — so the
        // window collapsed to nothing and the process left while its tunnels
        // were still being torn down. Worse, leaving is what killed them: the
        // outcome of a cancelled tunnel is appended to the audit chain by the
        // task handling it, and `exit` does not wait for anybody. The test that
        // watches for `cancelled`/`shutdown` in the chain caught exactly that,
        // with a chain that ended mid-conversation.
        //
        // So the thing waited for is the *tunnels*, not the flag: zero in
        // flight means every one of them has finished writing its outcome.
        let deadline = std::time::Instant::now() + SHUTDOWN_DRAIN;
        loop {
            let open = in_flight.count();
            if open == 0 {
                tracing::info!("every tunnel has ended; the broker is leaving");
                break;
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    open,
                    "shutdown drain window elapsed with tunnels still in flight; \
                     leaving anyway"
                );
                break;
            }
            std::thread::sleep(SHUTDOWN_POLL);
        }
        // Deliberately not a return through `main`: the Unix accept loop below
        // is a blocking `accept` that no amount of waiting will unblock, and a
        // process that refuses to leave is a worse outcome than one that leaves
        // without unwinding a stack frame. Everything that needed to be written
        // is written by this point — the audit log flushes per record — so
        // there is nothing here to lose.
        std::process::exit(0);
    });
}

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
    //
    // The default socket path is derived from the *running* uid rather than
    // written down. It used to be the literal `/run/user/1000/...`, which was
    // correct on one account on one machine and nowhere else: every user a
    // release is installed for would have the broker try to bind inside a
    // runtime directory that is not theirs. The derivation lives in
    // `asv_ipc_protocol::socket` so this binary and the CLI cannot drift
    // apart — a CLI dialling one path while the broker listens on another is
    // indistinguishable from a broker that is merely down.
    //
    // `getuid()` is a syscall, not an environment read, so it costs nothing
    // against the D9 quarantine that `uat_017_env_scan.rs` enforces. For the
    // same reason the broker does not consult `XDG_RUNTIME_DIR`: it may not
    // read the environment, so it takes the uid rule and the CLI, which is
    // exempt from the scan, may override it. Both land on the same path
    // whenever the runtime directory is the spec default.
    let mut args = std::env::args_os().skip(1);
    let mut socket_path: PathBuf =
        asv_ipc_protocol::socket::default_socket_path(unsafe { libc::getuid() });
    let mut vault_path: Option<PathBuf> = None;
    let mut passphrase_path: Option<PathBuf> = None;
    let mut harden = false;
    // C1-R: the identity this installation declared, and whether the operator
    // made the guarantee a condition of starting. See `identity.rs` for why
    // this is a declaration measured against a syscall rather than an inference
    // from the uid's shape.
    let mut declared_uid: Option<u32> = None;
    let mut require_dedicated_identity = false;
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
    // M9/V1-C2: the CONNECT proxy's bind address. Absent means the listener is
    // not started, which is the default for now: turning it on makes the broker
    // answer on a second socket, and that is an operator's decision to make
    // with their own allow-list in hand rather than something a shipped default
    // should do on their behalf.
    let mut connect_listen: Option<String> = None;
    // C2.6: the CONNECT route table. A file, not an environment variable, for
    // the same reason as every other operator setting above: the broker's
    // env-quarantine invariant (uat_017) scans production sources for env reads,
    // and a destination an operator cannot see in the launch contract is a
    // destination they cannot audit.
    let mut connect_routes: Option<PathBuf> = None;
    let mut workers_file: Option<PathBuf> = None;
    // C2.6: Cedar policy text. A route file declares what should be reachable;
    // this is the permission that makes it so. They are separate flags on
    // purpose — a route with no policy rule is refused, and that refusal is the
    // default, so widening CONNECT is two deliberate edits rather than one.
    let mut policy_file: Option<PathBuf> = None;
    // C2.8: the anchors a *destination's* certificate is verified against. Not
    // the public root set and not defaulted — see `Bridge::with_upstream`.
    let mut connect_roots: Option<PathBuf> = None;
    // M11: the credentials this installation trades for short-lived tokens.
    // A file rather than flags because it is structured, and because the
    // other structured operator inputs here are files too — a flag carrying
    // four colon-separated fields is a field separator waiting to be wrong.
    // It carries no secret: the client secret stays in the vault and the
    // loader refuses a file that tries to name one.
    let mut oauth2_clients: Option<PathBuf> = None;
    // M11 (R2.F): the OCI registries this broker will reach, and which stored
    // credential serves each. A file for the same reason as `--oauth2-clients`
    // above: it is structured, it is operator configuration rather than code,
    // and a flag carrying host/credential pairs is a separator waiting to be
    // wrong. **Empty is the default and refuses every registry pull** — a
    // deployment that has not said which registries it may reach is not one
    // that gets to reach whatever a request names.
    let mut registries: Option<PathBuf> = None;
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
            "--connect-listen" => {
                // From `argv`, never the environment: D9 forbids
                // `std::env::var*` in broker production sources, and the
                // reason is not tidiness. An address a parent process can set
                // silently is an address an operator cannot see, and this one
                // decides which sockets the broker answers on.
                connect_listen = match args.next() {
                    Some(os) => match os.into_string() {
                        Ok(s) => Some(s),
                        Err(_) => {
                            eprintln!("asv: --connect-listen address must be valid UTF-8");
                            std::process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("asv: --connect-listen requires an ADDR:PORT argument");
                        std::process::exit(1);
                    }
                };
            }
            "--connect-routes" => {
                connect_routes = args.next().map(PathBuf::from);
                if connect_routes.is_none() {
                    eprintln!("asv: --connect-routes requires a path argument");
                    std::process::exit(1);
                }
            }
            "--workers" => {
                workers_file = args.next().map(PathBuf::from);
                if workers_file.is_none() {
                    eprintln!("asv: --workers requires a path argument");
                    std::process::exit(1);
                }
            }
            "--policy" => {
                policy_file = args.next().map(PathBuf::from);
                if policy_file.is_none() {
                    eprintln!("asv: --policy requires a path argument");
                    std::process::exit(1);
                }
            }
            "--connect-roots" => {
                connect_roots = args.next().map(PathBuf::from);
                if connect_roots.is_none() {
                    eprintln!("asv: --connect-roots requires a path argument");
                    std::process::exit(1);
                }
            }
            "--oauth2-clients" => {
                oauth2_clients = args.next().map(PathBuf::from);
                if oauth2_clients.is_none() {
                    eprintln!("asv: --oauth2-clients requires a path argument");
                    std::process::exit(1);
                }
            }
            "--registries" => {
                registries = args.next().map(PathBuf::from);
                if registries.is_none() {
                    eprintln!("asv: --registries requires a path argument");
                    std::process::exit(1);
                }
            }
            "--identity-uid" => {
                // The launch contract, flag-not-env like every other operator
                // setting in this binary: the broker's env quarantine scans for
                // env reads in production sources, and an identity is exactly
                // the kind of thing that must be visible in `ps` rather than
                // inherited from whatever launched the process.
                let raw = args.next().unwrap_or_default();
                // `args` yields `OsString`. A non-UTF-8 argument is a usage
                // error, and `to_string_lossy` makes it one: the parse below
                // fails on the replacement characters and exits 2, which is the
                // same answer a typo gets.
                let raw = raw.to_string_lossy();
                match raw.parse::<u32>() {
                    Ok(uid) => declared_uid = Some(uid),
                    Err(_) => {
                        eprintln!("asv: --identity-uid requires a numeric uid, got {raw:?}");
                        std::process::exit(2);
                    }
                }
            }
            "--require-dedicated-identity" => require_dedicated_identity = true,
            "-h" | "--help" => {
                eprintln!(
                    "usage: asv-brokerd [SOCKET] [--vault PATH] [--passphrase-file PATH] [--audit-max-records N] [--audit-file PATH] [--enrol-principal PATH] [--harden] [--connect-listen ADDR] [--identity-uid N] [--require-dedicated-identity] [--oauth2-clients PATH]"
                );
                eprintln!();
                eprintln!("  --identity-uid N       the uid this installation expects the");
                eprintln!("                         broker to be. A broker running as any");
                eprintln!("                         other uid refuses to start, because an");
                eprintln!("                         operator who declared 998 and got their");
                eprintln!("                         own account believes they installed a");
                eprintln!("                         service. Absent means no identity was");
                eprintln!("                         declared, and the broker says so rather");
                eprintln!("                         than inferring one.");
                eprintln!("  --require-dedicated-identity  refuse to start unless a");
                eprintln!("                         --identity-uid was declared and this");
                eprintln!("                         process is not setuid. This is what");
                eprintln!("                         stops a packaged install from");
                eprintln!("                         degrading into the development shape");
                eprintln!("                         and reporting success.");
                eprintln!("  --connect-listen ADDR  serve the CONNECT proxy on ADDR. Needs a");
                eprintln!("                         --vault: a tunnel with no credential behind");
                eprintln!("                         it is refused, so there is nothing to serve.");
                eprintln!("  --connect-roots PATH   PEM anchors a TLS destination's certificate");
                eprintln!(
                    "                         is verified against. Absent means the store is"
                );
                eprintln!("                         empty, so every route declaring \"upstream\":");
                eprintln!("                         \"tls\" is refused. Not the public root set:");
                eprintln!("                         that would decide who gets this product's");
                eprintln!("                         credentials on the internet's say-so.");
                eprintln!("  --connect-routes PATH  the CONNECT route table. Every route is");
                eprintln!("                         authorized against the policy at load, so a");
                eprintln!("                         route the policy does not permit fails the");
                eprintln!("                         whole file rather than being dropped.");
                eprintln!(
                    "  --policy PATH          Cedar policy text. The built-in policy permits"
                );
                eprintln!(
                    "                         no CONNECT route at all, so a route file alone"
                );
                eprintln!("                         authorizes nothing.");
                eprintln!("  --oauth2-clients PATH  JSON list of credentials this broker");
                eprintln!("                         trades for short-lived tokens, each with a");
                eprintln!("                         credential, client_id, token_url,");
                eprintln!("                         resource_url and optional audience");
                eprintln!("                         and scope. token_url and");
                eprintln!("                         resource_url must both be https.");
                eprintln!("                         Carries no secret: the client secret");
                eprintln!("                         stays in the vault, and a file that");
                eprintln!("                         names one is refused.");
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
    // Declaring OAuth2 clients without a vault is refused, in the same place and
    // for the same reason as `--connect-listen`: the registrations name vault
    // credentials, and a broker with no vault has nothing to exchange them
    // against. Without this the flag would be accepted and then silently
    // ignored, which is the one outcome an operator cannot detect.
    if oauth2_clients.is_some() && vault_path.is_none() {
        eprintln!("asv: --oauth2-clients needs --vault; there is no client secret to trade");
        std::process::exit(1);
    }

    // The identity check runs before the vault, the passphrase and the harden
    // profile, and before the enrolment branch: every one of those acts on a
    // credential or writes a record, and a broker that is going to refuse over
    // its own identity should refuse before it has touched any of them. A
    // refusal that arrives after the passphrase has been read is a refusal
    // that has already had the secret.
    let identity_verdict = match asv_broker::identity::check(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        declared_uid,
        require_dedicated_identity,
    ) {
        Ok(verdict) => verdict,
        Err(error) => {
            eprintln!("asv: {error}");
            std::process::exit(1);
        }
    };
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
    // DX2: the harden block fills this in and the request path reads it,
    // so `asv doctor` can report the broker's real protections instead of
    // `unknown`. Declared out here because the block is conditional and a
    // broker run with `--no-harden` is exactly the case that must report
    // none of them.
    let mut self_report: Option<asv_broker::selfreport::SelfReport> = None;

    if harden {
        // The Landlock ruleset is irreversible, so the paths the broker is
        // actually pointed at have to be allowed BEFORE it installs, or the
        // broker would sandbox itself out of its own vault. All of them come
        // from explicit CLI input; none is read from the environment, which
        // the quarantine invariant forbids.
        //
        // The set is built by `harden::broker_install_paths` rather than here,
        // because an inline declaration is one nobody can test — and this one
        // was wrong: the passphrase file is opened *after* this call, and its
        // directory was never granted, so `--harden` sandboxed the broker out
        // of its own passphrase. See that function for the full account.
        let install_paths = asv_broker::harden::broker_install_paths(
            &socket_path,
            vault_path.as_deref(),
            audit_file.as_deref(),
            passphrase_path.as_deref(),
        );
        // DX2: kept for `Request::AgentInfo` rather than logged and dropped.
        // `asv doctor` asks the broker for these over the socket.
        let cfg = asv_broker::harden::install_with(install_paths).unwrap_or_else(|err| {
            eprintln!("asv: --harden failed on a mandatory step: {err}");
            std::process::exit(1);
        });
        let dumpable_zero = asv_broker::harden::dumpable_is_zero();
        let no_new_privs = asv_broker::harden::no_new_privs_is_set();
        // DX2: the same three numbers, kept rather than logged and dropped.
        // `asv doctor` asks the broker for these over the socket, and before
        // this they existed only for the length of the log line below.
        self_report = Some(asv_broker::selfreport::SelfReport::from_harden(
            &cfg,
            dumpable_zero,
            no_new_privs,
        ));
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
    // Configuration is built and validated **before** the socket is bound.
    //
    // It used to be bound first, which meant a broker that refused its own
    // `--policy` or `--workers` file exited non-zero and left a socket on
    // disk. A client that finds that socket connects, gets nothing, and has no
    // way to tell "the broker is not configured" from "the broker is not
    // there" — the same shape this codebase already calls out for a proxy that
    // looks alive and can never establish a tunnel, except here the process is
    // gone and the socket it left behind still answers.
    //
    // Binding last also means a configuration error costs nothing: no
    // directory, no socket, no window in which a half-configured broker is
    // reachable.
    let mut state = BrokerState::default();

    // C2.6: the operator's Cedar text, if they supplied one. Loaded before the
    // route table, because the route table is authorized *by* this engine and
    // asking the question in the other order would authorize routes against a
    // policy the operator is about to replace.
    if let Some(path) = policy_file.as_deref() {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("asv: cannot read --policy {}: {e}", path.display());
            std::process::exit(1);
        });
        state.policy = asv_policy::PolicyEngine::from_policy_text(&text).unwrap_or_else(|e| {
            // A policy that does not parse is not a policy this broker can run
            // with. Exiting is the fail-closed answer; falling back to the
            // built-in text would start a broker whose effective policy nobody
            // wrote, and every decision it made afterwards would be attributed
            // to a file the operator does not have.
            eprintln!(
                "asv: --policy {} is not valid Cedar policy: {e}",
                path.display()
            );
            std::process::exit(1);
        });
        tracing::info!(path = %path.display(), "Cedar policy loaded");
    }

    // The operator's worker declarations, loaded before anything can be run
    // and refused as a whole. A file that half-parses is not a worker file an
    // operator wrote, and starting with the subset that happened to be valid
    // would give the process an authority nobody declared.
    if let Some(path) = workers_file.as_deref() {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("asv: cannot read --workers {}: {e}", path.display());
            std::process::exit(1);
        });
        let registry = asv_broker::worker_file::load(&text).unwrap_or_else(|e| {
            eprintln!("asv: --workers {}: {e}", path.display());
            std::process::exit(1);
        });
        tracing::info!(
            path = %path.display(),
            workers = ?registry.names(),
            "isolated worker registry loaded"
        );
        state.workers = std::sync::Arc::new(registry);
    }

    // R2.F.3: the registry allowlist, validated *before* the listener exists.
    //
    // Placed here rather than beside `--oauth2-clients`, which is read later,
    // because a declaration file the broker cannot use should mean no socket is
    // ever created -- not a socket an agent connects to, finds nothing behind,
    // and has to diagnose from a daemon that has already exited. The sentence
    // above this function's bind already claims that everything that could
    // refuse has refused; this is the flag that made that true of it.
    //
    // And the refusal is a startup refusal for the same reason `--oauth2-clients`
    // is: an operator who wrote a registry file the broker half-understands
    // would otherwise learn it at the first pull, as a mystery.
    if let Some(path) = &registries {
        match asv_broker::registry_declaration::load(path) {
            Ok(declarations) => {
                let declared = declarations.len();
                tracing::info!(declared, "OCI registries declared");
                state.registries = declarations;
            }
            Err(error) => {
                eprintln!(
                    "asv: --registries {} cannot be used: {error}",
                    path.display()
                );
                std::process::exit(1);
            }
        }
    }

    // Bound only now: everything the operator declared has been read, and
    // everything that could refuse has refused.
    let listener = UnixListener::bind(&socket_path)?;
    set_socket_mode(&socket_path)?;
    tracing::info!(
        path = %socket_path.display(),
        protocol = asv_ipc_protocol::PROTOCOL_VERSION,
        workers = ?state.workers.names(),
        "broker listening"
    );

    if let Some(report) = self_report {
        state.self_report = report;
    }
    {
        // Set unconditionally, and **after** the conditional block above: a
        // broker run without `--harden` has no Landlock ruleset and no
        // `PR_SET_DUMPABLE`, and the temptation to report "no protections
        // measured, no identity either" is exactly the conflation this field
        // exists to prevent. The identity was measured either way.
        let (uid, declared) = identity_verdict.as_measured();
        state.self_report.identity =
            Some(asv_ipc_protocol::BrokerIdentity::measured(uid, declared));
    }
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
        let restored = log.query(0).len();
        let dropped = log.dropped();
        // Wrapped once, here, and handed to every path that appends: the
        // socket loop, and — when it is on — the CONNECT listener. One chain,
        // because two chains each verify on their own and an operator asking
        // "who spent this credential" would have to check both.
        state.audit = Arc::new(std::sync::Mutex::new(log));
        tracing::info!(path = %path.display(), restored, dropped, "durable audit log opened");
    } else if let Some(max) = audit_max_records {
        // Operator-configured retention (R9). 0 = unbounded. Logged so the
        // launch contract is visible in the broker's own output.
        state.audit = Arc::new(std::sync::Mutex::new(asv_broker::audit::AuditLog::new(max)));
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
        let vault_port: Arc<dyn asv_connector_http::SecretPort> =
            Arc::new(VaultSecretPort::new(Arc::clone(&store), key));
        state.secrets = Some(match &oauth2_clients {
            None => vault_port,
            Some(path) => {
                // Refusing to start on a bad registration file is the point.
                // A registration the broker half-understands would leave an
                // operator believing a credential is traded for a token when
                // the failure surfaces later, as a mystery, at the first
                // operation instead of here.
                let clients = match asv_broker::oauth2_port::load_clients(path) {
                    Ok(clients) => clients,
                    Err(error) => {
                        eprintln!(
                            "asv: --oauth2-clients {} cannot be used: {error}",
                            path.display()
                        );
                        std::process::exit(1);
                    }
                };
                let registered = clients.len();
                // Two passes over one `Vec<LoadedClient>`, and the pairing
                // between a port registration and a binding is by index over the
                // same list. It would be shorter to collect one `Vec` and build
                // the other later, but the binding needs the routing port to
                // exist first — and a binding built against a not-yet-real port
                // is a window in which it could borrow from the *vault*, which
                // for this provider means handing the client secret to the
                // resource as if it were a token. That is the one failure in
                // this file worth writing two loops to make impossible.
                let port_clients: Vec<_> =
                    clients.iter().map(|loaded| loaded.client.clone()).collect();
                let oauth2: Arc<dyn asv_connector_http::SecretPort> =
                    Arc::new(asv_broker::oauth2_port::OAuth2SecretPort::new(
                        Arc::clone(&vault_port),
                        port_clients,
                    ));
                // Only a credential that is *not registered* reaches the vault.
                // A provider failure is a refusal, so a temporary outage cannot
                // be answered by handing the operation the client secret.
                let routing: Arc<dyn asv_connector_http::SecretPort> = Arc::new(
                    asv_broker::oauth2_port::RoutingSecretPort::new(oauth2, vault_port),
                );
                for loaded in clients {
                    // A resource host that cannot be vetted stops the broker
                    // here, with a message about the configuration, rather than
                    // at the first agent call where it would be blamed on a
                    // credential the operator did not break.
                    match asv_broker::oauth2_binding::OAuth2Binding::new(
                        loaded.deployment,
                        loaded.client.client_id.clone(),
                        Arc::clone(&routing),
                    ) {
                        Ok(binding) => state.oauth2.push(binding),
                        Err(error) => {
                            eprintln!(
                                "asv: --oauth2-clients {} cannot be used for {}: {error}",
                                path.display(),
                                loaded.client.credential
                            );
                            std::process::exit(1);
                        }
                    }
                }
                tracing::info!(registered, "OAuth2 clients registered");
                routing
            }
        });

        tracing::info!(
            vault = %vault_path.display(),
            credentials = inventory.loaded,
            skipped = inventory.skipped,
            collisions = inventory.collisions,
            oauth2_clients = oauth2_clients.as_ref().map(|p| p.display().to_string()),
            registries = registries.as_ref().map(|p| p.display().to_string()),
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
    // exists to prevent. It is also what the CONNECT listener is spawned on, so
    // the binding is named rather than `_`: a reader seeing `_runtime` next to
    // a `runtime.spawn` further down would have to check whether the two were
    // the same value.
    let runtime_guard = runtime;

    // M9 / V1-C2: the CONNECT proxy, if the operator asked for one.
    //
    // Gated on a vault for a reason that is not a convenience: a tunnel with no
    // credential behind it is refused, so a broker with no vault could only
    // ever report a refusal. Starting it there would mean a second socket that
    // answers "no" to everything, and an operator would have to work out
    // whether that was a policy decision or a misconfiguration.
    //
    // The signal is the state's own (C2.8), not a local. It used to be built
    // here, and a local is precisely the defect: `EndSession` has to mark a
    // session revoked in the very object the listener cancels against, and
    // with a local in `main` the socket handler could not name that object at
    // all. So the whole revocation path worked in tests and did not exist in
    // the product.
    let shutdown = Arc::clone(&state.shutdown);
    // The gauge the drain waits on, created here rather than inside the listener
    // because the watcher thread has to be able to read it and the listener is
    // moved into the accept task.
    let in_flight = Arc::new(asv_broker::connect_listener::InFlight::default());
    // Installed before the listener rather than after it, so there is no window
    // in which the broker is serving tunnels and cannot yet be told to stop.
    install_ordered_shutdown(Arc::clone(&shutdown), Arc::clone(&in_flight));
    if let Some(addr) = connect_listen.as_deref() {
        let Some(secrets) = state.secrets.clone() else {
            eprintln!("asv: --connect-listen needs --vault; a tunnel with no credential behind it is refused");
            std::process::exit(1);
        };

        let bind: std::net::SocketAddr = addr.parse().unwrap_or_else(|e| {
            eprintln!("asv: --connect-listen address {addr:?} is not a valid ADDR:PORT: {e}");
            std::process::exit(1);
        });
        // Loopback only unless the operator says otherwise, and *not* silently:
        // this socket carries a proxy, and a proxy bound to 0.0.0.0 is a
        // decision with consequences that belongs in the launch contract rather
        // than in a default.
        if !bind.ip().is_loopback() {
            tracing::warn!(
                %bind,
                "the CONNECT listener is bound to a non-loopback address; every host that can \
                 reach it can open a tunnel, subject to the allow-list"
            );
        }

        let ca = Arc::new(asv_broker::tls_bridge::SessionCa::new(
            format!("connect-{}", asv_broker::surrogate::now_secs()),
            0,
            std::time::Duration::from_secs(3600),
        ));
        let leaves = Arc::new(asv_broker::connect_runtime::SessionLeafSource::new(
            Arc::clone(&ca),
        ));
        tracing::info!(
            root_len = ca.root_der.len(),
            "session CA generated for the CONNECT path"
        );

        // C2.6: the route table, loaded from the operator's file and authorized
        // against the policy engine one step above. Absent a file the table is
        // empty, which is the same closed posture this listener shipped with —
        // but now it is *closed by declaration* rather than by a hardcoded
        // empty `Vec`, and an operator can open it without a rebuild.
        //
        // A file that fails to load is fatal, and deliberately so. The
        // alternative — start with an empty table and log — is a broker that
        // looks healthy while authorizing nothing, which is the one reading an
        // operator cannot distinguish from "my routes are in force".
        let routes = match connect_routes.as_deref() {
            Some(path) => {
                let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
                    eprintln!("asv: cannot read --connect-routes {}: {e}", path.display());
                    std::process::exit(1);
                });
                let set = asv_broker::connect_routes::ConnectRouteSet::load(&text, &state.policy)
                    .unwrap_or_else(|e| {
                        eprintln!("asv: --connect-routes {} refused: {e}", path.display());
                        std::process::exit(1);
                    });
                tracing::info!(
                    path = %path.display(),
                    routes = set.len(),
                    "CONNECT route table loaded and authorized"
                );
                Arc::new(set)
            }
            None => {
                tracing::warn!(
                    "no --connect-routes given; the CONNECT listener will refuse every \
                     destination. This is the closed default, not a policy decision about \
                     any particular host."
                );
                Arc::new(asv_broker::connect_routes::ConnectRouteSet::default())
            }
        };
        // In state, not just in the listener: `CreateSession` mints one
        // surrogate per route, and it has no other way to learn which
        // credentials this broker will tunnel to. Set here, before the accept
        // loop, so no session can be created against a half-loaded table.
        state.connect_routes = Arc::clone(&routes);

        // The handler takes the table rather than a family and a credential
        // name, so which credential a tunnel may spend is the route's answer and
        // not a constant of this process. The old constant pair would have
        // substituted a GitHub credential for every host the first allow-list
        // let through.
        let handler = Arc::new(asv_broker::connect_runtime::SubstitutingHandler::new(
            Arc::clone(&state.surrogates),
            secrets,
            Arc::clone(&state.audit),
            Arc::clone(&routes),
        ));

        // The session store and the surrogate registry are the broker's own,
        // shared with the socket path — *not* fresh instances. A fresh
        // `SessionStore::new()` here compiles, binds, serves and refuses every
        // proof, which is a proxy that looks alive and can never establish a
        // tunnel; a fresh registry would mean a surrogate minted over the socket
        // is unknown to this path. Both are the same failure wearing two
        // different hats, and both are invisible until someone runs a real
        // CONNECT.
        let sessions = Arc::clone(&state.sessions);
        // C2.8: the anchors a TLS destination is verified against. Read from the
        // operator's file and *only* from it — an empty store verifies nothing,
        // so a broker started without this refuses every route that says
        // `"upstream": "tls"` instead of trusting whatever the internet's CAs
        // happen to say. A file that cannot be read is fatal for the same
        // reason a bad route file is: a broker that looks healthy while
        // verifying nothing is a reading an operator cannot act on.
        let mut destination_roots = rustls::RootCertStore::empty();
        if let Some(path) = connect_roots.as_deref() {
            let pem = std::fs::read(path).unwrap_or_else(|e| {
                eprintln!("asv: cannot read --connect-roots {}: {e}", path.display());
                std::process::exit(1);
            });
            // Parsed by rustls' own PEM reader rather than a hand-rolled one:
            // an anchor file is a place where a bespoke parser is a place where
            // "it loaded" and "it loaded the right certificates" come apart.
            //
            // Every section is counted. A file with one good certificate and
            // nine unparseable ones loads, verifies almost nothing, and reads as
            // working — so the unusable sections are named in the log rather
            // than dropped in a `filter_map` that cannot report itself.
            let mut usable = Vec::new();
            let mut unparseable = 0usize;
            for section in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
                match section {
                    Ok(der) => usable.push(der),
                    Err(_) => unparseable += 1,
                }
            }
            let (_, rejected) = destination_roots.add_parsable_certificates(usable);
            tracing::info!(
                path = %path.display(),
                anchors = destination_roots.len(),
                unparseable_sections = unparseable,
                rejected,
                "destination trust anchors loaded"
            );
            if destination_roots.is_empty() {
                eprintln!(
                    "asv: --connect-roots {} contained no usable certificate; every TLS \
                     destination would be refused",
                    path.display()
                );
                std::process::exit(1);
            }
        } else {
            tracing::warn!(
                "no --connect-roots given; the anchor store is empty, so every route \
                 declaring \"upstream\": \"tls\" is refused. The public root set is \
                 deliberately not the default: it would decide on the internet's say-so \
                 who receives this product's credentials."
            );
        }

        let connect_listener = asv_broker::connect_listener::ConnectListener::new(
            leaves,
            Arc::new(asv_broker::connect_runtime::SystemUpstream),
            Arc::new(asv_broker::connect_runtime::SharedSessions::new(sessions)),
            Arc::clone(&shutdown),
            routes.to_connect_policy().allowed,
            asv_broker::connect_listener::ListenerConfig::default(),
        )
        .with_upstream_transport(
            Arc::new(asv_broker::connect_runtime::RouteTransports(Arc::clone(
                &routes,
            ))),
            Arc::new(destination_roots),
        )
        .with_in_flight(Arc::clone(&in_flight));

        let tcp = std::net::TcpListener::bind(bind).unwrap_or_else(|e| {
            eprintln!("asv: cannot bind the CONNECT listener on {bind}: {e}");
            std::process::exit(1);
        });
        tcp.set_nonblocking(true).unwrap_or_else(|e| {
            eprintln!("asv: the CONNECT listener must be non-blocking: {e}");
            std::process::exit(1);
        });
        // The reactor context is required here, and it was missing.
        //
        // `tokio::net::TcpListener::from_std` registers the descriptor with the
        // runtime's reactor, and there is no ambient reactor on the main thread
        // just because a `Runtime` exists in scope — `runtime_guard` below is
        // held for its *lifetime*, not entered. So `--connect-listen` panicked
        // at startup with "there is no reactor running" and the CONNECT listener
        // has never once started in a real broker process.
        //
        // Every CONNECT test constructs its listener in-process, where the test
        // already runs inside a runtime, which is exactly why the suite stayed
        // green over a surface that could not come up. The binding is entered
        // rather than the whole function because that is the smallest scope that
        // fixes it: `Handle::spawn` further down does not need a context, and
        // entering one for the whole function would pin the reactor for the
        // life of the accept loop for no reason.
        let tcp = {
            let _reactor = runtime_guard.enter();
            tokio::net::TcpListener::from_std(tcp).unwrap_or_else(|e| {
                eprintln!("asv: cannot adopt the CONNECT listener: {e}");
                std::process::exit(1);
            })
        };
        // Read back from the listener, not from `bind`.
        //
        // Port 0 is the kernel saying "choose one", and `bind` still holds the
        // literal `127.0.0.1:0` that was asked for. Publishing that would hand
        // every session a port nobody is listening on, and the failure is
        // silent: the shim forwards each CONNECT into a closed port and the
        // session simply never tunnels. The log line had the same defect, and
        // this is the assertion that caught it.
        let bound = tcp.local_addr().unwrap_or_else(|e| {
            eprintln!("asv: cannot read back the CONNECT listener address: {e}");
            std::process::exit(1);
        });
        tracing::info!(%bound, "CONNECT listener bound");

        // Published so `asv run` can start this session's shim without being
        // told where to point it.
        state.self_report.connect_listen = Some(bound.to_string());

        // Cloned before the spawn because the task outlives this scope: moving
        // `state.audit` in would take a field out of a `BrokerState` the socket
        // loop is still using for the rest of the process's life.
        let audit_for_listener = Arc::clone(&state.audit);
        let report = Arc::new(asv_broker::connect_runtime::ChainReport::new(
            Arc::new(asv_broker::connect_listener::DiscardReport),
            audit_for_listener,
        ));
        runtime_guard.spawn(async move { connect_listener.run(tcp, handler, report).await });
    }

    // Shared, not borrowed. The loop below hands a handle to every connection
    // thread, and `BrokerState` is `Send + Sync` because each capability
    // carries its own lock rather than the state carrying one lock for all of
    // them.
    let state = Arc::new(state);
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                // The counter is incremented BEFORE the thread is spawned and
                // decremented inside it, so a burst of connections arriving
                // faster than they are served cannot race past the cap.
                let admitted = in_flight
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| (n < MAX_IN_FLIGHT_CONNECTIONS).then_some(n + 1),
                    )
                    .is_ok();
                if !admitted {
                    // Refused rather than queued. A queued connection is a
                    // client waiting on work the broker has not agreed to do,
                    // and refusing fails closed: nothing was read, nothing was
                    // applied, the client sees a closed socket.
                    tracing::warn!(
                        limit = MAX_IN_FLIGHT_CONNECTIONS,
                        "connection refused: that many are already in flight"
                    );
                    continue;
                }
                let state = Arc::clone(&state);
                let in_flight = Arc::clone(&in_flight);
                std::thread::spawn(move || {
                    // One bad connection must not take the broker down
                    // (UAT-017 requires fail-closed, not fail-crashed), and one
                    // slow connection must not delay another agent: `serve`
                    // runs to its own 5s deadline on this thread while the
                    // accept loop is already back on the next `incoming()`.
                    if let Err(e) = serve(&state, stream) {
                        tracing::warn!(error = %e, "connection failed");
                    }
                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }

    Ok(())
}

/// How long one connection may take before the broker stops waiting on it.
///
/// **This is the bound that keeps one peer from taking the whole broker down.**
/// `serve` is called from a single-threaded accept loop, and a blocking `read`
/// on a socket the peer has opened but not written to never returns on its own.
/// Without a deadline, connecting and saying nothing is enough to stop every
/// agent from reaching every credential for as long as the attacker cares to
/// hold the connection open.
///
/// The number is deliberately far larger than the work it bounds. A real client
/// sends its whole request in one `write` immediately after `connect`; five
/// seconds is four or five orders of magnitude more than that takes. A generous
/// bound is the right kind of wrong: it never cuts off a legitimate client, and
/// it converts an unbounded stall into a finite one.
///
/// **This is a mitigation, not the fix.** The structural problem is that one
/// thread serves every peer in turn; the fix is a thread or a task per
/// connection, which needs `BrokerState` to stop being exclusively borrowed. What
/// this buys is that the worst case is bounded and observable rather than
/// permanent.
const CONNECTION_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How many connections may be in flight at once.
///
/// A thread per connection is what makes "one slow peer does not stop every
/// other agent" true, and unbounded threads is its own denial of service: a
/// peer that opens thousands of sockets costs thousands of stacks, which is
/// the same failure the sequential loop had, only moved somewhere less visible.
///
/// Sixty-four is chosen against the thing it bounds. The workers a broker
/// actually runs at once is small — a handful of agents — so the cap is never
/// what makes an operator feel it, and a peer that opens more gets a refusal
/// it can see rather than a stall it cannot.
const MAX_IN_FLIGHT_CONNECTIONS: usize = 64;

fn serve(state: &BrokerState, stream: UnixStream) -> std::io::Result<()> {
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

    // Both directions, and before the socket is split: the timeout is a property
    // of the file description, so setting it once covers the reader and the
    // writer. A write that blocks is the same denial of service as a read that
    // does — a peer that connects, asks a question and then never drains the
    // answer would otherwise pin the single thread just as effectively.
    stream
        .set_read_timeout(Some(CONNECTION_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT)))
        .map_err(|e| {
            std::io::Error::other(format!("asv brokerd could not bound the connection: {e}"))
        })?;

    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    // The raw request bytes may carry secret-shaped material: a hostile client
    // controls every field. Leaving them in a heap buffer keeps them readable by
    // any same-uid peer for the process lifetime, which is exactly the leak the
    // adversarial harness looks for. Zeroize as soon as decoding is done.
    let mut buf = vec![0u8; asv_ipc_protocol::MAX_MESSAGE_BYTES + 1];
    let n = match reader.read(&mut buf) {
        Ok(n) => n,
        // A peer that opened the socket and then went quiet, or that stopped
        // reading the answer. Neither is a broker failure, so neither is logged
        // as one: this is the connection ending, and the next one is served
        // immediately.
        Err(e) if is_timeout(&e) => {
            tracing::debug!(
                "a connection was open for {}s without a complete exchange and \
                 was closed",
                CONNECTION_IO_TIMEOUT.as_secs()
            );
            buf.zeroize();
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if n == 0 {
        buf.zeroize();
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

/// Whether `error` is the kernel reporting that one of the deadlines above
/// expired.
///
/// `WouldBlock` and `TimedOut` are both what a socket with `SO_RCVTIMEO` /
/// `SO_SNDTIMEO` set returns once the time is up, and which one you get is
/// platform-dependent — Linux reports `WouldBlock` for a plain `read`, macOS
/// reports `TimedOut` — so accepting only one of them would leave the broker
/// unbounded on the other.
fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
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
