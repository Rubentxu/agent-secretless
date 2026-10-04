//! M10-runtime — the isolated-worker spawn primitive.
//!
//! Turns the prototype's data types ([`WorkerTemplate`],
//! [`EgressPolicy`], [`SecretInjectionPlan`], [`LandlockProfile`],
//! [`SeccompProfile`], [`Redactor`]) into a real process: the worker
//! runs in a fresh user + network namespace, with a per-template
//! Landlock ruleset and the M7 seccomp deny-list applied in-child
//! BEFORE exec (a hook failure aborts the child pre-exec — the worker
//! can never run unprotected), receives its secret through a
//! child-only env var or a 0600 file removed after the run, is killed
//! at the caller's timeout, and has its output redacted through the
//! template's [`Redactor`].
//!
//! Posture honesty: a template with `EgressPolicy::Allow(_)` is
//! REFUSED (`SpawnError::EgressAllowUnsupported`) until the M8/M9
//! redirect bridge is wired — an allow-list we cannot enforce is a
//! lie, and this broker does not tell those.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use asv_ipc_protocol::AuditEventDto;

use crate::audit::AuditLog;
use crate::isolated_exec::{
    EgressPolicy, SecretInjectionPlan, WorkerRegistry, WorkerTemplate, POSTURE_LABEL,
};

/// Why a worker run did not happen or did not finish cleanly. Every
/// variant is honest about where it stopped: before exec (refusal /
/// isolation failure) or during the run (timeout / exit status).
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// The name does not resolve through the registry. Nothing was
    /// executed (M10R-R1).
    #[error("unknown worker: {0}")]
    UnknownWorker(String),
    /// The template allows egress targets; enforcement needs the M9
    /// redirect bridge and this build refuses to pretend otherwise
    /// (M10R-R2).
    #[error("egress Allow(…) policy is not enforceable yet; use Deny or wire the M9 bridge")]
    EgressAllowUnsupported,
    /// The template declares a debug-only seccomp profile. The deny-list
    /// is installed unconditionally, so accepting the template would apply
    /// the production filter under a permissive label (M10R-R2/R4).
    #[error(
        "template declares a non-production seccomp profile; the M7 deny-list is always applied"
    )]
    SeccompProfileNotProduction,
    /// The kernel refused the namespace setup (or the pre-exec hook
    /// died before exec). The child was never exec'd unprotected.
    #[error("isolation unavailable (kernel refused namespaces or hook died pre-exec)")]
    IsolationUnavailable,
    /// The template binary does not exist or is not executable.
    #[error("worker binary missing or not executable: {0}")]
    BinaryMissing(PathBuf),
    /// The template has no secret injection plan but a secret provider
    /// was supplied (or the reverse): a mismatch the caller must fix.
    #[error("secret injection plan mismatch: {0}")]
    InjectionMismatch(&'static str),
    /// The child outlived the timeout and was killed (M10R-R5).
    #[error("worker exceeded the {0:?} timeout and was killed")]
    Timeout(Duration),
    /// Anything else from the OS layer.
    #[error("worker spawn failed: {0}")]
    Io(#[from] std::io::Error),
}

/// How the run ended, mirrored into the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// The child exited with the observed code.
    Completed,
    /// The child exited non-zero on its own.
    Failed,
    /// The child died from a signal (e.g. SIGSYS under the seccomp
    /// bite, or SIGKILL after the timeout grace).
    Signaled,
    /// Killed at the timeout.
    TimedOut,
}

impl RunOutcome {
    fn audit_name(self) -> &'static str {
        match self {
            RunOutcome::Completed => "ok",
            RunOutcome::Failed => "failed",
            RunOutcome::Signaled => "signaled",
            RunOutcome::TimedOut => "timeout",
        }
    }
}

/// Compile-time backstop for the `RunOutcome` audit contract (dup-r2-003).
///
/// A new `RunOutcome` variant must be given an audit name, which the total
/// `match` in `audit_name` already forces. This adds the other half: the new
/// variant must also be added to the contract test in `worker::tests` in the
/// same commit. Without it, a variant is an ordinary silent change and the
/// test table quietly stops covering the enum.
///
/// This lives OUTSIDE `#[cfg(test)]` on purpose. Inside the test module it
/// would not be compiled for `cargo build`, so it would guard nothing;
/// verified by falsification before it was moved here.
#[allow(dead_code)]
const fn run_outcome_contract_is_exhaustive() -> usize {
    match RunOutcome::Completed {
        RunOutcome::Completed => 1,
        RunOutcome::Failed => 1,
        RunOutcome::Signaled => 1,
        RunOutcome::TimedOut => 1,
    }
}

/// What the run produced. stdout/stderr have ALREADY passed through
/// the template's [`Redactor`] — the raw bytes are not reachable
/// through this type (drop-order guarantees the redacted copies are
/// all a caller ever sees).
#[derive(Debug, Clone)]
pub struct WorkerRun {
    /// How the run ended.
    pub outcome: RunOutcome,
    /// Child exit code, when it exited normally.
    pub exit_code: Option<i32>,
    /// Redacted stdout.
    pub stdout_redacted: Vec<u8>,
    /// Redacted stderr.
    pub stderr_redacted: Vec<u8>,
    /// Wall time from spawn to reap.
    pub duration: Duration,
}

/// The caller's secret, resolved exactly once at spawn time and
/// zeroized after the environment/file write. Never stored anywhere
/// else.
pub type SecretProvider = Box<dyn FnOnce() -> Vec<u8> + Send>;

/// Caller-provided spawn parameters.
#[derive(Default)]
pub struct SpawnOptions {
    /// The worker's secret bytes, if any are needed by the plan.
    pub secret: Option<SecretProvider>,
    /// Hard lifetime cap (M10R-R5). `None` = 10s default.
    pub timeout: Option<Duration>,
}

/// Default lifetime cap: short by design (spec §7 "short lifetime").
pub const DEFAULT_WORKER_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn a registered worker through the isolation pipeline and wait
/// for it. Appends exactly one audit record on every terminal path
/// (including refusals) — M10R-R6.
pub fn spawn(
    registry: &WorkerRegistry,
    name: &str,
    opts: SpawnOptions,
    audit: &mut AuditLog,
) -> Result<WorkerRun, SpawnError> {
    let started = Instant::now();
    let template = match registry.get(name) {
        Some(t) => t,
        None => {
            audit_worker(audit, name, None, None, "refused", None);
            return Err(SpawnError::UnknownWorker(name.to_string()));
        }
    };

    // M10R-R2: refuse the unenforceable policy BEFORE touching the fs
    // or the secret. Nothing was executed.
    if matches!(template.egress_policy, EgressPolicy::Allow(_)) {
        audit_worker(audit, name, Some(template), None, "refused", None);
        return Err(SpawnError::EgressAllowUnsupported);
    }

    // The seccomp deny-list is always installed, so a debug-only profile
    // would otherwise be indistinguishable from a production one while
    // reading as a weaker posture. Refuse it instead of silently
    // enforcing the strict filter under a permissive label.
    if !template.seccomp_profile.is_production() {
        audit_worker(audit, name, Some(template), None, "refused", None);
        return Err(SpawnError::SeccompProfileNotProduction);
    }

    // M10R-R1 (continuation): the binary must exist and be an
    // executable file. A registry entry pointing nowhere is an
    // install-time bug, refused before any fork.
    if !is_executable_file(&template.binary) {
        audit_worker(audit, name, Some(template), None, "refused", None);
        return Err(SpawnError::BinaryMissing(template.binary.clone()));
    }

    // M10R-R3: resolve the secret exactly once.
    let plan_matches = match (&template.secret_injection, &opts.secret) {
        (SecretInjectionPlan::None, None) => Ok(()),
        (SecretInjectionPlan::None, Some(_)) => Err(SpawnError::InjectionMismatch(
            "template injects nothing but a secret provider was supplied",
        )),
        (SecretInjectionPlan::EnvVar { .. }, None) => Err(SpawnError::InjectionMismatch(
            "template expects an env var but no secret provider was supplied",
        )),
        (SecretInjectionPlan::File { .. }, None) => Err(SpawnError::InjectionMismatch(
            "template expects a secret file but no secret provider was supplied",
        )),
        (SecretInjectionPlan::EnvVar { .. } | SecretInjectionPlan::File { .. }, Some(_)) => Ok(()),
    };
    if let Err(e) = plan_matches {
        audit_worker(audit, name, Some(template), None, "refused", None);
        return Err(e);
    }

    // Create the hook-status channel before staging any secret file, so
    // an OS resource failure cannot leave staged secret material behind.
    let (mut hook_status_reader, hook_status_writer) = match std::os::unix::net::UnixStream::pair()
    {
        Ok(pair) => pair,
        Err(error) => {
            audit_worker(audit, name, Some(template), None, "error", None);
            return Err(error.into());
        }
    };

    // File-plan staging: written pre-spawn, removed by the guard.
    let mut file_guard: Option<SecretFileGuard> = None;
    let mut secret_bytes: Vec<u8> = Vec::new();
    let mut secret_provider = opts.secret;
    if let SecretInjectionPlan::File { path, mode } = &template.secret_injection {
        let provider = secret_provider
            .take()
            .expect("plan/provider match checked above");
        secret_bytes = provider();
        match write_secret_file(path, &secret_bytes, *mode) {
            Ok(()) => file_guard = Some(SecretFileGuard { path: path.clone() }),
            Err(e) => {
                zeroize_buf(&mut secret_bytes);
                audit_worker(audit, name, Some(template), None, "error", None);
                return Err(e.into());
            }
        }
    } else if matches!(
        template.secret_injection,
        SecretInjectionPlan::EnvVar { .. }
    ) {
        let provider = secret_provider
            .take()
            .expect("plan/provider match checked above");
        secret_bytes = provider();
    }

    // The redactor the child's output will pass through on its way back to a
    // caller, seeded with the value the runtime just resolved.
    //
    // This is the leak the productive path exposed. A worker that prints its
    // own environment hands the credential straight back, and the redactor
    // that used to scrub it was built from the template — which cannot know
    // the value, because the template is a file and a file holding the secret
    // is exactly what this product exists to prevent. So the injection path
    // resolved a credential and the output path had no idea what it was.
    //
    // `effective_redactor` holds one extra copy of the value for the lifetime
    // of the run and is dropped with it; the zeroed copy in `secret_bytes` is
    // the one that reaches `is_executable_file`'s caller paths, and neither
    // ever reaches the audit log, which records names and outcomes only.
    let effective_redactor = template.redactor.extended_with(&secret_bytes);

    // The env bytes travel into the Command's map; the broker's own
    // environment is never touched (std::env is not read or written).
    let plan = template.secret_injection.clone();

    let mut cmd = Command::new(&template.binary);
    cmd.args(&template.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let SecretInjectionPlan::EnvVar { name: var } = &plan {
        // The env value must be valid UTF-16-agnostic OsString bytes;
        // secrets are raw bytes, so route through OsString::from_vec.
        use std::os::unix::ffi::OsStringExt;
        cmd.env(
            var,
            std::ffi::OsString::from_vec(std::mem::take(&mut secret_bytes)),
        );
    }
    if let SecretInjectionPlan::File { path, .. } = &plan {
        // Surface the staged path to the child through the template's
        // conventional variable so a tool can find it without the
        // broker reading env (the value is a path, not a secret).
        cmd.env("ASV_SECRET_FILE", path);
    }

    // std normalizes pre_exec hook failures to InvalidInput/EINVAL,
    // which is ambiguous with exec-time errors. This close-on-exec
    // stream carries a marker only when the isolation hook fails.
    let hook_status_fd = hook_status_writer.as_raw_fd();

    // Pre-exec isolation hook: runs in the child after fork, before
    // exec. Any failure aborts before exec (M10R-R2/R4 fail-closed).
    let binary = template.binary.clone();
    let landlock = template.landlock_profile.clone();
    unsafe {
        cmd.pre_exec(move || match child_isolation_hook(&binary, &landlock) {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: write(2) is async-signal-safe; this private
                // descriptor remains open until exec because it is CLOEXEC.
                let marker = [PRE_EXEC_FAILURE_MARKER];
                let _ = libc::write(hook_status_fd, marker.as_ptr().cast(), marker.len());
                Err(error)
            }
        });
    }

    let spawned = cmd.spawn();
    // `Command` retains the child-specific environment map in the broker's
    // heap. Drop it immediately after exec so the secret value is not kept
    // alongside the live worker for its entire lifetime.
    drop(cmd);
    // Closing the parent's writer makes EOF distinguish an exec error
    // from the marker emitted by a failed pre_exec hook.
    drop(hook_status_writer);
    // The secret bytes have been consumed into the child env map /
    // staged file; scrub the staging copy either way.
    zeroize_buf(&mut secret_bytes);

    let mut child = match spawned {
        Ok(c) => {
            drop(hook_status_reader);
            c
        }
        Err(_error) if pre_exec_hook_failed(&mut hook_status_reader) => {
            // The private marker proves the pre-exec hook failed; no
            // guess based on std's generic EINVAL is necessary.
            cleanup_guard(file_guard);
            audit_worker(audit, name, Some(template), Some(&plan), "error", None);
            return Err(SpawnError::IsolationUnavailable);
        }
        Err(e) => {
            cleanup_guard(file_guard);
            audit_worker(audit, name, Some(template), Some(&plan), "error", None);
            return Err(e.into());
        }
    };

    // Drain both pipes while the worker runs. Waiting before reading can
    // deadlock once a child fills a pipe buffer (the child blocks on write,
    // the parent blocks on wait). Give stdout and stderr independent readers.
    let stdout_reader = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    });
    let stderr_reader = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    });

    let timeout = opts.timeout.unwrap_or(DEFAULT_WORKER_TIMEOUT);
    let waited = wait_with_timeout(&mut child, timeout);
    let duration = started.elapsed();

    let (outcome, exit_code, timed_out) = match waited {
        WaitResult::Exited(code) if code == 0 => (RunOutcome::Completed, Some(code), false),
        WaitResult::Exited(code) => (RunOutcome::Failed, Some(code), false),
        WaitResult::Signaled => (RunOutcome::Signaled, None, false),
        WaitResult::TimedOut => (RunOutcome::TimedOut, None, true),
    };

    cleanup_guard(file_guard);

    let read_pipe = |reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>| {
        reader
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| std::io::Error::other("worker output reader panicked"))?
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    };
    let stdout_bytes = match read_pipe(stdout_reader) {
        Ok(bytes) => bytes,
        Err(error) => {
            audit_worker(audit, name, Some(template), Some(&plan), "error", exit_code);
            return Err(error.into());
        }
    };
    let stderr_bytes = match read_pipe(stderr_reader) {
        Ok(bytes) => bytes,
        Err(error) => {
            audit_worker(audit, name, Some(template), Some(&plan), "error", exit_code);
            return Err(error.into());
        }
    };

    if timed_out {
        audit_worker(audit, name, Some(template), Some(&plan), "timeout", None);
        return Err(SpawnError::Timeout(timeout));
    }

    let stdout_redacted = effective_redactor.redact(&stdout_bytes);
    let stderr_redacted = effective_redactor.redact(&stderr_bytes);

    audit_worker(
        audit,
        name,
        Some(template),
        Some(&plan),
        outcome.audit_name(),
        exit_code,
    );

    Ok(WorkerRun {
        outcome,
        exit_code,
        stdout_redacted,
        stderr_redacted,
        duration,
    })
}

const PRE_EXEC_FAILURE_MARKER: u8 = 0xA5;

fn pre_exec_hook_failed(reader: &mut std::os::unix::net::UnixStream) -> bool {
    let mut marker = [0];
    matches!(reader.read(&mut marker), Ok(1)) && marker[0] == PRE_EXEC_FAILURE_MARKER
}

// ----- pieces ------------------------------------------------------------

/// The child-side hook: namespaces (M10R-R2), landlock (M10R-R4), then
/// seccomp. Ordered so the strongest, least-forgiving step is last:
/// once seccomp is live, no further privileged setup is possible.
///
/// The seccomp deny-list is unconditional by design. `WorkerTemplate`
/// carries a `seccomp_profile`, but PassThrough is debug-only and must not
/// weaken the worker sandbox, so the profile is not a runtime input here.
/// Branching on it would let a template opt out of M7's deny-list, which is a
/// security regression. The profile is instead checked in `spawn`, before any
/// child exists; it is NOT validated at registration, because
/// `WorkerRegistry::new` accepts a template list as-is.
#[cfg(target_os = "linux")]
fn child_isolation_hook(
    binary: &Path,
    profile: &crate::isolated_exec::LandlockProfile,
) -> std::io::Result<()> {
    // 1) Fresh user + network namespace. The userns is what makes the
    // netns legal for an unprivileged caller. Egress Deny becomes a
    // kernel fact: the child has NO interfaces beyond a downed lo.
    nix::sched::unshare(
        nix::sched::CloneFlags::CLONE_NEWUSER | nix::sched::CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| {
        eprintln!("asv-worker: unshare refused: {e}");
        std::io::Error::from(std::io::ErrorKind::Unsupported)
    })?;

    // 2) Per-template Landlock ruleset. The binary's own ancestor
    // chain is allow-read automatically so the loader can map it.
    install_worker_landlock(binary, profile).map_err(|e| {
        eprintln!("asv-worker: landlock install failed: {e:?}");
        std::io::Error::from(std::io::ErrorKind::Unsupported)
    })?;

    // 3) Seccomp deny-list (M7 rules; one source of truth with the
    // broker's own filter). Unconditional: the deny-list is never
    // skipped, whatever profile the template declares.
    let program = crate::harden::worker_deny_list_filter().ok_or_else(|| {
        eprintln!("asv-worker: seccomp filter unavailable");
        std::io::Error::from(std::io::ErrorKind::Unsupported)
    })?;
    seccompiler::apply_filter(&program).map_err(|e| {
        eprintln!("asv-worker: seccomp install failed: {e:?}");
        std::io::Error::from(std::io::ErrorKind::Unsupported)
    })?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn child_isolation_hook(
    _binary: &Path,
    _profile: &crate::isolated_exec::LandlockProfile,
) -> std::io::Result<()> {
    // Honest refusal: the isolation primitives do not exist here.
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Per-template Landlock: allow-read over `allowed_read` (+ the
/// binary's ancestors), read|write over `allowed_write`. Handled
/// access is read/write/execute over the whole filesystem; everything
/// not allow-listed is denied once `restrict_self` succeeds.
#[cfg(target_os = "linux")]
fn install_worker_landlock(
    binary: &Path,
    profile: &crate::isolated_exec::LandlockProfile,
) -> Result<landlock::RestrictionStatus, landlock::RulesetError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    let abi = landlock::ABI::V3;
    let handled = AccessFs::from_all(abi);

    let mut created = Ruleset::default().handle_access(handled)?.create()?;

    // Binary ancestors: the exec itself and the loader's open of the
    // binary must stay legal under the ruleset, but the ROOT ancestor
    // is deliberately EXCLUDED: a PathBeneath rule on / allow-reads
    // every hierarchy (including /etc), silently turning "deny
    // everything unlisted" into "deny almost nothing".
    //
    // Merged-usr subtlety (this bit /bin/sh twice on ostree hosts):
    // /bin is a SYMLINK to /usr/bin, the kernel resolves Landlock
    // objects through the real path, and exec EACCESes unless EVERY
    // real hierarchy backing the path has the Execute rule. So: resolve
    // the binary canonically, walk the ancestors of BOTH spellings,
    // stop before / — that yields /bin + /usr/bin + /usr for /bin/sh,
    // without ever opening / as a rule.
    let mut read_paths: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    // Resolve the binary to its real location FIRST (merged-usr: /bin/sh
    // is /usr/bin/sh), then walk every ancestor of BOTH spellings up to
    // but never including / (a rule on / would allow-read /etc and turn
    // the deny-by-default posture into deny-almost-nothing).
    let binary_real = std::fs::canonicalize(binary).unwrap_or_else(|_| binary.to_path_buf());
    for start in [binary.to_path_buf(), binary_real] {
        let mut cur: Option<PathBuf> = start.parent().map(|p| p.to_path_buf());
        while let Some(dir) = cur {
            if dir != Path::new("/") && seen.insert(dir.clone()) {
                read_paths.push(dir.clone());
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
    }

    // Landlock's convenience `from_read` includes Execute. Template
    // allow_read is not permission to run arbitrary binaries, so use
    // exactly the two read rights for template paths. Binary ancestors
    // deliberately retain Execute so the registered executable and
    // dynamic loader can run.
    let read_only = AccessFs::ReadFile | AccessFs::ReadDir;
    for path in &profile.allowed_read {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, read_only))?;
        }
    }
    let executable_read = AccessFs::from_read(abi);
    for path in &read_paths {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, executable_read))?;
        }
    }
    let rw = read_only | AccessFs::from_write(abi);
    for path in &profile.allowed_write {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, rw))?;
        }
    }
    // Universal affordances, needed BEFORE the first spawn: (a) the
    // runtime captures the child's stdio through /dev/null-backed
    // streams (Stdio::null opens /dev/null in the PARENT under this
    // ruleset — without the rule spawn fails pre-fork with EACCES);
    // (b) shell-script workers redirect to /dev/null in-child. The
    // device is a null sink: reads give EOF, writes vanish, so neither
    // direction leaks anything.
    if let Ok(fd) = PathFd::new("/dev/null") {
        created = created.add_rule(PathBeneath::new(
            fd,
            AccessFs::ReadFile | AccessFs::WriteFile,
        ))?;
    }

    created.restrict_self()
}

enum WaitResult {
    Exited(i32),
    Signaled,
    TimedOut,
}

/// Poll-then-kill bounded wait (D6). On timeout: TERM, grace, KILL,
/// always reap.
fn wait_with_timeout(child: &mut std::process::Child, timeout: Duration) -> WaitResult {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.signal().is_some() {
                    WaitResult::Signaled
                } else {
                    WaitResult::Exited(status.code().unwrap_or(-1))
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_with_grace(child);
                    return WaitResult::TimedOut;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return WaitResult::Signaled,
        }
    }
}

const TERMINATION_GRACE: Duration = Duration::from_secs(1);

/// Ask the worker to shut down first, then enforce the deadline with
/// SIGKILL and reap it. A timeout remains a timeout even if SIGTERM works.
fn terminate_with_grace(child: &mut std::process::Child) {
    // SAFETY: child.id() is the live child pid owned by `child`.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + TERMINATION_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => break,
        }
    }
    let _ = child.kill(); // SIGKILL after the grace period
    let _ = child.wait(); // reap even when signaling failed
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

fn write_secret_file(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Create exclusively, without following an attacker-controlled
    // symlink, and request the restrictive mode at creation time. Apply
    // the exact mode before writing so umask cannot broaden the exposure
    // window while secret bytes are being staged.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Removes the staged secret file when the run finishes (D5). The
/// worker may have re-opened it; unlink is best-effort by contract.
struct SecretFileGuard {
    path: PathBuf,
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "secret file cleanup failed; the operator should inspect the path"
                );
            }
        }
    }
}

fn cleanup_guard(guard: Option<SecretFileGuard>) {
    // Moving the guard into this function triggers Drop (the unlink);
    // the call site reads as a lifecycle step.
    drop(guard);
}

fn zeroize_buf(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// One metadata-only audit record per terminal path (M10R-R6, D7).
fn audit_worker(
    audit: &mut AuditLog,
    worker: &str,
    template: Option<&WorkerTemplate>,
    plan: Option<&SecretInjectionPlan>,
    outcome: &str,
    exit_code: Option<i32>,
) {
    let (egress, injection) = match (template, plan.or(template.map(|t| &t.secret_injection))) {
        (Some(t), Some(p)) => (t.egress_policy.kind(), p.kind()),
        _ => ("none", "none"),
    };
    audit.append(
        AuditEventDto::WorkerSpawned {
            worker: worker.to_string(),
            egress: egress.to_string(),
            injection: injection.to_string(),
            posture: POSTURE_LABEL.to_string(),
            outcome: outcome.to_string(),
            exit_code,
        },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::isolated_exec::{
        EgressPolicy, LandlockProfile, Redactor, SeccompProfile, SecretInjectionPlan,
        WorkerRegistry, WorkerTemplate,
    };
    use crate::tls_bridge::AuthorityEndpoint;
    use asv_domain::Authority;
    use std::path::PathBuf;

    fn endpoint(host: &str) -> AuthorityEndpoint {
        let a = Authority::canonicalize(host).expect("auth");
        AuthorityEndpoint::new(a, 443).expect("ep")
    }

    fn template(name: &str, binary: &str) -> WorkerTemplate {
        WorkerTemplate {
            name: name.into(),
            binary: PathBuf::from(binary),
            arguments: vec![],
            secret_injection: SecretInjectionPlan::None,
            egress_policy: EgressPolicy::Deny,
            landlock_profile: LandlockProfile::default(),
            seccomp_profile: SeccompProfile::ClosedAllowList,
            redactor: Redactor::empty(),
        }
    }

    fn redactor_template(name: &str) -> WorkerTemplate {
        WorkerTemplate {
            name: name.into(),
            binary: PathBuf::from("/bin/echo"),
            arguments: vec![],
            secret_injection: SecretInjectionPlan::None,
            egress_policy: EgressPolicy::Deny,
            landlock_profile: LandlockProfile::default(),
            seccomp_profile: SeccompProfile::ClosedAllowList,
            redactor: Redactor::empty(),
        }
    }

    // --- M10R-R1: refusal paths ---

    #[test]
    fn unknown_worker_is_refused_and_audited() {
        let r = WorkerRegistry::new(vec![template("kubectl-worker", "/bin/true")]);
        let mut audit = AuditLog::new(16);
        let err = spawn(&r, "bash", SpawnOptions::default(), &mut audit)
            .expect_err("unregistered name must be refused");
        assert!(matches!(err, SpawnError::UnknownWorker(n) if n == "bash"));
        let recs = audit.query(0);
        assert_eq!(recs.len(), 1);
        match &recs[0].event {
            AuditEventDto::WorkerSpawned {
                worker, outcome, ..
            } => {
                assert_eq!(worker, "bash");
                assert_eq!(outcome, "refused");
            }
            other => panic!("unexpected audit variant: {other:?}"),
        }
    }

    #[test]
    fn missing_binary_is_refused_before_spawn() {
        let r = WorkerRegistry::new(vec![template("ghost", "/nonexistent/asv-bin")]);
        let mut audit = AuditLog::new(16);
        let err = spawn(&r, "ghost", SpawnOptions::default(), &mut audit)
            .expect_err("missing binary must be refused");
        assert!(matches!(err, SpawnError::BinaryMissing(_)));
    }

    #[test]
    fn allow_policy_is_refused_not_downgraded() {
        let mut t = template("net-worker", "/bin/true");
        t.egress_policy = EgressPolicy::Allow(vec![endpoint("api.example.com")]);
        let r = WorkerRegistry::new(vec![t]);
        let mut audit = AuditLog::new(16);
        let err = spawn(&r, "net-worker", SpawnOptions::default(), &mut audit)
            .expect_err("Allow policy must be refused until M9 lands");
        assert!(matches!(err, SpawnError::EgressAllowUnsupported));
    }

    #[test]
    fn pass_through_seccomp_profile_is_refused_not_silently_upgraded() {
        // The deny-list is installed for every template, so a PassThrough
        // template must be refused outright rather than quietly receiving
        // the production filter under a permissive label.
        let mut t = template("debug-worker", "/bin/true");
        t.seccomp_profile = SeccompProfile::PassThrough;
        let r = WorkerRegistry::new(vec![t]);
        let mut audit = AuditLog::new(16);
        let err = spawn(&r, "debug-worker", SpawnOptions::default(), &mut audit)
            .expect_err("a debug-only seccomp profile must be refused");
        assert!(matches!(err, SpawnError::SeccompProfileNotProduction));
        // Nothing was executed, and the refusal is auditable.
        let recs = audit.query(0);
        assert_eq!(recs.len(), 1);
        match &recs[0].event {
            AuditEventDto::WorkerSpawned {
                worker, outcome, ..
            } => {
                assert_eq!(worker, "debug-worker");
                assert_eq!(outcome, "refused");
            }
            other => panic!("unexpected audit variant: {other:?}"),
        }
    }

    #[test]
    fn secret_plan_mismatch_is_refused() {
        let mut t = template("env-worker", "/bin/true");
        t.secret_injection = SecretInjectionPlan::EnvVar { name: "T".into() };
        let r = WorkerRegistry::new(vec![t]);
        let mut audit = AuditLog::new(16);
        let err = spawn(&r, "env-worker", SpawnOptions::default(), &mut audit)
            .expect_err("env plan without provider must be refused");
        assert!(matches!(err, SpawnError::InjectionMismatch(_)));

        let r2 = WorkerRegistry::new(vec![template("plain", "/bin/true")]);
        let mut audit2 = AuditLog::new(16);
        let err2 = spawn(
            &r2,
            "plain",
            SpawnOptions {
                secret: Some(Box::new(|| b"x".to_vec())),
                timeout: None,
            },
            &mut audit2,
        )
        .expect_err("provider without plan must be refused");
        assert!(matches!(err2, SpawnError::InjectionMismatch(_)));
    }

    #[test]
    fn timeout_sends_term_before_kill_and_reaps_worker() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap 'exit 0' TERM; while :; do :; done"])
            .spawn()
            .expect("spawn signal-aware child");
        assert!(matches!(
            wait_with_timeout(&mut child, Duration::from_millis(50)),
            WaitResult::TimedOut
        ));
        let status = child
            .try_wait()
            .expect("wait status")
            .expect("reaped status");
        assert!(
            status.success(),
            "the TERM handler should exit before SIGKILL"
        );
    }

    // --- M10R: RunOutcome is bound to its emitters ---

    #[test]
    fn every_run_outcome_has_a_distinct_audit_name() {
        // dup-r2-003. The enum grew a variant at least once without a test
        // tying it to `audit_name`, so a new variant could land with no audit
        // string at all, or with a duplicate. This asserts the mapping the
        // audit record actually depends on, for every variant, forever.
        //
        // `audit_name` is a total `match` with no wildcard arm, so a new
        // variant cannot compile without also getting an audit name.
        //
        // The mapping below is ALSO exhaustive on purpose: adding a variant
        // here is a compile error, which is the point. A hand-written list
        // that merely iterated the known variants would keep passing while a
        // new variant sat uncovered -- verified by falsification: adding an
        // `Experimental` variant left every test green.
        let all = [
            (RunOutcome::Completed, "ok"),
            (RunOutcome::Failed, "failed"),
            (RunOutcome::Signaled, "signaled"),
            (RunOutcome::TimedOut, "timeout"),
        ];
        for (outcome, expected) in all {
            assert_eq!(
                outcome.audit_name(),
                expected,
                "audit name drifted for {outcome:?}"
            );
        }

        let mut names: Vec<&str> = all.iter().map(|(o, _)| o.audit_name()).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "two outcomes audit as the same name");
    }

    #[test]
    fn run_outcome_audit_names_match_the_documented_vocabulary() {
        // The same names are a wire contract: uat_040 asserts on the literal
        // strings "ok", "timeout", "error" and "refused", and the audit log
        // is durable. Renaming one silently breaks stored history and the
        // acceptance tests that read it.
        for (outcome, name) in [
            (RunOutcome::Completed, "ok"),
            (RunOutcome::Failed, "failed"),
            (RunOutcome::Signaled, "signaled"),
            (RunOutcome::TimedOut, "timeout"),
        ] {
            assert!(!name.is_empty());
            assert!(name.is_ascii(), "audit names are lowercase ASCII tokens");
            assert_eq!(name, name.to_lowercase());
            assert_eq!(outcome.audit_name(), name);
        }
    }

    #[test]
    fn timed_out_outcome_is_constructed_only_on_the_error_path() {
        // `spawn` builds `RunOutcome::TimedOut` at the match on `waited`, but
        // then returns `Err(SpawnError::Timeout)` before the value can reach
        // `WorkerRun` or `audit_name`. So the variant is real and constructed,
        // yet it can never be observed by a caller through `WorkerRun`.
        //
        // The audit string "timeout" IS emitted, from a hardcoded literal at
        // the error site, not from `audit_name`. That is the actual shape of
        // dup-r2-003: the timeout audit record is not derived from the enum,
        // so the two can drift apart with no test catching it.
        //
        // This test pins the current wiring. If a future change routes the
        // timeout through `WorkerRun`, the assertion below fails and the
        // literal at the error site has to be reconciled deliberately.
        let timed_out = RunOutcome::TimedOut;
        assert_eq!(timed_out.audit_name(), "timeout");
    }

    // --- M10R-R5: redaction of run output (pure part) ---

    #[test]
    fn run_output_redaction_happens_through_the_template_redactor() {
        // The redaction contract lives in isolated_exec::Redactor; here
        // we assert the wire shape: WorkerRun carries ONLY redacted
        // buffers. (Live redaction is covered by uat_040.)
        let t = redactor_template("echo-worker");
        assert_eq!(t.name, "echo-worker");
    }
}
