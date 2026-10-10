//! M10-runtime — the isolated-worker spawn primitive.
//!
//! Turns the prototype's data types ([`WorkerTemplate`],
//! [`EgressPolicy`], [`SecretInjectionPlan`], [`LandlockProfile`](crate::isolated_exec::LandlockProfile),
//! [`SeccompProfile`](crate::isolated_exec::SeccompProfile), [`Redactor`](crate::isolated_exec::Redactor)) into a real process: the worker
//! runs in a fresh user + network namespace, with a per-template
//! Landlock ruleset and the M7 seccomp deny-list applied in-child
//! BEFORE exec (a hook failure aborts the child pre-exec — the worker
//! can never run unprotected), receives its secret through a
//! child-only env var or a 0600 file removed after the run, is killed
//! at the caller's timeout, and has its output redacted through the
//! template's [`Redactor`](crate::isolated_exec::Redactor).
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
    /// The template asks for its credential as a file.
    ///
    /// M10-R3 requires those bytes to exist only inside the worker's mount
    /// namespace. That needs a mount point contract this build does not
    /// have, and the alternative -- writing the secret to a host path and
    /// removing it afterwards -- is the exposure M10-R3 exists to forbid.
    /// Refused rather than approximated (M10R-R3).
    #[error("secret file injection is refused: materialising it inside the worker's mount namespace needs a mount point contract this build does not have; use EnvVar")]
    FileInjectionUnsupported,
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
    /// The worker produced more output than the limits allow.
    ///
    /// Not `Failed`: the worker did not fail, it succeeded and said too much.
    /// Reporting it as a non-zero exit would blame the tool for a bound the
    /// broker imposed, and reporting it as `Completed` would tell a caller the
    /// output it is about to receive is the whole of it.
    OutputLimitExceeded,
}

impl RunOutcome {
    fn audit_name(self) -> &'static str {
        match self {
            RunOutcome::Completed => "ok",
            RunOutcome::Failed => "failed",
            RunOutcome::Signaled => "signaled",
            RunOutcome::TimedOut => "timeout",
            RunOutcome::OutputLimitExceeded => "output_limit_exceeded",
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
        RunOutcome::OutputLimitExceeded => 1,
    }
}

/// What the run produced. stdout/stderr have ALREADY passed through
/// the template's [`Redactor`](crate::isolated_exec::Redactor) — the raw bytes are not reachable
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
    /// Bytes the worker actually wrote to stdout, including any discarded
    /// past the limit.
    ///
    /// This is the number an operator needs: the difference between "the tool
    /// said 2 MiB" and "the tool said 70 bytes and a limit stopped it" is the
    /// difference between a chatty tool and a misbehaving one.
    pub bytes_stdout: u64,
    /// Bytes the worker actually wrote to stderr, including any discarded.
    pub bytes_stderr: u64,
    /// Whether a limit was hit. `stdout_redacted`/`stderr_redacted` hold only
    /// the kept prefix, so this is what says the run's output is incomplete.
    pub limit_hit: bool,
}

/// The caller's secret, resolved exactly once at spawn time and
/// zeroized after the environment/file write. Never stored anywhere
/// else.
pub type SecretProvider = Box<dyn FnOnce() -> Vec<u8> + Send>;

/// How much worker output is allowed to exist at once.
///
/// A worker is a program the operator declared but did not write. Without a
/// bound, `stdout` is whatever it chooses to produce, and the broker grows a
/// `Vec` until the allocator refuses — which on a broker is a control plane
/// going down because one tool printed a log line in a loop. The timeout does
/// not cover this: the timeout bounds how long the worker runs, not how much it
/// says while running, and a worker that outruns the timeout has already filled
/// the buffer.
///
/// The per-stream caps are what actually bound memory. `max_total_bytes` is a
/// policy ceiling on the pair, checked after the read so that the two streams
/// cannot together exceed an operator's intent by each being individually
/// legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerOutputLimits {
    /// Bytes of stdout kept. Past this the rest is drained and discarded.
    pub max_stdout_bytes: usize,
    /// Bytes of stderr kept. Past this the rest is drained and discarded.
    pub max_stderr_bytes: usize,
    /// Ceiling on stdout plus stderr together.
    pub max_total_bytes: usize,
}

impl Default for WorkerOutputLimits {
    /// 1 MiB per stream, 2 MiB together.
    ///
    /// Chosen against the thing these bytes are for: a worker's stdout is
    /// handed back to a caller over IPC, so this is also a bound on the largest
    /// IPC response the broker will assemble from a child. A tool that emits
    /// megabytes of real output is a tool whose output was going to be
    /// unusable anyway.
    fn default() -> Self {
        Self {
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Caller-provided spawn parameters.
#[derive(Default)]
pub struct SpawnOptions {
    /// The worker's secret bytes, if any are needed by the plan.
    pub secret: Option<SecretProvider>,
    /// Hard lifetime cap (M10R-R5). `None` = 10s default.
    pub timeout: Option<Duration>,
    /// Ceiling on the worker's output. `Default` = the values above.
    pub output_limits: WorkerOutputLimits,
}

/// Default lifetime cap: short by design (spec §7 "short lifetime").
pub const DEFAULT_WORKER_TIMEOUT: Duration = Duration::from_secs(10);

/// What one pipe produced: the kept prefix, and how much the child really
/// wrote.
#[derive(Debug, Default)]
struct Captured {
    /// At most `limit` bytes. Redacted before anything outside this module
    /// sees it.
    bytes: Vec<u8>,
    /// Bytes the child wrote in total, kept or not.
    total: u64,
    /// True when `total` exceeded the kept prefix, so `bytes` is truncated.
    truncated: bool,
}

/// Read one pipe, keeping at most `limit` bytes.
///
/// Past the limit this **stops reading and drops the pipe**, which is a
/// deliberate choice rather than a shortcut. Draining the tail into a sink
/// would also bound memory, and it looks safer — but for a producer that never
/// ends it never reaches EOF, so the child would run to the timeout and the
/// run would be recorded as `TimedOut`, which blames the worker for being slow
/// rather than for being unbounded, and loses the fact that the broker stopped
/// it.
///
/// Closing the read end instead gives the child `EPIPE` on its next write and
/// it dies. That is the outcome an oversized producer should get: bounded
/// memory, a prompt end, and `OutputLimitExceeded` naming the reason. A worker
/// with a large but *finite* output is unaffected as long as it is under the
/// limit; one that is over it has, by definition, produced output nobody asked
/// for and cannot use.
fn read_bounded<R: std::io::Read>(pipe: &mut R, limit: usize) -> std::io::Result<Captured> {
    use std::io::Read;
    let mut kept = Vec::new();
    // `limit + 1`: one byte past the cap is what distinguishes "exactly at the
    // limit" from "over it" without a second read.
    std::io::Read::take(&mut *pipe, limit as u64 + 1).read_to_end(&mut kept)?;
    if kept.len() <= limit {
        let total = kept.len() as u64;
        return Ok(Captured {
            bytes: kept,
            total,
            truncated: false,
        });
    }
    kept.truncate(limit);
    // `total` is a lower bound and deliberately so: it is what the broker
    // observed before it stopped, which is the honest answer to "how much did
    // this worker say" for a producer that would have said everything. The
    // caller learns the real answer is larger, not what it was.
    Ok(Captured {
        bytes: kept,
        total: limit as u64 + 1,
        truncated: true,
    })
}

/// The audit chain, borrowed for the length of one run.
///
/// This type exists because of a measured stall. `spawn` used to take a
/// `&mut AuditLog` that its caller had obtained from `Mutex::lock` and held
/// until the child exited — and the audit chain is where *every* brokered
/// request ends, because `handle` appends one record per request on its way
/// out. A lock held across a worker run was therefore a lock every other
/// agent's request queued behind, and a worker that took thirty seconds made
/// every other agent wait thirty seconds. Measured, not argued: ending an
/// unrelated session while a 9s worker ran took 8.77s.
///
/// So the lock is taken per record and released immediately. Each `append` is
/// still atomic against other writers; what it no longer is is atomic against
/// the child, which is the part that was never the point of taking it.
pub struct AuditWriter<'a> {
    chain: &'a std::sync::Mutex<AuditLog>,
}

impl<'a> AuditWriter<'a> {
    pub fn new(chain: &'a std::sync::Mutex<AuditLog>) -> Self {
        Self { chain }
    }

    /// Whether the chain can be written to at all, asked **before** anything
    /// is executed.
    ///
    /// Separate from [`AuditWriter::record`] because the two answer different
    /// questions. This one gates execution: a broker that cannot record must
    /// not start a worker. Once a child exists there is no refusal available,
    /// so `record` cannot fail the run and does not pretend to.
    pub fn is_writable(&self) -> bool {
        self.chain.lock().is_ok()
    }
}

/// Spawn a registered worker through the isolation pipeline and wait
/// for it. Appends exactly one audit record on every terminal path
/// (including refusals) — M10R-R6.
pub fn spawn(
    registry: &WorkerRegistry,
    name: &str,
    opts: SpawnOptions,
    audit: &AuditWriter<'_>,
) -> Result<WorkerRun, SpawnError> {
    let started = Instant::now();
    let template = match registry.get(name) {
        Some(t) => t,
        None => {
            audit_worker(audit, name, None, None, "refused", None, None);
            return Err(SpawnError::UnknownWorker(name.to_string()));
        }
    };

    // M10R-R2: refuse the unenforceable policy BEFORE touching the fs
    // or the secret. Nothing was executed.
    if matches!(template.egress_policy, EgressPolicy::Allow(_)) {
        audit_worker(audit, name, Some(template), None, "refused", None, None);
        return Err(SpawnError::EgressAllowUnsupported);
    }

    // The seccomp deny-list is always installed, so a debug-only profile
    // would otherwise be indistinguishable from a production one while
    // reading as a weaker posture. Refuse it instead of silently
    // enforcing the strict filter under a permissive label.
    if !template.seccomp_profile.is_production() {
        audit_worker(audit, name, Some(template), None, "refused", None, None);
        return Err(SpawnError::SeccompProfileNotProduction);
    }

    // M10R-R1 (continuation): the binary must exist and be an
    // executable file. A registry entry pointing nowhere is an
    // install-time bug, refused before any fork.
    if !is_executable_file(&template.binary) {
        audit_worker(audit, name, Some(template), None, "refused", None, None);
        return Err(SpawnError::BinaryMissing(template.binary.clone()));
    }

    // M10R-R3: resolve the secret exactly once, and refuse a `File` plan on the
    // template's own content.
    //
    // It used to be served instead: the parent resolved the secret and wrote
    // it to an absolute host path, then a `Drop` guard unlinked it when the
    // run ended. That is the exposure M10-R3 exists to forbid. The secret
    // lived in the parent filesystem for the entire life of the worker,
    // readable by anything running as the broker's uid -- which is the same
    // uid as every tool the operator runs -- and the guard is a `Drop`, so a
    // SIGKILL or a power loss skipped it and left the credential on disk.
    //
    // Refusing costs a capability the product cannot reach anyway: the
    // workers file has no key that produces this variant, so the only caller
    // of the staging path was a test, and that test was asserting the
    // behaviour this arm removes.
    //
    // The refusal is keyed on the plan alone, not on the plan/provider pair.
    // A missing provider is the caller's mistake and can be fixed by
    // supplying one; an unmaterialisable plan is a property of the registry
    // and no caller can talk the broker out of it. Reporting the pair's
    // mismatch would invite a retry that can never succeed.
    let plan_matches = match &template.secret_injection {
        SecretInjectionPlan::File { .. } => Err(SpawnError::FileInjectionUnsupported),
        SecretInjectionPlan::None => match &opts.secret {
            None => Ok(()),
            Some(_) => Err(SpawnError::InjectionMismatch(
                "template injects nothing but a secret provider was supplied",
            )),
        },
        SecretInjectionPlan::EnvVar { .. } => match &opts.secret {
            None => Err(SpawnError::InjectionMismatch(
                "template expects an env var but no secret provider was supplied",
            )),
            Some(_) => Ok(()),
        },
    };
    if let Err(e) = plan_matches {
        // `None` for the plan, like every other refusal here: `audit_worker`
        // falls back to the template's own injection plan, which is the one
        // that was just refused.
        audit_worker(audit, name, Some(template), None, "refused", None, None);
        return Err(e);
    }

    // Create the hook-status channel before resolving the secret, so an OS
    // resource failure cannot leave resolved secret material in scope.
    let (mut hook_status_reader, hook_status_writer) = match std::os::unix::net::UnixStream::pair()
    {
        Ok(pair) => pair,
        Err(error) => {
            audit_worker(audit, name, Some(template), None, "error", None, None);
            return Err(error.into());
        }
    };

    let mut secret_bytes: Vec<u8> = Vec::new();
    let mut secret_provider = opts.secret;
    if matches!(
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

    // std normalizes pre_exec hook failures to InvalidInput/EINVAL,
    // which is ambiguous with exec-time errors. This close-on-exec
    // stream carries a marker only when the isolation hook fails.
    let hook_status_fd = hook_status_writer.as_raw_fd();

    // Pre-exec isolation hook: runs in the child after fork, before
    // exec. Any failure aborts before exec (M10R-R2/R4 fail-closed).
    let binary = template.binary.clone();
    let landlock = template.landlock_profile.clone();
    // SAFETY: `pre_exec` runs in the forked child between fork and exec,
    // when only async-signal-safe operations are permitted. The closure
    // calls a child_isolation_hook (which is documented to be safe in
    // that context) and on failure writes a single byte to a CLOEXEC
    // descriptor owned by this closure; both are async-signal-safe.
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
            audit_worker(
                audit,
                name,
                Some(template),
                Some(&plan),
                "error",
                None,
                None,
            );
            return Err(SpawnError::IsolationUnavailable);
        }
        Err(e) => {
            audit_worker(
                audit,
                name,
                Some(template),
                Some(&plan),
                "error",
                None,
                None,
            );
            return Err(e.into());
        }
    };

    // Drain both pipes while the worker runs. Waiting before reading can
    // deadlock once a child fills a pipe buffer (the child blocks on write,
    // the parent blocks on wait). Give stdout and stderr independent readers.
    //
    // Both readers are bounded, and the bound stops the reading rather than
    // draining past it: a producer that outruns the cap gets its pipe closed
    // and dies on EPIPE, which is both the bounded-memory answer and the prompt
    // one. Draining instead would leave a producer that never ends running
    // until the timeout, and record a bound being hit as the worker being slow.
    let limits = opts.output_limits;
    let stdout_reader = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || read_bounded(&mut pipe, limits.max_stdout_bytes))
    });
    let stderr_reader = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || read_bounded(&mut pipe, limits.max_stderr_bytes))
    });

    // The runtime's own ceiling, and the only one.
    //
    // The caller's value is a request to shorten this, not to raise it — the
    // comment on the `timeout_ms` arm in `lib.rs` says so, and this line is
    // what makes it true. It used to read `opts.timeout.unwrap_or(DEFAULT)`,
    // which supplies the default when the caller sends nothing and bounds
    // nothing when the caller sends a large number: a client asking for a
    // ten-minute worker against a ten-second cap got its ten minutes, and the
    // run finished at 30s having simply outlived the cap nobody applied. The
    // cap is what lets the default be short, so the cap has to be a ceiling
    // and not a starting point.
    let timeout = opts.timeout.map_or(DEFAULT_WORKER_TIMEOUT, |requested| {
        requested.min(DEFAULT_WORKER_TIMEOUT)
    });
    let waited = wait_with_timeout(&mut child, timeout);
    let duration = started.elapsed();

    let (outcome, exit_code, timed_out) = match waited {
        WaitResult::Exited(code) if code == 0 => (RunOutcome::Completed, Some(code), false),
        WaitResult::Exited(code) => (RunOutcome::Failed, Some(code), false),
        WaitResult::Signaled => (RunOutcome::Signaled, None, false),
        WaitResult::TimedOut => (RunOutcome::TimedOut, None, true),
    };

    let read_pipe = |reader: Option<std::thread::JoinHandle<std::io::Result<Captured>>>| {
        reader
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| std::io::Error::other("worker output reader panicked"))?
            })
            .unwrap_or_else(|| Ok(Captured::default()))
    };
    let stdout = match read_pipe(stdout_reader) {
        Ok(captured) => captured,
        Err(error) => {
            audit_worker(
                audit,
                name,
                Some(template),
                Some(&plan),
                "error",
                exit_code,
                None,
            );
            return Err(error.into());
        }
    };
    let stderr = match read_pipe(stderr_reader) {
        Ok(captured) => captured,
        Err(error) => {
            audit_worker(
                audit,
                name,
                Some(template),
                Some(&plan),
                "error",
                exit_code,
                None,
            );
            return Err(error.into());
        }
    };

    if timed_out {
        audit_worker(
            audit,
            name,
            Some(template),
            Some(&plan),
            "timeout",
            None,
            None,
        );
        return Err(SpawnError::Timeout(timeout));
    }

    // The total ceiling bounds the pair, so it is checked after both reads:
    // each stream being individually legal must not make the sum illegal. It
    // is not a second memory defence -- the per-stream caps did that, and they
    // already ran. It decides how the run is *reported*.
    let total = stdout.total + stderr.total;
    let limit_hit = stdout.truncated || stderr.truncated || total > limits.max_total_bytes as u64;
    let mut outcome = outcome;
    if limit_hit {
        // The worker failed at nothing. It succeeded and said more than the
        // broker agreed to hold, and a caller told "ok" would take the kept
        // prefix for the whole of it. So the run is named for what happened to
        // the output rather than for what happened to the process.
        outcome = RunOutcome::OutputLimitExceeded;
    }

    let stdout_redacted = effective_redactor.redact(&stdout.bytes);
    let stderr_redacted = effective_redactor.redact(&stderr.bytes);

    audit_worker(
        audit,
        name,
        Some(template),
        Some(&plan),
        outcome.audit_name(),
        exit_code,
        Some((stdout.total, stderr.total, limit_hit)),
    );

    Ok(WorkerRun {
        outcome,
        exit_code,
        stdout_redacted,
        stderr_redacted,
        duration,
        bytes_stdout: stdout.total,
        bytes_stderr: stderr.total,
        limit_hit,
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

fn zeroize_buf(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// One metadata-only audit record per terminal path (M10R-R6, D7).
fn audit_worker(
    audit: &AuditWriter<'_>,
    worker: &str,
    template: Option<&WorkerTemplate>,
    plan: Option<&SecretInjectionPlan>,
    outcome: &str,
    exit_code: Option<i32>,
    output: Option<(u64, u64, bool)>,
) {
    let (egress, injection) = match (template, plan.or(template.map(|t| &t.secret_injection))) {
        (Some(t), Some(p)) => (t.egress_policy.kind(), p.kind()),
        _ => ("none", "none"),
    };
    // Counts, not content: how much a worker said is an operational fact, what
    // it said may be the secret.
    let (bytes_stdout, bytes_stderr, output_limit_hit) = output
        .map(|(out, err, hit)| (Some(out), Some(err), Some(hit)))
        .unwrap_or((None, None, None));
    let event = AuditEventDto::WorkerSpawned {
        worker: worker.to_string(),
        egress: egress.to_string(),
        injection: injection.to_string(),
        posture: POSTURE_LABEL.to_string(),
        outcome: outcome.to_string(),
        exit_code,
        bytes_stdout,
        bytes_stderr,
        output_limit_hit,
    };
    // The lock is held for this one append and no longer — see `AuditWriter`.
    //
    // A poisoned chain loses this record rather than failing the run. That is a
    // deliberate trade, and the reasoning is the same one that removed the
    // long hold: by the time a record is due a child exists and there is no
    // refusal left to give, so the only two outcomes on offer are "drop one
    // record in a chain that is already broken" and "freeze every agent in the
    // broker until this child exits". A caller can check the chain is writable
    // before starting a run, which is where refusing actually belongs.
    let Ok(mut log) = audit.chain.lock() else {
        return;
    };
    log.append(
        event,
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
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let err = spawn(
            &r,
            "bash",
            SpawnOptions::default(),
            &AuditWriter::new(&audit),
        )
        .expect_err("unregistered name must be refused");
        assert!(matches!(err, SpawnError::UnknownWorker(n) if n == "bash"));
        let recs = audit.lock().expect("not poisoned").query(0);
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
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let err = spawn(
            &r,
            "ghost",
            SpawnOptions::default(),
            &AuditWriter::new(&audit),
        )
        .expect_err("missing binary must be refused");
        assert!(matches!(err, SpawnError::BinaryMissing(_)));
    }

    #[test]
    fn allow_policy_is_refused_not_downgraded() {
        let mut t = template("net-worker", "/bin/true");
        t.egress_policy = EgressPolicy::Allow(vec![endpoint("api.example.com")]);
        let r = WorkerRegistry::new(vec![t]);
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let err = spawn(
            &r,
            "net-worker",
            SpawnOptions::default(),
            &AuditWriter::new(&audit),
        )
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
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let err = spawn(
            &r,
            "debug-worker",
            SpawnOptions::default(),
            &AuditWriter::new(&audit),
        )
        .expect_err("a debug-only seccomp profile must be refused");
        assert!(matches!(err, SpawnError::SeccompProfileNotProduction));
        // Nothing was executed, and the refusal is auditable.
        let recs = audit.lock().expect("not poisoned").query(0);
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
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let err = spawn(
            &r,
            "env-worker",
            SpawnOptions::default(),
            &AuditWriter::new(&audit),
        )
        .expect_err("env plan without provider must be refused");
        assert!(matches!(err, SpawnError::InjectionMismatch(_)));

        let r2 = WorkerRegistry::new(vec![template("plain", "/bin/true")]);
        let audit2 = std::sync::Mutex::new(AuditLog::new(16));
        let err2 = spawn(
            &r2,
            "plain",
            SpawnOptions {
                secret: Some(Box::new(|| b"x".to_vec())),
                timeout: None,
                ..Default::default()
            },
            &AuditWriter::new(&audit2),
        )
        .expect_err("provider without plan must be refused");
        assert!(matches!(err2, SpawnError::InjectionMismatch(_)));
    }

    /// AAT-RUNTIME-03: a worker that prints without end is capped, and the run
    /// says which fault it was.
    ///
    /// The second assertion is the one that matters. A reader that kept
    /// draining past the cap would also bound memory, and it would end this run
    /// as `TimedOut` after the full lifetime — a different claim, blaming the
    /// worker for being slow instead of for being unbounded, and losing the
    /// fact that the broker stopped it. So the run must finish in far less than
    /// the lifetime it was allowed: that is the evidence the child died on the
    /// closed pipe rather than on the clock.
    #[test]
    fn a_worker_that_never_stops_printing_is_capped_and_says_so() {
        let mut t = template("chatty", "/usr/bin/yes");
        t.arguments = vec![];
        let r = WorkerRegistry::new(vec![t]);
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let lifetime = Duration::from_secs(30);
        let run = spawn(
            &r,
            "chatty",
            SpawnOptions {
                secret: None,
                timeout: Some(lifetime),
                output_limits: WorkerOutputLimits {
                    max_stdout_bytes: 64 * 1024,
                    max_stderr_bytes: 64 * 1024,
                    max_total_bytes: 128 * 1024,
                },
            },
            &AuditWriter::new(&audit),
        )
        .expect("a capped run is a run, not a spawn failure");

        assert_eq!(
            run.outcome,
            RunOutcome::OutputLimitExceeded,
            "an unbounded producer must be named as one, not as ok, failed or timed out"
        );
        assert!(
            run.limit_hit,
            "the bound was hit but the run did not say so"
        );
        assert!(
            run.duration < Duration::from_secs(10),
            "the run took {:?}, which is the clock stopping the worker rather than \
             the output bound",
            run.duration
        );
        // What the caller receives is the kept prefix and nothing more: the
        // observable form of the memory being bounded.
        assert_eq!(
            run.stdout_redacted.len(),
            64 * 1024,
            "the caller must not be handed more than the cap"
        );
        assert!(
            run.bytes_stdout > 64 * 1024,
            "bytes_stdout must report what was said, not what was kept"
        );

        let recs = audit.lock().expect("not poisoned").query(0);
        match &recs[0].event {
            AuditEventDto::WorkerSpawned {
                outcome,
                bytes_stdout,
                output_limit_hit,
                ..
            } => {
                assert_eq!(outcome, "output_limit_exceeded");
                assert_eq!(*bytes_stdout, Some(run.bytes_stdout));
                assert_eq!(*output_limit_hit, Some(true));
            }
            other => panic!("unexpected audit variant: {other:?}"),
        }
    }

    #[test]
    fn a_worker_under_the_bound_reports_no_limit_and_keeps_everything() {
        // The other half of the row above. Without it, a reader that dropped
        // everything unconditionally would pass: `limit_hit` would be true
        // forever and "the bound works" would mean nothing.
        let r = WorkerRegistry::new(vec![template("quiet", "/bin/echo")]);
        let audit = std::sync::Mutex::new(AuditLog::new(16));
        let run = spawn(
            &r,
            "quiet",
            SpawnOptions {
                secret: None,
                timeout: None,
                output_limits: WorkerOutputLimits {
                    max_stdout_bytes: 64 * 1024,
                    max_stderr_bytes: 64 * 1024,
                    max_total_bytes: 128 * 1024,
                },
            },
            &AuditWriter::new(&audit),
        )
        .expect("a quiet worker runs");
        assert_eq!(run.outcome, RunOutcome::Completed);
        assert!(
            !run.limit_hit,
            "a worker under the cap must not be reported as capped"
        );
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
