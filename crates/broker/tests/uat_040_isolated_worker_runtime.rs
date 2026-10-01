//! UAT-040 — isolated worker runtime, denied rather than downgraded.
//! Isolated worker runtime — the M10 follow-up to UAT-021 and UAT-022.
//!
//! This suite was written ahead of the spec and originally took a number
//! nothing reserved, which it said so in this header. It is now normative:
//! UAT-040 is defined in `14-UAT-ADVERSARIAL.md` and owned by M10. The
//! decision is recorded rather than quietly applied — the suite always proved
//! the property, and the gap was that the roadmap could not gate on a test
//! whose id the spec did not recognise. What was provisional was the *number*,
//! never the property.
//!
use asv_broker::audit::AuditLog;
use asv_broker::isolated_exec::{
    EgressPolicy, LandlockProfile, Redactor, SeccompProfile, SecretInjectionPlan, WorkerRegistry,
    WorkerTemplate,
};
use asv_broker::worker::{spawn, SecretProvider, SpawnError, SpawnOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ----- helpers -----------------------------------------------------------

/// The budget a test gives a worker it expects to COMPLETE.
///
/// This is deliberately not the production default. `DEFAULT_WORKER_TIMEOUT`
/// (10s) is the lifetime cap of a real worker — spec §7 "short lifetime" —
/// and it is the right number for `uat_040_runaway_worker_is_killed_at_timeout`,
/// whose subject IS that cap. But a test that asserts "the worker ran and
/// produced this output" is not testing the lifetime cap; it is a bystander
/// to it. Under a full parallel `cargo test --workspace`, interpreter
/// startup (`python3`, `sh`) competes with dozens of binaries forking and
/// exec-ing at once, and the observed failure ran exactly that arithmetic:
/// the failing binary finished in 11.02s — 10s budget + 1s TERM grace — on
/// the one test that spawns the heaviest child.
///
/// A completion test that dies at the production budget reports a timeout
/// where the property under test never got a chance to run. 60s keeps the
/// assertion honest (a hung worker still fails, just later) and takes the
/// CI scheduler out of the result. The runaway test keeps its own short
/// timeout on purpose: there the budget is the thing being measured.
const COMPLETION_BUDGET: Duration = Duration::from_secs(60);

/// Spawn options for a worker the test expects to complete normally.
fn completion_opts() -> SpawnOptions {
    SpawnOptions {
        secret: None,
        timeout: Some(COMPLETION_BUDGET),
    }
}

/// The two-site form for completion tests that also inject a secret.
fn completion_opts_with_secret(secret: SecretProvider) -> SpawnOptions {
    SpawnOptions {
        secret: Some(secret),
        timeout: Some(COMPLETION_BUDGET),
    }
}

fn userns_available() -> bool {
    // The same kernel feature the runtime hook needs. Probe it the way
    // the hook will use it: unshare(CLONE_NEWUSER|CLONE_NEWNET) via a
    // `unshare` invocation (util-linux is present on dev hosts; the
    // probe is only used to decide skip-vs-run, never to assert).
    std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn deny_template(name: &str, binary: &str, args: &[&str]) -> WorkerTemplate {
    WorkerTemplate {
        name: name.into(),
        binary: binary.into(),
        arguments: args.iter().map(|s| s.to_string()).collect(),
        secret_injection: SecretInjectionPlan::None,
        egress_policy: EgressPolicy::Deny,
        landlock_profile: LandlockProfile::default(),
        seccomp_profile: SeccompProfile::ClosedAllowList,
        redactor: Redactor::empty(),
    }
}

// ----- M10R-R1: registered spawn only -------------------------------------

#[test]
fn uat_040_unregistered_name_is_refused_and_audited() {
    let r = WorkerRegistry::new(vec![deny_template("kubectl-worker", "/bin/true", &[])]);
    let mut audit = AuditLog::new(16);
    let err = spawn(&r, "bash", SpawnOptions::default(), &mut audit)
        .expect_err("arbitrary binaries are refused before any exec");
    assert!(matches!(err, SpawnError::UnknownWorker(ref n) if n == "bash"));
    let recs = audit.query(0);
    assert_eq!(recs.len(), 1, "the refusal itself is audit evidence");
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned {
            worker,
            outcome,
            posture,
            ..
        } => {
            assert_eq!(worker, "bash");
            assert_eq!(outcome, "refused");
            assert_eq!(posture, "ISOLATED_PROCESS_EXPOSURE");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

#[test]
fn uat_040_allow_policy_is_refused_not_downgraded() {
    use asv_domain::Authority;
    let auth = Authority::canonicalize("api.example.com").expect("auth");
    let ep = asv_broker::tls_bridge::AuthorityEndpoint::new(auth, 443).expect("ep");
    let mut t = deny_template("net-worker", "/bin/true", &[]);
    t.egress_policy = EgressPolicy::Allow(vec![ep]);
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let err = spawn(&r, "net-worker", SpawnOptions::default(), &mut audit)
        .expect_err("an Allow policy without the M9 bridge is a lie; refuse it");
    assert!(matches!(err, SpawnError::EgressAllowUnsupported));
}

// ----- M10R-R2: network namespace isolation (UAT-021 live) -----------------

#[test]
fn uat_040_deny_worker_sees_only_loopback_and_cannot_reach_out() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let t = deny_template(
        "net-probe",
        "/bin/sh",
        &[
            "-c",
            "ip -o link show | wc -l; timeout 2 sh -c 'exec 3<>/dev/tcp/10.255.255.1/65534' 2>/dev/null; echo reach=$?",
        ],
    );
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "net-probe", completion_opts(), &mut audit).expect("run");
    let out = String::from_utf8_lossy(&run.stdout_redacted);
    assert_eq!(run.exit_code, Some(0));
    // In the fresh netns the only interface is the downed lo.
    assert_eq!(out.lines().next().map(str::trim), Some("1"), "{out}");
    // The TCP attempt must have failed (reach != 0).
    let reach = out.lines().nth(1).unwrap_or("").trim();
    assert!(
        reach.starts_with("reach=") && !reach.ends_with("=0"),
        "an egress Deny worker must not be able to open a TCP socket: {reach}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn uat_040_pre_exec_isolation_failure_is_classified_and_audited() {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryFrom;

    // Make the real unshare syscall fail in the child. Command::spawn
    // then reports std's actual pre_exec sentinel, not a mocked error.
    let arch = TargetArch::try_from(std::env::consts::ARCH).expect("supported test arch");
    let rules = BTreeMap::from([(libc::SYS_unshare, Vec::new())]);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .expect("unshare denial filter");
    let program = BpfProgram::try_from(filter).expect("compile unshare denial filter");
    seccompiler::apply_filter(&program).expect("install current-thread filter");

    let registry = WorkerRegistry::new(vec![deny_template("blocked-isolation", "/bin/true", &[])]);
    let mut audit = AuditLog::new(16);
    let error = spawn(
        &registry,
        "blocked-isolation",
        SpawnOptions::default(),
        &mut audit,
    )
    .expect_err("a namespace setup failure must prevent exec");
    assert!(
        matches!(error, SpawnError::IsolationUnavailable),
        "{error:?}"
    );
    match &audit.query(0)[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned { outcome, .. } => {
            assert_eq!(outcome, "error");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn uat_040_exec_failure_without_hook_marker_remains_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "asv-uat040-invalid-exec-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(&path, b"not an executable image\n").expect("write invalid executable");
    let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make fixture executable");

    let template = deny_template(
        "invalid-exec",
        path.to_str().expect("UTF-8 fixture path"),
        &[],
    );
    let registry = WorkerRegistry::new(vec![template]);
    let mut audit = AuditLog::new(16);
    let error = spawn(
        &registry,
        "invalid-exec",
        SpawnOptions::default(),
        &mut audit,
    )
    .expect_err("an invalid executable image must fail exec");
    assert!(matches!(error, SpawnError::Io(_)), "{error:?}");
    std::fs::remove_file(path).expect("remove invalid executable fixture");
}

// ----- M10R-R3: secret injection at spawn only ------------------------------

#[test]
fn uat_040_env_injection_reaches_child_only() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let env_count_before = std::env::vars_os().count();
    let mut t = deny_template(
        "env-worker",
        "/bin/sh",
        &["-c", r#"test "$ASV_T" = sekrit && echo child-ok"#],
    );
    t.secret_injection = SecretInjectionPlan::EnvVar {
        name: "ASV_T".into(),
    };
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(
        &r,
        "env-worker",
        completion_opts_with_secret(Box::new(|| b"sekrit".to_vec())),
        &mut audit,
    )
    .expect("run");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run.stdout_redacted).trim(),
        "child-ok"
    );
    // The broker's own environment never changed.
    assert_eq!(
        std::env::vars_os().count(),
        env_count_before,
        "the broker env is not the injection channel"
    );
    assert!(std::env::var_os("ASV_T").is_none());
}

#[test]
fn uat_040_file_injection_is_0600_and_cleaned_up() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let dir = std::env::temp_dir().join(format!("asv-uat040-{}", std::process::id()));
    let path = dir.join("secret.bin");
    let mut t = deny_template(
        "file-worker",
        "/bin/sh",
        &[
            "-c",
            "stat -c '%a' \"$ASV_SECRET_FILE\"; cat \"$ASV_SECRET_FILE\"",
        ],
    );
    t.secret_injection = SecretInjectionPlan::File {
        path: path.clone(),
        mode: 0o600,
    };
    // The staged file lives outside the auto-allowed binary chain: the
    // template's landlock profile must name its directory (exactly what
    // a production template declares for its own secret staging dir).
    t.landlock_profile = LandlockProfile {
        allowed_read: vec![std::env::temp_dir()],
        allowed_write: vec![],
    };
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(
        &r,
        "file-worker",
        completion_opts_with_secret(Box::new(|| b"file-secret".to_vec())),
        &mut audit,
    )
    .expect("run");
    let out = String::from_utf8_lossy(&run.stdout_redacted);
    assert_eq!(run.exit_code, Some(0), "{out}");
    assert_eq!(out.lines().next().map(str::trim), Some("600"), "{out}");
    assert_eq!(out.lines().nth(1), Some("file-secret"));
    // Automatic destruction (§7): the file is gone after the run.
    assert!(!path.exists(), "the staged secret file must be removed");
    let _ = std::fs::remove_dir(dir);
}

// ----- M10R-R4: landlock + seccomp in-child ---------------------------------

#[test]
fn uat_040_landlock_profile_denies_unlisted_paths() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let mut t = deny_template(
        "ll-worker",
        "/bin/sh",
        &[
            "-c",
            // The runtime auto-allow-reads the binary's ancestor chain;
            // bash also needs its loader/libc/locale paths, so the probe
            // profile allow-reads the runtime dirs explicitly. The denial
            // signal is /etc/hostname, which is NOT in the profile.
            "cat /bin/true >/dev/null 2>&1 && echo bin-ok || echo bin-failed-$?; { cat /etc/hostname 2>/dev/null && echo etc-leaked; } || echo etc-denied; echo done",
        ],
    );
    t.landlock_profile = LandlockProfile {
        allowed_read: vec![
            PathBuf::from("/usr"),
            PathBuf::from("/usr/lib64"),
            PathBuf::from("/usr/share/locale"),
            PathBuf::from("/etc/ld.so.cache"),
        ],
        allowed_write: vec![],
    };
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "ll-worker", completion_opts(), &mut audit).expect("run");
    let out = String::from_utf8_lossy(&run.stdout_redacted);
    let err = String::from_utf8_lossy(&run.stderr_redacted);
    assert_eq!(run.exit_code, Some(0), "{out} | stderr: {err}");
    assert!(
        out.contains("bin-ok"),
        "allow-listed read must succeed: {out} | stderr: {err}"
    );
    assert!(
        !out.contains("etc-leaked"),
        "an unlisted path must be denied by the per-template ruleset: {out} | stderr: {err}"
    );
}

#[test]
fn uat_040_read_allow_does_not_grant_execute() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let dir = std::env::temp_dir().join(format!("asv-uat040-exec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let copied_binary = dir.join("true");
    std::fs::copy("/usr/bin/true", &copied_binary).expect("copy executable fixture");
    let mut t = deny_template(
        "read-only-worker",
        "/bin/sh",
        &[
            "-c",
            "if \"$1\"; then echo executed; else echo execute-denied; fi",
            "landlock-probe",
            copied_binary.to_str().expect("UTF-8 temp path"),
        ],
    );
    t.landlock_profile = LandlockProfile {
        allowed_read: vec![dir.clone()],
        allowed_write: vec![],
    };
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "read-only-worker", completion_opts(), &mut audit)
        .expect("run under read-only profile");
    let out = String::from_utf8_lossy(&run.stdout_redacted);
    assert_eq!(run.exit_code, Some(0), "{out}");
    assert!(
        out.contains("execute-denied"),
        "read-only access must not grant Execute: {out}"
    );
    assert!(
        !out.contains("executed"),
        "the copied binary must not run: {out}"
    );
    std::fs::remove_dir_all(dir).expect("remove fixture");
}

#[test]
fn uat_040_large_stdout_and_stderr_are_drained_concurrently() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").is_file() {
        eprintln!("SKIPPED: no /usr/bin/python3 for the pipe-capacity probe");
        return;
    }
    let t = deny_template(
        "chatty-worker",
        "/usr/bin/python3",
        &[
            "-c",
            "import sys; sys.stdout.write('o' * 131072); sys.stderr.write('e' * 131072)",
        ],
    );
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "chatty-worker", completion_opts(), &mut audit)
        .expect("large output must not deadlock");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(run.stdout_redacted.len(), 131072);
    assert_eq!(run.stderr_redacted.len(), 131072);
    assert!(run.stdout_redacted.iter().all(|byte| *byte == b'o'));
    assert!(run.stderr_redacted.iter().all(|byte| *byte == b'e'));
}

#[test]
fn uat_040_seccomp_bite_kills_worker_calling_bpf() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    // Use libc's syscall binding from Python with the target's compiled
    // SYS_bpf number. This is a live syscall probe, not a bpftool check.
    let python = Path::new("/usr/bin/python3");
    assert!(
        python.is_file(),
        "live seccomp bite requires /usr/bin/python3"
    );
    let syscall_number = libc::SYS_bpf.to_string();
    let t = deny_template(
        "bite-worker",
        python.to_str().expect("UTF-8 Python path"),
        &[
            "-c",
            "import ctypes,sys; ctypes.CDLL(None).syscall(int(sys.argv[1]),0,0,0)",
            &syscall_number,
        ],
    );
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "bite-worker", completion_opts(), &mut audit).expect("run");
    // The worker main thread must die from SIGSYS before bpf(2) returns.
    assert_eq!(
        run.outcome,
        asv_broker::worker::RunOutcome::Signaled,
        "bpf(2) under the deny-list must die by signal"
    );
}

// ----- M10R-R5: bounded lifetime + redaction --------------------------------

#[test]
fn uat_040_runaway_worker_is_killed_at_timeout() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let t = deny_template("sleeper", "/bin/sleep", &["30"]);
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let started = std::time::Instant::now();
    let err = spawn(
        &r,
        "sleeper",
        SpawnOptions {
            secret: None,
            timeout: Some(std::time::Duration::from_millis(700)),
        },
        &mut audit,
    )
    .expect_err("a runaway worker is killed, not adopted");
    assert!(matches!(err, SpawnError::Timeout(_)));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the kill must happen at the timeout, not at the child's leisure"
    );
    match &audit.query(0)[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned { outcome, .. } => {
            assert_eq!(outcome, "timeout");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

#[test]
fn uat_040_secret_in_stdout_is_redacted_transformed_is_not() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    // UAT-022's honesty contract: the exact-byte redactor removes the
    // secret, does NOT magically catch base64, and the run record
    // still carries the ISOLATED_PROCESS_EXPOSURE posture.
    let mut t = deny_template(
        "leaky",
        "/bin/sh",
        &[
            "-c",
            "printf '%s %s' \"$ASV_T\" \"$(printf %s \"$ASV_T\" | base64)\"",
        ],
    );
    t.secret_injection = SecretInjectionPlan::EnvVar {
        name: "ASV_T".into(),
    };
    t.redactor = Redactor::new([b"topsecret".to_vec()]);
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(
        &r,
        "leaky",
        completion_opts_with_secret(Box::new(|| b"topsecret".to_vec())),
        &mut audit,
    )
    .expect("run");
    let out = String::from_utf8_lossy(&run.stdout_redacted);
    assert!(
        !out.contains("topsecret"),
        "the raw secret must never survive redaction: {out}"
    );
    assert!(
        out.contains("[REDACTED]"),
        "the exact match is replaced: {out}"
    );
    // The transformed form survives and that is DOCUMENTED behaviour
    // (UAT-022): security comes from netns confinement, not filtering.
    let b64 = String::from_utf8_lossy(&run.stdout_redacted);
    assert!(
        b64.contains("dG9wc2VjcmV0"),
        "transformed leak is out of the redactor's reach by design (UAT-022): {out}"
    );
    match &audit.query(0)[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned { posture, .. } => {
            assert_eq!(posture, "ISOLATED_PROCESS_EXPOSURE");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

// ----- M10R-R6: audit on every terminal path --------------------------------

#[test]
fn uat_040_completed_run_is_audited_with_metadata_only() {
    if !userns_available() {
        eprintln!("SKIPPED: no unprivileged userns on this host");
        return;
    }
    let t = deny_template("ok-worker", "/bin/true", &[]);
    let r = WorkerRegistry::new(vec![t]);
    let mut audit = AuditLog::new(16);
    let run = spawn(&r, "ok-worker", completion_opts(), &mut audit).expect("run");
    assert_eq!(run.exit_code, Some(0));
    assert!(run.duration < std::time::Duration::from_secs(10));
    let recs = audit.query(0);
    assert_eq!(recs.len(), 1);
    let serialized = serde_json::to_string(&recs[0].event).expect("dto json");
    assert!(
        !serialized.contains("sekrit") && !serialized.contains("topsecret"),
        "audit records never carry secret bytes: {serialized}"
    );
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned {
            worker,
            egress,
            injection,
            outcome,
            exit_code,
            ..
        } => {
            assert_eq!(worker, "ok-worker");
            assert_eq!(egress, "deny");
            assert_eq!(injection, "none");
            assert_eq!(outcome, "ok");
            assert_eq!(*exit_code, Some(0));
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
    // And the durable chain still verifies with worker frames in it.
    assert_eq!(audit.verify(), Ok(()));
}

#[test]
fn uat_040_missing_binary_refusal_is_audited() {
    let r = WorkerRegistry::new(vec![deny_template(
        "ghost",
        "/nonexistent/asv-binary-probe",
        &[],
    )]);
    let mut audit = AuditLog::new(16);
    let err = spawn(&r, "ghost", SpawnOptions::default(), &mut audit)
        .expect_err("a registry entry pointing nowhere is an install-time bug");
    assert!(
        matches!(err, SpawnError::BinaryMissing(p) if *p == *Path::new("/nonexistent/asv-binary-probe"))
    );
    assert_eq!(audit.query(0).len(), 1, "refusals are evidence too");
}
