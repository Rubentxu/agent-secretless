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
use asv_broker::worker::{
    spawn, AuditWriter, RunOutcome, SecretProvider, SpawnError, SpawnOptions,
};
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
        ..Default::default()
    }
}

/// The two-site form for completion tests that also inject a secret.
fn completion_opts_with_secret(secret: SecretProvider) -> SpawnOptions {
    SpawnOptions {
        secret: Some(secret),
        timeout: Some(COMPLETION_BUDGET),
        ..Default::default()
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

/// Refuse the host that cannot run these rows, loudly.
///
/// These rows used to `eprintln!` and `return`, which Cargo reports as
/// **passed**. A row that examined nothing was indistinguishable from a row
/// that passed — the same failure R1 was reopened for in `9d3d556`, where a
/// test that never ran was indistinguishable from one that passed. It also
/// made the deficit invisible to the suite-size guard, because a `return`
/// produces a passing test rather than an ignored one.
///
/// The PostgreSQL suites take the other shape, `ASV_UAT033_REQUIRE=1` turning a
/// missing substrate into a failure on demand. That is the right answer for a
/// substrate a developer may legitimately lack, and it is not available here:
/// Cargo has no "skipped" state for an early return, so a skip is a pass. The
/// only way a row can report that it did not run is by failing.
///
/// The distinction that matters: `unshare` failing is **`UNAVAILABLE
/// SUBSTRATE`**, a host that cannot run the row. A row that runs and fails is
/// **`FAIL`**. Neither is `PASS`, and the full gate keeps them apart on
/// purpose. A release requirement that cannot run is not a pass.
fn require_userns(row: &str) {
    if !userns_available() {
        panic!(
            "UNAVAILABLE_SUBSTRATE: {row} needs unprivileged user namespaces, which \
             this host does not provide. Reported as a failure rather than a \
             return, because a return is reported as a pass."
        );
    }
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let err = spawn(
        &r,
        "bash",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect_err("arbitrary binaries are refused before any exec");
    assert!(matches!(err, SpawnError::UnknownWorker(ref n) if n == "bash"));
    let recs = audit.lock().expect("not poisoned").query(0);
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let err = spawn(
        &r,
        "net-worker",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect_err("an Allow policy without the M9 bridge is a lie; refuse it");
    assert!(matches!(err, SpawnError::EgressAllowUnsupported));
}

// ----- M10R-R2: network namespace isolation (UAT-021 live) -----------------

#[test]
fn uat_040_deny_worker_sees_only_loopback_and_cannot_reach_out() {
    require_userns("uat_040_deny_worker_sees_only_loopback_and_cannot_reach_out");
    let t = deny_template(
        "net-probe",
        "/bin/sh",
        &[
            "-c",
            "ip -o link show | wc -l; timeout 2 sh -c 'exec 3<>/dev/tcp/10.255.255.1/65534' 2>/dev/null; echo reach=$?",
        ],
    );
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "net-probe",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("run");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let error = spawn(
        &registry,
        "blocked-isolation",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect_err("a namespace setup failure must prevent exec");
    assert!(
        matches!(error, SpawnError::IsolationUnavailable),
        "{error:?}"
    );
    let recs = audit.lock().expect("not poisoned").query(0);
    match &recs[0].event {
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let error = spawn(
        &registry,
        "invalid-exec",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect_err("an invalid executable image must fail exec");
    assert!(matches!(error, SpawnError::Io(_)), "{error:?}");
    std::fs::remove_file(path).expect("remove invalid executable fixture");
}

// ----- M10R-R3: secret injection at spawn only ------------------------------

#[test]
fn uat_040_env_injection_reaches_child_only() {
    require_userns("uat_040_env_injection_reaches_child_only");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "env-worker",
        completion_opts_with_secret(Box::new(|| b"sekrit".to_vec())),
        &AuditWriter::new(&audit),
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
fn uat_040_file_injection_is_refused_and_leaves_nothing_on_the_host() {
    // AAT-RUNTIME-06. A `File` plan is refused, and refusing it is only worth
    // something if it is observable in two directions: the caller is told, and
    // the host is left untouched.
    //
    // The previous row asserted the opposite and passed for as long as the
    // defect was real. It staged the secret at an absolute host path, let the
    // worker read it, and then checked the file was gone — which is the
    // strongest possible way to certify a cleanup path, and the weakest way to
    // certify a security boundary. The bytes existed in the parent filesystem
    // for the whole life of the worker, and the cleanup it verified was a
    // `Drop`, which a SIGKILL skips.
    //
    // Note there is no `require_userns` here. The refusal happens before any
    // fork, so the property is provable on a kernel that cannot isolate
    // anything — which is the point: nothing about refusing depends on the
    // kernel cooperating.
    let dir = std::env::temp_dir().join(format!("asv-uat040-{}", std::process::id()));
    let path = dir.join("secret.bin");
    let mut t = deny_template("file-worker", "/bin/sh", &["-c", "echo should-never-run"]);
    t.secret_injection = SecretInjectionPlan::File {
        path: path.clone(),
        mode: 0o600,
    };
    // The old staging path called `create_dir_all` on the parent, so an empty
    // staging directory survived the unlink. The row below checks the
    // directory too, which is what makes it falsifiable against that code.
    t.landlock_profile = LandlockProfile {
        allowed_read: vec![std::env::temp_dir()],
        allowed_write: vec![],
    };
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));

    let err = spawn(
        &r,
        "file-worker",
        completion_opts_with_secret(Box::new(|| b"file-secret".to_vec())),
        &AuditWriter::new(&audit),
    )
    .expect_err("a File plan must be refused, not served");

    assert!(
        matches!(err, SpawnError::FileInjectionUnsupported),
        "expected the named refusal, got {err:?}"
    );

    // AAT-RUNTIME-06: nothing on the host, neither the file nor the directory
    // the old code created to hold it.
    assert!(
        !path.exists(),
        "the declared path must not exist: refusing must not create it"
    );
    assert!(
        !dir.exists(),
        "the staging directory must not exist either; the removed implementation \
         called create_dir_all on the parent and left it behind after unlinking"
    );

    // And the refusal is on the record, naming the plan it refused.
    let recs = audit.lock().expect("not poisoned").query(0);
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned {
            outcome, injection, ..
        } => {
            assert_eq!(outcome, "refused");
            assert_eq!(injection, "file", "the record must name the plan refused");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

// ----- M10R-R4: landlock + seccomp in-child ---------------------------------

#[test]
fn uat_040_landlock_profile_denies_unlisted_paths() {
    require_userns("uat_040_landlock_profile_denies_unlisted_paths");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "ll-worker",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("run");
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
    require_userns("uat_040_read_allow_does_not_grant_execute");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "read-only-worker",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
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
    require_userns("uat_040_large_stdout_and_stderr_are_drained_concurrently");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "chatty-worker",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("large output must not deadlock");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(run.stdout_redacted.len(), 131072);
    assert_eq!(run.stderr_redacted.len(), 131072);
    assert!(run.stdout_redacted.iter().all(|byte| *byte == b'o'));
    assert!(run.stderr_redacted.iter().all(|byte| *byte == b'e'));
}

#[test]
fn uat_040_seccomp_bite_kills_worker_calling_bpf() {
    require_userns("uat_040_seccomp_bite_kills_worker_calling_bpf");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "bite-worker",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("run");
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
    require_userns("uat_040_runaway_worker_is_killed_at_timeout");
    let t = deny_template("sleeper", "/bin/sleep", &["30"]);
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let started = std::time::Instant::now();
    let err = spawn(
        &r,
        "sleeper",
        SpawnOptions {
            secret: None,
            timeout: Some(std::time::Duration::from_millis(700)),
            ..Default::default()
        },
        &AuditWriter::new(&audit),
    )
    .expect_err("a runaway worker is killed, not adopted");
    assert!(matches!(err, SpawnError::Timeout(_)));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the kill must happen at the timeout, not at the child's leisure"
    );
    let recs = audit.lock().expect("not poisoned").query(0);
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned { outcome, .. } => {
            assert_eq!(outcome, "timeout");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

#[test]
fn uat_040_secret_in_stdout_is_redacted_transformed_is_not() {
    require_userns("uat_040_secret_in_stdout_is_redacted_transformed_is_not");
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
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "leaky",
        completion_opts_with_secret(Box::new(|| b"topsecret".to_vec())),
        &AuditWriter::new(&audit),
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
    let recs = audit.lock().expect("not poisoned").query(0);
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned { posture, .. } => {
            assert_eq!(posture, "ISOLATED_PROCESS_EXPOSURE");
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}

// ----- M10R-R6: audit on every terminal path --------------------------------

#[test]
fn uat_040_completed_run_is_audited_with_metadata_only() {
    require_userns("uat_040_completed_run_is_audited_with_metadata_only");
    let t = deny_template("ok-worker", "/bin/true", &[]);
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "ok-worker",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("run");
    assert_eq!(run.exit_code, Some(0));
    assert!(run.duration < std::time::Duration::from_secs(10));
    let recs = audit.lock().expect("not poisoned").query(0);
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
    assert_eq!(audit.lock().expect("not poisoned").verify(), Ok(()));
}

#[test]
fn uat_040_missing_binary_refusal_is_audited() {
    let r = WorkerRegistry::new(vec![deny_template(
        "ghost",
        "/nonexistent/asv-binary-probe",
        &[],
    )]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let err = spawn(
        &r,
        "ghost",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect_err("a registry entry pointing nowhere is an install-time bug");
    assert!(
        matches!(err, SpawnError::BinaryMissing(p) if *p == *Path::new("/nonexistent/asv-binary-probe"))
    );
    assert_eq!(
        audit.lock().expect("not poisoned").query(0).len(),
        1,
        "refusals are evidence too"
    );
}

// ----- B1.1: process-group lifetime hardening ------------------------------
//
// These rows are the post-fix contract for the WORKER-LIFETIME cap
// (plan canonico v1.0 B1.1). They do NOT need unprivileged user
// namespaces: the property under test is process-group membership and
// the SIGTERM/SIGKILL delivery to that group, which is host-only and
// std-only. Running them under `require_userns` would force the test
// to skip on hosts without userns and silently certify nothing.
//
// Each row is shaped so that a missing fix produces a measurable
// failure: the descendant row asserts a wall-clock upper bound, the
// runaway_grandchild row asserts no surviving `sleep 5` from the
// test, the posture row asserts an audit-record field.

/// Build a WorkerTemplate that backgrounds a sleeper which
/// outlives the shell AND keeps the inherited stdout FD open.
/// Used by the row that asserts the broker's `read_bounded`
/// returns without pinning on the inherited FD. The `exec 3>&1`
/// is required: without it, bash closes the inherited FD on
/// the sleeper before the sleeper starts, and the broker's
/// read end sees EOF immediately, masking the bug.
fn fd_holding_template(name: &str, secs: &str) -> WorkerTemplate {
    deny_template(
        name,
        "/bin/sh",
        &["-c", &format!("exec 3>&1; sleep {secs} &")],
    )
}

/// Build a WorkerTemplate that backgrounds a sleeper that
/// outlives the shell. Used by the row that asserts the
/// broker's killpg reaps the sleeper too. `disown` is required
/// so the shell does not wait for the sleeper (POSIX job
/// control) — without it, the shell reaps the sleeper as part
/// of its own exit, which would mask the broker's killpg
/// (false green).
fn orphan_template(name: &str, secs: &str) -> WorkerTemplate {
    deny_template(name, "/bin/sh", &["-c", &format!("sleep {secs} & disown")])
}

/// Worker forks a long-lived sleeper that holds the inherited
/// stdout FD, then the shell exits. The sleeper outlives the
/// shell and would otherwise keep the broker's `read_bounded`
/// blocked until the sleeper eventually closes the FD. With
/// setsid()+killpg() on the timeout path the entire group dies
/// at the cap, the inherited FD closes, and the bounded reader
/// returns in the same envelope as the timeout.
///
/// The contract under test is wall-clock: the spawn() call
/// returns in <2s when the cap is 250ms and the sleeper is 5s,
/// because killpg reaps the group at the cap. Without the fix,
/// the join blocks until the sleeper completes (5s) or the
/// shell's job-control reaps the sleeper into bash's wait (which
/// varies by shell, so the wall-clock check is the only honest
/// assertion).
#[test]
fn uat_040_descendant_holding_stdout_does_not_block_join() {
    let t = fd_holding_template("orphan-grandchild", "5");
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let started = std::time::Instant::now();
    // The shell exits in a few ms (it backgrounds the sleeper
    // and returns), so the broker's `wait_with_timeout` reaps
    // the shell as `Exited(0)` and the run is recorded as
    // `Completed`. The bug, if present, is in the
    // `read_bounded` join that follows: the inherited FD is
    // held open by the sleeper, and the join blocks until the
    // sleeper completes its 5s sleep. With killpg in place,
    // the cap path kills the sleeper too, the FD closes, and
    // the join returns promptly.
    let _run = spawn(
        &r,
        "orphan-grandchild",
        SpawnOptions {
            secret: None,
            // 250ms is well under the 5s sleeper. The shell exits
            // in ~5ms so the cap is irrelevant for the wait; the
            // cap is what bounds the join. With the fix, killpg
            // at the cap closes the inherited FD and the join
            // returns in <1s total. Without the fix, the join
            // blocks until the sleeper completes (~5s).
            timeout: Some(std::time::Duration::from_millis(250)),
            ..Default::default()
        },
        &AuditWriter::new(&audit),
    )
    .expect("the shell exits; the run record is not an Err");
    let elapsed = started.elapsed();
    // 4s catches the buggy path (5s sleeper minus a small
    // margin) without being so tight that a busy CI trips it.
    // The fixed path completes in ~1.2s.
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "the inherited FD must not pin the join (elapsed: {elapsed:?})"
    );
}

/// Worker spawns an immediate sleeper that outlives the shell;
/// the broker's timeout must kill the whole group, not just the
/// shell. The check is: the run returns in <5s (killpg at the cap,
/// not a 60s wait). The 60s sleeper is intentionally far longer
/// than the cap so a regression that re-introduces per-PID
/// signaling would either hang the broker for 60s (caught by the
/// elapsed bound).
///
/// Note: we do NOT assert "no `sleep 60` survives in ps" because
/// the orphan `sleep 60` is reparented to init as soon as the
/// leader bash exits, and the broker's killpg cannot reach a
/// process that has left the group. The honest property the
/// broker can prove is "I do not hang on the leader's exit" —
/// which is what the elapsed bound checks. Whether the orphan
/// is then reaped by init is an init-policy question, not a
/// broker one.
#[test]
fn uat_040_runaway_grandchild_is_killed_with_the_group() {
    let t = orphan_template("runaway-grandchild", "60");
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let started = std::time::Instant::now();
    let _ = spawn(
        &r,
        "runaway-grandchild",
        SpawnOptions {
            secret: None,
            // 300ms is well under the 60s sleeper. With the fix,
            // killpg on the timeout path reaps the leader
            // immediately (~1.3s total). Without the fix, the
            // broker hangs for the leader's wait_with_timeout.
            timeout: Some(std::time::Duration::from_millis(300)),
            ..Default::default()
        },
        &AuditWriter::new(&audit),
    )
    .expect("the shell exits; the run is not an Err");
    // The run must return in well under the sleeper's lifetime.
    // The fixed path is ~1.3s; the buggy path is 60s+. 5s is a
    // generous bound that catches the regression without flaking
    // on a slow CI.
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "killpg must reap the leader, not let the broker wait it out (elapsed: {elapsed:?})"
    );
}

/// The audit record must carry the posture label. Today that
/// label is the single string `ISOLATED_PROCESS_EXPOSURE`
/// (M10-R6). After B1.1, the label is a `PostureLabel` enum the
/// broker reports from the run; the audit DTO carries the wire
/// name. AAT-RUNTIME-04 (descendants) and AAT-RUNTIME-06
/// (posture in audit) are the canonical rows.
#[test]
fn uat_040_sigterm_trapping_descendant_is_killed_at_grace() {
    // The worker (bash) traps SIGTERM. A bare TERM-only signal
    // would let the broker hang for the worker's lifetime (5s).
    // The broker's grace period (1s) must elapse, then the
    // SIGKILL on the group must take the leader down regardless
    // of the trap. This proves the escalation path of
    // `terminate_with_grace`, not only the case where SIGKILL
    // fires immediately. We do NOT use `disown` because the
    // disowned sleeper would be reparented to init and survive
    // outside the worker's PG; here the worker itself is the
    // sleeper, so the PG kill reaches it.
    let r = WorkerRegistry::new(vec![deny_template(
        "term-trapper",
        "/bin/sh",
        &["-c", "trap '' TERM; sleep 5"],
    )]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let started = std::time::Instant::now();
    let run = match spawn(
        &r,
        "term-trapper",
        SpawnOptions {
            timeout: Some(std::time::Duration::from_millis(800)),
            ..Default::default()
        },
        &AuditWriter::new(&audit),
    ) {
        Ok(run) => run,
        Err(SpawnError::Timeout(_)) => {
            // The broker timed out and reaped the worker via killpg
            // SIGKILL. There is no WorkerRun to inspect; the elapsed
            // bound below is the property we care about. The
            // expected elapsed is timeout (800ms) + TERMINATION_GRACE
            // (1s) ≈ 1.8s; the bound is 2.5s to leave headroom on
            // slow CI while still catching a regression that waits
            // out the full 5s sleeper.
            let elapsed = started.elapsed();
            assert!(
                elapsed < std::time::Duration::from_millis(2500),
                "the trap must not pin the broker past the grace + KILL (elapsed: {elapsed:?})"
            );
            return;
        }
        Err(e) => panic!("unexpected spawn error: {e:?}"),
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(2500),
        "the trap must not pin the broker past the grace + KILL (elapsed: {elapsed:?})"
    );
    assert_eq!(run.outcome, RunOutcome::TimedOut);
}

#[test]
fn uat_040_completing_worker_is_not_blocked_by_postwait_killpg() {
    let r = WorkerRegistry::new(vec![deny_template("quiet", "/bin/true", &[])]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let started = std::time::Instant::now();
    let run = spawn(
        &r,
        "quiet",
        SpawnOptions::default(),
        &AuditWriter::new(&audit),
    )
    .expect("a quiet worker runs");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a clean run must not be slowed by the post-wait killpg (elapsed: {elapsed:?})"
    );
    assert_eq!(run.outcome, RunOutcome::Completed);
    assert_eq!(run.exit_code, Some(0));
}

#[test]
fn uat_040_posture_label_remains_isolated_process_exposure_in_test_path() {
    // B1.3: the B1.1 audit contract — a `WorkerSpawned` row's
    // `posture` is `ISOLATED_PROCESS_EXPOSURE` — still holds in
    // the test path, because the test harness does not install a
    // real `HardenConfig` and the broker falls back to
    // `PostureLabel::default()`. The runtime-aware posture is
    // exercised in the unit tests at `isolated_exec::tests`;
    // this row is the integration-level anchor that the audit
    // wire format is unchanged for current consumers.
    //
    // B1.3 ALSO adds a `degraded_reason: None` on the audit row
    // in the test path. Pinning that here too so a future change
    // that fills the field from the test harness (a lie) is
    // caught.
    let t = deny_template("audited-ok", "/bin/true", &[]);
    let r = WorkerRegistry::new(vec![t]);
    let audit = std::sync::Mutex::new(AuditLog::new(16));
    let run = spawn(
        &r,
        "audited-ok",
        completion_opts(),
        &AuditWriter::new(&audit),
    )
    .expect("run");
    assert_eq!(run.exit_code, Some(0));
    let recs = audit.lock().expect("not poisoned").query(0);
    match &recs[0].event {
        asv_ipc_protocol::AuditEventDto::WorkerSpawned {
            posture,
            degraded_reason,
            ..
        } => {
            assert_eq!(posture, "ISOLATED_PROCESS_EXPOSURE");
            // B1.3: degraded_reason is `None` in the test path
            // because the harness has no real HardenConfig. The
            // runtime-aware populate is exercised in the unit
            // tests at `isolated_exec::tests::effective_posture_*`.
            assert_eq!(
                degraded_reason, &None,
                "test path must not invent a degraded_reason (the harness has no real HardenConfig)"
            );
        }
        other => panic!("unexpected audit variant: {other:?}"),
    }
}
