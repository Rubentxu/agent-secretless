//! B1.8: real IPC reports a durable audit gap without terminating brokerd.
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_broker::audit::AuditLog;
use asv_ipc_protocol::AuditEventDto;

const LIMIT: u64 = 1024 * 1024;

struct BrokerGuard(Child);
impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cargo_bin(name: &str) -> std::path::PathBuf {
    asv_broker::binary::locate(name)
}

fn status(cli: &Path, socket: &Path, json: bool) -> String {
    let mut command = Command::new(cli);
    command.arg("--socket").arg(socket).arg("status");
    if json {
        command.arg("--json");
    }
    let output = command.output().expect("run status");
    assert!(output.status.success(), "status failed: {output:?}");
    assert!(output.stderr.is_empty(), "unexpected stderr: {output:?}");
    String::from_utf8(output.stdout).expect("UTF-8 status")
}

#[test]
fn durable_audit_gap_is_visible_over_real_ipc() {
    // Locate before imposing any limit: stale binaries are an error, not an
    // unavailable RLIMIT substrate, and must never be disguised as a skip.
    let broker_bin = cargo_bin("asv-brokerd");
    let cli_bin = cargo_bin("asv");
    let dir = tempfile::tempdir().expect("temporary fixture");
    let socket = dir.path().join("broker.sock");
    let audit_path = dir.path().join("audit.jsonl");
    let vault_path = dir.path().join("vault.asv");
    let pass_path = dir.path().join("passphrase.txt");
    std::fs::write(&pass_path, b"audit-gap-test\n").expect("fixture passphrase");
    drop(
        asv_vault::VaultStore::create(
            &vault_path,
            &secrecy::SecretString::from("audit-gap-test".to_string()),
            asv_vault::KdfParams::fast_for_tests(),
        )
        .expect("create fresh vault"),
    );
    assert!(std::fs::metadata(&vault_path).unwrap().len() < LIMIT);
    let mut log = AuditLog::open_persistent(0, &audit_path).expect("open durable audit");
    let mut timestamp = 0;
    while std::fs::metadata(&audit_path).unwrap().len() < LIMIT {
        log.append(
            AuditEventDto::RequestHandled {
                method: "ping".into(),
                session: None,
                peer_uid: 1000,
                pinned: false,
                outcome: "ok".into(),
                posture: "SERVICE_BROKERED".into(),
            },
            timestamp,
        )
        .expect("prefill through public audit API");
        timestamp += 1;
    }
    drop(log);
    let original_size = std::fs::metadata(&audit_path).unwrap().len();

    let mut command = Command::new(broker_bin);
    command
        .arg(&socket)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--passphrase-file")
        .arg(&pass_path)
        .arg("--audit-file")
        .arg(&audit_path)
        .arg("--audit-max-records")
        .arg("10000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Restrict only the forked test child; never mutate the test harness's
    // process-global signal disposition or limits. SIG_IGN survives exec.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: LIMIT,
                rlim_max: LIMIT,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut broker = match command.spawn() {
        Ok(child) => BrokerGuard(child),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EINVAL | libc::ENOSYS)
            ) =>
        {
            println!("UNAVAILABLE_SUBSTRATE: RLIMIT_FSIZE/SIGXFSZ: {error}");
            return;
        }
        Err(error) => panic!("spawn broker: {error}"),
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() && Instant::now() < deadline {
        assert!(
            broker.0.try_wait().unwrap().is_none(),
            "broker exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "broker socket readiness deadline exceeded");
    // Pong precedes the append for its own handled request.
    let first = status(&cli_bin, &socket, true);
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["data"]["result"]["audit_write_failures"], 0);
    let second = status(&cli_bin, &socket, true);
    let second: serde_json::Value = serde_json::from_str(&second).unwrap();
    let count = second["data"]["result"]["audit_write_failures"]
        .as_u64()
        .expect("failure count");
    assert!(count >= 1, "{second}");
    let human = status(&cli_bin, &socket, false);
    assert!(
        human.contains(&format!(
            "audit: {} durable audit write(s) failed since start; those records were not persisted",
            count + 1
        )),
        "{human}"
    );
    assert!(
        broker.0.try_wait().unwrap().is_none(),
        "broker must survive SIGXFSZ"
    );
    assert_eq!(std::fs::metadata(&audit_path).unwrap().len(), original_size);
    broker.0.kill().expect("stop fixture broker");
    broker.0.wait().expect("reap fixture broker");
    let mut stdout = String::new();
    broker
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(
        stdout.contains("did not land in the durable audit log"),
        "{stdout}"
    );
    println!("B1.8: first count=0, second count={count}; human warning, live broker, unchanged durable file, and error trace verified");
}
