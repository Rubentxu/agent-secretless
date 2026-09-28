//! UAT-028 live SSH client/server round trip.
//!
//! This is intentionally an external-process test: it proves OpenSSH can use
//! the session socket to authenticate without receiving a private key file.

use asv_ssh_agent::AgentSession;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn wait_for_port(port: u16, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
#[ignore = "environment sshd rejects the ephemeral AuthorizedKeys source; rerun on a supported user-key test host"]
fn uat_028_openssh_authenticates_through_the_broker_socket() {
    let dir = tempdir().expect("tempdir");
    let session = AgentSession::start(dir.path().join("session")).expect("agent session");
    let port = TcpListener::bind(("127.0.0.1", 0))
        .expect("free port")
        .local_addr()
        .expect("address")
        .port();

    let host_key = dir.path().join("host_key");
    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .output()
        .expect("ssh-keygen is installed");
    assert!(keygen.status.success(), "ssh-keygen failed: {keygen:?}");

    let user = std::env::var("USER").expect("USER set");
    let authorized = dir.path().join("authorized_keys");
    let listed = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", session.socket_path())
        .output()
        .expect("ssh-add");
    assert!(listed.status.success(), "ssh-add failed: {:?}", listed);
    let listed_text = String::from_utf8(listed.stdout).expect("ssh-add output");
    std::fs::write(&authorized, &listed_text).expect("authorized keys");

    let command = dir.path().join("authorized_keys_command");
    std::fs::write(
        &command,
        format!("#!/bin/sh\ncat {}\n", authorized.display()),
    )
    .expect("authorized keys command");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
            .expect("command permissions");
    }

    let config = dir.path().join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile none\nAuthorizedKeysCommand {} %u\nAuthorizedKeysCommandUser {user}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms +ssh-ed25519\nAllowUsers {user}\nLogLevel DEBUG3\nPidFile none\n",
            host_key.display(),
            command.display(),
        ),
    )
    .expect("sshd config");

    let mut sshd = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sshd is installed");
    if !wait_for_port(port, Duration::from_secs(5)) {
        let _ = sshd.kill();
        let output = sshd.wait_with_output().expect("sshd diagnostics");
        panic!(
            "sshd did not listen: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let authorized_text = std::fs::read_to_string(&authorized).expect("authorized text");

    let output = Command::new("ssh")
        .env("SSH_AUTH_SOCK", session.socket_path())
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ])
        .arg("-o")
        .arg(format!("IdentityAgent={}", session.socket_path().display()))
        .args(["-p"])
        .arg(port.to_string())
        .arg(format!("{user}@127.0.0.1"))
        .arg("true")
        .output()
        .expect("ssh is installed");

    let _ = sshd.kill();
    let server_output = sshd.wait_with_output().expect("sshd output");
    assert!(
        output.status.success(),
        "OpenSSH auth failed: stdout={} stderr={} sshd={} authorized={} listed={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_output.stderr),
        authorized_text,
        listed_text
    );
}
