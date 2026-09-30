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

    // The ssh user is whatever the client will log in as, which `ssh` takes
    // from the local username unless told otherwise. The test must not read
    // $USER to learn it: the UAT runner spawns every scenario with an empty
    // environment (sddk-gateway/src/runner.rs), so `USER` is absent there and
    // this line panicked with "USER set: NotPresent". That is exactly the
    // class of bug a hermetic UAT suite must not have, and it only surfaced
    // once the scenario was executed by the runner instead of by hand.
    //
    // No dependency is added for this. The uid is the same under an empty
    // environment, and it is what `ssh` and sshd resolve the account from.
    let user = unsafe {
        let uid = libc::getuid();
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr((*passwd).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
    .expect("resolve the local user name from the passwd database");
    let authorized = dir.path().join("authorized_keys");
    let listed = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", session.socket_path())
        .output()
        .expect("ssh-add");
    assert!(listed.status.success(), "ssh-add failed: {:?}", listed);
    let listed_text = String::from_utf8(listed.stdout).expect("ssh-add output");
    std::fs::write(&authorized, &listed_text).expect("authorized keys");
    let identity = dir.path().join("identity");
    std::fs::write(identity.with_extension("pub"), &listed_text).expect("identity public key");
    let config = dir.path().join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms +ssh-ed25519\nAllowUsers {user}\nLogLevel DEBUG3\nPidFile none\n",
            host_key.display(),
            authorized.display(),
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
            "PubkeyAuthentication=unbound",
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
        .arg("-o")
        .arg(format!("IdentityFile={}", identity.display()))
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
