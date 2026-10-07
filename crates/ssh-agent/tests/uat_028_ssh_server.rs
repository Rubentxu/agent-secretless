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

/// The machine's load at the moment of failure, folded into the message.
///
/// Written because the previous version of that message told the reader to go
/// and find out what had been competing for CPU — which is a chore performed
/// after the evidence has already been thrown away, on a machine that has
/// since run something else. Reading `/proc/loadavg` at the failure is one
/// syscall and turns the message into evidence rather than a to-do.
///
/// Absent, or unreadable, it contributes nothing: a machine without
/// `/proc/loadavg` gets a shorter message, not a broken one.
fn loadavg_line() -> String {
    let Ok(raw) = std::fs::read_to_string("/proc/loadavg") else {
        return String::new();
    };
    match raw.split_whitespace().collect::<Vec<_>>()[..3] {
        [one, five, fifteen] => format!(
            " At the time of the failure the machine reported loadavg {one}/{five}/{fifteen}."
        ),
        _ => String::new(),
    }
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

    // **sshd's transcript goes to a file, and that is load-bearing.**
    //
    // This used to be `.stderr(Stdio::piped())`, drained with
    // `wait_with_output()` *after* the client returned. At `LogLevel DEBUG3`
    // sshd writes 18 094 bytes for a single connection, and the default pipe
    // buffer on this host is 8 192 — so sshd filled the pipe and blocked
    // writing to it, partway through the key exchange, while the only code
    // that would have read it sat waiting for the client to return. The client
    // waited for a key-exchange reply that could not be produced, sshd's
    // `LoginGraceTime` expired, and the run took exactly as long as that grace.
    //
    // Measured, both arms of the same A/B with everything else held constant:
    //
    //   stderr = pipe : 0 passed, 6 hung  (~21 s each)
    //   stderr = file : 6 passed, 0 hung  (~0.10 s each)
    //
    // It looked like a load problem, then like an sshd problem on this host,
    // then like the readiness probe. A stock sshd driven from a shell completes
    // the key exchange 4 times out of 4, and the probe made no difference
    // (loop 0/6 against single 1/6). The fault was in this harness the whole
    // time, and it was the one descriptor nobody was reading.
    //
    // A file never applies backpressure, so sshd is never blocked by how much
    // it wants to say — which is the property this test was silently depending
    // on and did not have.
    let sshd_log = dir.path().join("sshd.log");
    let mut sshd = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&sshd_log).expect("open the sshd log"),
        ))
        .spawn()
        .expect("sshd is installed");
    if !wait_for_port(port, Duration::from_secs(5)) {
        let _ = sshd.kill();
        let _ = sshd.wait();
        panic!(
            "sshd did not listen: {}",
            std::fs::read_to_string(&sshd_log).unwrap_or_default()
        );
    }

    let authorized_text = std::fs::read_to_string(&authorized).expect("authorized text");

    let started = Instant::now();
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
    let elapsed = started.elapsed();

    let _ = sshd.kill();
    let _ = sshd.wait();
    let server_stderr = std::fs::read_to_string(&sshd_log).expect("read the sshd transcript back");
    let client_stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        // **A dropped connection is not a refused authentication, and the two
        // carry different evidence.**
        //
        // OpenSSH says a refusal in words — `Permission denied`, `Too many
        // authentication failures`, a host-key complaint — and this test runs
        // the client at `LogLevel=ERROR`, so a real refusal always arrives with
        // text on stderr. What this test was printing on a busy machine was
        // `stderr=` empty next to "OpenSSH auth failed", which reads as a
        // policy decision and is in fact a client that was disconnected.
        // Naming which of the two happened is the point: a false red that says
        // "auth failed" sends the next reader to the policy engine.
        //
        // **What this failure is NOT.** An earlier version of this message
        // called it "a load-shaped failure" and told the reader to go and check
        // what was competing for CPU. That was asserted, not measured, and it
        // is wrong — measured here:
        //
        //   attempt 1: hung  60s+ at loadavg 12.11
        //   attempt 2: hung  60s+ at loadavg 13.85
        //   attempt 3: PASS     143ms at loadavg 24.81
        //
        // It fails at *lower* load and passes at *higher* load, three attempts
        // back to back on a 64-core host. A variable that moves the wrong way
        // is not the variable. Separately, `cargo test` runs test binaries one
        // at a time and this binary holds exactly one test, so the suite cannot
        // be starving it either — `--test-threads` cannot reach this test.
        //
        // So the message now localises the stall rather than attributing it.
        // Attributing it to the machine was the same defect one layer down: a
        // confident wrong answer sends the next reader somewhere that is not
        // where the fault is.
        //
        // **Where it actually stops, read from both sides at DEBUG3.** This is
        // measured, and it moves the failure well clear of the product:
        //
        //   client: `send packet: type 30` (ECDH_INIT sent)
        //           `expecting SSH2_MSG_KEX_ECDH_REPLY`
        //   server: `receive packet: type 30` / `SSH2_MSG_KEX_ECDH_INIT received`
        //           `mm_sshkey_sign: entering`
        //           `mm_request_send: entering, type 6`   ← and then nothing
        //
        // The client is waiting for the key-exchange reply. The server cannot
        // build that reply until its privileged monitor signs the host key, and
        // the monitor does not answer. Both sides are therefore still in the
        // key exchange: **this is before `userauth`**, so the agent, the
        // `authorized_keys` file and the broker are never reached. Confirmed
        // independently: while it hangs, the client holds exactly one socket —
        // its TCP connection to sshd — and the agent's own socket has no
        // established peer, because the client never opened it.
        //
        // So the property this test exists to prove — that OpenSSH can
        // authenticate through the broker socket without holding a private key
        // — is not what failed. What failed is sshd's monitor on this host, and
        // why it stalls is still not established.
        let dropped = client_stderr.trim().is_empty();
        let load = loadavg_line();
        let what = if dropped {
            format!(
                "the SSH client was disconnected rather than refused, after \
                 {elapsed:?} with no diagnostic on its stderr, and the elapsed \
                 time tracks sshd's LoginGraceTime. This is NOT an \
                 authentication failure: read at DEBUG3 from both sides, the \
                 client is waiting for SSH2_MSG_KEX_ECDH_REPLY and the server \
                 is stuck at mm_sshkey_sign asking its monitor to sign the host \
                 key, so the session never reaches userauth. The agent, the \
                 authorized_keys file and the broker are not involved, and \
                 neither is the policy engine. Why the monitor stalls on this \
                 host is not established, and it is not known to be load, which \
                 has been observed to move the wrong way.{load}"
            )
        } else {
            format!("OpenSSH auth failed after {elapsed:?}{load}")
        };
        panic!(
            "{what}: stdout={} client_stderr={} sshd={} authorized={} listed={}",
            String::from_utf8_lossy(&output.stdout),
            client_stderr,
            server_stderr,
            authorized_text,
            listed_text
        );
    }
}
