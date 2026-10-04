//! C1-R — the broker must not run as an identity the installation did not ask
//! for, and must be able to when it was asked for correctly.
//!
//! ## The residual, measured rather than quoted
//!
//! M7's first scope item — *dedicated broker UID production packaging* — is
//! undelivered, and the gate row says so in prose. The code says what the
//! consequence is. `main.rs` derives the socket path from the running uid and
//! sets it `0600`, its directory `0700`; `harden::install` sets
//! `PR_SET_DUMPABLE` to 0 and installs Landlock and seccomp. All of that is
//! real, and all of it lives **inside the invoking user's own boundary**, so
//! any other program that user runs is in the same uid and can open the socket,
//! the vault and the audit log.
//!
//! UAT-003 proves the broker is unreadable by a process *lacking*
//! `CAP_SYS_PTRACE`. That is a narrower claim than "unreadable", and the
//! distance between those two sentences is this uid. The residual was a
//! footnote because nothing could *see* it.
//!
//! ## What can now be seen
//!
//! The launch contract declares the uid the installation expects
//! (`--identity-uid`) and can demand the guarantee
//! (`--require-dedicated-identity`). Three properties, each of which the unit
//! tests on `identity::check` cannot establish because they are about the
//! binary rather than the function:
//!
//! 1. a declaration that is not honoured **stops the broker**, and it does so
//!    **before the vault is opened** — a refusal that arrives after the
//!    passphrase has been read is a refusal that already had the secret;
//! 2. a demand with nothing declared stops it too, which is what stops a
//!    packaged install from degrading into the development shape quietly;
//! 3. and the honest case **still starts**. A gate that can only say no is not
//!    a gate, it is a wall, and these two tests are the difference between the
//!    two.
//!
//! ## Why the real binary
//!
//! The decision function has ten unit tests. What none of them can catch is
//! `main` not calling it — and this repository has now found that defect
//! twice on this very module: `ShutdownSignal::stop` and
//! `ShutdownSignal::revoke` were both complete, correct, tested mechanisms with
//! no caller in production. A refusal nobody executes is a comment.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The uid this test process runs as, which is the uid the broker it spawns
/// runs as. Read rather than written down, because a suite that hardcodes 1000
/// passes on one account and fails on every other — which is the defect the
/// socket-path derivation was rewritten to remove.
fn my_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// A uid that is certainly not ours.
///
/// `+ 1` rather than a literal, for the same reason: the property under test is
/// that the broker is *not* the declared identity, and any value other than our
/// own says that. Wrapping at the top of the uid space is the one case that
/// would break it, and 0xFFFF_FFFE is not a uid a process runs as.
fn not_my_uid() -> u32 {
    my_uid().wrapping_add(1)
}

/// Locates a workspace binary through the one locator, which also refuses one
/// older than the sources of the package that produces it.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
}
/// A working directory with a real vault and a real passphrase.
struct Sandbox {
    dir: PathBuf,
    vault: PathBuf,
    passphrase: PathBuf,
    sock: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-identity-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");
        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("identity-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
        VaultStore::create(
            &vault,
            &SecretString::new(value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");
        Self {
            dir,
            vault,
            passphrase,
            sock,
        }
    }

    /// A sandbox whose vault does not exist, for the ordering property.
    fn without_a_vault(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-identity-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");
        let passphrase = dir.join("passphrase.txt");
        std::fs::write(&passphrase, "absent-vault-passphrase\n").expect("write the passphrase");
        Self {
            vault: dir.join("no-such-vault.asv"),
            passphrase,
            sock: dir.join("broker.sock"),
            dir,
        }
    }
}

/// Stops the broker when the test ends, however it ends.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Ask the broker to describe itself, over its real socket.
fn agent_info(sock: &Path) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    let payload = serde_json::to_vec(&asv_ipc_protocol::Request::AgentInfo {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
    })
    .expect("serialize");
    stream.write_all(&payload).expect("write");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read");
    assert!(n > 0, "broker closed without answering AgentInfo");
    serde_json::from_slice(&buf[..n]).expect("parse response")
}

/// Wait for a broker to come up, and return the handle that keeps it alive.
///
/// The failure mode this guards is a broker that exits during startup: without
/// the wait, `sock.exists()` is false immediately after spawn and every test
/// would report a refusal for a broker that had not been given time to start.
fn wait_for_socket(sock: &Path, broker: Child) -> Result<Broker, (Child, String)> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if sock.exists() {
        Ok(Broker(broker))
    } else {
        Err((broker, "the broker never created its socket".to_string()))
    }
}

impl Sandbox {
    /// Start with `extra` appended, wait for the socket, and return the guard.
    fn start(&self, extra: &[&str]) -> Result<Broker, String> {
        let mut command = Command::new(cargo_bin("asv-brokerd"));
        command
            .arg(&self.sock)
            .arg("--vault")
            .arg(&self.vault)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let broker = command.spawn().expect("spawn asv-brokerd");
        match wait_for_socket(&self.sock, broker) {
            Ok(guard) => Ok(guard),
            Err((mut dead, note)) => {
                // No stderr is quoted here: this path nulls it, and a broker
                // that was *supposed* to start and did not is a failure the
                // operator reproduces by hand far more usefully than from a
                // string this test carries. The refusals below capture it,
                // because there the message is the thing under test.
                let exited = wait_for_exit(&mut dead, Duration::from_secs(5)).is_some();
                let _ = dead.kill();
                let _ = dead.wait();
                Err(if exited {
                    format!("{note}; it exited without refusing")
                } else {
                    format!("{note}; it was still running")
                })
            }
        }
    }

    /// Start with `extra` appended and expect the broker to **refuse**.
    ///
    /// Returns its stderr, which is the only place the refusal can be read: a
    /// broker that exits with a non-zero status and says nothing would satisfy
    /// an assertion on the status alone.
    ///
    /// Bounded rather than `output()`, because a refusal that is supposed to
    /// exit promptly and does not would otherwise hang the suite, and a test
    /// that hangs is worse than one that fails.
    fn expect_refusal(&self, extra: &[&str]) -> String {
        let mut command = Command::new(cargo_bin("asv-brokerd"));
        command
            .arg(&self.sock)
            .arg("--vault")
            .arg(&self.vault)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn asv-brokerd");
        let status = wait_for_exit(&mut child, Duration::from_secs(20)).unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            // **Not a hang, and the wording matters.** The first version of
            // this said "neither started nor exited", which is what a reader
            // takes away — and it is wrong. What actually happens when the gate
            // is absent is the more alarming thing: the broker starts, opens
            // the vault and *serves*, and keeps running until something kills
            // it. Reporting that as an ambiguous timeout would have hidden the
            // escape behind a word that reads like infrastructure.
            panic!(
                "the broker kept serving instead of refusing. With {extra:?} the \
                 identity gate did not stop a broker holding a credential under an \
                 identity the installation did not ask for."
            )
        });

        let mut text = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            text = String::from_utf8_lossy(&buf).into_owned();
        }
        assert!(
            !status.success(),
            "the broker started with {extra:?} when it should have refused. It said: {text}"
        );
        assert!(
            !self.sock.exists(),
            "the broker refused but left a socket behind at {}; a refused broker \
             that bound a listener is a broker that accepted a connection",
            self.sock.display()
        );
        text
    }
}

/// Bounded wait for a process that is expected to exit on its own.
fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_broker_declaring_an_identity_it_is_not_being_does_not_start() {
    let s = Sandbox::new("mismatch");
    let text = s.expect_refusal(&["--identity-uid", &not_my_uid().to_string()]);

    assert!(
        text.contains("declared uid")
            && text.contains(&not_my_uid().to_string())
            && text.contains(&my_uid().to_string()),
        "the refusal must name both the declared and the actual uid, or the \
         operator cannot tell which one is wrong. It said: {text}"
    );
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_broker_required_to_have_a_dedicated_identity_and_given_none_does_not_start() {
    let s = Sandbox::new("undeclared");
    let text = s.expect_refusal(&["--require-dedicated-identity"]);

    assert!(
        text.contains("--require-dedicated-identity") && text.contains("--identity-uid"),
        "the refusal must name both flags, because the two together are what an \
         operator has to change. It said: {text}"
    );
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn the_identity_refusal_happens_before_the_vault_is_opened() {
    // No vault exists here, so *something* has to be refused. If the broker
    // complained about the vault, the identity gate is running in the wrong
    // place — after the passphrase has been read, which is a refusal that
    // already had the secret.
    let s = Sandbox::without_a_vault("order");
    let text = s.expect_refusal(&["--identity-uid", &not_my_uid().to_string()]);

    assert!(
        !text.contains("vault") || text.contains("declared uid"),
        "the broker refused for something other than its identity, so the gate \
         runs after the vault is opened: {text}"
    );
    assert!(
        text.contains("declared uid"),
        "the refusal is not the identity one: {text}"
    );
    let _ = std::fs::remove_dir_all(&s.dir);
}

/// Ask the broker to describe itself, and read the identity out of the answer.
fn reported_identity(sock: &Path) -> Option<asv_ipc_protocol::BrokerIdentity> {
    let info = agent_info(sock);
    info["identity"]
        .as_object()
        .map(|_| serde_json::from_value(info["identity"].clone()).expect("parse the identity"))
}

#[test]
fn the_broker_reports_the_uid_it_is_actually_running_as() {
    // **The field the whole increment exists for.** The enforcement half landed
    // in the previous commit and was proved against the binary; this proves the
    // other half — that an operator can *ask* and get a measured answer instead
    // of reading a footnote in a gate row.
    let s = Sandbox::new("reported-shared");
    let broker = s.start(&[]).unwrap_or_else(|e| panic!("start: {e}"));

    let identity = reported_identity(&s.sock)
        .expect("a broker started by this binary has measured an identity");
    assert_eq!(
        identity.uid,
        my_uid(),
        "the broker reported a uid it is not running as: {identity:?}"
    );
    assert_eq!(
        identity.declared_uid, None,
        "nobody declared an identity, so none may be reported: {identity:?}"
    );
    assert!(
        !identity.dedicated,
        "a broker with no declared identity is not a dedicated one, and this is \
         the claim the M7 row spent a milestone narrowing to: {identity:?}"
    );
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_broker_reporting_a_declared_identity_says_it_is_dedicated() {
    let s = Sandbox::new("reported-dedicated");
    let mine = my_uid().to_string();
    let broker = s
        .start(&["--identity-uid", &mine])
        .unwrap_or_else(|e| panic!("start: {e}"));

    let identity = reported_identity(&s.sock).expect("a measured identity");
    assert!(
        identity.dedicated,
        "a broker running as the uid it declared must say so: {identity:?}"
    );
    assert_eq!(identity.declared_uid, Some(my_uid()), "{identity:?}");
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn the_report_carries_the_measured_uid_rather_than_a_default() {
    // The re-shaping test in `identity.rs` covers the function; this covers the
    // wire, which is where a wrong number would be *read by an operator* rather
    // than merely asserted. `0` is the value a default gives and it reads as
    // root, so it is the one that must not appear.
    let s = Sandbox::new("not-root");
    let broker = s.start(&[]).unwrap_or_else(|e| panic!("start: {e}"));
    let identity = reported_identity(&s.sock).expect("a measured identity");
    assert_ne!(
        identity.uid, 0,
        "a broker that measured no identity would default to 0, which reads as root"
    );
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_refused_broker_leaves_no_socket_and_no_listener() {
    // **The ordering property, stated as its own test because the falsification
    // campaign found that the message was the weaker witness.**
    //
    // `main` does, in this order: check the identity, bind the socket, read the
    // passphrase, open the vault. So a gate placed correctly refuses before
    // *any* of them, and the two that matter are separate. Moving the check to
    // just after `VaultStore::open` still refuses, and still says the right
    // words — and the broker has been listening the whole time. A client
    // dialling that socket in the window gets a broker that is about to die
    // holding its credential, and an operator reading the log sees a refusal
    // that looks like it happened first.
    //
    // So the assertion is about the filesystem, not the prose. A refusal that
    // left a listener behind is a refusal that already accepted a connection.
    let s = Sandbox::new("no-socket");
    let _ = s.expect_refusal(&["--identity-uid", &not_my_uid().to_string()]);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_broker_asked_for_nothing_starts() {
    // The development case. A developer on their own machine has no dedicated
    // uid, and a gate that refused them would be refused by the next person to
    // run the tests.
    let s = Sandbox::new("nothing-asked");
    let broker = s
        .start(&[])
        .unwrap_or_else(|e| panic!("a broker with no identity flags must start: {e}"));

    // It answers, so "it started" is not satisfied by a socket file left behind
    // by a process that is on its way out.
    let _ = agent_info(&s.sock);
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_broker_declaring_the_identity_it_is_being_starts_and_serves() {
    // The control for both refusals. Without it, "refuses everything" would
    // satisfy every assertion above.
    let s = Sandbox::new("honoured");
    let mine = my_uid().to_string();
    let broker = s
        .start(&["--identity-uid", &mine])
        .unwrap_or_else(|e| panic!("a broker declaring the uid it is running as must start: {e}"));

    let _ = agent_info(&s.sock);
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_broker_required_and_declaring_both_starts_and_serves() {
    // The strongest form, and the one the packaging depends on: the guarantee
    // is satisfiable. A demand that could only ever be refused would be a flag
    // nobody could ship.
    let s = Sandbox::new("required-and-honoured");
    let mine = my_uid().to_string();
    let broker = s
        .start(&["--identity-uid", &mine, "--require-dedicated-identity"])
        .unwrap_or_else(|e| panic!("a required identity that is honoured must start: {e}"));

    let _ = agent_info(&s.sock);
    drop(broker);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_non_numeric_identity_is_a_usage_error_rather_than_a_refusal() {
    // A typo must not read as "the broker refused for a policy reason", which
    // is what an unparsable uid falling through to a default would produce.
    // No vault is passed at all, so the only thing that can stop this broker is
    // the argument parser.
    let s = Sandbox::new("nonnumeric");
    let mut command = Command::new(cargo_bin("asv-brokerd"));
    let mut child = command
        .arg(&s.sock)
        .arg("--identity-uid")
        .arg("asv-broker")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn asv-brokerd");
    let status = wait_for_exit(&mut child, Duration::from_secs(20)).unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("a non-numeric uid did not stop the broker; it kept running");
    });
    let mut text = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        text = String::from_utf8_lossy(&buf).into_owned();
    }

    assert!(!status.success(), "a non-numeric uid was accepted: {text}");
    assert_eq!(
        status.code(),
        Some(2),
        "a usage error is exit 2 and a refusal is exit 1, so a script can tell a \
         typo from a policy decision. It exited {:?} saying: {text}",
        status.code()
    );
    let _ = std::fs::remove_dir_all(&s.dir);
}
