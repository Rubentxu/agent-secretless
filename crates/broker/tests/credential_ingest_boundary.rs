//! REQ-1a — the secret must not be observable from the process that plants it.
//!
//! # What is already covered, and why this file is not a duplicate
//!
//! `revoke_survives_restart.rs` plants a canary through the real CLI and
//! asserts it does not appear in a later listing or a revocation's output.
//! That is the response boundary, and it is proven.
//!
//! It is not the *process* boundary. Its `asv` helper concatenates stdout and
//! stderr and the planting output is consumed only by `assert!(ok, ...)` — so
//! a broker that echoed the secret back on the plant would still pass every
//! assertion in that file. It also never inspects `/proc`, which is where the
//! doc-comment on `add-credential` says the real risk lives:
//!
//! > The secret is read from **stdin**, never from argv and never from the
//! > environment. Both are readable by any same-uid peer through
//! > `/proc/<pid>/cmdline` and `/proc/<pid>/environ`, which is a kernel
//! > property this product does not claim to control.
//!
//! That paragraph is an argument. This file measures it.
//!
//! # The technique
//!
//! `add-credential` reads the secret with `read_to_string`, which blocks
//! until EOF. So the test writes the canary into the child's stdin and
//! deliberately **keeps the pipe open**. The child is then alive and parked
//! inside that read, which is exactly the window in which `/proc/<pid>/cmdline`
//! and `/proc/<pid>/environ` can be read for it. The canary is then closed
//! and the plant completes normally.
//!
//! If the implementation ever switched to `--secret <value>` or an environment
//! variable, the child would stop blocking on stdin, the `/proc` read would
//! race a process that is already gone, and the first assertion below would
//! fail on the missing `/proc` entry rather than passing quietly.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// Must not appear anywhere the planting process can be observed from.
const CANARY: &str = "ASV-CANARY-ingest-boundary-7c1f-DO-NOT-LEAK";

fn cargo_bin(name: &str) -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.join(name));
            }
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(profile)
            .join(name),
    );
    for c in &candidates {
        if c.is_file() {
            return c.clone();
        }
    }
    panic!("cannot find binary `{name}`; looked in {candidates:?}");
}

struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A broker on a real socket with a real vault behind it.
struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    vault: PathBuf,
    passphrase: PathBuf,
    _broker: Broker,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-ingest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("ingest-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");

        VaultStore::create(
            &vault,
            &SecretString::new(value.into()),
            KdfParams::fast_for_tests(),
        )
        .expect("create the vault");

        // ADR-0015: without an enrolled principal the plant is refused, and the
        // refusal would make every assertion below vacuous.
        let enrol = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("run --enrol-principal");
        assert!(
            enrol.status.success(),
            "enrolment failed: {}",
            String::from_utf8_lossy(&enrol.stderr)
        );

        let broker = Broker(
            Command::new(cargo_bin("asv-brokerd"))
                .arg(&sock)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&passphrase)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn asv-brokerd"),
        );

        let deadline = Instant::now() + Duration::from_secs(20);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the broker never created its socket");

        Self {
            dir,
            sock,
            vault,
            passphrase,
            _broker: broker,
        }
    }

    /// Runs the real CLI to completion, optionally feeding it a secret, and
    /// returns `(success, stdout+stderr)`.
    fn asv(&self, args: &[&str], stdin: Option<&str>) -> (bool, String) {
        let mut child = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv");
        if let Some(secret) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(secret.as_bytes())
                .expect("write the secret to the child's stdin");
        }
        let out = child.wait_with_output().expect("asv completes");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// Starts the CLI with the canary on stdin and **the pipe held open**, so
    /// the child is alive and blocked in `read_to_string` while we inspect it.
    fn cli_blocked_on_stdin(&self) -> Child {
        let mut child = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&self.sock)
            .args([
                "add-credential",
                "--label",
                "ingest-boundary",
                "--kind",
                "bearer_token",
                "--provider",
                "github",
                "--account",
                "acct",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn asv add-credential");
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(format!("{CANARY}\n").as_bytes())
            .expect("write the canary to the child's stdin");
        child
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Reads a `/proc/<pid>/<leaf>` file for a live process, waiting until it has
/// something in it.
///
/// Two things this has to survive, both learned the hard way:
///
/// 1. `read_to_end` on a `File`, **not** `fs::read_to_string`. A procfs file
///    reports a length of zero and `fs::read_to_string` sizes its buffer from
///    that length, so on `/proc/<pid>/cmdline` it returns `""` for a live
///    process. An earlier version of this file used it and both positive tests
///    went green while being vacuous — an empty string trivially contains no
///    canary. The negative test below is what caught it.
///
/// 2. **An empty read is retried, not accepted.** Between `fork` and `exec`
///    the kernel reports an empty `cmdline` for the new process, so a read
///    taken immediately after `spawn` can legitimately see nothing. Treating
///    that as "no canary" would be the same vacuous green as above. A process
///    that has exec'd has a non-empty `cmdline`, so the loop below waits for
///    that rather than guessing.
///
/// NUL bytes are expected here — `cmdline` is NUL-separated — so the bytes are
/// read raw and lossily decoded rather than validated as UTF-8.
fn proc_read(pid: u32, leaf: &str) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut file) = std::fs::File::open(format!("/proc/{pid}/{leaf}")) {
            let mut buf = Vec::new();
            if std::io::Read::read_to_end(&mut file, &mut buf).is_ok() && !buf.is_empty() {
                return Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        // The process is gone, or has not exec'd yet and never will.
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// REQ-1a, part one: the secret is in neither the command line nor the
/// environment of the process handling it, while that process is alive and
/// holding the secret.
#[test]
fn the_secret_is_in_neither_argv_nor_environ_of_the_live_cli() {
    let fx = Fixture::new("proc");
    let mut child = fx.cli_blocked_on_stdin();
    let pid = child.id();

    // The child is parked in `read_to_string`, so it is alive and has the
    // canary in its address space. This is the window the claim is about.
    let cmdline = proc_read(pid, "cmdline")
        .unwrap_or_else(|| panic!("the CLI exited before it could be observed: pid {pid} is gone"));
    let environ = proc_read(pid, "environ").unwrap_or_else(|| {
        panic!("the CLI exited before it could be observed: pid {pid} is gone")
    });

    // `/proc/<pid>/cmdline` is NUL-separated, and this is the property the
    // doc-comment claims: the secret is not among the arguments.
    assert!(
        !cmdline.contains(CANARY),
        "the secret is in the command line, where any same-uid peer could read \
         it from /proc/{pid}/cmdline: {cmdline:?}"
    );

    // And it is not in the environment either, which is the same read a peer
    // would do against /proc/<pid>/environ.
    assert!(
        !environ.contains(CANARY),
        "the secret is in the environment, where any same-uid peer could read \
         it from /proc/{pid}/environ"
    );

    // The canary really was in flight, or the two assertions above are
    // vacuous: they would also pass against a child that received nothing.
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the CLI finished before it could be observed. It should be blocked \
         reading the secret from stdin; if it is not, the secret is arriving \
         some other way and the assertions above prove nothing."
    );

    // Let the plant finish, and confirm it was a real one.
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("asv completes");
    assert!(
        out.status.success(),
        "planting failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// REQ-1a, part two: the output of the plant itself carries no secret.
///
/// `revoke_survives_restart.rs` checks the listing and the revocation but
/// consumes the planting output only through `assert!(ok, ...)`. A broker
/// that echoed the secret back on the plant would pass that file. This one
/// cannot.
#[test]
fn the_planting_output_carries_no_secret() {
    let fx = Fixture::new("output");

    let (ok, out) = fx.asv(
        &[
            "add-credential",
            "--label",
            "ingest-output",
            "--kind",
            "bearer_token",
            "--provider",
            "github",
            "--account",
            "acct",
        ],
        Some(&format!("{CANARY}\n")),
    );
    assert!(ok, "planting a credential failed:\n{out}");

    assert!(
        !out.contains(CANARY),
        "the plant echoed the secret back to the client:\n{out}"
    );

    // The plant is real: the credential exists, and listing it proves the
    // write landed rather than being swallowed by the assertion above.
    let (ok, listing) = fx.asv(&["credentials"], None);
    assert!(ok, "listing failed:\n{listing}");
    assert_ne!(
        listing.trim(),
        "no credentials stored",
        "the plant did not land, so the assertion above proved nothing"
    );
    assert!(
        !listing.contains(CANARY),
        "the listing carries the secret, not just its metadata:\n{listing}"
    );
}

/// The negative that keeps the first test honest: a canary passed as an
/// argument *is* observable in `/proc/<pid>/cmdline`, by the same read the
/// test above performs.
///
/// Without this, the first test would also pass if `/proc` simply could not be
/// read at all, which is the failure mode that would make it look like
/// evidence.
#[test]
fn a_canary_passed_as_an_argument_is_visible_in_proc() {
    let fx = Fixture::new("negative");

    // `sh -c SCRIPT NAME` sets `$0` to NAME, so the canary lands in the
    // child's argument vector.
    //
    // The script is a loop, and that is load-bearing. `sh -c 'sleep 5'`
    // **execs** sleep, which replaces the process image and therefore its
    // argv — the canary vanishes along with `sh`, and this negative would fail
    // for a reason that has nothing to do with argument visibility. A loop
    // cannot be exec'd: the shell has to keep interpreting it, so it stays in
    // its own process with its own argv intact.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("while :; do sleep 1; done")
        .arg(CANARY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the probe");
    let pid = child.id();

    let cmdline = proc_read(pid, "cmdline")
        .unwrap_or_else(|| panic!("the probe exited before it could be observed: pid {pid}"));
    assert!(
        cmdline.contains(CANARY),
        "an argument is not visible in /proc/{pid}/cmdline here, so the first \
         test's silence proves nothing about the implementation: {cmdline:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
    // The fixture is kept alive to the end so the broker outlives the probe.
    let _ = fx.sock.exists();
    let _: &Path = fx.vault.as_path();
    let _: &Path = fx.passphrase.as_path();
}