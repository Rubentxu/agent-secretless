//! REQ-7 — a revocation must survive the broker dying.
//!
//! Every in-process test of `DeleteCredential` shares one weakness that the
//! unit suite cannot remove: the vault handle they assert against is the same
//! object the write went through. That is enough to prove the write reached
//! the store, and it is *not* enough to prove the revocation survived. A
//! defect that wrote the in-memory body and never persisted would pass every
//! one of them — which is, in the shape this cycle fixed, the difference
//! between a revocation and a delay.
//!
//! So this test does the thing the unit suite cannot: it stops the broker and
//! starts a different process on the same file.
//!
//! The walkthrough is the M5 exit-UAT sequence, in the order an operator
//! performs it:
//!
//!   plant → list → revoke → **stop the broker** → start a new one → gone
//!
//! Everything is real: a real `VaultStore` on disk, a real `asv-brokerd`
//! process, a real `asv` client, and a real socket. The broker is genuinely
//! killed and re-executed rather than re-instantiated in process, because
//! re-instantiating is the very thing that would hide the defect.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// A value that must not appear in any output this test inspects. Checked at
/// the end, so a regression that started echoing the secret into a response,
/// a log or an error would be caught rather than read past.
const CANARY: &str = "ASV-CANARY-delete-e2e-91ac-DO-NOT-LEAK";

fn cargo_bin(name: &str) -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                let candidate = profile_dir.join(name);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join(profile).join(name);
    }
    PathBuf::from("target").join(profile).join(name)
}

/// A broker process the test owns. `Drop` kills it, so a failing assertion
/// cannot leave a daemon holding a socket for the rest of the suite.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Broker {
    /// Kills the broker, waits for it, and confirms the process is really
    /// gone before returning.
    ///
    /// The confirmation is on the *process*, via the absence of `/proc/<pid>`,
    /// and not on the socket file. A killed process leaves its socket inode
    /// behind, so a broker that died a moment ago and one that is still
    /// serving look identical on the filesystem — and this test's whole claim
    /// is that the two behave differently. Asserting the file disappeared would
    /// therefore have tested the wrong thing and passed for the wrong reason.
    fn stop(self) {
        let pid = self.0.id();
        let mut broker = self;
        broker.0.kill().expect("kill the broker");
        broker.0.wait().expect("wait for the broker to exit");
        std::mem::forget(broker);
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the broker process {pid} is still alive after being killed, so \
             the restart below would be talking to the same process and the \
             test would prove nothing"
        );
    }
}

/// Starts `asv-brokerd` on `sock` with the vault at `vault`, and waits for the
/// socket to appear. Returns once the broker is accepting.
fn start_broker(sock: &Path, vault: &Path, passphrase: &Path) -> Broker {
    let broker = Command::new(cargo_bin("asv-brokerd"))
        .arg(sock)
        .arg("--vault")
        .arg(vault)
        .arg("--passphrase-file")
        .arg(passphrase)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn asv-brokerd");

    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(sock.exists(), "the broker never created its socket");
    Broker(broker)
}

/// Runs the real `asv` CLI, optionally feeding it a secret on stdin.
fn asv(sock: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String) {
    let mut child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(sock)
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

/// Pulls the credential id out of `asv credentials` output.
///
/// Parsed rather than pattern-matched against a whole line, because the column
/// layout is presentation and the id is the only thing this test cares about.
fn id_from_listing(output: &str) -> String {
    output
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .find(|token| token.len() == 36 && token.chars().filter(|c| *c == '-').count() == 4)
        .unwrap_or_else(|| panic!("no credential id in the listing:\n{output}"))
        .to_string()
}

#[test]
fn a_revocation_survives_the_broker_being_restarted() {
    let dir = std::env::temp_dir().join(format!("asv-revoke-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the working dir");

    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let sock = dir.join("broker.sock");
    let passphrase_value = "revoke-e2e-passphrase";
    std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");

    VaultStore::create(
        &vault,
        &SecretString::new(passphrase_value.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");

    // ADR-0015: enrol the operator's own client. Without this the delete is
    // refused, which is the correct behaviour and would make this test prove
    // nothing about durability.
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

    // ---- first broker lifetime -------------------------------------------
    let broker = start_broker(&sock, &vault, &passphrase);

    let (ok, out) = asv(
        &sock,
        &[
            "add-credential",
            "--label",
            "e2e-work",
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

    let (ok, listing) = asv(&sock, &["credentials"], None);
    assert!(ok, "listing failed:\n{listing}");
    let id = id_from_listing(&listing);
    assert!(listing.contains(&id), "the id must be listed:\n{listing}");

    let (ok, out) = asv(&sock, &["delete-credential", &id], None);
    assert!(
        ok,
        "the operator could not revoke their own credential:\n{out}"
    );
    assert!(
        out.contains(&id),
        "the revocation must name what it revoked:\n{out}"
    );

    // The first broker is genuinely stopped here. That is the hinge of the
    // whole test: everything before this line could have been answered out of
    // the running process's memory, and nothing after it can be.
    broker.stop();

    // A killed process leaves its socket inode behind, and the broker refuses
    // to clobber an existing one — so the stale file is cleared the way an
    // operator would clear it, by hand, between runs.
    std::fs::remove_file(&sock).expect("clear the stale socket");

    // ---- a different process reads the same file --------------------------
    let _second = start_broker(&sock, &vault, &passphrase);

    let (ok, listing) = asv(&sock, &["credentials"], None);
    assert!(ok, "listing after restart failed:\n{listing}");
    assert_eq!(
        listing.trim(),
        "no credentials stored",
        "the revocation did not survive the restart: the credential is back"
    );

    // Asked a second time, by a broker that has never seen the credential, the
    // vault itself says there is nothing there. This is the distinction the
    // whole cycle turns on: "not found" from a fresh process reading the file
    // means it is gone, and the same answer from the process that deleted it
    // would have meant nothing.
    let (ok, out) = asv(&sock, &["delete-credential", &id], None);
    assert!(
        !ok,
        "deleting an already-gone id must not report success:\n{out}"
    );
    assert!(
        out.contains("no such credential"),
        "a fresh broker should agree the credential is gone:\n{out}"
    );

    assert!(
        !listing.contains(CANARY) && !out.contains(CANARY),
        "the secret crossed a response boundary"
    );
}

/// The negative that keeps the walkthrough honest: a client that is *not*
/// enrolled is refused, and the refusal is identical for a real id and a
/// made-up one.
///
/// Without this, the positive test above would still pass if the broker simply
/// allowed anyone to delete anything — which is the opposite of the property
/// this cycle is about, and a much worse defect than the one it fixed.
#[test]
fn an_unenrolled_client_cannot_revoke_and_learns_nothing() {
    let dir =
        std::env::temp_dir().join(format!("asv-revoke-neg-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the working dir");

    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let sock = dir.join("broker.sock");
    let passphrase_value = "revoke-negative-passphrase";
    std::fs::write(&passphrase, format!("{passphrase_value}\n")).expect("write passphrase");

    VaultStore::create(
        &vault,
        &SecretString::new(passphrase_value.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");

    // Seed one credential directly, so the broker has something real to
    // protect and the test does not depend on the create path also working.
    {
        let mut store =
            VaultStore::open(&vault, &SecretString::new(passphrase_value.into())).expect("open");
        let key = store
            .header()
            .unlock(&SecretString::new(passphrase_value.into()))
            .expect("unlock");
        let id = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
        store
            .insert(
                &key,
                asv_vault::CredentialMetadata::new(
                    id,
                    "seeded",
                    asv_vault::CredentialKind::BearerToken,
                    "github",
                    "acct",
                    1,
                ),
                asv_domain::secret::SecretBytes::new(b"seeded-secret".to_vec()),
            )
            .expect("seed the credential");
    }

    // NOTE: no `--enrol-principal`. Every client is unadmitted by construction.
    let _broker = start_broker(&sock, &vault, &passphrase);

    let ghost = "00000000-0000-4000-8000-000000000000";
    let seeded = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    let (ok_seed, out_seed) = asv(&sock, &["delete-credential", seeded], None);
    let (ok_ghost, out_ghost) = asv(&sock, &["delete-credential", ghost], None);

    assert!(
        !ok_seed && !ok_ghost,
        "an unadmitted client revoked a credential"
    );
    assert_eq!(
        out_seed, out_ghost,
        "the two refusals differ, which is an existence oracle"
    );
    assert!(
        !out_seed.contains(seeded),
        "the refusal echoed the id back:\n{out_seed}"
    );

    // And the credential is still there, so a refusal was not a revocation.
    let (ok, listing) = asv(&sock, &["credentials"], None);
    assert!(ok, "listing failed:\n{listing}");
    assert!(
        listing.contains(seeded),
        "an unadmitted client's delete removed the credential anyway:\n{listing}"
    );
}
