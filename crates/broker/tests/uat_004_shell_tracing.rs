//! UAT-004 — shell tracing
//!
//! A malicious script turns on `set -x`, dumps its positional parameters
//! and its environment, and then invokes the protected CLI. The
//! expectation is that no real credential appears.
//!
//! # The property, stated so it can fail
//!
//! Read naively, "no real credential appears" is not a property of this
//! product: the script is the attacker's own text and it can do whatever
//! it likes with its own literal. The property that *is* the product's is
//! this one, stated here in our own words rather than borrowed:
//!
//! the material of a real credential never enters the environment, the
//! argv, or the stdin of a session's child process. A `set -x` that
//! dumps all three cannot find it, because it is not there.
//!
//! That rests on two mechanisms, both already in the code and both
//! measured here rather than assumed:
//!
//! - the child is spawned with the quarantine applied
//!   (`crates/cli/src/main.rs:602-608`, `QUARANTINED_ENV_NAMES` at
//!   `:573-579`);
//! - the only credential channel the child is handed is `SSH_AUTH_SOCK`,
//!   whose protocol is bounded to request-identities and sign
//!   (`crates/ssh-agent/src/lib.rs:26-33`, dispatch at `:179-183`).
//!
//! # Why the attack has to be shown to have run
//!
//! An assertion of absence proves nothing on its own: it passes just as
//! happily when there was nothing to find. So this test also fails when
//! it *cannot* demonstrate that the attack happened — the `xtrace`
//! actually emitted, `ssh-add -L` actually got an identity off the live
//! socket, the protected CLI actually answered a real broker, and the
//! identity came back as a 47-byte public blob and not a seed.
//!
//! N2 is the load-bearing one. "No secret leaked" would be trivially
//! true if the attacker could not so much as touch the credential
//! channel. The test requires that the attacker *did* touch it, and
//! still found nothing private.
//!
//! # What this is not
//!
//! This is not the `psql` vector. UAT-039
//! (`crates/broker/tests/uat_039_pg.rs:132-169`) inspects the *structure*
//! of the built `Command` with `get_envs`/`get_args` and never runs
//! anything. This file executes a real process tree and greps its output.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use asv_domain::CredentialKind;
use asv_ipc_protocol::{OpaqueSecret, Request, Response};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The real credential's secret, held by a real broker in a real vault.
const VAULT_CANARY: &str = "ASV-UAT004-VAULT-3b81c5d9e2a7-must-never-cross";

/// An inherited secret planted in a *quarantined* variable. The child is
/// supposed to remove this before it ever exists as a process, so a
/// traced `env` must not show it even once.
const ENV_CANARY: &str = "ghp_UAT004INHERITED_7f3a9c2e1d8b4f6a-must-not-survive";

/// The marker `PS4` writes on every traced command. Its presence is the
/// proof that tracing ran; its absence fails the test.
const TRACE_MARKER: &str = "UAT004-TRACE";

/// The credential label, asserted to appear in the CLI output. It proves
/// the broker really described the real credential to the traced child —
/// and that describing it did not require showing it.
const CREDENTIAL_LABEL: &str = "uat004-subject";

/// `4 + len("ssh-ed25519") + 4 + 32` — a public key blob. A leaked seed
/// would be 79 and a leaked private key 111, so this single number is
/// what separates "the attacker got a public key" from "the attacker got
/// the key".
const PUBLIC_BLOB_LEN: usize = 4 + 11 + 4 + 32;

struct BrokerGuard(Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cargo_bin(name: &str) -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        // .../<target>/<profile>/deps/<test-bin>
        if let Some(deps) = exe.parent() {
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.join(name));
            }
        }
    }
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut root = PathBuf::from(&dir);
        while !root.join("crates").is_dir() && root.parent().is_some() {
            root = root.parent().unwrap().to_path_buf();
        }
        candidates.push(root.join("target").join(profile).join(name));
    }
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(target).join(profile).join(name));
    }
    candidates.push(PathBuf::from("target").join(profile).join(name));

    for c in &candidates {
        if c.is_file() {
            return c.clone();
        }
    }
    panic!(
        "cannot find binary `{name}`; looked in: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn roundtrip(sock: &std::path::Path, request: &Request) -> Response {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    let payload = serde_json::to_vec(request).expect("serialize");
    stream.write_all(&payload).expect("write request");
    stream.flush().expect("flush");
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read response");
    assert!(n > 0, "broker closed without responding");
    serde_json::from_slice(&buf[..n]).expect("parse response")
}

/// The attacker's protocol probe. It is deliberately written as a
/// hostile client: it asks for identities, then sweeps every opcode it
/// can think of looking for one that hands back raw key material.
const PROBE: &str = r#"
import os, socket, struct, sys

sock_path = os.environ["SSH_AUTH_SOCK"]

def call(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(struct.pack(">I", len(payload)) + payload)
    head = b""
    while len(head) < 4:
        chunk = s.recv(4 - len(head))
        if not chunk:
            raise RuntimeError("agent closed the connection")
        head += chunk
    want = struct.unpack(">I", head)[0]
    buf = b""
    while len(buf) < want:
        chunk = s.recv(want - len(buf))
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf

ident = call(bytes([11]))
print("UAT004_IDENT_OPCODE=%d" % ident[0])
print("UAT004_IDENT_COUNT=%d" % struct.unpack(">I", ident[1:5])[0])
print("UAT004_IDENT_BLOB=%d" % struct.unpack(">I", ident[5:9])[0])

# Sweep. A real OpenSSH agent answers several of these; this one answers
# only "list the identities". Anything that answers at all is reported
# so the test can insist on the exact set rather than on its size.
answered = []
for op in range(256):
    for shape in (bytes([op]), bytes([op]) + b"\x00" * 8):
        if call(shape) != b"\x05":
            if op not in answered:
                answered.append(op)
            break
print("UAT004_SWEEP_ANSWERED=%d" % len(answered))
print("UAT004_SWEEP_OK_OPCODES=%s" % ",".join(str(o) for o in answered))
"#;

#[test]
fn a_tracing_script_cannot_dump_a_real_credential() {
    let dir = std::env::temp_dir().join(format!("asv-u004-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");

    let sock = dir.join("b.sock");
    let vault_path = dir.join("vault.asv");
    let pass_path = dir.join("pass.txt");
    let script_path = dir.join("evil.sh");
    let probe_path = dir.join("probe.py");
    const PASSPHRASE: &str = "uat004-shell-tracing-passphrase";

    std::fs::write(&pass_path, format!("{PASSPHRASE}\n")).expect("write passphrase");
    std::fs::write(&probe_path, PROBE).expect("write probe");
    VaultStore::create(
        &vault_path,
        &SecretString::new(PASSPHRASE.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");

    // The control plane verb needs an enrolled principal, and the peer
    // that plants the credential is this test process.
    let this_exe = std::fs::canonicalize(std::env::current_exe().expect("exe")).expect("canon");
    let enrolled = Command::new(cargo_bin("asv-brokerd"))
        .arg("--vault")
        .arg(&vault_path)
        .arg("--enrol-principal")
        .arg(&this_exe)
        .output()
        .expect("enrol");
    assert!(
        enrolled.status.success(),
        "enrolment failed: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );

    let _broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault_path)
            .arg("--passphrase-file")
            .arg(&pass_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn broker"),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(sock.exists(), "broker did not create its socket");

    // A real credential with a real secret, so that "no real credential
    // appears" is a statement about something that exists.
    let credential_id = match roundtrip(
        &sock,
        &Request::CreateCredential {
            label: CREDENTIAL_LABEL.into(),
            kind: CredentialKind::BearerToken,
            provider: "github".into(),
            account: "app".into(),
            secret: OpaqueSecret::new(VAULT_CANARY.as_bytes().to_vec()),
        },
    ) {
        Response::CredentialCreated { id, .. } => id,
        other => panic!("expected a credential, got {other:?}"),
    };
    let _ = credential_id;

    // The script, verbatim, is the UAT-004 scenario. `set -v` on top of
    // `set -x` makes bash echo every line it reads, so the attacker sees
    // its own source too — which is why the canaries are planted in the
    // vault and the environment and never in this text.
    let script = format!(
        r#"#!/usr/bin/env bash
PS4='+{marker}+[script:${{BASH_SOURCE##*/}} line:${{LINENO}}] '
set -x
set -v
env
tr '\0' '\n' < /proc/self/environ
printf 'UAT004_ARGV=%s\n' "$*"
{asv} --socket "$1" credentials --json
ssh-add -L
ssh-add -l
python3 {probe}
"#,
        marker = TRACE_MARKER,
        asv = cargo_bin("asv").display(),
        probe = probe_path.display(),
    );
    std::fs::write(&script_path, &script).expect("write script");

    // The planted secret rides on a quarantined name, so the child must
    // not have it. Nothing in the script text mentions its value.
    let out = Command::new(cargo_bin("asv"))
        .arg("run")
        .arg("bash")
        .arg(&script_path)
        .arg(&sock)
        .env("GITHUB_TOKEN", ENV_CANARY)
        .output()
        .expect("run asv run");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}\n{stderr}");

    // N1 — the trace ran. Without this the rest of the assertions could
    // be satisfied by a script that never executed a single command.
    assert!(
        combined.contains(TRACE_MARKER),
        "xtrace produced no output; the attack never ran.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // N2 — the attacker reached the credential channel and got an
    // identity off it. This is what makes the absence below meaningful.
    assert!(
        combined.contains("ssh-ed25519"),
        "the agent socket yielded no identity; the attack never touched the credential channel.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // N3 — the protected CLI really answered a real broker about a real
    // credential. The label is the proof: the broker described the
    // credential to the traced child without handing over its material.
    assert!(
        combined.contains(CREDENTIAL_LABEL),
        "the protected CLI did not report the real credential; the scenario did not run.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // N4 — the identity that came back is a public key and nothing more.
    assert!(
        combined.contains(&format!("UAT004_IDENT_BLOB={PUBLIC_BLOB_LEN}")),
        "expected a {PUBLIC_BLOB_LEN}-byte public blob; anything else means key material moved.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        combined.contains("UAT004_IDENT_OPCODE=12"),
        "identities request was not answered.\n{combined}"
    );

    // R-004.4 — of 256 opcodes, only request-identities is answered at
    // all. Every opcode a real agent uses to hand over or add a private
    // key returns the single failure byte.
    assert!(
        combined.contains("UAT004_SWEEP_OK_OPCODES=11"),
        "the agent socket answered an opcode other than request-identities.\n{combined}"
    );
    assert!(
        combined.contains("UAT004_SWEEP_ANSWERED=1"),
        "the agent socket answered more than one opcode.\n{combined}"
    );

    // C1 — the real credential's secret is nowhere in the dump.
    assert!(
        !combined.contains(VAULT_CANARY),
        "the real credential leaked into the traced child.\n{combined}"
    );

    // C2 — the quarantine survived a full `env` + `/proc/self/environ`
    // dump under `set -x -v`.
    assert!(
        !combined.contains(ENV_CANARY),
        "a quarantined variable was inherited by the traced child.\n{combined}"
    );

    // C3 — the session was real. If these are absent, the child was just
    // a bare shell and every assertion above is about nothing.
    for marker in ["ASV_SESSION_ID=", "ASV_SESSION_MODE=", "SSH_AUTH_SOCK="] {
        assert!(
            combined.contains(marker),
            "the child was not a real ASV session; `{marker}` never appeared.\n{combined}"
        );
    }

    // The positional parameters really were dumped — the other half of
    // the scenario, and the part a `set -x` alone would not produce.
    assert!(
        combined.contains("UAT004_ARGV="),
        "the script never dumped its positional parameters.\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
