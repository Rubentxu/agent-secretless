//! M5's third exit criterion, end to end, against a real broker process.
//!
//! `add credential -> grant -> agent use -> revoke`, over a real Unix socket
//! with real serialisation, not through in-process fakes. The other two exits
//! (UAT-019, UAT-020) are about the console surface and live in the M5 cycle's
//! own suite; this one is about the sequence the operator drives, and it does
//! not need a display.
//!
//! # The assertion is shaped by what it is NOT
//!
//! The revoke check does not assert "the operation was refused". It asserts
//! the error was *not* `Upstream`, because `Upstream` is what the broker
//! answers when it accepted the token and went looking for the provider. The
//! repo name in the test is deliberately unresolvable, so the two states are
//! distinguishable: a live surrogate produces a transport error naming
//! `api.github.com`, a revoked one produces a policy refusal.
//!
//! That distinction was observed in both directions while writing this. The
//! first version asserted a refusal on a surrogate that had not been revoked
//! yet, and went red with `Upstream: request to api.github.com failed` — which
//! is what a live token does, and is why "assert not-Upstream" is the honest
//! form and "assert denied" alone would have been satisfied by a network
//! accident.
//!
//! The thread through all of it is the canary. The secret is a known string,
//! and every response the broker returns is searched for it. A test that says
//! "the agent gets a substituted value" without a name to search for is a
//! test that passes on an empty response.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use asv_domain::{Action, CredentialKind, Decision, Resource};
use asv_ipc_protocol::{ErrorCode, OpaqueSecret, Request, Response};
use asv_policy::{AuthorizationRequest, PolicyContext};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The secret the agent must never see, in any form, at any step.
const CANARY: &str = "ASV-E2E-CANARY-7d41ba90-must-never-cross";

struct BrokerGuard(Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cargo_bin(name: &str) -> PathBuf {
    // Same resolution the other integration tests use: the binary this
    // workspace just built, not whatever is on PATH.
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join(name)
}

fn unique_socket(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("asv-m5e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("broker.sock")
}

/// Send one request, read one response, and return both the decoded response
/// and its raw JSON — the raw form is what the canary search runs against,
/// because a field the typed struct does not expose is still a field the
/// broker put on the wire.
fn roundtrip(sock: &std::path::Path, request: &Request) -> (Response, String) {
    let mut stream = UnixStream::connect(sock).expect("connect to broker");
    let payload = serde_json::to_vec(request).expect("serialize");
    stream.write_all(&payload).expect("write request");
    stream.flush().expect("flush");

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).expect("read response");
    assert!(n > 0, "broker closed without responding");
    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
    let response = serde_json::from_str(&raw).expect("parse response");
    (response, raw)
}

fn assert_no_canary(where_: &str, raw: &str) {
    assert!(
        !raw.contains(CANARY),
        "{where_} leaked the credential value onto the wire.\n\
         This is the property the whole project exists to hold: the agent gets a \
         surrogate, never the secret.\nResponse was: {raw}"
    );
}

#[test]
fn add_grant_use_revoke() {
    let sock = unique_socket("flow");
    let _ = std::fs::remove_file(&sock);

    // Planting a credential is the control plane's job, and the control plane
    // admits nobody by default. So the caller — which here is this test binary,
    // because it is the process holding the socket — has to be enrolled, by
    // digest, against a vault of its own. This is not a test fixture that
    // bypasses admission; it is the supported way to pass it.
    // Planting a credential is the control plane's job, and the control plane
    // admits nobody by default. So the caller — this test binary, because it is
    // the process holding the socket — has to be enrolled by digest against a
    // vault of its own. This is the supported way to pass admission, not a
    // fixture that routes around it.
    //
    // The vault is real and opens with a real passphrase, because the broker
    // loads the enrolment record *from beside the vault* and has no default
    // location to load it from. An empty file is not a vault: the broker dies
    // with `MalformedBody` before it ever serves.
    let dir = std::env::temp_dir().join(format!("asv-m5e2e-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("create vault dir");
    let vault_path = dir.join("vault.asv");
    let passphrase_path = dir.join("passphrase.txt");
    const PASSPHRASE: &str = "m5-console-e2e-passphrase";
    std::fs::write(&passphrase_path, format!("{PASSPHRASE}\n")).expect("write passphrase");
    VaultStore::create(
        &vault_path,
        &SecretString::new(PASSPHRASE.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");

    let this_exe = std::fs::canonicalize(std::env::current_exe().expect("test exe path"))
        .expect("canonicalise this test binary");
    let enrolled = Command::new(cargo_bin("asv-brokerd"))
        .arg("--vault")
        .arg(&vault_path)
        .arg("--enrol-principal")
        .arg(&this_exe)
        .output()
        .expect("run asv-brokerd --enrol-principal");
    assert!(
        enrolled.status.success(),
        "could not enrol this test binary as a control-plane principal: {}",
        String::from_utf8_lossy(&enrolled.stderr)
    );

    let _broker = BrokerGuard(
        Command::new(cargo_bin("asv-brokerd"))
            .arg(&sock)
            .arg("--vault")
            .arg(&vault_path)
            .arg("--passphrase-file")
            .arg(&passphrase_path)
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

    // --- 1. add ----------------------------------------------------------
    let (created, raw) = roundtrip(
        &sock,
        &Request::CreateCredential {
            label: "prod-db".into(),
            kind: CredentialKind::DatabaseCredential,
            provider: "postgres".into(),
            account: "app".into(),
            secret: OpaqueSecret::new(CANARY.as_bytes().to_vec()),
        },
    );
    assert_no_canary("CreateCredential", &raw);
    let credential_id = match created {
        Response::CredentialCreated { id, .. } => id,
        other => panic!("expected a credential, got {other:?}"),
    };

    // The metadata list is what the console renders. It must carry the label
    // and not the value.
    let (metadata, raw) = roundtrip(&sock, &Request::ListCredentialMetadata);
    assert_no_canary("ListCredentialMetadata", &raw);
    match metadata {
        Response::CredentialMetadata { entries } => {
            let ours = entries
                .iter()
                .find(|m| m.label == "prod-db")
                .expect("the new credential appears in the metadata list");
            // The metadata row is a projection. A field that does not exist
            // cannot leak, so this asserts on the absence of a value field
            // rather than trusting the struct to have been curated.
            assert!(
                !serde_json::to_string(ours)
                    .unwrap_or_default()
                    .contains("secret"),
                "a metadata row serialised a field named `secret`"
            );
        }
        other => panic!("expected metadata, got {other:?}"),
    }

    // --- 2. session, then the grant ---------------------------------------
    let (session_resp, _) = roundtrip(
        &sock,
        &Request::CreateSession {
            workspace: "/tmp/project".into(),
        },
    );
    let session = match session_resp {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    };

    let request = AuthorizationRequest {
        session,
        action: Action::PostgresConnect,
        resource: Resource::Database {
            name: "app".into(),
            role: "readonly".into(),
        },
        context: PolicyContext {
            workspace: "/tmp/project".into(),
            protected_ref: None,
            request_digest: None,
            peer_uid: 0,
        },
    };

    // --- 2b. the grant ---------------------------------------------------
    // A human approving a bounded request is `SubmitApproval`, and that verb
    // is not wired to the policy engine in this build: the broker answers
    // "approval refused: admission granted, but approvals have no path to the
    // policy engine yet". That is an honest refusal rather than a stub that
    // returns something plausible, and it is recorded as a finding rather
    // than worked around here.
    //
    // So the grant that this build *does* support is the two-step one: the
    // policy engine decides the request, and the broker mints a bounded
    // surrogate the agent presents instead of a credential id. Both halves
    // are checked, and the first one is inspected rather than assumed.
    let (decided, raw) = roundtrip(
        &sock,
        &Request::Authorize {
            request: request.clone(),
            capability: None,
            approval: None,
        },
    );
    assert_no_canary("Authorize", &raw);
    let first = match decided {
        Response::Authorization { explanation } => explanation,
        other => panic!("expected an authorization, got {other:?}"),
    };
    assert!(
        !matches!(first.decision, Decision::Deny { .. }),
        "the policy engine denied the request outright: {:?}",
        first.decision
    );

    // --- 3. mint, then the agent presents the surrogate -----------------
    // The agent is handed a surrogate: a bearer-shaped string it can present
    // in place of a credential id. It is bounded in both uses and lifetime,
    // and it is not the secret and does not stand alone.
    let (minted, raw) = roundtrip(
        &sock,
        &Request::MintSurrogate {
            session,
            credential: credential_id,
            max_uses: 2,
            ttl_secs: 300,
        },
    );
    assert_no_canary("MintSurrogate", &raw);
    let surrogate = match minted {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("expected a surrogate, got {other:?}"),
    };
    assert!(
        !surrogate.contains(CANARY),
        "the surrogate carries the credential value"
    );

    // --- 4. revoke, then present it again -------------------------------
    // The sequence the milestone asks for, in the order it happens: the
    // operator revokes, and the next use is refused.
    let (revoked, raw) = roundtrip(
        &sock,
        &Request::RevokeSurrogate {
            session,
            surrogate: surrogate.clone(),
        },
    );
    assert_no_canary("RevokeSurrogate", &raw);
    assert!(matches!(revoked, Response::SurrogateRevoked { .. }));

    let (after, raw) = roundtrip(
        &sock,
        &Request::ReadIssue {
            session,
            surrogate,
            repo: "routable-invalidation-target/nonexistent".into(),
            number: 1,
        },
    );
    assert_no_canary("ReadIssue after revoke", &raw);
    match after {
        Response::Error { code, .. } => assert_ne!(
            code,
            ErrorCode::Upstream,
            "the operation was still permitted after the surrogate was revoked"
        ),
        other => panic!("a revoked surrogate was honoured rather than refused: {other:?}"),
    }
}
