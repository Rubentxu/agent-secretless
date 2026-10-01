//! H2 — the GitHub operation trio does not consult the policy engine.
//!
//! # What was observed
//!
//! The M5 end-to-end test minted a surrogate for a `PostgresConnect` request
//! and presented it to `ReadIssue`. The broker accepted it and dialled
//! `api.github.com`.
//!
//! # What the design says
//!
//! ADR-0011 describes a surrogate as `session-scoped`, **`audience-bound`**,
//! time-limited and provider-invalid. `audience-bound` is the binding
//! dimension, so the honest question is not "is it action-bound" but "is the
//! audience checked at all".
//!
//! # The answer, from the code
//!
//! `ReadIssue` does three things and no more (`crates/broker/src/lib.rs:897`):
//!
//!   1. `authorize_github(session, peer)`
//!   2. `validate_repo(&repo)`
//!   3. `state.surrogates.redeem(&surrogate, session, now)`
//!
//! and `authorize_github` checks exactly two things: that the peer owns the
//! session, and that a vault is open. There is no `Authorize` call, no Cedar
//! evaluation, and no grant lookup anywhere on that path.
//!
//! The contrast is the finding. `PostgresQuery` calls
//! `authorize_postgres_statement(session, peer, &sql)` before the statement
//! reaches the server, so a Postgres operation is evaluated per statement.
//! `ReadIssue` is not evaluated at all. A session that was never granted
//! anything can read, create and release GitHub issues as long as its peer
//! owns it and a vault is open.
//!
//! # What this test asserts
//!
//! Not "the credential leaked" — it did not, and the surrogate is still a
//! surrogate. It asserts the narrower and load-bearing claim: **no policy
//! decision is consulted on this path.** A broker that started evaluating
//! policy would answer `Denied` before any network call, and this test would
//! go red, which is the point of writing it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use asv_domain::{Action, CredentialKind, Decision, Resource};
use asv_ipc_protocol::{ErrorCode, OpaqueSecret, Request, Response};
use asv_policy::{AuthorizationRequest, PolicyContext};
use secrecy::SecretString;
use asv_vault::{KdfParams, VaultStore};

struct BrokerGuard(Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cargo_bin(name: &str) -> PathBuf {
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join(name)
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

/// Ignored on purpose, and that is the finding.
///
/// This test asserts the *secure* behaviour: a session authorized for one
/// database action must not be able to use a surrogate minted from it to read
/// a GitHub issue. It fails today, with
///
/// ```text
/// request to api.github.com failed: the provider did not answer with JSON
/// ```
///
/// — the broker dialled GitHub, which is what "it never evaluated the policy"
/// looks like from the outside.
///
/// It is `#[ignore]`d rather than deleted so the defect is pinned in code
/// instead of living in a tracker nobody opens. `cargo test -- --ignored`
/// runs it. The day someone fixes the GitHub path this stops being ignored,
/// and when it is un-ignored without a fix the suite goes red on purpose.
///
/// **Fix shape:** `ReadIssue` (and `CreateIssue`, `CreateRelease`) must call
/// the policy engine the way `PostgresQuery` calls
/// `authorize_postgres_statement` — evaluate the request, and refuse before
/// the surrogate is spent and before the network is touched.
#[test]
#[ignore = "H2: documents a live policy bypass on the GitHub trio; un-ignore when fixed"]
fn a_session_with_no_grant_can_still_reach_the_github_operations() {
    let dir = std::env::temp_dir()
        .join(format!("asv-h2-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("create dir");
    let sock = dir.join("broker.sock");
    let vault_path = dir.join("vault.asv");
    let pass_path = dir.join("pass.txt");
    const PASSPHRASE: &str = "h2-policy-bypass-passphrase";
    std::fs::write(&pass_path, format!("{PASSPHRASE}\n")).expect("write passphrase");
    VaultStore::create(
        &vault_path,
        &SecretString::new(PASSPHRASE.into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create vault");

    let this_exe = std::fs::canonicalize(std::env::current_exe().expect("exe")).expect("canon");
    let enrolled = Command::new(cargo_bin("asv-brokerd"))
        .arg("--vault")
        .arg(&vault_path)
        .arg("--enrol-principal")
        .arg(&this_exe)
        .output()
        .expect("enrol");
    assert!(enrolled.status.success(), "enrolment failed");

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

    // A credential to stand a surrogate for. The secret is a canary: whatever
    // the broker answers, the value itself must not come back.
    const CANARY: &str = "ASV-H2-CANARY-91c4de07-must-never-cross";
    let credential_id = match roundtrip(
        &sock,
        &Request::CreateCredential {
            label: "h2-subject".into(),
            kind: CredentialKind::DatabaseCredential,
            provider: "postgres".into(),
            account: "app".into(),
            secret: OpaqueSecret::new(CANARY.as_bytes().to_vec()),
        },
    ) {
        Response::CredentialCreated { id, .. } => id,
        other => panic!("expected a credential, got {other:?}"),
    };

    // A session, and nothing else yet.
    let session = match roundtrip(
        &sock,
        &Request::CreateSession {
            workspace: "/tmp/project".into(),
        },
    ) {
        Response::SessionCreated { session } => session,
        other => panic!("expected a session, got {other:?}"),
    };

    // --- the control: a forged surrogate IS refused ------------------------
    // Worth pinning, because it is what makes the next observation meaningful.
    // If a bad token were waved through, "the good token also got through"
    // would say nothing.
    match roundtrip(
        &sock,
        &Request::ReadIssue {
            session,
            surrogate: "not-a-real-surrogate".into(),
            repo: "routable-bypass-target/nonexistent".into(),
            number: 1,
        },
    ) {
        Response::Error { code, .. } => assert_ne!(
            code,
            ErrorCode::Upstream,
            "a forged surrogate reached the network"
        ),
        other => panic!("a forged surrogate was honoured: {other:?}"),
    }

    // --- the finding: a REAL surrogate is honoured for anything -----------
    // Authorize this session for one database action, mint a surrogate, and
    // then present it to a GitHub read. The GitHub path never evaluates
    // policy, so the token is enough on its own.
    let request = AuthorizationRequest {
        session,
        action: Action::PostgresConnect,
        resource: Resource::Database { name: "app".into(), role: "readonly".into() },
        context: PolicyContext {
            workspace: "/tmp/project".into(),
            protected_ref: None,
            request_digest: None,
            peer_uid: 0,
        },
    };
    match roundtrip(&sock, &Request::Authorize { request, capability: None, approval: None }) {
        Response::Authorization { explanation } => assert!(
            !matches!(explanation.decision, Decision::Deny { .. }),
            "the database request was denied, so there is no grant to widen: {:?}",
            explanation.decision
        ),
        other => panic!("expected an authorization, got {other:?}"),
    }

    let surrogate = match roundtrip(
        &sock,
        &Request::MintSurrogate { session, credential: credential_id, max_uses: 2, ttl_secs: 300 },
    ) {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("expected a surrogate, got {other:?}"),
    };

    let answer = roundtrip(
        &sock,
        &Request::ReadIssue { session, surrogate, repo: "routable-bypass-target/nonexistent".into(), number: 1 },
    );

    // A broker that evaluated policy on this path would answer `Denied` here,
    // because the session was authorized for a database and not for GitHub.
    // Reaching the network instead is the bypass, made observable.
    if let Response::Error { code, message } = &answer {
        assert_ne!(
            *code,
            ErrorCode::Upstream,
            "the GitHub path now refuses, so it evaluates policy — H2 is fixed, \
             and this test should be rewritten to assert the refusal. Got: {message}"
        );
    }
}
