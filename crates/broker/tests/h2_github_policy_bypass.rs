//! H2 — the GitHub operation trio did not consult the policy engine.
//!
//! **Status: fixed.** This file was a failing `#[ignore]`d test; it is now a
//! passing test that asserts the refusal. What follows is kept as the record
//! of what was wrong, because a defect with no recorded cause tends to come
//! back.
//!
//! # What was observed
//!
//! The M5 end-to-end test minted a surrogate for a `PostgresConnect` request
//! and presented it to `ReadIssue`. The broker accepted it and dialled
//! `api.github.com`:
//!
//! ```text
//! request to api.github.com failed: the provider did not answer with JSON
//! ```
//!
//! # What the design says
//!
//! ADR-0011 describes a surrogate as `session-scoped`, **`audience-bound`**,
//! time-limited and provider-invalid. `audience-bound` is the binding
//! dimension, so the honest question is not "is it action-bound" but "is the
//! audience checked at all". It was not.
//!
//! # The answer, from the code
//!
//! `ReadIssue` did three things and no more (`crates/broker/src/lib.rs:897`):
//!
//!   1. `authorize_github(session, peer)`
//!   2. `validate_repo(&repo)`
//!   3. `state.surrogates.redeem(&surrogate, session, now)`
//!
//! and `authorize_github` checked exactly two things: that the peer owns the
//! session, and that a vault is open. There was no `Authorize` call, no Cedar
//! evaluation, and no grant lookup anywhere on that path.
//!
//! The contrast was the finding. `PostgresQuery` called
//! `authorize_postgres_statement(session, peer, &sql)` before the statement
//! reached the server, so a Postgres operation was evaluated per statement.
//! `ReadIssue` was not evaluated at all.
//!
//! # The fix, in two halves
//!
//! **The class binding.** `SurrogateRecord` now records the
//! [`CredentialClass`] of the credential it stands for, and redemption asks
//! which [`OperationFamily`] it is being spent on. A database-class token
//! cannot back a GitHub call. This is the type-level half, and it is the half
//! this test exercises.
//!
//! **The issuance gate.** `MintSurrogate` now performs exactly one
//! `policy.authorize(...)` call, at mint, for the family the credential
//! belongs to. Before this, the policy was not consulted anywhere on the
//! GitHub path, so an operator who tightened `POLICY_TEXT` observed no change
//! at all. Minting is the right place: a surrogate *is* a capability, and
//! authorization belongs where the capability is created. It is also the only
//! affordable place — `uat_030_perf` times 100 `ReadIssue` calls, so a
//! per-operation evaluation would land inside the measured loop.
//!
//! The issuance gate has its own test (`m5_console_e2e` does not cover it;
//! see `h2_issuance_policy_gate.rs`), because the default policy *permits* the
//! GitHub trio, and a test that only ever sees a permit proves nothing about
//! the deny branch.
//!
//! [asv_domain::CredentialClass]: https://docs.rs/asv-domain
//! [`CredentialClass`]: asv_domain::CredentialClass
//! [`OperationFamily`]: asv_domain::OperationFamily

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use asv_domain::{Action, CredentialKind, Decision, Resource};
use asv_ipc_protocol::{ErrorCode, OpaqueSecret, Request, Response};
use asv_policy::{AuthorizationRequest, PolicyContext};
use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

struct BrokerGuard(Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Locates a workspace binary through the one locator, which also refuses one
/// older than the sources of the package that produces it.
fn cargo_bin(name: &str) -> PathBuf {
    asv_broker::binary::locate(name)
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

/// The GitHub trio refuses a surrogate minted from the wrong class of
/// credential, before any network is touched.
///
/// This used to be `#[ignore]`d and failing. The broker accepted the token and
/// dialled `api.github.com`:
///
/// ```text
/// request to api.github.com failed: the provider did not answer with JSON
/// ```
///
/// # The assertion is deliberately exact
///
/// The first version of this test asserted only `code != Upstream`. That
/// passes for *any* error, and — because the check sat inside an `if let
/// Response::Error` — it also passed when the answer was not an error at all,
/// which is to say it would have passed on a successful GitHub read. A test
/// that cannot fail is not evidence, so the assertion here is on the exact
/// code and on the reason.
///
/// The reason matters as much as the code: `WrongClass` proves the refusal came
/// from the binding and not from an incidental failure like an unreachable
/// host, an exhausted budget or a malformed argument. Asserting the code
/// alone would let any of those pass.
#[test]
fn a_surrogate_minted_from_a_database_credential_cannot_reach_github() {
    let dir = std::env::temp_dir().join(format!("asv-h2-{}-{}", std::process::id(), line!()));
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
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
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
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            workspace: "/tmp/project".into(),
        },
    ) {
        Response::SessionCreated { session, .. } => session,
        other => panic!("expected a session, got {other:?}"),
    };

    // --- the control: a forged surrogate IS refused ------------------------
    // Worth pinning, because it is what makes the next observation meaningful.
    // If a bad token were waved through, "the good token also got through"
    // would say nothing.
    match roundtrip(
        &sock,
        &Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
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

    // --- the setup: a REAL surrogate, minted from that database credential --
    // Minting succeeds, and it is allowed to: the default policy permits the
    // database read verb, so the issuance gate passes this one. What the mint
    // records is the *class*, and the class is what the operation checks.
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
    match roundtrip(
        &sock,
        &Request::Authorize {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            request,
            capability: None,
            approval: None,
        },
    ) {
        Response::Authorization { explanation } => assert!(
            !matches!(explanation.decision, Decision::Deny { .. }),
            "the database request was denied, so there is no grant to widen: {:?}",
            explanation.decision
        ),
        other => panic!("expected an authorization, got {other:?}"),
    }

    let surrogate = match roundtrip(
        &sock,
        &Request::MintSurrogate {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            credential: credential_id,
            max_uses: 2,
            ttl_secs: 300,
        },
    ) {
        Response::SurrogateMinted { surrogate, .. } => surrogate,
        other => panic!("expected a surrogate, got {other:?}"),
    };

    // --- the finding, now asserted -----------------------------------------
    let answer = roundtrip(
        &sock,
        &Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: surrogate.clone(),
            repo: "routable-bypass-target/nonexistent".into(),
            number: 1,
        },
    );

    match answer {
        Response::Error { code, message } => {
            assert_eq!(
                code,
                ErrorCode::Denied,
                "the refusal must be an authorization decision, not an upstream \
                 or validation failure: {message}"
            );
            assert!(
                message.contains("wrong class"),
                "the refusal must name the class binding, otherwise some other \
                 refusal satisfied this test: {message}"
            );
            assert!(
                !message.contains(CANARY),
                "the refusal leaked the secret: {message}"
            );
        }
        other => panic!(
            "H2 is NOT fixed: a database-class surrogate reached the GitHub \
             operations and the broker answered {other:?}"
        ),
    }

    // The budget must be intact. A refusal for the wrong class is a refusal to
    // spend, not a spend — so presenting the same token again must produce the
    // *same* refusal, not `Exhausted`. An implementation that charged a use per
    // refused attempt would pass the assertion above and quietly burn the
    // token, so the second presentation is the control.
    let second = roundtrip(
        &sock,
        &Request::ReadIssue {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            session,
            surrogate: surrogate.clone(),
            repo: "routable-bypass-target/nonexistent".into(),
            number: 1,
        },
    );
    match second {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::Denied, "second presentation: {message}");
            assert!(
                message.contains("wrong class"),
                "the second refusal must be the same class refusal, not an \
                 exhausted budget: {message}"
            );
        }
        other => panic!("the second presentation reached GitHub: {other:?}"),
    }
}
