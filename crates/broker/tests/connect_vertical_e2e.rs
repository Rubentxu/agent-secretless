//! C2.7-D — the vertical. This is the test that says CONNECT is in the product.
//!
//! Everything here is a real process. A real `asv-brokerd` binary, started with
//! a real vault, a real route file and a real policy file. A real `asv run`,
//! which opens a real session and starts a real shim. A real `curl`, which has
//! never heard of Agent Secretless and is told nothing except a proxy URL. A
//! real origin process on a real socket.
//!
//! ## Why this file and not fifteen unit tests
//!
//! The previous blocks each proved a piece, and every one of those proofs was
//! honest. What none of them could see is the *hop between processes*. A test
//! that constructs a listener in-process is running inside a runtime, so it
//! never notices that the binary did not enter one — and for the whole history
//! of this path, `asv-brokerd --connect-listen` panicked at startup and the
//! suite reported a surface that could not come up. That defect is in
//! `crates/broker/tests/connect_address_publication.rs` now, and it was found
//! by a test written for a different question.
//!
//! The properties are asserted together rather than one at a time, because the
//! interesting failures are combinations. A proxy that substitutes the real
//! credential but leaks it into the child's environment is secretless in the
//! way that matters least and leaky in the way that matters most, and a
//! per-property test suite would report both halves as passing.
//!
//! ## What each claim is checked against
//!
//! | claim | checked by |
//! |---|---|
//! | the origin received the REAL credential | the origin's own captured bytes |
//! | the agent never received it | the child's captured environment |
//! | curl never received it | the child's stdout and stderr |
//! | argv carries no secret | the child's reconstructed `argv` |
//! | env carries no secret | the child's captured environment, line by line |
//! | stdout/stderr carry no secret | the captured output |
//! | the shim is session-local and not bypassable | the `HTTPS_PROXY` the child was handed, and the absence of the `NO_PROXY` it was started with |
//! | the child was given *something* to present | the `ASV_SURROGATE_*` variable, and that its value is a surrogate and not the secret |
//! | a surrogate is bound to its session | session A's token presented inside a **live** session B, refused, with the origin as the independent witness |
//! | a fresh session still works | the same session B using its own token, `200` |
//! | a closed session's token is dead | the separate revoked-session test, plus the broker's own revocation path |
//! | a wrong destination fails | a CONNECT to a host with no route |
//! | a revoked session fails | a CONNECT after the session ends |
//! | the audit chain verifies | the durable log, through the broker's own verifier, plus a tampered copy that must be refused |
//! | the substitution and the refusal are both recorded | the parsed audit records, not a substring over the file |
//!
//! Three of these rows were written as claims the first version of the file did
//! not check, and the third is the one worth reading twice. The replay row
//! opened a second session and never carried a token across it. The audit row
//! called a flag that does not exist and wrapped the result in a conditional.
//! The session-binding row was then rewritten and *still* measured something
//! else: it took the token from a session that had already ended, and
//! `SessionEnded` deletes a session's surrogates, so the token was refused for
//! being unknown and the session comparison was never reached. It stayed green
//! when the falsification campaign deleted that comparison outright. Only with
//! both sessions open at once is the binding reachable at all.
//!
//! Every row above is checked by deleting its control and requiring the named
//! assertion to go red: `tests/connect_vertical_falsification.py`, 5 of 5.
//!
//! ## The one thing this test cannot claim
//!
//! `curl --insecure`. The session CA is minted per broker run and the test has
//! no channel to pin it, so the client's trust decision is waived here. That is
//! sound for what is being tested — the CONNECT path and the secret's
//! containment — and it is *not* evidence that certificate trust is solved for
//! an operator. That is a different claim and it is not made here.
//!
//! Nor does this file demonstrate that a *proof* is single-use end to end. The
//! shim mints one proof per connection, so an ordinary client is never in a
//! position to replay one; that property is measured where it can be, in the
//! broker's verifier and in the issuer's counter (`crates/ssh-agent/src/
//! client.rs`). Claiming it here would be claiming a hop this test does not
//! cross.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asv_vault::{KdfParams, VaultStore};
use secrecy::SecretString;

/// The real credential. Its presence in the origin's bytes is the whole point;
/// its absence everywhere else is the whole point.
///
/// Deliberately shaped like a token so a substring search cannot be satisfied by
/// a word that happens to appear in a stack trace.
const REAL: &str = "gho_ASVcanaryE2E4d7f1a9b3c5e8f0a2b4d6c8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f";

/// A two-label name that resolves to loopback.
///
/// The route loader refuses a bare `localhost` (one label is not routable) and
/// refuses an IP literal (no name to pin), so a loopback fixture needs a name
/// that is genuinely a name. This one is on every `/etc/hosts` and is two
/// labels, so it passes canonicalization and resolves locally — which is what
/// lets the *real* broker resolve it, rather than a resolver the test injected.
const FIXTURE_HOST: &str = "localhost.localdomain";

/// The credential's label, which is what the environment variable is named
/// after. The broker reports it back from the vault's own metadata, so the
/// variable name is the operator's spelling rather than something invented here.
const CREDENTIAL_LABEL: &str = "e2e-token";

// ---------------------------------------------------------------------------
// Binaries
// ---------------------------------------------------------------------------

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
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(dir).join(profile).join(name));
    }
    candidates.push(PathBuf::from("target").join(profile).join(name));
    candidates
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("could not locate the {name} binary"))
}

struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An `asv run` held open by the test until it is released.
///
/// The type exists for its `Drop`. The cross-session measurement needs the
/// first session to still be *alive* when the second one presents its token,
/// which means there is a window in the test where an assertion can fire with
/// a session open — and an `asv run` left running holds a shim, an agent
/// socket and a session the broker still has to reap. A failing test that also
/// leaks a process is a slower failing test, and the next test pays for it.
struct Session {
    child: Option<Child>,
    release: PathBuf,
}

impl Session {
    /// Let the child finish, and take its output.
    fn finish(mut self) -> std::process::Output {
        let _ = std::fs::write(&self.release, b"go");
        let child = self.child.take().expect("the session was already finished");
        child
            .wait_with_output()
            .expect("collect the session's output")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Release first, so a child that is polling the file gets to exit on
        // its own terms; kill it either way, because a test that failed is not
        // a reason to leave a process behind.
        let _ = std::fs::write(&self.release, b"go");
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Wait for a path to appear, bounded.
///
/// Every wait in this file is bounded. A test that hangs is worse than a test
/// that fails: the first one costs a person their afternoon, the second one
/// costs them a minute.
fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// A plain-TCP origin: the broker terminates TLS, so what arrives here is
/// readable bytes. That is deliberate — a fixture the test cannot read could
/// not assert that the real credential arrived.
struct Origin {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Origin {
    fn start() -> Self {
        // `[::]` is dual-stack on Linux, so one port answers on both `::1` and
        // `127.0.0.1`. The broker takes the first address the resolver returns,
        // and which one that is has changed between hosts; a single-family bind
        // would make this test a bet on the resolver's mood.
        let listener = TcpListener::bind("[::]:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let port = addr.port();
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 2048];
                    // Read until the headers are complete, then answer. The
                    // origin serves one request per connection because that is
                    // what the CONNECT path produces.
                    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => raw.extend_from_slice(&chunk[..n]),
                        }
                    }
                    sink.lock()
                        .expect("origin sink")
                        .push(String::from_utf8_lossy(&raw).into_owned());
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = stream.flush();
                });
            }
        });

        Self { port, requests }
    }

    /// Everything the origin was sent, joined, for substring assertions.
    fn saw(&self) -> String {
        self.requests.lock().expect("origin sink").join("\n")
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("origin sink").len()
    }

    /// Connections that carried a request at all.
    ///
    /// Not the same as `request_count`, and the difference is a property of the
    /// bridge rather than of this fixture: `serve_connect` dials the
    /// destination *before* it can read the client's head, because the head is
    /// what carries the surrogate and the head cannot arrive until the
    /// client-side TLS handshake is done. So a tunnel whose substitution is
    /// refused still leaves a connection open at the origin — one that carries
    /// nothing and is closed again.
    ///
    /// It is written down here rather than papered over, because the tempting
    /// assertion — "the origin served exactly one more request" — is counting
    /// the wrong thing, and would have gone green on a broker that opened a
    /// connection per tunnel and served every one of them.
    fn requests_with_bytes(&self) -> usize {
        self.requests
            .lock()
            .expect("origin sink")
            .iter()
            .filter(|r| !r.is_empty())
            .count()
    }

    /// How many of the captured requests carried the real credential.
    ///
    /// The witness that does not depend on how the bridge orders its dial: the
    /// secret is either in what the destination received or it is not.
    fn real_credential_requests(&self) -> usize {
        self.requests
            .lock()
            .expect("origin sink")
            .iter()
            .filter(|r| r.contains(REAL))
            .count()
    }

    /// Waits for at least `n` requests, bounded.
    ///
    /// The origin runs on its own threads, so reading straight after the client
    /// exits is a race and an early read would fail the test for being early
    /// rather than for being wrong.
    fn wait_for_requests(&self, n: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.request_count() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    origin: Origin,
    credential_id: String,
    credential_label: String,
    /// The durable audit log the broker appends every substitution to.
    ///
    /// The broker is handed the path rather than asked to *be* asked: a chain
    /// that only exists inside the running process is not a chain an operator
    /// can verify, and an assertion that reaches for it over a flag that does
    /// not exist verifies nothing at all.
    audit: PathBuf,
    _broker: Broker,
}

impl Fixture {
    /// Plant the credential, then start the broker that will tunnel to it.
    ///
    /// Two broker runs, and the first one is not ceremony. A route names a
    /// credential by its canonical id, and the *product* mints those ids — the
    /// vault's own seeded canary carries a non-canonical id and the broker
    /// deliberately skips it, which is the right behaviour and means the test
    /// cannot invent an id and write a route against it.
    ///
    /// So the credential is added the way an operator adds one, over the
    /// product's own verb with the secret on stdin, and the id that verb minted
    /// is what the route file names. The second run then exists because the
    /// broker reads its inventory at startup: a credential added afterwards
    /// would not be in `state.credentials` when the session tries to mint for
    /// it, and the mint would be skipped for a reason no log would explain.
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asv-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the working dir");

        let vault = dir.join("vault.asv");
        let passphrase = dir.join("passphrase.txt");
        let sock = dir.join("broker.sock");
        let value = format!("e2e-{tag}-passphrase");
        std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
        let secret = SecretString::new(value.clone().into());

        VaultStore::create(&vault, &secret, KdfParams::fast_for_tests()).expect("create the vault");

        // Enrolment writes to the vault, and the broker reads its admission
        // record at startup. Enrolling a broker that is already running is the
        // same ordering mistake as planting a credential into it: the record
        // exists on disk and the running process has never seen it, so the
        // refusal names the principal rather than the ordering.
        let enrolled = Command::new(cargo_bin("asv-brokerd"))
            .arg("--vault")
            .arg(&vault)
            .arg("--enrol-principal")
            .arg(cargo_bin("asv"))
            .output()
            .expect("enrol the CLI as a principal");
        assert!(
            enrolled.status.success(),
            "enrolment failed: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );

        // --- phase one: add the credential and learn its id ---------------
        let plant = Broker(
            Command::new(cargo_bin("asv-brokerd"))
                .arg(&sock)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&passphrase)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the planting broker"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            sock.exists(),
            "the planting broker never created its socket"
        );

        let mut add = Command::new(cargo_bin("asv"))
            .arg("--socket")
            .arg(&sock)
            .arg("add-credential")
            .arg("--label")
            .arg(CREDENTIAL_LABEL)
            .arg("--kind")
            .arg("bearer_token")
            .arg("--provider")
            .arg("github")
            .arg("--account")
            .arg("e2e")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run add-credential");
        {
            use std::io::Write as _;
            let mut stdin = add.stdin.take().expect("add-credential stdin");
            stdin.write_all(REAL.as_bytes()).expect("write the secret");
            stdin.write_all(b"\n").expect("terminate the secret");
            // Closed here, not earlier: `add-credential` reads to EOF.
            drop(stdin);
        }
        let added = add.wait_with_output().expect("add-credential finishes");
        assert!(
            added.status.success(),
            "add-credential failed: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        let plant_out = String::from_utf8_lossy(&added.stdout).into_owned();
        drop(plant);

        // "credential 00000000-...-.... created (e2e-token)"
        let credential_id = plant_out
            .split_whitespace()
            .nth(1)
            .filter(|word| word.contains('-'))
            .unwrap_or_else(|| panic!("could not read the minted id from: {plant_out}"))
            .to_owned();
        assert!(
            asv_domain::CredentialId::from_wire(&credential_id).is_ok(),
            "the broker minted an id this route file could not name: {credential_id}"
        );

        let _ = std::fs::remove_file(&sock);

        // --- phase two: the broker that will actually tunnel ---------------
        let origin = Origin::start();

        let routes = dir.join("routes.json");
        std::fs::write(
            &routes,
            format!(
                r#"[{{
  "authority": "{FIXTURE_HOST}",
  "port": {},
  "operation_family": "git_hub",
  "credential": "{credential_id}",
  "minimum_posture": "STRONG_SECRETLESS"
}}]"#,
                origin.port
            ),
        )
        .expect("write the route file");

        // The policy: the stock text plus the one rule C2.6 deliberately left
        // out. `from_policy_text` replaces the whole policy, so the GitHub
        // permit the mint consults has to be restated — a fixture policy that
        // omitted it would fail the mint for a reason unrelated to the route.
        let policy = dir.join("policy.cedar");
        std::fs::write(
            &policy,
            format!(
                r#"permit (principal, action == Action::"github_issue_read", resource is Api);
permit (principal, action == Action::"connect_route", resource == Host::"host:{FIXTURE_HOST}");
"#
            ),
        )
        .expect("write the policy file");

        let audit = dir.join("audit.jsonl");
        let broker = Broker(
            Command::new(cargo_bin("asv-brokerd"))
                .arg(&sock)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&passphrase)
                .arg("--connect-listen")
                .arg("127.0.0.1:0")
                .arg("--connect-routes")
                .arg(&routes)
                .arg("--policy")
                .arg(&policy)
                .arg("--audit-file")
                .arg(&audit)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the tunneling broker"),
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        while !sock.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the broker never created its socket");

        Self {
            dir,
            sock,
            origin,
            credential_id,
            credential_label: CREDENTIAL_LABEL.to_owned(),
            audit,
            _broker: broker,
        }
    }

    /// The environment variable `asv run` exports a session's surrogate under.
    ///
    /// Derived from the label the vault itself reported, so the test reads the
    /// product's own spelling rather than agreeing with it by construction.
    fn surrogate_env_name(&self) -> String {
        format!(
            "ASV_SURROGATE_{}",
            self.credential_label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                })
                .collect::<String>()
        )
    }

    /// The child script. A shell, because `curl` cannot read an environment
    /// variable on its own and the point is that an *ordinary* client is
    /// pointed at a proxy, not that it learned ASV's vocabulary.
    fn held_open_script(
        &self,
        status: &std::path::Path,
        token: &std::path::Path,
        release: &std::path::Path,
    ) -> String {
        let variable = self.surrogate_env_name();
        format!(
            "code=$(curl -sS -k --max-time 20 -o /dev/null -w '%{{http_code}}' \
               -H \"Authorization: Bearer ${variable}\" \
               https://{FIXTURE_HOST}:{port}/resource); \
             printf '%s' \"$code\" > {status}; \
             env | grep -iE 'asv|proxy' | sort; \
             printf '%s' \"${variable}\" > {token}; \
             while [ ! -f {release} ]; do sleep 0.2; done",
            port = self.origin.port,
            status = status.display(),
            token = token.display(),
            release = release.display()
        )
    }
}

// ---------------------------------------------------------------------------
// The vertical
// ---------------------------------------------------------------------------

#[test]
fn asv_run_curl_reaches_the_origin_with_the_real_credential_and_nobody_else() {
    let f = Fixture::new("vertical");
    let env_name = f.surrogate_env_name();
    let status_path = f.dir.join("session-a.status");
    let token_path = f.dir.join("session-a.token");
    let release_path = f.dir.join("release-a");

    // --- session A, held open ---------------------------------------------
    //
    // A has to still be *alive* when session B presents its token, and that is
    // the whole reason it is spawned rather than run to completion.
    //
    // `SessionEnded` calls `revoke_session`, which *deletes* a session's
    // surrogates from the registry. So a token taken from a session that has
    // already exited is refused for being unknown — a real property, and the
    // one the first version of this block measured while claiming to measure
    // another. The mutation campaign is what found the difference: deleting the
    // session comparison in `SurrogateRegistry::redeem_for` left the test
    // completely green, because the comparison was never reached. An assertion
    // satisfied by a refusal of the wrong cause is decoration, and it is
    // indistinguishable from a working one until you take the control away.
    let script_a = f.held_open_script(&status_path, &token_path, &release_path);
    let session_a = Session {
        child: Some(
            Command::new(cargo_bin("asv"))
                .arg("--socket")
                .arg(&f.sock)
                .arg("run")
                .arg("sh")
                .arg("-c")
                .arg(&script_a)
                // Inherited bypasses, planted so their removal is observable.
                .env("NO_PROXY", "should-be-removed")
                .env("no_proxy", "should-be-removed")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the first session"),
        ),
        release: release_path.clone(),
    };

    // The token is published after A's request has completed, so this is also
    // the wait for the happy path. Bounded, because a test that hangs is worse
    // than a test that fails.
    assert!(
        wait_for_file(&token_path, Duration::from_secs(90)),
        "session A never published a surrogate"
    );

    // 1. The origin received the REAL credential. This is the whole feature.
    let status_a = std::fs::read_to_string(&status_path).expect("read session A's status");
    assert_eq!(
        status_a.trim(),
        "200",
        "the tunnel did not complete; curl reported something other than 200"
    );
    assert!(
        f.origin.wait_for_requests(1),
        "the origin never received a request"
    );
    let seen = f.origin.saw();
    assert!(
        seen.contains(REAL),
        "the origin did not receive the real credential; it saw:\n{seen}"
    );

    // 2. The surrogate is a *session* capability, and the only way to measure
    // that is to carry one token into another live session.
    let token_a = std::fs::read_to_string(&token_path).expect("read session A's surrogate");
    let token_a = token_a.trim();
    assert!(
        token_a.starts_with("asv1_"),
        "the exported value is not a surrogate token: {token_a}"
    );
    assert!(token_a != REAL, "the surrogate *is* the real credential");

    // Session A is still open here. That is the whole point, and it is why this
    // block cannot be a `Command::output()`: that waits for the child.
    let bytes_before = f.origin.requests_with_bytes();
    let real_before = f.origin.real_credential_requests();
    let carried = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "curl -sS -k --max-time 20 -o /dev/null -w 'FOREIGN_%{{http_code}}' \
               -H 'Authorization: Bearer {token_a}' \
               https://{FIXTURE_HOST}:{port}/resource; echo; \
             curl -sS -k --max-time 20 -o /dev/null -w 'OWN_%{{http_code}}' \
               -H \"Authorization: Bearer ${env_name}\" \
               https://{FIXTURE_HOST}:{port}/resource; echo",
            port = f.origin.port
        ))
        .output()
        .expect("present another live session's surrogate");
    let carried_out = String::from_utf8_lossy(&carried.stdout);
    let carried_err = String::from_utf8_lossy(&carried.stderr);

    assert!(
        !carried_out.contains("FOREIGN_200"),
        "a live session's surrogate was redeemed by a different one: {carried_out}"
    );
    // The positive half, in the same run. Without it the refusal above is
    // ambiguous: a broker that refused every surrogate would also pass it, and
    // "not yours" has to be distinguishable from "nothing works at all".
    assert!(
        carried_out.contains("OWN_200"),
        "a fresh session could not use its own surrogate:\n{carried_out}\n{carried_err}"
    );

    // The origin is the independent witness, and it is asked two questions
    // because they are not the same question. The origin pushes each capture
    // *before* it answers, so both counts are settled by the time the client
    // has its status line.
    assert_eq!(
        f.origin.requests_with_bytes(),
        bytes_before + 1,
        "the origin received a request the sessions did not authorise"
    );
    // The one that matters: the foreign surrogate must not have put the real
    // credential in front of the destination. The bridge does open a connection
    // for a refused tunnel — it has to dial before it can read the head that
    // carries the surrogate — so a connection count would have grown by two.
    // Counting the secret is what measures the property.
    assert_eq!(
        f.origin.real_credential_requests(),
        real_before + 1,
        "the real credential reached the origin more times than it was authorised"
    );
    assert!(
        !carried_out.contains(REAL) && !carried_err.contains(REAL),
        "a refused surrogate leaked the credential:\n{carried_out}\n{carried_err}"
    );

    // 3-7. Now A can finish, and its output carries the rest of the claims:
    // the wiring the child was handed, and the four surfaces the secret must
    // not appear on.
    let a = session_a.finish();
    let stdout = String::from_utf8_lossy(&a.stdout);
    let stderr = String::from_utf8_lossy(&a.stderr);
    assert!(
        a.status.success(),
        "the session command failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // `Output` does not carry the argv, so it is reconstructed from what this
    // test asked for. The real `argv` of the process that ran is the script
    // text, and the secret is read from the broker, never passed in.
    let argv_used = format!("asv --socket {} run sh -c {script_a}", f.sock.display());
    for (what, haystack) in [
        ("the child's output", &format!("{stdout}\n{stderr}")),
        ("the child's argv", &argv_used),
    ] {
        assert!(
            !haystack.contains(REAL),
            "the real credential appeared in {what}:\n{haystack}"
        );
    }

    // The session ran with a real session id, a real agent socket and a proxy
    // pointed at this session's shim. If any of those were missing the tunnel
    // above could not have happened, so this is a positive check on the wiring
    // rather than a restatement of the 200.
    assert!(
        stdout.contains("ASV_SESSION_ID="),
        "the child was not told its session:\n{stdout}"
    );
    assert!(
        stdout.contains("SSH_AUTH_SOCK="),
        "the child had no agent socket:\n{stdout}"
    );
    assert!(
        stdout.contains("HTTPS_PROXY=http://127.0.0.1:"),
        "the child was not pointed at a session-local shim:\n{stdout}"
    );
    for inherited in ["NO_PROXY", "no_proxy"] {
        assert!(
            !stdout
                .lines()
                .any(|l| l.starts_with(&format!("{inherited}="))),
            "the inherited {inherited} survived into the child. It is a bypass, not a \
             preference: a destination named there is connected to directly, with no \
             CONNECT, no proof and no substitution.\n{stdout}"
        );
    }
    assert!(
        stdout.contains(&format!("{env_name}=")),
        "the child was given no surrogate to present, so nothing could be \
         substituted:\n{stdout}"
    );

    // 9. A wrong destination fails. Nothing routes it, so the tunnel is refused
    // and the origin count does not move.
    let wrong = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("curl")
        .arg("-sS")
        .arg("-k")
        .arg("--max-time")
        .arg("20")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(format!("https://{FIXTURE_HOST}:1/nowhere"))
        .output()
        .expect("connect to a port with no route");
    let wrong_out = String::from_utf8_lossy(&wrong.stdout);
    assert!(
        !wrong_out.contains("200"),
        "a destination with no route was tunnelled anyway: {wrong_out}"
    );
    assert!(
        !wrong_out.contains(REAL),
        "the refused destination leaked the credential:\n{wrong_out}\n{}",
        String::from_utf8_lossy(&wrong.stderr)
    );

    // 11. The audit chain verifies — read off the file the broker actually
    // wrote, with a tamper control, because a verifier that answers Ok to
    // everything verifies nothing.
    //
    // The first version shelled out to `asv-brokerd --audit-verify`. There is
    // no such flag, the broker was never started with an audit file, and the
    // whole assertion sat behind `if ... .success()`, so the one property this
    // file exists to certify was a no-op that would have passed against a
    // broker writing no audit at all. The flag name was never checked against
    // `main.rs`, which is the whole lesson of this block written down.
    let chain = std::fs::read_to_string(&f.audit).unwrap_or_else(|err| {
        panic!(
            "the broker wrote no audit log at {}: {err}",
            f.audit.display()
        )
    });
    // The records are parsed, not grepped.
    //
    // The first version of this block asserted that the chain text contained
    // `"destination":"localhost.localdomain:` — and it went green against a
    // mutation that rewrites the destination of every substitution record. It
    // was being satisfied by a *different* record: the listener writes one for
    // the connection as well as one for the credential, and the connection
    // record names the destination in its own spelling. A substring assertion
    // over a log cannot tell which line it was reading, so it cannot be made
    // red by changing the line it was supposed to be about.
    let records: Vec<asv_ipc_protocol::AuditRecordDto> = chain
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every audit line parses"))
        .collect();
    let substitutions: Vec<&asv_ipc_protocol::AuditRecordDto> = records
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { .. }
            )
        })
        .collect();
    let authorised = format!("{FIXTURE_HOST}:{}", f.origin.port);
    let done: Vec<_> = substitutions
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { outcome, .. }
                    if outcome == "substituted"
            )
        })
        .collect();
    assert_eq!(
        done.len(),
        2,
        "expected both authorised substitutions to be recorded, found {}\n{chain}",
        done.len()
    );
    for record in &done {
        let asv_ipc_protocol::AuditEventDto::CredentialSubstituted { destination, .. } =
            &record.event
        else {
            unreachable!("filtered to substitutions above")
        };
        assert_eq!(
            destination, &authorised,
            "a recorded substitution names a destination nobody authorised"
        );
    }
    // The refusal is recorded too, with the family left unresolved — the port
    // declined before it established one, and inventing it would put an
    // unestablished fact in the chain.
    let refused: Vec<_> = substitutions
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                asv_ipc_protocol::AuditEventDto::CredentialSubstituted { outcome, .. }
                    if outcome == "refused"
            )
        })
        .collect();
    assert_eq!(
        refused.len(),
        1,
        "the refused cross-session attempt was not recorded as refused\n{chain}"
    );
    // The chain is the artefact that gets exported, hashed and shipped, so it
    // has to be the surface that most obviously cannot hold the secret.
    assert!(
        !chain.contains(REAL),
        "the real credential reached the durable audit log:\n{chain}"
    );
    asv_broker::audit::verify_file(&f.audit).expect("the audit chain does not verify");

    // The control. `verify_file` returns Ok for an empty file and for a
    // single-record chain, so a green verification above means nothing on its
    // own. The same call has to be shown going red on an altered record before
    // it is allowed to be evidence of anything.
    let tampered = f.dir.join("tampered-audit.jsonl");
    let altered = chain.replacen("\"substituted\"", "\"refused\"", 1);
    assert_ne!(
        altered, chain,
        "the tamper control changed nothing, so it would have passed for the \
         wrong reason"
    );
    std::fs::write(&tampered, altered).expect("write the altered chain");
    assert!(
        asv_broker::audit::verify_file(&tampered).is_err(),
        "the chain verifier accepted an altered record, so it cannot see a break"
    );

    let _ = f.credential_id;
}

// ---------------------------------------------------------------------------
// The negative half
// ---------------------------------------------------------------------------

#[test]
fn a_session_that_ends_takes_its_proof_authority_with_it() {
    let f = Fixture::new("revoked");
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null -w 'HTTP_%{{http_code}}' \
           -H \"Authorization: Bearer ${variable}\" \
           https://{FIXTURE_HOST}:{port}/resource; \\\
             env | grep -iE 'asv|proxy' | sort",
        port = f.origin.port
    );

    let first = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("first session");
    assert!(
        first.status.success(),
        "the first session failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The precondition. Everything below asserts what happens *after* the
    // session ends, and a first request that never worked would make the
    // shim-stopping assertion pass without anything having been proven.
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("HTTP_200"),
        "the first session never reached the origin: {}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(f.origin.wait_for_requests(1));

    // After the command returns, `asv run` has ended the session and stopped the
    // shim. A later attempt must not be able to use anything that session held.
    // What the shim's port does now is the observable part: a proxy that is still
    // listening would accept a CONNECT and mint a proof for a session that no
    // longer exists, which resolves to nothing and reads as a broken signer.
    let proxy = String::from_utf8_lossy(&first.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("HTTPS_PROXY=").map(|s| s.to_owned()))
        .expect("the child was told a proxy");
    let addr: SocketAddr = proxy
        .trim_start_matches("http://")
        .parse()
        .expect("proxy addr");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut still_listening = true;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                still_listening = false;
                break;
            }
        }
    }
    assert!(
        !still_listening,
        "the shim at {addr} is still listening after its session ended"
    );
}

#[test]
fn a_route_the_policy_does_not_permit_is_refused_at_load() {
    // The fail-closed half of C2.6, through the real binary: a route file whose
    // host the policy does not name stops the broker from starting at all. A
    // broker that started with the route silently dropped would let an operator
    // read "it is running" as "my configuration is in force".
    let dir = std::env::temp_dir().join(format!("asv-e2e-refused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the working dir");

    let vault = dir.join("vault.asv");
    let passphrase = dir.join("passphrase.txt");
    let value = "e2e-refused-passphrase".to_owned();
    std::fs::write(&passphrase, format!("{value}\n")).expect("write the passphrase");
    VaultStore::create(
        &vault,
        &SecretString::new(value.clone().into()),
        KdfParams::fast_for_tests(),
    )
    .expect("create the vault");
    // No credential is planted here on purpose. This route is refused at *load*,
    // before any mint is attempted, so a credential would prove nothing — and
    // planting one needs a `VaultKey` this test has no honest way to get.
    //
    // The id below is well-formed so the refusal this test measures is the
    // policy's, not a malformed credential reported through the same exit.
    let id = "00000000-0000-4000-8000-0000000000e2".to_owned();

    let routes = dir.join("routes.json");
    std::fs::write(
        &routes,
        format!(
            r#"[{{
  "authority": "{FIXTURE_HOST}",
  "port": 443,
  "operation_family": "git_hub",
  "credential": "{id}",
  "minimum_posture": "STRONG_SECRETLESS"
}}]"#
        ),
    )
    .expect("write routes");

    // A policy that permits the GitHub mint but says nothing about this host.
    let policy = dir.join("policy.cedar");
    std::fs::write(
        &policy,
        "permit (principal, action == Action::\"github_issue_read\", resource is Api);\n",
    )
    .expect("write policy");

    let refused = Command::new(cargo_bin("asv-brokerd"))
        .arg(dir.join("broker.sock"))
        .arg("--vault")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--connect-listen")
        .arg("127.0.0.1:0")
        .arg("--connect-routes")
        .arg(&routes)
        .arg("--policy")
        .arg(&policy)
        .output()
        .expect("run the broker");

    assert!(
        !refused.status.success(),
        "a broker started with a route the policy does not permit"
    );
    let text = String::from_utf8_lossy(&refused.stderr);
    assert!(
        text.contains("connect-routes") || text.contains("policy does not permit"),
        "the refusal did not say why:\n{text}"
    );
}
