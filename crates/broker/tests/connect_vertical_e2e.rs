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
    /// Connections this origin is still holding open.
    ///
    /// The point of the fixture is the question "is that tunnel *still
    /// there*", and a request counter cannot answer it: a tunnel that is
    /// established and idle looks exactly like one that never existed.
    open: Arc<Mutex<usize>>,
}

impl Origin {
    /// An origin that answers `per_connection` requests on one connection
    /// before closing it.
    ///
    /// One is the shape the vertical uses: a CONNECT tunnel the client opens
    /// per request is what `curl` produces by default. More than one is the
    /// shape the *protocol* allows, and it is a different question — see
    /// `a_tunnel_serves_one_request_and_the_protocol_allows_more`.
    fn start_serving(per_connection: usize) -> Self {
        Self::spawn(per_connection, false)
    }

    /// An origin that answers one request and then *keeps the connection open*.
    ///
    /// This is what an established, idle tunnel looks like from the
    /// destination's side, and it is the only shape in which "did the tunnel
    /// end?" is a question about time rather than about a count.
    ///
    /// Two details make the answer trustworthy. The response omits
    /// `Connection: close`, so the client is not told to go; and the read that
    /// follows has **no deadline at all**, so the only thing that can end this
    /// connection is the other end going away. A holding origin with a read
    /// timeout would answer "is it still open?" with a yes for a while and a
    /// no for a reason that has nothing to do with the tunnel — which is how a
    /// lifecycle test ends up asserting a timer.
    fn start_holding() -> Self {
        Self::spawn(1, true)
    }

    fn spawn(per_connection: usize, holding: bool) -> Self {
        // `[::]` is dual-stack on Linux, so one port answers on both `::1` and
        // `127.0.0.1`. The broker takes the first address the resolver returns,
        // and which one that is has changed between hosts; a single-family bind
        // would make this test a bet on the resolver's mood.
        let listener = TcpListener::bind("[::]:0").expect("origin binds");
        let addr = listener.local_addr().expect("origin addr");
        let port = addr.port();
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);
        let open: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&open);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let sink = Arc::clone(&sink);
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    *counter.lock().expect("open counter") += 1;
                    serve_connection(&mut stream, &sink, per_connection, holding);
                    // The decrement is on the way out of every path, and there
                    // is no `return` in `serve_connection` to skip it. A counter
                    // that can be skipped is one the lifecycle test reads as
                    // "the tunnel closed" when the connection thread simply
                    // left early.
                    *counter.lock().expect("open counter") -= 1;
                });
            }
        });

        Self {
            port,
            requests,
            open,
        }
    }

    /// Everything the origin was sent, joined, for substring assertions.
    fn saw(&self) -> String {
        self.requests.lock().expect("origin sink").join("\n")
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("origin sink").len()
    }

    /// How many connections are still open.
    fn open_connections(&self) -> usize {
        *self.open.lock().expect("open counter")
    }

    /// Waits for the open count to *become* `n`, bounded.
    ///
    /// Polling rather than reading once, for the reason `wait_for_requests`
    /// gives: the fixture runs on its own threads, and a single read is a race
    /// that fails the test for being early instead of for being wrong.
    fn wait_for_open(&self, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.open_connections() == n {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
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

/// Serves one connection, and returns when that connection is over.
///
/// A free function rather than a method because it takes the mutable stream,
/// and a `&mut self` here would borrow the fixture for the whole life of a
/// connection that is supposed to outlive every line the test writes next.
///
/// `served_any` decides whether the hold is entered. A connection that never
/// carried a request is the bridge's dial-before-the-head behaviour, not a
/// tunnel; holding it open forever would pin a thread and inflate the open
/// count with something no session authorised.
fn serve_connection(
    stream: &mut TcpStream,
    sink: &Arc<Mutex<Vec<String>>>,
    per_connection: usize,
    holding: bool,
) {
    // This deadline covers the request phase only, so a client that connects
    // and says nothing cannot pin a thread for the life of the suite.
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let mut served_any = false;
    for served in 0..per_connection {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 2048];
        // Read until the headers are complete, then answer. A `break` here ends
        // the connection rather than the loop, so a client that hangs up
        // mid-sequence is not answered with a fabricated request.
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
        if raw.is_empty() {
            break;
        }
        served_any = true;
        sink.lock()
            .expect("origin sink")
            .push(String::from_utf8_lossy(&raw).into_owned());
        // `close` on the last request is what tells `curl` it may stop reusing
        // the connection. A holding origin never sends it: the point is that
        // the connection outlives the response, and a client told to close
        // would close it and take the tunnel with it.
        let last = served + 1 == per_connection;
        let response: &[u8] = if last && !holding {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        };
        if stream.write_all(response).is_err() {
            break;
        }
        let _ = stream.flush();
    }
    if holding && served_any {
        // No deadline. From here the connection ends when the tunnel ends and
        // for no other reason, which is what lets `open_connections` answer
        // "is the tunnel still there" instead of "has the timeout fired".
        stream.set_read_timeout(None).ok();
        let mut buf = [0u8; 256];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
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
        Self::with_origin(tag, Origin::start_serving(1))
    }

    /// A fixture whose origin answers several requests per connection.
    ///
    /// The port has to be the one the route file names, so the origin is
    /// started this way from the beginning rather than swapped afterwards: a
    /// fixture that reconnected the origin would leave the route naming a port
    /// nothing is listening on, and the tunnel would fail for a reason that has
    /// nothing to do with the question being asked.
    fn new_serving(tag: &str, per_connection: usize) -> Self {
        Self::with_origin(tag, Origin::start_serving(per_connection))
    }

    /// A fixture whose origin holds its connection open after answering.
    ///
    /// Started from the beginning for the same reason, and the origin is
    /// therefore a different *kind* of origin rather than a later phase of the
    /// same one.
    fn new_holding(tag: &str) -> Self {
        Self::with_origin(tag, Origin::start_holding())
    }

    fn with_origin(tag: &str, origin: Origin) -> Self {
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
                // The broker's tracing goes to *stdout*, not stderr, so a
                // fixture that silences stdout is silently hiding the only
                // account of why a tunnel was refused.
                .stdout(
                    std::fs::File::create(dir.join("broker.log")).expect("create the broker log"),
                )
                .stderr(
                    std::fs::File::create(dir.join("broker.err"))
                        .expect("create the broker error log"),
                )
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

/// The tunnel serves one request, and the protocol allows more.
///
/// **This is a characterization, not a claim.** It records the measured
/// behaviour of a gap that V1-C2 names in its own scope — "more than one
/// request per tunnel where the protocol allows" — and that is not closed.
///
/// The measurement, against the real broker with a real origin that keeps the
/// connection open:
///
/// ```text
/// CONN=1 CODE=200      the first request, on one connection
/// CONN=0 CODE=000      the second request, curl reusing that same connection
/// ```
///
/// `CONN=0` is the load-bearing half. `curl` did not open a second connection;
/// it reused the tunnel, and got nothing back. So the second request is not
/// failing because the origin refused it — the origin never saw it.
///
/// The cause is in `relay_substituted`: it reads one head, writes the rewritten
/// one, and then `relay_back` copies the response direction until EOF or a byte
/// limit. The request direction is never pumped again, so the second request
/// sits in a socket buffer that nobody reads. Every real HTTP/1.1 client
/// reuses its connection, so this is the shape of ordinary traffic and not an
/// edge case.
///
/// What still holds, and is asserted here, is the part that would be a security
/// problem if it did not: the destination never received a second request, so
/// it never received a second copy of the credential, and nothing forwarded a
/// surrogate it could not use. The gap is availability and opacity, not
/// disclosure. That is worth knowing precisely, because "the second request
/// fails" and "the second request leaks something" call for different work.
#[test]
fn a_tunnel_serves_one_request_and_the_protocol_allows_more() {
    let f = Fixture::new_serving("pipelined", 2);

    // One `-H`, two URLs: curl applies it to both and reuses the connection,
    // which is the whole shape of the question. Two `-H` flags would send the
    // header twice on every request, and the destination would see two.
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null \\
           -w 'CONN=%{{num_connects}} CODE=%{{http_code}}\\n' \\
           -H \"Authorization: Bearer ${{{variable}}}\" \\
           https://{FIXTURE_HOST}:{port}/first \\
           https://{FIXTURE_HOST}:{port}/second",
        port = f.origin.port
    );
    let child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("two requests on one tunnel");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);

    // The first request works, on one connection. Without this the rest of the
    // test would be measuring a broken setup.
    assert!(
        stdout.contains("CONN=1 CODE=200"),
        "the first request did not complete on one connection: {stdout}\n{stderr}"
    );

    // The measured limit, asserted rather than merely described. If this ever
    // goes green the gap is closed and the comment above is wrong, which is the
    // signal to rewrite both.
    let served = stdout.matches("CODE=200").count();
    assert_eq!(
        served, 1,
        "the tunnel served {served} requests where it is documented to serve one; if \
         this ever goes green the limit above is stale and both need rewriting: \
         {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("CONN=0"),
        "curl opened a second connection instead of reusing the tunnel, so this \
         measurement is about something else: {stdout}\n{stderr}"
    );

    // The part that must not move. If the broker ever starts forwarding a
    // second request without rewriting it, the destination receives a surrogate
    // it cannot spend, and this assertion is what would notice.
    let seen = f.origin.saw();
    assert_eq!(
        f.origin.real_credential_requests(),
        1,
        "the destination received the credential more than once: \n{seen}"
    );
    assert!(
        !seen.contains(&f.surrogate_env_name()),
        "a variable name in the destination's bytes would mean a token arrived: \n{seen}"
    );
    assert!(
        !stdout.contains(REAL) && !stderr.contains(REAL),
        "the real credential appeared outside the destination: \n{stdout}\n{stderr}"
    );
}

/// Sixty-four CONNECTs at once from one session, and the anti-replay window
/// must not refuse a single one of them.
///
/// This began as a characterisation of a defect and is now a claim, because the
/// defect is fixed. Before, 8 of 64 completed and the broker's log split the 56
/// refusals into 17 legitimate proofs refused as `Replayed` and 39 exhausted
/// surrogates. The 17 were the important half: proofs the session had just
/// minted, correctly signed, refused by the machinery that exists to stop
/// replays, in the one direction an honest client cannot distinguish from an
/// attack.
///
/// Two defects were behind it, both in this repository and neither in a test:
///
/// - The window marked the wrong bit when it advanced. Bit `i` means
///   `highest - 1 - i`, so the previous highest lands on `shift - 1`, not on
///   bit 0 — and those coincide only when the shift is exactly one, which is
///   the single case the existing test happened to cover.
/// - The surrogate's use budget was 8, not the 32 the broker asked for:
///   `mint` clamps into the protocol ceiling, and a clamp that lowers what you
///   asked for raises nothing and logs nothing. The wire reported the clamped
///   value, so every reader believed it.
///
/// Measured after both: **64 of 64 complete and nothing is refused.** The
/// surrogate budget was still 32 at that point, so the 32 that could not
/// complete were refused for the budget that was *documented* — a budget doing
/// its job, and the wrong job: `npm install express` needs 93. The budget is
/// now the protocol's ceiling, and a test that demanded a refusal at 64 would be
/// demanding the defect back.
///
/// The property asserted here is the one that must not regress: the anti-replay
/// window refuses nothing, every request is accounted for by a reason the
/// operator can read, and no session spends more than it was granted.
#[test]
fn the_anti_replay_window_refuses_no_honest_proof_under_load() {
    const PARALLEL: usize = 64;

    let f = Fixture::new_serving("concurrent", 1);
    let variable = f.surrogate_env_name();
    let out = f.dir.join("codes");
    let script = format!(
        "i=0; \
         while [ $i -lt {n} ]; do \
           ( curl -sS -k --max-time 60 -o /dev/null \
               -w '%{{http_code}}\n' \
               -H \"Authorization: Bearer ${{{variable}}}\" \
               \"https://{FIXTURE_HOST}:{port}/r$i\" >> {out} ) & \
           i=$((i+1)); \
         done; \
         wait",
        n = PARALLEL,
        port = f.origin.port,
        out = out.display()
    );
    let child = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("parallel tunnels from one session");
    let codes = std::fs::read_to_string(&out).unwrap_or_default();
    let ok = codes.lines().filter(|l| l.trim() == "200").count();
    assert!(
        ok > 0,
        "no tunnel completed, so this measured nothing:\n{codes}"
    );

    // The broker's own account, which is why the fixture captures its stdout:
    // `tracing_subscriber::fmt()` writes there, and a fixture that silences
    // stdout hides the only record of why a tunnel was refused. An observer
    // switched off is indistinguishable from one that does not exist.
    let log = std::fs::read_to_string(f.dir.join("broker.log")).unwrap_or_default();
    let proof_refusals = log.matches("no session proof resolved").count();
    let surrogate_refusals = log.matches("the presented surrogate was refused").count();

    // The property. Sixty-four freshly minted proofs, and not one of them
    // refused for being a replay.
    assert_eq!(
        proof_refusals, 0,
        "{proof_refusals} legitimate proofs were refused as replays; a client paying \
         for a concurrent burst cannot tell that from an attack"
    );
    // And every request has a reason an operator can act on.
    assert_eq!(
        proof_refusals + surrogate_refusals,
        PARALLEL - ok,
        "the broker refused {} tunnels but accounted for {} of them; a refusal with \
         no reason in the log is one nobody can act on",
        PARALLEL - ok,
        proof_refusals + surrogate_refusals
    );
    // Whatever is left is the budget, doing what a budget is for.
    //
    // **This assertion used to pin the number 32 and cannot any more.** Sixty-four
    // CONNECTs exceeded a budget of 32, so "something was refused" doubled as
    // evidence that the budget is enforced. The session's budget is now the
    // protocol's own ceiling — 64 is nowhere near it, every tunnel completes, and
    // a test that demanded a refusal would be demanding the defect back.
    //
    // What replaces it is the same property stated without a magic number: no
    // session may spend more than it was granted. Enforcement at the point of
    // spending is witnessed where it can actually be witnessed, by
    // `a_session_surrogate_pays_for_a_workload_that_was_actually_run` and by the
    // registry's own exhaustion cases — a budget can be checked by spending it to
    // zero in a unit test, and cannot be checked by a workload too small to reach
    // it.
    assert!(
        ok <= asv_broker::session_surrogate_budget() as usize,
        "{ok} of {PARALLEL} tunnels completed and the session was granted {} operations, \
         so more were spent than were granted",
        asv_broker::session_surrogate_budget()
    );

    // What a concurrency fix must not break: the destination saw the credential
    // once per completed tunnel, and never a surrogate.
    assert_eq!(
        f.origin.real_credential_requests(),
        ok,
        "the destination saw the credential a different number of times than \
         tunnels completed"
    );
    let seen = f.origin.saw();
    assert!(
        !seen.contains("asv1_"),
        "a surrogate reached the destination:\n{seen}"
    );
    let _ = child;
}

// ---------------------------------------------------------------------------
// The negative half
// ---------------------------------------------------------------------------

/// A tunnel does not outlive the session that authorised it.
///
/// Two things are being measured, and the difference between them is the whole
/// reason this test is worth writing down.
///
/// **What the destination sees.** The origin holds the connection it was given
/// and reports whether it is still holding it, with no read deadline behind
/// the answer — so "still open" cannot be a timer wearing a tunnel's clothes.
/// When the session ends and the count goes to zero, the tunnel is gone from
/// the far end of the chain, which is the shape an operator would recognise.
///
/// **What it cannot settle.** It cannot say *who* closed it. `asv run` stops
/// its shim and ends its session in that order, and a dead shim drops its
/// sockets, so a tunnel closing here is equally consistent with the shim dying
/// and with the broker cancelling. The vertical has no way to hold the shim
/// open while the session ends, because ending the session *is* the shim
/// stopping.
///
/// So the end-to-end claim is checked here and the broker's own claim is
/// checked where it can be isolated, in
/// `connect_session_revocation_wiring.rs`. A green test above and a green test
/// there are two different guarantees; a green one with the other missing is
/// a guarantee nobody actually has.
///
/// Two URLs on one connection, deliberately. The first is answered and the
/// second is not — the limit measured in
/// `a_tunnel_serves_one_request_and_the_protocol_allows_more` — and that is
/// precisely what keeps `curl` inside the tunnel. A single-URL curl exits on
/// its response, and a tunnel whose client has already exited is not a tunnel
/// that outlived anything: the control below would pass against a fixture that
/// never held a connection at all.
///
/// `--max-time` is the second request giving up, and it is why this test takes
/// twenty seconds rather than three: the release file is only read after `curl`
/// returns, so curl's own deadline is what ends the command and lets `asv run`
/// begin its teardown. It has to clear the settle window below with room to
/// spare, because a `curl` that hit its deadline first would close the tunnel
/// for a reason that has nothing to do with the session — the one confound this
/// test cannot survive. Twenty against a control that fires at under one is
/// that room.
#[test]
fn a_tunnel_does_not_outlive_the_session_that_authorised_it() {
    let f = Fixture::new_holding("midtunnel");
    let variable = f.surrogate_env_name();
    let release_path = f.dir.join("mid.release");
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/first \
           https://{FIXTURE_HOST}:{port}/second; \
         while [ ! -f {release} ]; do sleep 0.2; done",
        port = f.origin.port,
        release = release_path.display()
    );

    let session = Session {
        child: Some(
            Command::new(cargo_bin("asv"))
                .arg("--socket")
                .arg(&f.sock)
                .arg("run")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the session under measurement"),
        ),
        release: release_path.clone(),
    };

    // The destination is asked, not the client. A client inside its own tunnel
    // cannot tell a live tunnel from a socket it is holding open by itself.
    assert!(
        f.origin.wait_for_open(1, Duration::from_secs(90)),
        "the tunnel was never established: the destination holds {} connections, \
         so the assertion after the session ends would be measuring nothing",
        f.origin.open_connections()
    );
    assert!(
        f.origin.wait_for_requests(1),
        "the destination never received a request"
    );

    // The control, and the reason the tunnel has to survive the request that
    // built it. One sample is not an observation: a tunnel that collapses the
    // instant it is used satisfies "zero connections after the session ends"
    // perfectly while proving nothing. A second look, after a settle window
    // and with the session still live, is what gives the later zero its
    // meaning.
    std::thread::sleep(Duration::from_millis(750));
    assert_eq!(
        f.origin.open_connections(),
        1,
        "the tunnel did not survive the request that established it; the \
         destination gave the connection back while the session was still live, \
         so nothing here is measuring a tunnel outliving anything"
    );
    assert_eq!(
        f.origin.real_credential_requests(),
        1,
        "the credential did not reach the destination exactly once under a live \
         session; whatever closes later is not a tunnel that was working"
    );

    // The session ends. `Session::finish` releases the child, waits for it, and
    // so returns only after `asv run` has stopped its shim and sent
    // `EndSession` — the teardown is over before the first observation.
    let out = session.finish();
    assert!(
        out.status.success(),
        "the session failed while tearing down\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        f.origin.wait_for_open(0, Duration::from_secs(20)),
        "a tunnel outlived the session that authorised it: the destination still \
         holds {} connections 20s after the session ended, carrying a credential \
         nobody authorised any more",
        f.origin.open_connections()
    );
}

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

// ---------------------------------------------------------------------------
// The observability sweep
// ---------------------------------------------------------------------------

/// The address the broker said it was listening on, read out of its own log.
///
/// Taken from the log rather than from a flag or a fixture argument for the
/// same reason the concurrency test reads its refusals from there: the fixture
/// launches the real binary and the log is the only channel it has. The
/// circularity is benign — the address is a startup fact, and the thing under
/// test is what arrives *after* it.
fn connect_address_from_log(path: &std::path::Path) -> SocketAddr {
    let log = std::fs::read_to_string(path).expect("read the broker log");
    // `tracing_subscriber::fmt()` colourises, and the escape sequences land
    // either side of the field. Stripped rather than worked around: a fixture
    // that only parses the log when the terminal is a terminal is a fixture
    // that reports "no address" on half the machines it runs on.
    let plain = strip_ansi(&log);
    plain
        .lines()
        .filter_map(|line| line.split("bound=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .find_map(|addr| addr.parse().ok())
        .expect("the broker logged where it is listening")
}

/// Remove CSI escape sequences.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // `ESC [ … final-byte`, and the final byte is in `@`..=`~`.
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// Waits for `needle` to appear in the broker's log, bounded.
fn log_gains(log: &std::path::Path, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(log)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The broker's own log carries neither the credential nor a surrogate.
///
/// The vertical already proved the child's `argv`, its environment, its output
/// and the durable chain are clean. The operator's log is the surface that was
/// never checked, and it is the one an operator actually reads while something
/// is going wrong — so "it is not in the chain" says very little about it.
///
/// The control is the line that has to be there. A grep over an empty file
/// finds nothing and reports a pass, and an observer that is switched off is
/// indistinguishable from an observer that does not exist.
#[test]
fn the_brokers_own_log_carries_neither_the_credential_nor_a_surrogate() {
    let f = Fixture::new("observability");
    let variable = f.surrogate_env_name();
    let script = format!(
        "curl -sS -k --max-time 20 -o /dev/null -w '%{{http_code}}' \
           -H \"Authorization: Bearer ${{{variable}}}\" \
           https://{FIXTURE_HOST}:{port}/resource; echo",
        port = f.origin.port
    );
    let ran = Command::new(cargo_bin("asv"))
        .arg("--socket")
        .arg(&f.sock)
        .arg("run")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("a session that reaches the origin");
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("200"),
        "the session never reached the origin, so nothing was substituted and the \
         log sweep would be measuring an idle broker:\n{}\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(f.origin.wait_for_requests(1));

    let log_path = f.dir.join("broker.log");
    assert!(
        log_gains(&log_path, "CONNECT tunnel relayed", Duration::from_secs(30)),
        "the broker never logged relaying a tunnel; the log is not what this test \
         thinks it is"
    );
    let log = std::fs::read_to_string(&log_path).expect("read the broker log");

    assert!(
        !log.contains(REAL),
        "the real credential reached the operator's log:\n{log}"
    );
    // `asv1_` is the surrogate prefix, declared in `surrogate.rs` so a token is
    // never mistaken for a credential during triage. A log carrying one would
    // be a log carrying a spendable bearer token.
    assert!(
        !log.contains("asv1_"),
        "a surrogate reached the operator's log, so anything holding that file \
         holds a spendable token:\n{log}"
    );
}

/// A client with no credential cannot write its own words into the operator's
/// log.
///
/// **This is a claim, and it is red.** It is written as a claim rather than as
/// a characterisation because the thing it names is not a judgement call: a
/// client that never proves anything can put arbitrary bytes into a file the
/// operator reads, and the mechanism is short —
///
/// `parse_connect_target` runs **before** the session proof is authenticated
/// (the order in `serve_connect` is head, then target, then authorisation, then
/// proof), and `ConnectTargetError::NoPort` carries the request line's authority
/// verbatim. So `CONNECT <anything-without-a-colon>` writes `<anything>` into
/// the log, unvalidated and uncredited, up to the message bound.
///
/// The durable chain is already protected against exactly this, by
/// `refusal_class`; the operator's line was left carrying the raw text on the
/// judgement that it is "the surface that already exists to hold diagnostic
/// detail". The chain's own comment calls that text *attacker-controlled*, and
/// the reachability here is unauthenticated, which is a stronger statement than
/// the one that judgement was made under.
///
/// The client here is a bare socket. It carries no proof, no surrogate and no
/// credential, and it is not even a well-formed CONNECT — which is the point:
/// the bytes land before any of that is looked at.
#[test]
fn a_client_with_no_credential_cannot_write_its_own_text_into_the_operator_log() {
    let f = Fixture::new("injection");
    let log_path = f.dir.join("broker.log");
    // Waited for, not read once: the broker creates its control socket before
    // it binds the CONNECT listener, so the fixture's own readiness check can
    // be satisfied a moment before the line this test needs is written. A
    // fixture that read the log at that instant would report "no address" for
    // a broker that is about to say where it is.
    assert!(
        log_gains(&log_path, "CONNECT listener bound", Duration::from_secs(30)),
        "the broker never logged its CONNECT listener"
    );
    let addr = connect_address_from_log(&log_path);

    // Shaped like a credential so a substring search cannot be satisfied by a
    // word that happens to appear in a stack trace, and with no colon, so the
    // target parse fails with the request line's own text attached.
    let planted = "gho_ASVclientWroteThisE7b1c3d5f7a9b1d3f5a7c9e1b3d5f7a9b1d3f5a7c9e1";
    let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .expect("reach the CONNECT listener with no credential at all");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client
        .write_all(format!("CONNECT {planted} HTTP/1.1\r\nHost: {FIXTURE_HOST}\r\n\r\n").as_bytes())
        .expect("write a malformed CONNECT");
    let _ = client.flush();

    assert!(
        !log_gains(&log_path, planted, Duration::from_secs(15)),
        "a client that proved nothing, presented no surrogate and sent a malformed \
         request wrote its own text into the operator's log; the broker logs what \
         it cannot attribute to state it validated"
    );
}
