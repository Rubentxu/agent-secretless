//! R2.C.2.b, the port — the cache, the margin rule, and the revocation.
//!
//! No socket here, and that is deliberate: these are the properties of *when a
//! session is minted and when it stops being served*, and a socket would only
//! make them slower to falsify. The socket is measured in
//! `r2c2b_sts_vertical.rs`; the mint it performs is measured here through a
//! counting exchange.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use asv_broker::aws::port::{AwsSecretPort, SessionExchange};
use asv_broker::aws::sts::{AwsSecretSink, AwsSession, StsError};
use asv_connector_http::{SecretError, SecretPort, SecretSink};

const EXPIRES_AT: u64 = 1_573_306_481; // 2019-11-09T13:34:41Z
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TOKEN: &str = "FQoGZXIvYXdzEBYaDEXAMPLE";
const ACCESS_KEY: &str = "ASIAIOSFODNN7EXAMPLE";

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Builds a session expiring at `expires_at`, the only way to make one without
/// a provider.
///
/// **Through the real reader**, so a fixture cannot drift from the shape
/// `parse_assume_role` produces: a hand-assembled struct would be a second
/// definition of what a session is, and the rows below would then be asserting
/// about that second definition.
fn session_expiring_at(expires_at: u64) -> AwsSession {
    let body = format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult><Credentials>
    <AccessKeyId>{ACCESS_KEY}</AccessKeyId>
    <SecretAccessKey>{SECRET}</SecretAccessKey>
    <SessionToken>{TOKEN}</SessionToken>
    <Expiration>{}</Expiration>
  </Credentials></AssumeRoleResult>
</AssumeRoleResponse>"#,
        rfc3339(expires_at)
    );
    let request = asv_broker::aws::sts::AssumeRole::new(
        "arn:aws:iam::123456789012:role/demo",
        "asv-session",
        3600,
        None,
    )
    .expect("the fixture role is well-formed");
    asv_broker::aws::sts::parse_assume_role(
        body.as_bytes(),
        &request,
        at(expires_at.saturating_sub(3600)),
    )
    .expect("the fixture response parses")
}

fn a_session() -> AwsSession {
    session_expiring_at(EXPIRES_AT)
}

/// A `SecretSink` that records how many values it was handed, so the shared
/// one-value port can be watched rather than merely called.
struct Watcher {
    calls: Arc<AtomicUsize>,
}

impl SecretSink for Watcher {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        // The length, not the value. A failure message that printed what leaked
        // would put it in a test log, which is the habit this whole module is
        // written against.
        let _length = secret.len();
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// An exchange that counts mints and answers with a fresh session.
struct Counting {
    mints: Arc<AtomicUsize>,
    expires_at: u64,
}

impl SessionExchange for Counting {
    fn exchange(
        &self,
        _credential: &str,
        _now: SystemTime,
    ) -> Result<AwsSession, asv_broker::aws::client::StsClientError> {
        self.mints.fetch_add(1, Ordering::SeqCst);
        Ok(session_expiring_at(self.expires_at))
    }
}

/// An exchange that answers until it is told to stop, so a row can put a failure
/// *after* a good mint and watch what the failure does to the cache.
///
/// A separate fixture from `Counting` rather than a flag on it, because
/// "fails from the first call" and "fails after serving" are different rows and
/// sharing one fixture is how a row ends up asserting the easier one twice.
struct Flaky {
    mints: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
}

impl SessionExchange for Flaky {
    fn exchange(
        &self,
        _credential: &str,
        _now: SystemTime,
    ) -> Result<AwsSession, asv_broker::aws::client::StsClientError> {
        self.mints.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err(asv_broker::aws::client::StsClientError::UnreadableStatus { status: 503 });
        }
        Ok(a_session())
    }
}

/// A fixed set of instants, from the calendar oracle.
fn rfc3339(epoch: u64) -> String {
    // Only the two the fixtures use, and both are in the oracle's table.
    match epoch {
        1_573_306_481 => "2019-11-09T13:34:41Z".to_string(),
        1_573_306_800 => "2019-11-09T14:00:00Z".to_string(),
        other => panic!("no oracle value for {other}"),
    }
}

/// A sink that records the three values it was lent.
#[derive(Default)]
struct Recorded {
    seen: usize,
    access_key: String,
    secret: String,
    token: String,
}

impl AwsSecretSink for Recorded {
    fn accept(
        &mut self,
        access_key_id: &[u8],
        secret_access_key: &[u8],
        session_token: &[u8],
    ) -> Result<(), StsError> {
        self.seen += 1;
        self.access_key = String::from_utf8_lossy(access_key_id).into_owned();
        self.secret = String::from_utf8_lossy(secret_access_key).into_owned();
        self.token = String::from_utf8_lossy(session_token).into_owned();
        Ok(())
    }
}

fn port_expiring_at(expires_at: u64) -> (AwsSecretPort, Arc<AtomicUsize>) {
    let mints = Arc::new(AtomicUsize::new(0));
    let port = AwsSecretPort::new(Arc::new(Counting {
        mints: mints.clone(),
        expires_at,
    }));
    (port, mints)
}

/// A port whose exchange can be made to fail on demand, and the flag to do it.
fn port_that_can_fail() -> (AwsSecretPort, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let mints = Arc::new(AtomicUsize::new(0));
    let failing = Arc::new(AtomicBool::new(false));
    let port = AwsSecretPort::new(Arc::new(Flaky {
        mints: mints.clone(),
        failing: failing.clone(),
    }));
    (port, mints, failing)
}

#[test]
fn one_exchange_serves_many_lends_inside_the_margin() {
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let now = at(EXPIRES_AT - 3600);

    for _ in 0..5 {
        let mut sink = Recorded::default();
        port.lend_session("aws-prod", now, &mut sink)
            .expect("a cached session is served");
        assert_eq!(sink.seen, 1);
        assert_eq!(sink.access_key, ACCESS_KEY);
        assert_eq!(sink.secret, SECRET);
        assert_eq!(sink.token, TOKEN);
    }
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "five lends inside the margin must cost one exchange"
    );
}

#[test]
fn a_session_inside_the_margin_is_not_served_and_is_replaced() {
    // The margin is the whole reason the cache exists: a session that dies
    // mid-request fails at the provider with a name that does not point here.
    //
    // The boundary is strict, and the first draft of this row got it wrong by a
    // second — which is worth recording, because "a bit inside the margin" is
    // not a thing. A session with exactly the margin left is **not** usable: a
    // request signed now and sent a moment later would arrive with the margin
    // already spent, so the conservative side is the only defensible one. A
    // session with a second more than the margin is.
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let margin = AwsSecretPort::DEFAULT_MARGIN;

    // One second more than the margin left: served, and this is the first mint.
    let mut sink = Recorded::default();
    port.lend_session("aws-prod", at(EXPIRES_AT - margin.as_secs() - 1), &mut sink)
        .expect("served");
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "a session past the margin was not served"
    );

    // Exactly the margin left: not usable, so re-minted.
    let mut sink = Recorded::default();
    port.lend_session("aws-prod", at(EXPIRES_AT - margin.as_secs()), &mut sink)
        .expect("re-minted");
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "a session with exactly the margin left was served anyway"
    );
}

#[test]
fn a_margin_above_the_lifetime_serves_nothing_and_says_so() {
    // The silent case R2.B found on the OAuth2 port. A margin at or above the
    // lifetime does not refuse: it makes every call re-mint, and nothing fails
    // -- the port just gets slower and depends on STS for every request.
    let lifetime = Duration::from_secs(3600);
    assert_eq!(
        AwsSecretPort::serve_for(lifetime, Duration::from_secs(60)),
        Duration::from_secs(3540),
        "an ordinary margin must serve for the rest of the lifetime"
    );
    assert_eq!(
        AwsSecretPort::serve_for(lifetime, lifetime),
        Duration::ZERO,
        "a margin equal to the lifetime served for something"
    );
    assert_eq!(
        AwsSecretPort::serve_for(lifetime, lifetime + Duration::from_secs(1)),
        Duration::ZERO,
        "a margin above the lifetime served for something"
    );
}

#[test]
fn a_margin_that_swallows_the_session_makes_every_lend_mint_again() {
    // The row above says the arithmetic is degenerate; this is what degenerate
    // looks like through the port. Three lends, three exchanges, nothing logged
    // and nothing failed — the only symptom is STS sitting on the critical path
    // of every request, which is exactly the class of bug an operator finds by
    // asking why it got slow rather than by reading a red test.
    //
    // Which is why the margin is not a private field with a constant setter
    // that pretends to validate. It is settable, the arithmetic is public, and
    // this row makes the consequence measurable instead of folklore.
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let port = port.with_margin(Duration::from_secs(3600));
    let now = at(EXPIRES_AT - 3600);

    for _ in 0..3 {
        let mut sink = Recorded::default();
        port.lend_session("aws-prod", now, &mut sink)
            .expect("the exchange still answers");
    }
    assert_eq!(
        mints.load(Ordering::SeqCst),
        3,
        "a margin that swallows the whole session was served from the cache anyway"
    );
}

#[test]
fn forget_drops_the_cache_and_the_next_lend_re_mints() {
    // The property R2.B made structural by putting `forget` on `SecretPort` with
    // no default. `DeleteCredential` removes the vault record and revokes the
    // session's surrogates; a cache invisible to both is a credential still
    // being served after the operator was told it is gone.
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let now = at(EXPIRES_AT - 3600);

    let mut sink = Recorded::default();
    port.lend_session("aws-prod", now, &mut sink)
        .expect("minted");
    assert_eq!(mints.load(Ordering::SeqCst), 1);
    assert_eq!(port.cached(), vec!["aws-prod".to_string()]);

    port.forget("aws-prod");
    assert!(
        port.cached().is_empty(),
        "forget left the session in the cache: {:?}",
        port.cached()
    );

    let mut sink = Recorded::default();
    port.lend_session("aws-prod", now, &mut sink)
        .expect("re-minted");
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "a forgotten credential was served from the cache"
    );
}

#[test]
fn forgetting_one_credential_leaves_the_others_cached() {
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let now = at(EXPIRES_AT - 3600);
    for credential in ["aws-prod", "aws-staging"] {
        let mut sink = Recorded::default();
        port.lend_session(credential, now, &mut sink)
            .expect("minted");
    }
    assert_eq!(mints.load(Ordering::SeqCst), 2);
    assert_eq!(port.cached(), vec!["aws-prod", "aws-staging"]);

    port.forget("aws-prod");
    assert_eq!(port.cached(), vec!["aws-staging"]);
    let mut sink = Recorded::default();
    port.lend_session("aws-staging", now, &mut sink)
        .expect("served");
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "forgetting one credential evicted another"
    );
}

#[test]
fn the_single_value_sink_refuses_an_aws_session_and_says_why() {
    // The structural part. `SecretPort::lend` hands over one `&[u8]`, and its
    // only consumer in this tree builds a bearer `Authorization` header out of
    // it. An AWS session is three values that mean nothing apart, and one of
    // them is a session token. So the port refuses rather than converting, and
    // there is no conversion to add by accident.
    let (port, mints) = port_expiring_at(EXPIRES_AT);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut watcher = Watcher {
        calls: calls.clone(),
    };

    let outcome = port.lend("aws-prod", &mut watcher);
    match outcome {
        Err(SecretError::Unavailable(why)) => {
            assert!(
                why.contains("three values"),
                "the refusal does not explain: {why}"
            );
            assert!(
                why.contains("bearer"),
                "the refusal does not explain: {why}"
            );
        }
        other => panic!("an AWS session was served through the one-value sink: {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the sink was reached at all"
    );
    assert_eq!(
        mints.load(Ordering::SeqCst),
        0,
        "it even minted a session first"
    );
}

#[test]
fn printing_the_port_never_prints_a_session() {
    // `Debug` gets called by assertion failures, so a derived one on a type
    // holding sessions is a leak with a `{:?}` away from happening.
    let (port, _mints) = port_expiring_at(EXPIRES_AT);
    let mut sink = Recorded::default();
    port.lend_session("aws-prod", at(EXPIRES_AT - 3600), &mut sink)
        .expect("minted");
    let printed = format!("{port:?}");

    // The message here deliberately does not print what leaked: a diagnostic
    // that echoes a secret puts it in a test log, which is the habit this
    // module is written against.
    for secret in [SECRET, TOKEN] {
        assert!(!printed.contains(secret), "a session value reached Debug");
    }
    // And the listing describes the *cache*, so it names the credentials and not
    // the sessions behind them. Without this the two assertions above would be
    // defended somewhere else entirely -- `AwsSession` redacts its own `Debug`,
    // and that is R2.C.2.a's row, not this one -- so the row would read as if
    // this file were what kept the values out.
    for detail in [
        ACCESS_KEY,
        "arn:aws:iam::123456789012:role/demo",
        "asv-session",
    ] {
        assert!(
            !printed.contains(detail),
            "the cache listing leaked a session's own detail: {printed}"
        );
    }
    assert!(
        printed.contains("aws-prod"),
        "the receipt lost the credential id: {printed}"
    );
}

#[test]
fn a_failing_exchange_leaves_the_cache_alone() {
    // A failure must not destroy what was good. The obvious wrong
    // implementation is "clear the cache and start again", which turns one
    // unreachable STS into every credential re-minting at the same moment --
    // the failure amplifying itself.
    let (port, mints, failing) = port_that_can_fail();
    let now = at(EXPIRES_AT - 3600);

    let mut sink = Recorded::default();
    port.lend_session("aws-prod", now, &mut sink)
        .expect("minted");
    assert_eq!(mints.load(Ordering::SeqCst), 1);

    failing.store(true, Ordering::SeqCst);
    let mut sink = Recorded::default();
    assert!(
        port.lend_session("aws-staging", now, &mut sink).is_err(),
        "a failing exchange was reported as a lend"
    );
    assert_eq!(
        port.cached(),
        vec!["aws-prod".to_string()],
        "a failure changed the cache"
    );
    assert_eq!(
        sink.seen, 0,
        "a failed lend still handed values to the sink"
    );
}

#[test]
fn an_exchange_failure_does_not_buy_a_stale_session() {
    // The tempting fallback when STS is down is to serve whatever is cached,
    // margin or not: the caller asked for a credential and refusing is worse.
    // It is also exactly the failure the margin exists to prevent, and the
    // fallback converts a clean, local refusal into a signature AWS rejects
    // with a name that points somewhere else entirely. So a failure is a
    // failure, and this row is what says so.
    let (port, mints, failing) = port_that_can_fail();
    let margin = AwsSecretPort::DEFAULT_MARGIN;

    // Minted with an hour left, so the session is good and gets cached.
    let mut sink = Recorded::default();
    port.lend_session("aws-prod", at(EXPIRES_AT - 3600), &mut sink)
        .expect("minted");
    assert_eq!(mints.load(Ordering::SeqCst), 1);

    // Now the session is exactly inside the margin, so the cache may not serve
    // it -- and the exchange is down, so there is nothing to replace it with.
    failing.store(true, Ordering::SeqCst);
    let mut sink = Recorded::default();
    assert!(
        port.lend_session("aws-prod", at(EXPIRES_AT - margin.as_secs()), &mut sink)
            .is_err(),
        "an exchange failure served a session that was inside the margin"
    );
    assert_eq!(
        sink.seen, 0,
        "the stale session's values reached the sink anyway"
    );
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "a failing exchange was not attempted"
    );
}

/// The mutex is held only to read and write the map, so one slow exchange does
/// not put a different credential behind it. The alternative — holding the lock
/// across the exchange — is a lock held across a network call, and that is a
/// mutation this row has to be able to catch.
///
/// So the exchange is **held open** until the second lend has been answered, and
/// the row waits with a deadline rather than blocking: under the mutation the
/// second lend never returns, and a test that hangs is worse than one that
/// fails. The gate is released on the way out either way, so a failure here
/// costs a red row and not two threads stranded in the harness.
#[test]
fn the_cache_lock_is_not_held_across_an_exchange() {
    use std::sync::mpsc;
    use std::sync::Condvar;
    use std::time::Instant;

    /// A gate the exchange waits on, so the test decides when it returns.
    ///
    /// A `Condvar` rather than a channel because `SessionExchange` is `Sync` and
    /// `mpsc::Receiver` is not — the fixture has to satisfy the same bound the
    /// production exchange does, or it would be testing a shape nothing uses.
    struct Gate {
        open: Mutex<bool>,
        opened: Condvar,
    }

    impl Gate {
        fn wait(&self) {
            let mut open = self.open.lock().expect("the gate lock is free");
            while !*open {
                open = self.opened.wait(open).expect("the gate is not poisoned");
            }
        }

        fn release(&self) {
            *self.open.lock().expect("the gate lock is free") = true;
            self.opened.notify_all();
        }
    }

    struct Held {
        mints: Arc<AtomicUsize>,
        gate: Arc<Gate>,
    }

    impl SessionExchange for Held {
        fn exchange(
            &self,
            _credential: &str,
            _now: SystemTime,
        ) -> Result<AwsSession, asv_broker::aws::client::StsClientError> {
            // **Only the first exchange waits.** The first draft held every
            // exchange open, which meant the second thread blocked inside its
            // own exchange rather than behind the cache lock — a row that failed
            // on unmutated code and was measuring the fixture, not the port.
            let n = self.mints.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                self.gate.wait();
            }
            Ok(a_session())
        }
    }

    let deadline = Duration::from_secs(10);
    let mints = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Gate {
        open: Mutex::new(false),
        opened: Condvar::new(),
    });
    let port = Arc::new(AwsSecretPort::new(Arc::new(Held {
        mints: mints.clone(),
        gate: gate.clone(),
    })));

    // The first lend enters the exchange and stops there.
    let first = {
        let port = port.clone();
        std::thread::spawn(move || {
            let mut sink = Recorded::default();
            port.lend_session("aws-prod", at(EXPIRES_AT - 3600), &mut sink)
                .expect("minted");
        })
    };

    // Wait until the exchange is genuinely in flight, so the second lend races a
    // held exchange rather than an idle port.
    let entered = Instant::now();
    while mints.load(Ordering::SeqCst) == 0 {
        assert!(
            entered.elapsed() < deadline,
            "the first exchange never started"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // A different credential, answered while the first exchange is still in
    // flight. Under the mutation this is the thread that never returns.
    let (answered, answered_rx) = mpsc::channel();
    let second = {
        let port = port.clone();
        std::thread::spawn(move || {
            let mut sink = Recorded::default();
            port.lend_session("aws-staging", at(EXPIRES_AT - 3600), &mut sink)
                .expect("minted");
            answered.send(()).expect("the test is listening");
        })
    };

    let in_time = answered_rx.recv_timeout(deadline);
    gate.release();
    first.join().expect("the first exchange finished");
    second.join().expect("the second lend finished");

    assert!(
        in_time.is_ok(),
        "the second credential waited for the first exchange to return, so the \
         cache lock is held across the exchange"
    );
    assert_eq!(
        mints.load(Ordering::SeqCst),
        2,
        "a lend was served from an empty cache"
    );
}

/// A session the reader would have refused is not what the cache serves either:
/// the fixture goes through `parse_assume_role`, so a row that asserted a
/// hand-built session would be asserting a second definition of one.
#[test]
fn the_fixture_is_the_shape_the_reader_produces() {
    let session = a_session();
    assert_eq!(session.access_key_id, ACCESS_KEY);
    assert_eq!(session.expires_at, at(EXPIRES_AT));
    let mut sink = Recorded::default();
    session
        .with_signing_values(&mut sink)
        .expect("the fixture lends its three values");
    assert_eq!(sink.secret, SECRET);
    assert_eq!(sink.token, TOKEN);
}
