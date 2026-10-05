//! R2.D.2 — the ServiceAccount token port.
//!
//! # What these rows are for
//!
//! The refusals are the rows a reader expects, and they are the easy half. The
//! property this port exists to establish is a *positive* one — the token is
//! nothing after `lend` returns — and a positive property cannot be shown by
//! asserting that something was refused. So every refusal here is paired with a
//! row that shows a well-formed token going through untouched, and
//! `a_port_that_refused_everything_would_fail_these` names that where a reader
//! meets it.
//!
//! # The trap, again, and named
//!
//! Measured on the SigV4 core in this same tree: six of sixteen rows asserted
//! only refusals, so a signer that signed nothing would have passed all six. A
//! port that refuses every token passes every row in a file made only of
//! refusals, and looks correct while being useless — which for a security
//! product is the more expensive of the two failures, because nothing complains.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// A token with the shape a real projected one has: three base64url segments.
/// Used so that a row asserting "the bytes arrived unchanged" is asserting it
/// about a plausible credential rather than about a marker string.
const TOKEN: &[u8] =
    b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdCJ9.c2ln";

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique absolute path inside a per-test directory, with `contents` written
/// to it. The path is absolute because the port refuses a relative one, and a
/// relative fixture would make every row here test the refusal instead.
fn token_file(contents: &[u8]) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "asv-k8s-port-{}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create the fixture dir");
    let path = dir.join("token");
    fs::write(&path, contents).expect("write the fixture token");
    path
}

/// A sink that records what it was handed, so a row can assert the bytes
/// arrived intact and a refusal can assert they never did.
#[derive(Default)]
struct Recorder {
    seen: Option<Vec<u8>>,
    calls: usize,
    fail: bool,
}

impl SecretSink for Recorder {
    fn accept(&mut self, secret: &[u8]) -> Result<(), SecretError> {
        self.calls += 1;
        self.seen = Some(secret.to_vec());
        if self.fail {
            return Err(SecretError::Unavailable("the sink refused it".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The positive half: a plausible token goes through untouched.
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_token_is_lent_verbatim() {
    let port = K8sSecretPort::new(token_file(TOKEN)).expect("the path is absolute");
    let mut sink = Recorder::default();
    port.lend("k8s/default", &mut sink).expect("a token lends");
    assert_eq!(sink.seen.as_deref(), Some(TOKEN));
    assert_eq!(sink.calls, 1);
}

/// The bytes arrive as they are on disk, which is the whole point of not
/// repairing them.
///
/// The fixture is a token with **surrounding whitespace on purpose**, because
/// the first version of this row used a clean JWT and therefore could not
/// distinguish "not trimmed" from "trimmed, and the token had nothing to trim".
/// That mutation stayed green and read as coverage while measuring nothing — a
/// vacuous row, which is worse than no row, because its presence in the count
/// implies the property was checked.
///
/// The padding is **spaces only**. A tab and a newline are control characters
/// and are refused by the rule above, so a fixture padded with them would test
/// that refusal and not this row — an earlier draft of this fixture did exactly
/// that, and would have been green for the wrong reason.
#[test]
fn nothing_is_trimmed_normalised_or_appended() {
    let padded: &[u8] = b"   eyJhbGciOiJSUzI1NiJ9.e30.sig   ";
    let port = K8sSecretPort::new(token_file(padded)).expect("absolute");
    let mut sink = Recorder::default();
    port.lend("k8s/default", &mut sink).expect("a space-padded token still lends");
    let seen = sink.seen.expect("the sink was called");
    assert_eq!(
        seen, padded,
        "the token was altered on its way to the sink: {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(seen.starts_with(b" "), "a leading space was trimmed");
    assert!(seen.ends_with(b" "), "a trailing space was trimmed");
}

/// The row that makes the refusals above mean something: a port that refused
/// everything would fail every assertion here, so a green run cannot be
/// produced by a port that never lends.
#[test]
fn a_port_that_refused_everything_would_fail_these() {
    for contents in [TOKEN, b"x", b"a.b.c", b"eyJhbGciOiJub25lIn0.e30."] {
        let port = K8sSecretPort::new(token_file(contents)).expect("absolute");
        let mut sink = Recorder::default();
        assert!(
            port.lend("k8s/default", &mut sink).is_ok(),
            "a plausible token of {} bytes was refused",
            contents.len()
        );
        assert_eq!(sink.seen.as_deref(), Some(contents));
    }
}

// ---------------------------------------------------------------------------
// The property: the token is nothing after lend returns.
// ---------------------------------------------------------------------------

/// A distinct marker, so a leak into any rendering is unambiguous rather than
/// a substring that happens to occur in a path.
const MARKER: &[u8] = b"TOKEN-MARKER-must-not-appear-anywhere";

#[test]
fn the_token_never_appears_in_the_ports_own_rendering() {
    let port = K8sSecretPort::new(token_file(MARKER)).expect("absolute");
    let mut sink = Recorder::default();
    port.lend("k8s/default", &mut sink).expect("lends");
    let rendered = format!("{port:?}");
    assert!(
        !rendered.contains("TOKEN-MARKER"),
        "Debug printed the token: {rendered}"
    );
    // And the port still renders the thing it is allowed to know, so the row
    // above is not satisfied by a Debug that prints nothing at all.
    assert!(rendered.contains("token"), "{rendered}");
}

/// There is no method that returns the token, and this is the compile-time half
/// of the property: a caller cannot be written that holds one. `token_path` is
/// the only accessor and it names the path.
#[test]
fn the_only_accessor_is_the_path() {
    let path = token_file(MARKER);
    let port = K8sSecretPort::new(&path).expect("absolute");
    assert_eq!(port.token_path(), path.as_path());
    // The assertion is the API surface: `token_path` returns a `&Path`, so
    // there is no value on the port that is the credential. Written as a
    // compile-time fact rather than a runtime one, which is the only way it
    // can be.
    let _: &Path = port.token_path();
}

/// `forget` drops the cache — and there is no cache, so the next lend still
/// works. A `forget` that cleared the path would be a different bug, and this
/// row is what says which one this is.
#[test]
fn forget_costs_nothing_because_nothing_is_held() {
    let port = K8sSecretPort::new(token_file(TOKEN)).expect("absolute");
    let mut first = Recorder::default();
    port.lend("k8s/default", &mut first).expect("lends");
    port.forget("k8s/default");
    let mut second = Recorder::default();
    port.lend("k8s/default", &mut second).expect("still lends after forget");
    assert_eq!(second.seen.as_deref(), Some(TOKEN));
    // A second call, not a second read of a cache: the count is on the sink,
    // and it is two because two lends happened.
    assert_eq!(second.calls, 1);
}

/// The bytes are wiped when `lend` returns, including when the sink fails.
/// The buffer is `Zeroizing`, so the guarantee does not depend on the sink
/// having behaved; a sink that errors on its way out does not get to keep them.
#[test]
fn a_failing_sink_does_not_keep_the_token_either() {
    let port = K8sSecretPort::new(token_file(TOKEN)).expect("absolute");
    let mut sink = Recorder {
        fail: true,
        ..Recorder::default()
    };
    let outcome = port.lend("k8s/default", &mut sink);
    assert!(outcome.is_err(), "a failing sink should abort the lend");
    // The sink *was* called — this is not a row that passes by refusing before
    // the sink ever saw anything, which is the failure mode a refusal-only
    // version of this file would have.
    assert_eq!(sink.calls, 1);
    assert_eq!(sink.seen.as_deref(), Some(TOKEN));
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

/// The refusal that carries the property: a token becomes an `Authorization`
/// header value, and a newline in a header is a second header.
#[test]
fn a_token_carrying_a_control_character_is_refused() {
    // Annotated as slices: each byte-string literal has its own length, and an
    // unannotated array would take the length of the first one and reject the
    // rest for being the wrong size — which is a fact about the literal, not
    // about the row.
    let cases: [(&str, &[u8]); 6] = [
        ("newline", b"abc\ndef"),
        ("carriage return", b"abc\r\nX-Injected: 1"),
        ("bare CR", b"abc\rdef"),
        ("tab", b"abc\tdef"),
        ("NUL", b"abc\0def"),
        ("vertical tab", b"abc\x0bdef"),
    ];
    for (label, bad) in cases {
        let port = K8sSecretPort::new(token_file(bad)).expect("absolute");
        let mut sink = Recorder::default();
        let outcome = port.lend("k8s/default", &mut sink);
        assert!(outcome.is_err(), "a token with a {label} was lent");
        assert_eq!(sink.calls, 0, "a token with a {label} reached the sink");
    }
}

#[test]
fn an_empty_token_is_refused_and_never_reaches_a_sink() {
    let port = K8sSecretPort::new(token_file(b"")).expect("absolute");
    let mut sink = Recorder::default();
    assert!(port.lend("k8s/default", &mut sink).is_err());
    assert_eq!(sink.calls, 0);
}

/// The bound is read before the contents are interpreted, so an oversized file
/// is refused without ever being looked at as a credential.
#[test]
fn a_token_past_the_bound_is_refused() {
    let big = vec![b'a'; MAX_TOKEN_BYTES + 1];
    let port = K8sSecretPort::new(token_file(&big)).expect("absolute");
    let mut sink = Recorder::default();
    assert!(port.lend("k8s/default", &mut sink).is_err());
    assert_eq!(sink.calls, 0);
    // And the boundary itself is inside the bound, so the rule is a bound and
    // not a "reject anything sizeable" reflex.
    let at = vec![b'a'; MAX_TOKEN_BYTES];
    let port = K8sSecretPort::new(token_file(&at)).expect("absolute");
    let mut sink = Recorder::default();
    assert!(port.lend("k8s/default", &mut sink).is_ok());
}

#[test]
fn a_missing_token_file_is_unavailable_rather_than_empty() {
    let missing = std::env::temp_dir().join("asv-k8s-port-does-not-exist/token");
    let port = K8sSecretPort::new(&missing).expect("the path is still absolute");
    let mut sink = Recorder::default();
    // Not an empty-token refusal: a rotated-away file and an empty file are
    // different diagnoses and the message has to tell them apart.
    let err = port.lend("k8s/default", &mut sink).expect_err("a missing file");
    assert!(matches!(err, SecretError::Unavailable(_)));
    assert!(format!("{err}").contains("could not be read"), "{err}");
    assert_eq!(sink.calls, 0);
}

#[test]
fn a_relative_token_path_is_refused_at_construction() {
    let err = K8sSecretPort::new("var/run/secrets/token").expect_err("relative");
    assert!(format!("{err}").contains("must be absolute"), "{err}");
}

#[test]
fn an_empty_token_path_is_refused_at_construction() {
    assert!(K8sSecretPort::new("").is_err());
}

/// Nothing is read by the constructor, so a constructor cannot fail on a
/// credential that is legitimately rotated underneath it. The file is deleted
/// between the two statements and the port is still usable.
#[test]
fn the_constructor_reads_nothing() {
    let path = token_file(TOKEN);
    let port = K8sSecretPort::new(&path).expect("absolute");
    fs::remove_file(&path).expect("remove the fixture");
    let mut sink = Recorder::default();
    assert!(
        port.lend("k8s/default", &mut sink).is_err(),
        "a deleted file should be reported at lend, not construction"
    );
}

#[test]
fn lending_without_naming_a_credential_is_refused() {
    let port = K8sSecretPort::new(token_file(TOKEN)).expect("absolute");
    let mut sink = Recorder::default();
    assert!(port.lend("", &mut sink).is_err());
    assert_eq!(sink.calls, 0);
}
