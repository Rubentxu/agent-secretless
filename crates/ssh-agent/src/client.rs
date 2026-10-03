//! The client half of the agent protocol, and the one proof issuer a session has.
//!
//! [`crate::AgentSession`] signs. Nothing in the tree could ask it to: the crate
//! had a server and no client, so the one party that needs a signature — a
//! session-local shim holding a `SSH_AUTH_SOCK` path and a destination — had no
//! way to get one. That is why every proof on the wire to date was assembled by
//! a test.
//!
//! [`AgentClient`] speaks the bounded 11/13 subset the agent actually serves and
//! nothing else. It is a client of [`crate::AgentSession`], not of OpenSSH: it
//! does not negotiate extensions, does not read `~/.ssh`, and does not fall back
//! to a key on disk if the socket is missing. A missing socket is an error, not
//! an occasion to find another identity — the whole point is that the session's
//! key is the only key that can say anything about that session.
//!
//! [`ProofIssuer`] is the answer to "who owns the counter". One session gets
//! one issuer, the issuer holds the only counter, and every proof it mints
//! spends a distinct value from an atomic. Two processes each starting their own
//! counter at 1 is the failure this type exists to make unrepresentable: the
//! replay window would refuse the second of two legitimate tunnels, which is a
//! denial of service wearing a security costume.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::proof::{proof_nonce, SessionProof};
use super::{AgentError, MAX_AGENT_MESSAGE};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const ED25519_ALGORITHM: &[u8] = b"ssh-ed25519";

/// The first counter a session spends.
///
/// One rather than zero so that "no counter yet" and "counter zero" cannot be
/// confused by a reader of the wire, and so a proof that has clearly been
/// through a real issuer does not look like an unset field.
const FIRST_COUNTER: u64 = 1;

/// A client of this crate's agent socket.
///
/// Cheap to build and holds no connection: every operation opens one, does its
/// exchange and closes. That costs a round trip to a Unix socket per signature,
/// which is nothing next to the CONNECT it is about to enable, and it means a
/// shim that has been idle for an hour has no half-dead stream to discover.
#[derive(Debug, Clone)]
pub struct AgentClient {
    socket: PathBuf,
}

impl AgentClient {
    /// Points the client at an agent socket. The path is not checked here: a
    /// client that cannot reach its agent must fail when it asks to sign, not
    /// when it is constructed, so the failure names the operation.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// The socket this client talks to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Lists the identities the agent is willing to sign with.
    ///
    /// This implementation serves exactly one, and asking is still the honest
    /// way to learn it: the blob is what the proof has to carry, and reading it
    /// off the wire is what keeps the client from restating the key format.
    pub fn identities(&self) -> Result<Vec<Vec<u8>>, AgentError> {
        let response = self.exchange(&[REQUEST_IDENTITIES])?;
        if response.first().copied() != Some(IDENTITIES_ANSWER) {
            return Err(AgentError::Malformed);
        }
        let mut cursor = Reader::new(&response[1..]);
        let count = cursor.u32()?;
        if count == 0 {
            return Err(AgentError::NoIdentities);
        }
        let mut blobs = Vec::with_capacity(count.min(8) as usize);
        for _ in 0..count {
            blobs.push(cursor.string()?);
            // Every identity is a blob *and* a comment. The first version of
            // this reader took the blob and then asserted the frame was
            // exhausted, which it never is, so every call failed with
            // `Malformed`. An in-process fake would have agreed with the
            // mistake, because the fake would have been written from the same
            // wrong reading of the format.
            let _comment = cursor.string()?;
        }
        if !cursor.done() {
            return Err(AgentError::Malformed);
        }
        Ok(blobs)
    }

    /// Asks the agent to sign `data` with the key named by `key_blob`.
    ///
    /// The blob is named rather than implied. A client that asked the agent
    /// "sign this" and took whatever came back would be trusting a socket path
    /// to tell it which identity it is; naming the key means a socket pointed
    /// somewhere else produces a signature the broker will refuse, rather than
    /// one it might accept.
    pub fn sign(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        if data.len() > MAX_AGENT_MESSAGE {
            return Err(AgentError::Malformed);
        }
        let mut payload = vec![SIGN_REQUEST];
        put_string(&mut payload, key_blob);
        put_string(&mut payload, data);
        payload.extend_from_slice(&0u32.to_be_bytes()); // flags: none supported

        let response = self.exchange(&payload)?;
        if response.first().copied() != Some(SIGN_RESPONSE) {
            // A refusal is a refusal, not a transport error, and the caller
            // has to be able to tell "the session said no" from "the socket is
            // gone" because only one of them is worth retrying.
            return Err(if response.first().copied() == Some(FAILURE) {
                AgentError::Refused
            } else {
                AgentError::Malformed
            });
        }
        let mut cursor = Reader::new(&response[1..]);
        let blob = cursor.string()?;
        if !cursor.done() {
            return Err(AgentError::Malformed);
        }
        let mut inner = Reader::new(&blob);
        let algorithm = inner.string()?;
        if algorithm != ED25519_ALGORITHM {
            return Err(AgentError::Unsupported);
        }
        let signature = inner.string()?;
        if !inner.done() {
            return Err(AgentError::Malformed);
        }
        Ok(signature)
    }

    fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mut stream = UnixStream::connect(&self.socket)?;
        write_frame(&mut stream, payload)?;
        read_frame(&mut stream)
    }
}

/// The single proof issuer for one session.
///
/// Holds the session's key blob and the only counter that session spends. It is
/// `Sync` because the shim serves many CONNECT requests at once and every one of
/// them needs a distinct counter; the atomic is what makes that true without a
/// lock around the whole issue path.
#[derive(Debug, Clone)]
pub struct ProofIssuer {
    client: AgentClient,
    key_blob: Vec<u8>,
    counter: std::sync::Arc<AtomicU64>,
}

impl ProofIssuer {
    /// Binds an issuer to a session's agent.
    ///
    /// Takes the key blob from the agent rather than from the caller, because
    /// the agent is the authority on which key it signs with and the caller is
    /// not. A client that passed its own blob in would be able to ask for a
    /// signature it then mislabelled, and the failure would surface as a
    /// confusing refusal at the broker instead of here.
    pub fn discover(client: AgentClient) -> Result<Self, AgentError> {
        let mut blobs = client.identities()?;
        if blobs.len() != 1 {
            // This agent serves exactly one identity. More than one means the
            // socket belongs to something else, and picking the first would be
            // choosing a key on no evidence.
            return Err(AgentError::Unsupported);
        }
        let key_blob = blobs.remove(0);
        Ok(Self {
            client,
            key_blob,
            counter: std::sync::Arc::new(AtomicU64::new(FIRST_COUNTER)),
        })
    }

    /// The key blob every proof from this issuer carries.
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    /// Mints one proof for one destination.
    ///
    /// The counter is spent *before* the signature is requested, and a failure
    /// to sign does not give it back. That is deliberate and it is the same
    /// choice the broker makes: a counter that could be reused after a failed
    /// signing is a counter an attacker can advance by making the agent slow.
    /// The window is 128 wide, so a few lost counters cost nothing, and a
    /// *spendable* counter that can be walked backwards costs the property the
    /// counter exists to provide.
    pub fn issue(&self, host: &str, port: u16) -> Result<SessionProof, AgentError> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let signature = self.client.sign(
            &self.key_blob,
            &proof_nonce(&self.key_blob, host, port, counter),
        )?;
        Ok(SessionProof {
            key: self.key_blob.clone(),
            signature,
            counter,
        })
    }

    /// The counter this issuer will spend next.
    ///
    /// Exposed for tests and for the shim's shutdown accounting. Reading it is
    /// not a way to influence anything: the value it reports is already gone
    /// the moment a concurrent `issue` runs.
    pub fn next_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<(), AgentError> {
    if payload.is_empty() || payload.len() > MAX_AGENT_MESSAGE {
        return Err(AgentError::Malformed);
    }
    use std::io::Write;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, AgentError> {
    use std::io::Read;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let size = u32::from_be_bytes(len) as usize;
    // The same bound the server enforces, and for the same reason: this reads
    // a length from a socket and must not turn it into an allocation.
    if size == 0 || size > MAX_AGENT_MESSAGE {
        return Err(AgentError::Malformed);
    }
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// A strict reader over one response.
///
/// Fails on anything left over, which is the property that makes a reordering
/// or an extension visible here instead of as a signature that verifies against
/// bytes nobody meant to sign.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn done(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn u32(&mut self) -> Result<u32, AgentError> {
        let end = self.position.checked_add(4).ok_or(AgentError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentError::Malformed)?;
        self.position = end;
        Ok(u32::from_be_bytes(
            bytes.try_into().map_err(|_| AgentError::Malformed)?,
        ))
    }

    fn string(&mut self) -> Result<Vec<u8>, AgentError> {
        let len = self.u32()? as usize;
        let end = self
            .position
            .checked_add(len)
            .ok_or(AgentError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentError::Malformed)?;
        self.position = end;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_proof;
    use crate::{proof_nonce, AgentSession};
    use std::sync::Mutex;

    /// A real agent on a real socket. Every test here goes through the Unix
    /// socket, because a fake would let a framing bug pass: the thing being
    /// tested is that two halves of this crate agree across a length-prefixed
    /// frame, and a shared in-process buffer is exactly the thing that would
    /// agree while the wire did not.
    struct Fixture {
        session: AgentSession,
        // Held so the socket's parent directory outlives the session. Never
        // read, and named so that "unused" does not read as "forgot to remove".
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let session = AgentSession::start(dir.path().join("session")).expect("start");
            Self { session, _dir: dir }
        }

        fn client(&self) -> AgentClient {
            AgentClient::new(self.session.socket_path())
        }

        fn revoke(&mut self) {
            self.session.revoke().expect("revoke");
        }
    }

    #[test]
    fn the_client_reads_the_agents_only_identity() {
        let f = Fixture::new();
        let blobs = f.client().identities().expect("identities");
        assert_eq!(blobs, vec![f.session.public_key_blob()]);
    }

    #[test]
    fn a_minted_proof_verifies_against_the_nonce_the_broker_will_derive() {
        let f = Fixture::new();
        let issuer = ProofIssuer::discover(f.client()).expect("discover");
        let (host, port) = ("api.example.com", 443u16);

        let proof = issuer.issue(host, port).expect("issue");
        assert_eq!(proof.key, f.session.public_key_blob());

        // Exactly what `asv_broker::tls_bridge::proof_nonce` computes, through
        // the shared definition both sides call.
        let nonce = proof_nonce(&proof.key, host, port, proof.counter);
        assert!(verify_proof(&proof.key, &nonce, &proof.signature));
    }

    #[test]
    fn a_proof_is_refused_for_a_destination_it_was_not_minted_for() {
        let f = Fixture::new();
        let issuer = ProofIssuer::discover(f.client()).expect("discover");
        let proof = issuer.issue("api.example.com", 443).expect("issue");

        // The positive half comes first, and it is the half that gives the
        // negative half its meaning. This test was originally only negatives —
        // "this signature does not verify there" — and a signature over the
        // wrong nonce does not verify *anywhere*, so every one of them held
        // for a completely broken issuer. Asserting that the proof does verify
        // for the destination it was minted for is what makes the refusals
        // mean something.
        let own = proof_nonce(&proof.key, "api.example.com", 443, proof.counter);
        assert!(verify_proof(&proof.key, &own, &proof.signature));

        let elsewhere = proof_nonce(&proof.key, "evil.example.net", 443, proof.counter);
        assert!(!verify_proof(&proof.key, &elsewhere, &proof.signature));

        let other_port = proof_nonce(&proof.key, "api.example.com", 8443, proof.counter);
        assert!(!verify_proof(&proof.key, &other_port, &proof.signature));
    }

    /// The counter is the property this type exists for, so the test is about
    /// the *set* of counters, not about a pair of consecutive numbers. Checking
    /// adjacency would pass for an issuer that handed out 1, 2, 3 while two
    /// callers raced, and a duplicate is the whole failure.
    #[test]
    fn every_proof_spends_a_distinct_counter() {
        let f = Fixture::new();
        let issuer = ProofIssuer::discover(f.client()).expect("discover");
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let proof = issuer.issue("api.example.com", 443).expect("issue");
            assert!(
                seen.insert(proof.counter),
                "counter {} was spent twice",
                proof.counter
            );
        }
        assert_eq!(seen.len(), 64);
    }

    /// Two issuers for one session would be the bug this design exists to
    /// prevent, so it is worth showing the counter is per-issuer and that a
    /// caller can notice a second one rather than silently splitting the space.
    #[test]
    fn a_second_issuer_starts_its_own_counter_and_that_is_visible() {
        let f = Fixture::new();
        let first = ProofIssuer::discover(f.client()).expect("discover");
        let second = ProofIssuer::discover(f.client()).expect("discover");

        first.issue("api.example.com", 443).expect("issue");
        // A second issuer is constructible, and it restarts at the same place.
        // That is why the shim holds exactly one, and why `next_counter`
        // exists: the duplication is observable instead of silent.
        assert_eq!(second.next_counter(), 1);
        assert_eq!(first.next_counter(), 2);
    }

    #[test]
    fn concurrent_issuers_never_repeat_a_counter() {
        let f = Fixture::new();
        let issuer = ProofIssuer::discover(f.client()).expect("discover");
        let counters: Mutex<Vec<u64>> = Mutex::new(Vec::new());

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let issuer = issuer.clone();
                let counters = &counters;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    for _ in 0..8 {
                        mine.push(issuer.issue("api.example.com", 443).expect("issue").counter);
                    }
                    counters.lock().expect("lock").extend(mine);
                });
            }
        });

        let mut all = counters.into_inner().expect("counters");
        assert_eq!(all.len(), 64);
        all.sort_unstable();
        let unique = {
            let before = all.len();
            all.dedup();
            before - all.len()
        };
        assert_eq!(unique, 0, "a counter was spent twice under concurrency");
    }

    #[test]
    fn a_revoked_session_stops_signing_and_says_so() {
        let f = Fixture::new();
        let socket = f.session.socket_path().to_path_buf();
        let client = AgentClient::new(&socket);
        let key = f.session.public_key_blob();
        client.sign(&key, b"before").expect("signs while live");

        let mut f = f;
        f.revoke();

        // The socket is gone, so this is an I/O failure, not a refusal — and
        // the difference is the whole reason `Refused` is its own variant.
        let err = AgentClient::new(&socket)
            .sign(&key, b"after")
            .expect_err("a revoked session must not sign");
        assert!(matches!(err, AgentError::Io(_)), "got {err:?}");
    }

    #[test]
    fn a_socket_that_is_not_there_is_an_io_error_not_a_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = AgentClient::new(dir.path().join("absent.sock"));
        let err = client.identities().expect_err("no agent, no identities");
        assert!(matches!(err, AgentError::Io(_)), "got {err:?}");
    }

    #[test]
    fn a_socket_pointed_at_something_else_cannot_mint_a_proof() {
        // Two sessions: the proof is minted by one and checked against the
        // other's key. This is the shape of a hijacked `SSH_AUTH_SOCK`, and it
        // has to die at the broker, which is why the issuer takes its blob from
        // the agent rather than being told which key to claim.
        let honest = Fixture::new();
        let rogue = Fixture::new();
        let issuer = ProofIssuer::discover(rogue.client()).expect("discover");
        let proof = issuer.issue("api.example.com", 443).expect("issue");

        let nonce = proof_nonce(&proof.key, "api.example.com", 443, proof.counter);
        // It verifies — over the rogue key, which is its own.
        assert!(verify_proof(&proof.key, &nonce, &proof.signature));
        // And not over the session the broker registered.
        assert!(!verify_proof(
            &honest.session.public_key_blob(),
            &nonce,
            &proof.signature
        ));
    }

    #[test]
    fn a_failed_signing_still_spends_its_counter() {
        // A counter that came back after a failed signing is a counter an
        // attacker can walk backwards by making the agent slow: the shim
        // retries, the agent refuses, and the window remembers nothing. The
        // window is 128 wide, so a few lost counters cost nothing — a
        // *reusable* counter costs the property it exists to provide.
        let mut f = Fixture::new();
        let issuer = ProofIssuer::discover(f.client()).expect("discover");
        issuer.issue("api.example.com", 443).expect("issue");
        assert_eq!(issuer.next_counter(), 2);

        f.revoke();
        let err = issuer
            .issue("api.example.com", 443)
            .expect_err("a revoked session signs nothing");
        assert!(matches!(err, AgentError::Io(_)), "got {err:?}");

        // Spent, not returned.
        assert_eq!(issuer.next_counter(), 3);
    }

    #[test]
    fn a_wrong_key_blob_is_refused_by_the_agent() {
        let f = Fixture::new();
        let other = crate::public_key_blob(
            &ed25519_dalek::VerifyingKey::from_bytes(&[3u8; 32]).expect("valid key"),
        );
        let err = f
            .client()
            .sign(&other, b"payload")
            .expect_err("a key this session does not hold must not be signed");
        assert!(matches!(err, AgentError::Refused), "got {err:?}");
    }

    /// The socket in this test does not exist.
    ///
    /// The first version pointed at a live agent, which made the test pass for
    /// the wrong reason: the size is refused by `sign` *and* independently by
    /// the frame writer, so deleting the first check changed nothing that was
    /// observable. Against an absent socket the layers separate — a refusal
    /// before connecting is `Malformed`, and a check that was deleted becomes
    /// `Io`. A control that exists twice is only pinned by naming which copy
    /// is under test.
    #[test]
    fn an_unbounded_payload_is_refused_before_it_is_sent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = AgentClient::new(dir.path().join("absent.sock"));
        let huge = vec![0u8; MAX_AGENT_MESSAGE + 1];
        let err = client
            .sign(&[0u8; 32], &huge)
            .expect_err("oversized data must not be framed");
        assert!(
            matches!(err, AgentError::Malformed),
            "the size must be refused before any connection is attempted, got {err:?}"
        );
    }
}

/// Tests against an agent that misbehaves.
///
/// A real [`AgentSession`] cannot produce a wrong algorithm name, two
/// identities, a truncated frame or a length field that lies, so those are the
/// client's failure modes and testing them needs something that is willing to
/// send them. That is not the same as the fake the module doc warns about: a
/// fake that *agrees* with a misreading of the format hides a bug, while a fake
/// that *attacks* the client is the only way to reach the code that refuses.
#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::MAX_AGENT_MESSAGE;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// Serves one canned response per connection, then drops the socket.
    struct RawAgent {
        path: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl RawAgent {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("raw.sock");
            let listener = UnixListener::bind(&path).expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            std::thread::spawn(move || {
                for response in responses {
                    // Spin briefly so the client's connect cannot be refused
                    // before the listener is polled.
                    for _ in 0..2000 {
                        if let Ok((mut stream, _)) = listener.accept() {
                            use std::io::{Read, Write};
                            let mut len = [0u8; 4];
                            let _ = stream.read_exact(&mut len);
                            let size = u32::from_be_bytes(len) as usize;
                            let mut body = vec![0u8; size.min(MAX_AGENT_MESSAGE)];
                            let _ = stream.read_exact(&mut body);
                            let framed = (response.len() as u32).to_be_bytes().to_vec();
                            let mut out = framed;
                            out.extend_from_slice(&response);
                            let _ = stream.write_all(&out);
                            let _ = stream.flush();
                            break;
                        }
                        std::thread::yield_now();
                    }
                }
            });
            Self { path, _dir: dir }
        }

        fn client(&self) -> AgentClient {
            AgentClient::new(&self.path)
        }
    }

    fn u32le(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32le(bytes.len() as u32);
        out.extend_from_slice(bytes);
        out
    }

    const BLOB: &[u8] = b"ssh-ed25519";

    #[test]
    fn a_signature_blob_naming_another_algorithm_is_refused() {
        // The agent says it signed with something that is not Ed25519. The
        // client must not hand those 64 bytes on as if they were a signature;
        // `verify_proof` would reject them later, at the broker, as a mystery.
        let mut response = vec![SIGN_RESPONSE];
        let mut blob = string(b"ssh-rsa");
        blob.extend_from_slice(&string(&[0u8; 64]));
        response.extend_from_slice(&string(&blob));

        let agent = RawAgent::new(vec![response]);
        let err = agent
            .client()
            .sign(BLOB, b"payload")
            .expect_err("another algorithm is not this crate's");
        assert!(matches!(err, AgentError::Unsupported), "got {err:?}");
    }

    #[test]
    fn a_response_with_trailing_bytes_is_refused() {
        // A signature blob followed by junk. Strictness here is what makes a
        // reordered or extended response visible at the client instead of as a
        // signature over bytes nobody meant to sign.
        let mut response = vec![SIGN_RESPONSE];
        let mut blob = string(BLOB);
        blob.extend_from_slice(&string(&[7u8; 64]));
        blob.extend_from_slice(b"extra");
        response.extend_from_slice(&string(&blob));

        let agent = RawAgent::new(vec![response]);
        let err = agent
            .client()
            .sign(BLOB, b"payload")
            .expect_err("trailing bytes are not a signature");
        assert!(matches!(err, AgentError::Malformed), "got {err:?}");
    }

    #[test]
    fn two_identities_are_refused_rather_than_one_being_picked() {
        // Picking the first of two would be choosing a key on no evidence, and
        // the shim has no way to tell afterwards which one it got.
        let mut two = vec![IDENTITIES_ANSWER];
        two.extend_from_slice(&u32le(2));
        for tag in [1u8, 2u8] {
            two.extend_from_slice(&string(&[tag; 32]));
            two.extend_from_slice(&string(b"comment"));
        }

        // The reader is faithful — it reports both. The *policy* that this
        // crate's agent serves exactly one identity belongs to `discover`,
        // and this test originally aimed at the reader, which was the wrong
        // layer: a reader that refused a well-formed response would be the
        // bug.
        let reader = RawAgent::new(vec![two.clone()]);
        assert_eq!(reader.client().identities().expect("well formed").len(), 2);

        let agent = RawAgent::new(vec![two]);
        let err = ProofIssuer::discover(agent.client())
            .expect_err("two identities is not one session's agent");
        assert!(matches!(err, AgentError::Unsupported), "got {err:?}");
    }

    #[test]
    fn an_agent_with_no_identities_is_refused() {
        let mut response = vec![IDENTITIES_ANSWER];
        response.extend_from_slice(&u32le(0));

        let agent = RawAgent::new(vec![response]);
        let err = agent
            .client()
            .identities()
            .expect_err("no identities is not a usable session");
        assert!(matches!(err, AgentError::NoIdentities), "got {err:?}");
    }

    #[test]
    fn a_frame_claiming_more_than_the_bound_is_refused() {
        // A length field read off a socket must never become an allocation.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("liar.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = stream.write_all(&u32::MAX.to_be_bytes());
                let _ = stream.flush();
                // Hold the connection so the read fails on the bound rather
                // than on an EOF that would look like a short frame.
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });

        let err = AgentClient::new(&path)
            .identities()
            .expect_err("a frame larger than the bound is refused");
        assert!(matches!(err, AgentError::Malformed), "got {err:?}");
    }

    #[test]
    fn a_refusal_is_distinguishable_from_a_missing_socket() {
        let response = vec![FAILURE];
        let agent = RawAgent::new(vec![response]);
        let refused = agent
            .client()
            .sign(BLOB, b"payload")
            .expect_err("the agent said no");
        assert!(matches!(refused, AgentError::Refused), "got {refused:?}");

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = AgentClient::new(dir.path().join("absent.sock"))
            .sign(BLOB, b"payload")
            .expect_err("no socket at all");
        assert!(
            !matches!(missing, AgentError::Refused),
            "a missing socket must not be reported as a refusal: {missing:?}"
        );
    }
}
