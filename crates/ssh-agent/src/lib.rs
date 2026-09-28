//! Broker-owned SSH-agent-compatible signing for M2.
//!
//! The private key never crosses this crate's socket boundary. The wire
//! protocol exposes only a public Ed25519 key and signatures. The supported
//! subset is deliberately small and bounded:
//!
//! - request identities (11) → identities answer (12)
//! - sign request (13) → sign response (14)
//!
//! Every other message is rejected. This is an authorization boundary, not a
//! general-purpose SSH-agent implementation.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use zeroize::Zeroize;

/// Maximum SSH-agent payload accepted by this implementation.
pub const MAX_AGENT_MESSAGE: usize = 64 * 1024;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const ED25519_ALGORITHM: &[u8] = b"ssh-ed25519";

/// Errors from the bounded agent protocol.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Socket or frame I/O failed.
    #[error("agent io error: {0}")]
    Io(#[from] io::Error),
    /// The message did not satisfy the bounded protocol grammar.
    #[error("malformed agent message")]
    Malformed,
    /// Unsupported message type or flags.
    #[error("unsupported agent operation")]
    Unsupported,
    /// The key blob does not identify this session's public key.
    #[error("key is not bound to this session")]
    WrongKey,
    /// The session has been revoked.
    #[error("session revoked")]
    Revoked,
}

/// A broker-owned Ed25519 signer bound to one local session.
pub struct AgentSession {
    socket_path: PathBuf,
    signing_key: Arc<SigningKey>,
    revoked: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for AgentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSession")
            .field("socket_path", &self.socket_path)
            .field("revoked", &self.revoked.load(Ordering::Acquire))
            .finish()
    }
}

impl AgentSession {
    /// Creates a session with a fresh OS-random Ed25519 key and starts its
    /// owner-only Unix socket. The key exists only in the broker process.
    pub fn start(base_dir: impl AsRef<Path>) -> Result<Self, AgentError> {
        let base = base_dir.as_ref();
        std::fs::create_dir_all(base)?;
        restrict_dir(base)?;

        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing_key = Arc::new(SigningKey::from_bytes(&seed));
        seed.zeroize();

        let socket_path = base.join("ssh-agent.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        restrict_socket(&socket_path)?;

        let revoked = Arc::new(AtomicBool::new(false));
        let thread_key = Arc::clone(&signing_key);
        let thread_revoked = Arc::clone(&revoked);
        let listener_thread = thread::Builder::new()
            .name("asv-ssh-agent".into())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if thread_revoked.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = incoming else { continue };
                    let key = Arc::clone(&thread_key);
                    let dead = Arc::clone(&thread_revoked);
                    thread::spawn(move || {
                        let _ = serve_connection(stream, key, dead);
                    });
                }
            })
            .map_err(AgentError::Io)?;

        Ok(Self {
            socket_path,
            signing_key,
            revoked,
            listener_thread: Some(listener_thread),
        })
    }

    /// Socket path to put in `SSH_AUTH_SOCK`.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Public key blob in the SSH wire format. It contains no private bytes.
    pub fn public_key_blob(&self) -> Vec<u8> {
        public_key_blob(self.signing_key.verifying_key())
    }

    /// Revokes the session, closes the listener and removes the socket.
    pub fn revoke(&mut self) -> Result<(), AgentError> {
        self.revoked.store(true, Ordering::Release);
        // Connecting wakes an accept blocked on the listener so the thread can
        // observe the revocation flag and exit.
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(thread) = self.listener_thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        Ok(())
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

fn serve_connection(
    mut stream: UnixStream,
    key: Arc<SigningKey>,
    revoked: Arc<AtomicBool>,
) -> Result<(), AgentError> {
    loop {
        let payload = match read_frame(&mut stream) {
            Ok(payload) => payload,
            Err(AgentError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let response = if revoked.load(Ordering::Acquire) {
            failure_response()
        } else {
            handle_message(&payload, &key, &revoked)
        };
        write_frame(&mut stream, &response)?;
    }
}

/// Handles one unframed SSH-agent payload. Public for deterministic protocol
/// tests and for the broker's future async transport adapter.
pub fn handle_message(payload: &[u8], key: &SigningKey, revoked: &AtomicBool) -> Vec<u8> {
    if revoked.load(Ordering::Acquire) {
        return failure_response();
    }
    match payload.first().copied() {
        Some(REQUEST_IDENTITIES) if payload.len() == 1 => identities_response(key.verifying_key()),
        Some(SIGN_REQUEST) => sign_request(payload, key).unwrap_or_else(|_| failure_response()),
        _ => failure_response(),
    }
}

fn identities_response(verifying: VerifyingKey) -> Vec<u8> {
    let key_blob = public_key_blob(verifying);
    let mut out = vec![IDENTITIES_ANSWER];
    put_u32(&mut out, 1);
    put_string(&mut out, &key_blob);
    put_string(&mut out, b"asv-session-ed25519");
    out
}

fn sign_request(payload: &[u8], key: &SigningKey) -> Result<Vec<u8>, AgentError> {
    let mut cursor = Cursor::new(&payload[1..]);
    let key_blob = cursor.string()?;
    let data = cursor.string()?;
    let flags = cursor.u32()?;
    if flags != 0 || !cursor.done() {
        return Err(AgentError::Unsupported);
    }
    if key_blob != public_key_blob(key.verifying_key()) {
        return Err(AgentError::WrongKey);
    }

    let signature = key.sign(&data);
    let mut signature_blob = Vec::with_capacity(4 + ED25519_ALGORITHM.len() + 4 + 64);
    put_string(&mut signature_blob, ED25519_ALGORITHM);
    put_string(&mut signature_blob, &signature.to_bytes());

    let mut out = vec![SIGN_RESPONSE];
    put_string(&mut out, &signature_blob);
    Ok(out)
}

fn public_key_blob(key: VerifyingKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ED25519_ALGORITHM.len() + 4 + 32);
    put_string(&mut out, ED25519_ALGORITHM);
    put_string(&mut out, key.as_bytes());
    out
}

fn failure_response() -> Vec<u8> {
    vec![FAILURE]
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, AgentError> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let size = u32::from_be_bytes(len) as usize;
    if size == 0 || size > MAX_AGENT_MESSAGE {
        return Err(AgentError::Malformed);
    }
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<(), AgentError> {
    if payload.len() > MAX_AGENT_MESSAGE {
        return Err(AgentError::Malformed);
    }
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn u32(&mut self) -> Result<u32, AgentError> {
        let end = self.position.checked_add(4).ok_or(AgentError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentError::Malformed)?;
        self.position = end;
        Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    fn string(&mut self) -> Result<Vec<u8>, AgentError> {
        let size = self.u32()? as usize;
        if size > MAX_AGENT_MESSAGE {
            return Err(AgentError::Malformed);
        }
        let end = self
            .position
            .checked_add(size)
            .ok_or(AgentError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentError::Malformed)?;
        self.position = end;
        Ok(bytes.to_vec())
    }

    fn done(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn restrict_dir(path: &Path) -> Result<(), AgentError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn restrict_socket(path: &Path) -> Result<(), AgentError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use std::sync::atomic::AtomicBool;

    fn session_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign_request(key: &SigningKey, data: &[u8], flags: u32) -> Vec<u8> {
        let mut payload = vec![SIGN_REQUEST];
        put_string(&mut payload, &public_key_blob(key.verifying_key()));
        put_string(&mut payload, data);
        put_u32(&mut payload, flags);
        payload
    }

    #[test]
    fn identities_expose_only_public_material() {
        let key = session_key();
        let response = handle_message(&[REQUEST_IDENTITIES], &key, &AtomicBool::new(false));
        assert_eq!(response[0], IDENTITIES_ANSWER);
        assert!(!response.windows(32).any(|window| window == [7u8; 32]));
        assert!(response
            .windows(32)
            .any(|window| window == key.verifying_key().as_bytes()));
    }

    #[test]
    fn sign_round_trip_verifies_with_public_key() {
        let key = session_key();
        let data = b"git-upload-pack /repo.git";
        let response = handle_message(&sign_request(&key, data, 0), &key, &AtomicBool::new(false));
        assert_eq!(response[0], SIGN_RESPONSE);
        let mut cursor = Cursor::new(&response[1..]);
        let blob = cursor.string().expect("signature blob");
        let mut inner = Cursor::new(&blob);
        assert_eq!(inner.string().expect("algorithm"), ED25519_ALGORITHM);
        let signature = inner.string().expect("signature");
        assert!(inner.done());
        key.verifying_key()
            .verify(
                data,
                &ed25519_dalek::Signature::from_slice(&signature).expect("sig"),
            )
            .expect("signature verifies");
    }

    #[test]
    fn private_key_bytes_never_appear_in_identity_or_signature_response() {
        let key = session_key();
        let private = [7u8; 32];
        let identities = handle_message(&[REQUEST_IDENTITIES], &key, &AtomicBool::new(false));
        let signature = handle_message(
            &sign_request(&key, b"payload", 0),
            &key,
            &AtomicBool::new(false),
        );
        assert!(!identities.windows(32).any(|w| w == private));
        assert!(!signature.windows(32).any(|w| w == private));
    }

    #[test]
    fn wrong_key_and_flags_fail_closed() {
        let key = session_key();
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(
            handle_message(
                &sign_request(&other, b"x", 0),
                &key,
                &AtomicBool::new(false)
            ),
            vec![FAILURE]
        );
        assert_eq!(
            handle_message(&sign_request(&key, b"x", 1), &key, &AtomicBool::new(false)),
            vec![FAILURE]
        );
    }

    #[test]
    fn malformed_and_unknown_messages_fail_closed() {
        let key = session_key();
        for request in [
            &[][..],
            &[1u8][..],
            &[SIGN_REQUEST, 0, 0][..],
            &[REQUEST_IDENTITIES, 0][..],
        ] {
            assert_eq!(
                handle_message(request, &key, &AtomicBool::new(false)),
                vec![FAILURE]
            );
        }
    }

    #[test]
    fn revoked_session_rejects_every_operation() {
        let key = session_key();
        let revoked = AtomicBool::new(true);
        assert_eq!(
            handle_message(&[REQUEST_IDENTITIES], &key, &revoked),
            vec![FAILURE]
        );
        assert_eq!(
            handle_message(&sign_request(&key, b"x", 0), &key, &revoked),
            vec![FAILURE]
        );
    }

    #[test]
    fn socket_is_owner_only_and_revoke_removes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut session = AgentSession::start(dir.path().join("session")).expect("start");
        let socket = session.socket_path().to_path_buf();
        assert!(socket.exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&socket)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        session.revoke().expect("revoke");
        assert!(!socket.exists());
    }
}
