//! M2 real-socket acceptance tests for the first SSH vertical.
//!
//! These tests intentionally connect to the Unix socket rather than calling
//! `handle_message` directly. The boundary being verified is the one an SSH
//! client sees: framed messages, public identities, signatures and revocation.

use asv_ssh_agent::AgentSession;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use tempfile::tempdir;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn send_frame(stream: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .expect("write length");
    stream.write_all(payload).expect("write payload");
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).expect("read length");
    let mut response = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).expect("read response");
    response
}

fn frame(socket: &std::path::Path, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("connect agent socket");
    send_frame(&mut stream, payload)
}

fn parse_string(input: &[u8], offset: &mut usize) -> Vec<u8> {
    let end = *offset + 4;
    let size = u32::from_be_bytes(input[*offset..end].try_into().expect("length")) as usize;
    *offset = end;
    let end = *offset + size;
    let value = input[*offset..end].to_vec();
    *offset = end;
    value
}

#[test]
fn uat_001_real_socket_lists_public_key_and_signs_without_export() {
    let dir = tempdir().expect("tempdir");
    let mut session = AgentSession::start(dir.path().join("session")).expect("start session");
    let socket = session.socket_path().to_path_buf();

    let identities = frame(&socket, &[REQUEST_IDENTITIES]);
    assert_eq!(identities[0], IDENTITIES_ANSWER);
    let mut offset = 5;
    let public_blob = parse_string(&identities, &mut offset);
    let _comment = parse_string(&identities, &mut offset);
    assert_eq!(public_blob.len(), 51);

    let ssh_add = std::process::Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .expect("ssh-add is installed");
    assert!(ssh_add.status.success(), "ssh-add failed: {:?}", ssh_add);
    let listed = String::from_utf8_lossy(&ssh_add.stdout);
    assert!(
        listed.starts_with("ssh-ed25519 "),
        "unexpected identity: {listed}"
    );
    let data = b"git-upload-pack /repo.git";
    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, &public_blob);
    put_string(&mut request, data);
    put_u32(&mut request, 0);
    let signed = frame(&socket, &request);
    assert_eq!(signed[0], SIGN_RESPONSE);
    let mut offset = 1;
    let signature_blob = parse_string(&signed, &mut offset);
    let mut sig_offset = 0;
    let algorithm = parse_string(&signature_blob, &mut sig_offset);
    let signature = parse_string(&signature_blob, &mut sig_offset);
    assert_eq!(algorithm, b"ssh-ed25519");
    assert_eq!(signature.len(), 64);

    let mut key_offset = 0;
    let public_algorithm = parse_string(&public_blob, &mut key_offset);
    let key_bytes = parse_string(&public_blob, &mut key_offset);
    assert_eq!(public_algorithm, b"ssh-ed25519");
    let public_key = VerifyingKey::from_bytes(key_bytes.as_slice().try_into().expect("public key"))
        .expect("public key parses");

    public_key
        .verify(data, &Signature::from_slice(&signature).expect("signature"))
        .expect("signature verifies");
    assert_eq!(key_offset, public_blob.len());
    assert!(!signed.windows(32).any(|window| window == [0u8; 32]));

    session.revoke().expect("revoke");
}

#[test]
fn uat_015_one_connection_accepts_identity_and_sign_requests() {
    let dir = tempdir().expect("tempdir");
    let mut session = AgentSession::start(dir.path().join("session")).expect("start session");
    let socket = session.socket_path().to_path_buf();
    let mut stream = UnixStream::connect(&socket).expect("connect agent socket");

    let identities = send_frame(&mut stream, &[REQUEST_IDENTITIES]);
    assert_eq!(identities[0], IDENTITIES_ANSWER);
    let mut offset = 5;
    let public_blob = parse_string(&identities, &mut offset);
    let _comment = parse_string(&identities, &mut offset);

    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, &public_blob);
    put_string(&mut request, b"git-upload-pack /repo.git");
    put_u32(&mut request, 0);
    let signed = send_frame(&mut stream, &request);
    assert_eq!(signed[0], SIGN_RESPONSE);

    session.revoke().expect("revoke");
}

#[test]
fn uat_005_wrong_key_replay_is_rejected() {
    let dir = tempdir().expect("tempdir");
    let mut session = AgentSession::start(dir.path().join("session")).expect("start session");
    let socket = session.socket_path().to_path_buf();
    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, b"not-this-session-key");
    put_string(&mut request, b"payload");
    put_u32(&mut request, 0);
    assert_eq!(frame(&socket, &request), vec![FAILURE]);
    session.revoke().expect("revoke");
}

#[test]
fn uat_014_revoke_removes_socket_and_blocks_new_operations() {
    let dir = tempdir().expect("tempdir");
    let mut session = AgentSession::start(dir.path().join("session")).expect("start session");
    let socket = session.socket_path().to_path_buf();
    assert!(socket.exists());
    session.revoke().expect("revoke");
    assert!(!socket.exists());
    assert!(UnixStream::connect(socket).is_err());
}
