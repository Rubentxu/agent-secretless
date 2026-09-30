//! Chain verification for the per-session CA, checked by a tool that did not
//! produce the certificates.
//!
//! The unit tests in `tls_bridge` assert this module's own view of what it
//! emitted. That is a tautology: if `issue_leaf` wrote a broken certificate,
//! the unit test reading it back would agree. So this test exports the real
//! DER to disk and hands it to the `openssl` CLI, an independent x509
//! implementation, which is the same one an operator would use.
//!
//! `openssl` is required. The test skips loudly rather than passing silently
//! when it is missing, because "no verifier ran" must never look like
//! "the chain verified".

use std::process::Command;

use asv_broker::tls_bridge::{issue_leaf, SessionCa, DEFAULT_SESSION_CA_TTL};

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct Chain {
    _dir: std::path::PathBuf,
    root: std::path::PathBuf,
    intermediate: std::path::PathBuf,
    leaf: std::path::PathBuf,
}

fn export_chain(tag: &str) -> Chain {
    let dir = std::env::temp_dir().join(format!("asv-chain-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");

    let ca = SessionCa::new(tag, 1, DEFAULT_SESSION_CA_TTL);
    let leaf = issue_leaf(&ca, "api.example.com", std::time::Instant::now()).expect("issuance");

    let root = dir.join("root.pem");
    let intermediate = dir.join("intermediate.pem");
    let leaf_path = dir.join("leaf.pem");
    std::fs::write(&root, der_to_pem(&ca.root_der)).expect("write root");
    std::fs::write(&intermediate, der_to_pem(&ca.intermediate_der)).expect("write intermediate");
    std::fs::write(&leaf_path, der_to_pem(&leaf.leaf_der)).expect("write leaf");

    Chain {
        _dir: dir,
        root,
        intermediate,
        leaf: leaf_path,
    }
}

/// Minimal DER to PEM wrapper so the files are readable by any tool, not just
/// by Rust. Three input bytes become four output characters, padded with `=`
/// on the final short group.
fn der_to_pem(der: &[u8]) -> Vec<u8> {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        // Always four symbols per group; the last one or two are '='.
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63]);
        } else {
            out.push(b'=');
        }
    }
    out.push(b'\n');
    out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    out
}

fn openssl(args: &[&str]) -> (bool, String) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("spawn openssl");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The whole point of the module: a peer that trusts only the session root can
/// validate a leaf, because the intermediate completes the chain.
#[test]
fn leaf_verifies_against_the_session_root() {
    if !have_openssl() {
        panic!("openssl is required for this test; refusing to report a pass without it");
    }
    let c = export_chain("verify");

    let (ok, out) = openssl(&[
        "verify",
        "-CAfile",
        c.root.to_str().unwrap(),
        "-untrusted",
        c.intermediate.to_str().unwrap(),
        c.leaf.to_str().unwrap(),
    ]);
    assert!(ok, "openssl refused the chain:\n{out}");
}

/// The leaf must name exactly the host it was issued for, in its SAN.
///
/// "Contains the host" is not the claim. A leaf carrying
/// `api.example.com` *and* `internal.example.com` would pass a substring
/// check while letting the session authenticate as a host the allowlist
/// never named. This was falsified: adding a second SAN left the previous
/// version of this test green.
#[test]
fn leaf_carries_exactly_one_san_and_it_is_the_requested_host() {
    if !have_openssl() {
        panic!("openssl is required for this test; refusing to report a pass without it");
    }
    let c = export_chain("san");

    let (ok, out) = openssl(&[
        "x509",
        "-in",
        c.leaf.to_str().unwrap(),
        "-noout",
        "-ext",
        "subjectAltName",
    ]);
    assert!(ok, "openssl could not read the leaf:\n{out}");

    let dns_names: Vec<&str> = out
        .lines()
        .filter_map(|l| l.split_once("DNS:"))
        .map(|(_, rest)| rest.trim().trim_end_matches(','))
        .collect();
    assert_eq!(
        dns_names,
        vec!["api.example.com"],
        "the leaf must carry exactly one SAN, the requested host, got:\n{out}"
    );
}

/// A leaf is not a CA. If it were, a session could mint a sub-CA and sign
/// itself a certificate for any host.
#[test]
fn leaf_is_not_a_ca() {
    if !have_openssl() {
        panic!("openssl is required for this test; refusing to report a pass without it");
    }
    let c = export_chain("noca");

    let (ok, out) = openssl(&["x509", "-in", c.leaf.to_str().unwrap(), "-noout", "-text"]);
    assert!(ok, "openssl could not read the leaf:\n{out}");
    assert!(
        out.contains("CA:FALSE"),
        "the leaf must carry CA:FALSE, got:\n{out}"
    );
    assert!(
        out.contains("TLS Web Server Authentication"),
        "the leaf must be usable for TLS server auth, got:\n{out}"
    );
}

/// The CA must not inherit rcgen's default validity window, which is
/// 1975-4096 and would outlive every session by two thousand years.
#[test]
fn ca_validity_follows_the_session_ttl() {
    if !have_openssl() {
        panic!("openssl is required for this test; refusing to report a pass without it");
    }
    let c = export_chain("validity");

    let (ok, out) = openssl(&["x509", "-in", c.root.to_str().unwrap(), "-noout", "-dates"]);
    assert!(ok, "openssl could not read the root:\n{out}");
    assert!(
        !out.contains("4096"),
        "the root must not carry rcgen's default 4096 expiry, got:\n{out}"
    );
    assert!(
        !out.contains("1975"),
        "the root must not carry rcgen's default 1975 start, got:\n{out}"
    );
}
