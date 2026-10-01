//! A cross-implementation check: OpenSSL as the client, rustls as the server.
//!
//! The tests in `handshake.rs` use rustls on both ends, which means a bug
//! shared by both peers would cancel out. This file breaks that symmetry with
//! an implementation the acceptor shares no code with.
//!
//! It shells out to `openssl s_client` rather than linking a client, so it
//! cannot be satisfied by a shared bug. The cost is a dependency on a binary
//! being present, and the tests panic when it is not. That is deliberate: "no
//! verifier ran" must never render as "the handshake verified", which is the
//! same rule the previous cycle's OpenSSL chain tests follow.

use std::process::{Command, Stdio};

use asv_broker::tls_bridge::{issue_leaf, SessionCa};
use asv_tls_acceptor::{Acceptor, LeafMaterial};

const HOST: &str = "api.example.com";

fn material_for(host: &str) -> (LeafMaterial, SessionCa) {
    let ca = SessionCa::new("openssl-client", 11, std::time::Duration::from_secs(3600));
    let leaf = issue_leaf(&ca, host, std::time::Instant::now()).expect("mint a leaf");
    let material = LeafMaterial::new(
        ca.root_der.clone(),
        vec![leaf.leaf_der.clone(), ca.intermediate_der.clone()],
        leaf.leaf_key.serialize_der(),
    )
    .expect("material");
    (material, ca)
}

fn openssl_version() -> String {
    let output = Command::new("openssl")
        .arg("version")
        .output()
        .expect("openssl is required by these tests; without it nothing would be verified");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Both tests pass `-verify_hostname`, not just `-servername`.
///
/// `s_client` sends the SNI in `-servername` but does **not** check that the
/// presented certificate covers it, unless `-verify_hostname` is given. The
/// first version of this file used only `-servername` and asserted failure;
/// it failed, and OpenSSL's own output said `Verification: OK` for
/// `evil.example.net` against a leaf for `api.example.com`. The acceptor was
/// right and the test was asking the wrong question. `-verify_return_error`
/// without `-verify_hostname` checks the chain and nothing else.
fn openssl_args(addr: &std::net::SocketAddr, hostname: &str, cafile: &str) -> Vec<String> {
    vec![
        "s_client".into(),
        "-connect".into(),
        format!("127.0.0.1:{}", addr.port()),
        "-servername".into(),
        hostname.into(),
        "-verify_hostname".into(),
        hostname.into(),
        "-CAfile".into(),
        cafile.into(),
        "-verify_return_error".into(),
        "-brief".into(),
    ]
}

fn spawn_openssl(args: &[String]) -> std::process::Output {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");
    // OpenSSL waits for application data after the handshake, so the pipe is
    // closed immediately to make it exit instead of hanging the suite.
    drop(child.stdin.take());
    child.wait_with_output().expect("openssl finished")
}

#[test]
fn openssl_completes_the_handshake_trusting_only_the_session_root() {
    eprintln!("client: {}", openssl_version());
    let (material, ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");

    let root_path = std::env::temp_dir().join("asv-openssl-client-root.pem");
    // PEM, because `-CAfile` takes PEM. The DER is what the acceptor holds.
    std::fs::write(&root_path, pem_encode(&ca.root_der)).expect("write the trust anchor");

    let args = openssl_args(
        &acceptor.local_addr(),
        HOST,
        root_path.to_str().expect("utf-8 path"),
    );
    let output = spawn_openssl(&args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_file(&root_path);

    assert!(
        output.status.success(),
        "openssl s_client failed against the acceptor:\n{stderr}"
    );
    assert!(
        stderr.contains("Verification: OK") || stderr.contains("Verification ok"),
        "openssl did not report a successful verification:\n{stderr}"
    );
}

#[test]
fn openssl_is_refused_for_a_hostname_the_leaf_does_not_name() {
    let (material, ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");

    let root_path = std::env::temp_dir().join("asv-openssl-client-wrong-root.pem");
    std::fs::write(&root_path, pem_encode(&ca.root_der)).expect("write the trust anchor");

    let args = openssl_args(
        &acceptor.local_addr(),
        "evil.example.net",
        root_path.to_str().expect("utf-8 path"),
    );
    let output = spawn_openssl(&args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_file(&root_path);

    assert!(
        !output.status.success(),
        "openssl completed a handshake for a hostname the leaf does not name:\n{stderr}"
    );
}

/// What an implementation that shares no code with this one actually
/// negotiates.
///
/// The rest of the workspace names no cipher suite, no key-exchange group and
/// no signature algorithm, so `docs/tls-compatibility-matrix.md` had to
/// publish those rows as *unpinned*. This does not make them pinned — a
/// default can still change without failing anything — but it turns them from
/// "nobody looked" into "an independent client was observed", and it asserts
/// the one thing that is genuinely falsifiable about a default pair: the
/// ciphersuite has to belong to the protocol version that was reported.
///
/// The client offers `h2` and `http/1.1` through ALPN, exactly as `reqwest`
/// would. The handshake succeeding is therefore also cross-implementation
/// evidence for the ALPN row: a real third-party client offering `h2` gets a
/// working connection rather than an `h2` negotiation it could not speak.
#[test]
fn openssl_negotiates_a_suite_belonging_to_its_reported_version() {
    eprintln!("client: {}", openssl_version());
    let (material, ca) = material_for(HOST);
    let acceptor = Acceptor::bind(&material, 0).expect("bind");

    let root_path = std::env::temp_dir().join("asv-openssl-negotiated-root.pem");
    std::fs::write(&root_path, pem_encode(&ca.root_der)).expect("write the trust anchor");

    let mut args = openssl_args(
        &acceptor.local_addr(),
        HOST,
        root_path.to_str().expect("utf-8 path"),
    );
    args.push("-alpn".into());
    args.push("h2,http/1.1".into());

    let output = spawn_openssl(&args);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_file(&root_path);

    assert!(
        output.status.success(),
        "openssl failed against the acceptor even though it offered ALPN:\n{stderr}"
    );

    let version = field(&stderr, "Protocol version: ");
    let cipher = field(&stderr, "Ciphersuite: ");

    // Printed, not only asserted: this is the measurement the TLS
    // compatibility matrix quotes, and a matrix cell that nobody can reproduce
    // by running one command is a cell nobody can check.
    eprintln!("negotiated: {version} / {cipher} (ALPN offered h2,http/1.1)");

    // TLS 1.3 suites are named `TLS_AES_*` or `TLS_CHACHA20_*`. TLS 1.2
    // suites are not. That naming difference is the whole check, and it is
    // stable across OpenSSL versions, which pinning a specific default is not.
    let is_v13_suite =
        cipher.starts_with("TLS_") && (cipher.contains("AES") || cipher.contains("CHACHA20"));
    if version.contains("TLSv1.3") {
        assert!(
            is_v13_suite,
            "reported {version} but negotiated {cipher}, which is not a TLS 1.3 suite:\n{stderr}"
        );
    } else {
        assert!(
            !is_v13_suite,
            "reported {version} but negotiated {cipher}, which is a TLS 1.3 suite:\n{stderr}"
        );
    }
}

/// Reads the value after a `s_client -brief` field label.
fn field(stderr: &str, label: &str) -> String {
    stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .unwrap_or_else(|| panic!("openssl -brief printed no {label:?} line:\n{stderr}"))
        .trim()
        .to_string()
}

/// Minimal DER-to-PEM. Avoids a dependency for one call: the alternative is
/// adding `rustls-pemfile` to the test surface to convert bytes that are
/// already in hand.
fn pem_encode(der: &[u8]) -> String {
    let body = base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
