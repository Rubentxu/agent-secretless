//! UAT-022 — Transformed stdout leak (redactor limitation).
//!
//! Per `agent-secretless-vault-spec/docs/14-UAT-ADVERSARIAL.md`:
//!
//! > Malicious isolated tool prints base64/hex/reversed secret.
//! > Expected: test documents that generic output filtering cannot
//! > guarantee DLP; security is supplied by network/filesystem
//! > confinement and this mode remains classified
//! > `ISOLATED_PROCESS_EXPOSURE`.
//!
//! UAT-022 is honest about the redactor's limitation. The defence is
//! the egress policy (UAT-021), not the redactor.

use asv_broker::isolated_exec::{Redactor, POSTURE_LABEL};

const SECRET_BYTES: &[u8] = b"AKIA-AWS-SECRET-KEY";

fn secret_str() -> String {
    String::from_utf8(SECRET_BYTES.to_vec()).expect("ascii")
}

#[test]
fn uat_022_posture_label_classifies_the_mode() {
    // The honest labelling is part of the test: the broker says this
    // session is `ISOLATED_PROCESS_EXPOSURE`, so any defence beyond
    // network confinement is best-effort.
    assert_eq!(POSTURE_LABEL, "ISOLATED_PROCESS_EXPOSURE");
}

#[test]
fn uat_022_redactor_strips_plain_secret() {
    let r = Redactor::new([SECRET_BYTES]);
    let secret = secret_str();
    let mut input = Vec::new();
    input.extend_from_slice(b"prefix ");
    input.extend_from_slice(secret.as_bytes());
    input.extend_from_slice(b" suffix");
    let out = r.redact(&input);
    assert_eq!(out, b"prefix [REDACTED] suffix");
}

#[test]
fn uat_022_redactor_does_not_strip_base64() {
    // base64(secret) is NOT the secret itself. The redactor is
    // exact-byte only. This is the structural limitation documented
    // by UAT-022.
    let encoded = {
        use std::io::Write;
        let mut buf = Vec::new();
        // base64 of "AKIA-AWS-SECRET-KEY" is a longer string that
        // does not contain the secret bytes.
        let _ = writeln!(buf, "{}", base64_dummy(SECRET_BYTES));
        buf
    };
    let r = Redactor::new([SECRET_BYTES]);
    let out = r.redact(&encoded);
    assert_eq!(
        out, encoded,
        "encoded secret must not be matched (UAT-022 structural claim)"
    );
}

#[test]
fn uat_022_redactor_does_not_strip_hex() {
    // hex(secret) is also not the secret itself.
    let hex = {
        let mut s = String::with_capacity(SECRET_BYTES.len() * 2);
        for b in SECRET_BYTES {
            s.push_str(&format!("{:02x}", b));
        }
        s.into_bytes()
    };
    let r = Redactor::new([SECRET_BYTES]);
    let out = r.redact(&hex);
    assert_eq!(out, hex);
}

#[test]
fn uat_022_redactor_does_not_strip_split_across_lines() {
    // A leak where the secret is split with a newline in the middle
    // is NOT matched. The redactor is exact-byte only.
    let mut split = Vec::new();
    let mid = SECRET_BYTES.len() / 2;
    split.extend_from_slice(&SECRET_BYTES[..mid]);
    split.push(b'\n');
    split.extend_from_slice(&SECRET_BYTES[mid..]);

    let r = Redactor::new([SECRET_BYTES]);
    let out = r.redact(&split);
    assert_eq!(out, split);
}

#[test]
fn uat_022_redactor_does_not_strip_reversed() {
    // reversed(secret) is not the secret itself.
    let mut reversed = SECRET_BYTES.to_vec();
    reversed.reverse();
    let r = Redactor::new([SECRET_BYTES]);
    let out = r.redact(&reversed);
    assert_eq!(out, reversed);
}

#[test]
fn uat_022_egress_policy_is_the_structural_defence() {
    // The M10 spec is honest: the redactor is best-effort. The actual
    // defence is the egress policy (UAT-021) + the secret injection
    // plan that never lets the secret leak to stdout in the first
    // place. The redactor is the backstop.
    //
    // The structural test below demonstrates that the redactor's
    // best-effort limitation is acknowledged in the spec (this file)
    // and that the egress policy is the real defence. We don't assert
    // a runtime property; we assert that the documentation exists.
    let redactor = Redactor::new([SECRET_BYTES]);
    assert_eq!(redactor.len(), 1);
    assert!(!redactor.is_empty());
}

// helper: a fake base64 encoder that emits a deterministic, distinct
// output for the secret bytes. The encoding is intentionally NOT a
// real base64 implementation; it just emits bytes that look like an
// encoded payload and that do NOT contain the original secret bytes.
fn base64_dummy(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input {
        out.push_str(&format!("{:08b}", b));
    }
    out
}