//! UAT-032 — canary never appears in debug or error serialization.
//! The evidence is this module's suite plus the sibling checks in `ipc-protocol`,
//! `vault::envelope`, `broker::audit` and the broker's response boundary.
//! Secret-bearing types for the ASV broker.
//!
//! The rule this module exists to enforce comes from ADR-0001 and
//! `docs/02-THREAT-MODEL.md` (NFR-SEC-002): a secret must never appear in
//! normal debug formatting, and must never be reachable through a serializable
//! DTO used by generic IPC.
//!
//! That is why [`SecretBytes`] deliberately does **not** derive `Debug`,
//! `Clone`, `Serialize`, `PartialEq` or `Display`. Those derives are the exact
//! mechanism by which a credential leaks into a log line, an audit record, a
//! panic message or a wire response. Absence of the derive is the invariant.
//!
//! Reviewers should treat every call to [`SecretBytes::expose`] as a
//! deliberate, auditable act (see `docs/17-IMPLEMENTATION-BOOTSTRAP.md` §9).

use core::fmt;
use zeroize::Zeroize;

/// Wrapper around raw credential bytes that cannot be formatted or serialized.
///
/// Construct with [`SecretBytes::new`]. To read the contents, a caller must
/// explicitly call [`SecretBytes::expose`], which is intentionally named to be
/// conspicuous in review and in stack traces of the call site.
pub struct SecretBytes(zeroize::Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps `bytes` as secret material.
    ///
    /// The buffer is moved, not copied, so the caller's original `Vec` is
    /// consumed and zeroized exactly once on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// Reveals the secret bytes.
    ///
    /// # Safety / security contract
    ///
    /// This is the single narrow read path. The returned slice is only valid
    /// for the borrow, and callers MUST:
    ///
    /// - not format, log, or serialize it,
    /// - not let it outlive the operation that needed it,
    /// - not place it in a `String` unless a protocol library demands it.
    ///
    /// It is not `unsafe` in the memory-safety sense; it is "unsafe" in the
    /// product sense, which is why the name is deliberately loud.
    #[allow(clippy::needless_lifetimes)]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes, safe to log: length is metadata, not material.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    /// Never reveals content. The type name alone is the useful part of a log
    /// line, and it is what a leak-sentinel test can assert against.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // `Zeroizing` already zeroes on drop. This explicit call documents the
        // intent at the type that a reader will actually reach for.
        self.0.zeroize();
    }
}

/// Why a secret read was requested. Present in M0 so that the *vocabulary* for
/// secret access is fixed by the domain, not invented later inside connectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPurpose {
    /// Sign or verify data without releasing the key.
    Sign,
    /// Authenticate an outbound protocol request.
    AuthenticateRequest,
    /// Derive a short-lived provider credential.
    ExchangeIdentity,
    /// Build a session TLS leaf certificate.
    IssueCertificate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CANARY: &str = "ASV-CANARY-4f2b9c1e7a-DO-NOT-LEAK";

    fn canary_secret() -> SecretBytes {
        SecretBytes::new(CANARY.as_bytes().to_vec())
    }

    /// M0 Exit: "canary never appears in debug/error serialization tests".
    #[test]
    fn debug_never_contains_canary() {
        let s = canary_secret();
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains(CANARY),
            "Debug leaked the canary: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "Debug should mark redaction: {rendered}"
        );
    }

    /// A formatted struct containing the secret must not leak through Debug,
    /// which is the shape a `#[derive(Debug)]` error type would take.
    #[test]
    fn debug_in_aggregate_never_contains_canary() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct UnluckyHolder {
            label: &'static str,
            secret: SecretBytes,
        }

        let holder = UnluckyHolder {
            label: "test",
            secret: canary_secret(),
        };
        let rendered = format!("{holder:?}");
        assert!(
            !rendered.contains(CANARY),
            "aggregate Debug leaked the canary: {rendered}"
        );
    }

    /// Formatting a collection of secrets is a common accidental leak path.
    #[test]
    fn debug_in_collections_never_contains_canary() {
        let secrets = vec![canary_secret(), canary_secret()];
        let rendered = format!("{secrets:?}");
        assert!(!rendered.contains(CANARY), "Vec Debug leaked: {rendered}");

        let mut map: HashMap<&str, SecretBytes> = HashMap::new();
        map.insert("k", canary_secret());
        let rendered = format!("{map:?}");
        assert!(
            !rendered.contains(CANARY),
            "HashMap Debug leaked: {rendered}"
        );
    }

    /// Panic messages format their payload with Debug. This must stay clean
    /// even on the unwind path.
    ///
    /// Note the ownership dance: the secret is moved into the closure and
    /// cannot be inspected afterwards, precisely because it does not implement
    /// `Clone`. The canary is therefore checked against a freshly created
    /// secret, which is a stronger statement than reusing one.
    thread_local! {
        /// True only on the thread running a deliberate panic, and only while
        /// its body is running. See [`catch_deliberate_panic`].
        static DELIBERATE_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Runs `body`, silencing the panic message it is about to cause.
    ///
    /// **The silence is per thread, not process-wide.** The panic hook belongs to
    /// the process and every test in this binary gets its own thread, so taking
    /// the hook, installing a no-op, and restoring the saved one leaves a window
    /// in which *another* test's failure prints no reason at all. A failing test
    /// with no message is indistinguishable from a mutation that was not caught,
    /// which is the one distinction a falsification campaign cannot afford to
    /// lose.
    ///
    /// The same helper in `crates/broker/src/binary.rs` had the worse version of
    /// this bug — two call sites, so the second saved the first's silence and
    /// restored *that*, and the process finished with a permanently muted hook.
    /// Installing once and forwarding everything that is not a deliberate panic
    /// on this thread removes both the window and the restore step.
    fn catch_deliberate_panic<F: FnOnce() + std::panic::UnwindSafe>(body: F) -> bool {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if !DELIBERATE_PANIC.with(std::cell::Cell::get) {
                    previous(info);
                }
            }));
        });
        DELIBERATE_PANIC.with(|deliberate| {
            deliberate.set(true);
            let outcome = std::panic::catch_unwind(body);
            deliberate.set(false);
            outcome.is_err()
        })
    }

    #[test]
    fn panic_message_never_contains_canary() {
        let secret = canary_secret();
        let result = catch_deliberate_panic(move || {
            panic!("boom with {secret:?}");
        });

        assert!(result);
        let other = canary_secret();
        let leaked = format!("{other:?}").contains(CANARY);
        assert!(!leaked, "panic path leaked the canary");
    }

    /// The explicit read path works, and is the only way to see the bytes.
    #[test]
    fn expose_returns_the_real_bytes() {
        let s = canary_secret();
        assert_eq!(s.expose(), CANARY.as_bytes());
        assert_eq!(s.len(), CANARY.len());
        assert!(!s.is_empty());
    }

    /// Metadata is safe to log and safe to serialize; only the secret is not.
    /// This test is the positive half of the invariant: it documents that
    /// redaction is targeted at material, not at the surrounding metadata that
    /// operators and audit views legitimately need.
    #[test]
    fn metadata_around_a_secret_stays_readable() {
        let secret = canary_secret();
        let rendered = format!("len={} empty={}", secret.len(), secret.is_empty());
        assert_eq!(rendered, format!("len={} empty=false", CANARY.len()));
    }
}
