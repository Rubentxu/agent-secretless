//! The CONNECT session proof, defined once for both sides.
//!
//! This used to live in `asv-broker`'s `tls_bridge`, which was correct while
//! the broker was the only party that had to understand it. It stopped being
//! correct the moment a *producer* existed: a session-local shim has to build
//! the same wire string the broker parses, and a second definition of a nonce
//! derivation in a different crate is not a refactor, it is a future
//! divergence that passes every test on either side until the first proof is
//! minted by one and verified by the other.
//!
//! So the format lives here, next to [`crate::verify_proof`] and
//! [`crate::public_key_blob`], for the same reason those two do: this is the
//! crate that owns what a signature over a session key *means*, and a proof is
//! a signature over a nonce plus the wire shape that carries it. Both the
//! broker and the shim depend inward on this one definition; neither restates
//! it.
//!
//! The digest layout is pinned by a test vector. A nonce derivation that
//! changes silently does not break loudly at the broker — it breaks as "no
//! proof ever verifies", which is the same error a dozen unrelated mistakes
//! produce, and the cost of finding it is a bisect across a protocol change
//! nobody made.

use sha2::{Digest, Sha256};

/// The header a session proof travels in.
pub const SESSION_PROOF_HEADER: &str = "x-asv-session-proof";

/// Domain separation for the session proof, hashed in ahead of everything else.
///
/// The same session key also signs other things, so a signature produced for
/// one mechanism must not be replayable into another. Ten bytes buy the
/// statement that this signature can only ever mean "CONNECT session proof
/// v2".
pub const PROOF_DOMAIN: &[u8] = b"asv/connect/session-proof/v2";

/// A session proof: the client's key blob, the per-session counter it spends,
/// and a signature over [`proof_nonce`].
///
/// The counter sits in the clear because it is not a secret — it is a number
/// the client chose, and hiding it would buy nothing while making the
/// single-use property unauditable from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProof {
    /// The session key blob this proof speaks for.
    pub key: Vec<u8>,
    /// The signature over the nonce.
    pub signature: Vec<u8>,
    /// The counter this proof spends, folded into the nonce by
    /// [`proof_nonce`] so the signature commits to it.
    pub counter: u64,
}

impl SessionProof {
    /// Renders the proof as it travels: `base64(key).counter.base64(signature)`.
    ///
    /// Three segments, and the counter is not base64 because a counter is a
    /// number anyone may read. The two byte fields are, so that a proof with a
    /// stray `.` or a newline cannot be assembled out of header fragments.
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}",
            base64_encode(&self.key),
            self.counter,
            base64_encode(&self.signature)
        )
    }

    /// Parses what [`SessionProof::encode`] produced, and only that.
    ///
    /// Exactly three segments. A two-segment proof is not this version of the
    /// protocol, and parsing it leniently would hand the verifier a proof that
    /// costs no counter at all — which is the shape the replay fix exists to
    /// remove.
    pub fn decode(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        let key = base64_decode(parts.next()?)?;
        let counter: u64 = parts.next()?.parse().ok()?;
        let signature = base64_decode(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        // An empty half is not a malformed proof, it is *no* proof: accepting
        // one would hand the verifier an empty signature to fail on later, at
        // a point where the failure no longer says the client sent nonsense.
        if key.is_empty() || signature.is_empty() {
            return None;
        }
        Some(Self {
            key,
            signature,
            counter,
        })
    }
}

/// The nonce a session proof is computed over.
///
/// It is bound to the destination *and* to a per-session counter, and it is
/// not drawn fresh per tunnel. The destination binding is worth having and
/// costs nothing; the counter is what makes a proof single-use.
///
/// A server-issued nonce would be stronger still, and ADR-0019 already
/// rejected it for a reason that still holds: it costs a round trip *before*
/// the CONNECT, on a path that exists to serve clients that have no round trip
/// to spend. A counter needs no round trip and no clock agreement — the client
/// already holds a session, so it holds a counter too.
///
/// **What the destination binding buys:** a proof captured for one destination
/// does not verify against another, so it cannot be moved to a host the
/// operator did not authorise.
///
/// **What the counter buys, and what it does not.** It buys single use: the
/// broker spends a counter when a proof resolves, so the same `(key,
/// destination, counter)` triple is refused the second time. What it does not
/// buy is unpredictability — the counter is an attacker-supplied number, and
/// the window that remembers spent ones is bounded, so a proof older than the
/// window is refused as stale rather than replayed. Freshness here means
/// *single use*, not *recent*.
///
/// The host is hashed raw, not length-prefixed, and the port is eight bytes
/// wide. That is not an oversight to be tidied: the byte layout is protocol,
/// it is already deployed, and changing it would invalidate every proof in
/// flight for no security gain. `the_nonce_layout_is_pinned` holds it still.
pub fn proof_nonce(presented_key: &[u8], host: &str, port: u16, counter: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Domain separation first.
    hasher.update(PROOF_DOMAIN);
    // Length-prefixed so a key ending in the same bytes as a host cannot
    // produce the same digest as a shorter key followed by a longer host.
    hasher.update((presented_key.len() as u64).to_be_bytes());
    hasher.update(presented_key);
    hasher.update(host.as_bytes());
    hasher.update((port as u64).to_be_bytes());
    // Fixed width, so no choice of counter bytes can be confused with a
    // shorter host or a different port.
    hasher.update(counter.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Standard base64, no padding, no external dependency.
///
/// Unpadded because that is what the wire already carries, and a second
/// spelling of the same proof would be a second thing to canonicalise later.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 1);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let packed = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(packed >> 18) as usize & 63] as char);
        out.push(ALPHABET[(packed >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(packed >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[packed as usize & 63] as char);
        }
    }
    out
}

/// Standard base64, no padding, no external dependency.
///
/// Decoding is strict on purpose: this reads attacker-chosen bytes, and a
/// decoder that skips unknown characters would let `key` and `signature`
/// disagree with what was on the wire in a way no later check would notice.
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Unpadded base64 cannot have a group of one character: six bits do not
    // make a byte. Refusing it here means two encodings of the same nonce
    // cannot both be accepted, one of them truncated.
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{public_key_blob, verify_proof};
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The layout is protocol. These three digests were taken from the broker's
    /// implementation *before* the code moved here, so they are a record of
    /// what the deployed format is rather than a description of whatever this
    /// function currently does — which is the only kind of vector that can
    /// catch a refactor that changes the digest by accident.
    #[test]
    fn the_nonce_layout_is_pinned() {
        let key: Vec<u8> = (0u8..32).collect();
        for (host, port, counter, expected) in [
            (
                "api.example.com",
                443u16,
                0u64,
                "eba3c7ccc37c79ea49e809b2e693cc5ebe23f3ea865a66bc726f42991d25f8df",
            ),
            (
                "api.example.com",
                443,
                1,
                "d55181a11d4b5fecbf04328a0eee5b35354baea10d8f2a4a9e73b02c1792b034",
            ),
            (
                "api.example.com",
                443,
                41,
                "6d925ce25cd25037143793c279d0ea63fe50bf39d09084239626aa6b3e87e287",
            ),
        ] {
            assert_eq!(hex(&proof_nonce(&key, host, port, counter)), expected);
        }
    }

    /// The producer side, end to end: sign what the broker will derive, encode
    /// it, decode it as the broker would, and let the broker's own verifier
    /// accept it. A round trip that only checks the string round-trips would
    /// pass with the counter in the wrong segment.
    #[test]
    fn a_minted_proof_verifies_after_travel() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let blob = public_key_blob(&signing.verifying_key());
        let host = "api.example.com";
        let port = 443u16;
        let counter = 41u64;

        let signature = signing.sign(&proof_nonce(&blob, host, port, counter));
        let wire = SessionProof {
            key: blob.clone(),
            signature: signature.to_bytes().to_vec(),
            counter,
        }
        .encode();

        assert!(wire.split('.').count() == 3, "three segments: {wire}");
        let decoded = SessionProof::decode(&wire).expect("the broker can parse it");
        assert_eq!(decoded, wire_proof(&blob, &signature.to_bytes(), counter));
        assert!(verify_proof(
            &decoded.key,
            &proof_nonce(&decoded.key, host, port, decoded.counter),
            &decoded.signature
        ));
    }

    fn wire_proof(key: &[u8], signature: &[u8], counter: u64) -> SessionProof {
        SessionProof {
            key: key.to_vec(),
            signature: signature.to_vec(),
            counter,
        }
    }

    #[test]
    fn a_two_segment_proof_is_not_a_proof() {
        let key = base64_encode(&[1u8; 32]);
        let sig = base64_encode(&[2u8; 64]);

        // The legacy shape: no counter segment at all.
        assert!(SessionProof::decode(&format!("{key}.{sig}")).is_none());

        // A key and a counter, with the signature simply absent.
        //
        // This second case is here because of what the falsification run
        // found. The first case is refused for a reason that has nothing to
        // do with arity — the "signature" is not a number, so the counter
        // parse fails first — which meant a decoder that had quietly started
        // supplying a default for a missing signature would still pass it.
        // This is the shape such a decoder would actually admit, so this is
        // the case that pins the property.
        assert!(SessionProof::decode(&format!("{key}.7")).is_none());
    }

    #[test]
    fn a_four_segment_proof_is_not_a_proof() {
        let key = base64_encode(&[1u8; 32]);
        let sig = base64_encode(&[2u8; 64]);
        assert!(SessionProof::decode(&format!("{key}.1.{sig}.extra")).is_none());
    }

    #[test]
    fn a_proof_without_a_numeric_counter_is_not_a_proof() {
        let key = base64_encode(&[1u8; 32]);
        let sig = base64_encode(&[2u8; 64]);
        assert!(SessionProof::decode(&format!("{key}.notanumber.{sig}")).is_none());
        assert!(SessionProof::decode(&format!("{key}..{sig}")).is_none());
    }

    #[test]
    fn an_empty_half_is_no_proof_at_all() {
        let sig = base64_encode(&[2u8; 64]);
        assert!(SessionProof::decode(&format!(".1.{sig}")).is_none());
        assert!(SessionProof::decode(&format!("{}.1.", base64_encode(&[1u8; 32]))).is_none());
    }

    #[test]
    fn base64_survives_every_tail_length() {
        for len in 0..=48usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let encoded = base64_encode(&bytes);
            assert!(!encoded.contains('='), "unpadded at len {len}");
            assert_eq!(base64_decode(&encoded).as_deref(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn a_truncated_base64_group_is_refused() {
        // Six bits do not make a byte, so a group of one is never well formed.
        assert!(base64_decode("A").is_none());
    }

    /// The decoder's doc claims it refuses characters outside the alphabet,
    /// and until this test existed nothing checked that claim. A decoder that
    /// *skipped* them would let `key` and `signature` disagree with what was on
    /// the wire in a way no later check notices — the proof would still
    /// verify, against bytes the client never sent.
    ///
    /// The first version of this test built its inputs by replacing a
    /// character in a derived string and assumed the character was there. It
    /// was not, so the replacement was a no-op, the decode succeeded, and the
    /// test went red for a reason that had nothing to do with strictness. The
    /// version below asserts its own preconditions instead: if a future
    /// vector stops containing both `+` and `/`, the test says so instead of
    /// quietly passing on a substitution that changed nothing.
    #[test]
    fn a_character_outside_the_alphabet_is_refused() {
        // A space spliced into the middle of a well-formed encoding.
        let clean = base64_encode(&[0xfbu8; 32]);
        let mut spliced = clean.clone();
        spliced.insert(4, ' ');
        assert!(base64_decode(&spliced).is_none(), "a space is not base64");
        assert!(
            base64_decode(&format!("{clean}\n")).is_none(),
            "nor is a newline"
        );

        // A url-safe alphabet, which is what a second implementation of this
        // encoder would most plausibly emit instead. Two bytes of 0xfb encode
        // to "+/s" — three characters, no padding — so both characters are
        // present and neither replacement is a no-op.
        let both = base64_encode(&[0xfbu8; 2]);
        assert_eq!(both, "+/s", "unpadded: two bytes are three characters");
        assert!(base64_decode(&both.replace('+', "-")).is_none());
        assert!(base64_decode(&both.replace('/', "_")).is_none());
    }
}
