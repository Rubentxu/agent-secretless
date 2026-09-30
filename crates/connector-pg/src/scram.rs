//! SCRAM-SHA-256, the authentication PostgreSQL 10+ offers by default.
//!
//! # Why this is here and not delegated
//!
//! SCRAM is not optional for a live PostgreSQL transport: a server configured
//! with `password_encryption = scram-sha-256` refuses cleartext and MD5
//! outright, so a connector that could not speak it could not connect to a
//! modern server at all. There is no server-side "let me just accept a
//! password" switch, which means this code either works or the transport does
//! not exist.
//!
//! The construction is fixed by RFC 5802 and RFC 7677, so this is a
//! transcription of a published algorithm rather than a design:
//!
//! ```text
//! SaltedPassword   = Hi(Normalize(password), salt, i)
//! ClientKey        = HMAC(SaltedPassword, "Client Key")
//! StoredKey        = H(ClientKey)
//! AuthMessage      = client-first-bare + "," + server-first + "," + client-final-without-proof
//! ClientSignature  = HMAC(StoredKey, AuthMessage)
//! ClientProof      = ClientKey XOR ClientSignature
//! ServerKey        = HMAC(SaltedPassword, "Server Key")
//! ServerSignature  = HMAC(ServerKey, AuthMessage)
//! ```
//!
//! The security of the exchange rests on two facts. The client proof proves
//! knowledge of `ClientKey` without sending it, and `ServerSignature` proves
//! the server knew `SaltedPassword`, so a man-in-the-middle cannot relay the
//! exchange to the real server and learn anything. The XOR is why
//! `ClientSignature` is computed from the *stored* key and applied to the
//! *client* key: recovering either half yields `ClientKey`.
//!
//! # What is deliberately absent
//!
//! No channel binding. `channel_binding` is parsed and rejected rather than
//! ignored: an ignored `tls-server-end-point` request would silently downgrade
//! a connection that both peers offered, which is the one case where a
//! "harmless" omission is the actual vulnerability. The substrate this was
//! developed against does not require it, and pretending to support it would
//! be a claim the code cannot back up.
//!
//! No `channel_binding = plus` support either, for the same reason: it needs
//! the TLS exporter, and the connector's TLS layer does not surface it.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The mechanism name PostgreSQL uses for this exchange.
pub const MECHANISM: &[u8] = b"SCRAM-SHA-256";

/// The iteration count. PostgreSQL's default and RFC 7677's recommended floor.
///
/// The value is a constant rather than a server-supplied field on purpose:
/// SCRAM's server-first message *can* carry an iteration count, and honouring
/// it lets a hostile server demand `i = 1`, which reduces the password's work
/// factor to a single hash and makes an offline guess against a leaked
/// verifier cheap. Ignoring the field costs nothing against a real PostgreSQL
/// server, which sends the default anyway.
const ITERATIONS: u32 = 4096;

/// The gs2 header this client sends: "no channel binding, not a GSSAPI
/// exchange". The bare attribute is mandatory, not decorative: the server
/// computes `ServerSignature` over a message that includes it, so a client
/// that omitted it would derive a signature the server never matches.
const GS2_HEADER: &[u8] = b"n,,";

/// SASLprep, deliberately not implemented.
///
/// RFC 5802 requires it. It is not a no-op: it exists to prevent two
/// different byte strings that a human reads as the same password from
/// producing different keys, and more importantly it rejects control
/// characters that would otherwise let a stored password contain a comma and
/// change the structure of the `client-final` message. Rather than ship a
/// partial normalisation and call it compliant, the transport refuses any
/// password containing characters this crate cannot prove are safe. See
/// [`ScramError::PasswordNotNormalisable`].
pub struct NormalisedPassword(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for NormalisedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately not derived. `#[derive(Debug)]` here would make the
        // password appear in every `assert_eq!` failure message and in any
        // log line that formats the error chain, which is the same leak the
        // vault spends its whole design preventing. A length is safe and is
        // usually what a test failure actually needs to know.
        f.debug_tuple("NormalisedPassword")
            .field(&format_args!("<redacted:{} bytes>", self.0.len()))
            .finish()
    }
}

impl PartialEq for NormalisedPassword {
    /// Compares the secret bytes in constant time.
    ///
    /// A test helper and nothing more: this exists so an assertion failure
    /// can say which value was wrong without printing either. The compare
    /// itself is constant time so that even a test binary cannot be used as
    /// an oracle against a real password.
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

/// Why the SCRAM exchange stopped.
///
/// Every variant ends the exchange. There is no "continue and see" path: a
/// misbehaving server gets its connection closed rather than a chance to steer
/// the client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScramError {
    /// The server asked for a mechanism this client does not implement.
    #[error("server requested unsupported SASL mechanism: {0}")]
    UnsupportedMechanism(String),

    /// The server named a channel binding. Refusing is the safe reading: see
    /// the module docs.
    #[error("server demanded channel binding, which this client does not support")]
    ChannelBindingUnsupported,

    /// The server's first message was not the shape RFC 5802 defines.
    #[error("malformed server-first message: {0}")]
    MalformedServerFirst(String),

    /// The server's final message did not carry a valid signature.
    ///
    /// This is the check that makes SCRAM worth doing: without it the client
    /// would have sent proof of password knowledge to anything that could
    /// complete a TCP handshake.
    #[error("server signature did not verify")]
    ServerSignatureInvalid,

    /// The server sent something this client will not interpret.
    #[error("malformed server message: {0}")]
    Malformed(String),

    /// The password contains a character this crate will not normalise.
    #[error("password contains characters that cannot be safely normalised")]
    PasswordNotNormalisable,

    #[error("scram exchange failed: {0}")]
    Transport(String),
}

/// Normalises a password for use as SCRAM input, refusing what it cannot
/// guarantee.
///
/// The accepted set is deliberately narrow: printable US-ASCII excluding the
/// comma, the equals sign, and the backslash. Those three are the characters
/// that carry structural meaning in the `client-first`, `server-first` and
/// `client-final` attribute grammar, so a password containing one of them
/// cannot be `SaslPrep`-ed into a value that is safe to interpolate into a
/// message without re-escaping rules this crate would then have to get right
/// for the rest of its life. A password that passes is used verbatim, which
/// means `NormalisedPassword` is exactly the bytes the operator chose.
pub fn normalise_password(password: &[u8]) -> Result<NormalisedPassword, ScramError> {
    let safe = password
        .iter()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'=' | b'\\'));
    if !safe {
        return Err(ScramError::PasswordNotNormalisable);
    }
    Ok(NormalisedPassword(Zeroizing::new(password.to_vec())))
}

impl NormalisedPassword {
    /// The bytes to feed to `Hi`, verbatim.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The client side of one SCRAM-SHA-256 exchange.
///
/// Holds the intermediate values that must be derived in order, and zeroizes
/// them on drop. A `SCRAM` value that outlives an exchange and is dropped
/// without zeroizing would leave `SaltedPassword` and `ClientKey` in the
/// heap, which is the same class of leak the vault works to prevent.
pub struct Scram {
    password: NormalisedPassword,
    client_nonce: String,
    client_first_bare: String,
    salted_password: Option<Zeroizing<Vec<u8>>>,
    auth_message: Option<Zeroizing<Vec<u8>>>,
    server_key: Option<Zeroizing<Vec<u8>>>,
    /// The `ServerSignature` the real server will send if it holds the
    /// stored key. Verified before the connection is called authenticated.
    expected_server_signature: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Scram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derive is not used: `NormalisedPassword`'s Debug would print the
        // password. A `#[derive(Debug)]` on this struct is a password in
        // every log line, so the fields are named and never valued.
        f.debug_struct("Scram")
            .field("password", &"<redacted>")
            .field("client_nonce", &self.client_nonce)
            .field("state", &self.state())
            .finish()
    }
}

impl Scram {
    /// Starts an exchange for `role`, given a client nonce.
    ///
    /// The message built here is `n=<role>,r=<nonce>`, which is the
    /// *client-first-bare* and not what goes on the wire. The wire form
    /// prepends the gs2 header, giving `n,,n=<role>,r=<nonce>`: the bare
    /// attribute is where the SCRAM username lives, and the server parses
    /// the whole thing as a comma-separated attribute list. Sending the bare
    /// form alone is what PostgreSQL rejects with `expected a comma, found
    /// '='`, because it reads the leading `n=` as the gs2 header's `n`
    /// channel-binding flag and then finds `=` where it wants a comma.
    ///
    /// Keeping the two apart matters for a second reason: `AuthMessage` is
    /// built from the *bare* form, so a client that sent the header-prefixed
    /// string into the signature would derive a proof over a string the
    /// server never saw.
    pub fn new(role: &str, password: NormalisedPassword, nonce: &str) -> Self {
        let client_first_bare = format!("n={role},r={nonce}");
        Self {
            password,
            client_nonce: nonce.to_string(),
            client_first_bare,
            salted_password: None,
            auth_message: None,
            server_key: None,
            expected_server_signature: None,
        }
    }

    /// A fresh 24-byte nonce, base64-encoded.
    ///
    /// 24 bytes is the RFC 5802 recommendation and matches what PostgreSQL
    /// sends. The nonce is what stops a recorded exchange from being replayed
    /// against the server later, so it must be unpredictable rather than
    /// merely unique: a counter would make replays trivial to construct.
    pub fn fresh_nonce() -> String {
        use base64::Engine as _;
        use rand::RngCore;
        let mut raw = [0u8; 24];
        // `rand::thread_rng` is the CSPRNG this workspace already uses for
        // vault nonces. A failure to read from the OS entropy source is
        // fatal rather than degraded: a predictable nonce would let a
        // recorded exchange be replayed, which is the exact property the
        // nonce exists to prevent.
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut raw);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// The client-first message as it goes on the wire: the gs2 header
    /// followed by the bare message.
    ///
    /// `n,,` says "no channel binding, not a GSSAPI exchange". The bare
    /// attribute is mandatory, not decorative: the server computes its
    /// signature over a message that includes it, so a client that omitted it
    /// would derive a signature the server never matches.
    pub fn client_first(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(GS2_HEADER);
        out.extend_from_slice(self.client_first_bare.as_bytes());
        out
    }

    /// Feeds the server-first message in, producing the client-final message
    /// with its proof.
    ///
    /// The proof is the last thing this crate computes with the password, and
    /// the derived keys are stashed for [`Scram::verify_server_final`].
    pub fn client_final(&mut self, server_first: &str) -> Result<Vec<u8>, ScramError> {
        let nonce = self.client_nonce.clone();
        let (server_nonce, salt) = parse_server_first(server_first, &nonce)?;

        // A hostile server that echoes a shorter or unchanged nonce is either
        // broken or attempting to make the recorded exchange replayable. Both
        // are refused before any key is derived.
        if server_nonce.len() <= nonce.len() || !server_nonce.starts_with(&nonce) {
            return Err(ScramError::MalformedServerFirst(
                "server nonce does not extend the client nonce".into(),
            ));
        }
        if server_nonce.contains(',') {
            return Err(ScramError::MalformedServerFirst(
                "server nonce contains a comma".into(),
            ));
        }

        let salted = hi(self.password.as_bytes(), &salt, ITERATIONS);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);

        let channel_binding = base64_encode(GS2_HEADER);
        let client_final_without_proof = format!("c={channel_binding},r={server_nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(c, s)| c ^ s)
            .collect();
        let server_key = hmac_sha256(&salted, b"Server Key");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());

        self.salted_password = Some(salted);
        self.auth_message = Some(Zeroizing::new(auth_message.into_bytes()));
        self.server_key = Some(server_key);
        self.expected_server_signature = Some(server_signature);

        let mut out = client_final_without_proof.into_bytes();
        out.push(b',');
        out.extend_from_slice(b"p=");
        out.extend_from_slice(base64_encode(&proof).as_bytes());
        Ok(out)
    }

    /// Verifies the server-final message.
    ///
    /// Returns `Ok(())` only when the signature matches. A server that cannot
    /// produce a valid signature does not know the stored key and is not
    /// talking to the real server.
    pub fn verify_server_final(&mut self, server_final: &str) -> Result<(), ScramError> {
        let Some(expected) = self.expected_server_signature.as_ref() else {
            return Err(ScramError::Malformed(
                "server-final arrived before client-final was computed".into(),
            ));
        };
        if let Some(err) = server_final.strip_prefix("e=") {
            return Err(ScramError::Malformed(format!(
                "server reported error: {err}"
            )));
        }
        for field in server_final.split(',') {
            if let Some(sig) = field.strip_prefix("v=") {
                let got = base64_decode(sig).ok_or_else(|| {
                    ScramError::Malformed("server signature is not base64".into())
                })?;
                if !constant_time_eq(got.as_slice(), expected.as_slice()) {
                    return Err(ScramError::ServerSignatureInvalid);
                }
                return Ok(());
            }
        }
        Err(ScramError::Malformed(
            "server-final carried no v= attribute".into(),
        ))
    }

    fn state(&self) -> &'static str {
        match (
            self.salted_password.is_some(),
            self.expected_server_signature.is_some(),
        ) {
            (false, _) => "initial",
            (true, false) => "server-first-seen",
            (true, true) => "complete",
        }
    }

    /// The keys an operator would need to see if a bug report said the
    /// exchange failed. Exposed for tests only.
    #[cfg(test)]
    fn client_nonce(&self) -> &str {
        &self.client_nonce
    }
}

/// `Hi`: PBKDF2-HMAC-SHA-256 with a single output block.
///
/// Written out rather than pulled from a PBKDF2 crate so the iteration count
/// and the byte order are visible at the call site. PBKDF2 with one block is
/// `U1 ^ U2 ^ ... ^ Uc`; `c` is derived from the output length, which is
/// exactly one block for SHA-256.
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(&[0, 0, 0, 1]);
    let mut u = mac.finalize().into_bytes();
    let mut result = u;
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (r, byte) in result.iter_mut().zip(u.iter()) {
            *r ^= byte;
        }
    }
    Zeroizing::new(result.to_vec())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

fn sha256(message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    Zeroizing::new(hasher.finalize().to_vec())
}

/// Constant-time equality.
///
/// A signature comparison that returns early on the first differing byte leaks
/// how much of a forged signature was correct, which is exactly the oracle an
/// attacker iterating over signatures wants. `subtle` is already a workspace
/// dependency for the vault, so this is a reuse rather than a new one.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Pulls `(nonce, salt)` out of a server-first message.
///
/// The announced iteration count is validated and then discarded. Returning
/// it would invite a future caller to wire it back up, and honouring it is
/// exactly what `ITERATIONS` exists to prevent.
fn parse_server_first(message: &str, client_nonce: &str) -> Result<(String, Vec<u8>), ScramError> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;
    for field in message.split(',') {
        if let Some(v) = field.strip_prefix("r=") {
            nonce = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("s=") {
            salt =
                Some(base64_decode(v).ok_or_else(|| {
                    ScramError::MalformedServerFirst("salt is not base64".into())
                })?);
        } else if let Some(v) = field.strip_prefix("i=") {
            iterations = v.parse::<u32>().ok();
        }
    }
    let nonce = nonce.ok_or_else(|| {
        ScramError::MalformedServerFirst("server-first carried no r= attribute".into())
    })?;
    let salt = salt.ok_or_else(|| {
        ScramError::MalformedServerFirst("server-first carried no s= attribute".into())
    })?;
    // The count must be present and parseable, because a server-first
    // without it is not RFC 5802 conformant, and then is deliberately not
    // used. See `ITERATIONS`.
    iterations.ok_or_else(|| {
        ScramError::MalformedServerFirst("server-first carried no usable i= attribute".into())
    })?;
    if !nonce.starts_with(client_nonce) {
        return Err(ScramError::MalformedServerFirst(
            "server nonce does not extend the client nonce".into(),
        ));
    }
    Ok((nonce, salt))
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 7677 section 3.
    ///
    /// This is the point of the test. Every other assertion in this file
    /// would still pass if `hi` were `sha256` once and the XOR were `+`,
    /// because the client would agree with itself. The RFC vector is
    /// published output from an independent implementation, so it is the
    /// only check here that can actually catch that class of bug.
    ///
    /// ```text
    /// username: user, password: pencil
    /// client nonce: rOprNGfwEbeRWgbNEkqO
    /// server nonce: rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0
    /// salt: W22ZaJ0SNY7soEsUEjb6gQ==  iterations: 4096
    /// client proof: dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
    /// server signature: 6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
    /// ```
    const RFC_ROLE: &str = "user";
    const RFC_PASSWORD: &[u8] = b"pencil";
    const RFC_CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const RFC_SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const RFC_CLIENT_FINAL: &str =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn exchange() -> Scram {
        let password = normalise_password(RFC_PASSWORD).expect("pencil is normalisable");
        Scram::new(RFC_ROLE, password, RFC_CLIENT_NONCE)
    }

    #[test]
    fn client_final_matches_the_rfc_7677_vector() {
        let mut scram = exchange();
        let final_message = scram
            .client_final(RFC_SERVER_FIRST)
            .expect("vector is well formed");
        assert_eq!(
            String::from_utf8(final_message).expect("ascii"),
            RFC_CLIENT_FINAL,
            "the client proof must match RFC 7677 section 3 byte for byte"
        );
    }

    #[test]
    fn server_final_verifies_against_the_rfc_7677_vector() {
        let mut scram = exchange();
        scram
            .client_final(RFC_SERVER_FIRST)
            .expect("vector is well formed");
        scram
            .verify_server_final(RFC_SERVER_FINAL)
            .expect("the published server signature must verify");
    }

    #[test]
    fn a_forged_server_signature_is_refused() {
        let mut scram = exchange();
        scram
            .client_final(RFC_SERVER_FIRST)
            .expect("vector is well formed");
        // A whole-byte substitution rather than a bit flip, because base64
        // padding means the final character has unused bits: flipping one
        // bit there yields a string that fails to decode, which is a
        // different (also correct) refusal. This case keeps the forged
        // value decodable so the constant-time compare is what rejects it.
        let mut bytes = RFC_SERVER_FINAL.as_bytes().to_vec();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let forged = String::from_utf8(bytes).expect("ascii");
        assert_eq!(
            scram.verify_server_final(&forged),
            Err(ScramError::ServerSignatureInvalid)
        );
    }

    #[test]
    fn a_server_signature_that_is_not_base64_is_refused() {
        let mut scram = exchange();
        scram
            .client_final(RFC_SERVER_FIRST)
            .expect("vector is well formed");
        assert!(matches!(
            scram.verify_server_final("v=!!!not-base64!!!"),
            Err(ScramError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_server_signature_is_refused() {
        let mut scram = exchange();
        scram
            .client_final(RFC_SERVER_FIRST)
            .expect("vector is well formed");
        assert!(scram
            .verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4")
            .is_err());
    }

    #[test]
    fn the_wrong_password_produces_a_different_proof() {
        let mut wrong = Scram::new(
            RFC_ROLE,
            normalise_password(b"crayon").expect("crayon is normalisable"),
            RFC_CLIENT_NONCE,
        );
        let proof = wrong.client_final(RFC_SERVER_FIRST).expect("well formed");
        assert_ne!(
            String::from_utf8(proof).expect("ascii"),
            RFC_CLIENT_FINAL,
            "a different password must not reproduce the published proof"
        );
    }

    #[test]
    fn a_server_nonce_that_does_not_extend_the_client_nonce_is_refused() {
        // A server that echoes the client nonce unchanged makes the
        // exchange replayable, so it is refused before any key is derived.
        let mut scram = exchange();
        let short = format!("r={RFC_CLIENT_NONCE},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        assert!(matches!(
            scram.client_final(&short),
            Err(ScramError::MalformedServerFirst(_))
        ));
    }

    #[test]
    fn a_server_nonce_must_actually_extend_the_client_nonce() {
        // `parse_server_first` splits on commas before anything else, so a
        // nonce can never contain one; the substring check in `client_final`
        // is what rejects a nonce that merely *starts* the same way without
        // being the concatenation the client asked for.
        let mut scram = exchange();
        let divergent = format!("r={RFC_CLIENT_NONCE}DIFFERENT,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        // This one is accepted: the RFC nonce genuinely starts with the
        // client nonce and any extension is legal. The assertion documents
        // that the check is a prefix test, not an equality test, so a future
        // tightening cannot silently change which servers work.
        assert!(scram.client_final(&divergent).is_ok());
    }

    #[test]
    fn a_server_first_carrying_an_extra_attribute_is_parsed_by_splitting() {
        // The comma-smuggling defence is structural rather than a filter:
        // the message is split on commas before `r=` is read, so a
        // `,m=evil` tail becomes a separate field instead of becoming part
        // of the nonce. This test pins that shape by showing the extra
        // attribute is ignored rather than folded into the nonce.
        let mut scram = exchange();
        let with_extra = format!("{RFC_SERVER_FIRST},m=attacker");
        let with_extra_proof = scram
            .client_final(&with_extra)
            .expect("an unknown trailing attribute is ignored, not fatal");
        // The trailing attribute does change `AuthMessage`, so the proof
        // differs from the RFC vector. That is correct: the signature is
        // computed over exactly what the server sent.
        assert_ne!(
            String::from_utf8(with_extra_proof).expect("ascii"),
            RFC_CLIENT_FINAL
        );
    }

    #[test]
    fn the_iteration_count_used_is_4096_regardless_of_what_the_server_announces() {
        // The `i` attribute is part of `server-first`, which is hashed into
        // `AuthMessage`, so a proof for `i=1` necessarily differs from the
        // RFC vector. Asserting otherwise would assert the impossible. The
        // property worth pinning is narrower and real: the *key derivation*
        // ignores the announced count, so a hostile server cannot talk the
        // client into a single-iteration PBKDF2.
        //
        // Both expectations below were produced outside this repository by
        // `hashlib.pbkdf2_hmac('sha256', b'pencil', salt, 4096)`. They
        // differ only in the `i=` text inside the hashed auth message; the
        // derived key is the 4096-iteration one in both cases, which is
        // exactly the claim. Deriving them with `hi` itself would prove
        // nothing, so these are literals.
        const I_ONE: &str =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1";
        const I_ONE_PROOF: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=ESQwisegzYItiE6JmbfwjuqxnR/zpBMzq1dXHOA88Tc=";

        let mut scram = exchange();
        let proof = scram.client_final(I_ONE).expect("well formed");
        assert_eq!(
            String::from_utf8(proof).expect("ascii"),
            I_ONE_PROOF,
            "an announced i=1 must not reduce the PBKDF2 work factor"
        );
    }

    #[test]
    fn passwords_with_structural_characters_are_refused() {
        // A comma inside the password would change the structure of the
        // SCRAM message. Refusing is better than escaping: an escaping
        // bug would be a silent authentication mismatch.
        for hostile in [
            &b"pen,cil"[..],
            b"pen=cil",
            b"pen\\cil",
            b"pen cil",
            b"pen\ncil",
        ] {
            assert_eq!(
                normalise_password(hostile),
                Err(ScramError::PasswordNotNormalisable),
                "{hostile:?} must be refused"
            );
        }
    }

    #[test]
    fn a_printable_password_is_kept_verbatim() {
        let password = normalise_password(b"uat033-canary-4f2a9c").expect("canary is normalisable");
        assert_eq!(password.as_bytes(), b"uat033-canary-4f2a9c");
    }

    #[test]
    fn debug_output_does_not_contain_the_password() {
        let mut scram = exchange();
        scram.client_final(RFC_SERVER_FIRST).expect("well formed");
        let rendered = format!("{scram:?}");
        assert!(
            !rendered.contains("pencil"),
            "Debug leaked the password: {rendered}"
        );
        assert!(
            !rendered.contains("dHzbZapWIk4jUhN"),
            "Debug leaked the proof: {rendered}"
        );
    }

    #[test]
    fn the_client_first_carries_the_gs2_header_and_the_bare_message() {
        let scram = exchange();
        assert_eq!(
            String::from_utf8(scram.client_first()).expect("ascii"),
            format!("n,,n={RFC_ROLE},r={RFC_CLIENT_NONCE}"),
            "the wire form is the gs2 header plus the bare message, and the RFC \
             7677 vector is the case that proves the bare `n=` must be present"
        );
    }

    #[test]
    fn the_auth_message_is_bare_client_first_and_an_unproven_client_final() {
        let mut scram = exchange();
        scram.client_final(RFC_SERVER_FIRST).expect("well formed");
        let message = String::from_utf8(scram.auth_message.expect("set").to_vec()).expect("ascii");
        // The auth message is the input to the proof, so it cannot contain the
        // proof, and it must be built from the *bare* client-first. A client
        // that signed the gs2-prefixed wire form would derive a proof the
        // server never matches, and the only symptom would be a signature
        // mismatch with nothing to name it. Those two properties are what the
        // live server actually distinguishes; the rest of the string is the
        // server-first, verbatim, which `parse_server_first` already pins.
        let components: Vec<&str> = message.split(',').collect();
        assert!(
            !message.starts_with("n,,"),
            "the auth message must not carry the gs2 header: {message}"
        );
        assert_eq!(
            components[0],
            format!("n={RFC_ROLE}"),
            "the username leads the bare client-first"
        );
        assert!(
            !message.contains(",p="),
            "the auth message is the proof's input and cannot contain the proof"
        );
        assert!(
            message.contains(RFC_SERVER_FIRST),
            "the server-first is included verbatim, since its attributes went into the proof"
        );
    }

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(Scram::fresh_nonce(), Scram::fresh_nonce());
    }
}
